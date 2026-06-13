import json, os, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(__file__))
import server


class StateTests(unittest.TestCase):
    def test_review_requested_is_valid(self):
        self.assertIn("review-requested", server.VALID_STATES)

    def test_recommend_next_step_for_review_requested(self):
        label, hint = server.recommend_next_step("review-requested", "50", False)
        self.assertEqual(label, "review queued")

    def test_status_form_read_only(self):
        old = server.READ_ONLY
        try:
            server.READ_ONLY = True
            self.assertIn("read-only", server.render_status_form("poppler", "abc123def456", "new"))
            self.assertNotIn("<form", server.render_status_form("poppler", "abc123def456", "new"))
        finally:
            server.READ_ONLY = old

    def test_normalize_status_uses_first_token(self):
        self.assertEqual(server.normalize_status("dup\npoints-to: abc123\n"), "dup")
        self.assertEqual(server.normalize_status("review-requested note"), "review-requested")
        self.assertEqual(server.normalize_status(""), "new")


class ScanTests(unittest.TestCase):
    def test_target_crashes_parses_review_flag(self):
        line = "abc123def456|new|dblToCol|78|2026-04-19T15:36:10-05:00|N|Y"
        server.run_on_host = lambda cmd, timeout=20: (line + "\n", "", 0)
        rows = server.target_crashes("poppler")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["has_review"])
        self.assertFalse(rows[0]["has_notes"])

    def test_target_crashes_parses_report_priority(self):
        row = {
            "hash": "abc123def456",
            "status": "repro-ok",
            "top_frame": "RangeError @ packet.js:247",
            "hits": 6170,
            "first_seen": "2026-06-11T18:49:16-05:00",
            "has_notes": False,
            "has_review": False,
            "issue_class": "sqlnet-short-packet-bounds",
            "impact": "client-side-parser-dos",
            "confidence": "medium",
            "report_priority": "58",
            "assessed_severity": "MED",
        }
        server.run_on_host = lambda cmd, timeout=20: (json.dumps(row) + "\n", "", 0)
        rows = server.target_crashes("node-oracledb")
        self.assertEqual(rows[0]["report_priority"], "58")
        self.assertEqual(rows[0]["issue_class"], "sqlnet-short-packet-bounds")

    def test_frames_reviewed(self):
        crashes = [
            {"top_frame": "dblToCol", "has_review": True},
            {"top_frame": "dblToCol", "has_review": False},
            {"top_frame": "appendfv", "has_review": False},
        ]
        self.assertEqual(server.frames_reviewed(crashes), {"dblToCol"})


class FrontmatterTests(unittest.TestCase):
    SAMPLE = ("---\n"
              "reviewed_at: 2026-05-30T14:30:00-05:00\n"
              "frame: dblToCol\n"
              "model: claude-opus-4-8\n"
              "cost_usd: 0.62\n"
              "seconds: 48\n"
              "---\n"
              "# Review\n\nbody text\n")

    def test_splits_frontmatter_and_body(self):
        meta, body = server.parse_review_frontmatter(self.SAMPLE)
        self.assertEqual(meta["frame"], "dblToCol")
        self.assertEqual(meta["cost_usd"], "0.62")
        self.assertTrue(body.lstrip().startswith("# Review"))

    def test_no_frontmatter_returns_empty_meta(self):
        meta, body = server.parse_review_frontmatter("just text")
        self.assertEqual(meta, {})
        self.assertEqual(body, "just text")


class ListReviewTests(unittest.TestCase):
    def test_unreviewed_unnoted_frame_is_actionable(self):
        crashes = [{"top_frame": "x", "has_review": False, "has_notes": False}]
        reviewed = server.frames_reviewed(crashes)
        c = crashes[0]
        actionable = (not c["has_notes"]) and (c["top_frame"] not in reviewed)
        self.assertTrue(actionable)


class ViabilityTests(unittest.TestCase):
    def test_report_priority_overrides_high_hit_count(self):
        bucket, score, reason = server.viability(
            "RangeError @ packet.js:247", "6170", False, "repro-ok",
            report_priority="35",
            issue_class="sqlnet-send-path-harness-amplified",
            impact="harness-amplified",
            confidence="medium",
        )
        self.assertEqual(bucket, "low")
        self.assertEqual(score, 35)
        self.assertIn("hits=6170 is stability only", reason)

    def test_high_report_priority_is_high_even_with_few_hits(self):
        bucket, score, reason = server.viability(
            "RangeError: Maximum call stack size exceeded", "2", False, "repro-ok",
            report_priority="86",
            issue_class="oson-recursion-dos",
            impact="stack-exhaustion-dos",
            confidence="high",
        )
        self.assertEqual(bucket, "high")
        self.assertEqual(score, 86)
        self.assertIn("oson-recursion-dos", reason)


class LedgerTests(unittest.TestCase):
    def test_reads_and_sums_ledger(self):
        rows = ("2026-05-30T14:30:00-05:00\tdblToCol\t4971c05e06c1\tclaude-opus-4-8\t0.62\t13798\t3533\t48\n"
                "2026-05-30T14:40:00-05:00\tappendfv\tee40a47038bb\tclaude-opus-4-8\t0.55\t12000\t3000\t41\n")
        server.run_on_host = lambda cmd, timeout=20: (rows, "", 0)
        led = server.read_reviews_ledger("poppler")
        self.assertEqual(led["count"], 2)
        self.assertAlmostEqual(led["cost_usd"], 1.17, places=2)
        self.assertEqual(led["seconds"], 89)

    def test_empty_ledger(self):
        server.run_on_host = lambda cmd, timeout=20: ("", "", 0)
        led = server.read_reviews_ledger("poppler")
        self.assertEqual(led["count"], 0)
        self.assertEqual(led["cost_usd"], 0.0)


class JackalopeRolesTests(unittest.TestCase):
    STATS = {
        "engine": "jackalope", "pid": "23725", "alive": True,
        "execs_per_sec": 280, "execs_done": 392097, "corpus_count": 316,
        "coverage": 23874, "saved_crashes": 4, "last_find": 1781293714,
        "start_time": 1781282475, "updated_at": 1781293867,
    }

    def _write(self, obj):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "stats.json")
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def test_single_jackalope_role_shape(self):
        roles = server.jackalope_roles_from_stats(self._write(self.STATS))
        self.assertEqual(len(roles), 1)
        r = roles[0]
        # role identity + alive
        self.assertEqual(r["role"], "jackalope")
        self.assertIs(r["alive"], True)
        # numeric stats are stringified (parity with AFL fuzzer_stats parsing)
        self.assertEqual(r["execs_per_sec"], "280")
        self.assertEqual(r["execs_done"], "392097")
        self.assertEqual(r["corpus_count"], "316")
        self.assertEqual(r["bitmap_cvg"], "23874")   # coverage offsets -> bitmap_cvg
        self.assertEqual(r["saved_crashes"], "4")
        self.assertEqual(r["unique_crashes"], "4")
        self.assertEqual(r["pid"], "23725")
        self.assertEqual(r["fuzzer_pid"], "23725")
        # no-analogue fields default to "0"
        self.assertEqual(r["pending_total"], "0")
        self.assertEqual(r["pending_favs"], "0")
        self.assertEqual(r["saved_hangs"], "0")
        # last_find_age_s derived and non-negative
        self.assertIsNotNone(r["last_find_age_s"])
        self.assertGreaterEqual(r["last_find_age_s"], 0)

    def test_roles_consumable_by_renderers(self):
        # The aggregate/host_health math must not throw on a jackalope role.
        r = server.jackalope_roles_from_stats(self._write(self.STATS))[0]
        self.assertTrue(r["unique_crashes"].isdigit())
        self.assertEqual(int(r["execs_done"]), 392097)
        self.assertEqual(float(r["bitmap_cvg"].rstrip('%')), 23874.0)

    def test_dead_fuzzer_alive_false(self):
        dead = dict(self.STATS, alive=False)
        r = server.jackalope_roles_from_stats(self._write(dead))[0]
        self.assertIs(r["alive"], False)

    def test_missing_or_bad_file_returns_empty(self):
        self.assertEqual(server.jackalope_roles_from_stats("/no/such/stats.json"), [])
        bad = tempfile.mkdtemp()
        badp = os.path.join(bad, "stats.json")
        with open(badp, "w") as f:
            f.write("{ not json")
        self.assertEqual(server.jackalope_roles_from_stats(badp), [])


class FuzzilliRolesTests(unittest.TestCase):
    """A VM target with engine=fuzzilli exposes the SAME normalized stats.json
    schema as jackalope, but read over the VM proxy. roles_from_stats_json shapes
    both; only the role label + JSON source differ. crashes still come from the
    normal VM crashes-triaged scan, so only the role path is new here."""

    STATS = {
        "engine": "fuzzilli", "pid": "5512", "alive": True,
        "execs_per_sec": 1450, "execs_done": 9100000, "corpus_count": 2048,
        "coverage": 88123, "saved_crashes": 9, "last_find": 1781293714,
        "start_time": 1781200000, "updated_at": 1781293900,
    }

    def test_single_fuzzilli_role_shape(self):
        roles = server.roles_from_stats_json(self.STATS, "fuzzilli")
        self.assertEqual(len(roles), 1)
        r = roles[0]
        # synthetic single role, labelled 'fuzzilli'
        self.assertEqual(r["role"], "fuzzilli")
        self.assertIs(r["alive"], True)
        # numeric stats stringified (parity with AFL fuzzer_stats / jackalope)
        self.assertEqual(r["execs_per_sec"], "1450")
        self.assertEqual(r["execs_done"], "9100000")
        self.assertEqual(r["corpus_count"], "2048")
        self.assertEqual(r["bitmap_cvg"], "88123")   # coverage offsets -> bitmap_cvg
        self.assertEqual(r["saved_crashes"], "9")
        self.assertEqual(r["unique_crashes"], "9")
        self.assertEqual(r["pid"], "5512")
        self.assertEqual(r["fuzzer_pid"], "5512")
        # no-analogue fields default to "0"
        self.assertEqual(r["pending_total"], "0")
        self.assertEqual(r["pending_favs"], "0")
        self.assertEqual(r["saved_hangs"], "0")
        self.assertIsNotNone(r["last_find_age_s"])
        self.assertGreaterEqual(r["last_find_age_s"], 0)

    def test_role_is_consumable_by_aggregators(self):
        r = server.roles_from_stats_json(self.STATS, "fuzzilli")[0]
        # host_health/aggregate_kpis math must not throw on a fuzzilli role
        self.assertTrue(r["unique_crashes"].isdigit())
        self.assertEqual(int(r["execs_done"]), 9100000)
        self.assertEqual(float(r["bitmap_cvg"].rstrip('%')), 88123.0)

    def test_vm_fuzzilli_roles_reads_stats_via_proxy(self):
        # vm_stats_json cats stats.json through run_on_host; stub that round-trip.
        old = server.run_on_host
        try:
            server.run_on_host = lambda cmd, timeout=20: (json.dumps(self.STATS), "", 0)
            roles = server.vm_fuzzilli_roles("jsc")
        finally:
            server.run_on_host = old
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["role"], "fuzzilli")
        self.assertEqual(roles[0]["execs_per_sec"], "1450")

    def test_vm_fuzzilli_roles_empty_when_stats_missing(self):
        old = server.run_on_host
        try:
            # cat of a missing stats.json yields empty stdout -> [] (renders idle)
            server.run_on_host = lambda cmd, timeout=20: ("", "", 0)
            self.assertEqual(server.vm_fuzzilli_roles("jsc"), [])
        finally:
            server.run_on_host = old

    def test_roles_for_routes_fuzzilli_vm_target(self):
        # jsc is a VM target (NOT a host/jackalope target) whose engine=fuzzilli,
        # so roles_for must read stats.json, never target_roles' fuzzer_stats.
        server.CACHE.invalidate()
        old = (server.list_host_targets, server.vm_target_engine,
               server.vm_stats_json, server.target_roles)
        try:
            server.list_host_targets = lambda: []          # jsc is not a host target
            server.vm_target_engine = lambda t: "fuzzilli" if t == "jsc" else "afl"
            server.vm_stats_json = lambda t: dict(self.STATS) if t == "jsc" else None
            server.target_roles = lambda t: (_ for _ in ()).throw(
                AssertionError("fuzzilli target must not hit the AFL fuzzer_stats path"))
            roles = server.roles_for("jsc")
        finally:
            (server.list_host_targets, server.vm_target_engine,
             server.vm_stats_json, server.target_roles) = old
            server.CACHE.invalidate()
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0]["role"], "fuzzilli")

    def test_jackalope_shape_unchanged_after_refactor(self):
        # Same shaper now serves both engines; jackalope label/keys must be intact.
        jstats = dict(self.STATS, engine="jackalope")
        r = server.roles_from_stats_json(jstats, "jackalope")[0]
        self.assertEqual(r["role"], "jackalope")
        self.assertEqual(r["unique_crashes"], "9")


class StateEndpointTests(unittest.TestCase):
    """build_state() is the data path behind /api/state. We synthesize a
    reachable host + roles (no VM/orb), then assert the JSON shape the poller
    consumes. host_health and roles_for are looked up as module globals inside
    build_state/aggregate_kpis, so monkeypatching them on the module works."""

    def _role(self, **kw):
        base = {
            "role": "primary", "alive": True, "stats_age_s": 5,
            "execs_per_sec": "280", "execs_done": "100000", "last_find": "0",
            "pending_total": "10", "pending_favs": "2", "unique_crashes": "4",
            "saved_crashes": "4", "saved_hangs": "0", "corpus_count": "316",
            "bitmap_cvg": "23.4%", "last_find_age_s": 30,
        }
        base.update(kw)
        return base

    def setUp(self):
        self._h, self._r = server.host_health, server.roles_for
        server.CACHE.invalidate()
        self.roles = {
            "imageio": [self._role(role="jackalope", last_find_age_s=10,
                                   bitmap_cvg="23874", corpus_count="316",
                                   saved_crashes="4", unique_crashes="4")],
            "poppler": [self._role(role="primary", saved_crashes="3", unique_crashes="7",
                                   corpus_count="900", bitmap_cvg="41.2%", last_find_age_s=300),
                        self._role(role="asan", alive=True, saved_crashes="4", unique_crashes="7",
                                   corpus_count="120", bitmap_cvg="38.0%", last_find_age_s=120)],
        }
        self.health = {
            "reachable": True,
            "targets": ["imageio", "poppler"],
            "by_target": {
                "imageio": {"alive": 1, "calibrating": 0, "proc": 1,
                            "execs_per_sec": 280.0, "crashes": 4, "roles_seen": 1},
                "poppler": {"alive": 2, "calibrating": 1, "proc": 3,
                            "execs_per_sec": 900.0, "crashes": 7, "roles_seen": 2},
            },
            "total_alive": 3, "total_calibrating": 1,
            "total_execs_per_sec": 1180.0, "total_crashes": 11,
        }
        server.host_health = lambda: self.health
        server.roles_for = lambda t: self.roles.get(t, [])

    def tearDown(self):
        server.host_health, server.roles_for = self._h, self._r
        server.CACHE.invalidate()

    def test_global_state_shape(self):
        s = server.build_state()
        self.assertTrue(s["reachable"])
        self.assertIn("ts", s)
        k = s["kpis"]
        for key in ("live_roles", "calibrating", "execs_per_sec", "execs_done",
                    "max_cov", "corpus_count", "saved_crashes", "min_last_find_s"):
            self.assertIn(key, k)
        self.assertEqual(k["live_roles"], 3)
        self.assertEqual(k["calibrating"], 1)
        self.assertEqual(k["min_last_find_s"], 10)
        # round-trips through json
        self.assertIsInstance(json.loads(json.dumps(s)), dict)

    def test_global_targets_rows(self):
        s = server.build_state()
        names = {t["name"] for t in s["targets"]}
        self.assertEqual(names, {"imageio", "poppler"})
        for t in s["targets"]:
            for key in ("name", "alive", "execs_per_sec", "coverage",
                        "corpus", "crashes", "calibrating", "proc"):
                self.assertIn(key, t)
        img = next(t for t in s["targets"] if t["name"] == "imageio")
        self.assertEqual(img["alive"], 1)
        self.assertEqual(img["crashes"], 4)
        self.assertEqual(img["corpus"], 316)
        self.assertEqual(img["coverage"], 23874.0)

    def test_target_scoped_state(self):
        s = server.build_state("poppler")
        self.assertTrue(s["reachable"])
        self.assertIn("roles", s)
        self.assertEqual(len(s["roles"]), 2)
        self.assertEqual(len(s["targets"]), 1)
        self.assertEqual(s["targets"][0]["name"], "poppler")
        self.assertEqual(s["kpis"]["live_roles"], 2)
        # saved_crashes summed across this target's roles (3 + 4)
        self.assertEqual(s["kpis"]["saved_crashes"], 7)
        self.assertIsInstance(json.loads(json.dumps(s)), dict)

    def test_unknown_target_is_safe(self):
        self.assertEqual(server.build_state("nope")["error"], "unknown target")
        # path-injection style target is rejected before any fs/VM access
        self.assertEqual(server.build_state("../etc")["targets"], [])

    def test_unreachable_host(self):
        server.host_health = lambda: {"reachable": False, "error": "orb down"}
        server.CACHE.invalidate()
        s = server.build_state()
        self.assertFalse(s["reachable"])
        self.assertEqual(s["error"], "orb down")
        self.assertEqual(s["targets"], [])


if __name__ == "__main__":
    unittest.main()
