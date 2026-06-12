import json, os, sys, unittest
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


if __name__ == "__main__":
    unittest.main()
