import importlib.util
import json
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("collect.py")
spec = importlib.util.spec_from_file_location("collect", MODULE_PATH)
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)


class StatusTests(unittest.TestCase):
    def test_status_uses_first_token(self):
        self.assertEqual(collect.normalize_status("dup\npoints-to: abc123\n"), "dup")
        self.assertEqual(collect.normalize_status("repro-ok extra"), "repro-ok")
        self.assertEqual(collect.normalize_status(""), "new")


class HostLaneTests(unittest.TestCase):
    """The macOS host (jackalope) lane read from the local filesystem."""

    def _make_imageio(self, root: pathlib.Path, *, with_crash: bool) -> None:
        t = root / "imageio"
        (t / "findings").mkdir(parents=True)
        (t / "engine").write_text("jackalope\n")
        (t / "findings" / "stats.json").write_text(
            json.dumps(
                {
                    "engine": "jackalope",
                    "pid": "4242",
                    "alive": True,
                    "execs_per_sec": 20,
                    "execs_done": 24201,
                    "corpus_count": 380,
                    "coverage": 21514,
                    "saved_crashes": 4,
                    "last_find": 1781298281,
                    "start_time": 1781298058,
                }
            )
        )
        triaged = t / "crashes-triaged"
        triaged.mkdir()
        if with_crash:
            c = triaged / "0123456789ab"
            c.mkdir()
            (c / "meta.json").write_text(
                json.dumps(
                    {
                        "top_frame": "ImageIO`_cg_TIFFReadDirectory",
                        "hit_count": 3,
                        "first_seen": "2026-06-12T10:00:00Z",
                        "fuzzers": "imageio",
                        "poc_size": 512,
                        "engine": "jackalope",
                        "signature": "SIGSEGV-read",
                    }
                )
            )
            (c / ".status").write_text("new\n")
            (c / "poc.tiff").write_bytes(b"II*\x00")
            (c / "trace.txt").write_text("crash backtrace\n")

    def test_no_op_when_root_missing(self):
        with tempfile.TemporaryDirectory() as d:
            missing = pathlib.Path(d) / "nope"
            self.assertEqual(collect.collect_host_targets(missing), [])

    def test_host_target_maps_stats(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "targets"
            root.mkdir()
            self._make_imageio(root, with_crash=False)
            targets = collect.collect_host_targets(root)
            self.assertEqual(len(targets), 1)
            t = targets[0]
            self.assertEqual(t["name"], "imageio")
            self.assertEqual(t["engine"], "jackalope")
            self.assertEqual(t["alive_roles"], 1)
            self.assertEqual(t["execs_per_sec"], 20)
            self.assertEqual(t["coverage"], 21514)
            self.assertEqual(t["corpus_count"], 380)
            self.assertEqual(t["execs_done"], 24201)
            self.assertEqual(t["crashes"], [])
            # No AFL-style raw backlog for the digest's triage-drain to chew on.
            self.assertEqual(t["raw_crashes"]["unseen"], 0)
            self.assertEqual(t["roles"][0]["engine"], "jackalope")

    def test_host_target_with_crash(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "targets"
            root.mkdir()
            self._make_imageio(root, with_crash=True)
            targets = collect.collect_host_targets(root)
            self.assertEqual(len(targets), 1)
            t = targets[0]
            self.assertEqual(len(t["crashes"]), 1)
            crash = t["crashes"][0]
            self.assertEqual(crash["hash"], "0123456789ab")
            self.assertEqual(crash["engine"], "jackalope")
            self.assertEqual(crash["status"], "new")
            self.assertEqual(crash["top_frame"], "ImageIO`_cg_TIFFReadDirectory")
            self.assertEqual(crash["signature"], "SIGSEGV-read")
            self.assertEqual(crash["hit_count"], 3)
            self.assertEqual(crash["first_seen"], "2026-06-12T10:00:00Z")
            self.assertTrue(crash["has_trace"])
            # The AFL-replay enrichment docs are never present for jackalope.
            self.assertFalse(crash["has_report"])
            self.assertFalse(crash["has_repro"])
            self.assertFalse(crash["has_poc"])
            self.assertEqual(t["state_counts"], {"new": 1})
            self.assertIn("poc.tiff", [p["name"] for p in crash["poc_files"]])


if __name__ == "__main__":
    unittest.main()
