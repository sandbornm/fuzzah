import importlib.util
import pathlib
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("send-digest.py")
spec = importlib.util.spec_from_file_location("send_digest", MODULE_PATH)
send_digest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(send_digest)


class ScoreCrashTests(unittest.TestCase):
    def test_report_priority_is_displayed_score(self):
        crash = {
            "status": "repro-ok",
            "top_frame": "RangeError: Maximum call stack size exceeded",
            "hit_count": 6170,
            "report_priority": 86,
            "issue_class": "oson-recursion-dos",
            "impact": "stack-exhaustion-dos",
            "confidence": "high",
            "has_report": True,
            "has_poc": True,
        }
        score, reasons, changed = send_digest.score_crash(crash, previous=None)
        self.assertTrue(changed)
        self.assertEqual(score, 86)
        self.assertIn("priority=86", reasons)
        self.assertIn("6170 hits", reasons)


class RankingGateTests(unittest.TestCase):
    def test_default_rank_gate_keeps_only_memory_corruption(self):
        snapshot = {
            "targets": [
                {
                    "name": "jsc",
                    "crashes": [
                        {
                            "hash": "111111111111",
                            "status": "repro-ok",
                            "top_frame": "ASSERTION FAILED: !node->isTuple()",
                            "hit_count": 100,
                            "report_priority": 90,
                            "issue_class": "jsc-jit-assertion",
                            "impact": "process-abort-dos",
                        },
                        {
                            "hash": "222222222222",
                            "status": "repro-ok",
                            "top_frame": "RangeError: Maximum call stack size exceeded",
                            "hit_count": 6170,
                            "report_priority": 90,
                            "issue_class": "oson-recursion-dos",
                            "impact": "stack-exhaustion-dos",
                        },
                        {
                            "hash": "333333333333",
                            "status": "repro-ok",
                            "top_frame": "JSC::Foo",
                            "hit_count": 2,
                            "report_priority": 94,
                            "issue_class": "jsc-asan-heap-use-after-free",
                            "impact": "potential-memory-corruption",
                        },
                    ],
                }
            ]
        }

        with mock.patch.dict(send_digest.os.environ, {}, clear=True):
            ranked, all_crashes = send_digest.flatten_rank(snapshot, {})

        self.assertEqual([c["hash"] for c in ranked], ["333333333333"])
        self.assertEqual(len(all_crashes), 3)

    def test_can_exclude_legacy_targets_from_digest_snapshot(self):
        snapshot = {
            "targets": [
                {"name": "poppler", "crashes": []},
                {"name": "libvpx", "crashes": []},
                {"name": "jsc", "crashes": []},
            ]
        }

        filtered = send_digest.filter_snapshot_targets(snapshot, {"poppler", "libvpx"})

        self.assertEqual([t["name"] for t in filtered["targets"]], ["jsc"])


if __name__ == "__main__":
    unittest.main()
