import importlib.util
import pathlib
import unittest


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


if __name__ == "__main__":
    unittest.main()
