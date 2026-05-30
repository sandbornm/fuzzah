import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
import server


class StateTests(unittest.TestCase):
    def test_review_requested_is_valid(self):
        self.assertIn("review-requested", server.VALID_STATES)

    def test_recommend_next_step_for_review_requested(self):
        label, hint = server.recommend_next_step("review-requested", "50", False)
        self.assertEqual(label, "review queued")


class ScanTests(unittest.TestCase):
    def test_target_crashes_parses_review_flag(self):
        line = "abc123def456|new|dblToCol|78|2026-04-19T15:36:10-05:00|N|Y"
        server.run_on_host = lambda cmd, timeout=20: (line + "\n", "", 0)
        rows = server.target_crashes("poppler")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["has_review"])
        self.assertFalse(rows[0]["has_notes"])

    def test_frames_reviewed(self):
        crashes = [
            {"top_frame": "dblToCol", "has_review": True},
            {"top_frame": "dblToCol", "has_review": False},
            {"top_frame": "appendfv", "has_review": False},
        ]
        self.assertEqual(server.frames_reviewed(crashes), {"dblToCol"})


if __name__ == "__main__":
    unittest.main()
