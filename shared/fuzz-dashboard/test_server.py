import os, sys, unittest
sys.path.insert(0, os.path.dirname(__file__))
import server


class StateTests(unittest.TestCase):
    def test_review_requested_is_valid(self):
        self.assertIn("review-requested", server.VALID_STATES)

    def test_recommend_next_step_for_review_requested(self):
        label, hint = server.recommend_next_step("review-requested", "50", False)
        self.assertEqual(label, "review queued")


if __name__ == "__main__":
    unittest.main()
