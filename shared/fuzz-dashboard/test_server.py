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
