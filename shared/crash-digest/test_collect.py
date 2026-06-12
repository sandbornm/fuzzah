import importlib.util
import pathlib
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


if __name__ == "__main__":
    unittest.main()
