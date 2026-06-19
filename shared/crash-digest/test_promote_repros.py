import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("promote-repros.py")
spec = importlib.util.spec_from_file_location("promote_repros", MODULE_PATH)
promote_repros = importlib.util.module_from_spec(spec)
spec.loader.exec_module(promote_repros)


class JSCReplayTests(unittest.TestCase):
    def _make_target(self, root: pathlib.Path, *, reduced: bool = False) -> tuple[pathlib.Path, pathlib.Path]:
        target = root / "jsc"
        crash = target / "crashes-triaged" / "0123456789ab"
        (target / "findings").mkdir(parents=True)
        crash.mkdir(parents=True)
        (target / "engine").write_text("fuzzilli\n")
        (target / "findings" / "settings.json").write_text(
            json.dumps(
                {
                    "processArguments": [
                        "--validateOptions=true",
                        "--thresholdForFTLOptimizeSoon=1000",
                        "--reprl",
                    ]
                }
            )
        )
        (crash / "poc.js").write_text("function f() { return 1; }\nf();\n")
        if reduced:
            (crash / "poc.reduced.js").write_text("f();\n")
        return target, crash

    def _write_executable(self, path: pathlib.Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)

    def test_jsc_reproducer_prefers_sibling_asan_binary_and_strips_reprl(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            target, crash = self._make_target(root)
            asan_jsc = root / "jsc-asan" / "WebKitBuild" / "bin" / "jsc"
            self._write_executable(asan_jsc)

            command = promote_repros.shell_reproducer(
                target,
                crash,
                {"engine": "fuzzilli"},
                17,
            )

            self.assertIn("timeout 17 env", command)
            self.assertIn("rm -f /tmp/fuzzah-jsc-ubsan.*", command)
            self.assertIn("-u JSC_ASAN_NICE", command)
            self.assertIn("ASAN_OPTIONS=", command)
            self.assertIn("UBSAN_OPTIONS=", command)
            self.assertIn("log_path=/tmp/fuzzah-jsc-ubsan", command)
            self.assertIn(str(asan_jsc), command)
            self.assertIn("--validateOptions=true", command)
            self.assertIn("--thresholdForFTLOptimizeSoon=1000", command)
            self.assertNotIn("--reprl", command)
            self.assertIn(str(crash / "poc.js"), command)

    def test_jsc_reproducer_prefers_reduced_poc(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            target, crash = self._make_target(root, reduced=True)
            default_jsc = target / "WebKitBuild" / "bin" / "jsc"
            self._write_executable(default_jsc)

            command = promote_repros.shell_reproducer(
                target,
                crash,
                {"engine": "fuzzilli"},
                10,
            )

            self.assertIn(str(default_jsc), command)
            self.assertIn(str(crash / "poc.reduced.js"), command)
            self.assertNotIn(str(crash / "poc.js"), command)

    def test_jsc_reproducer_honors_explicit_asan_env(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            target, crash = self._make_target(root)
            configured = root / "custom-asan" / "jsc"
            self._write_executable(configured)

            with mock.patch.dict(os.environ, {"JSC_ASAN_BIN": str(configured)}):
                command = promote_repros.shell_reproducer(
                    target,
                    crash,
                    {"engine": "fuzzilli"},
                    10,
                )

            self.assertIn(str(configured), command)
            self.assertIn("-u JSC_ASAN_BIN", command)

    def test_poc_script_embeds_javascript(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            target, crash = self._make_target(root, reduced=True)
            text = promote_repros.poc_script(
                target,
                crash,
                "timeout 10 jsc poc.reduced.js",
                {"engine": "fuzzilli"},
            )

            self.assertIn("poc_file: poc.reduced.js", text)
            self.assertIn("```js", text)
            self.assertIn("f();", text)
            self.assertIn("timeout 10 jsc poc.reduced.js", text)


class ClassificationTests(unittest.TestCase):
    def test_asan_report_is_memory_bug(self):
        klass, severity, action = promote_repros.classify(
            "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1234",
            "JSC::Foo",
            1,
            False,
        )

        self.assertEqual((klass, severity, action), ("memory-bug", "HIGH", "file-upstream"))

    def test_jsc_assertion_is_assertion(self):
        klass, severity, action = promote_repros.classify(
            "ASSERTION FAILED: !node->isTuple()",
            "ASSERTION FAILED: !node->isTuple()",
            134,
            False,
        )

        self.assertEqual(klass, "assertion")
        self.assertEqual(severity, "LOW")
        self.assertEqual(action, "defer unless release/ASan replay shows memory corruption")

    def test_shell_timeout_wins_over_stored_assertion_frame(self):
        klass, severity, action = promote_repros.classify(
            "WARNING: ASAN interferes with JSC signal handlers",
            "ASSERTION FAILED: !node->isTuple()",
            124,
            False,
        )

        self.assertEqual((klass, severity, action), ("timeout", "LOW", "investigate if repeatable outside timeout"))

    def test_jsc_timeout_assessment_does_not_confirm_stored_assertion(self):
        assessment = promote_repros.jsc_assessment(
            {"engine": "fuzzilli"},
            "ASSERTION FAILED: !node->isTuple()",
            "WARNING: ASAN interferes with JSC signal handlers",
            "LOW",
            "investigate if repeatable outside timeout",
        )

        self.assertEqual(assessment["issue_class"], "jsc-asan-timeout")
        self.assertEqual(assessment["severity"], "LOW")
        self.assertLess(assessment["report_priority"], 30)

    def test_jsc_assertion_assessment_is_not_high_value(self):
        assessment = promote_repros.jsc_assessment(
            {"engine": "fuzzilli"},
            "ASSERTION FAILED: !node->isTuple()",
            "ASSERTION FAILED: !node->isTuple()",
            "LOW",
            "defer unless release/ASan replay shows memory corruption",
        )

        self.assertEqual(assessment["issue_class"], "jsc-jit-assertion")
        self.assertEqual(assessment["severity"], "LOW")
        self.assertLess(assessment["report_priority"], 30)

    def test_generic_asan_assessment_stays_high_value(self):
        assessment = promote_repros.target_assessment(
            pathlib.Path("/tmp/example"),
            {},
            "target_func",
            "==1==ERROR: AddressSanitizer: heap-use-after-free",
            "memory-bug",
            "HIGH",
            "file-upstream",
        )

        self.assertEqual(assessment["issue_class"], "generic-asan-memory-bug")
        self.assertEqual(assessment["severity"], "HIGH")
        self.assertGreaterEqual(assessment["report_priority"], 80)


if __name__ == "__main__":
    unittest.main()
