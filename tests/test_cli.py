"""End-to-end tests for the dependency-free CipherScope CLI."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cipherscope.cli import main, validate_bundle


class CLITests(unittest.TestCase):
    def test_demo_validate_and_view(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["demo", "--output", str(output)]), 0)
                self.assertEqual(main(["validate", str(output)]), 0)
                self.assertEqual(main(["view", str(output)]), 0)
            self.assertEqual(validate_bundle(output), [])
            trace = json.loads((output / "trace.json").read_text(encoding="utf-8"))
            self.assertEqual(len(trace["events"]), 8)
            self.assertIs(trace["run"]["synthetic_contract"], True)
            recommendations = json.loads(
                (output / "recommendations.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                recommendations["analyzer_status"]["keys.unused_in_observed_run.v1"],
                "clean",
            )

    def test_run_forwards_arguments_and_target_exit_code(self) -> None:
        source = """\
import sys
import os
import cipherscope
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
backend = FakeCryptoContext()
cc = cipherscope.attach(backend)
cc.EvalBootstrap(FakeCiphertext())
print('target-argv=' + '|'.join(sys.argv[1:]))
print('target-cwd=' + os.getcwd())
print('target-stderr', file=sys.stderr)
raise SystemExit(7)
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "target.py"
            script.write_text(source, encoding="utf-8")
            output = root / "run"
            stdout = io.StringIO()
            stderr = io.StringIO()
            expected_cwd = str(Path.cwd())
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "run",
                        "--output",
                        str(output),
                        str(script),
                        "one",
                        "two",
                    ]
                )
            self.assertEqual(code, 7)
            self.assertIn("target-argv=one|two", stdout.getvalue())
            self.assertIn(f"target-cwd={expected_cwd}", stdout.getvalue())
            self.assertIn("target-stderr", stderr.getvalue())
            self.assertEqual(validate_bundle(output), [])
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["status"], "failed")

    def test_run_without_attachment_is_explicit_failure_with_partial_bundle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "target.py"
            script.write_text("print('uninstrumented target')\n", encoding="utf-8")
            output = root / "run"
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = main(["run", "--output", str(output), str(script)])
            self.assertEqual(code, 2)
            self.assertEqual(validate_bundle(output), [])
            trace = json.loads((output / "trace.json").read_text(encoding="utf-8"))
            self.assertEqual(trace["run"]["status"], "failed")
            self.assertEqual(trace["events"], [])

    def test_runner_owned_session_accepts_target_trace_scope(self) -> None:
        source = """\
import cipherscope
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
with cipherscope.trace(FakeCryptoContext()) as session:
    session.context.EvalRotate(FakeCiphertext(), 2)
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "target.py"
            script.write_text(source, encoding="utf-8")
            output = root / "run"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["run", "--output", str(output), str(script)])
            self.assertEqual(code, 0)
            self.assertEqual(validate_bundle(output), [])
            trace = json.loads((output / "trace.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [event["operation"] for event in trace["events"]], ["EvalRotate"]
            )

    def test_uncaught_covered_failure_writes_sanitized_partial_bundle(self) -> None:
        source = """\
import cipherscope
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
backend = FakeCryptoContext()
backend.fail_operations['EvalMult'] = RuntimeError('SECRET-EXCEPTION-MESSAGE')
cc = cipherscope.attach(backend)
cc.EvalMult(FakeCiphertext(), FakeCiphertext())
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "target.py"
            script.write_text(source, encoding="utf-8")
            output = root / "run"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["run", "--output", str(output), str(script)])
            self.assertEqual(code, 1)
            self.assertEqual(validate_bundle(output), [])
            serialized = (output / "trace.json").read_text(encoding="utf-8")
            self.assertNotIn("SECRET-EXCEPTION-MESSAGE", serialized)
            trace = json.loads(serialized)
            self.assertEqual(trace["events"][0]["error_class"], "RuntimeError")
            self.assertEqual(trace["events"][0]["output_ciphertexts"], [])

    def test_keyboard_interrupt_preserves_130_and_interrupted_bundle(self) -> None:
        source = """\
import cipherscope
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
cc = cipherscope.attach(FakeCryptoContext())
cc.EvalBootstrap(FakeCiphertext())
raise KeyboardInterrupt()
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "target.py"
            script.write_text(source, encoding="utf-8")
            output = root / "run"
            code = main(["run", "--output", str(output), str(script)])
            self.assertEqual(code, 130)
            self.assertEqual(validate_bundle(output), [])
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["status"], "interrupted")

    def test_existing_output_refuses_before_target_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "marker"
            script = root / "target.py"
            script.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            output = root / "run"
            output.mkdir()
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["run", "--output", str(output), str(script)])
            self.assertEqual(code, 2)
            self.assertFalse(marker.exists())

    def test_validate_rejects_corrupted_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["demo", "--output", str(output)]), 0)
            (output / "trace.json").write_text('{"duplicate":1,"duplicate":2}\n')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["validate", str(output)]), 1)
            self.assertIn("duplicate JSON object key", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
