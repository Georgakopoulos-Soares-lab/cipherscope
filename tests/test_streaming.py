"""Bounded recording: spooling, hard limits, truncation, and scaling behavior."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path

import cipherscope
from cipherscope.cli import main, validate_bundle
from cipherscope.compatibility import CompatibilityRegistry
from cipherscope.coverage import PARTIAL_PERMISSIVE, classify_run
from cipherscope.graph import build_graph
from cipherscope.pipeline import analyze_trace, build_analysis_bundle
from cipherscope.recorder import EventRecorder
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
from cipherscope.validation import validate_trace


def _adds(session: cipherscope.Session, count: int) -> None:
    left, right = FakeCiphertext(), FakeCiphertext()
    for _ in range(count):
        session.context.EvalAdd(left, right)


class LimitTests(unittest.TestCase):
    def test_event_limit_truncates_but_never_blocks_the_workload(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, max_events=3) as session:
            _adds(session, 5)
            self.assertFalse(session.recorder.accepting)
        trace = session.to_trace()
        self.assertEqual(backend.calls["EvalAdd"], 5)
        self.assertEqual(len(trace["events"]), 3)
        self.assertTrue(trace["run"]["truncated"])
        self.assertTrue(trace["truncated"])
        coverage = trace["run"]["coverage"]
        self.assertTrue(coverage["truncated"])
        self.assertEqual(coverage["truncation"]["reason"], "max_events")
        self.assertEqual(coverage["truncation"]["limit"], 3)
        self.assertEqual(coverage["truncation"]["events_written"], 3)
        self.assertEqual(coverage["truncation"]["calls_dropped"], 2)
        self.assertTrue(validate_trace(trace).valid, validate_trace(trace).errors)
        self.assertEqual(classify_run(trace).coverage_class, PARTIAL_PERMISSIVE)

    def test_byte_limit(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, max_trace_bytes=1500) as session:
            _adds(session, 20)
        trace = session.to_trace()
        truncation = trace["run"]["coverage"]["truncation"]
        self.assertEqual(truncation["reason"], "max_trace_bytes")
        self.assertGreaterEqual(truncation["bytes_written"], 1500)
        self.assertLess(len(trace["events"]), 20)
        self.assertEqual(backend.calls["EvalAdd"], 20)
        self.assertTrue(validate_trace(trace).valid)

    def test_meta_calls_after_the_cut_are_dropped_cleanly(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, max_events=1, secret_key=object(), shadow_mode=True) as session:
            ciphertext = FakeCiphertext(decoded_values=[1.0])
            session.context.EvalAdd(ciphertext, ciphertext)
            self.assertIs(session.annotate(ciphertext, provenance="public_constant"), ciphertext)
            dropped = session.checkpoint("cp", ciphertext=ciphertext, expected=[1.0])
            self.assertEqual(dropped["status"], "dropped")
            with session.region("r", operator="multiply", associative=True):
                session.context.EvalMult(ciphertext, ciphertext)
        trace = session.to_trace()
        self.assertEqual(len(trace["events"]), 1)
        self.assertNotIn("regions", trace)
        self.assertEqual(trace["run"]["coverage"]["truncation"]["calls_dropped"], 4)
        self.assertTrue(validate_trace(trace).valid)

    def test_truncated_trace_analyzes_and_keys_rule_declines(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, max_events=2) as session:
            session.context.EvalRotateKeyGen(object(), [1, 2])
            session.context.EvalRotate(FakeCiphertext(), 1)
            session.context.EvalRotate(FakeCiphertext(), 2)
        recommendations = analyze_trace(session.to_trace())
        self.assertEqual(recommendations["analyzer_status"]["keys.unused_in_observed_run.v1"], "not_applicable")

    def test_invalid_limits_are_rejected(self) -> None:
        for bad in (0, -1, 1.5, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                EventRecorder(compatibility=CompatibilityRegistry(), max_events=bad)


class SpoolTests(unittest.TestCase):
    def test_spool_is_used_above_the_buffer_and_order_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeCryptoContext()
            session = cipherscope.Session(backend, spool_dir=temporary)
            session.recorder._events._buffer_lines = 10
            with session:
                _adds(session, 25)
            spool = session.recorder.spool_path
            self.assertIsNotNone(spool)
            self.assertTrue(spool.is_file())
            self.assertEqual(sum(1 for _ in spool.open()), 20)
            trace = session.to_trace()
            self.assertEqual([e["sequence"] for e in trace["events"]], list(range(1, 26)))
            self.assertTrue(validate_trace(trace).valid)
            self.assertFalse(trace["run"]["truncated"])
            del session
            import gc

            gc.collect()
            self.assertFalse(spool.exists())

    def test_small_runs_never_touch_disk(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            _adds(session, 50)
        self.assertIsNone(session.recorder.spool_path)

    def test_interrupted_run_still_finalizes_from_the_spool(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            backend = FakeCryptoContext()
            session = cipherscope.Session(backend, spool_dir=temporary)
            session.recorder._events._buffer_lines = 5
            with self.assertRaises(KeyboardInterrupt), session:
                _adds(session, 12)
                raise KeyboardInterrupt
            trace = session.to_trace(status="interrupted")
            self.assertEqual(len(trace["events"]), 12)
            self.assertEqual(trace["run"]["status"], "interrupted")
            self.assertTrue(validate_trace(trace).valid)

    def test_cli_limits_produce_a_valid_truncated_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "target.py"
            script.write_text(
                "import cipherscope\n"
                "from cipherscope.testing import FakeCiphertext, FakeCryptoContext\n"
                "with cipherscope.trace(FakeCryptoContext()) as s:\n"
                "    a = FakeCiphertext()\n"
                "    for _ in range(10):\n"
                "        s.context.EvalAdd(a, a)\n",
                encoding="utf-8",
            )
            output = Path(temporary) / "bundle"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["run", "--max-events", "4", "--output", str(output), str(script)])
            self.assertEqual(code, 0)
            self.assertEqual(validate_bundle(output), [])
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertTrue(manifest["coverage"]["truncated"])
            self.assertEqual(manifest["coverage"]["truncation"]["calls_dropped"], 6)


class ScalingTests(unittest.TestCase):
    def test_memory_stays_within_the_buffer_envelope(self) -> None:
        backend = FakeCryptoContext()
        left, right = FakeCiphertext(), FakeCiphertext()
        with tempfile.TemporaryDirectory() as temporary:
            session = cipherscope.Session(backend, spool_dir=temporary)
            session.recorder._events._buffer_lines = 2048
            session.recorder._states._buffer_lines = 2048
            tracemalloc.start()
            try:
                with session:
                    for _ in range(6000):
                        session.context.EvalAdd(left, right)
                    warm, _ = tracemalloc.get_traced_memory()
                    for _ in range(30000):
                        session.context.EvalAdd(left, right)
                    after, _ = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertEqual(session.recorder.events_written, 36000)
        growth_mb = (after - warm) / 1e6
        self.assertLess(growth_mb, 8.0, f"traced memory grew {growth_mb:.1f} MB over 30k events")

    def test_graph_and_analysis_scale_roughly_linearly(self) -> None:
        def run(count: int) -> float:
            backend = FakeCryptoContext()
            with cipherscope.trace(backend) as session:
                ciphertext = FakeCiphertext()
                for _ in range(count):
                    ciphertext = session.context.EvalAdd(ciphertext, ciphertext)
            trace = session.to_trace()
            started = time.perf_counter()
            build_graph(trace)
            build_analysis_bundle(trace)
            return time.perf_counter() - started

        small, large = run(4000), run(20000)
        self.assertLess(large / max(small, 1e-3), 12.0, f"5x events took {large / small:.1f}x longer")


if __name__ == "__main__":
    unittest.main()
