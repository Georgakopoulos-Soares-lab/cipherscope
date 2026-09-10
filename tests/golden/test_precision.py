"""Golden tests for precision-checkpoint drop analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.precision import analyze_precision
from cipherscope.errors import ShadowModeError
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


def _shadow_trace(first_values: list[float], second_values: list[float]) -> dict:
    backend = FakeCryptoContext()
    expected = [1.0, 2.0]
    first = FakeCiphertext(decoded_values=first_values)
    second = FakeCiphertext(decoded_values=second_values)
    with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
        session.checkpoint("early", ciphertext=first, expected=expected)
        session.checkpoint("late", ciphertext=second, expected=expected)
    trace = session.to_trace()
    first_checkpoint = trace["events"][0]["semantic_arguments"]
    assert first_checkpoint["expected_values"] == expected
    assert first_checkpoint["observed_values"] == first_values
    return trace


class PrecisionAnalyzerTests(unittest.TestCase):
    def test_precision_drop_between_checkpoints_is_ranked(self) -> None:
        # The late checkpoint decodes further from the expected values.
        trace = _shadow_trace([1.0, 2.0], [1.01, 2.01])
        result = analyze_precision(trace)

        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "precision.checkpoint_drop.v1")
        drop = finding["evidence"]
        self.assertEqual(drop["from_checkpoint"], "early")
        self.assertEqual(drop["to_checkpoint"], "late")
        self.assertGreater(drop["absolute_bits_lost"], 0)

    def test_improving_precision_is_clean(self) -> None:
        result = analyze_precision(_shadow_trace([1.01, 2.01], [1.0, 2.0]))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])

    def test_non_shadow_run_is_not_applicable(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalBootstrap(FakeCiphertext())
        result = analyze_precision(session.to_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn("shadow_mode=True", result["not_applicable_reasons"][0])

    def test_checkpoint_requires_enabled_shadow_mode(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            with self.assertRaises(ShadowModeError):
                session.checkpoint(
                    "cp",
                    ciphertext=FakeCiphertext(decoded_values=[1.0]),
                    expected=[1.0],
                )


if __name__ == "__main__":
    unittest.main()
