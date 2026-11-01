"""Golden tests for observed depth-headroom analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.parameters import analyze_parameters
from cipherscope.testing import FakeCryptoContext


def _trace(squares: int) -> dict:
    backend = FakeCryptoContext()
    with cipherscope.trace(backend) as session:
        ct = session.context.Encrypt(object(), object())
        for _ in range(squares):
            ct = session.context.EvalSquare(ct)
    return session.to_trace()


class ParameterAnalyzerTests(unittest.TestCase):
    def test_observed_headroom_below_configured_depth_emits_finding(self) -> None:
        # FakeCryptoContext advertises a configured multiplicative depth of 8.
        # Its EvalSquare never rescales, so the last product still carries a
        # pending rescale: five observed levels plus one deferred, headroom 2.
        result = analyze_parameters(_trace(5))

        self.assertEqual(result["analysis_status"], "positive")
        self.assertEqual(result["inventory"]["configured_multiplicative_depth"], 8)
        self.assertEqual(
            result["inventory"]["observed_max_levels_consumed_in_epoch"], 5
        )
        self.assertEqual(result["inventory"]["deferred_rescale_levels"], 1)
        self.assertEqual(result["inventory"]["observed_depth_headroom"], 2)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "parameters.depth_headroom_observed.v1")
        self.assertEqual(finding["confidence"], "measured")
        self.assertEqual(finding["estimated_impact"]["observed_depth_headroom"], 2.0)
        self.assertIn("this run's inputs", finding["limitations"][0])

    def test_full_utilization_is_clean(self) -> None:
        result = analyze_parameters(_trace(7))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["inventory"]["observed_depth_headroom"], 0)

    def test_missing_configured_depth_is_not_applicable(self) -> None:
        trace = _trace(5)
        trace["context"].pop("configured_multiplicative_depth", None)
        result = analyze_parameters(trace)
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])
        self.assertIn(
            "no known configured multiplicative depth",
            result["not_applicable_reasons"][0],
        )


if __name__ == "__main__":
    unittest.main()


class DeferredRescaleTests(unittest.TestCase):
    def test_pending_rescale_at_the_deepest_level_counts_as_a_committed_level(self) -> None:
        # FLEXIBLEAUTO leaves the last product at level k-1 with noise degree 2;
        # OpenFHE needs depth k for it, so the headroom must not include that level.
        from cipherscope.testing import FakeCiphertext

        class DeferringContext(FakeCryptoContext):
            def EvalSquare(self, ciphertext):
                self._called("EvalSquare")
                return self._fresh(ciphertext, level=ciphertext.level + 1, noise=2)

        backend = DeferringContext()
        with cipherscope.trace(backend) as session:
            ct = session.context.Encrypt(object(), object())
            for _ in range(7):
                ct = session.context.EvalSquare(ct)
        result = analyze_parameters(session.to_trace())
        # 7 observed levels + 1 deferred rescale == the configured depth of 8: nothing to reclaim.
        self.assertEqual(result["inventory"]["deferred_rescale_levels"], 1)
        self.assertEqual(result["inventory"]["observed_depth_headroom"], 0)
        self.assertEqual(result["analysis_status"], "clean")
