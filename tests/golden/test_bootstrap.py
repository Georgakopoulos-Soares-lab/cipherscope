"""Golden tests for observed-run bootstrap restoration analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.bootstrap import analyze_bootstrap
from cipherscope.testing import FakeCryptoContext


def _trace(pre_squares: int, post_squares: int, *, bootstrap: bool = True) -> dict:
    backend = FakeCryptoContext()
    with cipherscope.trace(backend) as session:
        ct = session.context.Encrypt(object(), object())
        for _ in range(pre_squares):
            ct = session.context.EvalSquare(ct)
        if bootstrap:
            ct = session.context.EvalBootstrap(ct)
        for _ in range(post_squares):
            ct = session.context.EvalSquare(ct)
    return session.to_trace()


class BootstrapAnalyzerTests(unittest.TestCase):
    def test_restored_levels_exceeding_suffix_emit_finding(self) -> None:
        result = analyze_bootstrap(_trace(5, 1))

        self.assertEqual(result["analysis_status"], "positive")
        record = result["inventory"][0]
        self.assertEqual(record["level_before"], 5)
        self.assertEqual(record["level_after"], 0)
        self.assertEqual(record["restored_levels"], 5)
        self.assertEqual(record["suffix_levels_consumed"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "bootstrap.restored_levels_underused.v1")
        self.assertEqual(finding["confidence"], "measured")
        self.assertEqual(finding["estimated_impact"]["unused_restored_levels"], 4.0)
        self.assertIsNone(finding["estimated_impact"]["speedup"])
        self.assertIn("not proof", finding["limitations"][0])

    def test_suffix_matching_restoration_is_clean(self) -> None:
        result = analyze_bootstrap(_trace(3, 3))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["inventory"][0]["restored_levels"], 3)
        self.assertEqual(result["inventory"][0]["suffix_levels_consumed"], 3)

    def test_fresh_operands_after_a_bootstrap_do_not_inflate_suffix_use(self) -> None:
        # Real OpenFHE returns a bootstrapped ciphertext at a fixed non-zero
        # level, and a chain typically keeps multiplying by *fresh* level-0
        # operands. Aligning a fresh operand down to the chain's level is a
        # free modulus drop, not consumed budget: after the bootstrap the tail
        # below uses exactly two levels, so restored (12 - 8 = 4) > 2 fires.
        class RealisticBootstrapContext(FakeCryptoContext):
            def EvalBootstrap(self, ciphertext):
                self._called("EvalBootstrap")
                return self._fresh(ciphertext, level=8, noise=1)

        backend = RealisticBootstrapContext()
        with cipherscope.trace(backend) as session:
            cc = session.context
            acc = cc.Encrypt(object(), object())
            for _ in range(12):
                acc = cc.EvalMult(acc, cc.Encrypt(object(), object()))
            acc = cc.EvalBootstrap(acc)
            for _ in range(2):
                acc = cc.EvalMult(acc, cc.Encrypt(object(), object()))
        result = analyze_bootstrap(session.to_trace())

        self.assertEqual(result["analysis_status"], "positive")
        record = result["inventory"][0]
        self.assertEqual((record["level_before"], record["level_after"]), (12, 8))
        self.assertEqual(record["restored_levels"], 4)
        self.assertEqual(record["suffix_levels_consumed"], 2)

    def test_missing_bootstrap_is_not_applicable(self) -> None:
        result = analyze_bootstrap(_trace(2, 0, bootstrap=False))
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])
        self.assertIn(
            "No successful EvalBootstrap", result["not_applicable_reasons"][0]
        )


if __name__ == "__main__":
    unittest.main()
