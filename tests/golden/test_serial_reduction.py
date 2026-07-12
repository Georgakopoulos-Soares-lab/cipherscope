"""Golden tests for the region-gated serial-reduction review."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.serial_reduction import analyze_serial_reductions
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


def _serial_product(term_count: int, *, region: bool, associative: bool = True) -> dict:
    backend = FakeCryptoContext()
    with cipherscope.trace(backend) as session:
        if region:
            scope = session.region(
                "product",
                operator="multiply",
                associative=associative,
                commutative=True,
            )
        else:
            import contextlib

            scope = contextlib.nullcontext()
        with scope:
            acc = session.context.EvalMult(FakeCiphertext(), FakeCiphertext())
            for _ in range(term_count - 2):
                acc = session.context.EvalMult(acc, FakeCiphertext())
    return session.to_trace()


class SerialReductionAnalyzerTests(unittest.TestCase):
    def test_long_serial_product_in_region_is_flagged(self) -> None:
        # Five terms reduce with four chained ciphertext-ciphertext products.
        result = analyze_serial_reductions(_serial_product(5, region=True))

        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(
            finding["rule_id"], "multiplication.serial_reduction_review.v1"
        )
        evidence = finding["evidence"]
        self.assertEqual(evidence["serial_multiplications"], 4)
        self.assertEqual(evidence["reduced_terms"], 5)
        self.assertEqual(evidence["serial_multiplicative_depth"], 4)
        self.assertEqual(evidence["balanced_multiplicative_depth"], 3)
        self.assertIn("user-asserted associative region", finding["limitations"][0])

    def test_short_product_in_region_is_clean(self) -> None:
        result = analyze_serial_reductions(_serial_product(3, region=True))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])

    def test_serial_product_without_region_is_not_applicable(self) -> None:
        result = analyze_serial_reductions(_serial_product(5, region=False))
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn(
            "associative multiply region", result["not_applicable_reasons"][0]
        )

    def test_non_associative_region_is_not_applicable(self) -> None:
        result = analyze_serial_reductions(
            _serial_product(5, region=True, associative=False)
        )
        self.assertEqual(result["analysis_status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
