"""Golden tests for annotated packing-utilization analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.packing import analyze_packing
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


def _trace(**annotation: object) -> dict:
    backend = FakeCryptoContext()
    ct = FakeCiphertext()
    with cipherscope.trace(backend) as session:
        if annotation:
            session.annotate(ct, **annotation)  # type: ignore[arg-type]
        else:
            session.context.EvalBootstrap(ct)
    return session.to_trace()


class PackingAnalyzerTests(unittest.TestCase):
    def test_low_utilization_annotation_emits_finding(self) -> None:
        result = analyze_packing(
            _trace(shape=[8], packing="row_major", meaningful_slots=8)
        )
        self.assertEqual(result["analysis_status"], "positive")
        record = result["inventory"][0]
        self.assertEqual(record["meaningful_slots"], 8)
        self.assertEqual(record["available_slots"], 16384)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "packing.low_utilization_annotated.v1")
        self.assertIn("not inferred from contents", finding["limitations"][0])

    def test_full_utilization_is_clean(self) -> None:
        result = analyze_packing(_trace(packing="row_major", meaningful_slots=16384))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["inventory"][0]["utilization"], 1.0)

    def test_unknown_packing_is_not_validated(self) -> None:
        result = analyze_packing(_trace(packing="mystery_layout", meaningful_slots=8))
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])

    def test_missing_annotation_is_not_applicable(self) -> None:
        result = analyze_packing(_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn("validated meaningful-slot", result["not_applicable_reasons"][0])


if __name__ == "__main__":
    unittest.main()
