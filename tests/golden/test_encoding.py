"""Golden tests for repeated public-constant encoding analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.encoding import analyze_encoding
from cipherscope.testing import FakeCryptoContext


def _trace(constant_ids: list[str | None]) -> dict:
    backend = FakeCryptoContext()
    with cipherscope.trace(backend) as session:
        for constant_id in constant_ids:
            session.annotate_plaintext(
                object(), provenance="public_constant", constant_id=constant_id
            )
    return session.to_trace()


class EncodingAnalyzerTests(unittest.TestCase):
    def test_repeated_constant_id_emits_finding(self) -> None:
        result = analyze_encoding(_trace(["w0", "w0", "b0"]))

        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "encoding.repeated_public_constant.v1")
        self.assertEqual(finding["evidence"]["constant_id"], "w0")
        self.assertEqual(finding["evidence"]["encoding_count"], 2)
        self.assertEqual(finding["estimated_impact"]["redundant_encodings"], 1.0)
        self.assertIn("not by comparing values", finding["limitations"][0])

    def test_distinct_constant_ids_are_clean(self) -> None:
        result = analyze_encoding(_trace(["w0", "b0", "w1"]))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])

    def test_no_constant_id_is_not_applicable(self) -> None:
        result = analyze_encoding(_trace([None, None]))
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn("explicit constant_id", result["not_applicable_reasons"][0])


if __name__ == "__main__":
    unittest.main()
