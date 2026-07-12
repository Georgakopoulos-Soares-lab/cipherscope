"""Golden tests for advisory public-value provenance analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.provenance import analyze_provenance
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


class PublicValueAnalyzerTests(unittest.TestCase):
    def test_public_operand_ct_ct_mult_is_flagged(self) -> None:
        backend = FakeCryptoContext()
        public = FakeCiphertext()
        encrypted = FakeCiphertext()
        with cipherscope.trace(backend) as session:
            session.annotate(public, provenance="public_constant")
            session.context.EvalMult(public, encrypted)
        result = analyze_provenance(session.to_trace())

        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(
            finding["rule_id"], "provenance.public_value_ciphertext_mult.v1"
        )
        self.assertEqual(len(finding["evidence"]["public_operands"]), 1)
        self.assertIn("advisory", finding["limitations"][0])

    def test_no_public_operand_is_clean(self) -> None:
        backend = FakeCryptoContext()
        public = FakeCiphertext()
        left = FakeCiphertext()
        right = FakeCiphertext()
        with cipherscope.trace(backend) as session:
            # A public annotation exists, but the product uses two other operands.
            session.annotate(public, provenance="public_constant")
            session.context.EvalMult(left, right)
        result = analyze_provenance(session.to_trace())
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])

    def test_no_public_annotation_is_not_applicable(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalMult(FakeCiphertext(), FakeCiphertext())
        result = analyze_provenance(session.to_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
