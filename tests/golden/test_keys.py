"""Golden tests for observed-run rotation-key inventory."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.keys import analyze_keys
from cipherscope.graph import build_graph
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


def _trace(generated: list[int] | None, used: list[int]) -> dict:
    backend = FakeCryptoContext()
    source = FakeCiphertext()
    with cipherscope.trace(backend) as session:
        if generated is not None:
            session.context.EvalRotateKeyGen(object(), generated)
        for index in used:
            session.context.EvalRotate(source, index)
    return session.to_trace()


class KeyUsageAnalyzerTests(unittest.TestCase):
    def test_unused_generated_indices_emit_observed_run_finding(self) -> None:
        trace = _trace([1, 2, 4], [1, 4])
        result = analyze_keys(trace)

        self.assertEqual(result["analysis_status"], "positive")
        self.assertEqual(result["inventory"]["generated_indices"], [1, 2, 4])
        self.assertEqual(result["inventory"]["used_indices"], [1, 4])
        self.assertEqual(result["inventory"]["unused_generated_indices"], [2])
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "keys.unused_in_observed_run.v1")
        self.assertEqual(finding["confidence"], "measured")
        self.assertIn("not globally unnecessary", finding["limitations"][0])

        graph = build_graph(trace)
        key_nodes = [
            node for node in graph["nodes"] if node["node_type"] == "EvalKeyRequirement"
        ]
        self.assertEqual([node["rotation_index"] for node in key_nodes], [1, 2, 4])
        requires_edges = [
            edge for edge in graph["edges"] if edge["edge_type"] == "requires_key"
        ]
        self.assertEqual(len(requires_edges), 2)

    def test_all_generated_indices_used_is_clean(self) -> None:
        result = analyze_keys(_trace([-2, 1], [1, -2, 1]))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["inventory"]["unused_generated_indices"], [])

    def test_missing_generation_is_not_applicable(self) -> None:
        result = analyze_keys(_trace(None, [1]))
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])
        self.assertIn(
            "No successful EvalRotateKeyGen", result["not_applicable_reasons"][0]
        )

    def test_permissive_passthrough_disables_unused_claim(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, strict=False) as session:
            session.context.EvalRotateKeyGen(object(), [1, 2])
            session.context.EvalRotate(FakeCiphertext(), 1)
            session.context.Unclassified("unclassified argument")
        result = analyze_keys(session.to_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertEqual(result["findings"], [])

    def test_invalid_generation_indices_are_not_applicable(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalRotateKeyGen(object(), [1, "invalid"])
        result = analyze_keys(session.to_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")


if __name__ == "__main__":
    unittest.main()
