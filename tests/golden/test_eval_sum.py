"""Golden test that EvalSum is a covered, depth-neutral traced operation."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.graph import build_graph
from cipherscope.testing import FakeCryptoContext


class EvalSumCoverageTests(unittest.TestCase):
    def test_eval_sum_is_traced_and_zero_depth(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            ciph = session.context.Encrypt(object(), object())
            session.context.EvalSum(ciph, 8)
        trace = session.to_trace()

        operations = [event["operation"] for event in trace["events"]]
        self.assertIn("EvalSum", operations)
        # No strict-mode rejection or unclassified passthrough occurred.
        self.assertEqual(
            trace["run"]["coverage"]["unclassified_proxy_passthrough_calls"], 0
        )
        self.assertEqual(trace["run"]["coverage"]["rejected_unclassified_calls"], 0)

        sum_event = next(e for e in trace["events"] if e["operation"] == "EvalSum")
        self.assertEqual(sum_event["semantic_arguments"], {"batch_size": 8})

        # EvalSum performs rotations and additions but consumes no multiplicative
        # depth, so the observed nonlinear path stays at zero.
        graph = build_graph(trace)
        self.assertEqual(
            graph["critical_paths"]["nonlinear_ciphertext"]["max_depth"], 0
        )


if __name__ == "__main__":
    unittest.main()
