"""Fixed-seed generative coverage for trace and graph invariants."""

from __future__ import annotations

import random
import unittest

import cipherscope
from cipherscope.graph import build_graph
from cipherscope.testing import FakeCiphertext, FakeCryptoContext
from cipherscope.validation import validate_graph, validate_trace


def generated_trace(seed: int, event_count: int) -> dict:
    randomizer = random.Random(seed)
    backend = FakeCryptoContext()
    pool = [FakeCiphertext(), FakeCiphertext(), FakeCiphertext()]
    with cipherscope.trace(backend, name=f"fixed-seed-{seed}") as session:
        for _ in range(event_count):
            operation = randomizer.choice(("add", "mult", "rotate", "bootstrap"))
            left = randomizer.choice(pool)
            if operation == "add":
                output = session.context.EvalAdd(left, randomizer.choice(pool))
            elif operation == "mult":
                output = session.context.EvalMult(left, randomizer.choice(pool))
            elif operation == "rotate":
                output = session.context.EvalRotate(
                    left,
                    randomizer.choice((-8, -4, -1, 1, 2, 4, 8)),
                )
            else:
                output = session.context.EvalBootstrap(left)
            pool.append(output)
            if len(pool) > 40:
                pool.pop(randomizer.randrange(0, 10))
    return session.to_trace()


class FixedSeedGenerativeTests(unittest.TestCase):
    def test_many_bounded_operation_sequences_are_valid_and_deterministic(self) -> None:
        for seed in range(12):
            with self.subTest(seed=seed):
                trace = generated_trace(seed, 36)
                self.assertTrue(validate_trace(trace).valid)
                first = build_graph(trace)
                second = build_graph(trace)
                self.assertEqual(first, second)
                self.assertTrue(validate_graph(first, trace=trace).valid)

    def test_large_seeded_trace_has_no_dangling_references(self) -> None:
        trace = generated_trace(8675309, 500)
        graph = build_graph(trace)
        self.assertEqual(len(trace["events"]), 500)
        self.assertGreater(len(trace["ciphertexts"]), 500)
        identifiers = {node["id"] for node in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertIn(edge["from"], identifiers)
            self.assertIn(edge["to"], identifiers)


if __name__ == "__main__":
    unittest.main()
