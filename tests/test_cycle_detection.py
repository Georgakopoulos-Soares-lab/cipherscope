"""Regression tests for cycle detection on long graphs."""

from __future__ import annotations

import unittest

from cipherscope.validation import _cycle


class CycleDetectionTests(unittest.TestCase):
    def test_long_chain_does_not_use_python_recursion(self) -> None:
        node_count = 5_000
        adjacency = {
            f"node_{index:04d}": {f"node_{index + 1:04d}"}
            for index in range(node_count - 1)
        }
        adjacency[f"node_{node_count - 1:04d}"] = set()

        self.assertIsNone(_cycle(adjacency))

    def test_cycle_near_end_of_long_chain_is_reported(self) -> None:
        node_count = 2_000
        adjacency = {
            f"node_{index:04d}": {f"node_{index + 1:04d}"}
            for index in range(node_count - 1)
        }
        adjacency[f"node_{node_count - 1:04d}"] = {"node_1900"}

        cycle = _cycle(adjacency)

        self.assertIsNotNone(cycle)
        assert cycle is not None
        self.assertEqual(cycle[0], "node_1900")
        self.assertEqual(cycle[-1], "node_1900")


if __name__ == "__main__":
    unittest.main()
