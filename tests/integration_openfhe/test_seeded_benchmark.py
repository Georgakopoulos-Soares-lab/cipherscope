"""Freeze the seeded benchmark: every case must match ground_truth.json on the real binding."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from cipherscope.seeded import (
    all_matched,
    evaluate_case,
    load_ground_truth,
    recall_table,
    run_case,
)

from . import support

GROUND_TRUTH = Path(__file__).resolve().parents[2] / "evaluation" / "seeded" / "ground_truth.json"


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class SeededBenchmarkTests(unittest.TestCase):
    def test_every_case_matches_ground_truth(self) -> None:
        """SEED-01: seeded positives are detected and hard negatives stay silent."""

        cases = load_ground_truth(GROUND_TRUTH)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            results = []
            for case in cases:
                bundle, code = run_case(case, output=output, python=sys.executable)
                results.append(evaluate_case(case, bundle, exit_code=code))
        mismatches = {
            result.case_id: result.invalid_reason
            or [f"{rule.rule_id}: {rule.outcome} {rule.detail}".strip() for rule in result.rules]
            for result in results
            if not result.matched
        }
        self.assertEqual(mismatches, {})
        self.assertTrue(all_matched(results))

        table = {row["rule_id"]: row for row in recall_table(results)}
        covered = [rule for rule in table if rule != "ALL"]
        self.assertEqual(len(covered), 12)
        # Depth always fires; its hard negative is a value check (max_depth 0) and
        # therefore counts as a seeded positive in the table.
        value_checked = {"depth.critical_path.v1"}
        for rule_id in covered:
            row = table[rule_id]
            with self.subTest(rule_id=rule_id):
                self.assertEqual(row["invalid_runs"], 0)
                self.assertEqual(row["false_positives"], 0)
                self.assertEqual(row["mismatches"], 0)
                if row["seeded_positives"]:
                    self.assertEqual(row["recall"], 1.0)
                if rule_id in value_checked:
                    self.assertGreaterEqual(row["seeded_positives"], 2)
                else:
                    self.assertGreaterEqual(row["seeded_negatives"], 1)
        support.record(
            "SEED-01",
            cases=len(results),
            seeded_positives=table["ALL"]["seeded_positives"],
            seeded_negatives=table["ALL"]["seeded_negatives"],
            rules_without_real_positive=[
                rule_id for rule_id in covered if table[rule_id]["seeded_positives"] == 0
            ],
        )


if __name__ == "__main__":
    unittest.main()
