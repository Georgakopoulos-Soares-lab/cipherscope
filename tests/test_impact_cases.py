"""The RQ4 impact suite must cover every prescriptive rule with a real case module."""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "evaluation" / "impact" / "cases"

sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(CASES))

from cipherscope.pipeline import analyze_trace  # noqa: E402

# Rules whose findings recommend a change to the program; each needs a
# before/after pair. The two diagnostic rules (depth.critical_path.v1,
# precision.checkpoint_drop.v1) are exercised by depth_headroom and
# precision_tolerance respectively rather than owning a pair.
PRESCRIPTIVE_RULES = {
    "keys.unused_in_observed_run.v1",
    "rotation.hoist_same_input.v1",
    "encoding.repeated_public_constant.v1",
    "packing.low_utilization_annotated.v1",
    "provenance.public_value_ciphertext_mult.v1",
    "multiplication.serial_reduction_review.v1",
    "parameters.depth_headroom_observed.v1",
    "bootstrap.restored_levels_underused.v1",
    "precision.tolerance_violated.v1",
    "configuration.testing_only_security.v1",
}


def _case_modules() -> list[str]:
    return sorted(p.stem for p in CASES.glob("*.py") if not p.name.startswith("_"))


class ImpactCaseTests(unittest.TestCase):
    def test_every_prescriptive_rule_has_a_case_and_every_case_names_a_real_rule(self) -> None:
        from cipherscope.testing import FakeCryptoContext
        import cipherscope

        with cipherscope.trace(FakeCryptoContext()) as session:
            session.context.Encrypt(object(), object())
        known_rules = set(analyze_trace(session.to_trace())["analyzer_status"])

        covered: dict[str, str] = {}
        for name in _case_modules():
            module = importlib.import_module(name)
            for variant in ("before", "after"):
                case = module.build(variant)
                self.assertIn(case.rule, known_rules, f"{name}: unknown rule {case.rule}")
                self.assertEqual(case.variant, variant)
                self.assertEqual(case.name, name)
            covered[module.build("before").rule] = name
        self.assertEqual(set(covered) & PRESCRIPTIVE_RULES, PRESCRIPTIVE_RULES,
                         f"rules without an impact case: {PRESCRIPTIVE_RULES - set(covered)}")

    def test_run_impact_lists_every_case_module(self) -> None:
        sys.path.insert(0, str(ROOT / "evaluation" / "impact"))
        run_impact = importlib.import_module("run_impact")
        self.assertEqual(sorted(run_impact.CASES), _case_modules())


if __name__ == "__main__":
    unittest.main()
