"""evaluation/parity/compare_lanes.py must flag every real disagreement and only those."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("compare_lanes", ROOT / "evaluation" / "parity" / "compare_lanes.py")
compare_lanes = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = compare_lanes  # dataclasses resolve annotations through sys.modules
SPEC.loader.exec_module(compare_lanes)

GOLDEN = json.loads((ROOT / "tests" / "integration_openfhe" / "golden_core.json").read_text(encoding="utf-8"))


def _feasibility(platform: str, res02: str) -> dict:
    return {
        "status": "pass",
        "summary": {"pass": 2, "skip": 0, "total": 2},
        "environment": {"platform": platform, "machine": "x86_64", "python": "3.11.15", "os_release": {}, "native_module_hashes": {"m.so": "ab" * 32}},
        "pins": {"wrapper_commit": "w", "native_commit": "n"},
        "checks": [
            {"id": "NUM-01", "status": "pass", "observed": {"max_direct_vs_traced_error": 1e-13, "max_expected_error": 1e-13, "tolerance": 0.001}},
            {"id": "RES-02", "status": res02},
        ],
    }


def _seeded(observed: str = "positive") -> dict:
    return {
        "all_matched": True,
        "cases": [
            {"case_id": "c1", "coverage_class": "COMPLETE", "exit_code": 0, "unexpected_positives": [],
             "rules": [{"rule_id": "r", "expected": "positive", "observed": observed, "outcome": "hit" if observed == "positive" else "miss"}]},
        ],
    }


def _lane(name: str, platform: str = "Linux", res02: str = "pass", **extra) -> compare_lanes.Lane:
    lane = compare_lanes.Lane(name=name, feasibility=_feasibility(platform, res02))
    for key, value in extra.items():
        setattr(lane, key, value)
    return lane


class CompareLanesTests(unittest.TestCase):
    def test_identical_lanes_have_no_disagreement(self) -> None:
        lanes = [_lane("a", seeded=_seeded()), _lane("b", seeded=_seeded())]
        report = compare_lanes.build_report(lanes, GOLDEN, None)
        self.assertEqual(report.disagreements, [])

    def test_res02_skip_on_darwin_is_allowed_but_not_on_linux(self) -> None:
        report = compare_lanes.build_report([_lane("mac", "Darwin", "skip"), _lane("linux")], GOLDEN, None)
        self.assertEqual(report.disagreements, [])
        self.assertEqual(len(report.allowed), 1)
        report = compare_lanes.build_report([_lane("a", "Linux", "skip"), _lane("b")], GOLDEN, None)
        self.assertTrue(any("RES-02" in d for d in report.disagreements))

    def test_pin_and_seeded_and_numeric_disagreements_are_reported(self) -> None:
        other = _lane("b", seeded=_seeded(observed="clean"))
        other.feasibility["pins"]["native_commit"] = "different"
        other.feasibility["checks"][0]["observed"]["max_expected_error"] = 0.5
        report = compare_lanes.build_report([_lane("a", seeded=_seeded()), other], GOLDEN, None)
        joined = "\n".join(report.disagreements)
        self.assertIn("pins.native_commit", joined)
        self.assertIn("seeded c1 / r", joined)
        self.assertIn("exceeds tolerance", joined)

    def test_examples_must_match_each_other_and_the_readme(self) -> None:
        recommendations = {
            "analysis_status": "positive",
            "analyzer_status": {"rotation.hoist_same_input.v1": "positive", "keys.unused_in_observed_run.v1": "positive"},
            "findings": [{"rule_id": "rotation.hoist_same_input.v1", "severity": "opportunity"}],
        }
        a = _lane("a", examples={"repeated_rotations": recommendations})
        b = _lane("b", examples={"repeated_rotations": copy.deepcopy(recommendations)})
        self.assertEqual(compare_lanes.build_report([a, b], GOLDEN, None).disagreements, [])
        b.examples["repeated_rotations"]["analyzer_status"]["keys.unused_in_observed_run.v1"] = "clean"
        report = compare_lanes.build_report([a, b], GOLDEN, None)
        self.assertTrue(any("diagnoses differ" in d for d in report.disagreements))
        self.assertTrue(any("README expects" in d for d in report.disagreements))

    def test_report_renders_and_names_every_lane(self) -> None:
        lanes = [_lane("a"), _lane("b")]
        text = compare_lanes.render(compare_lanes.build_report(lanes, GOLDEN, None), lanes)
        self.assertIn("No disagreement outside the allowed list", text)
        self.assertIn("| a |", text)
        self.assertIn("| b |", text)


if __name__ == "__main__":
    unittest.main()
