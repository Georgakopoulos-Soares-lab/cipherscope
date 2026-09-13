"""Semantic ablation: projections stay valid and each rule's minimum mode is measured."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import cipherscope
from cipherscope.ablation import (
    FULL,
    MODES,
    STATE,
    TIMING_ONLY,
    ablate,
    minimum_modes,
    project,
)
from cipherscope.cli import main
from cipherscope.exporters import write_bundle
from cipherscope.pipeline import analyze_trace, build_analysis_bundle
from cipherscope.testing import FakeCiphertext, FakeCryptoContext, FakeParameters
from cipherscope.validation import validate_trace

ROTATION = "rotation.hoist_same_input.v1"
KEYS = "keys.unused_in_observed_run.v1"
CONFIGURATION = "configuration.testing_only_security.v1"
DEPTH = "depth.critical_path.v1"
PARAMETERS = "parameters.depth_headroom_observed.v1"


def _rotation_trace() -> dict:
    backend = FakeCryptoContext()
    source = FakeCiphertext()
    with cipherscope.trace(backend, parameters=FakeParameters(security_level="HEStd_NotSet")) as session:
        session.context.EvalRotateKeyGen(object(), [1, 2, 5])
        session.context.EvalRotate(source, 1)
        session.context.EvalRotate(source, 2)
        chained = session.context.EvalMult(source, source)
        session.context.EvalMult(chained, source)
    return session.to_trace()


class ProjectionTests(unittest.TestCase):
    def test_every_mode_yields_a_valid_trace(self) -> None:
        trace = _rotation_trace()
        for mode in MODES:
            with self.subTest(mode=mode):
                projected = project(trace, mode)
                self.assertTrue(validate_trace(projected).valid, validate_trace(projected).errors[:2])

    def test_timing_only_has_no_identity_state_or_arguments(self) -> None:
        projected = project(_rotation_trace(), TIMING_ONLY)
        self.assertEqual(projected["ciphertexts"], [])
        for event in projected["events"]:
            self.assertEqual(event["input_ciphertexts"], [])
            self.assertEqual(event["input_states"], [])
            self.assertEqual(event["semantic_arguments"], {})
            self.assertNotIn("argument_representations", event)
        self.assertTrue(all(event["kind"] != "annotation" for event in projected["events"]))

    def test_state_mode_keeps_state_but_shares_no_identity_across_events(self) -> None:
        projected = project(_rotation_trace(), STATE)
        seen: set[str] = set()
        for event in projected["events"]:
            for identifier in [*event["input_ciphertexts"], *event["output_ciphertexts"]]:
                self.assertNotIn(identifier, seen, "a ciphertext ID appeared in two events")
                seen.add(identifier)
            for state in event["input_states"]:
                self.assertIn("level", state)
        self.assertEqual(len(projected["ciphertexts"]), len(seen))
        self.assertTrue(any(event["semantic_arguments"] for event in projected["events"]))

    def test_full_is_a_copy(self) -> None:
        trace = _rotation_trace()
        projected = project(trace, FULL)
        self.assertEqual(projected, trace)
        self.assertIsNot(projected, trace)

    def test_unknown_mode_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            project(_rotation_trace(), "PARTIAL")


class MinimumModeTests(unittest.TestCase):
    def test_rules_land_on_their_expected_minimum_modes(self) -> None:
        rows = ablate(_rotation_trace(), bundle="b", name="rotation")
        table = {row["rule_id"]: row for row in minimum_modes(rows)}
        self.assertEqual(table[ROTATION]["minimum_mode"], FULL)
        self.assertEqual(table[KEYS]["minimum_mode"], STATE)
        self.assertEqual(table[CONFIGURATION]["minimum_mode"], TIMING_ONLY)
        self.assertTrue(table[CONFIGURATION]["generic_profiler_can_diagnose"])
        self.assertFalse(table[ROTATION]["generic_profiler_can_diagnose"])
        # Depth fires under STATE too, but the chained depth of 2 needs lineage.
        self.assertEqual(table[DEPTH]["minimum_mode"], FULL)
        self.assertEqual(table[DEPTH]["detected_state"], 0)

    def test_state_less_trace_does_not_fabricate_headroom(self) -> None:
        projected = project(_rotation_trace(), TIMING_ONLY)
        status = analyze_trace(projected)["analyzer_status"]
        self.assertEqual(status[PARAMETERS], "not_applicable")
        self.assertEqual(status[ROTATION], "not_applicable")


class AblateCLITests(unittest.TestCase):
    def test_ablate_writes_raw_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trace = _rotation_trace()
            trace["run"]["runtime"]["backend"] = "CryptoContext"
            artifacts = build_analysis_bundle(trace)
            bundle = write_bundle(
                Path(temporary) / "b",
                manifest=artifacts["manifest"],
                trace=artifacts["trace"],
                graph=artifacts["graph"],
                recommendations=artifacts["recommendations"],
            )
            output = Path(temporary) / "semantic_ablation.csv"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["ablate", str(bundle), "--output", str(output)]), 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["rows"], 3 * 12)
            with output.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 36)
            self.assertEqual({row["mode"] for row in rows}, set(MODES))


if __name__ == "__main__":
    unittest.main()
