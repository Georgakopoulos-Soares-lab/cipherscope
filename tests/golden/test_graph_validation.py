"""Dependency-free golden tests for validation, graph, and first analyzers."""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cipherscope.analyzers.depth import analyze_depth  # noqa: E402
from cipherscope.analyzers.rotations import analyze_rotations  # noqa: E402
from cipherscope.graph import build_graph  # noqa: E402
from cipherscope.validation import (  # noqa: E402
    IssueCode,
    MAX_METADATA_STRING_LENGTH,
    StrictJSONError,
    load_json_strict,
    validate_graph,
    validate_manifest,
    validate_recommendations,
    validate_trace,
)


def _source(line: int, site: str) -> dict[str, object]:
    return {
        "file": "golden_workload.py",
        "line": line,
        "function": "workload",
        "qualified_function": "workload",
        "source_sha256": "a" * 64,
        "call_site_id": site,
    }


def _event(
    event_id: str,
    sequence: int,
    operation: str,
    inputs: list[str],
    outputs: list[str],
    input_levels: list[int],
    output_levels: list[int],
    *,
    overload: str = "ct_ct",
    rotation_index: int | None = None,
    status: str = "ok",
) -> dict[str, object]:
    arguments: dict[str, object] = {}
    if rotation_index is not None:
        arguments["rotation_index_requested"] = rotation_index
    event: dict[str, object] = {
        "event_id": event_id,
        "sequence": sequence,
        "kind": "crypto_operation",
        "operation": operation,
        "overload": overload,
        "granularity": "openfhe_api_inclusive",
        "status": status,
        "source": _source(100 + sequence, f"site_{sequence:04d}"),
        "input_ciphertexts": inputs,
        "output_ciphertexts": outputs,
        "operand_kinds": ["ciphertext" for _ in inputs],
        "timing": {
            "start_ns": sequence * 1000,
            "wall_duration_ns": sequence * 10,
            "process_cpu_duration_ns": sequence * 9,
            "thread_cpu_duration_ns": None,
        },
        "input_states": [
            {"id": ciphertext_id, "level": level, "noise_scale_degree": 1}
            for ciphertext_id, level in zip(inputs, input_levels)
        ],
        "output_states": [
            {"id": ciphertext_id, "level": level, "noise_scale_degree": 1}
            for ciphertext_id, level in zip(outputs, output_levels)
        ],
        "semantic_arguments": arguments,
        "thread_id": 1,
        "python_thread_id": 1,
        "missing": [],
    }
    if status == "error":
        event["error_class"] = "SyntheticError"
    return event


def _state(
    ciphertext_id: str,
    created_by: str | None,
    parents: list[str],
    level: int,
) -> dict[str, object]:
    return {
        "id": ciphertext_id,
        "created_by_event": created_by,
        "parent_ids": parents,
        "origin": "preexisting" if created_by is None else "derived",
        "level": level,
        "noise_scale_degree": 1,
        "context_id": "context_1",
        "key_tag": "key_1",
        "scaling_technique": "FLEXIBLEAUTO",
        "key_switch_technique": "HYBRID",
    }


def _depth_trace() -> dict[str, object]:
    states = [
        _state("ct_a:v0", None, [], 0),
        _state("ct_b:v0", None, [], 0),
        _state("ct_1:v0", "event_0001", ["ct_a:v0", "ct_b:v0"], 1),
        _state("ct_2:v0", "event_0002", ["ct_1:v0", "ct_b:v0"], 2),
        _state("ct_3:v0", "event_0003", ["ct_2:v0"], 0),
        _state("ct_4:v0", "event_0004", ["ct_3:v0", "ct_b:v0"], 1),
    ]
    events = [
        _event(
            "event_0001",
            1,
            "EvalMult",
            ["ct_a:v0", "ct_b:v0"],
            ["ct_1:v0"],
            [0, 0],
            [1],
        ),
        _event(
            "event_0002",
            2,
            "EvalMult",
            ["ct_1:v0", "ct_b:v0"],
            ["ct_2:v0"],
            [1, 0],
            [2],
        ),
        _event(
            "event_0003",
            3,
            "EvalBootstrap",
            ["ct_2:v0"],
            ["ct_3:v0"],
            [2],
            [0],
            overload="ct",
        ),
        _event(
            "event_0004",
            4,
            "EvalMult",
            ["ct_3:v0", "ct_b:v0"],
            ["ct_4:v0"],
            [0, 0],
            [1],
        ),
    ]
    return {
        "schema_version": "1.0.0",
        "run": {"run_id": "golden-run", "status": "completed"},
        "context": {
            "scheme": "CKKS",
            "ring_dimension": 8192,
            "available_slots": 4096,
            "configured_multiplicative_depth": 4,
        },
        "events": events,
        "ciphertexts": states,
    }


def _rotation_trace() -> dict[str, object]:
    events = [
        _event(
            "event_0001",
            1,
            "EvalRotate",
            ["ct_a:v0"],
            ["ct_r1:v0"],
            [0],
            [0],
            overload="ct_index",
            rotation_index=1,
        ),
        _event(
            "event_0002",
            2,
            "EvalRotate",
            ["ct_a:v0"],
            ["ct_r2:v0"],
            [0],
            [0],
            overload="ct_index",
            rotation_index=2,
        ),
    ]
    return {
        "schema_version": "1.0.0",
        "run": {"run_id": "rotation-run", "status": "completed"},
        "context": {"scheme": "CKKS"},
        "events": events,
        "ciphertexts": [
            _state("ct_a:v0", None, [], 0),
            _state("ct_r1:v0", "event_0001", ["ct_a:v0"], 0),
            _state("ct_r2:v0", "event_0002", ["ct_a:v0"], 0),
        ],
    }


def _codes(result: object) -> set[str]:
    return {issue.code for issue in result}  # type: ignore[attr-defined]


class StrictJSONTests(unittest.TestCase):
    def test_strict_loader_accepts_regular_json(self) -> None:
        self.assertEqual(
            load_json_strict('{"a": [1, 2.5, true]}'), {"a": [1, 2.5, True]}
        )

    def test_strict_loader_rejects_duplicate_keys_at_any_depth(self) -> None:
        with self.assertRaises(StrictJSONError) as raised:
            load_json_strict('{"outer": {"value": 1, "value": 2}}')
        self.assertEqual(raised.exception.code, "json.duplicate_key")

    def test_strict_loader_rejects_nonfinite_numbers(self) -> None:
        for token in ("NaN", "Infinity", "-Infinity", "1e999"):
            with (
                self.subTest(token=token),
                self.assertRaises(StrictJSONError) as raised,
            ):
                load_json_strict('{"value": ' + token + "}")
            self.assertEqual(raised.exception.code, "json.non_finite_number")


class TraceValidationTests(unittest.TestCase):
    def test_hand_authored_trace_is_valid(self) -> None:
        self.assertTrue(validate_trace(_depth_trace()).valid)

    def test_unknown_schema_major_is_rejected(self) -> None:
        trace = _depth_trace()
        trace["schema_version"] = "2.0.0"
        self.assertIn(IssueCode.SCHEMA_UNKNOWN_MAJOR, _codes(validate_trace(trace)))

    def test_duplicate_and_nonmonotonic_events_are_rejected(self) -> None:
        trace = _depth_trace()
        events = trace["events"]
        assert isinstance(events, list)
        events[1]["event_id"] = events[0]["event_id"]
        events[1]["sequence"] = events[0]["sequence"]
        result = validate_trace(trace)
        self.assertIn(IssueCode.EVENT_ID_DUPLICATE, _codes(result))
        self.assertIn(IssueCode.EVENT_SEQUENCE_DUPLICATE, _codes(result))
        self.assertIn(IssueCode.EVENT_SEQUENCE_NONMONOTONIC, _codes(result))

    def test_dangling_reference_and_negative_duration_are_rejected(self) -> None:
        trace = _depth_trace()
        events = trace["events"]
        assert isinstance(events, list)
        events[0]["input_ciphertexts"][0] = "ct_missing:v0"
        events[0]["timing"]["wall_duration_ns"] = -1
        result = validate_trace(trace)
        self.assertIn(IssueCode.REFERENCE_DANGLING_CIPHERTEXT, _codes(result))
        self.assertIn(IssueCode.TIMING_NEGATIVE_DURATION, _codes(result))

    def test_error_event_with_output_is_rejected(self) -> None:
        trace = _depth_trace()
        events = trace["events"]
        assert isinstance(events, list)
        events[0]["status"] = "error"
        events[0]["error_class"] = "SyntheticError"
        self.assertIn(IssueCode.EVENT_ERROR_HAS_OUTPUTS, _codes(validate_trace(trace)))

    def test_oversized_user_metadata_is_rejected(self) -> None:
        trace = _depth_trace()
        trace["metadata"] = {"annotation": "x" * (MAX_METADATA_STRING_LENGTH + 1)}
        self.assertIn(IssueCode.METADATA_LIMIT_EXCEEDED, _codes(validate_trace(trace)))


class GraphTests(unittest.TestCase):
    def test_graph_is_deterministic_and_preserves_prebootstrap_maximum(self) -> None:
        trace = _depth_trace()
        first = build_graph(trace)
        second = build_graph(copy.deepcopy(trace))
        self.assertEqual(first, second)
        nonlinear = first["critical_paths"]["nonlinear_ciphertext"]
        observed = first["critical_paths"]["observed_level_use"]
        self.assertEqual(nonlinear["max_depth"], 2)
        self.assertEqual([epoch["max_depth"] for epoch in nonlinear["epochs"]], [2, 1])
        self.assertEqual(observed["max_levels_consumed_in_epoch"], 2)
        self.assertEqual(
            [epoch["max_levels_consumed"] for epoch in observed["epochs"]], [2, 1]
        )
        nodes = {node["id"]: node for node in first["nodes"]}
        self.assertEqual(nodes["ct_3:v0"]["observed_nonlinear_depth"], 0)
        self.assertEqual(nodes["ct_4:v0"]["observed_nonlinear_depth"], 1)
        self.assertTrue(validate_graph(first, trace=trace).valid)

    def test_graph_dangling_edge_is_rejected(self) -> None:
        graph = build_graph(_depth_trace())
        graph["edges"].append(
            {"edge_type": "produces", "from": "event_missing", "to": "ct_4:v0"}
        )
        self.assertIn(IssueCode.GRAPH_DANGLING_EDGE, _codes(validate_graph(graph)))

    def test_ciphertext_lineage_cycle_is_rejected(self) -> None:
        graph = build_graph(_depth_trace())
        graph["edges"].append(
            {"edge_type": "derived_from", "from": "ct_a:v0", "to": "ct_1:v0"}
        )
        self.assertIn(IssueCode.GRAPH_CYCLE, _codes(validate_graph(graph)))

    def test_depth_analyzer_reports_both_metrics(self) -> None:
        result = analyze_depth(_depth_trace())
        self.assertEqual(result["analysis_status"], "positive")
        evidence = result["findings"][0]["evidence"]
        self.assertIn("nonlinear_ciphertext", evidence)
        self.assertIn("observed_level_use", evidence)


class RotationAnalyzerTests(unittest.TestCase):
    def test_positive_candidate_has_no_speedup_claim(self) -> None:
        trace = _rotation_trace()
        result = analyze_rotations(trace)
        self.assertEqual(result["analysis_status"], "positive")
        self.assertEqual(len(result["findings"]), 1)
        self.assertIsNone(result["findings"][0]["estimated_impact"]["speedup"])
        self.assertTrue(validate_recommendations(result, trace=trace).valid)

    def test_single_distinct_index_is_clean(self) -> None:
        trace = _rotation_trace()
        events = trace["events"]
        assert isinstance(events, list)
        events[1]["semantic_arguments"]["rotation_index_requested"] = 1
        result = analyze_rotations(trace)
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])

    def test_missing_compatibility_metadata_is_not_applicable(self) -> None:
        trace = _rotation_trace()
        states = trace["ciphertexts"]
        assert isinstance(states, list)
        states[0]["key_tag"] = None
        result = analyze_rotations(trace)
        self.assertEqual(result["analysis_status"], "not_applicable")

    def test_precompute_after_rotations_does_not_suppress(self) -> None:
        trace = _rotation_trace()
        events = trace["events"]
        assert isinstance(events, list)
        events.append(
            _event(
                "event_0003",
                3,
                "EvalFastRotationPrecompute",
                ["ct_a:v0"],
                [],
                [0],
                [],
                overload="ct",
            )
        )
        self.assertEqual(analyze_rotations(trace)["analysis_status"], "positive")

    def test_compatible_precompute_before_rotations_suppresses(self) -> None:
        trace = _rotation_trace()
        events = trace["events"]
        assert isinstance(events, list)
        for event in events:
            event["sequence"] += 1
            event["timing"]["start_ns"] += 1000
        events.insert(
            0,
            _event(
                "event_0000",
                1,
                "EvalFastRotationPrecompute",
                ["ct_a:v0"],
                [],
                [0],
                [],
                overload="ct",
            ),
        )
        self.assertEqual(analyze_rotations(trace)["analysis_status"], "clean")

    def test_incompatible_prior_precompute_does_not_suppress(self) -> None:
        trace = _rotation_trace()
        events = trace["events"]
        assert isinstance(events, list)
        for event in events:
            event["sequence"] += 1
            event["timing"]["start_ns"] += 1000
        precompute = _event(
            "event_0000",
            1,
            "EvalFastRotationPrecompute",
            ["ct_a:v0"],
            [],
            [0],
            [],
            overload="ct",
        )
        precompute["semantic_arguments"] = {"context_id": "other_context"}
        events.insert(0, precompute)
        self.assertEqual(analyze_rotations(trace)["analysis_status"], "positive")


class OtherArtifactValidationTests(unittest.TestCase):
    def test_recommendation_dangling_evidence_is_rejected(self) -> None:
        trace = _rotation_trace()
        recommendations = analyze_rotations(trace)
        recommendations["findings"][0]["evidence_event_ids"].append("event_missing")
        result = validate_recommendations(recommendations, trace=trace)
        self.assertIn(IssueCode.FINDING_DANGLING_EVIDENCE, _codes(result))

    def test_manifest_minimum_contract(self) -> None:
        trace = _depth_trace()
        manifest = {
            "schema_version": "1.0.0",
            "run_id": "golden-run",
            "status": "completed",
            "tool": {"name": "cipherscope", "version": "0.1.0"},
            "runtime": {"python": "3.11", "platform": "linux"},
            "coverage": {
                "strict": True,
                "traced_semantic_calls": 4,
                "allowed_passthrough_calls": 0,
                "unclassified_proxy_passthrough_calls": 0,
                "operator_overload_coverage": False,
                "original_reference_bypass_observable": False,
            },
            "privacy": {"shadow_mode": False, "plaintext_serialized": False},
            "clocks": {"wall": "time.perf_counter_ns", "cpu": "time.process_time_ns"},
            "parameter_set": {
                "scheme": "CKKS",
                "ring_dimension": 8192,
                "configured_multiplicative_depth": 4,
            },
        }
        self.assertTrue(validate_manifest(manifest, trace=trace).valid)

    def test_public_schema_files_are_draft_2020_12_json(self) -> None:
        schema_dir = PROJECT_ROOT / "schemas"
        names = {
            "manifest.schema.json",
            "trace.schema.json",
            "graph.schema.json",
            "recommendations.schema.json",
        }
        for name in names:
            with self.subTest(name=name):
                document = json.loads((schema_dir / name).read_text(encoding="utf-8"))
                self.assertEqual(
                    document["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                self.assertEqual(document["type"], "object")


if __name__ == "__main__":
    unittest.main()
