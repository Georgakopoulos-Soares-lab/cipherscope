"""The trace is the only interface between acquisition and analysis.

A trace hand-built the way the C++ frontend emits it -- no Python object
representations, a `producer` block naming another frontend, compiler
instrumentation coverage counters -- must pass validation and flow through the
existing graph, analyzers, and exporters without any code path knowing where
it came from.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cipherscope.coverage import COMPLETE, PARTIAL_PERMISSIVE, UNSUPPORTED, classify_run, scannable_entrypoint
from cipherscope.exporters import write_bundle
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.cli import validate_bundle
from cipherscope.validation import validate_trace


def _state(ct: str, level: int, noise: int = 1) -> dict:
    return {
        "id": ct, "level": level, "noise_scale_degree": noise, "scale": None, "slots": 8,
        "context_id": "context_0001", "key_tag": "k1", "scaling_technique": "FLEXIBLEAUTO",
        "key_switch_technique": "HYBRID",
    }


def _event(seq: int, op: str, kind: str, inputs: list[str], outputs: list[str], *, in_states=(), out_states=(),
           semantic=None, overload="ct_ct", operand_kinds=None, line=10) -> dict:
    return {
        "event_id": f"event_{seq:04d}", "sequence": seq, "kind": kind, "operation": op, "overload": overload,
        "granularity": "openfhe_api_inclusive", "status": "ok",
        "argument_representations": [], "keyword_argument_representations": {},
        "source": {"file": "src/model.cpp", "line": line, "function": "run_layer",
                   "qualified_function": "model::run_layer", "call_site_id": f"site_{seq:016x}"},
        "input_ciphertexts": inputs, "output_ciphertexts": outputs,
        "operand_kinds": operand_kinds if operand_kinds is not None else ["ciphertext"] * len(inputs),
        "timing": {"start_ns": 1000 * seq, "wall_duration_ns": 500, "process_cpu_duration_ns": 400,
                   "thread_cpu_duration_ns": 400},
        "input_states": list(in_states), "output_states": list(out_states),
        "semantic_arguments": semantic or {}, "thread_id": 4242, "missing": [],
    }


def cpp_trace() -> dict:
    """Encrypt, rotate the same version by 1 and 2, add, multiply, decrypt -- as the GCC frontend would emit it."""

    events = [
        _event(1, "KeyGen", "key_generation", [], [], overload="none", operand_kinds=[]),
        _event(2, "EvalRotateKeyGen", "key_generation", [], [], overload="key_indices",
               operand_kinds=["key", "rotation_indices"], semantic={"rotation_indices_requested": [1, 2, 5]}),
        _event(3, "Encrypt", "crypto_operation", [], ["ct_0001:v0"], overload="key_plaintext",
               operand_kinds=["key", "plaintext"], out_states=[_state("ct_0001:v0", 0)]),
        _event(4, "EvalRotate", "crypto_operation", ["ct_0001:v0"], ["ct_0002:v0"], overload="ct_index",
               operand_kinds=["ciphertext", "integer"], semantic={"rotation_index_requested": 1},
               in_states=[_state("ct_0001:v0", 0)], out_states=[_state("ct_0002:v0", 0)]),
        _event(5, "EvalRotate", "crypto_operation", ["ct_0001:v0"], ["ct_0003:v0"], overload="ct_index",
               operand_kinds=["ciphertext", "integer"], semantic={"rotation_index_requested": 2},
               in_states=[_state("ct_0001:v0", 0)], out_states=[_state("ct_0003:v0", 0)]),
        _event(6, "EvalAdd", "crypto_operation", ["ct_0002:v0", "ct_0003:v0"], ["ct_0004:v0"],
               in_states=[_state("ct_0002:v0", 0), _state("ct_0003:v0", 0)], out_states=[_state("ct_0004:v0", 0)]),
        _event(7, "EvalMult", "crypto_operation", ["ct_0004:v0", "ct_0001:v0"], ["ct_0005:v0"],
               in_states=[_state("ct_0004:v0", 0), _state("ct_0001:v0", 0)], out_states=[_state("ct_0005:v0", 1, 2)]),
        _event(8, "Decrypt", "crypto_operation", ["ct_0005:v0"], [], overload="ct_key",
               operand_kinds=["ciphertext", "key"], in_states=[_state("ct_0005:v0", 1, 2)]),
    ]
    ciphertexts = []
    for event in events:
        for state in event["output_states"]:
            ciphertexts.append({**state, "created_by_event": event["event_id"], "origin": "derived",
                                "parent_ids": list(event["input_ciphertexts"])})
    return {
        "schema_version": "1.0.0",
        "run": {
            "run_id": "run_cpp_fixture", "status": "completed", "truncated": False,
            "tool": {"name": "cipherscope", "version": "0.1.0"},
            "producer": {"frontend": "gcc-openfhe", "frontend_version": "0.1.0",
                         "instrumentation_manifest": "openfhe-1.5-v1"},
            "runtime": {"language": "c++", "compiler": "gcc", "compiler_version": "15.2.0", "framework": "openfhe",
                        "framework_version": "1.5.1", "platform": "linux", "architecture": "x86_64",
                        "backend": "CryptoContext"},
            "clocks": {"wall": "CLOCK_MONOTONIC", "cpu": "CLOCK_PROCESS_CPUTIME_ID", "thread_cpu": "CLOCK_THREAD_CPUTIME_ID"},
            "coverage": {"strict": True, "traced_semantic_calls": 6, "allowed_passthrough_calls": 0,
                         "unclassified_proxy_passthrough_calls": 0, "rejected_unclassified_calls": 0,
                         "unsupported_operations": [], "potentially_incomplete": False, "truncated": False,
                         "failed_state_reads": 0, "operator_overload_coverage": True,
                         "original_reference_bypass_observable": False,
                         "instrumentation_manifest": "openfhe-1.5-v1", "unmatched_openfhe_candidates": 0,
                         "instrumented_translation_units": 1, "expected_translation_units": 1,
                         "instrumented_binary_verified": True},
        },
        "context": {"context_id": "context_0001", "scheme": "CKKS", "ring_dimension": 16384, "available_slots": 8192,
                    "batch_size": 8, "configured_multiplicative_depth": 3, "scaling_technique": "FLEXIBLEAUTO",
                    "key_switch_technique": "HYBRID", "missing": []},
        "events": events,
        "ciphertexts": ciphertexts,
    }


class FrontendNeutralTraceTests(unittest.TestCase):
    def test_cpp_producer_trace_validates_without_python_fields(self) -> None:
        trace = cpp_trace()
        text = json.dumps(trace)
        self.assertNotIn("python", text.lower().replace("python-openfhe", ""))
        result = validate_trace(trace)
        self.assertTrue(result.valid, result.errors)

    def test_pipeline_and_exporters_do_not_care_who_produced_the_trace(self) -> None:
        trace = cpp_trace()
        artifacts = build_analysis_bundle(trace)
        statuses = artifacts["recommendations"]["analyzer_status"]
        # Same-version rotations by 1 and 2 -> hoisting; key 5 generated but unused; a depth-1 path.
        self.assertEqual(statuses["rotation.hoist_same_input.v1"], "positive")
        self.assertEqual(statuses["keys.unused_in_observed_run.v1"], "positive")
        self.assertEqual(statuses["depth.critical_path.v1"], "positive")
        # Evidence the C++ frontend cannot supply stays not_applicable, never fabricated.
        self.assertEqual(statuses["precision.checkpoint_drop.v1"], "not_applicable")
        self.assertEqual(artifacts["manifest"]["producer"]["frontend"], "gcc-openfhe")
        self.assertEqual(artifacts["manifest"]["clocks"]["wall"], "CLOCK_MONOTONIC")
        self.assertEqual(artifacts["manifest"]["runtime"]["language"], "c++")
        with tempfile.TemporaryDirectory() as temporary:
            bundle = write_bundle(Path(temporary) / "bundle", trace=artifacts["trace"], graph=artifacts["graph"],
                                  recommendations=artifacts["recommendations"], manifest=artifacts["manifest"])
            self.assertEqual(validate_bundle(bundle), [])
            html = (bundle / "summary.html").read_text(encoding="utf-8")
            self.assertIn("src/model.cpp", html)

    def test_python_recorder_declares_itself_as_a_producer(self) -> None:
        from cipherscope.demo import build_demo_trace  # fake backend, no OpenFHE

        trace = build_demo_trace()
        self.assertEqual(trace["run"]["producer"]["frontend"], "python-openfhe")
        self.assertEqual(trace["run"]["runtime"]["language"], "python")
        self.assertTrue(validate_trace(trace).valid)

    def test_native_coverage_evidence_drives_the_class(self) -> None:
        trace = cpp_trace()
        self.assertEqual(classify_run(trace).coverage_class, COMPLETE)
        unmatched = cpp_trace()
        unmatched["run"]["coverage"].update({"unmatched_openfhe_candidates": 2, "unmatched_candidate_names": ["EvalSumRows"]})
        assessment = classify_run(unmatched)
        self.assertEqual(assessment.coverage_class, PARTIAL_PERMISSIVE)
        self.assertTrue(any("EvalSumRows" in reason for reason in assessment.reasons))
        partial_units = cpp_trace()
        partial_units["run"]["coverage"].update({"instrumented_translation_units": 3, "expected_translation_units": 4})
        self.assertEqual(classify_run(partial_units).coverage_class, PARTIAL_PERMISSIVE)
        unverified = cpp_trace()
        unverified["run"]["coverage"]["instrumented_binary_verified"] = False
        self.assertEqual(classify_run(unverified).coverage_class, UNSUPPORTED)

    def test_only_python_entrypoints_are_scanned(self) -> None:
        self.assertTrue(scannable_entrypoint(Path("a/b.py")))
        self.assertFalse(scannable_entrypoint(Path("src/model.cpp")))
        self.assertFalse(scannable_entrypoint(Path("build/app")))
        self.assertFalse(scannable_entrypoint(None))


if __name__ == "__main__":
    unittest.main()
