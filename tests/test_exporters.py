"""Tests for deterministic bundle projections."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cipherscope.exporters import (
    build_manifest,
    operations_csv,
    perfetto_document,
    render_summary_html,
    write_bundle,
)
from cipherscope.graph import build_graph
from cipherscope.pipeline import analyze_trace


def sample_artifacts() -> tuple[dict, dict, dict]:
    trace = {
        "schema_version": "1.0.0",
        "run": {
            "run_id": "run-test-0001",
            "status": "completed",
            "tool": {"name": "cipherscope", "version": "0.1.0"},
            "runtime": {"backend": "synthetic"},
            "coverage": {
                "strict": True,
                "traced_semantic_calls": 1,
                "allowed_passthrough_calls": 0,
                "unclassified_proxy_passthrough_calls": 0,
                "operator_overload_coverage": False,
                "original_reference_bypass_observable": False,
            },
        },
        "context": {
            "scheme": "CKKS",
            "ring_dimension": 16,
            "available_slots": 8,
            "configured_multiplicative_depth": 2,
        },
        "events": [
            {
                "event_id": "event_0001",
                "sequence": 1,
                "kind": "crypto_operation",
                "operation": "EvalRotate",
                "overload": "ct_index",
                "granularity": "openfhe_api_inclusive",
                "status": "ok",
                "source": {
                    "file": "<script>alert(1)</script>.py",
                    "line": 7,
                    "function": "workload",
                    "qualified_function": "workload",
                    "call_site_id": "site_test",
                },
                "input_ciphertexts": ["ct_0001:v0"],
                "output_ciphertexts": ["ct_0002:v0"],
                "operand_kinds": ["ciphertext", "integer"],
                "timing": {
                    "start_ns": 1_000,
                    "wall_duration_ns": 250,
                    "process_cpu_duration_ns": 200,
                    "thread_cpu_duration_ns": None,
                },
                "input_states": [],
                "output_states": [],
                "semantic_arguments": {"rotation_index_requested": 1},
                "thread_id": 1,
                "python_thread_id": 1,
                "missing": [],
            }
        ],
        "ciphertexts": [
            {
                "id": "ct_0001:v0",
                "created_by_event": None,
                "parent_ids": [],
                "origin": "preexisting",
                "level": 0,
                "noise_scale_degree": 1,
                "context_id": "ctx",
                "key_tag": "key",
                "scaling_technique": "FLEXIBLEAUTO",
                "key_switch_technique": "HYBRID",
            },
            {
                "id": "ct_0002:v0",
                "created_by_event": "event_0001",
                "parent_ids": ["ct_0001:v0"],
                "origin": "derived",
                "level": 0,
                "noise_scale_degree": 1,
                "context_id": "ctx",
                "key_tag": "key",
                "scaling_technique": "FLEXIBLEAUTO",
                "key_switch_technique": "HYBRID",
            },
        ],
    }
    graph = build_graph(trace)
    recommendations = analyze_trace(trace, graph)
    recommendations["findings"][0]["recommendation"] = "Review <script>bad()</script>"
    return trace, graph, recommendations


class ExporterTests(unittest.TestCase):
    def test_csv_and_perfetto_are_deterministic_semantic_projections(self) -> None:
        trace, _, _ = sample_artifacts()
        csv_text = operations_csv(trace)
        perfetto = perfetto_document(trace)

        self.assertIn("event_0001", csv_text)
        self.assertEqual(perfetto["traceEvents"][0]["dur"], 0.25)
        self.assertEqual(perfetto["metadata"]["projection"], "visualization_only")

    def test_csv_neutralizes_spreadsheet_formula_prefixes(self) -> None:
        trace, _, _ = sample_artifacts()
        trace["events"][0]["source"]["file"] = "=HYPERLINK(unsafe)"
        csv_text = operations_csv(trace)
        self.assertIn("'=HYPERLINK(unsafe)", csv_text)
        self.assertNotIn(",=HYPERLINK(unsafe)", csv_text)

    def test_html_escapes_untrusted_source_and_finding_text(self) -> None:
        trace, graph, recommendations = sample_artifacts()
        html = render_summary_html(build_manifest(trace), trace, graph, recommendations)

        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<script>bad", html)
        self.assertIn("&lt;script&gt;alert", html)

    def test_complete_bundle_is_parseable_and_collision_safe(self) -> None:
        trace, graph, recommendations = sample_artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            written = write_bundle(
                output,
                trace=trace,
                graph=graph,
                recommendations=recommendations,
            )

            self.assertEqual(written, output)
            expected = {
                "manifest.json",
                "trace.json",
                "ciphertext_graph.json",
                "recommendations.json",
                "operations.csv",
                "perfetto-trace.json",
                "summary.html",
                "schemas",
            }
            self.assertEqual({path.name for path in output.iterdir()}, expected)
            json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            json.loads((output / "trace.json").read_text(encoding="utf-8"))
            json.loads((output / "perfetto-trace.json").read_text(encoding="utf-8"))
            self.assertGreater(len(list((output / "schemas").glob("*.schema.json"))), 0)

            with self.assertRaises(FileExistsError):
                write_bundle(
                    output,
                    trace=trace,
                    graph=graph,
                    recommendations=recommendations,
                )

    def test_failed_projection_leaves_no_partial_bundle(self) -> None:
        trace, graph, recommendations = sample_artifacts()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            with mock.patch(
                "cipherscope.exporters.semantic_json.render_summary_html",
                side_effect=RuntimeError("synthetic exporter failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "exporter failure"):
                    write_bundle(
                        output,
                        trace=trace,
                        graph=graph,
                        recommendations=recommendations,
                    )
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
