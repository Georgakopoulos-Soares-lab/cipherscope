"""Validate a trace, build its graph, and run every analyzer."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .analyzers import (
    analyze_bootstrap,
    analyze_depth,
    analyze_encoding,
    analyze_keys,
    analyze_packing,
    analyze_parameters,
    analyze_precision,
    analyze_provenance,
    analyze_rotations,
    analyze_serial_reductions,
)
from .exporters import build_manifest
from .graph import build_graph
from .validation import ValidationError, validate_recommendations, validate_trace


def analyze_trace(
    trace: Mapping[str, Any],
    graph: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run every analyzer and merge their validated findings."""

    trace_validation = validate_trace(trace)
    if not trace_validation.valid:
        raise ValidationError("trace", trace_validation.errors)
    resolved_graph = dict(graph) if graph is not None else build_graph(trace)
    reports = {
        "depth.critical_path.v1": analyze_depth(trace, resolved_graph),
        "keys.unused_in_observed_run.v1": analyze_keys(trace),
        "rotation.hoist_same_input.v1": analyze_rotations(trace),
        "bootstrap.restored_levels_underused.v1": analyze_bootstrap(
            trace, resolved_graph
        ),
        "parameters.depth_headroom_observed.v1": analyze_parameters(
            trace, resolved_graph
        ),
        "packing.low_utilization_annotated.v1": analyze_packing(trace),
        "provenance.public_value_ciphertext_mult.v1": analyze_provenance(trace),
        "precision.checkpoint_drop.v1": analyze_precision(trace),
        "encoding.repeated_public_constant.v1": analyze_encoding(trace),
        "multiplication.serial_reduction_review.v1": analyze_serial_reductions(trace),
    }
    findings = [
        finding for report in reports.values() for finding in report.get("findings", [])
    ]
    statuses = {
        rule_id: str(report.get("analysis_status", "not_applicable"))
        for rule_id, report in reports.items()
    }
    if findings:
        status = "positive"
    elif any(value == "clean" for value in statuses.values()):
        status = "clean"
    else:
        status = "not_applicable"
    result: dict[str, Any] = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
        "analysis_status": status,
        "analyzer_status": statuses,
        "findings": findings,
    }
    if trace["run"].get("synthetic_contract") is True:
        result["synthetic_contract"] = True
    reasons = [
        reason
        for report in reports.values()
        for reason in report.get("not_applicable_reasons", [])
    ]
    if reasons:
        result["not_applicable_reasons"] = sorted(set(reasons))
    validation = validate_recommendations(result, trace=trace, graph=resolved_graph)
    if not validation.valid:
        raise ValidationError("recommendations", validation.errors)
    return result


def build_analysis_bundle(trace: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Build the manifest, graph, and recommendations for a trace."""

    graph = build_graph(trace)
    recommendations = analyze_trace(trace, graph)
    return {
        "manifest": build_manifest(trace),
        "trace": dict(trace),
        "graph": graph,
        "recommendations": recommendations,
    }


__all__ = ["analyze_trace", "build_analysis_bundle"]
