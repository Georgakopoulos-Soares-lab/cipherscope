"""Observed depth-headroom analysis against the configured multiplicative depth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..graph import build_graph
from ..validation import (
    ValidationError,
    validate_graph,
    validate_recommendations,
    validate_trace,
)


RULE_ID = "parameters.depth_headroom_observed.v1"


def _observed_level_use(graph: Mapping[str, Any]) -> Mapping[str, Any] | None:
    paths = graph.get("critical_paths", {})
    if not isinstance(paths, Mapping):
        return None
    observed = paths.get("observed_level_use")
    return observed if isinstance(observed, Mapping) else None


def analyze_parameters(
    trace: Mapping[str, Any], graph: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Compare the configured multiplicative depth with fully modeled level use.

    The rule is not applicable whenever the observed level requirement is not
    fully measured (opaque or unresolved paths), because unused headroom cannot
    be claimed from an incomplete depth model. The result is limited to this run.
    """

    trace_result = validate_trace(trace)
    if not trace_result.valid:
        raise ValidationError("trace", trace_result.errors)
    if graph is None:
        graph = build_graph(trace)
    graph_result = validate_graph(graph, trace=trace)
    if not graph_result.valid:
        raise ValidationError("graph", graph_result.errors)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    context = trace.get("context", {})
    configured = (
        context.get("configured_multiplicative_depth")
        if isinstance(context, Mapping)
        else None
    )
    if not isinstance(configured, int) or isinstance(configured, bool):
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The trace has no known configured multiplicative depth."
            ],
            "findings": [],
        }

    observed = _observed_level_use(graph)
    if observed is None or observed.get("confidence") != "measured":
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "Observed level use is not fully measured; opaque or unresolved paths remain."
            ],
            "findings": [],
        }
    consumed = observed.get("max_levels_consumed_in_epoch")
    if not isinstance(consumed, int) or isinstance(consumed, bool):
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The observed maximum level use per epoch was not resolved."
            ],
            "findings": [],
        }

    headroom = configured - consumed
    inventory = {
        "configured_multiplicative_depth": configured,
        "observed_max_levels_consumed_in_epoch": consumed,
        "observed_depth_headroom": headroom,
    }
    if headroom <= 0:
        return {
            **base,
            "analysis_status": "clean",
            "inventory": inventory,
            "findings": [],
        }

    evidence_ids = [
        item for item in observed.get("event_ids", []) if isinstance(item, str)
    ]
    finding = {
        "finding_id": "finding_parameters_0001",
        "rule_id": RULE_ID,
        "analyzer": "ParameterAnalyzer",
        "category": "parameters",
        "severity": "opportunity",
        "confidence": "measured",
        "source_sites": [],
        "evidence_event_ids": evidence_ids,
        "evidence": inventory,
        "applicability": [
            "a known configured multiplicative depth for this run",
            "fully measured observed level use with no opaque or unresolved paths",
            "observed per-epoch level use below the configured depth",
        ],
        "estimated_impact": {
            "observed_depth_headroom": float(headroom),
            "speedup": None,
        },
        "recommendation": (
            "Test a smaller multiplicative depth on representative inputs before reducing "
            "it; a lower depth can change parameters and must be re-validated."
        ),
        "limitations": [
            "Headroom reflects this run's inputs and branches only, not all inputs.",
            "Reducing depth may alter security parameters and require re-tuning.",
            "Bootstrapping segments are measured per epoch, not summed across the run.",
        ],
    }
    result = {
        **base,
        "analysis_status": "positive",
        "inventory": inventory,
        "findings": [finding],
    }
    result_validation = validate_recommendations(result, trace=trace, graph=graph)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result



__all__ = ["RULE_ID", "analyze_parameters"]
