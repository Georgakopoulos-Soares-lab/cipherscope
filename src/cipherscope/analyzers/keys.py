"""Observed-run rotation-key generation and use analysis."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..validation import ValidationError, validate_recommendations, validate_trace


RULE_ID = "keys.unused_in_observed_run.v1"


def _event_order(event: Mapping[str, Any]) -> tuple[int, str]:
    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def _integer_list(value: Any) -> list[int] | None:
    if not isinstance(value, list) or any(
        not isinstance(item, int) or isinstance(item, bool) for item in value
    ):
        return None
    return list(value)


def analyze_keys(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Compare traced rotation-key generation with covered rotation uses.

    The result is intentionally limited to this execution. Missing generation
    events, truncated traces, and permissive passthroughs make the rule not
    applicable rather than turning unknown key use into an "unused" claim.
    """

    validation = validate_trace(trace)
    if not validation.valid:
        raise ValidationError("trace", validation.errors)
    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=_event_order,
    )
    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    coverage = trace["run"].get("coverage", {})
    if trace["run"].get("truncated") is True or (
        isinstance(coverage, Mapping)
        and coverage.get("unclassified_proxy_passthrough_calls", 0) != 0
    ):
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The trace is truncated or contains unclassified passthrough calls."
            ],
            "findings": [],
        }

    generation_events = [
        event
        for event in events
        if event.get("status") == "ok" and event.get("operation") == "EvalRotateKeyGen"
    ]
    if not generation_events:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No successful EvalRotateKeyGen event was observed through the proxy."
            ],
            "findings": [],
        }

    generated: set[int] = set()
    for event in generation_events:
        semantic = event.get("semantic_arguments")
        indices = (
            _integer_list(semantic.get("rotation_indices_requested"))
            if isinstance(semantic, Mapping)
            else None
        )
        if indices is None:
            return {
                **base,
                "analysis_status": "not_applicable",
                "not_applicable_reasons": [
                    "A rotation-key generation event lacks a validated index list."
                ],
                "findings": [],
            }
        generated.update(indices)
    if not generated:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "Observed rotation-key generation requested no indices."
            ],
            "findings": [],
        }

    rotation_events = [
        event
        for event in events
        if event.get("status") == "ok" and event.get("operation") == "EvalRotate"
    ]
    used: set[int] = set()
    for event in rotation_events:
        semantic = event.get("semantic_arguments")
        index = (
            semantic.get("rotation_index_requested")
            if isinstance(semantic, Mapping)
            else None
        )
        if not isinstance(index, int) or isinstance(index, bool):
            return {
                **base,
                "analysis_status": "not_applicable",
                "not_applicable_reasons": [
                    "A covered rotation event lacks a validated requested index."
                ],
                "findings": [],
            }
        used.add(index)

    unused = sorted(generated - used)
    inventory = {
        "generated_indices": sorted(generated),
        "used_indices": sorted(used),
        "unused_generated_indices": unused,
        "used_without_observed_generation": sorted(used - generated),
    }
    if not unused:
        return {
            **base,
            "analysis_status": "clean",
            "inventory": inventory,
            "findings": [],
        }

    evidence_events = [*generation_events, *rotation_events]
    evidence_ids = [str(event["event_id"]) for event in evidence_events]
    source_sites = sorted(
        {
            str(event["source"]["call_site_id"])
            for event in generation_events
            if isinstance(event.get("source"), Mapping)
            and isinstance(event["source"].get("call_site_id"), str)
            and event["source"]["call_site_id"]
        }
    )
    finding = {
        "finding_id": "finding_keys_0001",
        "rule_id": RULE_ID,
        "analyzer": "KeyUsageAnalyzer",
        "category": "keys",
        "severity": "opportunity",
        "confidence": "measured",
        "source_sites": source_sites,
        "evidence_event_ids": evidence_ids,
        "evidence": inventory,
        "applicability": [
            "rotation-key generation observed through the traced context",
            "rotation uses limited to covered events in this execution",
            "complete trace with no unclassified proxy passthroughs",
        ],
        "recommendation": (
            "Review whether the unused generated rotation indices are needed for "
            "other inputs or paths before removing them."
        ),
        "limitations": [
            "Unused means not observed in this run, not globally unnecessary.",
            "Calls through the original context or operator/free-function paths are unobservable.",
            "Pre-generated or loaded keys are outside this inventory.",
        ],
    }
    result = {
        **base,
        "analysis_status": "positive",
        "inventory": inventory,
        "findings": [finding],
    }
    result_validation = validate_recommendations(result, trace=trace)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result



__all__ = ["RULE_ID", "analyze_keys"]
