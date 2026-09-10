"""Observed-run bootstrap restoration and suffix-consumption analysis."""

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


RULE_ID = "bootstrap.restored_levels_underused.v1"


def _event_order(event: Mapping[str, Any]) -> tuple[int, str]:
    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def _snapshot_level(states: Any, ciphertext_id: str) -> int | None:
    if not isinstance(states, list):
        return None
    for snapshot in states:
        if not isinstance(snapshot, Mapping) or snapshot.get("id") != ciphertext_id:
            continue
        level = snapshot.get("level")
        return level if isinstance(level, int) and not isinstance(level, bool) else None
    return None


def _epochs_by_index(graph: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    paths = graph.get("critical_paths", {})
    level_use = (
        paths.get("observed_level_use", {}) if isinstance(paths, Mapping) else {}
    )
    epochs = level_use.get("epochs", []) if isinstance(level_use, Mapping) else []
    indexed: dict[int, Mapping[str, Any]] = {}
    for epoch in epochs:
        if isinstance(epoch, Mapping) and isinstance(epoch.get("epoch_index"), int):
            indexed[int(epoch["epoch_index"])] = epoch
    return indexed


def analyze_bootstrap(
    trace: Mapping[str, Any], graph: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Report observed level state around each bootstrap and its suffix use.

    A bootstrap that reclaims more levels than the segment it opens actually
    consumes is a review candidate, never an automatic move: the refresh may be
    correctly placed for noise reasons this executed run cannot observe.
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
    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=_event_order,
    )
    bootstraps = [
        event
        for event in events
        if event.get("status") == "ok" and event.get("operation") == "EvalBootstrap"
    ]
    if not bootstraps:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No successful EvalBootstrap event was observed."
            ],
            "findings": [],
        }

    epochs = _epochs_by_index(graph)
    # The Nth successful bootstrap (0-indexed) closes epoch N and opens epoch N+1.
    inventory: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    unresolved = False
    for closed_index, event in enumerate(bootstraps):
        event_id = str(event["event_id"])
        inputs = [str(item) for item in event.get("input_ciphertexts", [])]
        outputs = [str(item) for item in event.get("output_ciphertexts", [])]
        before = (
            _snapshot_level(event.get("input_states"), inputs[0]) if inputs else None
        )
        after = (
            _snapshot_level(event.get("output_states"), outputs[0]) if outputs else None
        )
        suffix_epoch = epochs.get(closed_index + 1)
        suffix_consumed: int | None = None
        suffix_confidence = "unknown"
        if isinstance(suffix_epoch, Mapping):
            consumed = suffix_epoch.get("max_levels_consumed")
            suffix_confidence = str(suffix_epoch.get("confidence", "unknown"))
            if isinstance(consumed, int) and not isinstance(consumed, bool):
                suffix_consumed = consumed
        restored = before - after if before is not None and after is not None else None
        record = {
            "bootstrap_event_id": event_id,
            "level_before": before,
            "level_after": after,
            "restored_levels": restored,
            "suffix_levels_consumed": suffix_consumed,
            "suffix_confidence": suffix_confidence,
        }
        inventory.append(record)
        if (
            restored is None
            or suffix_consumed is None
            or suffix_confidence != "measured"
        ):
            unresolved = True
            continue
        if restored > suffix_consumed:
            source = event.get("source", {})
            site = (
                [source["call_site_id"]]
                if isinstance(source, Mapping)
                and isinstance(source.get("call_site_id"), str)
                and source["call_site_id"]
                else []
            )
            findings.append(
                {
                    "finding_id": f"finding_bootstrap_{len(findings) + 1:04d}",
                    "rule_id": RULE_ID,
                    "analyzer": "BootstrapAnalyzer",
                    "category": "bootstrap",
                    "severity": "opportunity",
                    "confidence": "measured",
                    "source_sites": site,
                    "source": {
                        "file": source.get("file")
                        if isinstance(source, Mapping)
                        else None,
                        "function": (
                            source.get("function")
                            if isinstance(source, Mapping)
                            else None
                        ),
                        "lines": (
                            [source["line"]]
                            if isinstance(source, Mapping)
                            and isinstance(source.get("line"), int)
                            and not isinstance(source.get("line"), bool)
                            else []
                        ),
                    },
                    "evidence_event_ids": [event_id],
                    "evidence": record,
                    "applicability": [
                        "one successful EvalBootstrap with observed input and output levels",
                        "the segment opened by the bootstrap has fully measured level use",
                        "restored levels exceed the observed suffix consumption",
                    ],
                    "estimated_impact": {
                        "unused_restored_levels": float(restored - suffix_consumed),
                        "speedup": None,
                    },
                    "recommendation": (
                        "Test whether a cheaper bootstrap level budget or a later refresh "
                        "still completes this run before changing the placement."
                    ),
                    "limitations": [
                        "Underuse is observed for this run only, not proof the refresh is misplaced.",
                        "Noise, not only levels, can require a bootstrap at this point.",
                        "No speedup is claimed until a transformed program is rerun.",
                    ],
                }
            )

    if findings:
        result = {
            **base,
            "analysis_status": "positive",
            "inventory": inventory,
            "findings": findings,
        }
    elif unresolved:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "Bootstrap level state or suffix consumption was not fully measured."
            ],
            "findings": [],
        }
    else:
        result = {
            **base,
            "analysis_status": "clean",
            "inventory": inventory,
            "findings": [],
        }
    result_validation = validate_recommendations(result, trace=trace, graph=graph)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result



__all__ = ["RULE_ID", "analyze_bootstrap"]
