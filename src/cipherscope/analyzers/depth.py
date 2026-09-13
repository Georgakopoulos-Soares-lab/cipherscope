"""Critical-depth analyzer backed by the deterministic ciphertext graph."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from ._shared import finalize, resolve_graph

RULE_ID = "depth.critical_path.v1"


def _source_sites(trace: Mapping[str, Any], event_ids: set[str]) -> list[str]:
    sites: set[str] = set()
    for event in trace.get("events", []):
        if not isinstance(event, Mapping) or event.get("event_id") not in event_ids:
            continue
        source = event.get("source")
        if isinstance(source, Mapping):
            site_id = source.get("call_site_id")
            if isinstance(site_id, str) and site_id:
                sites.add(site_id)
    return sorted(sites)


def analyze_depth(
    trace: Mapping[str, Any], graph: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Return a recommendations-shaped report of both supported depth metrics."""

    graph = resolve_graph(trace, graph)

    critical_paths = graph.get("critical_paths", {})
    nonlinear = critical_paths.get("nonlinear_ciphertext")
    observed = critical_paths.get("observed_level_use")
    has_ciphertexts = any(
        isinstance(node, Mapping) and node.get("node_type") == "CiphertextVersion"
        for node in graph.get("nodes", [])
    )
    applicable = (
        has_ciphertexts
        and isinstance(nonlinear, Mapping)
        and isinstance(observed, Mapping)
    )
    if not applicable:
        result: dict[str, Any] = {
            "schema_version": trace["schema_version"],
            "run_id": trace["run"]["run_id"],
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No validated ciphertext lineage with both depth metrics was available."
            ],
            "findings": [],
        }
        return result

    evidence_ids = sorted(
        {
            *(item for item in nonlinear.get("event_ids", []) if isinstance(item, str)),
            *(item for item in observed.get("event_ids", []) if isinstance(item, str)),
            *(
                item
                for item in nonlinear.get("bootstrap_event_ids", [])
                if isinstance(item, str)
            ),
        },
        key=lambda event_id: next(
            (
                event.get("sequence", 2**63)
                for event in trace["events"]
                if event.get("event_id") == event_id
            ),
            2**63,
        ),
    )
    confidences = {nonlinear.get("confidence"), observed.get("confidence")}
    confidence = "unknown" if "unknown" in confidences else "inferred"
    finding = {
        "finding_id": "finding_depth_0001",
        "rule_id": RULE_ID,
        "analyzer": "DepthAnalyzer",
        "category": "depth",
        "severity": "information",
        "confidence": confidence,
        "source_sites": _source_sites(trace, set(evidence_ids)),
        "evidence_event_ids": evidence_ids,
        "evidence": {
            "nonlinear_ciphertext": deepcopy(dict(nonlinear)),
            "observed_level_use": deepcopy(dict(observed)),
        },
        "applicability": [
            "executed ciphertext lineage only",
            "nonlinear increments use declared operation semantics",
            "level use requires observed input/output level metadata",
        ],
        "recommendation": (
            "Use the two observed path metrics separately when reviewing the executed run."
        ),
        "limitations": [
            "Ciphertext-only nonlinear depth is not configured multiplicative-depth headroom.",
            "Bootstrap starts a new epoch but does not erase historical work from this report.",
            "Unknown composite operations or state transitions prevent an exact path claim.",
        ],
    }
    result = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
        "analysis_status": "positive",
        "findings": [finding],
    }
    return finalize(result, trace=trace, graph=graph)


__all__ = ["RULE_ID", "analyze_depth"]
