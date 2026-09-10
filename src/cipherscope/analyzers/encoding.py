"""Repeated public-constant encoding analysis over explicit constant IDs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._shared import event_order, finalize, require_valid_trace

RULE_ID = "encoding.repeated_public_constant.v1"


def analyze_encoding(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Flag public constants encoded more than once under the same constant ID.

    CipherScope does not hash or compare unannotated plaintext values; only an
    explicit, repeated run-local ``constant_id`` establishes that two encodings
    denote the same public constant.
    """

    require_valid_trace(trace)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=event_order,
    )
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        if event.get("status") != "ok":
            continue
        semantic = event.get("semantic_arguments")
        if not isinstance(semantic, Mapping):
            continue
        constant_id = semantic.get("constant_id")
        if isinstance(constant_id, str) and constant_id:
            groups.setdefault(constant_id, []).append(event)

    if not groups:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No plaintext encoding carried an explicit constant_id annotation."
            ],
            "findings": [],
        }

    findings: list[dict[str, Any]] = []
    for constant_id in sorted(groups):
        occurrences = groups[constant_id]
        if len(occurrences) < 2:
            continue
        source_sites = sorted(
            {
                str(event["source"]["call_site_id"])
                for event in occurrences
                if isinstance(event.get("source"), Mapping)
                and isinstance(event["source"].get("call_site_id"), str)
                and event["source"]["call_site_id"]
            }
        )
        findings.append(
            {
                "finding_id": f"finding_encoding_{len(findings) + 1:04d}",
                "rule_id": RULE_ID,
                "analyzer": "EncodingAnalyzer",
                "category": "encoding",
                "severity": "opportunity",
                "confidence": "measured",
                "source_sites": source_sites,
                "evidence_event_ids": [str(event["event_id"]) for event in occurrences],
                "evidence": {
                    "constant_id": constant_id,
                    "encoding_count": len(occurrences),
                },
                "applicability": [
                    "two or more encodings sharing one explicit run-local constant_id",
                    "provenance asserted by the user, not inferred from values",
                ],
                "estimated_impact": {
                    "redundant_encodings": float(len(occurrences) - 1),
                    "speedup": None,
                },
                "recommendation": (
                    "Encode this public constant once and reuse the plaintext across "
                    "the operations that need it."
                ),
                "limitations": [
                    "Repetition is asserted by the constant_id, not by comparing values.",
                    "Re-encoding may be intentional when parameters differ per use.",
                    "No speedup is claimed until the deduplicated program is rerun.",
                ],
            }
        )

    if findings:
        result = {**base, "analysis_status": "positive", "findings": findings}
    else:
        result = {**base, "analysis_status": "clean", "findings": []}
    return finalize(result, trace=trace)


__all__ = ["RULE_ID", "analyze_encoding"]
