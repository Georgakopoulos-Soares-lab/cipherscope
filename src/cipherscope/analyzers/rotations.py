"""Conservative repeated-rotation hoisting analysis."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..validation import ValidationError, validate_recommendations, validate_trace


RULE_ID = "rotation.hoist_same_input.v1"
_REQUIRED_STATE_FIELDS = (
    "context_id",
    "key_tag",
    "scaling_technique",
    "key_switch_technique",
)


def _event_order(event: Mapping[str, Any]) -> tuple[int, str]:
    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def _explicit_metadata(event: Mapping[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    semantic = event.get("semantic_arguments")
    if isinstance(semantic, Mapping):
        for field in _REQUIRED_STATE_FIELDS:
            if semantic.get(field) is not None:
                metadata[field] = semantic[field]
    snapshots = event.get("input_states")
    if isinstance(snapshots, list) and snapshots and isinstance(snapshots[0], Mapping):
        for field in _REQUIRED_STATE_FIELDS:
            if snapshots[0].get(field) is not None:
                metadata.setdefault(field, snapshots[0][field])
    return metadata


def _event_is_compatible(event: Mapping[str, Any], state: Mapping[str, Any]) -> bool:
    return all(
        field not in _explicit_metadata(event)
        or _explicit_metadata(event)[field] == state.get(field)
        for field in _REQUIRED_STATE_FIELDS
    )


def _precompute_source(event: Mapping[str, Any]) -> str | None:
    inputs = event.get("input_ciphertexts")
    if isinstance(inputs, list) and inputs and isinstance(inputs[0], str):
        return inputs[0]
    semantic = event.get("semantic_arguments")
    if isinstance(semantic, Mapping):
        source = semantic.get("source_ciphertext_version")
        return source if isinstance(source, str) else None
    return None


def _covered_by_prior_precompute(
    input_id: str,
    rotations: list[Mapping[str, Any]],
    events: list[Mapping[str, Any]],
    state: Mapping[str, Any],
) -> bool:
    first_sequence = min(int(event["sequence"]) for event in rotations)
    for event in events:
        if (
            event.get("status") == "ok"
            and event.get("operation") == "EvalFastRotationPrecompute"
            and _precompute_source(event) == input_id
            and isinstance(event.get("sequence"), int)
            and event["sequence"] < first_sequence
            and _event_is_compatible(event, state)
        ):
            return True
    return False


def _rotation_index(event: Mapping[str, Any]) -> int | None:
    arguments = event.get("semantic_arguments")
    if not isinstance(arguments, Mapping):
        return None
    index = arguments.get("rotation_index_requested")
    return index if isinstance(index, int) and not isinstance(index, bool) else None


def _has_intervening_mutation(
    input_id: str,
    rotations: list[Mapping[str, Any]],
    events: list[Mapping[str, Any]],
) -> bool:
    first_sequence = int(rotations[0]["sequence"])
    last_sequence = int(rotations[-1]["sequence"])
    for event in events:
        sequence = event.get("sequence")
        if (
            event.get("status") != "ok"
            or not isinstance(sequence, int)
            or not first_sequence < sequence < last_sequence
            or input_id not in event.get("input_ciphertexts", [])
        ):
            continue
        operation = event.get("operation")
        semantic = event.get("semantic_arguments")
        if (
            isinstance(operation, str)
            and operation.endswith("InPlace")
            or isinstance(semantic, Mapping)
            and semantic.get("in_place") is True
        ):
            return True
    return False


def analyze_rotations(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Find eligible repeated rotations from the same immutable ciphertext version.

    The top-level ``analysis_status`` distinguishes a finding (``positive``), an
    evidence-backed absence (``clean``), and missing prerequisites
    (``not_applicable``).  A precompute suppresses a group only when it is compatible
    and appears before every rotation in that group.
    """

    validation = validate_trace(trace)
    if not validation.valid:
        raise ValidationError("trace", validation.errors)
    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=_event_order,
    )
    states = {
        str(state["id"]): state
        for state in trace["ciphertexts"]
        if isinstance(state, Mapping)
    }
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        if event.get("status") != "ok" or event.get("operation") != "EvalRotate":
            continue
        inputs = event.get("input_ciphertexts")
        if isinstance(inputs, list) and inputs and isinstance(inputs[0], str):
            groups.setdefault(inputs[0], []).append(event)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    if not groups:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": ["No successful EvalRotate event was observed."],
            "findings": [],
        }

    findings: list[dict[str, Any]] = []
    evaluable_groups = 0
    unavailable_reasons: set[str] = set()
    for input_id in sorted(groups):
        rotations = sorted(groups[input_id], key=_event_order)
        state = states[input_id]
        missing = [
            field for field in _REQUIRED_STATE_FIELDS if state.get(field) is None
        ]
        if missing:
            unavailable_reasons.add(
                f"Ciphertext {input_id} lacks required metadata: {', '.join(missing)}."
            )
            continue
        if state.get("key_switch_technique") != "HYBRID":
            unavailable_reasons.add(
                f"Ciphertext {input_id} does not use the validated HYBRID key-switch technique."
            )
            continue
        if not all(_event_is_compatible(event, state) for event in rotations):
            unavailable_reasons.add(
                f"Rotation metadata for ciphertext {input_id} is inconsistent."
            )
            continue
        indices = [_rotation_index(event) for event in rotations]
        if any(index is None for index in indices):
            unavailable_reasons.add(
                f"Ciphertext {input_id} has a rotation with an unknown requested index."
            )
            continue
        evaluable_groups += 1
        distinct_indices = sorted(
            {int(index) for index in indices if index is not None}
        )
        if len(distinct_indices) < 2:
            continue
        if _has_intervening_mutation(input_id, rotations, events):
            continue
        if _covered_by_prior_precompute(input_id, rotations, events, state):
            continue

        source_sites = sorted(
            {
                str(event["source"]["call_site_id"])
                for event in rotations
                if isinstance(event.get("source"), Mapping)
                and isinstance(event["source"].get("call_site_id"), str)
                and event["source"]["call_site_id"]
            }
        )
        source_lines = sorted(
            {
                int(event["source"]["line"])
                for event in rotations
                if isinstance(event.get("source"), Mapping)
                and isinstance(event["source"].get("line"), int)
                and not isinstance(event["source"].get("line"), bool)
            }
        )
        first_source = rotations[0].get("source", {})
        combined_wall = sum(
            int(event.get("timing", {}).get("wall_duration_ns", 0))
            for event in rotations
            if isinstance(event.get("timing"), Mapping)
        )
        findings.append(
            {
                "finding_id": f"finding_rotation_{len(findings) + 1:04d}",
                "rule_id": RULE_ID,
                "analyzer": "RotationAnalyzer",
                "category": "rotation",
                "severity": "opportunity",
                "confidence": "measured",
                "source_sites": source_sites,
                "source": {
                    "file": first_source.get("file"),
                    "function": first_source.get("function"),
                    "lines": source_lines,
                },
                "evidence_event_ids": [str(event["event_id"]) for event in rotations],
                "evidence": {
                    "source_ciphertext_version": input_id,
                    "rotation_indices_requested": distinct_indices,
                    "rotation_count": len(rotations),
                    "combined_wall_duration_ns": combined_wall,
                },
                "applicability": [
                    "same immutable ciphertext version",
                    "at least two distinct requested rotation indices",
                    "matching context and key tag",
                    "matching scaling state and HYBRID key-switch technique",
                    "no compatible fast-rotation precompute precedes the group",
                ],
                "estimated_impact": {
                    "wall_duration_ns_affected": combined_wall,
                    "speedup": None,
                },
                "recommendation": (
                    "Test one EvalFastRotationPrecompute shared by compatible "
                    "EvalFastRotation calls."
                ),
                "limitations": [
                    "This is an executed-run candidate, not proof that hoisting is faster.",
                    "No speedup is claimed until the transformed real program is rerun.",
                ],
            }
        )

    if findings:
        result = {**base, "analysis_status": "positive", "findings": findings}
    elif evaluable_groups:
        result = {**base, "analysis_status": "clean", "findings": []}
    else:
        result = {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": sorted(unavailable_reasons),
            "findings": [],
        }
    result_validation = validate_recommendations(result, trace=trace)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result


analyze_repeated_rotations = analyze_rotations


class RotationAnalyzer:
    """Small analyzer object for plugin-style orchestration."""

    rule_id = RULE_ID
    required_fields = (
        "events[].semantic_arguments.rotation_index_requested",
        "ciphertexts[].context_id",
        "ciphertexts[].key_tag",
        "ciphertexts[].scaling_technique",
        "ciphertexts[].key_switch_technique",
    )

    def analyze(self, trace: Mapping[str, Any]) -> dict[str, Any]:
        return analyze_rotations(trace)


__all__ = [
    "RULE_ID",
    "RotationAnalyzer",
    "analyze_repeated_rotations",
    "analyze_rotations",
]
