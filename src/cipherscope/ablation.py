"""Project a trace onto less informative views to measure what each rule needs."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from .pipeline import analyze_trace
from .state import copy_mapping

TIMING_ONLY = "TIMING_ONLY"
STATE = "STATE"
FULL = "FULL"
MODES = (TIMING_ONLY, STATE, FULL)

# Fields a generic profiler cannot observe. TIMING_ONLY strips all of them;
# STATE keeps the state snapshots and semantic arguments but breaks identity.
_STATE_KEYS = ("context_id", "key_switch_technique", "key_tag", "level", "noise_scale_degree", "scale", "scaling_technique", "slots")

ABLATION_COLUMNS = ("bundle", "name", "mode", "rule_id", "analysis_status", "findings", "signature")


def _timing_only(trace: Mapping[str, Any]) -> dict[str, Any]:
    projected = copy_mapping(trace)
    events = []
    for event in projected["events"]:
        if event.get("kind") in {"annotation", "checkpoint"}:
            continue
        event["input_ciphertexts"] = []
        event["output_ciphertexts"] = []
        event["input_states"] = []
        event["output_states"] = []
        event["semantic_arguments"] = {}
        event.pop("argument_representations", None)
        event.pop("keyword_argument_representations", None)
        event.pop("output_representation", None)
        events.append(event)
    projected["events"] = events
    projected["ciphertexts"] = []
    projected.pop("regions", None)
    return projected


def _state_only(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Keep per-event state and arguments; give every reference a fresh identity."""

    projected = copy_mapping(trace)
    originals = {state["id"]: state for state in trace.get("ciphertexts", []) if isinstance(state, Mapping)}
    ciphertexts: list[dict[str, Any]] = []
    counter = 0

    def fresh(original_id: str, *, event_id: str | None, parents: Sequence[str] = ()) -> dict[str, Any]:
        nonlocal counter
        counter += 1
        anonymous = f"anon_{counter:05d}:v0"
        original = originals.get(original_id, {})
        state = {
            "id": anonymous,
            "created_by_event": event_id,
            # Lineage survives only inside one event; nothing links events together.
            "parent_ids": list(parents),
            "origin": "derived" if event_id else "preexisting",
            **{key: original[key] for key in _STATE_KEYS if key in original},
        }
        ciphertexts.append(state)
        return state

    events = []
    for event in projected["events"]:
        if event.get("kind") == "annotation" and event.get("operation") == "Annotate":
            continue
        rewritten_inputs = []
        input_states = []
        for original_id, snapshot in zip(event.get("input_ciphertexts", []), event.get("input_states", [])):
            state = fresh(str(original_id), event_id=None)
            rewritten_inputs.append(state["id"])
            input_states.append({**snapshot, "id": state["id"]})
        rewritten_outputs = []
        output_states = []
        for original_id, snapshot in zip(event.get("output_ciphertexts", []), event.get("output_states", [])):
            state = fresh(str(original_id), event_id=str(event["event_id"]), parents=rewritten_inputs)
            rewritten_outputs.append(state["id"])
            output_states.append({**snapshot, "id": state["id"]})
        event["input_ciphertexts"] = rewritten_inputs
        event["input_states"] = input_states
        event["output_ciphertexts"] = rewritten_outputs
        event["output_states"] = output_states
        events.append(event)
    projected["events"] = events
    projected["ciphertexts"] = ciphertexts
    projected.pop("regions", None)
    return projected


def project(trace: Mapping[str, Any], mode: str) -> dict[str, Any]:
    """Return the trace as seen under one observability mode."""

    if mode == FULL:
        return copy.deepcopy(dict(trace))
    if mode == STATE:
        return _state_only(trace)
    if mode == TIMING_ONLY:
        return _timing_only(trace)
    raise ValueError(f"unknown ablation mode {mode!r}; expected one of {', '.join(MODES)}")


def ablate(trace: Mapping[str, Any], *, bundle: str, name: str | None) -> list[dict[str, Any]]:
    """Run every analyzer under every mode; one row per (mode, rule)."""

    rows: list[dict[str, Any]] = []
    for mode in MODES:
        recommendations = analyze_trace(project(trace, mode))
        counts: dict[str, int] = {}
        signatures: dict[str, str] = {}
        for finding in recommendations.get("findings", []):
            rule_id = str(finding["rule_id"])
            counts[rule_id] = counts.get(rule_id, 0) + 1
            signatures[rule_id] = _signature(rule_id, finding)
        for rule_id, status in sorted(recommendations["analyzer_status"].items()):
            rows.append(
                {
                    "bundle": bundle,
                    "name": name,
                    "mode": mode,
                    "rule_id": rule_id,
                    "analysis_status": status,
                    "findings": counts.get(rule_id, 0),
                    "signature": signatures.get(rule_id, ""),
                }
            )
    return rows


def _signature(rule_id: str, finding: Mapping[str, Any]) -> str:
    """The value a finding must reproduce to count as the same diagnosis."""

    evidence = finding.get("evidence") or {}
    if rule_id == "depth.critical_path.v1":
        nonlinear = evidence.get("nonlinear_ciphertext") or {}
        return f"max_depth={nonlinear.get('max_depth')};confidence={nonlinear.get('confidence')}"
    if rule_id == "parameters.depth_headroom_observed.v1":
        return f"headroom={evidence.get('observed_depth_headroom')}"
    return ""


def minimum_modes(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per rule: how many FULL-mode positives survive each mode, and the weakest mode that fires."""

    positives: dict[str, dict[str, str]] = {}
    fired: dict[str, dict[str, dict[str, str]]] = {}
    for row in rows:
        rule_id = str(row["rule_id"])
        bundle = str(row["bundle"])
        signature = str(row.get("signature") or "")
        if row["mode"] == FULL and row["analysis_status"] == "positive":
            positives.setdefault(rule_id, {})[bundle] = signature
        if row["analysis_status"] == "positive":
            fired.setdefault(rule_id, {}).setdefault(str(row["mode"]), {})[bundle] = signature
    table: list[dict[str, Any]] = []
    for rule_id in sorted(set(positives) | set(fired)):
        full_positive = positives.get(rule_id, {})
        detected = {
            mode: sum(
                1
                for bundle, signature in full_positive.items()
                if fired.get(rule_id, {}).get(mode, {}).get(bundle) == signature
            )
            for mode in MODES
        }
        minimum = next((mode for mode in MODES if detected[mode] == len(full_positive) and full_positive), None)
        table.append(
            {
                "rule_id": rule_id,
                "full_positives": len(full_positive),
                "detected_timing_only": detected[TIMING_ONLY],
                "detected_state": detected[STATE],
                "detected_full": detected[FULL],
                "minimum_mode": minimum,
                "generic_profiler_can_diagnose": bool(full_positive) and detected[TIMING_ONLY] == len(full_positive),
            }
        )
    return table


MINIMUM_MODE_COLUMNS = (
    "rule_id",
    "full_positives",
    "detected_timing_only",
    "detected_state",
    "detected_full",
    "minimum_mode",
    "generic_profiler_can_diagnose",
)

__all__ = [
    "ABLATION_COLUMNS",
    "FULL",
    "MINIMUM_MODE_COLUMNS",
    "MODES",
    "STATE",
    "TIMING_ONLY",
    "ablate",
    "minimum_modes",
    "project",
]
