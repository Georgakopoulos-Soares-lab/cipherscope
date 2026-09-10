"""Advisory public-value provenance analysis for ciphertext-ciphertext products."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..validation import ValidationError, validate_recommendations, validate_trace


RULE_ID = "provenance.public_value_ciphertext_mult.v1"
_PUBLIC_PROVENANCES = {"public_constant", "model_parameter", "public_input"}


def _event_order(event: Mapping[str, Any]) -> tuple[int, str]:
    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def _public_derived_ids(states: list[Mapping[str, Any]]) -> set[str]:
    """Return ciphertext versions with a purely public lineage.

    A version is public-derived when it is annotated public, or it is derived
    only from parents that are themselves public-derived. Mixing an encrypted
    operand breaks the chain, so an encrypted+public sum is never called public.
    """

    by_id = {str(state["id"]): state for state in states}
    memo: dict[str, bool] = {}

    def is_public(state_id: str, stack: frozenset[str]) -> bool:
        if state_id in memo:
            return memo[state_id]
        if state_id in stack:
            return False
        state = by_id.get(state_id)
        if state is None:
            return False
        annotations = state.get("annotations")
        if (
            isinstance(annotations, Mapping)
            and annotations.get("provenance") in _PUBLIC_PROVENANCES
        ):
            memo[state_id] = True
            return True
        parents = [str(item) for item in state.get("parent_ids", [])]
        result = bool(parents) and all(
            is_public(parent, stack | {state_id}) for parent in parents
        )
        memo[state_id] = result
        return result

    return {state_id for state_id in by_id if is_public(state_id, frozenset())}


def analyze_provenance(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Flag ct-ct multiplications with an operand of purely public provenance.

    This is an advisory review item backed by explicit annotations, never proof
    that switching to a plaintext multiplication is correct for the protocol.
    """

    validation = validate_trace(trace)
    if not validation.valid:
        raise ValidationError("trace", validation.errors)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    states = [state for state in trace["ciphertexts"] if isinstance(state, Mapping)]
    public_ids = _public_derived_ids(states)
    if not public_ids:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No ciphertext carried an explicit public-value provenance annotation."
            ],
            "findings": [],
        }

    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=_event_order,
    )
    findings: list[dict[str, Any]] = []
    for event in events:
        if event.get("status") != "ok" or event.get("operation") != "EvalMult":
            continue
        if event.get("overload") not in {"ct_ct", "ciphertext_ciphertext"}:
            continue
        inputs = [str(item) for item in event.get("input_ciphertexts", [])]
        public_operands = [item for item in inputs if item in public_ids]
        if not public_operands:
            continue
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
                "finding_id": f"finding_provenance_{len(findings) + 1:04d}",
                "rule_id": RULE_ID,
                "analyzer": "PublicValueAnalyzer",
                "category": "provenance",
                "severity": "opportunity",
                "confidence": "measured",
                "source_sites": site,
                "source": {
                    "file": source.get("file") if isinstance(source, Mapping) else None,
                    "function": (
                        source.get("function") if isinstance(source, Mapping) else None
                    ),
                    "lines": (
                        [source["line"]]
                        if isinstance(source, Mapping)
                        and isinstance(source.get("line"), int)
                        and not isinstance(source.get("line"), bool)
                        else []
                    ),
                },
                "evidence_event_ids": [str(event["event_id"])],
                "evidence": {
                    "public_operands": sorted(public_operands),
                    "input_ciphertexts": inputs,
                },
                "applicability": [
                    "a successful ciphertext-ciphertext EvalMult",
                    "an operand with an explicit purely public provenance lineage",
                    "provenance asserted by the user, not inferred from contents",
                ],
                "recommendation": (
                    "Review whether the public operand can be supplied as a plaintext "
                    "multiplication to avoid a ciphertext-ciphertext product."
                ),
                "limitations": [
                    "This is advisory; it does not prove the protocol change is correct.",
                    "Provenance is a user annotation, not a cryptographic guarantee.",
                    "A plaintext multiplication may change parameters and must be re-validated.",
                ],
            }
        )

    if findings:
        result = {**base, "analysis_status": "positive", "findings": findings}
    else:
        result = {**base, "analysis_status": "clean", "findings": []}
    result_validation = validate_recommendations(result, trace=trace)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result



__all__ = ["RULE_ID", "analyze_provenance"]
