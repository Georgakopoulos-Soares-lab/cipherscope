"""Advisory public-value provenance analysis for ciphertext-ciphertext products."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._shared import event_order, finalize, require_valid_trace

RULE_ID = "provenance.public_value_ciphertext_mult.v1"
_PUBLIC_PROVENANCES = {"public_constant", "model_parameter", "public_input"}


def _public_derived_ids(states: list[Mapping[str, Any]]) -> set[str]:
    """Return ciphertext versions with a purely public lineage.

    A version is public-derived when it is annotated public, or it is derived
    only from parents that are themselves public-derived. Mixing an encrypted
    operand breaks the chain, so an encrypted+public sum is never called public.
    """

    ciphertext_by_id = {str(state["id"]): state for state in states}
    memo: dict[str, bool] = {}

    def is_public(ciphertext_id: str, stack: frozenset[str]) -> bool:
        if ciphertext_id in memo:
            return memo[ciphertext_id]
        if ciphertext_id in stack:
            return False
        state = ciphertext_by_id.get(ciphertext_id)
        if state is None:
            return False
        annotations = state.get("annotations")
        if (
            isinstance(annotations, Mapping)
            and annotations.get("provenance") in _PUBLIC_PROVENANCES
        ):
            memo[ciphertext_id] = True
            return True
        parents = [str(item) for item in state.get("parent_ids", [])]
        result = bool(parents) and all(
            is_public(parent, stack | {ciphertext_id}) for parent in parents
        )
        memo[ciphertext_id] = result
        return result

    return {
        ciphertext_id
        for ciphertext_id in ciphertext_by_id
        if is_public(ciphertext_id, frozenset())
    }


def analyze_provenance(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Flag ciphertext-ciphertext products with a public-only input.

    This is an advisory review item backed by explicit annotations, never proof
    that switching to a plaintext multiplication is correct for the protocol.
    """

    require_valid_trace(trace)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    states = [state for state in trace["ciphertexts"] if isinstance(state, Mapping)]
    public_ciphertext_ids = _public_derived_ids(states)
    if not public_ciphertext_ids:
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
        key=event_order,
    )
    findings: list[dict[str, Any]] = []
    for event in events:
        if event.get("status") != "ok" or event.get("operation") != "EvalMult":
            continue
        if event.get("overload") not in {"ct_ct", "ciphertext_ciphertext"}:
            continue
        inputs = [str(item) for item in event.get("input_ciphertexts", [])]
        public_operands = [item for item in inputs if item in public_ciphertext_ids]
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
    return finalize(result, trace=trace)


__all__ = ["RULE_ID", "analyze_provenance"]
