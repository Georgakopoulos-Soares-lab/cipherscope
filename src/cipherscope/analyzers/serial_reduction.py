"""Serial multiplication-reduction review, gated on explicit region assertions."""

from __future__ import annotations

from collections.abc import Mapping
from math import ceil, log2
from typing import Any

from ._shared import event_order, finalize, require_valid_trace

RULE_ID = "multiplication.serial_reduction_review.v1"
_MIN_SERIAL_MULTS = 3
_MULT_OPERATIONS = {"EvalMult", "EvalMultNoRelin"}
_CT_CT_OVERLOADS = {"ct_ct", "ciphertext_ciphertext"}


def _longest_chain(mults: list[Mapping[str, Any]]) -> list[str]:
    """Return the event IDs of the longest ciphertext product chain.

    An edge exists when one multiplication consumes an output produced by an
    earlier multiplication in the same region, which is exactly a serial fold.
    """

    producers: dict[str, str] = {}
    for event in mults:
        for output_ciphertext_id in event.get("output_ciphertexts", []):
            producers[str(output_ciphertext_id)] = str(event["event_id"])

    best_chain: dict[str, list[str]] = {}
    longest: list[str] = []
    for event in mults:
        event_id = str(event["event_id"])
        parents = [
            producers[str(input_ciphertext_id)]
            for input_ciphertext_id in event.get("input_ciphertexts", [])
            if str(input_ciphertext_id) in producers
            and producers[str(input_ciphertext_id)] != event_id
        ]
        best_parent: list[str] = []
        for parent_id in parents:
            candidate = best_chain.get(parent_id, [])
            if len(candidate) > len(best_parent):
                best_parent = candidate
        chain = [*best_parent, event_id]
        best_chain[event_id] = chain
        if len(chain) > len(longest):
            longest = chain
    return longest


def _leaf_terms(mults: list[Mapping[str, Any]]) -> int:
    produced = {
        str(output_id) for event in mults for output_id in event.get("output_ciphertexts", [])
    }
    consumed = {
        str(input_id) for event in mults for input_id in event.get("input_ciphertexts", [])
    }
    return len(consumed - produced)


def analyze_serial_reductions(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Flag long serial products only inside an associative multiply region.

    Without a ``session.region`` asserting an associative multiply, the rule is
    not applicable: CipherScope will not assume a balanced tree is equivalent.
    """

    require_valid_trace(trace)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    regions = trace.get("regions")
    multiply_regions = [
        region
        for region in (regions if isinstance(regions, list) else [])
        if isinstance(region, Mapping)
        and region.get("operator") == "multiply"
        and region.get("associative") is True
    ]
    if not multiply_regions:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No associative multiply region was declared for this run."
            ],
            "findings": [],
        }

    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=event_order,
    )
    findings: list[dict[str, Any]] = []
    evaluated = 0
    for region in multiply_regions:
        start = region.get("start_sequence")
        end = region.get("end_sequence")
        if not (isinstance(start, int) and isinstance(end, int)) or end < start:
            continue
        evaluated += 1
        mults = [
            event
            for event in events
            if event.get("status") == "ok"
            and event.get("operation") in _MULT_OPERATIONS
            and event.get("overload") in _CT_CT_OVERLOADS
            and isinstance(event.get("sequence"), int)
            and start <= event["sequence"] <= end
        ]
        chain = _longest_chain(mults)
        if len(chain) < _MIN_SERIAL_MULTS:
            continue
        # The region's real term count is its leaves: ciphertexts consumed by a
        # region multiplication but produced by none. A balanced tree over
        # `terms` needs ceil(log2(terms)) levels; a chain no longer than that is
        # already optimal and must not be reported as a serial fold.
        terms = max(_leaf_terms(mults), len(chain) + 1)
        if len(chain) <= ceil(log2(terms)):
            continue
        chain_events = [event for event in mults if str(event["event_id"]) in chain]
        source_sites = sorted(
            {
                str(event["source"]["call_site_id"])
                for event in chain_events
                if isinstance(event.get("source"), Mapping)
                and isinstance(event["source"].get("call_site_id"), str)
                and event["source"]["call_site_id"]
            }
        )
        findings.append(
            {
                "finding_id": f"finding_serial_{len(findings) + 1:04d}",
                "rule_id": RULE_ID,
                "analyzer": "SerialReductionAnalyzer",
                "category": "multiplication",
                "severity": "opportunity",
                "confidence": "measured",
                "source_sites": source_sites,
                "evidence_event_ids": chain,
                "evidence": {
                    "region": str(region.get("name")),
                    "serial_multiplications": len(chain),
                    "reduced_terms": terms,
                    "serial_multiplicative_depth": len(chain),
                    "balanced_multiplicative_depth": ceil(log2(terms)),
                    "commutative": bool(region.get("commutative")),
                },
                "applicability": [
                    "an explicit associative multiply region",
                    "a serial product chain of at least three ciphertext-ciphertext multiplications",
                    "associativity asserted by the user, not inferred",
                ],
                "estimated_impact": {
                    "serial_multiplicative_depth": float(len(chain)),
                    "balanced_multiplicative_depth": float(ceil(log2(terms))),
                    "speedup": None,
                },
                "recommendation": (
                    "Test a balanced (tree) reduction inside this region to lower the "
                    "multiplicative depth before relying on it."
                ),
                "limitations": [
                    "Applies only within the user-asserted associative region.",
                    "A balanced tree changes the depth profile but not always the runtime.",
                    "No speedup is claimed until the restructured program is rerun.",
                ],
            }
        )

    if findings:
        result = {**base, "analysis_status": "positive", "findings": findings}
    elif evaluated:
        result = {**base, "analysis_status": "clean", "findings": []}
    else:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No associative multiply region had a usable event-sequence span."
            ],
            "findings": [],
        }
    return finalize(result, trace=trace)


__all__ = ["RULE_ID", "analyze_serial_reductions"]
