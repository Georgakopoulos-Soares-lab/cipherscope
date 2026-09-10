"""Annotated packing-utilization analysis over validated meaningful-slot claims."""

from __future__ import annotations

from collections.abc import Mapping
from math import prod
from typing import Any

from ..validation import ValidationError, validate_recommendations, validate_trace


RULE_ID = "packing.low_utilization_annotated.v1"
_LOW_UTILIZATION_THRESHOLD = 0.5
_DENSE_PACKINGS = {"row_major", "col_major", "dense", "diagonal"}


def _shape_is_compatible(packing: str, shape: list[int], meaningful_slots: int) -> bool:
    """Validate the annotated shape against the declared packing.

    Only packings with a known validator are accepted; an unknown packing makes
    the annotation unvalidated rather than silently trusted.
    """

    if packing not in _DENSE_PACKINGS:
        return False
    if not shape:
        return True
    return prod(shape) <= meaningful_slots


def analyze_packing(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Report packing utilization only for annotations that pass validation.

    Without a validated ``meaningful_slots`` annotation and a known slot
    capacity, the rule is not applicable: CipherScope never infers semantic
    utilization from ciphertext contents.
    """

    validation = validate_trace(trace)
    if not validation.valid:
        raise ValidationError("trace", validation.errors)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    context = trace.get("context", {})
    available = context.get("available_slots") if isinstance(context, Mapping) else None
    if not isinstance(available, int) or isinstance(available, bool) or available <= 0:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The trace has no known CKKS slot capacity to compare against."
            ],
            "findings": [],
        }

    inventory: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for state in trace["ciphertexts"]:
        if not isinstance(state, Mapping):
            continue
        annotations = state.get("annotations")
        if not isinstance(annotations, Mapping):
            continue
        meaningful = annotations.get("meaningful_slots")
        if not isinstance(meaningful, int) or isinstance(meaningful, bool):
            continue
        if not 0 <= meaningful <= available:
            continue
        packing = annotations.get("packing")
        shape = annotations.get("shape")
        shape_list = (
            [int(item) for item in shape]
            if isinstance(shape, list)
            and all(
                isinstance(item, int) and not isinstance(item, bool) for item in shape
            )
            else []
        )
        if isinstance(packing, str) and not _shape_is_compatible(
            packing, shape_list, meaningful
        ):
            continue
        utilization = meaningful / available
        record = {
            "ciphertext_id": str(state["id"]),
            "meaningful_slots": meaningful,
            "available_slots": available,
            "utilization": utilization,
            "packing": packing if isinstance(packing, str) else None,
        }
        inventory.append(record)
        if utilization < _LOW_UTILIZATION_THRESHOLD:
            findings.append(
                {
                    "finding_id": f"finding_packing_{len(findings) + 1:04d}",
                    "rule_id": RULE_ID,
                    "analyzer": "PackingAnalyzer",
                    "category": "packing",
                    "severity": "opportunity",
                    "confidence": "measured",
                    "source_sites": [],
                    "evidence_event_ids": [],
                    "evidence": record,
                    "applicability": [
                        "an explicit validated meaningful-slot annotation",
                        "meaningful slots within the known CKKS slot capacity",
                        "declared packing whose shape validator accepts the annotation",
                    ],
                    "estimated_impact": {
                        "utilization": utilization,
                        "speedup": None,
                    },
                    "recommendation": (
                        "Review whether a tighter packing or batching of independent "
                        "items could use more of the available slots."
                    ),
                    "limitations": [
                        "Utilization is the user's annotation, not inferred from contents.",
                        "Fuller packing may not be possible given the algorithm's rotations.",
                        "No speedup is claimed until a repacked program is rerun.",
                    ],
                }
            )

    if not inventory:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No ciphertext carried a validated meaningful-slot annotation."
            ],
            "findings": [],
        }
    if findings:
        result = {
            **base,
            "analysis_status": "positive",
            "inventory": inventory,
            "findings": findings,
        }
    else:
        result = {
            **base,
            "analysis_status": "clean",
            "inventory": inventory,
            "findings": [],
        }
    result_validation = validate_recommendations(result, trace=trace)
    if not result_validation.valid:
        raise ValidationError("recommendations", result_validation.errors)
    return result



__all__ = ["RULE_ID", "analyze_packing"]
