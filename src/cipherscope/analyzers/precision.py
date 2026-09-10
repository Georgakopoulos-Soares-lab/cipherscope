"""Shadow-mode precision-checkpoint drop analysis."""

from __future__ import annotations

import math
import sys
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from ._shared import event_order, finalize, require_valid_trace

RULE_ID = "precision.checkpoint_drop.v1"


def _checkpoint_record(event: Mapping[str, Any]) -> dict[str, Any] | None:
    semantic = event.get("semantic_arguments")
    if not isinstance(semantic, Mapping):
        return None
    name = semantic.get("checkpoint_name")
    expected = semantic.get("expected_values")
    observed = semantic.get("observed_values")
    if (
        not isinstance(name, str)
        or not isinstance(expected, list)
        or not isinstance(observed, list)
    ):
        return None
    if (
        semantic.get("status") != "ok"
        or not expected
        or len(expected) != len(observed)
        or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            for value in [*expected, *observed]
        )
    ):
        return None
    max_error = max(
        abs(float(actual) - float(wanted)) for wanted, actual in zip(expected, observed)
    )
    absolute_bits = -math.log2(max(max_error, sys.float_info.epsilon))
    return {
        "event_id": str(event["event_id"]),
        "checkpoint_name": name,
        "absolute_bits": absolute_bits,
        "slot_count": len(expected),
    }


def analyze_precision(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Rank precision drops between compatible shadow-mode checkpoints."""

    require_valid_trace(trace)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    if trace["run"].get("shadow_mode") is not True:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "Precision analysis requires an explicitly enabled shadow-mode run."
            ],
            "findings": [],
        }

    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=event_order,
    )
    checkpoints = [
        record
        for event in events
        if event.get("status") == "ok" and event.get("kind") == "checkpoint"
        for record in [_checkpoint_record(event)]
        if record is not None
    ]
    if len(checkpoints) < 2:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "Fewer than two compatible precision checkpoints were recorded."
            ],
            "findings": [],
        }

    drops: list[dict[str, Any]] = []
    for earlier, later in pairwise(checkpoints):
        if earlier["slot_count"] != later["slot_count"]:
            continue
        bits_lost = earlier["absolute_bits"] - later["absolute_bits"]
        if bits_lost > 0:
            drops.append(
                {
                    "from_checkpoint": earlier["checkpoint_name"],
                    "to_checkpoint": later["checkpoint_name"],
                    "from_absolute_bits": earlier["absolute_bits"],
                    "to_absolute_bits": later["absolute_bits"],
                    "absolute_bits_lost": bits_lost,
                    "slot_count": later["slot_count"],
                    "evidence_event_ids": [earlier["event_id"], later["event_id"]],
                }
            )

    if not drops:
        return {
            **base,
            "analysis_status": "clean",
            "inventory": {"checkpoints": len(checkpoints), "drops": []},
            "findings": [],
        }

    drops.sort(key=lambda item: (-item["absolute_bits_lost"], item["to_checkpoint"]))
    findings = [
        {
            "finding_id": f"finding_precision_{index + 1:04d}",
            "rule_id": RULE_ID,
            "analyzer": "PrecisionAnalyzer",
            "category": "precision",
            "severity": "information",
            "confidence": "measured",
            "source_sites": [],
            "evidence_event_ids": drop["evidence_event_ids"],
            "evidence": drop,
            "applicability": [
                "an explicitly enabled shadow-mode run",
                "two compatible checkpoints with the same slot count",
                "a decrease in absolute precision bits between them",
            ],
            "estimated_impact": {
                "absolute_bits_lost": drop["absolute_bits_lost"],
                "speedup": None,
            },
            "recommendation": (
                "Review the operations between these checkpoints for the dominant "
                "source of precision loss before adjusting scale or depth."
            ),
            "limitations": [
                "Precision is measured only at the configured checkpoints.",
                "A drop can be expected for the computation and is not always a defect.",
                "Recorded values may reveal the data processed by the workload.",
            ],
        }
        for index, drop in enumerate(drops)
    ]
    result = {
        **base,
        "analysis_status": "positive",
        "inventory": {"checkpoints": len(checkpoints), "drops": drops},
        "findings": findings,
    }
    return finalize(result, trace=trace)


__all__ = ["RULE_ID", "analyze_precision"]
