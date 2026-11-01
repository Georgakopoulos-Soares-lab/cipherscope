"""Measure precision loss between recorded checkpoints."""

from __future__ import annotations

import math
import sys
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from ._shared import event_order, finalize, require_valid_trace

RULE_ID = "precision.checkpoint_drop.v1"
TOLERANCE_RULE_ID = "precision.tolerance_violated.v1"
# CKKS decryption is noise-flooded: re-decrypting one ciphertext jitters with
# stdev ~0.68 bits (measured over 40 repetitions, max observed 1.74 bits). A
# 1.0-bit minimum still left a normal-tailed ~5% false-positive rate on that
# jitter alone (confirmed: precision.negative.same_ciphertext failed 2 of 4
# CI runs). 3.0 bits is ~4.4 stdev above that noise floor while staying two
# orders of magnitude below a genuine precision-loss finding (~14 bits for
# three squarings in evaluation/seeded/cases/precision_drop.py).
MIN_BITS_LOST = 3.0


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
    """Rank precision drops between compatible checkpoints."""

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
                "Precision analysis requires a run created with shadow_mode=True."
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
        if bits_lost >= MIN_BITS_LOST:
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
            "inventory": {
                "checkpoints": len(checkpoints),
                "drops": [],
                "min_bits_lost_threshold": MIN_BITS_LOST,
            },
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
            "evidence": {**drop, "min_bits_lost_threshold": MIN_BITS_LOST},
            "applicability": [
                "a run created with shadow_mode=True",
                "two compatible checkpoints with the same slot count",
                f"a decrease of at least {MIN_BITS_LOST:g} absolute precision bits between them",
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
        "inventory": {
            "checkpoints": len(checkpoints),
            "drops": drops,
            "min_bits_lost_threshold": MIN_BITS_LOST,
        },
        "findings": findings,
    }
    return finalize(result, trace=trace)


def _tolerance_record(event: Mapping[str, Any]) -> dict[str, Any] | None:
    semantic = event.get("semantic_arguments")
    if not isinstance(semantic, Mapping) or semantic.get("status") != "ok":
        return None
    status = semantic.get("tolerance_status")
    if status not in {"within", "violated"} or not isinstance(semantic.get("tolerance"), Mapping):
        return None
    return {
        "event_id": str(event["event_id"]),
        "sequence": event.get("sequence"),
        "checkpoint_name": str(semantic.get("checkpoint_name", "")),
        "tolerance": dict(semantic["tolerance"]),
        "tolerance_status": status,
        "violated": list(semantic.get("violated") or []),
        "max_abs_error": semantic.get("max_abs_error"),
        "max_rel_error": semantic.get("max_rel_error"),
        "absolute_bits": semantic.get("absolute_bits"),
    }


def analyze_tolerance(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Report the first checkpoint that breaks its declared tolerance, with the region before it."""

    require_valid_trace(trace)
    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=event_order,
    )
    declared = [
        record
        for event in events
        if event.get("kind") == "checkpoint"
        for record in [_tolerance_record(event)]
        if record is not None
    ]
    if not declared:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "No precision checkpoint declared a tolerance (checkpoint(..., tolerance=...))."
            ],
            "findings": [],
        }
    violated = [record for record in declared if record["tolerance_status"] == "violated"]
    inventory = {"declared_checkpoints": len(declared), "violated_checkpoints": len(violated)}
    if not violated:
        return {**base, "analysis_status": "clean", "inventory": inventory, "findings": []}

    first = violated[0]
    previous = None
    for record in declared:
        if record is first:
            break
        previous = record
    start = -1 if previous is None else int(previous["sequence"])
    end = int(first["sequence"])
    region_ids = [
        str(event["event_id"])
        for event in events
        if event.get("kind") == "crypto_operation"
        and isinstance(event.get("sequence"), int)
        and start < event["sequence"] < end
    ]
    sites = sorted(
        {
            str(event["source"]["call_site_id"])
            for event in events
            if event.get("event_id") in set(region_ids)
            and isinstance(event.get("source"), Mapping)
            and isinstance(event["source"].get("call_site_id"), str)
        }
    )
    evidence = {
        "violated_checkpoint": first["checkpoint_name"],
        "previous_checkpoint": None if previous is None else previous["checkpoint_name"],
        "tolerance": first["tolerance"],
        "violated": first["violated"],
        "max_abs_error": first["max_abs_error"],
        "max_rel_error": first["max_rel_error"],
        "absolute_bits": first["absolute_bits"],
        "region_event_ids": region_ids,
        "later_violations": [record["checkpoint_name"] for record in violated[1:]],
    }
    finding = {
        "finding_id": "finding_tolerance_0001",
        "rule_id": TOLERANCE_RULE_ID,
        "analyzer": "PrecisionAnalyzer",
        "category": "precision",
        "severity": "warning",
        "confidence": "measured",
        "source_sites": sites,
        "evidence_event_ids": [first["event_id"], *region_ids],
        "evidence": evidence,
        "applicability": [
            "a run created with shadow_mode=True",
            "a checkpoint with a developer-declared tolerance",
            "an observed error outside that tolerance",
        ],
        "recommendation": (
            f"Checkpoint {first['checkpoint_name']!r} is the first to exceed its declared "
            "tolerance; review the operations between it and the previous checkpoint for "
            "the source of the loss."
        ),
        "limitations": [
            "The tolerance is the developer's contract, not a correctness proof.",
            "Localization is to the region between checkpoints, not to one operation.",
            "Recorded values may reveal the data processed by the workload.",
        ],
    }
    result = {**base, "analysis_status": "positive", "inventory": inventory, "findings": [finding]}
    return finalize(result, trace=trace)


__all__ = ["MIN_BITS_LOST", "RULE_ID", "TOLERANCE_RULE_ID", "analyze_precision", "analyze_tolerance"]
