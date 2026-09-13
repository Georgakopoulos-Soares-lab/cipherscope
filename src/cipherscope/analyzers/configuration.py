"""Report when OpenFHE's standard security-level enforcement was disabled."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._shared import finalize, require_valid_trace

RULE_ID = "configuration.testing_only_security.v1"
TESTING_ONLY_LEVEL = "HEStd_NotSet"


def analyze_configuration(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Flag a declared HEStd_NotSet security level as a testing-only configuration."""

    require_valid_trace(trace)
    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    context = trace.get("context") or {}
    security_level = context.get("security_level")
    if not isinstance(security_level, str) or not security_level:
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                (
                    "The security level is not readable from a live context; declare it "
                    "with trace(..., parameters=params) or attach(..., parameters=params)."
                )
            ],
            "findings": [],
        }
    inventory = {
        "security_level": security_level,
        "ring_dimension": context.get("ring_dimension"),
        "declared_ring_dimension": context.get("declared_ring_dimension"),
        "configured_multiplicative_depth": context.get("configured_multiplicative_depth"),
    }
    if security_level != TESTING_ONLY_LEVEL:
        return {**base, "analysis_status": "clean", "inventory": inventory, "findings": []}

    acknowledged = trace["run"].get("testing_security_acknowledged") is True
    finding = {
        "finding_id": "finding_configuration_0001",
        "rule_id": RULE_ID,
        "analyzer": "ConfigurationAnalyzer",
        "category": "configuration",
        "severity": "information" if acknowledged else "warning",
        "confidence": "measured",
        "source_sites": [],
        "evidence_event_ids": [],
        "evidence": {**inventory, "acknowledged": acknowledged},
        "applicability": [
            "a security level declared through the session's parameters",
            "HEStd_NotSet, which disables OpenFHE's standard security-level enforcement",
        ],
        "recommendation": (
            "This run disabled OpenFHE's standard security-level enforcement "
            "(HEStd_NotSet). That is a testing-only configuration; confirm it is not "
            "used where real data needs protection."
        ),
        "limitations": [
            (
                "This is a configuration observation, not a bit-security estimate; "
                "CipherScope never estimates security."
            ),
            (
                "A declared standard level is not verified against the ring dimension "
                "or modulus chain."
            ),
            (
                "The level comes from the parameters the program declared, not from the "
                "context itself."
            ),
        ],
    }
    result = {
        **base,
        "analysis_status": "positive",
        "inventory": inventory,
        "findings": [finding],
    }
    return finalize(result, trace=trace)


__all__ = ["RULE_ID", "TESTING_ONLY_LEVEL", "analyze_configuration"]
