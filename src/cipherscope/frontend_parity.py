"""Compare traces of the same workload recorded by different frontends.

The engineering test for the language-neutral trace is: if an equivalent
Python and C++ program produce traces, `build_analysis_bundle` must reach the
same graph and analyzer conclusions modulo identifiers, timing, source paths
and frontend provenance. This module reduces a trace to the semantic
signature that must agree and reports every difference.

Compared: event kind/operation/overload sequence, operand kinds, ciphertext
lineage (as first-appearance indices, not IDs), level/noise-degree/slot
transitions, semantic arguments (rotation indices, batch sizes, ...), analyzer
statuses and finding rule IDs. Ignored: event/ciphertext IDs, timings, thread
IDs, source files/lines/site IDs, run metadata, key tags, scales.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .pipeline import analyze_trace

# Operand labels whose position carries meaning for the analyzers; scalar
# tails (defaulted C++ parameters) are not part of the semantic signature.
_STRUCTURAL_KINDS = {"ciphertext", "plaintext", "key", "rotation_indices", "plaintext_values", "slot_count"}


@dataclass
class ParityReport:
    differences: list[str] = field(default_factory=list)
    left_signature: list[dict[str, Any]] = field(default_factory=list)
    right_signature: list[dict[str, Any]] = field(default_factory=list)

    @property
    def equivalent(self) -> bool:
        return not self.differences


def _lineage_map(trace: Mapping[str, Any]) -> dict[str, int]:
    order: dict[str, int] = {}
    for event in sorted(trace.get("events") or (), key=lambda e: e["sequence"]):
        for ct in list(event.get("input_ciphertexts") or ()) + list(event.get("output_ciphertexts") or ()):
            base = str(ct).partition(":v")[0]
            order.setdefault(base, len(order))
    return order


def _relative(ct: str, order: Mapping[str, int]) -> str:
    base, _, version = str(ct).partition(":v")
    return f"#{order.get(base, -1)}:v{version or '0'}"


def _state_signature(state: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not state:
        return None
    return {"level": state.get("level"), "noise_scale_degree": state.get("noise_scale_degree"), "slots": state.get("slots")}


def semantic_signature(trace: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The producer-independent content of every event, in order."""

    order = _lineage_map(trace)
    signature: list[dict[str, Any]] = []
    for event in sorted(trace.get("events") or (), key=lambda e: e["sequence"]):
        operands = [k for k in (event.get("operand_kinds") or ()) if k in _STRUCTURAL_KINDS]
        signature.append({
            "kind": event.get("kind"),
            "operation": event.get("operation"),
            "overload": event.get("overload"),
            "status": event.get("status"),
            "operands": operands,
            "inputs": [_relative(ct, order) for ct in event.get("input_ciphertexts") or ()],
            "outputs": [_relative(ct, order) for ct in event.get("output_ciphertexts") or ()],
            "input_states": [_state_signature(s) for s in event.get("input_states") or ()],
            "output_states": [_state_signature(s) for s in event.get("output_states") or ()],
            "semantic_arguments": dict(event.get("semantic_arguments") or {}),
        })
    return signature


def analysis_signature(trace: Mapping[str, Any]) -> dict[str, Any]:
    result = analyze_trace(trace)
    return {
        "analysis_status": result["analysis_status"],
        "analyzer_status": dict(sorted(result["analyzer_status"].items())),
        "findings": sorted(f["rule_id"] for f in result["findings"]),
    }


def compare_traces(left: Mapping[str, Any], right: Mapping[str, Any], *, left_name: str = "left", right_name: str = "right") -> ParityReport:
    report = ParityReport()
    report.left_signature = semantic_signature(left)
    report.right_signature = semantic_signature(right)
    if len(report.left_signature) != len(report.right_signature):
        report.differences.append(
            f"event count differs: {left_name}={len(report.left_signature)}, {right_name}={len(report.right_signature)}"
        )
    for index, (a, b) in enumerate(zip(report.left_signature, report.right_signature), start=1):
        for key in a:
            if a[key] != b.get(key):
                report.differences.append(
                    f"event {index} ({a['operation']}) {key}: {left_name}={json.dumps(a[key], sort_keys=True)} {right_name}={json.dumps(b.get(key), sort_keys=True)}"
                )
    left_context = {k: (left.get("context") or {}).get(k) for k in ("ring_dimension", "batch_size", "configured_multiplicative_depth", "scaling_technique", "key_switch_technique", "security_level")}
    right_context = {k: (right.get("context") or {}).get(k) for k in left_context}
    for key, value in left_context.items():
        if value != right_context[key]:
            report.differences.append(f"context {key}: {left_name}={value!r} {right_name}={right_context[key]!r}")
    left_analysis = analysis_signature(left)
    right_analysis = analysis_signature(right)
    for key in ("analysis_status", "analyzer_status", "findings"):
        if left_analysis[key] != right_analysis[key]:
            report.differences.append(
                f"{key}: {left_name}={json.dumps(left_analysis[key], sort_keys=True)} {right_name}={json.dumps(right_analysis[key], sort_keys=True)}"
            )
    return report


def render_markdown(report: ParityReport, left_name: str, right_name: str) -> str:
    lines = [f"# Frontend parity: {left_name} vs {right_name}", ""]
    lines.append("**Equivalent.**" if report.equivalent else f"**{len(report.differences)} difference(s).**")
    lines.append("")
    if report.differences:
        lines += ["## Differences", ""] + [f"- {d}" for d in report.differences] + [""]
    lines += ["## Semantic signature", "", "| # | operation | overload | operands | inputs | outputs | out level/noise | semantic arguments |", "|---|---|---|---|---|---|---|---|"]
    for index, (a, b) in enumerate(zip(report.left_signature, report.right_signature), start=1):
        same = a == b
        out = a["output_states"][0] if a["output_states"] else None
        state = "" if not out else f"{out['level']}/{out['noise_scale_degree']}"
        arguments = json.dumps(a["semantic_arguments"], sort_keys=True) if a["semantic_arguments"] else ""
        mark = "" if same else " ✗"
        lines.append(
            f"| {index}{mark} | {a['operation']} | {a['overload']} | {', '.join(a['operands'])} | "
            f"{', '.join(a['inputs'])} | {', '.join(a['outputs'])} | {state} | {arguments} |"
        )
    return "\n".join(lines) + "\n"


__all__ = ["ParityReport", "analysis_signature", "compare_traces", "render_markdown", "semantic_signature"]
