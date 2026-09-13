"""Export events in Perfetto's Chrome Trace Event format."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def perfetto_document(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Convert recorded calls to complete-duration Perfetto events.

    Perfetto uses microseconds, while the source trace uses nanoseconds.
    """

    projected: list[dict[str, Any]] = []
    for event in sorted(trace.get("events", ()), key=lambda item: item["sequence"]):
        timing = event.get("timing") or {}
        source = event.get("source") or {}
        projected.append(
            {
                "name": event.get("operation", "unknown"),
                "cat": "cipherscope.openfhe_api",
                "ph": "X",
                "ts": timing.get("start_ns", 0) / 1_000,
                "dur": timing.get("wall_duration_ns", 0) / 1_000,
                "pid": 1,
                "tid": event.get("thread_id", 0),
                "args": {
                    "event_id": event.get("event_id"),
                    "status": event.get("status"),
                    "source_file": source.get("file"),
                    "source_line": source.get("line"),
                    "overload": event.get("overload"),
                    "inputs": list(event.get("input_ciphertexts", ())),
                    "outputs": list(event.get("output_ciphertexts", ())),
                },
            }
        )
    return {
        "displayTimeUnit": "ns",
        "traceEvents": projected,
        "metadata": {
            "run_id": (trace.get("run") or {}).get("run_id"),
            "projection": "visualization_only",
            "synthetic_contract": bool(
                (trace.get("run") or {}).get("synthetic_contract", False)
            ),
        },
    }
