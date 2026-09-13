"""Export recorded events as CSV."""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping
from typing import Any

FIELDS = (
    "sequence",
    "event_id",
    "kind",
    "operation",
    "overload",
    "status",
    "source_file",
    "source_line",
    "source_function",
    "input_ciphertexts",
    "output_ciphertexts",
    "wall_duration_ns",
    "process_cpu_duration_ns",
)


def _spreadsheet_safe(value: object) -> object:
    """Keep spreadsheet programs from treating trace text as a formula."""

    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def operations_csv(trace: Mapping[str, Any]) -> str:
    """Return a CSV table of recorded events."""

    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    events = sorted(trace.get("events", ()), key=lambda event: event["sequence"])
    for event in events:
        source = event.get("source") or {}
        timing = event.get("timing") or {}
        row = {
            "sequence": event.get("sequence"),
            "event_id": event.get("event_id"),
            "kind": event.get("kind"),
            "operation": event.get("operation"),
            "overload": event.get("overload"),
            "status": event.get("status"),
            "source_file": source.get("file"),
            "source_line": source.get("line"),
            "source_function": source.get("function"),
            "input_ciphertexts": ";".join(event.get("input_ciphertexts", ())),
            "output_ciphertexts": ";".join(event.get("output_ciphertexts", ())),
            "wall_duration_ns": timing.get("wall_duration_ns"),
            "process_cpu_duration_ns": timing.get("process_cpu_duration_ns"),
        }
        writer.writerow({key: _spreadsheet_safe(value) for key, value in row.items()})
    return stream.getvalue()
