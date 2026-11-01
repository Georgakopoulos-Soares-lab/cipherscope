#!/usr/bin/env python3
"""Summarize evaluation/raw/native_overhead.csv as a Markdown table.

Per size: median plain loop time, median hooks and full loop times, their
ratios to plain, median peak RSS per arm, and spool bytes per event. Only the
ratios and bytes per event are comparable across machines.
"""

from __future__ import annotations

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main(path: Path = ROOT / "evaluation" / "raw" / "native_overhead.csv") -> int:
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    for allocator in sorted({row.get("allocator", "glibc-default") for row in rows}):
        print(f"\n### allocator: {allocator}\n")
        _table([row for row in rows if row.get("allocator", "glibc-default") == allocator])
    return 0


def _table(rows: list[dict[str, str]]) -> None:
    groups: dict[tuple[int, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(int(row["size"]), row["arm"])].append(row)
    sizes = sorted({size for size, _ in groups})
    print("| events | plain loop ms | hooks loop ms | hooks / plain | full loop ms | full / plain | plain peak MB | full peak MB | spool bytes / event | runs |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for size in sizes:
        def med(arm: str, column: str) -> float | None:
            values = [float(r[column]) for r in groups.get((size, arm), []) if r.get(column)]
            return statistics.median(values) if values else None
        plain, hooks, full = med("plain", "loop_ms"), med("hooks", "loop_ms"), med("full", "loop_ms")
        per_event = None
        full_rows = groups.get((size, "full"), [])
        if full_rows and full_rows[0].get("spool_bytes"):
            per_event = statistics.median(int(r["spool_bytes"]) / (int(r["events"]) or 1) for r in full_rows)
        ratio = lambda a, b: f"{a / b:.3f}" if a and b else "—"
        fmt = lambda v: f"{v:.0f}" if v is not None else "—"
        print(f"| {size} | {fmt(plain)} | {fmt(hooks)} | {ratio(hooks, plain)} | {fmt(full)} | {ratio(full, plain)} | "
              f"{fmt(med('plain', 'peak_rss_mb'))} | {fmt(med('full', 'peak_rss_mb'))} | {fmt(per_event)} | {len(groups.get((size, 'plain'), []))} |")


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evaluation" / "raw" / "native_overhead.csv"))
