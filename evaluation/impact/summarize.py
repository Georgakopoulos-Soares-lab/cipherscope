#!/usr/bin/env python3
"""evaluation/raw/impact.csv -> evaluation/tables/impact.csv (+ a console report).

One row per case. Timed metrics are medians over the repetitions; trace
metrics come from the single traced run. Ratios are before/after, so > 1 is
an improvement for time, memory and counts. `headline` names the metric(s)
the rule is about and states the measured change; the other columns are
the full picture, including where a fix costs something.

Deliberately outside cipherscope.tables / results.schema.json: these are
designed demonstration programs (evaluation/impact/cases), not adjudicated
findings from the external corpus. Run by `make tables`.
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
RAW = ROOT / "evaluation" / "raw" / "impact.csv"
OUT = ROOT / "evaluation" / "tables" / "impact.csv"

TIMED = ("prepare_ms", "setup_ms", "workload_ms", "total_ms", "peak_rss_mb")
TRACED = ("events", "ciphertext_versions", "max_nonlinear_depth", "max_levels_consumed", "configured_depth", "ring_dimension")

# Which metrics each rule is *about*; everything else is reported as context/cost.
HEADLINE = {
    "keys_unused": ("setup_ms", "peak_rss_mb"),
    "rotation_hoist": ("workload_ms",),
    "encoding_repeated": ("workload_ms", "events"),
    "packing_low": ("workload_ms", "events", "ciphertext_versions"),
    "provenance_public_ct": ("workload_ms",),
    "serial_reduction": ("max_levels_consumed", "ring_dimension", "total_ms", "peak_rss_mb"),
    "depth_headroom": ("ring_dimension", "total_ms", "peak_rss_mb"),
    "bootstrap_underused": ("total_ms", "peak_rss_mb"),
    "precision_tolerance": ("final_absolute_bits", "tolerance_met"),
    "security_config": ("security_bits", "total_ms", "peak_rss_mb"),
}
LOWER_IS_BETTER = set(TIMED) | {"events", "ciphertext_versions", "max_nonlinear_depth", "max_levels_consumed", "configured_depth", "ring_dimension"}


def _f(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def summarize(raw_path: Path) -> list[dict]:
    with raw_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    by_case: dict[str, dict[str, dict]] = defaultdict(lambda: {"before": {"timed": [], "traced": None}, "after": {"timed": [], "traced": None}})
    order: list[str] = []
    for row in rows:
        if row["case"] not in order:
            order.append(row["case"])
        slot = by_case[row["case"]][row["variant"]]
        if row["mode"] == "timed":
            slot["timed"].append(row)
        else:
            slot["traced"] = row

    out = []
    for case in order:
        variants = by_case[case]
        rule = (variants["before"]["traced"] or variants["before"]["timed"][0])["rule"]
        record: dict = {"case": case, "rule": rule}
        metrics: dict[str, dict[str, float | None]] = {}
        for variant in ("before", "after"):
            timed, traced = variants[variant]["timed"], variants[variant]["traced"]
            record[f"{variant}_status"] = traced["rule_status"] if traced else ""
            record[f"{variant}_repetitions"] = len(timed)
            for metric in TIMED:
                values = [_f(r[metric]) for r in timed if _f(r[metric]) is not None]
                metrics.setdefault(metric, {})[variant] = statistics.median(values) if values else None
            for metric in TRACED:
                metrics.setdefault(metric, {})[variant] = _f(traced[metric]) if traced else None
            extras: dict = {}
            for r in [*timed, *([traced] if traced else [])]:
                try:
                    extras.update(json.loads(r.get("extra") or "{}"))
                except json.JSONDecodeError:
                    pass
            for key, value in extras.items():
                metrics.setdefault(key, {})[variant] = _f(value)
            errors = [_f(r["max_abs_error"]) for r in timed if _f(r["max_abs_error"]) is not None]
            record[f"{variant}_max_abs_error"] = f"{max(errors):.2e}" if errors else ""

        for metric, values in metrics.items():
            b, a = values.get("before"), values.get("after")
            record[f"{metric}_before"] = "" if b is None else (f"{b:.3f}" if isinstance(b, float) and not b.is_integer() else f"{b:g}")
            record[f"{metric}_after"] = "" if a is None else (f"{a:.3f}" if isinstance(a, float) and not a.is_integer() else f"{a:g}")
            if b is not None and a is not None and a != 0 and metric in LOWER_IS_BETTER:
                record[f"{metric}_ratio"] = f"{b / a:.3f}"
            else:
                record[f"{metric}_ratio"] = ""

        parts = []
        for metric in HEADLINE.get(case, ()):
            values = metrics.get(metric, {})
            b, a = values.get("before"), values.get("after")
            if b is None or a is None:
                continue
            if metric in LOWER_IS_BETTER:
                word = "better" if a < b else ("worse" if a > b else "same")
                ratio = f"{b / a:.2f}x" if a else "inf"
                parts.append(f"{metric} {b:g} -> {a:g} ({ratio} {word})")
            else:
                parts.append(f"{metric} {b:g} -> {a:g}")
        record["headline"] = "; ".join(parts)
        out.append(record)
    return out


def main() -> int:
    if not RAW.is_file():
        print(f"impact summarize: {RAW} does not exist yet; run evaluation/impact/run_impact.py first. Skipping.", file=sys.stderr)
        return 0
    rows = summarize(RAW)
    columns: list[str] = []
    for row in rows:
        for key in row:
            if key not in columns:
                columns.append(key)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})
    print(f"wrote {len(rows)} rows to {OUT}\n")
    for row in rows:
        print(f"{row['case']:22s} {row['rule']}\n   before={row['before_status']} after={row['after_status']}  {row['headline']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
