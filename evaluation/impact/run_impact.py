#!/usr/bin/env python3
"""Before/after impact of every actionable CipherScope rule, measured.

For each case under cases/ (one per rule), both variants are run in fresh
processes:

  1. once traced through CipherScope, to prove the rule fires on `before`
     and is silent on `after` (the run is rejected otherwise), and to
     collect trace-level metrics (events, ciphertext versions, critical-path
     depth, levels consumed, per-operation counts);
  2. `--repeat` times untraced and timed (prepare / setup / workload phases,
     peak RSS, max abs error against the plaintext reference).

Every repetition's numbers go to evaluation/raw/impact.csv (long format);
evaluation/impact/summarize.py turns that into evaluation/tables/impact.csv.

    source ls6_env.sh
    OMP_NUM_THREADS=1 python3 evaluation/impact/run_impact.py --repeat 7
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

CASES = (
    "keys_unused",
    "rotation_hoist",
    "encoding_repeated",
    "packing_low",
    "provenance_public_ct",
    "serial_reduction",
    "depth_headroom",
    "bootstrap_underused",
    "precision_tolerance",
    "security_config",
)

RAW_COLUMNS = (
    "case", "rule", "variant", "mode", "repetition",
    "prepare_ms", "setup_ms", "workload_ms", "total_ms", "peak_rss_mb", "max_abs_error", "ring_dimension",
    "rule_status", "rule_findings", "coverage_class", "events", "semantic_calls", "ciphertext_versions",
    "max_nonlinear_depth", "max_levels_consumed", "configured_depth", "operations", "extra",
    "python_version", "machine", "omp_num_threads",
)

CLEAN = {"clean", "not_applicable"}


def _run(args: list[str]) -> dict:
    completed = subprocess.run([sys.executable, str(HERE / "runner.py"), *args], capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(f"runner failed: {' '.join(args)}\n{completed.stderr[-4000:]}")
    line = [l for l in completed.stdout.splitlines() if l.startswith("{")][-1]
    return json.loads(line)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=7)
    parser.add_argument("--cases", nargs="*", default=list(CASES))
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "raw" / "impact.csv")
    parser.add_argument("--bundles", type=Path, default=ROOT / "cipherscope-results" / "impact")
    args = parser.parse_args(argv)

    import os
    env_columns = {
        "python_version": platform.python_version(),
        "machine": platform.machine(),
        "omp_num_threads": os.environ.get("OMP_NUM_THREADS", ""),
    }
    if args.bundles.exists():
        shutil.rmtree(args.bundles)
    args.bundles.mkdir(parents=True)

    rows: list[dict] = []
    verification: list[tuple[str, str, str, str, bool]] = []
    for case in args.cases:
        for variant in ("before", "after"):
            bundle = args.bundles / f"{case}_{variant}"
            traced = _run([case, variant, "traced", "--bundle", str(bundle)])
            (bundle / "impact_report.json").write_text(json.dumps(traced, indent=2, default=str))
            status = traced["rule_status"]
            expected_ok = status == "positive" if variant == "before" else status in CLEAN
            verification.append((case, traced["rule"], variant, status, expected_ok))
            print(f"[traced] {case:22s} {variant:6s} {traced['rule']:45s} -> {status:14s} "
                  f"{'OK' if expected_ok else 'UNEXPECTED'}  events={traced['events']} depth={traced['max_nonlinear_depth']} "
                  f"levels={traced['max_levels_consumed']} ring={traced['ring_dimension']}", flush=True)
            rows.append({
                "case": case, "rule": traced["rule"], "variant": variant, "mode": "traced", "repetition": 0,
                "rule_status": status, "rule_findings": traced["rule_findings"], "coverage_class": traced["coverage_class"],
                "events": traced["events"], "semantic_calls": traced["semantic_calls"],
                "ciphertext_versions": traced["ciphertext_versions"], "max_nonlinear_depth": traced["max_nonlinear_depth"],
                "max_levels_consumed": traced["max_levels_consumed"], "configured_depth": traced["configured_depth"],
                "ring_dimension": traced["ring_dimension"], "max_abs_error": traced["max_abs_error"],
                "operations": json.dumps(traced["operations"], sort_keys=True),
                "extra": json.dumps({k[6:]: v for k, v in traced.items() if k.startswith("extra.")}, sort_keys=True),
                **env_columns,
            })
            for repetition in range(args.repeat):
                timed = _run([case, variant, "timed"])
                rows.append({
                    "case": case, "rule": timed["rule"], "variant": variant, "mode": "timed", "repetition": repetition,
                    "prepare_ms": f"{timed['prepare_ms']:.3f}", "setup_ms": f"{timed['setup_ms']:.3f}",
                    "workload_ms": f"{timed['workload_ms']:.3f}", "total_ms": f"{timed['total_ms']:.3f}",
                    "peak_rss_mb": f"{timed['peak_rss_mb']:.2f}", "max_abs_error": f"{timed['max_abs_error']:.3e}",
                    "ring_dimension": timed["ring_dimension"],
                    "extra": json.dumps({k[6:]: v for k, v in timed.items() if k.startswith("extra.")}, sort_keys=True),
                    **env_columns,
                })
            if args.repeat:
                print(f"[timed ] {case:22s} {variant:6s} x{args.repeat}: last total={timed['total_ms']:.1f} ms "
                      f"(prepare {timed['prepare_ms']:.1f} / setup {timed['setup_ms']:.1f} / workload {timed['workload_ms']:.1f}) "
                      f"peak RSS {timed['peak_rss_mb']:.1f} MB", flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in RAW_COLUMNS})
    print(f"wrote {len(rows)} rows to {args.output}")

    failed = [v for v in verification if not v[4]]
    print("\nRule verification:")
    for case, rule, variant, status, ok in verification:
        print(f"  {'OK ' if ok else 'BAD'} {case:22s} {variant:6s} {rule:45s} {status}")
    if failed:
        print(f"\n{len(failed)} variant(s) did not behave as required (before must be positive, after clean).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
