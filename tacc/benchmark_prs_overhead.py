#!/usr/bin/env python3
"""Measure CipherScope's overhead on the PRS cohort-scoring program.

Two arms, same crypto workload (imported directly from prs_dot_product.py,
not duplicated):
  * baseline -> run_cohort() called with the raw native context, session=None
  * traced   -> run_cohort() called inside a cipherscope.trace() session

Each arm is repeated with warmups dropped, and each arm is additionally run
once under cProfile so you can see where time actually goes.

Usage (PYTHONPATH must include cipherscope/src; run in the same environment
build_openfhe_ls6.sh set up -- same modules, same LD_LIBRARY_PATH):

    python3.11 benchmark_prs_overhead.py --repeats 10 --warmup 2 \
        --output prs-bench-results
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import pstats
import statistics
import time
from pathlib import Path
from typing import Any, Callable

import cipherscope
import prs_dot_product as prs


def _time_once(fn: Callable[[], Any]) -> tuple[float, float]:
    w0, c0 = time.perf_counter_ns(), time.process_time_ns()
    fn()
    return time.perf_counter_ns() - w0, time.process_time_ns() - c0


def _summarize(samples_ns: list[float]) -> dict[str, float]:
    return {
        "n": len(samples_ns),
        "median_ms": statistics.median(samples_ns) / 1e6,
        "mean_ms": statistics.fmean(samples_ns) / 1e6,
        "stdev_ms": (statistics.stdev(samples_ns) / 1e6) if len(samples_ns) > 1 else 0.0,
        "min_ms": min(samples_ns) / 1e6,
        "max_ms": max(samples_ns) / 1e6,
    }


def bench_arm(name: str, call: Callable[[], Any], repeats: int, warmup: int) -> dict:
    for _ in range(warmup):
        call()
    walls, cpus = [], []
    for _ in range(repeats):
        w, c = _time_once(call)
        walls.append(w)
        cpus.append(c)
    return {"name": name, "wall": _summarize(walls), "cpu": _summarize(cpus)}


def profile_arm(name: str, call: Callable[[], Any], out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    profiler = cProfile.Profile()
    profiler.enable()
    call()
    profiler.disable()
    profiler.dump_stats(str(out_dir / f"{name}.prof"))
    buf = io.StringIO()
    pstats.Stats(profiler, stream=buf).strip_dirs().sort_stats("cumulative").print_stats(30)
    top_path = out_dir / f"{name}.top.txt"
    top_path.write_text(buf.getvalue(), encoding="utf-8")
    return str(top_path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--output", type=Path, default=Path("prs-bench-results"))
    args = ap.parse_args()

    # Context/keys built once, outside the measured region, and shared by
    # both arms so key generation cost never pollutes the comparison.
    context, keys = prs.build_context()

    def baseline_call() -> None:
        prs.run_cohort(context, keys, session=None)

    def traced_call() -> None:
        with cipherscope.trace(context, name="prs_overhead_bench") as session:
            prs.run_cohort(session.context, keys, session)

    baseline = bench_arm("baseline", baseline_call, args.repeats, args.warmup)
    traced = bench_arm("traced", traced_call, args.repeats, args.warmup)

    b_ms = baseline["wall"]["median_ms"]
    t_ms = traced["wall"]["median_ms"]
    overhead_pct = ((t_ms - b_ms) / b_ms * 100.0) if b_ms else float("nan")

    args.output.mkdir(parents=True, exist_ok=True)
    baseline_top = profile_arm("baseline", baseline_call, args.output)
    traced_top = profile_arm("traced", traced_call, args.output)

    result = {
        "config": {
            "repeats": args.repeats,
            "warmup": args.warmup,
            "block_size": prs.BLOCK_SIZE,
            "num_blocks": prs.NUM_BLOCKS,
            "num_patients": prs.NUM_PATIENTS,
        },
        "baseline": baseline,
        "traced": traced,
        "overhead": {
            "median_wall_delta_ms": t_ms - b_ms,
            "median_wall_overhead_pct": overhead_pct,
        },
        "profiles": {"baseline_top": baseline_top, "traced_top": traced_top},
    }
    (args.output / "prs_overhead.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(
        {
            "baseline_median_ms": round(b_ms, 3),
            "traced_median_ms": round(t_ms, 3),
            "overhead_pct": round(overhead_pct, 2),
        },
        indent=2,
    ))
    print(f"\nWrote {args.output / 'prs_overhead.json'} and cProfile top-30 tables.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
