#!/usr/bin/env python3
"""Compare current memory use for untraced and traced PRS workloads.

Each arm runs in a separate process so one arm cannot raise the other's memory
baseline. Current resident memory (RSS) is sampled before the workload and after
each block, then written to CSV.

Usage:
    python3.11 memory_profile_prs.py --output prs-memory-results
"""

from __future__ import annotations

import argparse
import csv
import os
import subprocess
import sys
from pathlib import Path
from typing import Literal

import cipherscope

Arm = Literal["baseline", "traced"]


def current_rss_kb(statm: Path = Path("/proc/self/statm")) -> int:
    """Return the process's current resident memory in KiB."""

    if statm.is_file():
        try:
            resident_pages = int(statm.read_text(encoding="utf-8").split()[1])
            return resident_pages * os.sysconf("SC_PAGE_SIZE") // 1024
        except (IndexError, OSError, ValueError):
            pass

    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        rss_kb = int(completed.stdout.strip())
    except ValueError as error:
        raise RuntimeError("ps did not return a numeric RSS value") from error
    if rss_kb <= 0:
        raise RuntimeError("current RSS must be positive")
    return rss_kb


def run_baseline_with_sampling(context, keys) -> list[tuple[int, int]]:
    import prs_dot_product as prs

    samples = [(0, current_rss_kb())]

    def on_block(block_index: int) -> None:
        samples.append((block_index, current_rss_kb()))

    prs.run_cohort(context, keys, session=None, on_block=on_block)
    return samples


def run_traced_with_sampling(context, keys) -> list[tuple[int, int]]:
    import prs_dot_product as prs

    samples = [(0, current_rss_kb())]

    def on_block(block_index: int) -> None:
        samples.append((block_index, current_rss_kb()))

    with cipherscope.trace(context, name="prs_memory_profile") as session:
        prs.run_cohort(session.context, keys, session, on_block=on_block)
    return samples


def write_csv(path: Path, samples: list[tuple[int, int]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["block_index", "current_rss_kb"])
        writer.writerows(samples)


def summarize(name: str, samples: list[tuple[int, int]]) -> None:
    if not samples:
        print(f"{name}: no RSS samples")
        return

    first_block, first_rss = samples[0]
    last_block, last_rss = samples[-1]
    total_blocks = last_block - first_block
    growth_kb = last_rss - first_rss
    per_block_kb = growth_kb / total_blocks if total_blocks else 0.0
    print(
        f"{name}: current RSS {first_rss / 1024:.1f} MiB (block {first_block}) -> "
        f"{last_rss / 1024:.1f} MiB (block {last_block}); "
        f"changed by {growth_kb / 1024:.1f} MiB over {total_blocks} blocks "
        f"({per_block_kb:.2f} KiB/block)"
    )


def run_arm(arm: Arm, output: Path) -> None:
    """Build a fresh OpenFHE context and profile one arm in this process."""

    import prs_dot_product as prs

    output.mkdir(parents=True, exist_ok=True)
    context, keys = prs.build_context()
    if arm == "baseline":
        samples = run_baseline_with_sampling(context, keys)
    else:
        samples = run_traced_with_sampling(context, keys)
    write_csv(output / f"{arm}_memory.csv", samples)
    summarize(arm, samples)


def run_arm_in_subprocess(arm: Arm, output: Path) -> None:
    """Run one arm in a new process with its own RSS history."""

    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--output",
            str(output.resolve()),
            "--arm",
            arm,
        ],
        check=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=Path("prs-memory-results"))
    ap.add_argument("--arm", choices=("baseline", "traced"), help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    if args.arm is not None:
        run_arm(args.arm, args.output)
        return 0

    run_arm_in_subprocess("baseline", args.output)
    run_arm_in_subprocess("traced", args.output)

    print(f"\nWrote {args.output / 'baseline_memory.csv'} and 'traced_memory.csv'")
    print(
        "Compare current RSS after the initial warm-up. A traced curve that keeps\n"
        "rising while the baseline settles indicates retained tracing state."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
