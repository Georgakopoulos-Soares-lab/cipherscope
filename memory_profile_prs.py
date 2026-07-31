#!/usr/bin/env python3
"""Test whether CipherScope's memory footprint grows with total ciphertexts
ever created (not just those currently alive), as the registry.py code
suggests -- every ciphertext registered in `_identities` is held with a
strong reference for the whole session, with no eviction.

Samples peak resident memory (RSS) once per block, for both an untraced
baseline run and a traced run, and writes both curves to CSV so growth can
be inspected directly (e.g. plotted, or just eyeballed for linearity).

Usage:
    python3.11 memory_profile_prs.py --output prs-memory-results
"""

from __future__ import annotations

import argparse
import csv
import resource
from pathlib import Path

import cipherscope
import prs_dot_product as prs


def peak_rss_kb() -> int:
    """Peak RSS so far, in KB on Linux (ru_maxrss is monotonic non-decreasing,
    so this is a clean signal for "has memory grown", not just "how much is
    in use right now")."""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def run_baseline_with_sampling(context, keys) -> list[tuple[int, int]]:
    samples: list[tuple[int, int]] = []

    def on_block(block_index: int) -> None:
        samples.append((block_index, peak_rss_kb()))

    prs.run_cohort(context, keys, session=None, on_block=on_block)
    return samples


def run_traced_with_sampling(context, keys) -> list[tuple[int, int]]:
    samples: list[tuple[int, int]] = []

    def on_block(block_index: int) -> None:
        samples.append((block_index, peak_rss_kb()))

    with cipherscope.trace(context, name="prs_memory_profile") as session:
        prs.run_cohort(session.context, keys, session, on_block=on_block)
    return samples


def write_csv(path: Path, samples: list[tuple[int, int]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["block_index", "peak_rss_kb"])
        writer.writerows(samples)


def summarize(name: str, samples: list[tuple[int, int]]) -> None:
    first_block, first_rss = samples[0]
    last_block, last_rss = samples[-1]
    total_blocks = last_block - first_block
    growth_kb = last_rss - first_rss
    per_block_kb = growth_kb / total_blocks if total_blocks else 0.0
    print(
        f"{name}: RSS {first_rss/1024:.1f} MB (block {first_block}) -> "
        f"{last_rss/1024:.1f} MB (block {last_block}); "
        f"grew {growth_kb/1024:.1f} MB over {total_blocks} blocks "
        f"({per_block_kb:.2f} KB/block)"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=Path("prs-memory-results"))
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    context, keys = prs.build_context()

    baseline_samples = run_baseline_with_sampling(context, keys)
    write_csv(args.output / "baseline_memory.csv", baseline_samples)
    summarize("baseline", baseline_samples)

    traced_samples = run_traced_with_sampling(context, keys)
    write_csv(args.output / "traced_memory.csv", traced_samples)
    summarize("traced", traced_samples)

    print(f"\nWrote {args.output / 'baseline_memory.csv'} and 'traced_memory.csv'")
    print(
        "If per-block KB/block is roughly flat, memory is well-behaved.\n"
        "If the LATER blocks show a visibly higher per-block growth rate\n"
        "than the earlier ones (check e.g. rows 10 vs rows near the end),\n"
        "that confirms retained ciphertexts are compounding, not just adding\n"
        "up linearly for an expected/fixed reason."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
