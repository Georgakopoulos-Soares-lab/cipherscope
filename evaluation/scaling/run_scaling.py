#!/usr/bin/env python3
"""Run the scaling kernel once per (size, arm) in a fresh process and append raw rows.

Each point is its own process so that peak RSS belongs to that point alone.
Appends to evaluation/raw/scaling.csv (the record is defined in
evaluation/schema/results.schema.json).
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLUMNS = (
    "size", "arm", "repetition", "events", "run_wall_ms", "rss_start_mb", "rss_end_mb",
    "rss_growth_mb", "peak_rss_mb", "finalize_ms", "analyze_ms", "trace_bytes",
    "graph_bytes", "recommendations_bytes", "spooled", "python_version", "machine",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[100, 1000, 10000, 100000])
    parser.add_argument("--arms", nargs="+", default=["baseline", "streaming", "buffered"])
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output", type=Path, default=HERE.parent / "raw" / "scaling.csv")
    parser.add_argument("--max-buffered-size", type=int, default=10000,
                        help="skip the buffered arm above this size (it exists only as the ablation baseline)")
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_header = not args.output.exists() or args.output.stat().st_size == 0
    with args.output.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        if write_header:
            writer.writeheader()
        for size in args.sizes:
            for arm in args.arms:
                if arm == "buffered" and size > args.max_buffered_size:
                    continue
                for repetition in range(args.repeat):
                    completed = subprocess.run(
                        [args.python, str(HERE / "kernel.py"), str(size), "--arm", arm],
                        capture_output=True, text=True, check=False,
                    )
                    if completed.returncode != 0:
                        print(f"size={size} arm={arm}: failed\n{completed.stderr[-800:]}", file=sys.stderr)
                        return 1
                    record = json.loads(completed.stdout.strip().splitlines()[-1])
                    record["repetition"] = repetition
                    record["spooled"] = "true" if record["spooled"] else "false"
                    record = {key: ("" if value is None else value) for key, value in record.items()}
                    writer.writerow({column: record.get(column, "") for column in COLUMNS})
                    stream.flush()
                    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
