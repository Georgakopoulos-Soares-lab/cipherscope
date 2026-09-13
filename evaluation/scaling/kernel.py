#!/usr/bin/env python3
"""Generate N traced OpenFHE events with a stable operation mix and report costs.

Run in its own process per (size, arm) so that ru_maxrss is the peak of this
run alone. Prints one JSON line on stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import openfhe

import cipherscope
from cipherscope.exporters import write_bundle
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.recorder import SPOOL_BUFFER_EVENTS

SAMPLE_EVERY = 1000


def current_rss_mb() -> float:
    statm = Path("/proc/self/statm")
    if statm.is_file():
        pages = int(statm.read_text(encoding="utf-8").split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE") / 1e6
    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(os.getpid())], capture_output=True, text=True, check=False
    )
    return int(completed.stdout.strip() or 0) * 1024 / 1e6


def peak_rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / 1e6 if platform.system() == "Darwin" else peak * 1024 / 1e6


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("size", type=int)
    parser.add_argument("--arm", choices=("streaming", "buffered", "baseline"), default="streaming")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(8)
    context = openfhe.GenCryptoContext(parameters)
    context.Enable(openfhe.PKESchemeFeature.PKE)
    context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    keys = context.KeyGen()
    context.EvalRotateKeyGen(keys.secretKey, [1])
    data = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]

    rss_start = current_rss_mb()
    samples = [rss_start]

    def workload(cc: object, left: object, right: object) -> None:
        accumulator = left
        for index in range(args.size):
            step = index % 4
            if step == 0:
                accumulator = cc.EvalAdd(accumulator, right)
            elif step == 1:
                accumulator = cc.EvalSub(accumulator, right)
            elif step == 2:
                accumulator = cc.EvalRotate(accumulator, 1)
            else:
                accumulator = cc.EvalAdd(left, right)
            if (index + 1) % SAMPLE_EVERY == 0:
                samples.append(current_rss_mb())

    if args.arm == "baseline":
        started = time.perf_counter()
        left = context.Encrypt(keys.publicKey, context.MakeCKKSPackedPlaintext(data))
        right = context.Encrypt(keys.publicKey, context.MakeCKKSPackedPlaintext(data))
        workload(context, left, right)
        run_wall_ms = (time.perf_counter() - started) * 1000
        rss_end = current_rss_mb()
        record = {
            "size": args.size,
            "arm": args.arm,
            "events": 0,
            "run_wall_ms": round(run_wall_ms, 3),
            "rss_start_mb": round(rss_start, 3),
            "rss_end_mb": round(rss_end, 3),
            "rss_growth_mb": round(max(samples[1:], default=rss_start) - samples[min(1, len(samples) - 1)], 3),
            "peak_rss_mb": round(peak_rss_mb(), 3),
            "finalize_ms": None,
            "analyze_ms": None,
            "trace_bytes": None,
            "graph_bytes": None,
            "recommendations_bytes": None,
            "spooled": False,
            "rss_samples_mb": [round(v, 1) for v in samples],
            "python_version": platform.python_version(),
            "machine": platform.machine(),
        }
        print(json.dumps(record, sort_keys=True))
        return 0

    spool_buffer = args.size + SPOOL_BUFFER_EVENTS if args.arm == "buffered" else SPOOL_BUFFER_EVENTS
    session = cipherscope.Session(context, name=f"scaling_{args.size}_{args.arm}").with_parameters(parameters)
    session.recorder._events._buffer_lines = spool_buffer
    session.recorder._states._buffer_lines = spool_buffer

    started = time.perf_counter()
    with session:
        cc = session.context
        left = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
        right = cc.Encrypt(keys.publicKey, cc.MakeCKKSPackedPlaintext(data))
        workload(cc, left, right)
    run_wall_ms = (time.perf_counter() - started) * 1000
    rss_end = current_rss_mb()

    started = time.perf_counter()
    trace = session.to_trace()
    finalize_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    artifacts = build_analysis_bundle(trace)
    analyze_ms = (time.perf_counter() - started) * 1000

    sizes = {
        name: len(json.dumps(artifacts[key], sort_keys=True))
        for name, key in (("trace_bytes", "trace"), ("graph_bytes", "graph"), ("recommendations_bytes", "recommendations"))
    }
    if args.output is not None:
        write_bundle(
            args.output,
            manifest=artifacts["manifest"],
            trace=artifacts["trace"],
            graph=artifacts["graph"],
            recommendations=artifacts["recommendations"],
        )
    else:
        with tempfile.TemporaryDirectory() as temporary:
            write_bundle(
                Path(temporary) / "bundle",
                manifest=artifacts["manifest"],
                trace=artifacts["trace"],
                graph=artifacts["graph"],
                recommendations=artifacts["recommendations"],
            )

    record = {
        "size": args.size,
        "arm": args.arm,
        "events": len(trace["events"]),
        "run_wall_ms": round(run_wall_ms, 3),
        "rss_start_mb": round(rss_start, 3),
        "rss_end_mb": round(rss_end, 3),
        "rss_growth_mb": round(max(samples[1:], default=rss_start) - samples[min(1, len(samples) - 1)], 3),
        "peak_rss_mb": round(peak_rss_mb(), 3),
        "finalize_ms": round(finalize_ms, 3),
        "analyze_ms": round(analyze_ms, 3),
        **sizes,
        "spooled": session.recorder.spool_path is not None,
        "rss_samples_mb": [round(v, 1) for v in samples],
        "python_version": platform.python_version(),
        "machine": platform.machine(),
    }
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
