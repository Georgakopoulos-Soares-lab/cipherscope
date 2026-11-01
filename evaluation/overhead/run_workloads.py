#!/usr/bin/env python3
"""C-02 / E-01: matched baseline vs traced repetitions across the unmodified corpus.

Every workload below is an OpenFHE program that never calls CipherScope
itself, so it has a genuine untraced baseline: the ten `profile_unmodified`
example targets and the four python-log-reg-examples programs. Each
repetition of each arm is one fresh process measured from outside (wall,
child CPU, peak RSS from wait4 rusage):

  baseline   python3 <script>
  traced     python3 -m cipherscope.cli run --output <bundle> examples/profile_unmodified.py -- <script>
             (everything the user pays for: tracing, analysis, bundle write)

For traced rows the bundle supplies event_count, trace_bytes, graph_bytes,
coverage_class and passthrough_calls; analyzer_ms is the time to rebuild the
analysis from that trace in this process (the analysis share of the traced
arm). Rows are the `workload_run` record of evaluation/schema/results.schema.json
and go to evaluation/raw/workload_runs.csv; `make tables` turns them into
evaluation/tables/overhead.csv (medians, IQRs, bootstrap CIs).

Self-instrumented examples (annotate_packing, precision_checkpoints, ...)
are excluded: they have no untraced variant to compare against. The two
100-epoch bootstrapped training programs are opt-in (see OPTIONAL_WORKLOADS).

    source ls6_env.sh
    OMP_NUM_THREADS=1 python3 evaluation/overhead/run_workloads.py --repeat 3
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

CORPUS = Path(os.environ.get("LOG_REG_EXAMPLES", "/work/10899/kimopro/ls6/python-log-reg-examples"))

# (workload_id, script path, working directory, extra PYTHONPATH)
WORKLOADS = [
    *[(Path(p).stem, ROOT / p, ROOT, "") for p in (
        "examples/chebysev.py", "examples/dot_product.py", "examples/bootstrapping.py",
        "examples/synthetic/weighted_inner_product.py", "examples/synthetic/vector_variance.py",
        "examples/synthetic/polynomial_horner.py", "examples/synthetic/squared_distance.py",
        "examples/synthetic/matrix_vector_diag.py", "examples/synthetic/repeated_rotations.py",
        "examples/synthetic/bootstrap_then_idle.py",
    )],
    *[(name, CORPUS / f"{name}.py", CORPUS, str(CORPUS)) for name in (
        "sol_encrypted_inference", "sol_lin_reg",
    )],
]
# sol_log_reg and sol_nag_log_reg (100 bootstrapped epochs at ring 32768) take
# about an hour per run on the 1-vCPU LS6 VM; they are classified in
# coverage_report.csv but not timed by default. Name them in --workloads to include.
OPTIONAL_WORKLOADS = [(name, CORPUS / f"{name}.py", CORPUS, str(CORPUS)) for name in ("sol_log_reg", "sol_nag_log_reg")]

COLUMNS = (
    "workload_id", "workload_commit", "cipherscope_commit", "lane", "repetition", "arm",
    "wall_ms", "cpu_ms", "peak_rss_mb", "event_count", "trace_bytes", "graph_bytes", "analyzer_ms",
    "coverage_class", "passthrough_calls", "correctness_metric", "correctness_value",
    "machine_id", "cpu_model", "openfhe_version", "python_version",
)

_WRAPPER = r"""
import json, resource, subprocess, sys, time
start = time.perf_counter_ns()
completed = subprocess.run(sys.argv[1:], capture_output=True, text=True)
wall_ms = (time.perf_counter_ns() - start) / 1e6
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({"returncode": completed.returncode, "stderr": completed.stderr[-1500:], "wall_ms": wall_ms,
                  "cpu_ms": (usage.ru_utime + usage.ru_stime) * 1000.0, "peak_rss_mb": usage.ru_maxrss / 1024.0}))
"""


def _measure(command: list[str], cwd: Path, extra_pythonpath: str) -> dict:
    env = {**os.environ, "PYTHONPATH": ":".join(p for p in (str(ROOT / "src"), extra_pythonpath) if p)}
    completed = subprocess.run([sys.executable, "-c", _WRAPPER, *command], cwd=cwd, capture_output=True, text=True, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"wrapper failed for {command}: {completed.stderr[-800:]}")
    return json.loads(completed.stdout.splitlines()[-1])


def _git(path: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True).stdout.strip()


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _traced_extras(bundle: Path) -> dict:
    from cipherscope.coverage import classify_run
    from cipherscope.pipeline import build_analysis_bundle
    from cipherscope.validation import load_json_file

    trace = load_json_file(bundle / "trace.json")
    start = time.perf_counter_ns()
    build_analysis_bundle(trace)
    analyzer_ms = (time.perf_counter_ns() - start) / 1e6
    coverage = trace["run"].get("coverage") or {}
    return {
        "event_count": len(trace["events"]),
        "trace_bytes": (bundle / "trace.json").stat().st_size,
        "graph_bytes": (bundle / "ciphertext_graph.json").stat().st_size,
        "analyzer_ms": f"{analyzer_ms:.3f}",
        "coverage_class": classify_run(trace).coverage_class,
        "passthrough_calls": int(coverage.get("allowed_passthrough_calls") or 0) + int(coverage.get("unclassified_proxy_passthrough_calls") or 0),
        "lane": (trace["run"].get("runtime") or {}).get("lane") or "developer",
        "openfhe_version": (trace["run"].get("runtime") or {}).get("openfhe_compatibility_target") or "unknown",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--workloads", nargs="*", default=[w[0] for w in WORKLOADS])
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "raw" / "workload_runs.csv")
    parser.add_argument("--bundles", type=Path, default=ROOT / "cipherscope-results" / "workload_runs")
    args = parser.parse_args(argv)

    cipherscope_commit = _git(ROOT, "rev-parse", "--short", "HEAD") + ("-dirty" if _git(ROOT, "status", "--porcelain") else "")
    corpus_commit = _git(CORPUS, "rev-parse", "--short", "HEAD") if CORPUS.exists() else "missing"
    static = {
        "cipherscope_commit": cipherscope_commit,
        "machine_id": socket.gethostname(),
        "cpu_model": _cpu_model(),
        "python_version": platform.python_version(),
        "correctness_metric": "exit_code",
    }
    if args.bundles.exists():
        shutil.rmtree(args.bundles)
    args.bundles.mkdir(parents=True)

    from cipherscope.compatibility import DEFAULT_COMPATIBILITY

    rows: list[dict] = []
    lane_seen = "developer"
    openfhe_seen = DEFAULT_COMPATIBILITY.compatibility_target
    for workload_id, script, cwd, extra in [*WORKLOADS, *OPTIONAL_WORKLOADS]:
        if workload_id not in args.workloads:
            continue
        if not script.is_file():
            print(f"[skip ] {workload_id}: {script} missing", flush=True)
            continue
        workload_commit = corpus_commit if cwd == CORPUS else cipherscope_commit
        for repetition in range(args.repeat):
            for arm in ("baseline", "traced"):
                if arm == "baseline":
                    command = [sys.executable, str(script)]
                    extras: dict = {}
                else:
                    bundle = args.bundles / f"{workload_id}_{repetition}"
                    command = [sys.executable, "-m", "cipherscope.cli", "run", "--output", str(bundle),
                               str(ROOT / "examples" / "profile_unmodified.py"), "--", str(script)]
                measured = _measure(command, cwd, extra)
                if measured["returncode"] != 0:
                    raise RuntimeError(f"{workload_id} {arm} #{repetition} exited {measured['returncode']}:\n{measured['stderr']}")
                if arm == "traced":
                    extras = _traced_extras(bundle)
                    lane_seen, openfhe_seen = extras.pop("lane"), extras.pop("openfhe_version")
                rows.append({
                    "workload_id": workload_id, "workload_commit": workload_commit, "lane": lane_seen,
                    "repetition": repetition, "arm": arm,
                    "wall_ms": f"{measured['wall_ms']:.3f}", "cpu_ms": f"{measured['cpu_ms']:.3f}",
                    "peak_rss_mb": f"{measured['peak_rss_mb']:.2f}",
                    "correctness_value": measured["returncode"],
                    "openfhe_version": openfhe_seen,
                    **extras, **static,
                })
                print(f"[{arm:8s}] {workload_id:24s} #{repetition}: wall {measured['wall_ms']:.0f} ms, "
                      f"cpu {measured['cpu_ms']:.0f} ms, rss {measured['peak_rss_mb']:.0f} MB"
                      + (f", events {extras['event_count']}, analysis {extras['analyzer_ms']} ms" if extras else ""), flush=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in COLUMNS})
    print(f"wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
