#!/usr/bin/env python3
"""Run one impact case variant in this process and print a JSON report.

    runner.py <case_module> <before|after> timed
    runner.py <case_module> <before|after> traced --bundle <dir>

`timed` runs prepare/setup/workload on the raw OpenFHE context, times each
phase with time.perf_counter_ns, checks the result against the plaintext
reference and reports this process's peak RSS. `traced` runs setup/workload
through a CipherScope session, writes the bundle, and reports what the
analyzers concluded plus the trace-level metrics (events, ciphertext versions,
critical-path depth, levels consumed, per-operation counts). One process per
run keeps the peak-RSS numbers clean.
"""

from __future__ import annotations

import argparse
import importlib
import json
import resource
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE / "cases"))


def _ms(start_ns: int) -> float:
    return (time.perf_counter_ns() - start_ns) / 1e6


def run_timed(case) -> dict:
    t0 = time.perf_counter_ns()
    case.prepare()
    prepare_ms = _ms(t0)
    t1 = time.perf_counter_ns()
    case.setup(case.context)
    setup_ms = _ms(t1)
    t2 = time.perf_counter_ns()
    result = case.workload(case.context, None)
    workload_ms = _ms(t2)
    error = case.check(result)
    peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    if error > case.tolerance:
        raise AssertionError(f"{case.name}/{case.variant}: max abs error {error:.3e} exceeds tolerance {case.tolerance:.1e}")
    return {
        "mode": "timed",
        "prepare_ms": prepare_ms,
        "setup_ms": setup_ms,
        "workload_ms": workload_ms,
        "total_ms": prepare_ms + setup_ms + workload_ms,
        "peak_rss_mb": peak_rss_mb,
        "max_abs_error": error,
        "ring_dimension": case.ring_dimension(),
        **{f"extra.{k}": v for k, v in case.extra_metrics.items()},
    }


def run_traced(case, bundle_dir: Path) -> dict:
    import cipherscope
    from cipherscope.coverage import classify_run
    from cipherscope.exporters import write_bundle
    from cipherscope.pipeline import build_analysis_bundle

    case.prepare()
    with cipherscope.trace(case.context, name=f"{case.name}_{case.variant}", **case.trace_kwargs) as session:
        cc = session.context
        case.setup(cc)
        result = case.workload(cc, session)
    error = case.check(result)
    if error > case.tolerance:
        raise AssertionError(f"{case.name}/{case.variant} (traced): max abs error {error:.3e} exceeds tolerance {case.tolerance:.1e}")

    trace = session.to_trace(status="completed")
    artifacts = build_analysis_bundle(trace)
    write_bundle(bundle_dir, manifest=artifacts["manifest"], trace=artifacts["trace"],
                 graph=artifacts["graph"], recommendations=artifacts["recommendations"])

    recommendations = artifacts["recommendations"]
    graph = artifacts["graph"]
    events = trace["events"]
    operations = Counter(event.get("operation", "unknown") for event in events)
    critical = (graph.get("critical_paths") or {}).get("nonlinear_ciphertext", {}) or {}
    level_use = (graph.get("critical_paths") or {}).get("observed_level_use", {}) or {}
    rule_findings = [f for f in recommendations.get("findings", []) if f.get("rule_id") == case.rule]
    context = trace.get("context") or {}
    return {
        "mode": "traced",
        "bundle": str(bundle_dir),
        "coverage_class": classify_run(trace).coverage_class,
        "rule_status": recommendations["analyzer_status"].get(case.rule, "missing"),
        "rule_findings": len(rule_findings),
        "rule_evidence": [f.get("evidence") for f in rule_findings][:3],
        "all_positive_rules": sorted(k for k, v in recommendations["analyzer_status"].items() if v == "positive"),
        "events": len(events),
        "semantic_calls": (trace.get("run", {}).get("coverage") or {}).get("traced_semantic_calls"),
        "ciphertext_versions": len(trace.get("ciphertexts") or []),
        "max_nonlinear_depth": critical.get("max_depth"),
        "max_levels_consumed": level_use.get("max_levels_consumed_in_epoch"),
        "configured_depth": context.get("configured_multiplicative_depth"),
        "ring_dimension": context.get("ring_dimension") or case.ring_dimension(),
        "operations": dict(sorted(operations.items())),
        "max_abs_error": error,
        **{f"extra.{k}": v for k, v in case.extra_metrics.items()},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_module")
    parser.add_argument("variant", choices=("before", "after"))
    parser.add_argument("mode", choices=("timed", "traced"))
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args(argv)

    module = importlib.import_module(args.case_module)
    case = module.build(args.variant)
    if args.mode == "timed":
        report = run_timed(case)
    else:
        if args.bundle is None:
            parser.error("--bundle is required in traced mode")
        report = run_traced(case, args.bundle)
    report.update({"case": case.name, "rule": case.rule, "variant": case.variant})
    print(json.dumps(report, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
