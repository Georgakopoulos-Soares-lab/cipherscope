"""CipherScope command-line interface."""

from __future__ import annotations

import argparse
import csv
import json
import runpy
import subprocess
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .ablation import ABLATION_COLUMNS, ablate, minimum_modes
from .adjudication import (
    BundleExport,
    append_stale,
    export_bundle,
    merge_findings,
    precision_report,
    read_findings,
    write_findings,
    write_precision_table,
)
from .coverage import (
    classify_run,
    entrypoint_from_trace,
    report_row,
    scan_file,
    scannable_entrypoint,
    summarize_report,
    write_coverage_report,
)
from .demo import write_demo
from .exporters import write_bundle
from .pipeline import build_analysis_bundle
from .seeded import (
    all_matched,
    bundle_path,
    evaluate_case,
    load_ground_truth,
    recall_table,
    require_openfhe,
    run_case,
    write_results,
)
from .session import runner_session
from .validation import (
    StrictJSONError,
    ValidationError,
    load_json_file,
    validate_graph,
    validate_manifest,
    validate_recommendations,
    validate_trace,
)

REQUIRED_BUNDLE_FILES = (
    "manifest.json",
    "trace.json",
    "ciphertext_graph.json",
    "recommendations.json",
    "operations.csv",
    "perfetto-trace.json",
    "summary.html",
)


def _mapping(document: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(document, Mapping):
        raise ValueError(f"{name} must contain a JSON object")
    return document


def validate_bundle(path: Path | str) -> list[str]:
    """Return stable, human-readable failures for one run directory."""

    bundle = Path(path)
    failures: list[str] = []
    if not bundle.is_dir():
        return [f"bundle directory does not exist: {bundle}"]
    for filename in REQUIRED_BUNDLE_FILES:
        if not (bundle / filename).is_file():
            failures.append(f"missing required artifact: {filename}")
    if failures:
        return failures

    try:
        trace = _mapping(load_json_file(bundle / "trace.json"), "trace.json")
        graph = _mapping(
            load_json_file(bundle / "ciphertext_graph.json"),
            "ciphertext_graph.json",
        )
        recommendations = _mapping(
            load_json_file(bundle / "recommendations.json"),
            "recommendations.json",
        )
        manifest = _mapping(
            load_json_file(bundle / "manifest.json"),
            "manifest.json",
        )
        perfetto = _mapping(
            load_json_file(bundle / "perfetto-trace.json"),
            "perfetto-trace.json",
        )
    except (OSError, StrictJSONError, ValueError) as error:
        return [str(error)]

    validations = (
        validate_trace(trace),
        validate_graph(graph, trace=trace),
        validate_recommendations(
            recommendations,
            trace=trace,
            graph=graph,
        ),
        validate_manifest(manifest, trace=trace),
    )
    for result in validations:
        failures.extend(
            f"{result.kind}: {issue.code} at {issue.path}" for issue in result.errors
        )
    if not isinstance(perfetto.get("traceEvents"), list):
        failures.append("perfetto-trace.json: traceEvents must be an array")

    try:
        with (bundle / "operations.csv").open(
            "r", encoding="utf-8", newline=""
        ) as stream:
            fields = csv.DictReader(stream).fieldnames or []
        for required in ("sequence", "event_id", "operation", "status"):
            if required not in fields:
                failures.append(f"operations.csv: missing column {required}")
    except (OSError, UnicodeError, csv.Error) as error:
        failures.append(f"operations.csv: {error}")

    schema_directory = bundle / "schemas"
    schema_names = {
        "manifest.schema.json",
        "trace.schema.json",
        "graph.schema.json",
        "recommendations.schema.json",
    }
    if not schema_directory.is_dir():
        failures.append("missing required artifact: schemas/")
    else:
        actual = {item.name for item in schema_directory.glob("*.schema.json")}
        for missing in sorted(schema_names - actual):
            failures.append(f"schemas/: missing {missing}")
        for schema in sorted(schema_directory.glob("*.schema.json")):
            try:
                _mapping(load_json_file(schema), schema.name)
            except (OSError, StrictJSONError, ValueError) as error:
                failures.append(f"schemas/{schema.name}: {error}")
    return failures


def _write_session_bundle(session: Any, output: Path, status: str) -> None:
    trace = session.to_trace(status=status)
    artifacts = build_analysis_bundle(trace)
    write_bundle(
        output,
        manifest=artifacts["manifest"],
        trace=artifacts["trace"],
        graph=artifacts["graph"],
        recommendations=artifacts["recommendations"],
    )


def _system_exit_code(error: SystemExit) -> int:
    if error.code is None:
        return 0
    if isinstance(error.code, int):
        return error.code
    print(error.code, file=sys.stderr)
    return 1


def run_target(
    script: Path,
    script_args: Sequence[str],
    *,
    output: Path,
    strict: bool,
    allow_testing_security: bool = False,
    max_events: int | None = None,
    max_trace_bytes: int | None = None,
) -> int:
    """Execute a target in a runner-owned session and preserve its exit code."""

    if output.exists():
        print(f"cipherscope: output path already exists: {output}", file=sys.stderr)
        return 2
    if not script.is_file():
        print(f"cipherscope: target script does not exist: {script}", file=sys.stderr)
        return 2

    old_argv = sys.argv[:]
    old_path = sys.path[:]
    target_code = 0
    status = "completed"
    session = runner_session(
        name=script.stem,
        strict=strict,
        allow_testing_security=allow_testing_security,
        max_events=max_events,
        max_trace_bytes=max_trace_bytes,
    )
    try:
        with session:
            sys.argv = [str(script), *script_args]
            sys.path.insert(0, str(script.resolve().parent))
            try:
                runpy.run_path(str(script), run_name="__main__")
            except KeyboardInterrupt:
                status = "interrupted"
                target_code = 130
            except SystemExit as error:
                target_code = _system_exit_code(error)
                if target_code != 0:
                    status = "failed"
            except BaseException:
                status = "failed"
                target_code = 1
                traceback.print_exc()
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path

    if not session.has_attached_context:
        status = "failed"
        if target_code == 0:
            target_code = 2
        print(
            "cipherscope: target did not call cipherscope.attach() or trace()",
            file=sys.stderr,
        )
    try:
        _write_session_bundle(session, output, status)
    except (OSError, ValueError, ValidationError) as error:
        print(f"cipherscope: could not finalize bundle: {error}", file=sys.stderr)
        return target_code if target_code != 0 else 2
    return target_code


def preflight_targets(scripts: Sequence[Path]) -> dict[str, list[dict[str, Any]]]:
    """Scan each script for source patterns that can bypass the tracer."""

    report: dict[str, list[dict[str, Any]]] = {}
    for script in scripts:
        if not script.is_file():
            raise FileNotFoundError(f"target script does not exist: {script}")
        report[str(script)] = [risk.as_dict() for risk in scan_file(script)]
    return report


def coverage_report(
    bundles: Sequence[Path],
    *,
    scan_sources: bool,
) -> list[dict[str, Any]]:
    """Classify each run bundle; scan its recorded entrypoint when available."""

    rows: list[dict[str, Any]] = []
    for bundle in bundles:
        trace = _mapping(load_json_file(bundle / "trace.json"), str(bundle / "trace.json"))
        entrypoint = entrypoint_from_trace(trace)
        risks = ()
        if scan_sources and entrypoint is not None and entrypoint.is_file() and scannable_entrypoint(entrypoint):
            risks = scan_file(entrypoint)
        assessment = classify_run(trace, risks=risks)
        rows.append(report_row(bundle, trace, assessment, entrypoint=entrypoint))
    return rows


def export_findings(
    bundles: Sequence[Path],
    output: Path,
    *,
    allow_unscanned: bool,
) -> dict[str, Any]:
    """Merge findings from COMPLETE real bundles into output without losing verdicts."""

    exports: list[BundleExport] = []
    for bundle in bundles:
        failures = validate_bundle(bundle)
        if failures:
            exports.append(
                BundleExport(
                    bundle.resolve(),
                    bundle.resolve().name,
                    excluded_reason="bundle failed validation: " + "; ".join(failures),
                )
            )
            continue
        exports.append(export_bundle(bundle, allow_unscanned=allow_unscanned))

    summary: dict[str, Any] = {
        "output": str(output),
        "exported": {
            export.workload_id: len(export.rows)
            for export in exports
            if export.excluded_reason is None
        },
        "excluded": {
            str(export.bundle): export.excluded_reason
            for export in exports
            if export.excluded_reason is not None
        },
    }
    if not summary["exported"]:
        summary["written"] = False
        return summary

    existing = read_findings(output) if output.exists() else []
    merged = merge_findings(existing, exports)
    write_findings(merged.rows, output)
    if merged.stale:
        stale_path = output.with_name(output.stem + ".stale" + output.suffix)
        append_stale(merged.stale, stale_path)
        summary["stale_moved_to"] = str(stale_path)
    summary.update(
        {
            "written": True,
            "rows": len(merged.rows),
            "added": merged.added,
            "carried_verdicts": merged.carried,
            "untouched_other_workloads": merged.untouched,
            "stale": len(merged.stale),
        }
    )
    return summary


def run_seeded(
    ground_truth: Path,
    output: Path,
    *,
    python: str,
    from_bundles: bool,
) -> dict[str, Any]:
    """Run (or re-evaluate) every seeded case and write the recall table."""

    cases = load_ground_truth(ground_truth)
    if not from_bundles:
        require_openfhe(python)
    results = []
    for case in cases:
        if from_bundles:
            bundle, code = bundle_path(output, case), None
        else:
            bundle, code = run_case(case, output=output, python=python)
        results.append(evaluate_case(case, bundle, exit_code=code))
    table = recall_table(results)
    json_path, csv_path = write_results(results, table, output)
    failures = {
        result.case_id: (
            result.invalid_reason
            or [
                f"{rule.rule_id}: {rule.outcome}" + (f" ({rule.detail})" if rule.detail else "")
                for rule in result.rules
                if rule.outcome not in {"hit", "true_negative", "expected_not_applicable"}
            ]
        )
        for result in results
        if not result.matched
    }
    return {
        "all_matched": all_matched(results),
        "cases": len(results),
        "failures": failures,
        "unexpected_positives": {
            result.case_id: list(result.unexpected_positives)
            for result in results
            if result.unexpected_positives
        },
        "table": table,
        "case_results": str(json_path),
        "recall_table": str(csv_path),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cipherscope", description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    demo = subcommands.add_parser("demo", help="write a fake-backend example bundle")
    demo.add_argument("--output", type=Path, required=True)

    run = subcommands.add_parser("run", help="run an instrumented Python script")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument(
        "--permissive",
        action="store_true",
        help="forward unclassified proxy calls and mark coverage incomplete",
    )
    run.add_argument(
        "--allow-testing-security",
        action="store_true",
        help="acknowledge HEStd_NotSet so the configuration rule reports it as information",
    )
    run.add_argument(
        "--max-events", type=int, default=None, help="stop recording after this many events"
    )
    run.add_argument(
        "--max-trace-bytes",
        type=int,
        default=None,
        help="stop recording once the serialized events reach this many bytes",
    )
    run.add_argument("script", type=Path)
    run.add_argument("script_args", nargs=argparse.REMAINDER)

    analyze = subcommands.add_parser(
        "analyze", help="analyze a trace and write a run bundle"
    )
    analyze.add_argument("trace", type=Path)
    analyze.add_argument("--output", type=Path, required=True)

    validate = subcommands.add_parser("validate", help="validate a run bundle")
    validate.add_argument("bundle", type=Path)

    view = subcommands.add_parser("view", help="locate a validated static report")
    view.add_argument("bundle", type=Path)

    preflight = subcommands.add_parser(
        "preflight", help="scan scripts for source patterns that bypass the tracer"
    )
    preflight.add_argument("scripts", type=Path, nargs="+")

    coverage = subcommands.add_parser(
        "coverage", help="classify run bundles as COMPLETE, PARTIAL-PERMISSIVE, or UNSUPPORTED"
    )
    coverage.add_argument("bundles", type=Path, nargs="+")
    coverage.add_argument("--output", type=Path, help="write coverage_report.csv here")
    coverage.add_argument(
        "--no-scan",
        action="store_true",
        help="classify from the trace only; skip scanning each run's entrypoint",
    )

    findings = subcommands.add_parser(
        "findings",
        help="export findings from COMPLETE real bundles for human adjudication",
    )
    findings.add_argument("bundles", type=Path, nargs="+")
    findings.add_argument(
        "--output", type=Path, required=True, help="findings.csv to create or merge into"
    )
    findings.add_argument(
        "--allow-unscanned",
        action="store_true",
        help="accept bundles whose entrypoint source cannot be scanned for bypasses",
    )

    precision = subcommands.add_parser(
        "precision", help="report adjudication counts and precision from findings.csv"
    )
    precision.add_argument("findings", type=Path)
    precision.add_argument("--output", type=Path, help="write the per-rule table here")

    ablate_parser = subcommands.add_parser(
        "ablate", help="re-analyze bundles under TIMING_ONLY / STATE / FULL observability"
    )
    ablate_parser.add_argument("bundles", type=Path, nargs="+")
    ablate_parser.add_argument("--output", type=Path, help="write semantic_ablation.csv here")

    seeded = subcommands.add_parser(
        "seeded", help="run the seeded pathology benchmark and report per-rule recall"
    )
    seeded.add_argument("ground_truth", type=Path)
    seeded.add_argument("--output", type=Path, required=True)
    seeded.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter with the real OpenFHE binding (default: this one)",
    )
    seeded.add_argument(
        "--from-bundles",
        action="store_true",
        help="re-evaluate bundles already under OUTPUT/bundles instead of running cases",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "demo":
        try:
            destination = write_demo(args.output)
        except (OSError, ValueError, ValidationError) as error:
            print(f"cipherscope: demo failed: {error}", file=sys.stderr)
            return 2
        print(f"Wrote synthetic CipherScope bundle to {destination}")
        return 0
    if args.command == "run":
        forwarded = list(args.script_args)
        if forwarded and forwarded[0] == "--":
            forwarded.pop(0)
        return run_target(
            args.script,
            forwarded,
            output=args.output,
            strict=not args.permissive,
            allow_testing_security=args.allow_testing_security,
            max_events=args.max_events,
            max_trace_bytes=args.max_trace_bytes,
        )
    if args.command == "analyze":
        try:
            trace = _mapping(load_json_file(args.trace), str(args.trace))
            artifacts = build_analysis_bundle(trace)
            destination = write_bundle(
                args.output,
                manifest=artifacts["manifest"],
                trace=artifacts["trace"],
                graph=artifacts["graph"],
                recommendations=artifacts["recommendations"],
            )
        except (OSError, StrictJSONError, ValueError, ValidationError) as error:
            print(f"cipherscope: analysis failed: {error}", file=sys.stderr)
            return 2
        print(f"Wrote analyzed CipherScope bundle to {destination}")
        return 0
    if args.command in {"validate", "view"}:
        failures = validate_bundle(args.bundle)
        if failures:
            for failure in failures:
                print(f"cipherscope: {failure}", file=sys.stderr)
            return 1
        if args.command == "validate":
            manifest = _mapping(
                load_json_file(args.bundle / "manifest.json"),
                "manifest.json",
            )
            print(
                json.dumps(
                    {
                        "valid": True,
                        "run_id": manifest["run_id"],
                        "status": manifest["status"],
                    },
                    sort_keys=True,
                )
            )
        else:
            print((args.bundle / "summary.html").resolve())
        return 0
    if args.command == "preflight":
        try:
            report = preflight_targets(args.scripts)
        except (OSError, SyntaxError, UnicodeError) as error:
            print(f"cipherscope: preflight failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if any(risk["bypasses_tracer"] for risks in report.values() for risk in risks) else 0
    if args.command == "coverage":
        try:
            rows = coverage_report(args.bundles, scan_sources=not args.no_scan)
            if args.output is not None:
                write_coverage_report(rows, args.output)
        except (OSError, StrictJSONError, SyntaxError, UnicodeError, ValueError) as error:
            print(f"cipherscope: coverage failed: {error}", file=sys.stderr)
            return 2
        summary = summarize_report(rows)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if args.command == "findings":
        try:
            summary = export_findings(
                args.bundles, args.output, allow_unscanned=args.allow_unscanned
            )
        except (OSError, StrictJSONError, SyntaxError, UnicodeError, ValueError) as error:
            print(f"cipherscope: findings export failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(summary, indent=2, sort_keys=True))
        if not summary["written"]:
            print(
                "cipherscope: no bundle qualified; findings.csv was not touched",
                file=sys.stderr,
            )
            return 1
        return 0
    if args.command == "precision":
        try:
            report = precision_report(read_findings(args.findings))
            if args.output is not None:
                write_precision_table(report, args.output)
        except (OSError, UnicodeError, ValueError) as error:
            print(f"cipherscope: precision report failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if args.command == "ablate":
        rows: list[dict[str, Any]] = []
        try:
            for bundle in args.bundles:
                trace = _mapping(load_json_file(bundle / "trace.json"), str(bundle / "trace.json"))
                rows.extend(ablate(trace, bundle=bundle.name, name=trace["run"].get("name")))
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("w", encoding="utf-8", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(ABLATION_COLUMNS))
                    writer.writeheader()
                    writer.writerows(
                        {column: ("" if row.get(column) is None else row.get(column)) for column in ABLATION_COLUMNS}
                        for row in rows
                    )
        except (OSError, StrictJSONError, ValueError, ValidationError) as error:
            print(f"cipherscope: ablation failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps({"rows": len(rows), "minimum_modes": minimum_modes(rows)}, indent=2, sort_keys=True))
        return 0
    if args.command == "seeded":
        try:
            summary = run_seeded(
                args.ground_truth,
                args.output,
                python=args.python,
                from_bundles=args.from_bundles,
            )
        except (
            OSError,
            RuntimeError,
            StrictJSONError,
            TypeError,
            UnicodeError,
            ValueError,
            subprocess.TimeoutExpired,
        ) as error:
            print(f"cipherscope: seeded benchmark failed: {error}", file=sys.stderr)
            return 2
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["all_matched"] else 1
    raise AssertionError(f"unhandled command {args.command!r}")


if __name__ == "__main__":
    raise SystemExit(main())
