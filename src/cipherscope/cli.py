"""CipherScope command-line interface for the dependency-free MVP."""

from __future__ import annotations

import argparse
import csv
import json
import runpy
import sys
import traceback
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .demo import write_demo
from .exporters import write_bundle
from .pipeline import build_analysis_bundle
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
    session = runner_session(name=script.stem, strict=strict)
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cipherscope", description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    demo = subcommands.add_parser("demo", help="write the fake-backend MVP bundle")
    demo.add_argument("--output", type=Path, required=True)

    run = subcommands.add_parser("run", help="run an instrumented Python script")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument(
        "--permissive",
        action="store_true",
        help="forward unclassified proxy calls and mark coverage incomplete",
    )
    run.add_argument("script", type=Path)
    run.add_argument("script_args", nargs=argparse.REMAINDER)

    validate = subcommands.add_parser("validate", help="validate a run bundle")
    validate.add_argument("bundle", type=Path)

    view = subcommands.add_parser("view", help="locate a validated static report")
    view.add_argument("bundle", type=Path)
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
        )
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
    raise AssertionError(f"unhandled command {args.command!r}")


if __name__ == "__main__":
    raise SystemExit(main())
