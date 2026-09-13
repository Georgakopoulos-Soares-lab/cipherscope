"""Regenerate every paper table from raw evaluation records under one contract."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ablation import MINIMUM_MODE_COLUMNS, minimum_modes
from .adjudication import (
    PRECISION_COLUMNS,
    precision_report,
    read_findings,
    write_precision_table,
)
from .coverage import COVERAGE_CLASSES, summarize_report
from .seeded import TABLE_COLUMNS as RECALL_COLUMNS
from .seeded import recall_table, results_from_json, write_recall_table
from .validation import load_json_file

BOOTSTRAP_SEED = 20260913
BOOTSTRAP_ROUNDS = 2000

SEEDED_CASE_COLUMNS = (
    "case_id",
    "kind",
    "clean_kernel",
    "mutation_id",
    "rule_id",
    "expected",
    "should_fire",
    "expected_source_lines",
    "numerical_validity_expected",
    "hard_negative_reason",
    "observed",
    "outcome",
    "coverage_class",
    "bundle",
)
COVERAGE_COLUMNS = ("coverage_class", "runs", "fraction")
GENERIC_PROFILER_COLUMNS = ("rule_id", "seeded_positives", "generic_profiler_can_diagnose", "needs")
OVERHEAD_COLUMNS = (
    "workload_id",
    "n_baseline",
    "n_traced",
    "wall_baseline_median_ms",
    "wall_baseline_iqr_ms",
    "wall_traced_median_ms",
    "wall_traced_iqr_ms",
    "wall_overhead_ratio",
    "wall_overhead_ratio_ci_low",
    "wall_overhead_ratio_ci_high",
    "wall_overhead_abs_ms",
    "cpu_baseline_median_ms",
    "cpu_traced_median_ms",
    "cpu_overhead_ratio",
    "cpu_overhead_ratio_ci_low",
    "cpu_overhead_ratio_ci_high",
    "rss_baseline_median_mb",
    "rss_traced_median_mb",
    "rss_delta_mb",
    "event_count_median",
    "trace_bytes_median",
    "analyzer_ms_median",
)

SCALING_COLUMNS = (
    "size",
    "arm",
    "runs",
    "events",
    "run_wall_ms",
    "wall_overhead_ratio_vs_baseline",
    "rss_growth_mb",
    "rss_growth_vs_baseline_mb",
    "peak_rss_mb",
    "peak_rss_vs_baseline_mb",
    "finalize_ms",
    "analyze_ms",
    "trace_bytes",
    "bytes_per_event",
    "analyze_ms_per_1k_events",
)

INPUTS = {
    "findings": Path("adjudication/findings.csv"),
    "seeded": Path("raw/seeded/case_results.json"),
    "coverage": Path("raw/coverage_report.csv"),
    "workload_runs": Path("raw/workload_runs.csv"),
    "scaling": Path("raw/scaling.csv"),
    "ablation": Path("raw/semantic_ablation.csv"),
}


@dataclass(frozen=True)
class PropertySpec:
    types: frozenset[str]
    enum: tuple[Any, ...] | None
    const: Any
    has_const: bool
    minimum: float | None
    min_length: int | None


@dataclass(frozen=True)
class RecordSpec:
    kind: str
    columns: tuple[str, ...]
    properties: dict[str, PropertySpec]


class ContractError(ValueError):
    """Raised when a raw record violates results.schema.json."""


def _resolve(schema: Mapping[str, Any], node: Mapping[str, Any]) -> Mapping[str, Any]:
    reference = node.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/$defs/"):
        return _resolve(schema, schema["$defs"][reference[len("#/$defs/") :]])
    return node


def _property_spec(schema: Mapping[str, Any], node: Mapping[str, Any]) -> PropertySpec:
    node = _resolve(schema, node)
    types: set[str] = set()
    enum: list[Any] | None = None
    const: Any = None
    has_const = False
    minimum = None
    min_length = None
    branches = [node, *(_resolve(schema, item) for item in node.get("oneOf", ()))]
    for branch in branches:
        declared = branch.get("type")
        if isinstance(declared, str):
            types.add(declared)
        elif isinstance(declared, list):
            types.update(str(item) for item in declared)
        if "enum" in branch:
            enum = list(branch["enum"]) if enum is None else [*enum, *branch["enum"]]
        if "const" in branch:
            const, has_const = branch["const"], True
        if "minimum" in branch:
            minimum = float(branch["minimum"])
        if "minLength" in branch:
            min_length = int(branch["minLength"])
    if enum is not None and None in enum:
        types.add("null")
    return PropertySpec(frozenset(types), None if enum is None else tuple(enum), const, has_const, minimum, min_length)


def load_contract(schema_path: Path | str) -> dict[str, RecordSpec]:
    """Read results.schema.json into per-record column and type specs."""

    schema = load_json_file(schema_path)
    if not isinstance(schema, Mapping):
        raise ContractError(f"{schema_path}: schema must be a JSON object")
    contract: dict[str, RecordSpec] = {}
    for kind, definition in schema["$defs"].items():
        if not isinstance(definition, Mapping) or definition.get("type") != "object":
            continue
        columns = tuple(str(column) for column in definition.get("required", ()))
        properties = {
            str(name): _property_spec(schema, node)
            for name, node in definition.get("properties", {}).items()
        }
        contract[kind] = RecordSpec(kind, columns, properties)
    return contract


def _parse_cell(spec: PropertySpec, raw: str) -> Any:
    if raw == "":
        if "null" in spec.types:
            return None
        raise ValueError("must not be empty")
    if "boolean" in spec.types and raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    if "integer" in spec.types:
        try:
            return int(raw)
        except ValueError:
            if "number" not in spec.types and "string" not in spec.types:
                raise ValueError("must be an integer") from None
    if "number" in spec.types:
        try:
            value = float(raw)
        except ValueError:
            if "string" not in spec.types:
                raise ValueError("must be a number") from None
        else:
            if not math.isfinite(value):
                raise ValueError("must be finite")
            return value
    if "string" in spec.types or spec.enum is not None or spec.has_const:
        return raw
    if "boolean" in spec.types:
        raise ValueError("must be true or false")
    raise ValueError("unsupported cell")


def validate_rows(spec: RecordSpec, rows: Sequence[Mapping[str, str]]) -> list[dict[str, Any]]:
    """Check CSV rows against one record spec; return typed rows or raise ContractError."""

    problems: list[str] = []
    typed: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=2):
        unknown = sorted(set(row) - set(spec.properties))
        if unknown:
            problems.append(f"row {index}: unknown column(s) {', '.join(unknown)}")
        record: dict[str, Any] = {}
        for column in spec.columns:
            if column not in row:
                problems.append(f"row {index}: missing column {column}")
                continue
            prop = spec.properties[column]
            raw = row[column] if row[column] is not None else ""
            try:
                value = _parse_cell(prop, raw.strip())
            except ValueError as error:
                problems.append(f"row {index}: {column}={raw!r} {error}")
                continue
            if value is not None:
                if prop.has_const and value != prop.const:
                    problems.append(f"row {index}: {column}={raw!r} must be {prop.const!r}")
                if prop.enum is not None and value not in prop.enum:
                    problems.append(f"row {index}: {column}={raw!r} not in {list(prop.enum)}")
                if prop.minimum is not None and isinstance(value, (int, float)) and value < prop.minimum:
                    problems.append(f"row {index}: {column}={raw!r} below minimum {prop.minimum}")
                if prop.min_length is not None and isinstance(value, str) and len(value) < prop.min_length:
                    problems.append(f"row {index}: {column} must not be empty")
            record[column] = value
        typed.append(record)
    if problems:
        raise ContractError(f"{spec.kind}: " + "; ".join(problems[:20]) + (" ..." if len(problems) > 20 else ""))
    return typed


def read_csv(path: Path | str) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        return [dict(row) for row in csv.DictReader(stream)]


def _fmt(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.4f}"
    return value


def write_table(rows: Sequence[Mapping[str, Any]], columns: Sequence[str], path: Path | str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(columns))
        writer.writeheader()
        for row in rows:
            writer.writerow({column: _fmt(row.get(column)) for column in columns})
    return destination


def seeded_case_rows(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten case_results.json into one record per (case, rule)."""

    rows: list[dict[str, Any]] = []
    for result in results_from_json(document):
        for rule in result.rules:
            lines = result.expected_source_lines.get(rule.rule_id)
            rows.append(
                {
                    "case_id": result.case_id,
                    "kind": result.kind,
                    "clean_kernel": result.clean_kernel,
                    "mutation_id": result.mutation_id or None,
                    "rule_id": rule.rule_id,
                    "expected": rule.expected,
                    "should_fire": rule.expected == "positive",
                    "expected_source_lines": ",".join(str(line) for line in lines) if lines else None,
                    "numerical_validity_expected": result.numerical_validity_expected,
                    "hard_negative_reason": result.hard_negative_reason or None,
                    "observed": rule.observed or None,
                    "outcome": rule.outcome,
                    "coverage_class": result.coverage_class,
                    "bundle": result.bundle,
                }
            )
    rows.sort(key=lambda row: (row["case_id"], row["rule_id"]))
    return rows


def coverage_rows(report_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    summary = summarize_report(report_rows)
    total = summary["total"]
    rows = [
        {
            "coverage_class": name,
            "runs": summary["counts"][name],
            "fraction": (summary["counts"][name] / total) if total else None,
        }
        for name in COVERAGE_CLASSES
    ]
    rows.append({"coverage_class": "ALL", "runs": total, "fraction": 1.0 if total else None})
    return rows


def _median(values: Sequence[float]) -> float | None:
    return statistics.median(values) if values else None


def _iqr(values: Sequence[float]) -> float | None:
    if not values:
        return None
    if len(values) < 2:
        return 0.0
    quartiles = statistics.quantiles(values, n=4, method="inclusive")
    return quartiles[2] - quartiles[0]


def _ratio(traced: float | None, baseline: float | None) -> float | None:
    if traced is None or baseline is None or baseline == 0:
        return None
    return traced / baseline - 1.0


def _bootstrap_ratio(
    baseline: Sequence[float], traced: Sequence[float], generator: random.Random
) -> tuple[float | None, float | None]:
    if not baseline or not traced:
        return None, None
    samples: list[float] = []
    for _ in range(BOOTSTRAP_ROUNDS):
        base = statistics.median(generator.choices(baseline, k=len(baseline)))
        trac = statistics.median(generator.choices(traced, k=len(traced)))
        if base:
            samples.append(trac / base - 1.0)
    if not samples:
        return None, None
    samples.sort()
    low = samples[int(0.025 * (len(samples) - 1))]
    high = samples[int(0.975 * (len(samples) - 1))]
    return low, high


def _series(arms: Mapping[str, Sequence[Mapping[str, Any]]], arm: str, column: str) -> list[float]:
    return [float(run[column]) for run in arms[arm] if run.get(column) is not None]


def overhead_rows(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per-workload matched overhead with medians, IQRs, and bootstrap 95% CIs."""

    by_workload: dict[str, dict[str, list[Mapping[str, Any]]]] = {}
    for run in runs:
        arms = by_workload.setdefault(str(run["workload_id"]), {"baseline": [], "traced": []})
        arms[str(run["arm"])].append(run)

    rows: list[dict[str, Any]] = []
    ratios: list[float] = []
    for workload_id in sorted(by_workload):
        arms = by_workload[workload_id]
        generator = random.Random(f"{BOOTSTRAP_SEED}:{workload_id}")

        wall_b, wall_t = _series(arms, "baseline", "wall_ms"), _series(arms, "traced", "wall_ms")
        cpu_b, cpu_t = _series(arms, "baseline", "cpu_ms"), _series(arms, "traced", "cpu_ms")
        rss_b, rss_t = _series(arms, "baseline", "peak_rss_mb"), _series(arms, "traced", "peak_rss_mb")
        wall_low, wall_high = _bootstrap_ratio(wall_b, wall_t, generator)
        cpu_low, cpu_high = _bootstrap_ratio(cpu_b, cpu_t, generator)
        wall_ratio = _ratio(_median(wall_t), _median(wall_b))
        if wall_ratio is not None:
            ratios.append(wall_ratio)
        rss_delta = None
        if rss_b and rss_t:
            rss_delta = statistics.median(rss_t) - statistics.median(rss_b)
        rows.append(
            {
                "workload_id": workload_id,
                "n_baseline": len(arms["baseline"]),
                "n_traced": len(arms["traced"]),
                "wall_baseline_median_ms": _median(wall_b),
                "wall_baseline_iqr_ms": _iqr(wall_b),
                "wall_traced_median_ms": _median(wall_t),
                "wall_traced_iqr_ms": _iqr(wall_t),
                "wall_overhead_ratio": wall_ratio,
                "wall_overhead_ratio_ci_low": wall_low,
                "wall_overhead_ratio_ci_high": wall_high,
                "wall_overhead_abs_ms": (
                    None
                    if not wall_b or not wall_t
                    else statistics.median(wall_t) - statistics.median(wall_b)
                ),
                "cpu_baseline_median_ms": _median(cpu_b),
                "cpu_traced_median_ms": _median(cpu_t),
                "cpu_overhead_ratio": _ratio(_median(cpu_t), _median(cpu_b)),
                "cpu_overhead_ratio_ci_low": cpu_low,
                "cpu_overhead_ratio_ci_high": cpu_high,
                "rss_baseline_median_mb": _median(rss_b),
                "rss_traced_median_mb": _median(rss_t),
                "rss_delta_mb": rss_delta,
                "event_count_median": _median(_series(arms, "traced", "event_count")),
                "trace_bytes_median": _median(_series(arms, "traced", "trace_bytes")),
                "analyzer_ms_median": _median(_series(arms, "traced", "analyzer_ms")),
            }
        )
    rows.append(
        {
            "workload_id": "ALL",
            "n_baseline": sum(len(arms["baseline"]) for arms in by_workload.values()),
            "n_traced": sum(len(arms["traced"]) for arms in by_workload.values()),
            "wall_overhead_ratio": _median(ratios),
        }
    )
    return rows


def scaling_rows(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per (size, arm) medians with the untraced baseline arm as the reference."""

    groups: dict[tuple[int, str], list[Mapping[str, Any]]] = {}
    for run in runs:
        groups.setdefault((int(run["size"]), str(run["arm"])), []).append(run)

    def median_of(records: Sequence[Mapping[str, Any]], column: str) -> float | None:
        values = [float(record[column]) for record in records if record.get(column) is not None]
        return statistics.median(values) if values else None

    rows: list[dict[str, Any]] = []
    for (size, arm), records in sorted(groups.items(), key=lambda item: (item[0][0], ("baseline", "streaming", "buffered").index(item[0][1]))):
        baseline = groups.get((size, "baseline"), [])
        wall = median_of(records, "run_wall_ms")
        base_wall = median_of(baseline, "run_wall_ms")
        growth = median_of(records, "rss_growth_mb")
        base_growth = median_of(baseline, "rss_growth_mb")
        peak = median_of(records, "peak_rss_mb")
        base_peak = median_of(baseline, "peak_rss_mb")
        events = median_of(records, "events")
        trace_bytes = median_of(records, "trace_bytes")
        analyze = median_of(records, "analyze_ms")
        rows.append(
            {
                "size": size,
                "arm": arm,
                "runs": len(records),
                "events": events,
                "run_wall_ms": wall,
                "wall_overhead_ratio_vs_baseline": _ratio(wall, base_wall) if arm != "baseline" else None,
                "rss_growth_mb": growth,
                "rss_growth_vs_baseline_mb": (growth - base_growth) if arm != "baseline" and growth is not None and base_growth is not None else None,
                "peak_rss_mb": peak,
                "peak_rss_vs_baseline_mb": (peak - base_peak) if arm != "baseline" and peak is not None and base_peak is not None else None,
                "finalize_ms": median_of(records, "finalize_ms"),
                "analyze_ms": analyze,
                "trace_bytes": trace_bytes,
                "bytes_per_event": (trace_bytes / events) if trace_bytes and events else None,
                "analyze_ms_per_1k_events": (analyze / events * 1000) if analyze is not None and events else None,
            }
        )
    return rows


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_tables(
    evaluation_dir: Path | str,
    *,
    schema_path: Path | str | None = None,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Validate every present raw input, then write all tables and a manifest."""

    root = Path(evaluation_dir)
    schema = Path(schema_path) if schema_path is not None else root / "schema" / "results.schema.json"
    output = Path(output_dir) if output_dir is not None else root / "tables"
    contract = load_contract(schema)

    present = {name: root / relative for name, relative in INPUTS.items() if (root / relative).is_file()}
    skipped = {name: str(root / relative) for name, relative in INPUTS.items() if name not in present}

    findings = read_findings(present["findings"]) if "findings" in present else None
    if findings is not None:
        validate_rows(contract["finding"], findings)
    coverage = read_csv(present["coverage"]) if "coverage" in present else None
    if coverage is not None:
        validate_rows(contract["coverage_run"], coverage)
    runs = None
    if "workload_runs" in present:
        runs = validate_rows(contract["workload_run"], read_csv(present["workload_runs"]))
    scaling = None
    if "scaling" in present:
        scaling = validate_rows(contract["scaling_run"], read_csv(present["scaling"]))
    ablation = None
    if "ablation" in present:
        ablation = validate_rows(contract["ablation_run"], read_csv(present["ablation"]))
    seeded_document = None
    seeded_rows: list[dict[str, Any]] | None = None
    if "seeded" in present:
        seeded_document = load_json_file(present["seeded"])
        if not isinstance(seeded_document, Mapping):
            raise ContractError(f"{present['seeded']}: must be a JSON object")
        seeded_rows = seeded_case_rows(seeded_document)
        validate_rows(
            contract["seeded_case"],
            [{column: str(_fmt(row.get(column))) for column in SEEDED_CASE_COLUMNS} for row in seeded_rows],
        )

    written: dict[str, str] = {}
    if findings is not None:
        report = precision_report(findings)
        path = write_precision_table(report, output / "precision.csv")
        written["precision.csv"] = _sha256(path)
    if seeded_document is not None and seeded_rows is not None:
        results = results_from_json(seeded_document)
        path = write_recall_table(recall_table(results), output / "recall.csv")
        written["recall.csv"] = _sha256(path)
        path = write_table(seeded_rows, SEEDED_CASE_COLUMNS, output / "seeded_cases.csv")
        written["seeded_cases.csv"] = _sha256(path)
    if coverage is not None:
        path = write_table(coverage_rows(coverage), COVERAGE_COLUMNS, output / "coverage.csv")
        written["coverage.csv"] = _sha256(path)
    if runs is not None:
        path = write_table(overhead_rows(runs), OVERHEAD_COLUMNS, output / "overhead.csv")
        written["overhead.csv"] = _sha256(path)
    if scaling is not None:
        path = write_table(scaling_rows(scaling), SCALING_COLUMNS, output / "scaling.csv")
        written["scaling.csv"] = _sha256(path)
    if ablation is not None:
        path = write_table(minimum_modes(ablation), MINIMUM_MODE_COLUMNS, output / "semantic_ablation.csv")
        written["semantic_ablation.csv"] = _sha256(path)
        comparison = [
            {
                "rule_id": row["rule_id"],
                "seeded_positives": row["full_positives"],
                "generic_profiler_can_diagnose": row["generic_profiler_can_diagnose"],
                "needs": row["minimum_mode"],
            }
            for row in minimum_modes(ablation)
        ]
        path = write_table(comparison, GENERIC_PROFILER_COLUMNS, output / "generic_profiler_comparison.csv")
        written["generic_profiler_comparison.csv"] = _sha256(path)

    manifest = {
        "schema": str(schema.relative_to(root)) if schema.is_relative_to(root) else str(schema),
        "inputs": {name: {"path": str(path.relative_to(root)), "sha256": _sha256(path)} for name, path in sorted(present.items())},
        "skipped_inputs": skipped,
        "tables": written,
        "bootstrap": {"seed": BOOTSTRAP_SEED, "rounds": BOOTSTRAP_ROUNDS},
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


__all__ = [
    "BOOTSTRAP_ROUNDS",
    "BOOTSTRAP_SEED",
    "COVERAGE_COLUMNS",
    "GENERIC_PROFILER_COLUMNS",
    "INPUTS",
    "OVERHEAD_COLUMNS",
    "PRECISION_COLUMNS",
    "RECALL_COLUMNS",
    "SCALING_COLUMNS",
    "SEEDED_CASE_COLUMNS",
    "ContractError",
    "PropertySpec",
    "RecordSpec",
    "coverage_rows",
    "generate_tables",
    "load_contract",
    "overhead_rows",
    "read_csv",
    "scaling_rows",
    "seeded_case_rows",
    "validate_rows",
    "write_table",
]
