"""Export analyzer findings for human adjudication and report precision."""

from __future__ import annotations

import csv
import hashlib
import os
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .coverage import (
    COMPLETE,
    classify_run,
    entrypoint_from_trace,
    real_backend_rejection,
    scan_file,
)
from .validation import StrictJSONError, load_json_file

ADJUDICATIONS = (
    "TP-ACTIONABLE",
    "TP-NONACTIONABLE",
    "FALSE-POSITIVE",
    "UNCERTAIN",
    "NOT-IN-SCOPE",
)
TRUE_POSITIVES = ("TP-ACTIONABLE", "TP-NONACTIONABLE")

# Column order follows the action plan's findings.csv record exactly.
MACHINE_COLUMNS = (
    "finding_id",
    "workload_id",
    "rule_id",
    "source_file",
    "source_lines",
    "confidence",
)
HUMAN_COLUMNS = (
    "adjudication",
    "adjudicator_1",
    "adjudicator_2",
    "disagreement",
    "evidence_summary",
    "transformation_id",
    "transformation_status",
    "before_wall_ms",
    "after_wall_ms",
    "speedup",
    "before_rss_mb",
    "after_rss_mb",
    "correctness_before",
    "correctness_after",
    "upstream_issue_or_pr",
    "notes",
)
CONTEXT_COLUMNS = ("severity", "recommendation", "coverage_class", "bundle", "run_id")
FINDINGS_COLUMNS = MACHINE_COLUMNS + HUMAN_COLUMNS + CONTEXT_COLUMNS

COUNT_COLUMNS = (
    "findings",
    "pending",
    "adjudicated_without_evidence",
    *ADJUDICATIONS,
)
PRECISION_COLUMNS = (
    "rule_id",
    *COUNT_COLUMNS,
    "precision_numerator",
    "precision_denominator",
    "precision",
)
PRECISION_DEFINITION = (
    "precision = (TP-ACTIONABLE + TP-NONACTIONABLE) / "
    "(TP-ACTIONABLE + TP-NONACTIONABLE + FALSE-POSITIVE + UNCERTAIN); "
    "NOT-IN-SCOPE is excluded from the denominator; rows with no verdict or "
    "with a verdict but no evidence_summary are listed but never counted"
)


@dataclass(frozen=True)
class BundleExport:
    """Findings exported from one bundle, or the reason it was excluded."""

    bundle: Path
    workload_id: str
    rows: tuple[dict[str, Any], ...] = ()
    excluded_reason: str | None = None


@dataclass
class MergeResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    added: int = 0
    carried: int = 0
    untouched: int = 0


def _site_parts(site: str) -> tuple[str, str, str, str] | None:
    if not site.startswith("site:"):
        return None
    parts = site[len("site:") :].rsplit(":", 3)
    if len(parts) != 4:
        return None
    file, line, function, operation = parts
    return file, line, function, operation


def _relative(file: str, base: Path | None) -> str:
    if not file:
        return ""
    path = Path(file)
    if base is not None:
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            pass
    return path.name


def finding_source(finding: Mapping[str, Any]) -> tuple[str, list[int], str]:
    """Return (file, sorted lines, function) from the finding's source data."""

    source = finding.get("source")
    if isinstance(source, Mapping) and source.get("file"):
        lines = sorted(int(line) for line in source.get("lines") or ())
        return str(source["file"]), lines, str(source.get("function") or "")
    files: list[str] = []
    lines_set: set[int] = set()
    functions: list[str] = []
    for site in finding.get("source_sites") or ():
        parts = _site_parts(str(site))
        if parts is None:
            continue
        file, line, function, _ = parts
        if file not in files:
            files.append(file)
        if line.isdigit():
            lines_set.add(int(line))
        if function not in functions:
            functions.append(function)
    return ";".join(files), sorted(lines_set), ";".join(functions)


def stable_finding_key(
    workload_id: str,
    finding: Mapping[str, Any],
    *,
    base: Path | None,
) -> str:
    """Hash the finding's rule and source location, never its timing or event IDs."""

    file, lines, function = finding_source(finding)
    sites = []
    for site in finding.get("source_sites") or ():
        parts = _site_parts(str(site))
        if parts is None:
            sites.append(str(site))
            continue
        site_file, line, site_function, operation = parts
        sites.append(f"{_relative(site_file, base)}:{line}:{site_function}:{operation}")
    material = "\n".join(
        [
            workload_id,
            str(finding.get("rule_id", "")),
            ";".join(_relative(part, base) for part in file.split(";") if part),
            function,
            ",".join(str(line) for line in lines),
            *sorted(sites),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:8]


def export_bundle(
    bundle: Path | str,
    *,
    workload_id: str | None = None,
    allow_unscanned: bool = False,
) -> BundleExport:
    """Turn one bundle's findings into adjudication rows if it qualifies."""

    path = Path(bundle).resolve()
    workload = workload_id or path.name
    try:
        trace = load_json_file(path / "trace.json")
        recommendations = load_json_file(path / "recommendations.json")
    except (OSError, StrictJSONError) as error:
        return BundleExport(path, workload, excluded_reason=f"unreadable bundle: {error}")
    if not isinstance(trace, Mapping) or not isinstance(recommendations, Mapping):
        return BundleExport(path, workload, excluded_reason="bundle documents are not JSON objects")

    run = trace.get("run") or {}
    rejection = real_backend_rejection(trace, recommendations)
    if rejection is not None:
        return BundleExport(path, workload, excluded_reason=rejection)

    entrypoint = entrypoint_from_trace(trace)
    scannable = entrypoint is not None and entrypoint.is_file()
    if not scannable and not allow_unscanned:
        return BundleExport(
            path,
            workload,
            excluded_reason=(
                "entrypoint source unavailable for preflight scan"
                f"{'' if entrypoint is None else f': {entrypoint}'}"
                " (pass --allow-unscanned to classify from the trace alone)"
            ),
        )
    risks = scan_file(entrypoint) if scannable else ()
    assessment = classify_run(trace, risks=risks)
    if assessment.coverage_class != COMPLETE:
        return BundleExport(
            path,
            workload,
            excluded_reason=(
                f"coverage is {assessment.coverage_class}: " + "; ".join(assessment.reasons)
            ),
        )

    base = entrypoint.parent if scannable else None
    run_id = str(run.get("run_id", ""))
    rows: list[dict[str, Any]] = []
    seen: Counter[str] = Counter()
    for finding in recommendations.get("findings") or ():
        rule_id = str(finding.get("rule_id", ""))
        key = stable_finding_key(workload, finding, base=base)
        seen[key] += 1
        suffix = "" if seen[key] == 1 else f"#{seen[key]}"
        file, lines, _ = finding_source(finding)
        rows.append(
            {
                "finding_id": f"{workload}:{rule_id}:{key}{suffix}",
                "workload_id": workload,
                "rule_id": rule_id,
                "source_file": file,
                "source_lines": ",".join(str(line) for line in lines),
                "confidence": str(finding.get("confidence", "")),
                **{column: "" for column in HUMAN_COLUMNS},
                "severity": str(finding.get("severity", "")),
                "recommendation": str(finding.get("recommendation", "")),
                "coverage_class": assessment.coverage_class,
                "bundle": str(path),
                "run_id": run_id,
            }
        )
    return BundleExport(path, workload, rows=tuple(rows))


def read_findings(path: Path | str) -> list[dict[str, str]]:
    """Read an existing findings.csv; reject files whose columns do not match."""

    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        columns = tuple(reader.fieldnames or ())
        missing = [column for column in FINDINGS_COLUMNS if column not in columns]
        if missing:
            raise ValueError(
                f"{path}: missing findings.csv columns: {', '.join(missing)}"
            )
        rows = [{column: (row.get(column) or "") for column in FINDINGS_COLUMNS} for row in reader]
    ids = Counter(row["finding_id"] for row in rows)
    duplicates = sorted(finding_id for finding_id, count in ids.items() if count > 1)
    if duplicates:
        raise ValueError(f"{path}: duplicate finding_id values: {', '.join(duplicates)}")
    return rows


def merge_findings(
    existing: Sequence[Mapping[str, Any]],
    exports: Iterable[BundleExport],
) -> MergeResult:
    """Combine fresh exports with prior human work without losing either."""

    exported = [export for export in exports if export.excluded_reason is None]
    exported_workloads = {export.workload_id for export in exported}
    previous = {row["finding_id"]: row for row in existing}
    result = MergeResult()
    fresh_ids: set[str] = set()
    for export in exported:
        for row in export.rows:
            fresh_ids.add(row["finding_id"])
            old = previous.get(row["finding_id"])
            merged = dict(row)
            if old is not None:
                for column in HUMAN_COLUMNS:
                    merged[column] = old.get(column, "")
                result.carried += 1
            else:
                result.added += 1
            result.rows.append(merged)
    for row in existing:
        if row["finding_id"] in fresh_ids:
            continue
        if row.get("workload_id") in exported_workloads:
            result.stale.append(dict(row))
        else:
            result.rows.append(dict(row))
            result.untouched += 1
    result.rows.sort(key=lambda row: (row["workload_id"], row["rule_id"], row["finding_id"]))
    return result


def write_findings(rows: Sequence[Mapping[str, Any]], path: Path | str) -> Path:
    """Write findings.csv atomically so an interruption cannot truncate it."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix=destination.name, suffix=".tmp", dir=destination.parent
    )
    replaced = False
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=FINDINGS_COLUMNS)
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in FINDINGS_COLUMNS})
        os.replace(temporary, destination)
        replaced = True
    finally:
        if not replaced:
            Path(temporary).unlink(missing_ok=True)
    return destination


def append_stale(rows: Sequence[Mapping[str, Any]], path: Path | str) -> Path:
    """Append rows that vanished from a re-analyzed workload; never discard them."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_header = not destination.exists() or destination.stat().st_size == 0
    with destination.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FINDINGS_COLUMNS)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in FINDINGS_COLUMNS})
    return destination


def precision_report(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Count verdicts per rule and compute precision over adjudicated findings only."""

    invalid = [
        (row["finding_id"], row["adjudication"])
        for row in rows
        if row.get("adjudication") and row["adjudication"] not in ADJUDICATIONS
    ]
    if invalid:
        listed = ", ".join(f"{finding_id}={verdict!r}" for finding_id, verdict in invalid)
        raise ValueError(f"invalid adjudication values: {listed}")

    per_rule: dict[str, Counter[str]] = {}
    for row in rows:
        counts = per_rule.setdefault(row["rule_id"], Counter())
        counts["findings"] += 1
        verdict = row.get("adjudication") or ""
        if not verdict:
            counts["pending"] += 1
        elif not (row.get("evidence_summary") or "").strip():
            counts["adjudicated_without_evidence"] += 1
        else:
            counts[verdict] += 1

    def _table_row(rule_id: str, counts: Counter[str]) -> dict[str, Any]:
        numerator = sum(counts[name] for name in TRUE_POSITIVES)
        denominator = numerator + counts["FALSE-POSITIVE"] + counts["UNCERTAIN"]
        row: dict[str, Any] = {"rule_id": rule_id}
        for column in COUNT_COLUMNS:
            row[column] = counts[column]
        row["precision_numerator"] = numerator
        row["precision_denominator"] = denominator
        row["precision"] = (numerator / denominator) if denominator else None
        return row

    table = [_table_row(rule_id, counts) for rule_id, counts in sorted(per_rule.items())]
    total: Counter[str] = Counter()
    for counts in per_rule.values():
        total.update(counts)
    table.append(_table_row("ALL", total))

    second_reviews = sum(1 for row in rows if (row.get("adjudicator_2") or "").strip())
    disagreements = sum(1 for row in rows if (row.get("disagreement") or "").strip())
    limitations = ["recall is not defined on real workloads and is not reported"]
    if rows and second_reviews == 0:
        limitations.append("single reviewer: no adjudicator_2 recorded for any finding")
    elif rows and second_reviews < len(rows):
        limitations.append(
            f"second reviewer covered {second_reviews} of {len(rows)} findings"
        )
    return {
        "findings": len(rows),
        "adjudicated": int(sum(total[name] for name in ADJUDICATIONS)),
        "pending": int(total["pending"]),
        "adjudicated_without_evidence": int(total["adjudicated_without_evidence"]),
        "second_reviews": second_reviews,
        "disagreements": disagreements,
        "precision_definition": PRECISION_DEFINITION,
        "table": table,
        "limitations": limitations,
    }


def write_precision_table(report: Mapping[str, Any], path: Path | str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=PRECISION_COLUMNS)
        writer.writeheader()
        for row in report["table"]:
            precision = row["precision"]
            writer.writerow(
                {
                    **row,
                    "precision": "" if precision is None else f"{precision:.4f}",
                }
            )
    return destination


__all__ = [
    "ADJUDICATIONS",
    "CONTEXT_COLUMNS",
    "COUNT_COLUMNS",
    "FINDINGS_COLUMNS",
    "HUMAN_COLUMNS",
    "MACHINE_COLUMNS",
    "PRECISION_COLUMNS",
    "PRECISION_DEFINITION",
    "TRUE_POSITIVES",
    "BundleExport",
    "MergeResult",
    "append_stale",
    "export_bundle",
    "finding_source",
    "merge_findings",
    "precision_report",
    "read_findings",
    "stable_finding_key",
    "write_findings",
    "write_precision_table",
]
