"""Seeded pathology benchmark: known-answer programs for analyzer recall."""

from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .adjudication import finding_source
from .analyzers import (
    bootstrap,
    configuration,
    depth,
    encoding,
    keys,
    packing,
    parameters,
    precision,
    provenance,
    rotations,
    serial_reduction,
)
from .coverage import (
    COMPLETE,
    classify_run,
    entrypoint_from_trace,
    real_backend_rejection,
    scan_file,
)
from .validation import StrictJSONError, load_json_file

_RULE_MODULES = (
    bootstrap,
    configuration,
    depth,
    encoding,
    keys,
    packing,
    parameters,
    precision,
    provenance,
    rotations,
    serial_reduction,
)
KNOWN_RULES = frozenset(
    {module.RULE_ID for module in _RULE_MODULES} | {precision.TOLERANCE_RULE_ID}
)
OUTCOMES = ("positive", "clean", "not_applicable")
KINDS = ("positive", "hard_negative", "clean_kernel")

HIT = "hit"
MISS = "miss"
FALSE_POSITIVE = "false_positive"
TRUE_NEGATIVE = "true_negative"
EXPECTED_NOT_APPLICABLE = "expected_not_applicable"
UNEXPECTED_APPLICABILITY = "unexpected_applicability"
SOURCE_MISMATCH = "source_mismatch"
EVIDENCE_MISMATCH = "evidence_mismatch"
INVALID_RUN = "invalid_run"
MISMATCHES = (SOURCE_MISMATCH, EVIDENCE_MISMATCH, UNEXPECTED_APPLICABILITY)

TABLE_COLUMNS = (
    "rule_id",
    "seeded_positives",
    "detected",
    "recall",
    "seeded_negatives",
    "not_applicable_cases",
    "false_positives",
    "fp_rate",
    "mismatches",
    "invalid_runs",
)
CASE_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class SeededCase:
    case_id: str
    path: Path
    kind: str
    expected: dict[str, str]
    expected_source_lines: dict[str, list[int]]
    expected_evidence: dict[str, dict[str, Any]]
    clean_kernel: Path | None = None
    mutation_id: str = ""
    numerical_validity_expected: bool = True
    hard_negative_reason: str = ""
    notes: str = ""


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    expected: str
    observed: str
    outcome: str
    detail: str = ""


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    kind: str
    bundle: str
    coverage_class: str | None
    invalid_reason: str | None
    rules: tuple[RuleResult, ...]
    unexpected_positives: tuple[str, ...]
    exit_code: int | None = None
    clean_kernel: str | None = None
    mutation_id: str = ""
    expected_source_lines: dict[str, list[int]] = field(default_factory=dict)
    numerical_validity_expected: bool = True
    hard_negative_reason: str = ""

    @property
    def matched(self) -> bool:
        return self.invalid_reason is None and all(
            rule.outcome in {HIT, TRUE_NEGATIVE, EXPECTED_NOT_APPLICABLE}
            for rule in self.rules
        )


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be a JSON object")
    return value


def load_ground_truth(path: Path | str) -> list[SeededCase]:
    """Read and validate ground_truth.json; paths resolve relative to the file."""

    source = Path(path).resolve()
    document = _require_mapping(load_json_file(source), str(source))
    root = source.parent
    entries = document.get("cases")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{source}: 'cases' must be a non-empty array")

    cases: list[SeededCase] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        entry = _require_mapping(raw, f"{source}: cases[{index}]")
        case_id = entry.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{source}: cases[{index}] needs a non-empty case_id")
        if case_id in seen:
            raise ValueError(f"{source}: duplicate case_id {case_id!r}")
        seen.add(case_id)
        label = f"{source}: case {case_id!r}"

        script = root / str(entry.get("path", ""))
        if not script.is_file():
            raise ValueError(f"{label}: path does not exist: {script}")
        kernel = entry.get("clean_kernel")
        kernel_path = None
        if kernel is not None:
            kernel_path = root / str(kernel)
            if not kernel_path.is_file():
                raise ValueError(f"{label}: clean_kernel does not exist: {kernel_path}")

        kind = entry.get("kind")
        if kind not in KINDS:
            raise ValueError(f"{label}: kind must be one of {', '.join(KINDS)}")

        expected = _require_mapping(entry.get("expected"), f"{label}: expected")
        if not expected:
            raise ValueError(f"{label}: expected must name at least one rule")
        for rule_id, outcome in expected.items():
            if rule_id not in KNOWN_RULES:
                raise ValueError(f"{label}: unknown rule_id {rule_id!r}")
            if outcome not in OUTCOMES:
                raise ValueError(
                    f"{label}: expected[{rule_id!r}] must be one of {', '.join(OUTCOMES)}"
                )

        lines_by_rule: dict[str, list[int]] = {}
        for rule_id, lines in _require_mapping(
            entry.get("expected_source_lines", {}), f"{label}: expected_source_lines"
        ).items():
            if rule_id not in expected:
                raise ValueError(f"{label}: expected_source_lines names unlisted rule {rule_id!r}")
            if not isinstance(lines, list) or not all(
                isinstance(line, int) and line > 0 for line in lines
            ):
                raise ValueError(f"{label}: expected_source_lines[{rule_id!r}] must be positive ints")
            lines_by_rule[rule_id] = sorted(set(lines))

        evidence_by_rule: dict[str, dict[str, Any]] = {}
        for rule_id, evidence in _require_mapping(
            entry.get("expected_evidence", {}), f"{label}: expected_evidence"
        ).items():
            if rule_id not in expected:
                raise ValueError(f"{label}: expected_evidence names unlisted rule {rule_id!r}")
            evidence_by_rule[rule_id] = dict(
                _require_mapping(evidence, f"{label}: expected_evidence[{rule_id!r}]")
            )

        cases.append(
            SeededCase(
                case_id=case_id,
                path=script,
                kind=kind,
                expected=dict(expected),
                expected_source_lines=lines_by_rule,
                expected_evidence=evidence_by_rule,
                clean_kernel=kernel_path,
                mutation_id=str(entry.get("mutation_id", "")),
                numerical_validity_expected=bool(entry.get("numerical_validity_expected", True)),
                hard_negative_reason=str(entry.get("hard_negative_reason", "")),
                notes=str(entry.get("notes", "")),
            )
        )
    return cases


def _package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def require_openfhe(python: str) -> None:
    """Fail fast if the interpreter that will run the cases lacks OpenFHE."""

    probe = subprocess.run(
        [python, "-c", "import openfhe"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise RuntimeError(
            f"{python} cannot import openfhe; the seeded corpus needs the real binding"
            f"\n{probe.stderr.strip()}"
        )


def bundle_path(output: Path, case: SeededCase) -> Path:
    return output / "bundles" / case.case_id


def run_case(case: SeededCase, *, output: Path, python: str = sys.executable) -> tuple[Path, int]:
    """Execute one case under `cipherscope run` in a fresh process."""

    bundle = bundle_path(output, case).resolve()
    if bundle.exists():
        shutil.rmtree(bundle)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(_package_root()), env.get("PYTHONPATH", "")) if part
    )
    completed = subprocess.run(
        [python, "-m", "cipherscope", "run", "--output", str(bundle), str(case.path)],
        cwd=str(case.path.parent),
        env=env,
        capture_output=True,
        text=True,
        timeout=CASE_TIMEOUT_SECONDS,
        check=False,
    )
    (bundle.parent / f"{case.case_id}.log").write_text(
        f"exit code: {completed.returncode}\n--- stdout ---\n{completed.stdout}"
        f"\n--- stderr ---\n{completed.stderr}",
        encoding="utf-8",
    )
    return bundle, completed.returncode


def _lookup(evidence: Any, dotted: str) -> tuple[bool, Any]:
    current = evidence
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _judge_positive(case: SeededCase, rule_id: str, findings: list[Mapping[str, Any]]) -> RuleResult:
    expected_lines = case.expected_source_lines.get(rule_id)
    if expected_lines:
        observed_lines: set[int] = set()
        for finding in findings:
            _, lines, _ = finding_source(finding)
            observed_lines.update(lines)
        missing = sorted(set(expected_lines) - observed_lines)
        if missing:
            return RuleResult(
                rule_id,
                "positive",
                "positive",
                SOURCE_MISMATCH,
                f"expected source lines {expected_lines}, findings cover {sorted(observed_lines)}",
            )
    expected_evidence = case.expected_evidence.get(rule_id)
    if expected_evidence:
        problems: list[str] = []
        for dotted, wanted in expected_evidence.items():
            matched = False
            seen_values: list[Any] = []
            for finding in findings:
                found, value = _lookup(finding.get("evidence") or {}, dotted)
                if found:
                    seen_values.append(value)
                    if value == wanted:
                        matched = True
                        break
            if not matched:
                problems.append(f"{dotted}: expected {wanted!r}, observed {seen_values!r}")
        if problems:
            return RuleResult(rule_id, "positive", "positive", EVIDENCE_MISMATCH, "; ".join(problems))
    return RuleResult(rule_id, "positive", "positive", HIT)


def evaluate_case(case: SeededCase, bundle: Path | str, *, exit_code: int | None = None) -> CaseResult:
    """Compare one bundle against the case's declared expectations."""

    path = Path(bundle)

    def invalid(reason: str, coverage_class: str | None = None) -> CaseResult:
        return CaseResult(
            case.case_id,
            case.kind,
            str(path),
            coverage_class,
            reason,
            tuple(
                RuleResult(rule_id, expected, "", INVALID_RUN, reason)
                for rule_id, expected in sorted(case.expected.items())
            ),
            (),
            exit_code,
            **_case_metadata(case),
        )

    try:
        trace = _require_mapping(load_json_file(path / "trace.json"), "trace.json")
        recommendations = _require_mapping(
            load_json_file(path / "recommendations.json"), "recommendations.json"
        )
    except (OSError, StrictJSONError, TypeError) as error:
        return invalid(f"unreadable bundle: {error}")

    rejection = real_backend_rejection(trace, recommendations)
    if rejection is not None:
        return invalid(rejection)
    entrypoint = entrypoint_from_trace(trace)
    if entrypoint is None or not entrypoint.is_file():
        return invalid("entrypoint source unavailable for preflight scan")
    if entrypoint.resolve() != case.path.resolve():
        return invalid(f"bundle was recorded from {entrypoint}, not {case.path}")
    assessment = classify_run(trace, risks=scan_file(entrypoint))
    if assessment.coverage_class != COMPLETE:
        return invalid(
            f"coverage is {assessment.coverage_class}: " + "; ".join(assessment.reasons),
            assessment.coverage_class,
        )

    statuses = recommendations.get("analyzer_status")
    if not isinstance(statuses, Mapping):
        return invalid("recommendations.json has no analyzer_status map")
    findings_by_rule: dict[str, list[Mapping[str, Any]]] = {}
    for finding in recommendations.get("findings") or ():
        findings_by_rule.setdefault(str(finding.get("rule_id", "")), []).append(finding)

    results: list[RuleResult] = []
    for rule_id, expected in sorted(case.expected.items()):
        observed = str(statuses.get(rule_id, "not_applicable"))
        findings = findings_by_rule.get(rule_id, [])
        if expected == "positive":
            if observed == "positive":
                results.append(_judge_positive(case, rule_id, findings))
            else:
                results.append(RuleResult(rule_id, expected, observed, MISS))
        elif observed == "positive":
            results.append(
                RuleResult(
                    rule_id,
                    expected,
                    observed,
                    FALSE_POSITIVE,
                    f"{len(findings)} finding(s) on a program that must not fire",
                )
            )
        elif observed == expected:
            results.append(
                RuleResult(
                    rule_id,
                    expected,
                    observed,
                    TRUE_NEGATIVE if expected == "clean" else EXPECTED_NOT_APPLICABLE,
                )
            )
        else:
            results.append(
                RuleResult(
                    rule_id,
                    expected,
                    observed,
                    UNEXPECTED_APPLICABILITY,
                    "the rule did not assess the program the way the case assumes",
                )
            )

    unexpected = tuple(
        sorted(
            rule_id
            for rule_id, status in statuses.items()
            if status == "positive" and rule_id not in case.expected
        )
    )
    return CaseResult(
        case.case_id,
        case.kind,
        str(path),
        assessment.coverage_class,
        None,
        tuple(results),
        unexpected,
        exit_code,
        **_case_metadata(case),
    )


def _case_metadata(case: SeededCase) -> dict[str, Any]:
    return {
        "clean_kernel": None if case.clean_kernel is None else case.clean_kernel.name,
        "mutation_id": case.mutation_id,
        "expected_source_lines": {
            rule_id: list(lines) for rule_id, lines in case.expected_source_lines.items()
        },
        "numerical_validity_expected": case.numerical_validity_expected,
        "hard_negative_reason": case.hard_negative_reason,
    }


def results_from_json(document: Mapping[str, Any]) -> list[CaseResult]:
    """Rebuild CaseResult objects from a case_results.json document."""

    results: list[CaseResult] = []
    for entry in document.get("cases") or ():
        rules = tuple(
            RuleResult(
                str(rule["rule_id"]),
                str(rule["expected"]),
                str(rule.get("observed", "")),
                str(rule["outcome"]),
                str(rule.get("detail", "")),
            )
            for rule in entry.get("rules") or ()
        )
        results.append(
            CaseResult(
                str(entry["case_id"]),
                str(entry["kind"]),
                str(entry["bundle"]),
                entry.get("coverage_class"),
                entry.get("invalid_reason"),
                rules,
                tuple(str(item) for item in entry.get("unexpected_positives") or ()),
                entry.get("exit_code"),
                clean_kernel=entry.get("clean_kernel"),
                mutation_id=str(entry.get("mutation_id", "")),
                expected_source_lines={
                    str(rule_id): [int(line) for line in lines]
                    for rule_id, lines in (entry.get("expected_source_lines") or {}).items()
                },
                numerical_validity_expected=bool(entry.get("numerical_validity_expected", True)),
                hard_negative_reason=str(entry.get("hard_negative_reason", "")),
            )
        )
    return results


def recall_table(results: Sequence[CaseResult]) -> list[dict[str, Any]]:
    """Per-rule recall over seeded positives and false positives over negatives."""

    counts: dict[str, Counter[str]] = {}
    for result in results:
        for rule in result.rules:
            tally = counts.setdefault(rule.rule_id, Counter())
            if rule.outcome == INVALID_RUN:
                tally["invalid_runs"] += 1
                continue
            if rule.expected == "positive":
                tally["seeded_positives"] += 1
                if rule.outcome == HIT:
                    tally["detected"] += 1
            else:
                tally["seeded_negatives"] += 1
                if rule.expected == "not_applicable":
                    tally["not_applicable_cases"] += 1
                if rule.outcome == FALSE_POSITIVE:
                    tally["false_positives"] += 1
            if rule.outcome in MISMATCHES:
                tally["mismatches"] += 1

    def row(rule_id: str, tally: Counter[str]) -> dict[str, Any]:
        positives = tally["seeded_positives"]
        negatives = tally["seeded_negatives"]
        return {
            "rule_id": rule_id,
            "seeded_positives": positives,
            "detected": tally["detected"],
            "recall": (tally["detected"] / positives) if positives else None,
            "seeded_negatives": negatives,
            "not_applicable_cases": tally["not_applicable_cases"],
            "false_positives": tally["false_positives"],
            "fp_rate": (tally["false_positives"] / negatives) if negatives else None,
            "mismatches": tally["mismatches"],
            "invalid_runs": tally["invalid_runs"],
        }

    table = [row(rule_id, tally) for rule_id, tally in sorted(counts.items())]
    total: Counter[str] = Counter()
    for tally in counts.values():
        total.update(tally)
    table.append(row("ALL", total))
    return table


def all_matched(results: Sequence[CaseResult]) -> bool:
    return all(result.matched for result in results)


def write_results(
    results: Sequence[CaseResult],
    table: Sequence[Mapping[str, Any]],
    output: Path,
) -> tuple[Path, Path]:
    """Write case_results.json and recall_table.csv under output."""

    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "case_results.json"
    cases = []
    for result in results:
        entry = asdict(result)
        entry["bundle"] = _portable_bundle(result.bundle, output)
        cases.append(entry)
    document = {
        "all_matched": all_matched(results),
        "cases": cases,
        "environment": _environment(),
        "table": list(table),
    }
    json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = write_recall_table(table, output / "recall_table.csv")
    return json_path, csv_path


def _environment() -> dict[str, Any]:
    """Which lane, platform, and interpreter produced this result.

    A macOS and a Linux run of the same benchmark are otherwise
    indistinguishable; `results_from_json` ignores this block, so tables do not
    change.
    """

    from .fingerprint import build_fingerprint

    return {
        **build_fingerprint(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
    }


def _portable_bundle(bundle: str, output: Path) -> str:
    try:
        return Path(bundle).resolve().relative_to(output.resolve()).as_posix()
    except ValueError:
        return bundle


def write_recall_table(table: Sequence[Mapping[str, Any]], path: Path | str) -> Path:
    """Write the per-rule recall table as CSV with fixed number formatting."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TABLE_COLUMNS)
        writer.writeheader()
        for entry in table:
            writer.writerow({column: _cell(column, entry.get(column)) for column in TABLE_COLUMNS})
    return destination


def _cell(column: str, value: Any) -> Any:
    if value is None:
        return ""
    if column in {"recall", "fp_rate"}:
        return f"{value:.4f}"
    return value


__all__ = [
    "CASE_TIMEOUT_SECONDS",
    "EVIDENCE_MISMATCH",
    "EXPECTED_NOT_APPLICABLE",
    "FALSE_POSITIVE",
    "HIT",
    "INVALID_RUN",
    "KINDS",
    "KNOWN_RULES",
    "MISMATCHES",
    "MISS",
    "OUTCOMES",
    "SOURCE_MISMATCH",
    "TABLE_COLUMNS",
    "TRUE_NEGATIVE",
    "UNEXPECTED_APPLICABILITY",
    "CaseResult",
    "RuleResult",
    "SeededCase",
    "all_matched",
    "bundle_path",
    "evaluate_case",
    "load_ground_truth",
    "recall_table",
    "require_openfhe",
    "results_from_json",
    "run_case",
    "write_recall_table",
    "write_results",
]
