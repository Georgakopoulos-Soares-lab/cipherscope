"""Classify how completely a run observed its target program."""

from __future__ import annotations

import ast
import csv
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COMPLETE = "COMPLETE"
PARTIAL_PERMISSIVE = "PARTIAL-PERMISSIVE"
UNSUPPORTED = "UNSUPPORTED"

COVERAGE_CLASSES = (COMPLETE, PARTIAL_PERMISSIVE, UNSUPPORTED)
FAKE_BACKEND = "FakeCryptoContext"

REPORT_COLUMNS = (
    "bundle",
    "run_id",
    "name",
    "entrypoint",
    "status",
    "strict",
    "coverage_class",
    "traced_semantic_calls",
    "allowed_passthrough_calls",
    "unclassified_proxy_passthrough_calls",
    "rejected_unclassified_calls",
    "unsupported_operations",
    "static_risks",
    "reasons",
)


@dataclass(frozen=True)
class CoverageRisk:
    """One source pattern that can execute FHE calls outside the tracer."""

    kind: str
    line: int
    detail: str
    bypasses_tracer: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "line": self.line,
            "detail": self.detail,
            "bypasses_tracer": self.bypasses_tracer,
        }


@dataclass(frozen=True)
class CoverageAssessment:
    """The coverage class of one run and every reason behind it."""

    coverage_class: str
    reasons: tuple[str, ...]
    unsupported_operations: tuple[str, ...]
    risks: tuple[CoverageRisk, ...]


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _dotted_name(node.value)
        return None if owner is None else f"{owner}.{node.attr}"
    return None


class _RiskScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.risks: list[CoverageRisk] = []
        self._openfhe_modules: set[str] = set()
        self._openfhe_names: set[str] = set()
        self._openfhe_star = False
        self._cipherscope_modules: set[str] = set()
        self._cipherscope_names: set[str] = set()
        self._local_definitions: set[str] = set()
        # Calling a traced raw context directly inside its window bypasses the proxy.
        self._traced_windows: list[tuple[str, int, int]] = []
        self._receivers: list[tuple[str, int]] = []
        self._handled_calls: set[int] = set()
        self._last_line = 0

    def scan(self, tree: ast.Module) -> list[CoverageRisk]:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._local_definitions.add(node.name)
            end = getattr(node, "end_lineno", None)
            if end is not None:
                self._last_line = max(self._last_line, end)
        self.visit(tree)
        for expression, start, end in self._traced_windows:
            for receiver, line in self._receivers:
                if receiver == expression and start < line <= end:
                    self._add(
                        "retained_raw_context",
                        line,
                        f"{expression} is called directly while it is traced",
                        bypasses_tracer=True,
                    )
        return sorted(self.risks, key=lambda risk: (risk.line, risk.kind))

    def _add(self, kind: str, line: int, detail: str, *, bypasses_tracer: bool) -> None:
        self.risks.append(CoverageRisk(kind, line, detail, bypasses_tracer))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "openfhe":
                self._openfhe_modules.add(alias.asname or alias.name)
            elif alias.name == "cipherscope":
                self._cipherscope_modules.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "openfhe":
            for alias in node.names:
                if alias.name == "*":
                    self._openfhe_star = True
                    continue
                bound = alias.asname or alias.name
                self._openfhe_names.add(bound)
                if alias.name == "GenCryptoContext" and alias.asname:
                    self._add(
                        "gencryptocontext_alias",
                        node.lineno,
                        f"GenCryptoContext is imported as {alias.asname}",
                        bypasses_tracer=False,
                    )
        elif node.module == "cipherscope":
            for alias in node.names:
                if alias.name in {"attach", "trace"}:
                    self._cipherscope_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_gencryptocontext_reference(node.value):
            targets = ", ".join(
                filter(None, (_dotted_name(target) for target in node.targets))
            )
            self._add(
                "gencryptocontext_alias",
                node.lineno,
                f"GenCryptoContext is bound to {targets or 'another name'}",
                bypasses_tracer=False,
            )
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            call = item.context_expr
            if isinstance(call, ast.Call) and self._is_tracer_entry(call):
                self._handled_calls.add(id(call))
                self._track_traced(call, node.lineno, node.end_lineno or node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            receiver = _dotted_name(func.value)
            if receiver is not None:
                self._receivers.append((receiver, node.lineno))
            if func.attr == "GetCryptoContext":
                self._add(
                    "raw_context_from_ciphertext",
                    node.lineno,
                    "GetCryptoContext() returns the native context, not the proxy",
                    bypasses_tracer=True,
                )
            elif (
                func.attr.startswith("Eval")
                and receiver in self._openfhe_modules
            ):
                self._add(
                    "module_level_eval_call",
                    node.lineno,
                    f"{receiver}.{func.attr}() is a free function the proxy never sees",
                    bypasses_tracer=True,
                )
        elif isinstance(func, ast.Name) and func.id.startswith("Eval"):
            imported = func.id in self._openfhe_names or self._openfhe_star
            if imported and func.id not in self._local_definitions:
                self._add(
                    "module_level_eval_call",
                    node.lineno,
                    f"{func.id}() is a free function the proxy never sees",
                    bypasses_tracer=True,
                )
        if id(node) not in self._handled_calls and self._is_tracer_entry(node):
            self._track_traced(node, node.lineno, self._last_line)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "_context":
            owner = _dotted_name(node.value) or "<expression>"
            self._add(
                "proxy_private_access",
                node.lineno,
                f"{owner}._context reaches through the proxy to the native context",
                bypasses_tracer=True,
            )
        self.generic_visit(node)

    def _is_gencryptocontext_reference(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id == "GenCryptoContext" and (
                node.id in self._openfhe_names or self._openfhe_star
            )
        if isinstance(node, ast.Attribute):
            return (
                node.attr == "GenCryptoContext"
                and _dotted_name(node.value) in self._openfhe_modules
            )
        return False

    def _is_tracer_entry(self, call: ast.Call) -> bool:
        func = call.func
        if isinstance(func, ast.Name):
            return func.id in self._cipherscope_names
        if isinstance(func, ast.Attribute):
            return (
                func.attr in {"attach", "trace"}
                and _dotted_name(func.value) in self._cipherscope_modules
            )
        return False

    def _track_traced(self, call: ast.Call, start: int, end: int) -> None:
        if not call.args:
            return
        expression = _dotted_name(call.args[0])
        if expression is not None:
            self._traced_windows.append((expression, start, end))


def scan_source(source: str, *, filename: str = "<string>") -> tuple[CoverageRisk, ...]:
    """Report source patterns that can run FHE calls the tracer cannot see."""

    tree = ast.parse(source, filename=filename)
    return tuple(_RiskScanner().scan(tree))


def scan_file(path: Path | str) -> tuple[CoverageRisk, ...]:
    """Scan one Python file for coverage risks."""

    target = Path(path)
    return scan_source(target.read_text(encoding="utf-8"), filename=str(target))


def entrypoint_from_trace(trace: Mapping[str, Any]) -> Path | None:
    """Return the target script a trace was recorded from, if it is on disk."""

    run = trace.get("run") or {}
    name = run.get("name")
    files: Counter[str] = Counter()
    for event in trace.get("events") or ():
        source = event.get("source") or {}
        file = source.get("file")
        if isinstance(file, str) and not file.startswith("<"):
            files[file] += 1
    if not files:
        return None
    if isinstance(name, str):
        for file in files:
            if Path(file).stem == name:
                return Path(file)
    return Path(files.most_common(1)[0][0])


def real_backend_rejection(
    trace: Mapping[str, Any],
    recommendations: Mapping[str, Any] | None = None,
) -> str | None:
    """Return why a bundle is not a real OpenFHE run, or None if it is."""

    run = trace.get("run") or {}
    backend = str((run.get("runtime") or {}).get("backend", "unknown"))
    synthetic = run.get("synthetic_contract") is True or (
        recommendations is not None and recommendations.get("synthetic_contract") is True
    )
    if synthetic or backend == FAKE_BACKEND:
        return f"not a real OpenFHE run (backend {backend})"
    return None


def classify_run(
    trace: Mapping[str, Any],
    *,
    risks: Iterable[CoverageRisk] = (),
) -> CoverageAssessment:
    """Assign one coverage class to a trace; only COMPLETE may feed quality tables."""

    run = trace.get("run") or {}
    coverage = run.get("coverage") or {}
    status = run.get("status", "completed")
    static_risks = tuple(risks)
    unsupported = tuple(
        str(name) for name in coverage.get("unsupported_operations") or ()
    )
    traced_calls = int(coverage.get("traced_semantic_calls") or 0)
    rejected = int(coverage.get("rejected_unclassified_calls") or 0)
    forwarded = int(coverage.get("unclassified_proxy_passthrough_calls") or 0)
    truncated = bool(run.get("truncated") or coverage.get("truncated"))

    reasons: list[str] = []
    if status != "completed":
        reasons.append(f"run status is {status}")
    if rejected > 0:
        reasons.append(f"strict mode rejected {rejected} unsupported call(s)")
    if traced_calls == 0:
        reasons.append("no semantic call was traced")
    if reasons:
        return CoverageAssessment(UNSUPPORTED, tuple(reasons), unsupported, static_risks)

    if forwarded > 0:
        reasons.append(f"{forwarded} unclassified call(s) were forwarded untraced")
    if truncated:
        reasons.append("trace is truncated")
    if not coverage.get("strict", True):
        reasons.append("run used permissive mode")
    bypassing = [risk for risk in static_risks if risk.bypasses_tracer]
    if bypassing:
        kinds = ", ".join(sorted({risk.kind for risk in bypassing}))
        reasons.append(f"source shows tracer bypass pattern(s): {kinds}")
    if reasons:
        return CoverageAssessment(
            PARTIAL_PERMISSIVE, tuple(reasons), unsupported, static_risks
        )
    return CoverageAssessment(COMPLETE, (), unsupported, static_risks)


def report_row(
    bundle: Path | str,
    trace: Mapping[str, Any],
    assessment: CoverageAssessment,
    *,
    entrypoint: Path | None = None,
) -> dict[str, Any]:
    """Flatten one classified run into a coverage_report.csv row."""

    run = trace.get("run") or {}
    coverage = run.get("coverage") or {}
    return {
        "bundle": str(bundle),
        "run_id": run.get("run_id", ""),
        "name": run.get("name", ""),
        "entrypoint": "" if entrypoint is None else str(entrypoint),
        "status": run.get("status", ""),
        "strict": coverage.get("strict", ""),
        "coverage_class": assessment.coverage_class,
        "traced_semantic_calls": coverage.get("traced_semantic_calls", 0),
        "allowed_passthrough_calls": coverage.get("allowed_passthrough_calls", 0),
        "unclassified_proxy_passthrough_calls": coverage.get(
            "unclassified_proxy_passthrough_calls", 0
        ),
        "rejected_unclassified_calls": coverage.get("rejected_unclassified_calls", 0),
        "unsupported_operations": ";".join(assessment.unsupported_operations),
        "static_risks": ";".join(
            f"{risk.kind}@{risk.line}" for risk in assessment.risks
        ),
        "reasons": ";".join(assessment.reasons),
    }


def write_coverage_report(rows: Sequence[Mapping[str, Any]], path: Path | str) -> Path:
    """Write classified runs to CSV with one row per bundle."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in REPORT_COLUMNS})
    return destination


def summarize_report(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Count runs per class and list what kept the rest from being COMPLETE."""

    counts = {name: 0 for name in COVERAGE_CLASSES}
    excluded: list[dict[str, Any]] = []
    for row in rows:
        counts[str(row["coverage_class"])] += 1
        if row["coverage_class"] != COMPLETE:
            excluded.append(
                {
                    "bundle": row["bundle"],
                    "coverage_class": row["coverage_class"],
                    "unsupported_operations": [
                        name
                        for name in str(row.get("unsupported_operations", "")).split(";")
                        if name
                    ],
                    "reasons": [
                        reason
                        for reason in str(row.get("reasons", "")).split(";")
                        if reason
                    ],
                }
            )
    total = len(rows)
    return {
        "total": total,
        "counts": counts,
        "complete_fraction": (counts[COMPLETE] / total) if total else 0.0,
        "excluded": excluded,
    }


__all__ = [
    "COMPLETE",
    "COVERAGE_CLASSES",
    "FAKE_BACKEND",
    "PARTIAL_PERMISSIVE",
    "REPORT_COLUMNS",
    "UNSUPPORTED",
    "CoverageAssessment",
    "CoverageRisk",
    "classify_run",
    "entrypoint_from_trace",
    "real_backend_rejection",
    "report_row",
    "scan_file",
    "scan_source",
    "summarize_report",
    "write_coverage_report",
]
