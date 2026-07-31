"""Run the required real-binding matrix and emit machine-readable evidence.

Unlike normal unittest discovery, this command treats every required skip as an
incomplete feasibility gate and returns nonzero. The provisional Python 3.12
wheel lane may prove API behavior, but it cannot satisfy the primary Python 3.11
source-build pin.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unittest
from pathlib import Path
from typing import Any, TextIO

from . import support


EXPECTED_CHECKS = (
    "ENV-01",
    "ENV-02",
    "ENV-03",
    "ENV-04",
    "ENV-05",
    "API-01",
    "API-02",
    "API-03",
    "API-04",
    "API-05",
    "PROXY-01",
    "PROXY-02",
    "PROXY-03",
    "PROXY-04",
    "TRACE-01",
    "TRACE-02",
    "ID-01",
    "ID-02",
    "ID-03",
    "MUT-01",
    "MUT-02",
    "NUM-01",
    "NUM-02",
    "ROT-01",
    "ROT-02",
    "BOOT-01",
    "BOOT-02",
    "GAP-01",
    "GAP-02",
    "GAP-03",
    "GAP-04",
    "RES-01",
    "RES-02",
    "API-06",
    "MUT-03",
    "PROXY-05",
    "ROT-03"
)
CHECK_PATTERN = re.compile(r"^([A-Z]+-[0-9]{2}):")


def _check_id(test: unittest.TestCase) -> str | None:
    description = test.shortDescription() or ""
    match = CHECK_PATTERN.match(description)
    return match.group(1) if match else None


class EvidenceResult(unittest.TextTestResult):
    """Capture bounded per-check status while retaining normal test output."""

    def __init__(
        self,
        stream: unittest.runner._WritelnDecorator,
        descriptions: bool,
        verbosity: int,
    ) -> None:
        super().__init__(stream, descriptions, verbosity)
        self.checks: dict[str, dict[str, Any]] = {}
        self._started: dict[int, int] = {}

    def startTest(self, test: unittest.TestCase) -> None:
        self._started[id(test)] = time.perf_counter_ns()
        super().startTest(test)

    def addSuccess(self, test: unittest.TestCase) -> None:
        self._finish(test, "pass")
        super().addSuccess(test)

    def addFailure(self, test: unittest.TestCase, err: tuple[type, BaseException, Any]) -> None:
        self._finish(test, "fail", self._bounded_error(err))
        super().addFailure(test, err)

    def addError(self, test: unittest.TestCase, err: tuple[type, BaseException, Any]) -> None:
        self._finish(test, "fail", self._bounded_error(err))
        super().addError(test, err)

    def addSkip(self, test: unittest.TestCase, reason: str) -> None:
        self._finish(test, "skip", reason[:500])
        super().addSkip(test, reason)

    def _finish(
        self, test: unittest.TestCase, status: str, detail: str | None = None
    ) -> None:
        check_id = _check_id(test)
        if check_id is None:
            check_id = f"UNMAPPED-{len(self.checks) + 1:02d}"
        started = self._started.pop(id(test), time.perf_counter_ns())
        record: dict[str, Any] = {
            "id": check_id,
            "test": test.id(),
            "description": test.shortDescription(),
            "required": True,
            "status": status,
            "duration_ns": max(0, time.perf_counter_ns() - started),
        }
        if detail:
            record["detail"] = detail
        self.checks[check_id] = record

    @staticmethod
    def _bounded_error(err: tuple[type, BaseException, Any]) -> str:
        error_type, error, _traceback = err
        message = str(error).replace("\n", " ")[:400]
        return f"{error_type.__name__}: {message}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="Evidence JSON path (default: artifact/feasibility/<lane>/feasibility.json)",
    )
    parser.add_argument("--quiet", action="store_true", help="Use concise unittest output")
    return parser


def _write_private_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def run(*, output: Path, stream: TextIO, verbosity: int) -> tuple[int, dict[str, Any]]:
    started = time.time_ns()
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(support.HERE),
        pattern="test_*.py",
        top_level_dir=str(support.PROJECT_ROOT),
    )
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=verbosity,
        resultclass=EvidenceResult,
    )
    result = runner.run(suite)
    assert isinstance(result, EvidenceResult)

    missing = sorted(set(EXPECTED_CHECKS) - set(result.checks))
    unexpected = sorted(set(result.checks) - set(EXPECTED_CHECKS))
    observations = support.evidence()
    checks: list[dict[str, Any]] = []
    for check_id in EXPECTED_CHECKS:
        check = result.checks.get(
            check_id,
            {
                "id": check_id,
                "test": None,
                "description": None,
                "required": True,
                "status": "missing",
                "duration_ns": 0,
                "detail": "required check was not discovered",
            },
        )
        if check_id in observations:
            check["observed"] = observations[check_id]
        checks.append(check)
    for check_id in unexpected:
        checks.append(result.checks[check_id])

    counts = {
        status: sum(check["status"] == status for check in checks)
        for status in ("pass", "fail", "skip", "missing")
    }
    if counts["fail"] or counts["missing"] or unexpected:
        status = "fail"
        exit_code = 1
    elif counts["skip"]:
        status = "incomplete"
        exit_code = 2
    elif support.LANE == "primary-source-py311":
        status = "pass"
        exit_code = 0
    elif support.LANE == "provisional-wheel-py312":
        status = "provisional_pass"
        exit_code = 0
    else:
        status = "developer_pass"
        exit_code = 0

    document = {
        "schema_version": "1.0.0",
        "gate": "OpenFHE Python v1.5.1.0 feasibility",
        "lane": support.LANE,
        "authoritative_for_primary_target": support.LANE == "primary-source-py311",
        "status": status,
        "started_unix_ns": started,
        "duration_ns": max(0, time.time_ns() - started),
        "environment": support.environment_snapshot(),
        "pins": {
            "wrapper_tag": support.GOLDEN["wrapper_tag"],
            "wrapper_commit": support.GOLDEN["wrapper_commit"],
            "native_tag": support.GOLDEN["native_tag"],
            "native_commit": support.GOLDEN["native_commit"],
            "provisional_distribution": support.GOLDEN[
                "provisional_distribution"
            ],
            "provisional_wheel_sha256": support.GOLDEN[
                "provisional_wheel_sha256"
            ],
        },
        "summary": {
            **counts,
            "total": len(checks),
            "missing_check_ids": missing,
            "unexpected_check_ids": unexpected,
        },
        "checks": checks,
        "limitations": [
            "A provisional Python 3.12 wheel pass is not the primary Python 3.11 source-build gate.",
            "The bootstrap fixture uses HEStd_NotSet and ring dimension 4096 for testing tractability.",
            "Timing and memory checks establish sane measurement mechanics, not overhead claims.",
        ],
        "official_sources": [
            "https://github.com/openfheorg/openfhe-python/tree/v1.5.1.0",
            "https://github.com/openfheorg/openfhe-development/tree/v1.5.1",
            "https://pypi.org/project/openfhe/1.5.1.0.24.4/",
        ],
    }
    _write_private_json(output, document)
    return exit_code, document


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output or (
        support.PROJECT_ROOT
        / "artifact"
        / "feasibility"
        / support.LANE
        / "feasibility.json"
    )
    exit_code, document = run(
        output=output,
        stream=sys.stderr,
        verbosity=1 if args.quiet else 2,
    )
    print(
        json.dumps(
            {
                "status": document["status"],
                "lane": document["lane"],
                "summary": document["summary"],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
