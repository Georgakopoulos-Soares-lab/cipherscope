"""Findings export for human adjudication, merge safety, and precision."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import cipherscope
from cipherscope.adjudication import (
    ADJUDICATIONS,
    FINDINGS_COLUMNS,
    HUMAN_COLUMNS,
    PRECISION_COLUMNS,
    export_bundle,
    merge_findings,
    precision_report,
    read_findings,
    stable_finding_key,
    write_findings,
)
from cipherscope.cli import main
from cipherscope.exporters import write_bundle
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.testing import FakeCiphertext, FakeCryptoContext

REAL_BACKEND = "CryptoContext"


def _write_real_looking_bundle(
    directory: Path,
    *,
    generated: list[int] = (1, 2, 5),
    used: list[int] = (1, 2),
    backend_name: str = REAL_BACKEND,
    name: str = "workload",
) -> Path:
    """Write a bundle from the fake backend but labeled like a real OpenFHE run."""

    backend = FakeCryptoContext()
    source = FakeCiphertext()
    with cipherscope.trace(backend, name=name) as session:
        session.context.EvalRotateKeyGen(object(), list(generated))
        for index in used:
            session.context.EvalRotate(source, index)
    trace = session.to_trace()
    trace["run"]["runtime"]["backend"] = backend_name
    artifacts = build_analysis_bundle(trace)
    return write_bundle(
        directory,
        manifest=artifacts["manifest"],
        trace=artifacts["trace"],
        graph=artifacts["graph"],
        recommendations=artifacts["recommendations"],
    )


def _finding(rule_id: str, file: str, lines: list[int], *, event_ids: list[str] = ()) -> dict:
    return {
        "rule_id": rule_id,
        "source": {"file": file, "function": "<module>", "lines": lines},
        "source_sites": [f"site:{file}:{line}:<module>:EvalRotate" for line in lines],
        "evidence_event_ids": list(event_ids),
        "estimated_impact": {"wall_duration_ns_affected": 123456},
        "confidence": "measured",
        "severity": "opportunity",
        "recommendation": "hoist",
    }


class StableKeyTests(unittest.TestCase):
    def test_key_ignores_timing_and_event_ids(self) -> None:
        a = _finding("rotation.hoist_same_input.v1", "/w/x.py", [3, 4], event_ids=["event_0001"])
        b = _finding("rotation.hoist_same_input.v1", "/w/x.py", [3, 4], event_ids=["event_0099"])
        b["estimated_impact"]["wall_duration_ns_affected"] = 1
        self.assertEqual(
            stable_finding_key("w", a, base=Path("/w")),
            stable_finding_key("w", b, base=Path("/w")),
        )

    def test_key_survives_moving_the_workload_directory(self) -> None:
        a = _finding("rotation.hoist_same_input.v1", "/home/a/w/x.py", [3])
        b = _finding("rotation.hoist_same_input.v1", "/work/b/w/x.py", [3])
        self.assertEqual(
            stable_finding_key("w", a, base=Path("/home/a/w")),
            stable_finding_key("w", b, base=Path("/work/b/w")),
        )

    def test_key_changes_with_lines_rule_or_workload(self) -> None:
        base = _finding("rotation.hoist_same_input.v1", "/w/x.py", [3])
        key = stable_finding_key("w", base, base=Path("/w"))
        self.assertNotEqual(
            key,
            stable_finding_key(
                "w", _finding("rotation.hoist_same_input.v1", "/w/x.py", [4]), base=Path("/w")
            ),
        )
        self.assertNotEqual(
            key,
            stable_finding_key(
                "w", _finding("keys.unused_in_observed_run.v1", "/w/x.py", [3]), base=Path("/w")
            ),
        )
        self.assertNotEqual(key, stable_finding_key("other", base, base=Path("/w")))


class ExportGateTests(unittest.TestCase):
    def test_demo_bundle_is_excluded_as_synthetic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "demo"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["demo", "--output", str(bundle)]), 0)
            export = export_bundle(bundle)
            self.assertIsNotNone(export.excluded_reason)
            self.assertIn("not a real OpenFHE run", export.excluded_reason)
            self.assertEqual(export.rows, ())

    def test_unflagged_fake_backend_is_still_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = _write_real_looking_bundle(
                Path(temporary) / "fake", backend_name="FakeCryptoContext"
            )
            export = export_bundle(bundle, allow_unscanned=True)
            self.assertIn("FakeCryptoContext", export.excluded_reason or "")

    def test_partial_coverage_is_excluded(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, strict=False) as session:
            session.context.EvalRotateKeyGen(object(), [1, 2])
            session.context.EvalRotate(FakeCiphertext(), 1)
            session.context.Unclassified(1)
        trace = session.to_trace()
        trace["run"]["runtime"]["backend"] = REAL_BACKEND
        artifacts = build_analysis_bundle(trace)
        with tempfile.TemporaryDirectory() as temporary:
            bundle = write_bundle(
                Path(temporary) / "partial",
                manifest=artifacts["manifest"],
                trace=artifacts["trace"],
                graph=artifacts["graph"],
                recommendations=artifacts["recommendations"],
            )
            export = export_bundle(bundle, allow_unscanned=True)
            self.assertIn("PARTIAL-PERMISSIVE", export.excluded_reason or "")

    def test_unreadable_bundle_is_an_exclusion_not_a_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            export = export_bundle(Path(temporary) / "missing")
            self.assertIn("unreadable bundle", export.excluded_reason or "")

    def test_complete_real_bundle_exports_rows_with_empty_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = _write_real_looking_bundle(Path(temporary) / "w1")
            export = export_bundle(bundle)
            self.assertIsNone(export.excluded_reason)
            self.assertEqual(export.workload_id, "w1")
            rules = sorted(row["rule_id"] for row in export.rows)
            self.assertIn("keys.unused_in_observed_run.v1", rules)
            self.assertIn("rotation.hoist_same_input.v1", rules)
            for row in export.rows:
                self.assertEqual(tuple(row.keys()), FINDINGS_COLUMNS)
                self.assertTrue(row["finding_id"].startswith(f"w1:{row['rule_id']}:"))
                self.assertEqual(row["coverage_class"], "COMPLETE")
                for column in HUMAN_COLUMNS:
                    self.assertEqual(row[column], "", column)

    def test_finding_ids_are_stable_across_reruns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = export_bundle(_write_real_looking_bundle(Path(temporary) / "w"))
            second = export_bundle(_write_real_looking_bundle(Path(temporary) / "again" / "w"))
            self.assertNotEqual(first.rows[0]["run_id"], second.rows[0]["run_id"])
            self.assertEqual(
                sorted(row["finding_id"] for row in first.rows),
                sorted(row["finding_id"] for row in second.rows),
            )


class MergeTests(unittest.TestCase):
    def _rows(self, workload: str, *rules: str) -> list[dict]:
        return [
            {
                **{column: "" for column in FINDINGS_COLUMNS},
                "finding_id": f"{workload}:{rule}:{index:08x}",
                "workload_id": workload,
                "rule_id": rule,
            }
            for index, rule in enumerate(rules)
        ]

    def _export(self, workload: str, rows: list[dict]):
        from cipherscope.adjudication import BundleExport

        return BundleExport(Path("/b") / workload, workload, rows=tuple(rows))

    def test_verdicts_are_carried_and_new_rows_added(self) -> None:
        existing = self._rows("w", "rule.a", "rule.b")
        existing[0]["adjudication"] = "TP-ACTIONABLE"
        existing[0]["evidence_summary"] = "kept"
        fresh = self._rows("w", "rule.a", "rule.b", "rule.c")
        result = merge_findings(existing, [self._export("w", fresh)])
        self.assertEqual((result.added, result.carried, result.untouched), (1, 2, 0))
        by_id = {row["finding_id"]: row for row in result.rows}
        self.assertEqual(by_id[existing[0]["finding_id"]]["adjudication"], "TP-ACTIONABLE")
        self.assertEqual(by_id[existing[0]["finding_id"]]["evidence_summary"], "kept")
        self.assertEqual(result.stale, [])

    def test_vanished_finding_becomes_stale_not_lost(self) -> None:
        existing = self._rows("w", "rule.a", "rule.b")
        existing[1]["adjudication"] = "FALSE-POSITIVE"
        fresh = self._rows("w", "rule.a")
        result = merge_findings(existing, [self._export("w", fresh)])
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(len(result.stale), 1)
        self.assertEqual(result.stale[0]["adjudication"], "FALSE-POSITIVE")

    def test_other_workloads_are_untouched_by_a_partial_export(self) -> None:
        existing = self._rows("w1", "rule.a") + self._rows("w2", "rule.a")
        existing[1]["adjudication"] = "UNCERTAIN"
        result = merge_findings(existing, [self._export("w1", self._rows("w1", "rule.a"))])
        self.assertEqual(result.untouched, 1)
        self.assertEqual(result.stale, [])
        kept = [row for row in result.rows if row["workload_id"] == "w2"]
        self.assertEqual(kept[0]["adjudication"], "UNCERTAIN")

    def test_machine_columns_are_refreshed_from_the_export(self) -> None:
        existing = self._rows("w", "rule.a")
        existing[0]["source_lines"] = "old"
        existing[0]["notes"] = "human note"
        fresh = self._rows("w", "rule.a")
        fresh[0]["source_lines"] = "new"
        result = merge_findings(existing, [self._export("w", fresh)])
        self.assertEqual(result.rows[0]["source_lines"], "new")
        self.assertEqual(result.rows[0]["notes"], "human note")


class CSVSafetyTests(unittest.TestCase):
    def test_round_trip_and_column_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "findings.csv"
            rows = [{**{c: "" for c in FINDINGS_COLUMNS}, "finding_id": "a", "workload_id": "w", "rule_id": "r"}]
            write_findings(rows, path)
            self.assertEqual(read_findings(path)[0]["finding_id"], "a")
            path.write_text("finding_id,rule_id\na,r\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_findings(path)

    def test_duplicate_finding_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "findings.csv"
            row = {**{c: "" for c in FINDINGS_COLUMNS}, "finding_id": "dup", "workload_id": "w", "rule_id": "r"}
            write_findings([row, dict(row)], path)
            with self.assertRaises(ValueError):
                read_findings(path)


class PrecisionTests(unittest.TestCase):
    def _row(self, rule: str, verdict: str = "", evidence: str = "", second: str = "") -> dict:
        return {
            **{c: "" for c in FINDINGS_COLUMNS},
            "finding_id": f"w:{rule}:{verdict}{evidence}{second}",
            "workload_id": "w",
            "rule_id": rule,
            "adjudication": verdict,
            "evidence_summary": evidence,
            "adjudicator_2": second,
        }

    def test_counts_and_denominator(self) -> None:
        rows = [
            self._row("r1", "TP-ACTIONABLE", "ev"),
            self._row("r1", "TP-NONACTIONABLE", "ev"),
            self._row("r1", "FALSE-POSITIVE", "ev"),
            self._row("r1", "UNCERTAIN", "ev"),
            self._row("r1", "NOT-IN-SCOPE", "ev"),
            self._row("r1"),
            self._row("r2", "TP-ACTIONABLE"),
        ]
        report = precision_report(rows)
        self.assertEqual(report["findings"], 7)
        self.assertEqual(report["adjudicated"], 5)
        self.assertEqual(report["pending"], 1)
        self.assertEqual(report["adjudicated_without_evidence"], 1)
        r1 = next(row for row in report["table"] if row["rule_id"] == "r1")
        self.assertEqual((r1["precision_numerator"], r1["precision_denominator"]), (2, 4))
        self.assertEqual(r1["precision"], 0.5)
        r2 = next(row for row in report["table"] if row["rule_id"] == "r2")
        self.assertEqual(r2["adjudicated_without_evidence"], 1)
        self.assertIsNone(r2["precision"])
        self.assertIn("precision_definition", report)
        self.assertTrue(any("recall" in item for item in report["limitations"]))
        self.assertTrue(any("single reviewer" in item for item in report["limitations"]))

    def test_partial_second_review_is_stated(self) -> None:
        rows = [self._row("r", "TP-ACTIONABLE", "ev", second="B"), self._row("r", "UNCERTAIN", "ev")]
        report = precision_report(rows)
        self.assertEqual(report["second_reviews"], 1)
        self.assertTrue(any("1 of 2" in item for item in report["limitations"]))

    def test_invalid_verdict_is_rejected(self) -> None:
        with self.assertRaises(ValueError) as context:
            precision_report([self._row("r", "MAYBE", "ev")])
        self.assertIn("MAYBE", str(context.exception))

    def test_rubric_values_are_the_plan_rubric(self) -> None:
        self.assertEqual(
            ADJUDICATIONS,
            ("TP-ACTIONABLE", "TP-NONACTIONABLE", "FALSE-POSITIVE", "UNCERTAIN", "NOT-IN-SCOPE"),
        )


class FindingsCLITests(unittest.TestCase):
    def test_export_merge_and_precision_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = _write_real_looking_bundle(root / "w1")
            demo = root / "demo"
            findings = root / "evaluation" / "findings.csv"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["demo", "--output", str(demo)]), 0)
                stdout.truncate(0)
                stdout.seek(0)
                code = main(["findings", str(bundle), str(demo), "--output", str(findings)])
            self.assertEqual(code, 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(list(summary["exported"]), ["w1"])
            self.assertIn(str(demo.resolve()), summary["excluded"])
            self.assertTrue(summary["written"])

            with findings.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(tuple(rows[0].keys()), FINDINGS_COLUMNS)
            rows[0]["adjudication"] = "TP-ACTIONABLE"
            rows[0]["evidence_summary"] = "checked by hand"
            write_findings(rows, findings)

            with contextlib.redirect_stdout(stdout):
                stdout.truncate(0)
                stdout.seek(0)
                self.assertEqual(main(["findings", str(bundle), "--output", str(findings)]), 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["added"], 0)
            self.assertEqual(summary["carried_verdicts"], len(rows))

            table = root / "precision.csv"
            with contextlib.redirect_stdout(stdout):
                stdout.truncate(0)
                stdout.seek(0)
                self.assertEqual(main(["precision", str(findings), "--output", str(table)]), 0)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["adjudicated"], 1)
            with table.open(encoding="utf-8", newline="") as stream:
                self.assertEqual(tuple(csv.DictReader(stream).fieldnames), PRECISION_COLUMNS)

    def test_no_qualifying_bundle_does_not_touch_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            demo = root / "demo"
            findings = root / "findings.csv"
            findings.write_text("keep me", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["demo", "--output", str(demo)]), 0)
                self.assertEqual(main(["findings", str(demo), "--output", str(findings)]), 1)
            self.assertEqual(findings.read_text(encoding="utf-8"), "keep me")

    def test_precision_rejects_invalid_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "findings.csv"
            row = {**{c: "" for c in FINDINGS_COLUMNS}, "finding_id": "a", "workload_id": "w", "rule_id": "r", "adjudication": "YES"}
            write_findings([row], path)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["precision", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
