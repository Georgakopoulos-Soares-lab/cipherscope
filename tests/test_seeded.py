"""Seeded benchmark: ground-truth loading, case evaluation, and the recall table."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

import cipherscope
from cipherscope.cli import main
from cipherscope.exporters import write_bundle
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.seeded import (
    EVIDENCE_MISMATCH,
    EXPECTED_NOT_APPLICABLE,
    FALSE_POSITIVE,
    HIT,
    INVALID_RUN,
    MISS,
    SOURCE_MISMATCH,
    TABLE_COLUMNS,
    TRUE_NEGATIVE,
    UNEXPECTED_APPLICABILITY,
    CaseResult,
    RuleResult,
    SeededCase,
    evaluate_case,
    load_ground_truth,
    recall_table,
    write_results,
)
from cipherscope.testing import FakeCiphertext, FakeCryptoContext

THIS_FILE = Path(__file__).resolve()
ROTATION = "rotation.hoist_same_input.v1"
KEYS = "keys.unused_in_observed_run.v1"
DEPTH = "depth.critical_path.v1"
ENCODING = "encoding.repeated_public_constant.v1"


def _bundle(
    directory: Path,
    *,
    generated: tuple[int, ...] = (1, 2, 5),
    used: tuple[int, ...] = (1, 2),
    real: bool = True,
    permissive: bool = False,
) -> Path:
    """Write a bundle recorded from this test file so it is the case entrypoint."""

    backend = FakeCryptoContext()
    source = FakeCiphertext()
    with cipherscope.trace(backend, strict=not permissive) as session:
        session.context.EvalRotateKeyGen(object(), list(generated))
        for index in used:
            session.context.EvalRotate(source, index)
        if permissive:
            session.context.Unclassified(1)
    trace = session.to_trace()
    if real:
        trace["run"]["runtime"]["backend"] = "CryptoContext"
    artifacts = build_analysis_bundle(trace)
    return write_bundle(
        directory,
        manifest=artifacts["manifest"],
        trace=artifacts["trace"],
        graph=artifacts["graph"],
        recommendations=artifacts["recommendations"],
    )


def _case(expected: dict[str, str], *, lines=None, evidence=None, path: Path = THIS_FILE) -> SeededCase:
    return SeededCase(
        case_id="case",
        path=path,
        kind="positive",
        expected=expected,
        expected_source_lines=lines or {},
        expected_evidence=evidence or {},
    )


def _outcomes(result: CaseResult) -> dict[str, str]:
    return {rule.rule_id: rule.outcome for rule in result.rules}


class GroundTruthLoaderTests(unittest.TestCase):
    def _write(self, root: Path, cases: list[dict]) -> Path:
        (root / "cases").mkdir(exist_ok=True)
        (root / "cases" / "ok.py").write_text("print('ok')\n", encoding="utf-8")
        path = root / "ground_truth.json"
        path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
        return path

    def _entry(self, **overrides) -> dict:
        entry = {
            "case_id": "c1",
            "path": "cases/ok.py",
            "kind": "positive",
            "expected": {ROTATION: "positive"},
        }
        entry.update(overrides)
        return entry

    def test_valid_file_resolves_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = load_ground_truth(
                self._write(
                    root,
                    [
                        self._entry(
                            expected_source_lines={ROTATION: [5, 3, 5]},
                            expected_evidence={ROTATION: {"a.b": 1}},
                            clean_kernel="cases/ok.py",
                        )
                    ],
                )
            )
            self.assertEqual(cases[0].path, (root / "cases" / "ok.py").resolve())
            self.assertEqual(cases[0].expected_source_lines, {ROTATION: [3, 5]})
            self.assertEqual(cases[0].expected_evidence, {ROTATION: {"a.b": 1}})
            self.assertIsNotNone(cases[0].clean_kernel)

    def test_rejections(self) -> None:
        bad = {
            "empty": [],
            "duplicate_id": [self._entry(), self._entry()],
            "missing_path": [self._entry(path="cases/nope.py")],
            "bad_kind": [self._entry(kind="maybe")],
            "unknown_rule": [self._entry(expected={"no.such.rule": "positive"})],
            "bad_outcome": [self._entry(expected={ROTATION: "fires"})],
            "empty_expected": [self._entry(expected={})],
            "lines_for_unlisted_rule": [self._entry(expected_source_lines={KEYS: [1]})],
            "non_int_lines": [self._entry(expected_source_lines={ROTATION: ["1"]})],
            "evidence_for_unlisted_rule": [self._entry(expected_evidence={KEYS: {"x": 1}})],
            "missing_kernel": [self._entry(clean_kernel="cases/nope.py")],
        }
        for label, cases in bad.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                path = self._write(Path(temporary), cases)
                with self.assertRaises((ValueError, TypeError)):
                    load_ground_truth(path)


class EvaluateCaseTests(unittest.TestCase):
    def test_hit_miss_false_positive_true_negative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unused_key = _bundle(Path(temporary) / "unused")
            all_used = _bundle(Path(temporary) / "used", generated=(1, 2), used=(1, 2))

            result = evaluate_case(_case({ROTATION: "positive", KEYS: "positive"}), unused_key)
            self.assertIsNone(result.invalid_reason)
            self.assertEqual(_outcomes(result), {ROTATION: HIT, KEYS: HIT})
            self.assertTrue(result.matched)

            result = evaluate_case(_case({KEYS: "clean"}), unused_key)
            self.assertEqual(_outcomes(result), {KEYS: FALSE_POSITIVE})
            self.assertFalse(result.matched)

            result = evaluate_case(_case({KEYS: "positive"}), all_used)
            self.assertEqual(_outcomes(result), {KEYS: MISS})

            result = evaluate_case(_case({KEYS: "clean"}), all_used)
            self.assertEqual(_outcomes(result), {KEYS: TRUE_NEGATIVE})
            self.assertTrue(result.matched)

    def test_not_applicable_expectations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = _bundle(Path(temporary) / "b")
            result = evaluate_case(_case({ENCODING: "not_applicable"}), bundle)
            self.assertEqual(_outcomes(result), {ENCODING: EXPECTED_NOT_APPLICABLE})
            self.assertTrue(result.matched)
            self.assertTrue({DEPTH, KEYS, ROTATION} <= set(result.unexpected_positives))
            self.assertNotIn(ENCODING, result.unexpected_positives)

            result = evaluate_case(_case({ENCODING: "clean"}), bundle)
            self.assertEqual(_outcomes(result), {ENCODING: UNEXPECTED_APPLICABILITY})
            self.assertFalse(result.matched)

    def test_source_lines_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = _bundle(Path(temporary) / "b")
            recommendations = json.loads((bundle / "recommendations.json").read_text())
            rotation = next(f for f in recommendations["findings"] if f["rule_id"] == ROTATION)
            real_lines = sorted(rotation["source"]["lines"])

            hit = evaluate_case(_case({ROTATION: "positive"}, lines={ROTATION: real_lines[:1]}), bundle)
            self.assertEqual(_outcomes(hit), {ROTATION: HIT})
            wrong = evaluate_case(_case({ROTATION: "positive"}, lines={ROTATION: [999999]}), bundle)
            self.assertEqual(_outcomes(wrong), {ROTATION: SOURCE_MISMATCH})
            self.assertIn("999999", wrong.rules[0].detail)

            ok = evaluate_case(
                _case({DEPTH: "positive"}, evidence={DEPTH: {"nonlinear_ciphertext.max_depth": 0}}),
                bundle,
            )
            self.assertEqual(_outcomes(ok), {DEPTH: HIT})
            bad = evaluate_case(
                _case({DEPTH: "positive"}, evidence={DEPTH: {"nonlinear_ciphertext.max_depth": 42}}),
                bundle,
            )
            self.assertEqual(_outcomes(bad), {DEPTH: EVIDENCE_MISMATCH})
            missing = evaluate_case(
                _case({DEPTH: "positive"}, evidence={DEPTH: {"no.such.key": 1}}), bundle
            )
            self.assertEqual(_outcomes(missing), {DEPTH: EVIDENCE_MISMATCH})

    def test_invalid_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = evaluate_case(_case({ROTATION: "positive"}), _bundle(root / "fake", real=False))
            self.assertIn("FakeCryptoContext", fake.invalid_reason or "")
            partial = evaluate_case(
                _case({ROTATION: "positive"}), _bundle(root / "partial", permissive=True)
            )
            self.assertIn("PARTIAL-PERMISSIVE", partial.invalid_reason or "")
            self.assertEqual(partial.coverage_class, "PARTIAL-PERMISSIVE")
            other = evaluate_case(
                _case({ROTATION: "positive"}, path=root / "elsewhere.py"), _bundle(root / "b")
            )
            self.assertIn("not", other.invalid_reason or "")
            missing = evaluate_case(_case({ROTATION: "positive"}), root / "nope")
            self.assertIn("unreadable bundle", missing.invalid_reason or "")
            for result in (fake, partial, other, missing):
                self.assertFalse(result.matched)
                self.assertEqual(_outcomes(result), {ROTATION: INVALID_RUN})


class RecallTableTests(unittest.TestCase):
    def _result(self, case_id: str, *rules: tuple[str, str, str], invalid: str | None = None) -> CaseResult:
        return CaseResult(
            case_id,
            "positive",
            "/b",
            None if invalid else "COMPLETE",
            invalid,
            tuple(RuleResult(rule, expected, "", outcome) for rule, expected, outcome in rules),
            (),
        )

    def test_rates_and_zero_denominators(self) -> None:
        results = [
            self._result("p1", (ROTATION, "positive", HIT)),
            self._result("p2", (ROTATION, "positive", MISS)),
            self._result("p3", (ROTATION, "positive", SOURCE_MISMATCH)),
            self._result("n1", (ROTATION, "clean", TRUE_NEGATIVE)),
            self._result("n2", (ROTATION, "clean", FALSE_POSITIVE)),
            self._result("n3", (ROTATION, "not_applicable", EXPECTED_NOT_APPLICABLE)),
            self._result("n4", (ROTATION, "clean", UNEXPECTED_APPLICABILITY)),
            self._result("x1", (ROTATION, "positive", INVALID_RUN), invalid="bad"),
            self._result("k1", (KEYS, "clean", TRUE_NEGATIVE)),
        ]
        table = {row["rule_id"]: row for row in recall_table(results)}
        rotation = table[ROTATION]
        self.assertEqual((rotation["seeded_positives"], rotation["detected"]), (3, 1))
        self.assertAlmostEqual(rotation["recall"], 1 / 3)
        self.assertEqual((rotation["seeded_negatives"], rotation["false_positives"]), (4, 1))
        self.assertEqual(rotation["fp_rate"], 0.25)
        self.assertEqual(rotation["not_applicable_cases"], 1)
        self.assertEqual(rotation["mismatches"], 2)
        self.assertEqual(rotation["invalid_runs"], 1)
        self.assertIsNone(table[KEYS]["recall"])
        self.assertEqual(table[KEYS]["fp_rate"], 0.0)
        self.assertEqual(table["ALL"]["seeded_positives"], 3)
        self.assertEqual(table["ALL"]["seeded_negatives"], 5)

    def test_write_results_files(self) -> None:
        results = [self._result("p1", (ROTATION, "positive", HIT)), self._result("k1", (KEYS, "clean", TRUE_NEGATIVE))]
        with tempfile.TemporaryDirectory() as temporary:
            json_path, csv_path = write_results(results, recall_table(results), Path(temporary))
            document = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(document["all_matched"])
            self.assertEqual(document["cases"][0]["case_id"], "p1")
            with csv_path.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(tuple(rows[0].keys()), TABLE_COLUMNS)
            by_rule = {row["rule_id"]: row for row in rows}
            self.assertEqual(by_rule[KEYS]["recall"], "")
            self.assertEqual(by_rule[ROTATION]["recall"], "1.0000")


class SeededCLITests(unittest.TestCase):
    def _ground_truth(self, root: Path, expected: dict[str, str]) -> Path:
        path = root / "ground_truth.json"
        path.write_text(
            json.dumps(
                {
                    "cases": [
                        {
                            "case_id": "case",
                            "path": str(THIS_FILE),
                            "kind": "positive",
                            "expected": expected,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_from_bundles_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "out"
            _bundle(output / "bundles" / "case")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(
                    [
                        "seeded",
                        str(self._ground_truth(root, {ROTATION: "positive"})),
                        "--output",
                        str(output),
                        "--from-bundles",
                    ]
                )
            self.assertEqual(code, 0)
            summary = json.loads(stdout.getvalue())
            self.assertTrue(summary["all_matched"])
            self.assertTrue((output / "recall_table.csv").is_file())

            with contextlib.redirect_stdout(stdout):
                stdout.truncate(0)
                stdout.seek(0)
                code = main(
                    [
                        "seeded",
                        str(self._ground_truth(root, {KEYS: "clean"})),
                        "--output",
                        str(output),
                        "--from-bundles",
                    ]
                )
            self.assertEqual(code, 1)
            summary = json.loads(stdout.getvalue())
            self.assertIn("case", summary["failures"])
            self.assertIn(f"{KEYS}: {FALSE_POSITIVE}", summary["failures"]["case"][0])

    def test_bad_ground_truth_is_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "gt.json"
            path.write_text('{"cases": []}', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["seeded", str(path), "--output", temporary]), 2)


if __name__ == "__main__":
    unittest.main()
