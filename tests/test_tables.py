"""The evaluation data contract and the paper-table generator."""

from __future__ import annotations

import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cipherscope.adjudication import FINDINGS_COLUMNS, write_findings
from cipherscope.tables import (
    OVERHEAD_COLUMNS,
    SCALING_COLUMNS,
    ContractError,
    coverage_rows,
    generate_tables,
    load_contract,
    overhead_rows,
    scaling_rows,
    seeded_case_rows,
    validate_rows,
)

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "evaluation" / "schema" / "results.schema.json"
CONTRACT = load_contract(SCHEMA)

RUN_TEMPLATE = {
    "workload_id": "w",
    "workload_commit": "abc",
    "cipherscope_commit": "def",
    "lane": "primary-source-py311",
    "repetition": "0",
    "arm": "baseline",
    "wall_ms": "100.0",
    "cpu_ms": "90.0",
    "peak_rss_mb": "500",
    "event_count": "",
    "trace_bytes": "",
    "graph_bytes": "",
    "analyzer_ms": "",
    "coverage_class": "",
    "passthrough_calls": "",
    "correctness_metric": "max_abs_error",
    "correctness_value": "1e-6",
    "machine_id": "ls6",
    "cpu_model": "Grace",
    "openfhe_version": "1.5.1.0",
    "python_version": "3.11.15",
}


def _run(**overrides: str) -> dict[str, str]:
    return {**RUN_TEMPLATE, **overrides}


class ContractTests(unittest.TestCase):
    def test_schema_defines_the_plan_records(self) -> None:
        self.assertEqual(
            set(CONTRACT),
            {"workload_run", "finding", "seeded_case", "coverage_run", "scaling_run", "ablation_run"},
        )
        self.assertEqual(CONTRACT["finding"].columns, FINDINGS_COLUMNS)
        self.assertEqual(CONTRACT["workload_run"].columns[:6], (
            "workload_id", "workload_commit", "cipherscope_commit", "lane", "repetition", "arm",
        ))

    def test_valid_rows_are_typed(self) -> None:
        typed = validate_rows(CONTRACT["workload_run"], [_run(), _run(arm="traced", event_count="12", coverage_class="COMPLETE")])
        self.assertEqual(typed[0]["wall_ms"], 100.0)
        self.assertIsNone(typed[0]["event_count"])
        self.assertEqual(typed[1]["event_count"], 12)
        self.assertEqual(typed[1]["repetition"], 0)

    def test_rejections_name_the_offending_column(self) -> None:
        bad = {
            "unknown column": {**_run(), "extra": "x"},
            "missing column": {k: v for k, v in _run().items() if k != "arm"},
            "bad enum": _run(arm="warmup"),
            "bad lane": _run(lane="laptop"),
            "non-integer": _run(repetition="1.5"),
            "negative": _run(wall_ms="-1"),
            "empty required": _run(workload_id=""),
            "non-finite": _run(cpu_ms="nan"),
            "empty non-nullable": _run(wall_ms=""),
        }
        for label, row in bad.items():
            with self.subTest(label=label), self.assertRaises(ContractError) as context:
                validate_rows(CONTRACT["workload_run"], [row])
            self.assertIn("row 2", str(context.exception))

    def test_finding_rows_use_the_rubric_and_complete_only(self) -> None:
        row = {c: "" for c in FINDINGS_COLUMNS}
        row.update(finding_id="f", workload_id="w", rule_id="r", confidence="measured",
                   severity="opportunity", coverage_class="COMPLETE", bundle="b", run_id="run")
        validate_rows(CONTRACT["finding"], [row])
        with self.assertRaises(ContractError):
            validate_rows(CONTRACT["finding"], [{**row, "adjudication": "MAYBE"}])
        with self.assertRaises(ContractError):
            validate_rows(CONTRACT["finding"], [{**row, "coverage_class": "PARTIAL-PERMISSIVE"}])


class GeneratorTests(unittest.TestCase):
    def test_overhead_rows_medians_and_bootstrap_are_deterministic(self) -> None:
        runs = []
        for i, wall in enumerate([100, 102, 98, 101, 99]):
            runs.append({**_run(repetition=str(i), wall_ms=str(wall), cpu_ms=str(wall - 10), peak_rss_mb="500"), "arm": "baseline"})
        for i, wall in enumerate([120, 125, 118, 122, 121]):
            runs.append({**_run(repetition=str(i), wall_ms=str(wall), cpu_ms=str(wall - 10), peak_rss_mb="520", event_count="40", trace_bytes="8000", analyzer_ms="3"), "arm": "traced"})
        typed = validate_rows(CONTRACT["workload_run"], runs)
        first = overhead_rows(typed)
        second = overhead_rows(typed)
        self.assertEqual(first, second)
        row = first[0]
        self.assertEqual(tuple(row), OVERHEAD_COLUMNS)
        self.assertEqual((row["n_baseline"], row["n_traced"]), (5, 5))
        self.assertEqual(row["wall_baseline_median_ms"], 100)
        self.assertEqual(row["wall_traced_median_ms"], 121)
        self.assertAlmostEqual(row["wall_overhead_ratio"], 0.21)
        self.assertAlmostEqual(row["wall_overhead_abs_ms"], 21)
        self.assertLessEqual(row["wall_overhead_ratio_ci_low"], row["wall_overhead_ratio"])
        self.assertGreaterEqual(row["wall_overhead_ratio_ci_high"], row["wall_overhead_ratio"])
        self.assertEqual(row["rss_delta_mb"], 20)
        self.assertEqual(row["event_count_median"], 40)
        self.assertEqual(first[-1]["workload_id"], "ALL")
        self.assertAlmostEqual(first[-1]["wall_overhead_ratio"], 0.21)

    def test_overhead_with_one_arm_missing_has_no_ratio(self) -> None:
        typed = validate_rows(CONTRACT["workload_run"], [_run()])
        row = overhead_rows(typed)[0]
        self.assertIsNone(row["wall_overhead_ratio"])
        self.assertIsNone(row["wall_overhead_ratio_ci_low"])
        self.assertEqual(row["wall_baseline_iqr_ms"], 0.0)

    def test_coverage_rows_fractions(self) -> None:
        rows = coverage_rows([
            {"bundle": "a", "coverage_class": "COMPLETE"},
            {"bundle": "b", "coverage_class": "COMPLETE"},
            {"bundle": "c", "coverage_class": "UNSUPPORTED", "unsupported_operations": "EvalAddMany", "reasons": "x"},
        ])
        by_class = {row["coverage_class"]: row for row in rows}
        self.assertEqual(by_class["COMPLETE"]["runs"], 2)
        self.assertAlmostEqual(by_class["COMPLETE"]["fraction"], 2 / 3)
        self.assertEqual(by_class["ALL"]["runs"], 3)

    def test_seeded_case_rows_flatten_and_validate(self) -> None:
        document = json.loads((ROOT / "evaluation" / "raw" / "seeded" / "case_results.json").read_text())
        rows = seeded_case_rows(document)
        self.assertGreaterEqual(len(rows), 20)
        self.assertEqual(rows, sorted(rows, key=lambda r: (r["case_id"], r["rule_id"])))
        textual = [{k: ("" if v is None else str(v).lower() if isinstance(v, bool) else str(v)) for k, v in row.items()} for row in rows]
        validate_rows(CONTRACT["seeded_case"], textual)
        positive = next(r for r in rows if r["case_id"] == "rotation.positive.same_version" and r["rule_id"].startswith("rotation"))
        self.assertTrue(positive["should_fire"])
        self.assertEqual(positive["outcome"], "hit")
        self.assertEqual(positive["clean_kernel"], "rotation_kernel_clean.py")


class ScalingTableTests(unittest.TestCase):
    def _run(self, size: int, arm: str, wall: float, growth: float, peak: float, **extra) -> dict[str, str]:
        base = {
            "size": str(size), "arm": arm, "repetition": "0", "events": "0" if arm == "baseline" else str(size),
            "run_wall_ms": str(wall), "rss_start_mb": "40", "rss_end_mb": str(40 + growth), "rss_growth_mb": str(growth),
            "peak_rss_mb": str(peak), "finalize_ms": "", "analyze_ms": "", "trace_bytes": "", "graph_bytes": "",
            "recommendations_bytes": "", "spooled": "false", "python_version": "3.11.15", "machine": "arm64",
        }
        base.update({k: str(v) for k, v in extra.items()})
        return base

    def test_scaling_rows_reference_the_baseline_arm(self) -> None:
        runs = validate_rows(CONTRACT["scaling_run"], [
            self._run(1000, "baseline", 500, 10, 80),
            self._run(1000, "streaming", 600, 30, 130, analyze_ms=200, trace_bytes=2_000_000, finalize_ms=50, spooled="true"),
            self._run(1000, "buffered", 610, 40, 150, analyze_ms=200, trace_bytes=2_000_000, finalize_ms=50),
        ])
        rows = scaling_rows(runs)
        self.assertEqual([row["arm"] for row in rows], ["baseline", "streaming", "buffered"])
        self.assertEqual({row["machine"] for row in rows}, {"arm64"})
        self.assertEqual(tuple(rows[1]), SCALING_COLUMNS)
        streaming = rows[1]
        self.assertAlmostEqual(streaming["wall_overhead_ratio_vs_baseline"], 0.2)
        self.assertEqual(streaming["rss_growth_vs_baseline_mb"], 20)
        self.assertEqual(streaming["peak_rss_vs_baseline_mb"], 50)
        self.assertEqual(streaming["bytes_per_event"], 2000)
        self.assertEqual(streaming["analyze_ms_per_1k_events"], 200)
        self.assertIsNone(rows[0]["wall_overhead_ratio_vs_baseline"])
        self.assertEqual(scaling_rows(runs), rows)

    def test_scaling_rows_never_pool_machines(self) -> None:
        runs = validate_rows(CONTRACT["scaling_run"], [
            self._run(1000, "baseline", 500, 10, 80),
            self._run(1000, "streaming", 600, 30, 130, analyze_ms=200, trace_bytes=2_000_000, finalize_ms=50),
            self._run(1000, "baseline", 250, 10, 60, machine="x86_64"),
            self._run(1000, "streaming", 500, 30, 100, analyze_ms=100, trace_bytes=2_000_000, finalize_ms=25, machine="x86_64"),
        ])
        rows = scaling_rows(runs)
        self.assertEqual([(row["machine"], row["arm"]) for row in rows],
                         [("arm64", "baseline"), ("arm64", "streaming"), ("x86_64", "baseline"), ("x86_64", "streaming")])
        # Each machine's overhead ratio is taken against its own baseline.
        self.assertAlmostEqual(rows[1]["wall_overhead_ratio_vs_baseline"], 0.2)
        self.assertAlmostEqual(rows[3]["wall_overhead_ratio_vs_baseline"], 1.0)
        self.assertEqual(rows[3]["peak_rss_vs_baseline_mb"], 40)

    def test_archived_scaling_record_validates(self) -> None:
        from cipherscope.tables import read_csv

        rows = validate_rows(CONTRACT["scaling_run"], read_csv(ROOT / "evaluation" / "raw" / "scaling.csv"))
        self.assertGreaterEqual(len(rows), 6)
        arms = {row["arm"] for row in rows}
        self.assertEqual(arms, {"baseline", "streaming", "buffered"})


class EndToEndTests(unittest.TestCase):
    def _evaluation_dir(self, root: Path) -> Path:
        evaluation = root / "evaluation"
        (evaluation / "schema").mkdir(parents=True)
        shutil.copy(SCHEMA, evaluation / "schema" / "results.schema.json")
        (evaluation / "raw" / "seeded").mkdir(parents=True)
        shutil.copy(ROOT / "evaluation" / "raw" / "seeded" / "case_results.json", evaluation / "raw" / "seeded")
        (evaluation / "adjudication").mkdir()
        row = {c: "" for c in FINDINGS_COLUMNS}
        row.update(finding_id="w:r:1", workload_id="w", rule_id="rotation.hoist_same_input.v1", confidence="measured",
                   severity="opportunity", coverage_class="COMPLETE", bundle="b", run_id="run",
                   adjudication="TP-ACTIONABLE", evidence_summary="checked")
        write_findings([row], evaluation / "adjudication" / "findings.csv")
        with (evaluation / "raw" / "workload_runs.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(RUN_TEMPLATE))
            writer.writeheader()
            writer.writerow(_run())
            writer.writerow(_run(arm="traced", wall_ms="130", event_count="5", coverage_class="COMPLETE"))
        return evaluation

    def test_generate_is_byte_for_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evaluation = self._evaluation_dir(Path(temporary))
            first = generate_tables(evaluation)
            self.assertEqual(set(first["tables"]), {"precision.csv", "recall.csv", "seeded_cases.csv", "overhead.csv"})
            self.assertEqual(sorted(first["skipped_inputs"]), ["ablation", "coverage", "scaling"])
            snapshot = {p.name: p.read_bytes() for p in (evaluation / "tables").iterdir()}
            shutil.rmtree(evaluation / "tables")
            second = generate_tables(evaluation)
            self.assertEqual(first, second)
            for path in (evaluation / "tables").iterdir():
                self.assertEqual(path.read_bytes(), snapshot[path.name], path.name)
            manifest = json.loads((evaluation / "tables" / "MANIFEST.json").read_text())
            self.assertIn("seed", manifest["bootstrap"])
            self.assertNotIn("generated_at", manifest)
            # Paths are repository-relative so the manifest is identical on every machine.
            for name, path in manifest["skipped_inputs"].items():
                self.assertFalse(Path(path).is_absolute(), (name, path))
            for entry in manifest["inputs"].values():
                self.assertFalse(Path(entry["path"]).is_absolute(), entry)

    def test_bad_input_is_refused_before_anything_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evaluation = self._evaluation_dir(Path(temporary))
            runs = evaluation / "raw" / "workload_runs.csv"
            runs.write_text(runs.read_text().replace("baseline", "warmup", 1))
            with self.assertRaises(ContractError) as context:
                generate_tables(evaluation)
            self.assertIn("arm", str(context.exception))
            self.assertFalse((evaluation / "tables").exists())


if __name__ == "__main__":
    unittest.main()
