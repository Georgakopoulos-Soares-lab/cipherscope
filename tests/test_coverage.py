"""Coverage classification and the preflight bypass scanner."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
import textwrap
import unittest
from pathlib import Path

import cipherscope
from cipherscope.cli import main
from cipherscope.coverage import (
    COMPLETE,
    PARTIAL_PERMISSIVE,
    REPORT_COLUMNS,
    UNSUPPORTED,
    CoverageRisk,
    classify_run,
    entrypoint_from_trace,
    scan_file,
    scan_source,
    summarize_report,
)
from cipherscope.testing import FakeCiphertext, FakeCryptoContext

REPO = Path(__file__).resolve().parent.parent


def _scan(source: str) -> list[tuple[str, int, bool]]:
    risks = scan_source(textwrap.dedent(source))
    return [(risk.kind, risk.line, risk.bypasses_tracer) for risk in risks]


def _trace(
    *,
    status: str = "completed",
    strict: bool = True,
    traced: int = 3,
    forwarded: int = 0,
    rejected: int = 0,
    truncated: bool = False,
    unsupported: tuple[str, ...] = (),
    name: str | None = None,
    files: tuple[str, ...] = (),
) -> dict:
    run = {
        "run_id": "run_test",
        "status": status,
        "truncated": truncated,
        "coverage": {
            "strict": strict,
            "traced_semantic_calls": traced,
            "allowed_passthrough_calls": 0,
            "unclassified_proxy_passthrough_calls": forwarded,
            "rejected_unclassified_calls": rejected,
            "unsupported_operations": list(unsupported),
            "truncated": False,
        },
    }
    if name is not None:
        run["name"] = name
    return {
        "run": run,
        "events": [{"source": {"file": file}} for file in files],
    }


class PreflightScannerTests(unittest.TestCase):
    def test_raw_context_used_after_attach_is_a_bypass(self) -> None:
        risks = _scan(
            """
            import cipherscope, openfhe
            ctx = openfhe.GenCryptoContext(p)
            ctx.KeyGen()
            cc = cipherscope.attach(ctx)
            ctx.EvalAdd(a, b)
            """
        )
        self.assertEqual(risks, [("retained_raw_context", 6, True)])

    def test_raw_context_inside_trace_block_only(self) -> None:
        risks = _scan(
            """
            import cipherscope
            with cipherscope.trace(self.fixture.context) as session:
                result = self.fixture.context.EvalAdd(left, right)
            self.fixture.context.Decrypt(result, key)
            """
        )
        self.assertEqual(risks, [("retained_raw_context", 4, True)])

    def test_from_import_of_attach_is_recognized(self) -> None:
        risks = _scan(
            """
            from cipherscope import attach
            cc = attach(ctx)
            ctx.EvalMult(a, b)
            """
        )
        self.assertEqual(risks, [("retained_raw_context", 4, True)])

    def test_get_crypto_context_and_private_access(self) -> None:
        risks = _scan(
            """
            raw = ct.GetCryptoContext()
            cc._context.EvalAdd(a, b)
            """
        )
        self.assertEqual(
            risks,
            [
                ("raw_context_from_ciphertext", 2, True),
                ("proxy_private_access", 3, True),
            ],
        )

    def test_module_level_eval_calls(self) -> None:
        risks = _scan(
            """
            import openfhe as fhe
            from openfhe import EvalAddMany
            fhe.EvalSum(ct)
            EvalAddMany([a, b])
            """
        )
        self.assertEqual(
            risks,
            [("module_level_eval_call", 4, True), ("module_level_eval_call", 5, True)],
        )

    def test_star_import_free_function(self) -> None:
        risks = _scan(
            """
            from openfhe import *
            EvalRotate(ct, 1)
            """
        )
        self.assertEqual(risks, [("module_level_eval_call", 3, True)])

    def test_local_eval_function_is_not_flagged(self) -> None:
        risks = _scan(
            """
            from openfhe import *
            def EvalHelper(x):
                return x
            EvalHelper(1)
            """
        )
        self.assertEqual(risks, [])

    def test_gencryptocontext_alias_is_informational(self) -> None:
        risks = _scan(
            """
            import openfhe
            from openfhe import GenCryptoContext as gcc
            factory = openfhe.GenCryptoContext
            cc = gcc(p)
            """
        )
        self.assertEqual(
            risks,
            [("gencryptocontext_alias", 3, False), ("gencryptocontext_alias", 4, False)],
        )

    def test_plain_import_and_proxy_use_are_clean(self) -> None:
        risks = _scan(
            """
            from openfhe import GenCryptoContext
            import cipherscope
            cc = GenCryptoContext(p)
            with cipherscope.trace(cc) as session:
                session.context.EvalAdd(a, b)
            cc.Decrypt(x, key)
            """
        )
        self.assertEqual(risks, [])

    def test_repository_examples_scan_clean(self) -> None:
        for script in sorted((REPO / "examples" / "synthetic").glob("*.py")):
            with self.subTest(script=script.name):
                self.assertEqual(scan_file(script), ())
        self.assertEqual(scan_file(REPO / "examples" / "profiled_workload.py"), ())


class ClassificationTests(unittest.TestCase):
    def test_strict_clean_run_is_complete(self) -> None:
        assessment = classify_run(_trace())
        self.assertEqual(assessment.coverage_class, COMPLETE)
        self.assertEqual(assessment.reasons, ())

    def test_forwarded_calls_are_partial_and_named(self) -> None:
        assessment = classify_run(
            _trace(strict=False, forwarded=2, unsupported=("EvalAddMany",))
        )
        self.assertEqual(assessment.coverage_class, PARTIAL_PERMISSIVE)
        self.assertEqual(assessment.unsupported_operations, ("EvalAddMany",))
        self.assertIn("2 unclassified call(s) were forwarded untraced", assessment.reasons)

    def test_truncated_run_is_partial(self) -> None:
        assessment = classify_run(_trace(truncated=True))
        self.assertEqual(assessment.coverage_class, PARTIAL_PERMISSIVE)

    def test_bypassing_source_risk_downgrades_clean_trace(self) -> None:
        risk = CoverageRisk("retained_raw_context", 8, "detail", bypasses_tracer=True)
        assessment = classify_run(_trace(), risks=[risk])
        self.assertEqual(assessment.coverage_class, PARTIAL_PERMISSIVE)
        self.assertEqual(assessment.risks, (risk,))

    def test_informational_risk_keeps_complete(self) -> None:
        risk = CoverageRisk("gencryptocontext_alias", 2, "detail", bypasses_tracer=False)
        self.assertEqual(classify_run(_trace(), risks=[risk]).coverage_class, COMPLETE)

    def test_rejected_failed_or_empty_runs_are_unsupported(self) -> None:
        cases = {
            "rejected": _trace(rejected=1, unsupported=("EvalAddMany",)),
            "failed": _trace(status="failed"),
            "interrupted": _trace(status="interrupted"),
            "no_calls": _trace(traced=0),
        }
        for label, trace in cases.items():
            with self.subTest(label=label):
                self.assertEqual(classify_run(trace).coverage_class, UNSUPPORTED)

    def test_unsupported_wins_over_partial_reasons(self) -> None:
        assessment = classify_run(_trace(status="failed", strict=False, forwarded=1))
        self.assertEqual(assessment.coverage_class, UNSUPPORTED)
        self.assertEqual(assessment.reasons, ("run status is failed",))


class EntrypointTests(unittest.TestCase):
    def test_prefers_file_matching_run_name(self) -> None:
        trace = _trace(
            name="workload",
            files=("/lib/helper.py", "/lib/helper.py", "/w/workload.py"),
        )
        self.assertEqual(entrypoint_from_trace(trace), Path("/w/workload.py"))

    def test_falls_back_to_most_frequent_file(self) -> None:
        trace = _trace(files=("/a.py", "/b.py", "/b.py", "<string>"))
        self.assertEqual(entrypoint_from_trace(trace), Path("/b.py"))

    def test_no_sources_is_none(self) -> None:
        self.assertIsNone(entrypoint_from_trace(_trace(files=("<string>",))))


class RecorderNamesTests(unittest.TestCase):
    def test_strict_rejection_records_operation_name(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
            with self.assertRaises(cipherscope.UnsupportedOperationError):
                session.context.Unclassified(1)
        coverage = session.to_trace()["run"]["coverage"]
        self.assertEqual(coverage["unsupported_operations"], ["Unclassified"])
        self.assertEqual(coverage["rejected_unclassified_calls"], 1)
        self.assertEqual(classify_run(session.to_trace()).coverage_class, UNSUPPORTED)

    def test_permissive_forwarding_records_operation_name_once(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, strict=False) as session:
            session.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
            session.context.Unclassified(1)
            session.context.Unclassified(2)
        coverage = session.to_trace()["run"]["coverage"]
        self.assertEqual(coverage["unsupported_operations"], ["Unclassified"])
        self.assertEqual(coverage["unclassified_proxy_passthrough_calls"], 2)
        self.assertEqual(
            classify_run(session.to_trace()).coverage_class, PARTIAL_PERMISSIVE
        )


class CoverageCLITests(unittest.TestCase):
    def test_coverage_report_over_demo_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "demo"
            report = Path(temporary) / "coverage_report.csv"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["demo", "--output", str(bundle)]), 0)
                stdout.truncate(0)
                stdout.seek(0)
                self.assertEqual(
                    main(["coverage", str(bundle), "--output", str(report)]), 0
                )
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["counts"][COMPLETE], 1)
            self.assertEqual(summary["complete_fraction"], 1.0)
            self.assertEqual(summary["excluded"], [])
            with report.open(encoding="utf-8", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(tuple(rows[0].keys()), REPORT_COLUMNS)
            self.assertEqual(rows[0]["coverage_class"], COMPLETE)
            self.assertEqual(rows[0]["bundle"], str(bundle))

    def test_preflight_exit_code_reflects_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clean = Path(temporary) / "clean.py"
            bypass = Path(temporary) / "bypass.py"
            clean.write_text("import openfhe\ncc = openfhe.GenCryptoContext(p)\n")
            bypass.write_text("raw = ct.GetCryptoContext()\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(["preflight", str(clean)]), 0)
                stdout.truncate(0)
                stdout.seek(0)
                self.assertEqual(main(["preflight", str(bypass)]), 1)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report[str(bypass)][0]["kind"], "raw_context_from_ciphertext")
            self.assertTrue(report[str(bypass)][0]["bypasses_tracer"])

    def test_preflight_missing_script_fails(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["preflight", "/nonexistent/script.py"]), 2)


class SummaryTests(unittest.TestCase):
    def test_summary_lists_unsupported_operations_for_excluded_runs(self) -> None:
        rows = [
            {"bundle": "a", "coverage_class": COMPLETE},
            {
                "bundle": "b",
                "coverage_class": UNSUPPORTED,
                "unsupported_operations": "EvalAddMany;EvalSum",
                "reasons": "strict mode rejected 2 unsupported call(s)",
            },
        ]
        summary = summarize_report(rows)
        self.assertEqual(summary["complete_fraction"], 0.5)
        self.assertEqual(
            summary["excluded"][0]["unsupported_operations"], ["EvalAddMany", "EvalSum"]
        )

    def test_empty_summary(self) -> None:
        self.assertEqual(summarize_report([])["complete_fraction"], 0.0)


if __name__ == "__main__":
    unittest.main()
