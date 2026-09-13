"""Regression tests for the PRS examples and cluster launchers."""

from __future__ import annotations

import ast
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import memory_profile_prs

ROOT = Path(__file__).resolve().parents[1]


def _constant(path: Path, name: str) -> int:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for statement in module.body:
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        else:
            continue
        if any(
            isinstance(target, ast.Name) and target.id == name for target in targets
        ):
            return int(ast.literal_eval(statement.value))
    raise AssertionError(f"{name} is not assigned in {path}")


class PrsScriptTests(unittest.TestCase):
    def test_default_cohort_triggers_repeated_encoding_analysis(self) -> None:
        script = ROOT / "prs_dot_product.py"
        block_size = _constant(script, "BLOCK_SIZE")
        num_blocks = _constant(script, "NUM_BLOCKS")
        num_patients = _constant(script, "NUM_PATIENTS")

        self.assertGreaterEqual(num_patients, 2)
        self.assertEqual(block_size * num_blocks, 999_424)

    def test_analysis_launcher_removes_previous_bundle_first(self) -> None:
        script = (ROOT / "run_analysis.slurm").read_text(encoding="utf-8")

        remove_at = script.index("rm -rf prs_run/")
        run_command = (
            "python3.11 -m cipherscope.cli run --output prs_run/ "
            "prs_dot_product_analysis.py"
        )
        run_at = script.index(run_command)

        self.assertLess(remove_at, run_at)

    def test_solution_launchers_use_work_directory(self) -> None:
        for name in (
            "run_sol_encrypted_inference.slurm",
            "run_sol_log_reg.slurm",
            "run_sol_nag_log_reg.slurm",
        ):
            with self.subTest(script=name):
                script = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn('cd "$WORK/python-log-reg-examples"', script)
                self.assertNotIn("/work/11681/", script)

    def test_build_and_runtime_scripts_use_the_same_gcc_module(self) -> None:
        build = (ROOT / "build_openfhe_ls6.sh").read_text(encoding="utf-8")
        self.assertIn('GCC_MODULE="${GCC_MODULE:-gcc/15.1.0}"', build)
        self.assertNotIn("gcc/15.2.0", build)

        run_build = (ROOT / "run_build.slurm").read_text(encoding="utf-8")
        self.assertIn("export GCC_MODULE=gcc/15.1.0", run_build)
        for name in (
            "run_analysis.slurm",
            "run_external_suite.slurm",
            "run_memory.slurm",
            "run_profile.slurm",
            "run_sol_encrypted_inference.slurm",
            "run_sol_log_reg.slurm",
            "run_sol_nag_log_reg.slurm",
        ):
            with self.subTest(script=name):
                script = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("module load gcc/15.1.0", script)
                self.assertNotIn("gcc/15.2.0", script)

    def test_gitignore_has_no_duplicate_patterns(self) -> None:
        patterns = [
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(patterns), len(set(patterns)))


class MemoryHarnessTests(unittest.TestCase):
    def test_linux_current_rss_is_converted_from_pages_to_kib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            statm = Path(temporary) / "statm"
            statm.write_text("100 7 0 0 0 0 0\n", encoding="utf-8")
            with mock.patch.object(memory_profile_prs.os, "sysconf", return_value=4096):
                rss_kb = memory_profile_prs.current_rss_kb(statm)

        self.assertEqual(rss_kb, 28)

    def test_ps_current_rss_is_already_in_kib(self) -> None:
        completed = memory_profile_prs.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="1234\n"
        )
        with mock.patch.object(
            memory_profile_prs.subprocess, "run", return_value=completed
        ):
            rss_kb = memory_profile_prs.current_rss_kb(Path("/missing/statm"))

        self.assertEqual(rss_kb, 1234)

    def test_empty_summary_is_supported(self) -> None:
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            memory_profile_prs.summarize("empty", [])

        self.assertEqual(output.getvalue(), "empty: no RSS samples\n")

    def test_main_starts_each_arm_in_a_separate_process(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(memory_profile_prs, "run_arm_in_subprocess") as run_arm,
            mock.patch.object(
                sys,
                "argv",
                ["memory_profile_prs.py", "--output", temporary],
            ),
        ):
            result = memory_profile_prs.main()

        self.assertEqual(result, 0)
        self.assertEqual(
            run_arm.call_args_list,
            [
                mock.call("baseline", Path(temporary)),
                mock.call("traced", Path(temporary)),
            ],
        )


if __name__ == "__main__":
    unittest.main()
