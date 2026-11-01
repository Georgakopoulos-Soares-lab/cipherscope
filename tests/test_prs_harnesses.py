"""Regression tests for the PRS examples and cluster launchers."""

from __future__ import annotations

import ast
import contextlib
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TACC = ROOT / "tacc"

sys.path.insert(0, str(TACC))
import memory_profile_prs  # noqa: E402


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
        script = TACC / "prs_dot_product.py"
        block_size = _constant(script, "BLOCK_SIZE")
        num_blocks = _constant(script, "NUM_BLOCKS")
        num_patients = _constant(script, "NUM_PATIENTS")

        self.assertGreaterEqual(num_patients, 2)
        self.assertEqual(block_size * num_blocks, 999_424)

    def test_analysis_launcher_removes_previous_bundle_first(self) -> None:
        script = (TACC / "run_analysis.sh").read_text(encoding="utf-8")

        remove_at = script.index("rm -rf prs_run/")
        run_command = (
            "python3.11 -m cipherscope.cli run --output prs_run/ "
            "tacc/prs_dot_product_analysis.py"
        )
        run_at = script.index(run_command)

        self.assertLess(remove_at, run_at)

    def test_external_suite_launcher_uses_work_directory(self) -> None:
        # One parameterized script now covers both the full-suite run and any
        # single program (it replaced three near-duplicate run_sol_*.slurm
        # launchers that were each this same loop body pinned to one program).
        script = (TACC / "run_external_suite.sh").read_text(encoding="utf-8")
        self.assertIn('REPO="${LOG_REG_EXAMPLES:-$WORK/python-log-reg-examples}"', script)
        self.assertIn('cd "$REPO"', script)
        self.assertNotIn("/work/11681/", script)

    def test_launchers_do_not_submit_to_a_scheduler(self) -> None:
        # Project policy (docs/ls6_parity_plan.md): everything runs directly in
        # the allocated shell -- no sbatch, srun, idev, or #SBATCH directives.
        for name in (
            "run_build.sh",
            "run_analysis.sh",
            "run_external_suite.sh",
            "run_memory.sh",
            "run_profile.sh",
        ):
            with self.subTest(script=name):
                script = (TACC / name).read_text(encoding="utf-8")
                code_lines = "\n".join(
                    line for line in script.splitlines() if not line.lstrip().startswith("#")
                )
                self.assertNotIn("#SBATCH", script)
                self.assertNotRegex(code_lines, r"\b(sbatch|srun|idev)\b")

    def test_build_and_runtime_scripts_use_the_same_gcc_module(self) -> None:
        """Runtime scripts must load the module the extension was compiled with.

        A different gcc module puts a different libstdc++.so.6 first on
        LD_LIBRARY_PATH and the OpenFHE extension fails to import. The build
        script declares the module once; every launcher sources ls6_env.sh,
        which loads the same one, and none loads a compiler module itself.
        """

        build = (ROOT / "build_openfhe_ls6.sh").read_text(encoding="utf-8")
        build_module = re.search(r'GCC_MODULE="\$\{GCC_MODULE:-(gcc/[0-9.]+)\}"', build)
        self.assertIsNotNone(build_module, "build_openfhe_ls6.sh must default GCC_MODULE")

        env = (ROOT / "ls6_env.sh").read_text(encoding="utf-8")
        env_module = re.search(r"module load TACC (gcc/[0-9.]+)", env)
        self.assertIsNotNone(env_module, "ls6_env.sh must load a gcc module")
        self.assertEqual(env_module.group(1), build_module.group(1))
        # Both derive the runtime library path from the module, never a hard-coded /home1/apps path.
        self.assertIn("TACC_GCC_LIB64", env)
        self.assertIn("TACC_GCC_LIB64", build)
        self.assertNotIn("/home1/apps/gcc", build)

        for name in (
            "run_build.sh",
            "run_analysis.sh",
            "run_external_suite.sh",
            "run_memory.sh",
            "run_profile.sh",
        ):
            with self.subTest(script=name):
                script = (TACC / name).read_text(encoding="utf-8")
                self.assertIn('source "$CIPHERSCOPE_DIR/ls6_env.sh"', script)
                self.assertNotIn("module load gcc", script)
                self.assertNotIn("/home1/apps/gcc", script)
                # LS6 partitions only; gh-dev is a Vista (aarch64) queue.
                self.assertNotIn("gh-dev", script)

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
