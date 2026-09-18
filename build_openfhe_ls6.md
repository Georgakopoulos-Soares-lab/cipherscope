# LS6 parity progress

Execution log for [docs/ls6_parity_plan.md](docs/ls6_parity_plan.md). One line
per plan item; an item is ticked only when its "done when" condition was
observed on LS6, and the observation is written next to it. Times are
America/Chicago; 2026-09-13 (job 3436198) and 2026-09-17 (job 3452489), both on node `v320-008` (`vm-small`). The container, native build and results live on `$WORK`/`$SCRATCH` and survived the job boundary.

Conventions: `[x]` done and verified · `[ ]` not started · `[~]` in progress ·
`[-]` deliberately not done (reason given).

## Phase 0 — Session setup

- [x] `ls6_env.sh` created at the repository root; sourcing it loads
      `gcc/15.2.0`, `cmake/3.31.5`, `tacc-apptainer/1.4.1`, exports
      `BUILD_ROOT`, `RESULTS_ROOT`, `PRIMARY_SIF`, the pins, `OMP_NUM_THREADS=1`,
      `MAKE_JOBS=16`, node-local `APPTAINER_TMPDIR`, and defines `run_in_primary`.
      Verified: `g++ (GCC) 15.2.0`, `cmake 3.31.5`, `apptainer 1.4.1-1.el8`.

## Phase 1 — Repository fixes

- [x] B1 `tests/test_artifact.py` → `docs/ARTIFACT.md`; README link;
      `docs/ARTIFACT.md` relative link. (`make test` no longer errors.)
- [x] B2 `ENV-01` unchanged for the primary lane; new `ls6-native-py311` branch
      asserts Linux/x86_64 and records the distribution. ENV-02/03/04 treat
      the native lane like primary (`tests/integration_openfhe/test_environment.py`).
- [x] B3 `build_openfhe_ls6.sh`: `gcc/15.2.0`, `cmake/3.31.5`, `$TACC_GCC_LIB64`,
      Lmod init for non-login shells.
- [x] B4 `build_openfhe_ls6.sh`: lane `ls6-native-py311`, output
      `$BUILD_ROOT/feasibility-<lane>.json`, manifest records os-release,
      kernel, hostname, CPU model, SLURM job/partition, `OMP_NUM_THREADS`,
      `MAKE_JOBS`, loaded modules, Python configure flags.
- [x] B5 all eight `run_*.slurm` launchers: `-p vm-small`, source
      `ls6_env.sh`, no compiler module of their own, no `/home1/apps` path,
      external-suite runs strict first and permissive only as a fallback.
- [x] B6 `src/cipherscope/tables.py`: `skipped_inputs` are repository-relative;
      test asserts no absolute path in `MANIFEST.json`.
- [x] B7 `src/cipherscope/tables.py`: scaling medians grouped by
      `(machine, size, arm)`, `machine` column first in `tables/scaling.csv`;
      new test `test_scaling_rows_never_pool_machines`; `evaluation/README.md`.
- [x] B8 `src/cipherscope/seeded.py`: `case_results.json` gains an
      `environment` block (fingerprint + platform + machine + python + OMP threads).
- [x] B11 `Makefile` `shasum` kept (present on Rocky and macOS).
- [x] B12 `run_gate.py`: `ls6-native-py311` → `native_pass`, never authoritative.
- [x] `tests/test_prs_harnesses.py` rewritten around the real invariant
      (launchers source the env file that loads the build script's gcc module).
- [x] Gate: `make test` on x86_64 Linux (Python 3.13.5) — **Ran 262 tests, OK (skipped=38)**.

## Phase 2 — Authoritative container built on LS6

- [x] `artifact/apptainer/openfhe-py311-source.def` written (Dockerfile
      translation; same digest, tarball hash, and commits). Rootless build
      needed four additions, all verified by failure then success:
      `APT::Sandbox::User "root"`; staging on node-local `/tmp`
      (BeeGFS → `EBUSY`); pre-created `/usr/local/share/fonts` (fontconfig
      postinst chowns to an unmapped group); sources and the manifest script
      under `/usr/local/src` because Apptainer bind-mounts the host `/tmp`
      over `%files` staged there.
- [x] `apptainer build --fakeroot --build-arg MAKE_JOBS=16` — **3 min 10 s**
      (16:04:50 → 16:08:00), log `$RESULTS_ROOT/logs/apptainer-build.log`
      (attempts 1–2 kept as `.attempt1.log` / `.attempt2.log`).
- [x] Verified inside the image: Ubuntu 24.04.4, CPython 3.11.15,
      `native_int` 64, `c++ (Ubuntu 13.3.0-6ubuntu2~24.04.1)`, cmake 3.28.3,
      native module `openfhe.cpython-311-x86_64-linux-gnu.so` =
      `a3a6e18a…cad53e5`.
- [x] `$PRIMARY_SIF` = `$WORK/cipherscope-openfhe-build/openfhe-py311-source.sif`
      (305 MB), sha256 `bf5fcf126a44674d01209023450b3aae85fc499dc837d823400f63bc9abe2f98`
      recorded beside it.

## Phase 3 — Primary gate run and archived

- [x] `run_in_primary python3.11 -m tests.integration_openfhe.run_gate` —
      **`status = "pass"`, 38 / 0 / 38, `authoritative_for_primary_target = true`**,
      2 min 29 s; environment Linux x86_64, ubuntu 24.04, 3.11.15; `RES-02`
      passes (`VmRSS` 620 MB, `VmHWM` 649 MB).
- [x] `artifact/feasibility/primary-source-py311/feasibility.json` and
      `build-manifest.json` archived; the manifest's native-module hash equals
      the hash the gate observed.
- [x] `docs/evidence.md` primary row rewritten from the file; Apptainer
      regeneration commands replace the stale Docker `cp` instructions.
      `tests/test_evidence.py` + `tests/test_artifact.py`: OK.

## Phase 4 — Native Rocky lane (`ls6-native-py311`)

- [x] `build_openfhe_ls6.sh` ran 16:14:27 → ~16:22 in the background
      (`$RESULTS_ROOT/logs/native-build.log`): CPython 3.11.15 (`_ssl` built;
      only `_dbm _gdbm _tkinter nis` missing, as predicted), OpenFHE core and
      wrapper with GCC 15.2.0 — 0 compile errors, 786 warnings; no
      `-Wno-error` needed.
- [x] Gate reports **`native_pass` 38 / 0 / 38** in 141 s; environment Linux
      x86_64, rocky 8.10, 3.11.15, `native_int` 64; native module hash
      `429513c3…6e3a06` (distinct from the primary lane's `a3a6e18a…`).
- [x] Archived under `artifact/feasibility/ls6-native-py311/` with its build
      manifest (records g++ 15.2.0, cmake 3.31.5, host `v320-008`, EPYC 7763,
      `vm-small`, `OMP_NUM_THREADS=1`, `MAKE_JOBS=16`, loaded modules); row and
      description added to `docs/evidence.md`; `tests/test_evidence.py` OK.

## Phase 5 — M4 items reproduced on LS6

Driver: `evaluation/parity/run_lane.sh <lane> <out> [examples seeded scaling]`
runs the same commands for every lane; `run_in_primary bash …` for the
container, plain `bash …` for the native lane. Outputs under
`$RESULTS_ROOT/<lane>/`. Primary lane (container) / native lane:

- [-] 5.1 `make artifact-smoke` — superseded: `run_lane.sh` runs the same
      `run → validate → coverage` path on all 16 examples, not one.
- [x] 5.2 seeded benchmark: **`all_matched` true, 27 cases** on the primary
      lane (13 Sep) and the native lane (17 Sep 17:48); ablation 972 rows each.
      `case_results.json` now carries `environment` (lane, platform, machine,
      python, OMP threads, native-module hash — the hash needed a fix: the
      seeded runner's parent had never imported the binding).
- [x] 5.3 `make verify-checksums` OK before; primary-lane x86_64 rows appended
      to `evaluation/raw/scaling.csv` (22 rows: 11 arm64 + 11 x86_64); tables
      regenerated per machine; `make checksums` + `verify-checksums` OK.
- [x] 5.4 example gallery: **16 / 16 validated, 16 / 16 `COMPLETE`** on the
      primary lane; native lane finished 17:46 (verified in the parity report).
      Every `examples/README.md` expectation holds (`repeated_rotations` →
      hoist + unused key 5; `bootstrap_then_idle` → bootstrap rule
      `not_applicable`; packing / provenance / encoding / serial / precision
      rules fire on their programs).
- [x] 5.5 scaling sweep: primary lane reached 10⁴ baseline when job 3436198
      ended (13 Sep); restarted 17:42 on 17 Sep; native lane sweep started
      17:48. x86_64 10³ streaming: 3.1 s wall, 102 MB peak vs 3.2 s / 47 MB
      baseline (the KVM VM is ~10× slower per event than the M4; ratios are
      what get compared).
      The container sweep launched with `nohup setsid … &` died silently
      after its first minute (the native one launched identically did not);
      relaunched with `setsid -f` at 18:02 from the 10⁴ point and confirmed
      alive after the launching shell exited. `run_lane.sh` still uses the
      plain form; use `setsid -f` for `run_in_primary` jobs.
      **Actual cause found on the third attempt** (the log finally caught it):
      `OSError: [Errno 28] No space left on device` — `--containall` gives the
      container a private `/tmp` capped at Apptainer's 64 MB session dir, and
      the kernel spools there. `run_in_primary` now binds
      `$RESULTS_ROOT/container-tmp` over `/tmp`. Both sweeps complete:
      10⁵ streaming peak RSS 2.98 GB (container) / 3.13 GB (native) / 3.17 GB
      (arm64); 2 165 / 2 193 / 2 163 bytes per event; analysis 104 s / 95 s /
      44 s. Traced/baseline ratios: container 0.92 (its baseline ran under
      heavy concurrent load — single repetitions), native 1.09, arm64 1.22.
- [x] 5.6 PRS (native lane): `memory_profile_prs.py` done 17:56 →
      `$RESULTS_ROOT/prs/memory/{baseline,traced}_memory.csv`. Baseline RSS
      flat (208 → 220 MB over 244 blocks, 50 KiB/block); traced grows
      linearly, 208 → 398 MB (800 KiB/block). Observation for E-02: with
      `SPOOL_BUFFER_EVENTS = 4096` a run this size may never reach the first
      spool, so part of this is the documented buffer envelope, but the slope
      should be checked against the event count before the README's "bounded
      recording" sentence is quoted for a workload of this shape.
      `benchmark_prs_overhead.py --repeats 10 --warmup 2` done 18:5x →
      `$RESULTS_ROOT/prs/overhead/prs_overhead.json`: baseline median
      45.13 s (n=10, sd 0.35), traced 49.65 s (sd 0.26), **+4.52 s = +10.0 %
      wall**, CPU identical to wall (single-threaded). cProfile top-30 tables
      beside it.
- [x] 5.7 external suite: `python-log-reg-examples` cloned to `$WORK`, pinned
      at `5a34dc68386d96175bf665c05e48d974e55db327` (2024-02-20); `preflight`
      clean on all four programs and their helper modules; needs
      `numpy<2` on the LS6 KVM guests (NumPy 2 wheels require x86-64-v2
      features the VM does not expose). The programs never call `attach()`, so
      they run through `examples/profile_unmodified.py` (the old launchers
      ran them bare — fixed).
      - **`sol_lin_reg`: strict, valid, `COMPLETE`**, 356 traced semantic
        calls, 12 allowed passthroughs, 0 rejections; findings: depth critical
        path, unused rotation keys, depth headroom. First independently
        authored workload traced completely.
      - `sol_encrypted_inference`: strict **rejected** — `EvalSumColsKeyGen`
        is not a classified method (`UnsupportedOperationError`); rerun
        permissive to inventory it → will be `PARTIAL-PERMISSIVE`. A genuine
        coverage gap (row/column-sum key generation and `EvalSumCols`/`Rows`),
        recorded, not patched mid-study.
      - **All four finished 20:14** (`$RESULTS_ROOT/external/coverage_report.csv`):

        | workload | class | semantic calls | passthrough | unsupported | fired |
        |---|---|---|---|---|---|
        | `sol_lin_reg` | **COMPLETE** (strict) | 356 | 0 | — | depth path, unused keys, headroom |
        | `sol_encrypted_inference` | PARTIAL-PERMISSIVE | 4 | 3 | `EvalLogistic`, `EvalSumCols`, `EvalSumColsKeyGen` | testing-only security, depth, headroom |
        | `sol_log_reg` | PARTIAL-PERMISSIVE (71 min) | 803 | 302 | + `EvalSumRows`, `EvalSumRowsKeyGen` | same |
        | `sol_nag_log_reg` | PARTIAL-PERMISSIVE (71 min) | 2000 | 302 | same five | same |

        Coverage gap for B-01/B-02: the `EvalSum{Rows,Cols}[KeyGen]` family and
        `EvalLogistic` (Chebyshev logistic) are what real OpenFHE-Python
        applications call that the proxy does not classify. Only
        `sol_lin_reg` may enter finding-quality tables.
      - **RQ6 result:** `configuration.testing_only_security.v1` fired on the
        three `efficient_regression` workloads. Verified in source:
        `efficient_regression/{config,inference_config}.yml` set
        `security_level: HEStd_NotSet` (ring 32768) under a
        `# TODO: swap out the values below`, and the repository README tells
        readers to "turn off the security setting (via HEStd_NotSet)" while
        developing. Adjudication: true positive, intent documented → a
        testing-only configuration in independently authored public code,
        exactly what the rule is worded to report; not a vulnerability claim.
- [x] 5.8 `examples/repeated_rotations/manifest.json` → `runtime.lane =
      primary-source-py311`, `openfhe_native_module_hashes = a3a6e18a…` =
      the primary `feasibility.json` hash. Same check for the native lane
      (`429513c3…`) is part of the parity report header.

## Phase 6 — Cross-platform equivalence check

- [x] `evaluation/parity/compare_lanes.py` written (stdlib): pins, per-check
      status (allowed list = `RES-02` skip on Darwin only), observed numeric
      errors vs `golden_core.json` tolerances, seeded (case, rule) outcomes,
      ablation row sets, per-example diagnoses + README expectations +
      coverage classes, scaling side by side (ratios and bytes/event only).
      `tests/test_parity.py` (5 tests) proves it flags pin, seeded, numeric,
      diagnosis and README disagreements and allows only the platform skip.
- [x] Preliminary run (developer + primary + native gate, primary results):
      **0 disagreements, 1 allowed** — 58/58 seeded expectations identical
      macOS ↔ Ubuntu-x86_64, 972/972 ablation rows identical, all numerics
      within tolerance on three builds (e.g. NUM-01 1.5e-13 / 1.2e-13 / 7.8e-14).
- [x] Final `evaluation/parity/parity_report.md` (three lanes, both sweeps,
      arm64 rows): **0 disagreements, 1 allowed (`RES-02`)** — 58/58 seeded
      expectations, 972/972 ablation rows, 16/16 example diagnoses identical
      across macOS arm64, Ubuntu x86_64 (container), Rocky x86_64 (native);
      32/32 example bundles `COMPLETE`. `evaluation/parity/README.md` documents
      the tooling.

## Phase 7 — Documentation, checksums, commit

- [x] README: four-lane summary, Linux environment paragraph, limitations
      (archived primary; per-machine timing rule).
- [x] `docs/ARTIFACT.md`: Linux/LS6 requirements rows, parity command, RQ1/RQ2/RQ5
      statuses, parity row, troubleshooting (`ENV-01` on Rocky, rootless
      Apptainer symptoms, NumPy x86-64-v2). `tests/test_artifact.py` will pass
      once `parity_report.md` exists.
- [x] `examples/README.md`: Linux/LS6 activation subsection; macOS-only wording replaced.
- [x] `.gitignore` `*.sif`
- [x] external launchers route through `profile_unmodified.py`.
- [x] `make checksums`, `make verify-checksums`, `make test` (267 tests, OK,
      38 skips); committed on `ls6-parity`.

## Acceptance criteria (from the plan, §5)

- [x] primary `feasibility.json`: `pass`, 38/0/38, authoritative, ubuntu 24.04 x86_64 3.11.15, manifest beside it
- [x] native `feasibility.json`: `native_pass`, 38/0/38, rocky 8.10 x86_64 3.11.15, gcc 15.2.0 in the manifest
- [x] fake-backend suite green on LS6 (0 errors, 38 skips) — macOS re-run pending on the Mac
- [x] parity report with zero disagreements outside the allowed list
- [x] 16 examples + seeded benchmark `COMPLETE`/`all_matched` on both LS6 lanes
- [x] `raw/scaling.csv` has arm64 and x86_64 rows; `tables/scaling.csv` per machine
- [~] `tables/MANIFEST.json` is now path-portable (relative `skipped_inputs`); the byte-identity check needs one regeneration on the Mac from this branch
- [x] no `gcc/15.1.0` / `/home1/apps/gcc` / `gh-dev` / `/Users/` outside git history (`docs/ls6_parity_plan.md` mentions them as history; `build_openfhe_ls6.sh` names 15.1.0 only to say it was retired)
- [x] docs agree with archived artifacts (evidence.md, README, docs/ARTIFACT.md, examples/README.md; `tests/test_evidence.py` and `tests/test_artifact.py` enforce the table and every referenced path)

## Left for the Mac / a later session

- Regenerate `evaluation/tables/` on the Mac from this branch and confirm
  `MANIFEST.json` is byte-identical (B6 acceptance).
- Rerun `make test` on the Mac (expected: 267 tests, 38 skips without the
  binding).
- Coverage gap surfaced by the external corpus: `EvalSumRows`, `EvalSumCols`,
  `EvalSumRowsKeyGen`, `EvalSumColsKeyGen`, `EvalLogistic`. Classifying them
  is instrumentation (B-01/B-02), not a new analyzer; until then three of the
  four external workloads stay `PARTIAL-PERMISSIVE`.
- Scaling repetitions: all LS6 sweep points are single runs on a shared VM;
  E-02 wants ≥3 repetitions on an otherwise idle node before ratios are quoted.
