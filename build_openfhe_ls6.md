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

## C++ frontend (branch `cpp-gcc-frontend`, 2026-09-17)

Implements `docs/cpp_gcc_design.md` phases 0–6 on LS6 (node `v320-008`, job 3452489):

- [x] Phase 0 — trace producer-neutral: `run.producer`, `run.runtime.language/
      compiler/framework`, `run.clocks`, native coverage counters (one schema);
      Python recorder declares `python-openfhe`; `classify_run` reads native
      evidence; AST scan only for `.py`. `tests/test_frontend_neutral.py`.
- [x] Phase 1 — native runtime (`native/runtime/runtime.cpp`): C ABI
      (`native/include/cipherscope/runtime.h`), weak-ref identity registry,
      in-place versions, three clocks, thread IDs, unwound-call detection,
      limits, JSONL spool; OpenFHE adapter (`adapter.cpp`) the only
      OpenFHE-including TU; `.cipherscope.marker` ELF section.
- [x] Phase 2 — GCC plugin (`native/gcc/plugin.cpp`): GIMPLE pass after `cfg`,
      instruments application-code calls to manifest-listed
      `CryptoContextImpl` members and ciphertext operators; static operand
      kinds via `type_as_string`; unmatched/allowed calls reported; site
      tables; verified under `-fchecking=2`.
- [x] Phase 3 — adapter reads level/noise/scale/slots/key tag/context/
      techniques and `CCParams` at `GenCryptoContext`; C++ context block
      identical to Python's.
- [x] Phase 4 — manifest `native/openfhe/openfhe-1.5.operations.json`
      (30 ops + 7 operator aliases), bound to `CORE_OPERATIONS` by
      `tests/test_operation_manifest.py`; strict unmatched detection.
- [x] Phase 5 — `cipherscope profile BINARY`: CMakeCache/compile_commands
      discovery, toolchain built with the target's GCC into a fingerprinted
      cache, isolated shadow build via `CMAKE_CXX_COMPILER_LAUNCHER`,
      marker check, cached reuse (1.4 s second run).
- [x] Phase 6 — coverage classes from native evidence (TUs instrumented,
      unmatched candidates, marker).
- [x] Gate `tests/integration_cpp/run_gate.py`: **18/18 `native_pass`** on
      GCC 15.2.0 / OpenFHE 1.5.1 (Rocky), archived
      `artifact/feasibility/cpp-gcc152-openfhe151/`.
- [x] Parity: `frontend_parity.compare_traces`; four Python/C++ twin pairs
      equivalent (rotations, operators/in-place, aliasing, exception) —
      caught and fixed a Python-frontend bug (OpenFHE `Plaintext` has
      `GetLevel/GetNoiseScaleDeg`, so plaintext operands were recorded as
      ciphertexts and `ct×pt` as `ct_ct`).
- [x] Report (`summary.html`): frontend/language/toolchain/framework header
      and environment table, coverage evidence in each frontend's terms,
      source files with language, lineage per event.
- [x] Upstream unmodified examples: `simple-real-numbers.cpp` COMPLETE with a
      real `rotation.hoist_same_input.v1` finding; `advanced-real-numbers.cpp`
      PARTIAL-PERMISSIVE (`EvalFastRotation*` outside the manifest in both
      frontends).
- [x] Second GCC / distribution: `gcc-13-plugin-dev` added to the Apptainer
      definition and the Dockerfile; image rebuilt (3 min), primary Python
      gate re-run on it (38/0/38, artifact re-archived), and the C++ gate
      run inside it: **18/18 `native_pass` on GCC 13.3.0 / Ubuntu 24.04**
      (`artifact/feasibility/cpp-gcc133-openfhe151/`). The plugin is built on
      demand by whichever GCC built the target, so the frontend follows the
      project's toolchain.
- [ ] Phase 7 (thread-local buffering / native overhead study) — not started;
      the runtime uses one locked write per event.

### Manifest v2, bootstrap positive, corrected depth accounting (2026-09-17, later)

- [x] Manifest `openfhe-1.5-v2` (38 ops): `EvalFastRotation[Precompute]`,
      `EvalPoly`, `EvalLogistic`, `EvalSum{Rows,Cols}[KeyGen]` in both
      frontends. Python gate 38/38 (both LS6 lanes) and C++ gate 18/18 re-run
      and re-archived. External corpus: `sol_encrypted_inference` now
      strict-COMPLETE (was PARTIAL); `sol_log_reg`/`sol_nag_log_reg` strict
      re-runs in progress. Upstream `advanced-real-numbers.cpp` COMPLETE, with
      its `FastRotationsDemo1` "before" block (7 `EvalRotate` on one
      ciphertext) flagged and the hoisted block silent.
- [x] **Bootstrap rule limitation was misdiagnosed.** The C++ frontend on
      upstream `simple-ckks-bootstrapping.cpp` showed level 31 → 21 across
      `EvalBootstrap`; the Python binding shows the same for a deep input.
      OpenFHE returns bootstrap output at `depth − levelsAvailableAfterBootstrap`
      regardless of input, so only deep inputs show a restoration. Added
      seeded positive `bootstrap.positive.underused_deep`: **28/28 matched,
      every rule now has a real positive** (recall table 14/14). README,
      ARTIFACT, seeded README and the hard-negative case docstring corrected.
- [x] Plaintext-operand fix corrected depth accounting in three seeded cases
      (`ct × pt` no longer counts as depth); documented in
      `evaluation/parity/README.md` as the two current developer-lane
      disagreements pending a Mac rerun.
- [x] More upstream C++ examples profiled COMPLETE: `function-evaluation`
      (testing-only security fires: `HEStd_NotSet`), `polynomial-evaluation`,
      `simple-ckks-bootstrapping` (bootstrap underuse + testing-only security).
- [x] Native overhead (design phase 7, measurement half): plain / hooks /
      full ×3 at 10²–10⁵, two allocator settings. Pinned allocator: hooks and
      full within 0.3–7 % of plain, peak RSS 25–26 MB in every arm, spool
      1.2 KB/event. Default glibc makes the instrumented binary 6–16 %
      *faster* at 10⁴–10⁵ (heap trimming), so the raw record carries an
      `allocator` column and the doc explains it. Registry now prunes expired
      entries every 1024 registrations: 10⁵ full-arm peak RSS 49 MB → 26 MB.
      Thread-local buffering deliberately not implemented: one locked write
      per millisecond-scale FHE event is not measurable.
- [x] External corpus strict under manifest v2: **4/4 COMPLETE** (was 1/4);
      `evaluation/raw/coverage_report.csv` = 20/20 COMPLETE (16 examples +
      4 workloads); `evaluation/adjudication/findings.csv` exported (12
      findings, verdicts empty — human step).

### Coverage boundary closed on both frontends (2026-09-18)

User request: operator overloads in Python (GAP-01), a C++ counterpart for
checkpoints/annotations, and `EvalAddMany`/`EvalMultMany`,
`EvalChebyshevSeries`, BGV/BFV in the manifest — in both frontends.

- [x] GAP-01 — `src/cipherscope/operators.py`: while a session is active the
      binding's `Ciphertext.__add__` (and `__sub__`/`__mul__`/`__neg__`/in-place
      forms where a binding defines them) is rerouted to the owning session's
      proxy, so `a + b` records one `EvalAdd ct_ct` at the user's line; the
      native call runs once; originals restored at close (refcounted across
      sessions). Real-binding check `GAP-01` now asserts the traced event and
      numerical equality; `operator_overload_coverage` is evidence-based.
      Commit `ef85955`.
- [x] Manifest **`openfhe-1.5-v3`** (53 operations, shared table
      `CORE_OPERATIONS` ⇄ `native/openfhe/openfhe-1.5.operations.json`,
      `tests/test_operation_manifest.py` keeps them identical):
      `EvalAddMany`, `EvalAddManyInPlace` (non-mutating: reassigns handles),
      `EvalMultMany` (opaque depth), `EvalMultAndRelinearize`,
      `EvalLinearWSum[Mutable]`, `EvalMerge`, `EvalChebyshevSeries[Linear|PS]`
      (records `polynomial_degree`, bounds — never coefficients),
      `EvalSin`/`EvalCos`/`EvalDivide`, `MakePackedPlaintext`,
      `MakeCoefPackedPlaintext`; method aliases `EvalAtIndex[KeyGen]` →
      `EvalRotate[KeyGen]` (both frontends record the canonical name).
- [x] Schemes — trace/manifest schema `scheme ∈ {CKKS, BFV, BGV, null}`;
      Python reads `CCParams*.GetScheme()`; C++ adapter reads the base
      `lbcrypto::Params` of `CCParams<CKKSRNS|BFVRNS|BGVRNS>` (new ABI kinds
      22/23, `cs_declared_parameters(site, kind, params)`), spools the enum
      name (`BFVRNS`; Python binding says `BFVRNS_SCHEME` — both normalized);
      `available_slots` = N/2 (CKKS) or N (BFV/BGV); `plaintext_modulus`
      reported for integer schemes, null for CKKS (that slot holds the scaling
      mod size). Without declared params a `batch_size == N` context is left
      `scheme = null` (`batch_size_equals_ring_dimension_not_ckks`), never
      labelled CKKS.
- [x] C++ vector operands — plugin classifies
      `std::vector<std::shared_ptr<[const] CiphertextImpl>>` as
      `CS_KIND_CIPHERTEXT_VECTOR` (checked before the single-handle spelling);
      adapter describes every element (id, first_seen, state) under `items`;
      normalizer flattens them into inputs/parents in order, exactly like the
      Python list flattening; `operand_count` semantic argument.
- [x] Fixtures + twins: `many_and_series` (17 events), `bfv_arithmetic`
      (13), `bgv_arithmetic` (14); spools/sites/Python traces archived under
      `tests/cpp/expected/`; `unmatched.cpp` and Python `GAP-04` now use
      `EvalAddMutable`/`EvalMultMutable` as the out-of-manifest witnesses.
- [x] C++ gate **20/20 `native_pass`** (new `OP-03`, `SCHEME-01`; `PARITY-01`
      over 7 twin pairs) — GCC 15.2.0 / OpenFHE 1.5.1, archived
      `artifact/feasibility/cpp-gcc152-openfhe151/`.
- [x] Python gate gains `API-07` (vector composites, series, alias, numerics)
      and `API-08` (BFV and BGV contexts traced with scheme/slots/modulus):
      `ls6-native-py311` **40/40 `native_pass`**, `primary-source-py311`
      **40/40 `pass`** (authoritative), both re-archived; `docs/evidence.md`
      rows updated (macOS `developer` and the 3.12 wheel keep their older
      counts — not rerun here).
- [x] C++ counterpart for annotations/checkpoints —
      `native/include/cipherscope/annotate.h` (opt-in): `cipherscope::annotate`,
      `annotate_plaintext`, `checkpoint`. Inline no-ops unless the unit is
      compiled through the CipherScope launcher, which now defines
      `CIPHERSCOPE_INSTRUMENTED` (weak symbols were tried first and rejected:
      GCC 15 at `-O2` non-PIE folds the null check away). Runtime records
      `meta` records (`Annotate`, `AnnotatePlaintext`, `PrecisionCheckpoint`)
      with `__builtin_FILE/LINE/FUNCTION`, ciphertext id + state, the
      annotation, expected values and — via the adapter's own `Decrypt`, not a
      traced event — observed values; invalid input → `status: error`
      (`annotation_error`), never merged. Normalizer emits `annotation` /
      `checkpoint` events, merges ciphertext `annotations`, computes metrics
      with the session's `_precision_metrics` (identical numbers by
      construction), sets `run.shadow_mode` iff a checkpoint ran. Parity
      comparator ignores measured noise (observed values, error metrics) but
      keeps the checkpoint contract and outcome, and compares `shadow_mode`.
      Fixture `checkpoints.cpp` + twin `checkpoints.py`: 18 events,
      equivalent; both frontends reach the same five positives
      (`precision.checkpoint_drop`, `precision.tolerance_violated`,
      `packing.low_utilization_annotated`, `encoding.repeated_public_constant`,
      `provenance.public_value_ciphertext_mult`); programs without the header
      keep those rules `not_applicable` (asserted by `META-01` and unit tests).
- [x] C++ gate final: **21/21 `native_pass`** (`META-01` added; `PARITY-01`
      over 8 twin pairs), `artifact/feasibility/cpp-gcc152-openfhe151/`.
- [x] Unit suite (Python 3.13, no binding): 258 passed, 364 subtests.
