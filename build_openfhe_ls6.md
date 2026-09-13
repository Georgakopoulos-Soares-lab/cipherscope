# LS6 parity progress

Execution log for [docs/ls6_parity_plan.md](docs/ls6_parity_plan.md). One line
per plan item; an item is ticked only when its "done when" condition was
observed on LS6, and the observation is written next to it. Times are
America/Chicago on 2026-09-13, node `v320-008` (`vm-small`, job 3436198).

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

Primary lane (container) / native lane:

- [ ] 5.1 `make artifact-smoke` — / —
- [ ] 5.2 `make reproduce-small` (seeded 27, ablation, tables) — / —
- [ ] 5.3 `make verify-checksums` before, `make checksums` after
- [ ] 5.4 example gallery: 16 programs validated, all `COMPLETE` — / —
- [ ] 5.5 scaling sweep 10²–10⁵, `machine = x86_64` rows
- [ ] 5.6 PRS harnesses (native lane)
- [ ] 5.7 external suite (`python-log-reg-examples`, pinned; strict first)
- [ ] 5.8 runtime fingerprint of a bundle equals the lane's native-module hash

## Phase 6 — Cross-platform equivalence check

- [ ] `evaluation/parity/compare_lanes.py` written
- [ ] `evaluation/parity/parity_report.md` generated; only `RES-02` differs
      between macOS and Linux

## Phase 7 — Documentation, checksums, commit

- [ ] README "Current limitations" + Quick start Linux section
- [ ] `docs/ARTIFACT.md` claim table (RQ1 primary 38/38, RQ2, RQ5)
- [ ] `examples/README.md` Linux activation subsection
- [ ] `.gitignore` `*.sif`
- [ ] `make checksums`, `make verify-checksums`, `make test`; branch `ls6-parity`

## Acceptance criteria (from the plan, §5)

- [x] primary `feasibility.json`: `pass`, 38/0/38, authoritative, ubuntu 24.04 x86_64 3.11.15, manifest beside it
- [x] native `feasibility.json`: `native_pass`, 38/0/38, rocky 8.10 x86_64 3.11.15, gcc 15.2.0 in the manifest
- [x] fake-backend suite green on LS6 (0 errors, 38 skips) — macOS re-run pending on the Mac
- [ ] parity report with zero disagreements outside the allowed list
- [ ] 16 examples + seeded benchmark `COMPLETE`/`all_matched` on both LS6 lanes
- [ ] `raw/scaling.csv` has arm64 and x86_64 rows; `tables/scaling.csv` per machine
- [ ] `tables/MANIFEST.json` byte-identical LS6 vs Mac (needs a Mac regeneration after B6)
- [x] no `gcc/15.1.0` / `/home1/apps/gcc` / `gh-dev` / `/Users/` outside git history (`docs/ls6_parity_plan.md` mentions them as history; `build_openfhe_ls6.sh` names 15.1.0 only to say it was retired)
- [ ] docs agree with archived artifacts (evidence.md done; README/ARTIFACT/examples pending)
