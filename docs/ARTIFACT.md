# Artifact guide

This file is the map from every claim to the file that backs it, and the exact
commands that reproduce the small paths on a clean machine. Large or
cluster-only results are archived under `evaluation/raw/` with checksums; you
do not need to rerun them to check the artifact.

## What you need

| Path | Needs | Time |
|---|---|---|
| `make test` | Python 3.11+ only (stdlib; fake backend) | < 1 min |
| `make artifact-smoke` | above, plus the real OpenFHE Python 1.5.1.0 binding importable by `PYTHON` (skips the real part otherwise, and says so) | ~1 min |
| `make reproduce-small` | real binding | ~1 min (27 seeded cases, ablation, every table) |
| `make gate` | real binding; on Linux also `/proc` | ~30 s |
| Scaling sweep (`evaluation/scaling/run_scaling.py`) | real binding; ~4 GB RAM for the 10⁵ point | ~4 min on arm64; ~25 min on the LS6 VM lanes |
| `evaluation/parity/run_lane.sh <lane> <out>` | real binding; runs the 16 examples, the seeded benchmark, and the scaling sweep for one lane | ~30 min |
| `evaluation/parity/compare_lanes.py` | the archived `feasibility.json` files plus any `run_lane.sh` outputs; stdlib only | seconds |
| `python3 -m tests.integration_cpp.run_gate --openfhe-dir …` | GCC with plugin headers, CMake, an OpenFHE C++ install | ~2 min (21 checks, 10 fixture programs) |

Real-binding lanes and how to build them are in [docs/evidence.md](evidence.md).
The primary source lane is built either from the Dockerfile under
`artifact/docker/openfhe-py311-source/` or, without root or Docker, from the
equivalent `artifact/apptainer/openfhe-py311-source.def` (this is how the
archived artifact was produced, on a TACC Lonestar6 compute node with
`apptainer build --fakeroot`; the pinned base-image digest, Python tarball
hash, and OpenFHE commits are identical). The provisional wheel lane has its
own Dockerfile. `build_openfhe_ls6.sh` builds the same pins natively with Lmod
gcc/cmake modules for the supporting `ls6-native-py311` lane, and `ls6_env.sh`
sets up both Linux lanes in one shell. The macOS conda lane used for
development is described in the parent repository's `OPENFHE_ENVIRONMENT.md`.

Do not use the Apple Command Line Tools Python 3.9; every entry point refuses it.

## Commands and expected outputs

```bash
# 1. Fake-backend suite: instrumentation mechanics, contracts, generators.
make test                       # "OK (skipped=38)" without the binding; skips=3 with it

# 2. One real trace end to end (needs the binding).
make artifact-smoke             # validate prints {"valid": true, ...}; coverage prints COMPLETE: 1

# 3. Seeded benchmark, ablation, and all paper tables (needs the binding).
make reproduce-small            # seeded exits 0 with "all_matched": true; tables/ regenerated

# 4. Confirm archived raw results are the ones the tables were built from.
make verify-checksums           # every line ends in ": OK"

# 5. Developer-lane gate (needs the binding and the pins from docs/evidence.md).
CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51 \
CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e \
make gate                       # status "incomplete" on macOS (RES-02 is Linux-only), "pass" only on the primary lane

# 6. Cross-platform parity (uses the archived lanes; add run_lane.sh outputs for the full report).
python3 evaluation/parity/compare_lanes.py \
  --lane developer artifact/feasibility/developer/feasibility.json \
      --seeded developer=evaluation/raw/seeded/case_results.json \
      --ablation developer=evaluation/raw/semantic_ablation.csv \
  --lane primary-source-py311 artifact/feasibility/primary-source-py311/feasibility.json \
  --lane ls6-native-py311 artifact/feasibility/ls6-native-py311/feasibility.json
                                # exits 0; the only allowed difference is RES-02 skip on macOS
```

`make reproduce-small` overwrites `evaluation/raw/seeded/case_results.json` and
`evaluation/raw/semantic_ablation.csv` with the fresh run; run
`make checksums` afterwards if you intend to keep it, or `git checkout` them to
restore the archived versions.

## Claim-to-artifact mapping

| Claim / research question | Evidence | Generated table | Status |
|---|---|---|---|
| RQ1 Fidelity: tracing preserves OpenFHE numerics and reconstructs source/state/provenance | `artifact/feasibility/*/feasibility.json` (NUM/ID/MUT/PROXY/TRACE checks) | `docs/evidence.md`, `evaluation/parity/parity_report.md` | **primary 40/40 (archived, authoritative)**, native LS6 40/40, developer 37/38 and provisional 33/33 (older check sets, not rerun); numerics within tolerance on all |
| RQ2 Coverage: fraction of workloads completely observable | `evaluation/raw/coverage_report.csv` (16 examples + the 4 `python-log-reg-examples` @ `5a34dc68` workloads, strict) | `evaluation/tables/coverage.csv` | 20/20 `COMPLETE` with manifest v2 (the corpus was 1/4 before `EvalLogistic`/`EvalSum{Rows,Cols}` were covered); C++ upstream examples: 6/6 `COMPLETE` (re-profiled 2026-11-01 after fixing the exit-time context use-after-free that crashed `simple-real-numbers-serial`) |
| RQ3 Precision on real workloads | `evaluation/adjudication/findings.csv` (12 findings from the 4 external workloads, adjudicated) | `evaluation/tables/precision.csv` | **6/8 = 0.75**: 6 `TP-ACTIONABLE`, 2 `FALSE-POSITIVE` (both `parameters.depth_headroom_observed` — a pending rescale and the iterative-bootstrap reserve; the first cause is now fixed in the analyzer), 4 `NOT-IN-SCOPE` (information-level depth reports, outside the denominator). Two AI reviewers with recorded disagreements resolved per row (`disagreement` column); no human reviewer yet |
| RQ3 Recall on seeded pathologies | `evaluation/seeded/ground_truth.json`, `evaluation/raw/seeded/case_results.json` | `evaluation/tables/recall.csv`, `evaluation/tables/seeded_cases.csv` | 14/14 detected, 0 FP on 18 negatives, 12 rules (every rule has a real positive) |
| RQ4 Impact of validated findings (external corpus) | `findings.csv` transformation columns (external-corpus `TP-ACTIONABLE` findings) | `evaluation/tables/before_after.csv` | done: all 6 `TP-ACTIONABLE` findings patched and measured, plus the refused depth patch that made one verdict `FALSE-POSITIVE`. Depth 12→7 on `sol_lin_reg` 4.03×; rotation keys sized by features 1.21× and 3.8× less RSS; `sol_log_reg` depth 33→31 1.09× (4-epoch scale); `HEStd_128_classic` costs nothing on `sol_encrypted_inference` (`validated_fix`) but on the log_reg pair needs ring 131072, costs ~4× and changes the training trajectory (`fix_changes_result`). Patches in `evaluation/adjudication/transformations/` |
| RQ4 Impact suite: one before/after program per prescriptive rule | `evaluation/impact/` (10 case pairs), `evaluation/raw/impact.csv` | `evaluation/tables/impact.csv` | done: every pair traced (rule `positive` before, silent after, enforced by the runner) and timed 7× in fresh processes with a plaintext-reference check on every run; see `evaluation/impact/README.md` for the per-rule table. Kept deliberately outside the adjudicated-findings pipeline |
| RQ5 Cost: run-time overhead, memory, trace size, analysis time vs events | `evaluation/raw/scaling.csv` (Python, 10²–10⁵, per `machine`); `evaluation/raw/native_overhead.csv` (C++ plain / hooks / full, two allocator settings) | `evaluation/tables/scaling.csv`; `evaluation/native_overhead/summarize.py` | Python: arm64 + x86_64 rows; C++: see `docs/cpp_frontend.md` — instrumentation cost within noise of the FHE work, flat RSS, 1.2 KB/event spool; corpus-wide: `evaluation/raw/workload_runs.csv` → `evaluation/tables/overhead.csv` (12 workloads × 3 matched reps on LS6: a roughly fixed +0.4–0.7 s, i.e. +150–260 % on the sub-second examples, +22–30 % on the 2–7 s ones, +0.7–1.8 % on the 100–180 s bootstrapped and regression workloads; `sol_log_reg`/`sol_nag_log_reg` not included — about an hour per run) |
| RQ5 Bounded recording | `tests/test_streaming.py` (limits, spool, memory envelope) | — | done; run-phase memory flat, finalization is O(events) (see limits) |
| Semantic observability beyond a generic profiler | `evaluation/raw/semantic_ablation.csv` (TIMING_ONLY / STATE / FULL) | `evaluation/tables/semantic_ablation.csv`, `evaluation/tables/generic_profiler_comparison.csv` | done on the seeded corpus |
| RQ6 Security/correctness | configuration rule (`HEStd_NotSet`), tolerance contracts, seeded cases; F-02 hunt `evaluation/bug_hunt/run_bug_hunt.py` → `evaluation/raw/bug_hunt.csv` | `evaluation/tables/security_cases.csv` | done: 10 real programs (4 external Python, 6 upstream C++) re-analyzed; 5 `HEStd_NotSet` positives, all true (3 actionable in the corpus, 2 documented demo shortcuts upstream); precision rules `not_applicable` on every unmodified program (they need checkpoints); the hunt also surfaced a real C++ frontend crash, now fixed |
| Related-work positioning | `paper/prior_art_matrix.csv` | — | CryptOracle, HEIR, Rotom, HERTA verified against their full texts (2026-11-01); HEProfiler only against its abstract (PDF inaccessible), its remaining cells stay `verify` |
| Paper claims and non-claims | `paper/claims.md`, `paper/rq_matrix.csv` | — | draft |
| Language-neutral trace: C++ and Python frontends share schema, graph, analyzers, exporters | `artifact/feasibility/cpp-gcc152-openfhe151/feasibility.json` (BUILD/OP/MUT/ID/SRC/EXC/THR/NUM/COV/LIMIT/TRACE/PIPE/PARITY), `tests/cpp/expected/repeated_rotations/` | `docs/cpp_frontend.md` | 21/21 on GCC 15.2.0 (Rocky) and GCC 13.3.0 (Ubuntu) + OpenFHE 1.5.1, manifest `openfhe-1.5-v3` (both re-run 2026-11-01); 8 Python/C++ twin pairs semantically equivalent with identical findings |
| Cross-platform equivalence of platform-independent results | `evaluation/parity/compare_lanes.py` over the archived lanes and `run_lane.sh` outputs | `evaluation/parity/parity_report.md` | 0 disagreements (regenerated 2026-11-01 with `--allow-missing-cases`): seeded 60/60 expectations (28 cases), 1008/1008 ablation rows, 16/16 example diagnoses identical across the three lanes; API-07/08 absent from the older macOS gate archive (listed as allowed). The `developer` seeded/ablation records were themselves regenerated on LS6 x86_64, so the arm64 comparison of those two items awaits a Mac rerun |

## Known limits a reviewer will hit

- **Finalization is not streamed.** Recording is bounded (events and finished
  ciphertext states spool to disk), but `to_trace()` and analysis materialize
  the whole trace: peak RSS was 3.2 GB at 10⁵ events (2.2 KB/event of trace,
  ~44 s of analysis). `--max-events` / `--max-trace-bytes` cap a run honestly
  (`coverage.truncation` records what was dropped).
- **The bootstrap rule needs a deep input to see a restoration.** OpenFHE
  returns every bootstrap output at `depth - levelsAvailableAfterBootstrap`;
  only an input deeper than that (the intended use) shows restored levels.
  `bootstrap.positive.underused_deep` is the real-binding positive; the upstream
  C++ example `simple-ckks-bootstrapping.cpp` triggers the rule the same way.
- **The security level is not readable from a live context**; the
  configuration rule assesses only runs that declare their parameters.
- `evaluation/raw/seeded/case_results.json` and `semantic_ablation.csv` were
  last regenerated on LS6 x86_64 (after the deferred-rescale analyzer fix),
  not on the Mac; the parity report shows both LS6 lanes reproduce them
  exactly. The archived `scaling.csv` carries rows from both architectures,
  reported per machine. Re-running `make reproduce-small` on macOS is the
  remaining step to restore an arm64 comparison of those two records.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ImportError: cannot import name 'TypeAlias'` | Python 3.9; use 3.11+ |
| `ENV-03` fails on the developer lane | export `CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT` (source-built wrappers have no pip metadata) |
| `RES-02` skipped | expected off Linux; it reads `/proc/self/status` |
| `ENV-01` fails with `'rocky' != 'ubuntu'` | you ran the bare-host build as `primary-source-py311`; that lane is the Ubuntu 24.04 image only. Use `ls6-native-py311` (the default in `build_openfhe_ls6.sh`) or run the gate inside the container (`run_in_primary`) |
| `apptainer build` fails in `%post` with `setgroups`/`chown … Invalid argument`/`rename … Device or resource busy` | rootless-build constraints; the checked-in `.def` already handles them, but `APPTAINER_TMPDIR` must be on a local filesystem (`ls6_env.sh` sets it) |
| `NumPy was built with baseline optimizations: (X86_V2) but your machine doesn't support` | NumPy ≥ 2 wheels on the LS6 KVM nodes; the external corpus needs `pip install "numpy<2"` |
| `seeded benchmark failed: ... cannot import openfhe` | run with the interpreter that has the binding (`PYTHON=/path/to/python make reproduce-small`) |
| a workload is `PARTIAL-PERMISSIVE` | it was run with `--permissive`, was truncated, or its source calls the raw context; see `README.md` "Coverage classes" |
| `findings` exports nothing | only `COMPLETE` real-backend bundles qualify; the summary names the reason per bundle |
