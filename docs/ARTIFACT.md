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
| Scaling sweep (`evaluation/scaling/run_scaling.py`) | real binding; ~4 GB RAM for the 10⁵ point | ~4 min |

Real-binding lanes and how to build them are in [docs/evidence.md](docs/evidence.md).
The Docker recipes under `artifact/docker/` build the provisional wheel lane and
the primary source lane; the macOS conda lane used for development is described
in the parent repository's `OPENFHE_ENVIRONMENT.md`.

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
```

`make reproduce-small` overwrites `evaluation/raw/seeded/case_results.json` and
`evaluation/raw/semantic_ablation.csv` with the fresh run; run
`make checksums` afterwards if you intend to keep it, or `git checkout` them to
restore the archived versions.

## Claim-to-artifact mapping

| Claim / research question | Evidence | Generated table | Status |
|---|---|---|---|
| RQ1 Fidelity: tracing preserves OpenFHE numerics and reconstructs source/state/provenance | `artifact/feasibility/*/feasibility.json` (NUM/ID/MUT/PROXY/TRACE checks) | `docs/evidence.md` | developer 37/38, provisional 33/33 (older gate), **primary not archived** |
| RQ2 Coverage: fraction of workloads completely observable | `cipherscope coverage` output per corpus run | `evaluation/tables/coverage.csv` | tool done; corpus report needs strict LS6 re-runs |
| RQ3 Precision on real workloads | `evaluation/adjudication/findings.csv` (human verdicts) | `evaluation/tables/precision.csv` | pending adjudication |
| RQ3 Recall on seeded pathologies | `evaluation/seeded/ground_truth.json`, `evaluation/raw/seeded/case_results.json` | `evaluation/tables/recall.csv`, `evaluation/tables/seeded_cases.csv` | 13/13 detected, 0 FP on 18 negatives, 12 rules |
| RQ4 Impact of validated findings | `findings.csv` transformation columns | `evaluation/tables/before_after.csv` | not started (needs D-01 verdicts) |
| RQ5 Cost: run-time overhead, memory, trace size, analysis time vs events | `evaluation/raw/scaling.csv` (10²–10⁵ events, baseline/streaming/buffered) | `evaluation/tables/scaling.csv` | done locally; corpus-wide overhead (`workload_runs.csv`) pending LS6 |
| RQ5 Bounded recording | `tests/test_streaming.py` (limits, spool, memory envelope) | — | done; run-phase memory flat, finalization is O(events) (see limits) |
| Semantic observability beyond a generic profiler | `evaluation/raw/semantic_ablation.csv` (TIMING_ONLY / STATE / FULL) | `evaluation/tables/semantic_ablation.csv`, `evaluation/tables/generic_profiler_comparison.csv` | done on the seeded corpus |
| RQ6 Security/correctness | configuration rule (`HEStd_NotSet`), tolerance contracts, seeded cases | `evaluation/tables/security_cases.csv` | rules done; real-workload hunt (F-02) pending |
| Related-work positioning | `paper/prior_art_matrix.csv` | — | rows for other tools are marked `verify` until checked against each paper |
| Paper claims and non-claims | `paper/claims.md`, `paper/rq_matrix.csv` | — | draft |

## Known limits a reviewer will hit

- **Finalization is not streamed.** Recording is bounded (events and finished
  ciphertext states spool to disk), but `to_trace()` and analysis materialize
  the whole trace: peak RSS was 3.2 GB at 10⁵ events (2.2 KB/event of trace,
  ~44 s of analysis). `--max-events` / `--max-trace-bytes` cap a run honestly
  (`coverage.truncation` records what was dropped).
- **The bootstrap rule has no real-binding positive**; `GetLevel()` is
  unchanged by `EvalBootstrap` on OpenFHE Python 1.5.1.0.
- **The security level is not readable from a live context**; the
  configuration rule assesses only runs that declare their parameters.
- Real-binding results in this repository come from the macOS developer lane;
  the authoritative Linux gate artifact must be archived before the
  compatibility claim is made.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ImportError: cannot import name 'TypeAlias'` | Python 3.9; use 3.11+ |
| `ENV-03` fails on the developer lane | export `CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT` (source-built wrappers have no pip metadata) |
| `RES-02` skipped | expected off Linux; it reads `/proc/self/status` |
| `seeded benchmark failed: ... cannot import openfhe` | run with the interpreter that has the binding (`PYTHON=/path/to/python make reproduce-small`) |
| a workload is `PARTIAL-PERMISSIVE` | it was run with `--permissive`, was truncated, or its source calls the raw context; see `README.md` "Coverage classes" |
| `findings` exports nothing | only `COMPLETE` real-backend bundles qualify; the summary names the reason per bundle |
