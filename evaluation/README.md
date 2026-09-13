# Evaluation data contract

Every number in the paper is generated from raw records in this directory by
one command. No table is edited by hand; if a table is wrong, the raw record or
the generator is wrong, and that is fixed instead.

```bash
python evaluation/generate_paper_tables.py
```

The command validates every raw input against
[`schema/results.schema.json`](schema/results.schema.json), refuses to write
anything if a record violates it (naming the row and column), and otherwise
writes `tables/*.csv` plus `tables/MANIFEST.json` with the SHA-256 of every
input and output. Deleting `tables/` and rerunning produces identical bytes.
Bootstrap confidence intervals use a fixed seed recorded in the manifest.

## Layout

| Path | Owner | Contents |
|---|---|---|
| `schema/results.schema.json` | contract | The six record types and their column types. |
| `raw/workload_runs.csv` | you (exported from the C-02 / E-01 runs) | One row per measured repetition per arm; PDF section 11.1 columns. |
| `raw/coverage_report.csv` | `cipherscope coverage --output` | One row per classified bundle. |
| `raw/seeded/case_results.json` | `cipherscope seeded --output` | The seeded benchmark's raw result (copy `case_results.json` here; bundles are regenerable and stay out). |
| `raw/scaling.csv` | `scaling/run_scaling.py` | One row per (machine, event count, arm) kernel process; `baseline` is the untraced loop. Rows from different machines (`machine` column) coexist and are reported separately. |
| `raw/semantic_ablation.csv` | `cipherscope ablate --output` | One row per (bundle, mode, rule). |
| `raw/CHECKSUMS.sha256` | `make checksums` | SHA-256 of every raw file; `make verify-checksums` checks them. |
| `adjudication/findings.csv` | `cipherscope findings` + human verdicts | One row per finding from a `COMPLETE` real run; see `adjudication/GUIDE.md`. |
| `tables/` | generated | `precision.csv`, `recall.csv`, `seeded_cases.csv`, `coverage.csv`, `overhead.csv`, `scaling.csv`, `semantic_ablation.csv`, `generic_profiler_comparison.csv`, `MANIFEST.json`. |
| `seeded/` | benchmark source | Ground truth and case programs; see `seeded/README.md`. |
| `scaling/` | measurement source | `kernel.py` (one process per point) and `run_scaling.py`. |

Inputs that are absent are listed under `skipped_inputs` in the manifest, so a
table can never be silently produced from stale data.

## Records

**`workload_run`** — `workload_id, workload_commit, cipherscope_commit, lane,
repetition, arm, wall_ms, cpu_ms, peak_rss_mb, event_count, trace_bytes,
graph_bytes, analyzer_ms, coverage_class, passthrough_calls,
correctness_metric, correctness_value, machine_id, cpu_model, openfhe_version,
python_version`. `arm` is `baseline` or `traced`; baseline rows leave the
tracing-only columns empty. Export only measured repetitions (drop warm-ups).

**`finding`** — the 22 PDF section 11.2 columns followed by `severity,
recommendation, coverage_class, bundle, run_id`. `coverage_class` must be
`COMPLETE`; `adjudication` must be one of the five rubric values or empty.

**`seeded_case`** — one row per (case, rule) expectation with the observed
outcome; derived from `case_results.json`, never written by hand.

**`coverage_run`** — the columns `cipherscope coverage` writes.

**`scaling_run`** — one kernel process: `size, arm, repetition, events,
run_wall_ms, rss_start_mb, rss_end_mb, rss_growth_mb, peak_rss_mb, finalize_ms,
analyze_ms, trace_bytes, graph_bytes, recommendations_bytes, spooled,
python_version, machine`. `rss_growth_mb` is the growth of live RSS after the
first 1000 events; `peak_rss_mb` is the process's `ru_maxrss` and therefore
includes finalization and analysis.

**`ablation_run`** — `bundle, name, mode, rule_id, analysis_status, findings,
signature`; `signature` holds the value a finding must reproduce (depth, headroom)
to count as the same diagnosis.

## Tables

| Table | From | What it reports |
|---|---|---|
| `precision.csv` | `findings.csv` | Per-rule verdict counts and precision with its explicit numerator and denominator (definition in `adjudication/GUIDE.md`). |
| `recall.csv` | `raw/seeded/case_results.json` | Per-rule seeded recall and hard-negative false positives. |
| `seeded_cases.csv` | same | The flat per-case record behind `recall.csv`. |
| `coverage.csv` | `raw/coverage_report.csv` | Runs per coverage class and the `COMPLETE` fraction. |
| `overhead.csv` | `raw/workload_runs.csv` | Per workload: baseline and traced medians and IQRs, overhead ratio `(traced - baseline) / baseline` with a bootstrap 95% CI, absolute overhead, RSS delta, and traced event/trace-size/analyzer medians; an `ALL` row gives the median ratio across workloads. |
| `scaling.csv` | `raw/scaling.csv` | Per machine, event count, and arm (machines are never pooled; each is compared with its own baseline): wall time and its ratio to the untraced baseline, RSS growth and peak RSS minus the baseline's, finalization and analysis time, bytes per event, analysis ms per 1k events. Empirical slopes over the tested range only; no asymptotic claim. |
| `semantic_ablation.csv` | `raw/semantic_ablation.csv` | Per rule: seeded positives reproduced under `TIMING_ONLY`, `STATE`, and `FULL`, and the weakest mode that reproduces all of them. |
| `generic_profiler_comparison.csv` | same | Per rule: whether a timing-only view (what cProfile plus line attribution provides) can make the diagnosis. |

Overhead is reported per workload because percentage overhead on tiny
examples is misleading on its own; quote the absolute column with it.

## Adding a record type or table

Add the definition to `schema/results.schema.json`, a generator in
`src/cipherscope/tables.py`, and a test in `tests/test_tables.py` that proves
the output is byte-for-byte reproducible. Do not add a table that is not
traceable to a raw input.
