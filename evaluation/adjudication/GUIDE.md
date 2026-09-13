# Adjudicating CipherScope findings

CipherScope's warnings are not results until a person has checked each one.
This directory holds that check. `findings.csv` is the single table the paper's
"precision" number comes from, so every row in it must have a verdict and
written evidence before that number is reported.

## Which runs qualify

Only bundles that are both **real OpenFHE runs** and classified **`COMPLETE`**
by `cipherscope coverage` are exported. Fake-backend runs, permissive runs,
truncated runs, failed runs, and runs whose source shows a tracer bypass are
excluded, and the export prints the reason for each. There is no flag to
include them: a finding from a trace that may have missed calls cannot be
adjudicated honestly.

By default the export also refuses a bundle whose target script cannot be found
on disk, because it cannot scan the script for bypass patterns. Run the export
on the machine that produced the bundles, or pass `--allow-unscanned` and note
that in `notes`.

## Workflow

```bash
# 1. Export (or re-export) findings. Existing verdicts are kept.
PYTHONPATH=src python -m cipherscope findings BUNDLE... \
  --output evaluation/adjudication/findings.csv

# 2. Fill in the human columns for every row (see below).

# 3. Report counts and precision. Fails if any verdict is not in the rubric.
PYTHONPATH=src python -m cipherscope precision evaluation/adjudication/findings.csv \
  --output evaluation/adjudication/precision_table.csv
```

`workload_id` is the bundle directory name. Do not rename bundle directories
after adjudication starts; the `finding_id` is derived from it.

## Columns

Machine-owned columns are rewritten on every export. Never edit them.

| Column | Meaning |
|---|---|
| `finding_id` | `workload:rule:hash`. The hash covers the rule and source location only, so it is stable across re-runs and machines. A `#2` suffix separates two findings from the same rule at the same location. |
| `workload_id`, `rule_id`, `source_file`, `source_lines`, `confidence` | Copied from the bundle. |
| `severity`, `recommendation`, `coverage_class`, `bundle`, `run_id` | Context for the reviewer and a pointer back to the exact bundle. |

Human-owned columns are never touched by the export.

| Column | What to write |
|---|---|
| `adjudication` | Exactly one of the five rubric values below. |
| `adjudicator_1` | Who made the first verdict (initials). |
| `adjudicator_2` | Who made an independent second verdict, if anyone. Leave empty otherwise; the report states the single-reviewer limitation automatically. |
| `disagreement` | If the two reviewers differed: both verdicts and how it was resolved. |
| `evidence_summary` | Required for the row to count. See "Evidence". |
| `transformation_*`, `before_*`, `after_*`, `speedup`, `correctness_*`, `upstream_issue_or_pr` | Filled in during D-03 (before/after transformations). Leave empty here. |
| `notes` | Anything else, including "unscanned" if the export used `--allow-unscanned`. |

## Rubric

| Verdict | Use when |
|---|---|
| `TP-ACTIONABLE` | The rule is right about the program, and a concrete code change would test the claim. |
| `TP-NONACTIONABLE` | The rule is right, but no reasonable change follows (for example an intentionally unused key kept for another input). |
| `FALSE-POSITIVE` | The rule is wrong about the program. Say why in the evidence. |
| `UNCERTAIN` | You could not decide from the source and trace. This counts against precision. |
| `NOT-IN-SCOPE` | The row is not a diagnosis, for example an `information`-severity depth report. Excluded from the precision denominator. |

## Evidence

An adjudicated row without `evidence_summary` is reported as
"adjudicated without evidence" and is not counted. Write, in one or two
sentences:

1. the source lines you read and what they do;
2. the relevant FHE state (ciphertext version, level, key, rotation indices);
3. why the rule does or does not apply;
4. for a true positive, the transformation that would test it.

## What the report means

`precision = (TP-ACTIONABLE + TP-NONACTIONABLE) / (TP-ACTIONABLE + TP-NONACTIONABLE + FALSE-POSITIVE + UNCERTAIN)`

The report prints this definition, every count, and the denominator next to each
number. Quote them together. The report never computes recall: real programs
have no ground truth for missed opportunities, so recall comes only from the
seeded benchmark (D-02).

## Re-running a workload

Re-exporting after a fresh run keeps every verdict whose `finding_id` still
appears. A finding that no longer appears for a re-exported workload is moved to
`findings.stale.csv` together with its verdict; it is never deleted silently.
Workloads not included in an export are left exactly as they were.
