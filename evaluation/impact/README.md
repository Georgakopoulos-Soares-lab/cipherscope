# RQ4 impact suite: one program pair per rule, measured

Every actionable CipherScope rule ships with a `speedup: None` and the
sentence "No speedup is claimed until the transformed program is rerun."
This directory is where that rerun happens. For each rule there is one
medium-sized OpenFHE program in `cases/` with two variants:

* **before** — written to contain the pathology the rule describes, the way
  it actually shows up in practice (a reusable key-generation helper, a
  per-record loop, a development parameter set that shipped);
* **after** — the same program rewritten from the finding's own evidence
  and recommendation text, nothing else changed.

`run_impact.py` runs both variants of every case in fresh processes:

1. once **traced** through CipherScope, which must report the rule
   `positive` on `before` and `clean`/`not_applicable` on `after` — the suite
   fails otherwise — and yields the trace-level metrics (events, ciphertext
   versions, critical-path depth, levels consumed, per-operation counts);
2. `--repeat` times **untraced and timed**: `prepare` (context + keys),
   `setup` (rotation/bootstrap keys, hoisted encodings) and `workload` are
   timed separately because the benefit lands in different phases for
   different rules; peak RSS is read from the process at exit; the result is
   checked against a plaintext reference every time, so no number is ever
   reported next to a wrong answer.

`summarize.py` turns `evaluation/raw/impact.csv` into
`evaluation/tables/impact.csv` (medians, before/after ratios, and a
`headline` that names the metric each rule is about). Both scripts run with
`make impact`; `make tables` regenerates the summary from the archived raw
record.

| Case | Rule | before → after | Benefit lands in |
|---|---|---|---|
| `keys_unused` | `keys.unused_in_observed_run.v1` | rotation keys for 1..64 → keys for the 2 indices used | setup time, memory |
| `rotation_hoist` | `rotation.hoist_same_input.v1` | 8 × `EvalRotate` on one ciphertext → one `EvalFastRotationPrecompute` + 8 × `EvalFastRotation` | workload time |
| `encoding_repeated` | `encoding.repeated_public_constant.v1` | public weights re-encoded per record (32×) → encoded once | workload time, events |
| `packing_low` | `packing.low_utilization_annotated.v1` | 64 ciphertexts × 64 slots each (1.6 % utilization) → one full ciphertext | workload time, events, ciphertexts |
| `provenance_public_ct` | `provenance.public_value_ciphertext_mult.v1` | public weights encrypted, ct×ct products → plaintext, ct×pt products | workload time |
| `serial_reduction` | `multiplication.serial_reduction_review.v1` | 16-factor left fold (depth 15, ring 65536) → balanced tree (depth 4, ring 16384) | levels, ring dimension, time, memory |
| `depth_headroom` | `parameters.depth_headroom_observed.v1` | depth 12 configured for a 3-level kernel → depth 3 | ring dimension, time, memory |
| `bootstrap_underused` | `bootstrap.restored_levels_underused.v1` | bootstrap that restores 8 levels of which 2 are used → leveled context, no bootstrap | time, memory |
| `precision_tolerance` | `precision.tolerance_violated.v1` (+ `precision.checkpoint_drop.v1`) | 30-bit scale breaks a declared 1e-4 tolerance → 40-bit scale | absolute precision bits |
| `security_config` | `configuration.testing_only_security.v1` | `HEStd_NotSet`, ring 4096 → `HEStd_128_classic` | enforced security level (time/memory cost reported) |

Two rules have no pair of their own because they are diagnostic rather
than prescriptive: `depth.critical_path.v1` is the measurement that
`depth_headroom` acts on, and `precision.checkpoint_drop.v1` is the
localization that `precision_tolerance` acts on (squaring values above 1
loses absolute bits whatever the scale, so the drop rule correctly reports
the block in both variants of that case; the metric its companion fix
improves is precision at the final checkpoint).

Two things this suite found in the analyzers while being built, both fixed
with regression tests:

* `multiplication.serial_reduction_review.v1` flagged any chain of three or
  more multiplications, including an already-balanced tree, and inferred
  the term count from the chain instead of the region; it now counts the
  region's leaf ciphertexts and only fires when the chain is longer than a
  balanced tree over that many terms needs.
* the ciphertext graph charged level *alignment* as level *consumption*:
  multiplying a bootstrapped ciphertext by a fresh level-0 operand credited
  the fresh operand's lineage with the whole absolute level, so a
  post-bootstrap epoch reported "21 levels consumed" for two
  multiplications and `bootstrap.restored_levels_underused.v1` never fired
  on the shape it was written for. An operation now consumes
  `output_level - max(input_levels)`, attributed to the deepest input.

Parameters are `HEStd_128_classic` everywhere except where the case is
about the security level (`security_config`, before) and where a bootstrap
has to run in seconds (`bootstrap_underused`, both variants, declared with
`allow_testing_security=True`, matching the seeded corpus and OpenFHE's own
example).
