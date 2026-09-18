# Seeded pathology benchmark

Real programs have no ground truth for what an analyzer *missed*, so recall
cannot be measured on them. This directory holds small OpenFHE programs where
the answer is known in advance: for each analyzer, a program that must fire and
a near-miss that must not. `cipherscope seeded` runs them all, compares the
output with `ground_truth.json`, and writes a per-rule recall and
false-positive table.

What this benchmark measures: recall and hard-negative false positives of the
built-in rules on controlled programs. What it does not measure: precision on
real workloads (that is `evaluation/adjudication/`) or recall on real workloads
(undefined).

## Running it

```bash
PYTHONPATH=src python -m cipherscope seeded evaluation/seeded/ground_truth.json \
  --output /tmp/seeded-run
```

The interpreter must import the real `openfhe` binding; the command refuses to
start otherwise. It exits `0` only when every case matches, so it doubles as a
regression gate. Each case runs in its own process through `cipherscope run`
and its bundle is archived under `OUTPUT/bundles/<case_id>/`; pass
`--from-bundles` to regenerate the table from those bundles without OpenFHE.

The whole corpus takes about ten seconds on a laptop.

## Reading the table

| Column | Meaning |
|---|---|
| `seeded_positives`, `detected`, `recall` | Cases expected `positive`; how many fired with the expected source lines and evidence; their ratio |
| `seeded_negatives`, `false_positives`, `fp_rate` | Cases expected `clean` or `not_applicable`; how many fired anyway; their ratio |
| `not_applicable_cases` | The subset of negatives where the rule is expected to decline to assess |
| `mismatches` | Fired at the wrong lines, with the wrong evidence, or assessed when it should not have (or vice versa) |
| `invalid_runs` | Cases whose run was not `COMPLETE` on a real backend; excluded from every ratio |

Ratios are blank when their denominator is zero. Quote counts with ratios.

## Ground truth rules

- Every expectation was observed on OpenFHE Python 1.5.1.0 before it was
  written down, and every declared number (a depth, a level count, a source
  line) is hand-derivable from the case's source.
- A hard negative is expected `clean`: the rule assessed the program and
  correctly declined. `not_applicable` is a weaker near-miss (the rule refused to
  assess) and is counted separately.
- Rules not listed in a case's `expected` are not checked for that case; the
  runner still lists their firings under `unexpected_positives` for visibility.
- Every case calls `cipherscope.trace()` itself and makes every FHE call
  through `session.context`; the coverage scan rejects a case that reaches the
  raw context.
- `depth.critical_path.v1` always fires when there is lineage, so its cases are
  value checks: Horner (depth 3), a linear-only kernel (depth 0), and an opaque
  `EvalInnerProduct` where the correct answer is `confidence == "unknown"`.
- The corpus covers all twelve rules with 28 cases; every rule has at least one
  real-binding positive and one hard negative (the bootstrap rule's positive
  was added after the C++ frontend showed the rule firing on OpenFHE's own
  bootstrapping example; see below).

## Known limits found while building this

**`bootstrap.restored_levels_underused.v1` needs a deep input.** An earlier
version of this note claimed `GetLevel()` is unchanged by `EvalBootstrap`; that
was a misreading of one case. OpenFHE returns every bootstrapped ciphertext at
the fixed level `depth - levelsAvailableAfterBootstrap`, whatever the input
level. `bootstrap.limitation.underused_real` bootstraps after five squarings
of a fresh ciphertext (level 5 of about 23), so the output lands deeper than the
input and there is nothing restored: the rule stays clean, correctly.
`bootstrap.positive.underused_deep` encrypts at `depth - 1`, bootstraps
(31 → 21, ten levels restored) and decrypts without using them: the rule
fires with `restored_levels = 10`. The C++ frontend observes the same 31 → 21
transition on OpenFHE's own `simple-ckks-bootstrapping.cpp`, so this is the
library's semantics, not a binding artifact. (Bootstrapping a level-0
ciphertext returns level 0 on this build.)

**CKKS decryption is noise-flooded.** Two decryptions of the same ciphertext
differ at about 1e-12, stdev ~0.68 absolute bits (measured over 40
repetitions; max observed 1.74 bits). Before `precision.checkpoint_drop.v1`
had a minimum, `precision.negative.same_ciphertext` fired roughly half the
time. A first fix set `MIN_BITS_LOST` to one bit, but that still left a
normal-tailed ~5% false-positive rate on noise alone and the case kept
failing intermittently in CI (confirmed: 2 of 4 runs). `MIN_BITS_LOST` is now
three bits — about 4.4 stdev above the measured noise floor, and still two
orders of magnitude below a genuine drop (~14 bits for three squarings in
`precision_drop.py`) — and that case pins the corrected threshold.
`precision.tolerance_violated.v1` is the contract-based alternative: the
developer declares an absolute, relative, or minimum-bits tolerance per
checkpoint and the rule reports the first checkpoint that breaks it together
with the operations since the previous one.

**The security level is not readable from a live context.**
`configuration.testing_only_security.v1` assesses only runs that declared their
parameters (`trace(..., parameters=params)`); `configuration.negative.undeclared`
pins that it declines rather than inferring `HEStd_NotSet` from a 64-slot ring.

**`EvalFastRotationPrecompute` is not in the compatibility registry**, so the
"precompute already present" negative for the rotation rule cannot run
strictly on the real binding; `tests/golden/test_graph_validation.py` covers it
on the fake model.

## Adding a case

1. Write `cases/<rule>_<variant>.py` following the existing ones: build the
   context with `_kernel.make_context`, trace it, make every call through
   `session.context`, and end with a numerical check that raises on error.
2. Run it on the real binding and read `recommendations.json` before deciding
   what to expect. Do not write an expectation you have not seen.
3. Add the entry to `ground_truth.json` with a `hard_negative_reason` or
   `notes` that a reviewer can check against the source.
4. Run `cipherscope seeded` three times; a case that does not match every time
   is not ground truth.
