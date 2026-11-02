# Examples

`mvp_demo.py` runs a small CipherScope example against a deterministic,
metadata-only fake context. It demonstrates the complete tracing workflow, not
cryptography or OpenFHE compatibility.

Run it from the implementation repository:

```bash
PYTHONPATH=src python3 examples/mvp_demo.py --output /tmp/cipherscope-demo
PYTHONPATH=src python3 -m cipherscope.cli validate /tmp/cipherscope-demo
```

The workload intentionally generates the four required rotation keys, performs
four rotations of one recorded ciphertext version, an addition, a
ciphertext-ciphertext multiplication, and a bootstrap. Its output should contain
a versioned graph, a nonlinear-depth path, one conservative
`rotation.hoist_same_input.v1` finding, and a clean
`keys.unused_in_observed_run.v1` result.

## Profile a C++ program

OpenFHE C++ programs built with GCC and CMake need no change either:

```bash
PYTHONPATH=src python -m cipherscope profile --output /tmp/cipherscope-cpp ./build/my_program -- args
```

The plain fixture project under `tests/cpp/fixtures/` (rotations, operators
and in-place mutation, aliasing, exceptions, threads, an unmatched call) shows
what is observed; `docs/cpp_frontend.md` explains the shadow build and the
coverage evidence. `tests/cpp/twins/` holds the Python programs equivalent to
those fixtures, and their traces are semantically identical.

## Profile a small program with `cipherscope run`

`profiled_workload.py` is an ordinary instrumented target program using the real
OpenFHE Python CKKS binding. It generates a context and keys, encrypts two packed
vectors, evaluates rotations and arithmetic, decrypts the result, and checks the
numerical error.

Activate an environment with the pinned binding. On macOS ARM64 that is the
dedicated source-built conda environment (the same instructions are recorded
for Codex in `../.codex/OPENFHE_ENVIRONMENT.md`):

```bash
source /opt/miniconda3/etc/profile.d/conda.sh
conda activate cipherscope-openfhe
unset DYLD_LIBRARY_PATH
python --version
python -c "import openfhe, cipherscope; print(openfhe.get_native_int())"
```

On Linux / TACC Lonestar6, `ls6_env.sh` provides both lanes from
[docs/evidence.md](../docs/evidence.md). The native lane's `python3.11` is
put on `PATH` and can be used exactly as `python` is used below; the
authoritative Ubuntu container is reached through `run_in_primary`, which
mounts the checkout at `/workspace/cipherscope` and `$RESULTS_ROOT` at
`/results`:

```bash
source ls6_env.sh
python3.11 -c "import openfhe, cipherscope; print(openfhe.get_native_int())"   # native lane
run_in_primary python3.11 -m cipherscope run --output /results/dot-product \
  examples/profile_unmodified.py -- examples/dot_product.py                      # container lane
```

`evaluation/parity/run_lane.sh` runs every program on this page plus the
seeded benchmark and the scaling sweep for one lane; the results from the
macOS, container, and native lanes are compared in
`evaluation/parity/parity_report.md`.

From the `cipherscope/` implementation directory, run the program directly:

```bash
PYTHONPATH=src python examples/profiled_workload.py \
  --rotation 1 --rotation 2
```

Then run CipherScope around the same program. Choose a new output path for each
run because CipherScope intentionally refuses to overwrite an existing bundle:

```bash
OUTPUT="/tmp/cipherscope-profiled-workload-$(date +%s)"

PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" \
  examples/profiled_workload.py -- \
  --rotation 1 --rotation 2

PYTHONPATH=src python -m cipherscope validate "$OUTPUT"
PYTHONPATH=src python -m cipherscope view "$OUTPUT"
```

The bundle contains `trace.json`, `ciphertext_graph.json`,
`recommendations.json`, `operations.csv`, `perfetto-trace.json`, and
`summary.html`. With the arguments above, the recommendations include a
repeated-rotation opportunity and report generated rotation index `4` as unused
in this observed run. The trace and timings come from actual OpenFHE calls.
The same diagnoses are produced on the macOS ARM64 developer build and on both
x86_64 Linux lanes (see `evaluation/parity/parity_report.md`); only the
authoritative Linux lane backs the compatibility claim.

## Profile existing scripts without editing them

`profile_unmodified.py` intercepts only the target's `GenCryptoContext` factory,
attaches the returned native context to the active runner session, executes the
original file with `runpy`, and restores the factory afterward. It does not write
to or rewrite the target script.

After activating `cipherscope-openfhe`, run an example from the `cipherscope/`
directory with a fresh output path:

```bash
OUTPUT="/tmp/cipherscope-chebysev-$(date +%s)"
PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" \
  examples/profile_unmodified.py -- examples/chebysev.py
PYTHONPATH=src python -m cipherscope validate "$OUTPUT"
PYTHONPATH=src python -m cipherscope view "$OUTPUT"
```

Use the same launcher for the other files:

```bash
OUTPUT="/tmp/cipherscope-dot-product-$(date +%s)"
PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" \
  examples/profile_unmodified.py -- examples/dot_product.py
PYTHONPATH=src python -m cipherscope validate "$OUTPUT"

OUTPUT="/tmp/cipherscope-bootstrapping-$(date +%s)"
PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" \
  examples/profile_unmodified.py -- examples/bootstrapping.py
PYTHONPATH=src python -m cipherscope validate "$OUTPUT"
```

All three complete unchanged and produce validated bundles. `dot_product.py`
enables `ADVANCEDSHE` before `EvalSumKeyGen`, and `bootstrapping.py` performs an
eight-slot `EvalBootstrapSetup` (with a matching level budget and slot-count
encoding) before `EvalBootstrapKeyGen`. CipherScope observes the real calls and
preserves any failure as an error event instead of rewriting the
program.

`profile_unmodified.py` is the canonical launcher for corpus runs. After a batch
of runs, classify every bundle and keep only `COMPLETE` ones for analyzer-quality
tables:

```bash
PYTHONPATH=src python -m cipherscope coverage /tmp/cipherscope-*-* \
  --output /tmp/coverage_report.csv
```

Run `cipherscope preflight target.py` first to see whether a script calls the
raw context or a free function that the proxy cannot observe.

## Synthetic example gallery (`examples/synthetic/`)

`examples/synthetic/` contains sixteen additional real OpenFHE programs, each
exercising a specific CipherScope diagnostic. Twelve are CKKS; four are the
integer schemes, so the gallery covers every scheme CipherScope supports. They
come in two flavors.

### Bare programs (no CipherScope import)

These are ordinary OpenFHE scripts. Run them directly, or profile them without
edits through `profile_unmodified.py`.

| Program | Real computation | Diagnostic exercised |
|---|---|---|
| `weighted_inner_product.py` | `EvalInnerProduct` of two packed vectors | depth critical path |
| `vector_variance.py` | mean/variance via `EvalSum` and squares | depth, parameter headroom |
| `polynomial_horner.py` | degree-4 Horner evaluation | depth critical path |
| `squared_distance.py` | `sum (a-b)^2` | depth, parameter headroom |
| `matrix_vector_diag.py` | 4x4 diagonal-method matrix-vector product | rotations, keys |
| `repeated_rotations.py` | sum of rotations by 1, 2, 3 (key 5 unused) | rotation hoisting, unused keys |
| `bootstrap_then_idle.py` | five squarings, bootstrap, one product | bootstrap path, parameter headroom |
| `bfv_integer_rotations.py` | BFV: sum of rotations by 1, 2, 3 (key 5 unused) | rotation hoisting under BV key switching, unused keys |
| `bgv_integer_polynomial.py` | BGV: `3x^3 + 2x^2 + 5` by Horner on packed integers | depth critical path, parameter headroom |
| `bgv_windowed_sum.py` | BGV: sliding-window sums, 4 rotations of one version, key 7 unused | rotation hoisting, unused keys, parameter headroom |

The integer-scheme programs are exact: they print observed and expected
values that must match bit for bit, not within a tolerance. `bfv_integer_rotations.py`
also shows the two BFV differences that matter when reading its report — the
context uses BV key switching rather than HYBRID, and `EvalRotate` shifts left
with zero fill instead of wrapping the batch. Its depth-headroom finding
carries `confidence: inferred` rather than `measured`, because BFV's configured
depth is a noise budget counted from recorded multiplications, not a level
ladder read from ciphertext state.

Run one directly (without CipherScope):

```bash
PYTHONPATH=src python examples/synthetic/vector_variance.py
```

Profile the same file with CipherScope (with CipherScope), using a fresh output
path each time:

```bash
OUTPUT="/tmp/cipherscope-variance-$(date +%s)"
PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" \
  examples/profile_unmodified.py -- examples/synthetic/vector_variance.py
PYTHONPATH=src python -m cipherscope validate "$OUTPUT"
PYTHONPATH=src python -m cipherscope view "$OUTPUT"
```

`repeated_rotations.py` reports a `rotation.hoist_same_input.v1` opportunity and
lists rotation index `5` as unused in the observed run. `vector_variance.py` and
`squared_distance.py` report observed depth headroom below the configured
multiplicative depth.

Note on `bootstrap_then_idle.py`: on this real OpenFHE FLEXIBLEAUTO build the
bootstrap refreshes the modulus budget without changing the observable
`GetLevel()`, so `bootstrap.restored_levels_underused.v1` measures a zero level
delta and reports `clean`. The underuse finding itself is exercised by the
fake-model golden test (`tests/golden/test_bootstrap.py`); observing bootstrap
restoration from real ciphertext getters alone is a documented limitation.

### Instrumented programs (CipherScope annotations and precision checkpoints)

These use CipherScope's session API (`annotate`, `annotate_plaintext`, `region`,
`checkpoint`) to supply the explicit assertions that packing, provenance,
encoding, serial-reduction, and precision diagnostics require. The cryptography
is still real OpenFHE. Each program self-traces and prints its finding when run
directly:

| Program | Assertion used | Diagnostic exercised |
|---|---|---|
| `annotate_packing.py` | `annotate(meaningful_slots=...)` | packing low utilization |
| `bfv_encrypted_scoring.py` | BFV: score 8 encrypted records against a public model | repeated public encoding, public-value provenance, packing utilization, serial reduction |
| `public_constant_mult.py` | `annotate(provenance="public_constant")` | public-value ciphertext multiply |
| `repeated_public_constant.py` | `annotate_plaintext(constant_id=...)` | repeated public-constant encoding |
| `serial_reduction_region.py` | `region(operator="multiply", associative=True)` | serial multiplication reduction |
| `precision_checkpoints.py` | `checkpoint(...)` in `shadow_mode=True` | precision checkpoint drop |

Run one directly (it prints the diagnostic):

```bash
PYTHONPATH=src python examples/synthetic/public_constant_mult.py
```

The four non-precision programs can also be wrapped by `cipherscope run` to emit
a full bundle; the annotations flow into `recommendations.json`:

```bash
OUTPUT="/tmp/cipherscope-public-const-$(date +%s)"
PYTHONPATH=src python -m cipherscope run \
  --output "$OUTPUT" examples/synthetic/public_constant_mult.py
PYTHONPATH=src python -m cipherscope validate "$OUTPUT"
```

`precision_checkpoints.py` opts into shadow mode itself: `trace(...,
shadow_mode=True, secret_key=...)` holds the secret key in-process to decrypt at
each checkpoint, and that opt-in is honored both when the script runs directly
and when it joins the `cipherscope run` runner. Checkpoints record the expected
and observed values, so a trace from a shadow-mode run contains plaintext data.
The example squares values above 1 so that the absolute error grows and the
second checkpoint measurably loses bits; squaring values below 1 shrinks the
error instead and reports `clean`.
