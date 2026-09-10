# Examples

`mvp_demo.py` runs the first CipherScope vertical slice against a deterministic,
metadata-only fake context. It is an end-to-end instrumentation example, not
cryptography and not evidence of OpenFHE compatibility.

Run it from the implementation repository:

```bash
PYTHONPATH=src python3 examples/mvp_demo.py --output /tmp/cipherscope-demo
PYTHONPATH=src python3 -m cipherscope.cli validate /tmp/cipherscope-demo
```

The workload intentionally generates the four required rotation keys, performs
four rotations of one immutable ciphertext, an addition, a ciphertext-ciphertext
multiplication, and a bootstrap. Its output should contain a versioned graph, a
nonlinear-depth path, one conservative `rotation.hoist_same_input.v1` finding,
and a clean `keys.unused_in_observed_run.v1` result.

## Profile a small program with `cipherscope run`

`profiled_workload.py` is an ordinary instrumented target program using the real
OpenFHE Python CKKS binding. It generates a context and keys, encrypts two packed
vectors, evaluates rotations and arithmetic, decrypts the result, and checks the
numerical error.

Activate the dedicated source-built OpenFHE environment. The same instructions
are recorded for Codex in `../.codex/OPENFHE_ENVIRONMENT.md`:

```bash
source /opt/miniconda3/etc/profile.d/conda.sh
conda activate cipherscope-openfhe
unset DYLD_LIBRARY_PATH
python --version
python -c "import openfhe, cipherscope; print(openfhe.get_native_int())"
```

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
in this observed run. The trace and timings come from actual OpenFHE calls; this
local macOS ARM64 developer build is not a substitute for the canonical Linux
compatibility gate.

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

## Synthetic example gallery (`examples/synthetic/`)

`examples/synthetic/` contains twelve additional real OpenFHE programs, each
exercising a specific CipherScope diagnostic. They come in two flavors.

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

### Instrumented programs (CipherScope annotation and shadow-mode API)

These use CipherScope's session API (`annotate`, `annotate_plaintext`, `region`,
`checkpoint`) to supply the explicit assertions that packing, provenance,
encoding, serial-reduction, and precision diagnostics require. The cryptography
is still real OpenFHE. Each program self-traces and prints its finding when run
directly:

| Program | Assertion used | Diagnostic exercised |
|---|---|---|
| `annotate_packing.py` | `annotate(meaningful_slots=...)` | packing low utilization |
| `public_constant_mult.py` | `annotate(provenance="public_constant")` | public-value ct-ct multiply |
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

`precision_checkpoints.py` must be run directly: shadow mode holds the secret key
in-process to decrypt at each checkpoint and is off by default, so it is not
enabled by the `cipherscope run` runner. It computes aggregate precision metrics
only and never serializes the compared values.
