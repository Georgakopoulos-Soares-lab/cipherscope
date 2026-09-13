# CipherScope

CipherScope traces CKKS programs written with OpenFHE Python and suggests
possible optimizations. It currently:

- proxy encryption/decryption, core evaluation, state/depth, declared in-place,
  rotation-key generation, rotation, and bootstrap calls;
- attribute whole-call wall and process-CPU time to the executing Python site;
- assign a ciphertext ID to each recorded ciphertext version;
- reconstruct the executed ciphertext graph and critical paths;
- report critical paths, repeated compatible rotations, and generated rotation
  keys unused in the observed run;
- check precision checkpoints against developer-declared tolerances and flag a
  declared `HEStd_NotSet` security level as a testing-only configuration; and
- export a schema-versioned run bundle.

This is pre-alpha research software. The included fake backend performs no
cryptography. Real-OpenFHE evidence comes from three lanes, described in
[docs/evidence.md](docs/evidence.md): a macOS developer build (37 of 38 gate
checks; the one skip is Linux-only), a provisional Ubuntu/Python 3.12 wheel
(33 of 33 at the time it was archived), and the authoritative Python 3.11
source build on Linux, whose gate result is not yet archived in this
repository. CipherScope does not select secure parameters or prove precision.

## Quick start

The baseline workflow uses only Python 3.11 or newer and the standard library:

```bash
cd cipherscope
PYTHON=/opt/miniconda3/bin/python3.13  # use any Python >= 3.11
"$PYTHON" --version
PYTHONPATH=src "$PYTHON" -m unittest discover -s tests -p 'test_*.py'
PYTHONPATH=src "$PYTHON" -m cipherscope.cli demo --output cipherscope-results/demo
PYTHONPATH=src "$PYTHON" -m cipherscope.cli validate cipherscope-results/demo
PYTHONPATH=src "$PYTHON" -m cipherscope.cli analyze \
  cipherscope-results/demo/trace.json --output cipherscope-results/analyzed
PYTHONPATH=src "$PYTHON" -m cipherscope.cli view cipherscope-results/demo
```

Do not use the Apple Command Line Tools Python 3.9 interpreter; it is below the
package's supported version floor.

For the real macOS ARM64 OpenFHE example, activate the dedicated source-built
environment documented in [OPENFHE_ENVIRONMENT.md](../.codex/OPENFHE_ENVIRONMENT.md),
then follow [examples/README.md](examples/README.md). The metadata-only fake
backend remains only for deterministic unit and contract tests.

An editable installation exposes the `cipherscope` command:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/cipherscope --help
```

The provisional Ubuntu 24.04/Python 3.12 wheel lane is pinned separately;
installing it does not establish compatibility by itself:

```bash
.venv/bin/python -m pip install --require-hashes \
  -r requirements/openfhe-ubuntu24-py312.txt
```

The primary Python 3.11 lane uses the source-build recipe under
`artifact/docker/openfhe-py311-source/`.

## Instrumentation API

The main API wraps a native context without modifying it:

```python
import cipherscope

with cipherscope.trace(native_context, name="example") as session:
    cc = session.context
    rotated = cc.EvalRotate(encrypted_input, 1)
    combined = cc.EvalAdd(rotated, encrypted_input)
```

CipherScope records only calls made through `session.context`. It does not see
operator overloads, free functions, calls through the original context,
unexecuted branches, work inside a native call, or other processes. Strict mode
rejects methods it cannot classify. Permissive mode calls them and marks the
trace incomplete.

The runner owns the top-level session; the target must call `attach()` or
`trace()` and otherwise keeps its working directory, streams, arguments, and exit
status:

```bash
PYTHONPATH=src python3 -m cipherscope.cli run \
  --output cipherscope-results/my-run -- instrumented_program.py --model demo.json
```

Normal, nonzero `SystemExit`, uncaught covered-call failure, missing attachment,
and `KeyboardInterrupt` paths all finalize a validated bundle. `view` validates
the bundle and prints the self-contained HTML report path; it does not start a
server or upload an artifact.

## Coverage classes

Because CipherScope cannot see calls that bypass `session.context`, every run
gets one of three coverage classes. Only `COMPLETE` runs should feed analyzer
precision, recall, or impact tables.

| Class | Meaning |
|---|---|
| `COMPLETE` | Strict mode, finished, at least one traced call, nothing forwarded untraced, no bypass pattern in the source. |
| `PARTIAL-PERMISSIVE` | Finished, but some calls were forwarded untraced (permissive mode), the trace was truncated, or the target source calls the raw context, `GetCryptoContext()`, a module-level `Eval*` free function, or `_context`. |
| `UNSUPPORTED` | The run failed or was interrupted, strict mode rejected a call the target needed, or no semantic call was traced. |

`preflight` scans scripts before running them; it exits `1` when it finds a
pattern that bypasses the tracer. `coverage` classifies finished bundles and
writes `coverage_report.csv` with the exact unsupported operations for every
run that is not `COMPLETE`:

```bash
PYTHONPATH=src python3 -m cipherscope.cli preflight my_workload.py
PYTHONPATH=src python3 -m cipherscope.cli coverage cipherscope-results/* \
  --output cipherscope-results/coverage_report.csv
```

`coverage` scans each run's recorded entrypoint by default; pass `--no-scan` to
classify from the trace alone. The scan is a heuristic: a clean result is not
proof that nothing bypassed the proxy. The trace manifest also lists every
rejected or forwarded call under `coverage.unsupported_operations`.

## Adjudicating findings

Analyzer output is not evidence until a person has checked it. `findings`
exports every finding from every `COMPLETE` real-OpenFHE bundle into one CSV
with empty verdict columns; `precision` reports the counts once they are filled
in. Re-exporting keeps existing verdicts.

```bash
PYTHONPATH=src python3 -m cipherscope.cli findings cipherscope-results/* \
  --output evaluation/adjudication/findings.csv
PYTHONPATH=src python3 -m cipherscope.cli precision \
  evaluation/adjudication/findings.csv
```

The rubric, evidence requirements, and column meanings are in
[evaluation/adjudication/GUIDE.md](evaluation/adjudication/GUIDE.md).

## Seeded benchmark

Recall cannot be measured on real programs, so `evaluation/seeded/` holds
known-answer OpenFHE programs: for each rule, one that must fire and one
near-miss that must not. `seeded` runs them on the real binding, compares the
output with `ground_truth.json`, and exits non-zero on any mismatch:

```bash
PYTHONPATH=src python3 -m cipherscope.cli seeded evaluation/seeded/ground_truth.json \
  --output cipherscope-results/seeded
```

See [evaluation/seeded/README.md](evaluation/seeded/README.md) for the table
columns and the limits the benchmark uncovered.

## Ablation, scaling, and the artifact path

`ablate` re-analyzes bundles under three views of the same trace — `TIMING_ONLY`
(what a generic profiler sees), `STATE` (per-call level/scale/key metadata, no
ciphertext identity), and `FULL` — and reports the weakest view under which each
rule still produces the same diagnosis. `evaluation/scaling/run_scaling.py`
measures memory, trace size, and analysis time from 10² to 10⁵ events against an
untraced baseline. `ARTIFACT.md` maps every claim to its file, and the
`Makefile` provides `make artifact-smoke`, `make reproduce-small`, and
`make verify-checksums`.

## Repository map

```text
schemas/                 Versioned public JSON Schemas
src/cipherscope/         Session, proxy, recorder, graph, analyzers, CLI
examples/                Dependency-free demonstration workload
tests/fake_backend/      Proxy/session mechanics
tests/golden/            Expected analyzer results
tests/fixtures/          Synthetic corpus and provenance catalog
docs/                    Architecture and corpus notes
evaluation/adjudication/ Human review of real findings (guide; findings.csv is generated)
evaluation/seeded/       Known-answer programs and ground truth for analyzer recall
evaluation/scaling/      Event-count scaling kernel and runner
evaluation/raw/          Archived raw records with checksums; evaluation/tables/ is generated
```

See [architecture.md](docs/architecture.md) and [fixtures.md](docs/fixtures.md)
for the implementation boundary. The parent
research repository tracks verified status in `CIPHERSCOPE_PROGRESS.md`.

## Current limitations

- Real OpenFHE behavior is verified on three lanes with different weight
  ([docs/evidence.md](docs/evidence.md)): the macOS ARM64 developer build
  (all checks except the Linux-only `RES-02`, including bootstrap and the seeded
  benchmark), the provisional Ubuntu 24.04 / Python 3.12 wheel (every check that
  existed when it was archived), and the authoritative Python 3.11 source build,
  whose passing gate artifact still has to be copied into `artifact/feasibility/`.
  Until that file is present the compatibility claim is not backed by checked-in
  evidence.
- The fake-backend contract covers the planned state/depth matrix and observed
  rotation-key inventory. Its real-binding tests remain gated on an actual pinned
  OpenFHE installation; fake results are not compatibility evidence.
- `bootstrap.restored_levels_underused.v1` cannot fire on real traces: `GetLevel()`
  is unchanged by `EvalBootstrap` on OpenFHE Python 1.5.1.0 under every scaling
  technique that can bootstrap. `precision.checkpoint_drop.v1` ignores drops
  below one absolute bit because CKKS decryption is noise-flooded (about half a
  bit of jitter per decryption). Both are documented in
  [evaluation/seeded/README.md](evaluation/seeded/README.md).
- The security level is not readable from a live context. The configuration
  rule only assesses runs that declare their parameters
  (`trace(..., parameters=params)`, or any run launched through
  `examples/profile_unmodified.py`); it reports a configuration observation,
  never a bit-security estimate.
- Recording is bounded: events and finished ciphertext states spool to a
  temporary file, and `run --max-events N` / `--max-trace-bytes N` stop
  recording (never the workload) at a hard limit, marking the trace truncated.
  Finalization is not streamed: `to_trace()` and analysis load the whole trace,
  about 2.2 KB and 30 KB of peak memory per event on the scaling kernel
  (`evaluation/tables/scaling.csv`).
- Metadata getters may be unavailable. Missing evidence remains `unknown`; it is
  never fabricated.
- Traces include argument and output representations, exception messages,
  absolute source paths, and precision-checkpoint values.

## Independent repository and submodule status

This directory is an independent Git repository. A parent repository can track
it as a submodule after the owner selects a remote.

After the owner selects a remote, the integration sequence is:

```bash
git -C cipherscope add .
git -C cipherscope remote add origin <AUTHORIZED_REMOTE_URL>
git -C cipherscope push -u origin main
git submodule add --force <AUTHORIZED_REMOTE_URL> cipherscope
git add .gitmodules cipherscope CIPHERSCOPE_PROGRESS.md
```

The final parent commit remains an owner decision. Future clones initialize it
with `git submodule update --init --recursive`.
