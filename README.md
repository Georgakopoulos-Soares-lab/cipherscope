# CipherScope

CipherScope traces CKKS programs written with OpenFHE — in Python through a
proxy around the live context, or in C++ through a GCC plugin that
instruments an unmodified program's OpenFHE calls at compile time — and
suggests possible optimizations. Both frontends emit the same canonical
trace; validation, the ciphertext graph, every analyzer, and every exporter
are shared. It currently:

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
cryptography. Real-OpenFHE evidence comes from four lanes, described in
[docs/evidence.md](docs/evidence.md): the authoritative Python 3.11 source
build on Ubuntu 24.04 x86_64 (40 of 40 gate checks), the same pins built
natively on a Rocky Linux 8.10 cluster host with GCC 15.2 (40 of 40), a macOS
ARM64 developer build (37 of 38 on the older check set; the one skip is
Linux-only), and a
provisional Ubuntu/Python 3.12 wheel (33 of 33 at the time it was archived).
`evaluation/parity/parity_report.md` shows that the platform-independent
results (seeded benchmark, ablation, example diagnoses) are identical across
them. CipherScope does not select secure parameters or prove precision.

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

For the real OpenFHE examples you need the pinned binding. On macOS ARM64,
activate the source-built conda environment documented in
[OPENFHE_ENVIRONMENT.md](../.codex/OPENFHE_ENVIRONMENT.md). On Linux, build one
of the two lanes in [docs/evidence.md](docs/evidence.md): the Ubuntu 24.04
container (`artifact/apptainer/openfhe-py311-source.def`, or the equivalent
Dockerfile), or the native toolchain build (`build_openfhe_ls6.sh`, written
for TACC Lonestar6 but only assuming Lmod modules for gcc and cmake). On LS6,
`source ls6_env.sh` sets up both: it puts the native build's `python3.11` on
`PATH` and defines `run_in_primary` to run a command inside the container.
Then follow [examples/README.md](examples/README.md). The metadata-only fake
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
`artifact/docker/openfhe-py311-source/`, or its rootless Apptainer twin under
`artifact/apptainer/`; the archived gate artifact was produced with the latter.

## Profiling a C++ program

For an OpenFHE C++ program built with GCC and CMake, no source change is
needed:

```bash
PYTHONPATH=src python3 -m cipherscope profile --output cipherscope-results/app ./build/app -- --epochs 10
```

`profile` finds the build's `CMakeCache.txt`, compiles the CipherScope GCC
plugin and runtime with the project's own compiler, creates an isolated
instrumented shadow build under `.cipherscope/` (optimization flags kept),
runs it with your arguments, and writes the same bundle a Python run writes.
A binary that already carries the `.cipherscope.marker` section is run
directly. The frontend, its coverage evidence, and its supported envelope are
described in [docs/cpp_frontend.md](docs/cpp_frontend.md); `profile` also
accepts `.py` targets and then behaves exactly like `run`.

## Instrumentation API

The main API wraps a native context without modifying it:

```python
import cipherscope

with cipherscope.trace(native_context, name="example") as session:
    cc = session.context
    rotated = cc.EvalRotate(encrypted_input, 1)
    combined = cc.EvalAdd(rotated, encrypted_input)
```

In Python, CipherScope records calls made through `session.context` and, while
a session is active, ciphertext operator overloads (`a + b`) on ciphertexts
whose context the session owns: the binding's operators are rerouted through
the proxy for the session's lifetime and restored at close, so `a + b` and
`cc.EvalAdd(a, b)` produce the same single event. It does not see free
functions, calls through the original context, unexecuted branches, work
inside a native call, or other processes. Strict mode rejects methods it
cannot classify. Permissive mode calls them and marks the trace incomplete.
The C++ frontend sees every call the application makes to the `CryptoContext`
API, operator overloads included, because the compiler inserts the
observation; a call to a method outside the operation manifest is reported and
denies `COMPLETE` coverage.

## Coverage classes

Because CipherScope cannot see calls that bypass `session.context`, every run
gets one of three coverage classes. Only `COMPLETE` runs should feed analyzer
precision, recall, or impact tables.

| Class | Meaning |
|---|---|
| `COMPLETE` | Strict mode, finished, at least one traced call, nothing forwarded untraced, no bypass pattern in the source. C++: additionally every compiled translation unit instrumented, no executed call outside the manifest, and the binary that ran carries the marker. |
| `PARTIAL-PERMISSIVE` | Finished, but some calls were forwarded untraced (permissive mode), the trace was truncated, the target source calls the raw context, `GetCryptoContext()`, a module-level `Eval*` free function, or `_context`; C++: an executed `CryptoContext` call outside the manifest (named in the report) or a partially instrumented build. |
| `UNSUPPORTED` | The run failed or was interrupted, strict mode rejected a call the target needed, no semantic call was traced, or (C++) the binary carries no instrumentation marker. |

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
untraced baseline. [docs/ARTIFACT.md](docs/ARTIFACT.md) maps every claim to its file, and the
`Makefile` provides `make artifact-smoke`, `make reproduce-small`, and
`make verify-checksums`.

## Repository map

```text
schemas/                 Versioned public JSON Schemas (one trace schema for both frontends)
src/cipherscope/         Session, proxy, recorder, graph, analyzers, CLI; native_trace / build_discovery / native_profile for C++
native/                  GCC plugin, runtime, OpenFHE adapter, operation manifest
tests/cpp/               Plain OpenFHE C++ fixture project and archived spools
tests/integration_cpp/   C++ frontend feasibility gate
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

- The C++ frontend supports GCC (with plugin headers) and CMake projects only;
  it is verified on GCC 15.2.0 (Rocky 8.10) and GCC 13.3.0 (Ubuntu 24.04) with
  OpenFHE 1.5.1 by the 21-check gate, archived for both compilers under
  `artifact/feasibility/cpp-gcc152-openfhe151/` and `cpp-gcc133-openfhe151/`. Annotations and
  precision checkpoints are available through the opt-in header
  `native/include/cipherscope/annotate.h` (inline no-ops outside a shadow
  build); without it those rules report `not_applicable` on C++ traces.
- The external Python corpus (`python-log-reg-examples`) traces strict-`COMPLETE`
  on all four workloads with the current operation set. Manifest v3 covers the
  vector composites (`EvalAddMany`, `EvalMultMany`, `EvalLinearWSum`,
  `EvalMerge`), the Chebyshev series family, `EvalSin`/`EvalCos`/`EvalDivide`,
  the `EvalAtIndex` aliases and BFV/BGV contexts (`MakePackedPlaintext`, scheme
  and plaintext modulus from the declared parameters) in both frontends; the
  level-adjusting `*Mutable` variants remain outside it.
- Real OpenFHE behavior is verified on four lanes with different weight
  ([docs/evidence.md](docs/evidence.md)). The authoritative Python 3.11 source
  build on Ubuntu 24.04 x86_64 passes all 40 checks and is archived under
  `artifact/feasibility/primary-source-py311/`; the native Rocky Linux / GCC
  15.2 build passes the same 40; the macOS ARM64 developer build passes all
  but the Linux-only `RES-02` of the 38 checks that existed when it was
  archived; the provisional Python 3.12 wheel passes the 33 checks that
  existed when it was archived. The claim is about observing
  OpenFHE calls correctly on those builds; other distributions, compilers, or
  OpenFHE versions are untested.
- Timing and memory figures are per machine. `evaluation/tables/scaling.csv`
  carries a `machine` column and never pools rows from different hardware;
  compare ratios (traced / baseline, bytes per event) across machines, not
  absolute milliseconds.
- The fake-backend contract covers the planned state/depth matrix and observed
  rotation-key inventory. Its real-binding tests remain gated on an actual pinned
  OpenFHE installation; fake results are not compatibility evidence.
- `bootstrap.restored_levels_underused.v1` only sees a restoration when the
  bootstrapped ciphertext was deeper than the level OpenFHE returns every
  bootstrap output at (`depth - levelsAvailableAfterBootstrap`); bootstrapping
  a shallow ciphertext shows no restored levels and the rule stays clean. The
  seeded corpus has one real positive (`bootstrap.positive.underused_deep`) and
  one such shallow negative. `precision.checkpoint_drop.v1` ignores drops
  below three absolute bits because CKKS decryption is noise-flooded (stdev
  ~0.68 bits of jitter per decryption, measured; three bits is ~4.4 stdev
  above that floor). Both are documented in
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
