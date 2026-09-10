# CipherScope

CipherScope traces CKKS programs written with OpenFHE Python and suggests
possible optimizations. It currently:

- proxy encryption/decryption, core evaluation, state/depth, declared in-place,
  rotation-key generation, rotation, and bootstrap calls;
- attribute whole-call wall and process-CPU time to the executing Python site;
- assign a ciphertext ID to each recorded ciphertext version;
- reconstruct the executed ciphertext graph and critical paths;
- report critical paths, repeated compatible rotations, and generated rotation
  keys unused in the observed run; and
- export a schema-versioned run bundle.

This is pre-alpha research software. The included fake backend performs no
cryptography. An exact-pinned macOS ARM64 developer build now runs the real
example and targeted binding tests, but the required primary Linux OpenFHE
1.5.1.0 feasibility gate has not passed. CipherScope does not select secure
parameters or prove precision.

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

## Repository map

```text
schemas/                 Versioned public JSON Schemas
src/cipherscope/         Session, proxy, recorder, graph, analyzers, CLI
examples/                Dependency-free demonstration workload
tests/fake_backend/      Proxy/session mechanics
tests/golden/            Expected analyzer results
tests/fixtures/          Synthetic corpus and provenance catalog
docs/                    Architecture and corpus notes
```

See [architecture.md](docs/architecture.md) and [fixtures.md](docs/fixtures.md)
for the implementation boundary. The parent
research repository tracks verified status in `CIPHERSCOPE_PROGRESS.md`.

## Current limitations

- Targeted real OpenFHE behavior is verified only on the local exact-pinned macOS
  ARM64 developer build; the required Linux gate and bootstrap lane remain open.
- The fake-backend contract covers the planned state/depth matrix and observed
  rotation-key inventory. Its real-binding tests remain gated on an actual pinned
  OpenFHE installation; fake results are not compatibility evidence.
- Resource sampling, streaming output, and additional diagnostics are later
  milestones.
- Metadata getters may be unavailable. Missing evidence remains `unknown`; it is
  never fabricated.
- Trace size is not bounded and output is buffered in memory.
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
