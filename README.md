# CipherScope

CipherScope is a research-grade, source-aware profiler and optimization advisor
for CKKS programs written against OpenFHE Python. This repository begins with the
smallest coherent vertical slice from the canonical research plan:

- proxy encryption/decryption, core evaluation, state/depth, declared in-place,
  rotation-key generation, rotation, and bootstrap calls;
- attribute whole-call wall and process-CPU time to the executing Python site;
- assign opaque run-local ciphertext-version and event IDs;
- reconstruct the executed ciphertext graph and critical paths;
- report critical paths, repeated compatible rotations, and generated rotation
  keys unused in the observed run; and
- export a schema-versioned, privacy-conscious run bundle.

This is pre-alpha research software. The included fake backend performs no
cryptography. An exact-pinned macOS ARM64 developer build now runs the real
example and targeted binding tests, but the required primary Linux OpenFHE
1.5.1.0 feasibility gate has not passed. CipherScope does not select secure
parameters, prove precision, or make traces safe to publish.

## Quick start

The baseline workflow uses only Python 3.11 or newer and the standard library:

```bash
cd cipherscope
PYTHON=/opt/miniconda3/bin/python3.13  # use any Python >= 3.11
"$PYTHON" --version
PYTHONPATH=src "$PYTHON" -m unittest discover -s tests -p 'test_*.py'
PYTHONPATH=src "$PYTHON" -m cipherscope.cli demo --output cipherscope-results/demo
PYTHONPATH=src "$PYTHON" -m cipherscope.cli validate cipherscope-results/demo
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

The canonical API wraps a native context without modifying it:

```python
import cipherscope

with cipherscope.trace(native_context, name="example") as session:
    cc = session.context
    rotated = cc.EvalRotate(encrypted_input, 1)
    combined = cc.EvalAdd(rotated, encrypted_input)
```

Only explicit calls through `session.context` are observable. Operator
overloads, free functions, calls through the original reference, unexecuted
branches, native sub-phases, and other processes are outside this MVP's evidence
boundary. Strict mode rejects unclassified callable attributes before executing
them; permissive mode forwards them while marking the trace incomplete.

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
tests/golden/            Independent semantic expectations
tests/security/          Non-serialization, permissions, and escaping
tests/fixtures/          Synthetic corpus and provenance catalog
docs/                    Architecture, security, and corpus notes
```

See [architecture.md](docs/architecture.md), [security.md](docs/security.md),
and [fixtures.md](docs/fixtures.md) for the implementation boundary. The parent
research repository tracks verified status in `CIPHERSCOPE_PROGRESS.md`.

## Current limitations

- Targeted real OpenFHE behavior is verified only on the local exact-pinned macOS
  ARM64 developer build; the canonical Linux gate and bootstrap lane remain open.
- The fake-backend contract covers the planned state/depth matrix and observed
  rotation-key inventory. Its real-binding tests remain gated on an actual pinned
  OpenFHE installation; fake results are not compatibility evidence.
- Precision checkpoints, packing/public-value provenance, resource sampling,
  bounded streaming, and the remaining diagnostics are later milestones.
- Metadata getters may be unavailable. Missing evidence remains `unknown`; it is
  never fabricated.
- User metadata strings are bounded, but total event/trace byte caps and buffered
  streaming are not implemented yet; do not trace an untrusted unbounded workload.
- A Python process cannot guarantee physical zeroization of secret references.
- Timing and graph topology can themselves reveal sensitive program structure.
- Multi-language exception-stack fixtures exercise untrusted-text handling only;
  CipherScope does not claim to profile those runtimes.

## Independent repository and submodule status

This directory is an independent local Git repository. It intentionally has no
commit or remote because the implementation request forbids creating either
without authorization. Consequently, the parent repository cannot yet store a
valid gitlink.

After the owner selects a remote and authorizes commits, the integration sequence
is:

```bash
git -C cipherscope add .
git -C cipherscope commit -m "Initial CipherScope vertical slice"
git -C cipherscope remote add origin <AUTHORIZED_REMOTE_URL>
git -C cipherscope push -u origin main
git submodule add --force <AUTHORIZED_REMOTE_URL> cipherscope
git add .gitmodules cipherscope CIPHERSCOPE_PROGRESS.md
```

The final parent commit remains an owner decision. Future clones initialize it
with `git submodule update --init --recursive`.
