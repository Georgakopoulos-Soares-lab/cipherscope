# Evidence lanes

A lane is one exact combination of OS, Python, and OpenFHE build on which the
real-binding gate (`tests/integration_openfhe/run_gate.py`) was run. Only the
primary lane is authoritative for the paper's compatibility claim; the other
lanes are supporting evidence. Every row below is checked against its archived
`feasibility.json` by `tests/test_evidence.py`, so the table cannot drift from
the artifacts.

| Lane | Platform | Python | OpenFHE wrapper | Status | Pass / Skip / Total | Authoritative | Artifact |
|---|---|---|---|---|---|---|---|
| `developer` | macOS ARM64 (Darwin arm64) | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`) | `incomplete` | 37 / 1 / 38 | no | `artifact/feasibility/developer/feasibility.json` |
| `provisional-wheel-py312` | Ubuntu 24.04 x86_64 | 3.12.3 | PyPI wheel `1.5.1.0.24.4` | `provisional_pass` | 33 / 0 / 33 | no | `artifact/feasibility/provisional-wheel-py312/feasibility.json` |
| `primary-source-py311` | Ubuntu 24.04 x86_64 (LS6, gcc 15.1.0) | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`) | not archived | — | yes (when archived) | `artifact/feasibility/primary-source-py311/feasibility.json` (missing) |

## What each lane proves

**`developer`** — the local macOS build runs every real-binding check except
`RES-02`, which reads `/proc/self/status` and is Linux-only. That single skip is
why the status is `incomplete` rather than `pass`, and it is expected on macOS.
This lane also runs the seeded benchmark (`SEED-01`, 27 cases; see
`evaluation/seeded/README.md`). It is a developer convenience, not a
compatibility claim: the wheel is not the pinned Linux toolchain.

**`provisional-wheel-py312`** — the official PyPI wheel on the target OS passed
every check that existed when it was archived. It proves the API behavior
CipherScope relies on, but it is Python 3.12 and a wheel, not the Python 3.11
source build the paper pins. Note that the gate has since grown from 33 to 38
checks (`API-06`, `MUT-03`, `PROXY-05`, `ROT-03`, `SEED-01`); this artifact
predates them and does not cover them.

**`primary-source-py311`** — the pinned Python 3.11.15 / OpenFHE v1.5.1
source build on Linux x86_64. The gate has been run on LS6 with
`CIPHERSCOPE_OPENFHE_LANE=primary-source-py311`, but its `feasibility.json`
and build manifest have not been copied into this repository. Until
`artifact/feasibility/primary-source-py311/feasibility.json` exists here with
`status = "pass"` and `fail = skip = 0`, the compatibility claim is not backed
by checked-in evidence. Archive it with:

```bash
mkdir -p artifact/feasibility/primary-source-py311
cp "$WORK/cipherscope/primary-gate/feasibility.json" artifact/feasibility/primary-source-py311/
cp /opt/cipherscope-openfhe-build-manifest.json artifact/feasibility/primary-source-py311/build-manifest.json
```

and then add the row's counts above; `tests/test_evidence.py` will refuse a
row that disagrees with the file.

## Regenerating a lane

```bash
# developer (macOS conda env from OPENFHE_ENVIRONMENT.md)
CIPHERSCOPE_OPENFHE_LANE=developer CIPHERSCOPE_OPENFHE_BOOTSTRAP=1 \
CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51 \
CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e \
PYTHONPATH=src python -m tests.integration_openfhe.run_gate \
  --output artifact/feasibility/developer/feasibility.json
```

The primary and provisional lanes use the Docker recipes under
`artifact/docker/`; the primary recipe writes the build manifest that `ENV-04`
requires.

## Tying a run to a lane

Every run bundle's `manifest.json` records under `runtime`: `lane`,
`openfhe_distribution`, `openfhe_native_module_hashes` (SHA-256 of the loaded
wrapper's native modules), `cipherscope_version`, `cipherscope_commit`, and
`cipherscope_dirty`. Compare the hashes with the lane's `feasibility.json`
(`environment.native_module_hashes`) to prove which build produced a result.

## What no lane proves

Passing the gate shows that CipherScope observes OpenFHE calls correctly on that
build. It does not show that the chosen CKKS parameters are secure or that any
computation is numerically adequate; CipherScope makes neither claim.
