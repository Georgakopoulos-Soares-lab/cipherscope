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
| `ls6-native-py311` | Rocky Linux 8.10 x86_64, bare TACC LS6 host (AMD EPYC 7763), `gcc/15.2.0` + `cmake/3.31.5` modules | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`), GCC 15.2.0 | `native_pass` | 38 / 0 / 38 | no | `artifact/feasibility/ls6-native-py311/feasibility.json` |
| `primary-source-py311` | Ubuntu 24.04 x86_64 container (Apptainer 1.4.1 `--fakeroot` image built and run on TACC LS6; Rocky 8.10 host, AMD EPYC 7763) | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`), Ubuntu gcc 13.3.0 | `pass` | 38 / 0 / 38 | yes | `artifact/feasibility/primary-source-py311/feasibility.json` |

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
source build on Ubuntu 24.04 x86_64: every one of the 38 checks passes,
including `RES-02` and the 27-case seeded benchmark, so this is the
authoritative artifact behind the compatibility claim. The image is
`artifact/apptainer/openfhe-py311-source.def`, a section-by-section
translation of `artifact/docker/openfhe-py311-source/Dockerfile` with the same
base-image digest, Python tarball hash, and OpenFHE commits; it was built
rootless on an LS6 compute node and the gate ran inside it (2 min 29 s,
`OMP_NUM_THREADS=1`). `build-manifest.json` beside the artifact records the
Ubuntu toolchain and the native-module hash, which equals the hash the gate
observed. A Docker build of the same Dockerfile produces the same lane; only
the build host differs.

**`ls6-native-py311`** — the same Python 3.11.15 and OpenFHE commits built
directly on the Rocky Linux 8.10 host with the TACC `gcc/15.2.0` module by
`build_openfhe_ls6.sh` (no container). All 38 checks pass, so the gate holds
on a second distribution and a second compiler (GCC 15.2 rather than Ubuntu's
13.3); `ENV-01` records the distribution for this lane instead of asserting
Ubuntu, which is why its status is `native_pass` and it is never
authoritative. Its `build-manifest.json` also records the host, CPU, SLURM
partition, loaded modules, and `OMP_NUM_THREADS`. This is the lane used for
cluster-scale corpus and overhead runs, where a container is unnecessary
overhead; every bundle it produces carries its native-module hash
(`429513c3…`), distinct from the primary lane's (`a3a6e18a…`).

## Regenerating a lane

```bash
# developer (macOS conda env from OPENFHE_ENVIRONMENT.md)
CIPHERSCOPE_OPENFHE_LANE=developer CIPHERSCOPE_OPENFHE_BOOTSTRAP=1 \
CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51 \
CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e \
PYTHONPATH=src python -m tests.integration_openfhe.run_gate \
  --output artifact/feasibility/developer/feasibility.json
```

The provisional lane uses the Docker recipe under `artifact/docker/`. The
primary lane can be built either with that Docker recipe or, without Docker or
root, with Apptainer (this is how the archived artifact was produced; the
`ls6_env.sh` helper sets `APPTAINER_TMPDIR` to node-local storage, which a
rootless build needs):

```bash
source ls6_env.sh                                   # TACC LS6; sets BUILD_ROOT, PRIMARY_SIF, run_in_primary
apptainer build --fakeroot --build-arg MAKE_JOBS=16 \
  "$PRIMARY_SIF" artifact/apptainer/openfhe-py311-source.def
run_in_primary python3.11 -m tests.integration_openfhe.run_gate \
  --output artifact/feasibility/primary-source-py311/feasibility.json
apptainer exec "$PRIMARY_SIF" cat /opt/cipherscope-openfhe-build-manifest.json \
  > artifact/feasibility/primary-source-py311/build-manifest.json
```

`run_in_primary` runs the container with `--cleanenv --no-home --containall`
so nothing from the host (module paths, `PYTHONPATH`, user site-packages) can
reach the gate; the image's own environment declares the lane.

The native lane is one script on an allocated LS6 compute node (about ten
minutes at `MAKE_JOBS=16`; it skips the parts that already exist):

```bash
bash build_openfhe_ls6.sh                           # builds, then runs the gate as ls6-native-py311
mkdir -p artifact/feasibility/ls6-native-py311
cp "$WORK/cipherscope-openfhe-build/feasibility-ls6-native-py311.json" \
   artifact/feasibility/ls6-native-py311/feasibility.json
cp "$WORK/cipherscope-openfhe-build/cipherscope-openfhe-build-manifest.json" \
   artifact/feasibility/ls6-native-py311/build-manifest.json
```

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
