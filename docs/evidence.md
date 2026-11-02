# Evidence lanes

A lane is one exact combination of OS, Python, and OpenFHE build on which the
real-binding gate (`tests/integration_openfhe/run_gate.py`) was run. Only the
primary lane is authoritative for the paper's compatibility claim; the other
lanes are supporting evidence. Every row below is checked against its archived
`feasibility.json` by `tests/test_evidence.py`, so the table cannot drift from
the artifacts.

| Lane | Platform | Python | OpenFHE wrapper | Status | Pass / Skip / Total | Authoritative | Artifact |
|---|---|---|---|---|---|---|---|
| `developer` | macOS ARM64 (Darwin arm64) | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`) | `incomplete` | 41 / 1 / 42 | no | `artifact/feasibility/developer/feasibility.json` |
| `provisional-wheel-py312` | Ubuntu 24.04 x86_64 | 3.12.3 | PyPI wheel `1.5.1.0.24.4` | `provisional_pass` | 33 / 0 / 33 | no | `artifact/feasibility/provisional-wheel-py312/feasibility.json` |
| `ls6-native-py311` | Rocky Linux 8.10 x86_64, bare TACC LS6 host (AMD EPYC 7763), `gcc/15.2.0` + `cmake/3.31.5` modules | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`), GCC 15.2.0 | `native_pass` | 40 / 0 / 40 | no | `artifact/feasibility/ls6-native-py311/feasibility.json` |
| `cpp-gcc152-openfhe151` | Rocky Linux 8.10 x86_64, bare TACC LS6 host; GCC 15.2.0 plugin frontend against the native OpenFHE 1.5.1 C++ install | 3.11.15 (driver) | C++ API of the same native v1.5.1 build (`1306d14f`), instrumentation manifest `openfhe-1.5-v3` | `native_pass` | 21 / 0 / 21 | no | `artifact/feasibility/cpp-gcc152-openfhe151/feasibility.json` |
| `cpp-gcc133-openfhe151` | Ubuntu 24.04 x86_64 container (the primary lane's image, GCC 13.3.0 with `gcc-13-plugin-dev`) against its `/opt/openfhe` 1.5.1 install | 3.11.15 (driver) | same manifest, second compiler and distribution | `native_pass` | 21 / 0 / 21 | no | `artifact/feasibility/cpp-gcc133-openfhe151/feasibility.json` |
| `emulated-docker-py311` | Ubuntu 24.04 x86_64 container built and run **under x86_64 emulation** (Docker Desktop on an Apple M4 Pro, arm64 host); not physical x86_64 hardware | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`), Ubuntu gcc 13.3.0 | `emulated_pass` | 42 / 0 / 42 | no | `artifact/feasibility/emulated-docker-py311/feasibility.json` |
| `cpp-gcc133-openfhe151-emulated` | the same emulated Ubuntu 24.04 x86_64 image, GCC 13.3.0 plugin frontend against its `/opt/openfhe` 1.5.1 install; **emulated**, not physical x86_64 | 3.11.15 (driver) | C++ API of the same native v1.5.1 build (`1306d14f`), instrumentation manifest `openfhe-1.5-v3` | `emulated_pass` | 21 / 0 / 21 | no | `artifact/feasibility/cpp-gcc133-openfhe151-emulated/feasibility.json` |
| `primary-source-py311` | Ubuntu 24.04 x86_64 container (Apptainer 1.4.1 `--fakeroot` image built and run on TACC LS6; Rocky 8.10 host, AMD EPYC 7763) | 3.11.15 | source-built v1.5.1.0 (`4f13e2c3`) on native v1.5.1 (`1306d14f`), Ubuntu gcc 13.3.0 | `pass` | 40 / 0 / 40 | yes | `artifact/feasibility/primary-source-py311/feasibility.json` |

## What each lane proves

**`developer`** — the local macOS build runs every real-binding check except
`RES-02`, which reads `/proc/self/status` and is Linux-only. That single skip is
why the status is `incomplete` rather than `pass`, and it is expected on macOS.
This is currently the only lane carrying `API-09` and `ROT-04` (live scheme
identification for CKKS/BFV/BGV with no declared parameters, each scheme's own
depth coordinate, and fast-rotation equivalence under BV key switching), which
took the gate from 40 checks to 42 on 2026-11-01. The Linux lanes below were
archived at 40 and must be rerun before the paper quotes 42 anywhere outside
this row.
This lane also runs the seeded benchmark (`SEED-01`; 27 cases when archived,
28 since `bootstrap.positive.underused_deep` was added — see
`evaluation/seeded/README.md`). It is a developer convenience, not a
compatibility claim: the wheel is not the pinned Linux toolchain.

**`emulated-docker-py311`** — the same pinned Dockerfile, the same base-image
digest, the same Python tarball hash and the same two OpenFHE commits as the
primary lane, built with `docker buildx --platform linux/amd64` on an arm64
macOS host. It is the only lane that has run all 42 checks, so it is what
currently shows `API-09` and `ROT-04` passing somewhere other than macOS, and
the only place `RES-02` and the 61-case seeded benchmark have run together.

It is **not** a substitute for `primary-source-py311` and is never
authoritative. Two reasons, both checkable. The substrate is emulated rather
than the AMD EPYC hardware the primary lane names, so it is evidence that the
recipe and the code work on Linux x86_64, not that they work on the cluster.
And it is a genuinely different binary: its native module hashes to
`91b0253f…` where the primary lane's hashes to `a3a6e18a…`, so no run bundle
produced under one lane can be mistaken for the other. Treat it as a
pre-flight check that de-risks a cluster allocation, not as cluster evidence.

One practical caveat for anyone reproducing this lane: the Docker VM it was
built in has 7.7 GB of RAM, and the seeded bootstrap case peaks at 6.98 GB.
The 42-check gate passes because it runs that case with the memory to itself,
but `unittest discover` over the whole suite in the same container SIGKILLs it
(`unreadable bundle: ... trace.json`). That is the VM's limit, not a defect:
the identical suite passes with every real-binding test executing on the
developer lane (312 tests, 1 skip). Give the container 12 GB or more before
running the full suite inside it.

**`cpp-gcc133-openfhe151-emulated`** — the GCC plugin frontend inside that same
emulated image. The C++ gate derives its lane name from the toolchain, so this
run would otherwise have been called `cpp-gcc133-openfhe151` and overwritten
the LS6 artifact of the same name; the `--lane` override keeps them apart. It
is the only C++ evidence covering the per-scheme depth coordinate, through
`SCHEME-01` (BFV and BGV report their scheme, N packed slots and plaintext
modulus while CKKS keeps N/2 and none) and `PARITY-01` (the BFV and BGV C++
traces are semantically equivalent to the Python frontend's). Like the lane
above it is emulated and never authoritative; the GCC 15.2 and native GCC 13.3
cluster lanes remain the compiler evidence.

**`provisional-wheel-py312`** — the official PyPI wheel on the target OS passed
every check that existed when it was archived. It proves the API behavior
CipherScope relies on, but it is Python 3.12 and a wheel, not the Python 3.11
source build the paper pins. Note that the gate has since grown from 33 to 38
checks (`API-06`, `MUT-03`, `PROXY-05`, `ROT-03`, `SEED-01`); this artifact
predates them and does not cover them.

**`primary-source-py311`** — the pinned Python 3.11.15 / OpenFHE v1.5.1
source build on Ubuntu 24.04 x86_64: every one of the 40 checks passes
(`API-07`/`API-08` — vector composites, Chebyshev series, `EvalAtIndex`
aliases, BFV/BGV contexts — were added on 2026-09-18 and rerun on this lane),
including `RES-02` and the 27-case seeded benchmark, so this is the
authoritative artifact behind the compatibility claim. The image is
`artifact/apptainer/openfhe-py311-source.def`, a section-by-section
translation of `artifact/docker/openfhe-py311-source/Dockerfile` with the same
base-image digest, Python tarball hash, and OpenFHE commits; it was built
rootless on an LS6 compute node and the gate ran inside it (2 min 29 s,
`OMP_NUM_THREADS=1`). `build-manifest.json` beside the artifact records the
Ubuntu toolchain and the native-module hash, which equals the hash the gate
observed. A Docker build of the same Dockerfile produces the same lane; only
the build host differs. The image also carries `gcc-13-plugin-dev` so the C++
frontend gate can run inside it (the OpenFHE build itself is unchanged).

**`ls6-native-py311`** — the same Python 3.11.15 and OpenFHE commits built
directly on the Rocky Linux 8.10 host with the TACC `gcc/15.2.0` module by
`build_openfhe_ls6.sh` (no container). All 40 checks pass, so the gate holds
on a second distribution and a second compiler (GCC 15.2 rather than Ubuntu's
13.3); `ENV-01` records the distribution for this lane instead of asserting
Ubuntu, which is why its status is `native_pass` and it is never
authoritative. Its `build-manifest.json` also records the host, CPU, SLURM
partition, loaded modules, and `OMP_NUM_THREADS`. This is the lane used for
cluster-scale corpus and overhead runs, where a container is unnecessary
overhead; every bundle it produces carries its native-module hash
(`429513c3…`), distinct from the primary lane's (`a3a6e18a…`).

**`cpp-gcc152-openfhe151`, `cpp-gcc133-openfhe151`** — the C++ frontend's gate
(`tests/integration_cpp/run_gate.py`). It builds the plain fixture project
under `tests/cpp/fixtures` with GCC 15.2.0 and the native OpenFHE 1.5.1
install, profiles each fixture with `cipherscope profile <binary>` exactly as a
user would, and checks the properties [docs/cpp_frontend.md](cpp_frontend.md)
claims: transparent shadow builds with an untouched source tree and original
binary (BUILD-01..04), exactly-once interception with semantic arguments
(OP-01), operator and in-place normalization (OP-02, MUT-01), identity across
copies/moves/containers and no ID reuse after destruction (ID-01), exact
source attribution at -O0/-O2/-O3 (SRC-01/02), exceptions preserved and
recorded (EXC-01), OpenMP threads (THR-01), byte-identical program output
between plain and instrumented binaries (NUM-01), unmatched calls denying
COMPLETE (COV-01), hard limits (LIMIT-01), canonical validation and the
unchanged pipeline (TRACE-01, PIPE-01), vector composites, Chebyshev series
and the `EvalAtIndex` aliases (OP-03), BFV/BGV schemes from the declared
parameters (SCHEME-01), opt-in annotations and precision checkpoints through
`cipherscope/annotate.h` (META-01), and semantic parity with the Python
frontend's traces of the eight twin programs (PARITY-01). All 21 checks also
pass inside the Ubuntu 24.04 image with GCC 13.3.0 (`cpp-gcc133-openfhe151`,
re-run 2026-11-01 on manifest `openfhe-1.5-v3`): the plugin is built on demand
by whichever GCC built the target. It is a
frontend gate, not a compatibility claim about OpenFHE itself, so it is never
authoritative.

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

The C++ frontend gate needs GCC with plugin headers, CMake, and an OpenFHE
install (the native lane's is used on LS6):

```bash
source ls6_env.sh
PYTHONPATH=src:. python3.11 -m tests.integration_cpp.run_gate \
  --openfhe-dir "$BUILD_ROOT/opt/openfhe/lib/OpenFHE" \
  --output artifact/feasibility/cpp-gcc152-openfhe151/feasibility.json
# inside the primary image (GCC 13.3):
run_in_primary sh -c 'cd /workspace/cipherscope && PYTHONPATH=src:. python3.11 -m tests.integration_cpp.run_gate --openfhe-dir /opt/openfhe/lib/OpenFHE'
```

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
