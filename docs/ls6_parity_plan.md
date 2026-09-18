# LS6 parity plan: reproduce every macOS ARM64 (M4) item on x86_64 Linux

Written 2026-09-13 from an interactive session on LS6 compute node `v320-008`
(partition `vm-small`, SLURM job 3436198). Everything below runs **directly in
the allocated shell** — no `sbatch`, `srun`, or `idev`. Long steps are started
with `nohup … &` and a log file so a dropped SSH session does not kill them.

The goal is that every piece of real-OpenFHE evidence currently produced only
on the macOS ARM64 developer build (the "M4 items") has an x86_64 Linux
counterpart produced on LS6, that the two agree where they must agree, and
that the repository no longer contains anything that only works on one
platform.

---

## 0. Ground truth verified in this session

| Fact | Value | Consequence |
|---|---|---|
| Host OS / kernel | Rocky Linux 8.10, `4.18.0-553.150.1.el8_10.x86_64` | `ENV-01` (asserts Ubuntu 24.04 for the primary lane) **cannot pass on the bare host** |
| CPU / RAM | 16 × AMD EPYC 7763 (KVM VM), 31 GB, no swap | `MAKE_JOBS=16`; the 10⁵-event scaling point (3.2 GB peak) fits |
| Node-local `/tmp` | 286 GB free, wiped at job end | stage container builds here; copy results to `$WORK`/`$SCRATCH` |
| Allocation left | 11 h 19 m at 15:20 | whole plan fits with margin (≈ 4 h of compute) |
| Default env | `OMP_NUM_THREADS=1`, `intel/19.1.1`, `python3/3.9.7` (below the 3.11 floor) | always `module purge`; pin threads explicitly and record them |
| Modules | `gcc/15.2.0` (**`gcc/15.1.0` is gone**), `cmake/3.31.5`, `cmake/4.1.1`, `tacc-apptainer/1.4.1`, `python/3.12.11` | build script and every launcher reference a module that no longer exists |
| `gcc/15.2.0` layout | `/opt/apps/gcc/15.2.0/{bin,lib64}`; provides `c++` but **not** `cc` (`/usr/bin/cc` is GCC 8.5) | keep the explicit `-DCMAKE_C_COMPILER/-DCMAKE_CXX_COMPILER`; replace hard-coded `/home1/apps/gcc/15.1.0/lib64` with `$TACC_GCC_LIB64` |
| Network egress | `python.org`, `github.com`, `pypi.org`, `files.pythonhosted.org` all reachable | source builds and `apt-get` inside a container work from the compute node |
| System `-devel` headers | openssl, libffi, bzip2, xz, zlib, sqlite, readline, ncurses, libuuid, expat present; `gdbm`, `tk` absent | a `--enable-shared` CPython 3.11.15 with `_ssl` (pip needs it) builds natively; only `_gdbm`/`_tkinter` are missing, which nothing uses |
| Pinned CMake minimums | `openfhe-development@1306d14f` and `openfhe-python@4f13e2c3` both require ≥ 3.16.3 | `cmake/3.31.5` or `4.1.1` both work; prefer 3.31.5 (closest to Ubuntu's 3.28.3) |
| Prior LS6 build | none (`$WORK/cipherscope-openfhe-build` does not exist); the only `openfhe` on disk is a broken 1.4.2 wheel in conda env `specdec` (cpython-310 `.so` in a 3.11 env) | build from scratch; never let `specdec` onto `PATH`/`PYTHONPATH` |
| Apptainer | pulls the pinned `ubuntu@sha256:4fbb8e6a…` digest; user namespaces enabled (`max_user_namespaces=10000`), **no** `subuid` entry; `--fakeroot` root-emulation works | **`apptainer build --fakeroot` of the exact Dockerfile recipe succeeds on LS6** once (a) `APT::Sandbox::User "root"` is set and (b) `APPTAINER_TMPDIR` is on `/tmp` — verified with a probe image that installed `build-essential cmake git libssl-dev pybind11-dev` (cmake 3.28.3, g++ 13.3.0) |
| BeeGFS `/scratch` | no xattr support; `rename()` inside a rootless build rootfs returns `EBUSY` | never stage a container build on `/scratch` or `/work`; the `.sif` itself can live there |
| Fake-backend suite on this node (Python 3.13) | 261 tests, 38 skipped, **1 error** (`tests/test_artifact.py` looks for `ARTIFACT.md` at the root; it moved to `docs/ARTIFACT.md` in `9dc2b61`) | platform-independent bug; fix in Phase 1 |

## 1. The M4 items and their LS6 counterparts

| # | Item | macOS ARM64 state today | LS6 x86_64 target | Owner phase |
|---|---|---|---|---|
| 1 | Real-binding gate | `developer` lane, 37 / 1 / 38 (`RES-02` skipped, Linux-only) | `primary-source-py311`: **38 / 0 / 38, `status = "pass"`**, archived under `artifact/feasibility/primary-source-py311/` with the build manifest | 3 |
| 2 | Same gate, native toolchain | — | new supporting lane `ls6-native-py311` (Rocky 8.10, `gcc/15.2.0`): 38 / 0 / 38 | 4 |
| 3 | Seeded benchmark (`SEED-01`, 27 cases) | `evaluation/raw/seeded/case_results.json`, no platform provenance | rerun on both LS6 lanes; per-case outcomes identical to macOS; record lane/machine in the JSON | 5, 6 |
| 4 | Semantic ablation | `evaluation/raw/semantic_ablation.csv` (macOS bundles) | rerun; per-(bundle, mode, rule) rows identical | 5, 6 |
| 5 | Scaling sweep 10²–10⁵ | `evaluation/raw/scaling.csv`, every row `machine = arm64` | add `x86_64` rows from the primary lane; tables report per machine, never mixed | 5, 6 |
| 6 | Paper tables + `MANIFEST.json` | generated on macOS; manifest contains `/Users/kap4722/...` | regenerate on LS6; manifest byte-identical to a macOS regeneration after the path fix | 1, 5, 6 |
| 7 | Example gallery (16 programs: `profiled_workload`, 3 `profile_unmodified` targets, 12 synthetic) | verified only on macOS (`examples/README.md`) | all 16 run, validate, classify `COMPLETE`; rule firing identical to macOS | 5, 6 |
| 8 | `make test / artifact-smoke / reproduce-small / gate / verify-checksums` | green on macOS | green on LS6 in both lanes | 1, 5 |
| 9 | PRS harnesses (`benchmark_prs_overhead.py`, `memory_profile_prs.py`) and `run_*.slurm` | written for Vista `gh-dev` (never LS6); hard-coded gcc 15.1.0 paths | run directly on this node; launchers repointed to LS6 partitions for later batch use | 1, 5 |
| 10 | External suite (`python-log-reg-examples`: `sol_lin_reg`, `sol_log_reg`, `sol_nag_log_reg`, `sol_encrypted_inference`) | permissive runs planned, never archived | pinned clone in `$WORK`; strict-mode attempt first, permissive only to inventory unsupported calls; `coverage_report.csv` | 5 |
| 11 | Environment documentation | `OPENFHE_ENVIRONMENT.md` (macOS conda), `/opt/miniconda3` paths in README/examples | Linux section: container lane and native lane, one env script | 7 |

Mapping to the conference-readiness action plan: A-01 (docs ↔ evidence), **A-02
(primary gate archived)**, B-02 (strict LS6 corpus re-runs), C-02 (matched
runs), D-02 (seeded recall), E-01 (overhead), E-02 (scaling), E-03 (ablation).

## 2. Drift and bugs that block parity (fix first)

Each item names the file, the symptom on LS6, and the exact change.

| ID | Where | Problem | Fix |
|---|---|---|---|
| B1 | `tests/test_artifact.py:11`, `README.md:168` | `ARTIFACT = ROOT / "ARTIFACT.md"` but the file is `docs/ARTIFACT.md`; suite errors | `ARTIFACT = ROOT / "docs" / "ARTIFACT.md"`; README link → `docs/ARTIFACT.md`; inside `docs/ARTIFACT.md` change `docs/evidence.md` links to `evidence.md` (they are relative to `docs/`) |
| B2 | `tests/integration_openfhe/test_environment.py:22-26` | `ENV-01` requires `os_release.ID == "ubuntu"`, `VERSION_ID == "24.04"` for the primary lane; LS6 host is Rocky | **Do not relax it.** Run the primary lane inside the Ubuntu 24.04 container (Phase 2–3). Add the `ls6-native-py311` branch: assert `Linux`/`x86_64`, record `os_release` (`ID = rocky`, `VERSION_ID = 8.10`) without asserting a distribution |
| B3 | `build_openfhe_ls6.sh:60` (`GCC_MODULE=gcc/15.1.0`), `docs/evidence.md` primary row ("gcc 15.1.0"), every `run_*.slurm` (`module load gcc/15.1.0`, `/home1/apps/gcc/15.1.0/lib64`) | module does not exist on LS6 → `module load` fails before anything builds | default `GCC_MODULE=gcc/15.2.0`; derive the runtime library path from `$TACC_GCC_LIB64`; add `module load cmake/3.31.5` |
| B4 | `build_openfhe_ls6.sh:222-231` | exports `CIPHERSCOPE_OPENFHE_LANE=primary-source-py311` on a Rocky host → the gate it runs can only end in `fail` (`ENV-01`); the manifest even says "Rocky Linux, no container" | lane → `ls6-native-py311`; output → `$BUILD_ROOT/feasibility-ls6-native.json`; record `OMP_NUM_THREADS`, `SLURM_JOB_ID`, hostname, CPU model, and the loaded module list in the manifest |
| B5 | `run_build.slurm`, `run_profile.slurm`, `run_analysis.slurm`, `run_memory.slurm`, `run_external_suite.slurm`, `run_sol_*.slurm` | `#SBATCH -p gh-dev` is a Vista (Grace Hopper, aarch64) queue; none of these can be submitted on LS6 | source one `ls6_env.sh` (Phase 0) instead of repeating module/PATH lines; `-p vm-small` (or `normal`) for later batch use; not needed for this session |
| B6 | `src/cipherscope/tables.py:485` | `skipped_inputs` stores `str(root / relative)` → absolute, machine-specific paths in `evaluation/tables/MANIFEST.json`; "byte-for-byte reproducible" is false across machines | store `str(relative)`; regenerate `evaluation/tables/`; extend `tests/test_tables.py::test_generate_is_byte_for_byte_reproducible` to assert no `skipped_inputs` value is absolute |
| B7 | `src/cipherscope/tables.py:423-447` (`scaling_rows`) | groups by `(size, arm)` only; appending x86_64 rows to the arm64 `scaling.csv` would silently pool two machines into one median | group by `(machine, size, arm)`; add `machine` to `SCALING_COLUMNS`, `evaluation/schema/results.schema.json`, `tests/test_tables.py`, and `evaluation/README.md` |
| B8 | `src/cipherscope/seeded.py:549-553` | `case_results.json` has no lane/platform provenance; a macOS and an LS6 result are indistinguishable | add `"environment": {**fingerprint.build_fingerprint(), "platform", "machine", "python"}` at the top level (`results_from_json` only reads `cases`, so tables are unaffected) |
| B9 | `docs/evidence.md` | primary row says "Ubuntu 24.04 x86_64 (LS6, gcc 15.1.0)" — LS6 is not Ubuntu, and 15.1.0 is gone | after Phase 3: "Ubuntu 24.04 container (Apptainer 1.4.1 `--fakeroot` on LS6, Rocky 8.10 host), x86_64, Ubuntu gcc 13.3.0"; add the `ls6-native-py311` row. `tests/test_evidence.py` will refuse a row that disagrees with the JSON, so edit the row only from the archived file |
| B10 | `README.md` (Quick start, "For the real macOS ARM64 OpenFHE example…"), `examples/README.md` (`conda activate cipherscope-openfhe`, `/opt/miniconda3`) | Linux users have no activation path | add a "Linux / LS6" subsection pointing at `ls6_env.sh` and the container command (Phase 7) |
| B11 | `Makefile` `checksums` | `shasum -a 256` — present on Rocky (`/usr/bin/shasum`) and macOS; keep, but document `sha256sum -c` as the equivalent | docs only |
| B12 | `tests/integration_openfhe/run_gate.py:196-205` | status mapping knows `primary`, `provisional`, else `developer_pass` | add `ls6-native-py311 → "native_pass"`; `authoritative_for_primary_target` stays `False` for it |

## 3. Lane design decision (this is what makes it cross-platform)

Three lanes run the **same** gate, the **same** pins, and the **same**
evaluation scripts on three OS/architecture combinations:

| Lane | Platform | Toolchain | Role |
|---|---|---|---|
| `developer` | macOS ARM64 (M4) | conda source build | developer convenience; 37/38 (RES-02 is Linux-only) |
| `primary-source-py311` | **Ubuntu 24.04 x86_64 container**, built on LS6 with Apptainer from a `.def` that is a line-for-line copy of `artifact/docker/openfhe-py311-source/Dockerfile` | Ubuntu gcc 13.3.0, cmake 3.28.3, CPython 3.11.15 `--enable-shared` | **authoritative**; the artifact reviewers can rebuild with Docker or Apptainer on any x86_64 Linux |
| `ls6-native-py311` (new) | Rocky 8.10 x86_64, bare host | `gcc/15.2.0`, `cmake/3.31.5`, CPython 3.11.15 built by `build_openfhe_ls6.sh` | supporting; the lane for large corpus/overhead runs where container I/O and a second toolchain are unwanted; proves the gate is not tied to one distribution |

Rationale: the honest fix for B2 is not to weaken `ENV-01` but to run the
lane it describes. Because the container recipe is identical to the Docker
recipe, a pass on LS6 is a pass of the paper's pinned environment, and the
same `.sif` can be copied to any other x86_64 Linux machine. The native lane
is what makes the "cross-platform" claim more than "one Docker image": three
toolchains (Apple clang/conda, Ubuntu gcc 13, TACC gcc 15) must agree.

Every run bundle already records `runtime.lane` and the native-module hashes,
so results from the two LS6 lanes can never be confused.

## 4. Phases

### Phase 0 — Session setup (5 min)

Create `ls6_env.sh` at the repository root (sourced by every later step and by
the repointed launchers):

```bash
# ls6_env.sh — source me. Native-lane runtime + container tooling on LS6.
module purge
module load TACC gcc/15.2.0 cmake/3.31.5 tacc-apptainer/1.4.1
export BUILD_ROOT="$WORK/cipherscope-openfhe-build"
export PATH="$BUILD_ROOT/opt/python311/bin:$PATH"
export LD_LIBRARY_PATH="$TACC_GCC_LIB64:$BUILD_ROOT/opt/python311/lib:$BUILD_ROOT/opt/openfhe/lib:$BUILD_ROOT/opt/openfhe/lib64:${LD_LIBRARY_PATH:-}"
export PYTHONPATH="$PWD/src"
export PYTHONNOUSERSITE=1
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"      # parity with the single-threaded macOS build; record it
export MAKE_JOBS="${SLURM_CPUS_ON_NODE:-16}"
export APPTAINER_CACHEDIR="$SCRATCH/apptainer_cache"
export APPTAINER_TMPDIR="/tmp/$USER/apptainer-tmp"    # node-local: BeeGFS breaks rootless builds
mkdir -p "$APPTAINER_TMPDIR" "$SCRATCH/cipherscope-ls6/logs"
export CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
export CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51
```

Working directories: sources and installs in `$WORK/cipherscope-openfhe-build`
(Lustre, persistent); the `.sif` in `$WORK/cipherscope-openfhe-build/`; run
bundles and logs in `$SCRATCH/cipherscope-ls6/`. Background pattern for
anything longer than a few minutes:

```bash
nohup bash -c '…' > "$SCRATCH/cipherscope-ls6/logs/<step>.log" 2>&1 &
```

Done when: `source ls6_env.sh && g++ --version | head -1` prints GCC 15.2.0
and `apptainer --version` prints 1.4.1.

### Phase 1 — Repository fixes (30 min, no OpenFHE needed)

Apply B1, B3, B4, B6, B7, B8, B12 (B5/B9/B10 wait for the evidence they
describe). Then:

```bash
PYTHON=$WORK/miniconda3/bin/python3.13 make test     # expect OK, skipped=38, 0 errors
git checkout -b ls6-parity && git commit -am "Fix cross-platform drift found on LS6"
```

Done when: the fake-backend suite is green on x86_64 Linux and
`evaluation/tables/MANIFEST.json` no longer contains an absolute path.

### Phase 2 — Build the authoritative container on LS6 (≈ 40–60 min wall, background)

Add `artifact/apptainer/openfhe-py311-source.def`. It is the Dockerfile
translated section by section; the pins are the same bytes as
`golden_core.json`. The only additions are the two rootless requirements
verified in this session.

```
Bootstrap: docker
From: ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

%files
    artifact/docker/openfhe-py311-source/write_build_manifest.py /tmp/write_build_manifest.py

%environment
    export PATH=/opt/python311/bin:$PATH
    export LD_LIBRARY_PATH=/opt/python311/lib:/opt/openfhe/lib:/opt/openfhe/lib64
    export PYTHONPATH=/workspace/cipherscope/src
    export PYTHONNOUSERSITE=1
    export CIPHERSCOPE_OPENFHE_LANE=primary-source-py311
    export CIPHERSCOPE_OPENFHE_BOOTSTRAP=1
    export CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
    export CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51
    export CIPHERSCOPE_OPENFHE_BUILD_MANIFEST=/opt/cipherscope-openfhe-build-manifest.json

%post
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    MAKE_JOBS=${MAKE_JOBS:-16}
    PYTHON_VERSION=3.11.15
    PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625
    OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
    OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51

    # Rootless build (user namespace without subuid): apt must not drop to _apt.
    echo 'APT::Sandbox::User "root";' > /etc/apt/apt.conf.d/99-rootless-sandbox
    apt-get update
    apt-get install --yes --no-install-recommends \
        build-essential ca-certificates cmake curl git libbz2-dev libffi-dev \
        libgdbm-dev liblzma-dev libncursesw5-dev libreadline-dev libsqlite3-dev \
        libssl-dev libuuid1 libxml2-dev libzstd-dev pybind11-dev tk-dev uuid-dev \
        xz-utils zlib1g-dev
    rm -rf /var/lib/apt/lists/*

    mkdir -p /tmp/python-build && cd /tmp/python-build
    curl --fail --location --silent --show-error --output Python.tar.xz \
        "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz"
    echo "${PYTHON_SHA256}  Python.tar.xz" | sha256sum --check --strict
    tar --extract --file Python.tar.xz --xz --strip-components=1
    ./configure --prefix=/opt/python311 --enable-shared --with-ensurepip=install
    make --jobs "${MAKE_JOBS}" && make install
    export PATH=/opt/python311/bin:$PATH LD_LIBRARY_PATH=/opt/python311/lib

    git init /tmp/openfhe-development
    git -C /tmp/openfhe-development remote add origin https://github.com/openfheorg/openfhe-development.git
    git -C /tmp/openfhe-development fetch --depth 1 origin "${OPENFHE_NATIVE_COMMIT}"
    git -C /tmp/openfhe-development checkout --detach FETCH_HEAD
    test "$(git -C /tmp/openfhe-development rev-parse HEAD)" = "${OPENFHE_NATIVE_COMMIT}"
    cmake -S /tmp/openfhe-development -B /tmp/openfhe-development/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/openfhe \
        -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
    cmake --build /tmp/openfhe-development/build --parallel "${MAKE_JOBS}"
    cmake --install /tmp/openfhe-development/build
    export LD_LIBRARY_PATH=/opt/python311/lib:/opt/openfhe/lib:/opt/openfhe/lib64

    git init /tmp/openfhe-python
    git -C /tmp/openfhe-python remote add origin https://github.com/openfheorg/openfhe-python.git
    git -C /tmp/openfhe-python fetch --depth 1 origin "${OPENFHE_WRAPPER_COMMIT}"
    git -C /tmp/openfhe-python checkout --detach FETCH_HEAD
    test "$(git -C /tmp/openfhe-python rev-parse HEAD)" = "${OPENFHE_WRAPPER_COMMIT}"
    cmake -S /tmp/openfhe-python -B /tmp/openfhe-python/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/openfhe \
        -DCMAKE_INSTALL_PREFIX=/opt/python311/lib/python3.11/site-packages/openfhe \
        -DOPENFHE_REQUIRED_VERSION=1.5.1 \
        -DPython_EXECUTABLE=/opt/python311/bin/python3.11 \
        -DPython_ROOT_DIR=/opt/python311 \
        -DPYTHON_EXECUTABLE_PATH=/opt/python311/bin/python3.11
    cmake --build /tmp/openfhe-python/build --parallel "${MAKE_JOBS}"
    cmake --install /tmp/openfhe-python/build
    python3.11 -c 'import openfhe; assert openfhe.get_native_int() in (64, 128)'

    python3.11 /tmp/write_build_manifest.py
    rm -rf /tmp/python-build /tmp/openfhe-development /tmp/openfhe-python

%test
    . /etc/os-release && test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
    python3.11 -c 'import openfhe, platform; print(platform.python_version(), openfhe.get_native_int())'
```

Build it (from the repository root so `%files` resolves; ≈ 40–60 min at
`-j16`; the probe showed the apt stage alone takes ≈ 4 min):

```bash
source ls6_env.sh
nohup apptainer build --fakeroot --build-arg MAKE_JOBS=$MAKE_JOBS \
    "$BUILD_ROOT/openfhe-py311-source.sif" artifact/apptainer/openfhe-py311-source.def \
    > "$SCRATCH/cipherscope-ls6/logs/apptainer-build.log" 2>&1 &
```

If `--build-arg` is not honoured by this Apptainer, leave `MAKE_JOBS` at its
in-file default of 16. Verify:

```bash
apptainer exec "$BUILD_ROOT/openfhe-py311-source.sif" sh -c \
  'head -2 /etc/os-release; python3.11 -c "import openfhe; print(openfhe.get_native_int())"; \
   python3.11 -c "import json; m=json.load(open(\"/opt/cipherscope-openfhe-build-manifest.json\")); print(m[\"toolchain\"][\"cxx\"], m[\"openfhe_python\"][\"native_module_hashes\"])"'
sha256sum "$BUILD_ROOT/openfhe-py311-source.sif" > "$BUILD_ROOT/openfhe-py311-source.sif.sha256"
```

Done when: the manifest names Ubuntu's `c++ 13.3.0`, `native_int` is 64, and
the `.sif` hash is recorded.

Fallback if the rootless build ever fails for a reason other than the two
known ones: build the *Docker* image on the Mac with
`docker build --platform linux/amd64 -f artifact/docker/openfhe-py311-source/Dockerfile .`,
push it to a registry, and `apptainer pull` it here. The gate result is the
same lane either way; only the build host differs, and the manifest says
which.

### Phase 3 — Run and archive the primary gate (10 min)

```bash
source ls6_env.sh
apptainer exec --cleanenv --no-home --containall \
    --bind "$PWD:/workspace/cipherscope" --pwd /workspace/cipherscope \
    --env OMP_NUM_THREADS=1 \
    "$BUILD_ROOT/openfhe-py311-source.sif" \
    python3.11 -m tests.integration_openfhe.run_gate \
        --output artifact/feasibility/primary-source-py311/feasibility.json
apptainer exec "$BUILD_ROOT/openfhe-py311-source.sif" \
    cat /opt/cipherscope-openfhe-build-manifest.json \
    > artifact/feasibility/primary-source-py311/build-manifest.json
```

`--cleanenv --no-home --containall` keep the host's `LD_LIBRARY_PATH`
(gcc module), `PYTHONPATH`, and `~/.local` out of the container; the
`%environment` block supplies everything the gate needs. The repository is
bind-mounted read-write so `run_gate.py` can write the artifact with its 0700
directory and the fingerprint can run `git` on it.

Expected: `{"status": "pass", "summary": {"pass": 38, "fail": 0, "skip": 0, "total": 38}}`.
`RES-02` passes here because `/proc/self/status` exists — this is the one
check the M4 lane can never run, so LS6 is strictly a superset.

Then:

1. `docs/evidence.md`: replace the primary row with the counts from the file
   (`38 / 0 / 38`, `pass`, `yes`), platform text per B9, and delete the
   "not archived" paragraph plus the `cp … /opt/…` instructions (they
   describe the Docker path; replace with the Apptainer command above).
2. `PYTHONPATH=src python3.13 -m unittest tests.test_evidence` must pass —
   it cross-checks every cell against the JSON.
3. Commit `artifact/feasibility/primary-source-py311/*`, `docs/evidence.md`,
   the `.def` file, and the `.sif` checksum (not the `.sif`).

### Phase 4 — Build the native Rocky lane (≈ 40–60 min wall, background; start after Phase 2 finishes so the two builds do not contend for 16 cores)

`build_openfhe_ls6.sh` after B3/B4:

```bash
source ls6_env.sh          # gcc/15.2.0, cmake/3.31.5 loaded; MAKE_JOBS=16
export CIPHERSCOPE_OPENFHE_LANE=ls6-native-py311
nohup bash build_openfhe_ls6.sh > "$SCRATCH/cipherscope-ls6/logs/native-build.log" 2>&1 &
```

Things to watch in the log, with the pre-decided response:

- CPython `configure` summary: `_ssl`, `_sqlite3`, `_lzma`, `_bz2`, `_uuid`
  must build (headers verified present); `_gdbm`/`_tkinter` missing is
  expected. If `pip install pybind11` fails with an SSL error, `_ssl` did not
  build — stop and inspect `config.log`; do not fall back to the conda Python.
- OpenFHE with GCC 15: new warnings are possible. If a `-Werror` stop occurs,
  add `-DCMAKE_CXX_FLAGS="-Wno-error"` **and record the flag in the build
  manifest** (`toolchain.extra_cxx_flags`), never silently.
- The gate at the end of the script now runs as `ls6-native-py311` and must
  report `native_pass`, 38 / 0 / 38. Archive to
  `artifact/feasibility/ls6-native-py311/{feasibility.json,build-manifest.json}`
  and add its row to `docs/evidence.md` (`Authoritative = no`).

### Phase 5 — Reproduce every M4 item on LS6 (≈ 60 min per lane; run in the primary lane first, then the native lane)

Define once, for the container lane:

```bash
run_in_primary() { apptainer exec --cleanenv --no-home --containall \
    --bind "$PWD:/workspace/cipherscope" --bind "$SCRATCH/cipherscope-ls6:/results" \
    --pwd /workspace/cipherscope --env OMP_NUM_THREADS=1 \
    "$BUILD_ROOT/openfhe-py311-source.sif" "$@"; }
```

and for the native lane simply `source ls6_env.sh` with
`CIPHERSCOPE_OPENFHE_LANE=ls6-native-py311` exported. Each item, with the
macOS number it must reproduce:

| Step | Command (primary lane shown; native lane is the same command without the wrapper) | Expected on LS6 | M4 reference |
|---|---|---|---|
| 5.1 Makefile smoke | `run_in_primary make artifact-smoke PYTHON=python3.11` | validate `{"valid": true}`, coverage `COMPLETE: 1` | same |
| 5.2 Seeded + ablation + tables | `run_in_primary make reproduce-small PYTHON=python3.11` | `all_matched: true`, 27 cases, 13 positives detected, 0 FP on 18 negatives; tables regenerated | `evaluation/raw/seeded/case_results.json`, `recall.csv` |
| 5.3 Checksums | `make verify-checksums` before 5.2 (archived macOS files) and `make checksums` after (LS6 files become canonical for the primary lane) | every line `: OK` | — |
| 5.4 Example gallery | loop over `examples/profiled_workload.py --rotation 1 --rotation 2`, `profile_unmodified.py -- examples/{chebysev,dot_product,bootstrapping}.py`, the 7 bare synthetic programs via `profile_unmodified.py`, the 4 wrappable instrumented programs directly, and `precision_checkpoints.py` directly; each into `/results/examples/<name>`; then `cipherscope validate`, `coverage --output /results/examples/coverage_report.csv` | 16 validated bundles; all `COMPLETE`; `repeated_rotations` fires `rotation.hoist_same_input.v1` and lists key 5 unused; `bootstrap_then_idle` reports `clean` for the bootstrap rule (documented limitation) | `examples/README.md` |
| 5.5 Scaling sweep | `run_in_primary python3.11 evaluation/scaling/run_scaling.py --output /results/scaling.x86_64.csv` (10²–10⁵; buffered arm capped at 10⁴ by default) | rows with `machine = x86_64`; peak RSS at 10⁵ ≈ 3–4 GB; no superlinear jump | `evaluation/raw/scaling.csv` (arm64: 2.2 KB/event, ~44 s analysis at 10⁵) |
| 5.6 PRS harnesses | `python3.11 benchmark_prs_overhead.py --repeats 10 --warmup 2 --output /results/prs-bench` and `python3.11 memory_profile_prs.py --output /results/prs-memory` (native lane; these are the E-01 inputs) | JSON/CSV outputs; traced RSS curve flat after warm-up | `run_profile.slurm` / `run_memory.slurm` intent |
| 5.7 External suite | `git -C $WORK clone https://github.com/openfheorg/python-log-reg-examples && git -C $WORK/python-log-reg-examples rev-parse HEAD` (pin the SHA in `evaluation/corpus/manifest.yaml`); `cipherscope preflight` each script; run **strict** first, `--permissive` only if strict rejects, one bundle per program under `/results/external/<name>`; `cipherscope coverage /results/external/* --output evaluation/raw/coverage_report.csv` | a coverage class per workload and the exact unsupported operations for anything not `COMPLETE` | never archived |
| 5.8 Runtime fingerprint | `python3.11 -c 'import json;print(json.load(open("/results/examples/repeated_rotations/manifest.json"))["runtime"])'` | `lane`, `openfhe_native_module_hashes` equal to the lane's `feasibility.json` `environment.native_module_hashes` | `docs/evidence.md` "Tying a run to a lane" |

Notes that matter for equivalence:

- Keep `OMP_NUM_THREADS=1` for every timing run and record it (add it to the
  run manifest's `runtime` block if it is not already there). The macOS build
  is effectively single-threaded; comparing a 16-thread OpenFHE against it
  would not be a platform comparison.
- `sol_log_reg.py` was budgeted 2 h in its launcher; start it last, in the
  background, and treat it as optional for this session.
- Everything under `/results` (`$SCRATCH/cipherscope-ls6`) is regenerable;
  only the raw records named in `evaluation/README.md` get copied into the
  repository.

### Phase 6 — Cross-platform equivalence check (30 min)

Add `evaluation/parity/compare_lanes.py` (stdlib only) that takes N lane
result roots and prints a table plus a non-zero exit on any disagreement in
the platform-independent artifacts:

| Artifact | Comparison | Allowed difference |
|---|---|---|
| `feasibility.json` `checks[].status` | per check id, across `developer`, `primary-source-py311`, `ls6-native-py311` | only `RES-02`: `skip` on macOS, `pass` on Linux |
| `feasibility.json` `pins` | equal | none |
| `case_results.json` `cases[]` (rule fired / not fired per case) | equal | none — recall and hard negatives must not depend on the platform |
| `semantic_ablation.csv` | equal after sorting rows | none |
| `recommendations.json` per example (rule ids with `positive` status, finding counts) | equal per example | none |
| `tables/{recall,seeded_cases,semantic_ablation,generic_profiler_comparison}.csv` | byte-identical | none |
| `tables/MANIFEST.json` | byte-identical **after B6** | none |
| `tables/scaling.csv` | per-machine rows both present; ratios (`traced/baseline`, bytes per event) compared | absolute ms and MB differ by hardware; report them side by side, do not assert |
| decrypted values in NUM/ROT/BOOT checks (`observed` blocks) | max abs error within the `golden_core.json` tolerances on every lane | CKKS noise differs per build; the tolerance is the contract |

Archive its output as `evaluation/parity/parity_report.md` (generated, with
the three lanes' native-module hashes at the top). This report is the
evidence for the "cross-platform compatibility" claim; without it, three
green gates are three anecdotes.

### Phase 7 — Documentation, checksums, commit (30 min)

1. `docs/evidence.md`: three archived rows + the new one; regeneration
   commands for the container lane (Apptainer) and the native lane
   (`build_openfhe_ls6.sh`), both non-SLURM.
2. `README.md` "Current limitations": the primary lane is archived and
   authoritative; the macOS lane is a superset-minus-`RES-02`; state that
   the scaling table is reported per machine.
3. `docs/ARTIFACT.md`: claim table rows for RQ1 (primary 38/38, native
   38/38, developer 37/38), RQ2 (`coverage.csv` from 5.7), RQ5 (`scaling.csv`
   with `x86_64` rows), and a "Linux / LS6" block in "What you need".
4. `examples/README.md`: Linux activation subsection (`source ls6_env.sh`, or
   the `run_in_primary` wrapper).
5. `.gitignore`: add `*.sif`, `ls6_env.local.sh` (if any).
6. `make checksums`; `make verify-checksums`; `make test`; commit on
   `ls6-parity`; open the PR with the parity report in the description.

## 5. Acceptance criteria ("LS6 is equivalent to the M4 items")

- [ ] `artifact/feasibility/primary-source-py311/feasibility.json` exists, `status = "pass"`, `38 / 0 / 38`, `authoritative_for_primary_target = true`, environment `ubuntu 24.04`, `x86_64`, `3.11.15`; `build-manifest.json` beside it.
- [ ] `artifact/feasibility/ls6-native-py311/feasibility.json` exists, `native_pass`, `38 / 0 / 38`, environment `rocky 8.10`, `x86_64`, `3.11.15`, gcc 15.2.0 in the manifest.
- [ ] `tests/test_evidence.py` and the whole fake-backend suite pass on LS6 (0 errors, 38 skips) **and** on the Mac.
- [ ] `evaluation/parity/parity_report.md` shows zero disagreements outside the allowed list in §6.
- [ ] All 16 example programs and the seeded benchmark are `COMPLETE`/`all_matched` on both LS6 lanes.
- [ ] `evaluation/raw/scaling.csv` carries both `arm64` and `x86_64` rows and `tables/scaling.csv` reports them per machine.
- [ ] `evaluation/tables/MANIFEST.json` regenerated on LS6 is byte-identical to one regenerated on the Mac from the same raw inputs.
- [ ] No file in the repository references `gcc/15.1.0`, `/home1/apps/gcc`, `gh-dev`, or `/Users/`; `grep -rn` returns nothing outside git history.
- [ ] `docs/evidence.md`, `README.md`, `docs/ARTIFACT.md`, `examples/README.md` agree with the archived artifacts (the evidence test enforces the table; the rest is a read-through).

## 6. Time budget against the current allocation (11 h 19 m at 15:20)

| Phase | Wall time | CPU-bound? | Can overlap with |
|---|---|---|---|
| 0 setup | 5 min | no | — |
| 1 repo fixes + `make test` | 30 min | no | Phase 2 build |
| 2 container build | 40–60 min | yes (16 cores) | Phase 1 |
| 3 primary gate + archive | 10 min | no | Phase 4 build |
| 4 native build | 40–60 min | yes | Phase 3, 5 (primary lane) |
| 5 parity runs, primary lane | 60 min | partly | Phase 4 (leave 4 cores: `MAKE_JOBS=12`) |
| 5 parity runs, native lane | 60 min | partly | — |
| 6 comparison | 30 min | no | — |
| 7 docs + commit | 30 min | no | — |
| **Total** | **≈ 4 h 30 min sequential, ≈ 3 h 30 min with the overlaps above** | | |

`sol_log_reg.py` (2 h) is outside this budget and optional.

## 7. Risks and pre-decided responses

| Risk | Signal | Response |
|---|---|---|
| Rootless Apptainer build fails past the apt stage | `%post` error after "Setting up pybind11-dev" | check `APPTAINER_TMPDIR` is on `/tmp` (BeeGFS → `EBUSY`); otherwise Docker-on-Mac + `apptainer pull` fallback (Phase 2) |
| GCC 15 rejects OpenFHE 1.5.1 sources | `error:` in `native-build.log` during `cmake --build` | `-DCMAKE_CXX_FLAGS=-Wno-error` first; if a real error, try `gcc/13.2.0` and record the change — the native lane's purpose is a second toolchain, not a specific version |
| CPython built without `_ssl` | `pip install pybind11` SSL error | `openssl-devel` is present; check `config.log` for a `LD_LIBRARY_PATH` clash from the gcc module (`libcrypto` resolution); never substitute the conda interpreter |
| Node `/tmp` wiped at job end | job ends | `.sif`, manifests, and logs are written to `$WORK`/`$SCRATCH` as soon as they exist |
| Seeded per-case disagreement between macOS and LS6 | Phase 6 exit ≠ 0 on `case_results.json` | this is a real finding, not a platform bug to hide: open the case's bundle on both lanes, compare `GetLevel`/scale state; the documented `bootstrap` and half-bit `precision` limitations are the likely suspects; record it in `evaluation/seeded/README.md` |
| Timing comparisons across machines | anyone quoting arm64 ms next to x86_64 ms | only ratios and per-machine rows are reportable; `tables/scaling.csv` enforces the split after B7 |
| Later batch runs still target Vista | `sbatch: error: invalid partition` | launchers repointed in Phase 1 (B5) and sourcing `ls6_env.sh`; not exercised in this session |
