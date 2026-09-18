#!/usr/bin/env bash
# Build the pinned OpenFHE 1.5.1.0 Python stack on TACC Lonestar6 (x86_64,
# Rocky Linux 8) with the module toolchain, then run CipherScope's
# tests/integration_openfhe gate as the *native* supporting lane
# `ls6-native-py311`.
#
# This is a line-by-line translation of
#   artifact/docker/openfhe-py311-source/Dockerfile
# to a no-root, module-based HPC environment. The pins (Python version,
# OpenFHE commits) are copied verbatim from that Dockerfile and from
# tests/integration_openfhe/golden_core.json -- do not change them.
#
# What this lane is and is not: it uses the same Python 3.11.15 and OpenFHE
# commits as the primary lane, but the host is Rocky Linux with a TACC gcc
# module rather than the pinned Ubuntu 24.04 image, so the gate's ENV-01 would
# refuse to call it `primary-source-py311`. The authoritative primary lane is
# built on LS6 from artifact/apptainer/openfhe-py311-source.def instead (see
# docs/evidence.md); this script proves the gate on a second toolchain.
#
# USAGE (from an already-allocated compute node shell, e.g. idev or an
# interactive job; never the login node -- it compiles Python + two C++
# projects):
#   cd /path/to/cipherscope
#   bash build_openfhe_ls6.sh
#
# Everything is installed under $WORK/cipherscope-openfhe-build; rerunning
# skips the parts that already exist.

set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Pins -- copied from the Dockerfile / golden_core.json. Do not edit.
# ---------------------------------------------------------------------------
PYTHON_VERSION=3.11.15
PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625
OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51
MAKE_JOBS=${MAKE_JOBS:-8}

# ---------------------------------------------------------------------------
# 1. Workspace -- build in $WORK (Lustre, large quota), never $HOME.
# ---------------------------------------------------------------------------
: "${WORK:?WORK is not set -- are you on a TACC login/compute node?}"
BUILD_ROOT="$WORK/cipherscope-openfhe-build"
PREFIX_PY="$BUILD_ROOT/opt/python311"
PREFIX_FHE="$BUILD_ROOT/opt/openfhe"
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$PWD}"   # run this script from inside the checkout, or set CIPHERSCOPE_DIR
mkdir -p "$BUILD_ROOT"

echo "== Building into $BUILD_ROOT =="
echo "== CipherScope checkout: $CIPHERSCOPE_DIR =="
test -d "$CIPHERSCOPE_DIR/src/cipherscope" || {
  echo "ERROR: $CIPHERSCOPE_DIR doesn't look like the cipherscope repo root (no src/cipherscope)."
  echo "cd into the checkout, or set CIPHERSCOPE_DIR=/path/to/cipherscope before running this script."
  exit 1
}

# ---------------------------------------------------------------------------
# 2. Toolchain -- module-based, no apt/root. gcc module gives a real modern
#    GNU toolchain (avoid the bare system gcc, which is old on Rocky 8).
# ---------------------------------------------------------------------------
# Use the same compiler module as ls6_env.sh (which every runtime script
# sources). Mixing versions can load a different libstdc++.so.6 and make the
# OpenFHE extension fail to import. gcc/15.1.0 was retired from LS6; 15.2.0 is
# the current module.
GCC_MODULE="${GCC_MODULE:-gcc/15.2.0}"
CMAKE_MODULE="${CMAKE_MODULE:-cmake/3.31.5}"   # closest module to Ubuntu 24.04's 3.28

if ! type module >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  source /etc/profile.d/z01_lmod.sh
fi
module purge
module load TACC
module load "$GCC_MODULE"
module load "$CMAKE_MODULE"
module list

# Belt-and-suspenders: explicitly put this compiler's own lib64 (where its
# matching libstdc++.so.6 lives) at the FRONT of LD_LIBRARY_PATH, so it can't
# be shadowed by a different gcc module's runtime libs that may already be on
# the path from an earlier `module load` in this shell.
GCC_LIB64="${TACC_GCC_LIB64:-$(dirname "$(dirname "$(command -v g++)")")/lib64}"
export LD_LIBRARY_PATH="$GCC_LIB64:${LD_LIBRARY_PATH:-}"
echo "== Using g++ at $(command -v g++), lib64 at $GCC_LIB64 =="

# ---------------------------------------------------------------------------
# 3. Python 3.11.15 built from source (the Dockerfile does NOT use the
#    system or module python -- it builds this exact version with --enable-shared
#    so the openfhe extension can link against it).
# ---------------------------------------------------------------------------
if [ ! -x "$PREFIX_PY/bin/python3.11" ]; then
  echo "== Building Python $PYTHON_VERSION =="
  PYBUILD="$BUILD_ROOT/python-build"
  mkdir -p "$PYBUILD" && cd "$PYBUILD"
  curl --fail --location --silent --show-error \
      --output Python.tar.xz \
      "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tar.xz"
  echo "${PYTHON_SHA256}  Python.tar.xz" | sha256sum --check --strict
  tar --extract --file Python.tar.xz --xz --strip-components=1
  # --enable-shared: openfhe's pybind11 extension must link against libpython.
  # If configure complains about missing _ssl/_sqlite3/etc, check `module spider openssl`
  # / `module spider sqlite` and re-run with --with-openssl=<path>; Rocky 8's
  # system -devel headers are usually already present, but you have no apt/root
  # to add them if they're not -- file a TACC consulting ticket in that case.
  ./configure --prefix="$PREFIX_PY" --enable-shared --with-ensurepip=install
  make --jobs "$MAKE_JOBS"
  make install
else
  echo "== Python already built at $PREFIX_PY, skipping =="
fi

export PATH="$PREFIX_PY/bin:$PATH"
export LD_LIBRARY_PATH="$PREFIX_PY/lib:${LD_LIBRARY_PATH:-}"
python3.11 --version

# pybind11 headers: the Dockerfile gets these from Ubuntu's pybind11-dev.
# On Rocky/no-root we pip-install it into the freshly built interpreter instead;
# its CMake config ends up under site-packages/pybind11/share/cmake/pybind11.
python3.11 -m pip install --quiet "pybind11[global]"
PYBIND11_CMAKE_DIR="$("$PREFIX_PY/bin/python3.11" -c \
  'import pybind11; print(pybind11.get_cmake_dir())')"

# ---------------------------------------------------------------------------
# 4. OpenFHE native core, pinned commit, installed under $BUILD_ROOT/opt/openfhe
# ---------------------------------------------------------------------------
if [ ! -d "$PREFIX_FHE/include/openfhe" ]; then
  echo "== Building openfhe-development @ $OPENFHE_NATIVE_COMMIT =="
  NATIVE_SRC="$BUILD_ROOT/openfhe-development"
  git init "$NATIVE_SRC"
  git -C "$NATIVE_SRC" remote add origin https://github.com/openfheorg/openfhe-development.git
  git -C "$NATIVE_SRC" fetch --depth 1 origin "$OPENFHE_NATIVE_COMMIT"
  git -C "$NATIVE_SRC" checkout --detach FETCH_HEAD
  test "$(git -C "$NATIVE_SRC" rev-parse HEAD)" = "$OPENFHE_NATIVE_COMMIT"

  # IMPORTANT: pass the compilers explicitly. CMake's default auto-detection
  # searches for binaries literally named "c++"/"cc" first; on TACC, a loaded
  # gcc module often only provides "g++"/"gcc" (no unversioned c++/cc symlink),
  # so CMake silently falls through to Rocky's ancient /usr/bin/c++ regardless
  # of which gcc module you have loaded. Force it explicitly to avoid that.
  cmake -S "$NATIVE_SRC" -B "$NATIVE_SRC/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX_FHE" \
        -DCMAKE_C_COMPILER="$(command -v gcc)" \
        -DCMAKE_CXX_COMPILER="$(command -v g++)" \
        -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
  cmake --build "$NATIVE_SRC/build" --parallel "$MAKE_JOBS"
  cmake --install "$NATIVE_SRC/build"
else
  echo "== openfhe-development already installed at $PREFIX_FHE, skipping =="
fi
export LD_LIBRARY_PATH="$PREFIX_FHE/lib:$PREFIX_FHE/lib64:${LD_LIBRARY_PATH:-}"

# ---------------------------------------------------------------------------
# 5. OpenFHE Python wrapper, pinned commit, built against that core, and
#    installed straight into python3.11's site-packages/openfhe.
# ---------------------------------------------------------------------------
SITE_PACKAGES="$("$PREFIX_PY/bin/python3.11" -c \
  'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

if "$PREFIX_PY/bin/python3.11" -c 'import openfhe' >/dev/null 2>&1; then
  echo "== openfhe Python wrapper already importable, skipping wrapper build =="
else
  echo "== Building openfhe-python @ $OPENFHE_WRAPPER_COMMIT =="
  WRAPPER_SRC="$BUILD_ROOT/openfhe-python"
  # Start clean every time: a stale partial clone from an earlier failed run
  # (e.g. one that already ran `git remote add origin`) would otherwise make
  # the commands below fail with "remote origin already exists".
  rm -rf "$WRAPPER_SRC"
  git init "$WRAPPER_SRC"
  git -C "$WRAPPER_SRC" remote add origin https://github.com/openfheorg/openfhe-python.git
  git -C "$WRAPPER_SRC" fetch --depth 1 origin "$OPENFHE_WRAPPER_COMMIT"
  git -C "$WRAPPER_SRC" checkout --detach FETCH_HEAD
  test "$(git -C "$WRAPPER_SRC" rev-parse HEAD)" = "$OPENFHE_WRAPPER_COMMIT"

  cmake -S "$WRAPPER_SRC" -B "$WRAPPER_SRC/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$PREFIX_FHE;$PYBIND11_CMAKE_DIR" \
        -DCMAKE_INSTALL_PREFIX="$SITE_PACKAGES/openfhe" \
        -DCMAKE_C_COMPILER="$(command -v gcc)" \
        -DCMAKE_CXX_COMPILER="$(command -v g++)" \
        -DOPENFHE_REQUIRED_VERSION=1.5.1 \
        -DPython_EXECUTABLE="$PREFIX_PY/bin/python3.11" \
        -DPython_ROOT_DIR="$PREFIX_PY"
  cmake --build "$WRAPPER_SRC/build" --parallel "$MAKE_JOBS"
  cmake --install "$WRAPPER_SRC/build"
fi

echo "== Smoke test =="
python3.11 -c 'import openfhe; print("native_int:", openfhe.get_native_int())'

# ---------------------------------------------------------------------------
# 5b. Build provenance manifest. ENV-03/ENV-04 in the gate require these
#     three env vars AND a readable manifest JSON recording the pinned
#     commits + native module hashes + toolchain versions. Missing this
#     entirely was an omission in the earlier version of this script.
# ---------------------------------------------------------------------------
export CIPHERSCOPE_OPENFHE_NATIVE_COMMIT="$OPENFHE_NATIVE_COMMIT"
export CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT="$OPENFHE_WRAPPER_COMMIT"
export CIPHERSCOPE_OPENFHE_BUILD_MANIFEST="$BUILD_ROOT/cipherscope-openfhe-build-manifest.json"

MAKE_JOBS="$MAKE_JOBS" OMP_NUM_THREADS="${OMP_NUM_THREADS:-}" \
python3.11 - "$CIPHERSCOPE_OPENFHE_BUILD_MANIFEST" "$SITE_PACKAGES" "$OPENFHE_NATIVE_COMMIT" "$OPENFHE_WRAPPER_COMMIT" <<'PYEOF'
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

manifest_path, site_packages, native_commit, wrapper_commit = sys.argv[1:5]

def command_version(*command):
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout.splitlines()[0]

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

package = Path(site_packages) / "openfhe"
native_modules = {p.name: sha256(p) for p in sorted(package.glob("*.so"))}

def os_release():
    release = {}
    path = Path("/etc/os-release")
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip().strip('"')
    return release

def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None

manifest = {
    "schema_version": "1.0.0",
    # Honest about the actual platform -- this was built on TACC Lonestar6
    # (Rocky Linux), not the Ubuntu reference image the Dockerfile targets.
    "base_platform": {
        "name": "TACC Lonestar6 (Rocky Linux host, no container)",
        "architecture": platform.machine(),
        "os_release": os_release(),
        "kernel": platform.release(),
    },
    "host": {
        "hostname": platform.node(),
        "cpu_model": cpu_model(),
        "slurm_job_id": os.environ.get("SLURM_JOB_ID"),
        "slurm_partition": os.environ.get("SLURM_JOB_PARTITION"),
        "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
        "make_jobs": os.environ.get("MAKE_JOBS"),
        "modules": os.environ.get("LOADEDMODULES", "").split(":"),
    },
    "python": {
        "version": platform.python_version(),
        "source": "https://www.python.org/ftp/python/3.11.15/Python-3.11.15.tar.xz",
        "configure_flags": ["--enable-shared", "--with-ensurepip=install"],
    },
    "openfhe_native": {
        "repository": "https://github.com/openfheorg/openfhe-development.git",
        "commit": native_commit,
    },
    "openfhe_python": {
        "repository": "https://github.com/openfheorg/openfhe-python.git",
        "commit": wrapper_commit,
        "native_module_hashes": native_modules,
    },
    "toolchain": {
        # Use "gcc"/"g++" explicitly, not "cc"/"c++": on this cluster those
        # generic names resolve to Rocky's old system compiler, NOT the
        # module-loaded one actually used for CMAKE_C_COMPILER/CXX_COMPILER
        # above. Recording "cc"/"c++" here would silently misreport what
        # actually built this library.
        "cc": command_version("gcc", "--version"),
        "cxx": command_version("g++", "--version"),
        "cmake": command_version("cmake", "--version"),
    },
}
Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote build manifest to {manifest_path}")
PYEOF

# ---------------------------------------------------------------------------
# 6. Run CipherScope's real-binding gate as the native supporting lane. The
#    lane name is what tests/integration_openfhe/support.py reads; ENV-01
#    records this host's distribution instead of asserting Ubuntu, and
#    run_gate.py reports `native_pass` (never `pass`, which is reserved for
#    the Ubuntu 24.04 image) when every check succeeds.
# ---------------------------------------------------------------------------
export PYTHONPATH="$CIPHERSCOPE_DIR/src"
export PYTHONNOUSERSITE=1
export CIPHERSCOPE_OPENFHE_LANE="${CIPHERSCOPE_OPENFHE_LANE:-ls6-native-py311}"
export CIPHERSCOPE_OPENFHE_BOOTSTRAP=1
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
GATE_OUTPUT="$BUILD_ROOT/feasibility-$CIPHERSCOPE_OPENFHE_LANE.json"

cd "$CIPHERSCOPE_DIR"
echo "== Running tests/integration_openfhe gate as lane $CIPHERSCOPE_OPENFHE_LANE =="
python3.11 -m tests.integration_openfhe.run_gate --output "$GATE_OUTPUT"

echo
echo "Gate evidence written to: $GATE_OUTPUT"
echo "Check its \"status\" field: \"native_pass\" means all required checks passed;"
echo "\"incomplete\" means something still skipped; \"fail\" means a real failure."
echo "Archive it with the build manifest:"
echo "  mkdir -p artifact/feasibility/$CIPHERSCOPE_OPENFHE_LANE"
echo "  cp $GATE_OUTPUT artifact/feasibility/$CIPHERSCOPE_OPENFHE_LANE/feasibility.json"
echo "  cp $CIPHERSCOPE_OPENFHE_BUILD_MANIFEST artifact/feasibility/$CIPHERSCOPE_OPENFHE_LANE/build-manifest.json"
