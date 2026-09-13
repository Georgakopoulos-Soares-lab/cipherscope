# ls6_env.sh -- source me (bash). Native-lane runtime and container tooling on
# TACC Lonestar6. Every non-SLURM step in docs/ls6_parity_plan.md and every
# run_*.slurm launcher sources this file instead of repeating module lines.
#
#   source ls6_env.sh                      # native lane (after build_openfhe_ls6.sh)
#   source ls6_env.sh && run_in_primary …  # container lane (after the .sif exists)

if ! type module >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  source /etc/profile.d/z01_lmod.sh
fi
module purge >/dev/null 2>&1
module load TACC gcc/15.2.0 cmake/3.31.5 tacc-apptainer/1.4.1

CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
export CIPHERSCOPE_DIR
export BUILD_ROOT="${BUILD_ROOT:-$WORK/cipherscope-openfhe-build}"
export RESULTS_ROOT="${RESULTS_ROOT:-$SCRATCH/cipherscope-ls6}"

export PATH="$BUILD_ROOT/opt/python311/bin:$PATH"
# The gcc module's own lib64 first so the OpenFHE extension always resolves the
# libstdc++ it was compiled against; then the source-built Python and OpenFHE.
export LD_LIBRARY_PATH="$TACC_GCC_LIB64:$BUILD_ROOT/opt/python311/lib:$BUILD_ROOT/opt/openfhe/lib:$BUILD_ROOT/opt/openfhe/lib64:${LD_LIBRARY_PATH:-}"
export PYTHONPATH="$CIPHERSCOPE_DIR/src"
export PYTHONNOUSERSITE=1

# Parity with the effectively single-threaded macOS developer build. Every
# timing run records this value; change it deliberately, never implicitly.
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export MAKE_JOBS="${MAKE_JOBS:-${SLURM_CPUS_ON_NODE:-16}}"

# Apptainer: cache on $SCRATCH is fine, but the rootless build staging area
# must be node-local -- BeeGFS has no xattrs and returns EBUSY on rename().
export APPTAINER_CACHEDIR="${APPTAINER_CACHEDIR:-$SCRATCH/apptainer_cache}"
export APPTAINER_TMPDIR="${APPTAINER_TMPDIR:-/tmp/$USER/apptainer-tmp}"
mkdir -p "$APPTAINER_TMPDIR" "$RESULTS_ROOT/logs"

export PRIMARY_SIF="${PRIMARY_SIF:-$BUILD_ROOT/openfhe-py311-source.sif}"

# Pins (golden_core.json). ENV-03/ENV-04 read these for source-built lanes.
export CIPHERSCOPE_OPENFHE_NATIVE_COMMIT=1306d14f8c26bb6150d3e6ad54f28dfe1007689e
export CIPHERSCOPE_OPENFHE_WRAPPER_COMMIT=4f13e2c3a7e35f73f4816904dabd3a3db47b6e51
export CIPHERSCOPE_OPENFHE_BUILD_MANIFEST="${CIPHERSCOPE_OPENFHE_BUILD_MANIFEST:-$BUILD_ROOT/cipherscope-openfhe-build-manifest.json}"

# Run a command inside the authoritative Ubuntu 24.04 container. The host
# environment is dropped (--cleanenv) so the gcc module's LD_LIBRARY_PATH and
# this PYTHONPATH cannot leak in; the image's %environment supplies the lane.
run_in_primary() {
  apptainer exec --cleanenv --no-home --containall \
    --bind "$CIPHERSCOPE_DIR:/workspace/cipherscope" \
    --bind "$RESULTS_ROOT:/results" \
    --pwd /workspace/cipherscope \
    --env OMP_NUM_THREADS="$OMP_NUM_THREADS" \
    "$PRIMARY_SIF" "$@"
}
export -f run_in_primary
