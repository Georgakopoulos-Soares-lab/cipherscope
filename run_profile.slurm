#!/bin/bash
#SBATCH -J prs-profile
#SBATCH -o prs-profile.o%j
#SBATCH -e prs-profile.e%j
#SBATCH -p vm-small
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:45:00
#SBATCH -A MCB25091

set -euo pipefail
# LS6 launcher. The checkout is expected at $WORK/cipherscope unless
# CIPHERSCOPE_DIR is exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer,
# and the native-lane runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
python3.11 benchmark_prs_overhead.py --repeats 5 --warmup 1 --output prs-bench-results
