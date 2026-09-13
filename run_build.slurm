#!/bin/bash
#SBATCH -J openfhe-build
#SBATCH -o openfhe-build.o%j
#SBATCH -e openfhe-build.e%j
#SBATCH -p vm-small
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 02:00:00
#SBATCH -A MCB25091

# Native supporting lane (ls6-native-py311). The authoritative primary lane is
# the Apptainer image; see docs/ls6_parity_plan.md Phase 2.
set -euo pipefail
# LS6 launcher. The checkout is expected at $WORK/cipherscope unless
# CIPHERSCOPE_DIR is exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer,
# and the native-lane runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
bash build_openfhe_ls6.sh
