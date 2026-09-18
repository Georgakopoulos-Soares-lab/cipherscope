#!/bin/bash
# Direct-execution launcher (no sbatch/srun/idev -- run in an already-allocated
# LS6 x86_64 shell; see docs/ls6_parity_plan.md's "no scheduler" policy).
#
# Native supporting lane (ls6-native-py311). The authoritative primary lane is
# the Apptainer image; see docs/ls6_parity_plan.md Phase 2.
set -euo pipefail
# The checkout is expected at $WORK/cipherscope unless CIPHERSCOPE_DIR is
# exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer, and the native-lane
# runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
bash build_openfhe_ls6.sh
