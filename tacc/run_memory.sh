#!/bin/bash
# Direct-execution launcher (no sbatch/srun/idev -- run in an already-allocated
# LS6 x86_64 shell; see docs/ls6_parity_plan.md's "no scheduler" policy).
set -eo pipefail
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
python3.11 tacc/memory_profile_prs.py --output prs-memory-results
