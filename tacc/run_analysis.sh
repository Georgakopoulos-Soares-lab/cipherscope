#!/bin/bash
# Direct-execution launcher (no sbatch/srun/idev -- run in an already-allocated
# LS6 x86_64 shell; see docs/ls6_parity_plan.md's "no scheduler" policy).
set -euo pipefail
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
cp tacc/prs_dot_product.py tacc/prs_dot_product_analysis.py
sed -i 's/^NUM_BLOCKS = .*/NUM_BLOCKS = 4  # small, just need the analyzer to fire/' tacc/prs_dot_product_analysis.py
sed -i 's/^NUM_PATIENTS = .*/NUM_PATIENTS = 3  # >1 needed to reproduce the repeated-encoding case/' tacc/prs_dot_product_analysis.py

rm -rf prs_run/
python3.11 -m cipherscope.cli run --output prs_run/ tacc/prs_dot_product_analysis.py
echo "=== recommendations.json ==="
cat prs_run/recommendations.json
