#!/bin/bash
#SBATCH -J prs-analysis
#SBATCH -o prs-analysis.o%j
#SBATCH -e prs-analysis.e%j
#SBATCH -p vm-small
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:10:00
#SBATCH -A MCB25091

set -euo pipefail
# LS6 launcher. The checkout is expected at $WORK/cipherscope unless
# CIPHERSCOPE_DIR is exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer,
# and the native-lane runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

cd "$CIPHERSCOPE_DIR"
cp prs_dot_product.py prs_dot_product_analysis.py
sed -i 's/^NUM_BLOCKS = .*/NUM_BLOCKS = 4  # small, just need the analyzer to fire/' prs_dot_product_analysis.py
sed -i 's/^NUM_PATIENTS = .*/NUM_PATIENTS = 3  # >1 needed to reproduce the repeated-encoding case/' prs_dot_product_analysis.py

rm -rf prs_run/
python3.11 -m cipherscope.cli run --output prs_run/ prs_dot_product_analysis.py
echo "=== recommendations.json ==="
cat prs_run/recommendations.json
