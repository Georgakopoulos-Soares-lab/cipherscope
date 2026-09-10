#!/bin/bash
#SBATCH -J prs-analysis
#SBATCH -o prs-analysis.o%j
#SBATCH -e prs-analysis.e%j
#SBATCH -p gh-dev
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:10:00
#SBATCH -A MCB25091

set -euo pipefail
module purge
module load TACC
module load gcc/15.1.0
export PATH=$WORK/cipherscope-openfhe-build/opt/python311/bin:$PATH
export LD_LIBRARY_PATH=/home1/apps/gcc/15.1.0/lib64:$WORK/cipherscope-openfhe-build/opt/python311/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib64
export PYTHONPATH=$WORK/cipherscope/src

cd "$WORK/cipherscope"
cp prs_dot_product.py prs_dot_product_analysis.py
sed -i 's/^NUM_BLOCKS = .*/NUM_BLOCKS = 4  # small, just need the analyzer to fire/' prs_dot_product_analysis.py
sed -i 's/^NUM_PATIENTS = .*/NUM_PATIENTS = 3  # >1 needed to reproduce the repeated-encoding case/' prs_dot_product_analysis.py

rm -rf prs_run/
python3.11 -m cipherscope.cli run --output prs_run/ prs_dot_product_analysis.py
echo "=== recommendations.json ==="
cat prs_run/recommendations.json
