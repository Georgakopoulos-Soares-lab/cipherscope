#!/bin/bash
#SBATCH -J prs-memory
#SBATCH -o prs-memory.o%j
#SBATCH -e prs-memory.e%j
#SBATCH -p gh-dev
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:20:00
#SBATCH -A MCB25091

set -euo pipefail
module purge
module load TACC
module load gcc/15.1.0
export PATH=$WORK/cipherscope-openfhe-build/opt/python311/bin:$PATH
export LD_LIBRARY_PATH=/home1/apps/gcc/15.1.0/lib64:$WORK/cipherscope-openfhe-build/opt/python311/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib64
export PYTHONPATH=$WORK/cipherscope/src
cd $WORK/cipherscope
python3.11 memory_profile_prs.py --output prs-memory-results
