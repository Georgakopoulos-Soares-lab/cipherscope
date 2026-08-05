#!/bin/bash
#SBATCH -J sol_encrypted_inference
#SBATCH -o sol_encrypted_inference.o%j
#SBATCH -e sol_encrypted_inference.e%j
#SBATCH -p gh-dev
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 02:00:00
#SBATCH -A MCB25091

set -uo pipefail
module purge
module load TACC
module load gcc/15.1.0
export PATH=$WORK/cipherscope-openfhe-build/opt/python311/bin:$PATH
export LD_LIBRARY_PATH=/home1/apps/gcc/15.1.0/lib64:$WORK/cipherscope-openfhe-build/opt/python311/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib64
export PYTHONPATH=$WORK/cipherscope/src:$WORK/python-log-reg-examples

cd "/work/11681/karimbenhamou/vista/python-log-reg-examples"
rm -rf "$WORK/cipherscope/external_suite/sol_encrypted_inference"
python3.11 -m cipherscope.cli run --output "$WORK/cipherscope/external_suite/sol_encrypted_inference/" --permissive "sol_encrypted_inference.py"
echo "exit code: $?"
