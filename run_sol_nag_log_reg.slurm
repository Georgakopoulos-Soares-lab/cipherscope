#!/bin/bash
#SBATCH -J sol_nag_log_reg
#SBATCH -o sol_nag_log_reg.o%j
#SBATCH -e sol_nag_log_reg.e%j
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
rm -rf "$WORK/cipherscope/external_suite/sol_nag_log_reg"
python3.11 -m cipherscope.cli run --output "$WORK/cipherscope/external_suite/sol_nag_log_reg/" --permissive "sol_nag_log_reg.py"
echo "exit code: $?"
