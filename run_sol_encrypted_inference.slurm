#!/bin/bash
#SBATCH -J sol_encrypted_inference
#SBATCH -o sol_encrypted_inference.o%j
#SBATCH -e sol_encrypted_inference.e%j
#SBATCH -p vm-small
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 02:00:00
#SBATCH -A MCB25091

set -uo pipefail
# LS6 launcher. The checkout is expected at $WORK/cipherscope unless
# CIPHERSCOPE_DIR is exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer,
# and the native-lane runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

REPO="${LOG_REG_EXAMPLES:-$WORK/python-log-reg-examples}"
# The targets never call cipherscope.attach(); profile_unmodified.py intercepts
# GenCryptoContext instead. They import their helper packages from the repo root.
export PYTHONPATH="$PYTHONPATH:$REPO"
cd "$REPO"
rm -rf "$CIPHERSCOPE_DIR/external_suite/sol_encrypted_inference"
if ! python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/sol_encrypted_inference/" "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "sol_encrypted_inference.py"; then
  echo "strict run failed; re-running permissive for the coverage inventory"
  rm -rf "$CIPHERSCOPE_DIR/external_suite/sol_encrypted_inference"
  python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/sol_encrypted_inference/" --permissive "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "sol_encrypted_inference.py"
fi
echo "exit code: $?"
