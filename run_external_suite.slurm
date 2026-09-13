#!/bin/bash
#SBATCH -J external-suite
#SBATCH -o external-suite.o%j
#SBATCH -e external-suite.e%j
#SBATCH -p vm-small
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:20:00
#SBATCH -A MCB25091

set -uo pipefail
# LS6 launcher. The checkout is expected at $WORK/cipherscope unless
# CIPHERSCOPE_DIR is exported; ls6_env.sh loads gcc/15.2.0, cmake, apptainer,
# and the native-lane runtime under $WORK/cipherscope-openfhe-build.
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

REPO="${LOG_REG_EXAMPLES:-$WORK/python-log-reg-examples}"
export PYTHONPATH="$PYTHONPATH:$REPO"
rm -rf "$CIPHERSCOPE_DIR/external_suite"
mkdir -p "$CIPHERSCOPE_DIR/external_suite"
cd "$REPO"

PROGRAMS=(sol_lin_reg.py sol_log_reg.py sol_nag_log_reg.py sol_encrypted_inference.py)

for prog in "${PROGRAMS[@]}"; do
  [ -f "$prog" ] || { echo "MISSING: $prog"; continue; }
  name=$(basename "$prog" .py)
  echo "=== $name ==="
  # Strict first: only a COMPLETE run feeds the finding-quality tables. Fall
  # back to --permissive solely to inventory the unsupported operations.
  if ! python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/$name/" "$prog"; then
    echo "strict run of $name failed; re-running permissive for the coverage inventory"
    rm -rf "$CIPHERSCOPE_DIR/external_suite/$name"
    python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/$name/" --permissive "$prog"
  fi
  echo "exit code: $?"
done

echo "=== SUMMARY ==="
cd "$CIPHERSCOPE_DIR"
python3.11 -m cipherscope.cli coverage external_suite/* --output external_suite/coverage_report.csv
python3.11 - << 'PYEOF'
import json
from pathlib import Path
for run_dir in sorted(p for p in Path("external_suite").iterdir() if p.is_dir()):
    rec = run_dir / "recommendations.json"
    if not rec.exists():
        print(f"{run_dir.name}: NO OUTPUT (run failed)"); continue
    d = json.loads(rec.read_text())
    fired = [k for k, v in d["analyzer_status"].items() if v == "positive"]
    print(f"{run_dir.name}: status={d['analysis_status']}, findings={len(d['findings'])}, fired={fired}")
PYEOF
