#!/bin/bash
#SBATCH -J external-suite
#SBATCH -o external-suite.o%j
#SBATCH -e external-suite.e%j
#SBATCH -p gh-dev
#SBATCH -N 1
#SBATCH -n 1
#SBATCH -t 00:20:00
#SBATCH -A MCB25091

set -uo pipefail
module purge
module load TACC
module load gcc/15.1.0
export PATH=$WORK/cipherscope-openfhe-build/opt/python311/bin:$PATH
export LD_LIBRARY_PATH=/home1/apps/gcc/15.1.0/lib64:$WORK/cipherscope-openfhe-build/opt/python311/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib:$WORK/cipherscope-openfhe-build/opt/openfhe/lib64
export PYTHONPATH=$WORK/cipherscope/src:$WORK/python-log-reg-examples

REPO=$WORK/python-log-reg-examples
rm -rf external_suite
mkdir -p external_suite
cd "$REPO"

PROGRAMS=(sol_lin_reg.py sol_log_reg.py sol_nag_log_reg.py sol_encrypted_inference.py)

for prog in "${PROGRAMS[@]}"; do
  [ -f "$prog" ] || { echo "MISSING: $prog"; continue; }
  name=$(basename "$prog" .py)
  echo "=== $name ==="
  python3.11 -m cipherscope.cli run --output "$WORK/cipherscope/external_suite/$name/" --permissive "$prog"
  echo "exit code: $?"
done

echo "=== SUMMARY ==="
cd "$WORK/cipherscope"
python3.11 - << 'PYEOF'
import json
from pathlib import Path
for run_dir in sorted(Path("external_suite").iterdir()):
    rec = run_dir / "recommendations.json"
    if not rec.exists():
        print(f"{run_dir.name}: NO OUTPUT (run failed)"); continue
    d = json.loads(rec.read_text())
    fired = [k for k, v in d["analyzer_status"].items() if v == "positive"]
    print(f"{run_dir.name}: status={d['analysis_status']}, findings={len(d['findings'])}, fired={fired}")
PYEOF
