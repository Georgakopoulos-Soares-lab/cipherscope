#!/bin/bash
# Direct-execution launcher (no sbatch/srun/idev -- run in an already-allocated
# LS6 x86_64 shell; see docs/ls6_parity_plan.md's "no scheduler" policy).
#
# Profiles the python-log-reg-examples external corpus through CipherScope.
# With no argument, runs all four programs and writes the coverage summary
# (this replaces the old run_external_suite.slurm loop). With one argument
# (a program's base name, e.g. sol_lin_reg), runs just that one program --
# this replaces the three near-duplicate run_sol_*.slurm launchers, which
# were each just this same loop body pinned to a single program.
set -o pipefail
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$WORK/cipherscope}"
# shellcheck disable=SC1091
source "$CIPHERSCOPE_DIR/ls6_env.sh"

REPO="${LOG_REG_EXAMPLES:-$WORK/python-log-reg-examples}"
# The targets never call cipherscope.attach(); profile_unmodified.py intercepts
# GenCryptoContext instead. They import their helper packages from the repo root.
export PYTHONPATH="$PYTHONPATH:$REPO"

ALL_PROGRAMS=(sol_lin_reg sol_log_reg sol_nag_log_reg sol_encrypted_inference)
if [ $# -ge 1 ]; then
  PROGRAMS=("$1")
else
  PROGRAMS=("${ALL_PROGRAMS[@]}")
  rm -rf "$CIPHERSCOPE_DIR/external_suite"
fi
mkdir -p "$CIPHERSCOPE_DIR/external_suite"
cd "$REPO"

for name in "${PROGRAMS[@]}"; do
  prog="$name.py"
  [ -f "$prog" ] || { echo "MISSING: $prog"; continue; }
  echo "=== $name ==="
  # Strict first: only a COMPLETE run feeds the finding-quality tables. Fall
  # back to --permissive solely to inventory the unsupported operations.
  rm -rf "$CIPHERSCOPE_DIR/external_suite/$name"
  if ! python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/$name/" "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "$prog"; then
    echo "strict run of $name failed; re-running permissive for the coverage inventory"
    rm -rf "$CIPHERSCOPE_DIR/external_suite/$name"
    python3.11 -m cipherscope.cli run --output "$CIPHERSCOPE_DIR/external_suite/$name/" --permissive "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "$prog"
  fi
  echo "exit code: $?"
done

if [ ${#PROGRAMS[@]} -gt 1 ]; then
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
fi
