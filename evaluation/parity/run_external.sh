#!/usr/bin/env bash
# Trace the external python-log-reg-examples corpus, strict mode first, through
# the GenCryptoContext interceptor (the targets never call cipherscope.attach).
#   bash evaluation/parity/run_external.sh <output-root> [program.py ...]
set -uo pipefail
OUT="${1:?output root}"; shift
PROGRAMS=("${@:-sol_lin_reg.py sol_encrypted_inference.py sol_log_reg.py sol_nag_log_reg.py}")
[ ${#PROGRAMS[@]} -eq 1 ] && read -r -a PROGRAMS <<< "${PROGRAMS[0]}"
REPO="${LOG_REG_EXAMPLES:-$WORK/python-log-reg-examples}"
CIPHERSCOPE_DIR="${CIPHERSCOPE_DIR:-$PWD}"
PY="${PYTHON:-python3.11}"
export PYTHONPATH="${PYTHONPATH:-$CIPHERSCOPE_DIR/src}:$REPO"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
mkdir -p "$OUT"
echo "corpus commit: $(git -C "$REPO" rev-parse HEAD)" | tee "$OUT/corpus_commit.txt"
cd "$REPO"
for prog in "${PROGRAMS[@]}"; do
  name="$(basename "$prog" .py)"
  echo "[$(date +%T)] $name (strict)"
  rm -rf "$OUT/$name"
  if ! $PY -m cipherscope run --output "$OUT/$name" "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "$prog" > "$OUT/$name.log" 2>&1; then
    echo "[$(date +%T)] $name: strict run exited nonzero; rerunning permissive for the coverage inventory"
    rm -rf "$OUT/$name"
    $PY -m cipherscope run --output "$OUT/$name" --permissive "$CIPHERSCOPE_DIR/examples/profile_unmodified.py" -- "$prog" > "$OUT/$name.permissive.log" 2>&1 || echo "[$(date +%T)] $name: permissive run also exited nonzero"
  fi
  [ -f "$OUT/$name/manifest.json" ] && $PY -m cipherscope validate "$OUT/$name" > "$OUT/$name.validate.json" 2>&1
done
cd "$CIPHERSCOPE_DIR"
$PY -m cipherscope coverage "$OUT"/*/ --output "$OUT/coverage_report.csv"
echo "[$(date +%T)] done"
