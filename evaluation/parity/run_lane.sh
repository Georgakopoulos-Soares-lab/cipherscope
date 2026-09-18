#!/usr/bin/env bash
# Reproduce the real-binding evidence items for one lane, into one directory.
#
#   bash evaluation/parity/run_lane.sh <lane> <output-root> [steps...]
#
# Runs inside whichever environment provides the lane's `openfhe` binding:
#   run_in_primary bash evaluation/parity/run_lane.sh primary-source-py311 /results/primary-source-py311
#   bash evaluation/parity/run_lane.sh ls6-native-py311 "$RESULTS_ROOT/ls6-native-py311"
# The default step list is `examples seeded scaling`; name a subset to rerun
# only that part. Every lane runs exactly these commands so that
# evaluation/parity/compare_lanes.py compares like with like.
set -euo pipefail

LANE="${1:?lane name}"
OUT="${2:?output root}"
shift 2
STEPS=("${@:-examples seeded scaling}")
[ ${#STEPS[@]} -eq 1 ] && read -r -a STEPS <<< "${STEPS[0]}"

PY="${PYTHON:-python3.11}"
export PYTHONPATH="${PYTHONPATH:-$PWD/src}"
export PYTHONNOUSERSITE=1
export CIPHERSCOPE_OPENFHE_LANE="$LANE"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
mkdir -p "$OUT"

log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }
has_step() { local s; for s in "${STEPS[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }

# Provenance for the comparison: which build produced everything below.
$PY - "$OUT/lane.json" "$LANE" <<'PYEOF'
import json, os, platform, sys
sys.path.insert(0, os.path.join(os.getcwd(), "src"))
import openfhe  # noqa: F401 - loaded so the fingerprint records the native-module hash
from cipherscope.fingerprint import build_fingerprint
out, lane = sys.argv[1:3]
document = {
    **build_fingerprint(),
    "lane": lane,
    "platform": platform.system(),
    "machine": platform.machine(),
    "python": platform.python_version(),
    "omp_num_threads": os.environ.get("OMP_NUM_THREADS"),
    "hostname": platform.node(),
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(json.dumps(document, sort_keys=True))
PYEOF

# ---------------------------------------------------------------------------
# Example gallery: the 16 programs examples/README.md verifies on macOS.
# ---------------------------------------------------------------------------
if has_step examples; then
  log "examples -> $OUT/examples"
  rm -rf "$OUT/examples"
  mkdir -p "$OUT/examples"
  UNMODIFIED=(
    examples/chebysev.py
    examples/dot_product.py
    examples/bootstrapping.py
    examples/synthetic/weighted_inner_product.py
    examples/synthetic/vector_variance.py
    examples/synthetic/polynomial_horner.py
    examples/synthetic/squared_distance.py
    examples/synthetic/matrix_vector_diag.py
    examples/synthetic/repeated_rotations.py
    examples/synthetic/bootstrap_then_idle.py
  )
  INSTRUMENTED=(
    examples/synthetic/annotate_packing.py
    examples/synthetic/public_constant_mult.py
    examples/synthetic/repeated_public_constant.py
    examples/synthetic/serial_reduction_region.py
    examples/synthetic/precision_checkpoints.py
  )
  run_example() {  # name, then the `cipherscope run` arguments after --output
    local name="$1"; shift
    log "  $name"
    if ! $PY -m cipherscope run --output "$OUT/examples/$name" "$@" > "$OUT/examples/$name.log" 2>&1; then
      log "  $name: cipherscope run exited nonzero (see $name.log); bundle kept if finalized"
    fi
  }
  run_example profiled_workload examples/profiled_workload.py -- --rotation 1 --rotation 2
  for target in "${UNMODIFIED[@]}"; do
    run_example "$(basename "$target" .py)" examples/profile_unmodified.py -- "$target"
  done
  for target in "${INSTRUMENTED[@]}"; do
    run_example "$(basename "$target" .py)" "$target"
  done
  for bundle in "$OUT"/examples/*/; do
    $PY -m cipherscope validate "$bundle" > "${bundle%/}.validate.json"
  done
  $PY -m cipherscope coverage "$OUT"/examples/*/ --output "$OUT/examples/coverage_report.csv" > "$OUT/examples/coverage.log"
  cat "$OUT/examples/coverage.log"
fi

# ---------------------------------------------------------------------------
# Seeded benchmark (27 known-answer cases) and the semantic ablation over its
# bundles -- the same commands as `make reproduce-small`.
# ---------------------------------------------------------------------------
if has_step seeded; then
  log "seeded -> $OUT/seeded"
  rm -rf "$OUT/seeded"
  $PY -m cipherscope seeded evaluation/seeded/ground_truth.json --output "$OUT/seeded" > "$OUT/seeded.log" 2>&1 \
    || log "  seeded exited nonzero (mismatch or failure); see $OUT/seeded.log"
  tail -3 "$OUT/seeded.log"
  log "ablation -> $OUT/semantic_ablation.csv"
  $PY -m cipherscope ablate "$OUT"/seeded/bundles/*/ --output "$OUT/semantic_ablation.csv" > "$OUT/ablate.log" 2>&1
  tail -2 "$OUT/ablate.log"
fi

# ---------------------------------------------------------------------------
# Scaling sweep, 10^2..10^5 events; one process per point.
# ---------------------------------------------------------------------------
if has_step scaling; then
  log "scaling -> $OUT/scaling.csv"
  rm -f "$OUT/scaling.csv"
  $PY evaluation/scaling/run_scaling.py --python "$(command -v "$PY")" --output "$OUT/scaling.csv" > "$OUT/scaling.log" 2>&1
  tail -1 "$OUT/scaling.log"
fi

log "done: $LANE"
