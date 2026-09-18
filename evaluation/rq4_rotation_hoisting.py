#!/usr/bin/env python3
"""RQ4 flagship case: does the rotation.hoist_same_input.v1 finding's suggested
fix actually help?

`examples/synthetic/repeated_rotations.py` / `tests/cpp/fixtures/repeated_rotations.cpp`
rotate the same ciphertext by 1, 2 and 3 and sum the results -- the shape
CipherScope's rotation-hoisting analyzer flags, recommending "Test one
EvalFastRotationPrecompute shared by compatible EvalFastRotation calls."

This script builds both versions with OpenFHE's own Python API (the finding's
suggested transformation is a real OpenFHE technique, not a CipherScope
feature, so the "after" arm is measured directly against the library, not
through the tracer) and measures the isolated cost of the three-rotation
region -- not context setup, not key generation, not encryption -- over many
repetitions, alternating which arm goes first each round to cancel any warm-up
bias. Every repetition's "before" and "after" results are checked against the
same expected values so a speedup can never be reported alongside a wrong
answer.

    source ls6_env.sh
    PYTHONPATH=src python3 evaluation/rq4_rotation_hoisting.py --repeat 200 \\
        --output evaluation/raw/before_after.csv
"""

from __future__ import annotations

import argparse
import csv
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

COLUMNS = (
    "case_id", "arm", "repetition", "wall_ns", "openfhe_version", "python_version", "machine",
)


def _context():
    import openfhe

    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(1)
    parameters.SetScalingModSize(50)
    parameters.SetBatchSize(8)
    cc = openfhe.GenCryptoContext(parameters)
    cc.Enable(openfhe.PKESchemeFeature.PKE)
    cc.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    keys = cc.KeyGen()
    cc.EvalRotateKeyGen(keys.secretKey, [1, 2, 3])
    return cc, keys


def _decode(plaintext, length: int) -> list[float]:
    plaintext.SetLength(length)
    return [float(v) for v in plaintext.GetRealPackedValue()[:length]]


def _naive_rotate_sum(cc, ciph):
    r1 = cc.EvalRotate(ciph, 1)
    r2 = cc.EvalRotate(ciph, 2)
    r3 = cc.EvalRotate(ciph, 3)
    return cc.EvalAdd(cc.EvalAdd(r1, r2), r3)


def _hoisted_rotate_sum(cc, ciph, m: int):
    digits = cc.EvalFastRotationPrecompute(ciph)
    r1 = cc.EvalFastRotation(ciph, 1, m, digits)
    r2 = cc.EvalFastRotation(ciph, 2, m, digits)
    r3 = cc.EvalFastRotation(ciph, 3, m, digits)
    return cc.EvalAdd(cc.EvalAdd(r1, r2), r3)


def run(repeat: int, tolerance: float) -> list[dict[str, object]]:
    import openfhe

    cc, keys = _context()
    m = cc.GetCyclotomicOrder()
    data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    batch = len(data)
    expected = [data[(i + 1) % batch] + data[(i + 2) % batch] + data[(i + 3) % batch] for i in range(batch)]

    versions = {
        "openfhe_version": getattr(openfhe, "__version__", "unknown"),
        "python_version": platform.python_version(),
        "machine": platform.machine(),
    }
    rows: list[dict[str, object]] = []
    for repetition in range(repeat):
        plaintext = cc.MakeCKKSPackedPlaintext(data)
        ciph = cc.Encrypt(keys.publicKey, plaintext)
        # Alternate order each repetition so neither arm systematically benefits
        # from cache/branch-predictor warm-up from the one before it.
        arms = ("naive", "hoisted") if repetition % 2 == 0 else ("hoisted", "naive")
        results: dict[str, list[float]] = {}
        for arm in arms:
            start = time.perf_counter_ns()
            if arm == "naive":
                combined = _naive_rotate_sum(cc, ciph)
            else:
                combined = _hoisted_rotate_sum(cc, ciph, m)
            wall_ns = time.perf_counter_ns() - start
            plaintext_out = cc.Decrypt(keys.secretKey, combined)
            results[arm] = _decode(plaintext_out, batch)
            rows.append({"case_id": "rotation.hoist_same_input.v1:repeated_rotations", "arm": arm,
                         "repetition": repetition, "wall_ns": wall_ns, **versions})
        for arm, observed in results.items():
            worst = max(abs(a - b) for a, b in zip(observed, expected))
            if worst > tolerance:
                raise AssertionError(f"repetition {repetition} arm {arm}: max abs error {worst} > {tolerance}")
    return rows


def summarize(rows: list[dict[str, object]]) -> None:
    by_arm: dict[str, list[int]] = {}
    for row in rows:
        by_arm.setdefault(str(row["arm"]), []).append(int(row["wall_ns"]))
    stats = {arm: (statistics.mean(v), statistics.median(v), statistics.stdev(v)) for arm, v in by_arm.items()}
    for arm, (mean, median, stdev) in stats.items():
        print(f"{arm:8s} n={len(by_arm[arm]):4d} mean={mean/1e3:9.2f} us  median={median/1e3:9.2f} us  stdev={stdev/1e3:8.2f} us")
    if "naive" in stats and "hoisted" in stats:
        speedup_mean = stats["naive"][0] / stats["hoisted"][0]
        speedup_median = stats["naive"][1] / stats["hoisted"][1]
        print(f"speedup (naive/hoisted): mean={speedup_mean:.3f}x  median={speedup_median:.3f}x")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeat", type=int, default=200)
    parser.add_argument("--tolerance", type=float, default=1e-2)
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation" / "raw" / "before_after.csv")
    args = parser.parse_args(argv)

    rows = run(args.repeat, args.tolerance)
    summarize(rows)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
