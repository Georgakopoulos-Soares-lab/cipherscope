#!/usr/bin/env python3
"""Profile a small real CKKS computation with OpenFHE and CipherScope."""

from __future__ import annotations

import argparse
import math
from typing import Sequence

import cipherscope
import openfhe


def _context(batch_size: int) -> tuple[object, object]:
    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(6)
    parameters.SetBatchSize(batch_size)
    parameters.SetNumLargeDigits(2)
    if openfhe.get_native_int() == 128:
        parameters.SetFirstModSize(89)
        parameters.SetScalingModSize(78)
        parameters.SetScalingTechnique(openfhe.ScalingTechnique.FIXEDAUTO)
    else:
        parameters.SetFirstModSize(60)
        parameters.SetScalingModSize(56)
        parameters.SetScalingTechnique(openfhe.ScalingTechnique.FLEXIBLEAUTO)

    context = openfhe.GenCryptoContext(parameters)
    context.Enable(openfhe.PKESchemeFeature.PKE)
    context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    return context, keys


def _max_error(observed: Sequence[complex], expected: Sequence[float]) -> float:
    return max(
        (abs(actual - target) for actual, target in zip(observed, expected)),
        default=0.0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rotation",
        action="append",
        type=int,
        dest="rotations",
        default=[],
        help="rotation index to execute; may be supplied more than once",
    )
    args = parser.parse_args()
    rotations = args.rotations or [1, 2]
    if len(set(rotations)) < 2:
        parser.error("supply at least two distinct rotations for the example")

    values = [0.25, 0.5, 0.75, 1.0]
    weights = [1.0, 1.5, 2.0, 2.5]
    native_context, keys = _context(len(values))
    plaintext_values = native_context.MakeCKKSPackedPlaintext(values)
    plaintext_weights = native_context.MakeCKKSPackedPlaintext(weights)

    # Under `cipherscope run`, trace() joins the runner-owned session. Every
    # cryptographic operation below is executed by the real OpenFHE binding.
    with cipherscope.trace(native_context, name="openfhe_profiled_workload") as session:
        cc = session.context
        generated_indices = sorted({*rotations, 4})
        cc.EvalRotateKeyGen(keys.secretKey, generated_indices)
        encrypted_values = cc.Encrypt(keys.publicKey, plaintext_values)
        encrypted_weights = cc.Encrypt(keys.publicKey, plaintext_weights)

        rotated = [cc.EvalRotate(encrypted_values, index) for index in rotations]
        combined = cc.EvalAdd(rotated[0], encrypted_weights)
        result = cc.EvalSquare(combined)

        # Exercise lazy multiplication, relinearization, explicit rescaling, and
        # in-place versioning on a separate branch. The independently checked
        # result above stays simple enough to give this example a clear oracle.
        lazy_product = cc.EvalMultNoRelin(encrypted_values, encrypted_weights)
        relinearized = cc.Relinearize(lazy_product)
        reduced = cc.Rescale(relinearized)
        cc.EvalSubInPlace(1.0, reduced)
        decrypted = cc.Decrypt(result, keys.secretKey)

    decrypted.SetLength(len(values))
    observed = [
        complex(value) for value in decrypted.GetCKKSPackedValue()[: len(values)]
    ]
    rotated_values = [*values[1:], values[0]]
    expected = [
        (rotated_value + weight) ** 2
        for rotated_value, weight in zip(rotated_values, weights)
    ]
    max_error = _max_error(observed, expected)
    if not math.isfinite(max_error) or max_error > 1e-3:
        raise RuntimeError(f"CKKS result exceeded tolerance: {max_error:.3e}")

    trace = session.to_trace()
    print(
        "real OpenFHE workload complete: "
        f"events={len(trace['events'])}, "
        f"max_abs_error={max_error:.3e}, "
        f"rotations={rotations}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
