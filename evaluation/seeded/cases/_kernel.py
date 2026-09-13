"""Shared CKKS setup for the seeded cases. Nothing here runs under the tracer."""

from __future__ import annotations

from collections.abc import Sequence

import openfhe

TOLERANCE = 1e-2


def make_context(
    depth: int,
    *,
    technique: str = "FLEXIBLEAUTO",
    batch: int | None = 8,
    advanced: bool = False,
):
    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(depth)
    parameters.SetScalingModSize(50)
    if batch is not None:
        parameters.SetBatchSize(batch)
    parameters.SetScalingTechnique(getattr(openfhe.ScalingTechnique, technique))
    context = openfhe.GenCryptoContext(parameters)
    context.Enable(openfhe.PKESchemeFeature.PKE)
    context.Enable(openfhe.PKESchemeFeature.KEYSWITCH)
    context.Enable(openfhe.PKESchemeFeature.LEVELEDSHE)
    if advanced:
        context.Enable(openfhe.PKESchemeFeature.ADVANCEDSHE)
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    return context, keys


def decode(plaintext, length: int) -> list[float]:
    plaintext.SetLength(length)
    return [float(value) for value in plaintext.GetRealPackedValue()[:length]]


def check_close(observed: Sequence[float], expected: Sequence[float]) -> None:
    """Fail the case if the decrypted result is numerically wrong."""

    if len(observed) != len(expected):
        raise RuntimeError(f"length mismatch: {len(observed)} != {len(expected)}")
    worst = max(abs(a - b) for a, b in zip(observed, expected))
    if worst > TOLERANCE:
        raise RuntimeError(f"numerical mismatch: max abs error {worst:.3e} > {TOLERANCE}")
