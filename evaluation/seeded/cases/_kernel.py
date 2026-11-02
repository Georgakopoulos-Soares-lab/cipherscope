"""Shared setup for the seeded cases. Nothing here runs under the tracer."""

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


def make_integer_context(
    depth: int,
    *,
    scheme: str = "BFV",
    plaintext_modulus: int = 65537,
    batch: int | None = 8,
    technique: str | None = None,
    advanced: bool = False,
):
    """A BFV or BGV context, the integer counterpart of ``make_context``.

    These schemes are exact, so cases built on this assert equality rather
    than a tolerance. BFV keeps its level at 0 for the whole run and records
    multiplicative growth in the noise scale degree instead; BGV spends levels
    like CKKS. The tracer reads whichever coordinate the scheme moves.
    """

    if scheme not in {"BFV", "BGV"}:
        raise ValueError(f"make_integer_context is for BFV or BGV, not {scheme!r}")
    parameters = (
        openfhe.CCParamsBFVRNS() if scheme == "BFV" else openfhe.CCParamsBGVRNS()
    )
    parameters.SetPlaintextModulus(plaintext_modulus)
    parameters.SetMultiplicativeDepth(depth)
    if batch is not None:
        parameters.SetBatchSize(batch)
    if technique is not None:
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


def decode_integers(plaintext, length: int) -> list[int]:
    plaintext.SetLength(length)
    return [int(value) for value in plaintext.GetPackedValue()[:length]]


def check_exact(observed: Sequence[int], expected: Sequence[int]) -> None:
    """Fail the case unless an exact scheme reproduced its expected result."""

    if list(observed) != list(expected):
        raise RuntimeError(f"exact mismatch: {list(observed)} != {list(expected)}")


def rotate_left(data: Sequence[int], amount: int, length: int) -> list[int]:
    """Model one ``EvalRotate`` on a packed integer vector.

    BFV and BGV shift left and fill with zeros rather than wrapping the batch
    the way CKKS does, which is verified by the rotation cases themselves.
    """

    return [data[i + amount] if i + amount < len(data) else 0 for i in range(length)]


def check_close(observed: Sequence[float], expected: Sequence[float]) -> None:
    """Fail the case if the decrypted result is numerically wrong."""

    if len(observed) != len(expected):
        raise RuntimeError(f"length mismatch: {len(observed)} != {len(expected)}")
    worst = max(abs(a - b) for a, b in zip(observed, expected))
    if worst > TOLERANCE:
        raise RuntimeError(f"numerical mismatch: max abs error {worst:.3e} > {TOLERANCE}")
