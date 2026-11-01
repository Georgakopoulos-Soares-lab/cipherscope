"""Shared scaffolding for the before/after impact cases.

Every case module exposes ``build(variant)`` returning a ``Case``. The runner
drives it in two modes with the same code path:

* timed  -- ``prepare()`` (raw context + keys, untraced), ``setup(cc)`` and
            ``workload(cc, session=None)`` on the raw context; each phase is
            timed separately because for some rules the benefit lands in
            setup (key generation, context size), for others in the workload;
* traced -- the same ``setup``/``workload`` through ``session.context`` so
            CipherScope observes it; annotations are attached only when a
            session is present. The resulting bundle is what proves the rule
            fires on ``before`` and is silent on ``after``.

``check(result)`` returns the maximum absolute error against a plaintext
reference, so no speedup is ever reported alongside a wrong answer.
"""

from __future__ import annotations

from typing import Any, Sequence


def ckks_context(
    depth: int,
    *,
    scaling_mod_size: int = 50,
    first_mod_size: int = 60,
    batch: int | None = None,
    technique: str = "FLEXIBLEAUTO",
    security: str = "HEStd_128_classic",
    ring_dim: int | None = None,
    features: Sequence[str] = ("PKE", "KEYSWITCH", "LEVELEDSHE"),
):
    import openfhe  # the binding is only needed to run a case, not to describe it

    parameters = openfhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(depth)
    parameters.SetScalingModSize(scaling_mod_size)
    parameters.SetFirstModSize(first_mod_size)
    parameters.SetScalingTechnique(getattr(openfhe.ScalingTechnique, technique))
    parameters.SetSecurityLevel(getattr(openfhe.SecurityLevel, security))
    if ring_dim is not None:
        parameters.SetRingDim(ring_dim)
    if batch is not None:
        parameters.SetBatchSize(batch)
    context = openfhe.GenCryptoContext(parameters)
    for feature in features:
        context.Enable(getattr(openfhe.PKESchemeFeature, feature))
    return context, parameters


def decode(plaintext, length: int) -> list[float]:
    plaintext.SetLength(length)
    return [float(v) for v in plaintext.GetRealPackedValue()[:length]]


def max_abs_error(observed: Sequence[float], expected: Sequence[float]) -> float:
    return max(abs(float(a) - float(b)) for a, b in zip(observed, expected))


class Case:
    """Base class; subclasses set ``rule``/``name`` and implement the phases."""

    rule: str = ""
    name: str = ""
    variant: str = ""
    # Extra keyword arguments for cipherscope.trace() (parameters=..., allow_testing_security=..., shadow_mode/secret_key).
    trace_kwargs: dict[str, Any]
    # Case-specific scalar metrics the runner should copy into its report (e.g. precision bits).
    extra_metrics: dict[str, float]
    # Largest acceptable max-abs-error for check(); a run above it is a failed run, never a data point.
    tolerance: float = 1e-3

    def __init__(self, variant: str) -> None:
        self.variant = variant
        self.trace_kwargs = {}
        self.extra_metrics = {}
        self.context = None
        self.parameters = None
        self.keys = None

    def prepare(self) -> None:
        raise NotImplementedError

    def setup(self, cc) -> None:  # noqa: D401 - phase hook
        """Traced-able setup (rotation keys, bootstrap keys, constant encodings)."""

    def workload(self, cc, session=None):
        raise NotImplementedError

    def check(self, result) -> float:
        raise NotImplementedError

    def ring_dimension(self) -> int:
        return int(self.context.GetRingDimension())
