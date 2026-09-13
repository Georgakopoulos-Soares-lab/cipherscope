"""Dependency-free fake CKKS-shaped objects for core tests and examples."""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(eq=False)
class FakeCiphertext:
    """Metadata-only ciphertext stand-in; it performs no cryptography.

    ``decoded_values`` lets the fake stand in for a decrypted plaintext during
    precision-checkpoint tests.
    """

    level: int = 0
    noise_scale_degree: int = 1
    context_id: str = "fake_context_1"
    key_tag: str = "fake_key_1"
    scaling_technique: str = "FLEXIBLEAUTO"
    key_switch_technique: str = "HYBRID"
    decoded_values: list[float] | None = None

    def GetLevel(self) -> int:
        return self.level

    def GetNoiseScaleDeg(self) -> int:
        return self.noise_scale_degree

    def GetKeyTag(self) -> str:
        return self.key_tag


@dataclass(eq=False)
class FakePlaintext:
    """Plaintext-shaped result used for forwarding and shadow decoding."""

    marker: str = "fake_plaintext"
    values: list[float] | None = None
    _length: int | None = None

    def SetLength(self, length: int) -> None:
        self._length = length

    def GetRealPackedValue(self) -> list[float]:
        values = list(self.values or [])
        if self._length is not None:
            return values[: self._length]
        return values


@dataclass(eq=False)
class FakeParameters:
    """CCParams stand-in exposing the getters the real context cannot."""

    security_level: str = "HEStd_128_classic"
    ring_dim: int = 0
    multiplicative_depth: int = 8
    scaling_mod_size: int = 50

    def GetSecurityLevel(self) -> str:
        return self.security_level

    def GetRingDim(self) -> int:
        return self.ring_dim

    def GetMultiplicativeDepth(self) -> int:
        return self.multiplicative_depth

    def GetScalingModSize(self) -> int:
        return self.scaling_mod_size


class FakeCryptoContext:
    """Small OpenFHE-shaped backend with observable call counts.

    ``alias_operations`` is useful for registry tests. ``fail_operations`` maps
    an operation name to the exception that its single native invocation raises.
    """

    scheme = "CKKS"
    ring_dimension = 32768
    configured_multiplicative_depth = 8

    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.alias_operations: set[str] = set()
        self.fail_operations: dict[str, BaseException] = {}
        self._lock = threading.Lock()

    def _called(self, operation: str) -> None:
        with self._lock:
            self.calls[operation] += 1
        error = self.fail_operations.get(operation)
        if error is not None:
            raise error

    def GetRingDimension(self) -> int:
        self._called("GetRingDimension")
        return self.ring_dimension

    def Enable(self, feature: Any) -> None:
        del feature
        self._called("Enable")

    def Unclassified(self, value: Any) -> Any:
        self._called("Unclassified")
        return value

    def Encrypt(self, public_key: Any, plaintext: Any) -> FakeCiphertext:
        del public_key, plaintext
        self._called("Encrypt")
        return FakeCiphertext()

    def Decrypt(self, ciphertext: FakeCiphertext, private_key: Any) -> FakePlaintext:
        del private_key
        self._called("Decrypt")
        values = getattr(ciphertext, "decoded_values", None)
        return FakePlaintext(values=list(values) if values is not None else None)

    def EvalAdd(self, left: Any, right: Any) -> FakeCiphertext:
        self._called("EvalAdd")
        ciphertexts = self._ciphertext_operands(left, right)
        source = ciphertexts[0]
        if "EvalAdd" in self.alias_operations:
            return source
        return self._fresh(
            source,
            level=max(item.level for item in ciphertexts),
            noise=max(item.noise_scale_degree for item in ciphertexts),
        )

    def EvalAddInPlace(self, left: Any, right: Any) -> None:
        self._called("EvalAddInPlace")
        ciphertexts = self._ciphertext_operands(left, right)
        target = ciphertexts[0]
        target.level = max(item.level for item in ciphertexts)
        target.noise_scale_degree = max(item.noise_scale_degree for item in ciphertexts)

    def EvalSub(self, left: Any, right: Any) -> FakeCiphertext:
        self._called("EvalSub")
        ciphertexts = self._ciphertext_operands(left, right)
        source = ciphertexts[0]
        return self._fresh(
            source,
            level=max(item.level for item in ciphertexts),
            noise=max(item.noise_scale_degree for item in ciphertexts),
        )

    def EvalSubInPlace(self, left: Any, right: Any) -> None:
        self._called("EvalSubInPlace")
        ciphertexts = self._ciphertext_operands(left, right)
        target = ciphertexts[0]
        target.level = max(item.level for item in ciphertexts)
        target.noise_scale_degree = max(item.noise_scale_degree for item in ciphertexts)

    def EvalMult(self, left: FakeCiphertext, right: FakeCiphertext) -> FakeCiphertext:
        self._called("EvalMult")
        if "EvalMult" in self.alias_operations:
            return left
        return self._fresh(
            left,
            level=max(left.level, right.level) + 1,
            noise=max(left.noise_scale_degree, right.noise_scale_degree) + 1,
        )

    def EvalMultNoRelin(
        self, left: FakeCiphertext, right: FakeCiphertext
    ) -> FakeCiphertext:
        self._called("EvalMultNoRelin")
        return self._fresh(
            left,
            level=max(left.level, right.level) + 1,
            noise=max(left.noise_scale_degree, right.noise_scale_degree) + 1,
        )

    def EvalSquare(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("EvalSquare")
        return self._fresh(
            ciphertext,
            level=ciphertext.level + 1,
            noise=ciphertext.noise_scale_degree + 1,
        )

    def EvalSquareInPlace(self, ciphertext: FakeCiphertext) -> None:
        self._called("EvalSquareInPlace")
        ciphertext.level += 1
        ciphertext.noise_scale_degree += 1

    def Relinearize(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("Relinearize")
        return self._fresh(
            ciphertext,
            level=ciphertext.level,
            noise=ciphertext.noise_scale_degree,
        )

    def RelinearizeInPlace(self, ciphertext: FakeCiphertext) -> None:
        del ciphertext
        self._called("RelinearizeInPlace")

    def EvalNegate(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("EvalNegate")
        return self._fresh(
            ciphertext,
            level=ciphertext.level,
            noise=ciphertext.noise_scale_degree,
        )

    def EvalNegateInPlace(self, ciphertext: FakeCiphertext) -> None:
        del ciphertext
        self._called("EvalNegateInPlace")

    def ModReduce(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("ModReduce")
        return self._fresh(
            ciphertext,
            level=ciphertext.level + 1,
            noise=max(1, ciphertext.noise_scale_degree - 1),
        )

    def ModReduceInPlace(self, ciphertext: FakeCiphertext) -> None:
        self._called("ModReduceInPlace")
        ciphertext.level += 1
        ciphertext.noise_scale_degree = max(1, ciphertext.noise_scale_degree - 1)

    def Rescale(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("Rescale")
        return self._fresh(
            ciphertext,
            level=ciphertext.level + 1,
            noise=max(1, ciphertext.noise_scale_degree - 1),
        )

    def RescaleInPlace(self, ciphertext: FakeCiphertext) -> None:
        self._called("RescaleInPlace")
        ciphertext.level += 1
        ciphertext.noise_scale_degree = max(1, ciphertext.noise_scale_degree - 1)

    def EvalSum(self, ciphertext: FakeCiphertext, batch_size: int) -> FakeCiphertext:
        del batch_size
        self._called("EvalSum")
        return self._fresh(
            ciphertext,
            level=ciphertext.level,
            noise=ciphertext.noise_scale_degree,
        )

    def EvalRotate(self, ciphertext: FakeCiphertext, index: int) -> FakeCiphertext:
        del index
        self._called("EvalRotate")
        if "EvalRotate" in self.alias_operations:
            return ciphertext
        return self._fresh(
            ciphertext,
            level=ciphertext.level,
            noise=ciphertext.noise_scale_degree,
        )

    def EvalRotateKeyGen(self, private_key: Any, indices: list[int]) -> None:
        del private_key, indices
        self._called("EvalRotateKeyGen")

    def EvalBootstrap(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
        self._called("EvalBootstrap")
        if "EvalBootstrap" in self.alias_operations:
            return ciphertext
        return self._fresh(ciphertext, level=0, noise=1)

    @staticmethod
    def _ciphertext_operands(*values: Any) -> list[FakeCiphertext]:
        ciphertexts = [value for value in values if isinstance(value, FakeCiphertext)]
        if not ciphertexts:
            raise TypeError("the fake operation requires a ciphertext operand")
        return ciphertexts

    @staticmethod
    def _fresh(
        source: FakeCiphertext,
        *,
        level: int,
        noise: int,
    ) -> FakeCiphertext:
        return FakeCiphertext(
            level=level,
            noise_scale_degree=noise,
            context_id=source.context_id,
            key_tag=source.key_tag,
            scaling_technique=source.scaling_technique,
            key_switch_technique=source.key_switch_technique,
        )
