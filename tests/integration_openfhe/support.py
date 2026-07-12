"""Shared real-OpenFHE fixtures and bounded evidence collection.

Nothing in this module treats a skipped import as compatibility evidence. The
ordinary unittest suite may skip when OpenFHE is absent; ``run_gate.py`` turns
every required skip into a nonzero feasibility result.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import threading
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable, Sequence


try:
    import openfhe as fhe
except (ImportError, OSError):  # missing package or a non-loadable native module
    fhe = None


HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
GOLDEN = json.loads((HERE / "golden_core.json").read_text(encoding="utf-8"))
LANE = os.environ.get("CIPHERSCOPE_OPENFHE_LANE", "developer")
BOOTSTRAP_ENABLED = os.environ.get("CIPHERSCOPE_OPENFHE_BOOTSTRAP") == "1"

_EVIDENCE: dict[str, dict[str, Any]] = {}
_EVIDENCE_LOCK = threading.Lock()


def record(check_id: str, **observed: Any) -> None:
    """Record JSON-shaped observations for the authoritative gate artifact."""

    with _EVIDENCE_LOCK:
        _EVIDENCE[check_id] = _json_safe(observed)


def evidence() -> dict[str, dict[str, Any]]:
    with _EVIDENCE_LOCK:
        return json.loads(json.dumps(_EVIDENCE, sort_keys=True))


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return type(value).__name__


def require_openfhe() -> Any:
    if fhe is None:
        raise RuntimeError("the OpenFHE Python native module is unavailable")
    return fhe


def distribution_version() -> str | None:
    try:
        return metadata.version("openfhe")
    except metadata.PackageNotFoundError:
        return None


def native_module_hashes() -> dict[str, str]:
    module = require_openfhe()
    package_dir = Path(module.__file__).resolve().parent
    hashes: dict[str, str] = {}
    for path in sorted(package_dir.rglob("*")):
        if path.is_file() and path.suffix in {".so", ".pyd", ".dylib"}:
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def environment_snapshot() -> dict[str, Any]:
    os_release: dict[str, str] = {}
    release_path = Path("/etc/os-release")
    if release_path.is_file():
        for line in release_path.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    native_int = None
    if fhe is not None:
        native_int = fhe.get_native_int()
    return {
        "lane": LANE,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "executable": Path(sys.executable).name,
        "platform": platform.system(),
        "machine": platform.machine(),
        "os_release": os_release,
        "distribution_version": distribution_version(),
        "native_int": native_int,
        "native_module_hashes": native_module_hashes() if fhe is not None else {},
    }


def enum_name(value: Any) -> str | None:
    name = getattr(value, "name", None)
    return name if isinstance(name, str) and name else None


def decrypt_values(
    context: Any, secret_key: Any, ciphertext: Any, length: int
) -> list[complex]:
    plaintext = context.Decrypt(ciphertext, secret_key)
    plaintext.SetLength(length)
    return [complex(item) for item in plaintext.GetCKKSPackedValue()[:length]]


def max_abs_error(
    left: Sequence[complex | float], right: Sequence[complex | float]
) -> float:
    if len(left) != len(right):
        raise AssertionError(f"length mismatch: {len(left)} != {len(right)}")
    return max((abs(complex(a) - complex(b)) for a, b in zip(left, right)), default=0.0)


def add_expected(left: Sequence[float], right: Sequence[float]) -> list[float]:
    return [a + b for a, b in zip(left, right)]


def mult_expected(left: Sequence[float], right: Sequence[float]) -> list[float]:
    return [a * b for a, b in zip(left, right)]


def rotate_expected(values: Sequence[float], index: int) -> list[float]:
    normalized = index % len(values)
    return [*values[normalized:], *values[:normalized]]


@dataclass(frozen=True)
class BasicFixture:
    parameters: Any
    context: Any
    keys: Any
    a: tuple[float, ...]
    b: tuple[float, ...]
    batch_size: int

    def encrypt(self, values: Sequence[float]) -> Any:
        plaintext = self.context.MakeCKKSPackedPlaintext(list(values))
        return self.context.Encrypt(self.keys.publicKey, plaintext)


@lru_cache(maxsize=1)
def basic_fixture() -> BasicFixture:
    module = require_openfhe()
    batch_size = int(GOLDEN["batch_size"])
    parameters = module.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(5)
    native_int = module.get_native_int()
    if native_int == 128:
        parameters.SetFirstModSize(89)
        parameters.SetScalingModSize(78)
        parameters.SetScalingTechnique(module.ScalingTechnique.FIXEDAUTO)
    elif native_int == 64:
        parameters.SetFirstModSize(60)
        parameters.SetScalingModSize(56)
        parameters.SetScalingTechnique(module.ScalingTechnique.FLEXIBLEAUTO)
    else:
        raise RuntimeError(f"unsupported OpenFHE native integer width: {native_int}")
    parameters.SetBatchSize(batch_size)
    parameters.SetNumLargeDigits(2)

    context = module.GenCryptoContext(parameters)
    context.Enable(module.PKESchemeFeature.PKE)
    context.Enable(module.PKESchemeFeature.KEYSWITCH)
    context.Enable(module.PKESchemeFeature.LEVELEDSHE)
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    context.EvalRotateKeyGen(keys.secretKey, list(GOLDEN["rotation_indices"]))
    return BasicFixture(
        parameters=parameters,
        context=context,
        keys=keys,
        a=tuple(float(item) for item in GOLDEN["a"]),
        b=tuple(float(item) for item in GOLDEN["b"]),
        batch_size=batch_size,
    )


@dataclass(frozen=True)
class BootstrapFixture:
    context: Any
    keys: Any
    values: tuple[float, ...]
    depth: int
    slots: int
    level_budget: tuple[int, int]

    def encrypt_at_last_level(self) -> Any:
        plaintext = self.context.MakeCKKSPackedPlaintext(
            list(self.values), 1, self.depth - 1
        )
        plaintext.SetLength(len(self.values))
        return self.context.Encrypt(self.keys.publicKey, plaintext)


@lru_cache(maxsize=1)
def bootstrap_fixture() -> BootstrapFixture:
    module = require_openfhe()
    parameters = module.CCParamsCKKSRNS()
    secret_key_dist = module.SecretKeyDist.UNIFORM_TERNARY
    parameters.SetSecretKeyDist(secret_key_dist)
    parameters.SetSecurityLevel(module.SecurityLevel.HEStd_NotSet)
    parameters.SetRingDim(1 << 12)
    if module.get_native_int() == 128:
        parameters.SetScalingTechnique(module.ScalingTechnique.FIXEDAUTO)
        parameters.SetScalingModSize(78)
        parameters.SetFirstModSize(89)
    else:
        parameters.SetScalingTechnique(module.ScalingTechnique.FLEXIBLEAUTO)
        parameters.SetScalingModSize(59)
        parameters.SetFirstModSize(60)
    level_budget = (4, 4)
    depth = 10 + module.FHECKKSRNS.GetBootstrapDepth(
        list(level_budget), secret_key_dist
    )
    parameters.SetMultiplicativeDepth(depth)
    context = module.GenCryptoContext(parameters)
    for feature in (
        module.PKESchemeFeature.PKE,
        module.PKESchemeFeature.KEYSWITCH,
        module.PKESchemeFeature.LEVELEDSHE,
        module.PKESchemeFeature.ADVANCEDSHE,
        module.PKESchemeFeature.FHE,
    ):
        context.Enable(feature)
    slots = context.GetRingDimension() // 2
    context.EvalBootstrapSetup(list(level_budget))
    keys = context.KeyGen()
    context.EvalMultKeyGen(keys.secretKey)
    context.EvalBootstrapKeyGen(keys.secretKey, slots)
    return BootstrapFixture(
        context=context,
        keys=keys,
        values=tuple(float(item) for item in GOLDEN["a"]),
        depth=depth,
        slots=slots,
        level_budget=level_budget,
    )


class CountingContext:
    """Delegating real-backend adapter used to prove exactly-once forwarding."""

    def __init__(self, context: Any) -> None:
        self.context = context
        self.calls: Counter[str] = Counter()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.context, name)

    def EvalAdd(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalAdd"] += 1
        return self.context.EvalAdd(*args, **kwargs)

    def EvalAddInPlace(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalAddInPlace"] += 1
        return self.context.EvalAddInPlace(*args, **kwargs)

    def EvalMult(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalMult"] += 1
        return self.context.EvalMult(*args, **kwargs)

    def EvalRotate(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalRotate"] += 1
        return self.context.EvalRotate(*args, **kwargs)

    def EvalBootstrap(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalBootstrap"] += 1
        return self.context.EvalBootstrap(*args, **kwargs)

    def EvalSub(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalSub"] += 1
        return self.context.EvalSub(*args, **kwargs)

    def EvalAddMany(self, *args: Any, **kwargs: Any) -> Any:
        self.calls["EvalAddMany"] += 1
        return self.context.EvalAddMany(*args, **kwargs)


def unique_by_identity(values: Iterable[Any]) -> int:
    seen: dict[int, Any] = {}
    for value in values:
        if seen.get(id(value)) is not value:
            seen[id(value)] = value
    return len(seen)
