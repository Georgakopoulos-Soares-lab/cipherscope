"""Shadow-mode precision metrics computed from opt-in decoded checkpoints.

These helpers run only when the caller has explicitly enabled shadow mode and
supplied expected values. They emit aggregate error metrics; the compared values
themselves are never returned for serialization.
"""

from __future__ import annotations

import math
import sys
from collections.abc import Sequence
from typing import Any

_MACHINE_EPSILON = sys.float_info.epsilon
_ZERO_THRESHOLD = 1e-12


def _magnitude(value: Any) -> float:
    if isinstance(value, complex):
        return abs(value)
    return abs(float(value))


def precision_metrics(
    expected: Sequence[Any], observed: Sequence[Any]
) -> dict[str, Any]:
    """Return aggregate precision metrics for aligned expected/observed slots.

    A length mismatch is reported as a failed checkpoint rather than silently
    truncated. Relative metrics are ``None`` when every reference slot is near
    zero, matching the documented ``not_applicable`` case.
    """

    expected_list = list(expected)
    observed_list = list(observed)
    slot_count = len(expected_list)
    if slot_count == 0 or len(observed_list) != slot_count:
        return {
            "status": "failed",
            "reason": "shape_mismatch",
            "expected_slots": slot_count,
            "observed_slots": len(observed_list),
        }

    abs_errors = [
        _magnitude(observed_list[index] - expected_list[index])
        for index in range(slot_count)
    ]
    max_abs_error = max(abs_errors)
    rmse = math.sqrt(sum(error * error for error in abs_errors) / slot_count)
    absolute_bits = -math.log2(max(max_abs_error, _MACHINE_EPSILON))

    relative_candidates = [
        abs_errors[index] / _magnitude(expected_list[index])
        for index in range(slot_count)
        if _magnitude(expected_list[index]) > _ZERO_THRESHOLD
    ]
    relative_error: float | None = None
    relative_bits: float | None = None
    if relative_candidates:
        worst_relative = max(relative_candidates)
        relative_error = worst_relative
        relative_bits = -math.log2(max(worst_relative, _MACHINE_EPSILON))

    return {
        "status": "ok",
        "slot_count": slot_count,
        "max_abs_error": max_abs_error,
        "rmse": rmse,
        "absolute_bits": absolute_bits,
        "relative_error": relative_error,
        "relative_bits": relative_bits,
    }


def decode_real(plaintext: Any, length: int) -> list[float]:
    """Decode the leading ``length`` real slots from an OpenFHE-shaped plaintext.

    The plaintext is treated as opaque: only the documented packed-value getters
    are used, and no representation of the object is produced.
    """

    set_length = getattr(plaintext, "SetLength", None)
    if callable(set_length):
        set_length(length)
    for getter_name in ("GetRealPackedValue", "GetCKKSPackedValue"):
        getter = getattr(plaintext, getter_name, None)
        if callable(getter):
            values = getter()
            return [
                value.real if isinstance(value, complex) else float(value)
                for value in list(values)[:length]
            ]
    raise TypeError("the plaintext exposes no supported packed-value getter")


__all__ = ["decode_real", "precision_metrics"]
