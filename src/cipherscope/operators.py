"""Route ciphertext operator overloads through the traced context.

The OpenFHE Python binding lets an application write ``a + b`` for two
ciphertexts; the binding's ``Ciphertext.__add__`` forwards to
``CryptoContext::EvalAdd`` in C++, so the call never passes through the
session's proxy and the Python frontend used to miss it (gate check GAP-01).

While at least one session is active this module replaces each operator the
binding defines on the ciphertext type with a wrapper that:

* finds the session owning the left operand's crypto context
  (``ciphertext.GetCryptoContext()`` is the object the session attached to);
* if there is one and the operator maps to a covered operation, performs the
  operation through that session's proxy, so exactly one ``crypto_operation``
  event is recorded, with the same source attribution, states, lineage and
  overload the explicit ``cc.EvalAdd(a, b)`` call would produce;
* otherwise calls the binding's original operator unchanged.

The native operation still runs exactly once (inside the proxy, which is the
single native call site) and the result is what the original operator would
have returned. Installation is reference counted across sessions and the
original operators are restored when the last session closes, so nothing is
left patched in a process that no longer traces.

Only operators the binding actually defines are wrapped; the pinned wrapper
(v1.5.1.0) defines ``__add__`` for ciphertext + ciphertext. The mapping below
also covers ``__sub__``, ``__mul__``, ``__neg__`` and the in-place forms for
bindings that add them. Operands that are not ciphertexts (a scalar, a
plaintext) are passed to the proxy too; ``EvalAdd(ct, 2.0)`` is a covered
overload and is recorded as ``ct_scalar``.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .session import Session

# Dunder -> (canonical operation, argument order is (self, other)).
OPERATOR_OPERATIONS: dict[str, str] = {
    "__add__": "EvalAdd",
    "__sub__": "EvalSub",
    "__mul__": "EvalMult",
    "__neg__": "EvalNegate",
    "__iadd__": "EvalAddInPlace",
    "__isub__": "EvalSubInPlace",
    "__imul__": "EvalMult",
}
# In-place operators must return the mutated left operand.
_RETURNS_SELF = {"__iadd__", "__isub__", "__imul__"}

_LOCK = threading.RLock()
_ORIGINALS: dict[type, dict[str, Any]] = {}
_REFCOUNT: dict[type, int] = {}
_RESOLVER: Callable[[Any], "Session[Any] | None"] | None = None


def set_session_resolver(resolver: Callable[[Any], "Session[Any] | None"] | None) -> None:
    """Install the function that maps a ciphertext to the session owning its context."""

    global _RESOLVER
    with _LOCK:
        _RESOLVER = resolver


def _owning_session(ciphertext: Any) -> "Session[Any] | None":
    resolver = _RESOLVER
    if resolver is None:
        return None
    try:
        return resolver(ciphertext)
    except Exception:  # noqa: BLE001 - a lookup failure must never break the user's arithmetic
        return None


def _make_wrapper(name: str, original: Any, operation: str) -> Callable[..., Any]:
    if name == "__neg__":

        def unary(self: Any) -> Any:
            session = _owning_session(self)
            if session is None:
                return original(self)
            return session.context.EvalNegate(self)

        unary.__name__ = name
        unary.__qualname__ = f"traced.{name}"
        return unary

    def binary(self: Any, other: Any) -> Any:
        session = _owning_session(self)
        if session is None:
            return original(self, other)
        result = getattr(session.context, operation)(self, other)
        if name in _RETURNS_SELF:
            # EvalAddInPlace/EvalSubInPlace return None; a * b has no in-place form.
            return self if result is None else result
        return result

    binary.__name__ = name
    binary.__qualname__ = f"traced.{name}"
    return binary


def install(ciphertext_type: type) -> tuple[str, ...]:
    """Wrap the operators ``ciphertext_type`` defines; returns the wrapped dunder names.

    Idempotent per type: a second install only increments the reference count.
    A type that rejects attribute assignment yields an empty tuple and is left
    untouched; callers report ``operator_overload_coverage = False`` for it.
    """

    with _LOCK:
        if ciphertext_type in _ORIGINALS:
            _REFCOUNT[ciphertext_type] += 1
            return tuple(_ORIGINALS[ciphertext_type])
        originals: dict[str, Any] = {}
        for dunder, operation in OPERATOR_OPERATIONS.items():
            original = ciphertext_type.__dict__.get(dunder)
            if original is None:
                continue
            try:
                setattr(ciphertext_type, dunder, _make_wrapper(dunder, original, operation))
            except (TypeError, AttributeError):
                for restored, value in originals.items():
                    setattr(ciphertext_type, restored, value)
                return ()
            originals[dunder] = original
        if not originals:
            return ()
        _ORIGINALS[ciphertext_type] = originals
        _REFCOUNT[ciphertext_type] = 1
        return tuple(originals)


def uninstall(ciphertext_type: type) -> None:
    """Drop one reference; restore the original operators at zero."""

    with _LOCK:
        if ciphertext_type not in _ORIGINALS:
            return
        _REFCOUNT[ciphertext_type] -= 1
        if _REFCOUNT[ciphertext_type] > 0:
            return
        for dunder, original in _ORIGINALS.pop(ciphertext_type).items():
            setattr(ciphertext_type, dunder, original)
        del _REFCOUNT[ciphertext_type]


def installed_operators(ciphertext_type: type) -> tuple[str, ...]:
    with _LOCK:
        return tuple(_ORIGINALS.get(ciphertext_type, ()))


__all__ = ["OPERATOR_OPERATIONS", "install", "installed_operators", "set_session_resolver", "uninstall"]
