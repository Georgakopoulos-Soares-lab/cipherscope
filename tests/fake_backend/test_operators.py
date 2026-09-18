"""Ciphertext operator overloads are traced through the owning session.

The binding's ``Ciphertext.__add__`` forwards to ``EvalAdd`` in C++ and never
touches the proxy. While a session owns a ciphertext's context, the operator
is rerouted through ``session.context`` so it produces exactly one event; when
no session owns it, the original operator runs untouched; the original is
restored when the last session closes.
"""

from __future__ import annotations

import sys
import types
import unittest

import cipherscope
from cipherscope import operators
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


class OperatorCiphertext(FakeCiphertext):
    """A ciphertext type with the operators the pinned binding defines."""

    context: FakeCryptoContext | None = None
    native_operator_calls = 0

    def GetCryptoContext(self) -> FakeCryptoContext | None:
        return self.context

    def __add__(self, other: "OperatorCiphertext") -> "OperatorCiphertext":
        type(self).native_operator_calls += 1
        result = self.context.EvalAdd(self, other) if self.context else OperatorCiphertext()
        result.context = self.context
        return result


class OperatorBackend(FakeCryptoContext):
    def EvalAdd(self, left, right):  # type: ignore[override]
        result = super().EvalAdd(left, right)
        wrapped = OperatorCiphertext(level=result.level, noise_scale_degree=result.noise_scale_degree)
        wrapped.context = self
        return wrapped

    def Encrypt(self, key, plaintext):  # type: ignore[override]
        wrapped = OperatorCiphertext()
        wrapped.context = self
        self.calls["Encrypt"] += 1
        return wrapped


# The session finds the ciphertext type through the context's module, as it
# does for `openfhe.Ciphertext`; give the backend a module that exports it.
_MODULE = types.ModuleType("fake_operator_binding")
_MODULE.Ciphertext = OperatorCiphertext
OperatorBackend.__module__ = _MODULE.__name__
sys.modules[_MODULE.__name__] = _MODULE


class OperatorOverloadTests(unittest.TestCase):
    def setUp(self) -> None:
        OperatorCiphertext.native_operator_calls = 0
        self.original = OperatorCiphertext.__dict__["__add__"]

    def test_operator_inside_a_session_is_one_traced_event(self) -> None:
        backend = OperatorBackend()
        a = backend.Encrypt(None, None)
        b = backend.Encrypt(None, None)
        with cipherscope.trace(backend) as session:
            self.assertIsNot(OperatorCiphertext.__dict__["__add__"], self.original)
            c = a + b
            self.assertIsInstance(c, OperatorCiphertext)
        trace = session.to_trace()
        events = [e for e in trace["events"] if e["kind"] == "crypto_operation"]
        self.assertEqual([e["operation"] for e in events], ["EvalAdd"])
        self.assertEqual(events[0]["overload"], "ct_ct")
        self.assertEqual(len(events[0]["input_ciphertexts"]), 2)
        self.assertEqual(len(events[0]["output_ciphertexts"]), 1)
        self.assertEqual(backend.calls["EvalAdd"], 1, "the native operation runs exactly once")
        self.assertEqual(OperatorCiphertext.native_operator_calls, 0, "the binding's operator body was bypassed, not run twice")
        self.assertTrue(trace["run"]["coverage"]["operator_overload_coverage"])
        self.assertIs(OperatorCiphertext.__dict__["__add__"], self.original, "restored at close")

    def test_ciphertext_of_an_unowned_context_uses_the_original_operator(self) -> None:
        traced = OperatorBackend()
        other = OperatorBackend()
        x = other.Encrypt(None, None)
        y = other.Encrypt(None, None)
        with cipherscope.trace(traced) as session:
            z = x + y
        self.assertIsNotNone(z)
        self.assertEqual(OperatorCiphertext.native_operator_calls, 1)
        self.assertEqual([e for e in session.to_trace()["events"] if e["kind"] == "crypto_operation"], [])

    def test_joined_scope_keeps_the_hook_until_the_owning_session_closes(self) -> None:
        # A nested trace() joins the active session as a scope; both contexts
        # are owned by one session, so one installation serves both and the
        # hook survives the inner scope's exit.
        backend_a, backend_b = OperatorBackend(), OperatorBackend()
        with cipherscope.trace(backend_a) as session:
            self.assertEqual(operators.installed_operators(OperatorCiphertext), ("__add__",))
            with cipherscope.trace(backend_b):
                x = backend_b.Encrypt(None, None)
                _ = x + x
            self.assertEqual(operators.installed_operators(OperatorCiphertext), ("__add__",))
            p = backend_a.Encrypt(None, None)
            _ = p + p
        self.assertEqual(operators.installed_operators(OperatorCiphertext), ())
        events = [e for e in session.to_trace()["events"] if e["kind"] == "crypto_operation"]
        self.assertEqual([e["operation"] for e in events], ["EvalAdd", "EvalAdd"])
        self.assertEqual(backend_a.calls["EvalAdd"], 1)
        self.assertEqual(backend_b.calls["EvalAdd"], 1)

    def test_type_without_operators_reports_no_coverage(self) -> None:
        backend = FakeCryptoContext()  # its module exports no Ciphertext type
        with cipherscope.trace(backend) as session:
            pass
        self.assertFalse(session.to_trace()["run"]["coverage"]["operator_overload_coverage"])

    def test_install_is_reference_counted(self) -> None:
        self.assertEqual(operators.install(OperatorCiphertext), ("__add__",))
        self.assertEqual(operators.install(OperatorCiphertext), ("__add__",))
        operators.uninstall(OperatorCiphertext)
        self.assertIsNot(OperatorCiphertext.__dict__["__add__"], self.original)
        operators.uninstall(OperatorCiphertext)
        self.assertIs(OperatorCiphertext.__dict__["__add__"], self.original)


if __name__ == "__main__":
    unittest.main()
