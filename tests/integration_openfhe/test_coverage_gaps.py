"""Executable proof of the explicit proxy coverage boundary."""

from __future__ import annotations

import unittest
from pathlib import Path

import cipherscope

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class CoverageGapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_gap_01_operator_overload_is_traced(self) -> None:
        """GAP-01: ciphertext operator overloads are rerouted through the proxy and traced once."""

        fhe = support.require_openfhe()
        ciphertext_type = fhe.Ciphertext
        defined = sorted(name for name in ("__add__", "__sub__", "__mul__", "__neg__") if name in ciphertext_type.__dict__)
        originals = {name: ciphertext_type.__dict__[name] for name in defined}
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        raw = left + right  # the binding's own operator, outside any session
        with cipherscope.trace(self.fixture.context) as session:
            self.assertTrue(all(ciphertext_type.__dict__[name] is not originals[name] for name in defined))
            traced = left + right
        trace = session.to_trace()
        # Restored at close: the process is not left patched.
        self.assertTrue(all(ciphertext_type.__dict__[name] is originals[name] for name in defined))
        events = [event for event in trace["events"] if event["kind"] == "crypto_operation"]
        self.assertEqual([event["operation"] for event in events], ["EvalAdd"])
        self.assertEqual(events[0]["overload"], "ct_ct")
        self.assertEqual(len(events[0]["input_ciphertexts"]), 2)
        self.assertEqual(len(events[0]["output_ciphertexts"]), 1)
        self.assertEqual(events[0]["source"]["file"], str(Path(__file__).resolve()))
        self.assertTrue(trace["run"]["coverage"]["operator_overload_coverage"])
        traced_values = support.decrypt_values(
            self.fixture.context, self.fixture.keys.secretKey, traced, self.fixture.batch_size
        )
        raw_values = support.decrypt_values(
            self.fixture.context, self.fixture.keys.secretKey, raw, self.fixture.batch_size
        )
        error = support.max_abs_error(traced_values, raw_values)
        self.assertLessEqual(error, support.GOLDEN["direct_vs_traced_tolerance"] * 1e4)
        expected_error = support.max_abs_error(
            traced_values, support.add_expected(self.fixture.a, self.fixture.b)
        )
        self.assertLessEqual(expected_error, support.GOLDEN["basic_max_abs_tolerance"])
        support.record(
            "GAP-01",
            operators_defined_by_binding=defined,
            operators_traced=defined,
            emitted_events=len(events),
            max_traced_vs_raw_error=error,
            max_expected_error=expected_error,
            restored_after_close=True,
        )

    def test_gap_02_original_context_reference_bypasses_proxy(self) -> None:
        """GAP-02: a raw-context call executes but is not observable by the proxy."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            result = self.fixture.context.EvalAdd(left, right)
        trace = session.to_trace()
        self.assertIsNotNone(result)
        self.assertEqual(trace["events"], [])
        self.assertFalse(
            trace["run"]["coverage"]["original_reference_bypass_observable"]
        )
        support.record("GAP-02", emitted_events=0, raw_call_succeeded=True)

    def test_gap_03_module_level_callable_inventory(self) -> None:
        """GAP-03: module-level FHE callables are inventoried without coverage claims."""

        module = support.require_openfhe()
        names = sorted(
            name
            for name in dir(module)
            if name.startswith("Eval") and callable(getattr(module, name, None))
        )
        self.assertIsInstance(names, list)
        support.record(
            "GAP-03",
            module_level_eval_callables=names,
            free_function_coverage=False,
        )

    def test_gap_04_strict_and_permissive_eval_add_many(self) -> None:
        """GAP-04: an uncovered composite rejects or is counted as passthrough."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        strict_adapter = support.CountingContext(self.fixture.context)
        with cipherscope.trace(strict_adapter) as strict_session:
            with self.assertRaises(cipherscope.UnsupportedOperationError):
                strict_session.context.EvalAddMany([left, right])
        strict_coverage = strict_session.to_trace()["run"]["coverage"]
        self.assertEqual(strict_adapter.calls["EvalAddMany"], 0)
        self.assertEqual(strict_coverage["rejected_unclassified_calls"], 1)

        permissive_adapter = support.CountingContext(self.fixture.context)
        with cipherscope.trace(permissive_adapter, strict=False) as permissive_session:
            result = permissive_session.context.EvalAddMany([left, right])
        permissive_trace = permissive_session.to_trace()
        permissive_coverage = permissive_trace["run"]["coverage"]
        self.assertIsNotNone(result)
        self.assertEqual(permissive_adapter.calls["EvalAddMany"], 1)
        self.assertEqual(permissive_trace["events"], [])
        self.assertEqual(permissive_coverage["unclassified_proxy_passthrough_calls"], 1)
        self.assertTrue(permissive_coverage["potentially_incomplete"])
        support.record(
            "GAP-04",
            strict_native_calls=0,
            strict_rejections=1,
            permissive_native_calls=1,
            permissive_events=0,
            potentially_incomplete=True,
        )


if __name__ == "__main__":
    unittest.main()
