"""Executable proof of the explicit proxy coverage boundary."""

from __future__ import annotations

import unittest

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

    def test_gap_01_operator_overload_bypasses_proxy(self) -> None:
        """GAP-01: ciphertext addition overload executes but emits no proxy event."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            result = left + right
        trace = session.to_trace()
        self.assertIsNotNone(result)
        self.assertEqual(trace["events"], [])
        self.assertFalse(trace["run"]["coverage"]["operator_overload_coverage"])
        support.record(
            "GAP-01",
            operator="ciphertext.__add__",
            result_type=type(result).__name__,
            emitted_events=0,
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
