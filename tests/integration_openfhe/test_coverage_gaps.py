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

    def test_api_07_vector_composites_series_and_aliases_are_covered(self) -> None:
        """API-07: EvalAddMany/EvalMultMany/EvalLinearWSum, EvalChebyshevSeries and EvalAtIndex are covered under canonical names."""

        a = self.fixture.encrypt(self.fixture.a)
        b = self.fixture.encrypt(self.fixture.b)
        c = self.fixture.encrypt(self.fixture.a)
        adapter = support.CountingContext(self.fixture.context)
        with cipherscope.trace(adapter) as session:
            many = [a, b, c]
            total = session.context.EvalAddMany(many)
            product = session.context.EvalMultMany(many)
            weighted = session.context.EvalLinearWSum(many, [0.5, 0.25, 0.25])
            series = session.context.EvalChebyshevSeries(a, [0.5, 0.25, 0.125, 0.0625], -8.0, 8.0)
            rotated = session.context.EvalAtIndex(total, 1)
        trace = session.to_trace()
        events = [e for e in trace["events"] if e["kind"] == "crypto_operation"]
        self.assertEqual([e["operation"] for e in events],
                         ["EvalAddMany", "EvalMultMany", "EvalLinearWSum", "EvalChebyshevSeries", "EvalRotate"])
        by_op = {e["operation"]: e for e in events}
        inputs = [c["id"] for c in trace["ciphertexts"] if c["origin"] != "derived"]
        for name in ("EvalAddMany", "EvalMultMany", "EvalLinearWSum"):
            self.assertEqual(len(by_op[name]["input_ciphertexts"]), 3, name)
            self.assertEqual(by_op[name]["semantic_arguments"], {"operand_count": 3}, name)
            self.assertEqual(by_op[name]["operand_kinds"][0], "collection", name)
            self.assertEqual(len(by_op[name]["output_ciphertexts"]), 1, name)
        self.assertEqual(by_op["EvalChebyshevSeries"]["semantic_arguments"],
                         {"polynomial_degree": 3, "lower_bound": -8.0, "upper_bound": 8.0})
        self.assertEqual(by_op["EvalRotate"]["semantic_arguments"], {"rotation_index_requested": 1})
        self.assertEqual(by_op["EvalRotate"]["input_ciphertexts"], by_op["EvalAddMany"]["output_ciphertexts"])
        self.assertEqual(trace["run"]["coverage"]["rejected_unclassified_calls"], 0)
        # Numerically the composites are what the direct API computes.
        secret = self.fixture.keys.secretKey
        length = len(self.fixture.a)
        expected_sum = [2 * x + y for x, y in zip(self.fixture.a, self.fixture.b)]
        observed_sum = support.decrypt_values(self.fixture.context, secret, total, length)
        self.assertLess(support.max_abs_error(observed_sum, expected_sum), 1e-3)
        expected_weighted = [0.75 * x + 0.25 * y for x, y in zip(self.fixture.a, self.fixture.b)]
        observed_weighted = support.decrypt_values(self.fixture.context, secret, weighted, length)
        self.assertLess(support.max_abs_error(observed_weighted, expected_weighted), 1e-3)
        self.assertIsNotNone(product)
        self.assertIsNotNone(series)
        self.assertIsNotNone(rotated)
        support.record(
            "API-07",
            operations=[e["operation"] for e in events],
            operand_counts={name: by_op[name]["semantic_arguments"]["operand_count"] for name in ("EvalAddMany", "EvalMultMany", "EvalLinearWSum")},
            chebyshev=by_op["EvalChebyshevSeries"]["semantic_arguments"],
            alias_recorded_as="EvalRotate",
            max_abs_error_sum=support.max_abs_error(observed_sum, expected_sum),
            fresh_inputs=len(inputs),
        )

    def test_api_08_bfv_and_bgv_contexts_are_traced_with_their_scheme(self) -> None:
        """API-08: BFV and BGV contexts report their scheme, N packed slots and plaintext modulus; integer arithmetic is traced."""

        fhe = support.require_openfhe()
        observed: dict[str, dict[str, object]] = {}
        for scheme, params_type in (("BFV", fhe.CCParamsBFVRNS), ("BGV", fhe.CCParamsBGVRNS)):
            with self.subTest(scheme=scheme):
                parameters = params_type()
                parameters.SetPlaintextModulus(65537)
                parameters.SetMultiplicativeDepth(2)
                native = fhe.GenCryptoContext(parameters)
                native.Enable(fhe.PKESchemeFeature.PKE)
                native.Enable(fhe.PKESchemeFeature.KEYSWITCH)
                native.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
                native.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
                with cipherscope.trace(native, parameters=parameters) as session:
                    cc = session.context
                    keys = cc.KeyGen()
                    cc.EvalMultKeyGen(keys.secretKey)
                    x = [1, 2, 3, 4, 5, 6, 7, 8]
                    y = [8, 7, 6, 5, 4, 3, 2, 1]
                    a = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(x))
                    b = cc.Encrypt(keys.publicKey, cc.MakePackedPlaintext(y))
                    total = cc.EvalAddMany([a, b, a])
                    product = cc.EvalMult(a, b)
                    result = cc.EvalSub(product, total)
                    plaintext = cc.Decrypt(result, keys.secretKey)
                plaintext.SetLength(8)
                values = list(plaintext.GetPackedValue())
                self.assertEqual(values, [p * q - (2 * p + q) for p, q in zip(x, y)])
                trace = session.to_trace()
                context = trace["context"]
                ring = context["ring_dimension"]
                self.assertEqual(context["scheme"], scheme)
                self.assertEqual(context["scheme_evidence"], "declared_parameters")
                self.assertIsInstance(ring, int)
                self.assertEqual(context["available_slots"], ring)
                self.assertEqual(context["batch_size"], ring)
                self.assertEqual(context["plaintext_modulus"], 65537)
                operations = [e["operation"] for e in trace["events"]]
                self.assertEqual(operations, ["KeyGen", "EvalMultKeyGen", "MakePackedPlaintext", "Encrypt", "MakePackedPlaintext",
                                              "Encrypt", "EvalAddMany", "EvalMult", "EvalSub", "Decrypt"])
                self.assertEqual(trace["run"]["coverage"]["rejected_unclassified_calls"], 0)
                self.assertTrue(all(e["overload"] != "unknown" for e in trace["events"]))
                observed[scheme] = {"ring_dimension": ring, "available_slots": context["available_slots"],
                                    "plaintext_modulus": context["plaintext_modulus"], "events": len(trace["events"]),
                                    "scaling_technique": context["scaling_technique"]}
        support.record("API-08", **observed)

    def test_gap_04_strict_and_permissive_eval_add_mutable(self) -> None:
        """GAP-04: an uncovered call (EvalAddMutable, level-adjusting) rejects or is counted as passthrough."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        strict_adapter = support.CountingContext(self.fixture.context)
        with cipherscope.trace(strict_adapter) as strict_session:
            with self.assertRaises(cipherscope.UnsupportedOperationError):
                strict_session.context.EvalAddMutable(left, right)
        strict_coverage = strict_session.to_trace()["run"]["coverage"]
        self.assertEqual(strict_adapter.calls["EvalAddMutable"], 0)
        self.assertEqual(strict_coverage["rejected_unclassified_calls"], 1)

        permissive_adapter = support.CountingContext(self.fixture.context)
        with cipherscope.trace(permissive_adapter, strict=False) as permissive_session:
            result = permissive_session.context.EvalAddMutable(left, right)
        permissive_trace = permissive_session.to_trace()
        permissive_coverage = permissive_trace["run"]["coverage"]
        self.assertIsNotNone(result)
        self.assertEqual(permissive_adapter.calls["EvalAddMutable"], 1)
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
