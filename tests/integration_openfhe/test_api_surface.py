"""Binding availability, metadata, identity, and mutation feasibility checks."""

from __future__ import annotations

import weakref
import unittest

import cipherscope
from cipherscope.compatibility import CompatibilityRegistry
from cipherscope.validation import validate_trace

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class APISurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_api_01_core_setup_and_calls_exist(self) -> None:
        """API-01: setup and the core covered methods are bound and executable."""

        cc = self.fixture.context
        required = (
            "KeyGen",
            "EvalMultKeyGen",
            "EvalRotateKeyGen",
            "MakeCKKSPackedPlaintext",
            "Encrypt",
            "Decrypt",
            "EvalAdd",
            "EvalMult",
            "EvalRotate",
            "EvalBootstrap",
        )
        availability = {name: callable(getattr(cc, name, None)) for name in required}
        self.assertTrue(all(availability.values()), availability)
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        self.assertIsNotNone(cc.EvalAdd(left, right))
        self.assertIsNotNone(cc.EvalMult(left, right))
        self.assertIsNotNone(cc.EvalRotate(left, 1))
        support.record("API-01", availability=availability)

    def test_api_02_getter_inventory(self) -> None:
        """API-02: supported context/ciphertext getters execute with typed values."""

        cc = self.fixture.context
        ciphertext = self.fixture.encrypt(self.fixture.a)
        context_getters = (
            "GetRingDimension",
            "GetBatchSize",
            "GetScalingTechnique",
            "GetKeySwitchTechnique",
            "GetMultiplicativeDepth",
            "GetCyclotomicOrder",
        )
        ciphertext_getters = (
            "GetLevel",
            "GetNoiseScaleDeg",
            "GetScalingFactor",
            "GetSlots",
            "GetKeyTag",
            "GetCryptoContext",
            "GetElements",
        )
        context_values = {name: getattr(cc, name)() for name in context_getters}
        ciphertext_values = {
            name: getattr(ciphertext, name)() for name in ciphertext_getters
        }
        self.assertGreater(context_values["GetRingDimension"], 0)
        self.assertEqual(context_values["GetBatchSize"], self.fixture.batch_size)
        self.assertGreaterEqual(ciphertext_values["GetLevel"], 0)
        self.assertGreaterEqual(ciphertext_values["GetNoiseScaleDeg"], 0)
        support.record(
            "API-02",
            context_types={
                key: type(value).__name__ for key, value in context_values.items()
            },
            ciphertext_types={
                key: type(value).__name__ for key, value in ciphertext_values.items()
            },
        )

    def test_api_03_snapshot_matches_independent_getters(self) -> None:
        """API-03: CipherScope state snapshots agree with direct getter evidence."""

        cc = self.fixture.context
        ciphertext = self.fixture.encrypt(self.fixture.a)
        registry = CompatibilityRegistry().for_session()
        context_snapshot = registry.snapshot_context(cc)
        snapshot = registry.snapshot_ciphertext(ciphertext)
        expected_scaling = support.enum_name(cc.GetScalingTechnique())
        expected_key_switch = support.enum_name(cc.GetKeySwitchTechnique())
        self.assertEqual(snapshot.level, ciphertext.GetLevel())
        self.assertEqual(snapshot.noise_scale_degree, ciphertext.GetNoiseScaleDeg())
        self.assertEqual(snapshot.key_tag, ciphertext.GetKeyTag())
        self.assertEqual(snapshot.slots, ciphertext.GetSlots())
        self.assertEqual(snapshot.scale, ciphertext.GetScalingFactor())
        self.assertEqual(snapshot.context_id, context_snapshot["context_id"])
        self.assertEqual(snapshot.scaling_technique, expected_scaling)
        self.assertEqual(snapshot.key_switch_technique, expected_key_switch)
        self.assertEqual(context_snapshot["scheme"], "CKKS")
        self.assertEqual(
            context_snapshot["scheme_evidence"], "configured_ckks_contract"
        )
        support.record(
            "API-03",
            ciphertext_snapshot=snapshot.to_dict(),
            context_snapshot=context_snapshot,
        )

    def test_api_04_result_and_clone_inventory(self) -> None:
        """API-04: core result shapes and clone identity match the pinned binding."""

        cc = self.fixture.context
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        outputs = [
            cc.EvalAdd(left, right),
            cc.EvalMult(left, right),
            cc.EvalRotate(left, 1),
        ]
        self.assertTrue(
            all(CompatibilityRegistry().is_ciphertext(item) for item in outputs)
        )
        clone_method = getattr(left, "Clone", None)
        self.assertTrue(callable(clone_method))
        clone = clone_method()
        self.assertIsNot(clone, left)
        self.assertEqual(support.unique_by_identity([left, clone, *outputs]), 5)
        support.record(
            "API-04",
            result_types=[type(item).__name__ for item in outputs],
            clone_available=True,
            distinct_identities=5,
        )

    def test_api_05_in_place_inventory(self) -> None:
        """API-05: known in-place methods match the tagged binding inventory."""

        cc = self.fixture.context
        availability = {
            name: callable(getattr(cc, name, None))
            for name in (
                "EvalAddInPlace",
                "EvalSubInPlace",
                "EvalSquareInPlace",
                "RelinearizeInPlace",
                "EvalNegateInPlace",
                "ModReduceInPlace",
                "RescaleInPlace",
                "EvalMultInPlace",
            )
        }
        self.assertTrue(
            all(
                availability[name] for name in availability if name != "EvalMultInPlace"
            ),
            availability,
        )
        self.assertFalse(availability["EvalMultInPlace"])
        support.record("API-05", availability=availability)

    def test_api_06_state_depth_method_inventory(self) -> None:
        """API-06: every declared non-mutating state/depth method is bound."""

        required = (
            "EvalSub",
            "EvalSquare",
            "EvalMultNoRelin",
            "Relinearize",
            "EvalNegate",
            "ModReduce",
            "Rescale",
        )
        availability = {
            name: callable(getattr(self.fixture.context, name, None))
            for name in required
        }
        self.assertTrue(all(availability.values()), availability)
        support.record("API-06", availability=availability)

    def test_id_01_weakref_and_hash_behavior_is_classified(self) -> None:
        """ID-01: pybind weak-reference and hash behavior is observed explicitly."""

        ciphertext = self.fixture.encrypt(self.fixture.a)
        try:
            reference = weakref.ref(ciphertext)
            weakref_supported = reference() is ciphertext
        except TypeError:
            weakref_supported = False
        try:
            first_hash = hash(ciphertext)
            hash_supported = first_hash == hash(ciphertext)
        except TypeError:
            hash_supported = False
        registry = CompatibilityRegistry().for_session()
        registry.snapshot_context(self.fixture.context)
        first = registry.snapshot_ciphertext(ciphertext)
        second = registry.snapshot_ciphertext(ciphertext)
        self.assertEqual(first, second)
        support.record(
            "ID-01",
            weakref_supported=weakref_supported,
            hash_supported=hash_supported,
            fallback="guarded strong-reference identity table",
        )

    def test_id_02_nested_aliases_and_cycles(self) -> None:
        """ID-02: repeated aliases deduplicate and cyclic containers terminate."""

        ciphertext = self.fixture.encrypt(self.fixture.a)
        cyclic: list[object] = [ciphertext]
        cyclic.append(cyclic)
        registry = CompatibilityRegistry()
        found = registry.collect_ciphertexts(
            ciphertext, [ciphertext, {"nested": (ciphertext, cyclic)}]
        )
        unique = []
        for item in found:
            if not any(item is previous for previous in unique):
                unique.append(item)
        self.assertEqual(unique, [ciphertext])
        support.record("ID-02", observations=len(found), unique_identities=len(unique))

    def test_mut_01_eval_add_in_place_behavior(self) -> None:
        """MUT-01: EvalAddInPlace retains identity and changes decrypted value."""

        cc = self.fixture.context
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        identity = id(left)
        returned = cc.EvalAddInPlace(left, right)
        observed = support.decrypt_values(
            cc, self.fixture.keys.secretKey, left, self.fixture.batch_size
        )
        error = support.max_abs_error(
            observed, support.add_expected(self.fixture.a, self.fixture.b)
        )
        self.assertEqual(id(left), identity)
        self.assertIsNone(returned)
        self.assertLessEqual(error, support.GOLDEN["basic_max_abs_tolerance"])
        support.record(
            "MUT-01",
            returned_none=returned is None,
            identity_retained=True,
            max_error=error,
        )

    def test_mut_02_proxy_versions_supported_in_place_mutation(self) -> None:
        """MUT-02: the proxy records one immutable version for the mutation."""

        adapter = support.CountingContext(self.fixture.context)
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(adapter) as session:
            returned = session.context.EvalAddInPlace(left, right)
        trace = session.to_trace()
        event = trace["events"][0]
        old_left_id = event["input_ciphertexts"][0]
        new_left_id = event["output_ciphertexts"][0]
        self.assertIsNone(returned)
        self.assertEqual(adapter.calls["EvalAddInPlace"], 1)
        self.assertEqual(event["operation"], "EvalAddInPlace")
        self.assertEqual(old_left_id.split(":")[0], new_left_id.split(":")[0])
        self.assertTrue(old_left_id.endswith(":v0"))
        self.assertTrue(new_left_id.endswith(":v1"))
        support.record(
            "MUT-02",
            native_calls=1,
            old_left_id=old_left_id,
            new_left_id=new_left_id,
        )

    def test_mut_03_proxy_versions_declared_in_place_matrix(self) -> None:
        """MUT-03: every declared mutation emits one next state version."""

        cc = self.fixture.context
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        calls = [
            ("EvalSubInPlace", (left.Clone(), right)),
            ("EvalSquareInPlace", (left.Clone(),)),
            ("RelinearizeInPlace", (cc.EvalMultNoRelin(left, right),)),
            ("EvalNegateInPlace", (left.Clone(),)),
            ("ModReduceInPlace", (cc.EvalMultNoRelin(left, right),)),
            ("RescaleInPlace", (cc.EvalMultNoRelin(left, right),)),
        ]
        with cipherscope.trace(cc) as session:
            returned = [
                getattr(session.context, operation)(*operands)
                for operation, operands in calls
            ]
        trace = session.to_trace()
        self.assertEqual(returned, [None] * len(calls))
        self.assertTrue(validate_trace(trace).valid)
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            [operation for operation, _ in calls],
        )
        transitions = []
        for event in trace["events"]:
            self.assertEqual(len(event["output_ciphertexts"]), 1)
            old_id = event["input_ciphertexts"][0]
            new_id = event["output_ciphertexts"][0]
            self.assertEqual(old_id.split(":")[0], new_id.split(":")[0])
            self.assertTrue(old_id.endswith(":v0"))
            self.assertTrue(new_id.endswith(":v1"))
            transitions.append([event["operation"], old_id, new_id])
        support.record("MUT-03", transitions=transitions)


if __name__ == "__main__":
    unittest.main()
