"""Regular and fast rotation evidence for the pinned real binding."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.keys import analyze_keys

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class RotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_rot_01_positive_and_negative_rotation_semantics(self) -> None:
        """ROT-01: +1/-2 rotations have exact trace indices and slot semantics."""

        cc = self.fixture.context
        source = self.fixture.encrypt(self.fixture.a)
        direct_positive = cc.EvalRotate(source, 1)
        direct_negative = cc.EvalRotate(source, -2)
        with cipherscope.trace(cc) as session:
            traced_positive = session.context.EvalRotate(source, 1)
            traced_negative = session.context.EvalRotate(source, -2)
        trace = session.to_trace()
        observed_indices = [
            event["semantic_arguments"]["rotation_index_requested"]
            for event in trace["events"]
        ]
        self.assertEqual(observed_indices, [1, -2])
        input_ids = [event["input_ciphertexts"][0] for event in trace["events"]]
        self.assertEqual(input_ids[0], input_ids[1])
        output_ids = [event["output_ciphertexts"][0] for event in trace["events"]]
        self.assertNotEqual(output_ids[0], output_ids[1])

        observations: dict[str, float] = {}
        for label, direct, traced, index in (
            ("positive", direct_positive, traced_positive, 1),
            ("negative", direct_negative, traced_negative, -2),
        ):
            direct_values = support.decrypt_values(
                cc, self.fixture.keys.secretKey, direct, self.fixture.batch_size
            )
            traced_values = support.decrypt_values(
                cc, self.fixture.keys.secretKey, traced, self.fixture.batch_size
            )
            expected = support.rotate_expected(self.fixture.a, index)
            observations[f"{label}_expected_error"] = support.max_abs_error(
                traced_values, expected
            )
            observations[f"{label}_direct_error"] = support.max_abs_error(
                traced_values, direct_values
            )
            self.assertLessEqual(
                observations[f"{label}_expected_error"],
                support.GOLDEN["basic_max_abs_tolerance"],
            )
            self.assertLessEqual(
                observations[f"{label}_direct_error"],
                support.GOLDEN["direct_vs_traced_tolerance"],
            )
        support.record(
            "ROT-01",
            indices=observed_indices,
            shared_input_version=True,
            distinct_outputs=True,
            **observations,
        )

    def test_rot_02_fast_rotation_matches_regular(self) -> None:
        """ROT-02: fast rotations with one precompute agree with regular rotations."""

        cc = self.fixture.context
        source = self.fixture.encrypt(self.fixture.a)
        precompute = cc.EvalFastRotationPrecompute(source)
        cyclotomic_order = cc.GetCyclotomicOrder()
        errors: dict[str, float] = {}
        for index in (1, 2, 3):
            regular = cc.EvalRotate(source, index)
            fast = cc.EvalFastRotation(source, index, cyclotomic_order, precompute)
            regular_values = support.decrypt_values(
                cc, self.fixture.keys.secretKey, regular, self.fixture.batch_size
            )
            fast_values = support.decrypt_values(
                cc, self.fixture.keys.secretKey, fast, self.fixture.batch_size
            )
            error = support.max_abs_error(regular_values, fast_values)
            errors[str(index)] = error
            self.assertLessEqual(error, support.GOLDEN["basic_max_abs_tolerance"])
        support.record(
            "ROT-02",
            indices=[1, 2, 3],
            cyclotomic_order=cyclotomic_order,
            max_errors=errors,
        )

    def test_rot_03_traced_key_generation_inventory(self) -> None:
        """ROT-03: generated and used indices feed the observed-run key rule."""

        cc = self.fixture.context
        source = self.fixture.encrypt(self.fixture.a)
        with cipherscope.trace(cc) as session:
            session.context.EvalRotateKeyGen(self.fixture.keys.secretKey, [1, -2])
            session.context.EvalRotate(source, 1)
        trace = session.to_trace()
        self.assertEqual(trace["events"][0]["kind"], "key_generation")
        self.assertEqual(
            trace["events"][0]["semantic_arguments"]["rotation_indices_requested"],
            [1, -2],
        )
        result = analyze_keys(trace)
        self.assertEqual(result["analysis_status"], "positive")
        self.assertEqual(result["inventory"]["unused_generated_indices"], [-2])
        support.record("ROT-03", inventory=result["inventory"])


if __name__ == "__main__":
    unittest.main()
