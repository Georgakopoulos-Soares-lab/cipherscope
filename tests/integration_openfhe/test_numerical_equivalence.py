"""Direct, traced, and mathematical CKKS equivalence checks."""

from __future__ import annotations

import unittest

import cipherscope

from . import support


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class NumericalEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_num_01_eval_add_direct_vs_traced(self) -> None:
        """NUM-01: traced addition agrees with direct and expected slot values."""

        cc = self.fixture.context
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        direct = cc.EvalAdd(left, right)
        with cipherscope.trace(cc) as session:
            traced = session.context.EvalAdd(left, right)
        direct_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, direct, self.fixture.batch_size
        )
        traced_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, traced, self.fixture.batch_size
        )
        expected = support.add_expected(self.fixture.a, self.fixture.b)
        expected_error = support.max_abs_error(traced_values, expected)
        direct_error = support.max_abs_error(traced_values, direct_values)
        self.assertLessEqual(
            expected_error, support.GOLDEN["basic_max_abs_tolerance"]
        )
        self.assertLessEqual(
            direct_error, support.GOLDEN["direct_vs_traced_tolerance"]
        )
        support.record(
            "NUM-01",
            max_expected_error=expected_error,
            max_direct_vs_traced_error=direct_error,
            tolerance=support.GOLDEN["basic_max_abs_tolerance"],
        )

    def test_num_02_eval_mult_direct_vs_traced(self) -> None:
        """NUM-02: traced multiplication agrees with direct and expected values."""

        cc = self.fixture.context
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        direct = cc.EvalMult(left, right)
        with cipherscope.trace(cc) as session:
            traced = session.context.EvalMult(left, right)
        direct_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, direct, self.fixture.batch_size
        )
        traced_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, traced, self.fixture.batch_size
        )
        expected = support.mult_expected(self.fixture.a, self.fixture.b)
        expected_error = support.max_abs_error(traced_values, expected)
        direct_error = support.max_abs_error(traced_values, direct_values)
        self.assertLessEqual(
            expected_error, support.GOLDEN["basic_max_abs_tolerance"]
        )
        self.assertLessEqual(
            direct_error, support.GOLDEN["direct_vs_traced_tolerance"]
        )
        support.record(
            "NUM-02",
            max_expected_error=expected_error,
            max_direct_vs_traced_error=direct_error,
            tolerance=support.GOLDEN["basic_max_abs_tolerance"],
        )


if __name__ == "__main__":
    unittest.main()
