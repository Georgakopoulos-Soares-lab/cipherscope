"""Official-example-aligned CKKS bootstrapping feasibility checks."""

from __future__ import annotations

import unittest

import cipherscope

from . import golden_calls, support


@unittest.skipUnless(
    support.fhe is not None and support.BOOTSTRAP_ENABLED,
    "real OpenFHE bootstrapping runs only in the authoritative integration gate",
)
class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.bootstrap_fixture()

    def test_boot_01_official_setup_executes(self) -> None:
        """BOOT-01: official tagged setup, key generation, and bootstrap execute."""

        ciphertext = self.fixture.encrypt_at_last_level()
        before_level = ciphertext.GetLevel()
        result = self.fixture.context.EvalBootstrap(ciphertext)
        after_level = result.GetLevel()
        self.assertIsNotNone(result)
        self.assertEqual(self.fixture.context.GetRingDimension(), 1 << 12)
        support.record(
            "BOOT-01",
            testing_only_insecure=True,
            security_level="HEStd_NotSet",
            ring_dimension=1 << 12,
            level_budget=self.fixture.level_budget,
            configured_depth=self.fixture.depth,
            before_level=before_level,
            after_level=after_level,
        )

    def test_boot_02_direct_vs_traced_equivalence(self) -> None:
        """BOOT-02: traced bootstrap agrees with direct output and source values."""

        cc = self.fixture.context
        direct_input = self.fixture.encrypt_at_last_level()
        traced_input = self.fixture.encrypt_at_last_level()
        direct = cc.EvalBootstrap(direct_input)
        with cipherscope.trace(cc) as session:
            traced = golden_calls.eval_bootstrap_site(session.context, traced_input)
        trace = session.to_trace()
        direct_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, direct, len(self.fixture.values)
        )
        traced_values = support.decrypt_values(
            cc, self.fixture.keys.secretKey, traced, len(self.fixture.values)
        )
        source_error = support.max_abs_error(traced_values, self.fixture.values)
        direct_error = support.max_abs_error(traced_values, direct_values)
        self.assertLessEqual(
            source_error, support.GOLDEN["bootstrap_max_abs_tolerance"]
        )
        self.assertLessEqual(
            direct_error, support.GOLDEN["bootstrap_max_abs_tolerance"]
        )
        self.assertEqual(len(trace["events"]), 1)
        event = trace["events"][0]
        self.assertEqual(event["operation"], "EvalBootstrap")
        self.assertEqual(event["source"]["function"], "eval_bootstrap_site")
        self.assertEqual(len(event["input_states"]), 1)
        self.assertEqual(len(event["output_states"]), 1)
        support.record(
            "BOOT-02",
            source_max_error=source_error,
            direct_vs_traced_max_error=direct_error,
            tolerance=support.GOLDEN["bootstrap_max_abs_tolerance"],
            input_state=event["input_states"][0],
            output_state=event["output_states"][0],
            source=event["source"],
        )


if __name__ == "__main__":
    unittest.main()
