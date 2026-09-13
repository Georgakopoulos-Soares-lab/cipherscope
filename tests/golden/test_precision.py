"""Golden tests for precision-checkpoint drop analysis."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.precision import (
    MIN_BITS_LOST,
    TOLERANCE_RULE_ID,
    analyze_precision,
    analyze_tolerance,
)
from cipherscope.errors import AnnotationError, ShadowModeError
from cipherscope.testing import FakeCiphertext, FakeCryptoContext


def _shadow_trace(first_values: list[float], second_values: list[float]) -> dict:
    backend = FakeCryptoContext()
    expected = [1.0, 2.0]
    first = FakeCiphertext(decoded_values=first_values)
    second = FakeCiphertext(decoded_values=second_values)
    with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
        session.checkpoint("early", ciphertext=first, expected=expected)
        session.checkpoint("late", ciphertext=second, expected=expected)
    trace = session.to_trace()
    first_checkpoint = trace["events"][0]["semantic_arguments"]
    assert first_checkpoint["expected_values"] == expected
    assert first_checkpoint["observed_values"] == first_values
    return trace


class PrecisionAnalyzerTests(unittest.TestCase):
    def test_precision_drop_between_checkpoints_is_ranked(self) -> None:
        # The late checkpoint decodes further from the expected values.
        trace = _shadow_trace([1.0, 2.0], [1.01, 2.01])
        result = analyze_precision(trace)

        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "precision.checkpoint_drop.v1")
        drop = finding["evidence"]
        self.assertEqual(drop["from_checkpoint"], "early")
        self.assertEqual(drop["to_checkpoint"], "late")
        self.assertGreater(drop["absolute_bits_lost"], 0)

    def test_improving_precision_is_clean(self) -> None:
        result = analyze_precision(_shadow_trace([1.01, 2.01], [1.0, 2.0]))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["inventory"]["min_bits_lost_threshold"], MIN_BITS_LOST)

    def test_sub_threshold_drop_is_noise_not_a_finding(self) -> None:
        # 0.9 bits lost: below the noise-flooding threshold.
        early_error, late_error = 2.0**-20, 2.0 ** -(20 - 0.9)
        result = analyze_precision(_shadow_trace([1.0 + early_error, 2.0], [1.0 + late_error, 2.0]))
        self.assertEqual(result["analysis_status"], "clean")
        # 1.1 bits lost: counted.
        late_error = 2.0 ** -(20 - 1.1)
        result = analyze_precision(_shadow_trace([1.0 + early_error, 2.0], [1.0 + late_error, 2.0]))
        self.assertEqual(result["analysis_status"], "positive")
        self.assertAlmostEqual(result["findings"][0]["evidence"]["absolute_bits_lost"], 1.1, places=6)
        self.assertEqual(result["findings"][0]["evidence"]["min_bits_lost_threshold"], MIN_BITS_LOST)

    def test_non_shadow_run_is_not_applicable(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalBootstrap(FakeCiphertext())
        result = analyze_precision(session.to_trace())
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn("shadow_mode=True", result["not_applicable_reasons"][0])

    def test_checkpoint_requires_enabled_shadow_mode(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            with self.assertRaises(ShadowModeError):
                session.checkpoint(
                    "cp",
                    ciphertext=FakeCiphertext(decoded_values=[1.0]),
                    expected=[1.0],
                )

    def test_joining_trace_enables_shadow_mode_on_runner_session(self) -> None:
        backend = FakeCryptoContext()
        runner = cipherscope.runner_session(name="runner")
        with (
            runner,
            cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as joined,
        ):
            self.assertIs(joined, runner)
            joined.checkpoint(
                "cp",
                ciphertext=FakeCiphertext(decoded_values=[1.0]),
                expected=[1.0],
            )
        trace = runner.to_trace()
        self.assertTrue(trace["run"]["shadow_mode"])
        self.assertEqual(trace["events"][0]["kind"], "checkpoint")

    def test_checkpoint_records_metrics_and_tolerance_verdict(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
            within = session.checkpoint(
                "within",
                ciphertext=FakeCiphertext(decoded_values=[1.0, 2.0]),
                expected=[1.0, 2.0],
                tolerance={"absolute": 1e-6, "min_bits": 10},
            )
            violated = session.checkpoint(
                "violated",
                ciphertext=FakeCiphertext(decoded_values=[1.5, 2.0]),
                expected=[1.0, 2.0],
                tolerance={"relative": 0.1, "absolute": 0.25},
            )
            undeclared = session.checkpoint(
                "plain", ciphertext=FakeCiphertext(decoded_values=[1.0]), expected=[1.0]
            )
        self.assertEqual(within["tolerance_status"], "within")
        self.assertEqual(within["violated"], [])
        self.assertEqual(violated["tolerance_status"], "violated")
        self.assertEqual(violated["violated"], ["absolute", "relative"])
        self.assertEqual(violated["max_abs_error"], 0.5)
        self.assertEqual(violated["max_rel_error"], 0.5)
        self.assertEqual(undeclared["tolerance_status"], "undeclared")
        self.assertNotIn("tolerance", undeclared)
        recorded = session.to_trace()["events"][1]["semantic_arguments"]
        self.assertEqual(recorded["tolerance"], {"relative": 0.1, "absolute": 0.25})

    def test_tolerance_contract_is_validated(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
            for bad in ({}, {"absolute": -1}, {"relative": "0.1"}, {"typo": 1}, {"min_bits": float("nan")}, 5):
                with self.subTest(bad=bad), self.assertRaises(AnnotationError):
                    session.checkpoint(
                        "cp",
                        ciphertext=FakeCiphertext(decoded_values=[1.0]),
                        expected=[1.0],
                        tolerance=bad,
                    )

    def test_tolerance_rule_reports_the_first_violation_with_its_region(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
            session.checkpoint(
                "fresh", ciphertext=FakeCiphertext(decoded_values=[1.0]), expected=[1.0], tolerance={"absolute": 0.1}
            )
            session.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
            session.context.EvalMult(FakeCiphertext(), FakeCiphertext())
            session.checkpoint(
                "drifted", ciphertext=FakeCiphertext(decoded_values=[1.5]), expected=[1.0], tolerance={"absolute": 0.1}
            )
            session.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
            session.checkpoint(
                "worse", ciphertext=FakeCiphertext(decoded_values=[3.0]), expected=[1.0], tolerance={"absolute": 0.1}
            )
        trace = session.to_trace()
        result = analyze_tolerance(trace)
        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], TOLERANCE_RULE_ID)
        self.assertEqual(finding["severity"], "warning")
        evidence = finding["evidence"]
        self.assertEqual(evidence["violated_checkpoint"], "drifted")
        self.assertEqual(evidence["previous_checkpoint"], "fresh")
        self.assertEqual(evidence["later_violations"], ["worse"])
        region = [e for e in trace["events"] if e["kind"] == "crypto_operation"][:2]
        self.assertEqual(evidence["region_event_ids"], [e["event_id"] for e in region])
        self.assertTrue(finding["source_sites"])
        self.assertEqual(result["inventory"], {"declared_checkpoints": 3, "violated_checkpoints": 2})

    def test_tolerance_rule_clean_and_not_applicable(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend, secret_key=object(), shadow_mode=True) as session:
            session.checkpoint(
                "ok", ciphertext=FakeCiphertext(decoded_values=[1.0]), expected=[1.0], tolerance={"absolute": 0.1}
            )
        self.assertEqual(analyze_tolerance(session.to_trace())["analysis_status"], "clean")
        self.assertEqual(analyze_tolerance(_shadow_trace([1.0, 2.0], [1.0, 2.0]))["analysis_status"], "not_applicable")

    def test_joining_trace_with_shadow_mode_but_no_key_fails(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.runner_session(name="runner"), self.assertRaises(ShadowModeError):
            cipherscope.trace(backend, shadow_mode=True)


if __name__ == "__main__":
    unittest.main()
