"""Golden tests for the testing-only security configuration rule."""

from __future__ import annotations

import unittest

import cipherscope
from cipherscope.analyzers.configuration import RULE_ID, analyze_configuration
from cipherscope.pipeline import analyze_trace
from cipherscope.testing import FakeCiphertext, FakeCryptoContext, FakeParameters


def _trace(parameters: FakeParameters | None, *, acknowledged: bool = False) -> dict:
    backend = FakeCryptoContext()
    with cipherscope.trace(
        backend, parameters=parameters, allow_testing_security=acknowledged
    ) as session:
        session.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
    return session.to_trace()


class ConfigurationAnalyzerTests(unittest.TestCase):
    def test_not_set_is_a_warning(self) -> None:
        trace = _trace(FakeParameters(security_level="HEStd_NotSet", ring_dim=64))
        self.assertEqual(trace["context"]["security_level"], "HEStd_NotSet")
        self.assertEqual(trace["context"]["declared_ring_dimension"], 64)
        result = analyze_configuration(trace)
        self.assertEqual(result["analysis_status"], "positive")
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], RULE_ID)
        self.assertEqual(finding["severity"], "warning")
        self.assertFalse(finding["evidence"]["acknowledged"])
        self.assertTrue(any("not a bit-security estimate" in item for item in finding["limitations"]))
        self.assertNotIn("bits", finding["recommendation"])

    def test_acknowledged_run_downgrades_to_information(self) -> None:
        trace = _trace(FakeParameters(security_level="HEStd_NotSet"), acknowledged=True)
        self.assertTrue(trace["run"]["testing_security_acknowledged"])
        finding = analyze_configuration(trace)["findings"][0]
        self.assertEqual(finding["severity"], "information")
        self.assertTrue(finding["evidence"]["acknowledged"])

    def test_standard_level_is_clean(self) -> None:
        result = analyze_configuration(_trace(FakeParameters()))
        self.assertEqual(result["analysis_status"], "clean")
        self.assertEqual(result["inventory"]["security_level"], "HEStd_128_classic")
        self.assertIsNone(result["inventory"]["declared_ring_dimension"])

    def test_undeclared_parameters_are_not_applicable(self) -> None:
        trace = _trace(None)
        self.assertNotIn("security_level", trace["context"])
        result = analyze_configuration(trace)
        self.assertEqual(result["analysis_status"], "not_applicable")
        self.assertIn("parameters=", result["not_applicable_reasons"][0])

    def test_attach_and_runner_paths_declare_parameters(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.runner_session(name="runner") as runner:
            cipherscope.attach(backend, parameters=FakeParameters(security_level="HEStd_NotSet"))
            runner.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
        self.assertEqual(runner.to_trace()["context"]["security_level"], "HEStd_NotSet")

        backend = FakeCryptoContext()
        declared = FakeParameters(security_level="HEStd_192_classic")
        with (
            cipherscope.runner_session(name="runner") as runner,
            cipherscope.trace(backend, parameters=declared) as joined,
        ):
            joined.context.EvalAdd(FakeCiphertext(), FakeCiphertext())
        self.assertEqual(runner.to_trace()["context"]["security_level"], "HEStd_192_classic")

    def test_pipeline_reports_the_rule_and_manifest_carries_the_level(self) -> None:
        trace = _trace(FakeParameters(security_level="HEStd_NotSet"))
        recommendations = analyze_trace(trace)
        self.assertEqual(recommendations["analyzer_status"][RULE_ID], "positive")
        from cipherscope.exporters import build_manifest

        self.assertEqual(build_manifest(trace)["parameter_set"]["security_level"], "HEStd_NotSet")


if __name__ == "__main__":
    unittest.main()
