"""Real-context proxy forwarding, source attribution, and graph checks."""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path

import cipherscope
from cipherscope.graph import build_graph
from cipherscope.validation import validate_trace

from . import golden_calls, support


def _call_line(function: object, operation: str) -> int:
    lines, start = inspect.getsourcelines(function)
    marker = f"context.{operation}("
    for offset, line in enumerate(lines):
        if marker in line:
            return start + offset
    raise AssertionError(f"no {operation} call found in golden source function")


@unittest.skipUnless(
    support.fhe is not None,
    "OpenFHE Python is unavailable; fake-backend results are not integration evidence",
)
class ProxyAndTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = support.basic_fixture()

    def test_proxy_01_real_context_core_calls(self) -> None:
        """PROXY-01: a real context executes the non-bootstrap core through trace()."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            added = session.context.EvalAdd(left, right)
            multiplied = session.context.EvalMult(left, right)
            rotated = session.context.EvalRotate(left, 1)
        trace = session.to_trace()
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            ["EvalAdd", "EvalMult", "EvalRotate"],
        )
        self.assertTrue(
            all(
                item.GetCryptoContext() is not None
                for item in (added, multiplied, rotated)
            )
        )
        self.assertEqual(trace["run"]["coverage"]["traced_semantic_calls"], 3)
        support.record(
            "PROXY-01",
            operations=[event["operation"] for event in trace["events"]],
            output_types=[type(item).__name__ for item in (added, multiplied, rotated)],
        )

    def test_proxy_05_real_encrypt_decrypt_calls(self) -> None:
        """PROXY-05: encryption and decryption preserve native result behavior."""

        plaintext = self.fixture.context.MakeCKKSPackedPlaintext(list(self.fixture.a))
        with cipherscope.trace(self.fixture.context) as session:
            ciphertext = golden_calls.encrypt_site(
                session.context, self.fixture.keys.publicKey, plaintext
            )
            decrypted = golden_calls.decrypt_site(
                session.context, ciphertext, self.fixture.keys.secretKey
            )
        decrypted.SetLength(self.fixture.batch_size)
        values = [
            complex(item)
            for item in decrypted.GetCKKSPackedValue()[: self.fixture.batch_size]
        ]
        error = support.max_abs_error(values, self.fixture.a)
        trace = session.to_trace()
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            ["Encrypt", "Decrypt"],
        )
        self.assertLessEqual(error, support.GOLDEN["basic_max_abs_tolerance"])
        self.assertEqual(trace["events"][0]["input_ciphertexts"], [])
        self.assertEqual(len(trace["events"][0]["output_ciphertexts"]), 1)
        self.assertEqual(
            trace["events"][1]["input_ciphertexts"],
            trace["events"][0]["output_ciphertexts"],
        )
        self.assertEqual(trace["events"][1]["output_ciphertexts"], [])
        support.record(
            "PROXY-05",
            operations=[event["operation"] for event in trace["events"]],
            max_abs_error=error,
        )

    def test_proxy_02_exactly_once_delegation(self) -> None:
        """PROXY-02: one proxy call produces one adapter call and one event."""

        adapter = support.CountingContext(self.fixture.context)
        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(adapter) as session:
            session.context.EvalAdd(left, right)
        trace = session.to_trace()
        self.assertEqual(adapter.calls["EvalAdd"], 1)
        self.assertEqual(len(trace["events"]), 1)
        self.assertEqual(trace["events"][0]["operation"], "EvalAdd")
        support.record("PROXY-02", native_adapter_calls=1, trace_events=1)

    def test_proxy_03_plain_python_helper_accepts_proxy(self) -> None:
        """PROXY-03: a normal helper taking a context works without modification."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            result = golden_calls.eval_add_site(session.context, left, right)
        self.assertIsNotNone(result)
        self.assertEqual(
            session.to_trace()["events"][0]["source"]["function"], "eval_add_site"
        )
        support.record(
            "PROXY-03", helper="eval_add_site", result_type=type(result).__name__
        )

    def test_proxy_04_proxy_type_boundary_is_explicit(self) -> None:
        """PROXY-04: the proxy is not misrepresented as a native CryptoContext."""

        with cipherscope.trace(self.fixture.context) as session:
            proxy = session.context
            is_native_type = isinstance(proxy, type(self.fixture.context))
            native_context_result = self.fixture.encrypt(
                self.fixture.a
            ).GetCryptoContext()
        self.assertFalse(is_native_type)
        self.assertIsNot(native_context_result, proxy)
        support.record(
            "PROXY-04",
            proxy_type=type(proxy).__name__,
            native_type=type(self.fixture.context).__name__,
            isinstance_native=is_native_type,
            fallback="pass the original native context at native-only boundaries",
        )

    def test_trace_01_exact_golden_source_sites(self) -> None:
        """TRACE-01: operations resolve to exact manually inspectable source lines."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            golden_calls.eval_add_site(session.context, left, right)
            golden_calls.eval_mult_site(session.context, left, right)
            golden_calls.eval_rotate_site(session.context, left, 1)
        trace = session.to_trace()
        expected = [
            (
                "EvalAdd",
                "eval_add_site",
                _call_line(golden_calls.eval_add_site, "EvalAdd"),
            ),
            (
                "EvalMult",
                "eval_mult_site",
                _call_line(golden_calls.eval_mult_site, "EvalMult"),
            ),
            (
                "EvalRotate",
                "eval_rotate_site",
                _call_line(golden_calls.eval_rotate_site, "EvalRotate"),
            ),
        ]
        observed = [
            (event["operation"], event["source"]["function"], event["source"]["line"])
            for event in trace["events"]
        ]
        self.assertEqual(observed, expected)
        source_file = str(Path(golden_calls.__file__).resolve())
        self.assertTrue(
            all(event["source"]["file"] == source_file for event in trace["events"])
        )
        self.assertEqual([event["sequence"] for event in trace["events"]], [1, 2, 3])
        support.record("TRACE-01", expected=expected, observed=observed)

    def test_trace_02_valid_deterministic_graph(self) -> None:
        """TRACE-02: the real trace validates and builds the same graph twice."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            added = session.context.EvalAdd(left, right)
            session.context.EvalMult(added, right)
        trace = session.to_trace()
        validation = validate_trace(trace)
        self.assertTrue(
            validation.valid, [issue.to_dict() for issue in validation.errors]
        )
        first = build_graph(trace)
        second = build_graph(trace)
        self.assertEqual(first, second)
        self.assertTrue(first["roots"])
        self.assertTrue(first["outputs"])
        support.record(
            "TRACE-02",
            valid=True,
            node_count=len(first["nodes"]),
            edge_count=len(first["edges"]),
            roots=first["roots"],
            outputs=first["outputs"],
        )

    def test_id_03_fresh_outputs_get_distinct_ciphertext_ids(self) -> None:
        """ID-03: each new native output receives a distinct ciphertext ID."""

        left = self.fixture.encrypt(self.fixture.a)
        right = self.fixture.encrypt(self.fixture.b)
        with cipherscope.trace(self.fixture.context) as session:
            session.context.EvalAdd(left, right)
            session.context.EvalMult(left, right)
            session.context.EvalRotate(left, 1)
        trace = session.to_trace()
        output_ciphertext_ids = [
            event["output_ciphertexts"][0] for event in trace["events"]
        ]
        self.assertEqual(len(output_ciphertext_ids), len(set(output_ciphertext_ids)))
        self.assertTrue(
            all(identifier.endswith(":v0") for identifier in output_ciphertext_ids)
        )
        support.record("ID-03", output_ids=output_ciphertext_ids)


if __name__ == "__main__":
    unittest.main()
