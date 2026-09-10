"""Behavioral tests for the dependency-free CipherScope core."""

from __future__ import annotations

import threading
import unittest
from pathlib import Path
from unittest import mock

import cipherscope
from cipherscope.graph import build_graph
from cipherscope.testing import FakeCiphertext, FakeCryptoContext, FakePlaintext
from cipherscope.validation import validate_trace


class CoreTraceTests(unittest.TestCase):
    def test_state_depth_operations_forward_and_build_expected_paths(self) -> None:
        backend = FakeCryptoContext()
        left = FakeCiphertext(level=0, noise_scale_degree=1)
        right = FakeCiphertext(level=0, noise_scale_degree=1)

        with cipherscope.trace(backend) as session:
            subtracted = session.context.EvalSub(left, right)
            squared = session.context.EvalSquare(left)
            multiplied = session.context.EvalMultNoRelin(left, right)
            relinearized = session.context.Relinearize(multiplied)
            negated = session.context.EvalNegate(left)
            reduced = session.context.ModReduce(left)
            rescaled = session.context.Rescale(left)

        self.assertEqual(subtracted.level, 0)
        self.assertEqual(squared.level, 1)
        self.assertEqual(multiplied.level, 1)
        self.assertEqual(relinearized.level, 1)
        self.assertEqual(negated.level, 0)
        self.assertEqual(reduced.level, 1)
        self.assertEqual(rescaled.level, 1)
        trace = session.to_trace()
        operations = [
            "EvalSub",
            "EvalSquare",
            "EvalMultNoRelin",
            "Relinearize",
            "EvalNegate",
            "ModReduce",
            "Rescale",
        ]
        self.assertEqual([event["operation"] for event in trace["events"]], operations)
        self.assertEqual(
            {operation: backend.calls[operation] for operation in operations},
            {operation: 1 for operation in operations},
        )
        self.assertTrue(validate_trace(trace).valid)
        graph = build_graph(trace)
        self.assertEqual(
            graph["critical_paths"]["nonlinear_ciphertext"]["max_depth"], 1
        )
        nonlinear_events = set(
            graph["critical_paths"]["nonlinear_ciphertext"]["event_ids"]
        )
        self.assertIn(nonlinear_events, ({"event_0002"}, {"event_0003"}))
        self.assertEqual(
            graph["critical_paths"]["observed_level_use"][
                "max_levels_consumed_in_epoch"
            ],
            1,
        )

    def test_declared_in_place_matrix_versions_first_ciphertext(self) -> None:
        backend = FakeCryptoContext()
        calls: list[tuple[str, tuple[FakeCiphertext, ...]]] = [
            ("EvalSubInPlace", (FakeCiphertext(), FakeCiphertext(level=1))),
            ("EvalSquareInPlace", (FakeCiphertext(),)),
            ("RelinearizeInPlace", (FakeCiphertext(),)),
            ("EvalNegateInPlace", (FakeCiphertext(),)),
            ("ModReduceInPlace", (FakeCiphertext(),)),
            ("RescaleInPlace", (FakeCiphertext(),)),
        ]

        with cipherscope.trace(backend) as session:
            returns = [
                getattr(session.context, operation)(*operands)
                for operation, operands in calls
            ]

        self.assertEqual(returns, [None] * len(calls))
        trace = session.to_trace()
        self.assertTrue(validate_trace(trace).valid)
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            [operation for operation, _ in calls],
        )
        for event in trace["events"]:
            with self.subTest(operation=event["operation"]):
                self.assertEqual(len(event["output_ciphertexts"]), 1)
                old_id = event["input_ciphertexts"][0]
                new_id = event["output_ciphertexts"][0]
                self.assertEqual(old_id.split(":")[0], new_id.split(":")[0])
                self.assertTrue(old_id.endswith(":v0"))
                self.assertTrue(new_id.endswith(":v1"))

    def test_reverse_in_place_overloads_mutate_ciphertext_not_scalar(self) -> None:
        backend = FakeCryptoContext()
        add_source = FakeCiphertext()
        sub_source = FakeCiphertext()

        with cipherscope.trace(backend) as session:
            session.context.EvalAddInPlace(2.0, add_source)
            session.context.EvalSubInPlace(3.0, sub_source)

        trace = session.to_trace()
        self.assertTrue(validate_trace(trace).valid)
        for event in trace["events"]:
            self.assertEqual(event["overload"], "scalar_ct")
            self.assertEqual(event["input_ciphertexts"][0].split(":")[1], "v0")
            self.assertEqual(event["output_ciphertexts"][0].split(":")[1], "v1")
            self.assertEqual(
                event["input_ciphertexts"][0].split(":")[0],
                event["output_ciphertexts"][0].split(":")[0],
            )

    def test_eval_add_in_place_advances_mutated_operand_once(self) -> None:
        backend = FakeCryptoContext()
        left = FakeCiphertext(level=0, noise_scale_degree=1)
        right = FakeCiphertext(level=2, noise_scale_degree=3)

        with cipherscope.trace(backend) as session:
            returned = session.context.EvalAddInPlace(left, right)

        self.assertIsNone(returned)
        self.assertEqual((left.level, left.noise_scale_degree), (2, 3))
        self.assertEqual(backend.calls["EvalAddInPlace"], 1)
        trace = session.to_trace()
        self.assertTrue(validate_trace(trace).valid)
        event = trace["events"][0]
        self.assertEqual(event["operation"], "EvalAddInPlace")
        self.assertEqual(len(event["input_ciphertexts"]), 2)
        self.assertEqual(len(event["output_ciphertexts"]), 1)
        old_left_id = event["input_ciphertexts"][0]
        new_left_id = event["output_ciphertexts"][0]
        self.assertEqual(old_left_id.split(":")[0], new_left_id.split(":")[0])
        self.assertTrue(old_left_id.endswith(":v0"))
        self.assertTrue(new_left_id.endswith(":v1"))
        self.assertEqual(event["output_states"][0]["level"], 2)
        self.assertEqual(
            next(state for state in trace["ciphertexts"] if state["id"] == new_left_id)[
                "parent_ids"
            ],
            event["input_ciphertexts"],
        )

    def test_in_place_failure_does_not_advance_ciphertext_version(self) -> None:
        backend = FakeCryptoContext()
        backend.fail_operations["EvalAddInPlace"] = RuntimeError("sensitive")
        left = FakeCiphertext()

        with cipherscope.trace(backend) as session:
            with self.assertRaises(RuntimeError):
                session.context.EvalAddInPlace(left, FakeCiphertext())

        trace = session.to_trace(status="failed")
        self.assertEqual(len(trace["events"]), 1)
        self.assertEqual(trace["events"][0]["status"], "error")
        self.assertEqual(trace["events"][0]["output_ciphertexts"], [])
        self.assertTrue(
            all(state["id"].endswith(":v0") for state in trace["ciphertexts"])
        )

    def test_encrypt_decrypt_forwarding_lineage_and_representations(self) -> None:
        backend = FakeCryptoContext()
        public_key = object()
        private_key = object()
        plaintext = FakePlaintext("input")

        with cipherscope.trace(backend) as session:
            ciphertext = session.context.Encrypt(public_key, plaintext)
            decrypted = session.context.Decrypt(ciphertext, private_key)

        self.assertIsInstance(ciphertext, FakeCiphertext)
        self.assertIsInstance(decrypted, FakePlaintext)
        self.assertEqual(backend.calls["Encrypt"], 1)
        self.assertEqual(backend.calls["Decrypt"], 1)
        trace = session.to_trace()
        self.assertTrue(validate_trace(trace).valid)
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            ["Encrypt", "Decrypt"],
        )
        encrypted_id = trace["events"][0]["output_ciphertexts"][0]
        self.assertEqual(trace["events"][0]["input_ciphertexts"], [])
        self.assertEqual(trace["events"][0]["operand_kinds"], ["key", "plaintext"])
        self.assertEqual(trace["events"][0]["overload"], "key_plaintext")
        self.assertEqual(trace["events"][1]["input_ciphertexts"], [encrypted_id])
        self.assertEqual(trace["events"][1]["output_ciphertexts"], [])
        self.assertEqual(trace["events"][1]["operand_kinds"], ["ciphertext", "key"])
        self.assertEqual(trace["events"][1]["overload"], "ct_key")
        self.assertEqual(
            trace["events"][0]["argument_representations"],
            [repr(public_key), repr(plaintext)],
        )
        self.assertEqual(trace["events"][1]["output_representation"], repr(decrypted))
        self.assertEqual(trace["ciphertexts"][0]["created_by_event"], "event_0001")
        self.assertEqual(trace["ciphertexts"][0]["parent_ids"], [])
        graph = build_graph(trace)
        self.assertIn(
            {"edge_type": "produces", "from": "event_0001", "to": encrypted_id},
            graph["edges"],
        )
        self.assertIn(
            {"edge_type": "consumes", "from": encrypted_id, "to": "event_0002"},
            graph["edges"],
        )

    def test_four_operation_vertical_slice_and_trace_contract(self) -> None:
        backend = FakeCryptoContext()
        left = FakeCiphertext()
        right = FakeCiphertext(level=1, noise_scale_degree=2)

        with cipherscope.trace(backend, name="unit-workload") as session:
            rotated = session.context.EvalRotate(left, 3)
            added = session.context.EvalAdd(rotated, right)
            multiplied = session.context.EvalMult(added, right)
            result = session.context.EvalBootstrap(multiplied)

        trace = session.to_trace()
        self.assertEqual(
            set(trace), {"schema_version", "run", "context", "events", "ciphertexts"}
        )
        self.assertEqual(result.level, 0)
        self.assertEqual(
            [event["operation"] for event in trace["events"]],
            ["EvalRotate", "EvalAdd", "EvalMult", "EvalBootstrap"],
        )
        self.assertEqual([event["sequence"] for event in trace["events"]], [1, 2, 3, 4])
        self.assertEqual(
            trace["events"][0]["semantic_arguments"], {"rotation_index_requested": 3}
        )
        self.assertEqual(trace["run"]["coverage"]["traced_semantic_calls"], 4)
        self.assertEqual(trace["run"]["status"], "completed")
        self.assertEqual(trace["run"]["tool"]["name"], "cipherscope")
        self.assertIn("runtime", trace["run"])
        self.assertIs(trace["run"]["shadow_mode"], False)
        self.assertEqual(trace["context"]["ring_dimension"], 32768)
        self.assertEqual(
            {
                name: backend.calls[name]
                for name in ("EvalRotate", "EvalAdd", "EvalMult", "EvalBootstrap")
            },
            {"EvalRotate": 1, "EvalAdd": 1, "EvalMult": 1, "EvalBootstrap": 1},
        )

        states = trace["ciphertexts"]
        self.assertEqual(states[0]["origin"], "preexisting")
        self.assertIsNone(states[0]["created_by_event"])
        self.assertTrue(all(state["id"].startswith("ct_") for state in states))
        known_ids = {state["id"] for state in states}
        for event in trace["events"]:
            self.assertLessEqual(set(event["input_ciphertexts"]), known_ids)
            self.assertLessEqual(set(event["output_ciphertexts"]), known_ids)

    def test_native_failure_records_exactly_one_error_event(self) -> None:
        backend = FakeCryptoContext()
        backend.fail_operations["EvalMult"] = RuntimeError("do-not-record-this-secret")
        left = FakeCiphertext()
        right = FakeCiphertext()

        with cipherscope.trace(backend) as session:
            with self.assertRaisesRegex(RuntimeError, "do-not-record"):
                session.context.EvalMult(left, right)

        trace = session.to_trace(status="failed")
        self.assertEqual(backend.calls["EvalMult"], 1)
        self.assertEqual(len(trace["events"]), 1)
        event = trace["events"][0]
        self.assertEqual(event["status"], "error")
        self.assertEqual(event["error_class"], "RuntimeError")
        self.assertEqual(event["output_ciphertexts"], [])
        self.assertEqual(event["error_message"], "do-not-record-this-secret")

    def test_input_snapshot_precedes_timing_and_native_invocation(self) -> None:
        order: list[str] = []

        class OrderedCiphertext(FakeCiphertext):
            def GetLevel(self) -> int:
                order.append("input-get-level")
                return super().GetLevel()

            def GetNoiseScaleDeg(self) -> int:
                order.append("input-get-noise")
                return super().GetNoiseScaleDeg()

        class OrderedBackend(FakeCryptoContext):
            def EvalBootstrap(self, ciphertext: FakeCiphertext) -> FakeCiphertext:
                order.append("native")
                return super().EvalBootstrap(ciphertext)

        backend = OrderedBackend()
        value = OrderedCiphertext()
        clock_values = iter((100, 200))

        def wall_clock() -> int:
            order.append("wall-clock")
            return next(clock_values)

        with mock.patch(
            "cipherscope.context.time.perf_counter_ns", side_effect=wall_clock
        ):
            with cipherscope.trace(backend) as session:
                session.context.EvalBootstrap(value)

        self.assertEqual(backend.calls["EvalBootstrap"], 1)
        native_index = order.index("native")
        clock_index = order.index("wall-clock")
        self.assertLess(order.index("input-get-level"), clock_index)
        self.assertLess(order.index("input-get-noise"), clock_index)
        self.assertLess(order.index("input-get-level"), native_index)
        self.assertLess(order.index("input-get-noise"), native_index)

    def test_missing_covered_native_method_still_records_one_error_event(self) -> None:
        class IncompleteBackend:
            scheme = "CKKS"
            ring_dimension = 16
            configured_multiplicative_depth = 1

            def GetRingDimension(self) -> int:
                return self.ring_dimension

        with cipherscope.trace(IncompleteBackend()) as session:
            with self.assertRaises(AttributeError):
                session.context.EvalBootstrap(FakeCiphertext())
        events = session.to_trace(status="failed")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["status"], "error")
        self.assertEqual(events[0]["error_class"], "AttributeError")
        self.assertEqual(events[0]["output_ciphertexts"], [])

    def test_fresh_outputs_aliases_and_preexisting_roots(self) -> None:
        backend = FakeCryptoContext()
        source = FakeCiphertext()
        with cipherscope.trace(backend) as session:
            first = session.context.EvalRotate(source, 1)
            second = session.context.EvalRotate(source, 2)
        self.assertIsNot(first, source)
        self.assertIsNot(second, source)
        self.assertIsNot(first, second)
        trace = session.to_trace()
        first_id = trace["events"][0]["output_ciphertexts"][0]
        second_id = trace["events"][1]["output_ciphertexts"][0]
        root_id = trace["events"][0]["input_ciphertexts"][0]
        self.assertNotEqual(first_id, second_id)
        self.assertNotIn(root_id, {first_id, second_id})
        self.assertEqual(len(trace["ciphertexts"]), 3)

        alias_backend = FakeCryptoContext()
        alias_backend.alias_operations.add("EvalRotate")
        alias_source = FakeCiphertext()
        with cipherscope.trace(alias_backend) as alias_session:
            returned = alias_session.context.EvalRotate(alias_source, 4)
        alias_trace = alias_session.to_trace()
        self.assertIs(returned, alias_source)
        alias_input = alias_trace["events"][0]["input_ciphertexts"][0]
        alias_output = alias_trace["events"][0]["output_ciphertexts"][0]
        self.assertNotEqual(alias_input, alias_output)
        self.assertEqual(alias_input.split(":")[0], alias_output.split(":")[0])
        self.assertEqual(alias_output.split(":")[1], "v1")
        self.assertEqual(len(alias_trace["ciphertexts"]), 2)

    def test_nested_multiple_outputs_are_discovered_once(self) -> None:
        class MultipleOutputBackend(FakeCryptoContext):
            def EvalBootstrap(self, ciphertext: FakeCiphertext) -> dict:
                self._called("EvalBootstrap")
                first = self._fresh(ciphertext, level=0, noise=1)
                second = self._fresh(ciphertext, level=0, noise=1)
                return {"primary": first, "aliases": [second, first]}

        backend = MultipleOutputBackend()
        with cipherscope.trace(backend) as session:
            result = session.context.EvalBootstrap(FakeCiphertext())
        trace = session.to_trace()
        event = trace["events"][0]
        self.assertIs(result["primary"], result["aliases"][1])
        self.assertEqual(len(event["output_ciphertexts"]), 2)
        self.assertEqual(len(set(event["output_ciphertexts"])), 2)
        self.assertEqual(len(trace["ciphertexts"]), 3)
        self.assertEqual(backend.calls["EvalBootstrap"], 1)

    def test_strict_unknown_fails_closed_and_permissive_counts_forwarding(self) -> None:
        strict_backend = FakeCryptoContext()
        with cipherscope.trace(strict_backend) as strict_session:
            with self.assertRaises(cipherscope.UnsupportedOperationError):
                strict_session.context.Unclassified("value")
        strict_trace = strict_session.to_trace()
        self.assertEqual(strict_backend.calls["Unclassified"], 0)
        self.assertEqual(
            strict_trace["run"]["coverage"]["unclassified_proxy_passthrough_calls"], 0
        )
        self.assertEqual(
            strict_trace["run"]["coverage"]["rejected_unclassified_calls"], 1
        )

        permissive_backend = FakeCryptoContext()
        with cipherscope.trace(permissive_backend, strict=False) as permissive_session:
            self.assertEqual(permissive_session.context.Unclassified(17), 17)
            before = permissive_backend.calls["GetRingDimension"]
            self.assertEqual(permissive_session.context.GetRingDimension(), 32768)
            self.assertEqual(permissive_backend.calls["GetRingDimension"], before + 1)
        permissive_trace = permissive_session.to_trace()
        coverage = permissive_trace["run"]["coverage"]
        self.assertEqual(coverage["unclassified_proxy_passthrough_calls"], 1)
        self.assertEqual(coverage["allowed_passthrough_calls"], 1)
        self.assertTrue(coverage["potentially_incomplete"])

    def test_source_uses_absolute_path_and_function_name(self) -> None:
        backend = FakeCryptoContext()
        with cipherscope.trace(backend) as session:
            session.context.EvalBootstrap(FakeCiphertext())
        source = session.to_trace()["events"][0]["source"]
        expected_path = Path(__file__).resolve()
        self.assertEqual(source["file"], str(expected_path))
        self.assertEqual(
            source["function"],
            self.test_source_uses_absolute_path_and_function_name.__name__,
        )
        self.assertNotIn("source_sha256", source)
        self.assertTrue(source["call_site_id"].startswith(f"site:{expected_path}:"))

    def test_active_session_attach_and_lifecycle_errors(self) -> None:
        backend = FakeCryptoContext()
        with self.assertRaises(cipherscope.NoActiveSessionError):
            cipherscope.attach(backend)

        with cipherscope.trace(backend) as session:
            proxy = session.context
            self.assertIs(cipherscope.attach(backend), proxy)
            self.assertIs(cipherscope.attach(proxy), proxy)
            with self.assertRaises(cipherscope.AlreadyTracedError):
                with cipherscope.trace(backend):
                    pass

        with self.assertRaises(cipherscope.SessionClosedError):
            proxy.EvalBootstrap(FakeCiphertext())
        with self.assertRaises(cipherscope.SessionClosedError):
            session.__enter__()

        replacement = FakeCryptoContext()
        with cipherscope.runner_session(name="test-runner") as active:
            with self.assertRaises(cipherscope.AlreadyTracedError):
                active.attach(proxy)
            with cipherscope.trace(replacement) as joined:
                self.assertIs(joined, active)
                joined.context.EvalBootstrap(FakeCiphertext())
        self.assertEqual(len(active.to_trace()["events"]), 1)

    def test_thread_safe_event_sequence_and_registry(self) -> None:
        backend = FakeCryptoContext()
        source = FakeCiphertext()
        count = 24
        barrier = threading.Barrier(count)
        errors: list[BaseException] = []

        with cipherscope.trace(backend) as session:
            proxy = session.context

            def worker(index: int) -> None:
                try:
                    barrier.wait()
                    proxy.EvalRotate(source, index)
                except BaseException as error:  # pragma: no cover - asserted below
                    errors.append(error)

            threads = [
                threading.Thread(target=worker, args=(index,)) for index in range(count)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(errors, [])
        trace = session.to_trace()
        self.assertEqual(
            [event["sequence"] for event in trace["events"]], list(range(1, count + 1))
        )
        self.assertEqual(backend.calls["EvalRotate"], count)
        roots = [
            state for state in trace["ciphertexts"] if state["origin"] == "preexisting"
        ]
        self.assertEqual(len(roots), 1)
        self.assertEqual(len(trace["ciphertexts"]), count + 1)


if __name__ == "__main__":
    unittest.main()
