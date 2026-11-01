"""The C++ frontend's Python side, tested from archived spools without GCC or OpenFHE.

tests/cpp/expected/<fixture>/ holds the runtime spool and site table recorded
on LS6 (GCC 15.2, OpenFHE 1.5.1) together with the trace the Python frontend
recorded for the twin program. Real compilation runs live in
tests/integration_cpp and need the toolchain.
"""

from __future__ import annotations

import json
import math
import struct
import tempfile
import unittest
from pathlib import Path

from cipherscope.build_discovery import CMakeBuild, parse_cmake_cache
from cipherscope.coverage import COMPLETE, PARTIAL_PERMISSIVE, classify_run
from cipherscope.frontend_parity import compare_traces, semantic_signature
from cipherscope.native_profile import MARKER_SECTION, read_marker
from cipherscope.native_trace import NativeTraceError, normalize
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.validation import validate_trace

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "native" / "openfhe" / "openfhe-1.5.operations.json"
FIXTURE = ROOT / "tests" / "cpp" / "expected" / "repeated_rotations"


def normalize_fixture(**overrides):
    options = dict(run_id="run_fixture", name="repeated_rotations", expected_translation_units=1, instrumented_binary_verified=True)
    options.update(overrides)
    return normalize(FIXTURE / "spool.jsonl", FIXTURE / "sites", MANIFEST, **options)


class NormalizerTests(unittest.TestCase):
    def test_spool_becomes_a_valid_producer_neutral_trace(self) -> None:
        trace = normalize_fixture()
        self.assertEqual(trace["run"]["producer"]["frontend"], "gcc-openfhe")
        self.assertEqual(trace["run"]["runtime"]["language"], "c++")
        self.assertEqual(trace["run"]["runtime"]["compiler_version"], "15.2.0")
        self.assertEqual(trace["run"]["runtime"]["framework_version"], "1.5.1")
        self.assertEqual([e["operation"] for e in trace["events"]],
                         ["KeyGen", "EvalRotateKeyGen", "MakeCKKSPackedPlaintext", "Encrypt", "EvalRotate", "EvalRotate", "EvalRotate", "EvalAdd", "EvalAdd", "Decrypt"])
        self.assertEqual([e["sequence"] for e in trace["events"]], list(range(1, 11)))
        rotate = trace["events"][4]
        self.assertEqual(rotate["input_ciphertexts"], ["ct_0001:v0"])
        self.assertEqual(rotate["output_ciphertexts"], ["ct_0002:v0"])
        self.assertEqual(rotate["semantic_arguments"], {"rotation_index_requested": 1})
        self.assertEqual(rotate["source"]["line"], 33)
        self.assertTrue(rotate["source"]["file"].endswith("repeated_rotations.cpp"))
        self.assertEqual(rotate["source"]["function"], "main")
        decrypt = trace["events"][-1]
        self.assertEqual(decrypt["operand_kinds"], ["ciphertext", "key"])
        self.assertEqual(decrypt["input_ciphertexts"], ["ct_0006:v0"])
        self.assertEqual(trace["events"][3]["argument_representations"], [])  # C++ never records object reprs

    def test_context_declared_parameters_and_coverage_match_the_python_shape(self) -> None:
        trace = normalize_fixture()
        context = trace["context"]
        self.assertEqual((context["ring_dimension"], context["batch_size"], context["configured_multiplicative_depth"]), (16384, 8, 1))
        self.assertEqual(context["security_level"], "HEStd_128_classic")
        self.assertEqual(context["scaling_mod_size"], 50)
        self.assertIsNone(context["declared_ring_dimension"])
        coverage = trace["run"]["coverage"]
        self.assertEqual(coverage["traced_semantic_calls"], 7)  # crypto_operation events only, like the Python recorder
        self.assertEqual(coverage["allowed_passthrough_calls"], 3)
        self.assertEqual(coverage["unmatched_openfhe_candidates"], 0)
        self.assertEqual(classify_run(trace).coverage_class, COMPLETE)

    def test_analysis_reaches_the_same_conclusions_as_the_python_twin(self) -> None:
        cpp = normalize_fixture()
        python = json.loads((FIXTURE / "python_trace.json").read_text(encoding="utf-8"))
        report = compare_traces(python, cpp, left_name="python", right_name="c++")
        self.assertTrue(report.equivalent, report.differences)
        positives = {k for k, v in build_analysis_bundle(cpp)["recommendations"]["analyzer_status"].items() if v == "positive"}
        self.assertEqual(positives, {"depth.critical_path.v1", "keys.unused_in_observed_run.v1", "rotation.hoist_same_input.v1"})
        # Depth 1 with one pending FLEXIBLEAUTO rescale is exactly enough: no headroom finding.
        self.assertEqual(build_analysis_bundle(cpp)["recommendations"]["analyzer_status"]["parameters.depth_headroom_observed.v1"], "clean")

    def test_every_archived_twin_pair_is_equivalent(self) -> None:
        for name in ("repeated_rotations", "operators_inplace", "aliasing", "exception",
                     "many_and_series", "bfv_arithmetic", "bgv_arithmetic", "checkpoints"):
            with self.subTest(fixture=name):
                root = ROOT / "tests" / "cpp" / "expected" / name
                cpp = normalize(root / "spool.jsonl", root / "sites", MANIFEST, run_id=f"run_{name}", instrumented_binary_verified=True, expected_translation_units=1)
                python = json.loads((root / "python_trace.json").read_text(encoding="utf-8"))
                report = compare_traces(python, cpp, left_name="python", right_name="c++")
                self.assertTrue(report.equivalent, report.differences)

    def test_vector_composites_series_and_aliases_normalize_like_python(self) -> None:
        root = ROOT / "tests" / "cpp" / "expected" / "many_and_series"
        trace = normalize(root / "spool.jsonl", root / "sites", MANIFEST, run_id="run_many", instrumented_binary_verified=True, expected_translation_units=1)
        by_op = {}
        for event in trace["events"]:
            by_op.setdefault(event["operation"], event)
        # EvalAtIndexKeyGen / EvalAtIndex are recorded under their canonical names.
        self.assertIn("EvalRotateKeyGen", by_op)
        self.assertIn("EvalRotate", by_op)
        self.assertNotIn("EvalAtIndex", by_op)
        self.assertNotIn("EvalAtIndexKeyGen", by_op)
        for operation in ("EvalAddMany", "EvalMultMany", "EvalLinearWSum"):
            with self.subTest(operation=operation):
                event = by_op[operation]
                # Every element of the std::vector is an input, in order, like a Python list.
                self.assertEqual(event["input_ciphertexts"], ["ct_0001:v0", "ct_0002:v0", "ct_0003:v0"])
                self.assertEqual(len(event["input_states"]), 3)
                self.assertEqual(event["operand_kinds"][0], "collection")
                self.assertEqual(event["semantic_arguments"], {"operand_count": 3})
                self.assertEqual(len(event["output_ciphertexts"]), 1)
        series = by_op["EvalChebyshevSeries"]
        self.assertEqual(series["operand_kinds"], ["ciphertext", "collection", "scalar", "scalar"])
        self.assertEqual(series["semantic_arguments"], {"polynomial_degree": 3, "lower_bound": -8, "upper_bound": 8})
        self.assertEqual(series["input_ciphertexts"], ["ct_0001:v0"])
        lineage = {c["id"]: c for c in trace["ciphertexts"]}
        self.assertEqual(lineage[by_op["EvalMultMany"]["output_ciphertexts"][0]]["parent_ids"], ["ct_0001:v0", "ct_0002:v0", "ct_0003:v0"])
        self.assertEqual(trace["run"]["coverage"]["unmatched_openfhe_candidates"], 0)
        self.assertEqual(classify_run(trace).coverage_class, COMPLETE)

    def test_bfv_and_bgv_schemes_come_from_declared_parameters(self) -> None:
        expectations = {
            "bfv_arithmetic": ("BFV", 8192, "NORESCALE"),
            "bgv_arithmetic": ("BGV", 16384, "FLEXIBLEAUTOEXT"),
        }
        for name, (scheme, ring, scaling) in expectations.items():
            with self.subTest(fixture=name):
                root = ROOT / "tests" / "cpp" / "expected" / name
                trace = normalize(root / "spool.jsonl", root / "sites", MANIFEST, run_id=f"run_{name}", instrumented_binary_verified=True, expected_translation_units=1)
                context = trace["context"]
                self.assertEqual(context["scheme"], scheme)
                self.assertEqual(context["scheme_evidence"], "declared_parameters")
                self.assertEqual(context["ring_dimension"], ring)
                # Integer schemes pack N slots (CKKS packs N/2) and the batch size is N.
                self.assertEqual(context["available_slots"], ring)
                self.assertEqual(context["batch_size"], ring)
                self.assertEqual(context["plaintext_modulus"], 65537)
                self.assertEqual(context["scaling_technique"], scaling)
                self.assertEqual(context["declared_multiplicative_depth"], 2)
                self.assertTrue(any(e["operation"] == "MakePackedPlaintext" for e in trace["events"]))
                self.assertEqual(validate_trace(trace).issues, ())
        # A CKKS spool reports no plaintext modulus: that slot holds the scaling modulus size.
        self.assertIsNone(normalize_fixture()["context"]["plaintext_modulus"])
        self.assertEqual(normalize_fixture()["context"]["scheme"], "CKKS")

    def test_annotations_and_checkpoints_are_evidence_not_inference(self) -> None:
        root = ROOT / "tests" / "cpp" / "expected" / "checkpoints"
        trace = normalize(root / "spool.jsonl", root / "sites", MANIFEST, run_id="run_checkpoints", instrumented_binary_verified=True, expected_translation_units=1)
        self.assertTrue(trace["run"]["shadow_mode"])
        kinds = [(e["kind"], e["operation"]) for e in trace["events"] if e["kind"] in {"annotation", "checkpoint"}]
        self.assertEqual(kinds, [("annotation", "AnnotatePlaintext"), ("annotation", "AnnotatePlaintext"), ("annotation", "Annotate"),
                                 ("checkpoint", "PrecisionCheckpoint"), ("annotation", "Annotate"), ("checkpoint", "PrecisionCheckpoint")])
        by_op = {}
        for event in trace["events"]:
            by_op.setdefault(event["operation"], []).append(event)
        packing = by_op["Annotate"][0]
        self.assertEqual(packing["semantic_arguments"], {"shape": [4], "packing": "row_major", "meaningful_slots": 4})
        self.assertEqual(packing["input_ciphertexts"], ["ct_0001:v0"])
        self.assertEqual(packing["operand_kinds"], ["ciphertext"])
        self.assertTrue(packing["source"]["file"].endswith("checkpoints.cpp"))
        self.assertEqual((packing["source"]["line"], packing["source"]["function"]), (40, "main"))
        self.assertIsNone(packing["overload"])
        states = {c["id"]: c for c in trace["ciphertexts"]}
        self.assertEqual(states["ct_0001:v0"]["annotations"], packing["semantic_arguments"])
        self.assertEqual(states["ct_0002:v0"]["annotations"], {"provenance": "model_parameter"})
        plaintext = by_op["AnnotatePlaintext"][0]
        self.assertEqual(plaintext["operand_kinds"], ["plaintext"])
        self.assertEqual(plaintext["semantic_arguments"]["constant_id"], "layer0")
        fresh, later = by_op["PrecisionCheckpoint"]
        for checkpoint in (fresh, later):
            arguments = checkpoint["semantic_arguments"]
            self.assertEqual(arguments["status"], "ok")
            self.assertEqual(len(arguments["expected_values"]), len(arguments["observed_values"]))
            # Same metric functions as the Python session.
            self.assertEqual(arguments["absolute_bits"], -math.log2(arguments["max_abs_error"]))
        self.assertEqual(fresh["semantic_arguments"]["tolerance_status"], "undeclared")
        self.assertEqual(later["semantic_arguments"]["tolerance"], {"min_bits": 40.0})
        self.assertEqual(later["semantic_arguments"]["violated"], ["min_bits"])
        self.assertLess(later["semantic_arguments"]["absolute_bits"], fresh["semantic_arguments"]["absolute_bits"])
        self.assertEqual(sum(e["operation"] == "Decrypt" for e in trace["events"]), 1, "the runtime's own decryption is not an event")
        statuses = build_analysis_bundle(trace)["recommendations"]["analyzer_status"]
        for rule in ("precision.checkpoint_drop.v1", "precision.tolerance_violated.v1", "packing.low_utilization_annotated.v1",
                     "encoding.repeated_public_constant.v1", "provenance.public_value_ciphertext_mult.v1"):
            self.assertEqual(statuses[rule], "positive", rule)
        # A program without the opt-in header yields no such evidence: not_applicable, never faked.
        plain = build_analysis_bundle(normalize_fixture())["recommendations"]["analyzer_status"]
        self.assertFalse(normalize_fixture()["run"]["shadow_mode"])
        for rule in ("precision.checkpoint_drop.v1", "packing.low_utilization_annotated.v1", "provenance.public_value_ciphertext_mult.v1"):
            self.assertEqual(plain[rule], "not_applicable", rule)

    def test_invalid_annotation_records_become_error_events(self) -> None:
        root = ROOT / "tests" / "cpp" / "expected" / "checkpoints"
        lines = (root / "spool.jsonl").read_text(encoding="utf-8").splitlines()
        meta_index = next(i for i, line in enumerate(lines) if '"record":"meta"' in line)
        bad = json.loads(lines[meta_index])
        bad.update({"sequence": 900, "status": "error", "error_class": "annotation_error", "error_message": "at least one annotation field is required",
                    "operation": "Annotate", "annotation": {}, "ciphertext": {"id": "ct_0001:v0", "state": None}})
        lines.insert(meta_index + 1, json.dumps(bad))
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "spool.jsonl"
            spool.write_text("\n".join(lines) + "\n", encoding="utf-8")
            trace = normalize(spool, root / "sites", MANIFEST, run_id="run_bad", instrumented_binary_verified=True, expected_translation_units=1)
        errors = [e for e in trace["events"] if e["status"] == "error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual((errors[0]["kind"], errors[0]["error_class"]), ("annotation", "annotation_error"))
        self.assertEqual(errors[0]["output_ciphertexts"], [])
        # An invalid annotation never reaches the ciphertext's recorded annotations.
        states = {c["id"]: c for c in trace["ciphertexts"]}
        self.assertEqual(states["ct_0001:v0"]["annotations"], {"shape": [4], "packing": "row_major", "meaningful_slots": 4})

    def test_parity_comparator_reports_semantic_differences_only(self) -> None:
        cpp = normalize_fixture()
        python = json.loads((FIXTURE / "python_trace.json").read_text(encoding="utf-8"))
        self.assertEqual(semantic_signature(cpp), semantic_signature(python))
        changed = json.loads(json.dumps(cpp))
        changed["events"][4]["semantic_arguments"]["rotation_index_requested"] = 7
        report = compare_traces(python, changed)
        self.assertTrue(any("rotation_index_requested" in d for d in report.differences))

    def test_unmatched_calls_and_truncation_downgrade_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spool = Path(temporary) / "spool.jsonl"
            lines = (FIXTURE / "spool.jsonl").read_text(encoding="utf-8").splitlines()
            end_index = next(i for i, line in enumerate(lines) if '"record":"run_end"' in line.replace(" ", ""))
            end = json.loads(lines[end_index])
            end.update({"unmatched_candidates": 1, "truncated": True, "truncation_reason": "max_events", "calls_dropped": 4})
            lines[end_index] = json.dumps(end)
            lines.insert(end_index, json.dumps({"record": "unmatched", "site_id": "site_x", "name": "EvalSumRows", "sequence": 99}))
            spool.write_text("\n".join(lines) + "\n", encoding="utf-8")
            trace = normalize(spool, FIXTURE / "sites", MANIFEST, run_id="run_t", instrumented_binary_verified=True)
        self.assertTrue(trace["run"]["truncated"])
        self.assertEqual(trace["run"]["coverage"]["unsupported_operations"], ["EvalSumRows"])
        self.assertEqual(trace["run"]["coverage"]["truncation"]["calls_dropped"], 4)
        assessment = classify_run(trace)
        self.assertEqual(assessment.coverage_class, PARTIAL_PERMISSIVE)
        self.assertTrue(any("EvalSumRows" in r for r in assessment.reasons))

    def test_unwound_call_becomes_an_error_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spool = Path(temporary) / "spool.jsonl"
            lines = (FIXTURE / "spool.jsonl").read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                record = json.loads(line)
                if record["record"] == "event" and record["operation"] == "EvalAdd":
                    record.update({"status": "error", "error_class": "native_unwound", "error_message": "unwound", "result": {"kind": "none"}})
                    lines[i] = json.dumps(record)
                    break
            spool.write_text("\n".join(lines) + "\n", encoding="utf-8")
            trace = normalize(spool, FIXTURE / "sites", MANIFEST, run_id="run_e")
        error = next(e for e in trace["events"] if e["status"] == "error")
        self.assertEqual(error["error_class"], "native_unwound")
        self.assertEqual(error["output_ciphertexts"], [])

    def test_unknown_operation_in_spool_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spool = Path(temporary) / "spool.jsonl"
            spool.write_text(json.dumps({"record": "event", "sequence": 1, "operation": "EvalMystery", "site_id": "s", "arguments": [], "result": {"kind": "none"}, "timing": {"start_ns": 0, "wall_duration_ns": 1}}) + "\n", encoding="utf-8")
            with self.assertRaises(NativeTraceError):
                normalize(spool, FIXTURE / "sites", MANIFEST, run_id="run_x")


class BuildDiscoveryTests(unittest.TestCase):
    def test_cache_entries_forwarded_include_user_definitions_but_not_internals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "CMakeCache.txt"
            cache.write_text(
                "# comment\nCMAKE_BUILD_TYPE:STRING=Release\nCMAKE_CXX_COMPILER:STRING=/usr/bin/g++\n"
                "OpenFHE_DIR:UNINITIALIZED=/opt/openfhe/lib/OpenFHE\nCMAKE_CACHEFILE_DIR:INTERNAL=/tmp/build\n"
                "CMAKE_HOME_DIRECTORY:INTERNAL=/src\nMY_OPTION:BOOL=ON\nCMAKE_MAKE_PROGRAM:FILEPATH=/usr/bin/make\n",
                encoding="utf-8",
            )
            entries = parse_cmake_cache(cache)
            build = CMakeBuild(Path("/src"), Path(temporary), cache, None, Path("/usr/bin/g++"), "15.2.0", "Unix Makefiles", "Release", entries)
        definitions = build.forwarded_definitions
        self.assertIn("-DOpenFHE_DIR=/opt/openfhe/lib/OpenFHE", definitions)
        self.assertIn("-DCMAKE_BUILD_TYPE:STRING=Release", definitions)
        self.assertIn("-DMY_OPTION:BOOL=ON", definitions)
        self.assertFalse(any("CMAKE_HOME_DIRECTORY" in d or "CMAKE_CACHEFILE_DIR" in d or "CMAKE_MAKE_PROGRAM" in d for d in definitions))


class MarkerTests(unittest.TestCase):
    def _elf_with_section(self, name: bytes, payload: bytes) -> bytes:
        # Minimal ELF64 little-endian file: header, two sections (marker, shstrtab).
        shstrtab = b"\0" + name + b"\0" + b".shstrtab\0"
        header_size = 64
        payload_off = header_size
        shstr_off = payload_off + len(payload)
        shoff = shstr_off + len(shstrtab)
        header = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8)
        header += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 2)
        sections = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sections += struct.pack("<IIQQQQIIQQ", 1, 1, 0, 0, payload_off, len(payload), 0, 0, 1, 0)
        sections += struct.pack("<IIQQQQIIQQ", 1 + len(name) + 1, 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0)
        return bytes(header) + payload + shstrtab + sections

    def test_marker_is_read_from_the_dedicated_section(self) -> None:
        payload = b"cipherscope.instrumented=true;frontend=gcc-openfhe;frontend_version=0.1.0;schema_major=1;manifest=openfhe-1.5-v1\0"
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "app"
            binary.write_bytes(self._elf_with_section(MARKER_SECTION.encode(), payload))
            marker = read_marker(binary)
            plain = Path(temporary) / "plain"
            plain.write_bytes(self._elf_with_section(b".note.other", b"x\0"))
            self.assertIsNone(read_marker(plain))
            (Path(temporary) / "text").write_text("not an elf", encoding="utf-8")
            self.assertIsNone(read_marker(Path(temporary) / "text"))
        self.assertEqual(marker["frontend"], "gcc-openfhe")
        self.assertEqual(marker["manifest"], "openfhe-1.5-v1")


if __name__ == "__main__":
    unittest.main()
