"""C++ / GCC / OpenFHE feasibility gate for the CipherScope native frontend.

Builds the plain fixture project under tests/cpp/fixtures with the user's GCC
and OpenFHE, profiles every fixture through `cipherscope profile` exactly as a
user would, and checks the properties the design requires: transparent shadow
builds, exact interception, operator and in-place semantics, identity and
aliasing, source attribution across optimization levels, exception behaviour,
threads, truncation, unmatched-call detection, numerical equivalence of plain
and instrumented binaries, canonical-trace validation, unchanged analyzers,
and semantic parity with the Python frontend's trace of the twin program.

    PYTHONPATH=src python3 -m tests.integration_cpp.run_gate \\
        --openfhe-dir "$BUILD_ROOT/opt/openfhe/lib/OpenFHE" \\
        --output artifact/feasibility/cpp-gcc15-openfhe151/feasibility.json

Every required check that cannot run counts against the gate; a skipped suite
is not a passed gate.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cipherscope.build_discovery import discover_cmake_build, discover_openfhe, resolve_target
from cipherscope.cli import validate_bundle
from cipherscope.coverage import COMPLETE, PARTIAL_PERMISSIVE, classify_run
from cipherscope.frontend_parity import compare_traces
from cipherscope.native_profile import cache_root_for, ensure_toolchain, profile_native, read_marker
from cipherscope.native_trace import normalize
from cipherscope.pipeline import build_analysis_bundle
from cipherscope.validation import load_json_file
from tests.integration_openfhe.run_gate import _write_private_json

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "cpp" / "fixtures"
EXPECTED = ROOT / "tests" / "cpp" / "expected"
MANIFEST = ROOT / "native" / "openfhe" / "openfhe-1.5.operations.json"
LANE = "cpp-gcc15-openfhe151"

PROGRAMS = ("repeated_rotations", "operators_inplace", "aliasing", "exception", "threads", "unmatched",
            "many_and_series", "bfv_arithmetic", "bgv_arithmetic", "checkpoints")
TWINS = ("repeated_rotations", "operators_inplace", "aliasing", "exception", "many_and_series", "bfv_arithmetic",
         "bgv_arithmetic", "checkpoints")
REPEATED_ROTATIONS_OPS = ["KeyGen", "EvalRotateKeyGen", "MakeCKKSPackedPlaintext", "Encrypt", "EvalRotate", "EvalRotate",
                          "EvalRotate", "EvalAdd", "EvalAdd", "Decrypt"]
REPEATED_ROTATIONS_LINES = [25, 27, 30, 31, 33, 34, 35, 36, 36, 39]
OPERATORS_OPS = ["KeyGen", "EvalMultKeyGen", "MakeCKKSPackedPlaintext", "MakeCKKSPackedPlaintext", "MakeCKKSPackedPlaintext",
                 "Encrypt", "Encrypt", "EvalMult", "EvalAdd", "EvalAdd", "EvalAddInPlace", "RescaleInPlace", "EvalNegate",
                 "EvalMult", "Decrypt"]
MANY_AND_SERIES_OPS = ["KeyGen", "EvalMultKeyGen", "EvalRotateKeyGen",
                       "MakeCKKSPackedPlaintext", "Encrypt", "MakeCKKSPackedPlaintext", "Encrypt", "MakeCKKSPackedPlaintext", "Encrypt",
                       "EvalAddMany", "EvalMultMany", "EvalLinearWSum", "EvalChebyshevSeries", "EvalRotate", "EvalAdd",
                       "Decrypt", "Decrypt"]
CHECKPOINTS_OPS = ["KeyGen", "EvalMultKeyGen", "MakeCKKSPackedPlaintext", "AnnotatePlaintext", "MakeCKKSPackedPlaintext",
                   "AnnotatePlaintext", "MakeCKKSPackedPlaintext", "Encrypt", "Annotate", "PrecisionCheckpoint", "Encrypt",
                   "Annotate", "EvalMult", "EvalSquare", "EvalSquare", "EvalSquare", "PrecisionCheckpoint", "Decrypt"]


class Gate:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []

    def check(self, check_id: str, description: str, fn: Callable[[], dict[str, Any] | None]) -> None:
        started = time.perf_counter_ns()
        record: dict[str, Any] = {"id": check_id, "description": f"{check_id}: {description}", "required": True}
        try:
            observed = fn()
            record["status"] = "pass"
            if observed:
                record["observed"] = observed
        except AssertionError as error:
            record["status"] = "fail"
            record["detail"] = f"AssertionError: {error}"
        except Exception as error:  # noqa: BLE001 - every failure is evidence
            record["status"] = "fail"
            record["detail"] = f"{type(error).__name__}: {error}\n{traceback.format_exc()[-1500:]}"
        record["duration_ns"] = time.perf_counter_ns() - started
        self.checks.append(record)
        print(f"{record['status']:5s} {check_id}  {description}" + (f"\n      {record.get('detail', '').splitlines()[0]}" if record["status"] != "pass" else ""), file=sys.stderr)


def run_plain(binary: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary)], capture_output=True, text=True, env=env, check=False)


def main(argv: list[str] | None = None) -> int:
    global LANE
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openfhe-dir", type=Path, default=Path(os.environ.get("CIPHERSCOPE_OPENFHE_DIR", "")) or None,
                        help="directory containing OpenFHEConfig.cmake")
    parser.add_argument("--compiler", type=Path, default=Path(shutil.which(os.environ.get("CXX", "g++")) or "g++"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifact" / "feasibility" / LANE / "feasibility.json")
    parser.add_argument("--work", type=Path, default=None, help="working directory (default: temporary)")
    parser.add_argument("--python-twin", type=Path, default=EXPECTED / "repeated_rotations" / "python_trace.json",
                        help="trace.json recorded by the Python frontend for repeated_rotations.py")
    parser.add_argument("--lane", default=None, help="lane name (default: cpp-gcc<major><minor>-openfhe<version> from the toolchain)")
    args = parser.parse_args(argv)
    if args.openfhe_dir is None or not (args.openfhe_dir / "OpenFHEConfig.cmake").is_file():
        print("cipherscope: --openfhe-dir (or CIPHERSCOPE_OPENFHE_DIR) must point at OpenFHEConfig.cmake", file=sys.stderr)
        return 2

    started = time.time_ns()
    if args.lane:
        LANE = args.lane
    else:
        version = subprocess.run([str(args.compiler), "-dumpfullversion"], capture_output=True, text=True, check=False).stdout.strip()
        openfhe_text = (args.openfhe_dir / "OpenFHEConfig.cmake").read_text(encoding="utf-8", errors="replace")
        import re as _re
        fhe = _re.search(r"-DOPENFHE_VERSION=([0-9.]+)", openfhe_text)
        LANE = f"cpp-gcc{''.join(version.split('.')[:2])}-openfhe{(fhe.group(1) if fhe else 'x').replace('.', '')}"
    if args.output == ROOT / "artifact" / "feasibility" / "cpp-gcc15-openfhe151" / "feasibility.json":
        args.output = ROOT / "artifact" / "feasibility" / LANE / "feasibility.json"
    gate = Gate()
    work = args.work or Path(tempfile.mkdtemp(prefix="cipherscope-cpp-gate-"))
    work.mkdir(parents=True, exist_ok=True)
    project = work / "project"
    if project.exists():
        shutil.rmtree(project)
    shutil.copytree(FIXTURES, project, ignore=shutil.ignore_patterns("build", ".cipherscope"))
    build = project / "build"
    env = dict(os.environ, OMP_NUM_THREADS=os.environ.get("OMP_NUM_THREADS", "1"), CIPHERSCOPE_CACHE=str(work / "cache"))
    traces: dict[str, dict[str, Any]] = {}
    outputs: dict[str, Path] = {}
    plain_stdout: dict[str, str] = {}

    # ---- plain build of the fixture project, exactly as a user would do it ----
    def plain_build() -> dict[str, Any]:
        # The fixtures are built from a copy, so the opt-in header's location is given explicitly.
        subprocess.run(["cmake", "-S", str(project), "-B", str(build), f"-DOpenFHE_DIR={args.openfhe_dir}",
                        f"-DCMAKE_CXX_COMPILER={args.compiler}", f"-DCIPHERSCOPE_INCLUDE_DIR={ROOT / 'native' / 'include'}"],
                       check=True, capture_output=True, text=True)
        subprocess.run(["cmake", "--build", str(build), "--parallel", "8"], check=True, capture_output=True, text=True)
        for name in PROGRAMS:
            assert (build / name).is_file(), f"{name} was not built"
            completed = run_plain(build / name, env)
            assert completed.returncode == 0, f"plain {name} exited {completed.returncode}: {completed.stderr[-400:]}"
            plain_stdout[name] = completed.stdout
        return {"programs": list(PROGRAMS)}

    gate.check("BUILD-01", "the plain fixture project builds and runs without CipherScope", plain_build)

    def discovery() -> dict[str, Any]:
        discovered = discover_cmake_build(build / "repeated_rotations")
        assert discovered.source_root.resolve() == project.resolve()
        assert discovered.compiler.resolve() == args.compiler.resolve(), (discovered.compiler, args.compiler)
        openfhe = discover_openfhe(discovered.cache)
        assert openfhe is not None and openfhe.version, "OpenFHE install not discovered from the cache"
        target = resolve_target(build / "repeated_rotations", discovered)
        assert target.cmake_target == "repeated_rotations"
        assert read_marker(build / "repeated_rotations") is None, "the plain binary must carry no marker"
        return {"compiler_version": discovered.compiler_version, "openfhe_version": openfhe.version, "generator": discovered.generator}

    gate.check("BUILD-02", "CMakeCache.txt yields source root, GCC, OpenFHE and the CMake target; the plain binary has no marker", discovery)

    def profile_all() -> dict[str, Any]:
        observed: dict[str, Any] = {}
        for name in PROGRAMS:
            output = work / "runs" / name
            if output.exists():
                shutil.rmtree(output)
            program_env = dict(env, OMP_NUM_THREADS="4" if name == "threads" else env["OMP_NUM_THREADS"])
            code = subprocess.run(
                [sys.executable, "-m", "cipherscope", "profile", "--output", str(output), str(build / name)],
                env=dict(program_env, PYTHONPATH=str(ROOT / "src")), cwd=str(project), capture_output=True, text=True, check=False,
            )
            assert (output / "trace.json").is_file(), f"profile of {name} produced no bundle:\n{code.stderr[-1200:]}"
            traces[name] = load_json_file(output / "trace.json")
            outputs[name] = output
            observed[name] = {"exit": code.returncode, "events": len(traces[name]["events"]),
                              "coverage": classify_run(traces[name]).coverage_class}
            (output / "profile-stdout.txt").write_text(code.stdout, encoding="utf-8")
        return observed

    gate.check("BUILD-03", "`cipherscope profile <binary>` creates an instrumented shadow build for every fixture without touching the source tree", profile_all)

    def shadow_integrity() -> dict[str, Any]:
        trace = traces["repeated_rotations"]
        coverage = trace["run"]["coverage"]
        assert coverage["instrumented_binary_verified"] is True
        assert coverage["instrumented_translation_units"] == coverage["expected_translation_units"] == 1, coverage
        marker = read_marker(Path(trace["run"]["runtime"]["instrumented_binary"]))
        assert marker and marker.get("frontend") == "gcc-openfhe", marker
        original = (build / "repeated_rotations").stat().st_mtime_ns
        assert read_marker(build / "repeated_rotations") is None, "original binary was modified"
        for path in project.rglob("*"):
            assert ".cipherscope" in path.parts or path.is_relative_to(build) or path.suffix in {".cpp", ".txt"}, f"unexpected file in source tree: {path}"
        return {"marker": marker, "original_mtime_ns": original}

    gate.check("BUILD-04", "the shadow binary carries the marker, every translation unit was instrumented, and the original binary is untouched", shadow_integrity)

    def exact_interception() -> dict[str, Any]:
        events = traces["repeated_rotations"]["events"]
        assert [e["operation"] for e in events] == REPEATED_ROTATIONS_OPS, [e["operation"] for e in events]
        rotations = [e for e in events if e["operation"] == "EvalRotate"]
        assert [e["semantic_arguments"]["rotation_index_requested"] for e in rotations] == [1, 2, 3]
        assert all(e["input_ciphertexts"] == ["ct_0001:v0"] for e in rotations), "rotations must share the same input version"
        assert events[1]["semantic_arguments"] == {"rotation_indices_requested": [1, 2, 3, 5]}
        assert traces["repeated_rotations"]["run"]["coverage"]["traced_semantic_calls"] == 7
        return {"operations": REPEATED_ROTATIONS_OPS}

    gate.check("OP-01", "every application-level OpenFHE call is intercepted exactly once with its semantic arguments", exact_interception)

    def operators() -> dict[str, Any]:
        events = traces["operators_inplace"]["events"]
        ops = [e["operation"] for e in events]
        assert ops == OPERATORS_OPS, ops
        by_seq = {e["sequence"]: e for e in events}
        assert by_seq[8]["overload"] == "ct_ct" and by_seq[8]["output_ciphertexts"], "a * b -> one EvalMult ct_ct"
        assert by_seq[10]["output_ciphertexts"], "c += d must record the assigned result"
        assert by_seq[14]["overload"] == "ct_pt", by_seq[14]["overload"]
        assert by_seq[13]["operation"] == "EvalNegate" and by_seq[13]["input_ciphertexts"] == ["ct_0001:v0"]
        return {"operations": ops}

    gate.check("OP-02", "operator*, operator+, operator+=, unary operator- and ct*pt normalize to one canonical event each", operators)

    def in_place() -> dict[str, Any]:
        by_seq = {e["sequence"]: e for e in traces["operators_inplace"]["events"]}
        add = by_seq[11]
        assert add["operation"] == "EvalAddInPlace"
        assert add["input_ciphertexts"][0].endswith(":v0") and add["output_ciphertexts"] == [add["input_ciphertexts"][0].replace(":v0", ":v1")], add
        rescale = by_seq[12]
        assert rescale["operation"] == "RescaleInPlace" and rescale["output_ciphertexts"] == [rescale["input_ciphertexts"][0].replace(":v0", ":v1")], rescale
        decrypt = by_seq[15]
        assert decrypt["input_ciphertexts"] == rescale["output_ciphertexts"], "Decrypt must read the rescaled version"
        return {"add_in_place": add["output_ciphertexts"], "rescale_in_place": rescale["output_ciphertexts"]}

    gate.check("MUT-01", "in-place operations produce the next immutable version of their operand and later calls read it", in_place)

    def composites() -> dict[str, Any]:
        events = traces["many_and_series"]["events"]
        ops = [e["operation"] for e in events]
        assert ops == MANY_AND_SERIES_OPS, ops
        by_op = {e["operation"]: e for e in events}
        fresh = ["ct_0001:v0", "ct_0002:v0", "ct_0003:v0"]
        for operation in ("EvalAddMany", "EvalMultMany", "EvalLinearWSum"):
            event = by_op[operation]
            assert event["input_ciphertexts"] == fresh and len(event["input_states"]) == 3, (operation, event["input_ciphertexts"])
            assert event["semantic_arguments"] == {"operand_count": 3} and event["operand_kinds"][0] == "collection", event
            assert len(event["output_ciphertexts"]) == 1, event
        series = by_op["EvalChebyshevSeries"]
        assert series["semantic_arguments"] == {"polynomial_degree": 3, "lower_bound": -8, "upper_bound": 8}, series["semantic_arguments"]
        assert series["input_ciphertexts"] == ["ct_0001:v0"]
        assert by_op["EvalRotate"]["semantic_arguments"] == {"rotation_index_requested": 1}
        assert by_op["EvalRotate"]["input_ciphertexts"] == by_op["EvalAddMany"]["output_ciphertexts"]
        assert by_op["EvalRotateKeyGen"]["semantic_arguments"] == {"rotation_indices_requested": [1]}
        assert "EvalAtIndex" not in ops and "EvalAtIndexKeyGen" not in ops
        parents = {c["id"]: c["parent_ids"] for c in traces["many_and_series"]["ciphertexts"]}
        assert parents[by_op["EvalMultMany"]["output_ciphertexts"][0]] == fresh
        assert traces["many_and_series"]["run"]["coverage"]["unmatched_candidate_names"] == []
        return {"operations": ops}

    gate.check("OP-03", "EvalAddMany/EvalMultMany/EvalLinearWSum record every vector element as an input, EvalChebyshevSeries its degree and bounds, and EvalAtIndex[KeyGen] their canonical names", composites)

    def schemes() -> dict[str, Any]:
        observed: dict[str, Any] = {}
        for name, scheme in (("bfv_arithmetic", "BFV"), ("bgv_arithmetic", "BGV")):
            context = traces[name]["context"]
            ring = context["ring_dimension"]
            assert context["scheme"] == scheme and context["scheme_evidence"] == "declared_parameters", context
            assert isinstance(ring, int) and context["available_slots"] == ring == context["batch_size"], context
            assert context["plaintext_modulus"] == 65537, context
            assert context["declared_multiplicative_depth"] == 2, context
            events = traces[name]["events"]
            assert any(e["operation"] == "MakePackedPlaintext" for e in events)
            assert all(e["overload"] != "unknown" for e in events), [e["operation"] for e in events if e["overload"] == "unknown"]
            observed[name] = {"scheme": scheme, "ring_dimension": ring, "events": len(events)}
        bfv_levels = {s["level"] for e in traces["bfv_arithmetic"]["events"] for s in e["output_states"]}
        assert bfv_levels == {0}, f"BFV never consumes levels: {bfv_levels}"
        ckks = traces["repeated_rotations"]["context"]
        assert ckks["scheme"] == "CKKS" and ckks["available_slots"] == ckks["ring_dimension"] // 2 and ckks["plaintext_modulus"] is None, ckks
        return observed

    def annotations() -> dict[str, Any]:
        trace = traces["checkpoints"]
        events = trace["events"]
        assert [e["operation"] for e in events] == CHECKPOINTS_OPS, [e["operation"] for e in events]
        assert trace["run"]["shadow_mode"] is True, "a program that checkpoints handed over its secret key"
        by_seq = {e["sequence"]: e for e in events}
        for seq in (4, 6):
            plaintext = by_seq[seq]
            assert plaintext["kind"] == "annotation" and plaintext["operand_kinds"] == ["plaintext"], plaintext
            assert plaintext["semantic_arguments"]["constant_id"] == "layer0" and plaintext["semantic_arguments"]["provenance"] == "model_parameter"
            assert plaintext["semantic_arguments"]["plaintext_representation"].startswith("<Plaintext Object: (1, 1, 1, 1,")
        packing = by_seq[9]
        assert packing["kind"] == "annotation" and packing["input_ciphertexts"] == ["ct_0001:v0"]
        assert packing["semantic_arguments"] == {"shape": [4], "packing": "row_major", "meaningful_slots": 4}
        assert packing["source"]["line"] == 40 and packing["source"]["function"] == "main", packing["source"]
        provenance = by_seq[12]
        assert provenance["semantic_arguments"] == {"provenance": "model_parameter"} and provenance["input_ciphertexts"] == ["ct_0002:v0"]
        states = {c["id"]: c for c in trace["ciphertexts"]}
        assert states["ct_0001:v0"]["annotations"] == packing["semantic_arguments"]
        assert states["ct_0002:v0"]["annotations"] == {"provenance": "model_parameter"}
        fresh, later = by_seq[10], by_seq[17]
        for checkpoint in (fresh, later):
            assert checkpoint["kind"] == "checkpoint" and checkpoint["status"] == "ok", checkpoint
            arguments = checkpoint["semantic_arguments"]
            assert arguments["status"] == "ok" and len(arguments["observed_values"]) == len(arguments["expected_values"]) == 4
            assert arguments["max_abs_error"] >= 0 and "absolute_bits" in arguments
        assert fresh["semantic_arguments"]["checkpoint_name"] == "fresh" and fresh["semantic_arguments"]["tolerance_status"] == "undeclared"
        assert fresh["input_ciphertexts"] == ["ct_0001:v0"]
        assert later["semantic_arguments"]["checkpoint_name"] == "after_three_squarings"
        assert later["semantic_arguments"]["tolerance"] == {"min_bits": 40.0} and later["semantic_arguments"]["violated"] == ["min_bits"]
        assert later["semantic_arguments"]["absolute_bits"] < fresh["semantic_arguments"]["absolute_bits"], "three squarings lose bits"
        # The checkpoint's decryption is the runtime's own, never a traced event.
        assert sum(e["operation"] == "Decrypt" for e in events) == 1
        statuses = build_analysis_bundle(trace)["recommendations"]["analyzer_status"]
        positives = {k for k, v in statuses.items() if v == "positive"}
        for rule in ("precision.checkpoint_drop.v1", "precision.tolerance_violated.v1", "packing.low_utilization_annotated.v1",
                     "encoding.repeated_public_constant.v1", "provenance.public_value_ciphertext_mult.v1"):
            assert rule in positives, (rule, statuses)
        # Without the opt-in evidence those rules stay not_applicable (never faked).
        plain = build_analysis_bundle(traces["repeated_rotations"])["recommendations"]["analyzer_status"]
        for rule in ("precision.checkpoint_drop.v1", "packing.low_utilization_annotated.v1", "encoding.repeated_public_constant.v1",
                     "provenance.public_value_ciphertext_mult.v1"):
            assert plain[rule] == "not_applicable", (rule, plain[rule])
        assert traces["repeated_rotations"]["run"]["shadow_mode"] is False
        return {"positives": sorted(positives), "fresh_bits": fresh["semantic_arguments"]["absolute_bits"],
                "later_bits": later["semantic_arguments"]["absolute_bits"]}

    gate.check("META-01", "cipherscope/annotate.h annotations and precision checkpoints become annotation/checkpoint events with the caller's source line, shadow_mode follows the evidence, and the annotation-dependent analyzers fire only on that evidence", annotations)

    gate.check("SCHEME-01", "BFV and BGV programs report their scheme from the declared CCParams, N packed slots and the plaintext modulus; CKKS keeps N/2 slots and no plaintext modulus", schemes)

    def identity() -> dict[str, Any]:
        trace = traces["aliasing"]
        adds = [e for e in trace["events"] if e["operation"] == "EvalAdd"]
        assert adds[0]["input_ciphertexts"] == ["ct_0001:v0"], "a copied handle is the same ciphertext"
        assert adds[1]["input_ciphertexts"] == ["ct_0002:v0", "ct_0001:v0"], "a moved handle keeps its identity"
        loop_outputs = [e["output_ciphertexts"][0] for e in adds[2:5]]
        assert len(set(loop_outputs)) == 3, f"destroyed temporaries must not share an identity: {loop_outputs}"
        identities = {c["id"].split(":")[0] for c in trace["ciphertexts"]}
        assert len(identities) == 7, identities
        assert all(c["origin"] == "derived" for c in trace["ciphertexts"])
        return {"identities": sorted(identities)}

    gate.check("ID-01", "handle copies, moves and container storage keep one identity; destroyed objects never hand their ID to a reused address", identity)

    def source_lines() -> dict[str, Any]:
        events = traces["repeated_rotations"]["events"]
        lines = [e["source"]["line"] for e in events]
        assert lines == REPEATED_ROTATIONS_LINES, lines
        assert all(e["source"]["file"].endswith("repeated_rotations.cpp") for e in events)
        assert all(e["source"]["function"] == "main" for e in events)
        # The nested EvalAdd calls on line 36 are two call sites (different columns): distinct IDs.
        assert len({e["source"]["call_site_id"] for e in events}) == len(events), "every call site needs its own ID"
        return {"lines": lines}

    gate.check("SRC-01", "events resolve to the exact user source file, line and function", source_lines)

    def optimization_levels() -> dict[str, Any]:
        discovered = discover_cmake_build(build / "repeated_rotations")
        openfhe = discover_openfhe(discovered.cache)
        toolchain = ensure_toolchain(discovered.compiler, discovered.compiler_version, openfhe, Path(env["CIPHERSCOPE_CACHE"]))
        observed: dict[str, list[int]] = {}
        for level in ("-O0", "-O2", "-O3"):
            directory = work / f"opt{level[1:]}"
            if directory.exists():
                shutil.rmtree(directory)
            (directory / "sites").mkdir(parents=True)
            binary = directory / "repeated_rotations"
            subprocess.run([
                str(discovered.compiler), "-std=c++17", level, "-w", *openfhe.include_flags,
                *[f for f in openfhe.cxx_flags if f.startswith(("-D", "-f", "-m"))],
                f"-fplugin={toolchain.plugin}", f"-fplugin-arg-libcipherscope_gcc-manifest={toolchain.manifest_txt}",
                f"-fplugin-arg-libcipherscope_gcc-site-dir={directory / 'sites'}",
                str(project / "repeated_rotations.cpp"), "-o", str(binary),
                f"-L{toolchain.directory}", "-lcipherscope_openfhe", f"-Wl,-rpath,{toolchain.directory}", *openfhe.link_flags,
            ], check=True, capture_output=True, text=True)
            spool = directory / "spool.jsonl"
            completed = subprocess.run([str(binary)], env=dict(env, CIPHERSCOPE_NATIVE_SPOOL=str(spool)), capture_output=True, text=True, check=False)
            assert completed.returncode == 0, completed.stderr[-400:]
            trace = normalize(spool, directory / "sites", MANIFEST, run_id=f"run_{level[1:]}", instrumented_binary_verified=True, expected_translation_units=1)
            observed[level] = [e["source"]["line"] for e in trace["events"]]
            assert observed[level] == REPEATED_ROTATIONS_LINES, (level, observed[level])
            assert [e["operation"] for e in trace["events"]] == REPEATED_ROTATIONS_OPS, level
        return observed

    gate.check("SRC-02", "the same events and source lines are recorded at -O0, -O2 and -O3 (instrumentation precedes optimization)", optimization_levels)

    def exceptions() -> dict[str, Any]:
        trace = traces["exception"]
        assert trace["run"]["status"] == "completed", trace["run"]["status"]
        errors = [e for e in trace["events"] if e["status"] == "error"]
        assert len(errors) == 1 and errors[0]["operation"] == "EvalRotate" and errors[0]["semantic_arguments"] == {"rotation_index_requested": 4}, errors
        assert errors[0]["error_class"] == "native_unwound" and errors[0]["output_ciphertexts"] == []
        following = [e for e in trace["events"] if e["sequence"] > errors[0]["sequence"]]
        assert [e["operation"] for e in following] == ["EvalRotate", "Decrypt"] and following[0]["status"] == "ok"
        assert trace["run"]["coverage"]["unwound_calls"] == 1
        assert "caught=1" in plain_stdout["exception"]
        return {"error_event": errors[0]["event_id"]}

    gate.check("EXC-01", "a throwing OpenFHE call becomes an error event, the application's catch runs unchanged, and tracing continues", exceptions)

    def threads() -> dict[str, Any]:
        trace = traces["threads"]
        adds = [e for e in trace["events"] if e["operation"] == "EvalAdd"]
        assert len(adds) == 8, len(adds)
        thread_ids = {e["thread_id"] for e in adds}
        assert len(thread_ids) >= 2, f"expected concurrent threads, saw {thread_ids}"
        assert all(e["input_ciphertexts"] and e["output_ciphertexts"] and e["output_states"] for e in adds)
        assert len({e["sequence"] for e in trace["events"]}) == len(trace["events"])
        return {"thread_ids": sorted(thread_ids)}

    gate.check("THR-01", "concurrent semantic calls from OpenMP threads are recorded once each with their own thread IDs and complete lineage", threads)

    def numerical() -> dict[str, Any]:
        observed: dict[str, bool] = {}
        for name in PROGRAMS:
            instrumented = (outputs[name] / "profile-stdout.txt").read_text(encoding="utf-8")
            expected = plain_stdout[name]
            if name == "threads":
                expected = expected.replace("threads=1", "threads=4")
            assert instrumented.strip() == expected.strip(), f"{name}: plain and instrumented output differ:\n{expected}\n---\n{instrumented}"
            observed[name] = True
        return observed

    gate.check("NUM-01", "the instrumented binaries print exactly what the plain binaries print (same decrypted results, same control flow)", numerical)

    def unmatched() -> dict[str, Any]:
        assessment = classify_run(traces["unmatched"])
        coverage = traces["unmatched"]["run"]["coverage"]
        assert assessment.coverage_class == PARTIAL_PERMISSIVE, assessment
        assert coverage["unmatched_candidate_names"] == ["EvalAddMutable", "EvalMultMutable"], coverage["unmatched_candidate_names"]
        assert coverage["unsupported_operations"] == coverage["unmatched_candidate_names"]
        for name in PROGRAMS:
            if name != "unmatched":
                assert classify_run(traces[name]).coverage_class == COMPLETE, (name, classify_run(traces[name]))
        return {"unmatched": coverage["unmatched_candidate_names"]}

    gate.check("COV-01", "an executed OpenFHE call outside the manifest denies COMPLETE and is named; every other fixture is COMPLETE", unmatched)

    def truncation() -> dict[str, Any]:
        output = work / "runs" / "truncated"
        if output.exists():
            shutil.rmtree(output)
        code = profile_native(build / "repeated_rotations", [], output=output, max_events=5, stream=open(os.devnull, "w"))
        assert code == 0, code
        trace = load_json_file(output / "trace.json")
        assert trace["run"]["truncated"] is True and trace["run"]["coverage"]["truncation"]["reason"] == "max_events"
        assert classify_run(trace).coverage_class != COMPLETE
        assert validate_bundle(output) == []
        return {"events": len(trace["events"]), "calls_dropped": trace["run"]["coverage"]["truncation"]["calls_dropped"]}

    gate.check("LIMIT-01", "a hard event limit stops recording, never the workload, and the truncated bundle validates as incomplete", truncation)

    def canonical() -> dict[str, Any]:
        for name in PROGRAMS:
            assert validate_bundle(outputs[name]) == [], name
            trace = traces[name]
            assert trace["run"]["producer"]["frontend"] == "gcc-openfhe"
            assert trace["run"]["runtime"]["language"] == "c++"
            artifacts = build_analysis_bundle(trace)  # the unchanged pipeline
            assert artifacts["recommendations"]["run_id"] == trace["run"]["run_id"]
            text = json.dumps(trace)
            assert "0x" not in text.replace("0x", "", 0) or "object at 0x" not in text, "native addresses must never reach the trace"
        return {"validated": list(PROGRAMS)}

    gate.check("TRACE-01", "every bundle validates against the canonical schemas and runs through the unchanged graph/analyzer/export pipeline", canonical)

    def analyzers() -> dict[str, Any]:
        statuses = build_analysis_bundle(traces["repeated_rotations"])["recommendations"]["analyzer_status"]
        positives = {k for k, v in statuses.items() if v == "positive"}
        assert positives == {"depth.critical_path.v1", "keys.unused_in_observed_run.v1", "rotation.hoist_same_input.v1"}, positives
        # Depth 1 with the last product's rescale still pending is exactly enough.
        assert statuses["parameters.depth_headroom_observed.v1"] == "clean"
        assert statuses["precision.checkpoint_drop.v1"] == "not_applicable"
        return {"positives": sorted(positives)}

    gate.check("PIPE-01", "the existing analyzers reach the expected diagnoses on the C++ trace and mark unavailable evidence not_applicable", analyzers)

    def parity() -> dict[str, Any]:
        observed: dict[str, int] = {}
        for name in TWINS:
            twin = args.python_twin if name == "repeated_rotations" else EXPECTED / name / "python_trace.json"
            python_trace = load_json_file(twin)
            report = compare_traces(python_trace, traces[name], left_name="python", right_name="c++")
            assert report.equivalent, (name, report.differences)
            observed[name] = len(report.left_signature)
        return observed

    gate.check("PARITY-01", "the C++ traces of the twin programs (rotations, operators/in-place, aliasing, exception, vector composites/series, BFV, BGV, annotations/checkpoints) are semantically equivalent to the Python frontend's traces", parity)

    # ---- artifact ----
    counts = {status: sum(c["status"] == status for c in gate.checks) for status in ("pass", "fail", "skip")}
    status = "fail" if counts["fail"] else ("incomplete" if counts["skip"] else "native_pass")
    discovered = discover_cmake_build(build / "repeated_rotations") if (build / "CMakeCache.txt").is_file() else None
    openfhe = discover_openfhe(discovered.cache) if discovered else None
    os_release: dict[str, str] = {}
    release = Path("/etc/os-release")
    if release.is_file():
        for line in release.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    document = {
        "schema_version": "1.0.0",
        "gate": "CipherScope GCC/OpenFHE C++ frontend feasibility",
        "lane": LANE,
        "authoritative_for_primary_target": False,
        "status": status,
        "started_unix_ns": started,
        "duration_ns": time.time_ns() - started,
        "environment": {
            "lane": LANE,
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.system(),
            "machine": platform.machine(),
            "os_release": os_release,
            "compiler": str(discovered.compiler) if discovered else str(args.compiler),
            "compiler_version": discovered.compiler_version if discovered else None,
            "openfhe_version": openfhe.version if openfhe else None,
            "openfhe_dir": str(args.openfhe_dir),
            "frontend": "gcc-openfhe",
            "frontend_version": "0.1.0",
            "instrumentation_manifest": json.loads(MANIFEST.read_text(encoding="utf-8"))["name"],
        },
        "summary": {**counts, "total": len(gate.checks)},
        "checks": gate.checks,
        "limitations": [
            "GCC only; the compiler that built the target must provide plugin headers.",
            "CMake projects only; the CMake target is resolved from the binary name unless --cmake-target is given.",
            "An instrumented call nested inside another (a user callback invoked by OpenFHE that calls the API) is read as an unwound call.",
            "Fixtures use HEStd_128_classic defaults with small batch sizes for tractability; they are coverage evidence, not benchmarks.",
        ],
        "fixtures": [f"tests/cpp/fixtures/{name}.cpp" for name in PROGRAMS],
    }
    _write_private_json(args.output, document)
    print(json.dumps({"status": status, "lane": LANE, "summary": document["summary"], "output": str(args.output)}, sort_keys=True))
    return 0 if status == "native_pass" else 1


if __name__ == "__main__":
    sys.exit(main())
