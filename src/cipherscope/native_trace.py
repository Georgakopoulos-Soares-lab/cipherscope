"""Turn the native runtime's spool into the canonical CipherScope trace.

The GCC/OpenFHE frontend (``native/``) writes an internal JSON Lines spool and
a per-translation-unit site table. This module is the only place that knows
those formats; its output is a plain trace document that ``validate_trace``
accepts and ``build_analysis_bundle`` consumes exactly like a trace recorded by
the Python proxy. It never runs an analyzer.

Parity rules (the C++ event must be structurally indistinguishable from the
Python event for the same OpenFHE call):

* canonical operation names, event kinds, default overloads and in-place
  semantics come from the operation manifest shared with the Python table;
* ``ct_ct`` / ``ct_pt`` / ``pt_ct`` / ``ct_scalar`` overloads are derived from
  the observed operand kinds for the binary Eval operations;
* ``operand_kinds`` use the same labels the Python frontend uses (``ciphertext``,
  ``plaintext``, ``key``, ``integer``, ``scalar``, ``boolean``, ``collection``,
  ``unknown``) and the same positional roles (``rotation_indices``,
  ``plaintext_values``, ``slot_count``); output parameters (``Plaintext*``) are
  not operands;
* events are renumbered contiguously; unmatched calls are counted, never turned
  into events; ``traced_semantic_calls`` counts ``crypto_operation`` events;
* metadata the adapter could not read stays ``null`` and is listed under the
  event's ``missing`` as ``input[i].field`` / ``output[i].field``.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .compatibility import available_slots_for, normalize_scheme
from .session import _precision_metrics, _real_values
from .fingerprint import build_fingerprint
from .state import SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION
from .validation import ValidationError, validate_trace

FRONTEND = "gcc-openfhe"
STATE_FIELDS = (
    "level", "noise_scale_degree", "scale", "slots", "context_id", "key_tag",
    "scaling_technique", "key_switch_technique",
)
BINARY_OPERATIONS = {"EvalAdd", "EvalAddInPlace", "EvalSub", "EvalSubInPlace", "EvalMult", "EvalMultNoRelin"}
_KIND_LABELS = {
    "ciphertext": "ciphertext",
    "ciphertext_vector": "collection",
    "plaintext": "plaintext",
    "key": "key",
    "key_pair": "unknown",
    "integer": "integer",
    "boolean": "boolean",
    "scalar": "scalar",
    "integer_vector": "collection",
    "real_vector": "collection",
    "complex_vector": "collection",
    "string": "unknown",
    "function": "unknown",
    "ccparams": "unknown",
    "context": "unknown",
    "unknown": "unknown",
}


class NativeTraceError(ValueError):
    """The spool or site table cannot be normalized."""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise NativeTraceError(f"{path}:{number}: malformed spool record: {error}") from error
            if not isinstance(record, dict) or "record" not in record:
                raise NativeTraceError(f"{path}:{number}: spool record is not an object with a 'record' key")
            records.append(record)
    return records


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {op["canonical_name"]: op for op in document["operations"]}


def load_sites(site_dir: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Return (site_id -> site record, translation-unit records)."""

    sites: dict[str, dict[str, Any]] = {}
    units: list[dict[str, Any]] = []
    for path in sorted(site_dir.glob("*.sites.jsonl")):
        current: dict[str, Any] | None = None
        for record in _read_jsonl(path):
            kind = record["record"]
            if kind == "translation_unit":
                current = dict(record)
                units.append(current)
            elif kind == "translation_unit_end" and current is not None:
                current.update({k: v for k, v in record.items() if k != "record"})
            elif kind == "site":
                sites[record["site_id"]] = record
    return sites, units


def _label(argument: Mapping[str, Any]) -> str:
    return _KIND_LABELS.get(str(argument.get("kind")), "unknown")


def _overload(operation: str, spec: Mapping[str, Any], operands: Sequence[Mapping[str, Any]]) -> str:
    if operation in BINARY_OPERATIONS and len(operands) >= 2:
        left, right = operands[0].get("kind"), operands[1].get("kind")
        if left == "ciphertext" and right == "ciphertext":
            return "ct_ct"
        if left == "ciphertext" and right == "plaintext":
            return "ct_pt"
        if left == "plaintext" and right == "ciphertext":
            return "pt_ct"
        if left == "ciphertext" and right in {"scalar", "integer"}:
            return "ct_scalar"
        if right == "ciphertext" and left in {"scalar", "integer"}:
            return "scalar_ct"
        return "unknown"
    return str(spec.get("default_overload") or "unknown")


def _state_and_missing(state: Mapping[str, Any] | None, prefix: str) -> tuple[dict[str, Any] | None, list[str]]:
    if not state:
        return None, [f"{prefix}.{field}" for field in STATE_FIELDS]
    snapshot = {"id": state["id"]}
    for field in STATE_FIELDS:
        snapshot[field] = state.get(field)
    missing = [f"{prefix}.{field}" for field in state.get("missing") or ()]
    return snapshot, missing


def _semantic_value(argument: Mapping[str, Any], key: str) -> Any:
    kind = argument.get("kind")
    if kind in {"integer", "scalar", "boolean"}:
        return argument.get("value")
    if kind == "integer_vector":
        return list(argument.get("values") or [])
    if kind == "ciphertext_vector" and key == "operand_count":
        return len(argument.get("items") or [])
    if kind == "real_vector" and key == "polynomial_degree":
        # Chebyshev coefficients: the degree, never the coefficients themselves
        # (the adapter only spools their count) -- same as the Python frontend.
        length = argument.get("length")
        return max(int(length) - 1, 0) if isinstance(length, int) else None
    return None


def _event_from_record(
    record: Mapping[str, Any],
    sequence: int,
    spec: Mapping[str, Any],
    site: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return the canonical event and the ciphertext records it creates."""

    operation = str(record["operation"])
    arguments = list(record.get("arguments") or [])
    # `this` first; it is provenance (context_id), not an operand.
    operands = [a for a in arguments[1:] if a.get("kind") not in {"context", "plaintext_out"}] if arguments and arguments[0].get("kind") == "context" else [
        a for a in arguments if a.get("kind") not in {"context", "plaintext_out"}
    ]

    if operation in {"Encrypt", "Decrypt"}:
        # OpenFHE C++ offers both argument orders; the Python wrapper has one.
        # Order operands canonically (Encrypt: key, plaintext; Decrypt:
        # ciphertext, key) so both frontends describe the same call alike.
        rank = {"Encrypt": {"key": 0, "plaintext": 1}, "Decrypt": {"ciphertext": 0, "key": 1}}[operation]
        operands = sorted(operands, key=lambda a: rank.get(str(a.get("kind")), 9))

    operand_kinds = [_label(a) for a in operands]
    roles = {int(k): v for k, v in (spec.get("operand_roles") or {}).items()}
    for index, role in roles.items():
        # A role names what a generic value at a documented position means
        # (rotation indices, plaintext values, a slot count); it never
        # overrides an operand whose type already identifies it.
        if index < len(operand_kinds) and operand_kinds[index] in {"collection", "integer", "unknown"}:
            operand_kinds[index] = role
    if roles:
        # The Python frontend only sees the arguments the caller wrote; C++
        # passes every defaulted parameter too. Keep the documented positions.
        operand_kinds = operand_kinds[: max(roles) + 1]

    # A std::vector of ciphertexts contributes its elements in order, exactly
    # as the Python frontend flattens a list argument.
    ciphertext_inputs: list[Mapping[str, Any]] = []
    selected = spec.get("ciphertext_input_indices")
    for position, argument in enumerate(operands):
        if selected is not None and position not in set(selected):
            continue
        if argument.get("kind") == "ciphertext" and argument.get("id"):
            ciphertext_inputs.append(argument)
        elif argument.get("kind") == "ciphertext_vector":
            ciphertext_inputs.extend(item for item in (argument.get("items") or []) if item.get("id"))
    input_ids: list[str] = []
    input_states: list[dict[str, Any]] = []
    missing: list[str] = []
    for argument in ciphertext_inputs:
        if argument["id"] in input_ids:
            continue
        snapshot, absent = _state_and_missing(argument.get("state"), f"input[{len(input_ids)}]")
        input_ids.append(argument["id"])
        if snapshot is not None:
            input_states.append(snapshot)
        missing.extend(absent)

    result = record.get("result") or {}
    output_ids: list[str] = []
    output_states: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []
    if result.get("kind") == "ciphertext" and result.get("id"):
        snapshot, absent = _state_and_missing(result.get("state"), "output[0]")
        output_ids.append(result["id"])
        if snapshot is not None:
            output_states.append(snapshot)
        missing.extend(absent)
        parents = list(input_ids)
        created.append({
            **(snapshot or {"id": result["id"], **{f: None for f in STATE_FIELDS}}),
            "created_by_event": f"event_{sequence:04d}",
            "parent_ids": parents,
            "origin": "derived",
        })

    semantic: dict[str, Any] = {}
    for index_text, key in (spec.get("semantic_arguments") or {}).items():
        index = int(index_text)
        if index < len(operands):
            value = _semantic_value(operands[index], key)
            if value is not None:
                semantic[key] = value

    source = {
        "file": (site or {}).get("file"),
        "line": (site or {}).get("line"),
        "function": (site or {}).get("function"),
        "qualified_function": (site or {}).get("qualified_function"),
        "call_site_id": record.get("site_id"),
    }
    if source["line"] == 0:
        source["line"] = None

    event: dict[str, Any] = {
        "event_id": f"event_{sequence:04d}",
        "sequence": sequence,
        "kind": str(spec.get("kind") or "crypto_operation"),
        "operation": operation,
        "overload": _overload(operation, spec, operands),
        "granularity": "openfhe_api_inclusive",
        "status": str(record.get("status") or "ok"),
        "argument_representations": [],
        "keyword_argument_representations": {},
        "source": source,
        "input_ciphertexts": input_ids,
        "output_ciphertexts": output_ids,
        "operand_kinds": operand_kinds,
        "timing": dict(record.get("timing") or {"start_ns": 0, "wall_duration_ns": 0}),
        "input_states": input_states,
        "output_states": output_states,
        "semantic_arguments": semantic,
        "thread_id": record.get("thread_id"),
        "missing": sorted(set(missing)),
    }
    if event["status"] == "error":
        event["error_class"] = str(record.get("error_class") or "native_error")
        event["error_message"] = str(record.get("error_message") or "")
    return event, created


def _meta_event_from_record(record: Mapping[str, Any], sequence: int) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Canonical `annotation` / `checkpoint` event for one cipherscope/annotate.h call.

    Returns the event and, for a ciphertext annotation, ``{"id": ..., "annotations": {...}}``
    to merge into that ciphertext's state (as the Python registry does).
    Metrics are computed here with the Python session's own functions, so a
    C++ checkpoint reports exactly what the Python checkpoint would.
    """

    kind = str(record.get("kind"))
    operation = str(record.get("operation"))
    source_record = dict(record.get("source") or {})
    file = source_record.get("file") or None
    line = source_record.get("line") if isinstance(source_record.get("line"), int) and source_record.get("line") > 0 else None
    function = source_record.get("function") or None
    source = {
        "file": file,
        "line": line,
        "function": function,
        "qualified_function": function,
        "call_site_id": ":".join(("site", file or "unknown", str(line), function or "unknown", operation)),
    }
    status = str(record.get("status") or "ok")
    ciphertext = record.get("ciphertext") or {}
    input_ids: list[str] = []
    input_states: list[dict[str, Any]] = []
    missing: list[str] = []
    if ciphertext.get("id"):
        input_ids.append(str(ciphertext["id"]))
        snapshot, absent = _state_and_missing(ciphertext.get("state"), "input[0]")
        if snapshot is not None:
            input_states.append(snapshot)
        missing.extend(absent)

    semantic: dict[str, Any] = {}
    merge: dict[str, Any] | None = None
    if operation == "PrecisionCheckpoint":
        checkpoint = dict(record.get("checkpoint") or {})
        expected_values = _real_values(checkpoint.get("expected_values") or [])
        observed_raw = checkpoint.get("observed_values")
        observed_values = _real_values(observed_raw) if isinstance(observed_raw, list) else []
        tolerance = checkpoint.get("tolerance")
        contract = {k: float(v) for k, v in tolerance.items()} if isinstance(tolerance, Mapping) and tolerance else None
        comparison: dict[str, Any] = {
            "status": "ok" if expected_values and len(expected_values) == len(observed_values) else "failed",
            "expected_values": expected_values,
            "observed_values": observed_values,
        }
        if comparison["status"] == "failed":
            comparison["reason"] = "shape_mismatch"
        else:
            comparison.update(_precision_metrics(expected_values, observed_values, contract))
        semantic = {"checkpoint_name": checkpoint.get("name"), **comparison}
        operand_kinds = ["ciphertext"]
    elif operation == "AnnotatePlaintext":
        semantic = dict(record.get("annotation") or {})
        operand_kinds = ["plaintext"]
    else:
        semantic = dict(record.get("annotation") or {})
        operand_kinds = ["ciphertext"]
        if status == "ok" and input_ids:
            merge = {"id": input_ids[0], "annotations": dict(semantic)}

    event: dict[str, Any] = {
        "event_id": f"event_{sequence:04d}",
        "sequence": sequence,
        "kind": kind,
        "operation": operation,
        "overload": None,
        "granularity": None,
        "status": status,
        "argument_representations": [],
        "keyword_argument_representations": {},
        "source": source,
        "input_ciphertexts": input_ids,
        "output_ciphertexts": [],
        "operand_kinds": operand_kinds,
        "timing": {"start_ns": int(record.get("start_ns") or 0), "wall_duration_ns": 0,
                   "process_cpu_duration_ns": 0, "thread_cpu_duration_ns": None},
        "input_states": input_states,
        "output_states": [],
        "semantic_arguments": semantic,
        "thread_id": record.get("thread_id"),
        "missing": sorted(set(missing)),
    }
    if status == "error":
        event["error_class"] = str(record.get("error_class") or "annotation_error")
        event["error_message"] = str(record.get("error_message") or "")
    return event, merge


def _context_block(contexts: Sequence[Mapping[str, Any]], declared: Mapping[str, Any] | None) -> dict[str, Any]:
    first = dict(contexts[0]) if contexts else {}
    ring = first.get("ring_dimension")
    # Scheme: the CCParams observed at GenCryptoContext() names it (the
    # adapter spools OpenFHE's enum name, e.g. BFVRNS_SCHEME). Without declared
    # parameters, mirror the Python contract: a BFV/BGV context packs
    # batch_size == ring_dimension, a CKKS context at most ring_dimension / 2.
    scheme: str | None
    if declared and declared.get("available") and declared.get("scheme"):
        scheme = normalize_scheme(declared.get("scheme"))
        scheme_evidence = "declared_parameters"
    elif isinstance(ring, int) and first.get("batch_size") == ring:
        scheme, scheme_evidence = None, "batch_size_equals_ring_dimension_not_ckks"
    else:
        scheme, scheme_evidence = "CKKS", "configured_ckks_contract"
    block: dict[str, Any] = {
        "context_id": first.get("context_id", "context_0001"),
        "scheme": scheme,
        "scheme_evidence": scheme_evidence,
        "ring_dimension": ring,
        "available_slots": available_slots_for(scheme, ring) if isinstance(ring, int) else None,
        "batch_size": first.get("batch_size"),
        # CKKS keeps its scaling modulus size in the encoding parameters'
        # plaintext-modulus slot; it is not a plaintext modulus. Python nulls it too.
        "plaintext_modulus": (first.get("plaintext_modulus") or None) if scheme != "CKKS" else None,
        "configured_multiplicative_depth": first.get("configured_multiplicative_depth"),
        "scaling_technique": first.get("scaling_technique"),
        "key_switch_technique": first.get("key_switch_technique"),
        "cyclotomic_order": first.get("cyclotomic_order"),
        "missing": sorted(set(first.get("missing") or ())),
    }
    if len(contexts) > 1:
        block["additional_contexts"] = [dict(c) for c in contexts[1:]]
    if declared and declared.get("available"):
        declared_ring = declared.get("ring_dimension")
        block.update({
            "declared_multiplicative_depth": declared.get("multiplicative_depth"),
            "declared_ring_dimension": declared_ring if declared_ring else None,
            "security_level": declared.get("security_level"),
            "scaling_mod_size": declared.get("scaling_mod_size"),
            "first_mod_size": declared.get("first_mod_size"),
            "parameters_missing": [],
        })
    else:
        block.update({
            "declared_multiplicative_depth": None,
            "declared_ring_dimension": None,
            "security_level": None,
            "scaling_mod_size": None,
            "parameters_missing": ["security_level", "ring_dimension", "multiplicative_depth", "scaling_mod_size"],
        })
    return block


def normalize(
    spool: Path,
    site_dir: Path,
    manifest_path: Path,
    *,
    run_id: str,
    name: str | None = None,
    exit_status: int | None = 0,
    strict: bool = True,
    expected_translation_units: int | None = None,
    instrumented_binary_verified: bool | None = None,
    runtime_metadata: Mapping[str, Any] | None = None,
    testing_security_acknowledged: bool = False,
) -> dict[str, Any]:
    """Build and validate the canonical trace for one native run."""

    records = _read_jsonl(spool)
    manifest = load_manifest(manifest_path)
    sites, units = load_sites(site_dir)

    begin = next((r for r in records if r["record"] == "run_begin"), {})
    end = next((r for r in records if r["record"] == "run_end"), None)
    contexts = next((r.get("contexts") or [] for r in records if r["record"] == "contexts"), [])
    declared = next((r.get("parameters") for r in records if r["record"] == "declared_parameters"), None)
    unmatched = [r for r in records if r["record"] == "unmatched"]

    events: list[dict[str, Any]] = []
    ciphertexts: list[dict[str, Any]] = []
    annotations: dict[str, dict[str, Any]] = {}
    checkpoints = 0
    for record in sorted((r for r in records if r["record"] in {"event", "meta"}), key=lambda r: int(r["sequence"])):
        if record["record"] == "meta":
            event, merge = _meta_event_from_record(record, len(events) + 1)
            events.append(event)
            if merge is not None:
                annotations.setdefault(merge["id"], {}).update(merge["annotations"])
            checkpoints += event["kind"] == "checkpoint"
            continue
        operation = str(record["operation"])
        spec = manifest.get(operation)
        if spec is None:
            raise NativeTraceError(f"spool names operation {operation!r} that the manifest does not define")
        event, created = _event_from_record(record, len(events) + 1, spec, sites.get(record.get("site_id")))
        events.append(event)
        ciphertexts.extend(created)

    # Inputs never produced by a recorded event were created outside the
    # instrumented boundary (or before recording started): preexisting.
    known = {c["id"] for c in ciphertexts}
    for event in events:
        for index, ct in enumerate(event["input_ciphertexts"]):
            if ct in known:
                continue
            state = next((s for s in event["input_states"] if s["id"] == ct), {"id": ct, **{f: None for f in STATE_FIELDS}})
            ciphertexts.append({**state, "created_by_event": None, "parent_ids": [], "origin": "preexisting"})
            known.add(ct)
    for state in ciphertexts:
        if state["id"] in annotations:
            state["annotations"] = annotations[state["id"]]
    ciphertexts.sort(key=_ciphertext_order)

    traced_calls = sum(1 for e in events if e["kind"] == "crypto_operation")
    unmatched_names = sorted({str(r.get("name")) for r in unmatched})
    truncated = bool(end and end.get("truncated"))
    if end is None:
        status = "failed" if exit_status not in (0, None) else "incomplete"
    elif exit_status not in (0, None):
        status = "failed"
    else:
        status = "completed"

    coverage: dict[str, Any] = {
        "strict": strict,
        "traced_semantic_calls": traced_calls,
        "allowed_passthrough_calls": int((end or {}).get("allowed_passthrough_calls") or 0),
        "unclassified_proxy_passthrough_calls": 0,
        "rejected_unclassified_calls": 0,
        "unsupported_operations": unmatched_names,
        "potentially_incomplete": len(unmatched) > 0,
        "truncated": truncated,
        "failed_state_reads": sum(len(e["missing"]) for e in events),
        "operator_overload_coverage": True,
        "original_reference_bypass_observable": False,
        "instrumentation_manifest": begin.get("manifest") or (units[0].get("manifest") if units else None) or "openfhe-1.5-v1",
        "unmatched_openfhe_candidates": len(unmatched),
        "unmatched_candidate_names": unmatched_names,
        "instrumented_translation_units": len(units),
        "expected_translation_units": expected_translation_units,
        "instrumented_binary_verified": instrumented_binary_verified,
        "nested_internal_calls": int((end or {}).get("nested_internal_calls") or 0),
        "unwound_calls": int((end or {}).get("unwound_calls") or 0),
    }
    if truncated:
        coverage["truncation"] = {
            "reason": end.get("truncation_reason"),
            "events_written": end.get("events_written"),
            "bytes_written": end.get("bytes_written"),
            "calls_dropped": end.get("calls_dropped"),
        }

    compiler_version = units[0].get("gcc") if units else None
    runtime: dict[str, Any] = {
        "language": "c++",
        "language_version": None,
        "compiler": "gcc",
        "compiler_version": compiler_version,
        "framework": "openfhe",
        "framework_version": begin.get("framework_version"),
        "backend": "CryptoContext",
        "platform": platform.system().lower(),
        "architecture": platform.machine() or "unknown",
        "openfhe_compatibility_target": f"OpenFHE C++ {begin.get('framework_version') or '1.5.x'} via GCC plugin",
        **dict(build_fingerprint()),
    }
    if runtime_metadata:
        runtime.update(dict(runtime_metadata))

    run: dict[str, Any] = {
        "run_id": run_id,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "status": status,
        "truncated": truncated,
        "producer": {
            "frontend": FRONTEND,
            "frontend_version": str(begin.get("frontend_version") or "0.1.0"),
            "instrumentation_manifest": coverage["instrumentation_manifest"],
        },
        "runtime": runtime,
        "clocks": {"wall": "CLOCK_MONOTONIC", "cpu": "CLOCK_PROCESS_CPUTIME_ID", "thread_cpu": "CLOCK_THREAD_CPUTIME_ID"},
        "coverage": coverage,
        # Evidence-based: a program that called cipherscope::checkpoint()
        # handed the runtime its secret key, exactly what shadow mode means.
        "shadow_mode": checkpoints > 0,
        "testing_security_acknowledged": testing_security_acknowledged,
    }
    if name is not None:
        run["name"] = name

    trace: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run": run,
        "context": _context_block(contexts, declared),
        "events": events,
        "ciphertexts": ciphertexts,
    }
    if truncated:
        trace["truncated"] = True
    result = validate_trace(trace)
    if not result.valid:
        raise ValidationError("trace", result.errors)
    return trace


def _ciphertext_order(state: Mapping[str, Any]) -> tuple[int, int, str]:
    identifier = str(state.get("id", ""))
    base, _, version = identifier.partition(":v")
    digits = base.rpartition("_")[2]
    return (int(digits) if digits.isdigit() else 2**62, int(version) if version.isdigit() else 0, identifier)


__all__ = ["FRONTEND", "NativeTraceError", "load_manifest", "load_sites", "normalize"]
