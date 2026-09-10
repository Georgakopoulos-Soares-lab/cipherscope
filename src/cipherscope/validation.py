"""Strict JSON loading and semantic validation for CipherScope artifacts.

The project deliberately keeps validation in the standard library.  The JSON Schema
files shipped with CipherScope are the public interchange contract; the functions in
this module enforce the cross-record invariants that JSON Schema cannot express.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias, overload


JSONValue: TypeAlias = (
    None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
)
SUPPORTED_SCHEMA_MAJOR = 1
MAX_METADATA_STRING_LENGTH = 4096
_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class IssueCode:
    """Stable machine-readable issue codes emitted by this module."""

    DOCUMENT_TYPE = "document.type"
    FIELD_MISSING = "field.missing"
    FIELD_TYPE = "field.type"
    FIELD_VALUE = "field.value"
    SCHEMA_VERSION_FORMAT = "schema.version_format"
    SCHEMA_UNKNOWN_MAJOR = "schema.unknown_major"
    EVENT_ID_DUPLICATE = "event.id_duplicate"
    EVENT_SEQUENCE_DUPLICATE = "event.sequence_duplicate"
    EVENT_SEQUENCE_NONMONOTONIC = "event.sequence_nonmonotonic"
    EVENT_ERROR_HAS_OUTPUTS = "event.error_has_outputs"
    CIPHERTEXT_ID_DUPLICATE = "ciphertext.id_duplicate"
    REFERENCE_DANGLING_CIPHERTEXT = "reference.dangling_ciphertext"
    REFERENCE_DANGLING_EVENT = "reference.dangling_event"
    REFERENCE_INCONSISTENT = "reference.inconsistent"
    REFERENCE_DUPLICATE = "reference.duplicate"
    TIMING_NEGATIVE_DURATION = "timing.negative_duration"
    GRAPH_NODE_ID_DUPLICATE = "graph.node_id_duplicate"
    GRAPH_EDGE_DUPLICATE = "graph.edge_duplicate"
    GRAPH_DANGLING_EDGE = "graph.dangling_edge"
    GRAPH_EDGE_TYPE = "graph.edge_type"
    GRAPH_CYCLE = "graph.cycle"
    FINDING_ID_DUPLICATE = "finding.id_duplicate"
    FINDING_DANGLING_EVIDENCE = "finding.dangling_evidence"
    FINDING_DANGLING_SOURCE = "finding.dangling_source"
    ANALYSIS_STATUS = "analysis.status"
    ROTATION_SPEEDUP_CLAIM = "rotation.speedup_claim_forbidden"
    RUN_ID_MISMATCH = "run_id.mismatch"
    METADATA_LIMIT_EXCEEDED = "metadata.limit_exceeded"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One validation failure with a stable code and JSON-style path."""

    code: str
    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class ValidationResult(Sequence[ValidationIssue]):
    """Validation outcome.

    ``issues`` is a tuple so callers cannot accidentally alter a completed result.
    The object also behaves like a sequence for concise dependency-free tests.
    """

    kind: str
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    @property
    def errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    def __len__(self) -> int:
        return len(self.issues)

    @overload
    def __getitem__(self, index: int) -> ValidationIssue: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[ValidationIssue, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> ValidationIssue | tuple[ValidationIssue, ...]:
        return self.issues[index]

    def __iter__(self) -> Iterator[ValidationIssue]:
        return iter(self.issues)

    def raise_for_errors(self) -> None:
        if not self.valid:
            raise ValidationError(self.kind, self.errors)


class ValidationError(ValueError):
    """Raised when an artifact with semantic validation failures is consumed."""

    def __init__(self, kind: str, issues: Iterable[ValidationIssue]) -> None:
        self.kind = kind
        self.issues = tuple(issues)
        detail = "; ".join(
            f"{issue.code} at {issue.path}: {issue.message}"
            for issue in self.issues[:5]
        )
        if len(self.issues) > 5:
            detail += f"; and {len(self.issues) - 5} more issue(s)"
        super().__init__(f"invalid CipherScope {kind}: {detail}")


class StrictJSONError(ValueError):
    """Strict-decoding failure, including duplicate keys or non-finite numbers."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(
                "json.duplicate_key", f"duplicate JSON object key {key!r}"
            )
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise StrictJSONError(
        "json.non_finite_number", f"non-finite JSON number {token!r} is not allowed"
    )


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise StrictJSONError(
            "json.non_finite_number", f"non-finite JSON number {token!r} is not allowed"
        )
    return value


def load_json_strict(data: str | bytes | bytearray) -> JSONValue:
    """Decode strict RFC 8259 JSON.

    Python's default decoder accepts duplicate object names and JavaScript's
    ``NaN``/``Infinity`` extensions.  CipherScope rejects both, and also rejects a
    finite-looking exponent such as ``1e999`` when it overflows a Python float.
    """

    try:
        return json.loads(
            data,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except StrictJSONError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StrictJSONError("json.syntax", str(error)) from error


def load_json_file(path: str | Path) -> JSONValue:
    """Read *path* as UTF-8 and decode it with :func:`load_json_strict`."""

    return load_json_strict(Path(path).read_bytes())


# Discoverable aliases for callers accustomed to ``json.loads`` terminology.
loads_strict = load_json_strict
strict_json_loads = load_json_strict


def _add(issues: list[ValidationIssue], code: str, path: str, message: str) -> None:
    issues.append(ValidationIssue(code=code, path=path, message=message))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _mapping(
    value: Any, path: str, issues: list[ValidationIssue]
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        _add(issues, IssueCode.FIELD_TYPE, path, "must be an object")
        return None
    return value


def _list(value: Any, path: str, issues: list[ValidationIssue]) -> list[Any] | None:
    if not isinstance(value, list):
        _add(issues, IssueCode.FIELD_TYPE, path, "must be an array")
        return None
    return value


def _required(
    document: Mapping[str, Any],
    names: Iterable[str],
    path: str,
    issues: list[ValidationIssue],
) -> None:
    for name in names:
        if name not in document:
            _add(
                issues,
                IssueCode.FIELD_MISSING,
                f"{path}.{name}",
                f"required field {name!r} is missing",
            )


def _string(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
    *,
    allow_empty: bool = False,
) -> str | None:
    if not isinstance(value, str) or (not allow_empty and not value):
        suffix = "" if allow_empty else " and non-empty"
        _add(issues, IssueCode.FIELD_TYPE, path, f"must be a string{suffix}")
        return None
    return value


def _string_list(
    value: Any, path: str, issues: list[ValidationIssue]
) -> list[str] | None:
    values = _list(value, path, issues)
    if values is None:
        return None
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(values):
        item_path = f"{path}[{index}]"
        string = _string(item, item_path, issues)
        if string is None:
            continue
        result.append(string)
        if string in seen:
            _add(
                issues,
                IssueCode.REFERENCE_DUPLICATE,
                item_path,
                f"duplicate reference {string!r}",
            )
        seen.add(string)
    return result


def _validate_schema_version(
    document: Mapping[str, Any], path: str, issues: list[ValidationIssue]
) -> None:
    if "schema_version" not in document:
        _add(
            issues,
            IssueCode.FIELD_MISSING,
            f"{path}.schema_version",
            "required field 'schema_version' is missing",
        )
        return
    version = document.get("schema_version")
    if not isinstance(version, str):
        _add(
            issues,
            IssueCode.SCHEMA_VERSION_FORMAT,
            f"{path}.schema_version",
            "schema_version must be a semantic-version string",
        )
        return
    match = _SEMVER.fullmatch(version)
    if match is None:
        _add(
            issues,
            IssueCode.SCHEMA_VERSION_FORMAT,
            f"{path}.schema_version",
            f"invalid semantic version {version!r}",
        )
        return
    major = int(match.group("major"))
    if major != SUPPORTED_SCHEMA_MAJOR:
        _add(
            issues,
            IssueCode.SCHEMA_UNKNOWN_MAJOR,
            f"{path}.schema_version",
            f"schema major {major} is unsupported; expected {SUPPORTED_SCHEMA_MAJOR}",
        )


def _root(
    kind: str, document: Any, required: Iterable[str]
) -> tuple[Mapping[str, Any] | None, list[ValidationIssue]]:
    issues: list[ValidationIssue] = []
    if not isinstance(document, Mapping):
        _add(issues, IssueCode.DOCUMENT_TYPE, "$", f"{kind} must be a JSON object")
        return None, issues
    _validate_schema_version(document, "$", issues)
    _required(document, required, "$", issues)
    return document, issues


def _validate_metadata_size(
    value: Any, path: str, issues: list[ValidationIssue]
) -> None:
    """Bound user-controlled descriptive metadata without limiting event counts."""

    if isinstance(value, str):
        if len(value) > MAX_METADATA_STRING_LENGTH:
            _add(
                issues,
                IssueCode.METADATA_LIMIT_EXCEEDED,
                path,
                f"metadata string has {len(value)} characters; limit is {MAX_METADATA_STRING_LENGTH}",
            )
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if len(str(key)) > MAX_METADATA_STRING_LENGTH:
                _add(
                    issues,
                    IssueCode.METADATA_LIMIT_EXCEEDED,
                    path,
                    f"metadata key exceeds {MAX_METADATA_STRING_LENGTH} characters",
                )
            _validate_metadata_size(child, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_metadata_size(child, f"{path}[{index}]", issues)


def validate_trace(document: Any) -> ValidationResult:
    """Validate a semantic trace, including all cross-record references."""

    trace, issues = _root(
        "trace", document, ("run", "context", "events", "ciphertexts")
    )
    if trace is None:
        return ValidationResult("trace", tuple(issues))

    if "metadata" in trace:
        _validate_metadata_size(trace.get("metadata"), "$.metadata", issues)

    run = _mapping(trace.get("run"), "$.run", issues) if "run" in trace else None
    if run is not None:
        _required(run, ("run_id",), "$.run", issues)
        if "run_id" in run:
            _string(run.get("run_id"), "$.run.run_id", issues)
        if "status" in run and run.get("status") not in {
            "completed",
            "incomplete",
            "failed",
            "interrupted",
        }:
            _add(
                issues,
                IssueCode.FIELD_VALUE,
                "$.run.status",
                "must be 'completed', 'incomplete', 'failed', or 'interrupted'",
            )
    if "context" in trace:
        context = _mapping(trace.get("context"), "$.context", issues)
        if context is not None:
            scheme = context.get("scheme")
            if scheme is not None and scheme != "CKKS":
                _add(
                    issues,
                    IssueCode.FIELD_VALUE,
                    "$.context.scheme",
                    "must be 'CKKS' or null",
                )
            for field, minimum in (
                ("ring_dimension", 1),
                ("available_slots", 0),
                ("configured_multiplicative_depth", 0),
            ):
                value = context.get(field)
                if value is not None and (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < minimum
                ):
                    _add(
                        issues,
                        IssueCode.FIELD_TYPE,
                        f"$.context.{field}",
                        f"must be an integer >= {minimum} or null",
                    )

    raw_events = (
        _list(trace.get("events"), "$.events", issues) if "events" in trace else None
    )
    raw_states = (
        _list(trace.get("ciphertexts"), "$.ciphertexts", issues)
        if "ciphertexts" in trace
        else None
    )
    events: list[tuple[int, Mapping[str, Any]]] = []
    states: list[tuple[int, Mapping[str, Any]]] = []
    if raw_events is not None:
        for index, raw_event in enumerate(raw_events):
            event = _mapping(raw_event, f"$.events[{index}]", issues)
            if event is not None:
                events.append((index, event))
    if raw_states is not None:
        for index, raw_state in enumerate(raw_states):
            state = _mapping(raw_state, f"$.ciphertexts[{index}]", issues)
            if state is not None:
                states.append((index, state))

    event_ids: set[str] = set()
    sequences: set[int] = set()
    previous_sequence: int | None = None
    event_inputs: dict[str, list[str]] = {}
    event_outputs: dict[str, list[str]] = {}
    event_by_id: dict[str, Mapping[str, Any]] = {}

    for index, event in events:
        path = f"$.events[{index}]"
        _required(
            event,
            (
                "event_id",
                "sequence",
                "kind",
                "operation",
                "status",
                "source",
                "input_ciphertexts",
                "output_ciphertexts",
                "timing",
            ),
            path,
            issues,
        )
        event_id = (
            _string(event.get("event_id"), f"{path}.event_id", issues)
            if "event_id" in event
            else None
        )
        if event_id is not None:
            if event_id in event_ids:
                _add(
                    issues,
                    IssueCode.EVENT_ID_DUPLICATE,
                    f"{path}.event_id",
                    f"duplicate event ID {event_id!r}",
                )
            event_ids.add(event_id)
            event_by_id.setdefault(event_id, event)

        raw_sequence = event.get("sequence")
        if (
            not isinstance(raw_sequence, int)
            or isinstance(raw_sequence, bool)
            or raw_sequence < 0
        ):
            if "sequence" in event:
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"{path}.sequence",
                    "must be a nonnegative integer",
                )
        else:
            sequence = raw_sequence
            if sequence in sequences:
                _add(
                    issues,
                    IssueCode.EVENT_SEQUENCE_DUPLICATE,
                    f"{path}.sequence",
                    f"duplicate event sequence {sequence}",
                )
            if previous_sequence is not None and sequence <= previous_sequence:
                _add(
                    issues,
                    IssueCode.EVENT_SEQUENCE_NONMONOTONIC,
                    f"{path}.sequence",
                    f"sequence {sequence} does not follow {previous_sequence}",
                )
            sequences.add(sequence)
            previous_sequence = sequence

        for name in ("kind", "operation"):
            if name in event:
                _string(event.get(name), f"{path}.{name}", issues)
        status = event.get("status")
        if status not in {"ok", "error"}:
            if "status" in event:
                _add(
                    issues,
                    IssueCode.FIELD_VALUE,
                    f"{path}.status",
                    "must be 'ok' or 'error'",
                )
        source = (
            _mapping(event.get("source"), f"{path}.source", issues)
            if "source" in event
            else None
        )
        if source is not None:
            _required(
                source,
                ("file", "line", "function", "call_site_id"),
                f"{path}.source",
                issues,
            )
            for field in ("file", "function", "call_site_id"):
                if field in source:
                    _string(source.get(field), f"{path}.source.{field}", issues)
            line = source.get("line")
            if line is not None and (not _is_int(line) or line < 1):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"{path}.source.line",
                    "must be a positive integer",
                )

        inputs = (
            _string_list(
                event.get("input_ciphertexts"), f"{path}.input_ciphertexts", issues
            )
            if "input_ciphertexts" in event
            else None
        )
        outputs = (
            _string_list(
                event.get("output_ciphertexts"), f"{path}.output_ciphertexts", issues
            )
            if "output_ciphertexts" in event
            else None
        )
        if event_id is not None:
            event_inputs[event_id] = inputs or []
            event_outputs[event_id] = outputs or []

        output_states = event.get("output_states", [])
        if status == "error":
            has_output_states = isinstance(output_states, list) and bool(output_states)
            if outputs or has_output_states:
                _add(
                    issues,
                    IssueCode.EVENT_ERROR_HAS_OUTPUTS,
                    path,
                    "an error event must not record output ciphertexts or states",
                )
        for state_field, refs in (("input_states", inputs), ("output_states", outputs)):
            if state_field not in event:
                continue
            snapshots = _list(event.get(state_field), f"{path}.{state_field}", issues)
            if snapshots is None:
                continue
            for snapshot_index, raw_snapshot in enumerate(snapshots):
                snapshot_path = f"{path}.{state_field}[{snapshot_index}]"
                snapshot = _mapping(raw_snapshot, snapshot_path, issues)
                if snapshot is None:
                    continue
                snapshot_id = snapshot.get("id")
                if _string(snapshot_id, f"{snapshot_path}.id", issues) is not None:
                    if refs is not None and snapshot_id not in refs:
                        _add(
                            issues,
                            IssueCode.REFERENCE_INCONSISTENT,
                            f"{snapshot_path}.id",
                            f"snapshot {snapshot_id!r} is absent from {state_field[:-7]}_ciphertexts",
                        )

        timing = (
            _mapping(event.get("timing"), f"{path}.timing", issues)
            if "timing" in event
            else None
        )
        if timing is not None:
            _required(
                timing, ("start_ns", "wall_duration_ns"), f"{path}.timing", issues
            )
            start = timing.get("start_ns")
            if start is not None and (not _is_int(start) or start < 0):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"{path}.timing.start_ns",
                    "must be a nonnegative integer",
                )
            for field, value in timing.items():
                if not field.endswith("_duration_ns") or value is None:
                    continue
                if not _is_int(value):
                    _add(
                        issues,
                        IssueCode.FIELD_TYPE,
                        f"{path}.timing.{field}",
                        "must be a nonnegative integer or null",
                    )
                elif value < 0:
                    _add(
                        issues,
                        IssueCode.TIMING_NEGATIVE_DURATION,
                        f"{path}.timing.{field}",
                        "duration must not be negative",
                    )
        if "semantic_arguments" in event:
            _validate_metadata_size(
                event.get("semantic_arguments"), f"{path}.semantic_arguments", issues
            )

    ciphertext_ids: set[str] = set()
    state_by_id: dict[str, Mapping[str, Any]] = {}
    for index, state in states:
        path = f"$.ciphertexts[{index}]"
        _required(
            state, ("id", "created_by_event", "parent_ids", "origin"), path, issues
        )
        ciphertext_id = (
            _string(state.get("id"), f"{path}.id", issues) if "id" in state else None
        )
        if ciphertext_id is not None:
            if ciphertext_id in ciphertext_ids:
                _add(
                    issues,
                    IssueCode.CIPHERTEXT_ID_DUPLICATE,
                    f"{path}.id",
                    f"duplicate ciphertext ID {ciphertext_id!r}",
                )
            ciphertext_ids.add(ciphertext_id)
            state_by_id.setdefault(ciphertext_id, state)
        created_by = state.get("created_by_event")
        if created_by is not None:
            _string(created_by, f"{path}.created_by_event", issues)
        if "parent_ids" in state:
            _string_list(state.get("parent_ids"), f"{path}.parent_ids", issues)
        if "origin" in state:
            _string(state.get("origin"), f"{path}.origin", issues)
        for field in ("level", "noise_scale_degree"):
            value = state.get(field)
            if value is not None and (not _is_int(value) or value < 0):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"{path}.{field}",
                    "must be a nonnegative integer or null",
                )

    for event_id, references in event_inputs.items():
        for reference in references:
            if reference not in ciphertext_ids:
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_CIPHERTEXT,
                    f"$.events[{event_id}].input_ciphertexts",
                    f"unknown ciphertext {reference!r}",
                )
    producers: dict[str, str] = {}
    for event_id, references in event_outputs.items():
        for reference in references:
            if reference not in ciphertext_ids:
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_CIPHERTEXT,
                    f"$.events[{event_id}].output_ciphertexts",
                    f"unknown ciphertext {reference!r}",
                )
            if reference in producers and producers[reference] != event_id:
                _add(
                    issues,
                    IssueCode.REFERENCE_INCONSISTENT,
                    f"$.events[{event_id}].output_ciphertexts",
                    f"ciphertext {reference!r} is produced by multiple events",
                )
            producers[reference] = event_id

    for index, state in states:
        path = f"$.ciphertexts[{index}]"
        state_id = state.get("id")
        created_by = state.get("created_by_event")
        parents = state.get("parent_ids")
        if created_by is not None and created_by not in event_ids:
            _add(
                issues,
                IssueCode.REFERENCE_DANGLING_EVENT,
                f"{path}.created_by_event",
                f"unknown event {created_by!r}",
            )
        elif isinstance(state_id, str) and isinstance(created_by, str):
            if state_id not in event_outputs.get(created_by, []):
                _add(
                    issues,
                    IssueCode.REFERENCE_INCONSISTENT,
                    f"{path}.created_by_event",
                    f"event {created_by!r} does not list {state_id!r} as an output",
                )
        if isinstance(parents, list):
            for parent_index, parent in enumerate(parents):
                if isinstance(parent, str) and parent not in ciphertext_ids:
                    _add(
                        issues,
                        IssueCode.REFERENCE_DANGLING_CIPHERTEXT,
                        f"{path}.parent_ids[{parent_index}]",
                        f"unknown parent ciphertext {parent!r}",
                    )
            if isinstance(created_by, str):
                valid_parents = [
                    parent for parent in parents if isinstance(parent, str)
                ]
                if set(valid_parents) != set(event_inputs.get(created_by, [])):
                    _add(
                        issues,
                        IssueCode.REFERENCE_INCONSISTENT,
                        f"{path}.parent_ids",
                        "parent_ids do not match the producing event's ciphertext inputs",
                    )
        if isinstance(state_id, str):
            producer = producers.get(state_id)
            if producer is not None and producer != created_by:
                _add(
                    issues,
                    IssueCode.REFERENCE_INCONSISTENT,
                    f"{path}.created_by_event",
                    f"created_by_event should be {producer!r}",
                )

    collisions = event_ids.intersection(ciphertext_ids)
    for identifier in sorted(collisions):
        _add(
            issues,
            IssueCode.REFERENCE_INCONSISTENT,
            "$",
            f"ID {identifier!r} is used for both an event and a ciphertext",
        )
    return ValidationResult("trace", tuple(issues))


_NODE_TYPES = {
    "RuntimeEvent",
    "CiphertextVersion",
    "SourceSite",
    "PlaintextOrigin",
    "EvalKeyRequirement",
}
_EDGE_TYPES: dict[str, tuple[str, str]] = {
    "called_from": ("RuntimeEvent", "SourceSite"),
    "consumes": ("CiphertextVersion", "RuntimeEvent"),
    "produces": ("RuntimeEvent", "CiphertextVersion"),
    "derived_from": ("CiphertextVersion", "CiphertextVersion"),
    "uses_plaintext": ("PlaintextOrigin", "RuntimeEvent"),
    "requires_key": ("RuntimeEvent", "EvalKeyRequirement"),
}


def _cycle(adjacency: Mapping[str, set[str]]) -> list[str] | None:
    # Iterative DFS with an explicit stack, not Python's call stack -- a
    # recursive `visit(child)` implementation hits Python's ~1000-frame
    # recursion limit on long dependency chains (e.g. many-iteration
    # training loops), crashing analysis on an otherwise valid trace even
    # though the underlying program ran correctly. This has no depth
    # ceiling beyond available memory. Same visited/active bookkeeping and
    # deterministic sorted-order traversal as the original, same return
    # shape (a cycle path list, or None if no cycle exists).
    visited: set[str] = set()
    for start_node in sorted(adjacency):
        if start_node in visited:
            continue
        active: set[str] = set()
        stack: list[str] = [start_node]
        iter_stack: list = [iter(sorted(adjacency.get(start_node, ())))]
        active.add(start_node)
        visited.add(start_node)
        while stack:
            node = stack[-1]
            try:
                child = next(iter_stack[-1])
            except StopIteration:
                stack.pop()
                iter_stack.pop()
                active.discard(node)
                continue
            if child in active:
                start = stack.index(child)
                return [*stack[start:], child]
            if child in visited:
                continue
            visited.add(child)
            active.add(child)
            stack.append(child)
            iter_stack.append(iter(sorted(adjacency.get(child, ()))))
    return None


def validate_graph(
    document: Any, *, trace: Mapping[str, Any] | None = None
) -> ValidationResult:
    """Validate graph structure, typed edges, references, and dependency DAGs."""

    graph, issues = _root(
        "graph",
        document,
        ("run_id", "nodes", "edges", "roots", "outputs", "critical_paths"),
    )
    if graph is None:
        return ValidationResult("graph", tuple(issues))
    if "run_id" in graph:
        _string(graph.get("run_id"), "$.run_id", issues)

    raw_nodes = (
        _list(graph.get("nodes"), "$.nodes", issues) if "nodes" in graph else None
    )
    raw_edges = (
        _list(graph.get("edges"), "$.edges", issues) if "edges" in graph else None
    )
    node_types: dict[str, str] = {}
    nodes: list[tuple[int, Mapping[str, Any]]] = []
    if raw_nodes is not None:
        for index, raw_node in enumerate(raw_nodes):
            path = f"$.nodes[{index}]"
            node = _mapping(raw_node, path, issues)
            if node is None:
                continue
            nodes.append((index, node))
            _required(node, ("id", "node_type"), path, issues)
            node_id = (
                _string(node.get("id"), f"{path}.id", issues) if "id" in node else None
            )
            node_type = (
                _string(node.get("node_type"), f"{path}.node_type", issues)
                if "node_type" in node
                else None
            )
            if node_type is not None and node_type not in _NODE_TYPES:
                _add(
                    issues,
                    IssueCode.FIELD_VALUE,
                    f"{path}.node_type",
                    f"unknown node type {node_type!r}",
                )
            if node_id is not None:
                if node_id in node_types:
                    _add(
                        issues,
                        IssueCode.GRAPH_NODE_ID_DUPLICATE,
                        f"{path}.id",
                        f"duplicate graph node ID {node_id!r}",
                    )
                elif node_type is not None:
                    node_types[node_id] = node_type

    edge_keys: set[tuple[str, str, str]] = set()
    computation: dict[str, set[str]] = {}
    lineage: dict[str, set[str]] = {}
    if raw_edges is not None:
        for index, raw_edge in enumerate(raw_edges):
            path = f"$.edges[{index}]"
            edge = _mapping(raw_edge, path, issues)
            if edge is None:
                continue
            _required(edge, ("edge_type", "from", "to"), path, issues)
            edge_type = (
                _string(edge.get("edge_type"), f"{path}.edge_type", issues)
                if "edge_type" in edge
                else None
            )
            source = (
                _string(edge.get("from"), f"{path}.from", issues)
                if "from" in edge
                else None
            )
            target = (
                _string(edge.get("to"), f"{path}.to", issues) if "to" in edge else None
            )
            if edge_type is None or source is None or target is None:
                continue
            key = (edge_type, source, target)
            if key in edge_keys:
                _add(
                    issues,
                    IssueCode.GRAPH_EDGE_DUPLICATE,
                    path,
                    f"duplicate edge {key!r}",
                )
            edge_keys.add(key)
            dangling = False
            for endpoint_name, endpoint in (("from", source), ("to", target)):
                if endpoint not in node_types:
                    dangling = True
                    _add(
                        issues,
                        IssueCode.GRAPH_DANGLING_EDGE,
                        f"{path}.{endpoint_name}",
                        f"edge references unknown node {endpoint!r}",
                    )
            expected = _EDGE_TYPES.get(edge_type)
            if expected is None:
                _add(
                    issues,
                    IssueCode.GRAPH_EDGE_TYPE,
                    f"{path}.edge_type",
                    f"unknown edge type {edge_type!r}",
                )
            elif not dangling:
                actual = (node_types[source], node_types[target])
                if actual != expected:
                    _add(
                        issues,
                        IssueCode.GRAPH_EDGE_TYPE,
                        path,
                        f"{edge_type!r} requires {expected[0]} -> {expected[1]}, got {actual[0]} -> {actual[1]}",
                    )
            if not dangling and edge_type in {"consumes", "produces"}:
                computation.setdefault(source, set()).add(target)
                computation.setdefault(target, set())
            elif not dangling and edge_type == "derived_from":
                lineage.setdefault(source, set()).add(target)
                lineage.setdefault(target, set())

    computation_cycle = _cycle(computation)
    if computation_cycle is not None:
        _add(
            issues,
            IssueCode.GRAPH_CYCLE,
            "$.edges",
            f"computation contains a cycle: {' -> '.join(computation_cycle)}",
        )

    ciphertext_ids = {
        node_id
        for node_id, node_type in node_types.items()
        if node_type == "CiphertextVersion"
    }
    event_ids = {
        node_id
        for node_id, node_type in node_types.items()
        if node_type == "RuntimeEvent"
    }
    for field in ("roots", "outputs"):
        if field not in graph:
            continue
        values = _string_list(graph.get(field), f"$.{field}", issues)
        if values is not None:
            for index, value in enumerate(values):
                if value not in ciphertext_ids:
                    _add(
                        issues,
                        IssueCode.GRAPH_DANGLING_EDGE,
                        f"$.{field}[{index}]",
                        f"unknown ciphertext node {value!r}",
                    )

    declared_lineage = {node: set(parents) for node, parents in lineage.items()}
    for index, node in nodes:
        if node.get("node_type") != "CiphertextVersion":
            continue
        path = f"$.nodes[{index}]"
        node_id = node.get("id")
        created_by = node.get("created_by_event")
        if created_by is not None and created_by not in event_ids:
            _add(
                issues,
                IssueCode.GRAPH_DANGLING_EDGE,
                f"{path}.created_by_event",
                f"unknown runtime event {created_by!r}",
            )
        parents = node.get("parent_ids", [])
        if isinstance(parents, list):
            for parent_index, parent in enumerate(parents):
                if parent not in ciphertext_ids:
                    _add(
                        issues,
                        IssueCode.GRAPH_DANGLING_EDGE,
                        f"{path}.parent_ids[{parent_index}]",
                        f"unknown ciphertext node {parent!r}",
                    )
                elif isinstance(node_id, str):
                    declared_lineage.setdefault(node_id, set()).add(parent)
                    declared_lineage.setdefault(parent, set())

    lineage_cycle = _cycle(declared_lineage)
    if lineage_cycle is not None:
        _add(
            issues,
            IssueCode.GRAPH_CYCLE,
            "$.nodes",
            f"ciphertext lineage contains a cycle: {' -> '.join(lineage_cycle)}",
        )

    critical_paths = (
        _mapping(graph.get("critical_paths"), "$.critical_paths", issues)
        if "critical_paths" in graph
        else None
    )
    if critical_paths is not None:
        for path_name, raw_summary in critical_paths.items():
            path = f"$.critical_paths.{path_name}"
            summary = _mapping(raw_summary, path, issues)
            if summary is None:
                continue
            for list_field in ("event_ids", "bootstrap_event_ids"):
                if list_field not in summary:
                    continue
                references = _string_list(
                    summary.get(list_field), f"{path}.{list_field}", issues
                )
                if references is not None:
                    for ref_index, reference in enumerate(references):
                        if reference not in event_ids:
                            _add(
                                issues,
                                IssueCode.GRAPH_DANGLING_EDGE,
                                f"{path}.{list_field}[{ref_index}]",
                                f"unknown runtime event {reference!r}",
                            )
            for numeric_field in ("max_depth", "max_levels_consumed_in_epoch"):
                numeric_value = summary.get(numeric_field)
                if numeric_value is not None and (
                    not isinstance(numeric_value, int)
                    or isinstance(numeric_value, bool)
                    or numeric_value < 0
                ):
                    _add(
                        issues,
                        IssueCode.FIELD_TYPE,
                        f"{path}.{numeric_field}",
                        "must be a nonnegative integer",
                    )

    if trace is not None:
        trace_result = validate_trace(trace)
        if trace_result.valid:
            trace_run = trace.get("run", {}).get("run_id")
            if graph.get("run_id") != trace_run:
                _add(
                    issues,
                    IssueCode.RUN_ID_MISMATCH,
                    "$.run_id",
                    f"graph run_id does not match trace run_id {trace_run!r}",
                )
            trace_events: set[str] = set()
            for event in trace.get("events", []):
                if isinstance(event, Mapping):
                    trace_event_id = event.get("event_id")
                    if isinstance(trace_event_id, str):
                        trace_events.add(trace_event_id)
            trace_ciphertexts: set[str] = set()
            for state in trace.get("ciphertexts", []):
                if isinstance(state, Mapping):
                    trace_ciphertext_id = state.get("id")
                    if isinstance(trace_ciphertext_id, str):
                        trace_ciphertexts.add(trace_ciphertext_id)
            for node_id in sorted(event_ids - trace_events):
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_EVENT,
                    "$.nodes",
                    f"runtime event {node_id!r} is absent from the trace",
                )
            for node_id in sorted(ciphertext_ids - trace_ciphertexts):
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_CIPHERTEXT,
                    "$.nodes",
                    f"ciphertext {node_id!r} is absent from the trace",
                )
            for node_id in sorted(trace_events - event_ids):
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_EVENT,
                    "$.nodes",
                    f"trace event {node_id!r} is absent from the graph",
                )
            for node_id in sorted(trace_ciphertexts - ciphertext_ids):
                _add(
                    issues,
                    IssueCode.REFERENCE_DANGLING_CIPHERTEXT,
                    "$.nodes",
                    f"trace ciphertext {node_id!r} is absent from the graph",
                )
    return ValidationResult("graph", tuple(issues))


def validate_recommendations(
    document: Any,
    *,
    trace: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
) -> ValidationResult:
    """Validate a recommendations document and optional evidence references."""

    recommendations, issues = _root("recommendations", document, ("run_id", "findings"))
    if recommendations is None:
        return ValidationResult("recommendations", tuple(issues))
    if "run_id" in recommendations:
        _string(recommendations.get("run_id"), "$.run_id", issues)
    status = recommendations.get("analysis_status")
    if status is not None and status not in {"positive", "clean", "not_applicable"}:
        _add(
            issues,
            IssueCode.ANALYSIS_STATUS,
            "$.analysis_status",
            "must be 'positive', 'clean', or 'not_applicable'",
        )
    raw_findings = (
        _list(recommendations.get("findings"), "$.findings", issues)
        if "findings" in recommendations
        else None
    )
    findings: list[tuple[int, Mapping[str, Any]]] = []
    finding_ids: set[str] = set()
    if raw_findings is not None:
        if status in {"clean", "not_applicable"} and raw_findings:
            _add(
                issues,
                IssueCode.ANALYSIS_STATUS,
                "$.findings",
                f"{status!r} analysis must not contain findings",
            )
        if status == "positive" and not raw_findings:
            _add(
                issues,
                IssueCode.ANALYSIS_STATUS,
                "$.findings",
                "positive analysis must contain at least one finding",
            )
        for index, raw_finding in enumerate(raw_findings):
            path = f"$.findings[{index}]"
            finding = _mapping(raw_finding, path, issues)
            if finding is None:
                continue
            findings.append((index, finding))
            _required(
                finding,
                (
                    "finding_id",
                    "rule_id",
                    "category",
                    "severity",
                    "confidence",
                    "source_sites",
                    "evidence_event_ids",
                    "applicability",
                    "recommendation",
                    "limitations",
                ),
                path,
                issues,
            )
            finding_id = (
                _string(finding.get("finding_id"), f"{path}.finding_id", issues)
                if "finding_id" in finding
                else None
            )
            if finding_id is not None:
                if finding_id in finding_ids:
                    _add(
                        issues,
                        IssueCode.FINDING_ID_DUPLICATE,
                        f"{path}.finding_id",
                        f"duplicate finding ID {finding_id!r}",
                    )
                finding_ids.add(finding_id)
            for field in ("rule_id", "category", "severity", "recommendation"):
                if field in finding:
                    _string(finding.get(field), f"{path}.{field}", issues)
            confidence = finding.get("confidence")
            if confidence not in {"measured", "inferred", "estimated", "unknown"}:
                if "confidence" in finding:
                    _add(
                        issues,
                        IssueCode.FIELD_VALUE,
                        f"{path}.confidence",
                        "unknown confidence value",
                    )
            for field in (
                "source_sites",
                "evidence_event_ids",
                "applicability",
                "limitations",
            ):
                if field in finding:
                    _string_list(finding.get(field), f"{path}.{field}", issues)
            impact = finding.get("estimated_impact")
            if impact is not None:
                impact_map = _mapping(impact, f"{path}.estimated_impact", issues)
                if impact_map is not None:
                    for field, value in impact_map.items():
                        if value is not None and not _is_number(value):
                            _add(
                                issues,
                                IssueCode.FIELD_TYPE,
                                f"{path}.estimated_impact.{field}",
                                "impact values must be finite numbers or null",
                            )
                    if (
                        finding.get("rule_id") == "rotation.hoist_same_input.v1"
                        and impact_map.get("speedup") is not None
                    ):
                        _add(
                            issues,
                            IssueCode.ROTATION_SPEEDUP_CLAIM,
                            f"{path}.estimated_impact.speedup",
                            "rotation hoisting must not claim speedup before a transformed rerun",
                        )

    known_events: set[Any] | None = None
    known_sources: set[Any] | None = None
    expected_run_id: Any = None
    if trace is not None and validate_trace(trace).valid:
        expected_run_id = trace.get("run", {}).get("run_id")
        known_events = {
            event.get("event_id")
            for event in trace.get("events", [])
            if isinstance(event, Mapping)
        }
        known_sources = {
            event.get("source", {}).get("call_site_id")
            for event in trace.get("events", [])
            if isinstance(event, Mapping) and isinstance(event.get("source"), Mapping)
        }
    if graph is not None and validate_graph(graph).valid:
        expected_run_id = (
            graph.get("run_id") if expected_run_id is None else expected_run_id
        )
        graph_events = {
            node.get("id")
            for node in graph.get("nodes", [])
            if isinstance(node, Mapping) and node.get("node_type") == "RuntimeEvent"
        }
        graph_sources = {
            node.get("id")
            for node in graph.get("nodes", [])
            if isinstance(node, Mapping) and node.get("node_type") == "SourceSite"
        }
        known_events = (
            graph_events if known_events is None else known_events & graph_events
        )
        known_sources = (
            graph_sources if known_sources is None else known_sources & graph_sources
        )
    if expected_run_id is not None and recommendations.get("run_id") != expected_run_id:
        _add(
            issues,
            IssueCode.RUN_ID_MISMATCH,
            "$.run_id",
            f"recommendations run_id does not match {expected_run_id!r}",
        )
    for index, finding in findings:
        path = f"$.findings[{index}]"
        if known_events is not None:
            for evidence_index, event_id in enumerate(
                finding.get("evidence_event_ids", [])
            ):
                if event_id not in known_events:
                    _add(
                        issues,
                        IssueCode.FINDING_DANGLING_EVIDENCE,
                        f"{path}.evidence_event_ids[{evidence_index}]",
                        f"unknown evidence event {event_id!r}",
                    )
        if known_sources is not None:
            for source_index, source_id in enumerate(finding.get("source_sites", [])):
                if source_id not in known_sources:
                    _add(
                        issues,
                        IssueCode.FINDING_DANGLING_SOURCE,
                        f"{path}.source_sites[{source_index}]",
                        f"unknown source site {source_id!r}",
                    )
    return ValidationResult("recommendations", tuple(issues))


def validate_manifest(
    document: Any, *, trace: Mapping[str, Any] | None = None
) -> ValidationResult:
    """Validate minimum reproducibility, coverage, and privacy manifest fields."""

    manifest, issues = _root(
        "manifest",
        document,
        (
            "run_id",
            "status",
            "tool",
            "runtime",
            "coverage",
            "privacy",
            "clocks",
            "parameter_set",
        ),
    )
    if manifest is None:
        return ValidationResult("manifest", tuple(issues))
    if "run_id" in manifest:
        _string(manifest.get("run_id"), "$.run_id", issues)
    if manifest.get("status") not in {
        "completed",
        "incomplete",
        "failed",
        "interrupted",
    }:
        if "status" in manifest:
            _add(
                issues,
                IssueCode.FIELD_VALUE,
                "$.status",
                "must be 'completed', 'incomplete', 'failed', or 'interrupted'",
            )
    for field in ("tool", "runtime", "coverage", "privacy", "clocks", "parameter_set"):
        if field in manifest:
            _mapping(manifest.get(field), f"$.{field}", issues)
    tool = manifest.get("tool")
    if isinstance(tool, Mapping):
        _required(tool, ("name", "version"), "$.tool", issues)
        for field in ("name", "version"):
            if field in tool:
                _string(tool.get(field), f"$.tool.{field}", issues)
    coverage = manifest.get("coverage")
    if isinstance(coverage, Mapping):
        _required(
            coverage,
            (
                "strict",
                "traced_semantic_calls",
                "allowed_passthrough_calls",
                "unclassified_proxy_passthrough_calls",
                "operator_overload_coverage",
                "original_reference_bypass_observable",
            ),
            "$.coverage",
            issues,
        )
        for field in (
            "traced_semantic_calls",
            "allowed_passthrough_calls",
            "unclassified_proxy_passthrough_calls",
        ):
            value = coverage.get(field)
            if value is not None and (not _is_int(value) or value < 0):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"$.coverage.{field}",
                    "must be a nonnegative integer",
                )
        for field in (
            "strict",
            "operator_overload_coverage",
            "original_reference_bypass_observable",
        ):
            value = coverage.get(field)
            if value is not None and not isinstance(value, bool):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"$.coverage.{field}",
                    "must be a boolean",
                )
    privacy = manifest.get("privacy")
    if isinstance(privacy, Mapping):
        for field in (
            "shadow_mode",
            "argv_recorded",
            "plaintext_serialized",
            "key_material_serialized",
            "object_repr_serialized",
        ):
            value = privacy.get(field)
            if value is not None and not isinstance(value, bool):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"$.privacy.{field}",
                    "must be a boolean",
                )
    clocks = manifest.get("clocks")
    if isinstance(clocks, Mapping):
        _required(clocks, ("wall", "cpu"), "$.clocks", issues)
        for field in ("wall", "cpu"):
            if field in clocks:
                _string(clocks.get(field), f"$.clocks.{field}", issues)
    parameter_set = manifest.get("parameter_set")
    if isinstance(parameter_set, Mapping):
        _required(
            parameter_set,
            ("scheme", "ring_dimension", "configured_multiplicative_depth"),
            "$.parameter_set",
            issues,
        )
        scheme = parameter_set.get("scheme")
        if scheme is not None and scheme != "CKKS":
            _add(
                issues,
                IssueCode.FIELD_VALUE,
                "$.parameter_set.scheme",
                "must be 'CKKS' or null",
            )
        for field, minimum in (
            ("ring_dimension", 1),
            ("configured_multiplicative_depth", 0),
        ):
            value = parameter_set.get(field)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < minimum
            ):
                _add(
                    issues,
                    IssueCode.FIELD_TYPE,
                    f"$.parameter_set.{field}",
                    f"must be an integer >= {minimum} or null",
                )
    if trace is not None and validate_trace(trace).valid:
        trace_run_id = trace.get("run", {}).get("run_id")
        if manifest.get("run_id") != trace_run_id:
            _add(
                issues,
                IssueCode.RUN_ID_MISMATCH,
                "$.run_id",
                f"manifest run_id does not match trace run_id {trace_run_id!r}",
            )
        trace_events = trace.get("events", [])
        if isinstance(coverage, Mapping):
            traced_calls = coverage.get("traced_semantic_calls")
            semantic_call_count = sum(
                isinstance(event, Mapping) and event.get("kind") == "crypto_operation"
                for event in trace_events
            )
            if _is_int(traced_calls) and traced_calls != semantic_call_count:
                _add(
                    issues,
                    IssueCode.REFERENCE_INCONSISTENT,
                    "$.coverage.traced_semantic_calls",
                    f"declares {traced_calls} calls but trace contains {semantic_call_count} crypto-operation events",
                )
    return ValidationResult("manifest", tuple(issues))


def validate_document(
    kind: str,
    document: Any,
    *,
    trace: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
) -> ValidationResult:
    """Dispatch validation by public artifact kind."""

    normalized = kind.lower().replace("-", "_").removesuffix(".json")
    if normalized in {"trace", "semantic_trace"}:
        return validate_trace(document)
    if normalized in {"graph", "ciphertext_graph"}:
        return validate_graph(document, trace=trace)
    if normalized in {"recommendation", "recommendations", "findings"}:
        return validate_recommendations(document, trace=trace, graph=graph)
    if normalized == "manifest":
        return validate_manifest(document, trace=trace)
    raise ValueError(f"unknown CipherScope document kind {kind!r}")


def assert_valid(
    kind: str,
    document: Any,
    *,
    trace: Mapping[str, Any] | None = None,
    graph: Mapping[str, Any] | None = None,
) -> None:
    """Raise :class:`ValidationError` when *document* is invalid."""

    validate_document(kind, document, trace=trace, graph=graph).raise_for_errors()


def load_and_validate(path: str | Path, kind: str) -> JSONValue:
    """Strictly load one artifact and raise if its semantic contract is invalid."""

    document = load_json_file(path)
    assert_valid(kind, document)
    return document


__all__ = [
    "IssueCode",
    "JSONValue",
    "MAX_METADATA_STRING_LENGTH",
    "SUPPORTED_SCHEMA_MAJOR",
    "StrictJSONError",
    "ValidationError",
    "ValidationIssue",
    "ValidationResult",
    "assert_valid",
    "load_and_validate",
    "load_json_file",
    "load_json_strict",
    "loads_strict",
    "strict_json_loads",
    "validate_document",
    "validate_graph",
    "validate_manifest",
    "validate_recommendations",
    "validate_trace",
]
