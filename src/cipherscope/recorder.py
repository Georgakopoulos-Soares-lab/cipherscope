"""Collect events and build a trace for one session."""

from __future__ import annotations

import json
import os
import platform
import secrets
import sys
import tempfile
import threading
import weakref
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .compatibility import CompatibilityRegistry
from .fingerprint import build_fingerprint
from .registry import CiphertextRegistry
from .state import SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION, copy_mapping

# Events are kept serialized; above this many they are appended to a JSONL spool.
SPOOL_BUFFER_EVENTS = 4096


class _Spool:
    """Keep serialized JSON lines in memory up to a limit, then append them to a file."""

    def __init__(self, buffer_lines: int, directory: Path | None, prefix: str) -> None:
        self._buffer: list[str] = []
        self._buffer_lines = max(1, int(buffer_lines))
        self._directory = directory
        self._prefix = prefix
        self.path: Path | None = None
        self._finalizer: weakref.finalize | None = None

    def append(self, line: str, *, flush: bool = True) -> None:
        self._buffer.append(line)
        if flush:
            self.flush_if_full()

    def flush_if_full(self) -> None:
        if len(self._buffer) >= self._buffer_lines:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        if self.path is None:
            handle, name = tempfile.mkstemp(
                prefix=self._prefix, suffix=".jsonl", dir=self._directory
            )
            os.close(handle)
            self.path = Path(name)
            self._finalizer = weakref.finalize(self, _unlink_quietly, name)
        # Swap first: a GC weakref callback may append while the write allocates.
        pending, self._buffer = self._buffer, []
        with self.path.open("a", encoding="utf-8") as stream:
            stream.writelines(f"{line}\n" for line in pending)

    def read_all(self) -> list[dict[str, Any]]:
        lines: list[str] = []
        if self.path is not None and self.path.is_file():
            with self.path.open("r", encoding="utf-8") as stream:
                lines.extend(line for line in stream if line.strip())
        lines.extend(self._buffer)
        return [json.loads(line) for line in lines]


class EventRecorder:
    """Own one run's sequence, counters, events, and ciphertext registry."""

    def __init__(
        self,
        *,
        compatibility: CompatibilityRegistry,
        strict: bool = True,
        name: str | None = None,
        shadow_mode: bool = False,
        allow_testing_security: bool = False,
        max_events: int | None = None,
        max_trace_bytes: int | None = None,
        spool_dir: str | os.PathLike[str] | None = None,
        spool_buffer_events: int = SPOOL_BUFFER_EVENTS,
    ) -> None:
        for label, limit in (("max_events", max_events), ("max_trace_bytes", max_trace_bytes)):
            if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
                raise ValueError(f"{label} must be a positive integer or None")
        self.run_id = "run_" + secrets.token_hex(12)
        self.strict = strict
        self.name = name
        self.shadow_mode = shadow_mode
        self.allow_testing_security = allow_testing_security
        self.max_events = max_events
        self.max_trace_bytes = max_trace_bytes
        self.compatibility = compatibility
        directory = None if spool_dir is None else Path(spool_dir)
        self._events = _Spool(spool_buffer_events, directory, "cipherscope-events-")
        self._states = _Spool(spool_buffer_events, directory, "cipherscope-states-")
        self.registry: CiphertextRegistry[Any] = CiphertextRegistry(
            compatibility.snapshot_ciphertext, sink=self._sink_state
        )
        self._next_sequence = 1
        self._events_written = 0
        self._bytes_written = 0
        self._calls_dropped = 0
        self._truncation_reason: str | None = None
        self.accepting = True
        self._regions: list[dict[str, Any]] = []
        self._allowed_passthrough_calls = 0
        self._unclassified_passthrough_calls = 0
        self._rejected_unclassified_calls = 0
        self._unsupported_operations: set[str] = set()
        self._backend_names: list[str] = []
        self._backend_representations: list[str] = []
        self._lock = threading.RLock()

    def next_identity(self) -> tuple[int, str]:
        """Allocate the next event sequence and ID."""

        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            return sequence, f"event_{sequence:04d}"

    def peek_sequence(self) -> int:
        """Return the sequence number the next event would receive."""

        with self._lock:
            return self._next_sequence

    def record_region(self, region: Mapping[str, Any]) -> None:
        """Record one user-declared region for later analysis."""

        with self._lock:
            self._regions.append(copy_mapping(region))

    def record_event(self, event: Mapping[str, Any]) -> None:
        """Serialize and keep one completed event; apply the size limits afterwards."""

        owned = copy_mapping(event)
        line = json.dumps(owned, sort_keys=True, default=repr)
        with self._lock:
            self._events.append(line)
            # States arrive from GC callbacks; write them to disk here, not there.
            self._states.flush_if_full()
            self._events_written += 1
            self._bytes_written += len(line) + 1
            if self.max_events is not None and self._events_written >= self.max_events:
                self._stop("max_events")
            elif self.max_trace_bytes is not None and self._bytes_written >= self.max_trace_bytes:
                self._stop("max_trace_bytes")

    def _sink_state(self, state: Mapping[str, Any]) -> None:
        line = json.dumps(state, sort_keys=True, default=repr)
        with self._lock:
            self._states.append(line, flush=False)

    def _stop(self, reason: str) -> None:
        if self.accepting:
            self.accepting = False
            self._truncation_reason = reason

    def count_dropped_call(self) -> None:
        """Count a call that ran natively after the trace stopped accepting events."""

        with self._lock:
            self._calls_dropped += 1

    def _all_events(self) -> list[dict[str, Any]]:
        events = self._events.read_all()
        events.sort(key=lambda event: (event["sequence"], str(event.get("event_id", ""))))
        return events

    def _all_states(self) -> list[dict[str, Any]]:
        # Memory first, then the spool: a GC callback may finalize a state between
        # the two reads, in which case it shows up in both and is deduplicated.
        live = self.registry.states()
        spooled = self._states.read_all()
        merged: dict[str, dict[str, Any]] = {}
        for state in [*spooled, *live]:
            merged.setdefault(str(state.get("id", "")), state)
        states = list(merged.values())
        states.sort(key=_state_order)
        return states

    @property
    def spool_path(self) -> Path | None:
        return self._events.path

    @property
    def events_written(self) -> int:
        return self._events_written

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def calls_dropped(self) -> int:
        return self._calls_dropped

    def count_allowed_passthrough(self) -> None:
        with self._lock:
            self._allowed_passthrough_calls += 1

    def count_unclassified_passthrough(self, name: str) -> None:
        with self._lock:
            self._unclassified_passthrough_calls += 1
            self._unsupported_operations.add(name)

    def count_rejected_unclassified(self, name: str) -> None:
        with self._lock:
            self._rejected_unclassified_calls += 1
            self._unsupported_operations.add(name)

    def register_backend(self, context: Any) -> None:
        """Record the backend class and representation."""

        backend_name = type(context).__name__
        backend_representation = repr(context)
        with self._lock:
            if backend_name not in self._backend_names:
                self._backend_names.append(backend_name)
                self._backend_representations.append(backend_representation)

    def to_trace(
        self,
        *,
        context: Mapping[str, Any],
        status: str = "completed",
    ) -> dict[str, Any]:
        """Build the complete trace document."""

        if not isinstance(status, str) or not status:
            raise ValueError("status must be a non-empty string")
        with self._lock:
            events = self._all_events()
            states = self._all_states()
            truncated = not self.accepting
            traced_calls = sum(
                1 for event in events if event.get("kind") == "crypto_operation"
            )
            backend = self._backend_names[0] if self._backend_names else "unknown"
            backend_representation = (
                self._backend_representations[0]
                if self._backend_representations
                else "unknown"
            )
            coverage = {
                "strict": self.strict,
                "traced_semantic_calls": traced_calls,
                "allowed_passthrough_calls": self._allowed_passthrough_calls,
                "unclassified_proxy_passthrough_calls": (
                    self._unclassified_passthrough_calls
                ),
                "rejected_unclassified_calls": self._rejected_unclassified_calls,
                "unsupported_operations": sorted(self._unsupported_operations),
                "potentially_incomplete": self._unclassified_passthrough_calls > 0,
                "truncated": truncated,
                "failed_state_reads": sum(
                    len(event.get("missing", ())) for event in events
                ),
                "operator_overload_coverage": False,
                "original_reference_bypass_observable": False,
            }
            if truncated:
                coverage["truncation"] = {
                    "reason": self._truncation_reason,
                    "limit": (
                        self.max_events
                        if self._truncation_reason == "max_events"
                        else self.max_trace_bytes
                    ),
                    "events_written": self._events_written,
                    "bytes_written": self._bytes_written,
                    "calls_dropped": self._calls_dropped,
                }
            run: dict[str, Any] = {
                "run_id": self.run_id,
                "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
                "status": status,
                "truncated": truncated,
                "runtime": {
                    "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    "backend": backend,
                    "backend_representation": backend_representation,
                    "platform": platform.system().lower(),
                    "architecture": platform.machine() or "unknown",
                    "openfhe_compatibility_target": (
                        self.compatibility.compatibility_target
                    ),
                    **copy_mapping(build_fingerprint()),
                },
                "coverage": coverage,
                "shadow_mode": self.shadow_mode,
                "testing_security_acknowledged": self.allow_testing_security,
            }
            if self.name is not None:
                run["name"] = self.name
            regions = [copy_mapping(region) for region in self._regions]
        trace: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run": run,
            "context": copy_mapping(context),
            "events": events,
            "ciphertexts": states,
        }
        if regions:
            trace["regions"] = regions
        if truncated:
            trace["truncated"] = True
        return trace


def _state_order(state: Mapping[str, Any]) -> tuple[int, int, str]:
    """Allocation order: numeric base ID, then version (ct_0012:v3 -> (12, 3))."""

    identifier = str(state.get("id", ""))
    base, _, version = identifier.partition(":v")
    digits = base.rpartition("_")[2]
    return (
        int(digits) if digits.isdigit() else 2**62,
        int(version) if version.isdigit() else 0,
        identifier,
    )


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
