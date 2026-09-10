"""Thread-safe event buffering and semantic trace construction."""

from __future__ import annotations

import platform
import secrets
import sys
import threading
from typing import Any, Mapping

from .compatibility import CompatibilityRegistry
from .registry import CiphertextRegistry
from .state import SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION, copy_mapping


class EventRecorder:
    """Own one run's sequence, counters, events, and ciphertext registry."""

    def __init__(
        self,
        *,
        compatibility: CompatibilityRegistry,
        strict: bool = True,
        name: str | None = None,
        shadow_mode: bool = False,
    ) -> None:
        self.run_id = "run_" + secrets.token_hex(12)
        self.strict = strict
        self.name = name
        self.shadow_mode = shadow_mode
        self.compatibility = compatibility
        self.registry: CiphertextRegistry[Any] = CiphertextRegistry(
            compatibility.snapshot_ciphertext
        )
        self._next_sequence = 1
        self._events: list[dict[str, Any]] = []
        self._regions: list[dict[str, Any]] = []
        self._allowed_passthrough_calls = 0
        self._unclassified_passthrough_calls = 0
        self._rejected_unclassified_calls = 0
        self._backend_names: list[str] = []
        self._backend_representations: list[str] = []
        self._lock = threading.RLock()

    def next_identity(self) -> tuple[int, str]:
        """Atomically allocate a deterministic in-process event sequence."""

        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            return sequence, f"event_{sequence:04d}"

    def peek_sequence(self) -> int:
        """Return the sequence number the next event would receive."""

        with self._lock:
            return self._next_sequence

    def record_region(self, region: Mapping[str, Any]) -> None:
        """Record one user-declared region span for offline analyzers."""

        with self._lock:
            self._regions.append(copy_mapping(region))

    def record_event(self, event: Mapping[str, Any]) -> None:
        """Append one completed event without retaining caller-owned containers."""

        with self._lock:
            self._events.append(copy_mapping(event))

    def count_allowed_passthrough(self) -> None:
        with self._lock:
            self._allowed_passthrough_calls += 1

    def count_unclassified_passthrough(self) -> None:
        with self._lock:
            self._unclassified_passthrough_calls += 1

    def count_rejected_unclassified(self) -> None:
        with self._lock:
            self._rejected_unclassified_calls += 1

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
        """Build the canonical in-memory trace document."""

        if not isinstance(status, str) or not status:
            raise ValueError("status must be a non-empty string")
        with self._lock:
            events = sorted(
                (copy_mapping(event) for event in self._events),
                key=lambda event: event["sequence"],
            )
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
                "potentially_incomplete": self._unclassified_passthrough_calls > 0,
                "truncated": False,
                "failed_state_reads": sum(
                    len(event.get("missing", ())) for event in events
                ),
                "operator_overload_coverage": False,
                "original_reference_bypass_observable": False,
            }
            run: dict[str, Any] = {
                "run_id": self.run_id,
                "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
                "status": status,
                "truncated": False,
                "runtime": {
                    "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    "backend": backend,
                    "backend_representation": backend_representation,
                    "platform": platform.system().lower(),
                    "architecture": platform.machine() or "unknown",
                    "openfhe_compatibility_target": (
                        self.compatibility.compatibility_target
                    ),
                },
                "coverage": coverage,
                "shadow_mode": self.shadow_mode,
            }
            if self.name is not None:
                run["name"] = self.name
            regions = [copy_mapping(region) for region in self._regions]
        trace: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run": run,
            "context": copy_mapping(context),
            "events": events,
            "ciphertexts": self.registry.states(),
        }
        if regions:
            trace["regions"] = regions
        return trace
