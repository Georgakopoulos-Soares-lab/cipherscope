"""Thread-safe run-local identity registry for ciphertext-like objects."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Generic, Iterable, Mapping, TypeVar

from .state import CiphertextMetadata, CiphertextObservation, CiphertextState


CiphertextT = TypeVar("CiphertextT")


@dataclass
class _IdentityEntry(Generic[CiphertextT]):
    """An internal strong-reference guard; its process identity is never emitted."""

    value: CiphertextT
    base_id: str
    version: int
    trace_id: str


class CiphertextRegistry(Generic[CiphertextT]):
    """Assign opaque IDs while recognizing Python aliases by object identity.

    A strong reference is retained for the run so an internal ``id()`` lookup key
    cannot be reused. Neither that key nor an object representation is serialized.
    """

    def __init__(
        self,
        snapshotter: Callable[[CiphertextT], CiphertextMetadata],
    ) -> None:
        self._snapshotter = snapshotter
        self._next_id = 1
        self._identities: dict[int, _IdentityEntry[CiphertextT]] = {}
        self._states: dict[str, CiphertextState] = {}
        self._annotations: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def snapshot(self, value: CiphertextT) -> CiphertextMetadata:
        """Snapshot supported metadata without exposing object representations."""

        return self._snapshotter(value)

    def observe_input(
        self,
        value: CiphertextT,
        metadata: CiphertextMetadata | None = None,
    ) -> CiphertextObservation:
        """Resolve an input, creating an explicit preexisting root if necessary."""

        observed = metadata if metadata is not None else self.snapshot(value)
        lookup_key = id(value)
        with self._lock:
            entry = self._identities.get(lookup_key)
            if entry is not None and entry.value is value:
                return CiphertextObservation(entry.trace_id, observed)

            base_id = self._new_base_id_locked()
            trace_id = f"{base_id}:v0"
            self._identities[lookup_key] = _IdentityEntry(value, base_id, 0, trace_id)
            self._states[trace_id] = CiphertextState(
                trace_id=trace_id,
                created_by_event=None,
                parent_ids=(),
                origin="preexisting",
                metadata=observed,
            )
            return CiphertextObservation(trace_id, observed, is_fresh=True)

    def observe_output(
        self,
        value: CiphertextT,
        *,
        event_id: str,
        parent_ids: Iterable[str],
        metadata: CiphertextMetadata | None = None,
    ) -> CiphertextObservation:
        """Resolve an output alias or register a fresh derived ciphertext."""

        observed = metadata if metadata is not None else self.snapshot(value)
        lookup_key = id(value)
        with self._lock:
            entry = self._identities.get(lookup_key)
            if entry is not None and entry.value is value:
                # An operation returning an existing native object creates a new
                # immutable state version. This preserves a DAG while all aliases
                # subsequently resolve to the same current version.
                entry.version += 1
                trace_id = f"{entry.base_id}:v{entry.version}"
                entry.trace_id = trace_id
                self._states[trace_id] = CiphertextState(
                    trace_id=trace_id,
                    created_by_event=event_id,
                    parent_ids=tuple(parent_ids),
                    origin="derived",
                    metadata=observed,
                )
                return CiphertextObservation(trace_id, observed, is_fresh=False)

            base_id = self._new_base_id_locked()
            trace_id = f"{base_id}:v0"
            self._identities[lookup_key] = _IdentityEntry(value, base_id, 0, trace_id)
            self._states[trace_id] = CiphertextState(
                trace_id=trace_id,
                created_by_event=event_id,
                parent_ids=tuple(parent_ids),
                origin="derived",
                metadata=observed,
            )
            return CiphertextObservation(trace_id, observed, is_fresh=True)

    def annotate(
        self, value: CiphertextT, annotation: Mapping[str, Any]
    ) -> CiphertextObservation:
        """Attach a user annotation to the current version of a ciphertext.

        An unseen object is registered as a preexisting root first, so the
        annotation always names a concrete immutable version in the trace.
        """

        observed = self.snapshot(value)
        lookup_key = id(value)
        with self._lock:
            entry = self._identities.get(lookup_key)
            if entry is None or entry.value is not value:
                base_id = self._new_base_id_locked()
                trace_id = f"{base_id}:v0"
                self._identities[lookup_key] = _IdentityEntry(
                    value, base_id, 0, trace_id
                )
                self._states[trace_id] = CiphertextState(
                    trace_id=trace_id,
                    created_by_event=None,
                    parent_ids=(),
                    origin="preexisting",
                    metadata=observed,
                )
                entry = self._identities[lookup_key]
            trace_id = entry.trace_id
            merged = {**self._annotations.get(trace_id, {}), **dict(annotation)}
            self._annotations[trace_id] = merged
            return CiphertextObservation(trace_id, observed)

    def state(self, trace_id: str) -> CiphertextState:
        """Return an immutable state by its opaque trace ID."""

        with self._lock:
            return self._states[trace_id]

    def states(self) -> list[dict[str, Any]]:
        """Return states in monotonic ID allocation order."""

        with self._lock:
            result: list[dict[str, Any]] = []
            for state in self._states.values():
                item = state.to_dict()
                annotation = self._annotations.get(state.trace_id)
                if annotation:
                    item["annotations"] = dict(annotation)
                result.append(item)
            return result

    def _new_base_id_locked(self) -> str:
        trace_id = f"ct_{self._next_id:04d}"
        self._next_id += 1
        return trace_id
