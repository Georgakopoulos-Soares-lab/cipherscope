"""Track ciphertext IDs and versions for one tracing session."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from .state import CiphertextMetadata, CiphertextObservation, CiphertextState

CiphertextT = TypeVar("CiphertextT")


@dataclass
class _IdentityEntry(Generic[CiphertextT]):
    """Track one object without keeping weak-referenceable objects alive.

    The callback removes the entry when the object is collected. This prevents
    a later object with the same ``id()`` from being mistaken for it.
    """

    ref: Callable[[], CiphertextT | None]
    base_id: str
    version: int
    ciphertext_id: str

    @property
    def value(self) -> CiphertextT | None:
        return self.ref()


class CiphertextRegistry(Generic[CiphertextT]):
    """Assign ciphertext IDs and recognize aliases by Python object identity."""

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

    def _make_entry_locked(
        self,
        value: CiphertextT,
        base_id: str,
        version: int,
        ciphertext_id: str,
        lookup_key: int,
    ) -> _IdentityEntry[CiphertextT]:
        def _on_collected(dead_ref: Any) -> None:
            with self._lock:
                current = self._identities.get(lookup_key)
                if current is not None and current.ref is dead_ref:
                    del self._identities[lookup_key]

        try:
            ref = weakref.ref(value, _on_collected)
        except TypeError:

            def ref() -> CiphertextT | None:
                return value

        return _IdentityEntry(ref, base_id, version, ciphertext_id)

    def snapshot(self, value: CiphertextT) -> CiphertextMetadata:
        """Read the supported metadata from a ciphertext."""

        return self._snapshotter(value)

    def observe_input(
        self,
        value: CiphertextT,
        metadata: CiphertextMetadata | None = None,
    ) -> CiphertextObservation:
        """Return the input's current ID, registering it when first seen."""

        observed = metadata if metadata is not None else self.snapshot(value)
        lookup_key = id(value)
        with self._lock:
            entry = self._identities.get(lookup_key)
            if entry is not None and entry.value is value:
                return CiphertextObservation(entry.ciphertext_id, observed)

            base_id = self._new_base_id_locked()
            ciphertext_id = f"{base_id}:v0"
            self._identities[lookup_key] = self._make_entry_locked(
                value, base_id, 0, ciphertext_id, lookup_key
            )
            self._states[ciphertext_id] = CiphertextState(
                ciphertext_id=ciphertext_id,
                created_by_event=None,
                parent_ids=(),
                origin="preexisting",
                metadata=observed,
            )
            return CiphertextObservation(ciphertext_id, observed)

    def observe_output(
        self,
        value: CiphertextT,
        *,
        event_id: str,
        parent_ids: Iterable[str],
        metadata: CiphertextMetadata | None = None,
    ) -> CiphertextObservation:
        """Create the output's next ID and record its parent ciphertexts."""

        observed = metadata if metadata is not None else self.snapshot(value)
        lookup_key = id(value)
        with self._lock:
            entry = self._identities.get(lookup_key)
            if entry is not None and entry.value is value:
                entry.version += 1
                ciphertext_id = f"{entry.base_id}:v{entry.version}"
                entry.ciphertext_id = ciphertext_id
                self._states[ciphertext_id] = CiphertextState(
                    ciphertext_id=ciphertext_id,
                    created_by_event=event_id,
                    parent_ids=tuple(parent_ids),
                    origin="derived",
                    metadata=observed,
                )
                return CiphertextObservation(ciphertext_id, observed)

            base_id = self._new_base_id_locked()
            ciphertext_id = f"{base_id}:v0"
            self._identities[lookup_key] = self._make_entry_locked(
                value, base_id, 0, ciphertext_id, lookup_key
            )
            self._states[ciphertext_id] = CiphertextState(
                ciphertext_id=ciphertext_id,
                created_by_event=event_id,
                parent_ids=tuple(parent_ids),
                origin="derived",
                metadata=observed,
            )
            return CiphertextObservation(ciphertext_id, observed)

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
                ciphertext_id = f"{base_id}:v0"
                self._identities[lookup_key] = self._make_entry_locked(
                    value, base_id, 0, ciphertext_id, lookup_key
                )
                self._states[ciphertext_id] = CiphertextState(
                    ciphertext_id=ciphertext_id,
                    created_by_event=None,
                    parent_ids=(),
                    origin="preexisting",
                    metadata=observed,
                )
                entry = self._identities[lookup_key]
            ciphertext_id = entry.ciphertext_id
            merged = {**self._annotations.get(ciphertext_id, {}), **dict(annotation)}
            self._annotations[ciphertext_id] = merged
            return CiphertextObservation(ciphertext_id, observed)

    def state(self, ciphertext_id: str) -> CiphertextState:
        """Return the recorded state for a ciphertext ID."""

        with self._lock:
            return self._states[ciphertext_id]

    def states(self) -> list[dict[str, Any]]:
        """Return states in ciphertext ID allocation order."""

        with self._lock:
            result: list[dict[str, Any]] = []
            for state in self._states.values():
                item = state.to_dict()
                annotation = self._annotations.get(state.ciphertext_id)
                if annotation:
                    item["annotations"] = dict(annotation)
                result.append(item)
            return result

    def _new_base_id_locked(self) -> str:
        ciphertext_id = f"ct_{self._next_id:04d}"
        self._next_id += 1
        return ciphertext_id
