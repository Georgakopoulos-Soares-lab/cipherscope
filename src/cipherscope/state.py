"""Small, JSON-shaped state values used by the core recorder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TOOL_NAME = "cipherscope"
TOOL_VERSION = "0.1.0"


@dataclass(frozen=True)
class CiphertextMetadata:
    """A privacy-bounded snapshot of supported ciphertext getters.

    Missing or unsafe values are represented by ``None``. ``missing_fields`` is
    retained for event diagnostics but is not emitted as an arbitrary exception
    message.
    """

    level: int | float | str | bool | None = None
    noise_scale_degree: int | float | str | bool | None = None
    scale: int | float | str | bool | None = None
    slots: int | float | str | bool | None = None
    context_id: int | float | str | bool | None = None
    key_tag: int | float | str | bool | None = None
    scaling_technique: int | float | str | bool | None = None
    key_switch_technique: int | float | str | bool | None = None
    missing_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, int | float | str | bool | None]:
        """Return the stable, serializable metadata fields."""

        return {
            "level": self.level,
            "noise_scale_degree": self.noise_scale_degree,
            "scale": self.scale,
            "slots": self.slots,
            "context_id": self.context_id,
            "key_tag": self.key_tag,
            "scaling_technique": self.scaling_technique,
            "key_switch_technique": self.key_switch_technique,
        }


@dataclass(frozen=True)
class CiphertextState:
    """One immutable, run-local ciphertext version."""

    trace_id: str
    created_by_event: str | None
    parent_ids: tuple[str, ...]
    origin: Literal["preexisting", "derived"]
    metadata: CiphertextMetadata

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical trace representation."""

        return {
            "id": self.trace_id,
            "created_by_event": self.created_by_event,
            "parent_ids": list(self.parent_ids),
            "origin": self.origin,
            **self.metadata.to_dict(),
        }


@dataclass(frozen=True)
class CiphertextObservation:
    """A per-event observation associated with a registry identity."""

    trace_id: str
    metadata: CiphertextMetadata

    def event_state(self) -> dict[str, Any]:
        """Return metadata captured at this event boundary."""

        return {"id": self.trace_id, **self.metadata.to_dict()}


@dataclass(frozen=True)
class SourceAttribution:
    """A redacted first-external-frame source location."""

    file: str | None
    line: int | None
    function: str | None
    qualified_function: str | None
    source_sha256: str | None
    call_site_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "qualified_function": self.qualified_function,
            "source_sha256": self.source_sha256,
            "call_site_id": self.call_site_id,
        }


UNKNOWN_SOURCE = SourceAttribution(None, None, None, None, None, None)


def copy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively copy the JSON-shaped structures owned by the recorder."""

    result: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, dict):
            result[key] = copy_mapping(item)
        elif isinstance(item, list):
            result[key] = copy_sequence(item)
        elif isinstance(item, tuple):
            result[key] = copy_sequence(item)
        else:
            result[key] = item
    return result


def copy_sequence(value: Sequence[Any]) -> list[Any]:
    """Recursively copy a JSON-shaped sequence."""

    result: list[Any] = []
    for item in value:
        if isinstance(item, dict):
            result.append(copy_mapping(item))
        elif isinstance(item, (list, tuple)):
            result.append(copy_sequence(item))
        else:
            result.append(item)
    return result
