"""Small helpers shared by more than one analyzer module."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..graph import build_graph
from ..validation import (
    ValidationError,
    validate_graph,
    validate_recommendations,
    validate_trace,
)


def event_order(event: Mapping[str, Any]) -> tuple[int, str]:
    """Sort key: numeric sequence first, falling back to the event ID."""

    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def require_valid_trace(trace: Mapping[str, Any]) -> None:
    """Raise ``ValidationError`` unless the trace document is well-formed."""

    result = validate_trace(trace)
    if not result.valid:
        raise ValidationError("trace", result.errors)


def resolve_graph(
    trace: Mapping[str, Any], graph: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    """Validate the trace, then return a validated graph, building one if needed."""

    require_valid_trace(trace)
    if graph is None:
        graph = build_graph(trace)
    result = validate_graph(graph, trace=trace)
    if not result.valid:
        raise ValidationError("graph", result.errors)
    return graph


def finalize(
    result: dict[str, Any],
    *,
    trace: Mapping[str, Any],
    graph: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a recommendations-shaped result before returning it."""

    validation = validate_recommendations(result, trace=trace, graph=graph)
    if not validation.valid:
        raise ValidationError("recommendations", validation.errors)
    return result
