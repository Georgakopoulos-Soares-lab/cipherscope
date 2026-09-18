"""Build a graph of the operations and ciphertexts in a trace."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .validation import ValidationError, validate_graph, validate_trace

_ZERO_WEIGHT_OPERATIONS = {
    "Decrypt",
    "Encrypt",
    "EvalAdd",
    "EvalAddInPlace",
    "EvalNegate",
    "EvalNegateInPlace",
    "EvalRotate",
    "EvalFastRotation",
    "EvalFastRotationPrecompute",
    "EvalSum",
    "EvalSumRows",
    "EvalSumCols",
    "EvalAddMany",
    "EvalAddManyInPlace",
    "EvalLinearWSum",
    "EvalLinearWSumMutable",
    "EvalMerge",
    "EvalSub",
    "EvalSubInPlace",
    "ModReduce",
    "ModReduceInPlace",
    "Relinearize",
    "RelinearizeInPlace",
    "Rescale",
    "RescaleInPlace",
}
_OPAQUE_OPERATIONS = {
    "EvalPoly", "EvalChebyshevFunction", "EvalInnerProduct", "EvalLogistic",
    "EvalChebyshevSeries", "EvalChebyshevSeriesLinear", "EvalChebyshevSeriesPS",
    "EvalSin", "EvalCos", "EvalDivide",
    # A binary multiplication tree: its depth is ceil(log2(operands)), not 1.
    "EvalMultMany",
}


def _event_sort_key(event: Mapping[str, Any]) -> tuple[int, str]:
    sequence = event.get("sequence")
    return (
        sequence if isinstance(sequence, int) else 2**63,
        str(event.get("event_id", "")),
    )


def _state_sort_key(state: Mapping[str, Any]) -> str:
    return str(state.get("id", ""))


def _rotation_key_id(index: int) -> str:
    direction = "neg" if index < 0 else "pos"
    return f"key_rotation_{direction}_{abs(index)}"


def _nonlinear_weight(event: Mapping[str, Any]) -> int | None:
    operation = event.get("operation")
    if operation in {"EvalSquare", "EvalSquareInPlace"}:
        return 1
    if operation in {"EvalMult", "EvalMultNoRelin", "EvalMultAndRelinearize"}:
        overload = event.get("overload")
        if overload in {"ct_ct", "ciphertext_ciphertext"}:
            return 1
        if overload in {
            "ct_pt",
            "pt_ct",
            "ciphertext_plaintext",
            "plaintext_ciphertext",
        }:
            return 0
        operand_kinds = event.get("operand_kinds")
        if isinstance(operand_kinds, list):
            ciphertext_operands = sum(item == "ciphertext" for item in operand_kinds)
            if ciphertext_operands >= 2:
                return 1
            if ciphertext_operands == 1:
                return 0
        return None
    if operation in _ZERO_WEIGHT_OPERATIONS:
        return 0
    if operation in _OPAQUE_OPERATIONS:
        return None
    # Setup, annotation, checkpoint, resource, and key events do not add FHE depth.
    if event.get("kind") in {
        "annotation",
        "checkpoint",
        "coverage_gap",
        "key_generation",
        "resource_sample",
        "setup",
    }:
        return 0
    return None


def _snapshot_level(
    event: Mapping[str, Any], field: str, ciphertext_id: str
) -> int | None:
    snapshots = event.get(field)
    if not isinstance(snapshots, list):
        return None
    for snapshot in snapshots:
        if not isinstance(snapshot, Mapping) or snapshot.get("id") != ciphertext_id:
            continue
        level = snapshot.get("level")
        return level if isinstance(level, int) and not isinstance(level, bool) else None
    return None


def _epoch_record(
    *,
    index: int,
    start_sequence: int | None,
    end_sequence: int | None,
    closing_bootstrap: str | None,
    metric_name: str,
    maximum: int,
    event_ids: list[str],
    confidence: str,
) -> dict[str, Any]:
    return {
        "epoch_index": index,
        "start_sequence": start_sequence,
        "end_sequence": end_sequence,
        "closed_by_bootstrap_event_id": closing_bootstrap,
        metric_name: maximum,
        "event_ids": list(event_ids),
        "confidence": confidence,
    }


def _compute_depth_metrics(
    events: list[Mapping[str, Any]], states: list[Mapping[str, Any]]
) -> tuple[dict[str, int | None], dict[str, int | None], dict[str, Any]]:
    ciphertext_by_id = {str(state["id"]): state for state in states}
    roots = [
        str(state["id"]) for state in states if state.get("created_by_event") is None
    ]
    nonlinear: dict[str, int | None] = {root: 0 for root in roots}
    nonlinear_paths: dict[str, list[str]] = {root: [] for root in roots}
    level_use: dict[str, int | None] = {root: 0 for root in roots}
    level_paths: dict[str, list[str]] = {root: [] for root in roots}

    maximum_nonlinear = 0
    maximum_nonlinear_path: list[str] = []
    maximum_levels = 0
    maximum_level_path: list[str] = []
    nonlinear_unknown = False
    level_unknown = False
    bootstrap_ids: list[str] = []

    nonlinear_epochs: list[dict[str, Any]] = []
    level_epochs: list[dict[str, Any]] = []
    epoch_index = 0
    epoch_start = events[0].get("sequence") if events else None
    epoch_last_sequence: int | None = None
    epoch_nonlinear_max = 0
    epoch_nonlinear_path: list[str] = []
    epoch_level_max = 0
    epoch_level_path: list[str] = []
    epoch_nonlinear_unknown = False
    epoch_level_unknown = False

    for event in events:
        if event.get("status") != "ok":
            epoch_last_sequence = event.get("sequence")
            continue
        event_id = str(event["event_id"])
        operation = event.get("operation")
        input_ciphertext_ids = [
            str(item) for item in event.get("input_ciphertexts", [])
        ]
        output_ciphertext_ids = [
            str(item) for item in event.get("output_ciphertexts", [])
        ]
        sequence = event.get("sequence")
        epoch_last_sequence = (
            sequence if isinstance(sequence, int) else epoch_last_sequence
        )

        if operation == "EvalBootstrap":
            bootstrap_ids.append(event_id)
            nonlinear_epochs.append(
                _epoch_record(
                    index=epoch_index,
                    start_sequence=epoch_start
                    if isinstance(epoch_start, int)
                    else None,
                    end_sequence=sequence
                    if isinstance(sequence, int)
                    else epoch_last_sequence,
                    closing_bootstrap=event_id,
                    metric_name="max_depth",
                    maximum=epoch_nonlinear_max,
                    event_ids=epoch_nonlinear_path,
                    confidence="unknown" if epoch_nonlinear_unknown else "inferred",
                )
            )
            level_epochs.append(
                _epoch_record(
                    index=epoch_index,
                    start_sequence=epoch_start
                    if isinstance(epoch_start, int)
                    else None,
                    end_sequence=sequence
                    if isinstance(sequence, int)
                    else epoch_last_sequence,
                    closing_bootstrap=event_id,
                    metric_name="max_levels_consumed",
                    maximum=epoch_level_max,
                    event_ids=epoch_level_path,
                    confidence="unknown" if epoch_level_unknown else "measured",
                )
            )
            for output_ciphertext_id in output_ciphertext_ids:
                nonlinear[output_ciphertext_id] = 0
                nonlinear_paths[output_ciphertext_id] = []
                level_use[output_ciphertext_id] = 0
                level_paths[output_ciphertext_id] = []
            epoch_index += 1
            epoch_start = sequence + 1 if isinstance(sequence, int) else None
            epoch_nonlinear_max = 0
            epoch_nonlinear_path = []
            epoch_level_max = 0
            epoch_level_path = []
            epoch_nonlinear_unknown = False
            epoch_level_unknown = False
            continue

        weight = _nonlinear_weight(event)
        if input_ciphertext_ids:
            parent_depths = [
                nonlinear.get(ciphertext_id) for ciphertext_id in input_ciphertext_ids
            ]
            depth_is_unknown = weight is None or any(
                value is None for value in parent_depths
            )
            if depth_is_unknown:
                next_depth: int | None = None
                next_nonlinear_path: list[str] = []
                nonlinear_unknown = True
                epoch_nonlinear_unknown = True
            else:
                best_parent = min(
                    input_ciphertext_ids,
                    key=lambda item: (
                        -(nonlinear.get(item) or 0),
                        item,
                    ),
                )
                parent_depth = nonlinear.get(best_parent) or 0
                next_depth = parent_depth + (weight or 0)
                next_nonlinear_path = list(nonlinear_paths.get(best_parent, []))
                if weight:
                    next_nonlinear_path.append(event_id)
        else:
            next_depth = weight if weight is not None else None
            next_nonlinear_path = [event_id] if weight else []
            if weight is None:
                nonlinear_unknown = True
                epoch_nonlinear_unknown = True

        for output_ciphertext_id in output_ciphertext_ids:
            nonlinear[output_ciphertext_id] = next_depth
            nonlinear_paths[output_ciphertext_id] = list(next_nonlinear_path)
        if next_depth is not None and next_depth > maximum_nonlinear:
            maximum_nonlinear = next_depth
            maximum_nonlinear_path = list(next_nonlinear_path)
        if next_depth is not None and next_depth > epoch_nonlinear_max:
            epoch_nonlinear_max = next_depth
            epoch_nonlinear_path = list(next_nonlinear_path)

        for output_ciphertext_id in output_ciphertext_ids:
            if not input_ciphertext_ids:
                next_level_use: int | None = 0
                next_level_path: list[str] = []
            else:
                output_level = _snapshot_level(
                    event, "output_states", output_ciphertext_id
                )
                if output_level is None:
                    state_level = ciphertext_by_id.get(output_ciphertext_id, {}).get(
                        "level"
                    )
                    output_level = (
                        state_level
                        if isinstance(state_level, int)
                        and not isinstance(state_level, bool)
                        else None
                    )
                candidates: list[tuple[int, str, int, list[str]]] = []
                unresolved = output_level is None
                for input_ciphertext_id in input_ciphertext_ids:
                    input_level = _snapshot_level(
                        event, "input_states", input_ciphertext_id
                    )
                    if input_level is None:
                        state_level = ciphertext_by_id.get(input_ciphertext_id, {}).get(
                            "level"
                        )
                        input_level = (
                            state_level
                            if isinstance(state_level, int)
                            and not isinstance(state_level, bool)
                            else None
                        )
                    parent_use = level_use.get(input_ciphertext_id)
                    if (
                        input_level is None
                        or output_level is None
                        or parent_use is None
                    ):
                        unresolved = True
                        continue
                    delta = output_level - input_level
                    if delta < 0:
                        unresolved = True
                        continue
                    path = list(level_paths.get(input_ciphertext_id, []))
                    if delta:
                        path.append(event_id)
                    candidates.append(
                        (parent_use + delta, input_ciphertext_id, delta, path)
                    )
                if unresolved or not candidates:
                    next_level_use = None
                    next_level_path = []
                    level_unknown = True
                    epoch_level_unknown = True
                else:
                    # On ties, avoid charging level alignment to a shallower branch.
                    best = min(
                        candidates, key=lambda item: (-item[0], item[2], item[1])
                    )
                    next_level_use = best[0]
                    next_level_path = best[3]
            level_use[output_ciphertext_id] = next_level_use
            level_paths[output_ciphertext_id] = list(next_level_path)
            if next_level_use is not None and next_level_use > maximum_levels:
                maximum_levels = next_level_use
                maximum_level_path = list(next_level_path)
            if next_level_use is not None and next_level_use > epoch_level_max:
                epoch_level_max = next_level_use
                epoch_level_path = list(next_level_path)

    final_end = epoch_last_sequence
    if (
        isinstance(epoch_start, int)
        and isinstance(final_end, int)
        and final_end < epoch_start
    ):
        # A bootstrap may be the final event; the newly opened epoch is then empty.
        final_end = None
    nonlinear_epochs.append(
        _epoch_record(
            index=epoch_index,
            start_sequence=epoch_start if isinstance(epoch_start, int) else None,
            end_sequence=final_end,
            closing_bootstrap=None,
            metric_name="max_depth",
            maximum=epoch_nonlinear_max,
            event_ids=epoch_nonlinear_path,
            confidence="unknown" if epoch_nonlinear_unknown else "inferred",
        )
    )
    level_epochs.append(
        _epoch_record(
            index=epoch_index,
            start_sequence=epoch_start if isinstance(epoch_start, int) else None,
            end_sequence=final_end,
            closing_bootstrap=None,
            metric_name="max_levels_consumed",
            maximum=epoch_level_max,
            event_ids=epoch_level_path,
            confidence="unknown" if epoch_level_unknown else "measured",
        )
    )
    critical_paths = {
        "nonlinear_ciphertext": {
            "max_depth": maximum_nonlinear,
            "event_ids": maximum_nonlinear_path,
            "bootstrap_event_ids": bootstrap_ids,
            "epochs": nonlinear_epochs,
            "confidence": "unknown" if nonlinear_unknown else "inferred",
        },
        "observed_level_use": {
            "max_levels_consumed_in_epoch": maximum_levels,
            "event_ids": maximum_level_path,
            "bootstrap_event_ids": bootstrap_ids,
            "epochs": level_epochs,
            "confidence": "unknown" if level_unknown else "measured",
        },
    }
    return nonlinear, level_use, critical_paths


def build_graph(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Build a graph from one validated trace.

    Bootstrap outputs start new depth and level counts, while ``critical_paths``
    keeps earlier maximums. Missing data produces ``None`` or ``"unknown"``.
    """

    trace_result = validate_trace(trace)
    if not trace_result.valid:
        raise ValidationError("trace", trace_result.errors)

    events = sorted(
        (event for event in trace["events"] if isinstance(event, Mapping)),
        key=_event_sort_key,
    )
    states = sorted(
        (state for state in trace["ciphertexts"] if isinstance(state, Mapping)),
        key=_state_sort_key,
    )
    nonlinear, level_use, critical_paths = _compute_depth_metrics(events, states)

    ciphertext_nodes: list[dict[str, Any]] = []
    for state in states:
        ciphertext_id = str(state["id"])
        node = {
            "id": ciphertext_id,
            "node_type": "CiphertextVersion",
            **{
                key: deepcopy(value)
                for key, value in state.items()
                if key
                not in {
                    "id",
                    "node_type",
                    "observed_nonlinear_depth",
                    "observed_level_use_in_epoch",
                }
            },
            "observed_nonlinear_depth": nonlinear.get(ciphertext_id),
            "observed_level_use_in_epoch": level_use.get(ciphertext_id),
        }
        ciphertext_nodes.append(node)

    event_nodes = [
        {
            "id": str(event["event_id"]),
            "node_type": "RuntimeEvent",
            "sequence": event["sequence"],
            "kind": event["kind"],
            "operation": event["operation"],
            "status": event["status"],
        }
        for event in events
    ]

    source_nodes_by_id: dict[str, dict[str, Any]] = {}
    key_nodes_by_id: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for event in events:
        event_id = str(event["event_id"])
        source = event.get("source")
        if isinstance(source, Mapping):
            source_id = source.get("call_site_id")
            if isinstance(source_id, str) and source_id:
                source_nodes_by_id.setdefault(
                    source_id,
                    {
                        "id": source_id,
                        "node_type": "SourceSite",
                        **{
                            key: deepcopy(value)
                            for key, value in source.items()
                            if key not in {"call_site_id", "id", "node_type"}
                        },
                    },
                )
                edges.append(
                    {"edge_type": "called_from", "from": event_id, "to": source_id}
                )
        inputs = [str(item) for item in event.get("input_ciphertexts", [])]
        outputs = [str(item) for item in event.get("output_ciphertexts", [])]
        for input_ciphertext_id in inputs:
            edges.append(
                {"edge_type": "consumes", "from": input_ciphertext_id, "to": event_id}
            )
        for output_ciphertext_id in outputs:
            edges.append(
                {"edge_type": "produces", "from": event_id, "to": output_ciphertext_id}
            )
            for input_ciphertext_id in inputs:
                edges.append(
                    {
                        "edge_type": "derived_from",
                        "from": output_ciphertext_id,
                        "to": input_ciphertext_id,
                    }
                )

        semantic = event.get("semantic_arguments")
        if not isinstance(semantic, Mapping) or event.get("status") != "ok":
            continue
        rotation_indices: list[tuple[int, str]] = []
        if event.get("operation") == "EvalRotate":
            index = semantic.get("rotation_index_requested")
            if isinstance(index, int) and not isinstance(index, bool):
                rotation_indices.append((index, "used_by_event_ids"))
        elif event.get("operation") == "EvalRotateKeyGen":
            indices = semantic.get("rotation_indices_requested")
            if isinstance(indices, list):
                rotation_indices.extend(
                    (index, "generated_by_event_ids")
                    for index in indices
                    if isinstance(index, int) and not isinstance(index, bool)
                )
        for index, evidence_field in rotation_indices:
            key_id = _rotation_key_id(index)
            node = key_nodes_by_id.setdefault(
                key_id,
                {
                    "id": key_id,
                    "node_type": "EvalKeyRequirement",
                    "key_type": "rotation",
                    "rotation_index": index,
                    "generated_by_event_ids": [],
                    "used_by_event_ids": [],
                },
            )
            evidence = node[evidence_field]
            if isinstance(evidence, list) and event_id not in evidence:
                evidence.append(event_id)
            if evidence_field == "used_by_event_ids":
                edges.append(
                    {"edge_type": "requires_key", "from": event_id, "to": key_id}
                )

    source_nodes = [source_nodes_by_id[key] for key in sorted(source_nodes_by_id)]
    key_nodes = [key_nodes_by_id[key] for key in sorted(key_nodes_by_id)]
    consumed = {
        str(input_ciphertext_id)
        for event in events
        for input_ciphertext_id in event.get("input_ciphertexts", [])
    }
    roots = sorted(
        str(state["id"]) for state in states if state.get("created_by_event") is None
    )
    outputs = sorted(
        str(state["id"]) for state in states if str(state["id"]) not in consumed
    )
    run = trace["run"]
    graph: dict[str, Any] = {
        "schema_version": trace["schema_version"],
        "run_id": run["run_id"],
        "nodes": [*ciphertext_nodes, *event_nodes, *source_nodes, *key_nodes],
        "edges": edges,
        "roots": roots,
        "outputs": outputs,
        "critical_paths": critical_paths,
    }
    if "synthetic_contract" in run:
        graph["synthetic_contract"] = bool(run["synthetic_contract"])

    graph_result = validate_graph(graph, trace=trace)
    if not graph_result.valid:
        raise ValidationError("graph", graph_result.errors)
    return graph


build_ciphertext_graph = build_graph


__all__ = ["build_ciphertext_graph", "build_graph"]
