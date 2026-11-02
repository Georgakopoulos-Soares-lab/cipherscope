"""Observed depth-headroom analysis against the configured multiplicative depth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..graph import LEVELED_SCHEMES, depth_coordinate
from ._shared import finalize, resolve_graph

RULE_ID = "parameters.depth_headroom_observed.v1"


def _scheme(trace: Mapping[str, Any]) -> str | None:
    context = trace.get("context")
    scheme = context.get("scheme") if isinstance(context, Mapping) else None
    return scheme if isinstance(scheme, str) else None


def _observed_level_use(graph: Mapping[str, Any]) -> Mapping[str, Any] | None:
    paths = graph.get("critical_paths", {})
    if not isinstance(paths, Mapping):
        return None
    observed = paths.get("observed_level_use")
    return observed if isinstance(observed, Mapping) else None


def _observed_nonlinear_use(graph: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The multiplication count along the deepest recorded lineage.

    This is what bounds depth on a scheme with no level ladder. It is counted
    from the recorded operations rather than read from ciphertext state, so
    its confidence is ``inferred`` -- and ``inferred`` is only reached when
    every operation on the path had a known depth weight. One opaque call
    (``EvalPoly``, ``EvalChebyshevSeries``, ...) makes it ``unknown`` instead,
    which this rule refuses.
    """

    paths = graph.get("critical_paths", {})
    if not isinstance(paths, Mapping):
        return None
    observed = paths.get("nonlinear_ciphertext")
    return observed if isinstance(observed, Mapping) else None


def _has_level_metadata(trace: Mapping[str, Any]) -> bool:
    """Zero consumed depth is only a measurement if the scheme's coordinate was read."""

    scheme = _scheme(trace)
    for state in trace.get("ciphertexts", []):
        if isinstance(state, Mapping) and depth_coordinate(state, scheme) is not None:
            return True
    return False


def _deferred_rescale_levels(trace: Mapping[str, Any]) -> int:
    """1 if a ciphertext at the deepest observed level still awaits a rescale, else 0.

    Only the rescaling schemes can defer one. BFV does not rescale at all, and
    its depth coordinate is the noise scale degree itself, so a pending degree
    is already counted as consumption rather than owed on top of it.
    """

    scheme = _scheme(trace)
    if scheme not in {"CKKS", "BGV"}:
        return 0
    deepest = None
    pending = False
    for state in trace.get("ciphertexts", ()):
        if not isinstance(state, Mapping):
            continue
        level = state.get("level")
        if not isinstance(level, int) or isinstance(level, bool):
            continue
        degree = state.get("noise_scale_degree")
        has_pending = isinstance(degree, int) and not isinstance(degree, bool) and degree >= 2
        if deepest is None or level > deepest:
            deepest, pending = level, has_pending
        elif level == deepest and has_pending:
            pending = True
    return 1 if pending else 0


def analyze_parameters(
    trace: Mapping[str, Any], graph: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Compare the configured multiplicative depth with fully modeled level use.

    The rule is not applicable whenever the observed level requirement is not
    fully measured (no missing or unresolved paths), because unused headroom cannot
    be claimed from an incomplete depth model. The result is limited to this run.
    """

    graph = resolve_graph(trace, graph)

    base = {
        "schema_version": trace["schema_version"],
        "run_id": trace["run"]["run_id"],
    }
    context = trace.get("context", {})
    configured = (
        context.get("configured_multiplicative_depth")
        if isinstance(context, Mapping)
        else None
    )
    if not isinstance(configured, int) or isinstance(configured, bool):
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The trace has no known configured multiplicative depth."
            ],
            "findings": [],
        }

    scheme = _scheme(trace)
    if scheme is not None and scheme not in LEVELED_SCHEMES:
        # BFV has no level ladder to read, so depth is counted from the
        # recorded multiplications along the deepest lineage instead. The
        # count is exact whenever no opaque call hid an unknown depth, which
        # is exactly what an "inferred" confidence certifies.
        observed = _observed_nonlinear_use(graph)
        if observed is None or observed.get("confidence") != "inferred":
            return {
                **base,
                "analysis_status": "not_applicable",
                "not_applicable_reasons": [
                    f"{scheme} has no level ladder, and the recorded multiplication "
                    "depth is not fully resolved; an opaque call hides part of it."
                ],
                "findings": [],
            }
        consumed = observed.get("max_depth")
        depth_evidence = "recorded_multiplications"
    else:
        if not _has_level_metadata(trace):
            return {
                **base,
                "analysis_status": "not_applicable",
                "not_applicable_reasons": [
                    "No ciphertext state with a level was recorded, so level use cannot be observed."
                ],
                "findings": [],
            }
        observed = _observed_level_use(graph)
        if observed is None or observed.get("confidence") != "measured":
            return {
                **base,
                "analysis_status": "not_applicable",
                "not_applicable_reasons": [
                    "Observed level use is not fully measured; missing or unresolved paths remain."
                ],
                "findings": [],
            }
        consumed = observed.get("max_levels_consumed_in_epoch")
        depth_evidence = "ciphertext_levels"
    if not isinstance(consumed, int) or isinstance(consumed, bool):
        return {
            **base,
            "analysis_status": "not_applicable",
            "not_applicable_reasons": [
                "The observed maximum level use per epoch was not resolved."
            ],
            "findings": [],
        }

    # A ciphertext still carrying a deferred rescale (noise scale degree >= 2
    # at the deepest observed level, as FLEXIBLEAUTO leaves the last product)
    # has committed one more level than its level field shows: OpenFHE
    # refuses a depth equal to the observed level count in that state.
    deferred = _deferred_rescale_levels(trace)
    consumed_effective = consumed + deferred
    headroom = configured - consumed_effective
    inventory = {
        "configured_multiplicative_depth": configured,
        "observed_max_levels_consumed_in_epoch": consumed,
        "deferred_rescale_levels": deferred,
        "observed_depth_headroom": headroom,
        "depth_evidence": depth_evidence,
    }
    if headroom <= 0:
        return {
            **base,
            "analysis_status": "clean",
            "inventory": inventory,
            "findings": [],
        }

    evidence_ids = [
        item for item in observed.get("event_ids", []) if isinstance(item, str)
    ]
    # On a leveled scheme the depth is read off the ciphertext level ladder, so
    # the count is a measurement. On BFV it is counted from recorded
    # operations against a parameter that is a noise budget rather than a
    # multiplication counter, so the same number is an inference.
    counted_from_operations = depth_evidence == "recorded_multiplications"
    scheme_limitations = (
        [
            f"{scheme} configured depth is a noise budget, not a count of "
            "multiplications: on the pinned build a depth-2 context completed "
            "three multiplications, and depth 2 and depth 3 had the same "
            "capacity. How far the depth can actually fall is value-dependent "
            "and must be measured, not read from this number.",
            f"A {scheme} run that exceeds its noise budget decrypts to a wrong "
            "plaintext without raising, so any reduced depth has to be checked "
            "against expected values, not just for absence of an exception.",
        ]
        if counted_from_operations
        else [
            "Levels a library call consumes internally without a visible ciphertext level change (inside EvalLogistic, or below the input level of a multi-iteration EvalBootstrap) are not observed; the smallest depth that actually runs can be one or two above the observed use, so the reported headroom is an upper bound.",
        ]
    )
    finding = {
        "finding_id": "finding_parameters_0001",
        "rule_id": RULE_ID,
        "analyzer": "ParameterAnalyzer",
        "category": "parameters",
        "severity": "opportunity",
        "confidence": "inferred" if counted_from_operations else "measured",
        "source_sites": [],
        "evidence_event_ids": evidence_ids,
        "evidence": inventory,
        "applicability": [
            "a known configured multiplicative depth for this run",
            (
                "a fully resolved multiplication count with no opaque call on the path"
                if counted_from_operations
                else "fully measured observed level use with no missing or unresolved paths"
            ),
            "observed per-epoch level use below the configured depth",
        ],
        "estimated_impact": {
            "observed_depth_headroom": float(headroom),
            "speedup": None,
        },
        "recommendation": (
            "Test a smaller multiplicative depth on representative inputs before reducing "
            "it; a lower depth can change parameters and must be re-validated."
        ),
        "limitations": [
            "Headroom reflects this run's inputs and branches only, not all inputs.",
            "Reducing depth may alter security parameters and require re-tuning.",
            *scheme_limitations,
            "Bootstrapping segments are measured per epoch, not summed across the run.",
        ],
    }
    result = {
        **base,
        "analysis_status": "positive",
        "inventory": inventory,
        "findings": [finding],
    }
    return finalize(result, trace=trace, graph=graph)


__all__ = ["RULE_ID", "analyze_parameters"]
