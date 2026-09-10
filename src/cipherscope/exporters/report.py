"""Build a static HTML report."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from html import escape
from typing import Any


def _cell(value: object) -> str:
    return escape("unknown" if value is None else str(value), quote=True)


def render_summary_html(
    manifest: Mapping[str, Any],
    trace: Mapping[str, Any],
    graph: Mapping[str, Any],
    recommendations: Mapping[str, Any],
) -> str:
    """Build an HTML summary of validated documents."""

    events = sorted(trace.get("events", ()), key=lambda item: item["sequence"])
    counts = Counter(event.get("operation", "unknown") for event in events)
    findings = list(recommendations.get("findings", ()))
    critical = (graph.get("critical_paths") or {}).get("nonlinear_ciphertext", {})

    operation_rows = (
        "".join(
            f"<tr><td>{_cell(operation)}</td><td>{count}</td></tr>"
            for operation, count in sorted(counts.items())
        )
        or '<tr><td colspan="2">No semantic events</td></tr>'
    )

    event_rows = (
        "".join(
            "<tr>"
            f"<td>{_cell(event.get('sequence'))}</td>"
            f"<td>{_cell(event.get('operation'))}</td>"
            f"<td>{_cell(event.get('status'))}</td>"
            f"<td>{_cell((event.get('source') or {}).get('file'))}:"
            f"{_cell((event.get('source') or {}).get('line'))}</td>"
            f"<td>{_cell((event.get('timing') or {}).get('wall_duration_ns'))}</td>"
            "</tr>"
            for event in events
        )
        or '<tr><td colspan="5">No semantic events</td></tr>'
    )

    finding_rows = (
        "".join(
            "<article>"
            f"<h3>{_cell(finding.get('rule_id'))}</h3>"
            f"<p>{_cell(finding.get('recommendation'))}</p>"
            f"<p><strong>Confidence:</strong> {_cell(finding.get('confidence'))}</p>"
            f"<p><strong>Evidence:</strong> "
            f"{_cell(', '.join(finding.get('evidence_event_ids', ())))}</p>"
            "</article>"
            for finding in findings
        )
        or "<p>No applicable findings for the observed path.</p>"
    )

    run_id = manifest.get("run_id")
    status = manifest.get("status")
    synthetic = manifest.get("synthetic_contract") is True
    coverage = manifest.get("coverage") or {}
    synthetic_notice = (
        '<p class="warning"><strong>Synthetic contract:</strong> this bundle uses '
        "a metadata-only fake backend and is not cryptographic or OpenFHE evidence.</p>"
        if synthetic
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CipherScope {_cell(run_id)}</title>
<style>
body {{ font: 16px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; color: #172033; }}
.warning {{ border-left: .35rem solid #c97900; background: #fff6df; padding: .8rem 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
th, td {{ border: 1px solid #ccd2dc; padding: .45rem .6rem; text-align: left; }}
th {{ background: #edf1f7; }}
code {{ background: #edf1f7; padding: .1rem .25rem; }}
</style>
</head>
<body>
<h1>CipherScope run {_cell(run_id)}</h1>
{synthetic_notice}
<p>Status: <strong>{_cell(status)}</strong>. Traced semantic calls: <strong>{_cell(coverage.get("traced_semantic_calls"))}</strong>. Unclassified pass-throughs: <strong>{_cell(coverage.get("unclassified_proxy_passthrough_calls"))}</strong>.</p>
<p>Maximum observed ciphertext-ciphertext nonlinear depth: <strong>{_cell(critical.get("max_depth"))}</strong>.</p>
<h2>Operation summary</h2>
<table><thead><tr><th>Operation</th><th>Count</th></tr></thead><tbody>{operation_rows}</tbody></table>
<h2>Events</h2>
<table><thead><tr><th>#</th><th>Operation</th><th>Status</th><th>Source</th><th>Wall ns</th></tr></thead><tbody>{event_rows}</tbody></table>
<h2>Findings</h2>
{finding_rows}
<p>Complete trace data is in <code>trace.json</code>; this page is a summary.</p>
</body>
</html>
"""
