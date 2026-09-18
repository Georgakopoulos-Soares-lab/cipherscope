"""Build a static HTML report.

The page is generated from the validated bundle documents alone and works for
every producer: it names the frontend, source language, toolchain and
framework from `run.producer` / `run.runtime`, shows coverage evidence in the
terms that frontend uses (proxy pass-throughs for Python, instrumentation
manifest matching for C++), and lists source sites per file with the file's
language. No analyzer result is interpreted differently by language.
"""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable, Mapping
from html import escape
from typing import Any

_LANGUAGE_BY_SUFFIX = {
    ".py": "Python", ".pyw": "Python",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".C": "C++", ".hpp": "C++", ".h": "C/C++", ".hh": "C++",
}


def _cell(value: object) -> str:
    return escape("unknown" if value is None else str(value), quote=True)


def _language_of_file(path: str | None) -> str | None:
    if not path:
        return None
    _, suffix = os.path.splitext(path)
    return _LANGUAGE_BY_SUFFIX.get(suffix)


def _common_prefix(paths: Iterable[str]) -> str:
    absolute = [p for p in paths if p and os.path.isabs(p)]
    if len(absolute) < 1:
        return ""
    prefix = os.path.commonpath(absolute) if len(absolute) > 1 else os.path.dirname(absolute[0])
    return prefix if prefix and prefix != os.sep else ""


def describe_environment(manifest: Mapping[str, Any], trace: Mapping[str, Any]) -> dict[str, str | None]:
    """Human-readable frontend/language/toolchain facts for the header and table."""

    run = trace.get("run") or {}
    runtime = dict(manifest.get("runtime") or run.get("runtime") or {})
    producer = dict(manifest.get("producer") or run.get("producer") or {})
    language = runtime.get("language")
    if language is None:
        language = "python" if runtime.get("python") else None
    if language == "c++":
        language_label = "C++"
        toolchain = " ".join(part for part in (runtime.get("compiler"), runtime.get("compiler_version")) if part) or None
        toolchain_kind = "Compiler"
    elif language == "python":
        language_label = "Python"
        toolchain = runtime.get("language_version") or runtime.get("python")
        toolchain = f"CPython {toolchain}" if toolchain else None
        toolchain_kind = "Interpreter"
    else:
        language_label, toolchain, toolchain_kind = None, None, "Toolchain"
    framework = runtime.get("framework") or "openfhe"
    framework_version = runtime.get("framework_version") or runtime.get("openfhe_distribution")
    return {
        "frontend": producer.get("frontend"),
        "frontend_version": producer.get("frontend_version"),
        "instrumentation_manifest": producer.get("instrumentation_manifest"),
        "language": language_label,
        "toolchain_kind": toolchain_kind,
        "toolchain": toolchain,
        "framework": f"{'OpenFHE' if framework == 'openfhe' else framework}" + (f" {framework_version}" if framework_version else ""),
        "platform": " / ".join(part for part in (runtime.get("platform"), runtime.get("architecture")) if part) or None,
        "lane": runtime.get("lane"),
        "cipherscope": " ".join(part for part in (runtime.get("cipherscope_version"), (runtime.get("cipherscope_commit") or "")[:12]) if part) or None,
        "source_root": runtime.get("source_root"),
        "target": runtime.get("target"),
    }


def _coverage_rows(coverage: Mapping[str, Any], language: str | None) -> list[tuple[str, object]]:
    rows: list[tuple[str, object]] = [
        ("Strict mode", coverage.get("strict")),
        ("Traced semantic calls", coverage.get("traced_semantic_calls")),
        ("Allowed non-semantic calls", coverage.get("allowed_passthrough_calls")),
    ]
    if language == "C++":
        rows += [
            ("Instrumentation manifest", coverage.get("instrumentation_manifest")),
            ("Executed calls outside the manifest", coverage.get("unmatched_openfhe_candidates")),
            ("Instrumented translation units", f"{coverage.get('instrumented_translation_units')} of {coverage.get('expected_translation_units')}"),
            ("Instrumented binary verified", coverage.get("instrumented_binary_verified")),
            ("Nested internal calls folded", coverage.get("nested_internal_calls")),
            ("Calls that unwound", coverage.get("unwound_calls")),
        ]
    else:
        rows += [
            ("Unclassified pass-throughs", coverage.get("unclassified_proxy_passthrough_calls")),
            ("Rejected unclassified calls", coverage.get("rejected_unclassified_calls")),
            ("Operator overloads observed", coverage.get("operator_overload_coverage")),
        ]
    unsupported = coverage.get("unsupported_operations") or []
    rows += [
        ("Unsupported operations", ", ".join(map(str, unsupported)) if unsupported else "none"),
        ("Failed state reads", coverage.get("failed_state_reads")),
        ("Truncated", coverage.get("truncated")),
    ]
    return rows


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
    env = describe_environment(manifest, trace)
    coverage = manifest.get("coverage") or {}

    files = Counter((event.get("source") or {}).get("file") for event in events)
    files.pop(None, None)
    root = env.get("source_root") or _common_prefix(files)

    def short(path: str | None) -> str:
        if not path:
            return "unknown"
        if root and path.startswith(root.rstrip(os.sep) + os.sep):
            return path[len(root.rstrip(os.sep)) + 1 :]
        return path

    language_badge = (
        f'<span class="badge lang">{_cell(env["language"])}</span>' if env.get("language") else ""
    )
    headline_parts = [
        f"Source: <strong>{_cell(env['language'])}</strong>" if env.get("language") else "Source: <strong>unknown language</strong>",
        f"{_cell(env['toolchain_kind'])}: <strong>{_cell(env['toolchain'])}</strong>" if env.get("toolchain") else None,
        f"Framework: <strong>{_cell(env['framework'])}</strong>",
        f"Frontend: <strong>{_cell(env['frontend'])}</strong>" if env.get("frontend") else None,
    ]
    headline = " · ".join(part for part in headline_parts if part)

    environment_rows = "".join(
        f"<tr><th scope=\"row\">{_cell(label)}</th><td>{_cell(value)}</td></tr>"
        for label, value in (
            ("Frontend", f"{env['frontend']} {env['frontend_version'] or ''}".strip() if env.get("frontend") else None),
            ("Instrumentation manifest", env.get("instrumentation_manifest")),
            ("Source language", env.get("language")),
            (env.get("toolchain_kind") or "Toolchain", env.get("toolchain")),
            ("Framework", env.get("framework")),
            ("Platform", env.get("platform")),
            ("Evidence lane", env.get("lane")),
            ("CipherScope", env.get("cipherscope")),
            ("Target", env.get("target")),
            ("Source root", env.get("source_root")),
            ("Wall clock", (manifest.get("clocks") or {}).get("wall")),
        )
        if value not in (None, "")
    )

    coverage_rows = "".join(
        f"<tr><th scope=\"row\">{_cell(label)}</th><td>{_cell(value)}</td></tr>"
        for label, value in _coverage_rows(coverage, env.get("language"))
    )

    file_rows = (
        "".join(
            "<tr>"
            f"<td><code>{_cell(short(path))}</code></td>"
            f"<td>{_cell(_language_of_file(path) or env.get('language'))}</td>"
            f"<td class=\"num\">{count}</td>"
            "</tr>"
            for path, count in sorted(files.items(), key=lambda item: (-item[1], item[0]))
        )
        or '<tr><td colspan="3">No source-attributed events</td></tr>'
    )

    operation_rows = (
        "".join(
            f"<tr><td>{_cell(operation)}</td><td class=\"num\">{count}</td></tr>"
            for operation, count in sorted(counts.items())
        )
        or '<tr><td colspan="2">No semantic events</td></tr>'
    )

    def event_row(event: Mapping[str, Any]) -> str:
        source = event.get("source") or {}
        function = source.get("qualified_function") or source.get("function")
        location = f"{_cell(short(source.get('file')))}:{_cell(source.get('line'))}"
        if function:
            location += f" <span class=\"fn\">in {_cell(function)}</span>"
        status = event.get("status")
        return (
            "<tr>"
            f"<td class=\"num\">{_cell(event.get('sequence'))}</td>"
            f"<td>{_cell(event.get('operation'))}<span class=\"muted\"> {_cell(event.get('overload') or '')}</span></td>"
            f"<td>{_cell(', '.join(event.get('input_ciphertexts') or ()) or '—')} → {_cell(', '.join(event.get('output_ciphertexts') or ()) or '—')}</td>"
            f"<td class=\"{'error' if status == 'error' else ''}\">{_cell(status)}</td>"
            f"<td><code>{location}</code></td>"
            f"<td class=\"num\">{_cell((event.get('timing') or {}).get('wall_duration_ns'))}</td>"
            "</tr>"
        )

    event_rows = "".join(event_row(event) for event in events) or '<tr><td colspan="6">No semantic events</td></tr>'

    finding_rows = (
        "".join(
            "<article>"
            f"<h3>{_cell(finding.get('rule_id'))} <span class=\"badge {_cell(finding.get('severity')) if finding.get('severity') in ('opportunity', 'information', 'warning') else ''}\">{_cell(finding.get('severity'))}</span></h3>"
            f"<p>{_cell(finding.get('recommendation'))}</p>"
            f"<p><strong>Confidence:</strong> {_cell(finding.get('confidence'))}</p>"
            f"<p><strong>Evidence:</strong> {_cell(', '.join(finding.get('evidence_event_ids', ())))}</p>"
            + (
                "<p><strong>Sites:</strong> "
                + ", ".join(
                    f"<code>{_cell(short(site.get('file')))}:{_cell(site.get('line'))}</code>"
                    for site in finding.get("source_sites") or ()
                    if isinstance(site, Mapping)
                )
                + "</p>"
                if finding.get("source_sites")
                else ""
            )
            + "</article>"
            for finding in findings
        )
        or "<p>No applicable findings for the observed path.</p>"
    )

    run_id = manifest.get("run_id")
    status = manifest.get("status")
    synthetic = manifest.get("synthetic_contract") is True
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
:root {{ --ink: #172033; --muted: #5b6577; --rule: #ccd2dc; --panel: #edf1f7; --accent: #0f6e7a; --warn: #c97900; --error: #b23a3a; }}
body {{ font: 16px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 76rem; padding: 0 1rem; color: var(--ink); }}
h1 {{ margin-bottom: .25rem; }}
.headline {{ color: var(--muted); margin-top: 0; }}
.warning {{ border-left: .35rem solid var(--warn); background: #fff6df; padding: .8rem 1rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
th, td {{ border: 1px solid var(--rule); padding: .45rem .6rem; text-align: left; vertical-align: top; }}
th {{ background: var(--panel); }}
th[scope=row] {{ width: 18rem; font-weight: 600; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
td.error {{ color: var(--error); font-weight: 600; }}
code {{ background: var(--panel); padding: .1rem .25rem; font-size: .92em; }}
.fn {{ color: var(--muted); }}
.muted {{ color: var(--muted); font-size: .85em; }}
.badge {{ display: inline-block; font-size: .7rem; letter-spacing: .04em; text-transform: uppercase; padding: .1rem .5rem; border-radius: 999px; background: var(--panel); color: var(--muted); vertical-align: middle; }}
.badge.lang {{ background: var(--accent); color: #fff; }}
.badge.opportunity {{ background: #dcf1e4; color: #1d6b3d; }}
.badge.information {{ background: var(--panel); }}
.badge.warning {{ background: #fff0d6; color: #8a5300; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1.5rem; }}
.grid table {{ margin: .5rem 0 0; }}
article {{ border: 1px solid var(--rule); padding: .75rem 1rem; margin: 1rem 0; }}
article h3 {{ margin: 0 0 .5rem; }}
</style>
</head>
<body>
<h1>CipherScope run {_cell(run_id)} {language_badge}</h1>
<p class="headline">{headline}</p>
{synthetic_notice}
<p>Status: <strong>{_cell(status)}</strong>. Traced semantic calls: <strong>{_cell(coverage.get("traced_semantic_calls"))}</strong>. Maximum observed ciphertext-ciphertext nonlinear depth: <strong>{_cell(critical.get("max_depth"))}</strong>.</p>
<div class="grid">
<section>
<h2>Environment</h2>
<table><tbody>{environment_rows}</tbody></table>
</section>
<section>
<h2>Coverage evidence</h2>
<table><tbody>{coverage_rows}</tbody></table>
</section>
</div>
<h2>Source files</h2>
<table><thead><tr><th>File</th><th>Language</th><th>Events</th></tr></thead><tbody>{file_rows}</tbody></table>
<h2>Operation summary</h2>
<table><thead><tr><th>Operation</th><th>Count</th></tr></thead><tbody>{operation_rows}</tbody></table>
<h2>Events</h2>
<table><thead><tr><th>#</th><th>Operation</th><th>Ciphertexts</th><th>Status</th><th>Source</th><th>Wall ns</th></tr></thead><tbody>{event_rows}</tbody></table>
<h2>Findings</h2>
{finding_rows}
<p>Complete trace data is in <code>trace.json</code>; this page is a summary generated from the validated bundle.</p>
</body>
</html>
"""
