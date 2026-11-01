"""Build an interactive HTML report.

The page is generated from the validated bundle documents alone and works for
every producer: it names the frontend, source language, toolchain and
framework from `run.producer` / `run.runtime`, shows coverage evidence in the
terms that frontend uses (proxy pass-throughs for Python, instrumentation
manifest matching for C++), and lists source sites per file with the file's
language. No analyzer result is interpreted differently by language.

The page itself is a client-rendered dashboard (Overview / Timeline / Lineage
/ Source / Events tabs): the four bundle documents are embedded verbatim as a
JSON object in a <script> tag, and all rendering happens in the browser from
that data, so the file stays self-contained and works offline. Untrusted
strings from the trace (source paths, finding text) are never HTML-escaped
into markup by this module; they are JSON-encoded (with `<`, `>` and `&`
escaped to `\\uXXXX` so a value cannot break out of the <script> tag or inject
markup), and the page's own `esc()` helper HTML-escapes them again at render
time, just before they reach the DOM.
"""

from __future__ import annotations

import json
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


def _short_path(path: str | None, root: str) -> str:
    if not path:
        return "unknown"
    if root and path.startswith(root.rstrip(os.sep) + os.sep):
        return path[len(root.rstrip(os.sep)) + 1 :]
    return path


def _build_static_sections(
    manifest: Mapping[str, Any],
    trace: Mapping[str, Any],
    events: list[Mapping[str, Any]],
    findings: list[Mapping[str, Any]],
) -> tuple[str, str]:
    """Server-rendered fragments dropped into the interactive shell: the
    producer-neutral environment/coverage panel, and the <noscript> fallback."""

    env = describe_environment(manifest, trace)
    coverage = manifest.get("coverage") or {}

    files = Counter((event.get("source") or {}).get("file") for event in events)
    files.pop(None, None)
    root = env.get("source_root") or _common_prefix(files)

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
    ) or '<tr><td>No environment metadata</td></tr>'

    coverage_rows = "".join(
        f"<tr><th scope=\"row\">{_cell(label)}</th><td>{_cell(value)}</td></tr>"
        for label, value in _coverage_rows(coverage, env.get("language"))
    )

    file_rows = (
        "".join(
            "<tr>"
            f"<td><code>{_cell(_short_path(path, root))}</code></td>"
            f"<td>{_cell(_language_of_file(path) or env.get('language'))}</td>"
            f"<td class=\"num\">{count}</td>"
            "</tr>"
            for path, count in sorted(files.items(), key=lambda item: (-item[1], item[0]))
        )
        or '<tr><td colspan="3">No source-attributed events</td></tr>'
    )

    synthetic_notice = (
        '<p class="warning-note"><strong>Synthetic contract:</strong> this bundle uses '
        "a metadata-only fake backend and is not cryptographic or OpenFHE evidence.</p>"
        if manifest.get("synthetic_contract") is True
        else ""
    )

    env_panel = (
        '<section class="panel env-panel">'
        '<div class="panel-head"><div><h2>Environment &amp; coverage</h2>'
        "<p>Producer-neutral facts from this bundle's manifest — the same page renders for every frontend</p>"
        "</div></div>"
        f"{synthetic_notice}"
        '<div class="env-grid">'
        f'<div class="table-wrap"><table><tbody>{environment_rows}</tbody></table></div>'
        f'<div class="table-wrap"><table><tbody>{coverage_rows}</tbody></table></div>'
        '<div class="table-wrap"><table><thead><tr><th>Source file</th><th>Language</th><th>Events</th></tr></thead>'
        f"<tbody>{file_rows}</tbody></table></div>"
        "</div>"
        "</section>"
    )

    noscript_rows = (
        "".join(
            "<tr>"
            f"<td>{_cell(event.get('sequence'))}</td>"
            f"<td>{_cell(event.get('operation'))}</td>"
            f"<td>{_cell(_short_path((event.get('source') or {}).get('file'), root))}</td>"
            "</tr>"
            for event in events
        )
        or '<tr><td colspan="3">No events</td></tr>'
    )
    noscript_items = (
        "".join(
            f"<li><strong>{_cell(finding.get('rule_id'))}</strong>: {_cell(finding.get('recommendation'))}</li>"
            for finding in findings
        )
        or "<li>No applicable findings for the observed path.</li>"
    )
    noscript = (
        f"<h1>CipherScope run {_cell(manifest.get('run_id'))}</h1>"
        "<p><strong>Sensitive artifact:</strong> JavaScript is disabled; the accessible static projection follows.</p>"
        f"<table><thead><tr><th>#</th><th>Operation</th><th>Source</th></tr></thead><tbody>{noscript_rows}</tbody></table>"
        f"<ul>{noscript_items}</ul>"
    )
    return env_panel, noscript


def _json_for_inline_script(data: Mapping[str, Any]) -> str:
    """A JSON literal safe to splice into `const DATA=...;` inside a <script> tag.

    Untrusted trace/finding content (paths, recommendation text) can contain
    `<`, `>` or `&`; escaping those to `\\uXXXX` means no value can ever start
    or end an HTML tag (in particular `</script>`), regardless of what the
    profiled program's source looked like.
    """

    text = json.dumps(data, default=str)
    for char, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(char, escaped)
    return text


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>__CIPHERSCOPE_TITLE__</title>
<style>
:root {
  --bg:#080b11; --panel:#0e131d; --panel2:#121925; --line:#202b3a;
  --text:#f3f6fb; --muted:#8c9aab; --faint:#536173; --cyan:#4ee6c1;
  --blue:#6da8ff; --violet:#a987ff; --amber:#ffca68; --red:#ff7285;
  --shadow:0 18px 60px rgba(0,0,0,.28); --radius:18px;
}
*{box-sizing:border-box} html{scroll-behavior:smooth}
[hidden]{display:none!important}
body{margin:0;background:radial-gradient(circle at 75% -10%,#16233a 0,transparent 32rem),var(--bg);color:var(--text);font:14px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input{font:inherit} button{color:inherit}
.shell{display:grid;grid-template-columns:228px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;padding:28px 18px;border-right:1px solid var(--line);background:rgba(8,11,17,.86);backdrop-filter:blur(18px);z-index:5}
.brand{display:flex;align-items:center;gap:11px;padding:0 8px 30px;font-weight:760;letter-spacing:-.02em;font-size:16px}
.mark{width:29px;height:29px;border:1px solid #366a67;border-radius:9px;display:grid;place-items:center;background:linear-gradient(145deg,#152b2b,#0a1118);box-shadow:inset 0 0 20px rgba(78,230,193,.08)}
.mark svg{width:17px} .brand span{color:var(--muted);font-weight:520}
.nav{display:grid;gap:5px} .nav button{display:flex;gap:11px;align-items:center;width:100%;padding:10px 12px;border:0;border-radius:10px;background:transparent;color:var(--muted);cursor:pointer;text-align:left}
.nav button:hover{background:#111925;color:var(--text)} .nav button.active{background:#17202d;color:var(--text);box-shadow:inset 3px 0 var(--cyan)}
.nav svg{width:17px;height:17px;stroke:currentColor;fill:none;stroke-width:1.7}
.side-foot{position:absolute;left:26px;right:26px;bottom:24px;color:var(--faint);font-size:11px} .side-foot strong{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}
main{min-width:0;padding:32px clamp(24px,4vw,58px) 70px;max-width:1600px;width:100%;margin:auto}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:30px}
.eyebrow{text-transform:uppercase;letter-spacing:.16em;font-size:10px;font-weight:750;color:var(--cyan);margin-bottom:7px}
h1{margin:0;font-size:clamp(25px,3vw,38px);line-height:1.1;letter-spacing:-.045em} .run-id{margin-top:10px;color:var(--muted);font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
.status{display:flex;align-items:center;gap:8px;border:1px solid #274538;background:#101c19;padding:8px 12px;border-radius:999px;color:#a7f5df;font-size:12px;font-weight:700;text-transform:capitalize}
.status i{width:7px;height:7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 10px var(--cyan)}
.notice{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;border:1px solid #3a3323;border-radius:13px;background:rgba(65,49,20,.24);color:#dbc99f;margin-bottom:22px;font-size:12px}
.notice svg{width:17px;min-width:17px;stroke:var(--amber);fill:none}
.notice.coverage-gap{border-color:#633642;background:rgba(91,32,47,.25);color:#ffc0cb}
.view{display:none;animation:rise .22s ease} .view.active{display:block} @keyframes rise{from{opacity:.3;transform:translateY(5px)}}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:18px}
.metric,.panel{border:1px solid var(--line);background:linear-gradient(150deg,rgba(18,25,37,.94),rgba(12,17,26,.96));box-shadow:var(--shadow)}
.metric{border-radius:15px;padding:17px 18px;min-height:112px;position:relative;overflow:hidden} .metric:after{content:"";position:absolute;width:80px;height:80px;border-radius:50%;background:var(--glow,var(--blue));filter:blur(55px);opacity:.18;right:-15px;top:-15px}
.metric .label{color:var(--muted);font-size:11px;font-weight:650} .metric .value{font-size:27px;letter-spacing:-.04em;font-weight:720;margin:9px 0 2px} .metric .sub{font-size:11px;color:var(--faint)}
.grid2{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(300px,.75fr);gap:18px;margin-bottom:18px}
.panel{border-radius:var(--radius);padding:20px;min-width:0} .panel-head{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:20px} .panel-head h2{font-size:14px;margin:0;letter-spacing:-.01em} .panel-head p{margin:3px 0 0;color:var(--muted);font-size:11px}
.chip{padding:5px 8px;border:1px solid var(--line);border-radius:7px;color:var(--muted);font-size:10px}
.bars{display:grid;gap:13px} .bar-row{display:grid;grid-template-columns:minmax(100px,150px) 1fr 34px;align-items:center;gap:12px;font-size:11px} .bar-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#c9d2df;font-family:ui-monospace,SFMono-Regular,Menlo,monospace} .bar-track{height:7px;border-radius:10px;background:#1a2230;overflow:hidden} .bar-fill{height:100%;border-radius:10px;background:linear-gradient(90deg,var(--blue),var(--cyan));transform-origin:left;animation:grow .6s ease both} @keyframes grow{from{transform:scaleX(0)}} .bar-val{text-align:right;color:var(--muted)}
.depth-card{display:grid;place-items:center;min-height:205px;text-align:center} .ring{width:130px;height:130px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--violet) var(--ring),#1c2330 0);position:relative} .ring:after{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--panel)} .ring-inner{position:relative;z-index:1} .ring strong{font-size:32px;display:block;letter-spacing:-.05em} .ring span{font-size:10px;color:var(--muted)}
.findings{display:grid;gap:10px} .finding{display:grid;grid-template-columns:4px 1fr auto;gap:14px;padding:15px 15px 15px 0;border:1px solid var(--line);border-radius:12px;background:#0c121b;cursor:pointer;transition:.16s} .finding:hover{transform:translateY(-1px);border-color:#344359} .finding .stripe{border-radius:0 5px 5px 0;background:var(--blue)} .finding.opportunity .stripe{background:var(--cyan)} .finding.warning .stripe,.finding.error .stripe{background:var(--amber)} .finding h3{font-size:12px;margin:0 0 4px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace} .finding p{margin:0;color:var(--muted);font-size:11px;max-width:820px} .badge{height:max-content;border:1px solid var(--line);border-radius:999px;padding:4px 8px;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.06em}
.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px;flex-wrap:wrap} .toolbar h2{font-size:18px;margin:0} .toolbar p{color:var(--muted);margin:3px 0 0;font-size:11px}
.search{position:relative} .search input{width:min(320px,70vw);border:1px solid var(--line);background:#0c121b;color:var(--text);border-radius:10px;padding:9px 12px 9px 34px;outline:0} .search input:focus{border-color:#426582;box-shadow:0 0 0 3px rgba(109,168,255,.08)} .search svg{position:absolute;left:11px;top:10px;width:15px;stroke:var(--muted);fill:none}
.timeline-wrap{overflow:auto;padding-bottom:8px} #timeline{min-width:740px;width:100%;height:auto;display:block} .axis{fill:var(--faint);font-size:9px} .event-label{fill:#cbd5e2;font:10px ui-monospace,SFMono-Regular,Menlo,monospace} .event-bar{cursor:pointer;transition:opacity .15s} .event-bar:hover{opacity:.72} .ram-bar{opacity:.82} .ram-bar:hover{opacity:1} .guide{stroke:#202a38;stroke-width:1}
.graph-wrap{overflow:auto;min-height:450px} #graph{min-width:900px;width:100%;height:auto;display:block} .graph-edge{stroke:#334054;stroke-width:1.2;fill:none} .graph-node{cursor:pointer} .graph-node rect{fill:#121c29;stroke:#30405a;stroke-width:1} .graph-node:hover rect{stroke:var(--cyan)} .graph-node text{fill:#dbe4ef;font:9px ui-monospace,SFMono-Regular,Menlo,monospace} .graph-node .small{fill:var(--muted);font-size:8px}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px} table{border-collapse:collapse;width:100%;min-width:820px;background:#0d131c} th{position:sticky;top:0;background:#121a26;color:#7f8da0;text-transform:uppercase;letter-spacing:.08em;font-size:9px;text-align:left;padding:11px 14px;border-bottom:1px solid var(--line)} td{padding:12px 14px;border-bottom:1px solid #18212e;color:#c7d0dc;font-size:11px} tbody tr{cursor:pointer} tbody tr:hover{background:#111a27} td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace} .ok{color:var(--cyan)} .error{color:var(--red)}
.source-layout{display:grid;grid-template-columns:180px minmax(0,1fr);gap:14px;align-items:start} .source-files{display:grid;gap:6px;position:sticky;top:18px} .source-files button{border:1px solid var(--line);background:#0c121b;color:var(--muted);padding:9px 11px;border-radius:9px;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;font:10px ui-monospace,SFMono-Regular,Menlo,monospace} .source-files button.active{color:var(--text);border-color:#3c596c;background:#131e2b} .source-panel{padding:0;overflow:hidden} .source-head{display:flex;justify-content:space-between;gap:12px;padding:14px 17px;border-bottom:1px solid var(--line);background:#111925} .source-head strong{font:11px ui-monospace,SFMono-Regular,Menlo,monospace} .source-head span{font-size:10px;color:var(--muted)} .code{overflow:auto;max-height:72vh;background:#090d14} .code-line{display:grid;grid-template-columns:52px minmax(360px,1fr) minmax(260px,390px);min-height:27px;border-bottom:1px solid rgba(32,43,58,.35)} .code-line.hot{background:linear-gradient(90deg,rgba(78,230,193,.055),transparent 68%)} .line-no{padding:5px 13px 5px 5px;text-align:right;color:#465467;user-select:none;font:10px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;border-right:1px solid #18212d} .code-text{margin:0;padding:5px 14px;color:#bfcbd9;white-space:pre;tab-size:4;font:11px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace} .syn-keyword{color:#c792ea} .syn-builtin{color:#82aaff} .syn-string{color:#c3e88d} .syn-number{color:#f78c6c} .syn-comment{color:#65758a;font-style:italic} .line-metrics{padding:4px 10px;display:flex;gap:5px;align-items:center;flex-wrap:wrap;border-left:1px solid #18212d} .metric-tag{font-size:9px;padding:2px 6px;border-radius:5px;background:#172333;color:#9cb3cb;white-space:nowrap} .metric-tag.op{color:#9df2da;background:#10251f} .metric-tag.finding-tag{color:#f7d38c;background:#2a2111;cursor:pointer} .source-empty{padding:60px 25px;text-align:center;color:var(--muted)}
.explain{margin:14px 0;padding:13px 14px;border-left:3px solid var(--cyan);background:#101a20;border-radius:0 9px 9px 0;color:#c8d6e1;font-size:12px} .detail-section{margin-top:20px} .detail-section h3{font-size:11px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:0 0 9px} .detail-section p{margin:0;color:#cbd5e2;font-size:12px} .detail-list{padding-left:18px;margin:8px 0;color:#aebbc9;font-size:11px} .detail-list li{margin:5px 0}
.drawer{position:fixed;z-index:20;right:0;top:0;width:min(480px,92vw);height:100vh;background:#0d131c;border-left:1px solid var(--line);box-shadow:-25px 0 80px rgba(0,0,0,.5);padding:24px;transform:translateX(105%);transition:transform .22s ease;overflow:auto} .drawer.open{transform:none} .drawer-close{float:right;border:1px solid var(--line);background:#151e2b;border-radius:8px;width:32px;height:32px;cursor:pointer} .drawer h2{font-size:18px;margin:48px 0 4px} .drawer .meta{color:var(--muted);font:11px ui-monospace,SFMono-Regular,Menlo,monospace;margin-bottom:22px} .detail-grid{display:grid;grid-template-columns:120px 1fr;gap:9px;font-size:11px;padding:13px 0;border-top:1px solid var(--line)} .detail-grid dt{color:var(--muted)} .detail-grid dd{margin:0;word-break:break-word} .json{white-space:pre-wrap;word-break:break-word;background:#080c12;border:1px solid var(--line);padding:13px;border-radius:10px;color:#a9b8ca;font:10px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}
.empty{color:var(--muted);text-align:center;padding:45px 20px;border:1px dashed var(--line);border-radius:12px}
noscript{display:block;padding:20px} noscript table{min-width:0}
.env-panel{margin-bottom:18px} .env-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:4px;align-items:start} .env-grid .table-wrap{overflow:visible;max-width:100%} .env-grid table{width:100%;min-width:0;max-width:100%;table-layout:fixed} .env-grid th,.env-grid td{padding:8px 10px;font-size:11px;white-space:normal;word-break:break-word;overflow-wrap:anywhere} .env-grid th[scope="row"]{width:42%;position:static}
.warning-note{margin:0 0 14px;padding:10px 12px;border:1px solid #633642;background:rgba(91,32,47,.25);color:#ffc0cb;border-radius:10px;font-size:12px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.side{position:sticky;height:auto;padding:12px 16px;display:flex;align-items:center;border-right:0;border-bottom:1px solid var(--line)}.brand{padding:0;margin-right:auto}.brand span,.side-foot{display:none}.nav{display:flex;overflow:auto}.nav button{width:auto}.nav button span{display:none}main{padding:25px 18px 60px}.metrics{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}.source-layout{grid-template-columns:1fr}.source-files{position:static;display:flex;overflow:auto}.source-files button{min-width:150px}}
@media(max-width:520px){.metrics{grid-template-columns:1fr 1fr}.metric{padding:14px;min-height:98px}.metric .value{font-size:22px}.top{align-items:flex-end}}
</style>
</head>
<body>
<div class="shell">
<aside class="side">
  <div class="brand"><div class="mark"><svg viewBox="0 0 24 24"><path d="M6 7.5 12 4l6 3.5v9L12 20l-6-3.5z" fill="none" stroke="#4ee6c1"/><path d="m8.5 9 3.5 2 3.5-2M12 11v5" fill="none" stroke="#4ee6c1"/></svg></div>CipherScope <span>/ trace</span></div>
  <nav class="nav" aria-label="Report views">
    <button class="active" data-view="overview"><svg viewBox="0 0 24 24"><path d="M4 13h6V4H4zm10 7h6V11h-6zM4 20h6v-3H4zm10-13h6V4h-6z"/></svg><span>Overview</span></button>
    <button data-view="timeline"><svg viewBox="0 0 24 24"><path d="M4 6h9M4 12h16M4 18h11"/></svg><span>Timeline</span></button>
    <button data-view="lineage"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 12h4l6-6M11 12l6 6"/></svg><span>Lineage</span></button>
    <button data-view="source"><svg viewBox="0 0 24 24"><path d="m8 8-4 4 4 4m8-8 4 4-4 4m-3-11-2 14"/></svg><span>Source</span></button>
    <button data-view="events"><svg viewBox="0 0 24 24"><path d="M5 5h14M5 12h14M5 19h14"/></svg><span>Events</span></button>
  </nav>
  <div class="side-foot"><strong>Local report</strong>No network requests · data embedded</div>
</aside>
<main>
  <header class="top"><div><div class="eyebrow">OpenFHE execution profile</div><h1 id="title">Trace analysis</h1><div class="run-id" id="runId"></div></div><div class="status"><i></i><span id="status"></span></div></header>
  <div class="notice"><svg viewBox="0 0 24 24"><path d="M12 3 2.8 20h18.4zM12 9v5m0 3v.1"/></svg><div><strong>Sensitive artifact.</strong> This report embeds executed source text plus topology, source sites, rotation indices, and timing. Keep it private.</div></div>
  <div class="notice coverage-gap" id="coverageNotice" hidden><svg viewBox="0 0 24 24"><path d="M12 3 2.8 20h18.4zM12 9v5m0 3v.1"/></svg><div></div></div>

  <section class="view active" id="view-overview">
    __CIPHERSCOPE_ENV_PANEL__
    <div class="metrics" id="metrics"></div>
    <div class="grid2">
      <section class="panel"><div class="panel-head"><div><h2>Operation mix</h2><p>Calls grouped by OpenFHE operation</p></div><span class="chip" id="opKinds"></span></div><div class="bars" id="opBars"></div></section>
      <section class="panel depth-card"><div><div class="ring" id="depthRing"><div class="ring-inner"><strong id="depthValue">0</strong><span id="depthLabel">observed depth</span></div></div><p id="depthCaption" style="color:var(--muted);font-size:11px;margin:15px 0 0"></p></div></section>
    </div>
    <section class="panel"><div class="panel-head"><div><h2>Optimization signals</h2><p>Evidence-linked findings from this observed run</p></div><span class="chip" id="findingCount"></span></div><div class="findings" id="findings"></div></section>
  </section>

  <section class="view" id="view-timeline"><div class="toolbar"><div><h2>Execution timeline</h2><p>Top bar: inclusive wall duration. Bottom bar: peak process-RSS Δ. Both per call, both normalized to the observed run</p></div><span class="chip" id="ramScaleChip"></span><span class="chip">click an event for details</span></div><section class="panel"><div class="timeline-wrap"><svg id="timeline" role="img" aria-label="Event duration and memory timeline"></svg></div></section></section>
  <section class="view" id="view-lineage"><div class="toolbar"><div><h2>Ciphertext lineage</h2><p>Immutable versions and the operations that produced them</p></div><span class="chip" id="nodeCount"></span></div><section class="panel graph-wrap"><svg id="graph" role="img" aria-label="Ciphertext lineage graph"></svg></section></section>
  <section class="view" id="view-source"><div class="toolbar"><div><h2>Annotated source</h2><p>Executed call sites with timing, state, flow, and finding overlays</p></div><span class="chip" id="sourceCount"></span></div><div class="source-layout"><aside class="source-files" id="sourceFiles"></aside><section class="panel source-panel" id="sourceViewer"></section></div></section>
  <section class="view" id="view-events"><div class="toolbar"><div><h2>Semantic events</h2><p id="eventCount"></p></div><label class="search"><svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/></svg><input id="search" type="search" placeholder="Filter operation, source, status…" aria-label="Filter events"></label></div><div class="table-wrap"><table><thead><tr><th>#</th><th>Operation</th><th>Status</th><th>Source</th><th>Wall time</th><th>Process HWM Δ</th><th>Inputs → outputs</th></tr></thead><tbody id="eventRows"></tbody></table></div></section>
</main>
</div>
<aside class="drawer" id="drawer" aria-hidden="true"><button class="drawer-close" id="drawerClose" aria-label="Close details">×</button><div id="drawerBody"></div></aside>
<noscript>__CIPHERSCOPE_NOSCRIPT__</noscript>
<script>const DATA=__CIPHERSCOPE_DATA_JSON__;
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??"unknown").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const events=[...(DATA.trace.events||[])].sort((a,b)=>a.sequence-b.sequence), findings=DATA.recommendations.findings||[], sources=DATA.trace.sources||[], contexts=DATA.trace.contexts||[], artifacts=DATA.trace.artifacts||[], artifactById=new Map(artifacts.map(a=>[a.id,a])), ctx=DATA.trace.context||contexts[0]||{}, manifest=DATA.manifest||{}, coverage=manifest.coverage||{};
const fmt=n=>{n=Number(n||0);if(n>=1e9)return (n/1e9).toFixed(2)+" s";if(n>=1e6)return (n/1e6).toFixed(2)+" ms";if(n>=1e3)return (n/1e3).toFixed(2)+" μs";return n+" ns"};
const fmtBytes=n=>{if(n==null)return "unavailable";n=Number(n);if(n>=1073741824)return (n/1073741824).toFixed(2)+" GiB";if(n>=1048576)return (n/1048576).toFixed(2)+" MiB";if(n>=1024)return (n/1024).toFixed(2)+" KiB";return n+" B"};
const PY_KEYWORDS=new Set("False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield match case".split(" "));
const PY_BUILTINS=new Set("abs all any bool bytes dict enumerate filter float int len list map max min object open print range reversed round set sorted str sum super tuple type zip self cls".split(" "));
function highlightPython(line){let out="",i=0;while(i<line.length){const rest=line.slice(i);if(line[i]==="#"){out+=`<span class="syn-comment">${esc(rest)}</span>`;break}if(line[i]==="'"||line[i]==='"'){const q=line[i],triple=rest.startsWith(q.repeat(3));let j=i+(triple?3:1),end=q.repeat(triple?3:1);while(j<line.length){if(line[j]==="\\"){j+=2;continue}if(line.slice(j,j+end.length)===end){j+=end.length;break}j++}out+=`<span class="syn-string">${esc(line.slice(i,j))}</span>`;i=j;continue}const number=rest.match(/^(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/);if(number){out+=`<span class="syn-number">${esc(number[0])}</span>`;i+=number[0].length;continue}const name=rest.match(/^[A-Za-z_]\w*/);if(name){const word=name[0],kind=PY_KEYWORDS.has(word)?"syn-keyword":PY_BUILTINS.has(word)?"syn-builtin":"";out+=kind?`<span class="${kind}">${esc(word)}</span>`:esc(word);i+=word.length;continue}out+=esc(line[i]);i++}return out||" "}
const RULES={
"depth.critical_path.v1":["The longest observed chain of ciphertext-to-ciphertext nonlinear work is summarized across bootstrap epochs.","Nonlinear depth is a primary constraint on leveled FHE programs. A longer path generally consumes more modulus budget and can require heavier parameters."],
"keys.unused_in_observed_run.v1":["Rotation keys were generated but not used by any covered operation in this execution.","Every evaluation key adds generation time, memory, and serialized key material. Removing genuinely unnecessary keys can reduce setup and deployment cost."],
"rotation.hoist_same_input.v1":["Several rotations start from the same immutable ciphertext and appear compatible with one shared fast-rotation precomputation.","Hoisting can reuse expensive decomposition work across rotations. This is an experiment candidate, not a promised speedup, until the transformed program is measured."],
"parameters.depth_headroom_observed.v1":["The configured multiplicative-depth budget is larger than the maximum level use observed in this run.","Excess parameter headroom can increase ring/modulus cost, but one trace may not cover worst-case inputs or branches."],
"packing.low_utilization_annotated.v1":["The program explicitly marked fewer meaningful values than the available CKKS slot capacity.","Low slot utilization can leave SIMD throughput unused. Repacking independent work may amortize encryption and evaluation costs."],
"provenance.public_value_ciphertext_mult.v1":["A value declared public was represented as a ciphertext operand in a multiplication.","If semantics permit, plaintext-ciphertext multiplication can avoid ciphertext-ciphertext depth and relinearization cost."],
"encoding.repeated_public_constant.v1":["The same declared public constant was encoded repeatedly during the observed run.","Caching an encoded plaintext can avoid repeated encoding overhead when context, scale, and level requirements match."],
"multiplication.serial_reduction_review.v1":["An associative multiplication region was observed as a serial reduction chain.","A balanced tree can shorten dependency depth and may expose parallel work, although it may change scheduling and numerical behavior."],
"precision.checkpoint_drop.v1":["A shadow-mode checkpoint measured a precision decrease beyond the configured diagnostic threshold.","Precision loss can indicate scale, depth, approximation, or parameter issues. The checkpoint identifies where to investigate, not the root cause by itself."],
"bootstrap.restored_levels_underused.v1":["A bootstrap restored capacity that was only lightly consumed afterward in the observed path.","Bootstrapping is expensive. If refreshed capacity is consistently unused, placement or parameters may deserve review."],
"precision.tolerance_violated.v1":["A checkpoint's decrypted values fell outside the absolute, relative, or minimum-bits tolerance the developer declared for it.","The tolerance is the program's own correctness contract; the first checkpoint to break it, and the operations since the previous checkpoint, localize where precision was lost."],
"configuration.testing_only_security.v1":["The run declared HEStd_NotSet, which disables OpenFHE's standard security-level enforcement.","A hand-picked ring dimension with no enforced security level is a prototyping shortcut; it must not reach a deployment that protects real data."],
};
const explain=f=>RULES[f.rule_id]||[`This ${f.category||"analysis"} signal was produced from the operations and metadata observed in this run.`,`Treat it as evidence for investigation. It does not prove behavior on unexecuted inputs, branches, or calls outside CipherScope coverage.`];
const total=events.reduce((s,e)=>s+(e.timing?.wall_duration_ns||0),0), errors=events.filter(e=>e.status!=="ok").length;
$("#title").textContent=(ctx.scheme||"FHE")+" trace analysis"; $("#runId").textContent=(manifest.run_id||"unknown run")+(contexts.length>1?` · ${contexts.length} contexts`:""); $("#status").textContent=manifest.status||"unknown";
const gapNames=coverage.unsupported_operations||[], gapCount=Number(coverage.unmatched_openfhe_candidates||coverage.unclassified_proxy_passthrough_calls||0);if(gapCount||gapNames.length){const n=$("#coverageNotice");n.hidden=false;n.querySelector("div").innerHTML=`<strong>Incomplete semantic coverage.</strong> ${gapCount||gapNames.length} call(s) fell outside this frontend's coverage${gapNames.length?": "+esc(gapNames.join(", ")):""}. Dependent optimization findings may be unavailable.`}
const ciphertexts=DATA.trace.ciphertexts||[], metricData=[["Traced calls",coverage.traced_calls_total??events.length,gapCount?gapCount+" coverage-gap calls":"captured API operations","--blue"],["Total API time",fmt(total),"inclusive wall time","--cyan"],["Tracked objects",ciphertexts.length+artifacts.length,`${ciphertexts.length} ciphertext versions · ${artifacts.length} opaque artifacts`,"--violet"],["Findings",findings.length,errors?errors+" failed events":"no failed events","--amber"]];
$("#metrics").innerHTML=metricData.map(x=>`<article class="metric" style="--glow:var(${x[3]})"><div class="label">${esc(x[0])}</div><div class="value">${esc(x[1])}</div><div class="sub">${esc(x[2])}</div></article>`).join("");
const counts=DATA.operationCounts||{}, maxCount=Math.max(1,...Object.values(counts)); $("#opKinds").textContent=Object.keys(counts).length+" operation types";
$("#opBars").innerHTML=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([n,v])=>`<div class="bar-row"><span class="bar-name" title="${esc(n)}">${esc(n)}</span><div class="bar-track"><div class="bar-fill" style="width:${v/maxCount*100}%"></div></div><span class="bar-val">${v}</span></div>`).join("")||'<div class="empty">No operations captured</div>';
const critical=DATA.graph.critical_paths?.nonlinear_ciphertext||{};
let depth=Number(critical.max_depth||0), depthLabel="observed depth", depthCaption=null;
const configured=Number(ctx.configured_multiplicative_depth||0);
const gateFinding=findings.find(f=>f.rule_id==="binfhe.gate_critical_path.v1");
if(!configured && (critical.confidence||"unknown")==="unknown" && gateFinding){depth=Number(gateFinding.evidence.max_gate_depth||0);depthLabel="bootstrapped gate depth";depthCaption="Longest EvalBinGate chain · EvalNOT is free and adds none"}
const pct=configured?Math.min(100,depth/configured*100):Math.min(100,depth*20);
$("#depthRing").style.setProperty("--ring",pct+"%"); $("#depthValue").textContent=depth; $("#depthLabel").textContent=depthLabel; $("#depthCaption").textContent=depthCaption??(configured?`Configured budget: ${configured} · ${Math.max(0,configured-depth)} headroom`:`${critical.confidence||"unknown"} confidence`);
$("#findingCount").textContent=findings.length+" findings";
$("#findings").innerHTML=findings.map((f,i)=>`<article class="finding ${esc(f.severity)}" data-finding="${i}"><div class="stripe"></div><div><h3>${esc(f.rule_id)}</h3><p>${esc(explain(f)[0])} <strong style="color:#cbd5e2">Action:</strong> ${esc(f.recommendation)}</p></div><span class="badge">${esc(f.confidence)}</span></article>`).join("")||'<div class="empty">No applicable optimization findings on this path.</div>';
const list=(items,empty="None recorded")=>(items?.length?`<ul class="detail-list">${items.map(x=>`<li>${esc(x)}</li>`).join("")}</ul>`:`<p>${esc(empty)}</p>`);
const artifactLabels=ids=>(ids||[]).map(id=>artifactById.has(id)?`${id} (${artifactById.get(id).kind})`:id).join(", ")||"none";
function openDetail(kind,item){const d=$("#drawer"), body=$("#drawerBody"); if(kind==="event"){const src=item.source||{}, t=item.timing||{}, r=item.resources||{}; body.innerHTML=`<div class="eyebrow">Event ${esc(item.sequence)}</div><h2>${esc(item.operation)}</h2><div class="meta">${esc(item.event_id)}</div><dl class="detail-grid"><dt>Status</dt><dd class="${item.status}">${esc(item.status)}</dd><dt>Event kind</dt><dd>${esc(item.kind)}</dd><dt>Context</dt><dd>${esc(item.context_id)}</dd><dt>Source</dt><dd>${esc(src.file)}:${esc(src.line)} · ${esc(src.function)}</dd><dt>Wall duration</dt><dd>${fmt(t.wall_duration_ns)}</dd><dt>CPU duration</dt><dd>${fmt(t.process_cpu_duration_ns)}</dd><dt>Process HWM before</dt><dd>${fmtBytes(r.process_peak_rss_before_bytes)}</dd><dt>Process HWM after</dt><dd>${fmtBytes(r.process_peak_rss_after_bytes)}</dd><dt>Process HWM delta</dt><dd>${fmtBytes(r.process_peak_rss_increase_bytes)} (not owned allocation)</dd><dt>Overload</dt><dd>${esc(item.overload)}</dd><dt>Ciphertexts</dt><dd>${esc((item.input_ciphertexts||[]).join(", ")||"none")} → ${esc((item.output_ciphertexts||[]).join(", ")||"none")}</dd><dt>Artifacts</dt><dd>${esc(artifactLabels(item.input_artifacts))} → ${esc(artifactLabels(item.output_artifacts))}</dd></dl><div class="detail-section"><h3>Semantic arguments</h3><pre class="json">${esc(JSON.stringify(item.semantic_arguments||{},null,2))}</pre></div>`}else{const x=explain(item);body.innerHTML=`<div class="eyebrow">${esc(item.category)} finding</div><h2>${esc(item.rule_id)}</h2><div class="meta">${esc(item.finding_id)}</div><div class="explain"><strong>What this means</strong><br>${esc(x[0])}</div><div class="detail-section"><h3>Why it matters</h3><p>${esc(x[1])}</p></div><div class="detail-section"><h3>Suggested next step</h3><p>${esc(item.recommendation)}</p></div><dl class="detail-grid"><dt>Severity</dt><dd>${esc(item.severity)}</dd><dt>Confidence</dt><dd>${esc(item.confidence)}</dd><dt>Evidence events</dt><dd>${esc((item.evidence_event_ids||[]).join(", ")||"none")}</dd><dt>Source</dt><dd>${esc((item.source_sites&&item.source_sites[0]&&item.source_sites[0].file)||item.source?.file||"run-wide")}${item.source?.lines?.length?":"+esc(item.source.lines.join(", ")):""}</dd></dl><div class="detail-section"><h3>Observed evidence</h3><pre class="json">${esc(JSON.stringify(item.evidence||{},null,2))}</pre></div><div class="detail-section"><h3>When this applies</h3>${list(item.applicability)}</div><div class="detail-section"><h3>Limitations</h3>${list(item.limitations)}</div>`} d.classList.add("open");d.setAttribute("aria-hidden","false")}
$("#drawerClose").onclick=()=>{$("#drawer").classList.remove("open");$("#drawer").setAttribute("aria-hidden","true")};
$$('[data-finding]').forEach(el=>el.onclick=()=>openDetail("finding",findings[Number(el.dataset.finding)]));
function renderRows(filter=""){filter=filter.toLowerCase();const shown=events.filter(e=>[e.operation,e.kind,e.status,e.source?.file,e.source?.function,e.event_id].join(" ").toLowerCase().includes(filter));$("#eventCount").textContent=`${shown.length} of ${events.length} recorded calls`;$("#eventRows").innerHTML=shown.map(e=>`<tr data-event="${esc(e.event_id)}"><td class="mono">${e.sequence}</td><td class="mono">${esc(e.operation)}</td><td class="${e.status}">${esc(e.status)}</td><td>${esc(e.source?.file)}:${esc(e.source?.line)}</td><td class="mono">${fmt(e.timing?.wall_duration_ns)}</td><td class="mono">${fmtBytes(e.resources?.process_peak_rss_increase_bytes)}</td><td class="mono">ct ${(e.input_ciphertexts||[]).length}→${(e.output_ciphertexts||[]).length} · obj ${(e.input_artifacts||[]).length}→${(e.output_artifacts||[]).length}</td></tr>`).join("");$$('[data-event]').forEach(el=>el.onclick=()=>openDetail("event",events.find(e=>e.event_id===el.dataset.event)))}
renderRows(); $("#search").oninput=e=>renderRows(e.target.value);
function renderSource(index=0){$("#sourceCount").textContent=sources.length+" captured files";const files=$("#sourceFiles"),viewer=$("#sourceViewer");if(!sources.length){files.innerHTML="";viewer.innerHTML='<div class="source-empty"><strong>Source text was not captured for this trace.</strong><br>CipherScope records call sites (file/line/function), not source text — open the file in your editor from the Events tab’s Source column.</div>';return}files.innerHTML=sources.map((s,i)=>`<button class="${i===index?"active":""}" data-source="${i}" title="${esc(s.file)}">${esc(s.file)}</button>`).join("");const doc=sources[index], lines=String(doc.content||"").split(/\r?\n/), fileEvents=events.filter(e=>e.source?.source_sha256===doc.source_sha256);viewer.innerHTML=`<div class="source-head"><strong>${esc(doc.file)}</strong><span>${fileEvents.length} events · ${lines.length} lines · Python</span></div><div class="code">${lines.map((text,n)=>{const line=n+1,evs=fileEvents.filter(e=>e.source?.line===line),wall=evs.reduce((s,e)=>s+(e.timing?.wall_duration_ns||0),0),cpu=evs.reduce((s,e)=>s+(e.timing?.process_cpu_duration_ns||0),0),ram=Math.max(0,...evs.map(e=>e.resources?.process_peak_rss_increase_bytes||0)),ops=[...new Set(evs.map(e=>e.operation))],related=findings.map((f,i)=>({f,i})).filter(x=>evs.some(e=>(x.f.evidence_event_ids||[]).includes(e.event_id)||(x.f.source_sites||[]).includes(e.source?.call_site_id))||(x.f.source?.file===doc.file&&(x.f.source?.lines||[]).includes(line))),levels=evs.flatMap(e=>[...(e.input_states||[]),...(e.output_states||[])]).map(x=>x.level).filter(x=>x!=null),rot=evs.map(e=>e.semantic_arguments?.rotation_index_requested).filter(x=>x!=null),tags=[];if(evs.length){tags.push(`<span class="metric-tag op">${evs.length}× ${esc(ops.join(", "))}</span>`,`<span class="metric-tag">wall ${fmt(wall)}</span>`,`<span class="metric-tag">CPU ${fmt(cpu)}</span>`,`<span class="metric-tag">max process HWM Δ ${fmtBytes(ram)}</span>`);const ins=evs.reduce((s,e)=>s+(e.input_ciphertexts||[]).length,0),outs=evs.reduce((s,e)=>s+(e.output_ciphertexts||[]).length,0);if(ins||outs)tags.push(`<span class="metric-tag">ct ${ins}→${outs}</span>`);if(levels.length)tags.push(`<span class="metric-tag">level ${Math.min(...levels)}→${Math.max(...levels)}</span>`);if(rot.length)tags.push(`<span class="metric-tag">rotate ${esc(rot.join(", "))}</span>`)}related.forEach(x=>tags.push(`<button class="metric-tag finding-tag" data-source-finding="${x.i}">${esc(x.f.severity)} · ${esc(x.f.category)}</button>`));return `<div class="code-line ${evs.length||related.length?"hot":""}"><span class="line-no">${line}</span><pre class="code-text">${highlightPython(text)}</pre><span class="line-metrics">${tags.join("")}</span></div>`}).join("")}</div>`;$$('[data-source]').forEach(el=>el.onclick=()=>renderSource(Number(el.dataset.source)));$$('[data-source-finding]').forEach(el=>el.onclick=()=>openDetail("finding",findings[Number(el.dataset.sourceFinding)]))}
renderSource();
function renderTimeline(){const svg=$("#timeline"),W=1000,left=175,row=40,top=35,H=Math.max(170,top+events.length*row+20),starts=events.map(e=>e.timing?.start_ns||0),min=starts.length?Math.min(...starts):0,ends=events.map(e=>(e.timing?.start_ns||0)+(e.timing?.wall_duration_ns||0)),max=ends.length?Math.max(...ends):min+1,span=Math.max(1,max-min),plot=W-left-28,rssValues=events.map(e=>e.resources?.process_peak_rss_increase_bytes||0),hasRss=rssValues.some(v=>v>0),maxRss=Math.max(1,...rssValues);$("#ramScaleChip").textContent=hasRss?`RAM bar scaled to peak Δ ${fmtBytes(maxRss)}`:"No memory data recorded for this run";svg.setAttribute("viewBox",`0 0 ${W} ${H}`);let s="";for(let i=0;i<=5;i++){let x=left+plot*i/5;s+=`<line class="guide" x1="${x}" y1="22" x2="${x}" y2="${H-12}"/><text class="axis" x="${x}" y="13" text-anchor="middle">${fmt(span*i/5)}</text>`}events.forEach((e,i)=>{let y=top+i*row,w=Math.max(3,(e.timing?.wall_duration_ns||0)/span*plot),x=left+((e.timing?.start_ns||0)-min)/span*plot,c=e.status==="ok"?(e.operation.includes("Mult")?"#a987ff":e.operation.includes("Rotate")?"#4ee6c1":"#6da8ff"):"#ff7285",rss=e.resources?.process_peak_rss_increase_bytes||0,rw=rss>0?Math.max(2,rss/maxRss*plot):0;s+=`<text class="event-label" x="0" y="${y+10}">${esc(e.sequence+" · "+e.operation)}</text><rect class="event-bar" data-timeline="${esc(e.event_id)}" x="${x}" y="${y}" width="${w}" height="11" rx="4" fill="${c}"><title>${esc(e.operation)} · wall ${fmt(e.timing?.wall_duration_ns)}</title></rect>`;if(rw)s+=`<rect class="event-bar ram-bar" data-timeline="${esc(e.event_id)}" x="${left}" y="${y+15}" width="${rw}" height="6" rx="3" fill="#ffca68"><title>${esc(e.operation)} · peak RSS Δ ${fmtBytes(rss)} (not owned allocation)</title></rect>`});svg.innerHTML=s;$$('[data-timeline]').forEach(el=>el.onclick=()=>openDetail("event",events.find(e=>e.event_id===el.dataset.timeline)))}
function renderGraph(){const svg=$("#graph"),cts=DATA.trace.ciphertexts||[];$("#nodeCount").textContent=cts.length+" versions";if(!cts.length){svg.setAttribute("viewBox","0 0 900 450");svg.innerHTML='<text x="450" y="220" text-anchor="middle" fill="#8c9aab">No ciphertext lineage recorded</text>';return}const map=new Map(cts.map(c=>[c.id,c])),depths=new Map();function dep(c,seen=new Set()){if(depths.has(c.id))return depths.get(c.id);if(seen.has(c.id))return 0;seen.add(c.id);let d=(c.parent_ids||[]).reduce((m,p)=>Math.max(m,map.has(p)?dep(map.get(p),seen)+1:0),0);depths.set(c.id,d);return d}cts.forEach(c=>dep(c));const groups={};cts.forEach(c=>(groups[depths.get(c.id)]??=[]).push(c));const cols=Object.keys(groups).map(Number).sort((a,b)=>a-b),W=Math.max(900,cols.length*220+100),maxRows=Math.max(...Object.values(groups).map(x=>x.length)),H=Math.max(450,maxRows*105+100),pos=new Map();cols.forEach((d,ci)=>groups[d].forEach((c,ri)=>pos.set(c.id,{x:50+ci*220,y:55+ri*105})));let s="";cts.forEach(c=>(c.parent_ids||[]).forEach(p=>{if(pos.has(p)){let a=pos.get(p),b=pos.get(c.id);s+=`<path class="graph-edge" d="M ${a.x+150} ${a.y+28} C ${a.x+180} ${a.y+28}, ${b.x-30} ${b.y+28}, ${b.x} ${b.y+28}"/>`}}));cts.forEach(c=>{let p=pos.get(c.id),ev=events.find(e=>e.event_id===c.created_by_event),label=ev?.operation||c.origin||"input";s+=`<g class="graph-node" data-node-event="${esc(c.created_by_event||"")}" transform="translate(${p.x} ${p.y})"><rect width="150" height="58" rx="9"/><circle cx="15" cy="17" r="4" fill="#4ee6c1"/><text x="27" y="20">${esc(c.id.length>19?c.id.slice(0,17)+"…":c.id)}</text><text class="small" x="15" y="42">${esc(label)}</text></g>`});svg.setAttribute("viewBox",`0 0 ${W} ${H}`);svg.innerHTML=s;$$('[data-node-event]').forEach(el=>{if(el.dataset.nodeEvent)el.onclick=()=>openDetail("event",events.find(e=>e.event_id===el.dataset.nodeEvent))})}
renderTimeline();renderGraph();
$$('.nav button').forEach(btn=>btn.onclick=()=>{$$('.nav button').forEach(x=>x.classList.remove('active'));btn.classList.add('active');$$('.view').forEach(x=>x.classList.remove('active'));$('#view-'+btn.dataset.view).classList.add('active')});
document.addEventListener("keydown",e=>{if(e.key==="Escape")$("#drawerClose").click()});
</script>
</body>
</html>
"""


def render_summary_html(
    manifest: Mapping[str, Any],
    trace: Mapping[str, Any],
    graph: Mapping[str, Any],
    recommendations: Mapping[str, Any],
) -> str:
    """Build the interactive HTML summary of validated documents."""

    events = sorted(trace.get("events", ()), key=lambda item: item["sequence"])
    counts = dict(Counter(event.get("operation", "unknown") for event in events))
    findings = list(recommendations.get("findings", ()))
    run_id = manifest.get("run_id") or "unknown"

    env_panel, noscript = _build_static_sections(manifest, trace, events, findings)
    data_json = _json_for_inline_script(
        {
            "manifest": manifest,
            "trace": trace,
            "graph": graph,
            "recommendations": recommendations,
            "operationCounts": counts,
        }
    )

    return (
        _TEMPLATE.replace("__CIPHERSCOPE_TITLE__", escape(f"CipherScope · {run_id}", quote=True))
        .replace("__CIPHERSCOPE_ENV_PANEL__", env_panel)
        .replace("__CIPHERSCOPE_NOSCRIPT__", noscript)
        .replace("__CIPHERSCOPE_DATA_JSON__", data_json)
    )
