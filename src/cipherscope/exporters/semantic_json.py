"""Write a complete CipherScope bundle without replacing existing output."""

from __future__ import annotations

import json
import shutil
import sysconfig
import tempfile
from pathlib import Path
from typing import Any, Mapping

from ..validation import assert_valid
from .csv import operations_csv
from .perfetto import perfetto_document
from .report import render_summary_html


def build_manifest(trace: Mapping[str, Any]) -> dict[str, Any]:
    """Build the standalone manifest from canonical run metadata."""

    run = trace.get("run") or {}
    context = trace.get("context") or {}
    manifest = {
        "schema_version": trace.get("schema_version", "1.0.0"),
        "run_id": run.get("run_id"),
        "status": run.get("status"),
        "tool": run.get("tool") or {"name": "cipherscope", "version": "0.1.0"},
        "runtime": run.get("runtime") or {},
        "coverage": run.get("coverage") or {},
        "clocks": {
            "wall": "time.perf_counter_ns",
            "cpu": "time.process_time_ns",
        },
        "parameter_set": {
            "scheme": context.get("scheme", "CKKS"),
            "ring_dimension": context.get("ring_dimension"),
            "configured_multiplicative_depth": context.get(
                "configured_multiplicative_depth"
            ),
            "scaling_technique": context.get("scaling_technique"),
            "security_level": context.get("security_level"),
        },
    }
    if run.get("synthetic_contract") is True:
        manifest["synthetic_contract"] = True
    return manifest


def _write_bytes(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)


def _write_text(path: Path, payload: str) -> None:
    _write_bytes(path, payload.encode("utf-8"))


def _json_text(document: Mapping[str, Any]) -> str:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _schema_directory() -> Path:
    candidates = (
        Path(__file__).resolve().parents[3] / "schemas",
        Path(sysconfig.get_path("data")) / "share" / "cipherscope" / "schemas",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "CipherScope schema files are unavailable; use a source checkout or "
        "install package data correctly"
    )


def write_bundle(
    output_dir: Path | str,
    *,
    trace: Mapping[str, Any],
    graph: Mapping[str, Any],
    recommendations: Mapping[str, Any],
    manifest: Mapping[str, Any] | None = None,
) -> Path:
    """Stage a complete bundle and publish it without overwriting."""

    destination = Path(output_dir)
    if destination.exists():
        raise FileExistsError(f"output path already exists: {destination}")
    resolved_manifest = dict(manifest or build_manifest(trace))
    assert_valid("trace", trace)
    assert_valid("graph", graph, trace=trace)
    assert_valid(
        "recommendations",
        recommendations,
        trace=trace,
        graph=graph,
    )
    assert_valid("manifest", resolved_manifest, trace=trace)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.tmp-",
            dir=destination.parent,
        )
    )
    try:
        _write_text(staging / "manifest.json", _json_text(resolved_manifest))
        _write_text(staging / "trace.json", _json_text(trace))
        _write_text(staging / "ciphertext_graph.json", _json_text(graph))
        _write_text(staging / "recommendations.json", _json_text(recommendations))
        _write_text(staging / "operations.csv", operations_csv(trace))
        _write_text(
            staging / "perfetto-trace.json",
            _json_text(perfetto_document(trace)),
        )
        _write_text(
            staging / "summary.html",
            render_summary_html(resolved_manifest, trace, graph, recommendations),
        )

        schema_output = staging / "schemas"
        schema_output.mkdir()
        for source in sorted(_schema_directory().glob("*.schema.json")):
            _write_bytes(schema_output / source.name, source.read_bytes())

        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination
