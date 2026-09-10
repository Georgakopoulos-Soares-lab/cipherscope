"""Run a deterministic demonstration with a metadata-only backend."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .exporters import write_bundle
from .pipeline import build_analysis_bundle
from .session import trace
from .testing import FakeCiphertext, FakeCryptoContext


def build_demo_trace() -> dict[str, Any]:
    """Trace a tiny synthetic workload with a repeated-rotation opportunity."""

    backend = FakeCryptoContext()
    encrypted_input = FakeCiphertext()
    with trace(backend, name="cipherscope_fake_backend_demo") as session:
        session.context.EvalRotateKeyGen(object(), [1, 2, 4, 8])
        rotations = [
            session.context.EvalRotate(encrypted_input, index) for index in (1, 2, 4, 8)
        ]
        combined = session.context.EvalAdd(rotations[0], rotations[1])
        multiplied = session.context.EvalMult(combined, rotations[2])
        session.context.EvalBootstrap(multiplied)
    result = session.to_trace(status="completed")
    result["run"]["synthetic_contract"] = True
    return result


def build_demo_bundle() -> dict[str, dict[str, Any]]:
    """Build every document in the demonstration bundle."""

    return build_analysis_bundle(build_demo_trace())


def write_demo(output_dir: Path | str) -> Path:
    """Write the demonstration bundle without leaving partial output."""

    bundle = build_demo_bundle()
    return write_bundle(
        output_dir,
        manifest=bundle["manifest"],
        trace=bundle["trace"],
        graph=bundle["graph"],
        recommendations=bundle["recommendations"],
    )


__all__ = ["build_demo_bundle", "build_demo_trace", "write_demo"]
