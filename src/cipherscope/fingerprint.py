"""Identify the exact CipherScope and OpenFHE build a run was recorded on."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any

from .state import TOOL_VERSION

DEFAULT_LANE = "developer"
NATIVE_SUFFIXES = {".so", ".pyd", ".dylib"}


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(_repository_root()), *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def _distribution_version() -> str | None:
    try:
        return metadata.version("openfhe")
    except metadata.PackageNotFoundError:
        return None


def _native_module_hashes() -> dict[str, str]:
    """Hash the loaded OpenFHE wrapper's native modules; empty if it is not loaded."""

    module = sys.modules.get("openfhe")
    module_file = getattr(module, "__file__", None) if module is not None else None
    if not module_file:
        return {}
    package = Path(module_file).resolve().parent
    hashes: dict[str, str] = {}
    for path in sorted(package.rglob("*")):
        if path.is_file() and path.suffix in NATIVE_SUFFIXES:
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


@lru_cache(maxsize=1)
def build_fingerprint() -> dict[str, Any]:
    """Return the lane, wrapper provenance, and CipherScope commit for this process."""

    commit = _git("rev-parse", "HEAD")
    dirty = None
    if commit is not None:
        status = _git("status", "--porcelain")
        dirty = None if status is None else bool(status)
    return {
        "lane": os.environ.get("CIPHERSCOPE_OPENFHE_LANE", DEFAULT_LANE),
        "openfhe_distribution": _distribution_version(),
        "openfhe_native_module_hashes": _native_module_hashes(),
        "cipherscope_version": TOOL_VERSION,
        "cipherscope_commit": commit,
        "cipherscope_dirty": dirty,
    }


__all__ = ["DEFAULT_LANE", "build_fingerprint"]
