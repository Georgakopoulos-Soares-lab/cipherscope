"""Privacy-bounded source attribution for traced calls."""

from __future__ import annotations

import hashlib
import inspect
import threading
from pathlib import Path
from types import CodeType, FrameType

from .state import SourceAttribution, UNKNOWN_SOURCE


class SourceResolver:
    """Resolve and cache the first frame outside configured internal packages.

    Only a basename is emitted. The absolute path is used transiently to hash the
    source file and is never retained in the returned trace value.
    """

    def __init__(self, internal_modules: tuple[str, ...] = ("cipherscope",)) -> None:
        self._internal_modules = internal_modules
        self._cache: dict[tuple[CodeType, int, str], SourceAttribution] = {}
        self._lock = threading.Lock()

    def capture(self, operation: str) -> SourceAttribution:
        """Capture the first external Python frame for ``operation``."""

        frame = inspect.currentframe()
        try:
            frame = frame.f_back if frame is not None else None
            while frame is not None:
                if not self._is_internal(frame):
                    key = (frame.f_code, frame.f_lasti, operation)
                    with self._lock:
                        cached = self._cache.get(key)
                    if cached is not None:
                        return cached
                    resolved = self._resolve_frame(frame, operation)
                    with self._lock:
                        return self._cache.setdefault(key, resolved)
                frame = frame.f_back
        finally:
            del frame
        return UNKNOWN_SOURCE

    def _is_internal(self, frame: FrameType) -> bool:
        module_name = frame.f_globals.get("__name__")
        if not isinstance(module_name, str):
            return False
        return any(
            module_name == prefix or module_name.startswith(prefix + ".")
            for prefix in self._internal_modules
        )

    @staticmethod
    def _resolve_frame(frame: FrameType, operation: str) -> SourceAttribution:
        code = frame.f_code
        filename = code.co_filename
        basename = Path(filename).name if filename else None
        source_hash: str | None = None
        if filename and not (filename.startswith("<") and filename.endswith(">")):
            try:
                source_hash = hashlib.sha256(Path(filename).read_bytes()).hexdigest()
            except OSError:
                source_hash = None

        qualified_name = getattr(code, "co_qualname", code.co_name)
        line = frame.f_lineno
        material = "\0".join(
            (
                source_hash or "unknown",
                basename or "unknown",
                qualified_name,
                str(line),
                operation,
            )
        )
        call_site_id = (
            "site_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
        )
        return SourceAttribution(
            file=basename,
            line=line,
            function=code.co_name,
            qualified_function=qualified_name,
            source_sha256=source_hash,
            call_site_id=call_site_id,
        )
