"""Find the Python source location for traced calls."""

from __future__ import annotations

import inspect
import threading
from pathlib import Path
from types import CodeType, FrameType

from .state import UNKNOWN_SOURCE, SourceAttribution


class SourceResolver:
    """Find and cache the Python caller outside CipherScope."""

    def __init__(self, internal_modules: tuple[str, ...] = ("cipherscope",)) -> None:
        self._internal_modules = internal_modules
        self._cache: dict[tuple[CodeType, int, str], SourceAttribution] = {}
        self._lock = threading.Lock()

    def capture(self, operation: str) -> SourceAttribution:
        """Return the first Python caller outside CipherScope."""

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
        file = None
        if filename:
            file = (
                filename
                if filename.startswith("<") and filename.endswith(">")
                else str(Path(filename).resolve())
            )

        qualified_name = getattr(code, "co_qualname", code.co_name)
        line = frame.f_lineno
        call_site_id = ":".join(
            ("site", file or "unknown", str(line), qualified_name, operation)
        )
        return SourceAttribution(
            file=file,
            line=line,
            function=code.co_name,
            qualified_function=qualified_name,
            call_site_id=call_site_id,
        )
