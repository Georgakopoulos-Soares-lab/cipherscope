"""Small helpers for bounding and presenting opaque untrusted text.

CipherScope does not parse exception stacks in the MVP. These helpers exist for
future annotations/report fields and for exercising the ancillary security
corpus without expanding the supported-runtime claim.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass


_WINDOWS_PATH = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:\\[^\r\n\t<>\"]+")
_POSIX_PATH = re.compile(r"(?<![A-Za-z0-9_<>])/(?:[^/\s:<>]+/)*[^/\s:<>]+")
_TRUNCATION_MARKER = "\n[truncated]"


@dataclass(frozen=True, slots=True)
class SanitizedText:
    """A bounded presentation and whether bytes were discarded."""

    text: str
    truncated: bool
    original_bytes: int


def redact_paths(value: str) -> str:
    """Replace obvious Windows and POSIX absolute paths in opaque text."""

    value = _WINDOWS_PATH.sub("<redacted-path>", value)
    return _POSIX_PATH.sub("<redacted-path>", value)


def _utf8_prefix(value: bytes, budget: int) -> str:
    return value[: max(0, budget)].decode("utf-8", errors="ignore")


def sanitize_untrusted_text(
    value: str,
    *,
    max_bytes: int = 4096,
    for_html: bool = False,
) -> SanitizedText:
    """Redact paths, enforce a UTF-8 byte limit, and optionally HTML-escape.

    The byte bound applies before optional HTML expansion. The function never
    interprets frames, exception types, addresses, or language syntax.
    """

    if not isinstance(value, str):
        raise TypeError("untrusted text must be a string")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    redacted = redact_paths(value)
    encoded = redacted.encode("utf-8")
    truncated = len(encoded) > max_bytes
    if truncated:
        marker = _TRUNCATION_MARKER.encode("utf-8")
        if max_bytes >= len(marker):
            prefix = _utf8_prefix(encoded, max_bytes - len(marker))
            bounded = prefix + _TRUNCATION_MARKER
        else:
            bounded = _utf8_prefix(marker, max_bytes)
    else:
        bounded = redacted
    presented = html.escape(bounded, quote=True) if for_html else bounded
    return SanitizedText(presented, truncated, len(value.encode("utf-8")))


__all__ = ["SanitizedText", "redact_paths", "sanitize_untrusted_text"]
