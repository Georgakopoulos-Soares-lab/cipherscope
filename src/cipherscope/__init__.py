"""Trace and analyze OpenFHE workloads."""

from __future__ import annotations

from .context import TracedCryptoContext
from .errors import (
    AlreadyTracedError,
    AnnotationError,
    CipherScopeError,
    NoActiveSessionError,
    SessionClosedError,
    SessionLifecycleError,
    ShadowModeError,
    UnsupportedOperationError,
)
from .session import Session, attach, runner_session, trace
from .state import SCHEMA_VERSION, TOOL_VERSION

__version__ = TOOL_VERSION

__all__ = [
    "SCHEMA_VERSION",
    "AlreadyTracedError",
    "AnnotationError",
    "CipherScopeError",
    "NoActiveSessionError",
    "Session",
    "SessionClosedError",
    "SessionLifecycleError",
    "ShadowModeError",
    "TracedCryptoContext",
    "UnsupportedOperationError",
    "__version__",
    "attach",
    "runner_session",
    "trace",
]
