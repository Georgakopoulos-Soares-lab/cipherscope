"""Public exception hierarchy for CipherScope lifecycle and coverage errors."""

from __future__ import annotations


class CipherScopeError(Exception):
    """Base class for errors raised by CipherScope itself."""


class SessionLifecycleError(CipherScopeError):
    """Raised when a session operation is invalid for its lifecycle state."""


class NoActiveSessionError(SessionLifecycleError):
    """Raised when :func:`cipherscope.attach` has no active session to join."""


class SessionClosedError(SessionLifecycleError):
    """Raised when a closed session or one of its proxies is used again."""


class AlreadyTracedError(SessionLifecycleError):
    """Raised when a context or proxy is already owned by another trace scope."""


class UnsupportedOperationError(CipherScopeError):
    """Raised before an unclassified native callable executes in strict mode."""


class ShadowModeError(CipherScopeError):
    """Raised when a precision checkpoint is requested outside enabled shadow mode."""


class AnnotationError(CipherScopeError):
    """Raised when a user annotation is structurally invalid."""
