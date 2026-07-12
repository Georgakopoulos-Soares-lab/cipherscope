"""Session lifecycle, trace scopes, and active-session attachment."""

from __future__ import annotations

import contextvars
import threading
import time
from dataclasses import dataclass
from typing import Any, ContextManager, Generic, Literal, TypeVar

from .compatibility import DEFAULT_COMPATIBILITY, CompatibilityRegistry
from .context import TracedCryptoContext
from .errors import (
    AlreadyTracedError,
    AnnotationError,
    NoActiveSessionError,
    SessionClosedError,
    SessionLifecycleError,
    ShadowModeError,
)
from .recorder import EventRecorder
from .shadow import decode_real, precision_metrics
from .source import SourceResolver


ContextT = TypeVar("ContextT")


@dataclass
class _Ownership:
    native_context: Any
    session: "Session[Any]"


_OWNERS: dict[int, _Ownership] = {}
_OWNERS_LOCK = threading.RLock()
_ACTIVE_SESSION: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "cipherscope_active_session", default=None
)


class Session(Generic[ContextT]):
    """Own one trace run and all proxies attached during that run.

    Lifecycle is ``created -> active -> closed``. A session cannot be re-entered;
    proxies deliberately stop forwarding after their owner closes.
    """

    def __init__(
        self,
        native_context: ContextT | None = None,
        *,
        name: str | None = None,
        strict: bool = True,
        compatibility: CompatibilityRegistry | None = None,
        secret_key: Any = None,
        shadow_mode: bool = False,
    ) -> None:
        self.strict = strict
        self.shadow_mode = shadow_mode
        self._secret_key = secret_key
        self.compatibility = (compatibility or DEFAULT_COMPATIBILITY).for_session()
        self.recorder = EventRecorder(
            compatibility=self.compatibility,
            strict=strict,
            name=name,
            shadow_mode=shadow_mode,
        )
        self.source_resolver = SourceResolver()
        self._initial_context = native_context
        self._state = "created"
        self._token: contextvars.Token[Any] | None = None
        self._proxies: dict[int, TracedCryptoContext[Any, Any]] = {}
        self._owned_ids: set[int] = set()
        self._scoped_ids: set[int] = set()
        self._current_context: TracedCryptoContext[Any, Any] | None = None
        self._context_metadata: dict[str, Any] | None = None
        self._lock = threading.RLock()

    @property
    def context(self) -> TracedCryptoContext[Any, Any]:
        """Return the current proxy or raise if no context has been attached."""

        with self._lock:
            if self._current_context is None:
                raise SessionLifecycleError("the session has no attached context")
            return self._current_context

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def has_attached_context(self) -> bool:
        """Whether any native context participated in this run."""

        with self._lock:
            return bool(self._proxies)

    def __enter__(self) -> "Session[ContextT]":
        with self._lock:
            if self._state == "closed":
                raise SessionClosedError(
                    "a closed CipherScope session cannot be re-entered"
                )
            if self._state != "created":
                raise SessionLifecycleError("the CipherScope session is already active")
            active = _ACTIVE_SESSION.get()
            if active is not None:
                raise AlreadyTracedError(
                    "another CipherScope session is already active in this context"
                )
            self._state = "active"
            self._token = _ACTIVE_SESSION.set(self)
        try:
            if self._initial_context is not None:
                proxy = self.attach(self._initial_context)
                with self._lock:
                    self._scoped_ids.add(self._native_identity(proxy))
            return self
        except BaseException:
            self._abort_enter()
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Literal[False]:
        del exc_type, traceback
        self.close(status="failed" if exc is not None else "completed")
        return False

    def close(self, *, status: str = "completed") -> None:
        """Close the active session and release native-context ownership.

        The status is accepted for lifecycle symmetry; callers choose the status
        emitted later by :meth:`to_trace`.
        """

        del status
        with self._lock:
            if self._state == "created":
                raise SessionLifecycleError(
                    "a session must be entered before it can close"
                )
            if self._state == "closed":
                raise SessionClosedError("the CipherScope session is already closed")
            self._state = "closed"
            owned_ids = tuple(self._owned_ids)
            self._scoped_ids.clear()
            token = self._token
            self._token = None
        with _OWNERS_LOCK:
            for identity in owned_ids:
                ownership = _OWNERS.get(identity)
                if ownership is not None and ownership.session is self:
                    del _OWNERS[identity]
        if token is not None:
            _ACTIVE_SESSION.reset(token)

    def attach(self, native_context: Any) -> TracedCryptoContext[Any, Any]:
        """Attach one native context, idempotently within this active session."""

        self._require_active()
        if isinstance(native_context, TracedCryptoContext):
            if native_context.belongs_to(self):
                return native_context
            raise AlreadyTracedError(
                "the supplied proxy belongs to a different or closed session"
            )

        identity = id(native_context)
        with self._lock:
            existing = self._proxies.get(identity)
            if existing is not None and existing._context is native_context:
                self._current_context = existing
                return existing

            with _OWNERS_LOCK:
                ownership = _OWNERS.get(identity)
                if ownership is not None and ownership.native_context is native_context:
                    if ownership.session is not self:
                        raise AlreadyTracedError(
                            "the native context is already attached to another session"
                        )
                _OWNERS[identity] = _Ownership(native_context, self)

            proxy: TracedCryptoContext[Any, Any] = TracedCryptoContext(
                native_context, self
            )
            self._proxies[identity] = proxy
            self._owned_ids.add(identity)
            self._current_context = proxy
            self.recorder.register_backend(native_context)
            if self._context_metadata is None:
                self._context_metadata = self.compatibility.snapshot_context(
                    native_context
                )
            return proxy

    def annotate(
        self,
        ciphertext: Any,
        *,
        shape: Any = None,
        packing: str | None = None,
        meaningful_slots: int | None = None,
        provenance: str | None = None,
    ) -> Any:
        """Attach a user assertion to a ciphertext and record it as evidence.

        The ciphertext is returned unchanged so the annotation can wrap a value
        inline. Annotations are run-local claims; they never authorize logging
        the underlying value.
        """

        self._require_active()
        annotation: dict[str, Any] = {}
        if shape is not None:
            if not isinstance(shape, (list, tuple)) or any(
                not isinstance(item, int) or isinstance(item, bool) or item < 0
                for item in shape
            ):
                raise AnnotationError(
                    "shape must be a sequence of non-negative integers"
                )
            annotation["shape"] = [int(item) for item in shape]
        if packing is not None:
            if not isinstance(packing, str) or not packing:
                raise AnnotationError("packing must be a non-empty string")
            annotation["packing"] = packing
        if meaningful_slots is not None:
            if (
                not isinstance(meaningful_slots, int)
                or isinstance(meaningful_slots, bool)
                or meaningful_slots < 0
            ):
                raise AnnotationError("meaningful_slots must be a non-negative integer")
            annotation["meaningful_slots"] = meaningful_slots
        if provenance is not None:
            if not isinstance(provenance, str) or not provenance:
                raise AnnotationError("provenance must be a non-empty string")
            annotation["provenance"] = provenance
        if not annotation:
            raise AnnotationError("at least one annotation field is required")

        observation = self.recorder.registry.annotate(ciphertext, annotation)
        self._record_meta_event(
            kind="annotation",
            operation="Annotate",
            input_ids=[observation.trace_id],
            input_states=[observation.event_state()],
            operand_kinds=["ciphertext"],
            semantic_arguments=annotation,
        )
        return ciphertext

    def checkpoint(
        self,
        name: str,
        *,
        ciphertext: Any,
        expected: Any,
        decoder: Any = None,
    ) -> dict[str, Any]:
        """Record aggregate precision metrics for one shadow-mode checkpoint.

        Requires explicitly enabled shadow mode and a secret key. The secret key
        and expected values are used only to compute aggregate metrics and are
        never serialized into the trace.
        """

        self._require_active()
        if not self.shadow_mode:
            raise ShadowModeError(
                "precision checkpoints require a session created with shadow_mode=True"
            )
        if self._secret_key is None:
            raise ShadowModeError("shadow-mode checkpoints require a secret_key")
        if not isinstance(name, str) or not name:
            raise AnnotationError("checkpoint name must be a non-empty string")

        expected_list = list(expected)
        observation = self.recorder.registry.observe_input(ciphertext)
        native = self.context._context
        plaintext = native.Decrypt(ciphertext, self._secret_key)
        if decoder is not None:
            observed = list(decoder(plaintext))
        else:
            observed = decode_real(plaintext, len(expected_list))
        metrics = precision_metrics(expected_list, observed)
        # Only aggregate metrics and the checkpoint name survive; the decoded and
        # expected values are dropped as soon as this call returns.
        del observed, expected_list, plaintext
        semantic_arguments = {"checkpoint_name": name, "metrics": metrics}
        self._record_meta_event(
            kind="checkpoint",
            operation="PrecisionCheckpoint",
            input_ids=[observation.trace_id],
            input_states=[observation.event_state()],
            operand_kinds=["ciphertext"],
            semantic_arguments=semantic_arguments,
        )
        return metrics

    def annotate_plaintext(
        self,
        plaintext: Any,
        *,
        provenance: str,
        constant_id: str | None = None,
    ) -> Any:
        """Record a run-local plaintext provenance assertion.

        The plaintext object stays opaque; only the user-supplied provenance and
        optional ``constant_id`` are recorded. ``constant_id`` is a path-redacted
        run-local label and never authorizes logging the plaintext value.
        """

        del plaintext
        self._require_active()
        if not isinstance(provenance, str) or not provenance:
            raise AnnotationError("provenance must be a non-empty string")
        semantic_arguments: dict[str, Any] = {"provenance": provenance}
        if constant_id is not None:
            if not isinstance(constant_id, str) or not constant_id:
                raise AnnotationError("constant_id must be a non-empty string")
            semantic_arguments["constant_id"] = constant_id
        self._record_meta_event(
            kind="annotation",
            operation="AnnotatePlaintext",
            input_ids=[],
            input_states=[],
            operand_kinds=["plaintext"],
            semantic_arguments=semantic_arguments,
        )
        return None

    def region(
        self,
        name: str,
        *,
        operator: str,
        associative: bool = False,
        commutative: bool = False,
    ) -> "_Region":
        """Open a labeled span with explicit algebraic assertions.

        The assertions are the user's claim about the operation reduced inside
        the span; analyzers only propose a restructuring when the assertions make
        it plausible.
        """

        self._require_active()
        if not isinstance(name, str) or not name:
            raise AnnotationError("region name must be a non-empty string")
        if not isinstance(operator, str) or not operator:
            raise AnnotationError("region operator must be a non-empty string")
        return _Region(self, name, operator, bool(associative), bool(commutative))

    def _record_region(
        self,
        *,
        name: str,
        operator: str,
        associative: bool,
        commutative: bool,
        start_sequence: int,
        end_sequence: int,
    ) -> None:
        self.recorder.record_region(
            {
                "name": name,
                "operator": operator,
                "associative": associative,
                "commutative": commutative,
                "start_sequence": start_sequence,
                "end_sequence": end_sequence,
            }
        )

    def _record_meta_event(
        self,
        *,
        kind: str,
        operation: str,
        input_ids: list[str],
        input_states: list[dict[str, Any]],
        operand_kinds: list[str],
        semantic_arguments: dict[str, Any],
    ) -> None:
        sequence, event_id = self.recorder.next_identity()
        source = self.source_resolver.capture(operation)
        start_ns = time.perf_counter_ns()
        self.recorder.record_event(
            {
                "event_id": event_id,
                "sequence": sequence,
                "kind": kind,
                "operation": operation,
                "overload": None,
                "granularity": None,
                "status": "ok",
                "source": source.to_dict(),
                "input_ciphertexts": list(input_ids),
                "output_ciphertexts": [],
                "operand_kinds": list(operand_kinds),
                "timing": {
                    "start_ns": start_ns,
                    "wall_duration_ns": 0,
                    "process_cpu_duration_ns": 0,
                    "thread_cpu_duration_ns": None,
                },
                "input_states": list(input_states),
                "output_states": [],
                "semantic_arguments": semantic_arguments,
                "thread_id": threading.get_native_id(),
                "python_thread_id": threading.get_ident(),
                "missing": [],
            }
        )

    def to_trace(self, status: str = "completed") -> dict[str, Any]:
        """Return ``{schema_version, run, context, events, ciphertexts}``.

        This is an in-memory operation; output writing intentionally belongs to a
        later exporter layer.
        """

        with self._lock:
            if self._state == "created":
                raise SessionLifecycleError(
                    "the session must be entered before a trace can be produced"
                )
            context = dict(self._context_metadata or {})
        return self.recorder.to_trace(context=context, status=status)

    def _require_active(self) -> None:
        with self._lock:
            if self._state == "closed":
                raise SessionClosedError("the owning CipherScope session is closed")
            if self._state != "active":
                raise SessionLifecycleError("the CipherScope session is not active")

    def _enter_context_scope(
        self, native_context: Any
    ) -> tuple[TracedCryptoContext[Any, Any] | None, int]:
        self._require_active()
        raw_context = (
            native_context._context
            if isinstance(native_context, TracedCryptoContext)
            else native_context
        )
        identity = id(raw_context)
        with self._lock:
            if identity in self._scoped_ids:
                raise AlreadyTracedError(
                    "this native context already has an active trace scope"
                )
            previous = self._current_context
            proxy = self.attach(native_context)
            self._scoped_ids.add(identity)
            self._current_context = proxy
            return previous, identity

    def _exit_context_scope(
        self,
        previous: TracedCryptoContext[Any, Any] | None,
        identity: int,
    ) -> None:
        with self._lock:
            self._scoped_ids.discard(identity)
            self._current_context = previous

    @staticmethod
    def _native_identity(proxy: TracedCryptoContext[Any, Any]) -> int:
        return id(proxy._context)

    def _abort_enter(self) -> None:
        with self._lock:
            owned_ids = tuple(self._owned_ids)
            token = self._token
            self._token = None
            self._state = "created"
        with _OWNERS_LOCK:
            for identity in owned_ids:
                ownership = _OWNERS.get(identity)
                if ownership is not None and ownership.session is self:
                    del _OWNERS[identity]
        if token is not None:
            _ACTIVE_SESSION.reset(token)


class _Region(ContextManager["Session[Any]"]):
    """Record the event-sequence span covered by a labeled reduction region."""

    def __init__(
        self,
        session: Session[Any],
        name: str,
        operator: str,
        associative: bool,
        commutative: bool,
    ) -> None:
        self._session = session
        self._name = name
        self._operator = operator
        self._associative = associative
        self._commutative = commutative
        self._start_sequence: int | None = None
        self._entered = False

    def __enter__(self) -> Session[Any]:
        if self._entered:
            raise SessionLifecycleError("a region cannot be re-entered")
        self._session._require_active()
        self._start_sequence = self._session.recorder.peek_sequence()
        self._entered = True
        return self._session

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Literal[False]:
        del exc_type, exc, traceback
        if not self._entered or self._start_sequence is None:
            raise SessionLifecycleError("the region was not entered")
        end_sequence = self._session.recorder.peek_sequence() - 1
        self._session._record_region(
            name=self._name,
            operator=self._operator,
            associative=self._associative,
            commutative=self._commutative,
            start_sequence=self._start_sequence,
            end_sequence=end_sequence,
        )
        self._entered = False
        return False


class _ContextScope(ContextManager[Session[Any]]):
    """Join an active run without finalizing it when the local scope exits."""

    def __init__(self, session: Session[Any], native_context: Any) -> None:
        self._session = session
        self._native_context = native_context
        self._previous: TracedCryptoContext[Any, Any] | None = None
        self._identity: int | None = None
        self._entered = False

    def __enter__(self) -> Session[Any]:
        if self._entered:
            raise SessionLifecycleError("a trace context scope cannot be re-entered")
        self._previous, self._identity = self._session._enter_context_scope(
            self._native_context
        )
        self._entered = True
        return self._session

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Literal[False]:
        del exc_type, exc, traceback
        if not self._entered or self._identity is None:
            raise SessionLifecycleError("the trace context scope was not entered")
        self._session._exit_context_scope(self._previous, self._identity)
        self._entered = False
        return False


def trace(
    native_context: ContextT,
    *,
    name: str | None = None,
    strict: bool = True,
    compatibility: CompatibilityRegistry | None = None,
    secret_key: Any = None,
    shadow_mode: bool = False,
) -> Session[ContextT] | _ContextScope:
    """Create a top-level session or join the session active in this context."""

    active = _ACTIVE_SESSION.get()
    if active is None:
        return Session(
            native_context,
            name=name,
            strict=strict,
            compatibility=compatibility,
            secret_key=secret_key,
            shadow_mode=shadow_mode,
        )
    return _ContextScope(active, native_context)


def attach(native_context: ContextT) -> TracedCryptoContext[ContextT, Any]:
    """Attach to the active session, or fail with :class:`NoActiveSessionError`."""

    active = _ACTIVE_SESSION.get()
    if active is None:
        raise NoActiveSessionError(
            "cipherscope.attach() requires an active Session or trace() scope"
        )
    return active.attach(native_context)


def runner_session(
    *,
    name: str | None = None,
    strict: bool = True,
    compatibility: CompatibilityRegistry | None = None,
) -> Session[Any]:
    """Create a context-free session for a runner to activate.

    While the returned session is active, target code may call :func:`attach` or
    use :func:`trace` to join the runner-owned run. Closing a joined ``trace``
    scope never closes this top-level session.
    """

    return Session(name=name, strict=strict, compatibility=compatibility)
