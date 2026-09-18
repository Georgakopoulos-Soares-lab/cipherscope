"""Session lifecycle, trace scopes, and active-session attachment."""

from __future__ import annotations

import contextvars
import math
import sys
import threading
import time
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Generic, Literal, TypeVar

from .compatibility import DEFAULT_COMPATIBILITY, CompatibilityRegistry, available_slots_for
from .context import TracedCryptoContext
from .errors import (
    AlreadyTracedError,
    AnnotationError,
    NoActiveSessionError,
    SessionClosedError,
    SessionLifecycleError,
    ShadowModeError,
)
from . import operators
from .recorder import EventRecorder
from .source import SourceResolver

ContextT = TypeVar("ContextT")


def _real_values(values: Any) -> list[float]:
    """Convert decoded CKKS values to JSON numbers."""

    return [
        float(value.real if isinstance(value, complex) else value) for value in values
    ]


def _decode_real(plaintext: Any, length: int) -> list[float]:
    """Read real packed values from an OpenFHE plaintext."""

    set_length = getattr(plaintext, "SetLength", None)
    if callable(set_length):
        set_length(length)
    for getter_name in ("GetRealPackedValue", "GetCKKSPackedValue"):
        getter = getattr(plaintext, getter_name, None)
        if callable(getter):
            return _real_values(list(getter())[:length])
    raise TypeError("the plaintext exposes no supported packed-value getter")


TOLERANCE_KEYS = ("absolute", "relative", "min_bits")


def _tolerance_contract(tolerance: Any) -> dict[str, float] | None:
    """Validate a checkpoint tolerance: absolute and/or relative error, or a bits floor."""

    if tolerance is None:
        return None
    if not isinstance(tolerance, Mapping) or not tolerance:
        raise AnnotationError(
            "tolerance must be a non-empty mapping with absolute, relative, or min_bits"
        )
    contract: dict[str, float] = {}
    for key, value in tolerance.items():
        if key not in TOLERANCE_KEYS:
            raise AnnotationError(f"unknown tolerance key {key!r}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise AnnotationError(f"tolerance {key} must be a number")
        if not math.isfinite(value) or value < 0:
            raise AnnotationError(f"tolerance {key} must be finite and non-negative")
        contract[key] = float(value)
    return contract


def _precision_metrics(
    expected: list[float], observed: list[float], contract: dict[str, float] | None
) -> dict[str, Any]:
    """Compare a checkpoint with its expectation and, if declared, its tolerance."""

    errors = [abs(actual - wanted) for wanted, actual in zip(expected, observed)]
    max_abs_error = max(errors, default=0.0)
    max_rel_error = max(
        (
            error / max(abs(wanted), sys.float_info.epsilon)
            for wanted, error in zip(expected, errors)
        ),
        default=0.0,
    )
    absolute_bits = -math.log2(max(max_abs_error, sys.float_info.epsilon))
    metrics: dict[str, Any] = {
        "max_abs_error": max_abs_error,
        "max_rel_error": max_rel_error,
        "absolute_bits": absolute_bits,
        "tolerance_status": "undeclared",
    }
    if contract is None:
        return metrics
    violated: list[str] = []
    if "absolute" in contract and max_abs_error > contract["absolute"]:
        violated.append("absolute")
    if "relative" in contract and max_rel_error > contract["relative"]:
        violated.append("relative")
    if "min_bits" in contract and absolute_bits < contract["min_bits"]:
        violated.append("min_bits")
    metrics["tolerance"] = dict(contract)
    metrics["tolerance_status"] = "violated" if violated else "within"
    metrics["violated"] = violated
    return metrics


@dataclass
class _Ownership:
    native_context: Any
    session: Session[Any]


_OWNERS: dict[int, _Ownership] = {}
_OWNERS_LOCK = threading.RLock()


def _merge_declared_parameters(metadata: dict[str, Any], declared: Mapping[str, Any]) -> None:
    """Fold CCParams facts into the context block; the scheme decides the slot capacity."""

    metadata.update(declared)
    scheme = metadata.get("scheme")
    if isinstance(scheme, str):
        metadata["available_slots"] = available_slots_for(scheme, metadata.get("ring_dimension"))


def _session_for_ciphertext(ciphertext: Any) -> Session[Any] | None:
    """The active session that attached this ciphertext's crypto context, if any.

    Used by the operator hooks: ``ct.GetCryptoContext()`` returns the very
    object the application attached, so ownership is an identity lookup.
    """

    getter = getattr(ciphertext, "GetCryptoContext", None)
    if not callable(getter):
        return None
    try:
        native_context = getter()
    except Exception:  # noqa: BLE001 - never let a metadata read break arithmetic
        return None
    with _OWNERS_LOCK:
        ownership = _OWNERS.get(id(native_context))
    if ownership is None or ownership.native_context is not native_context:
        return None
    session = ownership.session
    return session if session.state == "active" and session.recorder.accepting else None


operators.set_session_resolver(_session_for_ciphertext)
_ACTIVE_SESSION: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "cipherscope_active_session", default=None
)


class Session(Generic[ContextT]):
    """Own one trace run and all proxies attached during that run.

    A session moves from ``created`` to ``active`` to ``closed``. It cannot be
    entered again after it closes, and its proxies stop accepting calls.
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
        allow_testing_security: bool = False,
        max_events: int | None = None,
        max_trace_bytes: int | None = None,
        spool_dir: Any = None,
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
            allow_testing_security=allow_testing_security,
            max_events=max_events,
            max_trace_bytes=max_trace_bytes,
            spool_dir=spool_dir,
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
        self._declared_parameters: dict[str, Any] | None = None
        self._pending_parameters: Any = None
        self._hooked_ciphertext_types: list[type] = []
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
        """Return whether the session has an attached context."""

        with self._lock:
            return bool(self._proxies)

    def __enter__(self) -> Session[ContextT]:
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
            if self._pending_parameters is not None:
                self.declare_parameters(self._pending_parameters)
                self._pending_parameters = None
            return self
        except BaseException:
            self._abort_enter()
            raise

    def with_parameters(self, parameters: Any) -> Session[ContextT]:
        """Declare CCParams once the session is entered; returns self for chaining."""

        self._pending_parameters = parameters
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_type, traceback
        self.close(status="failed" if exc is not None else "completed")
        return False

    def close(self, *, status: str = "completed") -> None:
        """Close the session and release its attached native contexts.

        ``status`` remains accepted for API compatibility. :meth:`to_trace`
        chooses the status written to the trace.
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
            hooked = tuple(self._hooked_ciphertext_types)
            self._hooked_ciphertext_types.clear()
        for ciphertext_type in hooked:
            operators.uninstall(ciphertext_type)
        with _OWNERS_LOCK:
            for identity in owned_ids:
                ownership = _OWNERS.get(identity)
                if ownership is not None and ownership.session is self:
                    del _OWNERS[identity]
        if token is not None:
            _ACTIVE_SESSION.reset(token)

    def declare_parameters(self, parameters: Any) -> None:
        """Record CCParams fields (security level, ring size) the context cannot expose."""

        self._require_active()
        snapshot = self.compatibility.snapshot_parameters(parameters)
        with self._lock:
            self._declared_parameters = snapshot
            if self._context_metadata is not None:
                _merge_declared_parameters(self._context_metadata, snapshot)

    def attach(
        self, native_context: Any, *, parameters: Any = None
    ) -> TracedCryptoContext[Any, Any]:
        """Attach a context, or return its existing proxy if already attached."""

        proxy = self._attach(native_context)
        if parameters is not None:
            self.declare_parameters(parameters)
        return proxy

    def _attach(self, native_context: Any) -> TracedCryptoContext[Any, Any]:
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
                if (
                    ownership is not None
                    and ownership.native_context is native_context
                    and ownership.session is not self
                ):
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
            self._hook_operators_for(native_context)
            if self._context_metadata is None:
                self._context_metadata = self.compatibility.snapshot_context(
                    native_context
                )
                if self._declared_parameters is not None:
                    _merge_declared_parameters(self._context_metadata, self._declared_parameters)
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
        """Attach a user assertion and return the ciphertext unchanged."""

        self._require_active()
        if not self.recorder.accepting:
            self.recorder.count_dropped_call()
            return ciphertext
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
            input_ciphertext_ids=[observation.ciphertext_id],
            input_states=[observation.event_state()],
            operand_kinds=["ciphertext"],
            semantic_arguments=annotation,
        )
        return ciphertext

    def enable_shadow_mode(self, secret_key: Any) -> None:
        """Turn on precision checkpoints for a session that started without them."""

        if secret_key is None:
            raise ShadowModeError("shadow mode requires a secret_key")
        with self._lock:
            self.shadow_mode = True
            self.recorder.shadow_mode = True
            self._secret_key = secret_key

    def checkpoint(
        self,
        name: str,
        *,
        ciphertext: Any,
        expected: Any,
        decoder: Any = None,
        tolerance: Any = None,
    ) -> dict[str, Any]:
        """Decrypt a checkpoint and record its expected and observed values."""

        self._require_active()
        if not self.shadow_mode:
            raise ShadowModeError(
                "precision checkpoints require a session created with shadow_mode=True"
            )
        if self._secret_key is None:
            raise ShadowModeError("precision checkpoints require a secret_key")
        if not isinstance(name, str) or not name:
            raise AnnotationError("checkpoint name must be a non-empty string")
        contract = _tolerance_contract(tolerance)
        if not self.recorder.accepting:
            self.recorder.count_dropped_call()
            return {"status": "dropped", "reason": "trace_truncated"}

        expected_values = _real_values(expected)
        observation = self.recorder.registry.observe_input(ciphertext)
        native = self.context._context
        plaintext = native.Decrypt(ciphertext, self._secret_key)
        if decoder is not None:
            observed_values = _real_values(decoder(plaintext))
        else:
            observed_values = _decode_real(plaintext, len(expected_values))
        comparison = {
            "status": (
                "ok"
                if expected_values and len(expected_values) == len(observed_values)
                else "failed"
            ),
            "expected_values": expected_values,
            "observed_values": observed_values,
        }
        if comparison["status"] == "failed":
            comparison["reason"] = "shape_mismatch"
        else:
            comparison.update(_precision_metrics(expected_values, observed_values, contract))
        semantic_arguments = {"checkpoint_name": name, **comparison}
        self._record_meta_event(
            kind="checkpoint",
            operation="PrecisionCheckpoint",
            input_ciphertext_ids=[observation.ciphertext_id],
            input_states=[observation.event_state()],
            operand_kinds=["ciphertext"],
            semantic_arguments=semantic_arguments,
        )
        return comparison

    def annotate_plaintext(
        self,
        plaintext: Any,
        *,
        provenance: str,
        constant_id: str | None = None,
    ) -> Any:
        """Record a plaintext representation and its declared provenance."""

        self._require_active()
        if not self.recorder.accepting:
            self.recorder.count_dropped_call()
            return plaintext
        if not isinstance(provenance, str) or not provenance:
            raise AnnotationError("provenance must be a non-empty string")
        semantic_arguments: dict[str, Any] = {
            "provenance": provenance,
            "plaintext_representation": repr(plaintext),
        }
        if constant_id is not None:
            if not isinstance(constant_id, str) or not constant_id:
                raise AnnotationError("constant_id must be a non-empty string")
            semantic_arguments["constant_id"] = constant_id
        self._record_meta_event(
            kind="annotation",
            operation="AnnotatePlaintext",
            input_ciphertext_ids=[],
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
    ) -> _Region:
        """Mark a named group of events and its algebraic properties.

        The serial-reduction analyzer uses these user-provided properties before
        suggesting a different evaluation order.
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
        if not self.recorder.accepting:
            self.recorder.count_dropped_call()
            return
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
        input_ciphertext_ids: list[str],
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
                "input_ciphertexts": list(input_ciphertext_ids),
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
        """Build and return the session's trace.

        This method does not write any files.
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

    def _hook_operators_for(self, native_context: Any) -> None:
        """Route the binding's ciphertext operators through this session's proxy.

        The ciphertext type is the one the attached context's binding module
        exports (``openfhe.Ciphertext``); a context from another module (the
        fake backend, a test double) is looked up by the same rule and simply
        has no operators to wrap. The flag is set only when at least one
        operator was actually rerouted, so it is evidence, not a promise.
        """

        module = sys.modules.get(type(native_context).__module__)
        candidates: list[type] = []
        for attribute in ("Ciphertext",):
            candidate = getattr(module, attribute, None) if module is not None else None
            if isinstance(candidate, type):
                candidates.append(candidate)
        # A binding whose Ciphertext lives in a submodule (openfhe.openfhe.Ciphertext).
        parent_name = type(native_context).__module__.rpartition(".")[0]
        parent = sys.modules.get(parent_name) if parent_name else None
        candidate = getattr(parent, "Ciphertext", None) if parent is not None else None
        if isinstance(candidate, type) and candidate not in candidates:
            candidates.append(candidate)
        for ciphertext_type in candidates:
            if ciphertext_type in self._hooked_ciphertext_types:
                continue
            if operators.install(ciphertext_type):
                self._hooked_ciphertext_types.append(ciphertext_type)
                self.recorder.operator_overload_coverage = True

    @staticmethod
    def _native_identity(proxy: TracedCryptoContext[Any, Any]) -> int:
        return id(proxy._context)

    def _abort_enter(self) -> None:
        with self._lock:
            owned_ids = tuple(self._owned_ids)
            token = self._token
            self._token = None
            self._state = "created"
            hooked = tuple(self._hooked_ciphertext_types)
            self._hooked_ciphertext_types.clear()
        for ciphertext_type in hooked:
            operators.uninstall(ciphertext_type)
        with _OWNERS_LOCK:
            for identity in owned_ids:
                ownership = _OWNERS.get(identity)
                if ownership is not None and ownership.session is self:
                    del _OWNERS[identity]
        if token is not None:
            _ACTIVE_SESSION.reset(token)


class _Region(AbstractContextManager["Session[Any]"]):
    """Record the events inside a named reduction region."""

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

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
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


class _ContextScope(AbstractContextManager[Session[Any]]):
    """Attach a context to the active session for one ``with`` block."""

    def __init__(
        self, session: Session[Any], native_context: Any, *, parameters: Any = None
    ) -> None:
        self._session = session
        self._native_context = native_context
        self._parameters = parameters
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
        if self._parameters is not None:
            self._session.declare_parameters(self._parameters)
        return self._session

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
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
    parameters: Any = None,
    allow_testing_security: bool = False,
    max_events: int | None = None,
    max_trace_bytes: int | None = None,
    spool_dir: Any = None,
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
            allow_testing_security=allow_testing_security,
            max_events=max_events,
            max_trace_bytes=max_trace_bytes,
            spool_dir=spool_dir,
        ).with_parameters(parameters)
    if shadow_mode and not active.shadow_mode:
        active.enable_shadow_mode(secret_key)
    if allow_testing_security:
        active.recorder.allow_testing_security = True
    return _ContextScope(active, native_context, parameters=parameters)


def attach(
    native_context: ContextT, *, parameters: Any = None
) -> TracedCryptoContext[ContextT, Any]:
    """Attach to the active session, or fail with :class:`NoActiveSessionError`."""

    active = _ACTIVE_SESSION.get()
    if active is None:
        raise NoActiveSessionError(
            "cipherscope.attach() requires an active Session or trace() scope"
        )
    return active.attach(native_context, parameters=parameters)


def runner_session(
    *,
    name: str | None = None,
    strict: bool = True,
    compatibility: CompatibilityRegistry | None = None,
    allow_testing_security: bool = False,
    max_events: int | None = None,
    max_trace_bytes: int | None = None,
    spool_dir: Any = None,
) -> Session[Any]:
    """Create a session that waits for target code to attach a context.

    Target code may call :func:`attach` or :func:`trace` while this session is
    active. Leaving that inner scope does not close the runner's session.
    """

    return Session(
        name=name,
        strict=strict,
        compatibility=compatibility,
        allow_testing_security=allow_testing_security,
        max_events=max_events,
        max_trace_bytes=max_trace_bytes,
        spool_dir=spool_dir,
    )
