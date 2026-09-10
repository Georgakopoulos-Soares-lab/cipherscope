"""OpenFHE-shaped tracing proxy for CipherScope's covered operations."""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Generic, Mapping, TypeVar, cast

from .errors import UnsupportedOperationError

if TYPE_CHECKING:
    from .session import Session


ContextT = TypeVar("ContextT")
CiphertextT = TypeVar("CiphertextT")


class TracedCryptoContext(Generic[ContextT, CiphertextT]):
    """Proxy a native context while tracing explicit semantic operations."""

    def __init__(self, context: ContextT, session: "Session[Any]") -> None:
        self._context = context
        self._session = session

    @property
    def session(self) -> "Session[Any]":
        """Return the owning session without exposing the native context."""

        return self._session

    def belongs_to(self, session: "Session[Any]") -> bool:
        """Test proxy ownership by identity."""

        return self._session is session

    def Encrypt(
        self, public_key: Any, plaintext: Any, *args: Any, **kwargs: Any
    ) -> CiphertextT:
        """Encrypt through the native context and register the fresh ciphertext."""

        return cast(
            CiphertextT,
            self._record_covered("Encrypt", (public_key, plaintext, *args), kwargs),
        )

    def Decrypt(
        self, ciphertext: Any, private_key: Any, *args: Any, **kwargs: Any
    ) -> Any:
        """Decrypt through the native context and record the call."""

        return self._record_covered("Decrypt", (ciphertext, private_key, *args), kwargs)

    def EvalAdd(self, left: Any, right: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalAdd", (left, right, *args), kwargs),
        )

    def EvalAddInPlace(self, left: Any, right: Any, *args: Any, **kwargs: Any) -> Any:
        """Trace the binding's declared first-operand mutation exactly once."""

        return self._record_covered("EvalAddInPlace", (left, right, *args), kwargs)

    def EvalSub(self, left: Any, right: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalSub", (left, right, *args), kwargs),
        )

    def EvalSubInPlace(self, left: Any, right: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("EvalSubInPlace", (left, right, *args), kwargs)

    def EvalMult(self, left: Any, right: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalMult", (left, right, *args), kwargs),
        )

    def EvalMultNoRelin(
        self, left: Any, right: Any, *args: Any, **kwargs: Any
    ) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalMultNoRelin", (left, right, *args), kwargs),
        )

    def EvalSquare(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalSquare", (ciphertext, *args), kwargs),
        )

    def EvalSquareInPlace(self, ciphertext: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("EvalSquareInPlace", (ciphertext, *args), kwargs)

    def Relinearize(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("Relinearize", (ciphertext, *args), kwargs),
        )

    def RelinearizeInPlace(self, ciphertext: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("RelinearizeInPlace", (ciphertext, *args), kwargs)

    def EvalNegate(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalNegate", (ciphertext, *args), kwargs),
        )

    def EvalNegateInPlace(self, ciphertext: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("EvalNegateInPlace", (ciphertext, *args), kwargs)

    def ModReduce(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("ModReduce", (ciphertext, *args), kwargs),
        )

    def ModReduceInPlace(self, ciphertext: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("ModReduceInPlace", (ciphertext, *args), kwargs)

    def Rescale(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("Rescale", (ciphertext, *args), kwargs),
        )

    def RescaleInPlace(self, ciphertext: Any, *args: Any, **kwargs: Any) -> Any:
        return self._record_covered("RescaleInPlace", (ciphertext, *args), kwargs)

    def EvalRotate(
        self, ciphertext: Any, index: int, *args: Any, **kwargs: Any
    ) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalRotate", (ciphertext, index, *args), kwargs),
        )

    def EvalRotateKeyGen(
        self, private_key: Any, indices: Any, *args: Any, **kwargs: Any
    ) -> Any:
        return self._record_covered(
            "EvalRotateKeyGen", (private_key, indices, *args), kwargs
        )

    def EvalBootstrap(self, ciphertext: Any, *args: Any, **kwargs: Any) -> CiphertextT:
        return cast(
            CiphertextT,
            self._record_covered("EvalBootstrap", (ciphertext, *args), kwargs),
        )

    def __getattr__(self, name: str) -> Any:
        """Forward non-semantic attributes according to the coverage policy."""

        self._session._require_active()
        attribute = getattr(self._context, name)
        if not callable(attribute):
            return attribute

        classification = self._session.compatibility.classify_callable(name)
        if classification == "traced":
            # Covered methods are normally found on the class. This path
            # also keeps subclass/dynamic method lookup within the same contract.
            def traced(*args: Any, **kwargs: Any) -> Any:
                return self._record_covered(name, args, kwargs)

            return traced

        if classification == "allowed":

            def allowed(*args: Any, **kwargs: Any) -> Any:
                self._session._require_active()
                self._session.recorder.count_allowed_passthrough()
                return attribute(*args, **kwargs)

            return allowed

        if self._session.strict:
            self._session.recorder.count_rejected_unclassified()
            raise UnsupportedOperationError(
                f"native callable {name!r} is not covered by this CipherScope version"
            )

        def permissive(*args: Any, **kwargs: Any) -> Any:
            self._session._require_active()
            self._session.recorder.count_unclassified_passthrough()
            return attribute(*args, **kwargs)

        return permissive

    def _record_covered(
        self,
        operation: str,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> Any:
        self._session._require_active()
        recorder = self._session.recorder
        compatibility = self._session.compatibility
        spec = compatibility.operation(operation)
        if spec is None:
            raise UnsupportedOperationError(f"operation {operation!r} is not covered")

        sequence, event_id = recorder.next_identity()
        source = self._session.source_resolver.capture(operation)
        operand_kinds = compatibility.operand_kinds_for(operation, args, kwargs)
        overload = compatibility.overload_for(operation, args, kwargs)
        semantic_arguments = compatibility.semantic_arguments(operation, args, kwargs)
        argument_representations = [repr(value) for value in args]
        keyword_argument_representations = {
            name: repr(value) for name, value in sorted(kwargs.items())
        }

        # This complete input observation phase intentionally precedes every timer.
        input_objects = self._unique_identities(
            compatibility.input_ciphertexts_for(spec, args, kwargs)
        )
        input_observations = []
        for value in input_objects:
            metadata = compatibility.snapshot_ciphertext(value)
            input_observations.append(
                recorder.registry.observe_input(value, metadata=metadata)
            )
        input_ids = [item.trace_id for item in input_observations]
        input_states = [item.event_state() for item in input_observations]
        input_missing = [
            f"input[{index}].{field}"
            for index, item in enumerate(input_observations)
            for field in item.metadata.missing_fields
        ]

        start_ns = time.perf_counter_ns()
        process_start_ns = time.process_time_ns()
        thread_clock = getattr(time, "thread_time_ns", None)
        thread_start_ns = thread_clock() if callable(thread_clock) else None

        output: Any = None
        try:
            try:
                native_method = getattr(self._context, operation)
                # The bound native method is invoked at exactly this one site.
                output = native_method(*args, **dict(kwargs))
            finally:
                wall_duration_ns = time.perf_counter_ns() - start_ns
                process_cpu_duration_ns = time.process_time_ns() - process_start_ns
                thread_cpu_duration_ns = (
                    thread_clock() - thread_start_ns
                    if callable(thread_clock) and thread_start_ns is not None
                    else None
                )
        except BaseException as error:
            recorder.record_event(
                self._event(
                    event_id=event_id,
                    sequence=sequence,
                    operation=operation,
                    kind=spec.event_kind,
                    overload=overload,
                    granularity=spec.granularity,
                    status="error",
                    source=source.to_dict(),
                    input_ids=input_ids,
                    output_ids=[],
                    operand_kinds=operand_kinds,
                    start_ns=start_ns,
                    wall_duration_ns=wall_duration_ns,
                    process_cpu_duration_ns=process_cpu_duration_ns,
                    thread_cpu_duration_ns=thread_cpu_duration_ns,
                    input_states=input_states,
                    output_states=[],
                    semantic_arguments=semantic_arguments,
                    argument_representations=argument_representations,
                    keyword_argument_representations=keyword_argument_representations,
                    missing=input_missing,
                    error_class=type(error).__name__,
                    error_message=str(error),
                )
            )
            raise

        mutated_objects = input_objects[: spec.mutated_ciphertext_count]
        observed_output_objects = self._unique_identities(
            [
                *mutated_objects,
                *(
                    compatibility.collect_ciphertexts(output)
                    if spec.has_ciphertext_output
                    else []
                ),
            ]
        )
        output_observations = []
        for value in observed_output_objects:
            metadata = compatibility.snapshot_ciphertext(value)
            output_observations.append(
                recorder.registry.observe_output(
                    value,
                    event_id=event_id,
                    parent_ids=input_ids,
                    metadata=metadata,
                )
            )
        output_ids = [item.trace_id for item in output_observations]
        output_states = [item.event_state() for item in output_observations]
        output_missing = [
            f"output[{index}].{field}"
            for index, item in enumerate(output_observations)
            for field in item.metadata.missing_fields
        ]
        recorder.record_event(
            self._event(
                event_id=event_id,
                sequence=sequence,
                operation=operation,
                kind=spec.event_kind,
                overload=overload,
                granularity=spec.granularity,
                status="ok",
                source=source.to_dict(),
                input_ids=input_ids,
                output_ids=output_ids,
                operand_kinds=operand_kinds,
                start_ns=start_ns,
                wall_duration_ns=wall_duration_ns,
                process_cpu_duration_ns=process_cpu_duration_ns,
                thread_cpu_duration_ns=thread_cpu_duration_ns,
                input_states=input_states,
                output_states=output_states,
                semantic_arguments=semantic_arguments,
                argument_representations=argument_representations,
                keyword_argument_representations=keyword_argument_representations,
                output_representation=repr(output),
                missing=[*input_missing, *output_missing],
            )
        )
        return output

    @staticmethod
    def _unique_identities(values: list[Any]) -> list[Any]:
        """Deduplicate aliases without equality, hashing, or representation calls."""

        unique: list[Any] = []
        seen: dict[int, Any] = {}
        for value in values:
            identity = id(value)
            previous = seen.get(identity)
            if previous is value:
                continue
            seen[identity] = value
            unique.append(value)
        return unique

    @staticmethod
    def _event(
        *,
        event_id: str,
        sequence: int,
        operation: str,
        kind: str,
        overload: str,
        granularity: str,
        status: str,
        source: dict[str, Any],
        input_ids: list[str],
        output_ids: list[str],
        operand_kinds: list[str],
        start_ns: int,
        wall_duration_ns: int,
        process_cpu_duration_ns: int,
        thread_cpu_duration_ns: int | None,
        input_states: list[dict[str, Any]],
        output_states: list[dict[str, Any]],
        semantic_arguments: dict[str, Any],
        argument_representations: list[str],
        keyword_argument_representations: dict[str, str],
        missing: list[str],
        error_class: str | None = None,
        error_message: str | None = None,
        output_representation: str | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_id": event_id,
            "sequence": sequence,
            "kind": kind,
            "operation": operation,
            "overload": overload,
            "granularity": granularity,
            "status": status,
            "source": source,
            "input_ciphertexts": input_ids,
            "output_ciphertexts": output_ids,
            "operand_kinds": operand_kinds,
            "timing": {
                "start_ns": start_ns,
                "wall_duration_ns": max(0, wall_duration_ns),
                "process_cpu_duration_ns": max(0, process_cpu_duration_ns),
                "thread_cpu_duration_ns": (
                    max(0, thread_cpu_duration_ns)
                    if thread_cpu_duration_ns is not None
                    else None
                ),
            },
            "input_states": input_states,
            "output_states": output_states,
            "semantic_arguments": semantic_arguments,
            "argument_representations": argument_representations,
            "keyword_argument_representations": keyword_argument_representations,
            "thread_id": threading.get_native_id(),
            "python_thread_id": threading.get_ident(),
            "missing": missing,
        }
        if error_class is not None:
            event["error_class"] = error_class
        if error_message is not None:
            event["error_message"] = error_message
        if output_representation is not None:
            event["output_representation"] = output_representation
        return event
