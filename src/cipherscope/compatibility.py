"""Describe and inspect the supported OpenFHE API calls."""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .state import CiphertextMetadata


@dataclass(frozen=True)
class OperationSpec:
    """Tracing settings for one OpenFHE context method."""

    name: str
    default_overload: str
    granularity: str = "openfhe_api_inclusive"
    mutated_ciphertext_count: int = 0
    ciphertext_input_indices: tuple[int, ...] | None = None
    has_ciphertext_output: bool = True
    event_kind: str = "crypto_operation"


CORE_OPERATIONS: dict[str, OperationSpec] = {
    "Encrypt": OperationSpec("Encrypt", "key_plaintext", ciphertext_input_indices=()),
    "Decrypt": OperationSpec(
        "Decrypt",
        "ct_key",
        ciphertext_input_indices=(0,),
        has_ciphertext_output=False,
    ),
    "EvalAdd": OperationSpec("EvalAdd", "ct_ct"),
    "EvalAddInPlace": OperationSpec(
        "EvalAddInPlace", "ct_ct", mutated_ciphertext_count=1
    ),
    "EvalSub": OperationSpec("EvalSub", "ct_ct"),
    "EvalSubInPlace": OperationSpec(
        "EvalSubInPlace", "ct_ct", mutated_ciphertext_count=1
    ),
    "EvalMult": OperationSpec("EvalMult", "ct_ct"),
    "EvalMultNoRelin": OperationSpec("EvalMultNoRelin", "ct_ct"),
    "EvalSquare": OperationSpec("EvalSquare", "ct"),
    "EvalSquareInPlace": OperationSpec(
        "EvalSquareInPlace", "ct", mutated_ciphertext_count=1
    ),
    "Relinearize": OperationSpec("Relinearize", "ct"),
    "RelinearizeInPlace": OperationSpec(
        "RelinearizeInPlace", "ct", mutated_ciphertext_count=1
    ),
    "EvalNegate": OperationSpec("EvalNegate", "ct"),
    "EvalNegateInPlace": OperationSpec(
        "EvalNegateInPlace", "ct", mutated_ciphertext_count=1
    ),
    "ModReduce": OperationSpec("ModReduce", "ct"),
    "ModReduceInPlace": OperationSpec(
        "ModReduceInPlace", "ct", mutated_ciphertext_count=1
    ),
    "Rescale": OperationSpec("Rescale", "ct"),
    "RescaleInPlace": OperationSpec("RescaleInPlace", "ct", mutated_ciphertext_count=1),
    "EvalRotate": OperationSpec("EvalRotate", "ct_index"),
    "EvalRotateKeyGen": OperationSpec(
        "EvalRotateKeyGen",
        "key_indices",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="key_generation",
    ),
    "KeyGen": OperationSpec(
        "KeyGen",
        "none",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="key_generation",
    ),
    "EvalMultKeyGen": OperationSpec(
        "EvalMultKeyGen",
        "key",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="key_generation",
    ),
    "EvalSumKeyGen": OperationSpec(
        "EvalSumKeyGen",
        "key",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="key_generation",
    ),
    "EvalBootstrapSetup": OperationSpec(
        "EvalBootstrapSetup",
        "level_budget",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="setup",
    ),
    "EvalBootstrapKeyGen": OperationSpec(
        "EvalBootstrapKeyGen",
        "key_slots",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="key_generation",
    ),
    "MakeCKKSPackedPlaintext": OperationSpec(
        "MakeCKKSPackedPlaintext",
        "values",
        ciphertext_input_indices=(),
        has_ciphertext_output=False,
        event_kind="setup",
    ),
    "EvalChebyshevFunction": OperationSpec(
        "EvalChebyshevFunction", "function_ct_bounds_degree"
    ),
    "EvalInnerProduct": OperationSpec("EvalInnerProduct", "ct_ct_size"),
    "EvalSum": OperationSpec("EvalSum", "ct_batch"),
    "EvalBootstrap": OperationSpec("EvalBootstrap", "ct"),
}


class CompatibilityRegistry:
    """Classify calls and read supported fields from OpenFHE objects.

    Applications can provide an explicit ``ciphertext_type`` or predicate. The
    default check looks for the level and noise-scale getters.
    """

    def __init__(
        self,
        *,
        ciphertext_type: type[Any] | tuple[type[Any], ...] | None = None,
        ciphertext_predicate: Callable[[Any], bool] | None = None,
        allowed_nonsemantic_calls: Iterable[str] = (
            "Enable",
            "GetBatchSize",
            "GetCyclotomicOrder",
            "GetKeySwitchTechnique",
            "GetMultiplicativeDepth",
            "GetRingDimension",
            "GetScalingTechnique",
        ),
        compatibility_target: str = "OpenFHE Python wrapper v1.5.1.0",
        scheme: str = "CKKS",
    ) -> None:
        self._ciphertext_type = ciphertext_type
        self._ciphertext_predicate = ciphertext_predicate
        self.allowed_nonsemantic_calls = frozenset(allowed_nonsemantic_calls)
        self.compatibility_target = compatibility_target
        self.scheme = scheme
        self._contexts: dict[int, tuple[Any, str]] = {}

    def for_session(self) -> CompatibilityRegistry:
        """Return the same configuration with no previously seen contexts."""

        return CompatibilityRegistry(
            ciphertext_type=self._ciphertext_type,
            ciphertext_predicate=self._ciphertext_predicate,
            allowed_nonsemantic_calls=self.allowed_nonsemantic_calls,
            compatibility_target=self.compatibility_target,
            scheme=self.scheme,
        )

    def operation(self, name: str) -> OperationSpec | None:
        return CORE_OPERATIONS.get(name)

    def classify_callable(self, name: str) -> str:
        if name in CORE_OPERATIONS:
            return "traced"
        if name in self.allowed_nonsemantic_calls:
            return "allowed"
        return "unclassified"

    def is_ciphertext(self, value: Any) -> bool:
        """Return whether a value has the expected ciphertext type or methods."""

        if self._ciphertext_predicate is not None:
            try:
                return bool(self._ciphertext_predicate(value))
            except Exception:
                return False
        if self._ciphertext_type is not None:
            return isinstance(value, self._ciphertext_type)
        try:
            # OpenFHE's Plaintext also has GetLevel/GetNoiseScaleDeg/GetSlots;
            # only a ciphertext carries a key tag (and only a plaintext a length).
            has_state = callable(getattr(value, "GetLevel", None)) and callable(
                getattr(value, "GetNoiseScaleDeg", None)
            )
            if not has_state:
                return False
            if callable(getattr(value, "SetLength", None)) and not callable(getattr(value, "GetKeyTag", None)):
                return False
            return True
        except Exception:
            return False

    def collect_ciphertexts(self, *values: Any) -> list[Any]:
        """Find ciphertexts in arguments while preserving their order."""

        found: list[Any] = []
        seen_containers: set[int] = set()

        def visit(value: Any) -> None:
            if self.is_ciphertext(value):
                found.append(value)
                return
            if isinstance(value, Mapping):
                identity = id(value)
                if identity in seen_containers:
                    return
                seen_containers.add(identity)
                for key, item in value.items():
                    visit(key)
                    visit(item)
                return
            if isinstance(value, (list, tuple)):
                identity = id(value)
                if identity in seen_containers:
                    return
                seen_containers.add(identity)
                for item in value:
                    visit(item)

        for value in values:
            visit(value)
        return found

    def snapshot_ciphertext(self, value: Any) -> CiphertextMetadata:
        """Read the supported metadata, replacing unavailable values with nulls."""

        missing: list[str] = []
        level = self._read(value, "level", ("GetLevel",), ("level",), missing)
        noise = self._read(
            value,
            "noise_scale_degree",
            ("GetNoiseScaleDeg",),
            ("noise_scale_degree",),
            missing,
        )
        scale = self._read(
            value,
            "scale",
            ("GetScalingFactor",),
            ("scale", "scaling_factor"),
            missing,
        )
        slots = self._read(value, "slots", ("GetSlots",), ("slots",), missing)
        native_context = self._read_object(value, ("GetCryptoContext",))
        context_id: int | float | str | bool | None = self._context_id_for(
            native_context
        )
        if context_id is None:
            context_id = self._read(value, "context_id", (), ("context_id",), missing)
        key_tag = self._read(value, "key_tag", ("GetKeyTag",), ("key_tag",), missing)
        if native_context is None:
            scaling = self._read(
                value, "scaling_technique", (), ("scaling_technique",), missing
            )
            key_switch = self._read(
                value,
                "key_switch_technique",
                (),
                ("key_switch_technique",),
                missing,
            )
        else:
            scaling = self._read(
                native_context,
                "scaling_technique",
                ("GetScalingTechnique",),
                (),
                missing,
            )
            key_switch = self._read(
                native_context,
                "key_switch_technique",
                ("GetKeySwitchTechnique",),
                (),
                missing,
            )
        return CiphertextMetadata(
            level=level,
            noise_scale_degree=noise,
            scale=scale,
            slots=slots,
            context_id=context_id,
            key_tag=key_tag,
            scaling_technique=scaling,
            key_switch_technique=key_switch,
            missing_fields=tuple(missing),
        )

    def snapshot_parameters(self, parameters: Any) -> dict[str, Any]:
        """Read the declared CCParams fields the live context cannot expose."""

        missing: list[str] = []
        security_level = self._read(
            parameters, "security_level", ("GetSecurityLevel",), ("security_level",), missing
        )
        ring_dimension = self._read(
            parameters, "declared_ring_dimension", ("GetRingDim",), ("ring_dim",), missing
        )
        depth = self._read(
            parameters,
            "declared_multiplicative_depth",
            ("GetMultiplicativeDepth",),
            ("multiplicative_depth",),
            missing,
        )
        scaling_mod_size = self._read(
            parameters, "scaling_mod_size", ("GetScalingModSize",), ("scaling_mod_size",), missing
        )
        # OpenFHE reports 0 when the library chose the ring dimension itself.
        if ring_dimension == 0:
            ring_dimension = None
        return {
            "security_level": security_level,
            "declared_ring_dimension": ring_dimension,
            "declared_multiplicative_depth": depth,
            "scaling_mod_size": scaling_mod_size,
            "parameters_missing": sorted(set(missing)),
        }

    def snapshot_context(self, context: Any) -> dict[str, Any]:
        """Read the supported context metadata fields."""

        missing: list[str] = []
        context_id = self._register_context(context)
        ring_dimension = self._read(
            context,
            "ring_dimension",
            ("GetRingDimension",),
            ("ring_dimension",),
            missing,
        )
        batch_size = self._read(
            context,
            "batch_size",
            ("GetBatchSize",),
            ("batch_size",),
            missing,
        )
        scheme = self._read(context, "scheme", (), ("scheme",), [])
        if scheme is None:
            # The supported wrapper has no GetScheme(), so use the configured scheme.
            scheme = self.scheme
        depth = self._read(
            context,
            "configured_multiplicative_depth",
            ("GetMultiplicativeDepth",),
            ("configured_multiplicative_depth",),
            missing,
        )
        scaling = self._read(
            context,
            "scaling_technique",
            ("GetScalingTechnique",),
            ("scaling_technique",),
            missing,
        )
        key_switch = self._read(
            context,
            "key_switch_technique",
            ("GetKeySwitchTechnique",),
            ("key_switch_technique",),
            missing,
        )
        cyclotomic_order = self._read(
            context,
            "cyclotomic_order",
            ("GetCyclotomicOrder",),
            ("cyclotomic_order",),
            missing,
        )
        slots: int | None = None
        if isinstance(ring_dimension, int) and not isinstance(ring_dimension, bool):
            slots = ring_dimension // 2
        return {
            "context_id": context_id,
            "scheme": scheme,
            "scheme_evidence": "configured_ckks_contract",
            "ring_dimension": ring_dimension,
            "available_slots": slots,
            "batch_size": batch_size,
            "configured_multiplicative_depth": depth,
            "scaling_technique": scaling,
            "key_switch_technique": key_switch,
            "cyclotomic_order": cyclotomic_order,
            "missing": sorted(set(missing)),
        }

    def _register_context(self, context: Any) -> str:
        identity = id(context)
        existing = self._contexts.get(identity)
        if existing is not None and existing[0] is context:
            return existing[1]
        context_id = f"context_{len(self._contexts) + 1:04d}"
        self._contexts[identity] = (context, context_id)
        return context_id

    def _context_id_for(self, context: Any) -> str | None:
        if context is None:
            return None
        existing = self._contexts.get(id(context))
        if existing is not None and existing[0] is context:
            return existing[1]
        # pybind may return a new Python object for the session's native context.
        if len(self._contexts) == 1:
            return next(iter(self._contexts.values()))[1]
        return None

    def is_plaintext(self, value: Any) -> bool:
        """An OpenFHE Plaintext exposes the packed-value getters and no ciphertext getters."""

        if self.is_ciphertext(value):
            return False
        try:
            return callable(getattr(value, "SetLength", None)) and (
                callable(getattr(value, "GetLength", None))
                or callable(getattr(value, "GetCKKSPackedValue", None))
                or callable(getattr(value, "GetPackedValue", None))
                or callable(getattr(value, "GetRealPackedValue", None))
            )
        except Exception:
            return False

    def operand_kind(self, value: Any) -> str:
        if self.is_ciphertext(value):
            return "ciphertext"
        if self.is_plaintext(value):
            return "plaintext"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "integer"
        if isinstance(value, (float, complex)):
            return "scalar"
        if isinstance(value, (list, tuple, dict)):
            return "collection"
        return "unknown"

    def operand_kinds_for(
        self,
        operation: str,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> list[str]:
        """Classify operands from their types and documented argument positions.

        Key and plaintext types vary across bindings, so their positions in the
        supported method signatures determine their labels.
        """

        values = [*args, *kwargs.values()]
        if operation == "Encrypt":
            return [
                "key"
                if index == 0
                else "plaintext"
                if index == 1
                else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        if operation == "Decrypt":
            return [
                "ciphertext"
                if index == 0
                else "key"
                if index == 1
                else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        if operation == "EvalRotateKeyGen":
            return [
                "key"
                if index == 0
                else "rotation_indices"
                if index == 1
                else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        if operation in {"EvalMultKeyGen", "EvalSumKeyGen"}:
            return [
                "key" if index == 0 else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        if operation == "EvalBootstrapKeyGen":
            return [
                "key"
                if index == 0
                else "slot_count"
                if index == 1
                else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        if operation == "MakeCKKSPackedPlaintext":
            return [
                "plaintext_values" if index == 0 else self.operand_kind(value)
                for index, value in enumerate(values)
            ]
        return [self.operand_kind(value) for value in values]

    def input_ciphertexts_for(
        self,
        spec: OperationSpec,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> list[Any]:
        """Collect ciphertext inputs according to the covered API contract."""

        if spec.ciphertext_input_indices is None:
            return self.collect_ciphertexts(args, kwargs)
        selected = [
            args[index] for index in spec.ciphertext_input_indices if index < len(args)
        ]
        return self.collect_ciphertexts(selected)

    def overload_for(
        self,
        operation: str,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> str:
        spec = CORE_OPERATIONS[operation]
        values = [*args, *kwargs.values()]
        if (
            operation
            in {
                "EvalAdd",
                "EvalAddInPlace",
                "EvalSub",
                "EvalSubInPlace",
                "EvalMult",
                "EvalMultNoRelin",
            }
            and len(values) >= 2
        ):
            left_ct = self.is_ciphertext(values[0])
            right_ct = self.is_ciphertext(values[1])
            if left_ct and right_ct:
                return "ct_ct"
            # The same labels the C++ frontend derives from static operand types.
            if left_ct and self.is_plaintext(values[1]):
                return "ct_pt"
            if right_ct and self.is_plaintext(values[0]):
                return "pt_ct"
            if left_ct and isinstance(values[1], (int, float, complex)):
                return "ct_scalar"
            if right_ct and isinstance(values[0], (int, float, complex)):
                return "scalar_ct"
            return "unknown"
        return spec.default_overload

    def semantic_arguments(
        self,
        operation: str,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> dict[str, Any]:
        if operation == "EvalRotate":
            index: Any = args[1] if len(args) > 1 else kwargs.get("index")
            if isinstance(index, int) and not isinstance(index, bool):
                return {"rotation_index_requested": index}
        if operation == "EvalRotateKeyGen":
            indices: Any = (
                args[1]
                if len(args) > 1
                else kwargs.get("indexList", kwargs.get("indices"))
            )
            if isinstance(indices, (list, tuple)) and all(
                isinstance(index, int) and not isinstance(index, bool)
                for index in indices
            ):
                return {"rotation_indices_requested": list(indices)}
        if operation == "EvalBootstrapKeyGen":
            slots: Any = args[1] if len(args) > 1 else kwargs.get("numSlots")
            if isinstance(slots, int) and not isinstance(slots, bool):
                return {"slot_count": slots}
        if operation == "EvalBootstrapSetup":
            setup_slots: Any = args[2] if len(args) > 2 else kwargs.get("slots")
            if isinstance(setup_slots, int) and not isinstance(setup_slots, bool):
                return {"slot_count": setup_slots}
        if operation == "EvalInnerProduct":
            size: Any = args[2] if len(args) > 2 else kwargs.get("batchSize")
            if isinstance(size, int) and not isinstance(size, bool):
                return {"vector_size": size}
        if operation == "EvalSum":
            batch: Any = args[1] if len(args) > 1 else kwargs.get("batchSize")
            if isinstance(batch, int) and not isinstance(batch, bool):
                return {"batch_size": batch}
        if operation == "EvalChebyshevFunction":
            lower: Any = args[2] if len(args) > 2 else kwargs.get("a")
            upper: Any = args[3] if len(args) > 3 else kwargs.get("b")
            degree: Any = args[4] if len(args) > 4 else kwargs.get("degree")
            if (
                isinstance(lower, (int, float))
                and not isinstance(lower, bool)
                and isinstance(upper, (int, float))
                and not isinstance(upper, bool)
                and isinstance(degree, int)
                and not isinstance(degree, bool)
            ):
                return {
                    "lower_bound": lower,
                    "upper_bound": upper,
                    "polynomial_degree": degree,
                }
        return {}

    @staticmethod
    def _read(
        owner: Any,
        field: str,
        getters: tuple[str, ...],
        attributes: tuple[str, ...],
        missing: list[str],
    ) -> int | float | str | bool | None:
        for getter_name in getters:
            try:
                getter = getattr(owner, getter_name)
            except AttributeError:
                continue
            except Exception:
                missing.append(field)
                return None
            if not callable(getter):
                continue
            try:
                raw = getter()
                normalized = CompatibilityRegistry._scalar_value(raw)
                if normalized is not None or raw is None:
                    return normalized
            except Exception:
                missing.append(field)
                return None
        for attribute_name in attributes:
            try:
                raw = getattr(owner, attribute_name)
                normalized = CompatibilityRegistry._scalar_value(raw)
                if normalized is not None or raw is None:
                    return normalized
            except AttributeError:
                continue
            except Exception:
                missing.append(field)
                return None
        missing.append(field)
        return None

    @staticmethod
    def _read_object(owner: Any, getters: tuple[str, ...]) -> Any:
        """Read a related object returned by one of the named getters."""

        for getter_name in getters:
            try:
                getter = getattr(owner, getter_name)
                if callable(getter):
                    return getter()
            except Exception:
                return None
        return None

    @staticmethod
    def _scalar_value(value: Any) -> int | float | str | bool | None:
        if value is None or isinstance(value, (str, bool, int)):
            return value
        if isinstance(value, float) and math.isfinite(value):
            return value
        # pybind11 enums expose their string value through ``name``.
        try:
            enum_name = value.name
        except Exception:
            return None
        if isinstance(enum_name, str) and enum_name:
            return enum_name
        return None


DEFAULT_COMPATIBILITY = CompatibilityRegistry()
