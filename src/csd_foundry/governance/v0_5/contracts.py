"""Immutable typed objects for the sixteen frozen v0.5 contracts."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, ClassVar, TypeAlias, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    canonical_bytes,
    catalog_digest,
    domain_digest,
)
from csd_foundry.governance.v0_5.resources import contract_catalog, load_json

JSONScalar: TypeAlias = None | bool | int | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
FrozenValue: TypeAlias = JSONScalar | "FrozenArray" | "FrozenObject"

_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}


@dataclass(frozen=True, slots=True)
class FrozenArray:
    values: tuple[FrozenValue, ...]


@dataclass(frozen=True, slots=True)
class FrozenObject:
    fields: tuple[tuple[str, FrozenValue], ...]


def freeze_json(value: Any) -> FrozenValue:
    if value is None or type(value) in {bool, int, str}:
        return cast(JSONScalar, value)
    if type(value) is list:
        return FrozenArray(tuple(freeze_json(item) for item in value))
    if type(value) is dict:
        if not all(type(key) is str for key in value):
            raise GovernanceContractError("NON_STRING_OBJECT_KEY")
        return FrozenObject(tuple((key, freeze_json(item)) for key, item in value.items()))
    if isinstance(value, float):
        raise GovernanceContractError("FLOAT_PROHIBITED")
    raise GovernanceContractError("UNSUPPORTED_TYPE", type(value).__qualname__)


def thaw_json(value: FrozenValue) -> JSONValue:
    if type(value) is FrozenArray:
        return [thaw_json(item) for item in value.values]
    if type(value) is FrozenObject:
        return {key: thaw_json(item) for key, item in value.fields}
    return cast(JSONScalar, value)


@dataclass(frozen=True, slots=True)
class ContractEntry:
    name: str
    schema_path: str
    schema_version: str
    digest_field: str
    domain_prefix: str


@dataclass(frozen=True, slots=True)
class ContractObject:
    """Immutable schema-validated object with frozen v0.5 identity semantics."""

    value: FrozenObject
    CONTRACT_NAME: ClassVar[str]

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> ContractObject:
        if type(value) is not dict:
            raise GovernanceContractError("CONTRACT_VALUE_NOT_OBJECT")
        entry = contract_entry(cls.CONTRACT_NAME)
        schema = contract_schema(cls.CONTRACT_NAME)
        candidate = deepcopy(value)
        try:
            Draft202012Validator(schema).validate(candidate)
        except ValidationError as exc:
            raise GovernanceContractError("SCHEMA_REJECTED", exc.json_path) from exc
        _semantic_validate(cls.CONTRACT_NAME, candidate)
        expected = domain_digest(
            candidate,
            schema,
            entry.digest_field,
            entry.domain_prefix,
        )
        actual = candidate.get(entry.digest_field)
        if actual != expected:
            raise GovernanceContractError("DIGEST_MISMATCH", entry.digest_field)
        frozen = freeze_json(candidate)
        if type(frozen) is not FrozenObject:
            raise GovernanceContractError("CONTRACT_VALUE_NOT_OBJECT")
        return cls(frozen)

    @classmethod
    def build(cls, unsigned_value: dict[str, Any]) -> ContractObject:
        if type(unsigned_value) is not dict:
            raise GovernanceContractError("CONTRACT_VALUE_NOT_OBJECT")
        entry = contract_entry(cls.CONTRACT_NAME)
        if entry.digest_field in unsigned_value:
            raise GovernanceContractError("DIGEST_FIELD_ALREADY_PRESENT", entry.digest_field)
        candidate = deepcopy(unsigned_value)
        candidate[entry.digest_field] = domain_digest(
            candidate,
            contract_schema(cls.CONTRACT_NAME),
            entry.digest_field,
            entry.domain_prefix,
        )
        return cls.from_json(candidate)

    def to_json_value(self) -> dict[str, Any]:
        value = thaw_json(self.value)
        if type(value) is not dict:
            raise GovernanceContractError("CONTRACT_VALUE_NOT_OBJECT")
        return cast(dict[str, Any], value)

    @property
    def schema(self) -> dict[str, Any]:
        return contract_schema(self.CONTRACT_NAME)

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_json_value(), self.schema)

    @property
    def digest(self) -> str:
        entry = contract_entry(self.CONTRACT_NAME)
        value = self.to_json_value().get(entry.digest_field)
        if type(value) is not str:
            raise GovernanceContractError("DIGEST_FIELD_INVALID", entry.digest_field)
        return value

    def with_updates(self, **updates: Any) -> ContractObject:
        entry = contract_entry(self.CONTRACT_NAME)
        candidate = self.to_json_value()
        candidate.pop(entry.digest_field, None)
        candidate.update(updates)
        return type(self).build(candidate)


class RawEvent(ContractObject):
    CONTRACT_NAME = "raw-event"


class SignatureSet(ContractObject):
    CONTRACT_NAME = "signature-set"


class ValidationPolicy(ContractObject):
    CONTRACT_NAME = "validation-policy"


class ValidatedEvent(ContractObject):
    CONTRACT_NAME = "validated-event"


class EventValidationFailure(ContractObject):
    CONTRACT_NAME = "event-validation-failure"


class ClockClaim(ContractObject):
    CONTRACT_NAME = "clock-claim"


class ClockProjectionFailure(ContractObject):
    CONTRACT_NAME = "clock-projection-failure"


class SemanticProjectionReceipt(ContractObject):
    CONTRACT_NAME = "semantic-projection-receipt"


class RegistryEvent(ContractObject):
    CONTRACT_NAME = "registry-event"


class DispositionReceipt(ContractObject):
    CONTRACT_NAME = "disposition-receipt"


class InvalidationEvent(ContractObject):
    CONTRACT_NAME = "invalidation-event"


class QuarantineMarker(ContractObject):
    CONTRACT_NAME = "quarantine-marker"


class ClockCompletionReceipt(ContractObject):
    CONTRACT_NAME = "clock-completion-receipt"


class ReleaseRequest(ContractObject):
    CONTRACT_NAME = "release-request"


class PromotionRequest(ContractObject):
    CONTRACT_NAME = "promotion-request"


class ReleaseManifest(ContractObject):
    CONTRACT_NAME = "release-manifest"


CONTRACT_TYPES: dict[str, type[ContractObject]] = {
    item.CONTRACT_NAME: item
    for item in (
        RawEvent,
        SignatureSet,
        ValidationPolicy,
        ValidatedEvent,
        EventValidationFailure,
        ClockClaim,
        ClockProjectionFailure,
        SemanticProjectionReceipt,
        RegistryEvent,
        DispositionReceipt,
        InvalidationEvent,
        QuarantineMarker,
        ClockCompletionReceipt,
        ReleaseRequest,
        PromotionRequest,
        ReleaseManifest,
    )
}


def _validated_catalog() -> dict[str, Any]:
    catalog = contract_catalog()
    expected = catalog_digest(catalog, b"CONTRACT_CATALOG\0")
    if catalog.get("catalog_digest") != expected:
        raise GovernanceContractError("CONTRACT_CATALOG_DIGEST_MISMATCH")
    if catalog.get("status") != "FROZEN_FOR_IMPLEMENTATION":
        raise GovernanceContractError("CONTRACT_CATALOG_NOT_FROZEN")
    return catalog


def contract_entry(name: str) -> ContractEntry:
    if type(name) is not str or not name:
        raise GovernanceContractError("CONTRACT_NAME_INVALID")
    for item in _validated_catalog().get("contracts", []):
        if item.get("name") == name:
            return ContractEntry(
                name=name,
                schema_path=cast(str, item["schema_path"]),
                schema_version=cast(str, item["schema_version"]),
                digest_field=cast(str, item["digest_field"]),
                domain_prefix=cast(str, item["domain_prefix"]),
            )
    raise GovernanceContractError("UNKNOWN_CONTRACT", name)


def contract_schema(name: str) -> dict[str, Any]:
    entry = contract_entry(name)
    schema = load_json(entry.schema_path)
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        raise GovernanceContractError("SCHEMA_INVALID", name) from exc
    actual_version = schema.get("properties", {}).get("schema_version", {}).get("const")
    if actual_version != entry.schema_version:
        raise GovernanceContractError("SCHEMA_VERSION_MISMATCH", name)
    return schema


def parse_contract(name: str, value: dict[str, Any]) -> ContractObject:
    try:
        contract_type = CONTRACT_TYPES[name]
    except KeyError as exc:
        raise GovernanceContractError("UNKNOWN_CONTRACT", name) from exc
    return contract_type.from_json(value)


def build_contract(name: str, unsigned_value: dict[str, Any]) -> ContractObject:
    try:
        contract_type = CONTRACT_TYPES[name]
    except KeyError as exc:
        raise GovernanceContractError("UNKNOWN_CONTRACT", name) from exc
    return contract_type.build(unsigned_value)


def _semantic_validate(name: str, value: dict[str, Any]) -> None:
    if (
        name in {"clock-claim", "clock-projection-failure"}
        and value["proposed_sequence"] != value["previous_committed_sequence"] + 1
    ):
        raise GovernanceContractError("CLOCK_SEQUENCE_NOT_SUCCESSOR")
    if (
        name == "clock-projection-failure"
        and value["recorded_against_tick"] != value["previous_committed_sequence"]
    ):
        raise GovernanceContractError("FAILURE_CONTEXT_TICK_MISMATCH")
    if name == "semantic-projection-receipt" and value["projection_result"] != "COMPLETED":
        raise GovernanceContractError("SEMANTIC_PROJECTION_NOT_COMPLETED")
    if name == "validated-event" and value["validation_result"] != "ACCEPTED":
        raise GovernanceContractError("VALIDATION_RESULT_NOT_ACCEPTED")
    if (
        name == "release-manifest"
        and _RANK[value["release_class"]] > _RANK[value["maximum_reuse_class"]]
    ):
        raise GovernanceContractError("REUSE_CLASS_BELOW_RELEASE_CLASS")
