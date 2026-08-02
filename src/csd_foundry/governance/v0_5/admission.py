"""Deterministic v0.5 event admission and reducer-facing receipt boundary."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    ContractObject,
    EventValidationFailure,
    RawEvent,
    SignatureSet,
    ValidatedEvent,
    ValidationPolicy,
)

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ContractT = TypeVar("ContractT", bound=ContractObject)


@dataclass(frozen=True, slots=True)
class CommittedValidationContext:
    """Immutable context whose tick is committed before admission begins."""

    tick: int
    state_root_digest: str
    authority_root_digest: str
    committed: bool
    context_digest: str

    def __post_init__(self) -> None:
        if type(self.tick) is not int or self.tick < 0:
            raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")
        _require_digest(self.state_root_digest, "state_root_digest")
        _require_digest(self.authority_root_digest, "authority_root_digest")
        if type(self.committed) is not bool:
            raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")
        expected = self._digest_for(
            self.tick,
            self.state_root_digest,
            self.authority_root_digest,
            self.committed,
        )
        if self.context_digest != expected:
            raise GovernanceContractError("DIGEST_MISMATCH", "context_digest")

    @classmethod
    def build(
        cls,
        *,
        tick: int,
        state_root_digest: str,
        authority_root_digest: str,
        committed: bool = True,
    ) -> CommittedValidationContext:
        return cls(
            tick=tick,
            state_root_digest=state_root_digest,
            authority_root_digest=authority_root_digest,
            committed=committed,
            context_digest=cls._digest_for(
                tick,
                state_root_digest,
                authority_root_digest,
                committed,
            ),
        )

    @staticmethod
    def _digest_for(
        tick: int,
        state_root_digest: str,
        authority_root_digest: str,
        committed: bool,
    ) -> str:
        unsigned = {
            "schema_version": "committed-validation-context/1",
            "authority_root_digest": authority_root_digest,
            "committed": committed,
            "state_root_digest": state_root_digest,
            "tick": tick,
        }
        payload = (
            json.dumps(
                unsigned,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(b"COMMITTED_VALIDATION_CONTEXT\0" + payload).hexdigest()

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": "committed-validation-context/1",
            "authority_root_digest": self.authority_root_digest,
            "committed": self.committed,
            "context_digest": self.context_digest,
            "state_root_digest": self.state_root_digest,
            "tick": self.tick,
        }

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> CommittedValidationContext:
        required = {
            "schema_version",
            "authority_root_digest",
            "committed",
            "context_digest",
            "state_root_digest",
            "tick",
        }
        if type(value) is not dict or set(value) != required:
            raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")
        if value.get("schema_version") != "committed-validation-context/1":
            raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")
        return cls(
            tick=cast(int, value["tick"]),
            state_root_digest=cast(str, value["state_root_digest"]),
            authority_root_digest=cast(str, value["authority_root_digest"]),
            committed=cast(bool, value["committed"]),
            context_digest=cast(str, value["context_digest"]),
        )

    @property
    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_json_value(),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class SignatureRecord:
    signer_id: str
    key_id: str
    algorithm: str
    signed_digest: str
    signature_base64: str
    authority_scope: str

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> SignatureRecord:
        required = {
            "signer_id",
            "key_id",
            "algorithm",
            "signed_digest",
            "signature_base64",
            "authority_scope",
        }
        if type(value) is not dict or set(value) != required:
            raise GovernanceContractError("SIGNATURE_INVALID")
        for field_name in required:
            if type(value[field_name]) is not str:
                raise GovernanceContractError("SIGNATURE_INVALID", field_name)
        _require_digest(cast(str, value["signed_digest"]), "signed_digest")
        return cls(
            signer_id=cast(str, value["signer_id"]),
            key_id=cast(str, value["key_id"]),
            algorithm=cast(str, value["algorithm"]),
            signed_digest=cast(str, value["signed_digest"]),
            signature_base64=cast(str, value["signature_base64"]),
            authority_scope=cast(str, value["authority_scope"]),
        )


class CommittedContextResolver(Protocol):
    def latest_committed_tick(self) -> int | None: ...

    def resolve(self, tick: int) -> CommittedValidationContext | None: ...


class PayloadSchemaResolver(Protocol):
    def resolve(self, schema_version: str) -> dict[str, Any] | None: ...


class SignatureVerifier(Protocol):
    def verify(self, signature: SignatureRecord, *, raw_event_digest: str) -> bool: ...


class SignerAuthorityResolver(Protocol):
    def is_authorized(
        self,
        signature: SignatureRecord,
        *,
        policy: ValidationPolicy,
        context: CommittedValidationContext,
    ) -> bool: ...


class ValidationPolicyRegistry(Protocol):
    def resolve(self, policy_digest: str) -> ValidationPolicy | None: ...

    def is_allowed(
        self,
        policy: ValidationPolicy,
        *,
        context: CommittedValidationContext,
    ) -> bool: ...


class EventAdmissionStore(Protocol):
    def put_contract(self, contract: ContractObject) -> None: ...

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None: ...

    def put_context(self, context: CommittedValidationContext) -> None: ...

    def get_context(self, tick: int) -> CommittedValidationContext | None: ...


@dataclass(frozen=True, slots=True)
class AdmissionOutcome:
    accepted: ValidatedEvent | None
    failure: EventValidationFailure | None

    def __post_init__(self) -> None:
        if (self.accepted is None) == (self.failure is None):
            raise GovernanceContractError("ADMISSION_OUTCOME_NOT_EXCLUSIVE")

    @property
    def receipt(self) -> ValidatedEvent | EventValidationFailure:
        if self.accepted is not None:
            return self.accepted
        if self.failure is None:
            raise GovernanceContractError("ADMISSION_OUTCOME_NOT_EXCLUSIVE")
        return self.failure


@dataclass(frozen=True, slots=True)
class AdmissionEvidenceBundle:
    receipt: ValidatedEvent
    raw_event: RawEvent
    signature_set: SignatureSet
    validation_policy: ValidationPolicy
    context: CommittedValidationContext


class EventAdmissionEngine:
    """Fail-closed admission relative to pinned resolver and verifier results."""

    def __init__(
        self,
        *,
        context_resolver: CommittedContextResolver,
        payload_schema_resolver: PayloadSchemaResolver,
        signature_verifier: SignatureVerifier,
        authority_resolver: SignerAuthorityResolver,
        policy_registry: ValidationPolicyRegistry,
        store: EventAdmissionStore,
    ) -> None:
        self._context_resolver = context_resolver
        self._payload_schema_resolver = payload_schema_resolver
        self._signature_verifier = signature_verifier
        self._authority_resolver = authority_resolver
        self._policy_registry = policy_registry
        self._store = store

    def admit(
        self,
        raw_event_input: RawEvent | dict[str, Any],
        signature_set_input: SignatureSet | dict[str, Any],
        validation_policy_input: ValidationPolicy | dict[str, Any],
        *,
        validated_at_tick: int,
    ) -> AdmissionOutcome:
        if type(validated_at_tick) is not int or validated_at_tick < 0:
            raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")

        raw_digest = _declared_or_input_digest(
            raw_event_input,
            "raw_event_digest",
            b"UNTRUSTED_RAW_EVENT\0",
        )
        signature_digest = _declared_or_input_digest(
            signature_set_input,
            "signature_set_digest",
            b"UNTRUSTED_SIGNATURE_SET\0",
        )
        policy_digest = _declared_or_input_digest(
            validation_policy_input,
            "policy_digest",
            b"UNTRUSTED_VALIDATION_POLICY\0",
        )
        failure_codes: set[str] = set()

        raw_event: RawEvent | None = None
        signature_set: SignatureSet | None = None
        validation_policy: ValidationPolicy | None = None

        try:
            raw_event = _coerce_contract(RawEvent, raw_event_input)
            raw_digest = raw_event.digest
        except GovernanceContractError as exc:
            failure_codes.add(
                "RAW_DIGEST_MISMATCH" if exc.code == "DIGEST_MISMATCH" else "RAW_SCHEMA_REJECTED"
            )

        try:
            signature_set = _coerce_contract(SignatureSet, signature_set_input)
            signature_digest = signature_set.digest
        except GovernanceContractError:
            failure_codes.add("SIGNATURE_INVALID")

        try:
            validation_policy = _coerce_contract(ValidationPolicy, validation_policy_input)
            policy_digest = validation_policy.digest
        except GovernanceContractError:
            failure_codes.add("VALIDATION_POLICY_NOT_ALLOWED")

        context: CommittedValidationContext | None
        latest_tick: int | None
        try:
            latest_tick = self._context_resolver.latest_committed_tick()
            context = self._context_resolver.resolve(validated_at_tick)
        except Exception:
            latest_tick = None
            context = None
        context_admissible = (
            context is not None
            and context.committed
            and context.tick == validated_at_tick
            and latest_tick == validated_at_tick
        )
        if context is None:
            failure_codes.add("VALIDATION_CONTEXT_UNAVAILABLE")
        elif not context_admissible:
            failure_codes.add("VALIDATION_CONTEXT_NOT_COMMITTED")

        registered_policy: ValidationPolicy | None = None
        policy_admissible = False
        if validation_policy is not None:
            try:
                registered_policy = self._policy_registry.resolve(validation_policy.digest)
            except Exception:
                registered_policy = None
            if (
                registered_policy is None
                or registered_policy.canonical_bytes != validation_policy.canonical_bytes
            ):
                failure_codes.add("VALIDATION_POLICY_NOT_ALLOWED")
            elif context_admissible and context is not None:
                policy_admissible = self._policy_registry.is_allowed(
                    registered_policy,
                    context=context,
                )
                if not policy_admissible:
                    failure_codes.add("VALIDATION_POLICY_NOT_ALLOWED")

        if raw_event is not None and context is not None:
            raw_value = raw_event.to_json_value()
            if cast(int, raw_value["submitted_against_tick"]) > context.tick:
                failure_codes.add("VALIDATION_CONTEXT_NOT_COMMITTED")
            if validation_policy is not None:
                self._validate_payload(raw_value, validation_policy, failure_codes)

        valid_signer_ids: set[str] = set()
        if signature_set is not None and validation_policy is not None and raw_event is not None:
            policy_value = validation_policy.to_json_value()
            allowed_algorithms = set(cast(list[str], policy_value["allowed_signature_algorithms"]))
            signature_values = cast(
                list[dict[str, Any]], signature_set.to_json_value()["signatures"]
            )
            seen_signers: set[str] = set()
            for signature_value in signature_values:
                signature = SignatureRecord.from_json(signature_value)
                signature_valid = True
                if signature.signer_id in seen_signers:
                    failure_codes.add("SIGNATURE_INVALID")
                    signature_valid = False
                seen_signers.add(signature.signer_id)
                if signature.signed_digest != raw_event.digest:
                    failure_codes.add("SIGNATURE_DIGEST_MISMATCH")
                    signature_valid = False
                if signature.algorithm not in allowed_algorithms:
                    failure_codes.add("SIGNATURE_ALGORITHM_NOT_ALLOWED")
                    signature_valid = False
                if not self._signature_verifier.verify(
                    signature,
                    raw_event_digest=raw_event.digest,
                ):
                    failure_codes.add("SIGNATURE_INVALID")
                    signature_valid = False
                if policy_admissible and context is not None and registered_policy is not None:
                    if not self._authority_resolver.is_authorized(
                        signature,
                        policy=registered_policy,
                        context=context,
                    ):
                        failure_codes.add("AUTHORITY_SCOPE_REJECTED")
                        signature_valid = False
                else:
                    signature_valid = False
                if signature_valid:
                    valid_signer_ids.add(signature.signer_id)

            if policy_admissible and context_admissible:
                minimum_count = cast(int, policy_value["minimum_signature_count"])
                if len(valid_signer_ids) < minimum_count:
                    failure_codes.add("SIGNATURE_THRESHOLD_NOT_MET")

        if failure_codes:
            failure = cast(
                EventValidationFailure,
                EventValidationFailure.build(
                    {
                        "schema_version": "event-validation-failure/1",
                        "raw_event_digest": raw_digest,
                        "validation_policy_digest": policy_digest,
                        "signature_set_digest": signature_digest,
                        "validated_at_tick": validated_at_tick,
                        "failure_codes": sorted(failure_codes),
                    }
                ),
            )
            self._persist_available_inputs(
                raw_event=raw_event,
                signature_set=signature_set,
                validation_policy=validation_policy,
                context=context,
            )
            self._store.put_contract(failure)
            return AdmissionOutcome(accepted=None, failure=failure)

        if (
            raw_event is None
            or signature_set is None
            or validation_policy is None
            or context is None
        ):
            raise GovernanceContractError("ADMISSION_INTERNAL_INCOMPLETE")

        accepted = cast(
            ValidatedEvent,
            ValidatedEvent.build(
                {
                    "schema_version": "validated-event/1",
                    "raw_event_digest": raw_event.digest,
                    "validation_policy_digest": validation_policy.digest,
                    "signature_set_digest": signature_set.digest,
                    "validation_result": "ACCEPTED",
                    "validated_at_tick": validated_at_tick,
                }
            ),
        )
        self._persist_available_inputs(
            raw_event=raw_event,
            signature_set=signature_set,
            validation_policy=validation_policy,
            context=context,
        )
        self._store.put_contract(accepted)
        return AdmissionOutcome(accepted=accepted, failure=None)

    def _validate_payload(
        self,
        raw_value: dict[str, Any],
        validation_policy: ValidationPolicy,
        failure_codes: set[str],
    ) -> None:
        schema_version = cast(str, raw_value["payload_schema_version"])
        policy_value = validation_policy.to_json_value()
        accepted_schemas = cast(list[str], policy_value["accepted_raw_event_schemas"])
        if schema_version not in accepted_schemas:
            failure_codes.add("RAW_SCHEMA_REJECTED")
            return
        try:
            payload_schema = self._payload_schema_resolver.resolve(schema_version)
        except Exception:
            payload_schema = None
        if payload_schema is None:
            failure_codes.add("RAW_SCHEMA_REJECTED")
            return
        try:
            Draft202012Validator.check_schema(payload_schema)
            Draft202012Validator(payload_schema).validate(raw_value["payload"])
        except (SchemaError, ValidationError):
            failure_codes.add("RAW_SCHEMA_REJECTED")

    def _persist_available_inputs(
        self,
        *,
        raw_event: RawEvent | None,
        signature_set: SignatureSet | None,
        validation_policy: ValidationPolicy | None,
        context: CommittedValidationContext | None,
    ) -> None:
        for contract in (raw_event, signature_set, validation_policy):
            if contract is not None:
                self._store.put_contract(contract)
        if context is not None:
            self._store.put_context(context)


def reconstruct_accepted(
    receipt: ValidatedEvent,
    store: EventAdmissionStore,
) -> AdmissionEvidenceBundle:
    require_validated_event(receipt)
    value = receipt.to_json_value()
    raw = store.get_contract("raw-event", cast(str, value["raw_event_digest"]))
    if type(raw) is not RawEvent:
        raise GovernanceContractError("RAW_EVENT_UNAVAILABLE")
    signatures = store.get_contract(
        "signature-set",
        cast(str, value["signature_set_digest"]),
    )
    if type(signatures) is not SignatureSet:
        raise GovernanceContractError("SIGNATURE_SET_UNAVAILABLE")
    policy = store.get_contract(
        "validation-policy",
        cast(str, value["validation_policy_digest"]),
    )
    if type(policy) is not ValidationPolicy:
        raise GovernanceContractError("VALIDATION_POLICY_UNAVAILABLE")
    context = store.get_context(cast(int, value["validated_at_tick"]))
    if context is None or not context.committed:
        raise GovernanceContractError("VALIDATION_CONTEXT_NOT_COMMITTED")
    return AdmissionEvidenceBundle(
        receipt=receipt,
        raw_event=raw,
        signature_set=signatures,
        validation_policy=policy,
        context=context,
    )


def require_validated_event(value: object) -> ValidatedEvent:
    """Reject raw and failure objects at the reducer boundary."""

    if type(value) is not ValidatedEvent:
        raise GovernanceContractError("VALIDATION_RESULT_NOT_ACCEPTED")
    return value


def _coerce_contract(
    contract_type: type[ContractT],
    value: ContractT | dict[str, Any],
) -> ContractT:
    if type(value) is contract_type:
        return value
    if type(value) is dict:
        return cast(ContractT, contract_type.from_json(value))
    raise GovernanceContractError("SCHEMA_REJECTED")


def _declared_or_input_digest(
    value: ContractObject | dict[str, Any],
    digest_field: str,
    domain: bytes,
) -> str:
    if isinstance(value, ContractObject):
        return value.digest
    if type(value) is dict:
        declared = value.get(digest_field)
        if type(declared) is str and _DIGEST_PATTERN.fullmatch(declared) is not None:
            return declared
        try:
            payload = (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            payload = type(value).__qualname__.encode("utf-8")
        return "sha256:" + hashlib.sha256(domain + payload).hexdigest()
    raise GovernanceContractError("SCHEMA_REJECTED")


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise GovernanceContractError("DIGEST_MISMATCH", field_name)
    return value
