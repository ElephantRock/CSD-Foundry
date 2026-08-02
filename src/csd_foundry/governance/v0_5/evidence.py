"""Typed evidence-unit lifecycle projection over the v0.5 registry substrate."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, cast

from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import RegistryStore, build_registry_event

EVIDENCE_PAYLOAD_SCHEMA_VERSION = "evidence-unit-event/1"

_STATUS_REGISTERED = "REGISTERED"
_STATUS_VERIFIED = "VERIFIED"
_STATUS_CHALLENGED = "CHALLENGED"
_STATUS_EXPIRED = "EXPIRED"
_STATUS_INVALIDATED = "INVALIDATED"
_STATUS_REJECTED = "REJECTED"
_STATUS_SUPERSEDED = "SUPERSEDED"

_TERMINAL_STATUSES = {
    _STATUS_EXPIRED,
    _STATUS_INVALIDATED,
    _STATUS_REJECTED,
    _STATUS_SUPERSEDED,
}
_REUSE_CLASSES = {"D0", "D1", "D2", "D3", "BENCHMARK"}
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvidenceRegistryError(RuntimeError):
    """Raised when an evidence event or lifecycle transition is invalid."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class EvidenceUnit:
    """Current immutable projection of one append-only evidence identity."""

    evidence_id: str
    proposition_id: str
    scope_ids: tuple[str, ...]
    source_id: str
    issuer_authority_id: str
    verifier_authority_id: str | None
    issued_at_sequence: int
    valid_from_sequence: int
    expires_at_sequence: int | None
    dependency_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    maximum_reuse_class: str
    status: str
    active_challenge_digest: str | None
    superseded_by_id: str | None
    registration_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int

    def __post_init__(self) -> None:
        _require_token(self.evidence_id, "EVIDENCE_ID_INVALID")
        _require_token(self.proposition_id, "EVIDENCE_PROPOSITION_INVALID")
        _require_token(self.source_id, "EVIDENCE_SOURCE_INVALID")
        _require_token(self.issuer_authority_id, "EVIDENCE_ISSUER_AUTHORITY_INVALID")
        if self.verifier_authority_id is not None:
            _require_token(
                self.verifier_authority_id,
                "EVIDENCE_VERIFIER_AUTHORITY_INVALID",
            )
        _require_sorted_tokens(self.scope_ids, "EVIDENCE_SCOPE_INVALID", allow_empty=False)
        _require_sorted_tokens(self.dependency_ids, "EVIDENCE_DEPENDENCIES_INVALID")
        _require_sorted_tokens(self.limitations, "EVIDENCE_LIMITATIONS_INVALID")
        if self.evidence_id in self.dependency_ids:
            raise EvidenceRegistryError("EVIDENCE_SELF_DEPENDENCY")
        if type(self.issued_at_sequence) is not int or self.issued_at_sequence < 1:
            raise EvidenceRegistryError("EVIDENCE_ISSUED_SEQUENCE_INVALID")
        if type(self.valid_from_sequence) is not int:
            raise EvidenceRegistryError("EVIDENCE_VALID_FROM_SEQUENCE_INVALID")
        if self.valid_from_sequence < self.issued_at_sequence:
            raise EvidenceRegistryError("EVIDENCE_VALIDITY_PRECEDES_ISSUANCE")
        if self.expires_at_sequence is not None:
            if type(self.expires_at_sequence) is not int:
                raise EvidenceRegistryError("EVIDENCE_EXPIRY_SEQUENCE_INVALID")
            if self.expires_at_sequence <= self.valid_from_sequence:
                raise EvidenceRegistryError("EVIDENCE_EXPIRY_NOT_AFTER_VALID_FROM")
        if self.maximum_reuse_class not in _REUSE_CLASSES:
            raise EvidenceRegistryError("EVIDENCE_REUSE_CLASS_INVALID")
        if self.status not in {
            _STATUS_REGISTERED,
            _STATUS_VERIFIED,
            _STATUS_CHALLENGED,
            *_TERMINAL_STATUSES,
        }:
            raise EvidenceRegistryError("EVIDENCE_STATUS_INVALID")
        if self.status == _STATUS_CHALLENGED:
            _require_digest(self.active_challenge_digest, "EVIDENCE_CHALLENGE_DIGEST_INVALID")
        elif self.active_challenge_digest is not None:
            raise EvidenceRegistryError("EVIDENCE_CHALLENGE_DIGEST_UNEXPECTED")
        if self.status == _STATUS_SUPERSEDED:
            if self.superseded_by_id is None:
                raise EvidenceRegistryError("EVIDENCE_REPLACEMENT_ID_REQUIRED")
            _require_token(self.superseded_by_id, "EVIDENCE_REPLACEMENT_ID_INVALID")
            if self.superseded_by_id == self.evidence_id:
                raise EvidenceRegistryError("EVIDENCE_SELF_SUPERSESSION")
        elif self.superseded_by_id is not None:
            raise EvidenceRegistryError("EVIDENCE_REPLACEMENT_ID_UNEXPECTED")
        _require_digest(
            self.registration_source_receipt_digest,
            "EVIDENCE_REGISTRATION_RECEIPT_INVALID",
        )
        _require_digest(
            self.current_source_receipt_digest,
            "EVIDENCE_CURRENT_RECEIPT_INVALID",
        )
        _require_digest(self.current_event_digest, "EVIDENCE_EVENT_DIGEST_INVALID")
        if type(self.current_entity_sequence) is not int or self.current_entity_sequence < 1:
            raise EvidenceRegistryError("EVIDENCE_ENTITY_SEQUENCE_INVALID")
        if type(self.last_clock_sequence) is not int or self.last_clock_sequence < 1:
            raise EvidenceRegistryError("EVIDENCE_CLOCK_SEQUENCE_INVALID")

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL_STATUSES


class EvidenceRegistry:
    """Apply evidence events to a deterministic append-only registry store."""

    def __init__(self, store: RegistryStore) -> None:
        self._store = store

    def current(self, evidence_id: str) -> EvidenceUnit | None:
        history = self._store.reconstruct_entity("EVIDENCE_UNIT", evidence_id)
        return project_evidence_history(history)

    def apply(self, event: RegistryEvent) -> EvidenceUnit:
        value = event.to_json_value()
        evidence_id = cast(str, value["entity_id"])
        head = self._store.entity_head("EVIDENCE_UNIT", evidence_id)
        if head is not None and head.event_digest == event.digest:
            current = self.current(evidence_id)
            if current is None:
                raise EvidenceRegistryError("EVIDENCE_IDEMPOTENT_PROJECTION_MISSING")
            return current
        previous = self.current(evidence_id)
        projected = reduce_evidence(previous, event)
        self._store.append(event)
        return projected


def build_evidence_event(
    *,
    evidence_id: str,
    entity_sequence: int,
    previous_entity_event_digest: str | None,
    clock_sequence: int,
    source_receipt_digest: str,
    payload: dict[str, object],
) -> RegistryEvent:
    """Build a frozen evidence registry envelope with the D2.1 payload version."""

    return build_registry_event(
        registry_type="EVIDENCE_UNIT",
        entity_id=evidence_id,
        entity_sequence=entity_sequence,
        previous_entity_event_digest=previous_entity_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=source_receipt_digest,
        payload_schema_version=EVIDENCE_PAYLOAD_SCHEMA_VERSION,
        payload=payload,
    )


def project_evidence_history(events: tuple[RegistryEvent, ...]) -> EvidenceUnit | None:
    """Replay one evidence event chain into its current projection."""

    state: EvidenceUnit | None = None
    for event in events:
        state = reduce_evidence(state, event)
    return state


def reduce_evidence(previous: EvidenceUnit | None, event: RegistryEvent) -> EvidenceUnit:
    """Apply one frozen evidence event without mutating prior state."""

    value = _event_value(event)
    payload = _payload(value)
    operation = _required_token(payload, "operation", "EVIDENCE_OPERATION_INVALID")
    _verify_chain(previous, event, value)
    if previous is None:
        if operation != "REGISTER":
            raise EvidenceRegistryError("EVIDENCE_FIRST_OPERATION_NOT_REGISTER")
        return _register(event, value, payload)
    if previous.terminal:
        raise EvidenceRegistryError("EVIDENCE_TERMINAL_IDENTITY_REUSE", previous.status)
    if operation == "REGISTER":
        raise EvidenceRegistryError("EVIDENCE_DUPLICATE_REGISTRATION")
    if operation == "VERIFY":
        return _verify(previous, event, value, payload)
    if operation == "REJECT":
        return _reject(previous, event, value, payload)
    if operation == "CHALLENGE":
        return _challenge(previous, event, value, payload)
    if operation == "RESOLVE_CHALLENGE":
        return _resolve_challenge(previous, event, value, payload)
    if operation == "EXPIRE":
        return _expire(previous, event, value, payload)
    if operation == "INVALIDATE":
        return _invalidate(previous, event, value, payload)
    if operation == "SUPERSEDE":
        return _supersede(previous, event, value, payload)
    raise EvidenceRegistryError("EVIDENCE_OPERATION_UNSUPPORTED", operation)


def _register(
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_exact_keys(
        payload,
        {
            "operation",
            "proposition_id",
            "scope_ids",
            "source_id",
            "issuer_authority_id",
            "issued_at_sequence",
            "valid_from_sequence",
            "expires_at_sequence",
            "dependency_ids",
            "limitations",
            "maximum_reuse_class",
        },
    )
    issued_at_sequence = _required_positive_int(
        payload,
        "issued_at_sequence",
        "EVIDENCE_ISSUED_SEQUENCE_INVALID",
    )
    clock_sequence = cast(int, value["clock_sequence"])
    if issued_at_sequence != clock_sequence:
        raise EvidenceRegistryError("EVIDENCE_ISSUANCE_CLOCK_MISMATCH")
    return EvidenceUnit(
        evidence_id=cast(str, value["entity_id"]),
        proposition_id=_required_token(
            payload,
            "proposition_id",
            "EVIDENCE_PROPOSITION_INVALID",
        ),
        scope_ids=_required_token_tuple(
            payload,
            "scope_ids",
            "EVIDENCE_SCOPE_INVALID",
            allow_empty=False,
        ),
        source_id=_required_token(payload, "source_id", "EVIDENCE_SOURCE_INVALID"),
        issuer_authority_id=_required_token(
            payload,
            "issuer_authority_id",
            "EVIDENCE_ISSUER_AUTHORITY_INVALID",
        ),
        verifier_authority_id=None,
        issued_at_sequence=issued_at_sequence,
        valid_from_sequence=_required_positive_int(
            payload,
            "valid_from_sequence",
            "EVIDENCE_VALID_FROM_SEQUENCE_INVALID",
        ),
        expires_at_sequence=_optional_positive_int(
            payload,
            "expires_at_sequence",
            "EVIDENCE_EXPIRY_SEQUENCE_INVALID",
        ),
        dependency_ids=_required_token_tuple(
            payload,
            "dependency_ids",
            "EVIDENCE_DEPENDENCIES_INVALID",
        ),
        limitations=_required_token_tuple(
            payload,
            "limitations",
            "EVIDENCE_LIMITATIONS_INVALID",
        ),
        maximum_reuse_class=_required_reuse_class(payload),
        status=_STATUS_REGISTERED,
        active_challenge_digest=None,
        superseded_by_id=None,
        registration_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_event_digest=event.digest,
        current_entity_sequence=cast(int, value["entity_sequence"]),
        last_clock_sequence=clock_sequence,
    )


def _verify(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(previous, {_STATUS_REGISTERED}, "EVIDENCE_VERIFY_TRANSITION_INVALID")
    _require_exact_keys(payload, {"operation", "verifier_authority_id"})
    return _advance(
        previous,
        event,
        value,
        status=_STATUS_VERIFIED,
        verifier_authority_id=_required_token(
            payload,
            "verifier_authority_id",
            "EVIDENCE_VERIFIER_AUTHORITY_INVALID",
        ),
    )


def _reject(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(previous, {_STATUS_REGISTERED}, "EVIDENCE_REJECT_TRANSITION_INVALID")
    _require_exact_keys(payload, {"operation", "rejecting_authority_id", "reason_code"})
    _required_token(
        payload,
        "rejecting_authority_id",
        "EVIDENCE_REJECTING_AUTHORITY_INVALID",
    )
    _required_token(payload, "reason_code", "EVIDENCE_REASON_CODE_INVALID")
    return _advance(previous, event, value, status=_STATUS_REJECTED)


def _challenge(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(previous, {_STATUS_VERIFIED}, "EVIDENCE_CHALLENGE_TRANSITION_INVALID")
    _require_exact_keys(
        payload,
        {
            "operation",
            "challenger_authority_id",
            "challenge_reason_code",
            "challenge_receipt_digest",
        },
    )
    _required_token(
        payload,
        "challenger_authority_id",
        "EVIDENCE_CHALLENGER_AUTHORITY_INVALID",
    )
    _required_token(
        payload,
        "challenge_reason_code",
        "EVIDENCE_CHALLENGE_REASON_INVALID",
    )
    challenge_digest = _required_digest(
        payload,
        "challenge_receipt_digest",
        "EVIDENCE_CHALLENGE_DIGEST_INVALID",
    )
    return _advance(
        previous,
        event,
        value,
        status=_STATUS_CHALLENGED,
        active_challenge_digest=challenge_digest,
    )


def _resolve_challenge(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(
        previous,
        {_STATUS_CHALLENGED},
        "EVIDENCE_CHALLENGE_RESOLUTION_TRANSITION_INVALID",
    )
    _require_exact_keys(
        payload,
        {
            "operation",
            "resolution",
            "resolver_authority_id",
            "resolution_receipt_digest",
        },
    )
    _required_token(
        payload,
        "resolver_authority_id",
        "EVIDENCE_RESOLVER_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "resolution_receipt_digest",
        "EVIDENCE_RESOLUTION_DIGEST_INVALID",
    )
    resolution = _required_token(payload, "resolution", "EVIDENCE_RESOLUTION_INVALID")
    if resolution == "UPHOLD":
        status = _STATUS_VERIFIED
    elif resolution == "INVALIDATE":
        status = _STATUS_INVALIDATED
    else:
        raise EvidenceRegistryError("EVIDENCE_RESOLUTION_INVALID", resolution)
    return _advance(
        previous,
        event,
        value,
        status=status,
        active_challenge_digest=None,
    )


def _expire(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(
        previous,
        {_STATUS_VERIFIED, _STATUS_CHALLENGED},
        "EVIDENCE_EXPIRE_TRANSITION_INVALID",
    )
    _require_exact_keys(payload, {"operation", "expiry_authority_id"})
    _required_token(
        payload,
        "expiry_authority_id",
        "EVIDENCE_EXPIRY_AUTHORITY_INVALID",
    )
    if previous.expires_at_sequence is None:
        raise EvidenceRegistryError("EVIDENCE_EXPIRY_NOT_DECLARED")
    if cast(int, value["clock_sequence"]) < previous.expires_at_sequence:
        raise EvidenceRegistryError("EVIDENCE_EXPIRY_PREMATURE")
    return _advance(
        previous,
        event,
        value,
        status=_STATUS_EXPIRED,
        active_challenge_digest=None,
    )


def _invalidate(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(
        previous,
        {_STATUS_VERIFIED, _STATUS_CHALLENGED},
        "EVIDENCE_INVALIDATE_TRANSITION_INVALID",
    )
    _require_exact_keys(
        payload,
        {"operation", "invalidating_authority_id", "reason_code"},
    )
    _required_token(
        payload,
        "invalidating_authority_id",
        "EVIDENCE_INVALIDATING_AUTHORITY_INVALID",
    )
    _required_token(payload, "reason_code", "EVIDENCE_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        status=_STATUS_INVALIDATED,
        active_challenge_digest=None,
    )


def _supersede(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> EvidenceUnit:
    _require_status(
        previous,
        {_STATUS_VERIFIED, _STATUS_CHALLENGED},
        "EVIDENCE_SUPERSEDE_TRANSITION_INVALID",
    )
    _require_exact_keys(
        payload,
        {
            "operation",
            "replacement_evidence_id",
            "superseding_authority_id",
            "reason_code",
        },
    )
    replacement_id = _required_token(
        payload,
        "replacement_evidence_id",
        "EVIDENCE_REPLACEMENT_ID_INVALID",
    )
    if replacement_id == previous.evidence_id:
        raise EvidenceRegistryError("EVIDENCE_SELF_SUPERSESSION")
    _required_token(
        payload,
        "superseding_authority_id",
        "EVIDENCE_SUPERSEDING_AUTHORITY_INVALID",
    )
    _required_token(payload, "reason_code", "EVIDENCE_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        status=_STATUS_SUPERSEDED,
        active_challenge_digest=None,
        superseded_by_id=replacement_id,
    )


def _advance(
    previous: EvidenceUnit,
    event: RegistryEvent,
    value: dict[str, Any],
    *,
    status: str,
    verifier_authority_id: str | None = None,
    active_challenge_digest: str | None = None,
    superseded_by_id: str | None = None,
) -> EvidenceUnit:
    return replace(
        previous,
        verifier_authority_id=(
            previous.verifier_authority_id
            if verifier_authority_id is None
            else verifier_authority_id
        ),
        status=status,
        active_challenge_digest=active_challenge_digest,
        superseded_by_id=superseded_by_id,
        current_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_event_digest=event.digest,
        current_entity_sequence=cast(int, value["entity_sequence"]),
        last_clock_sequence=cast(int, value["clock_sequence"]),
    )


def _event_value(event: RegistryEvent) -> dict[str, Any]:
    if type(event) is not RegistryEvent:
        raise EvidenceRegistryError("EVIDENCE_EVENT_TYPE_INVALID")
    value = event.to_json_value()
    if value["registry_type"] != "EVIDENCE_UNIT":
        raise EvidenceRegistryError("EVIDENCE_REGISTRY_TYPE_INVALID")
    if value["projection_phase"] != "EVIDENCE_REGISTRY":
        raise EvidenceRegistryError("EVIDENCE_PROJECTION_PHASE_INVALID")
    if value["payload_schema_version"] != EVIDENCE_PAYLOAD_SCHEMA_VERSION:
        raise EvidenceRegistryError("EVIDENCE_PAYLOAD_VERSION_INVALID")
    return value


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get("payload")
    if type(payload) is not dict:
        raise EvidenceRegistryError("EVIDENCE_PAYLOAD_NOT_OBJECT")
    return cast(dict[str, Any], payload)


def _verify_chain(
    previous: EvidenceUnit | None,
    event: RegistryEvent,
    value: dict[str, Any],
) -> None:
    sequence = cast(int, value["entity_sequence"])
    predecessor = cast(str | None, value["previous_entity_event_digest"])
    clock_sequence = cast(int, value["clock_sequence"])
    if previous is None:
        if sequence != 1 or predecessor is not None:
            raise EvidenceRegistryError("EVIDENCE_GENESIS_LINK_INVALID")
        return
    if value["entity_id"] != previous.evidence_id:
        raise EvidenceRegistryError("EVIDENCE_IDENTITY_CHANGED")
    if sequence != previous.current_entity_sequence + 1:
        raise EvidenceRegistryError("EVIDENCE_ENTITY_SEQUENCE_NOT_SUCCESSOR")
    if predecessor != previous.current_event_digest:
        raise EvidenceRegistryError("EVIDENCE_PREDECESSOR_MISMATCH")
    if clock_sequence <= previous.last_clock_sequence:
        raise EvidenceRegistryError("EVIDENCE_CLOCK_NOT_ADVANCING")
    if event.digest == previous.current_event_digest:
        raise EvidenceRegistryError("EVIDENCE_EVENT_IDENTITY_REUSED")


def _require_status(previous: EvidenceUnit, allowed: set[str], code: str) -> None:
    if previous.status not in allowed:
        raise EvidenceRegistryError(code, previous.status)


def _require_exact_keys(payload: dict[str, Any], expected: set[str]) -> None:
    actual = set(payload)
    if actual != expected:
        detail = f"missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}"
        raise EvidenceRegistryError("EVIDENCE_PAYLOAD_KEYS_INVALID", detail)


def _required_token(payload: dict[str, Any], field: str, code: str) -> str:
    value = payload.get(field)
    _require_token(value, code)
    return cast(str, value)


def _required_digest(payload: dict[str, Any], field: str, code: str) -> str:
    value = payload.get(field)
    _require_digest(value, code)
    return cast(str, value)


def _required_positive_int(payload: dict[str, Any], field: str, code: str) -> int:
    value = payload.get(field)
    if type(value) is not int or value < 1:
        raise EvidenceRegistryError(code)
    return value


def _optional_positive_int(payload: dict[str, Any], field: str, code: str) -> int | None:
    value = payload.get(field)
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise EvidenceRegistryError(code)
    return value


def _required_token_tuple(
    payload: dict[str, Any],
    field: str,
    code: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    value = payload.get(field)
    if type(value) is not list or not all(type(item) is str for item in value):
        raise EvidenceRegistryError(code)
    result = tuple(cast(list[str], value))
    _require_sorted_tokens(result, code, allow_empty=allow_empty)
    return result


def _required_reuse_class(payload: dict[str, Any]) -> str:
    value = payload.get("maximum_reuse_class")
    if type(value) is not str or value not in _REUSE_CLASSES:
        raise EvidenceRegistryError("EVIDENCE_REUSE_CLASS_INVALID")
    return value


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise EvidenceRegistryError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvidenceRegistryError(code)


def _require_sorted_tokens(
    values: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool = True,
) -> None:
    if not allow_empty and not values:
        raise EvidenceRegistryError(code)
    if tuple(sorted(values)) != values or len(set(values)) != len(values):
        raise EvidenceRegistryError(code)
    for value in values:
        _require_token(value, code)
