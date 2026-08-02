"""Typed assumption lifecycle projection over the v0.5 registry substrate."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, cast

from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import RegistryStore, build_registry_event

ASSUMPTION_PAYLOAD_SCHEMA_VERSION = "assumption-event/1"

STANDING_PROPOSED = "PROPOSED"
STANDING_ADMITTED = "ADMITTED"
STANDING_CONFIRMED = "CONFIRMED"
STANDING_REJECTED = "REJECTED"
STANDING_EXPIRED = "EXPIRED"
STANDING_SUPERSEDED = "SUPERSEDED"
DERIVED_CHALLENGED = "CHALLENGED"

_TERMINAL_STANDINGS = {
    STANDING_REJECTED,
    STANDING_EXPIRED,
    STANDING_SUPERSEDED,
}
_ACTIVE_STANDINGS = {STANDING_ADMITTED, STANDING_CONFIRMED}
_MATERIALITIES = {"ADVISORY", "MATERIAL", "CRITICAL"}
_REUSE_CLASSES = {"D0", "D1", "D2", "D3", "BENCHMARK"}
_RESOLUTION_OUTCOMES = {
    "RETURN_TO_ADMITTED",
    "CONFIRM",
    "REJECT",
    "SUPERSEDE",
}
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AssumptionRegistryError(RuntimeError):
    """Raised when an assumption event or lifecycle transition is invalid."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class AssumptionChallenge:
    """Current immutable record for one unresolved challenge identity."""

    challenge_id: str
    challenger_authority_id: str
    reason_code: str
    challenge_receipt_digest: str
    opened_at_sequence: int
    opening_event_digest: str

    def __post_init__(self) -> None:
        _require_token(self.challenge_id, "ASSUMPTION_CHALLENGE_ID_INVALID")
        _require_token(
            self.challenger_authority_id,
            "ASSUMPTION_CHALLENGER_AUTHORITY_INVALID",
        )
        _require_token(self.reason_code, "ASSUMPTION_CHALLENGE_REASON_INVALID")
        _require_digest(
            self.challenge_receipt_digest,
            "ASSUMPTION_CHALLENGE_RECEIPT_INVALID",
        )
        if type(self.opened_at_sequence) is not int or self.opened_at_sequence < 1:
            raise AssumptionRegistryError("ASSUMPTION_CHALLENGE_SEQUENCE_INVALID")
        _require_digest(
            self.opening_event_digest,
            "ASSUMPTION_CHALLENGE_EVENT_DIGEST_INVALID",
        )


@dataclass(frozen=True, slots=True)
class Assumption:
    """Current immutable projection of one append-only assumption identity."""

    assumption_id: str
    proposition_id: str
    scope_ids: tuple[str, ...]
    materiality: str
    proposer_authority_id: str
    admitting_authority_id: str | None
    confirming_authority_id: str | None
    proposed_at_sequence: int
    valid_from_sequence: int
    expires_at_sequence: int | None
    assumption_dependency_ids: tuple[str, ...]
    evidence_dependency_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    maximum_reuse_class: str
    standing: str
    active_challenges: tuple[AssumptionChallenge, ...]
    superseded_by_id: str | None
    proposal_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "ASSUMPTION_ID_INVALID")
        _require_token(self.proposition_id, "ASSUMPTION_PROPOSITION_INVALID")
        _require_sorted_tokens(self.scope_ids, "ASSUMPTION_SCOPE_INVALID", allow_empty=False)
        if self.materiality not in _MATERIALITIES:
            raise AssumptionRegistryError("ASSUMPTION_MATERIALITY_INVALID")
        _require_token(
            self.proposer_authority_id,
            "ASSUMPTION_PROPOSER_AUTHORITY_INVALID",
        )
        if self.admitting_authority_id is not None:
            _require_token(
                self.admitting_authority_id,
                "ASSUMPTION_ADMITTING_AUTHORITY_INVALID",
            )
        if self.confirming_authority_id is not None:
            _require_token(
                self.confirming_authority_id,
                "ASSUMPTION_CONFIRMING_AUTHORITY_INVALID",
            )
        if type(self.proposed_at_sequence) is not int or self.proposed_at_sequence < 1:
            raise AssumptionRegistryError("ASSUMPTION_PROPOSED_SEQUENCE_INVALID")
        if type(self.valid_from_sequence) is not int:
            raise AssumptionRegistryError("ASSUMPTION_VALID_FROM_SEQUENCE_INVALID")
        if self.valid_from_sequence < self.proposed_at_sequence:
            raise AssumptionRegistryError("ASSUMPTION_VALIDITY_PRECEDES_PROPOSAL")
        if self.expires_at_sequence is not None:
            if type(self.expires_at_sequence) is not int:
                raise AssumptionRegistryError("ASSUMPTION_EXPIRY_SEQUENCE_INVALID")
            if self.expires_at_sequence <= self.valid_from_sequence:
                raise AssumptionRegistryError("ASSUMPTION_EXPIRY_NOT_AFTER_VALID_FROM")
        _require_sorted_tokens(
            self.assumption_dependency_ids,
            "ASSUMPTION_DEPENDENCIES_INVALID",
        )
        _require_sorted_tokens(
            self.evidence_dependency_ids,
            "ASSUMPTION_EVIDENCE_DEPENDENCIES_INVALID",
        )
        if self.assumption_id in self.assumption_dependency_ids:
            raise AssumptionRegistryError("ASSUMPTION_SELF_DEPENDENCY")
        _require_sorted_tokens(self.limitations, "ASSUMPTION_LIMITATIONS_INVALID")
        if self.maximum_reuse_class not in _REUSE_CLASSES:
            raise AssumptionRegistryError("ASSUMPTION_REUSE_CLASS_INVALID")
        if self.standing not in {
            STANDING_PROPOSED,
            STANDING_ADMITTED,
            STANDING_CONFIRMED,
            *_TERMINAL_STANDINGS,
        }:
            raise AssumptionRegistryError("ASSUMPTION_STANDING_INVALID")
        if type(self.active_challenges) is not tuple:
            raise AssumptionRegistryError("ASSUMPTION_CHALLENGES_INVALID")
        canonical = tuple(sorted(self.active_challenges, key=lambda item: item.challenge_id))
        if self.active_challenges != canonical:
            raise AssumptionRegistryError("ASSUMPTION_CHALLENGES_NOT_CANONICAL")
        if len({item.challenge_id for item in self.active_challenges}) != len(
            self.active_challenges
        ):
            raise AssumptionRegistryError("ASSUMPTION_CHALLENGE_ID_DUPLICATE")
        if self.active_challenges and self.standing not in _ACTIVE_STANDINGS:
            raise AssumptionRegistryError("ASSUMPTION_CHALLENGE_STANDING_INVALID")
        if self.standing == STANDING_SUPERSEDED:
            if self.superseded_by_id is None:
                raise AssumptionRegistryError("ASSUMPTION_REPLACEMENT_ID_REQUIRED")
            _require_token(
                self.superseded_by_id,
                "ASSUMPTION_REPLACEMENT_ID_INVALID",
            )
            if self.superseded_by_id == self.assumption_id:
                raise AssumptionRegistryError("ASSUMPTION_SELF_SUPERSESSION")
        elif self.superseded_by_id is not None:
            raise AssumptionRegistryError("ASSUMPTION_REPLACEMENT_ID_UNEXPECTED")
        _require_digest(
            self.proposal_source_receipt_digest,
            "ASSUMPTION_PROPOSAL_RECEIPT_INVALID",
        )
        _require_digest(
            self.current_source_receipt_digest,
            "ASSUMPTION_CURRENT_RECEIPT_INVALID",
        )
        _require_digest(self.current_event_digest, "ASSUMPTION_EVENT_DIGEST_INVALID")
        if type(self.current_entity_sequence) is not int or self.current_entity_sequence < 1:
            raise AssumptionRegistryError("ASSUMPTION_ENTITY_SEQUENCE_INVALID")
        if type(self.last_clock_sequence) is not int or self.last_clock_sequence < 1:
            raise AssumptionRegistryError("ASSUMPTION_CLOCK_SEQUENCE_INVALID")

    @property
    def status(self) -> str:
        """Return the externally visible status derived from standing and challenges."""

        if self.active_challenges:
            return DERIVED_CHALLENGED
        return self.standing

    @property
    def terminal(self) -> bool:
        return self.standing in _TERMINAL_STANDINGS

    @property
    def active_challenge_ids(self) -> tuple[str, ...]:
        return tuple(item.challenge_id for item in self.active_challenges)


class AssumptionRegistry:
    """Apply assumption events to a deterministic append-only registry store."""

    def __init__(self, store: RegistryStore) -> None:
        self._store = store

    def current(self, assumption_id: str) -> Assumption | None:
        history = self._store.reconstruct_entity("ASSUMPTION", assumption_id)
        return project_assumption_history(history)

    def apply(self, event: RegistryEvent) -> Assumption:
        value = event.to_json_value()
        assumption_id = cast(str, value["entity_id"])
        head = self._store.entity_head("ASSUMPTION", assumption_id)
        if head is not None and head.event_digest == event.digest:
            current = self.current(assumption_id)
            if current is None:
                raise AssumptionRegistryError("ASSUMPTION_IDEMPOTENT_PROJECTION_MISSING")
            return current
        previous = self.current(assumption_id)
        projected = reduce_assumption(previous, event)
        self._store.append(event)
        return projected


def build_assumption_event(
    *,
    assumption_id: str,
    entity_sequence: int,
    previous_entity_event_digest: str | None,
    clock_sequence: int,
    source_receipt_digest: str,
    payload: dict[str, object],
) -> RegistryEvent:
    """Build a frozen assumption registry envelope with the D3.1 payload version."""

    return build_registry_event(
        registry_type="ASSUMPTION",
        entity_id=assumption_id,
        entity_sequence=entity_sequence,
        previous_entity_event_digest=previous_entity_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=source_receipt_digest,
        payload_schema_version=ASSUMPTION_PAYLOAD_SCHEMA_VERSION,
        payload=payload,
    )


def project_assumption_history(events: tuple[RegistryEvent, ...]) -> Assumption | None:
    """Order-sensitively fold one assumption event chain into current state."""

    state: Assumption | None = None
    for event in events:
        state = reduce_assumption(state, event)
    return state


def reduce_assumption(previous: Assumption | None, event: RegistryEvent) -> Assumption:
    """Apply one frozen assumption event without mutating prior state."""

    value = _event_value(event)
    payload = _payload(value)
    operation = _required_token(payload, "operation", "ASSUMPTION_OPERATION_INVALID")
    _verify_chain(previous, event, value)
    if previous is None:
        if operation != "PROPOSE":
            raise AssumptionRegistryError("ASSUMPTION_FIRST_OPERATION_NOT_PROPOSE")
        return _propose(event, value, payload)
    if previous.terminal:
        raise AssumptionRegistryError(
            "ASSUMPTION_TERMINAL_IDENTITY_REUSE",
            previous.standing,
        )
    if operation == "PROPOSE":
        raise AssumptionRegistryError("ASSUMPTION_DUPLICATE_PROPOSAL")
    if operation == "ADMIT":
        return _admit(previous, event, value, payload)
    if operation == "CONFIRM":
        return _confirm(previous, event, value, payload)
    if operation == "CHALLENGE":
        return _challenge(previous, event, value, payload)
    if operation == "RESOLVE_CHALLENGES":
        return _resolve_challenges(previous, event, value, payload)
    if operation == "REJECT":
        return _reject(previous, event, value, payload)
    if operation == "EXPIRE":
        return _expire(previous, event, value, payload)
    if operation == "SUPERSEDE":
        return _supersede(previous, event, value, payload)
    raise AssumptionRegistryError("ASSUMPTION_OPERATION_UNSUPPORTED", operation)


def _propose(
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_exact_keys(
        payload,
        {
            "operation",
            "proposition_id",
            "scope_ids",
            "materiality",
            "proposer_authority_id",
            "proposed_at_sequence",
            "valid_from_sequence",
            "expires_at_sequence",
            "assumption_dependency_ids",
            "evidence_dependency_ids",
            "limitations",
            "maximum_reuse_class",
        },
    )
    proposed_at_sequence = _required_positive_int(
        payload,
        "proposed_at_sequence",
        "ASSUMPTION_PROPOSED_SEQUENCE_INVALID",
    )
    clock_sequence = cast(int, value["clock_sequence"])
    if proposed_at_sequence != clock_sequence:
        raise AssumptionRegistryError("ASSUMPTION_PROPOSAL_CLOCK_MISMATCH")
    materiality = _required_token(
        payload,
        "materiality",
        "ASSUMPTION_MATERIALITY_INVALID",
    )
    if materiality not in _MATERIALITIES:
        raise AssumptionRegistryError("ASSUMPTION_MATERIALITY_INVALID")
    return Assumption(
        assumption_id=cast(str, value["entity_id"]),
        proposition_id=_required_token(
            payload,
            "proposition_id",
            "ASSUMPTION_PROPOSITION_INVALID",
        ),
        scope_ids=_required_token_tuple(
            payload,
            "scope_ids",
            "ASSUMPTION_SCOPE_INVALID",
            allow_empty=False,
        ),
        materiality=materiality,
        proposer_authority_id=_required_token(
            payload,
            "proposer_authority_id",
            "ASSUMPTION_PROPOSER_AUTHORITY_INVALID",
        ),
        admitting_authority_id=None,
        confirming_authority_id=None,
        proposed_at_sequence=proposed_at_sequence,
        valid_from_sequence=_required_positive_int(
            payload,
            "valid_from_sequence",
            "ASSUMPTION_VALID_FROM_SEQUENCE_INVALID",
        ),
        expires_at_sequence=_optional_positive_int(
            payload,
            "expires_at_sequence",
            "ASSUMPTION_EXPIRY_SEQUENCE_INVALID",
        ),
        assumption_dependency_ids=_required_token_tuple(
            payload,
            "assumption_dependency_ids",
            "ASSUMPTION_DEPENDENCIES_INVALID",
        ),
        evidence_dependency_ids=_required_token_tuple(
            payload,
            "evidence_dependency_ids",
            "ASSUMPTION_EVIDENCE_DEPENDENCIES_INVALID",
        ),
        limitations=_required_token_tuple(
            payload,
            "limitations",
            "ASSUMPTION_LIMITATIONS_INVALID",
        ),
        maximum_reuse_class=_required_reuse_class(payload),
        standing=STANDING_PROPOSED,
        active_challenges=(),
        superseded_by_id=None,
        proposal_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_event_digest=event.digest,
        current_entity_sequence=cast(int, value["entity_sequence"]),
        last_clock_sequence=clock_sequence,
    )


def _admit(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(previous, {STANDING_PROPOSED}, "ASSUMPTION_ADMIT_TRANSITION_INVALID")
    _require_exact_keys(
        payload,
        {"operation", "admitting_authority_id", "admission_receipt_digest"},
    )
    authority = _required_token(
        payload,
        "admitting_authority_id",
        "ASSUMPTION_ADMITTING_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "admission_receipt_digest",
        "ASSUMPTION_ADMISSION_RECEIPT_INVALID",
    )
    return _advance(
        previous,
        event,
        value,
        standing=STANDING_ADMITTED,
        admitting_authority_id=authority,
    )


def _confirm(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(previous, {STANDING_ADMITTED}, "ASSUMPTION_CONFIRM_TRANSITION_INVALID")
    if previous.active_challenges:
        raise AssumptionRegistryError("ASSUMPTION_CONFIRM_WITH_ACTIVE_CHALLENGES")
    _require_exact_keys(
        payload,
        {"operation", "confirming_authority_id", "confirmation_receipt_digest"},
    )
    authority = _required_token(
        payload,
        "confirming_authority_id",
        "ASSUMPTION_CONFIRMING_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "confirmation_receipt_digest",
        "ASSUMPTION_CONFIRMATION_RECEIPT_INVALID",
    )
    return _advance(
        previous,
        event,
        value,
        standing=STANDING_CONFIRMED,
        confirming_authority_id=authority,
    )


def _challenge(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(previous, _ACTIVE_STANDINGS, "ASSUMPTION_CHALLENGE_TRANSITION_INVALID")
    _require_exact_keys(
        payload,
        {
            "operation",
            "challenge_id",
            "challenger_authority_id",
            "challenge_reason_code",
            "challenge_receipt_digest",
        },
    )
    challenge_id = _required_token(
        payload,
        "challenge_id",
        "ASSUMPTION_CHALLENGE_ID_INVALID",
    )
    if challenge_id in previous.active_challenge_ids:
        raise AssumptionRegistryError("ASSUMPTION_CHALLENGE_ID_REUSED", challenge_id)
    challenge = AssumptionChallenge(
        challenge_id=challenge_id,
        challenger_authority_id=_required_token(
            payload,
            "challenger_authority_id",
            "ASSUMPTION_CHALLENGER_AUTHORITY_INVALID",
        ),
        reason_code=_required_token(
            payload,
            "challenge_reason_code",
            "ASSUMPTION_CHALLENGE_REASON_INVALID",
        ),
        challenge_receipt_digest=_required_digest(
            payload,
            "challenge_receipt_digest",
            "ASSUMPTION_CHALLENGE_RECEIPT_INVALID",
        ),
        opened_at_sequence=cast(int, value["clock_sequence"]),
        opening_event_digest=event.digest,
    )
    current = tuple(
        sorted((*previous.active_challenges, challenge), key=lambda item: item.challenge_id)
    )
    return _advance(previous, event, value, active_challenges=current)


def _resolve_challenges(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(previous, _ACTIVE_STANDINGS, "ASSUMPTION_RESOLUTION_TRANSITION_INVALID")
    if not previous.active_challenges:
        raise AssumptionRegistryError("ASSUMPTION_RESOLUTION_WITHOUT_ACTIVE_CHALLENGE")
    _require_exact_keys(
        payload,
        {
            "operation",
            "resolution_outcome",
            "resolver_authority_id",
            "resolution_receipt_digest",
            "resolution_basis_code",
            "resolved_challenge_ids",
            "replacement_assumption_id",
        },
    )
    outcome = _required_token(
        payload,
        "resolution_outcome",
        "ASSUMPTION_RESOLUTION_OUTCOME_INVALID",
    )
    if outcome not in _RESOLUTION_OUTCOMES:
        raise AssumptionRegistryError("ASSUMPTION_RESOLUTION_OUTCOME_INVALID", outcome)
    _required_token(
        payload,
        "resolver_authority_id",
        "ASSUMPTION_RESOLVER_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "resolution_receipt_digest",
        "ASSUMPTION_RESOLUTION_RECEIPT_INVALID",
    )
    _required_token(
        payload,
        "resolution_basis_code",
        "ASSUMPTION_RESOLUTION_BASIS_INVALID",
    )
    resolved_ids = _required_token_tuple(
        payload,
        "resolved_challenge_ids",
        "ASSUMPTION_RESOLVED_CHALLENGES_INVALID",
        allow_empty=False,
    )
    active_ids = set(previous.active_challenge_ids)
    unknown = set(resolved_ids) - active_ids
    if unknown:
        raise AssumptionRegistryError(
            "ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN",
            ",".join(sorted(unknown)),
        )
    replacement = payload.get("replacement_assumption_id")
    if outcome == "SUPERSEDE":
        _require_token(replacement, "ASSUMPTION_REPLACEMENT_ID_INVALID")
        replacement_id = cast(str, replacement)
        if replacement_id == previous.assumption_id:
            raise AssumptionRegistryError("ASSUMPTION_SELF_SUPERSESSION")
    else:
        if replacement is not None:
            raise AssumptionRegistryError("ASSUMPTION_REPLACEMENT_ID_UNEXPECTED")
        replacement_id = None
    remaining = tuple(
        item for item in previous.active_challenges if item.challenge_id not in set(resolved_ids)
    )
    if outcome == "RETURN_TO_ADMITTED":
        standing = STANDING_ADMITTED
    elif outcome == "CONFIRM":
        standing = STANDING_CONFIRMED
    elif outcome == "REJECT":
        standing = STANDING_REJECTED
        remaining = ()
    else:
        standing = STANDING_SUPERSEDED
        remaining = ()
    return _advance(
        previous,
        event,
        value,
        standing=standing,
        active_challenges=remaining,
        superseded_by_id=replacement_id,
    )


def _reject(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(
        previous,
        {STANDING_PROPOSED, STANDING_ADMITTED, STANDING_CONFIRMED},
        "ASSUMPTION_REJECT_TRANSITION_INVALID",
    )
    _require_exact_keys(
        payload,
        {
            "operation",
            "rejecting_authority_id",
            "rejection_receipt_digest",
            "reason_code",
        },
    )
    _required_token(
        payload,
        "rejecting_authority_id",
        "ASSUMPTION_REJECTING_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "rejection_receipt_digest",
        "ASSUMPTION_REJECTION_RECEIPT_INVALID",
    )
    _required_token(payload, "reason_code", "ASSUMPTION_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        standing=STANDING_REJECTED,
        active_challenges=(),
    )


def _expire(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(previous, _ACTIVE_STANDINGS, "ASSUMPTION_EXPIRE_TRANSITION_INVALID")
    _require_exact_keys(
        payload,
        {"operation", "expiry_authority_id", "expiry_receipt_digest"},
    )
    _required_token(
        payload,
        "expiry_authority_id",
        "ASSUMPTION_EXPIRY_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "expiry_receipt_digest",
        "ASSUMPTION_EXPIRY_RECEIPT_INVALID",
    )
    if previous.expires_at_sequence is None:
        raise AssumptionRegistryError("ASSUMPTION_EXPIRY_NOT_DECLARED")
    if cast(int, value["clock_sequence"]) < previous.expires_at_sequence:
        raise AssumptionRegistryError("ASSUMPTION_EXPIRY_PREMATURE")
    return _advance(
        previous,
        event,
        value,
        standing=STANDING_EXPIRED,
        active_challenges=(),
    )


def _supersede(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> Assumption:
    _require_standing(
        previous,
        {STANDING_PROPOSED, STANDING_ADMITTED, STANDING_CONFIRMED},
        "ASSUMPTION_SUPERSEDE_TRANSITION_INVALID",
    )
    _require_exact_keys(
        payload,
        {
            "operation",
            "replacement_assumption_id",
            "superseding_authority_id",
            "supersession_receipt_digest",
            "reason_code",
        },
    )
    replacement_id = _required_token(
        payload,
        "replacement_assumption_id",
        "ASSUMPTION_REPLACEMENT_ID_INVALID",
    )
    if replacement_id == previous.assumption_id:
        raise AssumptionRegistryError("ASSUMPTION_SELF_SUPERSESSION")
    _required_token(
        payload,
        "superseding_authority_id",
        "ASSUMPTION_SUPERSEDING_AUTHORITY_INVALID",
    )
    _required_digest(
        payload,
        "supersession_receipt_digest",
        "ASSUMPTION_SUPERSESSION_RECEIPT_INVALID",
    )
    _required_token(payload, "reason_code", "ASSUMPTION_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        standing=STANDING_SUPERSEDED,
        active_challenges=(),
        superseded_by_id=replacement_id,
    )


def _advance(
    previous: Assumption,
    event: RegistryEvent,
    value: dict[str, Any],
    *,
    standing: str | None = None,
    admitting_authority_id: str | None = None,
    confirming_authority_id: str | None = None,
    active_challenges: tuple[AssumptionChallenge, ...] | None = None,
    superseded_by_id: str | None = None,
) -> Assumption:
    return replace(
        previous,
        standing=previous.standing if standing is None else standing,
        admitting_authority_id=(
            previous.admitting_authority_id
            if admitting_authority_id is None
            else admitting_authority_id
        ),
        confirming_authority_id=(
            previous.confirming_authority_id
            if confirming_authority_id is None
            else confirming_authority_id
        ),
        active_challenges=(
            previous.active_challenges if active_challenges is None else active_challenges
        ),
        superseded_by_id=superseded_by_id,
        current_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_event_digest=event.digest,
        current_entity_sequence=cast(int, value["entity_sequence"]),
        last_clock_sequence=cast(int, value["clock_sequence"]),
    )


def _event_value(event: RegistryEvent) -> dict[str, Any]:
    if type(event) is not RegistryEvent:
        raise AssumptionRegistryError("ASSUMPTION_EVENT_TYPE_INVALID")
    value = event.to_json_value()
    if value["registry_type"] != "ASSUMPTION":
        raise AssumptionRegistryError("ASSUMPTION_REGISTRY_TYPE_INVALID")
    if value["projection_phase"] != "ASSUMPTION_REGISTRY":
        raise AssumptionRegistryError("ASSUMPTION_PROJECTION_PHASE_INVALID")
    if value["payload_schema_version"] != ASSUMPTION_PAYLOAD_SCHEMA_VERSION:
        raise AssumptionRegistryError("ASSUMPTION_PAYLOAD_VERSION_INVALID")
    return value


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get("payload")
    if type(payload) is not dict:
        raise AssumptionRegistryError("ASSUMPTION_PAYLOAD_NOT_OBJECT")
    return cast(dict[str, Any], payload)


def _verify_chain(
    previous: Assumption | None,
    event: RegistryEvent,
    value: dict[str, Any],
) -> None:
    sequence = cast(int, value["entity_sequence"])
    predecessor = cast(str | None, value["previous_entity_event_digest"])
    clock_sequence = cast(int, value["clock_sequence"])
    if previous is None:
        if sequence != 1 or predecessor is not None:
            raise AssumptionRegistryError("ASSUMPTION_GENESIS_LINK_INVALID")
        return
    if value["entity_id"] != previous.assumption_id:
        raise AssumptionRegistryError("ASSUMPTION_IDENTITY_CHANGED")
    if sequence != previous.current_entity_sequence + 1:
        raise AssumptionRegistryError("ASSUMPTION_ENTITY_SEQUENCE_NOT_SUCCESSOR")
    if predecessor != previous.current_event_digest:
        raise AssumptionRegistryError("ASSUMPTION_PREDECESSOR_MISMATCH")
    if clock_sequence <= previous.last_clock_sequence:
        raise AssumptionRegistryError("ASSUMPTION_CLOCK_NOT_ADVANCING")
    if event.digest == previous.current_event_digest:
        raise AssumptionRegistryError("ASSUMPTION_EVENT_IDENTITY_REUSED")


def _require_standing(previous: Assumption, allowed: set[str], code: str) -> None:
    if previous.standing not in allowed:
        raise AssumptionRegistryError(code, previous.standing)


def _require_exact_keys(payload: dict[str, Any], expected: set[str]) -> None:
    actual = set(payload)
    if actual != expected:
        detail = f"missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}"
        raise AssumptionRegistryError("ASSUMPTION_PAYLOAD_KEYS_INVALID", detail)


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
        raise AssumptionRegistryError(code)
    return value


def _optional_positive_int(payload: dict[str, Any], field: str, code: str) -> int | None:
    value = payload.get(field)
    if value is None:
        return None
    if type(value) is not int or value < 1:
        raise AssumptionRegistryError(code)
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
        raise AssumptionRegistryError(code)
    result = tuple(cast(list[str], value))
    _require_sorted_tokens(result, code, allow_empty=allow_empty)
    return result


def _required_reuse_class(payload: dict[str, Any]) -> str:
    value = payload.get("maximum_reuse_class")
    if type(value) is not str or value not in _REUSE_CLASSES:
        raise AssumptionRegistryError("ASSUMPTION_REUSE_CLASS_INVALID")
    return value


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AssumptionRegistryError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AssumptionRegistryError(code)


def _require_sorted_tokens(
    values: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool = True,
) -> None:
    if not allow_empty and not values:
        raise AssumptionRegistryError(code)
    if tuple(sorted(values)) != values or len(set(values)) != len(values):
        raise AssumptionRegistryError(code)
    for value in values:
        _require_token(value, code)
