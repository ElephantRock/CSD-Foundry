"""Frozen alternative-model lifecycle registry for v0.5-D4.

Event-sourced alternative-model lifecycle: PROPOSE → ADMIT → CHALLENGE →
RESOLVE_CHALLENGES → CONFIRM / REJECT / EXPIRE / SUPERSEDE.

The lifecycle is a substantive CSD registry that records shadow-graph model
admission, challenge, resolution, and terminal history. It carries enough
immutable information for later P3.4 comparison and replay: canonical
shadow-graph identity/content binding, scope, provenance, challenge basis,
evidence packet references, decision relevance, separation status, and
temporal/lifecycle state.

UNVERIFIED is an explicit separation outcome and is never silently upgraded
into admissibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, cast

from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import RegistryStore, build_registry_event

ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_VERSION = "alternative-model-event/1"

STANDING_PROPOSED = "PROPOSED"
STANDING_UNVERIFIED = "UNVERIFIED"
STANDING_ADMITTED = "ADMITTED"
STANDING_CONFIRMED = "CONFIRMED"
STANDING_CHALLENGED = "CHALLENGED"
STANDING_REJECTED = "REJECTED"
STANDING_EXPIRED = "EXPIRED"
STANDING_SUPERSEDED = "SUPERSEDED"

_TERMINAL_STANDINGS = frozenset({STANDING_REJECTED, STANDING_EXPIRED, STANDING_SUPERSEDED})
_ADMITTABLE_STANDINGS = frozenset({STANDING_UNVERIFIED})
# UNVERIFIED is the explicit post-ADMIT standing and is fully lifecycle-eligible
# (challengeable, confirmable, expirable, supersedeable, rejectable). It is never
# silently upgraded to ADMITTED; ADMITTED is reached only by RESOLVE_CHALLENGES
# all-resolved (which restores the pre-challenge standing).
_CHALLENGEABLE_STANDINGS = frozenset({STANDING_UNVERIFIED, STANDING_ADMITTED, STANDING_CONFIRMED})
_MATERIALITIES = frozenset({"ADVISORY", "MATERIAL", "CRITICAL"})
# Every standing a handler may emit must validate on the frozen projection.
_SEPARATION_STATUSES = frozenset(
    {
        STANDING_PROPOSED,
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
        STANDING_REJECTED,
        STANDING_EXPIRED,
        STANDING_SUPERSEDED,
    }
)
_RESOLUTION_OUTCOMES = frozenset({"UPHOLD", "INVALIDATE"})

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AlternativeModelRegistryError(RuntimeError):
    """Raised when an alternative-model event or lifecycle transition is invalid."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class AlternativeModelChallenge:
    """Current immutable record for one unresolved alternative-model challenge."""

    challenge_id: str
    challenger_authority_id: str
    reason_code: str
    challenge_receipt_digest: str
    opened_at_sequence: int
    opening_event_digest: str

    def __post_init__(self) -> None:
        _require_token(self.challenge_id, "ALTERNATIVE_MODEL_CHALLENGE_ID_INVALID")
        _require_token(self.challenger_authority_id, "ALTERNATIVE_MODEL_CHALLENGER_INVALID")
        _require_token(self.reason_code, "ALTERNATIVE_MODEL_CHALLENGE_REASON_INVALID")
        _require_digest(
            self.challenge_receipt_digest, "ALTERNATIVE_MODEL_CHALLENGE_RECEIPT_INVALID"
        )
        if type(self.opened_at_sequence) is not int or self.opened_at_sequence < 1:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGE_SEQUENCE_INVALID")
        _require_digest(self.opening_event_digest, "ALTERNATIVE_MODEL_CHALLENGE_EVENT_INVALID")


@dataclass(frozen=True, slots=True)
class AlternativeModel:
    """Current immutable projection of one alternative-model identity."""

    model_id: str
    model_version: str
    primary_model_id: str
    graph_digest: str
    declared_difference_digest: str
    scope_ids: tuple[str, ...]
    assumption_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    proposer_authority_id: str
    admitting_authority_id: str | None
    confirming_authority_id: str | None
    materiality: str
    separation_status: str
    valid_from_sequence: int
    expires_at_sequence: int | None
    active_challenges: tuple[AlternativeModelChallenge, ...]
    superseded_by_id: str | None
    limitations: tuple[str, ...]
    maximum_reuse_class: str
    proposal_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int

    def __post_init__(self) -> None:
        _require_token(self.model_id, "ALTERNATIVE_MODEL_ID_INVALID")
        _require_token(self.model_version, "ALTERNATIVE_MODEL_VERSION_INVALID")
        _require_token(self.primary_model_id, "ALTERNATIVE_MODEL_PRIMARY_INVALID")
        _require_digest(self.graph_digest, "ALTERNATIVE_MODEL_GRAPH_DIGEST_INVALID")
        _require_digest(
            self.declared_difference_digest, "ALTERNATIVE_MODEL_DIFFERENCE_DIGEST_INVALID"
        )
        _require_sorted_tokens(self.scope_ids, "ALTERNATIVE_MODEL_SCOPE_IDS_INVALID")
        _require_sorted_tokens(
            self.assumption_ids, "ALTERNATIVE_MODEL_ASSUMPTION_IDS_INVALID", allow_empty=True
        )
        _require_sorted_tokens(
            self.evidence_ids, "ALTERNATIVE_MODEL_EVIDENCE_IDS_INVALID", allow_empty=True
        )
        _require_token(self.proposer_authority_id, "ALTERNATIVE_MODEL_PROPOSER_INVALID")
        if self.admitting_authority_id is not None:
            _require_token(self.admitting_authority_id, "ALTERNATIVE_MODEL_ADMITTING_INVALID")
        if self.confirming_authority_id is not None:
            _require_token(self.confirming_authority_id, "ALTERNATIVE_MODEL_CONFIRMING_INVALID")
        if self.materiality not in _MATERIALITIES:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_MATERIALITY_INVALID")
        if self.separation_status not in _SEPARATION_STATUSES:
            raise AlternativeModelRegistryError(
                "ALTERNATIVE_MODEL_SEPARATION_STATUS_INVALID", self.separation_status
            )
        if type(self.valid_from_sequence) is not int or self.valid_from_sequence < 1:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_VALID_FROM_INVALID")
        if self.expires_at_sequence is not None:
            if type(self.expires_at_sequence) is not int:
                raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRES_INVALID")
            if self.expires_at_sequence <= self.valid_from_sequence:
                raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRY_NOT_AFTER_VALID_FROM")
        if type(self.active_challenges) is not tuple:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGES_NOT_TUPLE")
        ids = [c.challenge_id for c in self.active_challenges]
        if ids != sorted(ids):
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGES_NOT_CANONICAL")
        if len(set(ids)) != len(ids):
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGE_ID_DUPLICATE")
        if self.active_challenges and self.separation_status not in _CHALLENGEABLE_STANDINGS:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGE_STANDING_INVALID")
        if self.separation_status == STANDING_SUPERSEDED and not self.superseded_by_id:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_SUPERSESSION_MISSING")
        if self.separation_status != STANDING_SUPERSEDED and self.superseded_by_id is not None:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_SUPERSESSION_UNEXPECTED")
        if self.model_id == self.superseded_by_id:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_SELF_SUPERSESSION")
        _require_sorted_tokens(
            self.limitations, "ALTERNATIVE_MODEL_LIMITATIONS_INVALID", allow_empty=True
        )
        if self.maximum_reuse_class not in {"D0", "D1", "D2", "D3", "BENCHMARK"}:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_REUSE_CLASS_INVALID")
        _require_digest(
            self.proposal_source_receipt_digest, "ALTERNATIVE_MODEL_PROPOSAL_RECEIPT_INVALID"
        )
        _require_digest(
            self.current_source_receipt_digest, "ALTERNATIVE_MODEL_CURRENT_RECEIPT_INVALID"
        )
        _require_digest(self.current_event_digest, "ALTERNATIVE_MODEL_CURRENT_EVENT_INVALID")
        if type(self.current_entity_sequence) is not int or self.current_entity_sequence < 1:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_ENTITY_SEQUENCE_INVALID")
        if type(self.last_clock_sequence) is not int or self.last_clock_sequence < 1:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CLOCK_INVALID")

    @property
    def standing(self) -> str:
        """Return the externally visible standing derived from separation status and challenges."""
        if self.active_challenges:
            return STANDING_CHALLENGED
        return self.separation_status

    @property
    def status(self) -> str:
        """Alias for standing for compatibility with evidence/assumption patterns."""
        return self.standing

    @property
    def terminal(self) -> bool:
        return self.separation_status in _TERMINAL_STANDINGS


class AlternativeModelRegistry:
    """Registry wrapper for alternative-model lifecycle events."""

    def __init__(self, store: RegistryStore) -> None:
        self._store = store

    def current(self, model_id: str) -> AlternativeModel | None:
        history = self._store.reconstruct_entity("ALTERNATIVE_MODEL", model_id)
        return project_alternative_model_history(history)

    def apply(self, event: RegistryEvent) -> AlternativeModel:
        value = event.to_json_value()
        model_id = cast(str, value["entity_id"])
        head = self._store.entity_head("ALTERNATIVE_MODEL", model_id)
        if head is not None and head.event_digest == event.digest:
            current = self.current(model_id)
            if current is None:
                raise AlternativeModelRegistryError(
                    "ALTERNATIVE_MODEL_IDEMPOTENT_PROJECTION_MISSING"
                )
            return current
        previous = self.current(model_id)
        projected = reduce_alternative_model(previous, event)
        self._store.append(event)
        return projected


def build_alternative_model_event(
    *,
    model_id: str,
    entity_sequence: int,
    previous_entity_event_digest: str | None,
    clock_sequence: int,
    source_receipt_digest: str,
    payload: dict[str, object],
) -> RegistryEvent:
    """Build a frozen alternative-model registry envelope with the D4 payload version."""
    return build_registry_event(
        registry_type="ALTERNATIVE_MODEL",
        entity_id=model_id,
        entity_sequence=entity_sequence,
        previous_entity_event_digest=previous_entity_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=source_receipt_digest,
        payload_schema_version=ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_VERSION,
        payload=payload,
    )


def project_alternative_model_history(
    events: tuple[RegistryEvent, ...],
) -> AlternativeModel | None:
    """Order-sensitively fold one alternative-model event chain into current state."""
    state: AlternativeModel | None = None
    for event in events:
        state = reduce_alternative_model(state, event)
    return state


def reduce_alternative_model(
    previous: AlternativeModel | None, event: RegistryEvent
) -> AlternativeModel:
    """Apply one frozen alternative-model event without mutating prior state."""
    value = _event_value(event)
    payload = _payload(value)
    operation = _required_token(payload, "operation", "ALTERNATIVE_MODEL_OPERATION_INVALID")
    _verify_chain(previous, event, value)
    if previous is None:
        if operation != "PROPOSE":
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_FIRST_OPERATION_NOT_PROPOSE")
        return _propose(event, value, payload)
    if previous.terminal:
        raise AlternativeModelRegistryError(
            "ALTERNATIVE_MODEL_TERMINAL_IDENTITY_REUSE", previous.separation_status
        )
    if operation == "PROPOSE":
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_DUPLICATE_PROPOSAL")
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
    raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_OPERATION_UNSUPPORTED", operation)


# --------------------------------------------------------------------------- #
# Operation handlers
# --------------------------------------------------------------------------- #


def _propose(
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    _require_exact_keys(
        payload,
        {
            "operation",
            "model_version",
            "primary_model_id",
            "graph_digest",
            "declared_difference_digest",
            "scope_ids",
            "assumption_ids",
            "evidence_ids",
            "proposer_authority_id",
            "materiality",
            "valid_from_sequence",
            "expires_at_sequence",
            "limitations",
            "maximum_reuse_class",
        },
    )
    model_version = _required_token(payload, "model_version", "ALTERNATIVE_MODEL_VERSION_INVALID")
    primary_model_id = _required_token(
        payload, "primary_model_id", "ALTERNATIVE_MODEL_PRIMARY_INVALID"
    )
    graph_digest = _required_digest(
        payload, "graph_digest", "ALTERNATIVE_MODEL_GRAPH_DIGEST_INVALID"
    )
    declared_difference_digest = _required_digest(
        payload, "declared_difference_digest", "ALTERNATIVE_MODEL_DIFFERENCE_DIGEST_INVALID"
    )
    scope_ids = _required_token_tuple(payload, "scope_ids", "ALTERNATIVE_MODEL_SCOPE_IDS_INVALID")
    assumption_ids = _optional_token_tuple(
        payload, "assumption_ids", "ALTERNATIVE_MODEL_ASSUMPTION_IDS_INVALID"
    )
    evidence_ids = _optional_token_tuple(
        payload, "evidence_ids", "ALTERNATIVE_MODEL_EVIDENCE_IDS_INVALID"
    )
    proposer = _required_token(
        payload, "proposer_authority_id", "ALTERNATIVE_MODEL_PROPOSER_INVALID"
    )
    materiality = _required_token(payload, "materiality", "ALTERNATIVE_MODEL_MATERIALITY_INVALID")
    if materiality not in _MATERIALITIES:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_MATERIALITY_INVALID")
    valid_from = _required_positive_int(
        payload, "valid_from_sequence", "ALTERNATIVE_MODEL_VALID_FROM_INVALID"
    )
    expires_at = _optional_positive_int(
        payload, "expires_at_sequence", "ALTERNATIVE_MODEL_EXPIRES_INVALID"
    )
    if expires_at is not None and expires_at <= valid_from:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRY_NOT_AFTER_VALID_FROM")
    limitations = _optional_token_tuple(
        payload, "limitations", "ALTERNATIVE_MODEL_LIMITATIONS_INVALID"
    )
    reuse_class = _required_token(
        payload, "maximum_reuse_class", "ALTERNATIVE_MODEL_REUSE_CLASS_INVALID"
    )
    if reuse_class not in {"D0", "D1", "D2", "D3", "BENCHMARK"}:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_REUSE_CLASS_INVALID")
    clock = cast(int, value["clock_sequence"])
    model_id = cast(str, value["entity_id"])
    return AlternativeModel(
        model_id=model_id,
        model_version=model_version,
        primary_model_id=primary_model_id,
        graph_digest=graph_digest,
        declared_difference_digest=declared_difference_digest,
        scope_ids=scope_ids,
        assumption_ids=assumption_ids,
        evidence_ids=evidence_ids,
        proposer_authority_id=proposer,
        admitting_authority_id=None,
        confirming_authority_id=None,
        materiality=materiality,
        separation_status=STANDING_PROPOSED,
        valid_from_sequence=valid_from,
        expires_at_sequence=expires_at,
        active_challenges=(),
        superseded_by_id=None,
        limitations=limitations,
        maximum_reuse_class=reuse_class,
        proposal_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_source_receipt_digest=cast(str, value["source_receipt_digest"]),
        current_event_digest=event.digest,
        current_entity_sequence=cast(int, value["entity_sequence"]),
        last_clock_sequence=clock,
    )


def _admit(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status != STANDING_PROPOSED:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_ADMIT_TRANSITION_INVALID")
    _require_exact_keys(payload, {"operation", "admitting_authority_id"})
    authority = _required_token(
        payload, "admitting_authority_id", "ALTERNATIVE_MODEL_ADMITTING_INVALID"
    )
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_UNVERIFIED,
        admitting_authority_id=authority,
    )


def _confirm(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in {
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CONFIRM_TRANSITION_INVALID")
    if previous.active_challenges:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CONFIRM_WITH_ACTIVE_CHALLENGES")
    _require_exact_keys(payload, {"operation", "confirming_authority_id"})
    authority = _required_token(
        payload, "confirming_authority_id", "ALTERNATIVE_MODEL_CONFIRMING_INVALID"
    )
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_CONFIRMED,
        confirming_authority_id=authority,
    )


def _challenge(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in _CHALLENGEABLE_STANDINGS:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGE_TRANSITION_INVALID")
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
        payload, "challenge_id", "ALTERNATIVE_MODEL_CHALLENGE_ID_INVALID"
    )
    if any(c.challenge_id == challenge_id for c in previous.active_challenges):
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CHALLENGE_ID_REUSED")
    challenger = _required_token(
        payload, "challenger_authority_id", "ALTERNATIVE_MODEL_CHALLENGER_INVALID"
    )
    reason = _required_token(
        payload, "challenge_reason_code", "ALTERNATIVE_MODEL_CHALLENGE_REASON_INVALID"
    )
    receipt = _required_digest(
        payload, "challenge_receipt_digest", "ALTERNATIVE_MODEL_CHALLENGE_RECEIPT_INVALID"
    )
    clock = cast(int, value["clock_sequence"])
    challenge = AlternativeModelChallenge(
        challenge_id=challenge_id,
        challenger_authority_id=challenger,
        reason_code=reason,
        challenge_receipt_digest=receipt,
        opened_at_sequence=clock,
        opening_event_digest=event.digest,
    )
    new_challenges = tuple(
        sorted((*previous.active_challenges, challenge), key=lambda c: c.challenge_id)
    )
    return _advance(previous, event, value, active_challenges=new_challenges)


def _resolve_challenges(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in _CHALLENGEABLE_STANDINGS:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_RESOLUTION_TRANSITION_INVALID")
    if not previous.active_challenges:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_RESOLUTION_WITHOUT_ACTIVE_CHALLENGE")
    _require_exact_keys(
        payload,
        {
            "operation",
            "resolution_outcome",
            "resolver_authority_id",
            "resolution_receipt_digest",
            "resolution_basis_code",
            "resolved_challenge_ids",
            "replacement_model_id",
        },
    )
    outcome = _required_token(
        payload, "resolution_outcome", "ALTERNATIVE_MODEL_RESOLUTION_OUTCOME_INVALID"
    )
    if outcome not in _RESOLUTION_OUTCOMES:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_RESOLUTION_OUTCOME_INVALID", outcome)
    resolver = _required_token(
        payload, "resolver_authority_id", "ALTERNATIVE_MODEL_RESOLVER_INVALID"
    )
    del resolver  # validated but not stored on projection
    _required_digest(
        payload, "resolution_receipt_digest", "ALTERNATIVE_MODEL_RESOLUTION_RECEIPT_INVALID"
    )
    _required_token(payload, "resolution_basis_code", "ALTERNATIVE_MODEL_RESOLUTION_BASIS_INVALID")
    resolved_ids = _required_token_tuple(
        payload, "resolved_challenge_ids", "ALTERNATIVE_MODEL_RESOLVED_CHALLENGES_INVALID"
    )
    if not resolved_ids:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_RESOLVED_CHALLENGES_EMPTY")
    active_ids = {c.challenge_id for c in previous.active_challenges}
    unknown = set(resolved_ids) - active_ids
    if unknown:
        raise AlternativeModelRegistryError(
            "ALTERNATIVE_MODEL_RESOLUTION_CHALLENGE_UNKNOWN", ",".join(sorted(unknown))
        )
    replacement = payload.get("replacement_model_id")
    if outcome == "INVALIDATE":
        if replacement is not None:
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_REPLACEMENT_UNEXPECTED")
        return _advance(
            previous,
            event,
            value,
            separation_status=STANDING_REJECTED,
            active_challenges=(),
        )
    # UPHOLD: keep unresolved challenges, restore to pre-challenge standing
    remaining = tuple(
        c for c in previous.active_challenges if c.challenge_id not in set(resolved_ids)
    )
    if remaining:
        return _advance(previous, event, value, active_challenges=remaining)
    # All resolved: restore to ADMITTED (the original pre-challenge standing)
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_ADMITTED,
        active_challenges=(),
    )


def _reject(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in {
        STANDING_PROPOSED,
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_REJECT_TRANSITION_INVALID")
    _require_exact_keys(payload, {"operation", "rejecting_authority_id", "reason_code"})
    _required_token(payload, "rejecting_authority_id", "ALTERNATIVE_MODEL_REJECTING_INVALID")
    _required_token(payload, "reason_code", "ALTERNATIVE_MODEL_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_REJECTED,
        active_challenges=(),
    )


def _expire(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in {
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRE_TRANSITION_INVALID")
    _require_exact_keys(payload, {"operation", "expiry_authority_id", "expiry_receipt_digest"})
    _required_token(payload, "expiry_authority_id", "ALTERNATIVE_MODEL_EXPIRY_AUTHORITY_INVALID")
    _required_digest(payload, "expiry_receipt_digest", "ALTERNATIVE_MODEL_EXPIRY_RECEIPT_INVALID")
    if previous.expires_at_sequence is None:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRY_NOT_DECLARED")
    clock = cast(int, value["clock_sequence"])
    if clock < previous.expires_at_sequence:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EXPIRY_PREMATURE")
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_EXPIRED,
        active_challenges=(),
    )


def _supersede(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    payload: dict[str, Any],
) -> AlternativeModel:
    if previous.separation_status not in {
        STANDING_PROPOSED,
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_SUPERSEDE_TRANSITION_INVALID")
    _require_exact_keys(
        payload,
        {
            "operation",
            "replacement_model_id",
            "superseding_authority_id",
            "supersession_receipt_digest",
            "reason_code",
        },
    )
    replacement = _required_token(
        payload, "replacement_model_id", "ALTERNATIVE_MODEL_REPLACEMENT_ID_INVALID"
    )
    if replacement == previous.model_id:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_SELF_SUPERSESSION")
    _required_token(payload, "superseding_authority_id", "ALTERNATIVE_MODEL_SUPERSEDING_INVALID")
    _required_digest(
        payload, "supersession_receipt_digest", "ALTERNATIVE_MODEL_SUPERSESSION_RECEIPT_INVALID"
    )
    _required_token(payload, "reason_code", "ALTERNATIVE_MODEL_REASON_CODE_INVALID")
    return _advance(
        previous,
        event,
        value,
        separation_status=STANDING_SUPERSEDED,
        active_challenges=(),
        superseded_by_id=replacement,
    )


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _advance(
    previous: AlternativeModel,
    event: RegistryEvent,
    value: dict[str, Any],
    *,
    separation_status: str | None = None,
    admitting_authority_id: str | None = None,
    confirming_authority_id: str | None = None,
    active_challenges: tuple[AlternativeModelChallenge, ...] | None = None,
    superseded_by_id: str | None = None,
) -> AlternativeModel:
    return replace(
        previous,
        separation_status=(
            previous.separation_status if separation_status is None else separation_status
        ),
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
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EVENT_TYPE_INVALID")
    value = event.to_json_value()
    if value.get("registry_type") != "ALTERNATIVE_MODEL":
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_REGISTRY_TYPE_INVALID")
    if value.get("projection_phase") != "ALTERNATIVE_MODEL_REGISTRY":
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_PROJECTION_PHASE_INVALID")
    if value.get("payload_schema_version") != ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_VERSION:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_PAYLOAD_VERSION_INVALID")
    return value


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get("payload")
    if type(payload) is not dict:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_PAYLOAD_INVALID")
    return cast(dict[str, Any], payload)


def _verify_chain(
    previous: AlternativeModel | None,
    event: RegistryEvent,
    value: dict[str, Any],
) -> None:
    if previous is None:
        if (
            value.get("entity_sequence") != 1
            or value.get("previous_entity_event_digest") is not None
        ):
            raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_GENESIS_LINK_INVALID")
        return
    if value.get("entity_id") != previous.model_id:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_IDENTITY_CHANGED")
    if value.get("entity_sequence") != previous.current_entity_sequence + 1:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_ENTITY_SEQUENCE_NOT_SUCCESSOR")
    if value.get("previous_entity_event_digest") != previous.current_event_digest:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_PREDECESSOR_MISMATCH")
    if cast(int, value.get("clock_sequence", 0)) <= previous.last_clock_sequence:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_CLOCK_NOT_ADVANCING")
    if event.digest == previous.current_event_digest:
        raise AlternativeModelRegistryError("ALTERNATIVE_MODEL_EVENT_IDENTITY_REUSED")


def _require_exact_keys(payload: dict[str, Any], expected: set[str]) -> None:
    actual = set(payload)
    missing = expected - actual
    unexpected = actual - expected
    if missing or unexpected:
        raise AlternativeModelRegistryError(
            "ALTERNATIVE_MODEL_PAYLOAD_KEYS_INVALID",
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}",
        )


def _require_status(previous: AlternativeModel, allowed: frozenset[str], code: str) -> None:
    if previous.separation_status not in allowed:
        raise AlternativeModelRegistryError(code, previous.separation_status)


def _required_token(payload: dict[str, Any], field: str, code: str) -> str:
    value = payload.get(field)
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AlternativeModelRegistryError(code)
    return value


def _required_digest(payload: dict[str, Any], field: str, code: str) -> str:
    value = payload.get(field)
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AlternativeModelRegistryError(code)
    return value


def _required_positive_int(payload: dict[str, Any], field: str, code: str) -> int:
    value = payload.get(field)
    if type(value) is not int or isinstance(value, bool) or value < 1:
        raise AlternativeModelRegistryError(code)
    return value


def _optional_positive_int(payload: dict[str, Any], field: str, code: str) -> int | None:
    value = payload.get(field)
    if value is None:
        return None
    if type(value) is not int or isinstance(value, bool) or value < 1:
        raise AlternativeModelRegistryError(code)
    return value


def _required_token_tuple(payload: dict[str, Any], field: str, code: str) -> tuple[str, ...]:
    value = payload.get(field)
    if type(value) is not list:
        raise AlternativeModelRegistryError(code)
    result = tuple(cast(list[str], value))
    _require_sorted_tokens(result, code)
    return result


def _optional_token_tuple(payload: dict[str, Any], field: str, code: str) -> tuple[str, ...]:
    value = payload.get(field)
    if type(value) is not list:
        raise AlternativeModelRegistryError(code)
    result = tuple(cast(list[str], value))
    _require_sorted_tokens(result, code, allow_empty=True)
    return result


def _require_token(value: str, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AlternativeModelRegistryError(code)


def _require_digest(value: str, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AlternativeModelRegistryError(code)


def _require_sorted_tokens(value: tuple[str, ...], code: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, tuple):
        raise AlternativeModelRegistryError(code)
    if not allow_empty and not value:
        raise AlternativeModelRegistryError(code)
    for item in value:
        if type(item) is not str or _TOKEN.fullmatch(item) is None:
            raise AlternativeModelRegistryError(code)
    if tuple(sorted(value)) != value:
        raise AlternativeModelRegistryError(code)
    if len(set(value)) != len(value):
        raise AlternativeModelRegistryError(code)
