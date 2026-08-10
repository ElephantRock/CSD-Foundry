"""Independent serialized-artifact validation for v0.5-D3.1 assumption conformance.

This module mirrors :mod:`csd_foundry.governance.v0_5.evidence_validation` exactly
in structure but re-implements the assumption lifecycle state machine from
:mod:`csd_foundry.governance.v0_5.assumption` independently, reading only the
serialized registry-event envelopes. It MUST NOT import any production
governance module other than ``canonicalization``, ``contracts`` and
``resources``.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, replace
from typing import Any, cast

from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    catalog_digest,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.resources import assumption_vectors

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_REUSE_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}
_MATERIALITIES = {"ADVISORY", "MATERIAL", "CRITICAL"}
_RESOLUTION_OUTCOMES = {"RETURN_TO_ADMITTED", "CONFIRM", "REJECT", "SUPERSEDE"}
_TERMINAL = {"REJECTED", "EXPIRED", "SUPERSEDED"}
_ACTIVE = {"ADMITTED", "CONFIRMED"}
_AUTHORITY_FIELD = {
    "PROPOSE": "proposer_authority_id",
    "ADMIT": "admitting_authority_id",
    "CONFIRM": "confirming_authority_id",
    "CHALLENGE": "challenger_authority_id",
    "RESOLVE_CHALLENGES": "resolver_authority_id",
    "REJECT": "rejecting_authority_id",
    "EXPIRE": "expiry_authority_id",
    "SUPERSEDE": "superseding_authority_id",
}


class AssumptionConformanceError(RuntimeError):
    """Stable independent conformance failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class _IndependentChallenge:
    """Independent record of one unresolved challenge."""

    challenge_id: str
    challenger_authority_id: str
    reason_code: str
    challenge_receipt_digest: str
    opened_at_sequence: int
    opening_event_digest: str


@dataclass(frozen=True, slots=True)
class IndependentAssumptionProjection:
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
    active_challenges: tuple[_IndependentChallenge, ...]
    superseded_by_id: str | None
    proposal_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int

    @property
    def status(self) -> str:
        return "CHALLENGED" if self.active_challenges else self.standing

    @property
    def active_challenge_ids(self) -> tuple[str, ...]:
        return tuple(item.challenge_id for item in self.active_challenges)


@dataclass(frozen=True, slots=True)
class AssumptionRegistryValidationReport:
    accepted_vector_count: int
    rejected_vector_count: int
    accepted_registry_roots: tuple[tuple[str, str], ...]
    accepted_decision_digests: tuple[tuple[str, str], ...]
    rejected_failure_codes: tuple[tuple[str, str], ...]
    vector_catalog_digest: str | None
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "assumption-registry-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
            "accepted_vector_count": self.accepted_vector_count,
            "rejected_vector_count": self.rejected_vector_count,
            "accepted_registry_roots": dict(self.accepted_registry_roots),
            "accepted_decision_digests": dict(self.accepted_decision_digests),
            "rejected_failure_codes": dict(self.rejected_failure_codes),
            "vector_catalog_digest": self.vector_catalog_digest,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report establishes deterministic serialized assumption-history, "
                "authority, lifecycle, dependency, and admissibility behavior relative to "
                "committed conformance vectors and encoded policies. It does not establish "
                "external truth, source completeness, real-world dependency completeness, or "
                "production safety."
            ),
        }


def validate_assumption_registry(
    release: str = "v0.5",
    vectors: dict[str, Any] | None = None,
) -> AssumptionRegistryValidationReport:
    errors: list[str] = []
    catalog = assumption_vectors() if vectors is None else deepcopy(vectors)
    accepted_roots: list[tuple[str, str]] = []
    accepted_decisions: list[tuple[str, str]] = []
    rejected_codes: list[tuple[str, str]] = []

    if release != "v0.5":
        errors.append("assumption registry validation supports only v0.5")
    if type(catalog) is not dict:
        errors.append("assumption vector catalog is not an object")
        catalog = {}
    if catalog.get("schema_version") != "assumption-conformance-vectors/0.5":
        errors.append("assumption vector schema version changed")
    observed_catalog_digest = catalog.get("catalog_digest")
    if observed_catalog_digest != catalog_digest(catalog, b"ASSUMPTION_VECTOR_CATALOG\0"):
        errors.append("assumption vector catalog digest changed")

    try:
        policy = _parse_authority_policy(_object(catalog, "authority_policy"))
    except AssumptionConformanceError as exc:
        errors.append(f"policy: {exc}")
        policy = _empty_policy()

    accepted_values = catalog.get("accepted_vectors", [])
    rejected_values = catalog.get("rejected_vectors", [])
    if type(accepted_values) is not list:
        errors.append("accepted vectors are not an array")
        accepted_values = []
    if type(rejected_values) is not list:
        errors.append("rejected vectors are not an array")
        rejected_values = []

    seen_ids: set[str] = set()
    for raw_vector in cast(list[object], accepted_values):
        vector_id = _vector_id_or_placeholder(raw_vector)
        if vector_id in seen_ids:
            errors.append(f"{vector_id}: duplicate vector id")
            continue
        seen_ids.add(vector_id)
        try:
            vector = _as_object(raw_vector, "ASSUMPTION_VECTOR_NOT_OBJECT")
            result = _validate_history(_array(vector, "events"), policy)
            expected_root = _required_digest(vector, "expected_registry_root")
            actual_root = _snapshot_root(result.projections)
            if actual_root != expected_root:
                raise AssumptionConformanceError("ASSUMPTION_EXPECTED_ROOT_MISMATCH")
            _compare_projections(vector, result.projections)
            expected_decisions = _array(vector, "expected_authority_decision_digests")
            observed_decisions = [
                cast(str, decision["decision_digest"]) for decision in result.authority_decisions
            ]
            if observed_decisions != expected_decisions:
                raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_DECISIONS_MISMATCH")
            request = _object(vector, "use_request")
            decision = _evaluate_use(request, result.projections, policy)
            expected_decision = _object(vector, "expected_admissibility")
            observed_decision = {
                "allowed": decision["allowed"],
                "code": decision["code"],
                "decision_digest": decision["decision_digest"],
            }
            if observed_decision != expected_decision:
                raise AssumptionConformanceError("ASSUMPTION_ADMISSIBILITY_DECISION_MISMATCH")
            accepted_roots.append((vector_id, actual_root))
            accepted_decisions.append((vector_id, cast(str, decision["decision_digest"])))
        except (AssumptionConformanceError, GovernanceContractError) as exc:
            code = exc.code
            errors.append(f"{vector_id}: accepted vector failed with {code}")

    for raw_vector in cast(list[object], rejected_values):
        vector_id = _vector_id_or_placeholder(raw_vector)
        if vector_id in seen_ids:
            errors.append(f"{vector_id}: duplicate vector id")
            continue
        seen_ids.add(vector_id)
        observed: str | None = None
        expected = ""
        try:
            vector = _as_object(raw_vector, "ASSUMPTION_VECTOR_NOT_OBJECT")
            expected = _required_token(vector, "expected_error")
            stage = _required_token(vector, "stage")
            result = _validate_history(_array(vector, "events"), policy)
            if stage == "USE":
                request = _object(vector, "use_request")
                decision = _evaluate_use(request, result.projections, policy)
                if decision["allowed"] is False:
                    observed = cast(str, decision["code"])
            elif stage == "IDENTITY":
                # Verify the committed expected root against the recomputed root.
                expected_root = _required_digest(vector, "expected_registry_root")
                actual_root = _snapshot_root(result.projections)
                if actual_root != expected_root:
                    observed = "ASSUMPTION_EXPECTED_ROOT_MISMATCH"
            elif stage in {"CONTRACT", "AUTHORITY", "HISTORY", "LIFECYCLE"}:
                observed = None
            else:
                observed = "ASSUMPTION_VECTOR_STAGE_INVALID"
        except (AssumptionConformanceError, GovernanceContractError) as exc:
            observed = exc.code
        if observed != expected:
            errors.append(
                f"{vector_id}: expected {expected or 'ERROR'}, observed {observed or 'ACCEPTED'}"
            )
        else:
            rejected_codes.append((vector_id, expected))

    return AssumptionRegistryValidationReport(
        accepted_vector_count=len(accepted_values),
        rejected_vector_count=len(rejected_values),
        accepted_registry_roots=tuple(accepted_roots),
        accepted_decision_digests=tuple(accepted_decisions),
        rejected_failure_codes=tuple(rejected_codes),
        vector_catalog_digest=(
            observed_catalog_digest if type(observed_catalog_digest) is str else None
        ),
        errors=tuple(errors),
    )


@dataclass(frozen=True, slots=True)
class _HistoryResult:
    projections: dict[str, IndependentAssumptionProjection]
    authority_decisions: tuple[dict[str, object], ...]


def _validate_history(events: list[object], policy: dict[str, Any]) -> _HistoryResult:
    projections: dict[str, IndependentAssumptionProjection] = {}
    decisions: list[dict[str, object]] = []
    for raw_event in events:
        event_value = _as_object(raw_event, "ASSUMPTION_EVENT_NOT_OBJECT")
        event = cast(RegistryEvent, RegistryEvent.from_json(event_value))
        value = event.to_json_value()
        if value.get("registry_type") != "ASSUMPTION":
            raise AssumptionConformanceError("ASSUMPTION_REGISTRY_TYPE_INVALID")
        if value.get("projection_phase") != "ASSUMPTION_REGISTRY":
            raise AssumptionConformanceError("ASSUMPTION_PROJECTION_PHASE_INVALID")
        if value.get("payload_schema_version") != "assumption-event/1":
            raise AssumptionConformanceError("ASSUMPTION_PAYLOAD_SCHEMA_INVALID")
        assumption_id = _required_token(value, "entity_id")
        previous = projections.get(assumption_id)
        expected_sequence = 1 if previous is None else previous.current_entity_sequence + 1
        if value.get("entity_sequence") != expected_sequence:
            raise AssumptionConformanceError("ASSUMPTION_SEQUENCE_MISMATCH")
        expected_previous = None if previous is None else previous.current_event_digest
        if value.get("previous_entity_event_digest") != expected_previous:
            raise AssumptionConformanceError("ASSUMPTION_PREDECESSOR_MISMATCH")
        if (
            previous is not None
            and cast(int, value["clock_sequence"]) <= previous.last_clock_sequence
        ):
            raise AssumptionConformanceError("ASSUMPTION_CLOCK_NOT_ADVANCING")
        payload = _object(value, "payload")
        decision = _authority_decision(value, payload, previous, policy)
        decisions.append(decision)
        if decision["allowed"] is not True:
            raise AssumptionConformanceError(cast(str, decision["code"]))
        projections[assumption_id] = _reduce_independent(previous, value, payload)
    return _HistoryResult(projections=projections, authority_decisions=tuple(decisions))


def _reduce_independent(
    previous: IndependentAssumptionProjection | None,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    operation = _required_token(payload, "operation")
    if previous is None:
        if operation != "PROPOSE":
            raise AssumptionConformanceError("ASSUMPTION_FIRST_OPERATION_NOT_PROPOSE")
        return _propose(event, payload)
    if previous.standing in _TERMINAL:
        raise AssumptionConformanceError("ASSUMPTION_TERMINAL_IDENTITY_REUSE")
    if operation == "PROPOSE":
        raise AssumptionConformanceError("ASSUMPTION_DUPLICATE_PROPOSAL")
    if operation == "ADMIT":
        return _admit(previous, event, payload)
    if operation == "CONFIRM":
        return _confirm(previous, event, payload)
    if operation == "CHALLENGE":
        return _challenge(previous, event, payload)
    if operation == "RESOLVE_CHALLENGES":
        return _resolve_challenges(previous, event, payload)
    if operation == "REJECT":
        return _reject(previous, event, payload)
    if operation == "EXPIRE":
        return _expire(previous, event, payload)
    if operation == "SUPERSEDE":
        return _supersede(previous, event, payload)
    raise AssumptionConformanceError("ASSUMPTION_OPERATION_UNSUPPORTED")


def _propose(
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _exact_keys(
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
    proposed_at = _positive_int(payload, "proposed_at_sequence")
    if proposed_at != event["clock_sequence"]:
        raise AssumptionConformanceError("ASSUMPTION_PROPOSAL_CLOCK_MISMATCH")
    materiality = _required_token(payload, "materiality")
    if materiality not in _MATERIALITIES:
        raise AssumptionConformanceError("ASSUMPTION_MATERIALITY_INVALID")
    valid_from = _positive_int(payload, "valid_from_sequence")
    if valid_from < proposed_at:
        raise AssumptionConformanceError("ASSUMPTION_VALIDITY_PRECEDES_PROPOSAL")
    expires = payload.get("expires_at_sequence")
    if expires is not None and (type(expires) is not int or expires <= valid_from):
        raise AssumptionConformanceError("ASSUMPTION_EXPIRY_NOT_AFTER_VALID_FROM")
    assumption_dependency_ids = _token_tuple(payload, "assumption_dependency_ids")
    evidence_dependency_ids = _token_tuple(payload, "evidence_dependency_ids")
    assumption_id = _required_token(event, "entity_id")
    if assumption_id in assumption_dependency_ids:
        raise AssumptionConformanceError("ASSUMPTION_SELF_DEPENDENCY")
    reuse = _required_token(payload, "maximum_reuse_class")
    if reuse not in _REUSE_RANK:
        raise AssumptionConformanceError("ASSUMPTION_REUSE_CLASS_INVALID")
    receipt = _required_digest(event, "source_receipt_digest")
    return IndependentAssumptionProjection(
        assumption_id=assumption_id,
        proposition_id=_required_token(payload, "proposition_id"),
        scope_ids=_token_tuple(payload, "scope_ids", allow_empty=False),
        materiality=materiality,
        proposer_authority_id=_required_token(payload, "proposer_authority_id"),
        admitting_authority_id=None,
        confirming_authority_id=None,
        proposed_at_sequence=proposed_at,
        valid_from_sequence=valid_from,
        expires_at_sequence=expires,
        assumption_dependency_ids=assumption_dependency_ids,
        evidence_dependency_ids=evidence_dependency_ids,
        limitations=_token_tuple(payload, "limitations"),
        maximum_reuse_class=reuse,
        standing="PROPOSED",
        active_challenges=(),
        superseded_by_id=None,
        proposal_source_receipt_digest=receipt,
        current_source_receipt_digest=receipt,
        current_event_digest=_required_digest(event, "registry_event_digest"),
        current_entity_sequence=cast(int, event["entity_sequence"]),
        last_clock_sequence=cast(int, event["clock_sequence"]),
    )


def _admit(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(previous, {"PROPOSED"}, "ASSUMPTION_ADMIT_TRANSITION_INVALID")
    _exact_keys(payload, {"operation", "admitting_authority_id", "admission_receipt_digest"})
    _required_digest(payload, "admission_receipt_digest")
    return _advance(
        previous,
        event,
        standing="ADMITTED",
        admitting_authority_id=_required_token(payload, "admitting_authority_id"),
    )


def _confirm(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(previous, {"ADMITTED"}, "ASSUMPTION_CONFIRM_TRANSITION_INVALID")
    if previous.active_challenges:
        raise AssumptionConformanceError("ASSUMPTION_CONFIRM_WITH_ACTIVE_CHALLENGES")
    _exact_keys(
        payload,
        {"operation", "confirming_authority_id", "confirmation_receipt_digest"},
    )
    _required_digest(payload, "confirmation_receipt_digest")
    return _advance(
        previous,
        event,
        standing="CONFIRMED",
        confirming_authority_id=_required_token(payload, "confirming_authority_id"),
    )


def _challenge(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(previous, _ACTIVE, "ASSUMPTION_CHALLENGE_TRANSITION_INVALID")
    _exact_keys(
        payload,
        {
            "operation",
            "challenge_id",
            "challenger_authority_id",
            "challenge_reason_code",
            "challenge_receipt_digest",
        },
    )
    challenge_id = _required_token(payload, "challenge_id")
    if challenge_id in previous.active_challenge_ids:
        raise AssumptionConformanceError("ASSUMPTION_CHALLENGE_ID_REUSED")
    challenge = _IndependentChallenge(
        challenge_id=challenge_id,
        challenger_authority_id=_required_token(payload, "challenger_authority_id"),
        reason_code=_required_token(payload, "challenge_reason_code"),
        challenge_receipt_digest=_required_digest(payload, "challenge_receipt_digest"),
        opened_at_sequence=cast(int, event["clock_sequence"]),
        opening_event_digest=_required_digest(event, "registry_event_digest"),
    )
    current = tuple(
        sorted((*previous.active_challenges, challenge), key=lambda item: item.challenge_id)
    )
    return _advance(previous, event, active_challenges=current)


def _resolve_challenges(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(previous, _ACTIVE, "ASSUMPTION_RESOLUTION_TRANSITION_INVALID")
    if not previous.active_challenges:
        raise AssumptionConformanceError("ASSUMPTION_RESOLUTION_WITHOUT_ACTIVE_CHALLENGE")
    _exact_keys(
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
    outcome = _required_token(payload, "resolution_outcome")
    if outcome not in _RESOLUTION_OUTCOMES:
        raise AssumptionConformanceError("ASSUMPTION_RESOLUTION_OUTCOME_INVALID")
    _required_token(payload, "resolver_authority_id")
    _required_digest(payload, "resolution_receipt_digest")
    _required_token(payload, "resolution_basis_code")
    resolved_ids = _token_tuple(payload, "resolved_challenge_ids", allow_empty=False)
    active_ids = set(previous.active_challenge_ids)
    unknown = set(resolved_ids) - active_ids
    if unknown:
        raise AssumptionConformanceError("ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN")
    replacement = payload.get("replacement_assumption_id")
    if outcome == "SUPERSEDE":
        replacement_id = _required_token(payload, "replacement_assumption_id")
        if replacement_id == previous.assumption_id:
            raise AssumptionConformanceError("ASSUMPTION_SELF_SUPERSESSION")
    else:
        if replacement is not None:
            raise AssumptionConformanceError("ASSUMPTION_REPLACEMENT_ID_UNEXPECTED")
        replacement_id = None
    remaining = tuple(
        item for item in previous.active_challenges if item.challenge_id not in set(resolved_ids)
    )
    if outcome == "RETURN_TO_ADMITTED":
        standing = "ADMITTED"
    elif outcome == "CONFIRM":
        standing = "CONFIRMED"
    elif outcome == "REJECT":
        standing = "REJECTED"
        remaining = ()
    else:
        standing = "SUPERSEDED"
        remaining = ()
    return _advance(
        previous,
        event,
        standing=standing,
        active_challenges=remaining,
        superseded_by_id=replacement_id,
    )


def _reject(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(
        previous,
        {"PROPOSED", "ADMITTED", "CONFIRMED"},
        "ASSUMPTION_REJECT_TRANSITION_INVALID",
    )
    _exact_keys(
        payload,
        {
            "operation",
            "rejecting_authority_id",
            "rejection_receipt_digest",
            "reason_code",
        },
    )
    _required_digest(payload, "rejection_receipt_digest")
    _required_token(payload, "reason_code")
    return _advance(previous, event, standing="REJECTED", active_challenges=())


def _expire(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(previous, _ACTIVE, "ASSUMPTION_EXPIRE_TRANSITION_INVALID")
    _exact_keys(payload, {"operation", "expiry_authority_id", "expiry_receipt_digest"})
    _required_digest(payload, "expiry_receipt_digest")
    if previous.expires_at_sequence is None:
        raise AssumptionConformanceError("ASSUMPTION_EXPIRY_NOT_DECLARED")
    if cast(int, event["clock_sequence"]) < previous.expires_at_sequence:
        raise AssumptionConformanceError("ASSUMPTION_EXPIRY_PREMATURE")
    return _advance(previous, event, standing="EXPIRED", active_challenges=())


def _supersede(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAssumptionProjection:
    _require_standing(
        previous,
        {"PROPOSED", "ADMITTED", "CONFIRMED"},
        "ASSUMPTION_SUPERSEDE_TRANSITION_INVALID",
    )
    _exact_keys(
        payload,
        {
            "operation",
            "replacement_assumption_id",
            "superseding_authority_id",
            "supersession_receipt_digest",
            "reason_code",
        },
    )
    replacement_id = _required_token(payload, "replacement_assumption_id")
    if replacement_id == previous.assumption_id:
        raise AssumptionConformanceError("ASSUMPTION_SELF_SUPERSESSION")
    _required_digest(payload, "supersession_receipt_digest")
    _required_token(payload, "reason_code")
    return _advance(
        previous,
        event,
        standing="SUPERSEDED",
        active_challenges=(),
        superseded_by_id=replacement_id,
    )


def _advance(
    previous: IndependentAssumptionProjection,
    event: dict[str, Any],
    *,
    standing: str | None = None,
    admitting_authority_id: str | None = None,
    confirming_authority_id: str | None = None,
    active_challenges: tuple[_IndependentChallenge, ...] | None = None,
    superseded_by_id: str | None = None,
) -> IndependentAssumptionProjection:
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
        current_source_receipt_digest=_required_digest(event, "source_receipt_digest"),
        current_event_digest=_required_digest(event, "registry_event_digest"),
        current_entity_sequence=cast(int, event["entity_sequence"]),
        last_clock_sequence=cast(int, event["clock_sequence"]),
    )


def _authority_decision(
    event: dict[str, Any],
    payload: dict[str, Any],
    previous: IndependentAssumptionProjection | None,
    policy: dict[str, Any],
) -> dict[str, object]:
    operation = _required_token(payload, "operation")
    authority_field = _AUTHORITY_FIELD.get(operation)
    if authority_field is None:
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_OPERATION_UNSUPPORTED")
    authority_id = _required_token(payload, authority_field)
    if operation == "PROPOSE":
        scope_ids = _token_tuple(payload, "scope_ids", allow_empty=False)
        materiality = _required_token(payload, "materiality")
        if materiality not in _MATERIALITIES:
            raise AssumptionConformanceError("ASSUMPTION_MATERIALITY_INVALID")
    elif previous is None:
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_PREVIOUS_STATE_MISSING")
    else:
        scope_ids = previous.scope_ids
        materiality = previous.materiality
    if cast(int, event["clock_sequence"]) < cast(int, policy["committed_at_sequence"]):
        code = "ASSUMPTION_AUTHORITY_POLICY_NOT_EFFECTIVE"
        allowed = False
    else:
        allowed = _policy_permits(policy, operation, authority_id, scope_ids, materiality)
        code = "ASSUMPTION_AUTHORITY_PERMITTED" if allowed else "ASSUMPTION_AUTHORITY_DENIED"
    unsigned: dict[str, object] = {
        "schema_version": "assumption-authority-decision/1",
        "allowed": allowed,
        "authority_id": authority_id,
        "authority_root_digest": policy["authority_root_digest"],
        "code": code,
        "event_digest": event["registry_event_digest"],
        "assumption_id": event["entity_id"],
        "operation": operation,
        "policy_digest": policy["policy_digest"],
        "scope_ids": list(scope_ids),
        "materiality": materiality,
    }
    return {
        **unsigned,
        "decision_digest": _domain_digest("ASSUMPTION_AUTHORITY_DECISION", unsigned),
    }


def _evaluate_use(
    request: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
    policy: dict[str, Any],
) -> dict[str, object]:
    _validate_use_request(request)
    work = _WorkCounters()
    try:
        root = _evaluate_node(
            _required_token(request, "assumption_id"),
            request,
            projections,
            visiting=set(),
            visiting_stack=[],
            work=work,
            root=True,
        )
        allowed = True
        code = "ASSUMPTION_USE_ALLOWED"
        event_digest: str | None = root.current_event_digest
    except AssumptionConformanceError as exc:
        allowed = False
        code = exc.code
        current = projections.get(cast(str, request.get("assumption_id")))
        event_digest = None if current is None else current.current_event_digest
    work.finalize()
    unsigned: dict[str, object] = {
        "schema_version": "assumption-use-admissibility-decision/1",
        "allowed": allowed,
        "authority_policy_digest": policy["policy_digest"],
        "code": code,
        "assumption_id": request["assumption_id"],
        "decision_id": request["decision_id"],
        "assumption_event_digest": event_digest,
        "request_digest": request["request_digest"],
        "assumption_histories_reconstructed": work.histories,
        "assumption_events_replayed": work.events,
        "unique_assumption_nodes_evaluated": work.unique_nodes,
        "assumption_dependency_edges_examined": work.dep_edges,
        "evidence_dependency_references_evaluated": work.evidence_refs,
        "active_challenges_evaluated": work.challenges,
        "work_digest": work.work_digest,
    }
    return {
        **unsigned,
        "decision_digest": _domain_digest("ASSUMPTION_USE_ADMISSIBILITY_DECISION", unsigned),
    }


@dataclass
class _WorkCounters:
    histories: int = 0
    events: int = 0
    unique_nodes: int = 0
    dep_edges: int = 0
    evidence_refs: int = 0
    challenges: int = 0
    work_digest: str = ""

    def finalize(self) -> None:
        unsigned: dict[str, object] = {
            "schema_version": "assumption-evaluation-work/1",
            "assumption_histories_reconstructed": self.histories,
            "assumption_events_replayed": self.events,
            "authority_decisions_evaluated": 0,
            "unique_assumption_nodes_evaluated": self.unique_nodes,
            "assumption_dependency_edges_examined": self.dep_edges,
            "evidence_dependency_references_evaluated": self.evidence_refs,
            "active_challenges_evaluated": self.challenges,
            "separation_duty_rules_evaluated": 0,
        }
        self.work_digest = _domain_digest("ASSUMPTION_EVALUATION_WORK", unsigned)


def _evaluate_node(
    assumption_id: str,
    request: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
    *,
    visiting: set[str],
    visiting_stack: list[str],
    work: _WorkCounters,
    root: bool,
) -> IndependentAssumptionProjection:
    if assumption_id in visiting:
        raise AssumptionConformanceError("ASSUMPTION_USE_DEPENDENCY_CYCLE")
    visiting.add(assumption_id)
    visiting_stack.append(assumption_id)
    assumption = projections.get(assumption_id)
    if assumption is None:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError(
            "ASSUMPTION_USE_MISSING" if root else "ASSUMPTION_USE_DEPENDENCY_MISSING"
        )
    work.histories += 1
    work.events += assumption.current_entity_sequence
    work.unique_nodes += 1
    work.challenges += len(assumption.active_challenges)
    if root and assumption.proposition_id != request["proposition_id"]:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_PROPOSITION_MISMATCH")
    if not set(cast(list[str], request["scope_ids"])).issubset(assumption.scope_ids):
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_SCOPE_INSUFFICIENT")
    # Gate precedence matches production _evaluate_one_assumption exactly:
    # TERMINAL > NOT_ADMITTED > CHALLENGED > NOT_YET_VALID > EXPIRED.
    if assumption.standing in _TERMINAL:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_TERMINAL")
    if assumption.standing not in _ACTIVE:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_NOT_ADMITTED")
    if assumption.active_challenges:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_CHALLENGED")
    clock = cast(int, request["clock_sequence"])
    if clock < assumption.valid_from_sequence:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_NOT_YET_VALID")
    if assumption.expires_at_sequence is not None and clock >= assumption.expires_at_sequence:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_EXPIRED")
    required_reuse = cast(str, request["required_reuse_class"])
    if _REUSE_RANK[required_reuse] > _REUSE_RANK[assumption.maximum_reuse_class]:
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_REUSE_CLASS_INSUFFICIENT")
    accepted_limitations = set(cast(list[str], request["accepted_limitation_codes"]))
    if not set(assumption.limitations).issubset(accepted_limitations):
        visiting.discard(assumption_id)
        visiting_stack.pop()
        raise AssumptionConformanceError("ASSUMPTION_USE_LIMITATION_NOT_ACCEPTED")
    for evidence_id in assumption.evidence_dependency_ids:
        work.evidence_refs += 1
        _evaluate_evidence_dependency(
            evidence_id,
            request,
            assumption,
        )
    for dependency_id in assumption.assumption_dependency_ids:
        work.dep_edges += 1
        _evaluate_node(
            dependency_id,
            request,
            projections,
            visiting=visiting,
            visiting_stack=visiting_stack,
            work=work,
            root=False,
        )
    visiting.discard(assumption_id)
    visiting_stack.pop()
    return assumption


def _evaluate_evidence_dependency(
    evidence_id: str,
    request: dict[str, Any],
    owner: IndependentAssumptionProjection,
) -> None:
    """Independently rebuild the evidence-use request digest and require it.

    The assumption corpus pins a ``use_request`` whose evidence bindings are
    serialized. Each evidence dependency carries a rebuilt request digest; if
    the rebuilt request does not match the pinned value, the substitution is
    detected.
    """

    evidence_requests = _object(request, "evidence_requests")
    expected_request = evidence_requests.get(evidence_id)
    if expected_request is None:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUEST_MISSING")
    rebuilt = {
        "schema_version": "evidence-use-request/1",
        "decision_id": request["decision_id"],
        "evidence_id": evidence_id,
        "proposition_id": owner.proposition_id,
        "scope_ids": sorted(owner.scope_ids),
        "required_reuse_class": owner.maximum_reuse_class,
        "clock_sequence": request["clock_sequence"],
        "accepted_limitation_codes": sorted(owner.limitations),
    }
    expected_digest = _domain_digest("EVIDENCE_USE_REQUEST", rebuilt)
    if expected_request.get("request_digest") != expected_digest:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUEST_MISMATCH")
    receipt = _object(expected_request, "admissibility_receipt")
    if receipt.get("allowed") is not True:
        code = receipt.get("code", "EVIDENCE_INADMISSIBLE")
        raise AssumptionConformanceError(code)


def _validate_use_request(request: dict[str, Any]) -> None:
    _exact_keys(
        request,
        {
            "schema_version",
            "accepted_limitation_codes",
            "clock_sequence",
            "decision_id",
            "assumption_id",
            "proposition_id",
            "required_reuse_class",
            "scope_ids",
            "request_digest",
            "evidence_requests",
        },
        code="ASSUMPTION_USE_REQUEST_KEYS_INVALID",
    )
    if request.get("schema_version") != "assumption-use-request/1":
        raise AssumptionConformanceError("ASSUMPTION_USE_REQUEST_SCHEMA_INVALID")
    _required_token(request, "decision_id")
    _required_token(request, "assumption_id")
    _required_token(request, "proposition_id")
    _token_tuple(request, "scope_ids", allow_empty=False)
    _token_tuple(request, "accepted_limitation_codes")
    reuse = _required_token(request, "required_reuse_class")
    if reuse not in _REUSE_RANK:
        raise AssumptionConformanceError("ASSUMPTION_USE_REUSE_CLASS_INVALID")
    if type(request.get("clock_sequence")) is not int or cast(int, request["clock_sequence"]) < 0:
        raise AssumptionConformanceError("ASSUMPTION_USE_CLOCK_INVALID")
    if type(request.get("evidence_requests")) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUESTS_INVALID")
    expected = _domain_digest(
        "ASSUMPTION_USE_REQUEST",
        {
            key: value
            for key, value in request.items()
            if key not in {"request_digest", "evidence_requests"}
        },
    )
    if request.get("request_digest") != expected:
        raise AssumptionConformanceError("ASSUMPTION_USE_REQUEST_DIGEST_MISMATCH")


def _parse_authority_policy(value: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        value,
        {
            "schema_version",
            "authority_root_digest",
            "committed_at_sequence",
            "grants",
            "policy_id",
            "policy_digest",
        },
        code="ASSUMPTION_AUTHORITY_POLICY_KEYS_INVALID",
    )
    if value.get("schema_version") != "assumption-authority-policy/1":
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_POLICY_SCHEMA_INVALID")
    _required_token(value, "policy_id")
    _required_digest(value, "authority_root_digest")
    if (
        type(value.get("committed_at_sequence")) is not int
        or cast(int, value["committed_at_sequence"]) < 0
    ):
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_POLICY_SEQUENCE_INVALID")
    grants = _array(value, "grants")
    canonical: list[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = []
    for raw_grant in grants:
        grant = _as_object(raw_grant, "ASSUMPTION_AUTHORITY_GRANT_INVALID")
        _exact_keys(
            grant,
            {"grant_id", "action", "authority_id", "scope_ids", "assumption_materialities"},
            code="ASSUMPTION_AUTHORITY_GRANT_KEYS_INVALID",
        )
        _required_token(grant, "grant_id")
        action = _required_token(grant, "action")
        if action not in _AUTHORITY_FIELD:
            raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_ACTION_INVALID")
        scopes = _token_tuple(grant, "scope_ids", allow_empty=False)
        materialities = _token_tuple(grant, "assumption_materialities", allow_empty=False)
        for mat in materialities:
            if mat not in _MATERIALITIES:
                raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_MATERIALITY_INVALID")
        canonical.append(
            (
                cast(str, grant["grant_id"]),
                action,
                scopes,
                materialities,
            )
        )
    if canonical != sorted(canonical) or len(set(canonical)) != len(canonical) or not canonical:
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANTS_NOT_CANONICAL")
    expected = _domain_digest(
        "ASSUMPTION_AUTHORITY_POLICY",
        {key: item for key, item in value.items() if key != "policy_digest"},
    )
    if value.get("policy_digest") != expected:
        raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_POLICY_DIGEST_MISMATCH")
    return value


def _policy_permits(
    policy: dict[str, Any],
    operation: str,
    authority_id: str,
    scope_ids: tuple[str, ...],
    materiality: str,
) -> bool:
    requested = set(scope_ids)
    for raw_grant in cast(list[object], policy["grants"]):
        grant = cast(dict[str, Any], raw_grant)
        if grant["action"] != operation or grant["authority_id"] != authority_id:
            continue
        if materiality not in set(cast(list[str], grant["assumption_materialities"])):
            continue
        granted = set(cast(list[str], grant["scope_ids"]))
        if "scope:*" in granted or requested.issubset(granted):
            return True
    return False


def _compare_projections(
    vector: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
) -> None:
    expected_statuses = _object(vector, "expected_statuses")
    expected_digests = _object(vector, "expected_current_event_digests")
    observed_statuses = {key: projections[key].status for key in sorted(projections)}
    observed_digests = {key: projections[key].current_event_digest for key in sorted(projections)}
    if observed_statuses != expected_statuses or observed_digests != expected_digests:
        raise AssumptionConformanceError("ASSUMPTION_PROJECTION_MISMATCH")


def _snapshot_root(projections: dict[str, IndependentAssumptionProjection]) -> str:
    value = {
        "schema_version": "registry-snapshot/1",
        "registry_type": "ASSUMPTION",
        "heads": [
            {
                "entity_id": item.assumption_id,
                "entity_sequence": item.current_entity_sequence,
                "event_digest": item.current_event_digest,
            }
            for item in (projections[key] for key in sorted(projections))
        ],
    }
    return "sha256:" + hashlib.sha256(b"REGISTRY_SNAPSHOT\0" + _compact_bytes(value)).hexdigest()


def _domain_digest(domain: str, value: object) -> str:
    return (
        "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + _json_bytes(value)).hexdigest()
    )


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _compact_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    code: str = "ASSUMPTION_PAYLOAD_KEYS_INVALID",
) -> None:
    if set(value) != expected:
        raise AssumptionConformanceError(code)


def _require_status(
    previous: IndependentAssumptionProjection,
    allowed: set[str],
    code: str,
) -> None:
    if previous.standing not in allowed:
        raise AssumptionConformanceError(code)


def _require_standing(
    previous: IndependentAssumptionProjection,
    allowed: set[str],
    code: str,
) -> None:
    if previous.standing not in allowed:
        raise AssumptionConformanceError(code)


def _positive_int(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 1:
        raise AssumptionConformanceError("ASSUMPTION_POSITIVE_INTEGER_INVALID", field)
    return item


def _token_tuple(
    value: dict[str, Any],
    field: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    item = value.get(field)
    if type(item) is not list or any(type(member) is not str for member in item):
        raise AssumptionConformanceError("ASSUMPTION_TOKEN_ARRAY_INVALID", field)
    result = tuple(cast(list[str], item))
    if (not allow_empty and not result) or result != tuple(sorted(result)):
        raise AssumptionConformanceError("ASSUMPTION_TOKEN_ARRAY_INVALID", field)
    if len(set(result)) != len(result):
        raise AssumptionConformanceError("ASSUMPTION_TOKEN_ARRAY_INVALID", field)
    for member in result:
        if _TOKEN.fullmatch(member) is None:
            raise AssumptionConformanceError("ASSUMPTION_TOKEN_ARRAY_INVALID", field)
    return result


def _required_token(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _TOKEN.fullmatch(item) is None:
        raise AssumptionConformanceError("ASSUMPTION_TOKEN_INVALID", field)
    return item


def _required_digest(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _DIGEST.fullmatch(item) is None:
        raise AssumptionConformanceError("ASSUMPTION_DIGEST_INVALID", field)
    return item


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    item = value.get(field)
    if type(item) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _as_object(value: object, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise AssumptionConformanceError(code)
    return cast(dict[str, Any], value)


def _array(value: dict[str, Any], field: str) -> list[object]:
    item = value.get(field)
    if type(item) is not list:
        raise AssumptionConformanceError("ASSUMPTION_ARRAY_INVALID", field)
    return cast(list[object], item)


def _vector_id_or_placeholder(value: object) -> str:
    if type(value) is dict and type(value.get("vector_id")) is str:
        return cast(str, value["vector_id"])
    return "<invalid-vector-id>"


def _empty_policy() -> dict[str, Any]:
    return {
        "committed_at_sequence": 0,
        "authority_root_digest": "sha256:" + "0" * 64,
        "grants": [],
        "policy_digest": "sha256:" + "0" * 64,
    }
