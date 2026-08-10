"""Independent serialized-artifact validation for v0.5-D3.2 assumption conformance.

This module mirrors :mod:`csd_foundry.governance.v0_5.evidence_validation` exactly
in structure but re-implements the assumption lifecycle state machine, the I1-B
separation-of-duty evaluator, the I1-C admission-time dependency validator, and
the D3.2-B use-time admissibility evaluator from the production governance
modules, reading only the serialized registry-event envelopes and the serialized
V3 policy context. It MUST NOT import any production governance module other
than ``canonicalization``, ``contracts`` and ``resources``.

What this validator independently reimplements (and therefore independently
detects tampering of):

* V3 policy resolution at an admission clock, with half-open
  ``[effective_from_sequence, effective_until_sequence)`` interval semantics.
* Applicable grant selection (action / authority / scope / materiality /
  effective interval) with deterministic ``SELECTED`` /
  ``NO_APPLICABLE_GRANT`` / ``AMBIGUOUS_GRANTS`` outcomes.
* B0 prior-role derivation from the assumption event history (operation ->
  governance-role total function, prior-to-candidate-entity-sequence).
* Per-rule separation-of-duty conflict evaluation with bounded per-rule
  exceptions (a waiver relaxes one named rule; it does not waive a role
  globally).
* The I1-C admission-time dependency gate: exact pre-ADMIT state, assumption
  dependency DFS (existence + reconstructability + acyclicity), evidence
  admission eligibility, candidate predecessor binding, root stability.
* The D3.2-B use-time evaluator: self-gates (standing / challenge / temporal),
  followed by complete assumption DFS, followed (only after a successful DFS) by
  the evidence phase. Multi-assumption ``DecisionAssumptionBinding``-shaped
  requests are evaluated for every required assumption, with cross-evaluation
  deduplication of shared dependency nodes for work counters.
* Full D2 ``EvidenceUseRequest`` + ``EvidenceAdmissibilityReceipt`` rebuilding
  and verification from the owner assumption's projected state.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass, field, replace
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
_MATERIALITIES = ("ADVISORY", "MATERIAL", "CRITICAL")
_RESOLUTION_OUTCOMES = {"RETURN_TO_ADMITTED", "CONFIRM", "REJECT", "SUPERSEDE"}
_TERMINAL = {"REJECTED", "EXPIRED", "SUPERSEDED"}
_ACTIVE = {"ADMITTED", "CONFIRMED"}
# Frozen authority-action vocabulary, replicated from
# _assumption_governance_contracts. Lifecycle operations map onto these
# authority actions; RESOLVE_CHALLENGES expands to one of the four
# RESOLVE_TO_* actions via the resolution_outcome.
_AUTHORITY_ACTIONS = (
    "ADMIT",
    "CHALLENGE",
    "CONFIRM",
    "EXPIRE",
    "PROPOSE",
    "REJECT",
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
    "SUPERSEDE",
)
_RESOLUTION_AUTHORITY_ACTIONS = (
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
)
# Frozen resolution_outcome -> authority action expansion.
_OUTCOME_TO_ACTION = {
    "RETURN_TO_ADMITTED": "RESOLVE_TO_ADMITTED",
    "CONFIRM": "RESOLVE_TO_CONFIRMED",
    "REJECT": "RESOLVE_TO_REJECTED",
    "SUPERSEDE": "RESOLVE_TO_SUPERSEDED",
}
# Frozen governance-role vocabulary, replicated from
# _assumption_governance_contracts. Used to derive prior roles in frozen order
# for the I1-B separation-of-duty evaluator.
_ASSUMPTION_GOVERNANCE_ROLES = (
    "ADMITTER",
    "CHALLENGER",
    "CONFIRMER",
    "EXPIRY_AUTHORITY",
    "PROPOSER",
    "REJECTOR",
    "RESOLVER",
    "SUPERSEDER",
)
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
# Frozen operation -> governance-role mapping, replicated from
# _assumption_governance_role_derivation. Every lifecycle operation carries
# exactly one authority-identity field; each yields exactly one role.
_OPERATION_TO_ROLE: dict[str, str] = {
    "PROPOSE": "PROPOSER",
    "ADMIT": "ADMITTER",
    "CONFIRM": "CONFIRMER",
    "CHALLENGE": "CHALLENGER",
    "RESOLVE_CHALLENGES": "RESOLVER",
    "REJECT": "REJECTOR",
    "EXPIRE": "EXPIRY_AUTHORITY",
    "SUPERSEDE": "SUPERSEDER",
}
_GLOBAL_SCOPE = "scope:*"
_AUTHORITY_GRANT_SCHEMA_VERSION = "assumption-authority-grant/1"
_SEPARATION_DUTY_RULE_SCHEMA_VERSION = "assumption-separation-duty-rule/1"
_DUTY_EXCEPTION_SCHEMA_VERSION = "assumption-duty-exception/1"
_AUTHORITY_POLICY_SCHEMA_VERSION = "assumption-authority-policy/1"
_EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION = "evidence-admission-eligibility/1"
_ADMISSION_DEPENDENCY_RECEIPT_SCHEMA_VERSION = "assumption-dependency-validation/1"
# Defect #1: schema versions and domain strings for the production-equivalent
# Governed-ADMIT receipt chain (I1-C dep receipt + I1-B SoD decisions + D3.2-A3.2
# governed authorization).
_GOVERNED_ADMIT_AUTHORIZATION_SCHEMA_VERSION = "assumption-governed-admit-authorization/1"
_SOD_DECISION_SCHEMA_VERSION = "assumption-separation-of-duty-decision/1"
_GRANT_SELECTION_DECISION_SCHEMA_VERSION = "assumption-grant-selection-decision/1"
_SOD_DOMAIN = "ASSUMPTION_SEPARATION_OF_DUTY_DECISION"


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
    # Chain of authority-bearing events (entity_sequence, operation, authority_id,
    # clock_sequence, event_digest) for B0 prior-role derivation at any candidate
    # position. Captured during reduction so the SoD evaluator never re-derives
    # roles from raw events.
    role_history: tuple[tuple[int, str, str, int, str], ...] = field(default=())

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
                "authority, lifecycle, dependency, separation-of-duty, and use-time "
                "admissibility behavior relative to committed conformance vectors and "
                "the encoded V3 policy context. It does not establish external truth, "
                "source completeness, real-world dependency completeness, or production "
                "safety."
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
        policy_context = _parse_policy_context(_object(catalog, "authority_policy"))
    except AssumptionConformanceError as exc:
        errors.append(f"policy: {exc}")
        policy_context = _empty_policy_context()

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
            result = _validate_history(_array(vector, "events"), policy_context)
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
            binding = _object(vector, "use_binding")
            decision = _evaluate_use(binding, result.projections, policy_context, actual_root)
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
            result = _validate_history(_array(vector, "events"), policy_context)
            if stage == "USE":
                binding = _object(vector, "use_binding")
                actual_root = _snapshot_root(result.projections)
                decision = _evaluate_use(binding, result.projections, policy_context, actual_root)
                if decision["allowed"] is False:
                    observed = cast(str, decision["code"])
            elif stage == "IDENTITY":
                expected_root = _required_digest(vector, "expected_registry_root")
                actual_root = _snapshot_root(result.projections)
                if actual_root != expected_root:
                    observed = "ASSUMPTION_EXPECTED_ROOT_MISMATCH"
            elif stage in {"CONTRACT", "AUTHORITY", "HISTORY", "LIFECYCLE", "ADMISSION"}:
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
    # Ordered list of events (entity_id, event_value) in the order encountered,
    # used to reconstruct per-entity history tuples for B0 role derivation.
    events_in_order: tuple[tuple[str, dict[str, Any]], ...] = field(default=())


def _validate_history(
    events: list[object],
    policy_context: dict[str, Any],
) -> _HistoryResult:
    projections: dict[str, IndependentAssumptionProjection] = {}
    decisions: list[dict[str, object]] = []
    events_in_order: list[tuple[str, dict[str, Any]]] = []
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
        operation = _required_token(payload, "operation")
        decision = _authority_decision(value, payload, previous, policy_context, projections)
        decisions.append(decision)
        if decision["allowed"] is not True:
            raise AssumptionConformanceError(cast(str, decision["code"]))
        # I1-C admission-time dependency gate. ADMIT must independently validate
        # the immutable dependencies before the projection advances. The gate
        # runs only when the prior state is PROPOSED (a valid ADMIT transition);
        # any other prior standing is rejected by the lifecycle reducer below
        # with the appropriate transition code, which takes precedence.
        if operation == "ADMIT" and previous is not None and previous.standing == "PROPOSED":
            _validate_admission_dependencies(previous, value, projections, policy_context)
        projections[assumption_id] = _reduce_independent(previous, value, payload)
        events_in_order.append((assumption_id, value))
    return _HistoryResult(
        projections=projections,
        authority_decisions=tuple(decisions),
        events_in_order=tuple(events_in_order),
    )


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
    authority_id = _required_token(payload, "proposer_authority_id")
    clock = cast(int, event["clock_sequence"])
    seq = cast(int, event["entity_sequence"])
    event_digest = _required_digest(event, "registry_event_digest")
    return IndependentAssumptionProjection(
        assumption_id=assumption_id,
        proposition_id=_required_token(payload, "proposition_id"),
        scope_ids=_token_tuple(payload, "scope_ids", allow_empty=False),
        materiality=materiality,
        proposer_authority_id=authority_id,
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
        current_event_digest=event_digest,
        current_entity_sequence=seq,
        last_clock_sequence=clock,
        role_history=((seq, "PROPOSE", authority_id, clock, event_digest),),
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
    operation = _required_token(_object(event, "payload"), "operation")
    authority_field = _AUTHORITY_FIELD[operation]
    authority_id = _required_token(_object(event, "payload"), authority_field)
    clock = cast(int, event["clock_sequence"])
    seq = cast(int, event["entity_sequence"])
    event_digest = _required_digest(event, "registry_event_digest")
    role_history = (*previous.role_history, (seq, operation, authority_id, clock, event_digest))
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
        current_event_digest=event_digest,
        current_entity_sequence=seq,
        last_clock_sequence=clock,
        role_history=role_history,
    )


# =====================================================================
# I1-A: V3 policy resolution + grant selection (independently replicated).
# =====================================================================


def _resolve_policy_at(
    policy_context: dict[str, Any],
    event_sequence: int,
) -> dict[str, Any]:
    """Resolve the active ledger entry at ``event_sequence``.

    Walks the ledger entries in reverse, returning the unique entry whose
    half-open ``[effective_from_sequence, +inf)`` interval contains
    ``event_sequence``. ``event_sequence`` precedes the genesis entry's
    effective_from_sequence raises (no policy active).
    """
    entries = cast(list[dict[str, Any]], policy_context["ledger_entries"])
    for entry in reversed(entries):
        if cast(int, entry["effective_from_sequence"]) <= event_sequence:
            return dict(entry)
    raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_POLICY_NOT_EFFECTIVE")


def _scope_covers_request(scope_id: str, grant_scopes: tuple[str, ...]) -> bool:
    """A global grant set covers any request scope; else exact membership."""
    return grant_scopes == (_GLOBAL_SCOPE,) or scope_id in grant_scopes


def _select_applicable_grant(
    resolved_entry: dict[str, Any],
    *,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    event_sequence: int,
    challenge_materiality: str = "",
) -> tuple[str, dict[str, Any] | None]:
    """Select exactly one applicable grant or deny with NO_APPLICABLE_GRANT /
    AMBIGUOUS_GRANTS. Returns ``(decision_type, grant_or_none)``.

    A grant is applicable iff action, authority, scope (global-or-exact),
    materiality, challenge materiality (resolution grants only), and the
    half-open effective interval all match. Exactly one applicable grant
    yields SELECTED; zero yields NO_APPLICABLE_GRANT; two or more yields
    AMBIGUOUS_GRANTS (fail-closed).
    """
    is_resolution = action in _RESOLUTION_AUTHORITY_ACTIONS
    matches: list[dict[str, Any]] = []
    for grant in cast(list[dict[str, Any]], resolved_entry["grants"]):
        if cast(str, grant["action"]) != action:
            continue
        if cast(str, grant["authority_id"]) != authority_id:
            continue
        if not _scope_covers_request(scope_id, tuple(cast(list[str], grant["scope_ids"]))):
            continue
        if assumption_materiality not in set(cast(list[str], grant["assumption_materialities"])):
            continue
        if is_resolution:
            grant_challenge_materialities = tuple(
                cast(list[str], grant.get("challenge_materialities", []))
            )
            if not grant_challenge_materialities:
                continue
            if challenge_materiality not in grant_challenge_materialities:
                continue
        eff_from = cast(int, grant["effective_from_sequence"])
        eff_until = grant.get("effective_until_sequence")
        if event_sequence < eff_from:
            continue
        if eff_until is not None and event_sequence >= cast(int, eff_until):
            continue
        matches.append(grant)
    if not matches:
        return "NO_APPLICABLE_GRANT", None
    if len(matches) == 1:
        return "SELECTED", matches[0]
    return "AMBIGUOUS_GRANTS", None


def _derive_prior_roles(
    previous: IndependentAssumptionProjection | None,
    *,
    authority_id: str,
    candidate_entity_sequence: int,
) -> tuple[str, ...]:
    """Return the canonical set of governance roles an authority performed
    prior to the candidate position, in frozen _OPERATION_TO_ROLE-image order.

    Prior means events at entity_sequence strictly less than
    ``candidate_entity_sequence``. Roles are deduplicated.
    """
    if previous is None:
        return ()
    observed: set[str] = set()
    for seq, _operation, auth_id, _clock, _digest in previous.role_history:
        if seq >= candidate_entity_sequence:
            break
        if auth_id == authority_id:
            observed.add(_OPERATION_TO_ROLE[_operation])
    # Frozen role order: ASSUMPTION_GOVERNANCE_ROLES is the authoritative
    # tuple; correctness depends on tuple order, not on the _OPERATION_TO_ROLE
    # image happening to share it.
    return tuple(role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in observed)


def _authority_action_for(operation: str, payload: dict[str, Any]) -> str:
    """Map a lifecycle operation (and its payload) onto the frozen authority
    action vocabulary. For seven operations the action equals the operation;
    for ``RESOLVE_CHALLENGES`` the action expands to one of the four
    ``RESOLVE_TO_*`` actions via the resolution_outcome."""
    if operation != "RESOLVE_CHALLENGES":
        return operation
    outcome = _required_token(payload, "resolution_outcome")
    if outcome not in _OUTCOME_TO_ACTION:
        raise AssumptionConformanceError("ASSUMPTION_RESOLUTION_OUTCOME_INVALID")
    return _OUTCOME_TO_ACTION[outcome]


def _challenge_materiality_for(
    operation: str,
    payload: dict[str, Any],
    previous: IndependentAssumptionProjection | None,
    policy_context: dict[str, Any],
) -> str:
    """Derive the challenge materiality of the resolved challenge(s) for a
    RESOLVE_CHALLENGES candidate. Resolution grants bind to the challenge's
    materiality, which is a SEPARATE dimension from the assumption's own
    materiality.

    Defect #4: challenge materiality is derived from the serialized
    ``challenge_classifications`` map (reason_code -> materiality) in the policy
    context, NOT synthesized from the assumption's materiality. Production
    treats ``assumption_materialities`` and ``challenge_materialities`` as
    independent dimensions; a CRITICAL assumption can carry an ADVISORY
    challenge (or vice versa).
    """
    if operation != "RESOLVE_CHALLENGES" or previous is None:
        return ""
    resolved_ids = _token_tuple(payload, "resolved_challenge_ids", allow_empty=False)
    challenge_by_id = {item.challenge_id: item for item in previous.active_challenges}
    classifications: dict[str, str] = dict(
        cast(dict[str, str], policy_context.get("challenge_classifications", {}))
    )

    def _classify(challenge: _IndependentChallenge) -> str:
        mat = classifications.get(challenge.reason_code)
        if mat is None:
            raise AssumptionConformanceError(
                "ASSUMPTION_CHALLENGE_MATERIALITY_UNCLASSIFIED", challenge.reason_code
            )
        if mat not in _MATERIALITIES:
            raise AssumptionConformanceError("ASSUMPTION_CHALLENGE_MATERIALITY_INVALID", mat)
        return mat

    # Derive the materiality of the first KNOWN resolved challenge from its
    # reason_code via the classification map. A resolved challenge that is NOT
    # active (unknown) cannot be classified; the lifecycle reducer will catch it
    # with ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN. To let the authority gate
    # proceed in that case, fall back to the materiality of any active challenge
    # on the assumption.
    for cid in resolved_ids:
        challenge = challenge_by_id.get(cid)
        if challenge is not None:
            return _classify(challenge)
    # No resolved challenge is active: fall back to the first active challenge's
    # classified materiality (if any), so the authority gate is evaluated against
    # a valid materiality and the lifecycle reducer catches the unknown set.
    if previous.active_challenges:
        return _classify(previous.active_challenges[0])
    return ""


# =====================================================================
# I1-B: separation-of-duty evaluation (independently replicated).
# =====================================================================


def _evaluate_separation_of_duty(
    *,
    resolved_entry: dict[str, Any],
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    event_sequence: int,
    previous: IndependentAssumptionProjection | None,
    candidate_entity_sequence: int,
    challenge_materiality: str = "",
) -> str:
    """Independently evaluate separation-of-duty for one candidate action.

    Returns ``"ALLOW"`` or ``"DENY"``. Recomputes the I1-A grant selection,
    derives B0 prior roles, and evaluates every applicable duty rule with its
    exact per-rule bounded exceptions. An authority denial short-circuits to
    DENY without evaluating B0 history (an exception never creates authority).
    """
    decision_type, _grant = _select_applicable_grant(
        resolved_entry,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        event_sequence=event_sequence,
        challenge_materiality=challenge_materiality,
    )
    if decision_type != "SELECTED":
        return "DENY"
    prior_roles = set(
        _derive_prior_roles(
            previous,
            authority_id=authority_id,
            candidate_entity_sequence=candidate_entity_sequence,
        )
    )
    rules = cast(list[dict[str, Any]], resolved_entry.get("duty_rules", []))
    exceptions = cast(list[dict[str, Any]], resolved_entry.get("duty_exceptions", []))
    for rule in rules:
        if cast(str, rule["action"]) != action:
            continue
        if not _scope_covers_request(scope_id, tuple(cast(list[str], rule["scope_ids"]))):
            continue
        if assumption_materiality not in set(cast(list[str], rule["assumption_materialities"])):
            continue
        rule_conflicts = prior_roles & set(cast(list[str], rule["conflicting_roles"]))
        if not rule_conflicts:
            continue
        rule_waived: set[str] = set()
        for exception in exceptions:
            if cast(str, exception["rule_id"]) != cast(str, rule["rule_id"]):
                continue
            if cast(str, exception["action"]) != action:
                continue
            if cast(str, exception["authority_id"]) != authority_id:
                continue
            if not _scope_covers_request(scope_id, tuple(cast(list[str], exception["scope_ids"]))):
                continue
            if assumption_materiality not in set(
                cast(list[str], exception["assumption_materialities"])
            ):
                continue
            exc_assumptions = cast(list[str], exception.get("assumption_ids", []))
            if exc_assumptions and (
                previous is None or previous.assumption_id not in exc_assumptions
            ):
                continue
            eff_from = cast(int, exception["effective_from_sequence"])
            eff_until = cast(int, exception["effective_until_sequence"])
            if not (eff_from <= event_sequence < eff_until):
                continue
            waived_by_this = set(cast(list[str], exception["conflicting_roles"])) & rule_conflicts
            rule_waived |= waived_by_this
        remaining = rule_conflicts - rule_waived
        if remaining:
            return "DENY"
    return "ALLOW"


# =====================================================================
# I1-C: admission-time dependency gate (independently replicated).
# =====================================================================


def _validate_admission_dependencies(
    previous: IndependentAssumptionProjection | None,
    admit_event: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
    policy_context: dict[str, Any],
) -> None:
    """Independently validate the immutable dependencies BEFORE ADMIT.

    Phase order (matches production _assumption_dependency_validator):
    1. exact pre-ADMIT state (PROPOSED, seq 1);
    2. assumption dependency DFS (existence + reconstructability + acyclicity);
    3. evidence admission eligibility.

    The evidence phase here is a structural A0-style check: the candidate's
    evidence_dependency_ids must each have a pinned admission_receipt in the
    serialized policy context (the fixture's evidence registry), and the
    receipt must be eligible at the ADMIT clock.
    """
    if previous is None:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_NO_PRIOR")
    if previous.standing != "PROPOSED":
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_NOT_PROPOSED")
    if previous.current_entity_sequence != 1:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_NOT_GENESIS")
    admit_clock = cast(int, admit_event["clock_sequence"])
    if admit_clock <= previous.last_clock_sequence:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_CLOCK_NOT_ADVANCING")
    # Candidate predecessor binding: the ADMIT event's
    # previous_entity_event_digest must equal the PROPOSE head digest.
    if cast(str, admit_event["previous_entity_event_digest"]) != previous.current_event_digest:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_PREDECESSOR_MISMATCH")
    # Phase 1: assumption dependency DFS (existence + reconstructability +
    # acyclicity). Collect first-discovery traversal records so we can later
    # derive the admission dependency receipt.
    assumption_dep_ids = previous.assumption_dependency_ids
    traversed: list[dict[str, Any]] = []
    visited: set[str] = set()
    stack: list[str] = [previous.assumption_id]
    stack_index: dict[str, int] = {previous.assumption_id: 0}

    def _dfs(node: str) -> None:
        if node in stack_index:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_DEPENDENCY_CYCLE")
        if node in visited:
            return
        dep = projections.get(node)
        if dep is None:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_DEPENDENCY_MISSING")
        # Reconstructability: a non-PROPOSED/non-active dep is acceptable for
        # admission (admission only requires existence + acyclicity), matching
        # the production admission gate which checks existence + canonical
        # reconstruction, not standing. Here "reconstructable" means the
        # projection chain is internally consistent (already enforced by
        # _validate_history for every appended event).
        traversed.append(
            {
                "assumption_id": dep.assumption_id,
                "validation_code": "DEPENDENCY_PRESENT",
                "current_entity_sequence": dep.current_entity_sequence,
                "current_event_digest": dep.current_event_digest,
                "direct_dependency_ids": list(dep.assumption_dependency_ids),
            }
        )
        stack_index[node] = len(stack)
        stack.append(node)
        for child in dep.assumption_dependency_ids:
            _dfs(child)
        stack.pop()
        del stack_index[node]
        visited.add(node)

    for dep_id in assumption_dep_ids:
        _dfs(dep_id)
    # Phase 2: evidence admission eligibility (A0-style). Each direct evidence
    # dependency must have a pinned A0 EvidenceAdmissionEligibilityDecision in
    # the policy context's evidence registry whose evidence_id,
    # evaluated_at_sequence (== ADMIT clock), and evidence_registry_root all
    # bind to this ADMIT, fail-fast through the first ineligible. The decision
    # digest is already required by _parse_policy_context; here we re-check the
    # binding fields and derive the admission dependency receipt.
    evidence_registry = cast(dict[str, Any], policy_context.get("evidence_registry", {}))
    receipts = cast(dict[str, Any], evidence_registry.get("receipts", {}))
    evidence_registry_root = cast(str, evidence_registry.get("evidence_registry_root", ""))
    evidence_decisions: list[dict[str, Any]] = []
    for evidence_id in previous.evidence_dependency_ids:
        decision = receipts.get(evidence_id)
        if decision is None:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_EVIDENCE_MISSING")
        if cast(str, decision["evidence_id"]) != evidence_id:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_EVIDENCE_ID_MISMATCH")
        if cast(int, decision["evaluated_at_sequence"]) != admit_clock:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_EVIDENCE_CLOCK_MISMATCH")
        if cast(str, decision["evidence_registry_root"]) != evidence_registry_root:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_EVIDENCE_ROOT_MISMATCH")
        evidence_decisions.append(decision)
        if decision.get("eligible") is not True:
            raise AssumptionConformanceError("ASSUMPTION_ADMISSION_EVIDENCE_INELIGIBLE")
    # Derive the admission dependency receipt from canonical fields and require
    # the supplied admission_receipt_digest to equal the derived digest.
    #
    # Defect #1: production-equivalent Governed-ADMIT receipt chain. The
    # envelope's ``source_receipt_digest`` binds the DependencyValidationReceipt
    # receipt_digest, and the payload's ``admission_receipt_digest`` binds the
    # GovernedAdmitAuthorization authorization_digest (which itself cross-binds
    # the dependency receipt + both registry roots + authority + materiality +
    # scope_ids + per-scope SoD decisions). We independently construct each
    # layer and bind them exactly as production does.
    payload = _object(admit_event, "payload")
    supplied_auth_digest = _required_digest(payload, "admission_receipt_digest")
    supplied_source_receipt = _required_digest(admit_event, "source_receipt_digest")
    admitting_authority_id = _required_token(payload, "admitting_authority_id")
    # Pre-ADMIT assumption_registry_root: the snapshot root of the projections
    # with the candidate at its PROPOSE head (BEFORE this ADMIT is applied). At
    # this point ``projections`` still holds the candidate's PROPOSE state.
    assumption_registry_root = _snapshot_root(projections)
    # --- Layer 1: DependencyValidationReceipt (with REAL registry root) ---
    dep_receipt_unsigned = _admission_dependency_receipt_unsigned_value(
        assumption_id=previous.assumption_id,
        candidate_predecessor_event_digest=previous.current_event_digest,
        assumption_registry_root=assumption_registry_root,
        evidence_registry_root=evidence_registry_root,
        assumption_dependency_ids=previous.assumption_dependency_ids,
        evidence_dependency_ids=previous.evidence_dependency_ids,
        traversed_dependencies=traversed,
        cycle_witness=(),
        evidence_eligibility_decisions=[
            _evidence_admission_unsigned_value(d) for d in evidence_decisions
        ],
        event_sequence=admit_clock,
        validation_code="DEPENDENCY_VALIDATION_PASSED",
        validation_result="PASS",
    )
    dep_receipt_digest = _domain_digest("ASSUMPTION_DEPENDENCY_VALIDATION", dep_receipt_unsigned)
    # The envelope's source_receipt_digest binds the dependency receipt digest.
    if supplied_source_receipt != dep_receipt_digest:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_SOURCE_RECEIPT_MISMATCH")
    # --- Layer 2: per-scope SeparationOfDutyDecision (ADMIT, challenge=None) ---
    sod_decisions = [
        _sod_decision_unsigned_value(
            policy_context=policy_context,
            action="ADMIT",
            authority_id=admitting_authority_id,
            scope_id=scope_id,
            assumption_materiality=previous.materiality,
            challenge_materiality=None,
            event_sequence=admit_clock,
            previous=previous,
            candidate_entity_sequence=2,
        )
        for scope_id in previous.scope_ids
    ]
    # --- Layer 3: GovernedAdmitAuthorization ---
    auth_unsigned = _governed_admit_authorization_unsigned_value(
        admitting_authority_id=admitting_authority_id,
        assumption_id=previous.assumption_id,
        assumption_materiality=previous.materiality,
        assumption_registry_root=assumption_registry_root,
        candidate_entity_sequence=2,
        candidate_predecessor_event_digest=previous.current_event_digest,
        dependency_validation_receipt=dep_receipt_unsigned,
        event_sequence=admit_clock,
        evidence_registry_root=evidence_registry_root,
        scope_ids=previous.scope_ids,
        sod_decisions=sod_decisions,
    )
    derived_auth_digest = _domain_digest("ASSUMPTION_GOVERNED_ADMIT_AUTHORIZATION", auth_unsigned)
    # The payload's admission_receipt_digest binds the authorization digest.
    if supplied_auth_digest != derived_auth_digest:
        raise AssumptionConformanceError("ASSUMPTION_ADMISSION_RECEIPT_MISMATCH")


def _admission_dependency_receipt_unsigned_value(
    *,
    assumption_id: str,
    candidate_predecessor_event_digest: str,
    assumption_registry_root: str,
    evidence_registry_root: str,
    assumption_dependency_ids: tuple[str, ...],
    evidence_dependency_ids: tuple[str, ...],
    traversed_dependencies: list[dict[str, Any]],
    cycle_witness: tuple[str, ...],
    evidence_eligibility_decisions: list[dict[str, object]],
    event_sequence: int,
    validation_code: str,
    validation_result: str,
) -> dict[str, object]:
    """Independently recompute the admission dependency receipt UNSIGNED value.

    Replicates DependencyValidationReceipt._unsigned_value exactly. The
    candidate_entity_sequence is mechanically 2 (PROPOSE seq 1 -> ADMIT seq 2)
    and the traversed/evidence fields are canonicalized.
    """
    return {
        "schema_version": _ADMISSION_DEPENDENCY_RECEIPT_SCHEMA_VERSION,
        "assumption_dependency_ids": list(assumption_dependency_ids),
        "assumption_id": assumption_id,
        "assumption_registry_root": assumption_registry_root,
        "candidate_entity_sequence": 2,
        "candidate_predecessor_event_digest": candidate_predecessor_event_digest,
        "cycle_witness": list(cycle_witness),
        "evidence_dependency_ids": list(evidence_dependency_ids),
        "evidence_eligibility_decisions": evidence_eligibility_decisions,
        "evidence_registry_root": evidence_registry_root,
        "event_sequence": event_sequence,
        "traversed_dependencies": traversed_dependencies,
        "validation_code": validation_code,
        "validation_result": validation_result,
    }


def _governed_admit_authorization_unsigned_value(
    *,
    admitting_authority_id: str,
    assumption_id: str,
    assumption_materiality: str,
    assumption_registry_root: str,
    candidate_entity_sequence: int,
    candidate_predecessor_event_digest: str,
    dependency_validation_receipt: dict[str, object],
    event_sequence: int,
    evidence_registry_root: str,
    scope_ids: tuple[str, ...],
    sod_decisions: list[dict[str, object]],
) -> dict[str, object]:
    """Independently recompute the GovernedAdmitAuthorization UNSIGNED value.

    Replicates GovernedAdmitAuthorization._unsigned_value exactly. The
    ``dependency_validation_receipt`` and ``sod_decisions`` are passed as their
    fully-expanded ``to_json_value()`` shapes (the receipt_digest /
    decision_digest are included in those nested serializations, exactly as
    production serializes the composite authorization).
    """
    return {
        "schema_version": _GOVERNED_ADMIT_AUTHORIZATION_SCHEMA_VERSION,
        "admitting_authority_id": admitting_authority_id,
        "assumption_id": assumption_id,
        "assumption_materiality": assumption_materiality,
        "assumption_registry_root": assumption_registry_root,
        "candidate_entity_sequence": candidate_entity_sequence,
        "candidate_predecessor_event_digest": candidate_predecessor_event_digest,
        "dependency_validation_receipt": {
            **dependency_validation_receipt,
            "receipt_digest": _domain_digest(
                "ASSUMPTION_DEPENDENCY_VALIDATION", dependency_validation_receipt
            ),
        },
        "event_sequence": event_sequence,
        "evidence_registry_root": evidence_registry_root,
        "scope_ids": list(scope_ids),
        "sod_decisions": [
            {**dec, "decision_digest": _domain_digest(_SOD_DOMAIN, dec)} for dec in sod_decisions
        ],
    }


def _grant_selection_unsigned_value(
    *,
    resolved_entry: dict[str, Any],
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    decision_type: str,
    grant: dict[str, Any] | None,
) -> dict[str, object]:
    """Independently recompute the GrantSelectionDecision UNSIGNED value.

    Replicates the I1-A ``_build_decision`` unsigned value exactly so the
    ``selection_digest`` bound into the SoD decision matches production.
    """
    decision_code = {
        "SELECTED": "ASSUMPTION_GRANT_SELECTED",
        "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
        "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
    }[decision_type]
    return {
        "schema_version": _GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_materiality": assumption_materiality,
        "authority_id": authority_id,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": resolved_entry["commit_receipt_digest"],
        "decision_code": decision_code,
        "decision_type": decision_type,
        "effective_from_sequence": resolved_entry["effective_from_sequence"],
        "event_sequence": event_sequence,
        "grant_digest": grant["grant_digest"] if grant is not None else None,
        "ledger_entry_digest": resolved_entry["ledger_entry_digest"],
        "ledger_root_digest": resolved_entry.get("ledger_root_digest", ""),
        "policy_digest": resolved_entry["policy_digest"],
        "policy_id": resolved_entry["policy_id"],
        "scope_id": scope_id,
        "selected_grant_id": grant["grant_id"] if grant is not None else None,
        "signing_payload_digest": resolved_entry["signing_payload_digest"],
    }


def _sod_decision_unsigned_value(
    *,
    policy_context: dict[str, Any],
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    previous: IndependentAssumptionProjection | None,
    candidate_entity_sequence: int,
) -> dict[str, object]:
    """Independently recompute the SeparationOfDutyDecision UNSIGNED value.

    Replicates ``SeparationOfDutyDecision._unsigned_value`` exactly: the I1-A
    grant selection, B0 prior roles, per-rule evaluations with per-rule bounded
    exceptions, and the mechanically-derived aggregate fields. Used by the
    Governed-ADMIT receipt chain to bind the per-scope SoD decisions.
    """
    resolved_entry = _resolve_policy_at(policy_context, event_sequence)
    # The ledger_root_digest lives at the policy-context level (the whole
    # ledger's root), not on each entry. Bind it so the selection_digest /
    # SoD decision match production's ResolvedPolicyAtSequence binding.
    resolved_entry["ledger_root_digest"] = policy_context["ledger_root_digest"]
    decision_type, selected_grant = _select_applicable_grant(
        resolved_entry,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        event_sequence=event_sequence,
        challenge_materiality=challenge_materiality or "",
    )
    selection_unsigned = _grant_selection_unsigned_value(
        resolved_entry=resolved_entry,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        decision_type=decision_type,
        grant=selected_grant,
    )
    selection_digest = _domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", selection_unsigned)
    prior_roles = _derive_prior_roles(
        previous,
        authority_id=authority_id,
        candidate_entity_sequence=candidate_entity_sequence,
    )
    prior_set = set(prior_roles)
    rules = cast(list[dict[str, Any]], resolved_entry.get("duty_rules", []))
    exceptions = cast(list[dict[str, Any]], resolved_entry.get("duty_exceptions", []))
    rule_evaluations: list[dict[str, object]] = []
    conflicting_union: set[str] = set()
    waived_union: set[str] = set()
    remaining_union: set[str] = set()
    evaluated_rule_digests: list[str] = []
    waiving_exception_digests: list[str] = []
    for rule in rules:
        if cast(str, rule["action"]) != action:
            continue
        if not _scope_covers_request(scope_id, tuple(cast(list[str], rule["scope_ids"]))):
            continue
        if assumption_materiality not in set(cast(list[str], rule["assumption_materialities"])):
            continue
        rule_conflicts = prior_set & set(cast(list[str], rule["conflicting_roles"]))
        if not rule_conflicts:
            continue
        rule_waived: set[str] = set()
        rule_waiving: list[tuple[str, str]] = []
        for exception in exceptions:
            if cast(str, exception["rule_id"]) != cast(str, rule["rule_id"]):
                continue
            if cast(str, exception["action"]) != action:
                continue
            if cast(str, exception["authority_id"]) != authority_id:
                continue
            if not _scope_covers_request(scope_id, tuple(cast(list[str], exception["scope_ids"]))):
                continue
            if assumption_materiality not in set(
                cast(list[str], exception["assumption_materialities"])
            ):
                continue
            exc_assumptions = cast(list[str], exception.get("assumption_ids", []))
            if exc_assumptions and (
                previous is None or previous.assumption_id not in exc_assumptions
            ):
                continue
            eff_from = cast(int, exception["effective_from_sequence"])
            eff_until = cast(int, exception["effective_until_sequence"])
            if not (eff_from <= event_sequence < eff_until):
                continue
            waived_by_this = set(cast(list[str], exception["conflicting_roles"])) & rule_conflicts
            if waived_by_this:
                rule_waived |= waived_by_this
                rule_waiving.append(
                    (cast(str, exception["exception_id"]), cast(str, exception["exception_digest"]))
                )
        rule_waiving.sort(key=lambda pair: pair[0])
        rule_remaining = rule_conflicts - rule_waived
        rule_conflicts_ordered = tuple(
            role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in rule_conflicts
        )
        rule_waived_ordered = tuple(
            role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in rule_waived
        )
        rule_remaining_ordered = tuple(
            role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in rule_remaining
        )
        evaluated_rule_digests.append(cast(str, rule["rule_digest"]))
        conflicting_union |= rule_conflicts
        waived_union |= rule_waived
        remaining_union |= rule_remaining
        waiving_exception_digests.extend(digest for _eid, digest in rule_waiving)
        rule_evaluations.append(
            {
                "rule_id": rule["rule_id"],
                "rule_digest": rule["rule_digest"],
                "conflicting_roles": list(rule_conflicts_ordered),
                "waiving_exceptions": [list(pair) for pair in rule_waiving],
                "waived_roles": list(rule_waived_ordered),
                "remaining_conflicts": list(rule_remaining_ordered),
            }
        )
    conflicting_ordered = tuple(
        role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in conflicting_union
    )
    waived_ordered = tuple(role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in waived_union)
    remaining_ordered = tuple(
        role for role in _ASSUMPTION_GOVERNANCE_ROLES if role in remaining_union
    )
    decision = "ALLOW" if decision_type == "SELECTED" and not remaining_union else "DENY"
    return {
        "schema_version": _SOD_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_id": previous.assumption_id if previous is not None else "",
        "assumption_materiality": assumption_materiality,
        "candidate_entity_sequence": candidate_entity_sequence,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": resolved_entry["commit_receipt_digest"],
        "conflicting_roles": list(conflicting_ordered),
        "decision": decision,
        "event_sequence": event_sequence,
        "authority_id": authority_id,
        "evaluated_rule_digests": evaluated_rule_digests,
        "grant_digest": selected_grant["grant_digest"] if selected_grant is not None else None,
        "ledger_root_digest": resolved_entry.get("ledger_root_digest", ""),
        "policy_digest": resolved_entry["policy_digest"],
        "prior_roles": list(prior_roles),
        "remaining_conflicts": list(remaining_ordered),
        "rule_evaluations": rule_evaluations,
        "scope_id": scope_id,
        "selected_grant_id": selected_grant["grant_id"] if selected_grant is not None else None,
        "selection_decision_type": decision_type,
        "selection_digest": selection_digest,
        "waived_roles": list(waived_ordered),
        "waiving_exception_digests": waiving_exception_digests,
    }


# =====================================================================
# Authority decision (I1-A grant selection + I1-B SoD).
# =====================================================================


def _authority_decision(
    event: dict[str, Any],
    payload: dict[str, Any],
    previous: IndependentAssumptionProjection | None,
    policy_context: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
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
    event_sequence = cast(int, event["clock_sequence"])
    # Map the lifecycle operation onto the frozen authority action vocabulary.
    # RESOLVE_CHALLENGES expands to one of the four RESOLVE_TO_* actions via
    # the resolution_outcome.
    action = _authority_action_for(operation, payload)
    challenge_materiality = _challenge_materiality_for(operation, payload, previous, policy_context)
    # I1-A: V3 policy resolution at the admission clock.
    resolved_entry = _resolve_policy_at(policy_context, event_sequence)
    # The request scope for grant selection is the single narrow scope of the
    # assumption (production uses scope_id singular). All corpus assumptions
    # carry exactly one scope; this mirrors the production evaluator.
    scope_id = scope_ids[0] if scope_ids else _GLOBAL_SCOPE
    decision_type, selected_grant = _select_applicable_grant(
        resolved_entry,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=materiality,
        event_sequence=event_sequence,
        challenge_materiality=challenge_materiality,
    )
    if decision_type == "SELECTED":
        grant_allowed = True
        grant_code = "ASSUMPTION_AUTHORITY_PERMITTED"
    elif decision_type == "NO_APPLICABLE_GRANT":
        grant_allowed = False
        grant_code = "ASSUMPTION_AUTHORITY_DENIED"
    else:  # AMBIGUOUS_GRANTS
        grant_allowed = False
        grant_code = "ASSUMPTION_AUTHORITY_AMBIGUOUS"
    # I1-B: separation-of-duty (only when the grant was selected). An authority
    # denial short-circuits; the SoD code is layered on top.
    if grant_allowed:
        candidate_entity_sequence = cast(int, event["entity_sequence"])
        sod_decision = _evaluate_separation_of_duty(
            resolved_entry=resolved_entry,
            action=action,
            authority_id=authority_id,
            scope_id=scope_id,
            assumption_materiality=materiality,
            event_sequence=event_sequence,
            previous=previous,
            candidate_entity_sequence=candidate_entity_sequence,
            challenge_materiality=challenge_materiality,
        )
        if sod_decision == "DENY":
            allowed = False
            code = "ASSUMPTION_SEPARATION_OF_DUTY_DENIED"
        else:
            allowed = True
            code = grant_code
    else:
        allowed = False
        code = grant_code
    unsigned: dict[str, object] = {
        "schema_version": "assumption-authority-decision/1",
        "allowed": allowed,
        "authority_id": authority_id,
        "authority_root_digest": policy_context["authority_root_digest"],
        "code": code,
        "event_digest": event["registry_event_digest"],
        "assumption_id": event["entity_id"],
        "operation": operation,
        "policy_digest": resolved_entry["policy_digest"],
        "scope_ids": list(scope_ids),
        "materiality": materiality,
    }
    return {
        **unsigned,
        "decision_digest": _domain_digest("ASSUMPTION_AUTHORITY_DECISION", unsigned),
    }


# =====================================================================
# D3.2-B: use-time admissibility (independently replicated).
# =====================================================================


@dataclass
class _WorkCounters:
    histories: int = 0
    events: int = 0
    unique_nodes: int = 0
    dep_edges: int = 0
    evidence_refs: int = 0
    challenges: int = 0
    sod_rules: int = 0
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
            "separation_duty_rules_evaluated": self.sod_rules,
        }
        self.work_digest = _domain_digest("ASSUMPTION_EVALUATION_WORK", unsigned)


@dataclass(frozen=True, slots=True)
class _EvaluatedNode:
    """Snapshot of one assumption node visited during the use-time DFS.

    Repeated occurrences of the same assumption_id across multiple top-level
    evaluations carry identical authoritative state, so work counters
    deduplicate on assumption_id while preserving first-discovery order.
    """

    projection: IndependentAssumptionProjection
    history_event_count: int


def _evaluate_use(
    binding: dict[str, Any],
    projections: dict[str, IndependentAssumptionProjection],
    policy_context: dict[str, Any],
    assumption_registry_root: str,
) -> dict[str, object]:
    _validate_use_binding(binding, assumption_registry_root)
    work = _WorkCounters()
    required_assumption_ids = tuple(cast(list[str], binding["required_assumption_ids"]))
    clock = cast(int, binding["logical_clock_sequence"])
    decision_id = cast(str, binding["decision_id"])
    # Cross-evaluation work-counter dedup: shared across all top-level
    # evaluations so a dependency reached from more than one root counts once.
    shared_visited: set[str] = set()
    shared_nodes: dict[str, _EvaluatedNode] = {}
    # Corr #2: evaluate EVERY required assumption. D3.2-B forbids a global
    # top-level fail-fast: every top-level assumption must be evaluated so a
    # tamper on the second assumption cannot hide behind a denial on the first.
    # Each top-level evaluation is itself fail-closed (its own DFS+evidence
    # short-circuits on the first denial), but the top-level loop runs to
    # completion. The binding is admissible iff EVERY evaluation ALLOWs.
    evaluated_assumptions: list[dict[str, object]] = []
    per_root_codes: list[tuple[str, str, str | None]] = []
    for assumption_id in required_assumption_ids:
        evaluation, allowed, code, event_digest = _evaluate_one_use_assumption(
            assumption_id,
            projections=projections,
            binding=binding,
            decision_id=decision_id,
            clock=clock,
            work=work,
            shared_visited=shared_visited,
            shared_nodes=shared_nodes,
            policy_context=policy_context,
        )
        evaluated_assumptions.append(evaluation)
        per_root_codes.append((assumption_id, code, event_digest))
    admissible = all(cast(str, ev["result"]) == "ALLOW" for ev in evaluated_assumptions)
    if admissible:
        allowed = True
        code = "ASSUMPTION_USE_ALLOWED"
    else:
        allowed = False
        # Report the first denial encountered.
        first_denial = next(item for item in per_root_codes if item[1] != "ASSUMPTION_USE_ALLOWED")
        code = first_denial[1]
    work.finalize()
    # Defect #2: reconstruct the production AssumptionUseAdmissibilityDecision
    # unsigned value exactly, so the decision_digest is computed over the
    # production receipt shape (binding + evaluated_assumptions +
    # evaluation_work), not a flat synthetic decision.
    evaluation_work_unsigned = {
        "schema_version": "assumption-evaluation-work/1",
        "active_challenges_evaluated": work.challenges,
        "assumption_dependency_edges_examined": work.dep_edges,
        "assumption_events_replayed": work.events,
        "assumption_histories_reconstructed": work.histories,
        "authority_decisions_evaluated": 0,
        "evidence_dependency_references_evaluated": work.evidence_refs,
        "separation_duty_rules_evaluated": 0,
        "unique_assumption_nodes_evaluated": work.unique_nodes,
    }
    work_digest = _domain_digest("ASSUMPTION_EVALUATION_WORK", evaluation_work_unsigned)
    evaluation_work = {**evaluation_work_unsigned, "work_digest": work_digest}
    binding_value = _binding_to_json_value(binding)
    decision_unsigned: dict[str, object] = {
        "schema_version": "assumption-use-admissibility-decision/1",
        "admissible": admissible,
        "binding": binding_value,
        "evaluated_assumptions": evaluated_assumptions,
        "evaluation_work": evaluation_work,
    }
    decision_digest = _domain_digest("ASSUMPTION_USE_ADMISSIBILITY_DECISION", decision_unsigned)
    return {
        "allowed": allowed,
        "code": code,
        "decision_digest": decision_digest,
        "decision_unsigned": decision_unsigned,
    }


def _evaluate_one_use_assumption(
    assumption_id: str,
    *,
    projections: dict[str, IndependentAssumptionProjection],
    binding: dict[str, Any],
    decision_id: str,
    clock: int,
    work: _WorkCounters,
    shared_visited: set[str],
    shared_nodes: dict[str, _EvaluatedNode],
    policy_context: dict[str, Any],
) -> tuple[dict[str, object], bool, str, str | None]:
    """Evaluate one required assumption for use-time admissibility, building the
    production-shaped :class:`AssumptionUseEvaluation` record.

    Returns ``(evaluation_dict, allowed, code, event_digest)``. The evaluation
    dict carries the full production shape: assumption_id, validation_code,
    result, self_state, traversed_dependencies, cycle_witness,
    evidence_evaluations. Defect #2: this is the structure the
    AssumptionUseAdmissibilityDecision unsigned value binds.

    This is a non-raising DFS+evidence evaluator that mirrors production's
    ``_evaluate_one_assumption`` exactly: self-gate precedence, complete DFS
    (with per-evaluation first-discovery dedup + cycle detection), then
    fail-fast evidence phase. The traversed records and evidence evaluations are
    collected as they are produced so the production receipt shape can be bound
    for both ALLOW and DENY outcomes.
    """
    del policy_context  # bound at the decision level, not per-assumption
    # --- SELF_HISTORY: reconstruct + project ---
    assumption = projections.get(assumption_id)
    if assumption is None:
        # Top-level MISSING: no projected state.
        self_state = _traversed_to_json_value(
            assumption_id=assumption_id,
            projection=None,
            code="ASSUMPTION_USE_MISSING",
            history_event_count=0,
        )
        _record_self_node_failure(assumption_id, shared_visited)
        return (
            _build_use_evaluation(
                assumption_id=assumption_id,
                validation_code="ASSUMPTION_USE_MISSING",
                result="DENY",
                self_state=self_state,
                traversed=(),
                cycle_witness=(),
                evidence_evaluations=(),
            ),
            False,
            "ASSUMPTION_USE_MISSING",
            None,
        )
    history_event_count = len(assumption.role_history)
    # --- Self-gate precedence (frozen): TERMINAL > NOT_ADMITTED > CHALLENGED >
    # NOT_YET_VALID > EXPIRED. On failure the full projected state is RETAINED. ---
    gate_code = _self_gate_code(assumption, clock)
    if gate_code is not None:
        self_state = _traversed_to_json_value(
            assumption_id=assumption_id,
            projection=assumption,
            code=gate_code,
            history_event_count=history_event_count,
        )
        _record_self_node(assumption, history_event_count, work, shared_visited, shared_nodes)
        return (
            _build_use_evaluation(
                assumption_id=assumption_id,
                validation_code=gate_code,
                result="DENY",
                self_state=self_state,
                traversed=(),
                cycle_witness=(),
                evidence_evaluations=(),
            ),
            False,
            gate_code,
            assumption.current_event_digest,
        )
    # Self-gates passed: self_state is NODE_PRESENT.
    self_state = _traversed_to_json_value(
        assumption_id=assumption_id,
        projection=assumption,
        code="ASSUMPTION_USE_NODE_PRESENT",
        history_event_count=history_event_count,
    )
    # --- Complete assumption DFS (only after self-gates pass) ---
    # Per-evaluation first-discovery dedup + active-stack cycle detection,
    # matching production. Collects traversed records in first-discovery order.
    traversed_records: list[dict[str, object]] = []
    cycle_witness: tuple[str, ...] = ()
    dfs_failed = False
    dfs_code = ""
    dfs_stack: list[str] = [assumption_id]
    dfs_stack_index: dict[str, int] = {assumption_id: 0}
    dfs_visited: set[str] = set()

    def _dfs(node: str, is_top_level: bool) -> None:
        nonlocal dfs_failed, dfs_code, cycle_witness
        if dfs_failed:
            return
        if node in dfs_stack_index:
            i = dfs_stack_index[node]
            raw_cycle = tuple(dfs_stack[i:] + [node])
            cycle_witness = _canonical_cycle_witness(raw_cycle)
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_DEPENDENCY_CYCLE"
            return
        if node in dfs_visited:
            return
        dep = projections.get(node)
        if dep is None:
            code = "ASSUMPTION_USE_MISSING" if is_top_level else "ASSUMPTION_USE_DEPENDENCY_MISSING"
            traversed_records.append(
                _traversed_to_json_value(
                    assumption_id=node,
                    projection=None,
                    code=code,
                    history_event_count=0,
                )
            )
            dfs_failed = True
            dfs_code = code
            return
        dep_history = len(dep.role_history)
        dep_gate = _self_gate_code(dep, clock)
        if dep_gate is not None:
            traversed_records.append(
                _traversed_to_json_value(
                    assumption_id=node,
                    projection=dep,
                    code=dep_gate,
                    history_event_count=dep_history,
                )
            )
            dfs_failed = True
            dfs_code = dep_gate
            return
        traversed_records.append(
            _traversed_to_json_value(
                assumption_id=node,
                projection=dep,
                code="ASSUMPTION_USE_NODE_PRESENT",
                history_event_count=dep_history,
            )
        )
        work.dep_edges += 1
        dfs_stack_index[node] = len(dfs_stack)
        dfs_stack.append(node)
        for child in dep.assumption_dependency_ids:
            _dfs(child, is_top_level=False)
            if dfs_failed:
                break
        if not dfs_failed:
            dfs_stack.pop()
            del dfs_stack_index[node]
            dfs_visited.add(node)

    for dep_id in assumption.assumption_dependency_ids:
        if dfs_failed:
            break
        _dfs(dep_id, is_top_level=False)

    if dfs_failed:
        # Record the self node as a work-counter node (it passed self-gates).
        _record_self_node(assumption, history_event_count, work, shared_visited, shared_nodes)
        return (
            _build_use_evaluation(
                assumption_id=assumption_id,
                validation_code=dfs_code,
                result="DENY",
                self_state=self_state,
                traversed=tuple(traversed_records),
                cycle_witness=cycle_witness,
                evidence_evaluations=(),
            ),
            False,
            dfs_code,
            assumption.current_event_digest,
        )
    # DFS passed: record self node for work counters, then evidence phase.
    _record_self_node(assumption, history_event_count, work, shared_visited, shared_nodes)
    # Build the ordered node list (self + traversed, first-discovery order) for
    # evidence evaluation.
    ordered_projections: list[IndependentAssumptionProjection] = [assumption]
    # The traversed_records list is in first-discovery order; map back to
    # projections for evidence evaluation.
    traversed_ids_in_order = [cast(str, rec["assumption_id"]) for rec in traversed_records]
    for tid in traversed_ids_in_order:
        proj = projections.get(tid)
        if proj is not None:
            ordered_projections.append(proj)
    # --- Evidence phase (only after DFS completes) ---
    # Capture each EvidenceEvaluation (including a denying one) before
    # fail-closing, so the production-shaped evidence_evaluations list matches
    # production exactly: the denying receipt IS part of the list.
    evidence_evaluations: list[dict[str, object]] = []
    evidence_failed = False
    evidence_code = ""
    for owner in ordered_projections:
        if evidence_failed:
            break
        for evidence_id in owner.evidence_dependency_ids:
            try:
                pinned_request, pinned_receipt = _evaluate_evidence_dependency(
                    evidence_id,
                    decision_id=decision_id,
                    clock=clock,
                    owner=owner,
                    binding=binding,
                )
            except AssumptionConformanceError as exc:
                # Structural failure (missing/mismatch/invalid digest): the
                # evaluation list up to this point is retained, and the
                # decision terminates with this code.
                evidence_failed = True
                evidence_code = exc.code
                break
            # Count the evidence reference only when the evaluation was
            # successfully performed (matching production's
            # len(evidence_evaluations) work counter).
            work.evidence_refs += 1
            evidence_evaluations.append(
                {
                    "owner_assumption_id": owner.assumption_id,
                    "request": pinned_request,
                    "receipt": pinned_receipt,
                }
            )
            # Fail-closed on an inadmissible receipt (after capturing it).
            if pinned_receipt.get("allowed") is not True:
                evidence_failed = True
                evidence_code = cast(str, pinned_receipt.get("code", "EVIDENCE_INADMISSIBLE"))
                break
    if evidence_failed:
        return (
            _build_use_evaluation(
                assumption_id=assumption_id,
                validation_code=evidence_code,
                result="DENY",
                self_state=self_state,
                traversed=tuple(traversed_records),
                cycle_witness=(),
                evidence_evaluations=tuple(evidence_evaluations),
            ),
            False,
            evidence_code,
            assumption.current_event_digest,
        )
    return (
        _build_use_evaluation(
            assumption_id=assumption_id,
            validation_code="ASSUMPTION_USE_ALLOWED",
            result="ALLOW",
            self_state=self_state,
            traversed=tuple(traversed_records),
            cycle_witness=(),
            evidence_evaluations=tuple(evidence_evaluations),
        ),
        True,
        "ASSUMPTION_USE_ALLOWED",
        None,
    )


def _record_self_node_failure(
    assumption_id: str,
    shared_visited: set[str],
) -> None:
    """Record a top-level MISSING failure (no projection to count)."""
    if assumption_id in shared_visited:
        return
    shared_visited.add(assumption_id)


def _self_gate_code(assumption: IndependentAssumptionProjection, clock: int) -> str | None:
    """Return the self-gate denial code for ``assumption`` at ``clock``, or None
    if all self-gates pass (the node is NODE_PRESENT)."""
    if assumption.standing in _TERMINAL:
        return "ASSUMPTION_USE_TERMINAL"
    if assumption.standing not in _ACTIVE:
        return "ASSUMPTION_USE_NOT_ADMITTED"
    if assumption.active_challenges:
        return "ASSUMPTION_USE_CHALLENGED"
    if clock < assumption.valid_from_sequence:
        return "ASSUMPTION_USE_NOT_YET_VALID"
    if assumption.expires_at_sequence is not None and clock >= assumption.expires_at_sequence:
        return "ASSUMPTION_USE_EXPIRED"
    return None


def _traversed_to_json_value(
    *,
    assumption_id: str,
    projection: IndependentAssumptionProjection | None,
    code: str,
    history_event_count: int,
) -> dict[str, object]:
    """Build one UseTimeTraversedAssumption-shaped record.

    For NODE_PRESENT: full projected state. For self-gate failures: full
    projected state retained (proves WHY it failed). For MISSING: every
    projected field is absent.
    """
    if projection is None:
        return {
            "assumption_id": assumption_id,
            "validation_code": code,
            "current_event_digest": None,
            "current_entity_sequence": None,
            "history_event_count": history_event_count,
            "proposition_id": None,
            "scope_ids": [],
            "materiality": None,
            "standing": None,
            "active_challenge_ids": [],
            "valid_from_sequence": None,
            "expires_at_sequence": None,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": None,
        }
    return {
        "assumption_id": assumption_id,
        "validation_code": code,
        "current_event_digest": projection.current_event_digest,
        "current_entity_sequence": projection.current_entity_sequence,
        "history_event_count": history_event_count,
        "proposition_id": projection.proposition_id,
        "scope_ids": list(projection.scope_ids),
        "materiality": projection.materiality,
        "standing": projection.standing,
        "active_challenge_ids": list(projection.active_challenge_ids),
        "valid_from_sequence": projection.valid_from_sequence,
        "expires_at_sequence": projection.expires_at_sequence,
        "assumption_dependency_ids": list(projection.assumption_dependency_ids),
        "evidence_dependency_ids": list(projection.evidence_dependency_ids),
        "limitations": list(projection.limitations),
        "maximum_reuse_class": projection.maximum_reuse_class,
    }


def _build_use_evaluation(
    *,
    assumption_id: str,
    validation_code: str,
    result: str,
    self_state: dict[str, object],
    traversed: tuple[dict[str, object], ...],
    cycle_witness: tuple[str, ...],
    evidence_evaluations: tuple[dict[str, object], ...],
) -> dict[str, object]:
    """Build one AssumptionUseEvaluation-shaped record."""
    return {
        "assumption_id": assumption_id,
        "validation_code": validation_code,
        "result": result,
        "self_state": self_state,
        "traversed_dependencies": list(traversed),
        "cycle_witness": list(cycle_witness),
        "evidence_evaluations": list(evidence_evaluations),
    }


def _binding_to_json_value(binding: dict[str, Any]) -> dict[str, object]:
    """Build the DecisionAssumptionBinding-shaped unsigned value (without
    binding_digest, matching production's to_json_value used inside the decision
    unsigned value)."""
    return {
        "schema_version": "decision-assumption-binding/1",
        "assumption_registry_root": binding["assumption_registry_root"],
        "control_state_digest": binding["control_state_digest"],
        "decision_id": binding["decision_id"],
        "evidence_registry_root": binding["evidence_registry_root"],
        "logical_clock_sequence": binding["logical_clock_sequence"],
        "required_assumption_ids": list(binding["required_assumption_ids"]),
        "semantic_projection_receipt_digest": binding["semantic_projection_receipt_digest"],
        "validated_event_digest": binding["validated_event_digest"],
    }


def _canonical_cycle_witness(raw_cycle: tuple[str, ...]) -> tuple[str, ...]:
    """Canonicalize a directed cycle witness by rotating to start at the
    lexicographically smallest member. Returns (smallest, ...rest) so the
    canonical form is deterministic regardless of DFS entry point."""
    # Find the rotation that starts at the lexicographically smallest id.
    smallest_idx = min(range(len(raw_cycle) - 1), key=lambda i: raw_cycle[i])
    rotated = raw_cycle[smallest_idx:-1] + raw_cycle[:smallest_idx] + (raw_cycle[smallest_idx],)
    return rotated


def _record_self_node(
    assumption: IndependentAssumptionProjection,
    history_event_count: int,
    work: _WorkCounters,
    shared_visited: set[str],
    shared_nodes: dict[str, _EvaluatedNode],
) -> None:
    """Record one node in the work counters, deduplicating by assumption_id."""
    if assumption.assumption_id in shared_visited:
        # Already counted; verify repeated-node state consistency.
        existing = shared_nodes[assumption.assumption_id]
        if existing.projection.current_event_digest != assumption.current_event_digest:
            raise AssumptionConformanceError("ASSUMPTION_USE_NODE_INCONSISTENT")
        return
    shared_visited.add(assumption.assumption_id)
    shared_nodes[assumption.assumption_id] = _EvaluatedNode(
        projection=assumption,
        history_event_count=history_event_count,
    )
    work.histories += 1
    work.events += history_event_count
    work.unique_nodes += 1
    work.challenges += len(assumption.active_challenges)


def _evaluate_evidence_dependency(
    evidence_id: str,
    *,
    decision_id: str,
    clock: int,
    owner: IndependentAssumptionProjection,
    binding: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Independently rebuild the D2 EvidenceUseRequest from the owner's
    projected state and verify the pinned EvidenceAdmissibilityReceipt.

    The fixture carries a complete serialized EvidenceUseRequest +
    EvidenceAdmissibilityReceipt per evidence dependency. The validator rebuilds
    the request digest from the owner's proposition/scope/reuse/limitations and
    the binding's decision_id + clock, requires it to match the pinned
    request_digest, then rebuilds the receipt from its own canonical fields and
    requires the rebuilt receipt to equal the pinned one. Any field-level
    tamper that leaves the receipt_digest stale is rejected here.

    Returns ``(pinned_request, pinned_receipt)``. The CALLER checks
    ``receipt.allowed`` and fail-closes on an inadmissible receipt (so the
    denying receipt is captured in the production-shaped evidence_evaluations
    list before the decision terminates).
    """
    evidence_requests = cast(dict[str, Any], binding.get("evidence_requests", {}))
    pinned = evidence_requests.get(evidence_id)
    if pinned is None:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUEST_MISSING")
    pinned_request = _object(pinned, "request")
    # Rebuild the EvidenceUseRequest digest from the owner's projected state.
    rebuilt_request_unsigned = {
        "schema_version": "evidence-use-request/1",
        "accepted_limitation_codes": sorted(owner.limitations),
        "clock_sequence": clock,
        "decision_id": decision_id,
        "evidence_id": evidence_id,
        "proposition_id": owner.proposition_id,
        "required_reuse_class": owner.maximum_reuse_class,
        "scope_ids": sorted(owner.scope_ids),
    }
    rebuilt_request_digest = _domain_digest("EVIDENCE_USE_REQUEST", rebuilt_request_unsigned)
    if pinned_request.get("request_digest") != rebuilt_request_digest:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUEST_MISMATCH")
    # Verify the pinned request's own digest is self-consistent.
    pinned_request_unsigned = {
        key: value for key, value in pinned_request.items() if key != "request_digest"
    }
    if pinned_request.get("request_digest") != _domain_digest(
        "EVIDENCE_USE_REQUEST", pinned_request_unsigned
    ):
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUEST_DIGEST_INVALID")
    # Rebuild the EvidenceAdmissibilityReceipt from its canonical fields and
    # require the rebuilt receipt to equal the pinned one.
    pinned_receipt = _object(pinned, "receipt")
    receipt_unsigned = {
        "schema_version": "evidence-admissibility-receipt/1",
        "advisory_codes": sorted(set(cast(list[str], pinned_receipt.get("advisory_codes", [])))),
        "allowed": pinned_receipt.get("allowed"),
        "authority_policy_digest": pinned_receipt.get("authority_policy_digest"),
        "challenge_policy_digest": pinned_receipt.get("challenge_policy_digest"),
        "code": pinned_receipt.get("code"),
        "dependency_event_digests": sorted(
            cast(list[str], pinned_receipt.get("dependency_event_digests", []))
        ),
        "evidence_event_digest": pinned_receipt.get("evidence_event_digest"),
        "evidence_id": evidence_id,
        "request_digest": pinned_request.get("request_digest"),
    }
    rebuilt_receipt_digest = _domain_digest("EVIDENCE_ADMISSIBILITY_RECEIPT", receipt_unsigned)
    if pinned_receipt.get("receipt_digest") != rebuilt_receipt_digest:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_RECEIPT_INVALID")
    # The receipt must bind to this evidence_id and this request.
    if pinned_receipt.get("evidence_id") != evidence_id:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_RECEIPT_EVIDENCE_MISMATCH")
    if pinned_receipt.get("request_digest") != pinned_request.get("request_digest"):
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_RECEIPT_REQUEST_MISMATCH")
    return pinned_request, pinned_receipt


def _validate_use_binding(
    binding: dict[str, Any],
    assumption_registry_root: str,
) -> None:
    """Validate the DecisionAssumptionBinding-shaped use request.

    Replaces the simplified assumption-use-request/1 with the production
    DecisionAssumptionBinding shape: decision_id, validated_event_digest,
    semantic_projection_receipt_digest, control_state_digest, both registry
    roots, logical_clock_sequence, required_assumption_ids, binding_digest.
    Carries a parallel evidence_requests map keyed by evidence_id.
    """
    _exact_keys(
        binding,
        {
            "schema_version",
            "decision_id",
            "validated_event_digest",
            "semantic_projection_receipt_digest",
            "control_state_digest",
            "assumption_registry_root",
            "evidence_registry_root",
            "logical_clock_sequence",
            "required_assumption_ids",
            "binding_digest",
            "evidence_requests",
        },
        code="ASSUMPTION_USE_BINDING_KEYS_INVALID",
    )
    if binding.get("schema_version") != "decision-assumption-binding/1":
        raise AssumptionConformanceError("ASSUMPTION_USE_BINDING_SCHEMA_INVALID")
    _required_token(binding, "decision_id")
    _required_digest(binding, "validated_event_digest")
    _required_digest(binding, "semantic_projection_receipt_digest")
    _required_digest(binding, "control_state_digest")
    _required_digest(binding, "assumption_registry_root")
    _required_digest(binding, "evidence_registry_root")
    if cast(str, binding["assumption_registry_root"]) != assumption_registry_root:
        raise AssumptionConformanceError("ASSUMPTION_USE_BINDING_ROOT_MISMATCH")
    if (
        type(binding.get("logical_clock_sequence")) is not int
        or cast(int, binding["logical_clock_sequence"]) < 0
    ):
        raise AssumptionConformanceError("ASSUMPTION_USE_CLOCK_INVALID")
    required = _token_tuple(binding, "required_assumption_ids", allow_empty=False)
    if type(binding.get("evidence_requests")) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_USE_EVIDENCE_REQUESTS_INVALID")
    unsigned = {
        "schema_version": "decision-assumption-binding/1",
        "assumption_registry_root": binding["assumption_registry_root"],
        "control_state_digest": binding["control_state_digest"],
        "decision_id": binding["decision_id"],
        "evidence_registry_root": binding["evidence_registry_root"],
        "logical_clock_sequence": binding["logical_clock_sequence"],
        "required_assumption_ids": list(required),
        "semantic_projection_receipt_digest": binding["semantic_projection_receipt_digest"],
        "validated_event_digest": binding["validated_event_digest"],
    }
    if binding.get("binding_digest") != _domain_digest("DECISION_ASSUMPTION_BINDING", unsigned):
        raise AssumptionConformanceError("ASSUMPTION_USE_BINDING_DIGEST_MISMATCH")


# =====================================================================
# Serialized V3 policy context parsing.
# =====================================================================


def _grant_unsigned_value(grant: dict[str, Any]) -> dict[str, object]:
    """Independently recompute the canonical unsigned value of an authority
    grant. Replicates AssumptionAuthorityGrant._unsigned_value exactly: the
    grant's challenge_materialities are part of the digest regardless of
    whether the action is a resolution action.
    """
    return {
        "schema_version": _AUTHORITY_GRANT_SCHEMA_VERSION,
        "action": grant["action"],
        "assumption_materialities": list(grant["assumption_materialities"]),
        "authority_id": grant["authority_id"],
        "challenge_materialities": list(grant["challenge_materialities"]),
        "effective_from_sequence": grant["effective_from_sequence"],
        "effective_until_sequence": grant["effective_until_sequence"],
        "grant_id": grant["grant_id"],
        "scope_ids": list(grant["scope_ids"]),
    }


def _rule_unsigned_value(rule: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": _SEPARATION_DUTY_RULE_SCHEMA_VERSION,
        "action": rule["action"],
        "assumption_materialities": list(rule["assumption_materialities"]),
        "conflicting_roles": list(rule["conflicting_roles"]),
        "rule_id": rule["rule_id"],
        "scope_ids": list(rule["scope_ids"]),
    }


def _exception_unsigned_value(exc: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": _DUTY_EXCEPTION_SCHEMA_VERSION,
        "action": exc["action"],
        "assumption_ids": list(exc["assumption_ids"]),
        "assumption_materialities": list(exc["assumption_materialities"]),
        "authority_id": exc["authority_id"],
        "conflicting_roles": list(exc["conflicting_roles"]),
        "effective_from_sequence": exc["effective_from_sequence"],
        "effective_until_sequence": exc["effective_until_sequence"],
        "exception_id": exc["exception_id"],
        "reason_code": exc["reason_code"],
        "rule_id": exc["rule_id"],
        "scope_ids": list(exc["scope_ids"]),
    }


def _set_digest(domain: str, members: list[dict[str, object]]) -> str:
    """Set digest = domain digest over ``{"members": [...]}``. Replicates
    _set_digest from _assumption_governance_contracts exactly."""
    return _domain_digest(domain, {"members": members})


def _policy_unsigned_value(
    *,
    policy_id: str,
    authority_root_digest: str,
    grants: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> tuple[dict[str, object], str, str, str]:
    """Independently recompute the canonical authority-policy unsigned value and
    its three set digests. Returns ``(unsigned, grant_set_digest,
    rule_set_digest, exception_set_digest)``.
    """
    grant_members: list[dict[str, object]] = [dict(g) for g in grants]
    rule_members: list[dict[str, object]] = [dict(r) for r in rules]
    exception_members: list[dict[str, object]] = [dict(e) for e in exceptions]
    grant_set = _set_digest("ASSUMPTION_AUTHORITY_GRANT_SET", grant_members)
    rule_set = _set_digest("ASSUMPTION_SEPARATION_DUTY_RULE_SET", rule_members)
    exception_set = _set_digest("ASSUMPTION_DUTY_EXCEPTION_SET", exception_members)
    unsigned: dict[str, object] = {
        "schema_version": _AUTHORITY_POLICY_SCHEMA_VERSION,
        "authority_root_digest": authority_root_digest,
        "duty_exceptions": exception_members,
        "exception_set_digest": exception_set,
        "grant_set_digest": grant_set,
        "grants": grant_members,
        "policy_id": policy_id,
        "separation_duty_rule_set_digest": rule_set,
        "separation_duty_rules": rule_members,
    }
    return unsigned, grant_set, rule_set, exception_set


def _parse_policy_context(value: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate the serialized V3 policy context.

    The catalog-level ``authority_policy`` is replaced with a serialized V3
    ledger carrying: authority_root_digest, ledger_root_digest, policy_digest
    (the active policy generation's digest), and ledger_entries (each with
    effective_from_sequence, policy_id, policy_digest,
    commit_receipt_digest, ledger_entry_digest, signing_payload_digest, grants,
    duty_rules, duty_exceptions). Plus an evidence_registry of pinned
    admission receipts used by the I1-C evidence phase.
    """
    _exact_keys(
        value,
        {
            "schema_version",
            "authority_root_digest",
            "ledger_root_digest",
            "policy_digest",
            "ledger_entries",
            "evidence_registry",
            # Defect #4: serialized challenge-classification material mapping
            # each challenge reason_code to its own materiality, independent of
            # the assumption's own materiality.
            "challenge_classifications",
        },
        code="ASSUMPTION_POLICY_CONTEXT_KEYS_INVALID",
    )
    if value.get("schema_version") != "assumption-policy-context/1":
        raise AssumptionConformanceError("ASSUMPTION_POLICY_CONTEXT_SCHEMA_INVALID")
    _required_digest(value, "authority_root_digest")
    _required_digest(value, "ledger_root_digest")
    _required_digest(value, "policy_digest")
    # Defect #4: validate the challenge-classification map. Each entry maps a
    # reason_code (token) to a materiality in the frozen vocabulary.
    classifications_raw = value.get("challenge_classifications")
    if type(classifications_raw) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_CHALLENGE_CLASSIFICATIONS_INVALID")
    parsed_classifications: dict[str, str] = {}
    for reason_code, materiality in cast(dict[str, object], classifications_raw).items():
        if type(reason_code) is not str or _TOKEN.fullmatch(reason_code) is None:
            raise AssumptionConformanceError("ASSUMPTION_CHALLENGE_CLASSIFICATION_KEY_INVALID")
        if type(materiality) is not str or materiality not in _MATERIALITIES:
            raise AssumptionConformanceError("ASSUMPTION_CHALLENGE_CLASSIFICATION_VALUE_INVALID")
        parsed_classifications[reason_code] = materiality
    entries_raw = value.get("ledger_entries")
    if type(entries_raw) is not list or not entries_raw:
        raise AssumptionConformanceError("ASSUMPTION_POLICY_LEDGER_ENTRIES_INVALID")
    parsed_entries: list[dict[str, Any]] = []
    prev_effective: int | None = None
    for raw_entry in cast(list[object], entries_raw):
        entry = _as_object(raw_entry, "ASSUMPTION_POLICY_LEDGER_ENTRY_INVALID")
        _exact_keys(
            entry,
            {
                "effective_from_sequence",
                "policy_id",
                "policy_digest",
                "commit_receipt_digest",
                "ledger_entry_digest",
                "signing_payload_digest",
                "grant_set_digest",
                "separation_duty_rule_set_digest",
                "exception_set_digest",
                "grants",
                "duty_rules",
                "duty_exceptions",
            },
            code="ASSUMPTION_POLICY_LEDGER_ENTRY_KEYS_INVALID",
        )
        effective = _non_negative_int(entry, "effective_from_sequence")
        if prev_effective is not None and effective <= prev_effective:
            raise AssumptionConformanceError("ASSUMPTION_POLICY_LEDGER_NOT_STRICTLY_INCREASING")
        prev_effective = effective
        policy_id = _required_token(entry, "policy_id")
        _required_digest(entry, "policy_digest")
        _required_digest(entry, "commit_receipt_digest")
        _required_digest(entry, "ledger_entry_digest")
        _required_digest(entry, "signing_payload_digest")
        _required_digest(entry, "grant_set_digest")
        _required_digest(entry, "separation_duty_rule_set_digest")
        _required_digest(entry, "exception_set_digest")
        parsed_grants: list[dict[str, Any]] = []
        for raw_grant in _array(entry, "grants"):
            grant = _as_object(raw_grant, "ASSUMPTION_AUTHORITY_GRANT_INVALID")
            _exact_keys(
                grant,
                {
                    "grant_id",
                    "action",
                    "authority_id",
                    "scope_ids",
                    "assumption_materialities",
                    "challenge_materialities",
                    "effective_from_sequence",
                    "effective_until_sequence",
                    "grant_digest",
                },
                code="ASSUMPTION_AUTHORITY_GRANT_KEYS_INVALID",
            )
            _required_token(grant, "grant_id")
            action = _required_token(grant, "action")
            if action not in _AUTHORITY_ACTIONS:
                raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_ACTION_INVALID")
            _required_token(grant, "authority_id")
            _token_tuple(grant, "scope_ids", allow_empty=False)
            materialities = _token_tuple(grant, "assumption_materialities", allow_empty=False)
            for mat in materialities:
                if mat not in _MATERIALITIES:
                    raise AssumptionConformanceError(
                        "ASSUMPTION_AUTHORITY_GRANT_MATERIALITY_INVALID"
                    )
            challenge_materialities = _token_tuple(
                grant, "challenge_materialities", allow_empty=True
            )
            for mat in challenge_materialities:
                if mat not in _MATERIALITIES:
                    raise AssumptionConformanceError(
                        "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_INVALID"
                    )
            # Resolution grants require challenge_materialities; non-resolution
            # grants must not carry any.
            is_resolution = action in _RESOLUTION_AUTHORITY_ACTIONS
            if is_resolution and not challenge_materialities:
                raise AssumptionConformanceError(
                    "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_REQUIRED"
                )
            if not is_resolution and challenge_materialities:
                raise AssumptionConformanceError(
                    "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_UNEXPECTED"
                )
            eff_from_value = _non_negative_int(grant, "effective_from_sequence")
            eff_until = grant.get("effective_until_sequence")
            if eff_until is not None and (
                type(eff_until) is not int or eff_until <= eff_from_value
            ):
                raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_INTERVAL_INVALID")
            # Independently recompute the grant digest and require equality.
            grant["grant_digest"]  # shape-check via _required_digest below
            _required_digest(grant, "grant_digest")
            rebuilt_grant_digest = _domain_digest(
                "ASSUMPTION_AUTHORITY_GRANT", _grant_unsigned_value(grant)
            )
            if cast(str, grant["grant_digest"]) != rebuilt_grant_digest:
                raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_DIGEST_MISMATCH")
            parsed_grants.append(grant)
        # Grants must be canonical (sorted by grant_id, unique).
        grant_ids = [cast(str, g["grant_id"]) for g in parsed_grants]
        if grant_ids != sorted(grant_ids) or len(set(grant_ids)) != len(grant_ids):
            raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANTS_NOT_CANONICAL")
        parsed_rules: list[dict[str, Any]] = []
        for raw_rule in _array(entry, "duty_rules"):
            rule = _as_object(raw_rule, "ASSUMPTION_DUTY_RULE_INVALID")
            _exact_keys(
                rule,
                {
                    "rule_id",
                    "action",
                    "conflicting_roles",
                    "scope_ids",
                    "assumption_materialities",
                    "rule_digest",
                },
                code="ASSUMPTION_DUTY_RULE_KEYS_INVALID",
            )
            _required_token(rule, "rule_id")
            r_action = _required_token(rule, "action")
            if r_action not in _AUTHORITY_ACTIONS:
                raise AssumptionConformanceError("ASSUMPTION_DUTY_RULE_ACTION_INVALID")
            roles = _token_tuple(rule, "conflicting_roles", allow_empty=False)
            for role in roles:
                if role not in _ASSUMPTION_GOVERNANCE_ROLES:
                    raise AssumptionConformanceError("ASSUMPTION_DUTY_RULE_ROLE_INVALID")
            _token_tuple(rule, "scope_ids", allow_empty=False)
            r_mats = _token_tuple(rule, "assumption_materialities", allow_empty=False)
            for mat in r_mats:
                if mat not in _MATERIALITIES:
                    raise AssumptionConformanceError("ASSUMPTION_DUTY_RULE_MATERIALITY_INVALID")
            _required_digest(rule, "rule_digest")
            rebuilt_rule_digest = _domain_digest(
                "ASSUMPTION_SEPARATION_DUTY_RULE", _rule_unsigned_value(rule)
            )
            if cast(str, rule["rule_digest"]) != rebuilt_rule_digest:
                raise AssumptionConformanceError("ASSUMPTION_DUTY_RULE_DIGEST_MISMATCH")
            parsed_rules.append(rule)
        rule_ids = [cast(str, r["rule_id"]) for r in parsed_rules]
        if rule_ids != sorted(rule_ids) or len(set(rule_ids)) != len(rule_ids):
            raise AssumptionConformanceError("ASSUMPTION_DUTY_RULES_NOT_CANONICAL")
        parsed_exceptions: list[dict[str, Any]] = []
        for raw_exc in _array(entry, "duty_exceptions"):
            exc = _as_object(raw_exc, "ASSUMPTION_DUTY_EXCEPTION_INVALID")
            _exact_keys(
                exc,
                {
                    "exception_id",
                    "rule_id",
                    "action",
                    "authority_id",
                    "conflicting_roles",
                    "scope_ids",
                    "assumption_ids",
                    "assumption_materialities",
                    "reason_code",
                    "effective_from_sequence",
                    "effective_until_sequence",
                    "exception_digest",
                },
                code="ASSUMPTION_DUTY_EXCEPTION_KEYS_INVALID",
            )
            _required_token(exc, "exception_id")
            _required_token(exc, "rule_id")
            e_action = _required_token(exc, "action")
            if e_action not in _AUTHORITY_ACTIONS:
                raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTION_ACTION_INVALID")
            _required_token(exc, "authority_id")
            e_roles = _token_tuple(exc, "conflicting_roles", allow_empty=False)
            for role in e_roles:
                if role not in _ASSUMPTION_GOVERNANCE_ROLES:
                    raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTION_ROLE_INVALID")
            _token_tuple(exc, "scope_ids", allow_empty=False)
            _token_tuple(exc, "assumption_ids", allow_empty=True)
            e_mats = _token_tuple(exc, "assumption_materialities", allow_empty=False)
            for mat in e_mats:
                if mat not in _MATERIALITIES:
                    raise AssumptionConformanceError(
                        "ASSUMPTION_DUTY_EXCEPTION_MATERIALITY_INVALID"
                    )
            _required_token(exc, "reason_code")
            _positive_int(exc, "effective_from_sequence")
            _positive_int(exc, "effective_until_sequence")
            if cast(int, exc["effective_until_sequence"]) <= cast(
                int, exc["effective_from_sequence"]
            ):
                raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTION_INTERVAL_INVALID")
            _required_digest(exc, "exception_digest")
            rebuilt_exc_digest = _domain_digest(
                "ASSUMPTION_DUTY_EXCEPTION", _exception_unsigned_value(exc)
            )
            if cast(str, exc["exception_digest"]) != rebuilt_exc_digest:
                raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTION_DIGEST_MISMATCH")
            parsed_exceptions.append(exc)
        exc_ids = [cast(str, e["exception_id"]) for e in parsed_exceptions]
        if exc_ids != sorted(exc_ids) or len(set(exc_ids)) != len(exc_ids):
            raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTIONS_NOT_CANONICAL")
        # Independently recompute the policy content and its three set digests
        # from the parsed grants/rules/exceptions and require equality with the
        # serialized set digests and policy_digest.
        (
            policy_unsigned,
            grant_set_digest,
            rule_set_digest,
            exception_set_digest,
        ) = _policy_unsigned_value(
            policy_id=policy_id,
            authority_root_digest=cast(str, value["authority_root_digest"]),
            grants=parsed_grants,  # full grant dicts (with digest) feed set digests
            rules=parsed_rules,
            exceptions=parsed_exceptions,
        )
        if cast(str, entry["grant_set_digest"]) != grant_set_digest:
            raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_GRANT_SET_DIGEST_MISMATCH")
        if cast(str, entry["separation_duty_rule_set_digest"]) != rule_set_digest:
            raise AssumptionConformanceError("ASSUMPTION_DUTY_RULE_SET_DIGEST_MISMATCH")
        if cast(str, entry["exception_set_digest"]) != exception_set_digest:
            raise AssumptionConformanceError("ASSUMPTION_DUTY_EXCEPTION_SET_DIGEST_MISMATCH")
        rebuilt_policy_digest = _domain_digest("ASSUMPTION_AUTHORITY_POLICY", policy_unsigned)
        if cast(str, entry["policy_digest"]) != rebuilt_policy_digest:
            raise AssumptionConformanceError("ASSUMPTION_AUTHORITY_POLICY_DIGEST_MISMATCH")
        entry["grants"] = parsed_grants
        entry["duty_rules"] = parsed_rules
        entry["duty_exceptions"] = parsed_exceptions
        parsed_entries.append(entry)
    # Validate the evidence registry (pinned admission decisions). Each receipt
    # is a complete A0-style EvidenceAdmissionEligibilityDecision whose
    # decision_digest the validator independently recompute-and-requires. This
    # replaces the prior trust of a bare ``eligible`` boolean.
    ev_reg_raw = value.get("evidence_registry")
    if type(ev_reg_raw) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_REGISTRY_INVALID")
    _exact_keys(
        cast(dict[str, Any], ev_reg_raw),
        {"evidence_registry_root", "receipts"},
        code="ASSUMPTION_EVIDENCE_REGISTRY_KEYS_INVALID",
    )
    evidence_registry_root = _required_digest(
        cast(dict[str, Any], ev_reg_raw), "evidence_registry_root"
    )
    receipts_raw = cast(dict[str, Any], ev_reg_raw).get("receipts")
    if type(receipts_raw) is not dict:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPTS_INVALID")
    parsed_receipts: dict[str, dict[str, Any]] = {}
    for evidence_id, raw_receipt in cast(dict[str, object], receipts_raw).items():
        receipt = _as_object(raw_receipt, "ASSUMPTION_EVIDENCE_RECEIPT_INVALID")
        _validate_evidence_admission_decision(receipt, evidence_id, evidence_registry_root)
        parsed_receipts[evidence_id] = receipt
    return {
        "schema_version": value["schema_version"],
        "authority_root_digest": value["authority_root_digest"],
        "ledger_root_digest": value["ledger_root_digest"],
        "policy_digest": value["policy_digest"],
        "ledger_entries": parsed_entries,
        "evidence_registry": {
            "evidence_registry_root": evidence_registry_root,
            "receipts": parsed_receipts,
        },
        "challenge_classifications": parsed_classifications,
    }


def _validate_evidence_admission_decision(
    receipt: dict[str, Any],
    evidence_id: str,
    evidence_registry_root: str,
) -> None:
    """Independently validate one A0 EvidenceAdmissionEligibilityDecision.

    Replicates EvidenceAdmissionEligibilityDecision.__post_init__: requires the
    canonical keys, binds the evidence_id / evaluated_at_sequence /
    evidence_registry_root, recompute-and-requires the decision_digest, and
    enforces eligible<->code consistency.
    """
    _exact_keys(
        receipt,
        {
            "schema_version",
            "evidence_id",
            "eligible",
            "code",
            "evaluated_at_sequence",
            "evidence_registry_root",
            "current_event_digest",
            "current_status",
            "decision_digest",
        },
        code="ASSUMPTION_EVIDENCE_RECEIPT_KEYS_INVALID",
    )
    if cast(str, receipt["schema_version"]) != _EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_SCHEMA_INVALID")
    if cast(str, receipt["evidence_id"]) != evidence_id:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_ID_MISMATCH")
    eligible = receipt.get("eligible")
    if type(eligible) is not bool:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_ELIGIBLE_INVALID")
    code = _required_token(receipt, "code")
    if eligible != (code == "EVIDENCE_ADMISSION_ELIGIBLE"):
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_RESULT_MISMATCH")
    evaluated_at = receipt.get("evaluated_at_sequence")
    if type(evaluated_at) is not int or isinstance(evaluated_at, bool) or evaluated_at < 0:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_SEQUENCE_INVALID")
    if cast(str, receipt["evidence_registry_root"]) != evidence_registry_root:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_ROOT_MISMATCH")
    current_event_digest = receipt.get("current_event_digest")
    if current_event_digest is not None and (
        type(current_event_digest) is not str or _DIGEST.fullmatch(current_event_digest) is None
    ):
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_EVENT_INVALID")
    current_status = receipt.get("current_status")
    if current_status is not None and (
        type(current_status) is not str or _TOKEN.fullmatch(current_status) is None
    ):
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_STATUS_INVALID")
    _required_digest(receipt, "decision_digest")
    rebuilt_decision_digest = _domain_digest(
        "EVIDENCE_ADMISSION_ELIGIBILITY", _evidence_admission_unsigned_value(receipt)
    )
    if cast(str, receipt["decision_digest"]) != rebuilt_decision_digest:
        raise AssumptionConformanceError("ASSUMPTION_EVIDENCE_RECEIPT_DIGEST_MISMATCH")


def _evidence_admission_unsigned_value(receipt: dict[str, Any]) -> dict[str, object]:
    return {
        "schema_version": _EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION,
        "code": receipt["code"],
        "current_event_digest": receipt["current_event_digest"],
        "current_status": receipt["current_status"],
        "eligible": receipt["eligible"],
        "evaluated_at_sequence": receipt["evaluated_at_sequence"],
        "evidence_id": receipt["evidence_id"],
        "evidence_registry_root": receipt["evidence_registry_root"],
    }


def _empty_policy_context() -> dict[str, Any]:
    zero = "sha256:" + "0" * 64
    return {
        "schema_version": "assumption-policy-context/1",
        "authority_root_digest": zero,
        "ledger_root_digest": zero,
        "policy_digest": zero,
        "ledger_entries": [],
        "evidence_registry": {"evidence_registry_root": zero, "receipts": {}},
        "challenge_classifications": {},
    }


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


def _non_negative_int(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 0:
        raise AssumptionConformanceError("ASSUMPTION_NON_NEGATIVE_INTEGER_INVALID", field)
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
