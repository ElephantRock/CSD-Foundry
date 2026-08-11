"""Independent serialized-artifact validation for v0.5-D4 alternative-model conformance.

This module mirrors :mod:`csd_foundry.governance.v0_5.assumption_validation` in
structure but re-implements the alternative-model lifecycle state machine, the
governed ADMIT authorization reconstruction (from a PROPOSE state + structural-
difference receipt), the structural-difference detector, the FULL_REPLAY receipt
invariant checks, the canonical INVARIANT/DIVERGENT comparison classifier, and
the D4 use-time authority gate from the production governance modules. It reads
only the serialized registry-event envelopes and the serialized receipts. It
MUST NOT import any production alternative-model governance module other than
``canonicalization``, ``contracts`` and ``resources``.

What this validator independently reimplements (and therefore independently
detects tampering of):

* The alternative-model lifecycle reducer (PROPOSE -> ADMIT -> UNVERIFIED ->
  CHALLENGE -> RESOLVE_CHALLENGES -> CONFIRM / REJECT / EXPIRE / SUPERSEDE),
  including chain verification (entity sequence, predecessor digest, advancing
  clock) and terminal-revival rejection.
* Registry snapshot-root computation over the projected entity heads.
* Structural-difference detection between two canonical JSON graphs (recursive
  dict + array walk, RFC 6901 JSON Pointer paths, six closed difference
  families), fail-closed on non-canonical graph bytes and on a declared
  difference digest that does not match the computed difference set.
* FULL_REPLAY receipt validation: executed == required, skipped == (), pruned
  == (), plus the self-digest.
* Canonical comparison validation (identical decision context, graph binding to
  the structural-difference receipt, INVARIANT/DIVERGENT classification, self-
  digest).
* The governed ADMIT authorization reconstruction: independently rebuild the
  :class:`GovernedAlternativeModelAuthorization` unsigned value from the
  PROPOSE state + structural-difference receipt + pre-ADMIT registry root, and
  require the ADMIT event's ``source_receipt_digest`` to equal the derived
  ``authorization_digest``.
* The D4 use-time authority gate: ALLOW only for ADMITTED/CONFIRMED, in-scope,
  reuse-class-eligible, non-expired models; DENY for UNVERIFIED, terminal,
  expired, out-of-scope, or reuse-class-exceeded requests.
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
from csd_foundry.governance.v0_5.resources import alternative_model_vectors

ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_VERSION = "alternative-model-event/1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

STANDING_PROPOSED = "PROPOSED"
STANDING_UNVERIFIED = "UNVERIFIED"
STANDING_ADMITTED = "ADMITTED"
STANDING_CONFIRMED = "CONFIRMED"
STANDING_CHALLENGED = "CHALLENGED"
STANDING_REJECTED = "REJECTED"
STANDING_EXPIRED = "EXPIRED"
STANDING_SUPERSEDED = "SUPERSEDED"

_TERMINAL_STANDINGS = frozenset({STANDING_REJECTED, STANDING_EXPIRED, STANDING_SUPERSEDED})
_CHALLENGEABLE_STANDINGS = frozenset({STANDING_UNVERIFIED, STANDING_ADMITTED, STANDING_CONFIRMED})
_USABLE_STANDINGS = frozenset({STANDING_ADMITTED, STANDING_CONFIRMED})
_MATERIALITIES = frozenset({"ADVISORY", "MATERIAL", "CRITICAL"})
_REUSE_CLASSES = frozenset({"D0", "D1", "D2", "D3", "BENCHMARK"})
_REUSE_CLASS_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}
_RESOLUTION_OUTCOMES = frozenset({"UPHOLD", "INVALIDATE"})
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
_DIFFERENCE_FAMILIES = frozenset(
    {
        "ADDED_REMOVED",
        "RELABELED",
        "SCOPE",
        "TEMPORAL",
        "AUTHORITY",
        "EVIDENCE_ADMISSION",
    }
)

# Schema versions and domain strings, replicated from _governed_alternative_model.
_STRUCTURAL_DIFFERENCE_SCHEMA_VERSION = "alternative-model-structural-difference-receipt/1"
_AUTHORIZATION_SCHEMA_VERSION = "alternative-model-governed-admit-authorization/1"
_REPLAY_RECEIPT_SCHEMA_VERSION = "alternative-model-replay-receipt/1"
_COMPARISON_RECEIPT_SCHEMA_VERSION = "alternative-model-comparison-receipt/1"
_USE_AUTHORITY_DECISION_SCHEMA_VERSION = "alternative-model-use-authority-decision/1"

_STRUCTURAL_DIFFERENCE_SET_DOMAIN = "ALTERNATIVE_MODEL_STRUCTURAL_DIFFERENCE"
_STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_STRUCTURAL_DIFFERENCE_RECEIPT"
_AUTHORIZATION_DOMAIN = "ALTERNATIVE_MODEL_GOVERNED_ADMIT_AUTHORIZATION"
_REPLAY_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_REPLAY_RECEIPT"
_COMPARISON_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_COMPARISON_RECEIPT"
_USE_AUTHORITY_DECISION_DOMAIN = "ALTERNATIVE_MODEL_USE_AUTHORITY_DECISION"


class AlternativeModelConformanceError(RuntimeError):
    """Stable independent conformance failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class _IndependentChallenge:
    """Independent record of one unresolved alternative-model challenge."""

    challenge_id: str
    challenger_authority_id: str
    reason_code: str
    challenge_receipt_digest: str
    opened_at_sequence: int
    opening_event_digest: str


@dataclass(frozen=True, slots=True)
class IndependentAlternativeModelProjection:
    """Independent projection of one alternative-model identity."""

    model_id: str
    model_version: str
    primary_model_id: str
    graph_digest: str
    declared_difference_digest: str
    challenge_basis_code: str
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
    active_challenges: tuple[_IndependentChallenge, ...]
    superseded_by_id: str | None
    limitations: tuple[str, ...]
    maximum_reuse_class: str
    proposal_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int

    @property
    def standing(self) -> str:
        if self.active_challenges:
            return STANDING_CHALLENGED
        return self.separation_status

    @property
    def status(self) -> str:
        return self.standing

    @property
    def terminal(self) -> bool:
        return self.separation_status in _TERMINAL_STANDINGS

    @property
    def active_challenge_ids(self) -> tuple[str, ...]:
        return tuple(item.challenge_id for item in self.active_challenges)


@dataclass(frozen=True, slots=True)
class AlternativeModelRegistryValidationReport:
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
            "schema_version": "alternative-model-registry-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
            "accepted_vector_count": self.accepted_vector_count,
            "rejected_vector_count": self.rejected_vector_count,
            "accepted_registry_roots": dict(self.accepted_registry_roots),
            "accepted_decision_digests": dict(self.accepted_decision_digests),
            "rejected_failure_codes": dict(self.rejected_failure_codes),
            "vector_catalog_digest": self.vector_catalog_digest,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report establishes deterministic serialized alternative-model-history, "
                "lifecycle, structural-difference, governed-ADMIT authorization, FULL_REPLAY, "
                "comparison, and use-time authority behavior relative to committed conformance "
                "vectors. It does not establish external truth, source completeness, real-world "
                "dependency completeness, or production safety."
            ),
        }


# =====================================================================
# Public entry point.
# =====================================================================


def validate_alternative_model_registry(
    release: str = "v0.5",
    vectors: dict[str, Any] | None = None,
) -> AlternativeModelRegistryValidationReport:
    errors: list[str] = []
    catalog = alternative_model_vectors() if vectors is None else deepcopy(vectors)
    accepted_roots: list[tuple[str, str]] = []
    accepted_decisions: list[tuple[str, str]] = []
    rejected_codes: list[tuple[str, str]] = []

    if release != "v0.5":
        errors.append("alternative model registry validation supports only v0.5")
    if type(catalog) is not dict:
        errors.append("alternative model vector catalog is not an object")
        catalog = {}
    if catalog.get("schema_version") != "alternative-model-conformance-vectors/0.5":
        errors.append("alternative model vector schema version changed")
    observed_catalog_digest = catalog.get("catalog_digest")
    if observed_catalog_digest != catalog_digest(catalog, b"ALTERNATIVE_MODEL_VECTOR_CATALOG\0"):
        errors.append("alternative model vector catalog digest changed")

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
            vector = _as_object(raw_vector, "ALTERNATIVE_MODEL_VECTOR_NOT_OBJECT")
            admissions = _admissions_by_model(vector)
            result = _validate_history(_array(vector, "events"), admissions)
            expected_root = _required_digest(vector, "expected_registry_root")
            actual_root = _snapshot_root(result.projections)
            if actual_root != expected_root:
                raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EXPECTED_ROOT_MISMATCH")
            expected_auth = _object(vector, "expected_authorization_digests")
            observed_auth = {pair[0]: pair[1] for pair in result.authorization_digests}
            if observed_auth != expected_auth:
                raise AlternativeModelConformanceError(
                    "ALTERNATIVE_MODEL_AUTHORIZATION_DIGESTS_MISMATCH"
                )
            # Validate any serialized structural-difference / replay / comparison receipts.
            _validate_structural_difference_receipts(vector)
            _validate_replay_receipts(vector)
            _validate_comparison_receipts(vector)
            binding = _optional_object(vector, "use_authority")
            decision = _evaluate_use_authority(binding, result.projections)
            expected_decision = _optional_object(vector, "expected_use_authority")
            if expected_decision is not None:
                observed_decision = {
                    "decision": decision["decision"],
                    "reason_code": decision["reason_code"],
                    "decision_digest": decision["decision_digest"],
                }
                if observed_decision != expected_decision:
                    raise AlternativeModelConformanceError(
                        "ALTERNATIVE_MODEL_USE_AUTHORITY_DECISION_MISMATCH"
                    )
            accepted_roots.append((vector_id, actual_root))
            if decision["decision_digest"]:
                accepted_decisions.append((vector_id, cast(str, decision["decision_digest"])))
        except (AlternativeModelConformanceError, GovernanceContractError) as exc:
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
            vector = _as_object(raw_vector, "ALTERNATIVE_MODEL_VECTOR_NOT_OBJECT")
            expected = _required_token(vector, "expected_error")
            stage = _required_token(vector, "stage")
            admissions = _admissions_by_model(vector)
            result = _validate_history(_array(vector, "events"), admissions)
            if stage == "USE":
                binding = _optional_object(vector, "use_authority")
                decision = _evaluate_use_authority(binding, result.projections)
                if decision["decision"] == "DENY":
                    observed = cast(str, decision["reason_code"])
            elif stage == "IDENTITY":
                expected_root = _required_digest(vector, "expected_registry_root")
                actual_root = _snapshot_root(result.projections)
                if actual_root != expected_root:
                    observed = "ALTERNATIVE_MODEL_EXPECTED_ROOT_MISMATCH"
            elif stage in {
                "HISTORY",
                "LIFECYCLE",
                "ADMISSION",
                "STRUCTURAL_DIFFERENCE",
                "REPLAY",
                "COMPARISON",
            }:
                observed = None
            else:
                observed = "ALTERNATIVE_MODEL_VECTOR_STAGE_INVALID"
        except (AlternativeModelConformanceError, GovernanceContractError) as exc:
            observed = exc.code
        if observed != expected:
            errors.append(
                f"{vector_id}: expected {expected or 'ERROR'}, observed {observed or 'ACCEPTED'}"
            )
        else:
            rejected_codes.append((vector_id, expected))

    return AlternativeModelRegistryValidationReport(
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


# =====================================================================
# History validation (lifecycle reducer).
# =====================================================================


@dataclass(frozen=True, slots=True)
class _HistoryResult:
    projections: dict[str, IndependentAlternativeModelProjection]
    authorization_digests: tuple[tuple[str, str], ...]


def _admissions_by_model(vector: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map model_id -> admission evidence (structural-difference receipt)."""
    admissions: dict[str, dict[str, Any]] = {}
    raw = vector.get("admissions")
    if raw is None:
        return admissions
    if type(raw) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ADMISSIONS_INVALID")
    for entry in cast(list[object], raw):
        item = _as_object(entry, "ALTERNATIVE_MODEL_ADMISSION_NOT_OBJECT")
        model_id = _required_token(item, "model_id")
        if model_id in admissions:
            raise AlternativeModelConformanceError(
                "ALTERNATIVE_MODEL_ADMISSION_DUPLICATE", model_id
            )
        admissions[model_id] = item
    return admissions


def _validate_history(
    events: list[object],
    admissions: dict[str, dict[str, Any]],
) -> _HistoryResult:
    projections: dict[str, IndependentAlternativeModelProjection] = {}
    auth_digests: list[tuple[str, str]] = []
    for raw_event in events:
        event_value = _as_object(raw_event, "ALTERNATIVE_MODEL_EVENT_NOT_OBJECT")
        event = cast(RegistryEvent, RegistryEvent.from_json(event_value))
        value = event.to_json_value()
        if value.get("registry_type") != "ALTERNATIVE_MODEL":
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_REGISTRY_TYPE_INVALID")
        if value.get("projection_phase") != "ALTERNATIVE_MODEL_REGISTRY":
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_PROJECTION_PHASE_INVALID")
        if value.get("payload_schema_version") != ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_VERSION:
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_PAYLOAD_SCHEMA_INVALID")
        model_id = _required_token(value, "entity_id")
        previous = projections.get(model_id)
        _verify_chain(previous, value, event)
        payload = _object(value, "payload")
        operation = _required_token(payload, "operation")
        # Governed ADMIT authorization reconstruction. Runs only when the prior
        # state is PROPOSED (a valid ADMIT transition); any other prior standing
        # is rejected by the lifecycle reducer with the appropriate transition
        # code, which takes precedence.
        if operation == "ADMIT" and previous is not None and previous.standing == STANDING_PROPOSED:
            auth_digest = _validate_governed_admit_authorization(
                previous, value, payload, admissions, projections
            )
            auth_digests.append((model_id, auth_digest))
        projections[model_id] = _reduce_independent(previous, value, payload)
    return _HistoryResult(
        projections=projections,
        authorization_digests=tuple(auth_digests),
    )


def _verify_chain(
    previous: IndependentAlternativeModelProjection | None,
    value: dict[str, Any],
    event: RegistryEvent,
) -> None:
    if previous is None:
        if (
            value.get("entity_sequence") != 1
            or value.get("previous_entity_event_digest") is not None
        ):
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GENESIS_LINK_INVALID")
        return
    if value.get("entity_id") != previous.model_id:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_IDENTITY_CHANGED")
    if value.get("entity_sequence") != previous.current_entity_sequence + 1:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ENTITY_SEQUENCE_NOT_SUCCESSOR")
    if value.get("previous_entity_event_digest") != previous.current_event_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_PREDECESSOR_MISMATCH")
    if cast(int, value.get("clock_sequence", 0)) <= previous.last_clock_sequence:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_CLOCK_NOT_ADVANCING")
    if event.digest == previous.current_event_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EVENT_IDENTITY_REUSED")


def _reduce_independent(
    previous: IndependentAlternativeModelProjection | None,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    operation = _required_token(payload, "operation")
    if previous is None:
        if operation != "PROPOSE":
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_FIRST_OPERATION_NOT_PROPOSE")
        return _propose(event, payload)
    if previous.separation_status in _TERMINAL_STANDINGS:
        raise AlternativeModelConformanceError(
            "ALTERNATIVE_MODEL_TERMINAL_IDENTITY_REUSE", previous.separation_status
        )
    if operation == "PROPOSE":
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_DUPLICATE_PROPOSAL")
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
    raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_OPERATION_UNSUPPORTED", operation)


def _propose(
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    _exact_keys(
        payload,
        {
            "operation",
            "model_version",
            "primary_model_id",
            "graph_digest",
            "declared_difference_digest",
            "challenge_basis_code",
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
    model_version = _required_token(payload, "model_version")
    primary_model_id = _required_token(payload, "primary_model_id")
    graph_digest = _required_digest(payload, "graph_digest")
    declared_difference_digest = _required_digest(payload, "declared_difference_digest")
    challenge_basis_code = _required_token(payload, "challenge_basis_code")
    scope_ids = _token_tuple(payload, "scope_ids", allow_empty=False)
    assumption_ids = _token_tuple(payload, "assumption_ids", allow_empty=True)
    evidence_ids = _token_tuple(payload, "evidence_ids", allow_empty=True)
    proposer = _required_token(payload, "proposer_authority_id")
    materiality = _required_token(payload, "materiality")
    if materiality not in _MATERIALITIES:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_MATERIALITY_INVALID")
    valid_from = _positive_int(payload, "valid_from_sequence")
    expires_at = _optional_positive_int(payload, "expires_at_sequence")
    if expires_at is not None and expires_at <= valid_from:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EXPIRY_NOT_AFTER_VALID_FROM")
    limitations = _token_tuple(payload, "limitations", allow_empty=True)
    reuse_class = _required_token(payload, "maximum_reuse_class")
    if reuse_class not in _REUSE_CLASSES:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_REUSE_CLASS_INVALID")
    return IndependentAlternativeModelProjection(
        model_id=_required_token(event, "entity_id"),
        model_version=model_version,
        primary_model_id=primary_model_id,
        graph_digest=graph_digest,
        declared_difference_digest=declared_difference_digest,
        challenge_basis_code=challenge_basis_code,
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
        proposal_source_receipt_digest=_required_digest(event, "source_receipt_digest"),
        current_source_receipt_digest=_required_digest(event, "source_receipt_digest"),
        current_event_digest=_required_digest(event, "registry_event_digest"),
        current_entity_sequence=cast(int, event["entity_sequence"]),
        last_clock_sequence=cast(int, event["clock_sequence"]),
    )


def _admit(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    _require_status(
        previous, frozenset({STANDING_PROPOSED}), "ALTERNATIVE_MODEL_ADMIT_TRANSITION_INVALID"
    )
    _exact_keys(payload, {"operation", "admitting_authority_id"})
    authority = _required_token(payload, "admitting_authority_id")
    return _advance(
        previous,
        event,
        separation_status=STANDING_UNVERIFIED,
        admitting_authority_id=authority,
    )


def _confirm(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    if previous.separation_status not in {
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_CONFIRM_TRANSITION_INVALID")
    if previous.active_challenges:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_CONFIRM_WITH_ACTIVE_CHALLENGES")
    _exact_keys(payload, {"operation", "confirming_authority_id"})
    authority = _required_token(payload, "confirming_authority_id")
    return _advance(
        previous,
        event,
        separation_status=STANDING_CONFIRMED,
        confirming_authority_id=authority,
    )


def _challenge(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    _require_status(
        previous, _CHALLENGEABLE_STANDINGS, "ALTERNATIVE_MODEL_CHALLENGE_TRANSITION_INVALID"
    )
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
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_CHALLENGE_ID_REUSED")
    challenge = _IndependentChallenge(
        challenge_id=challenge_id,
        challenger_authority_id=_required_token(payload, "challenger_authority_id"),
        reason_code=_required_token(payload, "challenge_reason_code"),
        challenge_receipt_digest=_required_digest(payload, "challenge_receipt_digest"),
        opened_at_sequence=cast(int, event["clock_sequence"]),
        opening_event_digest=_required_digest(event, "registry_event_digest"),
    )
    new_challenges = tuple(
        sorted((*previous.active_challenges, challenge), key=lambda item: item.challenge_id)
    )
    return _advance(previous, event, active_challenges=new_challenges)


def _resolve_challenges(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    _require_status(
        previous,
        _CHALLENGEABLE_STANDINGS,
        "ALTERNATIVE_MODEL_RESOLUTION_TRANSITION_INVALID",
    )
    if not previous.active_challenges:
        raise AlternativeModelConformanceError(
            "ALTERNATIVE_MODEL_RESOLUTION_WITHOUT_ACTIVE_CHALLENGE"
        )
    _exact_keys(
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
    outcome = _required_token(payload, "resolution_outcome")
    if outcome not in _RESOLUTION_OUTCOMES:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_RESOLUTION_OUTCOME_INVALID")
    _required_token(payload, "resolver_authority_id")
    _required_digest(payload, "resolution_receipt_digest")
    _required_token(payload, "resolution_basis_code")
    resolved_ids = _token_tuple(payload, "resolved_challenge_ids", allow_empty=False)
    active_ids = set(previous.active_challenge_ids)
    unknown = set(resolved_ids) - active_ids
    if unknown:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_RESOLUTION_CHALLENGE_UNKNOWN")
    replacement = payload.get("replacement_model_id")
    if replacement is not None:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_REPLACEMENT_UNEXPECTED")
    if outcome == "INVALIDATE":
        return _advance(
            previous,
            event,
            separation_status=STANDING_REJECTED,
            active_challenges=(),
        )
    # UPHOLD: keep unresolved challenges, preserve pre-challenge standing.
    remaining = tuple(
        item for item in previous.active_challenges if item.challenge_id not in set(resolved_ids)
    )
    if remaining:
        return _advance(previous, event, active_challenges=remaining)
    # All resolved: preserve previous.separation_status (not hardcoded ADMITTED).
    return _advance(previous, event, active_challenges=())


def _reject(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    if previous.separation_status not in {
        STANDING_PROPOSED,
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_REJECT_TRANSITION_INVALID")
    _exact_keys(payload, {"operation", "rejecting_authority_id", "reason_code"})
    _required_token(payload, "rejecting_authority_id")
    _required_token(payload, "reason_code")
    return _advance(previous, event, separation_status=STANDING_REJECTED, active_challenges=())


def _expire(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    if previous.separation_status not in {
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EXPIRE_TRANSITION_INVALID")
    _exact_keys(payload, {"operation", "expiry_authority_id", "expiry_receipt_digest"})
    _required_token(payload, "expiry_authority_id")
    _required_digest(payload, "expiry_receipt_digest")
    if previous.expires_at_sequence is None:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EXPIRY_NOT_DECLARED")
    if cast(int, event["clock_sequence"]) < previous.expires_at_sequence:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_EXPIRY_PREMATURE")
    return _advance(previous, event, separation_status=STANDING_EXPIRED, active_challenges=())


def _supersede(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentAlternativeModelProjection:
    if previous.separation_status not in {
        STANDING_PROPOSED,
        STANDING_UNVERIFIED,
        STANDING_ADMITTED,
        STANDING_CONFIRMED,
    }:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_SUPERSEDE_TRANSITION_INVALID")
    _exact_keys(
        payload,
        {
            "operation",
            "replacement_model_id",
            "superseding_authority_id",
            "supersession_receipt_digest",
            "reason_code",
        },
    )
    replacement = _required_token(payload, "replacement_model_id")
    if replacement == previous.model_id:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_SELF_SUPERSESSION")
    _required_token(payload, "superseding_authority_id")
    _required_digest(payload, "supersession_receipt_digest")
    _required_token(payload, "reason_code")
    return _advance(
        previous,
        event,
        separation_status=STANDING_SUPERSEDED,
        active_challenges=(),
        superseded_by_id=replacement,
    )


def _advance(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    *,
    separation_status: str | None = None,
    admitting_authority_id: str | None = None,
    confirming_authority_id: str | None = None,
    active_challenges: tuple[_IndependentChallenge, ...] | None = None,
    superseded_by_id: str | None = None,
) -> IndependentAlternativeModelProjection:
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
        current_source_receipt_digest=_required_digest(event, "source_receipt_digest"),
        current_event_digest=_required_digest(event, "registry_event_digest"),
        current_entity_sequence=cast(int, event["entity_sequence"]),
        last_clock_sequence=cast(int, event["clock_sequence"]),
    )


# =====================================================================
# Governed ADMIT authorization reconstruction (independently replicated).
# =====================================================================


def _validate_governed_admit_authorization(
    previous: IndependentAlternativeModelProjection,
    event: dict[str, Any],
    payload: dict[str, Any],
    admissions: dict[str, dict[str, Any]],
    projections: dict[str, IndependentAlternativeModelProjection],
) -> str:
    """Independently reconstruct the GovernedAlternativeModelAuthorization and
    require the ADMIT event's ``source_receipt_digest`` to equal the derived
    ``authorization_digest``.

    Mirrors ``append_governed_alternative_model_admit`` + the
    ``GovernedAlternativeModelAuthorization`` self-digest exactly. The
    authorization binds the model's PROPOSE state, the structural-difference
    receipt (validated independently), the pre-ADMIT registry root, and the
    admitting authority.
    """
    admission = admissions.get(previous.model_id)
    if admission is None:
        raise AlternativeModelConformanceError(
            "ALTERNATIVE_MODEL_ADMISSION_EVIDENCE_MISSING", previous.model_id
        )
    receipt_value = _object(admission, "structural_difference_receipt")
    receipt = _validate_structural_difference_receipt(receipt_value)
    if not receipt["has_material_difference"]:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_NO_MATERIAL_DIFFERENCE")
    if receipt["shadow_graph_digest"] != previous.graph_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_SHADOW_GRAPH_MISMATCH")
    if receipt["declared_difference_digest"] != previous.declared_difference_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_DECLARED_DIFFERENCE_MISMATCH")
    admitting_authority_id = _required_token(payload, "admitting_authority_id")
    event_sequence = cast(int, event["clock_sequence"])
    if event_sequence <= previous.last_clock_sequence:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ADMISSION_CLOCK_NOT_ADVANCING")
    if cast(str, event["previous_entity_event_digest"]) != previous.current_event_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ADMISSION_PREDECESSOR_MISMATCH")
    alt_model_root = _snapshot_root(projections)
    unsigned = {
        "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
        "admitting_authority_id": admitting_authority_id,
        "alternative_model_registry_root": alt_model_root,
        "assumption_ids": list(previous.assumption_ids),
        "candidate_entity_sequence": 2,
        "candidate_predecessor_event_digest": previous.current_event_digest,
        "evidence_ids": list(previous.evidence_ids),
        "event_sequence": event_sequence,
        "materiality": previous.materiality,
        "model_id": previous.model_id,
        "primary_graph_digest": receipt["primary_graph_digest"],
        "primary_model_id": previous.primary_model_id,
        "scope_ids": list(previous.scope_ids),
        "shadow_graph_digest": receipt["shadow_graph_digest"],
        "structural_difference_receipt": receipt_value,
    }
    auth_digest = _domain_digest(_AUTHORIZATION_DOMAIN, unsigned)
    supplied = _required_digest(event, "source_receipt_digest")
    if supplied != auth_digest:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ADMISSION_AUTHORIZATION_MISMATCH")
    return auth_digest


# =====================================================================
# Structural-difference detector (independently replicated).
# =====================================================================


def _canonical_graph_bytes(supplied_bytes: bytes) -> bytes:
    """Parse supplied JSON, deterministically re-encode, require equality."""
    if type(supplied_bytes) is not bytes:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID")
    try:
        value = json.loads(supplied_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID") from exc
    try:
        canonical = _json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID") from exc
    if canonical != supplied_bytes:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GRAPH_BYTES_NONCANONICAL")
    return canonical


def _graph_digest_of(canonical_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


def _classify_difference(path: str, *, present_both_sides: bool) -> str:
    lower = path.lower()
    if "scope" in lower:
        return "SCOPE"
    if (
        "temporal" in lower
        or "time" in lower
        or "sequence" in lower
        or "valid_from" in lower
        or "expires" in lower
    ):
        return "TEMPORAL"
    if "authority" in lower:
        return "AUTHORITY"
    if "evidence" in lower or "admission" in lower:
        return "EVIDENCE_ADMISSION"
    return "RELABELED" if present_both_sides else "ADDED_REMOVED"


def _escape_pointer_segment(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _collect_differences(
    primary: dict[str, Any],
    shadow: dict[str, Any],
    prefix: str,
    paths: list[str],
    families: list[str],
) -> None:
    all_keys = set(primary) | set(shadow)
    for key in sorted(all_keys):
        escaped = _escape_pointer_segment(key)
        path = f"{prefix}/{escaped}"
        in_primary = key in primary
        in_shadow = key in shadow
        if in_primary and in_shadow:
            primary_value = primary[key]
            shadow_value = shadow[key]
            if type(primary_value) is dict and type(shadow_value) is dict:
                _collect_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is list and type(shadow_value) is list:
                _collect_list_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is not type(shadow_value) or primary_value != shadow_value:
                paths.append(path)
                families.append(_classify_difference(path, present_both_sides=True))
        else:
            paths.append(path)
            families.append(_classify_difference(path, present_both_sides=False))


def _collect_list_differences(
    primary: list[Any],
    shadow: list[Any],
    prefix: str,
    paths: list[str],
    families: list[str],
) -> None:
    max_len = max(len(primary), len(shadow))
    for i in range(max_len):
        path = f"{prefix}/{i}"
        in_primary = i < len(primary)
        in_shadow = i < len(shadow)
        if in_primary and in_shadow:
            primary_value = primary[i]
            shadow_value = shadow[i]
            if type(primary_value) is dict and type(shadow_value) is dict:
                _collect_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is list and type(shadow_value) is list:
                _collect_list_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is not type(shadow_value) or primary_value != shadow_value:
                paths.append(path)
                families.append(_classify_difference(path, present_both_sides=True))
        else:
            paths.append(path)
            families.append(_classify_difference(path, present_both_sides=False))


def _compute_difference_set_digest(
    difference_families: tuple[str, ...],
    difference_paths: tuple[str, ...],
) -> str:
    return _domain_digest(
        _STRUCTURAL_DIFFERENCE_SET_DOMAIN,
        {
            "difference_families": list(difference_families),
            "difference_paths": list(difference_paths),
        },
    )


def _compute_structural_difference(
    primary_graph_bytes: bytes,
    shadow_graph_bytes: bytes,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Independently compute the canonical difference families + paths."""
    primary_canon = _canonical_graph_bytes(primary_graph_bytes)
    shadow_canon = _canonical_graph_bytes(shadow_graph_bytes)
    primary = json.loads(primary_canon.decode("utf-8"))
    shadow = json.loads(shadow_canon.decode("utf-8"))
    if type(primary) is not dict or type(shadow) is not dict:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_GRAPH_NOT_OBJECT")
    paths: list[str] = []
    families: list[str] = []
    _collect_differences(primary, shadow, "", paths, families)
    return tuple(sorted(set(families))), tuple(sorted(set(paths)))


def _validate_structural_difference_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Independently validate a serialized structural-difference receipt.

    Re-derives the computed difference-set digest from the receipt's own
    family/path tuples, requires it to match both the stored computed digest and
    the declared digest, and verifies the self-digest. Optionally, when
    ``primary_graph`` and ``shadow_graph`` objects are carried alongside the
    receipt (in the parent admission), the difference set is independently
    re-derived from the graphs and required to match.
    """
    if type(receipt) is not dict:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_RECEIPT_INVALID")
    _require_digest_value(
        receipt.get("primary_graph_digest"), "STRUCTURAL_DIFFERENCE_PRIMARY_GRAPH_DIGEST_INVALID"
    )
    _require_digest_value(
        receipt.get("shadow_graph_digest"), "STRUCTURAL_DIFFERENCE_SHADOW_GRAPH_DIGEST_INVALID"
    )
    _require_digest_value(
        receipt.get("computed_difference_digest"),
        "STRUCTURAL_DIFFERENCE_COMPUTED_DIGEST_INVALID",
    )
    _require_digest_value(
        receipt.get("declared_difference_digest"),
        "STRUCTURAL_DIFFERENCE_DECLARED_DIGEST_INVALID",
    )
    families = _require_difference_families(receipt.get("difference_families"))
    paths = _require_difference_paths(receipt.get("difference_paths"))
    has_material = receipt.get("has_material_difference")
    if type(has_material) is not bool:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_MATERIALITY_NOT_BOOL")
    if bool(families) != bool(paths):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_FAMILY_PATH_INCONSISTENT")
    if has_material != (len(paths) > 0):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_MATERIALITY_INCONSISTENT")
    recomputed = _compute_difference_set_digest(families, paths)
    if recomputed != receipt.get("computed_difference_digest"):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_COMPUTED_DIGEST_MISMATCH")
    if receipt.get("computed_difference_digest") != receipt.get("declared_difference_digest"):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_DECLARED_MISMATCH")
    unsigned = {
        "schema_version": _STRUCTURAL_DIFFERENCE_SCHEMA_VERSION,
        "primary_graph_digest": receipt["primary_graph_digest"],
        "shadow_graph_digest": receipt["shadow_graph_digest"],
        "computed_difference_digest": receipt["computed_difference_digest"],
        "declared_difference_digest": receipt["declared_difference_digest"],
        "difference_families": list(families),
        "difference_paths": list(paths),
        "has_material_difference": has_material,
    }
    _require_self_digest(
        _STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN,
        unsigned,
        receipt.get("receipt_digest"),
        "STRUCTURAL_DIFFERENCE_RECEIPT_DIGEST_MISMATCH",
    )
    return {**unsigned, "receipt_digest": receipt["receipt_digest"]}


def _validate_structural_difference_receipts(vector: dict[str, Any]) -> None:
    """Validate every structural-difference receipt carried by admissions."""
    admissions = vector.get("admissions")
    if admissions is None:
        return
    if type(admissions) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ADMISSIONS_INVALID")
    for entry in cast(list[object], admissions):
        item = _as_object(entry, "ALTERNATIVE_MODEL_ADMISSION_NOT_OBJECT")
        receipt = item.get("structural_difference_receipt")
        if receipt is None:
            continue
        validated = _validate_structural_difference_receipt(
            _object(item, "structural_difference_receipt")
        )
        # When the admission carries the raw graphs, re-derive the difference set
        # from them and require it to match the receipt's families/paths.
        primary_graph = item.get("primary_graph")
        shadow_graph = item.get("shadow_graph")
        if primary_graph is not None and shadow_graph is not None:
            primary_bytes = _json_bytes(primary_graph)
            shadow_bytes = _json_bytes(shadow_graph)
            expected_families, expected_paths = _compute_structural_difference(
                primary_bytes, shadow_bytes
            )
            if expected_families != tuple(validated["difference_families"]):
                raise AlternativeModelConformanceError(
                    "STRUCTURAL_DIFFERENCE_FAMILY_REDERIVE_MISMATCH"
                )
            if expected_paths != tuple(validated["difference_paths"]):
                raise AlternativeModelConformanceError(
                    "STRUCTURAL_DIFFERENCE_PATH_REDERIVE_MISMATCH"
                )
            if _graph_digest_of(primary_bytes) != validated["primary_graph_digest"]:
                raise AlternativeModelConformanceError(
                    "STRUCTURAL_DIFFERENCE_PRIMARY_GRAPH_DIGEST_MISMATCH"
                )
            if _graph_digest_of(shadow_bytes) != validated["shadow_graph_digest"]:
                raise AlternativeModelConformanceError(
                    "STRUCTURAL_DIFFERENCE_SHADOW_GRAPH_DIGEST_MISMATCH"
                )


# =====================================================================
# FULL_REPLAY receipt validation (independently replicated).
# =====================================================================


def _require_canonical_tokens(value: object, code: str, *, allow_empty: bool) -> tuple[str, ...]:
    if type(value) is not tuple:
        if type(value) is not list:
            raise AlternativeModelConformanceError(code)
        value = tuple(cast(list[str], value))
    if type(value) is not tuple:
        raise AlternativeModelConformanceError(code)
    if not allow_empty and not value:
        raise AlternativeModelConformanceError(code)
    for item in value:
        if type(item) is not str:
            raise AlternativeModelConformanceError(code)
        if _TOKEN.fullmatch(item) is None:
            raise AlternativeModelConformanceError(code)
    if tuple(sorted(value)) != value:
        raise AlternativeModelConformanceError(code)
    if len(set(value)) != len(value):
        raise AlternativeModelConformanceError(code)
    return cast(tuple[str, ...], value)


def _validate_replay_receipt(receipt: dict[str, Any]) -> None:
    """Independently validate a serialized FULL_REPLAY receipt."""
    if type(receipt) is not dict:
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_INVALID")
    _require_digest_value(receipt.get("graph_digest"), "REPLAY_RECEIPT_GRAPH_DIGEST_INVALID")
    _require_digest_value(
        receipt.get("decision_context_digest"), "REPLAY_RECEIPT_DECISION_CONTEXT_INVALID"
    )
    _require_digest_value(
        receipt.get("initial_state_digest"), "REPLAY_RECEIPT_INITIAL_STATE_INVALID"
    )
    _require_digest_value(
        receipt.get("semantic_outcome_digest"), "REPLAY_RECEIPT_SEMANTIC_OUTCOME_INVALID"
    )
    logical_clock = receipt.get("logical_clock")
    if type(logical_clock) is not int or isinstance(logical_clock, bool) or logical_clock < 1:
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_LOGICAL_CLOCK_INVALID")
    runner = receipt.get("runner_revision")
    if type(runner) is not str or _TOKEN.fullmatch(runner) is None:
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_RUNNER_REVISION_INVALID")
    required = _require_canonical_tokens(
        receipt.get("required_inventory"),
        "REPLAY_RECEIPT_REQUIRED_INVENTORY_INVALID",
        allow_empty=True,
    )
    executed = _require_canonical_tokens(
        receipt.get("executed_inventory"),
        "REPLAY_RECEIPT_EXECUTED_INVENTORY_INVALID",
        allow_empty=True,
    )
    skipped = _require_canonical_tokens(
        receipt.get("skipped_inventory"),
        "REPLAY_RECEIPT_SKIPPED_INVENTORY_INVALID",
        allow_empty=True,
    )
    pruned = _require_canonical_tokens(
        receipt.get("pruned_inventory"),
        "REPLAY_RECEIPT_PRUNED_INVENTORY_INVALID",
        allow_empty=True,
    )
    if executed != required:
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_NOT_FULLY_EXECUTED")
    if skipped != ():
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_SKIPPED_NONEMPTY")
    if pruned != ():
        raise AlternativeModelConformanceError("REPLAY_RECEIPT_PRUNED_NONEMPTY")
    unsigned = {
        "schema_version": _REPLAY_RECEIPT_SCHEMA_VERSION,
        "graph_digest": receipt["graph_digest"],
        "decision_context_digest": receipt["decision_context_digest"],
        "initial_state_digest": receipt["initial_state_digest"],
        "logical_clock": logical_clock,
        "runner_revision": runner,
        "required_inventory": list(required),
        "executed_inventory": list(executed),
        "skipped_inventory": list(skipped),
        "pruned_inventory": list(pruned),
        "semantic_outcome_digest": receipt["semantic_outcome_digest"],
    }
    _require_self_digest(
        _REPLAY_RECEIPT_DOMAIN,
        unsigned,
        receipt.get("receipt_digest"),
        "REPLAY_RECEIPT_DIGEST_MISMATCH",
    )


def _validate_replay_receipts(vector: dict[str, Any]) -> None:
    raw = vector.get("replay_receipts")
    if raw is None:
        return
    if type(raw) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_REPLAY_RECEIPTS_INVALID")
    for entry in cast(list[object], raw):
        _validate_replay_receipt(_as_object(entry, "REPLAY_RECEIPT_NOT_OBJECT"))


# =====================================================================
# Canonical comparison validation (independently replicated).
# =====================================================================


def _validate_comparison_receipt(receipt: dict[str, Any]) -> None:
    """Independently validate a serialized comparison receipt."""
    if type(receipt) is not dict:
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_INVALID")
    primary = _object(receipt, "primary_replay_receipt")
    shadow = _object(receipt, "shadow_replay_receipt")
    diff = _object(receipt, "structural_difference_receipt")
    comparison_result = receipt.get("comparison_result")
    if type(comparison_result) is not str:
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_RESULT_TYPE_INVALID")
    # Validate nested receipts.
    _validate_replay_receipt(primary)
    _validate_replay_receipt(shadow)
    _validate_structural_difference_receipt(diff)
    # Identical decision context binding.
    if primary.get("decision_context_digest") != shadow.get("decision_context_digest"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_DECISION_CONTEXT_MISMATCH")
    if primary.get("initial_state_digest") != shadow.get("initial_state_digest"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_INITIAL_STATE_MISMATCH")
    if primary.get("logical_clock") != shadow.get("logical_clock"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_LOGICAL_CLOCK_MISMATCH")
    if primary.get("runner_revision") != shadow.get("runner_revision"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_RUNNER_REVISION_MISMATCH")
    if primary.get("required_inventory") != shadow.get("required_inventory"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_REQUIRED_INVENTORY_MISMATCH")
    # Graph binding to the structural-difference receipt.
    if primary.get("graph_digest") != diff.get("primary_graph_digest"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_PRIMARY_GRAPH_BINDING_MISMATCH")
    if shadow.get("graph_digest") != diff.get("shadow_graph_digest"):
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_SHADOW_GRAPH_BINDING_MISMATCH")
    # Result classification.
    if primary.get("semantic_outcome_digest") == shadow.get("semantic_outcome_digest"):
        expected_result = "INVARIANT"
    else:
        expected_result = "DIVERGENT"
    if comparison_result not in ("INVARIANT", "DIVERGENT"):
        raise AlternativeModelConformanceError(
            "COMPARISON_RECEIPT_RESULT_INVALID", comparison_result
        )
    if comparison_result != expected_result:
        raise AlternativeModelConformanceError("COMPARISON_RECEIPT_RESULT_MISMATCH")
    unsigned: dict[str, object] = {
        "schema_version": _COMPARISON_RECEIPT_SCHEMA_VERSION,
        "primary_replay_receipt": primary,
        "shadow_replay_receipt": shadow,
        "structural_difference_receipt": diff,
        "comparison_result": comparison_result,
    }
    _require_self_digest(
        _COMPARISON_RECEIPT_DOMAIN,
        unsigned,
        receipt.get("comparison_digest"),
        "COMPARISON_RECEIPT_DIGEST_MISMATCH",
    )


def _validate_comparison_receipts(vector: dict[str, Any]) -> None:
    raw = vector.get("comparison_receipts")
    if raw is None:
        return
    if type(raw) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_COMPARISON_RECEIPTS_INVALID")
    for entry in cast(list[object], raw):
        _validate_comparison_receipt(_as_object(entry, "COMPARISON_RECEIPT_NOT_OBJECT"))


# =====================================================================
# Use-time authority gate (independently replicated).
# =====================================================================


def _evaluate_use_authority(
    binding: dict[str, Any] | None,
    projections: dict[str, IndependentAlternativeModelProjection],
) -> dict[str, Any]:
    """Independently evaluate the D4 use-time authority decision."""
    if binding is None:
        return {"decision": "", "reason_code": "", "decision_digest": ""}
    model_id = _required_token(binding, "model_id")
    logical_clock = binding.get("logical_clock")
    if type(logical_clock) is not int or isinstance(logical_clock, bool) or logical_clock < 1:
        raise AlternativeModelConformanceError("USE_AUTHORITY_LOGICAL_CLOCK_INVALID")
    scope_id = _required_token(binding, "scope_id")
    required_reuse_class = _required_token(binding, "required_reuse_class")
    if required_reuse_class not in _REUSE_CLASSES:
        raise AlternativeModelConformanceError("USE_AUTHORITY_REQUIRED_REUSE_CLASS_INVALID")
    model = projections.get(model_id)
    if model is None:
        raise AlternativeModelConformanceError("USE_AUTHORITY_MODEL_MISSING")
    standing = model.standing
    maximum_reuse_class = model.maximum_reuse_class
    if maximum_reuse_class not in _REUSE_CLASSES:
        raise AlternativeModelConformanceError("USE_AUTHORITY_MAXIMUM_REUSE_CLASS_INVALID")
    if standing == STANDING_UNVERIFIED:
        decision = "DENY"
        reason_code = "USE_DENIED_UNVERIFIED"
    elif model.terminal:
        decision = "DENY"
        reason_code = "USE_DENIED_TERMINAL"
    elif standing not in _USABLE_STANDINGS:
        decision = "DENY"
        reason_code = "USE_DENIED_NOT_ADMISSIBLE"
    elif model.expires_at_sequence is not None and logical_clock >= model.expires_at_sequence:
        decision = "DENY"
        reason_code = "USE_DENIED_EXPIRED"
    elif scope_id not in model.scope_ids:
        decision = "DENY"
        reason_code = "USE_DENIED_SCOPE"
    elif _REUSE_CLASS_RANK[required_reuse_class] > _REUSE_CLASS_RANK[maximum_reuse_class]:
        decision = "DENY"
        reason_code = "USE_DENIED_REUSE_CLASS"
    else:
        decision = "ALLOW"
        reason_code = "USE_ALLOWED"
    unsigned = {
        "schema_version": _USE_AUTHORITY_DECISION_SCHEMA_VERSION,
        "model_id": model_id,
        "logical_clock": logical_clock,
        "scope_id": scope_id,
        "required_reuse_class": required_reuse_class,
        "maximum_reuse_class": maximum_reuse_class,
        "separation_status": model.separation_status,
        "expires_at_sequence": model.expires_at_sequence,
        "decision": decision,
        "reason_code": reason_code,
    }
    decision_digest = _domain_digest(_USE_AUTHORITY_DECISION_DOMAIN, unsigned)
    return {
        "decision": decision,
        "reason_code": reason_code,
        "decision_digest": decision_digest,
    }


# =====================================================================
# Internal helpers.
# =====================================================================


def _snapshot_root(
    projections: dict[str, IndependentAlternativeModelProjection],
) -> str:
    value = {
        "schema_version": "registry-snapshot/1",
        "registry_type": "ALTERNATIVE_MODEL",
        "heads": [
            {
                "entity_id": item.model_id,
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


def _require_self_digest(
    domain: str,
    unsigned: dict[str, object],
    actual: object,
    code: str,
) -> None:
    _require_digest_value(actual, code)
    if actual != _domain_digest(domain, unsigned):
        raise AlternativeModelConformanceError(code)


def _require_digest_value(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AlternativeModelConformanceError(code)


def _require_difference_families(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_FAMILIES_INVALID")
    for item in value:
        if type(item) is not str or item not in _DIFFERENCE_FAMILIES:
            raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_FAMILIES_INVALID")
    if sorted(value) != value:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_FAMILIES_INVALID")
    if len(set(value)) != len(value):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_FAMILIES_INVALID")
    return tuple(cast(list[str], value))


def _require_difference_paths(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_PATHS_INVALID")
    for item in value:
        if type(item) is not str or not item:
            raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_PATHS_INVALID")
    str_value = cast(list[str], value)
    if sorted(str_value) != str_value:
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_PATHS_INVALID")
    if len(set(str_value)) != len(str_value):
        raise AlternativeModelConformanceError("STRUCTURAL_DIFFERENCE_PATHS_INVALID")
    return tuple(str_value)


def _exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    actual = set(value)
    missing = expected - actual
    unexpected = actual - expected
    if missing or unexpected:
        raise AlternativeModelConformanceError(
            "ALTERNATIVE_MODEL_PAYLOAD_KEYS_INVALID",
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}",
        )


def _require_status(
    previous: IndependentAlternativeModelProjection,
    allowed: frozenset[str],
    code: str,
) -> None:
    if previous.separation_status not in allowed:
        raise AlternativeModelConformanceError(code, previous.separation_status)


def _positive_int(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or isinstance(item, bool) or item < 1:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_POSITIVE_INTEGER_INVALID", field)
    return item


def _optional_positive_int(value: dict[str, Any], field: str) -> int | None:
    item = value.get(field)
    if item is None:
        return None
    if type(item) is not int or isinstance(item, bool) or item < 1:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_POSITIVE_INTEGER_INVALID", field)
    return item


def _token_tuple(value: dict[str, Any], field: str, *, allow_empty: bool) -> tuple[str, ...]:
    item = value.get(field)
    if type(item) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_TUPLE_INVALID", field)
    result = tuple(cast(list[str], item))
    if not allow_empty and not result:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_TUPLE_INVALID", field)
    for entry in result:
        if type(entry) is not str or _TOKEN.fullmatch(entry) is None:
            raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_TUPLE_INVALID", field)
    if tuple(sorted(result)) != result:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_TUPLE_INVALID", field)
    if len(set(result)) != len(result):
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_TUPLE_INVALID", field)
    return result


def _as_object(value: object, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise AlternativeModelConformanceError(code)
    return cast(dict[str, Any], value)


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    item = value.get(field)
    if type(item) is not dict:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _optional_object(value: dict[str, Any], field: str) -> dict[str, Any] | None:
    item = value.get(field)
    if item is None:
        return None
    if type(item) is not dict:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _array(value: dict[str, Any], field: str) -> list[object]:
    item = value.get(field)
    if type(item) is not list:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_ARRAY_INVALID", field)
    return cast(list[object], item)


def _required_digest(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _DIGEST.fullmatch(item) is None:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_DIGEST_INVALID", field)
    return item


def _required_token(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _TOKEN.fullmatch(item) is None:
        raise AlternativeModelConformanceError("ALTERNATIVE_MODEL_TOKEN_INVALID", field)
    return item


def _vector_id_or_placeholder(value: object) -> str:
    if type(value) is dict:
        item = cast(dict[str, Any], value).get("vector_id")
        if type(item) is str and item:
            return item
    return "UNKNOWN-VECTOR"
