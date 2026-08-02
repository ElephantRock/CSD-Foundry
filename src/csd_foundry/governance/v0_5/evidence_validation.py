"""Independent serialized-artifact validation for v0.5-D2 evidence conformance."""

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
from csd_foundry.governance.v0_5.resources import evidence_vectors

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_REUSE_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}
_TERMINAL = {"EXPIRED", "INVALIDATED", "REJECTED", "SUPERSEDED"}
_AUTHORITY_FIELD = {
    "REGISTER": "issuer_authority_id",
    "VERIFY": "verifier_authority_id",
    "REJECT": "rejecting_authority_id",
    "CHALLENGE": "challenger_authority_id",
    "RESOLVE_CHALLENGE": "resolver_authority_id",
    "EXPIRE": "expiry_authority_id",
    "INVALIDATE": "invalidating_authority_id",
    "SUPERSEDE": "superseding_authority_id",
}


class EvidenceConformanceError(RuntimeError):
    """Stable independent conformance failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class IndependentEvidenceProjection:
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
    active_challenge_reason: str | None
    superseded_by_id: str | None
    registration_source_receipt_digest: str
    current_source_receipt_digest: str
    current_event_digest: str
    current_entity_sequence: int
    last_clock_sequence: int


@dataclass(frozen=True, slots=True)
class EvidenceRegistryValidationReport:
    accepted_vector_count: int
    rejected_vector_count: int
    accepted_registry_roots: tuple[tuple[str, str], ...]
    accepted_receipt_digests: tuple[tuple[str, str], ...]
    rejected_failure_codes: tuple[tuple[str, str], ...]
    vector_catalog_digest: str | None
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "evidence-registry-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
            "accepted_vector_count": self.accepted_vector_count,
            "rejected_vector_count": self.rejected_vector_count,
            "accepted_registry_roots": dict(self.accepted_registry_roots),
            "accepted_receipt_digests": dict(self.accepted_receipt_digests),
            "rejected_failure_codes": dict(self.rejected_failure_codes),
            "vector_catalog_digest": self.vector_catalog_digest,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report establishes deterministic serialized evidence-history, authority, "
                "dependency, and admissibility behavior relative to committed conformance "
                "vectors and encoded policies. It does not establish external truth, source "
                "completeness, real-world dependency completeness, or production safety."
            ),
        }


def validate_evidence_registry(
    release: str = "v0.5",
    vectors: dict[str, Any] | None = None,
) -> EvidenceRegistryValidationReport:
    errors: list[str] = []
    catalog = evidence_vectors() if vectors is None else deepcopy(vectors)
    accepted_roots: list[tuple[str, str]] = []
    accepted_receipts: list[tuple[str, str]] = []
    rejected_codes: list[tuple[str, str]] = []

    if release != "v0.5":
        errors.append("evidence registry validation supports only v0.5")
    if type(catalog) is not dict:
        errors.append("evidence vector catalog is not an object")
        catalog = {}
    if catalog.get("schema_version") != "evidence-conformance-vectors/0.5":
        errors.append("evidence vector schema version changed")
    observed_catalog_digest = catalog.get("catalog_digest")
    if observed_catalog_digest != catalog_digest(catalog, b"EVIDENCE_VECTOR_CATALOG\0"):
        errors.append("evidence vector catalog digest changed")

    try:
        policy = _parse_authority_policy(_object(catalog, "authority_policy"))
        challenge_policy = _parse_challenge_policy(_object(catalog, "challenge_policy"))
    except EvidenceConformanceError as exc:
        errors.append(f"policy: {exc}")
        policy = _empty_policy()
        challenge_policy = _empty_challenge_policy()

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
            vector = _as_object(raw_vector, "EVIDENCE_VECTOR_NOT_OBJECT")
            result = _validate_history(_array(vector, "events"), policy)
            expected_root = _required_digest(vector, "expected_registry_root")
            actual_root = _snapshot_root(result.projections)
            if actual_root != expected_root:
                raise EvidenceConformanceError("EVIDENCE_EXPECTED_ROOT_MISMATCH")
            _compare_projections(vector, result.projections)
            expected_decisions = _array(vector, "expected_authority_decision_digests")
            observed_decisions = [
                cast(str, decision["decision_digest"]) for decision in result.authority_decisions
            ]
            if observed_decisions != expected_decisions:
                raise EvidenceConformanceError("EVIDENCE_AUTHORITY_DECISIONS_MISMATCH")
            request = _object(vector, "use_request")
            receipt = _evaluate_use(
                request,
                result.projections,
                policy,
                challenge_policy,
            )
            expected_receipt = _object(vector, "expected_admissibility")
            observed_receipt = {
                "allowed": receipt["allowed"],
                "code": receipt["code"],
                "receipt_digest": receipt["receipt_digest"],
            }
            if observed_receipt != expected_receipt:
                raise EvidenceConformanceError("EVIDENCE_ADMISSIBILITY_RECEIPT_MISMATCH")
            accepted_roots.append((vector_id, actual_root))
            accepted_receipts.append((vector_id, cast(str, receipt["receipt_digest"])))
        except (EvidenceConformanceError, GovernanceContractError) as exc:
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
            vector = _as_object(raw_vector, "EVIDENCE_VECTOR_NOT_OBJECT")
            expected = _required_token(vector, "expected_error")
            stage = _required_token(vector, "stage")
            result = _validate_history(_array(vector, "events"), policy)
            if stage == "USE":
                request = _object(vector, "use_request")
                receipt = _evaluate_use(
                    request,
                    result.projections,
                    policy,
                    challenge_policy,
                )
                if receipt["allowed"] is False:
                    observed = cast(str, receipt["code"])
            elif stage in {"CONTRACT", "AUTHORITY", "HISTORY"}:
                observed = None
            else:
                observed = "EVIDENCE_VECTOR_STAGE_INVALID"
        except (EvidenceConformanceError, GovernanceContractError) as exc:
            observed = exc.code
        if observed != expected:
            errors.append(
                f"{vector_id}: expected {expected or 'ERROR'}, observed {observed or 'ACCEPTED'}"
            )
        else:
            rejected_codes.append((vector_id, expected))

    return EvidenceRegistryValidationReport(
        accepted_vector_count=len(accepted_values),
        rejected_vector_count=len(rejected_values),
        accepted_registry_roots=tuple(accepted_roots),
        accepted_receipt_digests=tuple(accepted_receipts),
        rejected_failure_codes=tuple(rejected_codes),
        vector_catalog_digest=(
            observed_catalog_digest if type(observed_catalog_digest) is str else None
        ),
        errors=tuple(errors),
    )


@dataclass(frozen=True, slots=True)
class _HistoryResult:
    projections: dict[str, IndependentEvidenceProjection]
    authority_decisions: tuple[dict[str, object], ...]


def _validate_history(events: list[object], policy: dict[str, Any]) -> _HistoryResult:
    projections: dict[str, IndependentEvidenceProjection] = {}
    decisions: list[dict[str, object]] = []
    for raw_event in events:
        event_value = _as_object(raw_event, "EVIDENCE_EVENT_NOT_OBJECT")
        event = cast(RegistryEvent, RegistryEvent.from_json(event_value))
        value = event.to_json_value()
        if value.get("registry_type") != "EVIDENCE_UNIT":
            raise EvidenceConformanceError("EVIDENCE_REGISTRY_TYPE_INVALID")
        if value.get("projection_phase") != "EVIDENCE_REGISTRY":
            raise EvidenceConformanceError("EVIDENCE_PROJECTION_PHASE_INVALID")
        if value.get("payload_schema_version") != "evidence-unit-event/1":
            raise EvidenceConformanceError("EVIDENCE_PAYLOAD_SCHEMA_INVALID")
        evidence_id = _required_token(value, "entity_id")
        previous = projections.get(evidence_id)
        expected_sequence = 1 if previous is None else previous.current_entity_sequence + 1
        if value.get("entity_sequence") != expected_sequence:
            raise EvidenceConformanceError("EVIDENCE_SEQUENCE_MISMATCH")
        expected_previous = None if previous is None else previous.current_event_digest
        if value.get("previous_entity_event_digest") != expected_previous:
            raise EvidenceConformanceError("EVIDENCE_PREDECESSOR_MISMATCH")
        if (
            previous is not None
            and cast(int, value["clock_sequence"]) <= previous.last_clock_sequence
        ):
            raise EvidenceConformanceError("EVIDENCE_CLOCK_NOT_ADVANCING")
        payload = _object(value, "payload")
        decision = _authority_decision(value, payload, previous, policy)
        decisions.append(decision)
        if decision["allowed"] is not True:
            raise EvidenceConformanceError(cast(str, decision["code"]))
        projections[evidence_id] = _reduce_independent(previous, value, payload)
    return _HistoryResult(projections=projections, authority_decisions=tuple(decisions))


def _reduce_independent(
    previous: IndependentEvidenceProjection | None,
    event: dict[str, Any],
    payload: dict[str, Any],
) -> IndependentEvidenceProjection:
    operation = _required_token(payload, "operation")
    if previous is None:
        if operation != "REGISTER":
            raise EvidenceConformanceError("EVIDENCE_FIRST_OPERATION_NOT_REGISTER")
        _exact_keys(
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
        issued = _positive_int(payload, "issued_at_sequence")
        if issued != event["clock_sequence"]:
            raise EvidenceConformanceError("EVIDENCE_ISSUANCE_CLOCK_MISMATCH")
        valid_from = _positive_int(payload, "valid_from_sequence")
        if valid_from < issued:
            raise EvidenceConformanceError("EVIDENCE_VALIDITY_PRECEDES_ISSUANCE")
        expires = payload.get("expires_at_sequence")
        if expires is not None:
            if type(expires) is not int or expires <= valid_from:
                raise EvidenceConformanceError("EVIDENCE_EXPIRY_NOT_AFTER_VALID_FROM")
        scope_ids = _token_tuple(payload, "scope_ids", allow_empty=False)
        dependency_ids = _token_tuple(payload, "dependency_ids")
        evidence_id = _required_token(event, "entity_id")
        if evidence_id in dependency_ids:
            raise EvidenceConformanceError("EVIDENCE_SELF_DEPENDENCY")
        reuse = _required_token(payload, "maximum_reuse_class")
        if reuse not in _REUSE_RANK:
            raise EvidenceConformanceError("EVIDENCE_REUSE_CLASS_INVALID")
        receipt = _required_digest(event, "source_receipt_digest")
        return IndependentEvidenceProjection(
            evidence_id=evidence_id,
            proposition_id=_required_token(payload, "proposition_id"),
            scope_ids=scope_ids,
            source_id=_required_token(payload, "source_id"),
            issuer_authority_id=_required_token(payload, "issuer_authority_id"),
            verifier_authority_id=None,
            issued_at_sequence=issued,
            valid_from_sequence=valid_from,
            expires_at_sequence=cast(int | None, expires),
            dependency_ids=dependency_ids,
            limitations=_token_tuple(payload, "limitations"),
            maximum_reuse_class=reuse,
            status="REGISTERED",
            active_challenge_digest=None,
            active_challenge_reason=None,
            superseded_by_id=None,
            registration_source_receipt_digest=receipt,
            current_source_receipt_digest=receipt,
            current_event_digest=_required_digest(event, "registry_event_digest"),
            current_entity_sequence=cast(int, event["entity_sequence"]),
            last_clock_sequence=cast(int, event["clock_sequence"]),
        )
    if previous.status in _TERMINAL:
        raise EvidenceConformanceError("EVIDENCE_TERMINAL_IDENTITY_REUSE")
    if operation == "REGISTER":
        raise EvidenceConformanceError("EVIDENCE_DUPLICATE_REGISTRATION")
    if operation == "VERIFY":
        _require_status(previous, {"REGISTERED"}, "EVIDENCE_VERIFY_TRANSITION_INVALID")
        _exact_keys(payload, {"operation", "verifier_authority_id"})
        return _advance(
            previous,
            event,
            status="VERIFIED",
            verifier_authority_id=_required_token(payload, "verifier_authority_id"),
        )
    if operation == "REJECT":
        _require_status(previous, {"REGISTERED"}, "EVIDENCE_REJECT_TRANSITION_INVALID")
        _exact_keys(payload, {"operation", "rejecting_authority_id", "reason_code"})
        return _advance(previous, event, status="REJECTED")
    if operation == "CHALLENGE":
        _require_status(previous, {"VERIFIED"}, "EVIDENCE_CHALLENGE_TRANSITION_INVALID")
        _exact_keys(
            payload,
            {
                "operation",
                "challenger_authority_id",
                "challenge_reason_code",
                "challenge_receipt_digest",
            },
        )
        return _advance(
            previous,
            event,
            status="CHALLENGED",
            active_challenge_digest=_required_digest(payload, "challenge_receipt_digest"),
            active_challenge_reason=_required_token(payload, "challenge_reason_code"),
        )
    if operation == "RESOLVE_CHALLENGE":
        _require_status(
            previous,
            {"CHALLENGED"},
            "EVIDENCE_CHALLENGE_RESOLUTION_TRANSITION_INVALID",
        )
        _exact_keys(
            payload,
            {"operation", "resolution", "resolver_authority_id", "resolution_receipt_digest"},
        )
        resolution = _required_token(payload, "resolution")
        if resolution not in {"UPHOLD", "INVALIDATE"}:
            raise EvidenceConformanceError("EVIDENCE_RESOLUTION_INVALID")
        _required_digest(payload, "resolution_receipt_digest")
        return _advance(
            previous,
            event,
            status="VERIFIED" if resolution == "UPHOLD" else "INVALIDATED",
        )
    if operation == "EXPIRE":
        _require_status(
            previous,
            {"VERIFIED", "CHALLENGED"},
            "EVIDENCE_EXPIRE_TRANSITION_INVALID",
        )
        _exact_keys(payload, {"operation", "expiry_authority_id"})
        if previous.expires_at_sequence is None:
            raise EvidenceConformanceError("EVIDENCE_EXPIRY_NOT_DECLARED")
        if cast(int, event["clock_sequence"]) < previous.expires_at_sequence:
            raise EvidenceConformanceError("EVIDENCE_EXPIRY_PREMATURE")
        return _advance(previous, event, status="EXPIRED")
    if operation == "INVALIDATE":
        _require_status(
            previous,
            {"VERIFIED", "CHALLENGED"},
            "EVIDENCE_INVALIDATE_TRANSITION_INVALID",
        )
        _exact_keys(payload, {"operation", "invalidating_authority_id", "reason_code"})
        return _advance(previous, event, status="INVALIDATED")
    if operation == "SUPERSEDE":
        _require_status(
            previous,
            {"VERIFIED", "CHALLENGED"},
            "EVIDENCE_SUPERSEDE_TRANSITION_INVALID",
        )
        _exact_keys(
            payload,
            {
                "operation",
                "replacement_evidence_id",
                "superseding_authority_id",
                "reason_code",
            },
        )
        replacement = _required_token(payload, "replacement_evidence_id")
        if replacement == previous.evidence_id:
            raise EvidenceConformanceError("EVIDENCE_SELF_SUPERSESSION")
        return _advance(previous, event, status="SUPERSEDED", superseded_by_id=replacement)
    raise EvidenceConformanceError("EVIDENCE_OPERATION_UNSUPPORTED")


def _advance(
    previous: IndependentEvidenceProjection,
    event: dict[str, Any],
    *,
    status: str,
    verifier_authority_id: str | None = None,
    active_challenge_digest: str | None = None,
    active_challenge_reason: str | None = None,
    superseded_by_id: str | None = None,
) -> IndependentEvidenceProjection:
    return replace(
        previous,
        verifier_authority_id=(
            previous.verifier_authority_id
            if verifier_authority_id is None
            else verifier_authority_id
        ),
        status=status,
        active_challenge_digest=active_challenge_digest,
        active_challenge_reason=active_challenge_reason,
        superseded_by_id=superseded_by_id,
        current_source_receipt_digest=_required_digest(event, "source_receipt_digest"),
        current_event_digest=_required_digest(event, "registry_event_digest"),
        current_entity_sequence=cast(int, event["entity_sequence"]),
        last_clock_sequence=cast(int, event["clock_sequence"]),
    )


def _authority_decision(
    event: dict[str, Any],
    payload: dict[str, Any],
    previous: IndependentEvidenceProjection | None,
    policy: dict[str, Any],
) -> dict[str, object]:
    operation = _required_token(payload, "operation")
    authority_field = _AUTHORITY_FIELD.get(operation)
    if authority_field is None:
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_OPERATION_UNSUPPORTED")
    authority_id = _required_token(payload, authority_field)
    if operation == "REGISTER":
        scope_ids = _token_tuple(payload, "scope_ids", allow_empty=False)
    elif previous is None:
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_PREVIOUS_STATE_MISSING")
    else:
        scope_ids = previous.scope_ids
    if cast(int, event["clock_sequence"]) < cast(int, policy["committed_at_sequence"]):
        code = "EVIDENCE_AUTHORITY_POLICY_NOT_EFFECTIVE"
        allowed = False
    else:
        allowed = _policy_permits(policy, operation, authority_id, scope_ids)
        code = "EVIDENCE_AUTHORITY_PERMITTED" if allowed else "EVIDENCE_AUTHORITY_DENIED"
    unsigned: dict[str, object] = {
        "schema_version": "evidence-authority-decision/1",
        "allowed": allowed,
        "authority_id": authority_id,
        "authority_root_digest": policy["authority_root_digest"],
        "code": code,
        "event_digest": event["registry_event_digest"],
        "evidence_id": event["entity_id"],
        "operation": operation,
        "policy_digest": policy["policy_digest"],
        "scope_ids": list(scope_ids),
    }
    return {
        **unsigned,
        "decision_digest": _domain_digest("EVIDENCE_AUTHORITY_DECISION", unsigned),
    }


def _evaluate_use(
    request: dict[str, Any],
    projections: dict[str, IndependentEvidenceProjection],
    policy: dict[str, Any],
    challenge_policy: dict[str, Any],
) -> dict[str, object]:
    _validate_use_request(request)
    dependencies: set[str] = set()
    advisories: list[str] = []
    try:
        root = _evaluate_node(
            _required_token(request, "evidence_id"),
            request,
            projections,
            challenge_policy,
            visiting=set(),
            dependencies=dependencies,
            advisories=advisories,
            root=True,
        )
        allowed = True
        code = "EVIDENCE_ADMISSIBLE"
        event_digest: str | None = root.current_event_digest
    except EvidenceConformanceError as exc:
        allowed = False
        code = exc.code
        current = projections.get(cast(str, request.get("evidence_id")))
        event_digest = None if current is None else current.current_event_digest
    unsigned: dict[str, object] = {
        "schema_version": "evidence-admissibility-receipt/1",
        "advisory_codes": sorted(set(advisories)),
        "allowed": allowed,
        "authority_policy_digest": policy["policy_digest"],
        "challenge_policy_digest": challenge_policy["policy_digest"],
        "code": code,
        "dependency_event_digests": sorted(dependencies),
        "evidence_event_digest": event_digest,
        "evidence_id": request["evidence_id"],
        "request_digest": request["request_digest"],
    }
    return {
        **unsigned,
        "receipt_digest": _domain_digest("EVIDENCE_ADMISSIBILITY_RECEIPT", unsigned),
    }


def _evaluate_node(
    evidence_id: str,
    request: dict[str, Any],
    projections: dict[str, IndependentEvidenceProjection],
    challenge_policy: dict[str, Any],
    *,
    visiting: set[str],
    dependencies: set[str],
    advisories: list[str],
    root: bool,
) -> IndependentEvidenceProjection:
    if evidence_id in visiting:
        raise EvidenceConformanceError("EVIDENCE_DEPENDENCY_CYCLE")
    visiting.add(evidence_id)
    evidence = projections.get(evidence_id)
    if evidence is None:
        raise EvidenceConformanceError(
            "EVIDENCE_MISSING" if root else "EVIDENCE_DEPENDENCY_MISSING"
        )
    if root and evidence.proposition_id != request["proposition_id"]:
        raise EvidenceConformanceError("EVIDENCE_PROPOSITION_MISMATCH")
    if not set(cast(list[str], request["scope_ids"])).issubset(evidence.scope_ids):
        raise EvidenceConformanceError("EVIDENCE_SCOPE_INSUFFICIENT")
    clock = cast(int, request["clock_sequence"])
    if clock < evidence.valid_from_sequence:
        raise EvidenceConformanceError("EVIDENCE_NOT_YET_VALID")
    if evidence.expires_at_sequence is not None and clock >= evidence.expires_at_sequence:
        raise EvidenceConformanceError("EVIDENCE_EXPIRED_BY_TIME")
    required_reuse = cast(str, request["required_reuse_class"])
    if _REUSE_RANK[required_reuse] > _REUSE_RANK[evidence.maximum_reuse_class]:
        raise EvidenceConformanceError("EVIDENCE_REUSE_CLASS_INSUFFICIENT")
    accepted_limitations = set(cast(list[str], request["accepted_limitation_codes"]))
    if not set(evidence.limitations).issubset(accepted_limitations):
        raise EvidenceConformanceError("EVIDENCE_LIMITATION_NOT_ACCEPTED")
    if evidence.status == "CHALLENGED":
        reason = evidence.active_challenge_reason
        if reason is None:
            raise EvidenceConformanceError("EVIDENCE_ACTIVE_CHALLENGE_NOT_FOUND")
        if _challenge_materiality(challenge_policy, reason) == "MATERIAL":
            raise EvidenceConformanceError("EVIDENCE_CHALLENGE_MATERIAL")
        advisories.append(f"EVIDENCE_CHALLENGE_ADVISORY:{evidence_id}:{reason}")
    elif evidence.status != "VERIFIED":
        raise EvidenceConformanceError("EVIDENCE_STATUS_INADMISSIBLE")
    for dependency_id in evidence.dependency_ids:
        dependency = _evaluate_node(
            dependency_id,
            request,
            projections,
            challenge_policy,
            visiting=visiting,
            dependencies=dependencies,
            advisories=advisories,
            root=False,
        )
        dependencies.add(dependency.current_event_digest)
    visiting.remove(evidence_id)
    return evidence


def _validate_use_request(request: dict[str, Any]) -> None:
    _exact_keys(
        request,
        {
            "schema_version",
            "accepted_limitation_codes",
            "clock_sequence",
            "decision_id",
            "evidence_id",
            "proposition_id",
            "required_reuse_class",
            "scope_ids",
            "request_digest",
        },
        code="EVIDENCE_USE_REQUEST_KEYS_INVALID",
    )
    if request.get("schema_version") != "evidence-use-request/1":
        raise EvidenceConformanceError("EVIDENCE_USE_REQUEST_SCHEMA_INVALID")
    _required_token(request, "decision_id")
    _required_token(request, "evidence_id")
    _required_token(request, "proposition_id")
    _token_tuple(request, "scope_ids", allow_empty=False)
    _token_tuple(request, "accepted_limitation_codes")
    reuse = _required_token(request, "required_reuse_class")
    if reuse not in _REUSE_RANK:
        raise EvidenceConformanceError("EVIDENCE_USE_REUSE_CLASS_INVALID")
    if type(request.get("clock_sequence")) is not int or cast(int, request["clock_sequence"]) < 0:
        raise EvidenceConformanceError("EVIDENCE_USE_CLOCK_INVALID")
    expected = _domain_digest(
        "EVIDENCE_USE_REQUEST",
        {key: value for key, value in request.items() if key != "request_digest"},
    )
    if request.get("request_digest") != expected:
        raise EvidenceConformanceError("EVIDENCE_USE_REQUEST_DIGEST_MISMATCH")


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
        code="EVIDENCE_AUTHORITY_POLICY_KEYS_INVALID",
    )
    if value.get("schema_version") != "evidence-authority-policy/1":
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_POLICY_SCHEMA_INVALID")
    _required_token(value, "policy_id")
    _required_digest(value, "authority_root_digest")
    if (
        type(value.get("committed_at_sequence")) is not int
        or cast(int, value["committed_at_sequence"]) < 0
    ):
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_POLICY_SEQUENCE_INVALID")
    grants = _array(value, "grants")
    canonical: list[tuple[str, str, tuple[str, ...]]] = []
    for raw_grant in grants:
        grant = _as_object(raw_grant, "EVIDENCE_AUTHORITY_GRANT_INVALID")
        _exact_keys(
            grant,
            {"operation", "authority_id", "scope_ids"},
            code="EVIDENCE_AUTHORITY_GRANT_KEYS_INVALID",
        )
        operation = _required_token(grant, "operation")
        if operation not in _AUTHORITY_FIELD:
            raise EvidenceConformanceError("EVIDENCE_AUTHORITY_OPERATION_INVALID")
        canonical.append(
            (
                operation,
                _required_token(grant, "authority_id"),
                _token_tuple(grant, "scope_ids"),
            )
        )
    if canonical != sorted(canonical) or len(set(canonical)) != len(canonical) or not canonical:
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_GRANTS_NOT_CANONICAL")
    expected = _domain_digest(
        "EVIDENCE_AUTHORITY_POLICY",
        {key: item for key, item in value.items() if key != "policy_digest"},
    )
    if value.get("policy_digest") != expected:
        raise EvidenceConformanceError("EVIDENCE_AUTHORITY_POLICY_DIGEST_MISMATCH")
    return value


def _parse_challenge_policy(value: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        value,
        {"schema_version", "rules", "policy_digest"},
        code="EVIDENCE_CHALLENGE_POLICY_KEYS_INVALID",
    )
    if value.get("schema_version") != "evidence-challenge-policy/1":
        raise EvidenceConformanceError("EVIDENCE_CHALLENGE_POLICY_SCHEMA_INVALID")
    canonical: list[tuple[str, str]] = []
    for raw_rule in _array(value, "rules"):
        rule = _as_object(raw_rule, "EVIDENCE_CHALLENGE_RULE_INVALID")
        _exact_keys(
            rule,
            {"reason_code", "materiality"},
            code="EVIDENCE_CHALLENGE_RULE_KEYS_INVALID",
        )
        reason = _required_token(rule, "reason_code")
        materiality = _required_token(rule, "materiality")
        if materiality not in {"ADVISORY", "MATERIAL"}:
            raise EvidenceConformanceError("EVIDENCE_CHALLENGE_MATERIALITY_INVALID")
        canonical.append((reason, materiality))
    if canonical != sorted(canonical) or len({reason for reason, _ in canonical}) != len(canonical):
        raise EvidenceConformanceError("EVIDENCE_CHALLENGE_RULES_NOT_CANONICAL")
    expected = _domain_digest(
        "EVIDENCE_CHALLENGE_POLICY",
        {key: item for key, item in value.items() if key != "policy_digest"},
    )
    if value.get("policy_digest") != expected:
        raise EvidenceConformanceError("EVIDENCE_CHALLENGE_POLICY_DIGEST_MISMATCH")
    return value


def _policy_permits(
    policy: dict[str, Any],
    operation: str,
    authority_id: str,
    scope_ids: tuple[str, ...],
) -> bool:
    requested = set(scope_ids)
    for raw_grant in cast(list[object], policy["grants"]):
        grant = cast(dict[str, Any], raw_grant)
        if grant["operation"] != operation or grant["authority_id"] != authority_id:
            continue
        granted = set(cast(list[str], grant["scope_ids"]))
        if not granted or requested.issubset(granted):
            return True
    return False


def _challenge_materiality(policy: dict[str, Any], reason_code: str) -> str:
    for raw_rule in cast(list[object], policy["rules"]):
        rule = cast(dict[str, Any], raw_rule)
        if rule["reason_code"] == reason_code:
            return cast(str, rule["materiality"])
    return "MATERIAL"


def _compare_projections(
    vector: dict[str, Any],
    projections: dict[str, IndependentEvidenceProjection],
) -> None:
    expected_statuses = _object(vector, "expected_statuses")
    expected_digests = _object(vector, "expected_current_event_digests")
    observed_statuses = {key: projections[key].status for key in sorted(projections)}
    observed_digests = {key: projections[key].current_event_digest for key in sorted(projections)}
    if observed_statuses != expected_statuses or observed_digests != expected_digests:
        raise EvidenceConformanceError("EVIDENCE_PROJECTION_MISMATCH")


def _snapshot_root(projections: dict[str, IndependentEvidenceProjection]) -> str:
    value = {
        "schema_version": "registry-snapshot/1",
        "registry_type": "EVIDENCE_UNIT",
        "heads": [
            {
                "entity_id": item.evidence_id,
                "entity_sequence": item.current_entity_sequence,
                "event_digest": item.current_event_digest,
            }
            for item in (projections[key] for key in sorted(projections))
        ],
    }
    return "sha256:" + hashlib.sha256(b"REGISTRY_SNAPSHOT\0" + _compact_bytes(value)).hexdigest()


def _domain_digest(domain: str, value: object) -> str:
    return (
        "sha256:"
        + hashlib.sha256(domain.encode("ascii") + b"\0" + _json_bytes(value)).hexdigest()
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
    code: str = "EVIDENCE_PAYLOAD_KEYS_INVALID",
) -> None:
    if set(value) != expected:
        raise EvidenceConformanceError(code)


def _require_status(
    previous: IndependentEvidenceProjection,
    allowed: set[str],
    code: str,
) -> None:
    if previous.status not in allowed:
        raise EvidenceConformanceError(code)


def _positive_int(value: dict[str, Any], field: str) -> int:
    item = value.get(field)
    if type(item) is not int or item < 1:
        raise EvidenceConformanceError("EVIDENCE_POSITIVE_INTEGER_INVALID", field)
    return item


def _token_tuple(
    value: dict[str, Any],
    field: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    item = value.get(field)
    if type(item) is not list or any(type(member) is not str for member in item):
        raise EvidenceConformanceError("EVIDENCE_TOKEN_ARRAY_INVALID", field)
    result = tuple(cast(list[str], item))
    if (not allow_empty and not result) or result != tuple(sorted(result)):
        raise EvidenceConformanceError("EVIDENCE_TOKEN_ARRAY_INVALID", field)
    if len(set(result)) != len(result):
        raise EvidenceConformanceError("EVIDENCE_TOKEN_ARRAY_INVALID", field)
    for member in result:
        if _TOKEN.fullmatch(member) is None:
            raise EvidenceConformanceError("EVIDENCE_TOKEN_ARRAY_INVALID", field)
    return result


def _required_token(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _TOKEN.fullmatch(item) is None:
        raise EvidenceConformanceError("EVIDENCE_TOKEN_INVALID", field)
    return item


def _required_digest(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or _DIGEST.fullmatch(item) is None:
        raise EvidenceConformanceError("EVIDENCE_DIGEST_INVALID", field)
    return item


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    return _as_object(value.get(field), "EVIDENCE_OBJECT_INVALID")


def _as_object(value: object, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceConformanceError(code)
    return cast(dict[str, Any], value)


def _array(value: dict[str, Any], field: str) -> list[object]:
    item = value.get(field)
    if type(item) is not list:
        raise EvidenceConformanceError("EVIDENCE_ARRAY_INVALID", field)
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


def _empty_challenge_policy() -> dict[str, Any]:
    return {"rules": [], "policy_digest": "sha256:" + "0" * 64}
