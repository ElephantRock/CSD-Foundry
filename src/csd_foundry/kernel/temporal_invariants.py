"""Independent verification for logical-time and governance semantics."""

from __future__ import annotations

from csd_foundry.kernel.events import (
    AdvanceClock,
    CsdEvent,
    ProfileChange,
    Reassess,
    RecordHeartbeat,
    RequestReassessment,
)
from csd_foundry.kernel.invariants import Violation
from csd_foundry.kernel.models import (
    Assurance,
    Basis,
    ControlState,
    Evidence,
    EvidenceStatus,
    ObligationStatus,
    ReassessmentRequest,
    RequestStatus,
    SourceState,
)

_SUBSTANTIVE = {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}


def _basis_is_supported(basis: Basis, evidence: dict[str, Evidence]) -> bool:
    return (
        bool(basis.member_evidence_ids)
        and basis.approved
        and all(
            member in evidence and evidence[member].status is EvidenceStatus.CURRENT
            for member in basis.member_evidence_ids
        )
    )


def _expected_basis_survival(
    before: ControlState, after_evidence: dict[str, Evidence]
) -> tuple[frozenset[str], frozenset[str]]:
    bases = before.bases_by_id()
    source = frozenset(
        basis_id
        for basis_id in before.current_source_basis_ids
        if (basis := bases.get(basis_id)) is not None
        and _basis_is_supported(basis, after_evidence)
    )
    verdict = frozenset(
        basis_id
        for basis_id in before.current_verdict_basis_ids
        if (basis := bases.get(basis_id)) is not None
        and _basis_is_supported(basis, after_evidence)
    )
    return source, verdict


def _validate_profile_pair(
    profile_id: str | None, profile_version: int | None, subject: str
) -> list[Violation]:
    violations: list[Violation] = []
    if (profile_id is None) != (profile_version is None):
        violations.append(Violation("P-INV-01", f"{subject} has an incomplete profile binding"))
    if profile_version is not None and profile_version <= 0:
        violations.append(Violation("P-INV-01", f"{subject} has a non-positive profile version"))
    return violations


def validate_temporal_state(state: ControlState) -> tuple[Violation, ...]:
    violations: list[Violation] = []
    if state.logical_time < 0:
        violations.append(Violation("T-INV-01", "logical time cannot be negative"))

    violations.extend(
        _validate_profile_pair(
            state.required_profile_id,
            state.required_profile_version,
            "required profile",
        )
    )

    for item in state.evidence:
        if item.issued_at < 0 or item.issued_at > state.logical_time:
            violations.append(
                Violation("T-INV-02", f"evidence {item.evidence_id} has an invalid issue time")
            )
        if item.expires_at is not None and item.expires_at <= item.issued_at:
            violations.append(
                Violation("T-INV-02", f"evidence {item.evidence_id} has an invalid expiry")
            )
        if (
            item.status is EvidenceStatus.CURRENT
            and item.expires_at is not None
            and item.expires_at <= state.logical_time
        ):
            violations.append(
                Violation("T-INV-02", f"evidence {item.evidence_id} remained current after expiry")
            )
        if item.status is EvidenceStatus.EXPIRED and (
            item.expires_at is None or item.expires_at > state.logical_time
        ):
            violations.append(
                Violation("T-INV-02", f"evidence {item.evidence_id} expired before its deadline")
            )
        violations.extend(
            _validate_profile_pair(item.profile_id, item.profile_version, f"evidence {item.evidence_id}")
        )

    requests = state.requests_by_id()
    if len(requests) != len(state.reassessment_requests):
        violations.append(Violation("R-INV-01", "duplicate reassessment request identity"))
    for request in state.reassessment_requests:
        if request.requested_at < 0 or request.requested_at > state.logical_time:
            violations.append(
                Violation("R-INV-01", f"request {request.request_id} has an invalid request time")
            )
        if request.due_at < request.requested_at:
            violations.append(
                Violation("R-INV-01", f"request {request.request_id} has an invalid due time")
            )
        if request.status is RequestStatus.PENDING and request.closed_at is not None:
            violations.append(
                Violation("R-INV-03", f"pending request {request.request_id} has a close time")
            )
        if request.status is RequestStatus.CLOSED and (
            request.closed_at is None or request.closed_at > state.logical_time
        ):
            violations.append(
                Violation("R-INV-03", f"closed request {request.request_id} has an invalid close time")
            )

    if state.heartbeat is not None:
        heartbeat = state.heartbeat
        if heartbeat.interval <= 0:
            violations.append(Violation("H-INV-01", "heartbeat interval must be positive"))
        if heartbeat.last_recorded_at > state.logical_time:
            violations.append(Violation("H-INV-01", "heartbeat is recorded in the future"))
        if heartbeat.due_at != heartbeat.last_recorded_at + heartbeat.interval:
            violations.append(Violation("H-INV-01", "heartbeat deadline is not canonical"))
        if heartbeat.due_at <= state.logical_time and state.assurance in _SUBSTANTIVE:
            violations.append(
                Violation("T-INV-06", "missed heartbeat retained a substantive verdict")
            )

    return tuple(violations)


def validate_temporal_transition(
    before: ControlState, after: ControlState
) -> tuple[Violation, ...]:
    violations = list(validate_temporal_state(after))
    if after.logical_time < before.logical_time:
        violations.append(Violation("T-INV-01", "logical time moved backward"))

    before_evidence = before.evidence_by_id()
    after_evidence = after.evidence_by_id()
    for evidence_id, old in before_evidence.items():
        new = after_evidence.get(evidence_id)
        if new is None:
            continue
        if (
            old.issued_at != new.issued_at
            or old.expires_at != new.expires_at
            or old.profile_id != new.profile_id
            or old.profile_version != new.profile_version
        ):
            violations.append(
                Violation("T-INV-03", f"evidence {evidence_id} temporal metadata was rewritten")
            )

    before_requests = before.requests_by_id()
    after_requests = after.requests_by_id()
    for request_id, old in before_requests.items():
        new = after_requests.get(request_id)
        if new is None:
            violations.append(Violation("R-INV-03", f"request {request_id} was deleted"))
            continue
        stable_fields = (
            old.request_id == new.request_id
            and old.reason == new.reason
            and old.requested_at == new.requested_at
            and old.due_at == new.due_at
        )
        valid_closure = (
            old == new
            or (
                old.status is RequestStatus.PENDING
                and new.status is RequestStatus.CLOSED
                and new.closed_at == after.logical_time
                and stable_fields
            )
        )
        if not valid_closure:
            violations.append(Violation("R-INV-03", f"request {request_id} was rewritten"))

    if (
        before.required_profile_id == after.required_profile_id
        and before.required_profile_version is not None
        and after.required_profile_version is not None
        and after.required_profile_version < before.required_profile_version
    ):
        violations.append(Violation("P-INV-01", "required profile version moved backward"))
    return tuple(violations)


def _unchanged_temporal_governance(
    before: ControlState, after: ControlState, *, allow_requests: bool = False
) -> list[Violation]:
    violations: list[Violation] = []
    if after.logical_time != before.logical_time:
        violations.append(Violation("T-INV-01", "event changed logical time unexpectedly"))
    if (
        after.required_profile_id != before.required_profile_id
        or after.required_profile_version != before.required_profile_version
    ):
        violations.append(Violation("P-INV-01", "event changed the required profile unexpectedly"))
    if not allow_requests and after.reassessment_requests != before.reassessment_requests:
        violations.append(Violation("R-INV-03", "event changed requests unexpectedly"))
    if after.heartbeat != before.heartbeat:
        violations.append(Violation("H-INV-01", "event changed heartbeat state unexpectedly"))
    return violations


def _validate_advance_clock(
    before: ControlState, event: AdvanceClock, after: ControlState
) -> list[Violation]:
    violations: list[Violation] = []
    if event.target_time < before.logical_time or after.logical_time != event.target_time:
        violations.append(Violation("T-INV-01", "clock result does not match the target time"))
    if set(after.evidence_by_id()) != set(before.evidence_by_id()):
        violations.append(Violation("T-INV-02", "clock advance altered evidence identities"))

    after_evidence = after.evidence_by_id()
    for evidence_id, old in before.evidence_by_id().items():
        new = after_evidence.get(evidence_id)
        if new is None:
            continue
        should_expire = (
            old.status is EvidenceStatus.CURRENT
            and old.expires_at is not None
            and old.expires_at <= event.target_time
        )
        expected_status = EvidenceStatus.EXPIRED if should_expire else old.status
        if new.status is not expected_status:
            violations.append(
                Violation(
                    "T-INV-02",
                    f"evidence {evidence_id} has {new.status.value}; expected {expected_status.value}",
                )
            )

    expected_source_bases, expected_verdict_bases = _expected_basis_survival(
        before, after_evidence
    )
    heartbeat_missed = before.heartbeat is not None and before.heartbeat.due_at <= event.target_time
    if heartbeat_missed:
        expected_verdict_bases = frozenset()
    if after.current_source_basis_ids != expected_source_bases:
        violations.append(Violation("T-INV-03", "clock source-basis survival is not canonical"))
    if after.current_verdict_basis_ids != expected_verdict_bases:
        violations.append(Violation("T-INV-06", "clock verdict-basis survival is not canonical"))

    expected_source = before.source_state
    if expected_source is not SourceState.UNKNOWN and not expected_source_bases:
        expected_source = SourceState.UNKNOWN
    expected_assurance = before.assurance
    if before.obligation is not ObligationStatus.CURRENT:
        expected_assurance = Assurance.NA
    elif heartbeat_missed and expected_assurance in _SUBSTANTIVE:
        expected_assurance = Assurance.STALE
    elif expected_assurance in _SUBSTANTIVE and not expected_verdict_bases:
        expected_assurance = Assurance.STALE
    if after.source_state is not expected_source:
        violations.append(Violation("T-INV-03", "clock source result is not canonical"))
    if after.assurance is not expected_assurance:
        violations.append(Violation("T-INV-06", "clock assurance result is not canonical"))

    if (
        after.required_profile_id != before.required_profile_id
        or after.required_profile_version != before.required_profile_version
        or after.reassessment_requests != before.reassessment_requests
        or after.heartbeat != before.heartbeat
    ):
        violations.append(Violation("T-INV-01", "clock changed unrelated governance state"))
    return violations


def _validate_profile_change(
    before: ControlState, event: ProfileChange, after: ControlState
) -> list[Violation]:
    violations: list[Violation] = []
    if after.logical_time != before.logical_time:
        violations.append(Violation("P-INV-01", "profile change altered logical time"))
    if (
        after.required_profile_id != event.profile_id
        or after.required_profile_version != event.profile_version
    ):
        violations.append(Violation("P-INV-01", "profile result does not match the event"))

    after_evidence = after.evidence_by_id()
    for evidence_id, old in before.evidence_by_id().items():
        new = after_evidence.get(evidence_id)
        if new is None:
            continue
        bound_to_old = (
            before.required_profile_id is not None
            and old.profile_id == before.required_profile_id
            and old.profile_version == before.required_profile_version
        )
        affected = old.status is EvidenceStatus.CURRENT and bound_to_old
        expected_status = EvidenceStatus.INVALIDATED if affected else old.status
        if new.status is not expected_status:
            violations.append(
                Violation("P-INV-02", f"profile impact is incorrect for evidence {evidence_id}")
            )

    new_request_ids = set(after.requests_by_id()) - set(before.requests_by_id())
    expected_request_ids = {event.request_id} if event.request_id is not None else set()
    if new_request_ids != expected_request_ids:
        violations.append(Violation("P-INV-03", "profile request identities do not match the event"))
    if after.heartbeat != before.heartbeat:
        violations.append(Violation("H-INV-01", "profile change altered heartbeat state"))
    return violations


def _validate_request(
    before: ControlState, event: RequestReassessment, after: ControlState
) -> list[Violation]:
    violations = _unchanged_temporal_governance(before, after, allow_requests=True)
    if (
        after.evidence != before.evidence
        or after.bases != before.bases
        or after.current_source_basis_ids != before.current_source_basis_ids
        or after.current_verdict_basis_ids != before.current_verdict_basis_ids
        or after.source_state is not before.source_state
        or after.assurance is not before.assurance
        or after.obligation is not before.obligation
    ):
        violations.append(Violation("R-INV-02", "reassessment request changed substantive state"))
    expected = ReassessmentRequest(
        request_id=event.request_id,
        reason=event.reason,
        requested_at=before.logical_time,
        due_at=event.due_at,
    )
    new_ids = set(after.requests_by_id()) - set(before.requests_by_id())
    if new_ids != {event.request_id} or after.requests_by_id().get(event.request_id) != expected:
        violations.append(Violation("R-INV-01", "request result does not match the event"))
    return violations


def _validate_heartbeat(
    before: ControlState, event: RecordHeartbeat, after: ControlState
) -> list[Violation]:
    violations = _unchanged_temporal_governance(before, after)
    if (
        after.evidence != before.evidence
        or after.bases != before.bases
        or after.current_source_basis_ids != before.current_source_basis_ids
        or after.current_verdict_basis_ids != before.current_verdict_basis_ids
        or after.source_state is not before.source_state
        or after.assurance is not before.assurance
        or after.obligation is not before.obligation
        or after.reassessment_requests != before.reassessment_requests
    ):
        violations.append(Violation("H-INV-02", "heartbeat changed substantive state"))
    interval = event.interval
    if interval is None and before.heartbeat is not None:
        interval = before.heartbeat.interval
    if (
        interval is None
        or after.heartbeat is None
        or after.heartbeat.interval != interval
        or after.heartbeat.last_recorded_at != event.at_time
        or after.heartbeat.due_at != event.at_time + interval
    ):
        violations.append(Violation("H-INV-01", "heartbeat result does not match the event"))
    return violations


def _validate_reassessment_requests(
    before: ControlState, event: Reassess, after: ControlState
) -> list[Violation]:
    violations: list[Violation] = []
    requested = set(event.close_request_ids)
    if len(requested) != len(event.close_request_ids):
        violations.append(Violation("R-INV-03", "request closure identities are duplicated"))
    before_requests = before.requests_by_id()
    after_requests = after.requests_by_id()
    if set(after_requests) != set(before_requests):
        violations.append(Violation("R-INV-03", "reassessment altered request identities"))
    for request_id, old in before_requests.items():
        new = after_requests.get(request_id)
        if new is None:
            continue
        expected = old.close(before.logical_time) if request_id in requested else old
        if new != expected:
            violations.append(
                Violation("R-INV-03", f"request {request_id} closure does not match the event")
            )
    return violations


def validate_temporal_event(
    before: ControlState, event: CsdEvent, after: ControlState
) -> tuple[Violation, ...]:
    if isinstance(event, AdvanceClock):
        return tuple(_validate_advance_clock(before, event, after))
    if isinstance(event, ProfileChange):
        return tuple(_validate_profile_change(before, event, after))
    if isinstance(event, RequestReassessment):
        return tuple(_validate_request(before, event, after))
    if isinstance(event, RecordHeartbeat):
        return tuple(_validate_heartbeat(before, event, after))
    if isinstance(event, Reassess):
        return tuple(
            [
                *_unchanged_temporal_governance(before, after, allow_requests=True),
                *_validate_reassessment_requests(before, event, after),
            ]
        )
    return tuple(_unchanged_temporal_governance(before, after))
