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
    AuditEvent,
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


def _validate_exact_audit(
    before: ControlState,
    after: ControlState,
    expected: AuditEvent,
    invariant_id: str,
) -> list[Violation]:
    if after.history == (*before.history, expected):
        return []
    return [Violation(invariant_id, f"{expected.event_type} audit append is not canonical")]


def _evidence_matches_required_profile(
    item: Evidence,
    required_profile_id: str | None,
    required_profile_version: int | None,
) -> bool:
    if required_profile_id is None or item.profile_id is None:
        return True
    return (
        item.profile_id == required_profile_id and item.profile_version == required_profile_version
    )


def _basis_is_supported(
    basis: Basis,
    evidence: dict[str, Evidence],
    required_profile_id: str | None,
    required_profile_version: int | None,
) -> bool:
    return (
        bool(basis.member_evidence_ids)
        and basis.approved
        and all(
            member in evidence
            and evidence[member].status is EvidenceStatus.CURRENT
            and _evidence_matches_required_profile(
                evidence[member],
                required_profile_id,
                required_profile_version,
            )
            for member in basis.member_evidence_ids
        )
    )


def _expected_basis_survival(
    before: ControlState,
    after_evidence: dict[str, Evidence],
    required_profile_id: str | None,
    required_profile_version: int | None,
) -> tuple[frozenset[str], frozenset[str]]:
    bases = before.bases_by_id()
    source = frozenset(
        basis_id
        for basis_id in before.current_source_basis_ids
        if (basis := bases.get(basis_id)) is not None
        and _basis_is_supported(
            basis,
            after_evidence,
            required_profile_id,
            required_profile_version,
        )
    )
    verdict = frozenset(
        basis_id
        for basis_id in before.current_verdict_basis_ids
        if (basis := bases.get(basis_id)) is not None
        and _basis_is_supported(
            basis,
            after_evidence,
            required_profile_id,
            required_profile_version,
        )
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
        if (
            item.status is EvidenceStatus.EXPIRED
            and item.expires_at is not None
            and item.expires_at > state.logical_time
        ):
            violations.append(
                Violation("T-INV-02", f"evidence {item.evidence_id} expired before its deadline")
            )
        violations.extend(
            _validate_profile_pair(
                item.profile_id, item.profile_version, f"evidence {item.evidence_id}"
            )
        )

    evidence_by_id = state.evidence_by_id()
    bases_by_id = state.bases_by_id()
    for basis_id in state.current_source_basis_ids | state.current_verdict_basis_ids:
        basis = bases_by_id.get(basis_id)
        if basis is not None and not _basis_is_supported(
            basis,
            evidence_by_id,
            state.required_profile_id,
            state.required_profile_version,
        ):
            violations.append(
                Violation(
                    "P-INV-02",
                    f"current basis {basis_id} is incomplete under the required profile",
                )
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
                Violation(
                    "R-INV-03", f"closed request {request.request_id} has an invalid close time"
                )
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
    for request_id, old_request in before_requests.items():
        new_request = after_requests.get(request_id)
        if new_request is None:
            violations.append(Violation("R-INV-03", f"request {request_id} was deleted"))
            continue
        stable_fields = (
            old_request.request_id == new_request.request_id
            and old_request.reason == new_request.reason
            and old_request.requested_at == new_request.requested_at
            and old_request.due_at == new_request.due_at
        )
        valid_closure = old_request == new_request or (
            old_request.status is RequestStatus.PENDING
            and new_request.status is RequestStatus.CLOSED
            and new_request.closed_at == after.logical_time
            and stable_fields
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
    if after.bases != before.bases:
        violations.append(Violation("T-INV-03", "clock advance rewrote historical bases"))

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
        before,
        after_evidence,
        after.required_profile_id,
        after.required_profile_version,
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
    elif (
        heartbeat_missed
        and expected_assurance in _SUBSTANTIVE
        or expected_assurance in _SUBSTANTIVE
        and not expected_verdict_bases
    ):
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
    expired_ids = {
        item.evidence_id
        for item in before.evidence
        if item.status is EvidenceStatus.CURRENT
        and item.expires_at is not None
        and item.expires_at <= event.target_time
    }
    expected_audit = AuditEvent.create(
        "AdvanceClock",
        from_time=str(before.logical_time),
        target_time=str(event.target_time),
        expired_evidence=",".join(sorted(expired_ids)),
        heartbeat_missed=str(heartbeat_missed).lower(),
    )
    violations.extend(_validate_exact_audit(before, after, expected_audit, "T-INV-04"))
    return violations


def _validate_profile_change(
    before: ControlState, event: ProfileChange, after: ControlState
) -> list[Violation]:
    violations: list[Violation] = []
    if event.authority != "I3":
        violations.append(Violation("P-INV-01", "profile change requires I3 authority"))
    if after.logical_time != before.logical_time:
        violations.append(Violation("P-INV-01", "profile change altered logical time"))
    if (
        after.required_profile_id != event.profile_id
        or after.required_profile_version != event.profile_version
    ):
        violations.append(Violation("P-INV-01", "profile result does not match the event"))
    if after.evidence != before.evidence:
        violations.append(Violation("P-INV-02", "profile change rewrote historical evidence"))
    if after.bases != before.bases:
        violations.append(Violation("P-INV-02", "profile change rewrote historical bases"))

    after_evidence = after.evidence_by_id()
    expected_source_bases, expected_verdict_bases = _expected_basis_survival(
        before,
        after_evidence,
        event.profile_id,
        event.profile_version,
    )
    if after.current_source_basis_ids != expected_source_bases:
        violations.append(
            Violation("P-INV-02", "profile source-basis eligibility is not canonical")
        )
    if after.current_verdict_basis_ids != expected_verdict_bases:
        violations.append(
            Violation("P-INV-02", "profile verdict-basis eligibility is not canonical")
        )

    expected_source = before.source_state
    if expected_source is not SourceState.UNKNOWN and not expected_source_bases:
        expected_source = SourceState.UNKNOWN
    expected_assurance = before.assurance
    if before.obligation is not ObligationStatus.CURRENT:
        expected_assurance = Assurance.NA
    elif expected_assurance in _SUBSTANTIVE and not expected_verdict_bases:
        expected_assurance = Assurance.STALE
    if after.source_state is not expected_source:
        violations.append(Violation("P-INV-02", "profile source result is not canonical"))
    if after.assurance is not expected_assurance:
        violations.append(Violation("P-INV-02", "profile assurance result is not canonical"))
    if after.obligation is not before.obligation:
        violations.append(Violation("P-INV-02", "profile change altered obligation state"))

    new_request_ids = set(after.requests_by_id()) - set(before.requests_by_id())
    expected_request_ids = {event.request_id} if event.request_id is not None else set()
    if new_request_ids != expected_request_ids:
        violations.append(
            Violation("P-INV-03", "profile request identities do not match the event")
        )
    if event.request_id is not None and event.request_due_at is not None:
        expected_request = ReassessmentRequest(
            request_id=event.request_id,
            reason="required profile changed",
            requested_at=before.logical_time,
            due_at=event.request_due_at,
        )
        if after.requests_by_id().get(event.request_id) != expected_request:
            violations.append(
                Violation("P-INV-03", "profile reassessment request is not canonical")
            )
    if after.heartbeat != before.heartbeat:
        violations.append(Violation("H-INV-01", "profile change altered heartbeat state"))
    incompatible_ids = {
        item.evidence_id
        for item in before.evidence
        if item.status is EvidenceStatus.CURRENT
        and item.profile_id is not None
        and (item.profile_id != event.profile_id or item.profile_version != event.profile_version)
    }
    expected_audit = AuditEvent.create(
        "ProfileChange",
        authority=event.authority,
        profile_id=event.profile_id,
        profile_version=str(event.profile_version),
        profile_incompatible_evidence=",".join(sorted(incompatible_ids)),
        request_id=event.request_id or "none",
    )
    violations.extend(_validate_exact_audit(before, after, expected_audit, "P-INV-04"))
    return violations


def _validate_request(
    before: ControlState, event: RequestReassessment, after: ControlState
) -> list[Violation]:
    violations = _unchanged_temporal_governance(before, after, allow_requests=True)
    if event.authority != "I3":
        violations.append(Violation("R-INV-01", "reassessment request requires I3 authority"))
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
    before_requests = before.requests_by_id()
    after_requests = after.requests_by_id()
    new_ids = set(after_requests) - set(before_requests)
    if new_ids != {event.request_id} or after_requests.get(event.request_id) != expected:
        violations.append(Violation("R-INV-01", "request result does not match the event"))
    for request_id, existing_request in before_requests.items():
        if after_requests.get(request_id) != existing_request:
            violations.append(
                Violation(
                    "R-INV-01",
                    f"request creation rewrote existing request {request_id}",
                )
            )
    expected_audit = AuditEvent.create(
        "RequestReassessment",
        authority=event.authority,
        request_id=event.request_id,
        due_at=str(event.due_at),
        reason=event.reason,
    )
    violations.extend(_validate_exact_audit(before, after, expected_audit, "R-INV-04"))
    return violations


def _validate_heartbeat(
    before: ControlState, event: RecordHeartbeat, after: ControlState
) -> list[Violation]:
    violations: list[Violation] = []
    if event.authority != "I3":
        violations.append(Violation("H-INV-01", "heartbeat requires I3 authority"))
    if after.logical_time != before.logical_time:
        violations.append(Violation("T-INV-01", "heartbeat altered logical time"))
    if (
        after.required_profile_id != before.required_profile_id
        or after.required_profile_version != before.required_profile_version
    ):
        violations.append(Violation("P-INV-01", "heartbeat altered the required profile"))
    if after.reassessment_requests != before.reassessment_requests:
        violations.append(Violation("R-INV-03", "heartbeat altered reassessment requests"))
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
    if interval is not None:
        expected_audit = AuditEvent.create(
            "RecordHeartbeat",
            authority=event.authority,
            at_time=str(event.at_time),
            interval=str(interval),
            due_at=str(event.at_time + interval),
        )
        violations.extend(_validate_exact_audit(before, after, expected_audit, "H-INV-03"))
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
    unknown_request_ids = requested - set(before_requests)
    if unknown_request_ids:
        violations.append(
            Violation(
                "R-INV-03",
                f"unknown request closure identities: {sorted(unknown_request_ids)}",
            )
        )
    nonpending_request_ids = {
        request_id
        for request_id in requested & set(before_requests)
        if before_requests[request_id].status is not RequestStatus.PENDING
    }
    if nonpending_request_ids:
        violations.append(
            Violation(
                "R-INV-03",
                f"request closures must target pending requests: {sorted(nonpending_request_ids)}",
            )
        )
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
        violations = [
            *_unchanged_temporal_governance(before, after, allow_requests=True),
            *_validate_reassessment_requests(before, event, after),
        ]
        audit_details = {
            "authority": event.authority,
            "evidence_ids": ",".join(sorted(item.evidence_id for item in event.new_evidence)),
            "basis_ids": ",".join(sorted(item.basis_id for item in event.new_bases)),
        }
        if event.close_request_ids:
            audit_details["closed_request_ids"] = ",".join(sorted(event.close_request_ids))
        expected_audit = AuditEvent.create("Reassess", **audit_details)
        violations.extend(_validate_exact_audit(before, after, expected_audit, "R-INV-04"))
        return tuple(violations)
    return tuple(_unchanged_temporal_governance(before, after))
