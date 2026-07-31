"""Deterministic logical-time and governance transitions."""

from __future__ import annotations

from dataclasses import replace

from csd_foundry.kernel.events import (
    AdvanceClock,
    ProfileChange,
    RecordHeartbeat,
    RequestReassessment,
)
from csd_foundry.kernel.models import (
    Assurance,
    AuditEvent,
    ControlState,
    EvidenceStatus,
    HeartbeatState,
    ObligationStatus,
    ReassessmentRequest,
    RequestStatus,
    SourceState,
)
from csd_foundry.kernel.trace import TransitionTrace


class TemporalTransitionError(ValueError):
    """Raised when a temporal or governance event violates a precondition."""


def is_temporal_event(event: object) -> bool:
    return isinstance(event, (AdvanceClock, ProfileChange, RequestReassessment, RecordHeartbeat))


def _basis_is_current(state: ControlState, basis_id: str) -> bool:
    evidence = state.evidence_by_id()
    basis = state.bases_by_id().get(basis_id)
    if basis is None or not basis.approved or not basis.member_evidence_ids:
        return False
    return all(
        member in evidence and evidence[member].status is EvidenceStatus.CURRENT
        for member in basis.member_evidence_ids
    )


def _surviving_bases(state: ControlState) -> tuple[frozenset[str], frozenset[str]]:
    source = frozenset(
        basis_id for basis_id in state.current_source_basis_ids if _basis_is_current(state, basis_id)
    )
    verdict = frozenset(
        basis_id for basis_id in state.current_verdict_basis_ids if _basis_is_current(state, basis_id)
    )
    return source, verdict


def _canonical_claims(
    before: ControlState,
    interim: ControlState,
    *,
    force_stale: bool = False,
) -> tuple[SourceState, Assurance, frozenset[str], frozenset[str]]:
    source_bases, verdict_bases = _surviving_bases(interim)
    source_state = before.source_state
    if source_state is not SourceState.UNKNOWN and not source_bases:
        source_state = SourceState.UNKNOWN

    assurance = before.assurance
    if before.obligation is not ObligationStatus.CURRENT:
        assurance = Assurance.NA
        verdict_bases = frozenset()
    elif force_stale and assurance in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}:
        assurance = Assurance.STALE
        verdict_bases = frozenset()
    elif assurance in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL} and not verdict_bases:
        assurance = Assurance.STALE

    return source_state, assurance, source_bases, verdict_bases


def _request_from_event(event: RequestReassessment, logical_time: int) -> ReassessmentRequest:
    if event.authority != "I3":
        raise TemporalTransitionError("reassessment request requires I3 authority")
    if not event.request_id:
        raise TemporalTransitionError("reassessment request requires an identity")
    if event.due_at < logical_time:
        raise TemporalTransitionError("reassessment request due time cannot precede logical time")
    return ReassessmentRequest(
        request_id=event.request_id,
        reason=event.reason,
        requested_at=logical_time,
        due_at=event.due_at,
    )


def apply_advance_clock(
    state: ControlState, event: AdvanceClock
) -> tuple[ControlState, TransitionTrace]:
    if event.target_time < state.logical_time:
        raise TemporalTransitionError("logical time cannot move backward")

    expired_ids: set[str] = set()
    evidence = []
    for item in state.evidence:
        due = item.expires_at is not None and item.expires_at <= event.target_time
        if item.status is EvidenceStatus.CURRENT and due:
            expired_ids.add(item.evidence_id)
            evidence.append(item.expire())
        else:
            evidence.append(item)

    heartbeat_missed = state.heartbeat is not None and state.heartbeat.due_at <= event.target_time
    interim = replace(state, evidence=tuple(evidence), logical_time=event.target_time)
    source, assurance, source_bases, verdict_bases = _canonical_claims(
        state,
        interim,
        force_stale=heartbeat_missed,
    )
    removed = (
        state.current_source_basis_ids | state.current_verdict_basis_ids
    ) - source_bases - verdict_bases
    post = replace(
        interim,
        source_state=source,
        assurance=assurance,
        current_source_basis_ids=source_bases,
        current_verdict_basis_ids=verdict_bases,
        history=(
            *state.history,
            AuditEvent.create(
                "AdvanceClock",
                from_time=str(state.logical_time),
                target_time=str(event.target_time),
                expired_evidence=",".join(sorted(expired_ids)),
                heartbeat_missed=str(heartbeat_missed).lower(),
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="AdvanceClock",
        invalidated_evidence=tuple(sorted(expired_ids)),
        preserved_evidence=tuple(
            sorted(item.evidence_id for item in post.evidence if item.status is EvidenceStatus.CURRENT)
        ),
        removed_bases=tuple(sorted(removed)),
        surviving_bases=tuple(sorted(source_bases | verdict_bases)),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        forbidden_inferences=("heartbeat or expiry based substantive promotion",),
        rules_fired=("T-INV-01", "T-INV-02", "T-INV-03", "T-INV-06"),
        next_governed_step=(
            "complete governed reassessment"
            if expired_ids or heartbeat_missed
            else "none required"
        ),
    )
    return post, trace


def apply_profile_change(
    state: ControlState, event: ProfileChange
) -> tuple[ControlState, TransitionTrace]:
    if event.authority != "I3":
        raise TemporalTransitionError("profile change requires I3 authority")
    if not event.profile_id or event.profile_version <= 0:
        raise TemporalTransitionError("profile identity and positive version are required")
    if (
        state.required_profile_id == event.profile_id
        and state.required_profile_version is not None
        and event.profile_version <= state.required_profile_version
    ):
        raise TemporalTransitionError("profile version must advance monotonically")
    if (event.request_id is None) != (event.request_due_at is None):
        raise TemporalTransitionError("profile request identity and due time must be supplied together")

    invalidated_ids: set[str] = set()
    evidence = []
    for item in state.evidence:
        bound_to_old_profile = (
            state.required_profile_id is not None
            and item.profile_id == state.required_profile_id
            and item.profile_version == state.required_profile_version
        )
        if item.status is EvidenceStatus.CURRENT and bound_to_old_profile:
            invalidated_ids.add(item.evidence_id)
            evidence.append(item.invalidate())
        else:
            evidence.append(item)

    requests = state.reassessment_requests
    if event.request_id is not None and event.request_due_at is not None:
        if event.request_id in state.requests_by_id():
            raise TemporalTransitionError("profile change request identity already exists")
        request = _request_from_event(
            RequestReassessment(
                request_id=event.request_id,
                reason="required profile changed",
                due_at=event.request_due_at,
                authority=event.authority,
            ),
            state.logical_time,
        )
        requests = (*requests, request)

    interim = replace(
        state,
        evidence=tuple(evidence),
        required_profile_id=event.profile_id,
        required_profile_version=event.profile_version,
        reassessment_requests=requests,
    )
    source, assurance, source_bases, verdict_bases = _canonical_claims(state, interim)
    removed = (
        state.current_source_basis_ids | state.current_verdict_basis_ids
    ) - source_bases - verdict_bases
    post = replace(
        interim,
        source_state=source,
        assurance=assurance,
        current_source_basis_ids=source_bases,
        current_verdict_basis_ids=verdict_bases,
        history=(
            *state.history,
            AuditEvent.create(
                "ProfileChange",
                authority=event.authority,
                profile_id=event.profile_id,
                profile_version=str(event.profile_version),
                invalidated_evidence=",".join(sorted(invalidated_ids)),
                request_id=event.request_id or "none",
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="ProfileChange",
        invalidated_evidence=tuple(sorted(invalidated_ids)),
        preserved_evidence=tuple(
            sorted(item.evidence_id for item in post.evidence if item.status is EvidenceStatus.CURRENT)
        ),
        removed_bases=tuple(sorted(removed)),
        surviving_bases=tuple(sorted(source_bases | verdict_bases)),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        forbidden_inferences=("profile-change based substantive promotion",),
        rules_fired=("P-INV-01", "P-INV-02", "P-INV-03"),
        next_governed_step=(
            "complete the profile-change reassessment request"
            if event.request_id is not None
            else "issue a governed reassessment request if evidence was invalidated"
        ),
    )
    return post, trace


def apply_request_reassessment(
    state: ControlState, event: RequestReassessment
) -> tuple[ControlState, TransitionTrace]:
    if event.request_id in state.requests_by_id():
        raise TemporalTransitionError("reassessment request identity already exists")
    request = _request_from_event(event, state.logical_time)
    post = replace(
        state,
        reassessment_requests=(*state.reassessment_requests, request),
        history=(
            *state.history,
            AuditEvent.create(
                "RequestReassessment",
                authority=event.authority,
                request_id=event.request_id,
                due_at=str(event.due_at),
                reason=event.reason,
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="RequestReassessment",
        preserved_evidence=tuple(sorted(item.evidence_id for item in state.evidence)),
        surviving_bases=tuple(
            sorted(state.current_source_basis_ids | state.current_verdict_basis_ids)
        ),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        forbidden_inferences=("request-based source state or verdict change",),
        rules_fired=("R-INV-01", "R-INV-02"),
        next_governed_step="complete reassessment before the governed due time",
    )
    return post, trace


def apply_record_heartbeat(
    state: ControlState, event: RecordHeartbeat
) -> tuple[ControlState, TransitionTrace]:
    if event.authority != "I3":
        raise TemporalTransitionError("heartbeat recording requires I3 authority")
    if event.at_time != state.logical_time:
        raise TemporalTransitionError("heartbeat must be recorded at the current logical time")
    interval = event.interval if event.interval is not None else None
    if interval is None and state.heartbeat is not None:
        interval = state.heartbeat.interval
    if interval is None or interval <= 0:
        raise TemporalTransitionError("heartbeat requires a positive interval")

    heartbeat = HeartbeatState(
        interval=interval,
        last_recorded_at=event.at_time,
        due_at=event.at_time + interval,
    )
    post = replace(
        state,
        heartbeat=heartbeat,
        history=(
            *state.history,
            AuditEvent.create(
                "RecordHeartbeat",
                authority=event.authority,
                at_time=str(event.at_time),
                interval=str(interval),
                due_at=str(heartbeat.due_at),
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="RecordHeartbeat",
        preserved_evidence=tuple(sorted(item.evidence_id for item in state.evidence)),
        surviving_bases=tuple(
            sorted(state.current_source_basis_ids | state.current_verdict_basis_ids)
        ),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        forbidden_inferences=("heartbeat-based substantive promotion",),
        rules_fired=("H-INV-01", "H-INV-02"),
        next_governed_step=f"record the next heartbeat by logical time {heartbeat.due_at}",
    )
    return post, trace


def close_reassessment_requests(
    state: ControlState, request_ids: tuple[str, ...]
) -> tuple[ReassessmentRequest, ...]:
    if len(set(request_ids)) != len(request_ids):
        raise TemporalTransitionError("reassessment request closures must be unique")
    requested = set(request_ids)
    known = state.requests_by_id()
    missing = requested - set(known)
    if missing:
        raise TemporalTransitionError(f"unknown reassessment requests: {sorted(missing)}")
    already_closed = {
        request_id
        for request_id in requested
        if known[request_id].status is RequestStatus.CLOSED
    }
    if already_closed:
        raise TemporalTransitionError(
            f"reassessment requests are already closed: {sorted(already_closed)}"
        )
    return tuple(
        request.close(state.logical_time) if request.request_id in requested else request
        for request in state.reassessment_requests
    )
