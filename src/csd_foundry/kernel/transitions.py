"""Deterministic state transitions for the executable CSD kernel."""

from __future__ import annotations

from dataclasses import replace

from csd_foundry.kernel.events import (
    AdvanceClock,
    CsdEvent,
    DependencyChange,
    ProfileChange,
    Reassess,
    RecordHeartbeat,
    RequestReassessment,
    RetireControl,
)
from csd_foundry.kernel.models import (
    Assurance,
    AuditEvent,
    Basis,
    BasisKind,
    ControlState,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)
from csd_foundry.kernel.temporal import (
    apply_advance_clock,
    apply_profile_change,
    apply_record_heartbeat,
    apply_request_reassessment,
    close_reassessment_requests,
)
from csd_foundry.kernel.trace import TransitionTrace


class TransitionError(ValueError):
    """Raised when a governed transition violates an explicit precondition."""


def _basis_is_current(state: ControlState, basis_id: str) -> bool:
    evidence = state.evidence_by_id()
    basis = state.bases_by_id().get(basis_id)
    if basis is None or not basis.approved or not basis.member_evidence_ids:
        return False
    return all(
        member in evidence and evidence[member].status is EvidenceStatus.CURRENT
        for member in basis.member_evidence_ids
    )


def _basis_matches_claim(basis: Basis, kind: BasisKind, claim: str) -> bool:
    return basis.kind is kind and basis.claim == claim


def apply_dependency_change(
    state: ControlState, event: DependencyChange
) -> tuple[ControlState, TransitionTrace]:
    invalidated_ids: set[str] = set()
    updated_evidence = []
    for item in state.evidence:
        if item.status is EvidenceStatus.CURRENT and event.dependency_id in item.dependencies:
            invalidated_ids.add(item.evidence_id)
            updated_evidence.append(item.invalidate())
        else:
            updated_evidence.append(item)

    interim = replace(state, evidence=tuple(updated_evidence))
    source_survivors = frozenset(
        basis_id
        for basis_id in state.current_source_basis_ids
        if _basis_is_current(interim, basis_id)
    )
    verdict_survivors = frozenset(
        basis_id
        for basis_id in state.current_verdict_basis_ids
        if _basis_is_current(interim, basis_id)
    )

    removed = (
        state.current_source_basis_ids.union(state.current_verdict_basis_ids)
        - source_survivors
        - verdict_survivors
    )

    resulting_source = state.source_state
    if state.source_state is not SourceState.UNKNOWN and not source_survivors:
        resulting_source = SourceState.UNKNOWN

    resulting_assurance = state.assurance
    if state.obligation is not ObligationStatus.CURRENT:
        resulting_assurance = Assurance.NA
    elif (
        state.assurance in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}
        and not verdict_survivors
    ):
        resulting_assurance = Assurance.STALE

    event_record = AuditEvent.create(
        "DependencyChange",
        dependency_id=event.dependency_id,
        apparent_direction=event.apparent_direction or "unspecified",
    )
    post = replace(
        interim,
        source_state=resulting_source,
        assurance=resulting_assurance,
        current_source_basis_ids=source_survivors,
        current_verdict_basis_ids=verdict_survivors,
        history=(*state.history, event_record),
    )

    preserved = tuple(
        sorted(item.evidence_id for item in post.evidence if item.status is EvidenceStatus.CURRENT)
    )
    surviving = tuple(sorted(source_survivors | verdict_survivors))
    trace = TransitionTrace(
        event_type="DependencyChange",
        invalidated_evidence=tuple(sorted(invalidated_ids)),
        preserved_evidence=preserved,
        removed_bases=tuple(sorted(removed)),
        surviving_bases=surviving,
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        forbidden_inferences=("replacement substantive state or verdict",),
        rules_fired=(
            "INV-11",
            "INV-12",
            "INV-13",
            "INV-14",
            "INV-15",
            "INV-16",
            "SYM-01",
        ),
        next_governed_step=(
            "governed reassessment with new evidence and new approved basis"
            if resulting_source is SourceState.UNKNOWN or resulting_assurance is Assurance.STALE
            else "none required for surviving current claims"
        ),
    )
    return post, trace


def apply_reassess(state: ControlState, event: Reassess) -> tuple[ControlState, TransitionTrace]:
    if event.authority != "I3":
        raise TransitionError("reassessment requires I3 authority")

    existing_evidence_ids = set(state.evidence_by_id())
    existing_basis_ids = set(state.bases_by_id())
    new_evidence_ids = {item.evidence_id for item in event.new_evidence}
    new_basis_ids = {basis.basis_id for basis in event.new_bases}
    if existing_evidence_ids & new_evidence_ids:
        raise TransitionError("reassessment must use new evidence identities")
    if existing_basis_ids & new_basis_ids:
        raise TransitionError("reassessment must use new basis identities")
    if any(item.status is not EvidenceStatus.CURRENT for item in event.new_evidence):
        raise TransitionError("new reassessment evidence must be current")
    if any(item.issued_at > state.logical_time for item in event.new_evidence):
        raise TransitionError("new reassessment evidence cannot be issued in the future")

    resulting_source = event.source_state or state.source_state
    resulting_assurance = event.assurance or state.assurance
    evidence_ids_after = existing_evidence_ids | new_evidence_ids
    for basis in event.new_bases:
        if not basis.approved:
            raise TransitionError("new basis must be approved")
        if not basis.member_evidence_ids:
            raise TransitionError("new basis must contain evidence")
        if not basis.member_evidence_ids <= evidence_ids_after:
            raise TransitionError("basis references unknown evidence")
        if basis.kind is BasisKind.SOURCE and basis.claim != resulting_source.value:
            raise TransitionError("source basis claim does not match reassessed source state")
        if basis.kind is BasisKind.VERDICT and basis.claim != resulting_assurance.value:
            raise TransitionError("verdict basis claim does not match reassessed assurance")

    bases_before = state.bases_by_id()
    source_basis_ids = {
        basis_id
        for basis_id in state.current_source_basis_ids
        if (existing_source_basis := bases_before.get(basis_id)) is not None
        and _basis_matches_claim(existing_source_basis, BasisKind.SOURCE, resulting_source.value)
    }
    verdict_basis_ids = {
        basis_id
        for basis_id in state.current_verdict_basis_ids
        if (existing_verdict_basis := bases_before.get(basis_id)) is not None
        and _basis_matches_claim(
            existing_verdict_basis, BasisKind.VERDICT, resulting_assurance.value
        )
    }
    for basis in event.new_bases:
        if basis.kind is BasisKind.SOURCE:
            source_basis_ids.add(basis.basis_id)
        elif basis.kind is BasisKind.VERDICT:
            verdict_basis_ids.add(basis.basis_id)

    if resulting_source is SourceState.UNKNOWN:
        source_basis_ids.clear()
    if resulting_assurance not in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}:
        verdict_basis_ids.clear()

    requests = close_reassessment_requests(state, event.close_request_ids)
    post = replace(
        state,
        evidence=(*state.evidence, *event.new_evidence),
        bases=(*state.bases, *event.new_bases),
        current_source_basis_ids=frozenset(source_basis_ids),
        current_verdict_basis_ids=frozenset(verdict_basis_ids),
        source_state=resulting_source,
        assurance=resulting_assurance,
        reassessment_requests=requests,
        history=(
            *state.history,
            AuditEvent.create(
                "Reassess",
                authority=event.authority,
                evidence_ids=",".join(sorted(new_evidence_ids)),
                basis_ids=",".join(sorted(new_basis_ids)),
                closed_request_ids=",".join(sorted(event.close_request_ids)),
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="Reassess",
        preserved_evidence=tuple(sorted(existing_evidence_ids)),
        surviving_bases=tuple(sorted(source_basis_ids | verdict_basis_ids)),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        rules_fired=(
            "INV-18",
            "INV-19",
            "G-INV-06",
            "G-INV-09",
            "G-INV-10",
            "G-INV-11",
            "R-INV-03",
        ),
        next_governed_step="publish the new current view while retaining superseded history",
    )
    return post, trace


def apply_retire(state: ControlState, event: RetireControl) -> tuple[ControlState, TransitionTrace]:
    if event.authority != "I3":
        raise TransitionError("retirement requires I3 authority")
    if event.retirement_evidence.evidence_id in state.evidence_by_id():
        raise TransitionError("retirement evidence must use a new identity")
    if event.retirement_evidence.status is not EvidenceStatus.CURRENT:
        raise TransitionError("retirement evidence must be current")

    post = replace(
        state,
        obligation=ObligationStatus.RETIRED,
        source_state=SourceState.UNKNOWN,
        assurance=Assurance.NA,
        evidence=(*state.evidence, event.retirement_evidence),
        current_source_basis_ids=frozenset(),
        current_verdict_basis_ids=frozenset(),
        history=(
            *state.history,
            AuditEvent.create(
                "RetireControl",
                authority=event.authority,
                evidence_id=event.retirement_evidence.evidence_id,
            ),
        ),
    )
    trace = TransitionTrace(
        event_type="RetireControl",
        preserved_evidence=tuple(sorted(item.evidence_id for item in state.evidence)),
        removed_bases=tuple(
            sorted(state.current_source_basis_ids | state.current_verdict_basis_ids)
        ),
        previous_source_state=state.source_state.value,
        resulting_source_state=post.source_state.value,
        previous_assurance=state.assurance.value,
        resulting_assurance=post.assurance.value,
        rules_fired=("INV-04", "INV-19", "G-INV-11", "G-INV-12", "G-INV-13"),
        next_governed_step="none unless the obligation is reintroduced through governance",
    )
    return post, trace


def apply_event(state: ControlState, event: CsdEvent) -> tuple[ControlState, TransitionTrace]:
    if isinstance(event, DependencyChange):
        return apply_dependency_change(state, event)
    if isinstance(event, Reassess):
        return apply_reassess(state, event)
    if isinstance(event, RetireControl):
        return apply_retire(state, event)
    if isinstance(event, AdvanceClock):
        return apply_advance_clock(state, event)
    if isinstance(event, ProfileChange):
        return apply_profile_change(state, event)
    if isinstance(event, RequestReassessment):
        return apply_request_reassessment(state, event)
    if isinstance(event, RecordHeartbeat):
        return apply_record_heartbeat(state, event)
    raise TypeError(f"unsupported event type: {type(event).__name__}")
