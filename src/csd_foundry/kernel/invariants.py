"""Independent invariant checks for canonical CSD states and transitions."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.kernel.events import CsdEvent, DependencyChange, Reassess, RetireControl
from csd_foundry.kernel.models import (
    Assurance,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)


@dataclass(frozen=True, slots=True)
class Violation:
    invariant_id: str
    message: str


def _basis_is_supported(basis: Basis, evidence: dict[str, Evidence]) -> bool:
    return (
        bool(basis.member_evidence_ids)
        and basis.approved
        and all(
            member in evidence and evidence[member].status is EvidenceStatus.CURRENT
            for member in basis.member_evidence_ids
        )
    )


def validate_state(state: ControlState) -> tuple[Violation, ...]:
    violations: list[Violation] = []
    evidence = state.evidence_by_id()
    bases = state.bases_by_id()

    if len(evidence) != len(state.evidence):
        violations.append(Violation("G-INV-06", "duplicate evidence identity"))
    if len(bases) != len(state.bases):
        violations.append(Violation("G-INV-11", "duplicate basis identity"))

    current_ids = state.current_source_basis_ids | state.current_verdict_basis_ids
    for basis_id in sorted(current_ids):
        basis = bases.get(basis_id)
        if basis is None:
            violations.append(Violation("INV-07", f"missing current basis {basis_id}"))
            continue
        if not basis.approved:
            violations.append(Violation("INV-07", f"unapproved current basis {basis_id}"))
        if not basis.member_evidence_ids:
            violations.append(Violation("INV-07", f"current basis {basis_id} has no evidence"))
        for member in sorted(basis.member_evidence_ids):
            item = evidence.get(member)
            if item is None:
                violations.append(
                    Violation("INV-07", f"basis {basis_id} references missing evidence {member}")
                )
            elif item.status is not EvidenceStatus.CURRENT:
                violations.append(
                    Violation(
                        "INV-13",
                        f"basis {basis_id} references non-current evidence {member}",
                    )
                )

    for basis_id in state.current_source_basis_ids:
        basis = bases.get(basis_id)
        if basis is None:
            continue
        if basis.kind is not BasisKind.SOURCE:
            violations.append(Violation("INV-05", f"{basis_id} is not a source basis"))
        elif basis.claim != state.source_state.value:
            violations.append(
                Violation(
                    "INV-05",
                    f"source basis {basis_id} claims {basis.claim}, not {state.source_state.value}",
                )
            )

    for basis_id in state.current_verdict_basis_ids:
        basis = bases.get(basis_id)
        if basis is None:
            continue
        if basis.kind is not BasisKind.VERDICT:
            violations.append(Violation("INV-07", f"{basis_id} is not a verdict basis"))
        elif basis.claim != state.assurance.value:
            violations.append(
                Violation(
                    "INV-07",
                    f"verdict basis {basis_id} claims {basis.claim}, not {state.assurance.value}",
                )
            )

    if state.source_state is not SourceState.UNKNOWN and not state.current_source_basis_ids:
        violations.append(Violation("INV-05", "substantive source state has no current basis"))
    if (
        state.obligation is ObligationStatus.CURRENT
        and state.assurance in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}
        and not state.current_verdict_basis_ids
    ):
        violations.append(Violation("INV-07", "substantive verdict has no current basis"))
    if state.obligation is not ObligationStatus.CURRENT and state.assurance is not Assurance.NA:
        violations.append(Violation("INV-04", "non-current obligation must have assuranceNA"))

    return tuple(violations)


def validate_transition(before: ControlState, after: ControlState) -> tuple[Violation, ...]:
    """Validate event-independent immutability and state consistency."""
    violations = list(validate_state(after))
    if after.history[: len(before.history)] != before.history:
        violations.append(Violation("INV-19", "history is not append-only"))

    before_evidence = before.evidence_by_id()
    after_evidence = after.evidence_by_id()
    for evidence_id, old in before_evidence.items():
        new = after_evidence.get(evidence_id)
        if new is None:
            violations.append(Violation("INV-19", f"evidence {evidence_id} was deleted"))
            continue
        if old.status is not EvidenceStatus.CURRENT and new.status is EvidenceStatus.CURRENT:
            violations.append(Violation("INV-18", f"evidence {evidence_id} was reactivated"))
        if (
            old.evidence_id != new.evidence_id
            or old.dimension != new.dimension
            or old.dependencies != new.dependencies
            or old.outcome != new.outcome
        ):
            violations.append(Violation("G-INV-06", f"evidence {evidence_id} was rewritten"))

    before_bases = before.bases_by_id()
    after_bases = after.bases_by_id()
    for basis_id, old_basis in before_bases.items():
        new_basis = after_bases.get(basis_id)
        if new_basis is None:
            violations.append(Violation("INV-19", f"basis {basis_id} was deleted"))
        elif old_basis != new_basis:
            violations.append(Violation("G-INV-11", f"basis {basis_id} was rewritten"))

    return tuple(violations)


def _validate_dependency_change(
    before: ControlState,
    event: DependencyChange,
    after: ControlState,
) -> list[Violation]:
    violations: list[Violation] = []
    before_evidence = before.evidence_by_id()
    after_evidence = after.evidence_by_id()

    if set(after_evidence) != set(before_evidence):
        violations.append(Violation("INV-11", "dependency change altered evidence identities"))
    if set(after.bases_by_id()) != set(before.bases_by_id()):
        violations.append(Violation("INV-13", "dependency change altered basis identities"))

    for evidence_id, old in before_evidence.items():
        new = after_evidence.get(evidence_id)
        if new is None:
            continue
        affected = old.status is EvidenceStatus.CURRENT and event.dependency_id in old.dependencies
        expected_status = EvidenceStatus.INVALIDATED if affected else old.status
        if new.status is not expected_status:
            invariant = "INV-11" if affected else "INV-14"
            violations.append(
                Violation(
                    invariant,
                    f"evidence {evidence_id} has {new.status.value}; "
                    f"expected {expected_status.value}",
                )
            )

    after_bases = after.bases_by_id()
    expected_source = frozenset(
        basis_id
        for basis_id in before.current_source_basis_ids
        if (basis := after_bases.get(basis_id)) is not None
        and _basis_is_supported(basis, after_evidence)
    )
    expected_verdict = frozenset(
        basis_id
        for basis_id in before.current_verdict_basis_ids
        if (basis := after_bases.get(basis_id)) is not None
        and _basis_is_supported(basis, after_evidence)
    )
    if after.current_source_basis_ids != expected_source:
        violations.append(Violation("INV-13", "source-basis survival does not match impact"))
    if after.current_verdict_basis_ids != expected_verdict:
        violations.append(Violation("INV-16", "verdict-basis survival does not match impact"))

    expected_source_state = before.source_state
    if before.source_state is not SourceState.UNKNOWN and not expected_source:
        expected_source_state = SourceState.UNKNOWN
    if after.source_state is not expected_source_state:
        violations.append(Violation("INV-15", "source-state result does not match basis survival"))

    expected_assurance = before.assurance
    if before.obligation is not ObligationStatus.CURRENT:
        expected_assurance = Assurance.NA
    elif (
        before.assurance in {Assurance.PASS, Assurance.PARTIAL, Assurance.FAIL}
        and not expected_verdict
    ):
        expected_assurance = Assurance.STALE
    if after.assurance is not expected_assurance:
        violations.append(Violation("INV-15", "assurance result does not match basis survival"))

    return violations


def _validate_reassess(
    before: ControlState,
    event: Reassess,
    after: ControlState,
) -> list[Violation]:
    violations: list[Violation] = []
    before_evidence = before.evidence_by_id()
    after_evidence = after.evidence_by_id()
    expected_new_evidence = {item.evidence_id: item for item in event.new_evidence}
    actual_new_evidence_ids = set(after_evidence) - set(before_evidence)
    if actual_new_evidence_ids != set(expected_new_evidence):
        violations.append(
            Violation("INV-18", "reassessment evidence identities do not match the event")
        )
    for evidence_id, expected in expected_new_evidence.items():
        actual = after_evidence.get(evidence_id)
        if actual is not None and actual != expected:
            violations.append(
                Violation("G-INV-06", f"reassessment evidence {evidence_id} differs from the event")
            )

    before_bases = before.bases_by_id()
    after_bases = after.bases_by_id()
    expected_new_bases = {basis.basis_id: basis for basis in event.new_bases}
    actual_new_basis_ids = set(after_bases) - set(before_bases)
    if actual_new_basis_ids != set(expected_new_bases):
        violations.append(
            Violation("G-INV-11", "reassessment basis identities do not match the event")
        )
    for basis_id, expected_basis in expected_new_bases.items():
        actual_basis = after_bases.get(basis_id)
        if actual_basis is not None and actual_basis != expected_basis:
            violations.append(
                Violation("G-INV-11", f"reassessment basis {basis_id} differs from the event")
            )

    resulting_source = event.source_state or before.source_state
    resulting_assurance = event.assurance or before.assurance
    if after.source_state is not resulting_source:
        violations.append(
            Violation("G-INV-10", "reassessment source state does not match the event")
        )
    if after.assurance is not resulting_assurance:
        violations.append(Violation("G-INV-10", "reassessment assurance does not match the event"))

    expected_source = frozenset(
        basis_id
        for basis_id in before.current_source_basis_ids | set(expected_new_bases)
        if (basis := after_bases.get(basis_id)) is not None
        and basis.kind is BasisKind.SOURCE
        and basis.claim == resulting_source.value
        and _basis_is_supported(basis, after_evidence)
    )
    expected_verdict = frozenset(
        basis_id
        for basis_id in before.current_verdict_basis_ids | set(expected_new_bases)
        if (basis := after_bases.get(basis_id)) is not None
        and basis.kind is BasisKind.VERDICT
        and basis.claim == resulting_assurance.value
        and _basis_is_supported(basis, after_evidence)
    )
    if after.current_source_basis_ids != expected_source:
        violations.append(Violation("G-INV-10", "reassessment source references are not canonical"))
    if after.current_verdict_basis_ids != expected_verdict:
        violations.append(
            Violation("G-INV-10", "reassessment verdict references are not canonical")
        )
    return violations


def _validate_retirement(
    before: ControlState,
    event: RetireControl,
    after: ControlState,
) -> list[Violation]:
    violations: list[Violation] = []
    before_evidence = before.evidence_by_id()
    after_evidence = after.evidence_by_id()
    expected_id = event.retirement_evidence.evidence_id
    actual_new_ids = set(after_evidence) - set(before_evidence)
    if actual_new_ids != {expected_id}:
        violations.append(
            Violation("G-INV-13", "retirement evidence identity does not match the event")
        )
    actual_evidence = after_evidence.get(expected_id)
    if actual_evidence is not None and actual_evidence != event.retirement_evidence:
        violations.append(
            Violation("G-INV-06", "retirement evidence content does not match the event")
        )
    if set(after.bases_by_id()) != set(before.bases_by_id()):
        violations.append(Violation("G-INV-13", "retirement altered basis identities"))
    if after.obligation is not ObligationStatus.RETIRED:
        violations.append(Violation("INV-04", "retirement did not retire the obligation"))
    if after.assurance is not Assurance.NA:
        violations.append(Violation("INV-04", "retirement did not set assuranceNA"))
    if after.source_state is not SourceState.UNKNOWN:
        violations.append(Violation("INV-05", "retirement retained a substantive source state"))
    if after.current_source_basis_ids or after.current_verdict_basis_ids:
        violations.append(Violation("G-INV-13", "retirement retained current basis references"))
    return violations


def validate_event_transition(
    before: ControlState,
    event: CsdEvent,
    after: ControlState,
) -> tuple[Violation, ...]:
    """Validate the post-state independently against the triggering event."""
    if isinstance(event, DependencyChange):
        return tuple(_validate_dependency_change(before, event, after))
    if isinstance(event, Reassess):
        return tuple(_validate_reassess(before, event, after))
    if isinstance(event, RetireControl):
        return tuple(_validate_retirement(before, event, after))
    raise TypeError(f"unsupported event type: {type(event).__name__}")
