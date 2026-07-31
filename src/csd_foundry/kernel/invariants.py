"""Independent invariant checks for canonical CSD states and transitions."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.kernel.models import (
    Assurance,
    BasisKind,
    ControlState,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)


@dataclass(frozen=True, slots=True)
class Violation:
    invariant_id: str
    message: str


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
        if basis and basis.kind is not BasisKind.SOURCE:
            violations.append(Violation("INV-05", f"{basis_id} is not a source basis"))
    for basis_id in state.current_verdict_basis_ids:
        basis = bases.get(basis_id)
        if basis and basis.kind is not BasisKind.VERDICT:
            violations.append(Violation("INV-07", f"{basis_id} is not a verdict basis"))

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
