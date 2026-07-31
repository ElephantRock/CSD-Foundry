"""Invariant-targeted adversarial state mutations."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from csd_foundry.kernel.models import Assurance, ControlState, EvidenceStatus, SourceState


class MutationOperator(StrEnum):
    RETAIN_INVALID_BASIS = "retain_invalid_basis"
    PROMOTE_AFTER_REVOCATION = "promote_after_revocation"
    REACTIVATE_EVIDENCE = "reactivate_evidence"
    OVERWRITE_HISTORY = "overwrite_history"


@dataclass(frozen=True, slots=True)
class Mutation:
    mutation_id: str
    operator: MutationOperator
    expected_invariants: tuple[str, ...]
    state: ControlState


def retain_invalid_basis(
    mutation_id: str, before: ControlState, valid_after: ControlState
) -> Mutation:
    state = replace(
        valid_after,
        current_source_basis_ids=before.current_source_basis_ids,
        current_verdict_basis_ids=before.current_verdict_basis_ids,
    )
    return Mutation(mutation_id, MutationOperator.RETAIN_INVALID_BASIS, ("INV-13",), state)


def promote_after_revocation(mutation_id: str, valid_after: ControlState) -> Mutation:
    state = replace(
        valid_after,
        source_state=SourceState.CONNECTED,
        assurance=Assurance.PASS,
    )
    return Mutation(
        mutation_id,
        MutationOperator.PROMOTE_AFTER_REVOCATION,
        ("INV-05", "INV-07"),
        state,
    )


def reactivate_evidence(mutation_id: str, valid_after: ControlState) -> Mutation:
    items = list(valid_after.evidence)
    for index, item in enumerate(items):
        if item.status is EvidenceStatus.INVALIDATED:
            items[index] = replace(item, status=EvidenceStatus.CURRENT)
            break
    else:
        raise ValueError("state contains no invalidated evidence")
    return Mutation(
        mutation_id,
        MutationOperator.REACTIVATE_EVIDENCE,
        ("INV-18",),
        replace(valid_after, evidence=tuple(items)),
    )


def overwrite_history(mutation_id: str, valid_after: ControlState) -> Mutation:
    state = replace(valid_after, history=valid_after.history[-1:])
    return Mutation(mutation_id, MutationOperator.OVERWRITE_HISTORY, ("INV-19",), state)
