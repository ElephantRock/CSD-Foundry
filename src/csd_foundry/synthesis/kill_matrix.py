"""Mutation kill-matrix evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.kernel.invariants import validate_transition
from csd_foundry.kernel.models import ControlState
from csd_foundry.synthesis.mutations import Mutation


@dataclass(frozen=True, slots=True)
class KillResult:
    mutation_id: str
    killed: bool
    expected_invariants: tuple[str, ...]
    observed_invariants: tuple[str, ...]


def evaluate(canonical_state: ControlState, mutation: Mutation) -> KillResult:
    """Evaluate a mutated state against the canonical state it was derived from."""
    observed = tuple(
        sorted(
            {
                violation.invariant_id
                for violation in validate_transition(canonical_state, mutation.state)
            }
        )
    )
    killed = bool(set(mutation.expected_invariants) & set(observed))
    return KillResult(
        mutation_id=mutation.mutation_id,
        killed=killed,
        expected_invariants=mutation.expected_invariants,
        observed_invariants=observed,
    )
