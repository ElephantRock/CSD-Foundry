"""Fail-closed CSD oracle combining transitions with independent verification."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.kernel.events import CsdEvent
from csd_foundry.kernel.invariants import (
    Violation,
    validate_event_transition,
    validate_state,
    validate_transition,
)
from csd_foundry.kernel.models import ControlState
from csd_foundry.kernel.temporal import is_temporal_event
from csd_foundry.kernel.temporal_invariants import (
    validate_temporal_event,
    validate_temporal_state,
    validate_temporal_transition,
)
from csd_foundry.kernel.trace import TransitionTrace
from csd_foundry.kernel.transitions import apply_event


class OracleRejected(RuntimeError):
    """Raised when a proposed transition violates the implemented CSD semantics."""


@dataclass(frozen=True, slots=True)
class OracleResult:
    before: ControlState
    after: ControlState
    trace: TransitionTrace
    violations: tuple[Violation, ...] = ()


class CsdOracle:
    """Execute one governed transition and independently validate the result."""

    def apply(self, state: ControlState, event: CsdEvent) -> OracleResult:
        initial = (*validate_state(state), *validate_temporal_state(state))
        if initial:
            raise OracleRejected(_format_violations("invalid pre-state", initial))
        after, trace = apply_event(state, event)
        core_event_violations: tuple[Violation, ...] = ()
        if not is_temporal_event(event):
            core_event_violations = validate_event_transition(state, event, after)
        violations = (
            *validate_transition(state, after),
            *validate_temporal_transition(state, after),
            *core_event_violations,
            *validate_temporal_event(state, event, after),
        )
        if violations:
            raise OracleRejected(_format_violations("invalid post-state", violations))
        return OracleResult(before=state, after=after, trace=trace)


def _format_violations(prefix: str, violations: tuple[Violation, ...]) -> str:
    joined = "; ".join(f"{item.invariant_id}: {item.message}" for item in violations)
    return f"{prefix}: {joined}"
