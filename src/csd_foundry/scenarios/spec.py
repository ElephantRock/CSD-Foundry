"""Typed contracts for executable CSD scenario releases."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.kernel.events import CsdEvent
from csd_foundry.kernel.models import (
    Assurance,
    ControlState,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)


class ScenarioMode(StrEnum):
    """Execution shape used by a scenario specification."""

    TRANSITION = "transition"
    SEQUENCE = "sequence"
    MULTI_CONTROL = "multi_control"
    OBSERVATION = "observation"
    REJECTED_TRANSITION = "rejected_transition"


@dataclass(frozen=True, slots=True)
class StateExpectation:
    """Partial, explicit expectations for one canonical state."""

    obligation: ObligationStatus | None = None
    source_state: SourceState | None = None
    assurance: Assurance | None = None
    evidence_statuses: tuple[tuple[str, EvidenceStatus], ...] = ()
    evidence_outcomes: tuple[tuple[str, str | None], ...] = ()
    basis_claims: tuple[tuple[str, str], ...] = ()
    current_source_basis_ids: frozenset[str] | None = None
    current_verdict_basis_ids: frozenset[str] | None = None
    history_length: int | None = None
    history_event_types: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class TransitionCase:
    """One oracle-backed state transition."""

    case_id: str
    before: ControlState
    event: CsdEvent
    expected: StateExpectation
    expected_invalidated_evidence: frozenset[str] | None = None
    expected_surviving_bases: frozenset[str] | None = None
    required_trace_rules: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ObservationCase:
    """A valid canonical state used for non-transition semantic obligations."""

    case_id: str
    state: ControlState
    expected: StateExpectation
    assertion: str


@dataclass(frozen=True, slots=True)
class RejectedTransitionCase:
    """A proposed post-state that must be rejected by independent verification."""

    case_id: str
    before: ControlState
    proposed_after: ControlState
    expected_invariants: frozenset[str]
    event: CsdEvent | None = None


ExecutableCase = TransitionCase | ObservationCase | RejectedTransitionCase


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    """Manifest-aligned executable scenario definition."""

    scenario_id: str
    split: str
    family: str
    source_section: str
    rule_ids: frozenset[str]
    mode: ScenarioMode
    cases: tuple[ExecutableCase, ...]
    forbidden_inferences: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
