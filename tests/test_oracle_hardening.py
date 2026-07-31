from dataclasses import replace

import pytest

from csd_foundry.fixtures.v0_1.scenarios import m01
from csd_foundry.kernel.events import DependencyChange, Reassess, RetireControl
from csd_foundry.kernel.invariants import validate_event_transition, validate_state
from csd_foundry.kernel.models import (
    Assurance,
    AuditEvent,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.kernel.transitions import TransitionError


def test_dependency_verifier_rejects_wrong_impact_set() -> None:
    before = ControlState(
        control_id="CTRL-1",
        evidence=(
            Evidence("EV-X", "D", dependencies=frozenset({"DEP-X"})),
            Evidence("EV-Y", "D", dependencies=frozenset({"DEP-Y"})),
        ),
    )
    after = replace(
        before,
        evidence=(
            replace(before.evidence[0], status=EvidenceStatus.INVALIDATED),
            before.evidence[1],
        ),
        history=(AuditEvent.create("DependencyChange", dependency_id="DEP-Y"),),
    )

    observed = {
        violation.invariant_id
        for violation in validate_event_transition(
            before,
            DependencyChange("DEP-Y"),
            after,
        )
    }
    assert {"INV-11", "INV-14"} <= observed


def test_source_basis_claim_must_match_current_source_state() -> None:
    state = ControlState(
        control_id="CTRL-1",
        source_state=SourceState.CONNECTED,
        evidence=(Evidence("EV-1", "S1"),),
        bases=(
            Basis(
                "BASIS-1",
                BasisKind.SOURCE,
                SourceState.WIRED_INERT.value,
                frozenset({"EV-1"}),
            ),
        ),
        current_source_basis_ids=frozenset({"BASIS-1"}),
    )
    assert "INV-05" in {violation.invariant_id for violation in validate_state(state)}


def test_empty_current_basis_is_rejected() -> None:
    state = ControlState(
        control_id="CTRL-1",
        source_state=SourceState.CONNECTED,
        bases=(Basis("BASIS-1", BasisKind.SOURCE, "connected", frozenset()),),
        current_source_basis_ids=frozenset({"BASIS-1"}),
    )
    assert "INV-07" in {violation.invariant_id for violation in validate_state(state)}


def test_reassessment_rejects_empty_new_basis() -> None:
    event = Reassess(
        new_evidence=(),
        new_bases=(Basis("BASIS-1", BasisKind.SOURCE, "connected", frozenset()),),
        source_state=SourceState.CONNECTED,
    )
    with pytest.raises(TransitionError, match="must contain evidence"):
        CsdOracle().apply(ControlState(control_id="CTRL-1"), event)


def test_retirement_clears_substantive_current_view() -> None:
    state, _ = m01()
    event = RetireControl(Evidence("EV-RETIRE", "lifecycle"))
    result = CsdOracle().apply(state, event)

    assert result.after.obligation is ObligationStatus.RETIRED
    assert result.after.source_state is SourceState.UNKNOWN
    assert result.after.assurance is Assurance.NA
    assert result.after.current_source_basis_ids == frozenset()
    assert result.after.current_verdict_basis_ids == frozenset()
    assert result.after.bases_by_id()["BASIS-N17-01"].claim == "wiredInert"


def test_reassessment_supersedes_contradictory_current_basis() -> None:
    state = ControlState(
        control_id="CTRL-1",
        source_state=SourceState.CONNECTED,
        evidence=(Evidence("EV-OLD", "S1"),),
        bases=(
            Basis(
                "BASIS-OLD",
                BasisKind.SOURCE,
                SourceState.CONNECTED.value,
                frozenset({"EV-OLD"}),
            ),
        ),
        current_source_basis_ids=frozenset({"BASIS-OLD"}),
    )
    event = Reassess(
        new_evidence=(Evidence("EV-NEW", "S1"),),
        new_bases=(
            Basis(
                "BASIS-NEW",
                BasisKind.SOURCE,
                SourceState.WIRED_INERT.value,
                frozenset({"EV-NEW"}),
            ),
        ),
        source_state=SourceState.WIRED_INERT,
    )
    result = CsdOracle().apply(state, event)

    assert result.after.current_source_basis_ids == frozenset({"BASIS-NEW"})
    assert {basis.basis_id for basis in result.after.bases} == {"BASIS-OLD", "BASIS-NEW"}
