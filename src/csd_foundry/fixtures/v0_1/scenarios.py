"""Executable representative fixtures from the CSD Reasoning Seed v0.1."""

from __future__ import annotations

from csd_foundry.kernel.events import DependencyChange, Reassess
from csd_foundry.kernel.models import (
    Assurance,
    AuditEvent,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    SourceState,
)


def m01() -> tuple[ControlState, DependencyChange]:
    state = ControlState(
        control_id="CTRL-NET-17",
        source_state=SourceState.WIRED_INERT,
        evidence=(
            Evidence(
                "EV-N17-001",
                dimension="S0",
                dependencies=frozenset({"DEP-FW-POLICY-7"}),
            ),
        ),
        bases=(
            Basis(
                "BASIS-N17-01",
                BasisKind.SOURCE,
                SourceState.WIRED_INERT.value,
                frozenset({"EV-N17-001"}),
            ),
        ),
        current_source_basis_ids=frozenset({"BASIS-N17-01"}),
        history=(AuditEvent.create("IssueEvidence", evidence_id="EV-N17-001"),),
    )
    return state, DependencyChange("DEP-FW-POLICY-7", "apparentlyFavourable")


def m06() -> tuple[ControlState, DependencyChange]:
    state = ControlState(
        control_id="CTRL-NET-17",
        assurance=Assurance.FAIL,
        evidence=(
            Evidence("EV-N17-001", "D", dependencies=frozenset({"DEP-FW-POLICY-7"})),
            Evidence("EV-N17-002", "D", dependencies=frozenset({"DEP-IDENTITY-4"})),
        ),
        bases=(
            Basis("BASIS-N17-01", BasisKind.VERDICT, "fail", frozenset({"EV-N17-001"})),
            Basis("BASIS-N17-02", BasisKind.VERDICT, "fail", frozenset({"EV-N17-002"})),
        ),
        current_verdict_basis_ids=frozenset({"BASIS-N17-01", "BASIS-N17-02"}),
    )
    return state, DependencyChange("DEP-FW-POLICY-7", "apparentlyUnfavourable")


def m09() -> tuple[ControlState, Reassess]:
    state = ControlState(
        control_id="CTRL-NET-17",
        source_state=SourceState.UNKNOWN,
        evidence=(
            Evidence(
                "EV-N17-001",
                "S1",
                status=EvidenceStatus.INVALIDATED,
                dependencies=frozenset({"DEP-FW-POLICY-7"}),
            ),
        ),
        bases=(Basis("BASIS-N17-01", BasisKind.SOURCE, "connected", frozenset({"EV-N17-001"})),),
        history=(AuditEvent.create("InvalidateEvidence", evidence_id="EV-N17-001"),),
    )
    event = Reassess(
        new_evidence=(Evidence("EV-N17-002", "S1"),),
        new_bases=(
            Basis("BASIS-N17-02", BasisKind.SOURCE, "connected", frozenset({"EV-N17-002"})),
        ),
        source_state=SourceState.CONNECTED,
    )
    return state, event
