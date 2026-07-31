"""Manifest-complete executable definitions for CSD Reasoning Seed v0.1."""

from __future__ import annotations

from dataclasses import replace

from csd_foundry.kernel.events import DependencyChange, Reassess, RetireControl
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
from csd_foundry.scenarios.spec import (
    ObservationCase,
    RejectedTransitionCase,
    ScenarioMode,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)


def _e(
    evidence_id: str,
    dimension: str,
    *,
    dependencies: tuple[str, ...] = (),
    status: EvidenceStatus = EvidenceStatus.CURRENT,
    outcome: str | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        dimension=dimension,
        status=status,
        dependencies=frozenset(dependencies),
        outcome=outcome,
    )


def _b(
    basis_id: str,
    kind: BasisKind,
    claim: str,
    *members: str,
) -> Basis:
    return Basis(basis_id, kind, claim, frozenset(members))


def _expect(
    *,
    obligation: ObligationStatus | None = None,
    source_state: SourceState | None = None,
    assurance: Assurance | None = None,
    evidence_statuses: tuple[tuple[str, EvidenceStatus], ...] = (),
    evidence_outcomes: tuple[tuple[str, str | None], ...] = (),
    basis_claims: tuple[tuple[str, str], ...] = (),
    source_bases: frozenset[str] | None = None,
    verdict_bases: frozenset[str] | None = None,
    history_length: int | None = None,
    history_event_types: tuple[str, ...] | None = None,
) -> StateExpectation:
    return StateExpectation(
        obligation=obligation,
        source_state=source_state,
        assurance=assurance,
        evidence_statuses=evidence_statuses,
        evidence_outcomes=evidence_outcomes,
        basis_claims=basis_claims,
        current_source_basis_ids=source_bases,
        current_verdict_basis_ids=verdict_bases,
        history_length=history_length,
        history_event_types=history_event_types,
    )


def _scenario(
    scenario_id: str,
    split: str,
    family: str,
    source_section: str,
    rules: tuple[str, ...],
    mode: ScenarioMode,
    cases: tuple[TransitionCase | ObservationCase | RejectedTransitionCase, ...],
    *,
    forbidden: tuple[str, ...] = (),
    assumptions: tuple[str, ...] = (),
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        split=split,
        family=family,
        source_section=source_section,
        rule_ids=frozenset(rules),
        mode=mode,
        cases=cases,
        forbidden_inferences=forbidden,
        assumptions=assumptions,
    )


# M-01 — sole source basis revoked; no replacement classification is inferred.
_m01_e1 = _e("EV-N17-001", "S0", dependencies=("DEP-FW-POLICY-7",))
_m01_b1 = _b("BASIS-N17-01", BasisKind.SOURCE, "wiredInert", _m01_e1.evidence_id)
_m01_before = ControlState(
    control_id="CTRL-NET-17",
    source_state=SourceState.WIRED_INERT,
    evidence=(_m01_e1,),
    bases=(_m01_b1,),
    current_source_basis_ids=frozenset({_m01_b1.basis_id}),
    history=(AuditEvent.create("IssueEvidence", evidence_id=_m01_e1.evidence_id),),
)
_m01 = _scenario(
    "M-01",
    "train",
    "revocation_non_inference",
    "Charter §12 M-01",
    ("INV-11", "INV-12", "INV-13", "INV-15", "SYM-01"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-01/dependency-change",
            _m01_before,
            DependencyChange("DEP-FW-POLICY-7", "apparentlyFavourable"),
            _expect(
                source_state=SourceState.UNKNOWN,
                evidence_statuses=((_m01_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                source_bases=frozenset(),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset({_m01_e1.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-11", "INV-13", "INV-15", "SYM-01"}),
        ),
    ),
    forbidden=("promote to connected because the event appears favourable",),
)


# M-02 — the only connected source basis is lost.
_m02_e1 = _e("EV-M02-001", "S1", dependencies=("DEP-M02",))
_m02_b1 = _b("BASIS-M02-01", BasisKind.SOURCE, "connected", _m02_e1.evidence_id)
_m02_before = ControlState(
    control_id="CTRL-M02",
    source_state=SourceState.CONNECTED,
    evidence=(_m02_e1,),
    bases=(_m02_b1,),
    current_source_basis_ids=frozenset({_m02_b1.basis_id}),
)
_m02 = _scenario(
    "M-02",
    "train",
    "lost_source_basis",
    "Charter §12 M-02",
    ("INV-05", "INV-11", "INV-13", "INV-15"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-02/dependency-change",
            _m02_before,
            DependencyChange("DEP-M02", "apparentlyUnfavourable"),
            _expect(
                source_state=SourceState.UNKNOWN,
                evidence_statuses=((_m02_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                source_bases=frozenset(),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m02_e1.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-11", "INV-13", "INV-15"}),
        ),
    ),
    forbidden=("select wiredInert as a replacement source state",),
)


# M-03 — canonical post-expiry state. The bootstrap kernel does not yet model clocks.
_m03_e1 = _e("EV-M03-001", "D", status=EvidenceStatus.EXPIRED)
_m03_b1 = _b("BASIS-M03-D", BasisKind.DEPLOYMENT, "active", _m03_e1.evidence_id)
_m03_b2 = _b("BASIS-M03-V", BasisKind.VERDICT, "pass", _m03_e1.evidence_id)
_m03_state = ControlState(
    control_id="CTRL-M03",
    assurance=Assurance.STALE,
    evidence=(_m03_e1,),
    bases=(_m03_b1, _m03_b2),
    history=(AuditEvent.create("AdvanceClock", expired_evidence=_m03_e1.evidence_id),),
)
_m03 = _scenario(
    "M-03",
    "train",
    "expiry_and_staleness",
    "Charter §12 M-03",
    ("INV-06", "INV-07", "INV-09", "INV-15", "INV-20", "INV-21"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "M-03/post-expiry",
            _m03_state,
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_m03_e1.evidence_id, EvidenceStatus.EXPIRED),),
                verdict_bases=frozenset(),
                history_event_types=("AdvanceClock",),
            ),
            "Expired evidence is not exposed as support for a current deployment or verdict.",
        ),
    ),
    assumptions=("Clock-trigger execution remains outside the bootstrap event kernel.",),
)


# M-04 — independent failure basis survives an unrelated revocation.
_m04_e1 = _e("EV-M04-F", "F", dependencies=("DEP-M04",))
_m04_e2 = _e("EV-M04-A", "A")
_m04_e3 = _e("EV-M04-B", "B")
_m04_e4 = _e("EV-M04-D", "D")
_m04_b1 = _b("BASIS-M04-F", BasisKind.VERDICT, "fail", _m04_e1.evidence_id)
_m04_b2 = _b(
    "BASIS-M04-ABD",
    BasisKind.VERDICT,
    "fail",
    _m04_e2.evidence_id,
    _m04_e3.evidence_id,
    _m04_e4.evidence_id,
)
_m04_before = ControlState(
    control_id="CTRL-M04",
    assurance=Assurance.FAIL,
    evidence=(_m04_e1, _m04_e2, _m04_e3, _m04_e4),
    bases=(_m04_b1, _m04_b2),
    current_verdict_basis_ids=frozenset({_m04_b1.basis_id, _m04_b2.basis_id}),
)
_m04 = _scenario(
    "M-04",
    "train",
    "independent_failure_preservation",
    "Charter §12 M-04",
    ("INV-11", "INV-14", "INV-16", "INV-21", "SYM-01"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-04/dependency-change",
            _m04_before,
            DependencyChange("DEP-M04", "apparentlyFavourable"),
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=((_m04_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                verdict_bases=frozenset({_m04_b2.basis_id}),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m04_e1.evidence_id}),
            expected_surviving_bases=frozenset({_m04_b2.basis_id}),
            required_trace_rules=frozenset({"INV-11", "INV-14", "INV-16", "SYM-01"}),
        ),
    ),
    forbidden=("apply whole-record staleness while an independent fail basis survives",),
)


# M-05 — an established verdict with no surviving basis becomes stale.
_m05_e1 = _e("EV-M05-D", "D", dependencies=("DEP-M05",))
_m05_e2 = _e("EV-M05-A", "A")
_m05_e3 = _e("EV-M05-B", "B")
_m05_b1 = _b(
    "BASIS-M05-FAIL",
    BasisKind.VERDICT,
    "fail",
    _m05_e1.evidence_id,
    _m05_e2.evidence_id,
    _m05_e3.evidence_id,
)
_m05_before = ControlState(
    control_id="CTRL-M05",
    assurance=Assurance.FAIL,
    evidence=(_m05_e1, _m05_e2, _m05_e3),
    bases=(_m05_b1,),
    current_verdict_basis_ids=frozenset({_m05_b1.basis_id}),
)
_m05 = _scenario(
    "M-05",
    "train",
    "unsupported_historical_verdict",
    "Charter §12 M-05",
    ("INV-07", "INV-09", "INV-13", "INV-15"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-05/dependency-change",
            _m05_before,
            DependencyChange("DEP-M05", "apparentlyUnfavourable"),
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_m05_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                verdict_bases=frozenset(),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m05_e1.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-13", "INV-15"}),
        ),
    ),
    forbidden=("replace an established fail verdict with unverified",),
)


# M-06 — disjunctive alternative basis survives.
_m06_e1 = _e("EV-M06-001", "D", dependencies=("DEP-M06",))
_m06_e2 = _e("EV-M06-002", "D", dependencies=("DEP-M06-INDEPENDENT",))
_m06_b1 = _b("BASIS-M06-01", BasisKind.VERDICT, "fail", _m06_e1.evidence_id)
_m06_b2 = _b("BASIS-M06-02", BasisKind.VERDICT, "fail", _m06_e2.evidence_id)
_m06_before = ControlState(
    control_id="CTRL-M06",
    assurance=Assurance.FAIL,
    evidence=(_m06_e1, _m06_e2),
    bases=(_m06_b1, _m06_b2),
    current_verdict_basis_ids=frozenset({_m06_b1.basis_id, _m06_b2.basis_id}),
)
_m06 = _scenario(
    "M-06",
    "train",
    "alternative_basis",
    "Charter §12 M-06",
    ("INV-11", "INV-14", "INV-16"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-06/dependency-change",
            _m06_before,
            DependencyChange("DEP-M06", "apparentlyUnfavourable"),
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_m06_e1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m06_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m06_b2.basis_id}),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m06_e1.evidence_id}),
            expected_surviving_bases=frozenset({_m06_b2.basis_id}),
            required_trace_rules=frozenset({"INV-11", "INV-14", "INV-16"}),
        ),
    ),
)


# M-07 — revoking pass support does not manufacture fail.
_m07_e1 = _e("EV-M07-PASS", "D", dependencies=("DEP-M07",))
_m07_e2 = _e("EV-M07-ADVERSE", "F", outcome="apparentlyAdverse")
_m07_b1 = _b("BASIS-M07-PASS", BasisKind.VERDICT, "pass", _m07_e1.evidence_id)
_m07_before = ControlState(
    control_id="CTRL-M07",
    assurance=Assurance.PASS,
    evidence=(_m07_e1, _m07_e2),
    bases=(_m07_b1,),
    current_verdict_basis_ids=frozenset({_m07_b1.basis_id}),
)
_m07 = _scenario(
    "M-07",
    "train",
    "no_replacement_verdict",
    "Charter §12 M-07",
    ("INV-09", "INV-12", "INV-13", "INV-15"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-07/dependency-change",
            _m07_before,
            DependencyChange("DEP-M07", "apparentlyUnfavourable"),
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=(
                    (_m07_e1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m07_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset(),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m07_e1.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-12", "INV-13", "INV-15"}),
        ),
    ),
    forbidden=("automatically replace pass with fail",),
)


# M-08 — issuing S0 evidence does not restore S1/D claims.
_m08_old_s1 = _e("EV-M08-S1-OLD", "S1", status=EvidenceStatus.INVALIDATED)
_m08_old_d = _e("EV-M08-D-OLD", "D", status=EvidenceStatus.INVALIDATED)
_m08_new_s0 = _e("EV-M08-S0-NEW", "S0")
_m08_before = ControlState(
    control_id="CTRL-M08",
    assurance=Assurance.STALE,
    evidence=(_m08_old_s1, _m08_old_d),
    history=(AuditEvent.create("InvalidateEvidence", evidence_id=_m08_old_s1.evidence_id),),
)
_m08_event = Reassess(new_evidence=(_m08_new_s0,), new_bases=())
_m08 = _scenario(
    "M-08",
    "train",
    "level_preserving_recovery",
    "Charter §12 M-08",
    ("INV-17", "INV-18", "G-INV-10"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-08/rebase-s0",
            _m08_before,
            _m08_event,
            _expect(
                source_state=SourceState.UNKNOWN,
                assurance=Assurance.STALE,
                evidence_statuses=(
                    (_m08_old_s1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m08_old_d.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m08_new_s0.evidence_id, EvidenceStatus.CURRENT),
                ),
                source_bases=frozenset(),
                verdict_bases=frozenset(),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-18", "G-INV-10"}),
        ),
    ),
    forbidden=("restore connected or pass from S0 evidence alone",),
)


# M-09 — governed restoration uses new evidence and basis identities.
_m09_old = _e("EV-M09-OLD", "S1", status=EvidenceStatus.INVALIDATED)
_m09_old_basis = _b("BASIS-M09-OLD", BasisKind.SOURCE, "connected", _m09_old.evidence_id)
_m09_new = _e("EV-M09-NEW", "S1")
_m09_new_basis = _b("BASIS-M09-NEW", BasisKind.SOURCE, "connected", _m09_new.evidence_id)
_m09_before = ControlState(
    control_id="CTRL-M09",
    evidence=(_m09_old,),
    bases=(_m09_old_basis,),
    history=(AuditEvent.create("InvalidateEvidence", evidence_id=_m09_old.evidence_id),),
)
_m09_event = Reassess(
    new_evidence=(_m09_new,),
    new_bases=(_m09_new_basis,),
    source_state=SourceState.CONNECTED,
)
_m09 = _scenario(
    "M-09",
    "train",
    "governed_source_restoration",
    "Charter §12 M-09",
    ("INV-05", "INV-18", "G-INV-09", "G-INV-10"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-09/reassess-source",
            _m09_before,
            _m09_event,
            _expect(
                source_state=SourceState.CONNECTED,
                evidence_statuses=(
                    (_m09_old.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m09_new.evidence_id, EvidenceStatus.CURRENT),
                ),
                source_bases=frozenset({_m09_new_basis.basis_id}),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_m09_new_basis.basis_id}),
            required_trace_rules=frozenset({"INV-18", "G-INV-09", "G-INV-10"}),
        ),
    ),
    forbidden=("reactivate the invalidated evidence identity",),
)


# M-10 — one shared event has per-control impact and survival results.
_m10_a_e = _e("EV-M10-A", "D", dependencies=("DEP-M10-SHARED",))
_m10_a_b = _b("BASIS-M10-A", BasisKind.VERDICT, "fail", _m10_a_e.evidence_id)
_m10_a = ControlState(
    control_id="CTRL-M10-A",
    assurance=Assurance.FAIL,
    evidence=(_m10_a_e,),
    bases=(_m10_a_b,),
    current_verdict_basis_ids=frozenset({_m10_a_b.basis_id}),
)
_m10_b_e1 = _e("EV-M10-B-SHARED", "D", dependencies=("DEP-M10-SHARED",))
_m10_b_e2 = _e("EV-M10-B-INDEPENDENT", "D", dependencies=("DEP-M10-OTHER",))
_m10_b_b1 = _b("BASIS-M10-B-SHARED", BasisKind.VERDICT, "fail", _m10_b_e1.evidence_id)
_m10_b_b2 = _b("BASIS-M10-B-INDEPENDENT", BasisKind.VERDICT, "fail", _m10_b_e2.evidence_id)
_m10_b = ControlState(
    control_id="CTRL-M10-B",
    assurance=Assurance.FAIL,
    evidence=(_m10_b_e1, _m10_b_e2),
    bases=(_m10_b_b1, _m10_b_b2),
    current_verdict_basis_ids=frozenset({_m10_b_b1.basis_id, _m10_b_b2.basis_id}),
)
_m10_c_e = _e("EV-M10-C", "D", dependencies=("DEP-M10-OTHER",))
_m10_c_b = _b("BASIS-M10-C", BasisKind.VERDICT, "pass", _m10_c_e.evidence_id)
_m10_c = ControlState(
    control_id="CTRL-M10-C",
    assurance=Assurance.PASS,
    evidence=(_m10_c_e,),
    bases=(_m10_c_b,),
    current_verdict_basis_ids=frozenset({_m10_c_b.basis_id}),
)
_m10_event = DependencyChange("DEP-M10-SHARED", "apparentlyUnfavourable")
_m10 = _scenario(
    "M-10",
    "train",
    "dependency_scoped_multi_control",
    "Charter §12 M-10 and README Layer 2",
    ("INV-11", "INV-14", "INV-15", "INV-16"),
    ScenarioMode.MULTI_CONTROL,
    (
        TransitionCase(
            "M-10/control-a",
            _m10_a,
            _m10_event,
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_m10_a_e.evidence_id, EvidenceStatus.INVALIDATED),),
                verdict_bases=frozenset(),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m10_a_e.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-11", "INV-15"}),
        ),
        TransitionCase(
            "M-10/control-b",
            _m10_b,
            _m10_event,
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_m10_b_e1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m10_b_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m10_b_b2.basis_id}),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset({_m10_b_e1.evidence_id}),
            expected_surviving_bases=frozenset({_m10_b_b2.basis_id}),
            required_trace_rules=frozenset({"INV-11", "INV-14", "INV-16"}),
        ),
        TransitionCase(
            "M-10/control-c",
            _m10_c,
            _m10_event,
            _expect(
                assurance=Assurance.PASS,
                evidence_statuses=((_m10_c_e.evidence_id, EvidenceStatus.CURRENT),),
                verdict_bases=frozenset({_m10_c_b.basis_id}),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_m10_c_b.basis_id}),
            required_trace_rules=frozenset({"INV-14", "INV-16"}),
        ),
    ),
    forbidden=("mark every control stale merely because the event is shared",),
)


# M-11 — both serializable action orders preserve support invariants.
_m11_e1 = _e("EV-M11-OLD", "D", dependencies=("DEP-M11",))
_m11_b1 = _b("BASIS-M11-OLD", BasisKind.VERDICT, "fail", _m11_e1.evidence_id)
_m11_initial = ControlState(
    control_id="CTRL-M11",
    assurance=Assurance.FAIL,
    evidence=(_m11_e1,),
    bases=(_m11_b1,),
    current_verdict_basis_ids=frozenset({_m11_b1.basis_id}),
    history=(AuditEvent.create("IssueEvidence", evidence_id=_m11_e1.evidence_id),),
)
_m11_dep = DependencyChange("DEP-M11", "apparentlyUnfavourable")
_m11_e2 = _e("EV-M11-NEW", "D")
_m11_b2 = _b("BASIS-M11-NEW", BasisKind.VERDICT, "fail", _m11_e2.evidence_id)
_m11_reassess = Reassess(
    new_evidence=(_m11_e2,),
    new_bases=(_m11_b2,),
    assurance=Assurance.FAIL,
)
_m11_after_dep = replace(
    _m11_initial,
    assurance=Assurance.STALE,
    evidence=(replace(_m11_e1, status=EvidenceStatus.INVALIDATED),),
    current_verdict_basis_ids=frozenset(),
    history=(
        *_m11_initial.history,
        AuditEvent.create(
            "DependencyChange",
            dependency_id="DEP-M11",
            apparent_direction="apparentlyUnfavourable",
        ),
    ),
)
_m11_after_reassess = replace(
    _m11_initial,
    evidence=(*_m11_initial.evidence, _m11_e2),
    bases=(*_m11_initial.bases, _m11_b2),
    current_verdict_basis_ids=frozenset({_m11_b1.basis_id, _m11_b2.basis_id}),
    history=(
        *_m11_initial.history,
        AuditEvent.create(
            "Reassess",
            authority="I3",
            evidence_ids=_m11_e2.evidence_id,
            basis_ids=_m11_b2.basis_id,
        ),
    ),
)
_m11 = _scenario(
    "M-11",
    "train",
    "atomic_interleavings",
    "Charter §12 M-11 and README Layer 2",
    ("INV-03", "INV-07", "INV-18", "INV-19", "INV-20"),
    ScenarioMode.SEQUENCE,
    (
        TransitionCase(
            "M-11/order-a/1-dependency",
            _m11_initial,
            _m11_dep,
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_m11_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                verdict_bases=frozenset(),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset({_m11_e1.evidence_id}),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-13", "INV-15"}),
        ),
        TransitionCase(
            "M-11/order-a/2-reassess",
            _m11_after_dep,
            _m11_reassess,
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_m11_e1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m11_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m11_b2.basis_id}),
                history_length=3,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_m11_b2.basis_id}),
            required_trace_rules=frozenset({"INV-18", "INV-19", "G-INV-10"}),
        ),
        TransitionCase(
            "M-11/order-b/1-reassess",
            _m11_initial,
            _m11_reassess,
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_m11_e1.evidence_id, EvidenceStatus.CURRENT),
                    (_m11_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m11_b1.basis_id, _m11_b2.basis_id}),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_m11_b1.basis_id, _m11_b2.basis_id}),
            required_trace_rules=frozenset({"INV-18", "INV-19", "G-INV-10"}),
        ),
        TransitionCase(
            "M-11/order-b/2-dependency",
            _m11_after_reassess,
            _m11_dep,
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_m11_e1.evidence_id, EvidenceStatus.INVALIDATED),
                    (_m11_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m11_b2.basis_id}),
                history_length=3,
            ),
            expected_invalidated_evidence=frozenset({_m11_e1.evidence_id}),
            expected_surviving_bases=frozenset({_m11_b2.basis_id}),
            required_trace_rules=frozenset({"INV-14", "INV-16"}),
        ),
    ),
    forbidden=("publish an intermediate current verdict supported by invalidated evidence",),
)


# G-01 — evidence issuance alone does not create a verdict.
_g01_e1 = _e("EV-G01-A", "A")
_g01_e2 = _e("EV-G01-B", "B")
_g01_state = ControlState(control_id="CTRL-G01", evidence=(_g01_e1, _g01_e2))
_g01 = _scenario(
    "G-01",
    "train",
    "evidence_is_not_verdict",
    "README Layer 3B workflow 1",
    ("INV-07", "G-INV-07", "A-07"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "G-01/no-basis",
            _g01_state,
            _expect(
                assurance=Assurance.UNVERIFIED,
                evidence_statuses=(
                    (_g01_e1.evidence_id, EvidenceStatus.CURRENT),
                    (_g01_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset(),
            ),
            "Current evidence without an approved verdict basis remains unverified.",
        ),
    ),
    forbidden=("infer pass from evidence presence alone",),
)


# G-02 — verdict restoration creates new immutable identities.
_g02_old_e = _e("EV-G02-OLD", "D", status=EvidenceStatus.INVALIDATED)
_g02_old_b = _b("BASIS-G02-OLD", BasisKind.VERDICT, "fail", _g02_old_e.evidence_id)
_g02_new_e = _e("EV-G02-NEW", "D", outcome="demonstratesFailure")
_g02_new_b = _b("BASIS-G02-NEW", BasisKind.VERDICT, "fail", _g02_new_e.evidence_id)
_g02_before = ControlState(
    control_id="CTRL-G02",
    assurance=Assurance.STALE,
    evidence=(_g02_old_e,),
    bases=(_g02_old_b,),
    history=(AuditEvent.create("InvalidateEvidence", evidence_id=_g02_old_e.evidence_id),),
)
_g02_event = Reassess(
    new_evidence=(_g02_new_e,),
    new_bases=(_g02_new_b,),
    assurance=Assurance.FAIL,
)
_g02 = _scenario(
    "G-02",
    "train",
    "new_identity_restoration",
    "README Layer 3B workflow 2",
    ("INV-18", "G-INV-06", "G-INV-08", "G-INV-09", "G-INV-10", "G-INV-11"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "G-02/reassess-verdict",
            _g02_before,
            _g02_event,
            _expect(
                assurance=Assurance.FAIL,
                evidence_statuses=(
                    (_g02_old_e.evidence_id, EvidenceStatus.INVALIDATED),
                    (_g02_new_e.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_g02_new_b.basis_id}),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_g02_new_b.basis_id}),
            required_trace_rules=frozenset({"INV-18", "G-INV-06", "G-INV-10", "G-INV-11"}),
        ),
    ),
    forbidden=("overwrite or reactivate the old evidence and basis identities",),
)


# C-01 — a fresh adverse outcome is still current evidence.
_c01_e1 = _e("EV-C01-FAIL", "D", outcome="demonstratesFailure")
_c01_state = ControlState(control_id="CTRL-C01", evidence=(_c01_e1,))
_c01 = _scenario(
    "C-01",
    "train",
    "fresh_adverse_evidence",
    "Charter §7.2 and INV-21",
    ("INV-07", "INV-21"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "C-01/fresh-adverse",
            _c01_state,
            _expect(
                assurance=Assurance.UNVERIFIED,
                evidence_statuses=((_c01_e1.evidence_id, EvidenceStatus.CURRENT),),
                evidence_outcomes=((_c01_e1.evidence_id, "demonstratesFailure"),),
                verdict_bases=frozenset(),
            ),
            "Freshness, substantive outcome, and collection failure are distinct.",
        ),
    ),
    forbidden=("map an adverse outcome to evidence-production failure",),
)


# M-12 — expiry is scoped and an independent same-verdict basis preserves pass.
_m12_e1 = _e("EV-M12-EXP", "D", status=EvidenceStatus.EXPIRED)
_m12_e2 = _e("EV-M12-LIVE", "D")
_m12_b1 = _b("BASIS-M12-EXP", BasisKind.VERDICT, "pass", _m12_e1.evidence_id)
_m12_b2 = _b("BASIS-M12-LIVE", BasisKind.VERDICT, "pass", _m12_e2.evidence_id)
_m12_state = ControlState(
    control_id="CTRL-M12",
    assurance=Assurance.PASS,
    evidence=(_m12_e1, _m12_e2),
    bases=(_m12_b1, _m12_b2),
    current_verdict_basis_ids=frozenset({_m12_b2.basis_id}),
    history=(AuditEvent.create("AdvanceClock", expired_evidence=_m12_e1.evidence_id),),
)
_m12 = _scenario(
    "M-12",
    "validation",
    "age_trigger_symmetry",
    "Charter §12 M-12",
    ("INV-11", "INV-14", "INV-15", "INV-20", "INV-21"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "M-12/post-expiry-with-survivor",
            _m12_state,
            _expect(
                assurance=Assurance.PASS,
                evidence_statuses=(
                    (_m12_e1.evidence_id, EvidenceStatus.EXPIRED),
                    (_m12_e2.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset({_m12_b2.basis_id}),
                history_event_types=("AdvanceClock",),
            ),
            "Expiry removes only the expired path; a same-verdict independent basis survives.",
        ),
    ),
    assumptions=("Clock-trigger execution remains outside the bootstrap event kernel.",),
)


# M-13 — a retired obligation stays assuranceNA after historical dependency processing.
_m13_e1 = _e(
    "EV-M13-HIST",
    "D",
    dependencies=("DEP-M13",),
    status=EvidenceStatus.INVALIDATED,
)
_m13_before = ControlState(
    control_id="CTRL-M13",
    obligation=ObligationStatus.RETIRED,
    assurance=Assurance.NA,
    evidence=(_m13_e1,),
    history=(AuditEvent.create("RetireControl", evidence_id="EV-M13-RETIRE"),),
)
_m13 = _scenario(
    "M-13",
    "validation",
    "non_current_obligation",
    "Charter §12 M-13",
    ("INV-04", "INV-12"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-13/historical-dependency-change",
            _m13_before,
            DependencyChange("DEP-M13", "apparentlyUnfavourable"),
            _expect(
                obligation=ObligationStatus.RETIRED,
                source_state=SourceState.UNKNOWN,
                assurance=Assurance.NA,
                evidence_statuses=((_m13_e1.evidence_id, EvidenceStatus.INVALIDATED),),
                source_bases=frozenset(),
                verdict_bases=frozenset(),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-12"}),
        ),
    ),
    forbidden=("create stale or another substantive verdict for a retired obligation",),
)


# M-14 — canonical state after profile strengthening.
_m14_e1 = _e("EV-M14-A", "A")
_m14_b1 = _b("BASIS-M14-PASS-A", BasisKind.VERDICT, "pass", _m14_e1.evidence_id)
_m14_state = ControlState(
    control_id="CTRL-M14",
    assurance=Assurance.STALE,
    evidence=(_m14_e1,),
    bases=(_m14_b1,),
    history=(AuditEvent.create("ChangeRequiredProfile", profile="A,B"),),
)
_m14 = _scenario(
    "M-14",
    "validation",
    "profile_strengthening",
    "Charter §12 M-14 and README Layer 3B workflow 3",
    ("INV-08", "INV-09", "G-INV-12", "G-INV-14"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "M-14/post-profile-strengthening",
            _m14_state,
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_m14_e1.evidence_id, EvidenceStatus.CURRENT),),
                basis_claims=((_m14_b1.basis_id, "pass"),),
                verdict_bases=frozenset(),
                history_event_types=("ChangeRequiredProfile",),
            ),
            "The historical A-only pass basis is retained but is not current under profile A,B.",
        ),
    ),
    assumptions=(
        "Required-profile structure is represented in the audit event, not ControlState v0.1.",
    ),
)


# G-04 — governed retirement changes the current view and retains history.
_g04_e1 = _e("EV-G04-CURRENT", "D")
_g04_b1 = _b("BASIS-G04-PASS", BasisKind.VERDICT, "pass", _g04_e1.evidence_id)
_g04_before = ControlState(
    control_id="CTRL-G04",
    assurance=Assurance.PASS,
    evidence=(_g04_e1,),
    bases=(_g04_b1,),
    current_verdict_basis_ids=frozenset({_g04_b1.basis_id}),
    history=(AuditEvent.create("EstablishBasis", basis_id=_g04_b1.basis_id),),
)
_g04_retire_evidence = _e("EV-G04-RETIRE", "lifecycle", outcome="retirementAuthorized")
_g04 = _scenario(
    "G-04",
    "validation",
    "governed_retirement",
    "README Layer 3B workflow 4",
    ("INV-04", "INV-19", "G-INV-11", "G-INV-12", "G-INV-13"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "G-04/retire",
            _g04_before,
            RetireControl(_g04_retire_evidence),
            _expect(
                obligation=ObligationStatus.RETIRED,
                source_state=SourceState.UNKNOWN,
                assurance=Assurance.NA,
                evidence_statuses=(
                    (_g04_e1.evidence_id, EvidenceStatus.CURRENT),
                    (_g04_retire_evidence.evidence_id, EvidenceStatus.CURRENT),
                ),
                verdict_bases=frozenset(),
                history_length=2,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset(),
            required_trace_rules=frozenset({"INV-04", "INV-19", "G-INV-13"}),
        ),
    ),
    forbidden=("delete historical evidence or bases during retirement",),
)


# M-15 — internally valid declared-graph result with an explicit external-truth boundary.
_m15_e2 = _e("EV-M15-DECLARED-INDEPENDENT", "D", dependencies=("DEP-M15-OTHER",))
_m15_b2 = _b("BASIS-M15-PASS", BasisKind.VERDICT, "pass", _m15_e2.evidence_id)
_m15_before = ControlState(
    control_id="CTRL-M15",
    assurance=Assurance.PASS,
    evidence=(_m15_e2,),
    bases=(_m15_b2,),
    current_verdict_basis_ids=frozenset({_m15_b2.basis_id}),
)
_m15 = _scenario(
    "M-15",
    "test",
    "assumption_boundary",
    "Charter §12 M-15 and Layer 3A results",
    ("A-04", "INV-11", "REAL-01", "REAL-02"),
    ScenarioMode.TRANSITION,
    (
        TransitionCase(
            "M-15/declared-graph-execution",
            _m15_before,
            DependencyChange("DEP-M15-REAL", "apparentlyUnfavourable"),
            _expect(
                assurance=Assurance.PASS,
                evidence_statuses=((_m15_e2.evidence_id, EvidenceStatus.CURRENT),),
                verdict_bases=frozenset({_m15_b2.basis_id}),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_m15_b2.basis_id}),
            required_trace_rules=frozenset({"INV-11", "INV-14", "INV-16"}),
        ),
    ),
    forbidden=("treat internal invariant success as proof of real dependency completeness",),
    assumptions=(
        "A-04 is false in the external oracle: EV-M15-DECLARED-INDEPENDENT "
        "really depends on DEP-M15-REAL.",
    ),
)


# L-01 — the liveness contract permits explicit success or explicit failure, not guaranteed pass.
_l01_success_e = _e("EV-L01-SUCCESS", "D")
_l01_success_b = _b("BASIS-L01-SUCCESS", BasisKind.VERDICT, "pass", _l01_success_e.evidence_id)
_l01_success = ControlState(
    control_id="CTRL-L01",
    assurance=Assurance.PASS,
    evidence=(_l01_success_e,),
    bases=(_l01_success_b,),
    current_verdict_basis_ids=frozenset({_l01_success_b.basis_id}),
    history=(
        AuditEvent.create("RequestReassessment", request_id="REQ-L01"),
        AuditEvent.create("Heartbeat", request_id="REQ-L01"),
        AuditEvent.create("CompleteReassessment", request_id="REQ-L01", outcome="success"),
    ),
)
_l01_failed_old = _e("EV-L01-OLD", "D", status=EvidenceStatus.INVALIDATED)
_l01_failure = ControlState(
    control_id="CTRL-L01",
    assurance=Assurance.STALE,
    evidence=(_l01_failed_old,),
    history=(
        AuditEvent.create("RequestReassessment", request_id="REQ-L01"),
        AuditEvent.create("Heartbeat", request_id="REQ-L01"),
        AuditEvent.create("CompleteReassessment", request_id="REQ-L01", outcome="failure"),
    ),
)
_l01 = _scenario(
    "L-01",
    "test",
    "conditional_liveness",
    "Charter LIVE-01 and README temporal structure",
    ("LIVE-01", "INV-07", "INV-18", "INV-19"),
    ScenarioMode.OBSERVATION,
    (
        ObservationCase(
            "L-01/success-outcome",
            _l01_success,
            _expect(
                assurance=Assurance.PASS,
                evidence_statuses=((_l01_success_e.evidence_id, EvidenceStatus.CURRENT),),
                verdict_bases=frozenset({_l01_success_b.basis_id}),
                history_event_types=(
                    "RequestReassessment",
                    "Heartbeat",
                    "CompleteReassessment",
                ),
            ),
            "A fair, continuously enabled request may complete with a new current basis.",
        ),
        ObservationCase(
            "L-01/failure-outcome",
            _l01_failure,
            _expect(
                assurance=Assurance.STALE,
                evidence_statuses=((_l01_failed_old.evidence_id, EvidenceStatus.INVALIDATED),),
                verdict_bases=frozenset(),
                history_event_types=(
                    "RequestReassessment",
                    "Heartbeat",
                    "CompleteReassessment",
                ),
            ),
            "Explicit failed reassessment completes the request while preserving stale.",
        ),
    ),
    forbidden=("interpret weak fairness as a guarantee of pass",),
    assumptions=("The request remains continuously enabled and completion is weakly fair.",),
)


# H-01 — corrected reassessment is accepted; history replacement is rejected.
_h01_old_e = _e("EV-H01-OLD", "S1", status=EvidenceStatus.INVALIDATED)
_h01_old_b = _b("BASIS-H01-OLD", BasisKind.SOURCE, "connected", _h01_old_e.evidence_id)
_h01_new_e = _e("EV-H01-NEW", "S1")
_h01_new_b = _b("BASIS-H01-NEW", BasisKind.SOURCE, "connected", _h01_new_e.evidence_id)
_h01_before = ControlState(
    control_id="CTRL-H01",
    assurance=Assurance.STALE,
    evidence=(_h01_old_e,),
    bases=(_h01_old_b,),
    history=(
        AuditEvent.create("IssueEvidence", evidence_id=_h01_old_e.evidence_id),
        AuditEvent.create("EstablishBasis", basis_id=_h01_old_b.basis_id),
        AuditEvent.create("InvalidateEvidence", evidence_id=_h01_old_e.evidence_id),
    ),
)
_h01_event = Reassess(
    new_evidence=(_h01_new_e,),
    new_bases=(_h01_new_b,),
    source_state=SourceState.CONNECTED,
)
_h01_bad_after = ControlState(
    control_id="CTRL-H01",
    source_state=SourceState.CONNECTED,
    assurance=Assurance.STALE,
    evidence=(_h01_old_e, _h01_new_e),
    bases=(_h01_old_b, _h01_new_b),
    current_source_basis_ids=frozenset({_h01_new_b.basis_id}),
    history=(
        AuditEvent.create("IssueEvidence", evidence_id=_h01_new_e.evidence_id),
        AuditEvent.create("EstablishBasis", basis_id=_h01_new_b.basis_id),
    ),
)
_h01 = _scenario(
    "H-01",
    "test",
    "append_only_history",
    "Charter INV-19 and counterexample policy",
    ("INV-18", "INV-19", "G-INV-06", "G-INV-11"),
    ScenarioMode.REJECTED_TRANSITION,
    (
        TransitionCase(
            "H-01/corrected-reassessment",
            _h01_before,
            _h01_event,
            _expect(
                source_state=SourceState.CONNECTED,
                assurance=Assurance.STALE,
                evidence_statuses=(
                    (_h01_old_e.evidence_id, EvidenceStatus.INVALIDATED),
                    (_h01_new_e.evidence_id, EvidenceStatus.CURRENT),
                ),
                source_bases=frozenset({_h01_new_b.basis_id}),
                history_length=4,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=frozenset({_h01_new_b.basis_id}),
            required_trace_rules=frozenset({"INV-18", "INV-19", "G-INV-06", "G-INV-11"}),
        ),
        RejectedTransitionCase(
            "H-01/history-replacement",
            _h01_before,
            _h01_bad_after,
            frozenset({"INV-19"}),
            _h01_event,
        ),
    ),
    forbidden=("replace the existing audit history with only the new reassessment records",),
)


SCENARIOS: dict[str, ScenarioSpec] = {
    spec.scenario_id: spec
    for spec in (
        _m01,
        _m02,
        _m03,
        _m04,
        _m05,
        _m06,
        _m07,
        _m08,
        _m09,
        _m10,
        _m11,
        _g01,
        _g02,
        _c01,
        _m12,
        _m13,
        _m14,
        _g04,
        _m15,
        _l01,
        _h01,
    )
}

if len(SCENARIOS) != 21:
    raise RuntimeError(f"expected 21 v0.1 scenarios, found {len(SCENARIOS)}")
