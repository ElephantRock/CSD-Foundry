"""Canonical temporal and governance scenarios for kernel release v0.3."""

from __future__ import annotations

from dataclasses import dataclass, replace

from csd_foundry.kernel.events import (
    AdvanceClock,
    ProfileChange,
    RecordHeartbeat,
    RequestReassessment,
)
from csd_foundry.kernel.models import (
    Assurance,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    HeartbeatState,
    RequestStatus,
    SourceState,
)
from csd_foundry.kernel.oracle import CsdOracle, OracleResult


@dataclass(frozen=True, slots=True)
class TemporalScenarioResult:
    scenario_id: str
    accepted: bool
    details: tuple[str, ...] = ()
    trajectory: tuple[OracleResult, ...] = ()


@dataclass(frozen=True, slots=True)
class TemporalReport:
    release: str
    total: int
    accepted: int
    failed: int
    replay_identical: int
    scenarios: tuple[TemporalScenarioResult, ...]

    @property
    def success(self) -> bool:
        return self.total > 0 and self.failed == 0 and self.replay_identical == self.total

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "total": self.total,
            "accepted": self.accepted,
            "failed": self.failed,
            "replay_identical": self.replay_identical,
            "scenarios": [
                {
                    "scenario_id": item.scenario_id,
                    "accepted": item.accepted,
                    "details": list(item.details),
                    "trajectory_steps": len(item.trajectory),
                }
                for item in self.scenarios
            ],
        }


def base_state(
    *,
    source_expires_at: int | None = None,
    verdict_expires_at: int | None = None,
    logical_time: int = 0,
    profile_id: str | None = None,
    profile_version: int | None = None,
    heartbeat: HeartbeatState | None = None,
) -> ControlState:
    source_evidence = Evidence(
        "EV-SOURCE",
        "source",
        expires_at=source_expires_at,
        profile_id=profile_id,
        profile_version=profile_version,
    )
    verdict_evidence = Evidence(
        "EV-VERDICT",
        "verdict",
        expires_at=verdict_expires_at,
    )
    source_basis = Basis(
        "BASIS-SOURCE",
        BasisKind.SOURCE,
        SourceState.CONNECTED.value,
        frozenset({source_evidence.evidence_id}),
    )
    verdict_basis = Basis(
        "BASIS-VERDICT",
        BasisKind.VERDICT,
        Assurance.PASS.value,
        frozenset({verdict_evidence.evidence_id}),
    )
    return ControlState(
        control_id="CTRL-TEMPORAL",
        source_state=SourceState.CONNECTED,
        assurance=Assurance.PASS,
        evidence=(source_evidence, verdict_evidence),
        bases=(source_basis, verdict_basis),
        current_source_basis_ids=frozenset({source_basis.basis_id}),
        current_verdict_basis_ids=frozenset({verdict_basis.basis_id}),
        logical_time=logical_time,
        required_profile_id=profile_id,
        required_profile_version=profile_version,
        heartbeat=heartbeat,
    )


def _result(
    scenario_id: str,
    accepted: bool,
    *details: str,
    trajectory: tuple[OracleResult, ...],
) -> TemporalScenarioResult:
    return TemporalScenarioResult(
        scenario_id=scenario_id,
        accepted=accepted,
        details=tuple(details),
        trajectory=trajectory,
    )


def _t01_expiry_boundary() -> TemporalScenarioResult:
    oracle = CsdOracle()
    state = base_state(source_expires_at=5)
    before_deadline_result = oracle.apply(state, AdvanceClock(4))
    at_deadline_result = oracle.apply(before_deadline_result.after, AdvanceClock(5))
    before_deadline = before_deadline_result.after
    at_deadline = at_deadline_result.after
    accepted = (
        before_deadline.evidence_by_id()["EV-SOURCE"].status is EvidenceStatus.CURRENT
        and at_deadline.evidence_by_id()["EV-SOURCE"].status is EvidenceStatus.EXPIRED
        and at_deadline.logical_time == 5
    )
    return _result(
        "T-01",
        accepted,
        "expiry is exact at the governed deadline",
        trajectory=(before_deadline_result, at_deadline_result),
    )


def _t02_last_source_basis_expires() -> TemporalScenarioResult:
    result = CsdOracle().apply(base_state(source_expires_at=5), AdvanceClock(5))
    after = result.after
    accepted = (
        after.source_state is SourceState.UNKNOWN
        and not after.current_source_basis_ids
        and after.assurance is Assurance.PASS
    )
    return _result(
        "T-02",
        accepted,
        "last source basis expiry demotes source only",
        trajectory=(result,),
    )


def _t03_independent_basis_survives() -> TemporalScenarioResult:
    state = base_state(source_expires_at=5)
    independent_evidence = Evidence("EV-SOURCE-ALT", "source")
    independent_basis = Basis(
        "BASIS-SOURCE-ALT",
        BasisKind.SOURCE,
        SourceState.CONNECTED.value,
        frozenset({independent_evidence.evidence_id}),
    )
    state = replace(
        state,
        evidence=(*state.evidence, independent_evidence),
        bases=(*state.bases, independent_basis),
        current_source_basis_ids=frozenset({"BASIS-SOURCE", independent_basis.basis_id}),
    )
    result = CsdOracle().apply(state, AdvanceClock(5))
    after = result.after
    accepted = (
        after.source_state is SourceState.CONNECTED
        and after.current_source_basis_ids == frozenset({independent_basis.basis_id})
    )
    return _result(
        "T-03",
        accepted,
        "independent source support survives expiry",
        trajectory=(result,),
    )


def _t04_profile_change_is_scoped() -> TemporalScenarioResult:
    state = base_state(profile_id="PROFILE-A", profile_version=1)
    result = CsdOracle().apply(
        state,
        ProfileChange(
            "PROFILE-A",
            2,
            request_id="REQ-PROFILE-A-2",
            request_due_at=10,
        ),
    )
    after = result.after
    evidence = after.evidence_by_id()
    request = after.requests_by_id()["REQ-PROFILE-A-2"]
    accepted = (
        evidence["EV-SOURCE"].status is EvidenceStatus.CURRENT
        and evidence["EV-VERDICT"].status is EvidenceStatus.CURRENT
        and "BASIS-SOURCE" in after.bases_by_id()
        and not after.current_source_basis_ids
        and after.source_state is SourceState.UNKNOWN
        and after.assurance is Assurance.PASS
        and request.status is RequestStatus.PENDING
    )
    return _result(
        "T-04",
        accepted,
        "profile change preserves evidence and removes incompatible current support",
        trajectory=(result,),
    )


def _t05_request_preserves_verdict() -> TemporalScenarioResult:
    state = base_state()
    result = CsdOracle().apply(
        state,
        RequestReassessment("REQ-1", "scheduled review", due_at=8),
    )
    after = result.after
    accepted = (
        after.source_state is state.source_state
        and after.assurance is state.assurance
        and after.current_source_basis_ids == state.current_source_basis_ids
        and after.current_verdict_basis_ids == state.current_verdict_basis_ids
        and after.requests_by_id()["REQ-1"].status is RequestStatus.PENDING
    )
    return _result(
        "T-05",
        accepted,
        "request creation does not manufacture a verdict",
        trajectory=(result,),
    )


def _t06_missed_heartbeat_stales() -> TemporalScenarioResult:
    heartbeat = HeartbeatState(interval=5, last_recorded_at=0, due_at=5)
    result = CsdOracle().apply(
        base_state(heartbeat=heartbeat),
        AdvanceClock(5),
    )
    after = result.after
    accepted = after.assurance is Assurance.STALE and not after.current_verdict_basis_ids
    return _result(
        "T-06",
        accepted,
        "missed heartbeat stales substantive assurance",
        trajectory=(result,),
    )


def _t07_late_heartbeat_does_not_restore() -> TemporalScenarioResult:
    oracle = CsdOracle()
    heartbeat = HeartbeatState(interval=5, last_recorded_at=0, due_at=5)
    stale_result = oracle.apply(base_state(heartbeat=heartbeat), AdvanceClock(5))
    heartbeat_result = oracle.apply(
        stale_result.after,
        RecordHeartbeat(at_time=5, interval=5),
    )
    after = heartbeat_result.after
    accepted = (
        after.assurance is Assurance.STALE
        and not after.current_verdict_basis_ids
        and after.heartbeat is not None
        and after.heartbeat.due_at == 10
    )
    return _result(
        "T-07",
        accepted,
        "late heartbeat cannot retroactively promote assurance",
        trajectory=(stale_result, heartbeat_result),
    )


def _t08_simultaneous_expiry_is_deterministic() -> TemporalScenarioResult:
    state = base_state(source_expires_at=5, verdict_expires_at=5)
    result = CsdOracle().apply(state, AdvanceClock(5))
    accepted = (
        result.trace.invalidated_evidence == ("EV-SOURCE", "EV-VERDICT")
        and result.after.source_state is SourceState.UNKNOWN
        and result.after.assurance is Assurance.STALE
    )
    return _result(
        "T-08",
        accepted,
        "simultaneous expiries have a canonical sorted trace",
        trajectory=(result,),
    )


def _t09_replay_is_identical() -> TemporalScenarioResult:
    state = base_state(source_expires_at=5)
    event = AdvanceClock(5)
    oracle = CsdOracle()
    first = oracle.apply(state, event)
    second = oracle.apply(state, event)
    return _result(
        "T-09",
        first == second,
        "serialized inputs replay identically",
        trajectory=(first, second),
    )


def _t10_independent_events_converge() -> TemporalScenarioResult:
    state = base_state()
    request = RequestReassessment("REQ-COMMUTE", "independent review", due_at=9)
    heartbeat = RecordHeartbeat(at_time=0, interval=5)
    oracle = CsdOracle()

    request_first = oracle.apply(state, request)
    request_then_heartbeat = oracle.apply(request_first.after, heartbeat)
    heartbeat_first = oracle.apply(state, heartbeat)
    heartbeat_then_request = oracle.apply(heartbeat_first.after, request)
    accepted = replace(request_then_heartbeat.after, history=()) == replace(
        heartbeat_then_request.after,
        history=(),
    )
    return _result(
        "T-10",
        accepted,
        "causally independent request and heartbeat events converge substantively",
        trajectory=(
            request_first,
            request_then_heartbeat,
            heartbeat_first,
            heartbeat_then_request,
        ),
    )


def run_scenarios() -> tuple[TemporalScenarioResult, ...]:
    return (
        _t01_expiry_boundary(),
        _t02_last_source_basis_expires(),
        _t03_independent_basis_survives(),
        _t04_profile_change_is_scoped(),
        _t05_request_preserves_verdict(),
        _t06_missed_heartbeat_stales(),
        _t07_late_heartbeat_does_not_restore(),
        _t08_simultaneous_expiry_is_deterministic(),
        _t09_replay_is_identical(),
        _t10_independent_events_converge(),
    )


def validate_release(release: str = "v0.3") -> TemporalReport:
    if release != "v0.3":
        raise ValueError(f"unsupported temporal release: {release}")
    first = run_scenarios()
    second = run_scenarios()
    replay = sum(
        left.trajectory == right.trajectory
        for left, right in zip(first, second, strict=True)
    )
    accepted = sum(item.accepted for item in first)
    return TemporalReport(
        release=release,
        total=len(first),
        accepted=accepted,
        failed=len(first) - accepted,
        replay_identical=replay,
        scenarios=first,
    )
