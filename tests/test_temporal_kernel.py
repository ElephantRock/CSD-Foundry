from dataclasses import replace

import pytest

from csd_foundry.kernel.events import AdvanceClock, Reassess, RequestReassessment
from csd_foundry.kernel.models import (
    Assurance,
    EvidenceStatus,
    RequestStatus,
    SourceState,
)
from csd_foundry.kernel.oracle import CsdOracle, OracleRejected
from csd_foundry.synthesis.temporal_mutations import evaluate_release as evaluate_mutations
from csd_foundry.temporal.v0_3 import base_state, validate_release


def test_temporal_release_is_deterministic_and_complete() -> None:
    report = validate_release("v0.3")

    assert report.success, report.to_dict()
    assert report.total == 10
    assert report.accepted == 10
    assert report.failed == 0
    assert report.replay_identical == 10
    assert all(scenario.trajectory for scenario in report.scenarios)
    assert sum(len(scenario.trajectory) for scenario in report.scenarios) == 16


def test_temporal_mutation_policy_kills_every_probe() -> None:
    report = evaluate_mutations("v0.3")

    assert report.success, report.to_dict()
    assert report.total == 11
    assert report.killed == 11
    assert report.escaped == 0
    assert report.invalid_canonical == 0
    assert {"T-INV-01", "T-INV-02", "R-INV-03"} <= set(report.covered_invariants)


def test_reassessment_closes_only_named_pending_request() -> None:
    oracle = CsdOracle()
    requested = oracle.apply(
        base_state(),
        RequestReassessment("REQ-1", "first", due_at=8),
    ).after
    requested = oracle.apply(
        requested,
        RequestReassessment("REQ-2", "second", due_at=9),
    ).after

    after = oracle.apply(
        requested,
        Reassess((), (), close_request_ids=("REQ-1",)),
    ).after

    assert after.requests_by_id()["REQ-1"].status is RequestStatus.CLOSED
    assert after.requests_by_id()["REQ-1"].closed_at == after.logical_time
    assert after.requests_by_id()["REQ-2"].status is RequestStatus.PENDING


def test_clock_rejects_backward_time() -> None:
    state = base_state(logical_time=5)
    with pytest.raises(ValueError, match="cannot move backward"):
        CsdOracle().apply(state, AdvanceClock(4))


def test_invalid_current_evidence_past_expiry_is_rejected() -> None:
    state = base_state(source_expires_at=5, logical_time=5)
    assert state.evidence_by_id()["EV-SOURCE"].status is EvidenceStatus.CURRENT

    with pytest.raises(OracleRejected, match="remained current after expiry"):
        CsdOracle().apply(state, AdvanceClock(5))


def test_request_cannot_promote_stale_assurance() -> None:
    oracle = CsdOracle()
    stale = replace(
        base_state(),
        assurance=Assurance.STALE,
        current_verdict_basis_ids=frozenset(),
    )
    after = oracle.apply(
        stale,
        RequestReassessment("REQ-PRESERVE", "preserve control", due_at=7),
    ).after

    assert after.assurance is Assurance.STALE
    assert not after.current_verdict_basis_ids


def test_legacy_expired_evidence_without_timestamp_remains_valid() -> None:
    oracle = CsdOracle()
    original = base_state()
    legacy = replace(
        original,
        evidence=tuple(
            replace(item, status=EvidenceStatus.EXPIRED)
            if item.evidence_id == "EV-SOURCE"
            else item
            for item in original.evidence
        ),
        source_state=SourceState.UNKNOWN,
        current_source_basis_ids=frozenset(),
    )

    after = oracle.apply(
        legacy,
        RequestReassessment("REQ-LEGACY", "legacy expiry control", due_at=5),
    ).after

    assert after.evidence_by_id()["EV-SOURCE"].status is EvidenceStatus.EXPIRED
    assert after.requests_by_id()["REQ-LEGACY"].status is RequestStatus.PENDING
