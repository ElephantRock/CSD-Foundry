from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from csd_foundry.governance.v0_5.admission_validation import build_reference_admission_fixture
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    ClockCompletionReceipt,
    ClockProjectionFailure,
    ContractObject,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.resources import temporal_vectors
from csd_foundry.governance.v0_5.temporal import TemporalHead
from csd_foundry.governance.v0_5.temporal_store import (
    FilesystemTemporalStore,
    InMemoryTemporalStore,
    TemporalStoreConflictError,
)
from csd_foundry.governance.v0_5.temporal_validation import (
    build_reference_coordinator,
    build_reference_validated_event,
    validate_atomic_temporal,
)

_ROOT = Path(__file__).resolve().parents[1]


def test_atomic_temporal_validation_report_passes() -> None:
    report = validate_atomic_temporal()
    assert report.success, report.errors
    assert report.concurrent_claimants == 12
    assert report.concurrent_winners == 1
    assert report.concurrent_losers == 11
    assert report.failure_sequences_unchanged
    assert report.retry_reused_sequence
    assert report.partial_visibility_blocked
    assert report.prepared_completion_recovered
    assert report.incomplete_claim_failed_on_recovery
    assert report.restart_deterministic
    assert report.chain_length == 2
    assert report.release_compilation_invocations == 0

    rendered = report.to_dict()
    vectors = temporal_vectors()
    committed_report = json.loads(
        (_ROOT / "reports/atomic_temporal_v0.5.json").read_text(encoding="utf-8")
    )
    assert rendered == committed_report
    for field_name in (
        "successful_claim_digest",
        "semantic_receipt_digest",
        "completion_receipt_digest",
        "failed_phase_receipt_digests",
        "concurrent_claimants",
        "concurrent_winners",
        "concurrent_losers",
        "chain_length",
        "release_compilation_invocations",
    ):
        assert rendered[field_name] == vectors[field_name]


def test_temporal_boundary_rejects_non_validated_events() -> None:
    admission = build_reference_admission_fixture()
    failure = admission.engine.admit(
        admission.raw_event,
        admission.single_signatures,
        admission.single_policy,
        validated_at_tick=99,
    ).failure
    coordinator = build_reference_coordinator(InMemoryTemporalStore())
    for invalid in (admission.raw_event, failure):
        with pytest.raises(GovernanceContractError) as exc:
            coordinator.build_claim(
                cast(ValidatedEvent, invalid),
                attempt_id="invalid-temporal-input",
                claimant_id="validator",
            )
        assert exc.value.code == "VALIDATION_RESULT_NOT_ACCEPTED"


def test_attempt_ids_cannot_escape_the_store_root(tmp_path: Path) -> None:
    event = build_reference_validated_event()
    store = FilesystemTemporalStore(tmp_path)
    coordinator = build_reference_coordinator(store)
    attempt_id = "a/../../../../csd-temporal-path-escape-sentinel"
    _, result = coordinator.claim(
        event,
        attempt_id=attempt_id,
        claimant_id="validator",
    )
    assert result.acquired
    unsafe_path = store.attempts / attempt_id / "claim.json"
    assert not unsafe_path.exists()
    claim_paths = list(store.attempts.rglob("claim.json"))
    assert len(claim_paths) == 1
    assert claim_paths[0].resolve().is_relative_to(store.attempts.resolve())


def test_conflicting_completion_cannot_rebind_committed_sequence() -> None:
    event = build_reference_validated_event()
    store = InMemoryTemporalStore()
    coordinator = build_reference_coordinator(store)
    genesis = TemporalHead(0, None)
    outcome = coordinator.execute(
        event,
        attempt_id="completion-conflict-base",
        claimant_id="validator",
    )
    assert outcome.completion is not None
    conflicting = cast(
        ClockCompletionReceipt,
        outcome.completion.with_updates(
            completion_policy_digest="sha256:" + "f" * 64,
        ),
    )
    with pytest.raises(TemporalStoreConflictError):
        store.publish_completion(genesis, outcome.claim, conflicting)


def test_release_compilation_inside_tick_fails_closed() -> None:
    event = build_reference_validated_event()
    store = InMemoryTemporalStore()
    coordinator = build_reference_coordinator(
        store,
        release_compilation_invocations=1,
    )
    outcome = coordinator.execute(
        event,
        attempt_id="release-in-tick",
        claimant_id="validator",
    )
    assert outcome.failure is not None
    assert outcome.completion is None
    assert store.read_head() == TemporalHead(0, None)
    assert store.current_snapshot() is None


def test_every_temporal_receipt_field_is_identity_protected() -> None:
    event = build_reference_validated_event()
    success_store = InMemoryTemporalStore()
    success = build_reference_coordinator(success_store).execute(
        event,
        attempt_id="mutation-success",
        claimant_id="validator",
    )
    assert success.semantic_receipt is not None
    assert success.completion is not None

    failure_store = InMemoryTemporalStore()
    failure = build_reference_coordinator(failure_store, fail_phase="DISPOSITION").execute(
        event,
        attempt_id="mutation-failure",
        claimant_id="validator",
    )
    assert failure.failure is not None

    contracts: tuple[ContractObject, ...] = (
        success.claim,
        success.semantic_receipt,
        success.completion,
        failure.failure,
    )
    expected_types: tuple[type[ContractObject], ...] = (
        ClockClaim,
        SemanticProjectionReceipt,
        ClockCompletionReceipt,
        ClockProjectionFailure,
    )
    for contract, contract_type in zip(contracts, expected_types, strict=True):
        value = contract.to_json_value()
        for field_name, original in value.items():
            mutated = dict(value)
            mutated[field_name] = _different_value(original)
            with pytest.raises(GovernanceContractError):
                contract_type.from_json(cast(dict[str, Any], mutated))


def _different_value(value: Any) -> Any:
    if value is None:
        return "sha256:" + "0" * 64
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        if value.startswith("sha256:"):
            replacement = "0" if value[-1] != "0" else "1"
            return value[:-1] + replacement
        return value + "-mutated"
    if type(value) is list:
        return [*value, "sha256:" + "0" * 64]
    if type(value) is dict:
        return {**value, "unexpected": "sha256:" + "0" * 64}
    raise AssertionError(f"unsupported test mutation type: {type(value).__qualname__}")
