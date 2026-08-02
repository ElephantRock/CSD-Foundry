from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from csd_foundry.governance.v0_5.admission import (
    CommittedValidationContext,
    EventAdmissionEngine,
    reconstruct_accepted,
    require_validated_event,
)
from csd_foundry.governance.v0_5.admission_store import (
    AdmissionStoreConflictError,
    FilesystemEventAdmissionStore,
    InMemoryEventAdmissionStore,
)
from csd_foundry.governance.v0_5.admission_validation import (
    ReferenceCommittedContextResolver,
    build_reference_admission_fixture,
    build_signature_set,
    make_signature,
    validate_event_admission,
)
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import RawEvent, ValidatedEvent


def test_event_admission_validation_report_passes() -> None:
    report = validate_event_admission()
    assert report.success, report.errors
    assert len(report.accepted_receipt_digests) == 2
    assert len(report.failure_receipt_digests) == 12
    assert report.reconstructed_acceptance_count == 2
    assert report.restart_deterministic
    assert report.reducer_boundary_enforced


def test_admission_emits_exactly_one_outcome() -> None:
    fixture = build_reference_admission_fixture()
    accepted = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert accepted.accepted is not None
    assert accepted.failure is None

    rejected = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=99,
    )
    assert rejected.accepted is None
    assert rejected.failure is not None
    assert rejected.failure.to_json_value()["failure_codes"] == ["VALIDATION_CONTEXT_UNAVAILABLE"]


def test_reducer_boundary_accepts_only_validated_event() -> None:
    fixture = build_reference_admission_fixture()
    outcome = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert outcome.accepted is not None
    assert require_validated_event(outcome.accepted) is outcome.accepted

    for invalid in (fixture.raw_event, outcome.failure):
        with pytest.raises(GovernanceContractError) as exc:
            require_validated_event(invalid)
        assert exc.value.code == "VALIDATION_RESULT_NOT_ACCEPTED"


def test_receipt_identity_changes_with_each_pinned_commitment() -> None:
    fixture = build_reference_admission_fixture()
    base = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert base.accepted is not None

    changed_raw = cast(
        RawEvent,
        RawEvent.build(
            {
                "schema_version": "raw-event/1",
                "event_id": "evt-advance-clock-002",
                "event_type": "AdvanceClock",
                "payload_schema_version": "advance-clock/1",
                "payload": {"delta_ticks": 2},
                "submitted_against_tick": 41,
            }
        ),
    )
    changed_raw_signatures = build_signature_set(
        changed_raw.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=changed_raw.digest,
                authority_scope="csd.events",
            ),
        ),
    )
    raw_outcome = fixture.engine.admit(
        changed_raw,
        changed_raw_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert raw_outcome.accepted is not None

    policy_outcome = fixture.engine.admit(
        fixture.raw_event,
        fixture.threshold_signatures,
        fixture.threshold_policy,
        validated_at_tick=41,
    )
    assert policy_outcome.accepted is not None

    bob_signatures = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="bob",
                key_id="key-bob-1",
                algorithm="ed25519",
                signed_digest=fixture.raw_event.digest,
                authority_scope="csd.events",
            ),
        ),
    )
    signature_outcome = fixture.engine.admit(
        fixture.raw_event,
        bob_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert signature_outcome.accepted is not None

    tick_42 = CommittedValidationContext.build(
        tick=42,
        state_root_digest="sha256:" + "4" * 64,
        authority_root_digest="sha256:" + "5" * 64,
    )
    tick_store = InMemoryEventAdmissionStore()
    tick_engine = EventAdmissionEngine(
        context_resolver=ReferenceCommittedContextResolver((tick_42,)),
        signature_verifier=fixture.signature_verifier,
        authority_resolver=fixture.authority_resolver,
        policy_registry=fixture.policy_registry,
        store=tick_store,
    )
    tick_outcome = tick_engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=42,
    )
    assert tick_outcome.accepted is not None

    identities = {
        base.accepted.digest,
        raw_outcome.accepted.digest,
        policy_outcome.accepted.digest,
        signature_outcome.accepted.digest,
        tick_outcome.accepted.digest,
    }
    assert len(identities) == 5


def test_every_accepted_receipt_field_is_digest_protected() -> None:
    fixture = build_reference_admission_fixture()
    outcome = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    assert outcome.accepted is not None
    value = outcome.accepted.to_json_value()
    mutations = {
        "raw_event_digest": "sha256:" + "1" * 64,
        "validation_policy_digest": "sha256:" + "2" * 64,
        "signature_set_digest": "sha256:" + "3" * 64,
        "validation_result": "REJECTED",
        "validated_at_tick": 40,
        "validated_event_digest": "sha256:" + "4" * 64,
    }
    for field_name, replacement in mutations.items():
        mutated = dict(value)
        mutated[field_name] = replacement
        with pytest.raises(GovernanceContractError):
            ValidatedEvent.from_json(mutated)


def test_filesystem_store_reconstructs_after_restart(tmp_path: Path) -> None:
    first_store = FilesystemEventAdmissionStore(tmp_path)
    first_fixture = build_reference_admission_fixture(first_store)
    first = first_fixture.engine.admit(
        first_fixture.raw_event,
        first_fixture.threshold_signatures,
        first_fixture.threshold_policy,
        validated_at_tick=41,
    )
    assert first.accepted is not None

    second_store = FilesystemEventAdmissionStore(tmp_path)
    second_fixture = build_reference_admission_fixture(second_store)
    second = second_fixture.engine.admit(
        second_fixture.raw_event,
        second_fixture.threshold_signatures,
        second_fixture.threshold_policy,
        validated_at_tick=41,
    )
    assert second.accepted is not None
    assert second.accepted.canonical_bytes == first.accepted.canonical_bytes
    bundle = reconstruct_accepted(second.accepted, second_store)
    assert bundle.raw_event == second_fixture.raw_event
    assert bundle.validation_policy == second_fixture.threshold_policy
    assert bundle.signature_set == second_fixture.threshold_signatures
    assert bundle.context.tick == 41


def test_context_tick_is_immutable_in_store() -> None:
    store = InMemoryEventAdmissionStore()
    first = CommittedValidationContext.build(
        tick=7,
        state_root_digest="sha256:" + "1" * 64,
        authority_root_digest="sha256:" + "2" * 64,
    )
    conflicting = CommittedValidationContext.build(
        tick=7,
        state_root_digest="sha256:" + "3" * 64,
        authority_root_digest="sha256:" + "2" * 64,
    )
    store.put_context(first)
    with pytest.raises(AdmissionStoreConflictError):
        store.put_context(conflicting)
