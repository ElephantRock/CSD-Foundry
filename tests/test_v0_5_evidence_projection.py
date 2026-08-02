from __future__ import annotations

import hashlib
from typing import cast

import pytest

from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
)
from csd_foundry.governance.v0_5.evidence_governance import (
    EvidenceAuthorityGrant,
    EvidenceAuthorityPolicy,
)
from csd_foundry.governance.v0_5.evidence_projection import (
    EvidenceExpiryPlanner,
    EvidenceImpactResolver,
    EvidenceProjectionError,
    StagedEvidenceProjectionAdapter,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStore
from csd_foundry.governance.v0_5.resources import evidence_vectors
from csd_foundry.governance.v0_5.temporal_validation import (
    ReferenceSemanticProjector,
    build_reference_validated_event,
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _authority_policy() -> EvidenceAuthorityPolicy:
    grants = (
        EvidenceAuthorityGrant("CHALLENGE", "authority:challenger", ()),
        EvidenceAuthorityGrant("EXPIRE", "authority:clock", ()),
        EvidenceAuthorityGrant("INVALIDATE", "authority:resolver", ()),
        EvidenceAuthorityGrant("REGISTER", "authority:issuer", ("control:17",)),
        EvidenceAuthorityGrant("REJECT", "authority:verifier", ()),
        EvidenceAuthorityGrant("RESOLVE_CHALLENGE", "authority:resolver", ()),
        EvidenceAuthorityGrant("SUPERSEDE", "authority:issuer", ()),
        EvidenceAuthorityGrant("VERIFY", "authority:verifier", ("control:17",)),
    )
    return EvidenceAuthorityPolicy.build(
        policy_id="policy:evidence-v1",
        committed_at_sequence=0,
        authority_root_digest=_digest("authority-root"),
        grants=grants,
    )


def _seed_store(vector_id: str) -> InMemoryRegistryStore:
    catalog = evidence_vectors()
    accepted = catalog["accepted_vectors"]
    assert isinstance(accepted, list)
    vector = next(item for item in accepted if item["vector_id"] == vector_id)
    events = vector["events"]
    assert isinstance(events, list)
    store = InMemoryRegistryStore()
    for value in events:
        assert isinstance(value, dict)
        store.append(cast(RegistryEvent, RegistryEvent.from_json(value)))
    return store


def _context(sequence: int) -> tuple[ClockClaim, object, SemanticProjectionReceipt]:
    validated_event = build_reference_validated_event()
    claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": f"attempt-evidence-{sequence}",
                "previous_committed_sequence": sequence - 1,
                "previous_completion_digest": _digest(f"completion:{sequence - 1}"),
                "proposed_sequence": sequence,
                "validated_event_digest": validated_event.digest,
                "claimant_id": "validator",
                "claim_policy_digest": _digest("claim-policy"),
            }
        ),
    )
    semantic = ReferenceSemanticProjector().project(
        claim=claim,
        validated_event=validated_event,
    )
    return claim, validated_event, semantic


class _ReferenceImpactResolver(EvidenceImpactResolver):
    def resolve(
        self,
        *,
        evidence: object,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        del evidence, trigger_event, store
        return ("basis:17",), ("control:17",)


def test_expiry_planner_is_logical_clock_driven_and_idempotent() -> None:
    store = _seed_store("EV-A01-REGISTER-VERIFY")
    planner = EvidenceExpiryPlanner(
        authority_policy=_authority_policy(),
        expiry_authority_id="authority:clock",
    )
    original_root = store.snapshot("EVIDENCE_UNIT").root_digest

    early = planner.plan(
        store=store,
        clock_sequence=19,
        source_receipt_digest=_digest("tick:19"),
    )
    first = planner.plan(
        store=store,
        clock_sequence=20,
        source_receipt_digest=_digest("tick:20"),
    )
    second = planner.plan(
        store=store,
        clock_sequence=20,
        source_receipt_digest=_digest("tick:20"),
    )

    assert early.events == ()
    assert len(first.events) == 1
    assert first.to_json_value() == second.to_json_value()
    assert first.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"
    assert store.snapshot("EVIDENCE_UNIT").root_digest == original_root


def test_staged_projection_emits_expiry_impact_without_committed_mutation() -> None:
    store = _seed_store("EV-A05-DEPENDENCY-CHAIN")
    claim, validated_event, semantic = _context(20)
    original_root = store.snapshot("EVIDENCE_UNIT").root_digest
    adapter = StagedEvidenceProjectionAdapter(
        authority_policy=_authority_policy(),
        expiry_authority_id="authority:clock",
        impact_resolver=_ReferenceImpactResolver(),
    )

    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
    )
    repeated = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
    )

    assert plan.to_json_value() == repeated.to_json_value()
    assert len(plan.events) == 2
    assert len(plan.authority_decisions) == 2
    assert len(plan.impact_receipts) == 2
    assert plan.projected_root_digest != original_root
    assert store.snapshot("EVIDENCE_UNIT").root_digest == original_root
    impacts = {item.evidence_id: item for item in plan.impact_receipts}
    assert impacts["evidence:b"].affected_dependency_ids == ("evidence:a",)
    assert impacts["evidence:b"].candidate_basis_ids == ("basis:17",)
    assert impacts["evidence:b"].candidate_semantic_object_ids == ("control:17",)
    assert all(item.impact_kind == "REASSESSMENT_REQUIRED" for item in plan.impact_receipts)


def test_terminal_evidence_is_not_replanned() -> None:
    store = _seed_store("EV-A01-REGISTER-VERIFY")
    planner = EvidenceExpiryPlanner(
        authority_policy=_authority_policy(),
        expiry_authority_id="authority:clock",
    )
    plan = planner.plan(
        store=store,
        clock_sequence=20,
        source_receipt_digest=_digest("tick:20"),
    )
    store.append(plan.events[0])

    later = planner.plan(
        store=store,
        clock_sequence=21,
        source_receipt_digest=_digest("tick:21"),
    )

    assert later.events == ()


def test_projection_context_mismatch_fails_without_registry_change() -> None:
    store = _seed_store("EV-A01-REGISTER-VERIFY")
    claim, validated_event, semantic = _context(20)
    original_root = store.snapshot("EVIDENCE_UNIT").root_digest
    wrong_claim = cast(
        ClockClaim,
        claim.with_updates(validated_event_digest=_digest("wrong-event")),
    )
    adapter = StagedEvidenceProjectionAdapter(
        authority_policy=_authority_policy(),
        expiry_authority_id="authority:clock",
    )

    with pytest.raises(EvidenceProjectionError, match="EVIDENCE_PROJECTION_EVENT_MISMATCH"):
        adapter.project(
            claim=wrong_claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
        )

    assert store.snapshot("EVIDENCE_UNIT").root_digest == original_root
