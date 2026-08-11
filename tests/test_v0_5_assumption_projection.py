"""Full isolation qualification for staged assumption projection (P3.2)."""

from __future__ import annotations

import hashlib
import json
from typing import cast

import pytest

from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionExpiryPlanner,
    AssumptionProjectionError,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5.assumption import (
    DERIVED_CHALLENGED,
    STANDING_ADMITTED,
    STANDING_EXPIRED,
    Assumption,
    AssumptionRegistry,
    build_assumption_event,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.registry import (
    InMemoryRegistryStore,
    RegistryStore,
)
from csd_foundry.governance.v0_5.temporal_validation import (
    ReferenceSemanticProjector,
    build_reference_validated_event,
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _projection_source(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
) -> str:
    """Mirror the adapter's internal ASSUMPTION_PROJECTION_SOURCE digest."""

    return (
        "sha256:"
        + hashlib.sha256(
            b"ASSUMPTION_PROJECTION_SOURCE\0"
            + _canonical_json(
                {
                    "clock_claim_digest": claim.digest,
                    "semantic_receipt_digest": semantic.digest,
                    "validated_event_digest": validated_event.digest,
                }
            )
        ).hexdigest()
    )


# ---------------------------------------------------------------------------
# Committed-state builders
# ---------------------------------------------------------------------------


def _propose(
    store: RegistryStore,
    *,
    assumption_id: str = "assumption:1",
    clock: int = 1,
    expires: int | None = 10,
    assumption_dependencies: list[str] | None = None,
    evidence_dependencies: list[str] | None = None,
    proposition_id: str = "proposition:control-connected",
    scope_ids: list[str] | None = None,
) -> Assumption:
    event = build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{assumption_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": proposition_id,
            "scope_ids": scope_ids or ["scope:control-17"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": assumption_dependencies or [],
            "evidence_dependency_ids": evidence_dependencies or [],
            "limitations": ["limitation:declared-model"],
            "maximum_reuse_class": "D2",
        },
    )
    return AssumptionRegistry(store).apply(event)


def _admit(
    store: RegistryStore,
    previous: Assumption,
    *,
    clock: int = 2,
    authority: str = "authority:admitter",
    receipt: str = _digest("admit-receipt"),
) -> Assumption:
    event = build_assumption_event(
        assumption_id=previous.assumption_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"admit:{previous.assumption_id}"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": authority,
            "admission_receipt_digest": receipt,
        },
    )
    return AssumptionRegistry(store).apply(event)


def _challenge(
    store: RegistryStore,
    previous: Assumption,
    *,
    clock: int,
    challenge_id: str = "challenge:1",
    challenger: str = "authority:challenger",
    reason: str = "reason:dispute",
    receipt: str = _digest("challenge-receipt"),
) -> Assumption:
    event = build_assumption_event(
        assumption_id=previous.assumption_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"challenge:{previous.assumption_id}"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": challenge_id,
            "challenger_authority_id": challenger,
            "challenge_reason_code": reason,
            "challenge_receipt_digest": receipt,
        },
    )
    return AssumptionRegistry(store).apply(event)


# ---------------------------------------------------------------------------
# Expiry authority + temporal context
# ---------------------------------------------------------------------------


class _StaticExpiryAuthority:
    """Deterministic expiry authority for tests."""

    def __init__(self, *, authority_id: str = "authority:clock") -> None:
        self._authority_id = authority_id

    @property
    def expiry_authority_id(self) -> str:
        return self._authority_id

    def expiry_receipt_digest(self, *, assumption_id: str, clock_sequence: int) -> str:
        return _digest(f"expiry:{assumption_id}:{clock_sequence}")


def _context(
    sequence: int,
) -> tuple[ClockClaim, ValidatedEvent, SemanticProjectionReceipt]:
    validated_event = build_reference_validated_event()
    claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": f"attempt-assumption-{sequence}",
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


def _adapter() -> StagedAssumptionProjectionAdapter:
    return StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
    )


class _IntentResolver:
    """Single-event intent resolver that closes over a prebuilt event."""

    def __init__(self, event: RegistryEvent) -> None:
        self._event = event

    def resolve(self, **kwargs: object) -> tuple[RegistryEvent, ...]:
        del kwargs
        return (self._event,)


# ---------------------------------------------------------------------------
# Expiry planner tests
# ---------------------------------------------------------------------------


def test_expiry_planner_is_logical_clock_driven_and_idempotent() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ASSUMPTION").root_digest

    planner = AssumptionExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
    early = planner.plan(
        store=store,
        clock_sequence=9,
        source_receipt_digest=_digest("tick:9"),
    )
    first = planner.plan(
        store=store,
        clock_sequence=10,
        source_receipt_digest=_digest("tick:10"),
    )
    second = planner.plan(
        store=store,
        clock_sequence=10,
        source_receipt_digest=_digest("tick:10"),
    )

    assert early.events == ()
    assert len(first.events) == 1
    assert first.to_json_value() == second.to_json_value()
    assert first.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"
    assert store.snapshot("ASSUMPTION").root_digest == original_root


def test_challenged_assumption_expiry_is_eligible() -> None:
    """standing=ADMITTED with active_challenges (status CHALLENGED) still expires."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)
    challenged = _challenge(store, admitted, clock=3, challenge_id="challenge:x")

    assert challenged.status == DERIVED_CHALLENGED
    assert challenged.standing == STANDING_ADMITTED

    planner = AssumptionExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
    plan = planner.plan(
        store=store,
        clock_sequence=10,
        source_receipt_digest=_digest("tick:10"),
    )

    assert len(plan.events) == 1
    assert plan.events[0].to_json_value()["entity_id"] == "assumption:1"


def test_expiry_planner_skips_terminal_and_unexpired_assumptions() -> None:
    store = InMemoryRegistryStore()
    # An unexpired admitted assumption (expires=100).
    p_keep = _propose(store, assumption_id="assumption:keep", clock=1, expires=100)
    _admit(store, p_keep, clock=2)
    # An expirable admitted assumption (expires=10).
    p_die = _propose(store, assumption_id="assumption:die", clock=3, expires=10)
    _admit(store, p_die, clock=4)

    planner = AssumptionExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
    plan = planner.plan(
        store=store,
        clock_sequence=20,
        source_receipt_digest=_digest("tick:20"),
    )

    assert len(plan.events) == 1
    assert plan.events[0].to_json_value()["entity_id"] == "assumption:die"


# ---------------------------------------------------------------------------
# Impact closure tests
# ---------------------------------------------------------------------------


def test_empty_impact_closure_when_no_dependents() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _digest("confirm-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert len(plan.impact_receipts) == 1
    assert plan.impact_receipts[0].affected_assumption_ids == ()


def test_multi_level_reverse_dependency_closure() -> None:
    """A→B→C: A depends on B, B depends on C. Event on C affects B and A."""

    store = InMemoryRegistryStore()
    proposed_c = _propose(store, assumption_id="assumption:c", clock=1, expires=100)
    _admit(store, proposed_c, clock=2)
    proposed_b = _propose(
        store,
        assumption_id="assumption:b",
        clock=3,
        expires=100,
        assumption_dependencies=["assumption:c"],
    )
    _admit(store, proposed_b, clock=4)
    proposed_a = _propose(
        store,
        assumption_id="assumption:a",
        clock=5,
        expires=100,
        assumption_dependencies=["assumption:b"],
    )
    _admit(store, proposed_a, clock=6)

    c_state = AssumptionRegistry(store).current("assumption:c")
    assert c_state is not None
    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    trigger = build_assumption_event(
        assumption_id="assumption:c",
        entity_sequence=c_state.current_entity_sequence + 1,
        previous_entity_event_digest=c_state.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:closure",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _digest("challenge-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(trigger),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    # Impact: CHALLENGE on C affects A and B (reverse closure), excludes C.
    assert len(plan.impact_receipts) == 1
    receipt = plan.impact_receipts[0]
    assert receipt.assumption_id == "assumption:c"
    assert receipt.affected_assumption_ids == ("assumption:a", "assumption:b")


def test_reverse_closure_excludes_trigger_assumption() -> None:
    """An assumption that depends on itself transitively must not include itself."""

    store = InMemoryRegistryStore()
    # Diamond: D depends on B and C; B and C both depend on A.
    p_a = _propose(store, assumption_id="assumption:a", clock=1, expires=100)
    _admit(store, p_a, clock=2)
    p_b = _propose(
        store,
        assumption_id="assumption:b",
        clock=3,
        expires=100,
        assumption_dependencies=["assumption:a"],
    )
    _admit(store, p_b, clock=4)
    p_c = _propose(
        store,
        assumption_id="assumption:c",
        clock=5,
        expires=100,
        assumption_dependencies=["assumption:a"],
    )
    _admit(store, p_c, clock=6)
    p_d = _propose(
        store,
        assumption_id="assumption:d",
        clock=7,
        expires=100,
        assumption_dependencies=["assumption:b", "assumption:c"],
    )
    _admit(store, p_d, clock=8)

    a_state = AssumptionRegistry(store).current("assumption:a")
    assert a_state is not None
    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    trigger = build_assumption_event(
        assumption_id="assumption:a",
        entity_sequence=a_state.current_entity_sequence + 1,
        previous_entity_event_digest=a_state.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:diamond",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _digest("challenge-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(trigger),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    receipt = plan.impact_receipts[0]
    assert receipt.assumption_id == "assumption:a"
    assert "assumption:a" not in receipt.affected_assumption_ids
    assert receipt.affected_assumption_ids == (
        "assumption:b",
        "assumption:c",
        "assumption:d",
    )


# ---------------------------------------------------------------------------
# Impact operation coverage
# ---------------------------------------------------------------------------


def _build_impact_event(
    admitted: Assumption,
    operation: str,
    source_digest: str,
) -> RegistryEvent:
    if operation == "CHALLENGE":
        payload: dict[str, object] = {
            "operation": "CHALLENGE",
            "challenge_id": "challenge:impact",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _digest("challenge-receipt"),
        }
    elif operation == "CONFIRM":
        payload = {
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _digest("confirm-receipt"),
        }
    elif operation == "REJECT":
        payload = {
            "operation": "REJECT",
            "rejecting_authority_id": "authority:rejecter",
            "rejection_receipt_digest": _digest("reject-receipt"),
            "reason_code": "reason:invalid",
        }
    elif operation == "SUPERSEDE":
        payload = {
            "operation": "SUPERSEDE",
            "replacement_assumption_id": "assumption:replacement",
            "superseding_authority_id": "authority:superseder",
            "supersession_receipt_digest": _digest("supersede-receipt"),
            "reason_code": "reason:superseded",
        }
    else:
        pytest.fail(f"unsupported operation {operation}")

    return build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload=payload,
    )


@pytest.mark.parametrize("operation", ["CHALLENGE", "CONFIRM", "REJECT", "SUPERSEDE"])
def test_each_impact_operation_emits_receipt(operation: str) -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = _build_impact_event(admitted, operation, source_digest)

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1, (
        f"expected one impact for {operation}, got {len(plan.impact_receipts)}"
    )


def test_resolve_challenges_impact_emits_receipt() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)
    challenged = _challenge(store, admitted, clock=3, challenge_id="challenge:r")

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_assumption_event(
        assumption_id=challenged.assumption_id,
        entity_sequence=challenged.current_entity_sequence + 1,
        previous_entity_event_digest=challenged.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest("resolve-receipt"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": ["challenge:r"],
            "replacement_assumption_id": None,
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1
    assert impacts[0].previous_status == DERIVED_CHALLENGED
    assert impacts[0].current_status == STANDING_ADMITTED


def test_expire_impact_emits_receipt() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:clock",
            "expiry_receipt_digest": _digest("expiry-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1
    assert impacts[0].previous_status == STANDING_ADMITTED
    assert impacts[0].current_status == STANDING_EXPIRED


def test_non_impact_operations_emit_no_receipt() -> None:
    """PROPOSE and ADMIT are not impact operations and must not emit receipts."""

    store = InMemoryRegistryStore()
    # Seed nothing; the staged ADMIT will be the only event.
    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    propose_event = build_assumption_event(
        assumption_id="assumption:new",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:new",
            "scope_ids": ["scope:control-17"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": 20,
            "valid_from_sequence": 20,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(propose_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert plan.impact_receipts == ()


# ---------------------------------------------------------------------------
# Isolation / byte-identity / reconstruction tests
# ---------------------------------------------------------------------------


def test_staged_projection_does_not_mutate_committed_store() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ASSUMPTION").root_digest

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert plan.projected_root_digest != original_root
    assert store.snapshot("ASSUMPTION").root_digest == original_root
    assert len(plan.events) == 1
    assert plan.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"


def test_restart_replay_byte_identity() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    first = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )
    second = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert first.to_json_value() == second.to_json_value()
    assert first.plan_digest == second.plan_digest
    assert first.projected_root_digest == second.projected_root_digest
    assert first.event_digests == second.event_digests
    assert first.impact_receipt_digests == second.impact_receipt_digests


def test_same_predecessor_and_inputs_yield_identical_events_root_receipts() -> None:
    """Two independent stores with identical committed state produce identical plans."""

    def _seed() -> InMemoryRegistryStore:
        s = InMemoryRegistryStore()
        p = _propose(s, assumption_id="assumption:1", clock=1, expires=10)
        _admit(s, p, clock=2)
        return s

    store_a = _seed()
    store_b = _seed()
    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan_a = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store_a,
        evidence_root_digest=store_a.snapshot("EVIDENCE_UNIT").root_digest,
    )
    plan_b = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store_b,
        evidence_root_digest=store_b.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert plan_a.to_json_value() == plan_b.to_json_value()
    assert plan_a.projected_root_digest == plan_b.projected_root_digest


def test_candidate_root_reconstruction_from_predecessor_and_events() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    rebuilt = InMemoryRegistryStore()
    for history in store.reconstruct_snapshot("ASSUMPTION"):
        for event in history:
            rebuilt.append(event)
    for event in plan.events:
        rebuilt.append(event)

    assert rebuilt.snapshot("ASSUMPTION").root_digest == plan.projected_root_digest


def test_committed_root_unchanged_after_context_failure() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ASSUMPTION").root_digest

    claim, validated_event, semantic = _context(20)
    wrong_claim = cast(
        ClockClaim,
        claim.with_updates(validated_event_digest=_digest("wrong-event")),
    )
    adapter = _adapter()

    with pytest.raises(AssumptionProjectionError, match="ASSUMPTION_PROJECTION_EVENT_MISMATCH"):
        adapter.project(
            claim=wrong_claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
        )

    assert store.snapshot("ASSUMPTION").root_digest == original_root


def test_committed_root_unchanged_after_binding_failure() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)
    original_root = store.snapshot("ASSUMPTION").root_digest

    wrong_event = build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=_digest("wrong-source"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _digest("confirm-receipt"),
        },
    )

    claim, validated_event, semantic = _context(20)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(wrong_event),
    )

    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_EVENT_SOURCE_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
        )

    assert store.snapshot("ASSUMPTION").root_digest == original_root


def test_committed_root_unchanged_after_reduction_failure() -> None:
    """A CONFIRM on an assumption with active challenges is rejected by the reducer."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)
    challenged = _challenge(store, admitted, clock=3, challenge_id="challenge:c")
    assert challenged.status == DERIVED_CHALLENGED
    original_root = store.snapshot("ASSUMPTION").root_digest

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    bad_event = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=challenged.current_entity_sequence + 1,
        previous_entity_event_digest=challenged.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _digest("confirm-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(bad_event),
    )

    with pytest.raises(Exception):  # noqa: B017 - any reducer failure is acceptable
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
        )

    assert store.snapshot("ASSUMPTION").root_digest == original_root


# ---------------------------------------------------------------------------
# Explicit-expiry-suppression + canonical ordering
# ---------------------------------------------------------------------------


def test_explicit_expire_suppresses_planned_expiry() -> None:
    """An assumption explicitly expired by intent should NOT also get a planned expiry event."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    explicit_expire = build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:explicit",
            "expiry_receipt_digest": _digest("explicit-expiry-receipt"),
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(explicit_expire),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert len(plan.events) == 1
    assert plan.events[0].digest == explicit_expire.digest
    operations = [event.to_json_value()["payload"]["operation"] for event in plan.events]
    assert operations == ["EXPIRE"]


def test_canonical_impact_event_ordering() -> None:
    """Multiple impact events are applied in canonical (entity_id, sequence) order."""

    store = InMemoryRegistryStore()
    p_b = _propose(store, assumption_id="assumption:b", clock=1, expires=10)
    _admit(store, p_b, clock=2)
    p_a = _propose(store, assumption_id="assumption:a", clock=3, expires=10)
    _admit(store, p_a, clock=4)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert len(plan.events) == 2
    ids = [event.to_json_value()["entity_id"] for event in plan.events]
    assert ids == ["assumption:a", "assumption:b"]


# ---------------------------------------------------------------------------
# Governed-ADMIT binding preservation
# ---------------------------------------------------------------------------


def test_governed_admit_bindings_preserved_on_staged_admit() -> None:
    """A staged ADMIT event preserves source_receipt_digest and
    admission_receipt_digest exactly as supplied by the intent resolver."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    governed_admission = _digest("governed:authorization")
    admit_event = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": governed_admission,
        },
    )

    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert len(plan.events) == 1
    staged = plan.events[0]
    staged_value = staged.to_json_value()
    assert staged_value["source_receipt_digest"] == source_digest
    assert staged_value["payload"]["admission_receipt_digest"] == governed_admission
    assert staged.canonical_bytes == admit_event.canonical_bytes
    assert staged.digest == admit_event.digest


# ---------------------------------------------------------------------------
# Empty projection + isolated clone sanity
# ---------------------------------------------------------------------------


def test_empty_projection_when_nothing_expirable() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ASSUMPTION").root_digest

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert plan.events == ()
    assert plan.impact_receipts == ()
    assert plan.projected_root_digest == original_root
    assert store.snapshot("ASSUMPTION").root_digest == original_root


def test_clone_is_independent_of_committed_store() -> None:
    """Mutating events applied during projection do not leak into the committed store."""

    store = InMemoryRegistryStore()
    p_a = _propose(store, assumption_id="assumption:a", clock=1, expires=10)
    _admit(store, p_a, clock=2)
    original_snapshot = store.snapshot("ASSUMPTION")

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    after_snapshot = store.snapshot("ASSUMPTION")
    assert after_snapshot.root_digest == original_snapshot.root_digest
    assert after_snapshot.heads == original_snapshot.heads
    assert len(plan.events) == 1


def test_predecessor_root_captured_before_staging() -> None:
    store = InMemoryRegistryStore()
    p_a = _propose(store, assumption_id="assumption:a", clock=1, expires=10)
    _admit(store, p_a, clock=2)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert plan.predecessor_root_digest == store.snapshot("ASSUMPTION").root_digest
    assert plan.predecessor_root_digest != plan.projected_root_digest
