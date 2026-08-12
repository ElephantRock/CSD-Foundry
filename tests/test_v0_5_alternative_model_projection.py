"""Staging qualification for alternative-model projection (P3.5).

Mirrors the assumption projection test structure, adapted for the D4
alternative-model lifecycle. Exercises expiry planning, impact receipts, clone-
then-mutate isolation, byte-stable replay, and governed-ADMIT binding
preservation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import cast

import pytest

from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelExpiryAuthorization,
    AlternativeModelExpiryPlanner,
    AlternativeModelProjectionError,
    AlternativeModelProjectionPlan,
    StagedAlternativeModelProjectionAdapter,
)
from csd_foundry.governance.v0_5._governed_alternative_model import (
    ComparisonReceipt,
    GovernedAlternativeModelAuthorization,
    StructuralDifferenceReceipt,
    append_governed_alternative_model_admit,
    compare_alternative_model_replays,
    compute_structural_difference_digest,
    detect_structural_difference,
)
from csd_foundry.governance.v0_5.alternative_model import (
    STANDING_CONFIRMED,
    AlternativeModel,
    AlternativeModelRegistry,
    build_alternative_model_event,
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


def _graph_digest_of(graph_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(graph_bytes).hexdigest()


def _projection_source(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            b"ALTERNATIVE_MODEL_PROJECTION_SOURCE\0"
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
    model_id: str = "alt-model:1",
    clock: int = 1,
    expires: int | None = 10,
    graph_digest: str = _digest("shadow-graph"),
    declared_difference_digest: str = _digest("difference-set"),
) -> AlternativeModel:
    event = build_alternative_model_event(
        model_id=model_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{model_id}"),
        payload={
            "operation": "PROPOSE",
            "model_version": "v1",
            "primary_model_id": "model:primary",
            "graph_digest": graph_digest,
            "declared_difference_digest": declared_difference_digest,
            "challenge_basis_code": "basis:shadow-divergence",
            "scope_ids": ["scope:control-17"],
            "assumption_ids": [],
            "evidence_ids": [],
            "proposer_authority_id": "authority:proposer",
            "materiality": "MATERIAL",
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "limitations": ["limitation:declared-model"],
            "maximum_reuse_class": "D2",
        },
    )
    return AlternativeModelRegistry(store).apply(event)


def _admit(
    store: RegistryStore,
    previous: AlternativeModel,
    *,
    clock: int = 2,
    authority: str = "authority:admitter",
) -> AlternativeModel:
    event = build_alternative_model_event(
        model_id=previous.model_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"admit:{previous.model_id}"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": authority,
        },
    )
    return AlternativeModelRegistry(store).apply(event)


def _confirm(
    store: RegistryStore,
    previous: AlternativeModel,
    *,
    clock: int = 3,
) -> AlternativeModel:
    event = build_alternative_model_event(
        model_id=previous.model_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"confirm:{previous.model_id}"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    return AlternativeModelRegistry(store).apply(event)


def _challenge(
    store: RegistryStore,
    previous: AlternativeModel,
    *,
    clock: int,
    challenge_id: str = "challenge:1",
) -> AlternativeModel:
    event = build_alternative_model_event(
        model_id=previous.model_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"challenge:{previous.model_id}"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": challenge_id,
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _digest("challenge-receipt"),
        },
    )
    return AlternativeModelRegistry(store).apply(event)


# ---------------------------------------------------------------------------
# Expiry authority + temporal context
# ---------------------------------------------------------------------------


class _StaticExpiryAuthority:
    def __init__(self, *, authority_id: str = "authority:clock") -> None:
        self._authority_id = authority_id

    @property
    def expiry_authority_id(self) -> str:
        return self._authority_id

    def expiry_authorization(
        self, *, model_id: str, clock_sequence: int
    ) -> AlternativeModelExpiryAuthorization | None:
        return AlternativeModelExpiryAuthorization.build(
            model_id=model_id,
            clock_sequence=clock_sequence,
            expiry_authority_id=self._authority_id,
            expiry_receipt_digest=_digest(f"expiry:{model_id}:{clock_sequence}"),
        )


def _context(
    sequence: int,
) -> tuple[ClockClaim, ValidatedEvent, SemanticProjectionReceipt]:
    validated_event = build_reference_validated_event()
    claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": f"attempt-alt-model-{sequence}",
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


def _adapter() -> StagedAlternativeModelProjectionAdapter:
    return StagedAlternativeModelProjectionAdapter(
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
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:1"), clock=3)
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    planner = AlternativeModelExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
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
    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root


def test_expiry_planner_expires_unverified_models() -> None:
    """UNVERIFIED models ARE expirable (P3.5 includes UNVERIFIED in expirable standings)."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:unverified", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    # Model is now UNVERIFIED, which IS expirable per the frozen P3.5 contract.
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    planner = AlternativeModelExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
    early = planner.plan(
        store=store,
        clock_sequence=9,
        source_receipt_digest=_digest("tick:9"),
    )
    on_time = planner.plan(
        store=store,
        clock_sequence=10,
        source_receipt_digest=_digest("tick:10"),
    )

    # clock 9 < expires_at 10 → not yet expirable.
    assert early.events == ()
    # clock 10 >= expires_at 10 → expirable.
    assert len(on_time.events) == 1
    assert on_time.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"
    # Planner must not mutate the committed store.
    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root


def test_challenged_model_expiry_still_works() -> None:
    """A CHALLENGED model (derived from underlying UNVERIFIED with active challenges)
    is still expirable — the expiry check uses the underlying separation_status."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:challenged", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)
    challenged = _challenge(store, admitted, clock=4, challenge_id="challenge:c1")
    # The model's separation_status is still UNVERIFIED (challenges don't change it),
    # but the derived standing is CHALLENGED due to the active challenge.
    assert challenged.standing == "CHALLENGED"
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    planner = AlternativeModelExpiryPlanner(expiry_authority=_StaticExpiryAuthority())
    plan = planner.plan(
        store=store,
        clock_sequence=10,
        source_receipt_digest=_digest("tick:10"),
    )

    assert len(plan.events) == 1
    assert plan.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"
    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root


# ---------------------------------------------------------------------------
# Impact receipt tests
# ---------------------------------------------------------------------------


def test_empty_impact_closure_when_no_impact_event() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_alternative_model_event(
        model_id=admitted.model_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert len(plan.impact_receipts) == 1
    assert plan.impact_receipts[0].scope_ids == ("scope:control-17",)
    assert plan.impact_receipts[0].assumption_ids == ()
    assert plan.impact_receipts[0].evidence_ids == ()


@pytest.mark.parametrize(
    "operation,payload",
    [
        (
            "CHALLENGE",
            {
                "challenge_id": "challenge:impact",
                "challenger_authority_id": "authority:challenger",
                "challenge_reason_code": "reason:dispute",
                "challenge_receipt_digest": _digest("challenge-receipt"),
            },
        ),
        (
            "CONFIRM",
            {"confirming_authority_id": "authority:confirmer"},
        ),
        (
            "REJECT",
            {
                "rejecting_authority_id": "authority:rejector",
                "reason_code": "reason:invalid",
            },
        ),
        (
            "SUPERSEDE",
            {
                "replacement_model_id": "alt-model:replacement",
                "superseding_authority_id": "authority:superseder",
                "supersession_receipt_digest": _digest("supersede-receipt"),
                "reason_code": "reason:superseded",
            },
        ),
    ],
)
def test_each_impact_operation_emits_receipt(operation: str, payload: dict[str, object]) -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)
    confirmed = _confirm(store, admitted, clock=3)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_alternative_model_event(
        model_id=confirmed.model_id,
        entity_sequence=confirmed.current_entity_sequence + 1,
        previous_entity_event_digest=confirmed.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={"operation": operation, **payload},
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1, (
        f"expected one impact for {operation}, got {len(plan.impact_receipts)}"
    )


def test_resolve_challenges_impact_emits_receipt() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)
    confirmed = _confirm(store, admitted, clock=3)
    challenged = _challenge(store, confirmed, clock=4, challenge_id="challenge:r")

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_alternative_model_event(
        model_id=challenged.model_id,
        entity_sequence=challenged.current_entity_sequence + 1,
        previous_entity_event_digest=challenged.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "UPHOLD",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest("resolve-receipt"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": ["challenge:r"],
            "replacement_model_id": None,
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1


# ---------------------------------------------------------------------------
# Isolation / byte-identity tests
# ---------------------------------------------------------------------------


def test_staged_projection_does_not_mutate_committed_store() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:1"), clock=3)
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert plan.projected_root_digest != original_root
    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root
    assert len(plan.events) == 1
    assert plan.events[0].to_json_value()["payload"]["operation"] == "EXPIRE"


def test_restart_replay_byte_identity() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:1"), clock=3)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    first = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )
    second = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert first.to_json_value() == second.to_json_value()
    assert first.plan_digest == second.plan_digest


def test_candidate_root_reconstruction_from_predecessor_and_events() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:1"), clock=3)

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    rebuilt = InMemoryRegistryStore()
    for history in store.reconstruct_snapshot("ALTERNATIVE_MODEL"):
        for event in history:
            rebuilt.append(event)
    for event in plan.events:
        rebuilt.append(event)

    assert rebuilt.snapshot("ALTERNATIVE_MODEL").root_digest == plan.projected_root_digest


def test_committed_root_unchanged_after_context_failure() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    claim, validated_event, semantic = _context(20)
    wrong_claim = cast(
        ClockClaim,
        claim.with_updates(validated_event_digest=_digest("wrong-event")),
    )
    adapter = _adapter()

    with pytest.raises(
        AlternativeModelProjectionError, match="ALT_MODEL_PROJECTION_EVENT_MISMATCH"
    ):
        adapter.project(
            claim=wrong_claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
        )

    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root


def test_empty_projection_when_nothing_expirable() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    _admit(store, proposed, clock=2)
    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest

    claim, validated_event, semantic = _context(20)
    adapter = _adapter()
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert plan.events == ()
    assert plan.impact_receipts == ()
    assert plan.projected_root_digest == original_root
    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root


def test_explicit_expire_suppresses_planned_expiry() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)
    confirmed = _confirm(store, admitted, clock=3)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    explicit_expire = build_alternative_model_event(
        model_id=confirmed.model_id,
        entity_sequence=confirmed.current_entity_sequence + 1,
        previous_entity_event_digest=confirmed.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:explicit",
            "expiry_receipt_digest": _digest("explicit-expiry-receipt"),
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(explicit_expire),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert len(plan.events) == 1
    assert plan.events[0].digest == explicit_expire.digest


# ---------------------------------------------------------------------------
# Governed-ADMIT binding preservation (production-shaped)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GovernedAdmitEvidence:
    authorization: GovernedAlternativeModelAuthorization
    receipt: StructuralDifferenceReceipt
    alt_model_root_pre_admit: str
    model_id: str


def _build_governed_admit_evidence(
    store: RegistryStore,
    *,
    model_id: str = "alt-model:gov",
    clock: int = 1,
    admit_clock: int = 2,
) -> _GovernedAdmitEvidence:
    """Run a real governed ADMIT append and return its production evidence."""
    primary_graph = {
        "nodes": [{"node_id": "n1", "authority_id": "authority:primary"}],
        "semantic_seed": "primary",
    }
    shadow_graph = {
        "nodes": [
            {"node_id": "n1", "authority_id": "authority:shadow"},
            {"node_id": "n2", "authority_id": "authority:shadow"},
        ],
        "semantic_seed": "shadow",
    }
    primary_bytes = _canonical_json(primary_graph)
    shadow_bytes = _canonical_json(shadow_graph)
    primary_digest = _graph_digest_of(primary_bytes)
    shadow_digest = _graph_digest_of(shadow_bytes)
    declared_digest = compute_structural_difference_digest(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
    )
    receipt = detect_structural_difference(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        primary_graph_digest=primary_digest,
        shadow_graph_digest=shadow_digest,
        declared_difference_digest=declared_digest,
    )
    _propose(
        store,
        model_id=model_id,
        clock=clock,
        expires=100,
        graph_digest=shadow_digest,
        declared_difference_digest=declared_digest,
    )
    alt_model_root_pre_admit = store.snapshot("ALTERNATIVE_MODEL").root_digest
    result = append_governed_alternative_model_admit(
        store=store,
        model_id=model_id,
        structural_difference_receipt=receipt,
        admitting_authority_id="authority:admitter",
        event_sequence=admit_clock,
    )
    assert result.applied is True
    return _GovernedAdmitEvidence(
        authorization=result.authorization,
        receipt=receipt,
        alt_model_root_pre_admit=alt_model_root_pre_admit,
        model_id=model_id,
    )


def _build_governed_admit_with_comparison(
    store: RegistryStore,
    *,
    model_id: str = "alt-model:govcmp",
    clock: int = 1,
    admit_clock: int = 2,
) -> tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt]:
    """Run a governed ADMIT and a DIVERGENT comparison, returning both."""
    evidence = _build_governed_admit_evidence(
        store, model_id=model_id, clock=clock, admit_clock=admit_clock
    )
    auth = evidence.authorization
    receipt = auth.structural_difference_receipt
    # Build two replay receipts (DIVERGENT) sharing decision context.
    decision_context = _digest("decision-context:cmp")
    initial_state = _digest("initial-state:cmp")
    primary_replay = _build_replay_receipt(
        graph_digest=receipt.primary_graph_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("outcome:primary"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=receipt.shadow_graph_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("outcome:shadow"),
    )
    comparison = compare_alternative_model_replays(
        structural_difference_receipt=receipt,
        primary_replay_receipt=primary_replay,
        shadow_replay_receipt=shadow_replay,
    )
    return auth, comparison


def _build_replay_receipt(
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    semantic_outcome_digest: str,
) -> object:
    """Build a self-digesting ReplayReceipt using the production domain digest."""
    from csd_foundry.governance.v0_5._governed_alternative_model import ReplayReceipt

    required = ("node:n1",)
    unsigned: dict[str, object] = {
        "schema_version": "alternative-model-replay-receipt/1",
        "graph_digest": graph_digest,
        "decision_context_digest": decision_context_digest,
        "initial_state_digest": initial_state_digest,
        "logical_clock": 5,
        "runner_revision": "runner:v1",
        "required_inventory": list(required),
        "executed_inventory": list(required),
        "skipped_inventory": [],
        "pruned_inventory": [],
        "semantic_outcome_digest": semantic_outcome_digest,
    }
    receipt_digest = (
        "sha256:"
        + hashlib.sha256(
            b"ALTERNATIVE_MODEL_REPLAY_RECEIPT" + _canonical_json(unsigned)
        ).hexdigest()
    )
    return ReplayReceipt(
        graph_digest=graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=5,
        runner_revision="runner:v1",
        required_inventory=required,
        executed_inventory=required,
        skipped_inventory=(),
        pruned_inventory=(),
        semantic_outcome_digest=semantic_outcome_digest,
        receipt_digest=receipt_digest,
    )


def test_governed_admit_bindings_preserved_on_staged_admit() -> None:
    """A staged ADMIT built from a real authorization is validated and preserved."""
    seed_store = InMemoryRegistryStore()
    auth, comparison = _build_governed_admit_with_comparison(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )

    # Committed store has only PROPOSE.
    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )

    admit_event = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=auth.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    plan: AlternativeModelProjectionPlan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
        governed_admit_evidence=((auth, comparison),),
    )

    assert len(plan.events) == 1
    staged = plan.events[0]
    assert staged.canonical_bytes == admit_event.canonical_bytes
    assert staged.digest == admit_event.digest
    assert plan.admit_comparison_bindings == (("alt-model:1", comparison.comparison_digest),)


def test_governed_admit_without_evidence_rejected() -> None:
    seed_store = InMemoryRegistryStore()
    evidence = _build_governed_admit_evidence(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )
    auth = evidence.authorization

    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )

    admit_event = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=auth.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    with pytest.raises(
        AlternativeModelProjectionError,
        match="ALT_MODEL_PROJECTION_ADMIT_EVIDENCE_MISSING",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
        )


def test_governed_admit_source_digest_tamper_rejected() -> None:
    seed_store = InMemoryRegistryStore()
    auth, comparison = _build_governed_admit_with_comparison(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )

    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )

    tampered_admit = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=_digest("tampered-source"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(tampered_admit),
    )
    with pytest.raises(
        AlternativeModelProjectionError,
        match="ALT_MODEL_PROJECTION_ADMIT_SOURCE_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
            governed_admit_evidence=((auth, comparison),),
        )


def test_governed_admit_stale_root_rejected() -> None:
    """An authorization bound to root R1 is rejected when the predecessor store
    has a different root R2 (ROOT_MISMATCH)."""
    seed_store = InMemoryRegistryStore()
    auth, comparison = _build_governed_admit_with_comparison(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )

    # Different store with a different root (extra entity).
    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )
    _propose(store, model_id="alt-model:other", clock=1, expires=100)

    admit_event = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=auth.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    with pytest.raises(
        AlternativeModelProjectionError,
        match="ALT_MODEL_PROJECTION_ADMIT_ROOT_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
            governed_admit_evidence=((auth, comparison),),
        )


def test_non_admit_event_does_not_require_governed_evidence() -> None:
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    confirm_event = build_alternative_model_event(
        model_id=admitted.model_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(confirm_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    confirm_events = [
        event for event in plan.events if event.to_json_value()["payload"]["operation"] == "CONFIRM"
    ]
    assert len(confirm_events) == 1
    assert confirm_events[0].digest == confirm_event.digest


# ---------------------------------------------------------------------------
# Governed-ADMIT with comparison evidence
# ---------------------------------------------------------------------------


def test_governed_admit_with_comparison_evidence_accepted() -> None:
    """A staged ADMIT with governed authorization + comparison evidence is
    accepted when the comparison's structural-difference set matches."""
    seed_store = InMemoryRegistryStore()
    auth, comparison = _build_governed_admit_with_comparison(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )

    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )

    admit_event = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=auth.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
        governed_admit_evidence=((auth, comparison),),
    )

    assert len(plan.events) == 1
    assert plan.events[0].digest == admit_event.digest


def test_governed_admit_without_comparison_rejected() -> None:
    """ADMIT + authorization but no comparison receipt → fail closed."""
    seed_store = InMemoryRegistryStore()
    auth, _ = _build_governed_admit_with_comparison(
        seed_store, model_id="alt-model:1", clock=1, admit_clock=2
    )

    store = InMemoryRegistryStore()
    proposed = _propose(
        store,
        model_id="alt-model:1",
        clock=1,
        expires=100,
        graph_digest=auth.shadow_graph_digest,
        declared_difference_digest=auth.structural_difference_receipt.declared_difference_digest,
    )

    admit_event = build_alternative_model_event(
        model_id="alt-model:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=auth.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    with pytest.raises(
        AlternativeModelProjectionError,
        match="ALT_MODEL_PROJECTION_COMPARISON_MISSING",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
            governed_admit_evidence=cast(
                "tuple[tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...]",
                ((auth, None),),
            ),
        )


# ---------------------------------------------------------------------------
# Fault-injection / staging-store isolation
# ---------------------------------------------------------------------------


class _FaultingStore:
    """Wrap an InMemoryRegistryStore and fail on the Nth staging append."""

    def __init__(self, *, fail_on_append: int, skip_clone_appends: int = 0) -> None:
        self._inner = InMemoryRegistryStore()
        self._append_count = 0
        self._fail_on_append = fail_on_append
        self._skip_clone_appends = skip_clone_appends
        self._staging_append_count = 0

    def append(self, event: RegistryEvent) -> object:
        self._append_count += 1
        if self._append_count <= self._skip_clone_appends:
            return self._inner.append(event)
        self._staging_append_count += 1
        if self._staging_append_count == self._fail_on_append:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_STAGING_APPEND_FAULT")
        return self._inner.append(event)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def test_staging_append_fault_leaves_committed_store_byte_identical() -> None:
    store = InMemoryRegistryStore()
    p_a = _propose(store, model_id="alt-model:a", clock=1, expires=10)
    _admit(store, p_a, clock=2)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:a"), clock=3)
    p_b = _propose(store, model_id="alt-model:b", clock=4, expires=10)
    _admit(store, p_b, clock=5)
    _confirm(store, AlternativeModelRegistry(store).current("alt-model:b"), clock=6)

    original_root = store.snapshot("ALTERNATIVE_MODEL").root_digest
    original_snapshot = store.snapshot("ALTERNATIVE_MODEL")

    claim, validated_event, semantic = _context(20)

    faulting_store_holder: list[_FaultingStore | None] = [None]

    def _factory() -> RegistryStore:
        fs = _FaultingStore(fail_on_append=2, skip_clone_appends=6)
        faulting_store_holder[0] = fs
        return fs

    faulting_adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        staging_store_factory=_factory,
    )

    with pytest.raises(
        AlternativeModelProjectionError,
        match="ALT_MODEL_PROJECTION_STAGING_APPEND_FAULT",
    ):
        faulting_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("evidence-root"),
            assumption_root_digest=_digest("assumption-root"),
        )

    assert store.snapshot("ALTERNATIVE_MODEL").root_digest == original_root
    assert store.snapshot("ALTERNATIVE_MODEL").heads == original_snapshot.heads
    assert faulting_store_holder[0] is not None
    assert faulting_store_holder[0]._staging_append_count == 2

    healthy_adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
    )
    plan = healthy_adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    assert len(plan.events) == 2
    operations = [event.to_json_value()["payload"]["operation"] for event in plan.events]
    assert operations == ["EXPIRE", "EXPIRE"]
    assert plan.predecessor_root_digest == original_root


def test_impact_receipt_records_confirmed_to_challenged_transition() -> None:
    """A CHALLENGE on a CONFIRMED model records CONFIRMED -> CHALLENGED."""
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)
    confirmed = _confirm(store, admitted, clock=3)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    event = build_alternative_model_event(
        model_id=confirmed.model_id,
        entity_sequence=confirmed.current_entity_sequence + 1,
        previous_entity_event_digest=confirmed.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:transition",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _digest("challenge-receipt"),
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    impacts = [item for item in plan.impact_receipts if item.trigger_event_digest == event.digest]
    assert len(impacts) == 1
    assert impacts[0].previous_status == STANDING_CONFIRMED
    # CONFIRM -> CHALLENGE: standing becomes CHALLENGED.
    assert impacts[0].current_status == "CHALLENGED"


def test_expire_impact_receipt_carries_model_local_d4_surface() -> None:
    """A staged EXPIRE on an expirable ADMITTED/CONFIRMED model emits an
    ``AlternativeModelImpactReceipt`` carrying the previous/current status, the
    trigger event digest, the declared model-local D4 surface (scope, assumption,
    evidence identifiers), and the post-event D4 registry root."""
    store = InMemoryRegistryStore()
    proposed = _propose(store, model_id="alt-model:expire-impact", clock=1, expires=10)
    admitted = _admit(store, proposed, clock=2)
    confirmed = _confirm(store, admitted, clock=3)

    claim, validated_event, semantic = _context(20)
    source_digest = _projection_source(claim, validated_event, semantic)
    expire_event = build_alternative_model_event(
        model_id=confirmed.model_id,
        entity_sequence=confirmed.current_entity_sequence + 1,
        previous_entity_event_digest=confirmed.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=source_digest,
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:explicit",
            "expiry_receipt_digest": _digest("explicit-expiry-receipt"),
        },
    )

    adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(expire_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=_digest("evidence-root"),
        assumption_root_digest=_digest("assumption-root"),
    )

    # The explicit EXPIRE makes the model EXPIRED, which suppresses any planned
    # expiry, so there is exactly one staged event and one impact receipt.
    assert len(plan.events) == 1
    assert plan.events[0].digest == expire_event.digest

    impacts = [
        item for item in plan.impact_receipts if item.trigger_event_digest == expire_event.digest
    ]
    assert len(impacts) == 1
    receipt = impacts[0]
    assert receipt.previous_status == STANDING_CONFIRMED
    assert receipt.current_status == "EXPIRED"
    assert receipt.trigger_event_digest == expire_event.digest
    assert receipt.scope_ids == ("scope:control-17",)
    assert receipt.assumption_ids == ()
    assert receipt.evidence_ids == ()
    # Post-event D4 root captured immediately after the EXPIRE was applied.
    assert receipt.alternative_model_registry_root_digest == plan.projected_root_digest
