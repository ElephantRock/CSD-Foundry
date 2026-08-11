"""Full isolation qualification for staged assumption projection (P3.2)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import cast

import pytest

from csd_foundry.governance.v0_5._assumption_dependency_validator import (
    DependencyValidationReceipt,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
)
from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionExpiryAuthorization,
    AssumptionExpiryPlanner,
    AssumptionProjectionError,
    AssumptionProjectionPlan,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5._governed_admit_append import (
    GovernedAdmitAuthorization,
    append_governed_admit_assumption,
)
from csd_foundry.governance.v0_5.assumption import (
    DERIVED_CHALLENGED,
    STANDING_ADMITTED,
    STANDING_EXPIRED,
    Assumption,
    AssumptionRegistry,
    build_assumption_event,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
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
    """Deterministic expiry authority for tests.

    Returns a self-digesting :class:`AssumptionExpiryAuthorization` per
    assumption so the planner never invents authority/receipt strings.
    """

    def __init__(self, *, authority_id: str = "authority:clock") -> None:
        self._authority_id = authority_id

    @property
    def expiry_authority_id(self) -> str:
        return self._authority_id

    def expiry_authorization(
        self, *, assumption_id: str, clock_sequence: int
    ) -> AssumptionExpiryAuthorization | None:
        return AssumptionExpiryAuthorization.build(
            assumption_id=assumption_id,
            clock_sequence=clock_sequence,
            expiry_authority_id=self._authority_id,
            expiry_receipt_digest=_digest(f"expiry:{assumption_id}:{clock_sequence}"),
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


def _assumption_policy_ledger(
    *,
    authority_id: str,
    scope_ids: tuple[str, ...],
) -> AssumptionPolicyLedgerV3:
    """Build a minimal V3 policy ledger that grants one authority an ADMIT grant
    over the supplied scopes.

    Reuses the scaffolding from ``test_v0_5_governed_admit_append`` so a real
    governed ADMIT append (I1-A/I1-B/I1-C) can run in-projection tests.
    """

    approval_policy = AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:assumptions:1",
        authority_root_digest=_digest("root"),
        rules=(
            AssumptionPolicyApprovalRule.build(
                approval_class="STANDARD",
                eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
                required_signature_count=2,
                required_signer_ids=("authority:a",),
            ),
            AssumptionPolicyApprovalRule.build(
                approval_class="DUTY_EXCEPTION",
                eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
                required_signature_count=3,
                required_signer_ids=("authority:a",),
            ),
        ),
    )
    signature_profile = AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ed25519",
                verification_profile="ed25519-rfc8032-strict/1",
            ),
        ),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("root"),
    )
    challenge_policy = AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="PROVENANCE_CONFLICT",
                materiality="MATERIAL",
            ),
        )
    )
    grant = AssumptionAuthorityGrant.build(
        grant_id="grant:admit",
        action="ADMIT",
        authority_id=authority_id,
        scope_ids=scope_ids,
        assumption_materialities=("MATERIAL",),
        effective_from_sequence=1,
    )
    policy = AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=_digest("root"),
        grants=(grant,),
    )
    payload = AssumptionPolicySigningPayload.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=1,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
    )
    commit = AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=_digest("sigset"),
    )
    rule = approval_policy.rule_for(payload.approval_class)
    proof = AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=payload.signing_payload_digest,
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=approval_policy.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=signature_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        authority_root_digest=payload.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )
    entry = AssumptionPolicyLedgerEntryV3.build(
        policy=policy,
        signing_payload=payload,
        policy_commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_classification_policy=challenge_policy,
        activation_proof=proof,
    )
    return AssumptionPolicyLedgerV3.build((entry,))


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


def test_committed_root_unchanged_after_admit_binding_failure() -> None:
    """A staged ADMIT event whose source/admission digest does not match the
    supplied governed authorization is rejected fail-closed, leaving the
    committed store byte-identical.

    Uses the SAME store that generated the governed evidence, so that the
    predecessor binding is correct; only the source receipt is tampered.
    """

    store = InMemoryRegistryStore()
    governed = _build_governed_admit_evidence(
        store,
        candidate_id="assumption:1",
        clock=1,
        admit_clock=2,
    )
    # The governed ADMIT was already applied to the seed store. We need to
    # work against a store with only the PROPOSE. Clone a fresh store with
    # just the PROPOSE event from the governed evidence.
    propose_store = InMemoryRegistryStore()
    proposed = _propose(propose_store, assumption_id="assumption:1", clock=1, expires=100)
    original_root = propose_store.snapshot("ASSUMPTION").root_digest

    # Build an ADMIT event with a tampered source digest.
    tampered_admit = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=_digest("tampered-source"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": governed.authorization.admitting_authority_id,
            "admission_receipt_digest": governed.authorization.authorization_digest,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(tampered_admit),
    )

    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_ADMIT_SOURCE_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=propose_store,
            evidence_root_digest=governed.evidence_root,
            governed_evidence=(governed.authorization,),
        )

    assert propose_store.snapshot("ASSUMPTION").root_digest == original_root


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
        clock_sequence=2,
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
# Governed-ADMIT binding preservation (production-shaped)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GovernedAdmitEvidence:
    """Real production evidence produced by a governed ADMIT append."""

    authorization: GovernedAdmitAuthorization
    dependency_receipt: DependencyValidationReceipt
    evidence_root: str
    assumption_root_pre_admit: str
    predecessor_event_digest: str
    assumption_id: str


def _build_governed_admit_evidence(
    store: RegistryStore,
    *,
    candidate_id: str,
    clock: int,
    admit_clock: int,
    proposition_id: str = "proposition:control-connected",
    scope_ids: tuple[str, ...] = ("scope:control-17",),
    proposer_authority_id: str = "authority:proposer",
    admitting_authority_id: str = "authority:admitter",
) -> _GovernedAdmitEvidence:
    """Run a real governed ADMIT append and return its production evidence.

    Seeds the candidate PROPOSE against the supplied store, runs the full
    governed ADMIT orchestrator (I1-A/I1-B/I1-C), and returns the resulting
    :class:`GovernedAdmitAuthorization` plus its embedded
    :class:`DependencyValidationReceipt`, plus the snapshot roots observed at
    admission time. The projection adapter uses these to validate production-
    shaped ADMIT bindings.
    """

    # Seed the PROPOSE against the caller's store so its assumption root and
    # candidate predecessor are observable to the orchestrator.
    propose = build_assumption_event(
        assumption_id=candidate_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{candidate_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": proposition_id,
            "scope_ids": list(scope_ids),
            "materiality": "MATERIAL",
            "proposer_authority_id": proposer_authority_id,
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": ["limitation:declared-model"],
            "maximum_reuse_class": "D2",
        },
    )
    AssumptionRegistry(store).apply(propose)
    propose_state = AssumptionRegistry(store).current(candidate_id)
    assert propose_state is not None

    assumption_root_pre_admit = store.snapshot("ASSUMPTION").root_digest

    ledger = _assumption_policy_ledger(
        authority_id=admitting_authority_id,
        scope_ids=scope_ids,
    )
    result = append_governed_admit_assumption(
        store=store,
        ledger=ledger,
        assumption_id=candidate_id,
        admitting_authority_id=admitting_authority_id,
        event_sequence=admit_clock,
    )
    assert result.applied is True
    return _GovernedAdmitEvidence(
        authorization=result.authorization,
        dependency_receipt=result.authorization.dependency_validation_receipt,
        evidence_root=result.evidence_registry_root,
        assumption_root_pre_admit=assumption_root_pre_admit,
        predecessor_event_digest=propose_state.current_event_digest,
        assumption_id=candidate_id,
    )


def test_governed_admit_bindings_preserved_on_staged_admit() -> None:
    """A staged ADMIT event built from a real :class:`GovernedAdmitAuthorization`
    is validated against the production cross-bindings and preserved exactly in
    the staged plan.

    Production shape:

    * ``event.source_receipt_digest == dependency_receipt.receipt_digest``
    * ``payload.admission_receipt_digest == authorization.authorization_digest``
    """

    seed_store = InMemoryRegistryStore()
    governed = _build_governed_admit_evidence(
        seed_store,
        candidate_id="assumption:1",
        clock=1,
        admit_clock=2,
    )
    auth = governed.authorization
    dep_receipt = governed.dependency_receipt

    # Production-shaped committed store: only the PROPOSE is present.
    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)

    admit_event = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,  # MUST match auth.event_sequence
        source_receipt_digest=dep_receipt.receipt_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
            "admission_receipt_digest": auth.authorization_digest,
        },
    )

    claim, validated_event, semantic = _context(2)  # same clock as auth
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    plan: AssumptionProjectionPlan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=governed.evidence_root,
        governed_evidence=(auth,),
    )

    assert len(plan.events) == 1
    staged = plan.events[0]
    staged_value = staged.to_json_value()
    assert staged_value["source_receipt_digest"] == dep_receipt.receipt_digest
    assert staged_value["payload"]["admission_receipt_digest"] == auth.authorization_digest
    assert staged_value["payload"]["admitting_authority_id"] == auth.admitting_authority_id
    assert staged.canonical_bytes == admit_event.canonical_bytes
    assert staged.digest == admit_event.digest
    # The explicitly-supplied evidence root is bound into the plan receipt.
    assert plan.evidence_root_digest == governed.evidence_root


def test_governed_admit_admission_receipt_tamper_rejected() -> None:
    """A staged ADMIT whose ``admission_receipt_digest`` does not match the
    authorization digest is rejected fail-closed."""

    governed = _build_governed_admit_evidence(
        InMemoryRegistryStore(),
        candidate_id="assumption:1",
        clock=1,
        admit_clock=2,
    )
    auth = governed.authorization
    dep_receipt = governed.dependency_receipt

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)

    tampered_admit = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=dep_receipt.receipt_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
            "admission_receipt_digest": _digest("forged-admission"),
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(tampered_admit),
    )
    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_ADMISSION_RECEIPT_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=governed.evidence_root,
            governed_evidence=(auth,),
        )


def test_governed_admit_without_evidence_rejected() -> None:
    """A staged ADMIT with no matching governed authorization is rejected
    fail-closed (the adapter does not invent production bindings)."""

    governed = _build_governed_admit_evidence(
        InMemoryRegistryStore(),
        candidate_id="assumption:1",
        clock=1,
        admit_clock=2,
    )
    auth = governed.authorization
    dep_receipt = governed.dependency_receipt

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)

    admit_event = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=dep_receipt.receipt_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
            "admission_receipt_digest": auth.authorization_digest,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_ADMIT_EVIDENCE_MISSING",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=governed.evidence_root,
        )


def test_governed_admit_evidence_root_mismatch_rejected() -> None:
    """If a governed authorization's ``evidence_registry_root`` does not equal
    the explicitly-supplied ``evidence_root_digest`` the projection is rejected."""

    governed = _build_governed_admit_evidence(
        InMemoryRegistryStore(),
        candidate_id="assumption:1",
        clock=1,
        admit_clock=2,
    )
    auth = governed.authorization
    dep_receipt = governed.dependency_receipt

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)

    admit_event = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proposed.current_entity_sequence + 1,
        previous_entity_event_digest=proposed.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=dep_receipt.receipt_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": auth.admitting_authority_id,
            "admission_receipt_digest": auth.authorization_digest,
        },
    )

    claim, validated_event, semantic = _context(2)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(admit_event),
    )
    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_EVIDENCE_ROOT_MISMATCH",
    ):
        adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=_digest("mismatched-evidence-root"),
            governed_evidence=(auth,),
        )


def test_non_admit_event_does_not_require_governed_evidence() -> None:
    """Non-ADMIT explicit events skip the ADMIT-specific binding validation
    even when no governed evidence is supplied (and even with a non-projection
    source digest, mirroring production operation-specific receipts)."""

    store = InMemoryRegistryStore()
    proposed = _propose(store, assumption_id="assumption:1", clock=1, expires=100)
    admitted = _admit(store, proposed, clock=2)

    # Source digest is the operation-specific confirmation receipt, not the
    # generic ASSUMPTION_PROJECTION_SOURCE — the adapter no longer requires that.
    confirm_event = build_assumption_event(
        assumption_id=admitted.assumption_id,
        entity_sequence=admitted.current_entity_sequence + 1,
        previous_entity_event_digest=admitted.current_event_digest,
        clock_sequence=20,
        source_receipt_digest=_digest("confirm:operation-specific"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _digest("confirm-receipt"),
        },
    )

    claim, validated_event, semantic = _context(20)
    adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        intent_resolver=_IntentResolver(confirm_event),
    )
    plan = adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    confirm_events = [
        event for event in plan.events if event.to_json_value()["payload"]["operation"] == "CONFIRM"
    ]
    assert len(confirm_events) == 1
    assert confirm_events[0].digest == confirm_event.digest


# ---------------------------------------------------------------------------
# Fault-injection / staging-store isolation
# ---------------------------------------------------------------------------


class _FaultingStore:
    """Wrap an :class:`InMemoryRegistryStore` and fail on the Nth append AFTER
    a specified clone-load count.

    Used to prove that a mid-staging fault leaves the committed store
    byte-identical and yields no projection plan. The ``skip_clone_appends``
    parameter specifies how many appends are clone-loading (pre-staging) and
    should not be faulted.
    """

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
            raise AssumptionProjectionError("ASSUMPTION_PROJECTION_STAGING_APPEND_FAULT")
        return self._inner.append(event)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def test_staging_append_fault_leaves_committed_store_byte_identical() -> None:
    """A fault on the Nth post-clone staging append raises, leaves the committed
    store byte-identical, and produces no projection plan. Rerunning from the
    same predecessor without the fault yields the canonical successful plan.

    Four committed events are cloned first (PROPOSE+ADMIT x2). Then two planned
    EXPIRE events are staged. The fault fires on the 2nd staging append (the
    2nd EXPIRE), proving one staged event succeeded before the fault.
    """

    store = InMemoryRegistryStore()
    p_a = _propose(store, assumption_id="assumption:a", clock=1, expires=10)
    _admit(store, p_a, clock=2)
    p_b = _propose(store, assumption_id="assumption:b", clock=3, expires=10)
    _admit(store, p_b, clock=4)

    original_root = store.snapshot("ASSUMPTION").root_digest
    original_snapshot = store.snapshot("ASSUMPTION")

    claim, validated_event, semantic = _context(20)

    faulting_store_holder: list[_FaultingStore | None] = [None]

    def _factory() -> RegistryStore:
        fs = _FaultingStore(fail_on_append=2, skip_clone_appends=4)
        faulting_store_holder[0] = fs
        return fs

    faulting_adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
        staging_store_factory=_factory,
    )

    with pytest.raises(
        AssumptionProjectionError,
        match="ASSUMPTION_PROJECTION_STAGING_APPEND_FAULT",
    ):
        faulting_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            committed_store=store,
            evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
        )

    # Committed head/root is byte-identical before and after.
    assert store.snapshot("ASSUMPTION").root_digest == original_root
    assert store.snapshot("ASSUMPTION").heads == original_snapshot.heads

    # The faulting store must have observed at least one successful staging
    # append before the fault (proving the fault is post-clone, during staging).
    assert faulting_store_holder[0] is not None
    assert faulting_store_holder[0]._staging_append_count == 2  # faulted on 2nd
    assert faulting_store_holder[0]._append_count == 6  # 4 clone + 2 staging

    # Rerun from the same predecessor without the fault: canonical success.
    healthy_adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticExpiryAuthority(),
    )
    plan = healthy_adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=store,
        evidence_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
    )

    assert len(plan.events) == 2
    operations = [event.to_json_value()["payload"]["operation"] for event in plan.events]
    assert operations == ["EXPIRE", "EXPIRE"]
    assert plan.predecessor_root_digest == original_root


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
