"""Tests for the frozen assumption use-time admissibility evaluator (D3.2-B).

Covers the 24 semantic cases: standing/challenge/temporal/dependency/evidence
gates, deterministic replay, no-mutation proofs, root-drift / substitution
hardening, and receipt-level tamper rejection.

Uses InMemoryRegistryStore + AssumptionRegistry/EvidenceRegistry to build
multi-entity assumption graphs and evidence in various A0 states, then binds
them under a DecisionAssumptionBinding and evaluates use-time admissibility.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionGovernanceContractError,
    DecisionAssumptionBinding,
)
from csd_foundry.governance.v0_5._assumption_use_admissibility import (
    UseAdmissibilityError,
    evaluate_assumption_use_admissibility,
)
from csd_foundry.governance.v0_5.assumption import (
    AssumptionRegistry,
    build_assumption_event,
)
from csd_foundry.governance.v0_5.evidence import (
    EvidenceRegistry,
    build_evidence_event,
)
from csd_foundry.governance.v0_5.evidence_governance import (
    ChallengeMaterialityRule,
    EvidenceAdmissibilityEvaluator,
    EvidenceAuthorityGrant,
    EvidenceAuthorityPolicy,
    EvidenceChallengePolicy,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore

# --------------------------------------------------------------------------- #
# Digest helper
# --------------------------------------------------------------------------- #


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Assumption lifecycle event builders
# --------------------------------------------------------------------------- #


def _propose_event(
    *,
    assumption_id: str = "assumption:candidate",
    clock: int = 10,
    assumption_deps: list[str] | None = None,
    evidence_deps: list[str] | None = None,
    expires: int | None = 100,
) -> object:
    """Build a genesis PROPOSE event with specific dependency IDs."""
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{assumption_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:1",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": assumption_deps or [],
            "evidence_dependency_ids": evidence_deps or [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _next_assumption_event(
    registry: AssumptionRegistry,
    assumption_id: str,
    *,
    operation: str,
    extra_payload: dict[str, object],
    clock: int | None = None,
    seed: str | None = None,
) -> object:
    """Build the next event in an assumption's chain, derived from current state."""
    current = registry.current(assumption_id)
    assert current is not None, f"assumption {assumption_id} must exist"
    next_clock = clock if clock is not None else current.last_clock_sequence + 1
    s = seed if seed is not None else f"{assumption_id}:{operation}:{next_clock}"
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=current.current_entity_sequence + 1,
        previous_entity_event_digest=current.current_event_digest,
        clock_sequence=next_clock,
        source_receipt_digest=_digest(s),
        payload={"operation": operation, **extra_payload},
    )


def _admit(
    registry: AssumptionRegistry,
    assumption_id: str,
    *,
    clock: int | None = None,
) -> object:
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="ADMIT",
        extra_payload={
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _digest(f"admit:{assumption_id}"),
        },
        clock=clock,
    )


def _reject(
    registry: AssumptionRegistry,
    assumption_id: str,
    *,
    clock: int | None = None,
) -> object:
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="REJECT",
        extra_payload={
            "rejecting_authority_id": "authority:rejector",
            "rejection_receipt_digest": _digest(f"reject:{assumption_id}"),
            "reason_code": "reason:reject",
        },
        clock=clock,
    )


def _expire(
    registry: AssumptionRegistry,
    assumption_id: str,
    *,
    clock: int | None = None,
) -> object:
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="EXPIRE",
        extra_payload={
            "expiry_authority_id": "authority:expiry",
            "expiry_receipt_digest": _digest(f"expire:{assumption_id}"),
        },
        clock=clock,
    )


def _supersede(
    registry: AssumptionRegistry,
    assumption_id: str,
    replacement_id: str,
    *,
    clock: int | None = None,
) -> object:
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="SUPERSEDE",
        extra_payload={
            "replacement_assumption_id": replacement_id,
            "superseding_authority_id": "authority:superseder",
            "supersession_receipt_digest": _digest(f"supersede:{assumption_id}"),
            "reason_code": "reason:supersede",
        },
        clock=clock,
    )


def _challenge(
    registry: AssumptionRegistry,
    assumption_id: str,
    challenge_id: str = "challenge:1",
    *,
    clock: int | None = None,
) -> object:
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="CHALLENGE",
        extra_payload={
            "challenge_id": challenge_id,
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:challenge",
            "challenge_receipt_digest": _digest(f"challenge:{assumption_id}:{challenge_id}"),
        },
        clock=clock,
    )


def _resolve_challenges(
    registry: AssumptionRegistry,
    assumption_id: str,
    *,
    outcome: str = "RETURN_TO_ADMITTED",
    resolved_challenge_ids: list[str] | None = None,
    replacement_assumption_id: str | None = None,
    clock: int | None = None,
) -> object:
    current = registry.current(assumption_id)
    assert current is not None
    if resolved_challenge_ids is None:
        resolved_challenge_ids = list(current.active_challenge_ids)
    return _next_assumption_event(
        registry,
        assumption_id,
        operation="RESOLVE_CHALLENGES",
        extra_payload={
            "resolution_outcome": outcome,
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest(f"resolve:{assumption_id}"),
            "resolution_basis_code": "basis:resolution",
            "resolved_challenge_ids": resolved_challenge_ids,
            "replacement_assumption_id": replacement_assumption_id,
        },
        clock=clock,
    )


# --------------------------------------------------------------------------- #
# Evidence helpers
# --------------------------------------------------------------------------- #


def _register_evidence(
    evidence_id: str,
    *,
    clock: int = 1,
    scope_ids: list[str] | None = None,
    proposition_id: str = "proposition:1",
    expires_at_sequence: int | None = 100,
    valid_from_sequence: int | None = None,
    maximum_reuse_class: str = "D2",
    dependency_ids: list[str] | None = None,
) -> object:
    scope = scope_ids if scope_ids is not None else ["scope:control"]
    vfr = valid_from_sequence if valid_from_sequence is not None else clock
    return build_evidence_event(
        evidence_id=evidence_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"register:{evidence_id}"),
        payload={
            "operation": "REGISTER",
            "proposition_id": proposition_id,
            "scope_ids": scope,
            "source_id": f"assessment:{evidence_id}",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": clock,
            "valid_from_sequence": vfr,
            "expires_at_sequence": expires_at_sequence,
            "dependency_ids": dependency_ids or [],
            "limitations": [],
            "maximum_reuse_class": maximum_reuse_class,
        },
    )


def _add_verified_evidence(
    store: InMemoryRegistryStore,
    evidence_id: str,
    *,
    expires_at_sequence: int | None = 100,
    valid_from_sequence: int | None = None,
    scope_ids: list[str] | None = None,
    maximum_reuse_class: str = "D2",
) -> None:
    """Add REGISTER + VERIFY evidence to the store."""
    registry = EvidenceRegistry(store)
    reg = _register_evidence(
        evidence_id,
        expires_at_sequence=expires_at_sequence,
        valid_from_sequence=valid_from_sequence,
        scope_ids=scope_ids,
        maximum_reuse_class=maximum_reuse_class,
    )
    proj = registry.apply(reg)
    ver = build_evidence_event(
        evidence_id=proj.evidence_id,
        entity_sequence=proj.current_entity_sequence + 1,
        previous_entity_event_digest=proj.current_event_digest,
        clock_sequence=proj.last_clock_sequence + 1,
        source_receipt_digest=_digest(f"verify:{evidence_id}"),
        payload={"operation": "VERIFY", "verifier_authority_id": "authority:verifier"},
    )
    registry.apply(ver)


def _add_invalidated_evidence(
    store: InMemoryRegistryStore,
    evidence_id: str,
) -> None:
    """Add REGISTER + VERIFY + INVALIDATE evidence to the store."""
    registry = EvidenceRegistry(store)
    reg = _register_evidence(evidence_id)
    proj = registry.apply(reg)
    ver = build_evidence_event(
        evidence_id=proj.evidence_id,
        entity_sequence=proj.current_entity_sequence + 1,
        previous_entity_event_digest=proj.current_event_digest,
        clock_sequence=proj.last_clock_sequence + 1,
        source_receipt_digest=_digest(f"verify:{evidence_id}"),
        payload={"operation": "VERIFY", "verifier_authority_id": "authority:verifier"},
    )
    proj2 = registry.apply(ver)
    inv = build_evidence_event(
        evidence_id=proj2.evidence_id,
        entity_sequence=proj2.current_entity_sequence + 1,
        previous_entity_event_digest=proj2.current_event_digest,
        clock_sequence=proj2.last_clock_sequence + 1,
        source_receipt_digest=_digest(f"invalidate:{evidence_id}"),
        payload={
            "operation": "INVALIDATE",
            "invalidating_authority_id": "authority:resolver",
            "reason_code": "reason:invalidate",
        },
    )
    registry.apply(inv)


# --------------------------------------------------------------------------- #
# Policy builders
# --------------------------------------------------------------------------- #


def _authority_policy(*, committed_at_sequence: int = 0) -> EvidenceAuthorityPolicy:
    grants = (
        # REGISTER/VERIFY use empty scope (== all scopes) so evidence may be
        # registered under any scope; the per-request scope check is exercised
        # separately by the evidence evaluator.
        EvidenceAuthorityGrant("REGISTER", "authority:issuer", ()),
        EvidenceAuthorityGrant("VERIFY", "authority:verifier", ()),
        EvidenceAuthorityGrant("REJECT", "authority:rejector", ()),
        EvidenceAuthorityGrant("CHALLENGE", "authority:challenger", ()),
        EvidenceAuthorityGrant("RESOLVE_CHALLENGE", "authority:resolver", ()),
        EvidenceAuthorityGrant("EXPIRE", "authority:expiry", ()),
        EvidenceAuthorityGrant("INVALIDATE", "authority:resolver", ()),
        EvidenceAuthorityGrant("SUPERSEDE", "authority:superseder", ()),
    )
    return EvidenceAuthorityPolicy.build(
        policy_id="policy:evidence-v1",
        committed_at_sequence=committed_at_sequence,
        authority_root_digest=_digest("authority-root"),
        grants=grants,
    )


def _challenge_policy() -> EvidenceChallengePolicy:
    return EvidenceChallengePolicy.build(
        (ChallengeMaterialityRule("reason:challenge", "MATERIAL"),)
    )


# --------------------------------------------------------------------------- #
# Binding + evaluation harness
# --------------------------------------------------------------------------- #


def _build_binding(
    store: InMemoryRegistryStore,
    *,
    decision_id: str = "decision:release",
    clock: int = 15,
    required_assumption_ids: tuple[str, ...] = ("assumption:candidate",),
) -> DecisionAssumptionBinding:
    return DecisionAssumptionBinding.build(
        decision_id=decision_id,
        validated_event_digest=_digest("event"),
        semantic_projection_receipt_digest=_digest("sem"),
        control_state_digest=_digest("ctrl"),
        assumption_registry_root=store.snapshot("ASSUMPTION").root_digest,
        evidence_registry_root=store.snapshot("EVIDENCE_UNIT").root_digest,
        logical_clock_sequence=clock,
        required_assumption_ids=required_assumption_ids,
    )


def _build_evaluator(store: InMemoryRegistryStore) -> EvidenceAdmissibilityEvaluator:
    return EvidenceAdmissibilityEvaluator(store, _authority_policy(), _challenge_policy())


def _admitted_candidate(
    store: InMemoryRegistryStore,
    *,
    candidate_id: str = "assumption:candidate",
    propose_clock: int = 10,
    admit_clock: int = 11,
    expires: int | None = 100,
    assumption_deps: list[str] | None = None,
    evidence_deps: list[str] | None = None,
) -> AssumptionRegistry:
    """Build a store with the candidate PROPOSEd + ADMITTed."""
    registry = AssumptionRegistry(store)
    registry.apply(
        _propose_event(
            assumption_id=candidate_id,
            clock=propose_clock,
            assumption_deps=assumption_deps,
            evidence_deps=evidence_deps,
            expires=expires,
        )
    )
    registry.apply(_admit(registry, candidate_id, clock=admit_clock))
    return registry


# --------------------------------------------------------------------------- #
# Cases 1-7: standing / challenge gates
# --------------------------------------------------------------------------- #


def test_01_admitted_no_deps_no_challenges_allows() -> None:
    """Valid ADMITTED assumption, no deps, no challenges -> ALLOW."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    assert len(decision.evaluated_assumptions) == 1
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert ev.validation_code == "ASSUMPTION_USE_ALLOWED"
    assert ev.self_state.standing == "ADMITTED"
    assert ev.traversed_dependencies == ()
    assert ev.cycle_witness == ()


def test_02_never_admitted_proposed_only_denies() -> None:
    """Never-admitted (PROPOSED only) -> DENY (ASSUMPTION_USE_NOT_ADMITTED)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event())
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_NOT_ADMITTED"


def test_03_rejected_assumption_denies() -> None:
    """Rejected assumption -> DENY (ASSUMPTION_USE_TERMINAL)."""
    store = InMemoryRegistryStore()
    registry = _admitted_candidate(store)
    registry.apply(_reject(registry, "assumption:candidate", clock=12))
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"


def test_04_expired_assumption_denies() -> None:
    """Expired assumption (standing=EXPIRED via lifecycle EXPIRE) -> DENY (TERMINAL)."""
    store = InMemoryRegistryStore()
    registry = _admitted_candidate(store, expires=20)
    # EXPIRE requires clock >= expires_at_sequence.
    registry.apply(_expire(registry, "assumption:candidate", clock=20))
    binding = _build_binding(store, clock=15)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"


def test_05_superseded_assumption_denies() -> None:
    """Superseded assumption -> DENY (ASSUMPTION_USE_TERMINAL)."""
    store = InMemoryRegistryStore()
    registry = _admitted_candidate(store)
    # SUPERSEDE references a replacement assumption id (need not exist for the lifecycle).
    registry.apply(_supersede(registry, "assumption:candidate", "assumption:replacement", clock=12))
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"


def test_06_active_challenge_denies() -> None:
    """Active challenge on an ADMITTED assumption -> DENY (ASSUMPTION_USE_CHALLENGED)."""
    store = InMemoryRegistryStore()
    registry = _admitted_candidate(store)
    registry.apply(_challenge(registry, "assumption:candidate", clock=12))
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_CHALLENGED"


def test_07_challenge_resolved_returns_to_admitted_allows() -> None:
    """Challenge opened then resolved -> ADMITTED -> ALLOW."""
    store = InMemoryRegistryStore()
    registry = _admitted_candidate(store)
    registry.apply(_challenge(registry, "assumption:candidate", clock=12))
    registry.apply(
        _resolve_challenges(
            registry, "assumption:candidate", outcome="RETURN_TO_ADMITTED", clock=13
        )
    )
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert ev.validation_code == "ASSUMPTION_USE_ALLOWED"


# --------------------------------------------------------------------------- #
# Cases 8-11: dependency gates
# --------------------------------------------------------------------------- #


def test_08_missing_top_level_assumption_denies() -> None:
    """Missing required top-level assumption -> DENY (ASSUMPTION_USE_MISSING)."""
    store = InMemoryRegistryStore()
    # Build a binding whose required id was never proposed.
    binding = _build_binding(
        store, required_assumption_ids=("assumption:candidate", "assumption:phantom")
    )
    # Put the candidate in the store AFTER computing the binding roots — rebind to current roots.
    _admitted_candidate(store)
    binding = _build_binding(
        store, required_assumption_ids=("assumption:candidate", "assumption:phantom")
    )
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    # Both assumptions are evaluated (no fail-fast across top-level).
    codes = {ev.assumption_id: ev.validation_code for ev in decision.evaluated_assumptions}
    assert codes["assumption:candidate"] == "ASSUMPTION_USE_ALLOWED"
    assert codes["assumption:phantom"] == "ASSUMPTION_USE_MISSING"


def test_09_missing_assumption_dependency_denies() -> None:
    """Missing assumption dependency -> DENY (ASSUMPTION_USE_DEPENDENCY_MISSING)."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, assumption_deps=["assumption:dep-missing"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_DEPENDENCY_MISSING"


def test_10_cyclic_dependency_denies() -> None:
    """Cyclic dependency (A→B→A) -> DENY (ASSUMPTION_USE_DEPENDENCY_CYCLE)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # Propose B depending on A; propose A depending on B; admit both.
    registry.apply(
        _propose_event(assumption_id="assumption:b", clock=5, assumption_deps=["assumption:a"])
    )
    registry.apply(
        _propose_event(assumption_id="assumption:a", clock=10, assumption_deps=["assumption:b"])
    )
    registry.apply(_admit(registry, "assumption:b", clock=6))
    registry.apply(_admit(registry, "assumption:a", clock=11))
    binding = _build_binding(store, required_assumption_ids=("assumption:a",))
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_DEPENDENCY_CYCLE"
    assert ev.cycle_witness != ()
    assert ev.cycle_witness[0] == ev.cycle_witness[-1]


def test_11_dependency_terminalized_denies_inherited() -> None:
    """Dependency that was ADMITTED, now REJECTED -> DENY (inherited TERMINAL)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    registry.apply(_reject(registry, "assumption:dep", clock=7))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"


# --------------------------------------------------------------------------- #
# Cases 12-14: temporal validity
# --------------------------------------------------------------------------- #


def test_12_clock_expiry_denies() -> None:
    """ADMITTED but logical_clock >= expires_at_sequence -> DENY (EXPIRED)."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, expires=20)
    binding = _build_binding(store, clock=25)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_EXPIRED"


def test_13_not_yet_valid_denies() -> None:
    """logical_clock < valid_from_sequence -> DENY (NOT_YET_VALID)."""
    store = InMemoryRegistryStore()
    # valid_from_sequence is set to the propose clock. Use a high clock on the assumption.
    registry = AssumptionRegistry(store)
    registry.apply(
        build_assumption_event(
            assumption_id="assumption:candidate",
            entity_sequence=1,
            previous_entity_event_digest=None,
            clock_sequence=50,
            source_receipt_digest=_digest("propose:future"),
            payload={
                "operation": "PROPOSE",
                "proposition_id": "proposition:1",
                "scope_ids": ["scope:control"],
                "materiality": "MATERIAL",
                "proposer_authority_id": "authority:proposer",
                "proposed_at_sequence": 50,
                "valid_from_sequence": 50,
                "expires_at_sequence": 100,
                "assumption_dependency_ids": [],
                "evidence_dependency_ids": [],
                "limitations": [],
                "maximum_reuse_class": "D2",
            },
        )
    )
    registry.apply(_admit(registry, "assumption:candidate", clock=51))
    binding = _build_binding(store, clock=15)  # 15 < 50
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_NOT_YET_VALID"


def test_14_temporally_invalid_transitive_dependency_denies() -> None:
    """Transitive dependency whose valid_from > clock -> DENY (inherited)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # dep has valid_from = 50 (far future).
    registry.apply(
        build_assumption_event(
            assumption_id="assumption:dep",
            entity_sequence=1,
            previous_entity_event_digest=None,
            clock_sequence=50,
            source_receipt_digest=_digest("propose:dep-future"),
            payload={
                "operation": "PROPOSE",
                "proposition_id": "proposition:1",
                "scope_ids": ["scope:control"],
                "materiality": "MATERIAL",
                "proposer_authority_id": "authority:proposer",
                "proposed_at_sequence": 50,
                "valid_from_sequence": 50,
                "expires_at_sequence": 100,
                "assumption_dependency_ids": [],
                "evidence_dependency_ids": [],
                "limitations": [],
                "maximum_reuse_class": "D2",
            },
        )
    )
    registry.apply(_admit(registry, "assumption:dep", clock=51))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store, clock=15)  # 15 < dep.valid_from (50)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_NOT_YET_VALID"


# --------------------------------------------------------------------------- #
# Case 15: evidence invalidated after admission
# --------------------------------------------------------------------------- #


def test_15_evidence_invalidated_after_admission_denies() -> None:
    """Evidence invalidated after admission -> DENY (D2 code from evidence evaluator)."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:dep"])
    _add_invalidated_evidence(store, "evidence:dep")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    # The evidence evaluator returns its status-inadmissible code (D2 vocabulary).
    assert ev.validation_code.startswith("EVIDENCE_")


# --------------------------------------------------------------------------- #
# Cases 16-18: determinism + no-mutation
# --------------------------------------------------------------------------- #


def test_16_deterministic_replay_byte_identical() -> None:
    """Repeated evaluation produces a byte-identical decision_digest."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    d1 = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    d2 = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert d1.decision_digest == d2.decision_digest
    assert d1.canonical_bytes == d2.canonical_bytes


def test_17_zero_mutation_on_allow_roots_unchanged() -> None:
    """ALLOW leaves registry roots unchanged."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    assumption_root_before = store.snapshot("ASSUMPTION").root_digest
    evidence_root_before = store.snapshot("EVIDENCE_UNIT").root_digest
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    assert store.snapshot("ASSUMPTION").root_digest == assumption_root_before
    assert store.snapshot("EVIDENCE_UNIT").root_digest == evidence_root_before
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_18_zero_mutation_on_deny_roots_unchanged() -> None:
    """DENY leaves registry roots unchanged."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event())  # never admitted
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    assumption_root_before = store.snapshot("ASSUMPTION").root_digest
    evidence_root_before = store.snapshot("EVIDENCE_UNIT").root_digest

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    assert store.snapshot("ASSUMPTION").root_digest == assumption_root_before
    assert store.snapshot("EVIDENCE_UNIT").root_digest == evidence_root_before


# --------------------------------------------------------------------------- #
# Case 19: root drift (binding roots ≠ store roots)
# --------------------------------------------------------------------------- #


def test_19_root_drift_binding_roots_mismatch_raises() -> None:
    """Binding roots that differ from store roots -> UseAdmissibilityError."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    # Mutate the store by adding another assumption after binding construction.
    other = AssumptionRegistry(store)
    other.apply(_propose_event(assumption_id="assumption:other", clock=99))

    with pytest.raises(UseAdmissibilityError, match="USE_ROOT_ASSUMPTION_MISMATCH"):
        evaluate_assumption_use_admissibility(
            store=store, binding=binding, evidence_evaluator=evaluator
        )


# --------------------------------------------------------------------------- #
# Case 20: multiple required assumptions — early deny, all still evaluated
# --------------------------------------------------------------------------- #


def test_20_multiple_required_all_evaluated_on_deny() -> None:
    """Multiple required assumptions: an early deny does not short-circuit
    evaluation of the remaining top-level assumptions."""
    store = InMemoryRegistryStore()
    # a is admissible; b is rejected.
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:a", clock=10))
    registry.apply(_admit(registry, "assumption:a", clock=11))
    registry.apply(_propose_event(assumption_id="assumption:b", clock=10))
    registry.apply(_admit(registry, "assumption:b", clock=11))
    registry.apply(_reject(registry, "assumption:b", clock=12))

    binding = _build_binding(
        store,
        required_assumption_ids=("assumption:a", "assumption:b"),
    )
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    # Both top-level assumptions are present in the decision (canonical sort: a, b).
    eval_ids = tuple(ev.assumption_id for ev in decision.evaluated_assumptions)
    assert eval_ids == ("assumption:a", "assumption:b")
    results = {ev.assumption_id: ev.result for ev in decision.evaluated_assumptions}
    assert results["assumption:a"] == "ALLOW"
    assert results["assumption:b"] == "DENY"


# --------------------------------------------------------------------------- #
# Case 21: evaluator/store substitution
# --------------------------------------------------------------------------- #


def test_21_evaluator_store_substitution_raises() -> None:
    """An evaluator bound to a different store object -> UseAdmissibilityError."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    # Evaluator built against a *different* store instance.
    evaluator = _build_evaluator(InMemoryRegistryStore())

    with pytest.raises(UseAdmissibilityError, match="USE_EVALUATOR_STORE_MISMATCH"):
        evaluate_assumption_use_admissibility(
            store=store, binding=binding, evidence_evaluator=evaluator
        )


# --------------------------------------------------------------------------- #
# Case 22: decision-binding tamper (decision_digest)
# --------------------------------------------------------------------------- #


def test_22_decision_digest_tamper_rejected() -> None:
    """Tampering with decision_digest is rejected by __post_init__."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    with pytest.raises(AssumptionGovernanceContractError, match="USE_DECISION_DIGEST_MISMATCH"):
        replace(decision, decision_digest=_digest("tampered"))


# --------------------------------------------------------------------------- #
# Case 23: work-counter tampering
# --------------------------------------------------------------------------- #


def test_23_work_counter_tamper_rejected() -> None:
    """Tampering with evaluation_work counters is rejected.

    AssumptionEvaluationWork is itself a self-digesting frozen dataclass, so
    any counter mutation is caught at the work object's own __post_init__
    (ASSUMPTION_EVALUATION_WORK_DIGEST_MISMATCH) before it could ever reach the
    decision's work-counter reconciliation. Both boundaries reject the tamper.
    """
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    original_work = decision.evaluation_work
    # Mutating any counter breaks the work object's own self-digest.
    with pytest.raises(
        AssumptionGovernanceContractError, match="ASSUMPTION_EVALUATION_WORK_DIGEST_MISMATCH"
    ):
        replace(
            original_work,
            assumption_events_replayed=original_work.assumption_events_replayed + 1,
        )


def test_23b_decision_rejects_mismatched_work_counters() -> None:
    """A decision whose evaluation_work counters disagree with its children is
    rejected by the decision's own work-counter reconciliation.

    Constructs a work object with internally-consistent digest but externally-
    wrong counters (using AssumptionEvaluationWork.build with different counts),
    then attempts to graft it onto the decision.
    """
    from csd_foundry.governance.v0_5._assumption_governance_contracts import (
        AssumptionEvaluationWork,
    )

    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    # Build a *different* but internally-valid work object (wrong counters + digest).
    mismatched_work = AssumptionEvaluationWork.build(
        assumption_histories_reconstructed=decision.evaluation_work.assumption_histories_reconstructed
        + 1,
        assumption_events_replayed=decision.evaluation_work.assumption_events_replayed + 1,
        authority_decisions_evaluated=0,
        unique_assumption_nodes_evaluated=decision.evaluation_work.unique_assumption_nodes_evaluated
        + 1,
        assumption_dependency_edges_examined=decision.evaluation_work.assumption_dependency_edges_examined,
        evidence_dependency_references_evaluated=decision.evaluation_work.evidence_dependency_references_evaluated,
        active_challenges_evaluated=decision.evaluation_work.active_challenges_evaluated,
        separation_duty_rules_evaluated=0,
    )
    with pytest.raises(AssumptionGovernanceContractError, match="USE_WORK_HISTORIES_MISMATCH"):
        replace(decision, evaluation_work=mismatched_work)


# --------------------------------------------------------------------------- #
# Case 24: valid with assumption + evidence deps -> ALLOW
# --------------------------------------------------------------------------- #


def test_24_valid_with_assumption_and_evidence_deps_allows() -> None:
    """Valid assumption with one assumption dep + one evidence dep -> ALLOW."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep"], evidence_deps=["evidence:dep"])
    _add_verified_evidence(store, "evidence:dep")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    # One traversed assumption dep, one evidence evaluation.
    assert len(ev.traversed_dependencies) == 1
    assert ev.traversed_dependencies[0].assumption_id == "assumption:dep"
    assert len(ev.evidence_evaluations) == 1
    assert ev.evidence_evaluations[0].receipt.allowed


# --------------------------------------------------------------------------- #
# Additional structural / hardening tests
# --------------------------------------------------------------------------- #


def test_decision_admissible_flag_consistency_enforced() -> None:
    """A decision whose admissible flag disagrees with child results is rejected."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    # Flip admissible while keeping the same (ALLOW) child evaluations.
    with pytest.raises(AssumptionGovernanceContractError, match="USE_DECISION_ADMISSIBLE_MISMATCH"):
        replace(decision, admissible=False, decision_digest=_digest("x"))


def test_decision_evaluated_ids_must_match_binding() -> None:
    """Evaluated assumption IDs must equal binding.required_assumption_ids."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    # Drop one evaluation; __post_init__ must reject via USE_DECISION_IDS_MISMATCH.
    with pytest.raises(AssumptionGovernanceContractError, match="USE_DECISION_IDS_MISMATCH"):
        replace(decision, evaluated_assumptions=(), decision_digest=_digest("x"))


def test_decision_digest_matches_domain_digest() -> None:
    """The decision digest is a deterministic domain-separated SHA-256."""
    from csd_foundry.governance.v0_5._assumption_governance_contracts import (
        _domain_digest as contracts_domain_digest,
    )

    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    unsigned = decision._unsigned_value()
    unsigned_for_digest = {k: v for k, v in unsigned.items() if k != "decision_digest"}
    expected = contracts_domain_digest("ASSUMPTION_USE_ADMISSIBILITY_DECISION", unsigned_for_digest)
    assert decision.decision_digest == expected


def test_evaluated_assumptions_preserve_binding_order() -> None:
    """Evaluated assumption IDs appear in the binding's canonical (sorted) order."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    for aid in ("assumption:zeta", "assumption:alpha", "assumption:mid"):
        registry.apply(_propose_event(assumption_id=aid, clock=10))
        registry.apply(_admit(registry, aid, clock=11))
    binding = _build_binding(
        store,
        required_assumption_ids=("assumption:zeta", "assumption:alpha", "assumption:mid"),
    )
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    eval_ids = tuple(ev.assumption_id for ev in decision.evaluated_assumptions)
    # Binding sorts required_assumption_ids; decision must mirror that order exactly.
    assert eval_ids == binding.required_assumption_ids
    assert decision.admissible is True


def test_assumption_root_drift_during_evaluation_raises() -> None:
    """Assumption-root drift between start and end snapshot raises (no decision)."""

    class _DriftingStore:
        """Wraps a real store; mutates the assumption root after N snapshot reads."""

        def __init__(self, real: InMemoryRegistryStore) -> None:
            self._real = real
            self._reads = 0

        def append(self, event):
            return self._real.append(event)

        def get_event(self, digest):
            return self._real.get_event(digest)

        def entity_head(self, registry_type, entity_id):
            return self._real.entity_head(registry_type, entity_id)

        def reconstruct_entity(self, registry_type, entity_id):
            return self._real.reconstruct_entity(registry_type, entity_id)

        def reconstruct_snapshot(self, registry_type):
            return self._real.reconstruct_snapshot(registry_type)

        def snapshot(self, registry_type):
            self._reads += 1
            # Inject junk only on the END-of-evaluation ASSUMPTION snapshot read
            # (reads 1-2: binding; reads 3-4: evaluator start checks;
            #  reads 5-6: evaluator end checks). Trigger at read >= 5.
            if self._reads >= 5 and registry_type == "ASSUMPTION":
                AssumptionRegistry(self._real).apply(
                    _propose_event(assumption_id="assumption:junk", clock=999, expires=None)
                )
            return self._real.snapshot(registry_type)

    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    drifting = _DriftingStore(store)
    # Binding + evaluator must be built against the SAME store object that is
    # passed to the evaluator (the wrapper), since the evaluator checks identity.
    binding = _build_binding(drifting)
    evaluator = _build_evaluator(drifting)

    with pytest.raises(UseAdmissibilityError, match="USE_ROOT_ASSUMPTION_DRIFTED"):
        evaluate_assumption_use_admissibility(
            store=drifting, binding=binding, evidence_evaluator=evaluator
        )


def test_evidence_root_drift_during_evaluation_raises() -> None:
    """Evidence-root drift between start and end snapshot raises (no decision)."""

    class _EvidenceDriftingStore:
        def __init__(self, real: InMemoryRegistryStore) -> None:
            self._real = real
            self._reads = 0

        def append(self, event):
            return self._real.append(event)

        def get_event(self, digest):
            return self._real.get_event(digest)

        def entity_head(self, registry_type, entity_id):
            return self._real.entity_head(registry_type, entity_id)

        def reconstruct_entity(self, registry_type, entity_id):
            return self._real.reconstruct_entity(registry_type, entity_id)

        def reconstruct_snapshot(self, registry_type):
            return self._real.reconstruct_snapshot(registry_type)

        def snapshot(self, registry_type):
            self._reads += 1
            # Inject junk only on the END-of-evaluation EVIDENCE_UNIT snapshot read.
            if self._reads >= 6 and registry_type == "EVIDENCE_UNIT":
                EvidenceRegistry(self._real).apply(
                    _register_evidence("evidence:junk", clock=999, expires_at_sequence=None)
                )
            return self._real.snapshot(registry_type)

    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:dep"])
    _add_verified_evidence(store, "evidence:dep")
    drifting = _EvidenceDriftingStore(store)
    binding = _build_binding(drifting)
    evaluator = _build_evaluator(drifting)

    with pytest.raises(UseAdmissibilityError, match="USE_ROOT_EVIDENCE_DRIFTED"):
        evaluate_assumption_use_admissibility(
            store=drifting, binding=binding, evidence_evaluator=evaluator
        )


def test_dependency_history_invalid_denies() -> None:
    """A dependency whose stored history is lifecycle-invalid -> DENY
    (ASSUMPTION_USE_HISTORY_INVALID)."""

    class _HistoryInjectionStore:
        def __init__(self, real: InMemoryRegistryStore, target: str, history: tuple) -> None:
            self._real = real
            self._target = target
            self._history = history

        def append(self, event):
            return self._real.append(event)

        def get_event(self, digest):
            return self._real.get_event(digest)

        def entity_head(self, registry_type, entity_id):
            return self._real.entity_head(registry_type, entity_id)

        def reconstruct_entity(self, registry_type, entity_id):
            if registry_type == "ASSUMPTION" and entity_id == self._target:
                return self._history
            return self._real.reconstruct_entity(registry_type, entity_id)

        def reconstruct_snapshot(self, registry_type):
            return self._real.reconstruct_snapshot(registry_type)

        def snapshot(self, registry_type):
            return self._real.snapshot(registry_type)

    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])

    # Build a second PROPOSE event after the first (duplicate proposal -> lifecycle invalid).
    dep_proj = registry.current("assumption:dep")
    assert dep_proj is not None
    bad_second = build_assumption_event(
        assumption_id="assumption:dep",
        entity_sequence=dep_proj.current_entity_sequence + 1,
        previous_entity_event_digest=dep_proj.current_event_digest,
        clock_sequence=dep_proj.last_clock_sequence + 1,
        source_receipt_digest=_digest("bad-dep-second"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "p",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:p",
            "proposed_at_sequence": dep_proj.last_clock_sequence + 1,
            "valid_from_sequence": dep_proj.last_clock_sequence + 1,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    real_history = store.reconstruct_entity("ASSUMPTION", "assumption:dep")
    injected = real_history + (bad_second,)
    injected_store = _HistoryInjectionStore(store, "assumption:dep", injected)

    # Binding + evaluator must be bound to the SAME (wrapper) store object.
    binding = _build_binding(injected_store)
    evaluator = _build_evaluator(injected_store)

    decision = evaluate_assumption_use_admissibility(
        store=injected_store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "ASSUMPTION_USE_HISTORY_INVALID"


def test_indirect_cycle_three_nodes_denies() -> None:
    """Indirect cycle A→B→C→A -> DENY (ASSUMPTION_USE_DEPENDENCY_CYCLE)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(
        _propose_event(assumption_id="assumption:c", clock=4, assumption_deps=["assumption:a"])
    )
    registry.apply(
        _propose_event(assumption_id="assumption:b", clock=5, assumption_deps=["assumption:c"])
    )
    registry.apply(
        _propose_event(assumption_id="assumption:a", clock=10, assumption_deps=["assumption:b"])
    )
    for aid in ("assumption:c", "assumption:b", "assumption:a"):
        proj = registry.current(aid)
        assert proj is not None
        registry.apply(_admit(registry, aid, clock=proj.last_clock_sequence + 1))
    binding = _build_binding(store, required_assumption_ids=("assumption:a",))
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.validation_code == "ASSUMPTION_USE_DEPENDENCY_CYCLE"
    assert ev.cycle_witness != ()
    assert ev.cycle_witness[0] == ev.cycle_witness[-1]


def test_valid_dag_with_shared_subdep_allows() -> None:
    """Valid DAG with a shared transitive subdependency -> ALLOW (traversed once)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:shared", clock=3))
    registry.apply(_admit(registry, "assumption:shared", clock=4))
    registry.apply(
        _propose_event(
            assumption_id="assumption:dep-a", clock=5, assumption_deps=["assumption:shared"]
        )
    )
    registry.apply(_admit(registry, "assumption:dep-a", clock=6))
    registry.apply(
        _propose_event(
            assumption_id="assumption:dep-b", clock=5, assumption_deps=["assumption:shared"]
        )
    )
    registry.apply(_admit(registry, "assumption:dep-b", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep-a", "assumption:dep-b"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    ev = decision.evaluated_assumptions[0]
    traversed_ids = [td.assumption_id for td in ev.traversed_dependencies]
    # Shared subdep is reached once via DFS first-discovery.
    assert traversed_ids.count("assumption:shared") == 1


def test_confirmed_standing_allows() -> None:
    """A CONFIRMED assumption (no active challenges) is admissible."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:candidate", clock=10))
    registry.apply(_admit(registry, "assumption:candidate", clock=11))
    # CONFIRM requires ADMITTED standing and no active challenges.
    registry.apply(
        _next_assumption_event(
            registry,
            "assumption:candidate",
            operation="CONFIRM",
            extra_payload={
                "confirming_authority_id": "authority:confirmer",
                "confirmation_receipt_digest": _digest("confirm:candidate"),
            },
            clock=12,
        )
    )
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert ev.self_state.standing == "CONFIRMED"


def test_evidence_missing_denies() -> None:
    """A required evidence dependency that is absent from the store -> DENY."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:absent"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code.startswith("EVIDENCE_")


def test_evidence_scope_insufficient_denies() -> None:
    """Evidence whose scopes do not cover the assumption's request -> DENY."""
    store = InMemoryRegistryStore()
    # Evidence registered under scope:other; assumption requests scope:control.
    _admitted_candidate(store, evidence_deps=["evidence:scoped"])
    _add_verified_evidence(store, "evidence:scoped", scope_ids=["scope:other"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code == "EVIDENCE_SCOPE_INSUFFICIENT"


def test_work_counters_match_evaluations() -> None:
    """The decision's work counters are mechanically recomputed from children."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    w = decision.evaluation_work
    # Two unique nodes: candidate + dep. Each has 2 events (PROPOSE + ADMIT).
    assert w.assumption_histories_reconstructed == 2
    assert w.assumption_events_replayed == 4
    assert w.unique_assumption_nodes_evaluated == 2
    # Authority decisions and SoD rules are not part of use-time work.
    assert w.authority_decisions_evaluated == 0
    assert w.separation_duty_rules_evaluated == 0
    assert w.active_challenges_evaluated == 0


def test_self_state_present_for_allowed() -> None:
    """An ALLOW evaluation's self_state has NODE_PRESENT with full state."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.self_state.validation_code == "ASSUMPTION_USE_NODE_PRESENT"
    assert ev.self_state.current_event_digest is not None
    assert ev.self_state.current_entity_sequence is not None
    assert ev.self_state.proposition_id == "proposition:1"
    assert ev.self_state.materiality == "MATERIAL"
    assert ev.self_state.maximum_reuse_class == "D2"


def test_decision_is_frozen_dataclass() -> None:
    """The decision dataclass and its child evaluations are frozen."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    with pytest.raises((AttributeError, Exception)):
        decision.admissible = False  # type: ignore[misc]
    ev = decision.evaluated_assumptions[0]
    with pytest.raises((AttributeError, Exception)):
        ev.result = "DENY"  # type: ignore[misc]


def test_empty_required_assumptions_rejected_at_binding() -> None:
    """A binding with no required assumptions is rejected by the binding contract."""
    store = InMemoryRegistryStore()
    with pytest.raises(AssumptionGovernanceContractError):
        DecisionAssumptionBinding.build(
            decision_id="decision:x",
            validated_event_digest=_digest("event"),
            semantic_projection_receipt_digest=_digest("sem"),
            control_state_digest=_digest("ctrl"),
            assumption_registry_root=store.snapshot("ASSUMPTION").root_digest,
            evidence_registry_root=store.snapshot("EVIDENCE_UNIT").root_digest,
            logical_clock_sequence=10,
            required_assumption_ids=(),
        )


def test_traversed_dependency_rejects_nonpresent_with_digest() -> None:
    """A non-PRESENT traversed node carrying a digest is rejected."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    with pytest.raises(AssumptionGovernanceContractError, match="USE_TRAVERSED_NONPRESENT_DIGEST"):
        UseTimeTraversedAssumption(
            assumption_id="assumption:x",
            validation_code="ASSUMPTION_USE_MISSING",
            current_event_digest=_digest("should-be-none"),
            current_entity_sequence=None,
            history_event_count=0,
            proposition_id=None,
            scope_ids=(),
            materiality=None,
            standing=None,
            active_challenge_ids=(),
            valid_from_sequence=None,
            expires_at_sequence=None,
            assumption_dependency_ids=(),
            evidence_dependency_ids=(),
            limitations=(),
            maximum_reuse_class=None,
        )


def test_traversed_dependency_rejects_present_without_digest() -> None:
    """A PRESENT traversed node missing its digest is rejected."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_TRAVERSED_PRESENT_DIGEST_MISSING"
    ):
        UseTimeTraversedAssumption(
            assumption_id="assumption:x",
            validation_code="ASSUMPTION_USE_NODE_PRESENT",
            current_event_digest=None,
            current_entity_sequence=1,
            history_event_count=1,
            proposition_id="proposition:1",
            scope_ids=("scope:control",),
            materiality="MATERIAL",
            standing="ADMITTED",
            active_challenge_ids=(),
            valid_from_sequence=10,
            expires_at_sequence=100,
            assumption_dependency_ids=(),
            evidence_dependency_ids=(),
            limitations=(),
            maximum_reuse_class="D2",
        )


def test_traversed_dependency_rejects_unknown_code() -> None:
    """An unknown validation_code is rejected."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    with pytest.raises(AssumptionGovernanceContractError, match="USE_TRAVERSED_CODE_INVALID"):
        UseTimeTraversedAssumption(
            assumption_id="assumption:x",
            validation_code="BOGUS_CODE",
            current_event_digest=None,
            current_entity_sequence=None,
            history_event_count=0,
            proposition_id=None,
            scope_ids=(),
            materiality=None,
            standing=None,
            active_challenge_ids=(),
            valid_from_sequence=None,
            expires_at_sequence=None,
            assumption_dependency_ids=(),
            evidence_dependency_ids=(),
            limitations=(),
            maximum_reuse_class=None,
        )


# --------------------------------------------------------------------------- #
# Mutation tests: prove the four receipt-validation fixes catch tampering.
# Each test builds a valid receipt/evaluation, then mutates one field with
# dataclasses.replace and asserts AssumptionGovernanceContractError.
# --------------------------------------------------------------------------- #


def _mut_propose(
    *,
    assumption_id: str,
    clock: int,
    proposition_id: str = "proposition:1",
    scope_ids: tuple[str, ...] = ("scope:control",),
    assumption_deps: tuple[str, ...] = (),
    evidence_deps: tuple[str, ...] = (),
    expires: int | None = 100,
    maximum_reuse_class: str = "D2",
) -> object:
    """Custom PROPOSE event with configurable proposition/scope (for mutation tests)."""
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{assumption_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": proposition_id,
            "scope_ids": list(scope_ids),
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": list(assumption_deps),
            "evidence_dependency_ids": list(evidence_deps),
            "limitations": [],
            "maximum_reuse_class": maximum_reuse_class,
        },
    )


def test_mut_01_d2_request_transplanted_to_incompatible_owner_rejected() -> None:
    """Fix #1: a D2 evidence request transplanted onto an owner with a different
    proposition/scope is rejected because the rebuilt request_digest mismatches."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # dep has a DIFFERENT proposition + scope than the candidate.
    registry.apply(
        _mut_propose(
            assumption_id="assumption:dep",
            clock=5,
            proposition_id="proposition:other",
            scope_ids=("scope:other",),
        )
    )
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep"], evidence_deps=["evidence:e1"])
    _add_verified_evidence(store, "evidence:e1")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert len(ev.evidence_evaluations) == 1
    ee = ev.evidence_evaluations[0]
    assert ee.owner_assumption_id == "assumption:candidate"

    # Transplant the evidence evaluation onto assumption:dep (different proposition/scope).
    tampered_ee = replace(ee, owner_assumption_id="assumption:dep")
    tampered_ev = replace(ev, evidence_evaluations=(tampered_ee,))
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_DECISION_EVIDENCE_REQUEST_DIGEST_MISMATCH"
    ):
        # Re-trigger validation by constructing the decision via replace (runs __post_init__).
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_mut_02_allow_evaluation_with_omitted_reachable_dependency_rejected() -> None:
    """Fix #2: an ALLOW evaluation that omits a reachable dependency record is
    rejected because the DFS replay cannot find the record for the edge."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert len(ev.traversed_dependencies) == 1

    # Drop the only traversed record: root still declares the dep edge, but no
    # record exists for the replay to consume. Validation fires at the
    # evaluation's own __post_init__ (the DFS replay runs there).
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVAL_TRAVERSAL_RECORD_MISSING"
    ):
        replace(ev, traversed_dependencies=())


def test_mut_03_reordered_traversed_dependency_rejected() -> None:
    """Fix #2: reordering traversed records out of DFS order is rejected."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # Two sibling leaf deps, both present.
    registry.apply(_propose_event(assumption_id="assumption:dep-a", clock=5))
    registry.apply(_admit(registry, "assumption:dep-a", clock=6))
    registry.apply(_propose_event(assumption_id="assumption:dep-b", clock=5))
    registry.apply(_admit(registry, "assumption:dep-b", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:dep-a", "assumption:dep-b"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    order = [td.assumption_id for td in ev.traversed_dependencies]
    assert order == ["assumption:dep-a", "assumption:dep-b"]

    # Swap the two records: DFS drives dep-a first but would consume dep-b.
    # Validation fires at the evaluation's __post_init__ (DFS replay).
    reordered = (ev.traversed_dependencies[1], ev.traversed_dependencies[0])
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVAL_TRAVERSAL_ORDER_MISMATCH"
    ):
        replace(ev, traversed_dependencies=reordered)


def test_mut_04_wrong_cycle_witness_rejected() -> None:
    """Fix #2: a cycle decision whose cycle_witness does not match the replayed
    cycle is rejected."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(
        _propose_event(assumption_id="assumption:b", clock=5, assumption_deps=["assumption:a"])
    )
    registry.apply(
        _propose_event(assumption_id="assumption:a", clock=10, assumption_deps=["assumption:b"])
    )
    registry.apply(_admit(registry, "assumption:b", clock=6))
    registry.apply(_admit(registry, "assumption:a", clock=11))
    binding = _build_binding(store, required_assumption_ids=("assumption:a",))
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.validation_code == "ASSUMPTION_USE_DEPENDENCY_CYCLE"
    assert ev.cycle_witness != ()

    # Tamper the witness to a syntactically-valid but wrong closed cycle.
    # Validation fires at the evaluation's __post_init__ (DFS replay compares the
    # witness it derives against the one on the receipt).
    wrong_witness = ev.cycle_witness[:-1] + ("assumption:zzz",)
    with pytest.raises(AssumptionGovernanceContractError, match="USE_EVAL_CYCLE_WITNESS_MISMATCH"):
        replace(ev, cycle_witness=wrong_witness)


def test_mut_05_dependency_record_with_altered_state_rejected() -> None:
    """Fix #2 + Fix #4: a gate-failed dependency record RETAINS its own
    assumption_dependency_ids (part of the authoritative projected state), and
    a gate-failed node whose recorded standing disagrees with its code is
    rejected by the decision-level code/state consistency check."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # dep is ADMITTED then EXPIRED -> TERMINAL (gate-failed, retains projected
    # state). dep itself declares an assumption dependency (assumption:grandchild)
    # which is part of its projected state and must be retained even though the
    # DFS never traversed it (the DFS terminated at dep).
    registry.apply(
        _propose_event(
            assumption_id="assumption:grandchild",
            clock=3,
        )
    )
    registry.apply(_admit(registry, "assumption:grandchild", clock=4))
    registry.apply(
        _propose_event(
            assumption_id="assumption:dep",
            clock=5,
            expires=20,
            assumption_deps=["assumption:grandchild"],
        )
    )
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    registry.apply(_expire(registry, "assumption:dep", clock=20))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store, clock=15)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"
    failed_dep = ev.traversed_dependencies[0]
    assert failed_dep.validation_code == "ASSUMPTION_USE_TERMINAL"
    # Gate-failed node retains full projected state...
    assert failed_dep.standing == "EXPIRED"
    assert failed_dep.current_event_digest is not None
    # ...AND retains its own assumption_dependency_ids from the projected state
    # (Fix #2): these edges were declared on the assumption but never traversed
    # by the DFS, which terminated at this node.
    assert failed_dep.assumption_dependency_ids == ("assumption:grandchild",)

    # Fix #4: a gate-failed node whose recorded standing disagrees with its
    # TERMINAL code is rejected at the decision-level code/state check. Flip the
    # standing to ADMITTED while keeping the TERMINAL code; the rebuild via
    # dataclasses.replace re-runs the decision's __post_init__.
    tampered_dep = replace(failed_dep, standing="ADMITTED")
    tampered_ev = replace(ev, traversed_dependencies=(tampered_dep,))
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="USE_NODE_CODE_STATE_TERMINAL_MISMATCH",
    ):
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_mut_06_fail_fast_edge_count_root_denies_first_child() -> None:
    """Fix #4: root -> [a, b, c] where a denies (fail-fast) yields edges_examined == 1
    (only the edge to a was followed). Grafting a work object with a different
    edge count onto the decision is rejected."""
    from csd_foundry.governance.v0_5._assumption_governance_contracts import (
        AssumptionEvaluationWork,
    )

    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # a is rejected (TERMINAL) -> first child fails the gate, fail-fast stops.
    registry.apply(_propose_event(assumption_id="assumption:a", clock=5))
    registry.apply(_admit(registry, "assumption:a", clock=6))
    registry.apply(_reject(registry, "assumption:a", clock=7))
    # b and c are valid (never reached because a denies first).
    registry.apply(_propose_event(assumption_id="assumption:b", clock=5))
    registry.apply(_admit(registry, "assumption:b", clock=6))
    registry.apply(_propose_event(assumption_id="assumption:c", clock=5))
    registry.apply(_admit(registry, "assumption:c", clock=6))
    _admitted_candidate(store, assumption_deps=["assumption:a", "assumption:b", "assumption:c"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    # Producer computed edges_examined == 1 (only candidate -> a was followed).
    assert decision.evaluation_work.assumption_dependency_edges_examined == 1

    # Graft a work object that claims 3 edges examined (all declared deps).
    mismatched_work = AssumptionEvaluationWork.build(
        assumption_histories_reconstructed=decision.evaluation_work.assumption_histories_reconstructed,
        assumption_events_replayed=decision.evaluation_work.assumption_events_replayed,
        authority_decisions_evaluated=0,
        unique_assumption_nodes_evaluated=decision.evaluation_work.unique_assumption_nodes_evaluated,
        assumption_dependency_edges_examined=3,
        evidence_dependency_references_evaluated=decision.evaluation_work.evidence_dependency_references_evaluated,
        active_challenges_evaluated=decision.evaluation_work.active_challenges_evaluated,
        separation_duty_rules_evaluated=0,
    )
    with pytest.raises(AssumptionGovernanceContractError, match="USE_WORK_EDGES_MISMATCH"):
        replace(decision, evaluation_work=mismatched_work)


def test_mut_07_d2_receipt_with_tampered_digest_rejected() -> None:
    """The D2 evidence receipt's request_digest must match its request; tampering
    the receipt's request_digest is rejected at EvidenceEvaluation construction."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:e1"])
    _add_verified_evidence(store, "evidence:e1")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    ee = ev.evidence_evaluations[0]

    # Tamper the receipt's request_digest to disagree with the request.
    tampered_receipt = replace(ee.receipt, request_digest=_digest("tampered"))
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVIDENCE_EVAL_REQUEST_MISMATCH"
    ):
        replace(ee, receipt=tampered_receipt)


# --------------------------------------------------------------------------- #
# Tests for the receipt-validation defect fixes (Fix #1 - Fix #4).
# --------------------------------------------------------------------------- #


def test_transitive_evidence_deny_completes_dfs_and_records_d2_code() -> None:
    """Fix #1: a dependency whose DFS completes but whose evidence is
    inadmissible yields a valid receipt with result=DENY, a D2 evidence
    validation_code, and NON-EMPTY traversed_dependencies (the DFS completed).

    Previously the receipt-construction replay raised USE_EVAL_DENY_TRAVERSAL_
    NOT_TERMINATED because it inferred DFS termination from the overall DENY
    result rather than from the validation_code."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    # dep is ADMITTED and clean: the DFS over assumption deps will complete.
    # dep declares an inadmissible evidence dependency.
    registry.apply(
        _propose_event(
            assumption_id="assumption:dep",
            clock=5,
            evidence_deps=["evidence:bad"],
        )
    )
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    # candidate depends on dep (DFS will traverse and complete at dep).
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    # evidence:bad is INVALIDATED -> inadmissible at use time.
    _add_invalidated_evidence(store, "evidence:bad")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    # The decision constructs without raising (Fix #1) and is a DENY driven by
    # the D2 evidence code.
    assert decision.admissible is False
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code.startswith("EVIDENCE_")
    # The DFS completed before the evidence phase ran, so the traversed
    # dependency record for assumption:dep is present.
    assert len(ev.traversed_dependencies) == 1
    assert ev.traversed_dependencies[0].assumption_id == "assumption:dep"
    assert ev.traversed_dependencies[0].validation_code == "ASSUMPTION_USE_NODE_PRESENT"
    assert ev.cycle_witness == ()


def test_d2_receipt_field_tamper_without_request_digest_change_rejected() -> None:
    """Fix #3: tampering a D2 receipt field (code or evidence_event_digest)
    WITHOUT changing request_digest is rejected because the rebuilt receipt no
    longer equals the supplied receipt (its receipt_digest is now stale)."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:e1"])
    _add_verified_evidence(store, "evidence:e1")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    ee = ev.evidence_evaluations[0]
    assert ee.receipt.allowed

    # Tamper the receipt's code while leaving request_digest untouched. The
    # receipt's stored receipt_digest is now stale relative to its content.
    tampered_code = replace(ee.receipt, code="EVIDENCE_TAMPERED")
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVIDENCE_EVAL_RECEIPT_REBUILD_MISMATCH"
    ):
        replace(ee, receipt=tampered_code)

    # Tamper the receipt's evidence_event_digest while leaving request_digest
    # untouched. Same detection path.
    tampered_event = replace(ee.receipt, evidence_event_digest=_digest("tampered-event"))
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVIDENCE_EVAL_RECEIPT_REBUILD_MISMATCH"
    ):
        replace(ee, receipt=tampered_event)


def test_gate_failed_node_retains_assumption_dependency_ids() -> None:
    """Fix #2: a gate-failed UseTimeTraversedAssumption may carry non-empty
    assumption_dependency_ids (part of the authoritative projected state) and is
    accepted by UseTimeTraversedAssumption.__post_init__."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    # A TERMINAL node (standing=EXPIRED) that retains its own declared
    # assumption dependency. This is legal post-Fix #2.
    node = UseTimeTraversedAssumption(
        assumption_id="assumption:dep",
        validation_code="ASSUMPTION_USE_TERMINAL",
        current_event_digest=_digest("dep-event"),
        current_entity_sequence=3,
        history_event_count=3,
        proposition_id="proposition:1",
        scope_ids=("scope:control",),
        materiality="MATERIAL",
        standing="EXPIRED",
        active_challenge_ids=(),
        valid_from_sequence=5,
        expires_at_sequence=20,
        assumption_dependency_ids=("assumption:grandchild",),
        evidence_dependency_ids=("evidence:dep-of-dep",),
        limitations=(),
        maximum_reuse_class="D2",
    )
    assert node.validation_code == "ASSUMPTION_USE_TERMINAL"
    assert node.assumption_dependency_ids == ("assumption:grandchild",)
    assert node.evidence_dependency_ids == ("evidence:dep-of-dep",)


def test_node_code_state_mismatch_terminal_with_admitted_standing_rejected() -> None:
    """Fix #4: a node carrying ASSUMPTION_USE_TERMINAL but a non-terminal
    standing (ADMITTED) is rejected by _validate_node_code_against_state."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
        _validate_node_code_against_state,
    )

    node = UseTimeTraversedAssumption(
        assumption_id="assumption:dep",
        validation_code="ASSUMPTION_USE_TERMINAL",
        current_event_digest=_digest("dep-event"),
        current_entity_sequence=2,
        history_event_count=2,
        proposition_id="proposition:1",
        scope_ids=("scope:control",),
        materiality="MATERIAL",
        standing="ADMITTED",  # disagrees with TERMINAL code
        active_challenge_ids=(),
        valid_from_sequence=5,
        expires_at_sequence=None,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=(),
        maximum_reuse_class="D2",
    )
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_NODE_CODE_STATE_TERMINAL_MISMATCH"
    ):
        _validate_node_code_against_state(node, clock=15)


# --------------------------------------------------------------------------- #
# Mutation tests for the three receipt-validation defect fixes (Fix #1, Fix #2
# precedence, Fix #3 DFS terminal binding). Each builds a valid receipt via the
# evaluator, then mutates one field with dataclasses.replace and asserts the
# tamper is rejected at the appropriate boundary.
# --------------------------------------------------------------------------- #


def test_fix1_allow_with_omitted_evidence_evaluation_rejected() -> None:
    """Fix #1: an ALLOW evaluation that omits a required evidence evaluation is
    rejected by the evidence-closure coverage check.

    Builds an ALLOW decision whose candidate declares one evidence dependency
    (verified -> admissible), then drops the single evidence evaluation. The
    evidence-closure replay discovers the missing (owner, evidence_id) pair and
    rejects at the decision's __post_init__."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:e1"])
    _add_verified_evidence(store, "evidence:e1")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert len(ev.evidence_evaluations) == 1

    # Drop the only evidence evaluation: the candidate still declares the dep,
    # but no evaluation exists for it.
    tampered_ev = replace(ev, evidence_evaluations=())
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVAL_ALLOW_EVIDENCE_SEQUENCE_MISMATCH"
    ):
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_fix1_allow_with_reordered_evidence_evaluations_rejected() -> None:
    """Fix #1: an ALLOW evaluation whose evidence evaluations are out of the
    canonical (first-discovery node order x evidence_dependency_ids order) is
    rejected by the evidence-closure ordering check.

    Builds an ALLOW decision whose candidate declares two evidence deps
    (evidence:e1 then evidence:e2), both admissible, then swaps the two
    evaluations. The expected sequence is [(candidate, e1), (candidate, e2)];
    the swapped sequence mismatches."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store, evidence_deps=["evidence:e1", "evidence:e2"])
    _add_verified_evidence(store, "evidence:e1")
    _add_verified_evidence(store, "evidence:e2")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "ALLOW"
    assert len(ev.evidence_evaluations) == 2
    order = [ee.receipt.evidence_id for ee in ev.evidence_evaluations]
    assert order == ["evidence:e1", "evidence:e2"]

    # Swap the two evaluations: the producer's order is violated.
    swapped = (ev.evidence_evaluations[1], ev.evidence_evaluations[0])
    tampered_ev = replace(ev, evidence_evaluations=swapped)
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVAL_ALLOW_EVIDENCE_SEQUENCE_MISMATCH"
    ):
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_fix1_evidence_deny_with_evaluations_after_denial_rejected() -> None:
    """Fix #1: an evidence-DENY evaluation that carries evaluations AFTER the
    denying receipt is rejected by the evidence-closure fail-fast check.

    Builds an evidence DENY (candidate declares evidence:e1 admissible then
    evidence:e2 inadmissible), then appends a spurious extra evaluation after
    the denying one. The producer fail-stops at the first denial, so any
    trailing evaluation is illegal."""
    store = InMemoryRegistryStore()
    # Candidate declares e1 (admissible) then e2 (inadmissible).
    _admitted_candidate(store, evidence_deps=["evidence:e1", "evidence:e2"])
    _add_verified_evidence(store, "evidence:e1")
    _add_invalidated_evidence(store, "evidence:e2")
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.result == "DENY"
    assert ev.validation_code.startswith("EVIDENCE_")
    # Two evaluations: e1 (allowed) then e2 (denied, fail-fast).
    assert len(ev.evidence_evaluations) == 2
    assert ev.evidence_evaluations[-1].receipt.allowed is False

    # Append the allowed e1 evaluation again after the denial: the producer
    # would have fail-stopped at e2, so any trailing evaluation is illegal.
    # The fail-fast check catches this as the last receipt now being allowed.
    allowed_e1 = ev.evidence_evaluations[0]
    trailing = ev.evidence_evaluations + (allowed_e1,)
    tampered_ev = replace(ev, evidence_evaluations=trailing)
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="USE_EVAL_EVIDENCE_DENY_(PREFIX_TOO_LONG|SEQUENCE_MISMATCH|LAST_RECEIPT_ALLOWED)",
    ):
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_fix2_rejected_node_with_challenges_must_be_terminal_not_challenged() -> None:
    """Fix #2: a node whose recorded standing is REJECTED (terminal) but whose
    code is CHALLENGED is rejected: frozen precedence derives TERMINAL.

    Builds a decision with a dependency that is REJECTED (inherited TERMINAL),
    then mutates BOTH the dependency's code AND the evaluation's validation_code
    to CHALLENGED (keeping them consistent so the DFS terminal-code binding of
    Fix #3 passes), and adds an active challenge so CHALLENGED would be locally
    self-consistent under the OLD per-code validator. Frozen precedence derives
    TERMINAL from the REJECTED standing regardless of the active challenge, so
    the mismatch is detected at the decision's node-code check."""
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    registry.apply(_reject(registry, "assumption:dep", clock=7))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"
    failed_dep = ev.traversed_dependencies[0]
    assert failed_dep.standing == "REJECTED"

    # Mutate the dep: claim CHALLENGED with an active challenge present, keeping
    # the REJECTED (terminal) standing. Under frozen precedence the terminal
    # standing still wins -> TERMINAL, not CHALLENGED.
    tampered_dep = UseTimeTraversedAssumption(
        assumption_id=failed_dep.assumption_id,
        validation_code="ASSUMPTION_USE_CHALLENGED",  # wrong: must be TERMINAL
        current_event_digest=failed_dep.current_event_digest,
        current_entity_sequence=failed_dep.current_entity_sequence,
        history_event_count=failed_dep.history_event_count,
        proposition_id=failed_dep.proposition_id,
        scope_ids=failed_dep.scope_ids,
        materiality=failed_dep.materiality,
        standing="REJECTED",  # terminal standing wins over challenge gate
        active_challenge_ids=("challenge:fake",),  # so CHALLENGED is locally plausible
        valid_from_sequence=failed_dep.valid_from_sequence,
        expires_at_sequence=failed_dep.expires_at_sequence,
        assumption_dependency_ids=failed_dep.assumption_dependency_ids,
        evidence_dependency_ids=failed_dep.evidence_dependency_ids,
        limitations=failed_dep.limitations,
        maximum_reuse_class=failed_dep.maximum_reuse_class,
    )
    # Keep the evaluation's validation_code consistent with the (mutated)
    # terminal node's code so Fix #3's DFS-terminal-code binding passes; the
    # precedence mismatch then surfaces at the decision's node-code check.
    tampered_ev = replace(
        ev,
        validation_code="ASSUMPTION_USE_CHALLENGED",
        traversed_dependencies=(tampered_dep,),
    )
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_NODE_CODE_STATE_TERMINAL_MISMATCH"
    ):
        replace(decision, evaluated_assumptions=(tampered_ev,))


def test_fix3_dfs_failure_with_wrong_terminal_code_rejected() -> None:
    """Fix #3: a DFS-failure evaluation whose validation_code disagrees with the
    terminal node's inherited denial code is rejected.

    Builds a DFS failure (dependency REJECTED -> inherited TERMINAL), then
    mutates the evaluation's validation_code to NOT_YET_VALID (also a valid
    DFS-failure code) while the terminal node still carries TERMINAL. The DFS
    replay exposes terminal_code=TERMINAL, which must equal the evaluation's
    own validation_code; the mismatch is detected at the evaluation's own
    __post_init__."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)
    registry.apply(_propose_event(assumption_id="assumption:dep", clock=5))
    registry.apply(_admit(registry, "assumption:dep", clock=6))
    registry.apply(_reject(registry, "assumption:dep", clock=7))
    _admitted_candidate(store, assumption_deps=["assumption:dep"])
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    ev = decision.evaluated_assumptions[0]
    assert ev.validation_code == "ASSUMPTION_USE_TERMINAL"
    # The terminal traversed node carries the inherited TERMINAL code.
    assert ev.traversed_dependencies[0].validation_code == "ASSUMPTION_USE_TERMINAL"

    # Mutate the evaluation's validation_code to a DIFFERENT DFS-failure code.
    # The DFS replay still terminates at the same terminal record (code=TERMINAL),
    # so terminal_code=TERMINAL, but now validation_code=NOT_YET_VALID mismatches.
    with pytest.raises(
        AssumptionGovernanceContractError, match="USE_EVAL_DFS_TERMINAL_CODE_MISMATCH"
    ):
        replace(ev, validation_code="ASSUMPTION_USE_NOT_YET_VALID")


def test_repeated_node_state_mismatch_across_evaluations_rejected() -> None:
    """Two top-level assumptions both depending on a shared dep. Tampering
    the second copy's current_event_digest is rejected by decision-wide
    node consistency validation."""
    store = InMemoryRegistryStore()
    # Build shared dep.
    _admitted_candidate(store, candidate_id="assumption:shared", propose_clock=5, admit_clock=6)
    # Build A depending on shared.
    _admitted_candidate(
        store,
        candidate_id="assumption:a",
        propose_clock=7,
        admit_clock=8,
        assumption_deps=["assumption:shared"],
    )
    # Build B depending on shared.
    _admitted_candidate(
        store,
        candidate_id="assumption:b",
        propose_clock=9,
        admit_clock=10,
        assumption_deps=["assumption:shared"],
    )
    binding = _build_binding(
        store,
        required_assumption_ids=("assumption:a", "assumption:b"),
    )
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )
    assert decision.admissible is True

    # Tamper: change the shared node's current_event_digest in evaluation B.
    ev_b = decision.evaluated_assumptions[1]
    assert ev_b.assumption_id == "assumption:b"
    tampered_deps = list(ev_b.traversed_dependencies)
    for i, td in enumerate(tampered_deps):
        if td.assumption_id == "assumption:shared":
            tampered_deps[i] = replace(td, current_event_digest=_digest("tampered"))
            break
    tampered_ev = replace(ev_b, traversed_dependencies=tuple(tampered_deps))
    tampered_evals = (decision.evaluated_assumptions[0], tampered_ev)

    with pytest.raises(AssumptionGovernanceContractError, match="NODE_CONSISTENCY_MISMATCH"):
        replace(
            decision,
            evaluated_assumptions=tampered_evals,
            decision_digest=_digest("tampered"),
        )


def test_toplevel_dependency_missing_role_code_rejected() -> None:
    """A top-level self_state using ASSUMPTION_USE_DEPENDENCY_MISSING (instead
    of ASSUMPTION_USE_MISSING) is rejected by the role check."""
    store = InMemoryRegistryStore()
    _admitted_candidate(store)
    binding = _build_binding(store)
    evaluator = _build_evaluator(store)

    decision = evaluate_assumption_use_admissibility(
        store=store, binding=binding, evidence_evaluator=evaluator
    )

    # Tamper: change self_state to DEPENDENCY_MISSING (wrong role).
    from csd_foundry.governance.v0_5._assumption_use_admissibility import (
        UseTimeTraversedAssumption,
    )

    ev = decision.evaluated_assumptions[0]
    tampered_self = UseTimeTraversedAssumption(
        assumption_id=ev.self_state.assumption_id,
        validation_code="ASSUMPTION_USE_DEPENDENCY_MISSING",
        current_event_digest=None,
        current_entity_sequence=None,
        history_event_count=0,
        proposition_id=None,
        scope_ids=(),
        materiality=None,
        standing=None,
        active_challenge_ids=(),
        valid_from_sequence=None,
        expires_at_sequence=None,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=(),
        maximum_reuse_class=None,
    )
    # The rejection happens at AssumptionUseEvaluation construction (frozen dataclass),
    # because self_state.validation_code == DEPENDENCY_MISSING is checked there.
    with pytest.raises(AssumptionGovernanceContractError, match="TOPLEVEL_DEPENDENCY_MISSING"):
        replace(
            ev,
            self_state=tampered_self,
            validation_code="ASSUMPTION_USE_DEPENDENCY_MISSING",
        )
