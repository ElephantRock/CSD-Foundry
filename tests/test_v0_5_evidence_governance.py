from __future__ import annotations

import hashlib

import pytest

from csd_foundry.governance.v0_5.evidence import EvidenceRegistry, build_evidence_event
from csd_foundry.governance.v0_5.evidence_governance import (
    ChallengeMaterialityRule,
    EvidenceAdmissibilityEvaluator,
    EvidenceAuthorityGrant,
    EvidenceAuthorityPolicy,
    EvidenceChallengePolicy,
    EvidenceGovernanceError,
    EvidenceUseRequest,
    GovernedEvidenceRegistry,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _policy(*, committed_at_sequence: int = 0) -> EvidenceAuthorityPolicy:
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
        committed_at_sequence=committed_at_sequence,
        authority_root_digest=_digest("authority-root"),
        grants=grants,
    )


def _challenge_policy(*, advisory: bool = False) -> EvidenceChallengePolicy:
    materiality = "ADVISORY" if advisory else "MATERIAL"
    return EvidenceChallengePolicy.build(
        (
            ChallengeMaterialityRule(
                "SOURCE_RELIABILITY_DISPUTED",
                materiality,
            ),
        )
    )


def _register(
    evidence_id: str,
    *,
    clock_sequence: int,
    proposition_id: str = "control.connected",
    scope_ids: list[str] | None = None,
    dependencies: list[str] | None = None,
    limitations: list[str] | None = None,
    maximum_reuse_class: str = "D2",
    valid_from_sequence: int | None = None,
    expires_at_sequence: int | None = 20,
):
    scope = ["control:17"] if scope_ids is None else scope_ids
    return build_evidence_event(
        evidence_id=evidence_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock_sequence,
        source_receipt_digest=_digest(f"register:{evidence_id}"),
        payload={
            "operation": "REGISTER",
            "proposition_id": proposition_id,
            "scope_ids": scope,
            "source_id": f"assessment:{evidence_id}",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": clock_sequence,
            "valid_from_sequence": (
                clock_sequence if valid_from_sequence is None else valid_from_sequence
            ),
            "expires_at_sequence": expires_at_sequence,
            "dependency_ids": [] if dependencies is None else dependencies,
            "limitations": [] if limitations is None else limitations,
            "maximum_reuse_class": maximum_reuse_class,
        },
    )


def _next(previous, operation: str, clock_sequence: int, **payload: object):
    return build_evidence_event(
        evidence_id=previous.evidence_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=_digest(f"{previous.evidence_id}:{operation}:{clock_sequence}"),
        payload={"operation": operation, **payload},
    )


def _verify(registry: GovernedEvidenceRegistry, evidence_id: str, clock_sequence: int):
    current = registry.current(evidence_id)
    assert current is not None
    return registry.apply(
        _next(
            current,
            "VERIFY",
            clock_sequence,
            verifier_authority_id="authority:verifier",
        )
    ).evidence


def _request(
    evidence_id: str,
    *,
    clock_sequence: int = 5,
    scope_ids: tuple[str, ...] = ("control:17",),
    reuse_class: str = "D2",
    accepted_limitations: tuple[str, ...] = (),
) -> EvidenceUseRequest:
    return EvidenceUseRequest.build(
        decision_id="decision:release-17",
        evidence_id=evidence_id,
        proposition_id="control.connected",
        scope_ids=scope_ids,
        required_reuse_class=reuse_class,
        clock_sequence=clock_sequence,
        accepted_limitation_codes=accepted_limitations,
    )


def test_authority_policy_is_canonical_and_decisions_are_deterministic() -> None:
    first = _policy()
    second = EvidenceAuthorityPolicy.build(
        policy_id=first.policy_id,
        committed_at_sequence=first.committed_at_sequence,
        authority_root_digest=first.authority_root_digest,
        grants=tuple(reversed(first.grants)),
    )
    assert first.policy_digest == second.policy_digest
    assert first.canonical_bytes == second.canonical_bytes

    registry = GovernedEvidenceRegistry(InMemoryRegistryStore(), first)
    event = _register("evidence:1", clock_sequence=1)
    result = registry.apply(event)
    repeated = registry.apply(event)
    assert result.authority_decision.allowed
    assert result.authority_decision.decision_digest == repeated.authority_decision.decision_digest


def test_unauthorized_operation_fails_before_registry_append() -> None:
    store = InMemoryRegistryStore()
    registry = GovernedEvidenceRegistry(store, _policy())
    registered = registry.apply(_register("evidence:1", clock_sequence=1)).evidence
    unauthorized = _next(
        registered,
        "VERIFY",
        2,
        verifier_authority_id="authority:intruder",
    )
    with pytest.raises(EvidenceGovernanceError) as exc:
        registry.apply(unauthorized)
    assert exc.value.code == "EVIDENCE_AUTHORITY_DENIED"
    head = store.entity_head("EVIDENCE_UNIT", "evidence:1")
    assert head is not None
    assert head.entity_sequence == 1


def test_policy_effective_sequence_blocks_earlier_events() -> None:
    registry = GovernedEvidenceRegistry(InMemoryRegistryStore(), _policy(committed_at_sequence=3))
    with pytest.raises(EvidenceGovernanceError) as exc:
        registry.apply(_register("evidence:1", clock_sequence=2))
    assert exc.value.code == "EVIDENCE_AUTHORITY_POLICY_NOT_EFFECTIVE"


def test_verified_evidence_is_admissible_with_stable_receipt() -> None:
    store = InMemoryRegistryStore()
    governed = GovernedEvidenceRegistry(store, _policy())
    governed.apply(_register("evidence:1", clock_sequence=1))
    _verify(governed, "evidence:1", 2)
    evaluator = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy())
    request = _request("evidence:1")

    first = evaluator.evaluate(request)
    second = evaluator.evaluate(request)
    assert first.allowed
    assert first.code == "EVIDENCE_ADMISSIBLE"
    assert first.receipt_digest == second.receipt_digest
    assert first.canonical_bytes == second.canonical_bytes


@pytest.mark.parametrize(
    ("use_request", "code"),
    [
        (_request("evidence:1", scope_ids=("control:18",)), "EVIDENCE_SCOPE_INSUFFICIENT"),
        (_request("evidence:1", reuse_class="D3"), "EVIDENCE_REUSE_CLASS_INSUFFICIENT"),
        (_request("evidence:1", clock_sequence=20), "EVIDENCE_EXPIRED_BY_TIME"),
    ],
)
def test_scope_reuse_and_time_fail_closed(
    use_request: EvidenceUseRequest,
    code: str,
) -> None:
    store = InMemoryRegistryStore()
    governed = GovernedEvidenceRegistry(store, _policy())
    governed.apply(_register("evidence:1", clock_sequence=1))
    _verify(governed, "evidence:1", 2)
    receipt = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy()).evaluate(
        use_request
    )
    assert not receipt.allowed
    assert receipt.code == code


def test_limitations_require_explicit_acceptance() -> None:
    store = InMemoryRegistryStore()
    governed = GovernedEvidenceRegistry(store, _policy())
    governed.apply(
        _register(
            "evidence:1",
            clock_sequence=1,
            limitations=["LAB_ONLY"],
        )
    )
    _verify(governed, "evidence:1", 2)
    evaluator = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy())
    blocked = evaluator.evaluate(_request("evidence:1"))
    accepted = evaluator.evaluate(_request("evidence:1", accepted_limitations=("LAB_ONLY",)))
    assert blocked.code == "EVIDENCE_LIMITATION_NOT_ACCEPTED"
    assert accepted.allowed


def test_material_challenge_blocks_and_advisory_challenge_is_exposed() -> None:
    store = InMemoryRegistryStore()
    governed = GovernedEvidenceRegistry(store, _policy())
    governed.apply(_register("evidence:1", clock_sequence=1))
    verified = _verify(governed, "evidence:1", 2)
    governed.apply(
        _next(
            verified,
            "CHALLENGE",
            3,
            challenger_authority_id="authority:challenger",
            challenge_reason_code="SOURCE_RELIABILITY_DISPUTED",
            challenge_receipt_digest=_digest("challenge"),
        )
    )
    material = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy()).evaluate(
        _request("evidence:1")
    )
    advisory = EvidenceAdmissibilityEvaluator(
        store,
        _policy(),
        _challenge_policy(advisory=True),
    ).evaluate(_request("evidence:1"))
    assert material.code == "EVIDENCE_CHALLENGE_MATERIAL"
    assert advisory.allowed
    assert advisory.advisory_codes == (
        "EVIDENCE_CHALLENGE_ADVISORY:evidence:1:SOURCE_RELIABILITY_DISPUTED",
    )


def test_dependencies_must_be_admissible_and_cycles_fail_closed() -> None:
    store = InMemoryRegistryStore()
    governed = GovernedEvidenceRegistry(store, _policy())
    governed.apply(_register("evidence:b", clock_sequence=1))
    _verify(governed, "evidence:b", 2)
    governed.apply(
        _register(
            "evidence:a",
            clock_sequence=3,
            dependencies=["evidence:b"],
        )
    )
    _verify(governed, "evidence:a", 4)
    evaluator = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy())
    receipt = evaluator.evaluate(_request("evidence:a"))
    assert receipt.allowed
    assert len(receipt.dependency_event_digests) == 1

    cycle_store = InMemoryRegistryStore()
    cycle = GovernedEvidenceRegistry(cycle_store, _policy())
    cycle.apply(
        _register(
            "evidence:a",
            clock_sequence=1,
            dependencies=["evidence:b"],
        )
    )
    cycle.apply(
        _register(
            "evidence:b",
            clock_sequence=2,
            dependencies=["evidence:a"],
        )
    )
    _verify(cycle, "evidence:a", 3)
    _verify(cycle, "evidence:b", 4)
    cycle_receipt = EvidenceAdmissibilityEvaluator(
        cycle_store,
        _policy(),
        _challenge_policy(),
    ).evaluate(_request("evidence:a"))
    assert cycle_receipt.code == "EVIDENCE_DEPENDENCY_CYCLE"


def test_raw_unauthorized_history_is_rejected_at_use_time() -> None:
    store = InMemoryRegistryStore()
    raw = EvidenceRegistry(store)
    registered = raw.apply(_register("evidence:1", clock_sequence=1))
    raw.apply(
        _next(
            registered,
            "VERIFY",
            2,
            verifier_authority_id="authority:intruder",
        )
    )
    receipt = EvidenceAdmissibilityEvaluator(store, _policy(), _challenge_policy()).evaluate(
        _request("evidence:1")
    )
    assert not receipt.allowed
    assert receipt.code == "EVIDENCE_AUTHORITY_HISTORY_INVALID"
