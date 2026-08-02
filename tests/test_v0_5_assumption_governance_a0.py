from __future__ import annotations

import hashlib

import pytest

from csd_foundry.governance.v0_5.assumption import build_assumption_event
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionAuthorityPolicyCommit,
    AssumptionDutyException,
    AssumptionSeparationDutyRule,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    ASSUMPTION_SAME_HEAD_CONFLICT_CODE,
    ASSUMPTION_SAME_HEAD_RETRY_POLICY,
    AssumptionAppendValidationTelemetry,
    AssumptionGovernanceExecutionContractError,
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalReceipt,
    AssumptionPolicyApprovalRule,
    AssumptionPolicyLedger,
    AssumptionPolicyLedgerEntry,
    evaluate_evidence_admission_eligibility,
)
from csd_foundry.governance.v0_5.evidence import (
    EvidenceRegistry,
    build_evidence_event,
)
from csd_foundry.governance.v0_5.registry import (
    InMemoryRegistryStore,
    RegistryStoreConflictError,
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _approval_policy(
    *,
    standard_count: int = 2,
    duty_count: int = 3,
) -> AssumptionPolicyApprovalPolicy:
    eligible = (
        "authority:governor-a",
        "authority:governor-b",
        "authority:governor-c",
    )
    standard = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=eligible,
        required_signature_count=standard_count,
        required_signer_ids=("authority:governor-a",),
    )
    duty = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=eligible,
        required_signature_count=duty_count,
        required_signer_ids=(
            "authority:governor-a",
            "authority:governor-c",
        ),
    )
    return AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval-policy:assumptions:1",
        authority_root_digest=_digest("authority-root"),
        rules=(standard, duty),
    )


def _standard_policy(label: str) -> AssumptionAuthorityPolicy:
    grant = AssumptionAuthorityGrant.build(
        grant_id=f"grant:{label}",
        action="PROPOSE",
        authority_id="authority:proposer",
        scope_ids=("scope:*",),
        assumption_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        effective_from_sequence=0,
    )
    return AssumptionAuthorityPolicy.build(
        policy_id=f"policy:{label}",
        authority_root_digest=_digest("authority-root"),
        grants=(grant,),
    )


def _duty_policy(label: str) -> AssumptionAuthorityPolicy:
    grant = AssumptionAuthorityGrant.build(
        grant_id=f"grant:{label}",
        action="CONFIRM",
        authority_id="authority:governor-a",
        scope_ids=("scope:*",),
        assumption_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        effective_from_sequence=0,
    )
    rule = AssumptionSeparationDutyRule.build(
        rule_id=f"rule:{label}",
        action="CONFIRM",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:*",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id=f"exception:{label}",
        rule_id=rule.rule_id,
        action="CONFIRM",
        authority_id="authority:governor-a",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:*",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="EMERGENCY_SINGLE_AUTHORITY",
        effective_from_sequence=0,
        effective_until_sequence=100,
    )
    return AssumptionAuthorityPolicy.build(
        policy_id=f"policy:{label}",
        authority_root_digest=_digest("authority-root"),
        grants=(grant,),
        separation_duty_rules=(rule,),
        duty_exceptions=(exception,),
    )


def _entry(
    *,
    policy: AssumptionAuthorityPolicy,
    approval_policy: AssumptionPolicyApprovalPolicy,
    effective_from_sequence: int,
    predecessor: AssumptionPolicyLedgerEntry | None,
    signers: tuple[str, ...] | None = None,
) -> AssumptionPolicyLedgerEntry:
    signature_set_digest = _digest(
        f"signatures:{policy.policy_id}:{effective_from_sequence}"
    )
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=policy,
        predecessor_policy_digest=(
            None if predecessor is None else predecessor.policy.policy_digest
        ),
        predecessor_commit_receipt_digest=(
            None
            if predecessor is None
            else predecessor.policy_commit.commit_receipt_digest
        ),
        effective_from_sequence=effective_from_sequence,
        approval_policy_digest=approval_policy.approval_policy_digest,
        signature_set_digest=signature_set_digest,
    )
    if signers is None:
        signers = (
            (
                "authority:governor-a",
                "authority:governor-b",
                "authority:governor-c",
            )
            if commit.approval_class == "DUTY_EXCEPTION"
            else ("authority:governor-a", "authority:governor-b")
        )
    receipt = AssumptionPolicyApprovalReceipt.build(
        approval_policy=approval_policy,
        policy_commit=commit,
        valid_signer_ids=signers,
        signature_set_digest=signature_set_digest,
    )
    return AssumptionPolicyLedgerEntry.build(
        policy=policy,
        policy_commit=commit,
        approval_policy=approval_policy,
        approval_receipt=receipt,
    )


def test_approval_thresholds_are_unweighted_and_duplicate_signers_do_not_count() -> None:
    approval_policy = _approval_policy()
    policy = _standard_policy("standard")
    signature_set_digest = _digest("signatures:standard")
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=approval_policy.approval_policy_digest,
        signature_set_digest=signature_set_digest,
    )

    receipt = AssumptionPolicyApprovalReceipt.build(
        approval_policy=approval_policy,
        policy_commit=commit,
        valid_signer_ids=(
            "authority:governor-b",
            "authority:governor-a",
        ),
        signature_set_digest=signature_set_digest,
    )
    assert receipt.valid_signer_ids == (
        "authority:governor-a",
        "authority:governor-b",
    )

    with pytest.raises(AssumptionGovernanceExecutionContractError) as duplicate_exc:
        AssumptionPolicyApprovalReceipt.build(
            approval_policy=approval_policy,
            policy_commit=commit,
            valid_signer_ids=(
                "authority:governor-a",
                "authority:governor-a",
            ),
            signature_set_digest=signature_set_digest,
        )
    assert duplicate_exc.value.code == "ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET"

    with pytest.raises(AssumptionGovernanceExecutionContractError) as required_exc:
        AssumptionPolicyApprovalReceipt.build(
            approval_policy=approval_policy,
            policy_commit=commit,
            valid_signer_ids=(
                "authority:governor-b",
                "authority:governor-c",
            ),
            signature_set_digest=signature_set_digest,
        )
    assert required_exc.value.code == "ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING"


def test_duty_exception_approval_is_mechanically_stronger() -> None:
    with pytest.raises(AssumptionGovernanceExecutionContractError) as exc:
        _approval_policy(standard_count=2, duty_count=2)
    assert exc.value.code == "ASSUMPTION_APPROVAL_POLICY_DUTY_THRESHOLD_NOT_STRONGER"

    approval_policy = _approval_policy()
    duty_policy = _duty_policy("duty")
    signature_set_digest = _digest("signatures:duty")
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=duty_policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=approval_policy.approval_policy_digest,
        signature_set_digest=signature_set_digest,
    )

    with pytest.raises(AssumptionGovernanceExecutionContractError) as threshold_exc:
        AssumptionPolicyApprovalReceipt.build(
            approval_policy=approval_policy,
            policy_commit=commit,
            valid_signer_ids=(
                "authority:governor-a",
                "authority:governor-c",
            ),
            signature_set_digest=signature_set_digest,
        )
    assert threshold_exc.value.code == "ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET"

    receipt = AssumptionPolicyApprovalReceipt.build(
        approval_policy=approval_policy,
        policy_commit=commit,
        valid_signer_ids=(
            "authority:governor-a",
            "authority:governor-b",
            "authority:governor-c",
        ),
        signature_set_digest=signature_set_digest,
    )
    assert receipt.approval_class == "DUTY_EXCEPTION"


def test_policy_ledger_resolves_half_open_historical_intervals() -> None:
    approval_policy = _approval_policy()
    first = _entry(
        policy=_standard_policy("p0"),
        approval_policy=approval_policy,
        effective_from_sequence=10,
        predecessor=None,
    )
    second = _entry(
        policy=_standard_policy("p1"),
        approval_policy=approval_policy,
        effective_from_sequence=20,
        predecessor=first,
    )
    third = _entry(
        policy=_standard_policy("p2"),
        approval_policy=approval_policy,
        effective_from_sequence=30,
        predecessor=second,
    )

    ledger = AssumptionPolicyLedger.build((third, first, second))

    with pytest.raises(AssumptionGovernanceExecutionContractError) as before_exc:
        ledger.resolve_at(9)
    assert before_exc.value.code == "ASSUMPTION_POLICY_NOT_ACTIVE"
    assert ledger.resolve_at(10) == first
    assert ledger.resolve_at(19) == first
    assert ledger.resolve_at(20) == second
    assert ledger.resolve_at(29) == second
    assert ledger.resolve_at(30) == third
    assert ledger.current_entry == third

    repeated = AssumptionPolicyLedger.build((first, second, third))
    assert repeated.canonical_bytes == ledger.canonical_bytes


def test_equal_effective_sequence_is_rejected() -> None:
    approval_policy = _approval_policy()
    first = _entry(
        policy=_standard_policy("p0"),
        approval_policy=approval_policy,
        effective_from_sequence=10,
        predecessor=None,
    )
    collision = _entry(
        policy=_standard_policy("p1"),
        approval_policy=approval_policy,
        effective_from_sequence=10,
        predecessor=first,
    )

    with pytest.raises(AssumptionGovernanceExecutionContractError) as exc:
        AssumptionPolicyLedger.build((first, collision))
    assert exc.value.code == "ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING"


def test_policy_chain_fork_is_rejected_even_when_effective_sequences_differ() -> None:
    approval_policy = _approval_policy()
    first = _entry(
        policy=_standard_policy("p0"),
        approval_policy=approval_policy,
        effective_from_sequence=10,
        predecessor=None,
    )
    left = _entry(
        policy=_standard_policy("left"),
        approval_policy=approval_policy,
        effective_from_sequence=20,
        predecessor=first,
    )
    right = _entry(
        policy=_standard_policy("right"),
        approval_policy=approval_policy,
        effective_from_sequence=30,
        predecessor=first,
    )

    with pytest.raises(AssumptionGovernanceExecutionContractError) as exc:
        AssumptionPolicyLedger.build((first, left, right))
    assert exc.value.code == "ASSUMPTION_POLICY_CHAIN_FORK"


def _register_evidence(
    *,
    evidence_id: str,
    expires_at_sequence: int | None = 10,
):
    return build_evidence_event(
        evidence_id=evidence_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=1,
        source_receipt_digest=_digest(f"register:{evidence_id}"),
        payload={
            "operation": "REGISTER",
            "proposition_id": "control.connected",
            "scope_ids": ["scope:control"],
            "source_id": "assessment:42",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": 1,
            "valid_from_sequence": 1,
            "expires_at_sequence": expires_at_sequence,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _next_evidence(previous, operation: str, clock_sequence: int, **payload: object):
    return build_evidence_event(
        evidence_id=previous.evidence_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=_digest(
            f"{operation}:{previous.evidence_id}:{clock_sequence}"
        ),
        payload={"operation": operation, **payload},
    )


def test_evidence_admission_eligibility_is_stricter_than_existence() -> None:
    store = InMemoryRegistryStore()
    registry = EvidenceRegistry(store)

    missing = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id="evidence:missing",
        evaluated_at_sequence=2,
    )
    assert missing.code == "ASSUMPTION_EVIDENCE_DEPENDENCY_MISSING"

    registered = registry.apply(_register_evidence(evidence_id="evidence:registered"))
    not_verified = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id=registered.evidence_id,
        evaluated_at_sequence=2,
    )
    assert not_verified.code == "ASSUMPTION_EVIDENCE_NOT_VERIFIED"

    verified = registry.apply(
        _next_evidence(
            registered,
            "VERIFY",
            2,
            verifier_authority_id="authority:verifier",
        )
    )
    eligible = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id=verified.evidence_id,
        evaluated_at_sequence=2,
    )
    assert eligible.eligible
    assert eligible.code == "EVIDENCE_ADMISSION_ELIGIBLE"

    challenged = registry.apply(
        _next_evidence(
            verified,
            "CHALLENGE",
            3,
            challenger_authority_id="authority:challenger",
            challenge_reason_code="SOURCE_RELIABILITY_DISPUTED",
            challenge_receipt_digest=_digest("challenge"),
        )
    )
    challenged_decision = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id=challenged.evidence_id,
        evaluated_at_sequence=3,
    )
    assert challenged_decision.code == "ASSUMPTION_EVIDENCE_CHALLENGED"


def test_known_terminal_and_clock_expired_evidence_are_rejected_at_admission() -> None:
    store = InMemoryRegistryStore()
    registry = EvidenceRegistry(store)

    registered = registry.apply(_register_evidence(evidence_id="evidence:rejected"))
    rejected = registry.apply(
        _next_evidence(
            registered,
            "REJECT",
            2,
            rejecting_authority_id="authority:verifier",
            reason_code="SOURCE_UNACCEPTABLE",
        )
    )
    rejected_decision = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id=rejected.evidence_id,
        evaluated_at_sequence=2,
    )
    assert rejected_decision.code == "ASSUMPTION_EVIDENCE_TERMINAL"

    registered_expiring = registry.apply(
        _register_evidence(evidence_id="evidence:expiring")
    )
    verified_expiring = registry.apply(
        _next_evidence(
            registered_expiring,
            "VERIFY",
            2,
            verifier_authority_id="authority:verifier",
        )
    )
    expired_by_clock = evaluate_evidence_admission_eligibility(
        store=store,
        evidence_id=verified_expiring.evidence_id,
        evaluated_at_sequence=10,
    )
    assert expired_by_clock.code == "ASSUMPTION_EVIDENCE_EXPIRED"


def _proposal_event():
    return build_assumption_event(
        assumption_id="assumption:race",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=1,
        source_receipt_digest=_digest("proposal"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "control.available",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": 1,
            "valid_from_sequence": 1,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def test_same_head_loser_has_exact_code_and_is_never_retried_implicitly() -> None:
    store = InMemoryRegistryStore()
    proposal = _proposal_event()
    store.append(proposal)

    first = build_assumption_event(
        assumption_id="assumption:race",
        entity_sequence=2,
        previous_entity_event_digest=proposal.digest,
        clock_sequence=2,
        source_receipt_digest=_digest("admit:first"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter-a",
            "admission_receipt_digest": _digest("admission:first"),
        },
    )
    second = build_assumption_event(
        assumption_id="assumption:race",
        entity_sequence=2,
        previous_entity_event_digest=proposal.digest,
        clock_sequence=2,
        source_receipt_digest=_digest("admit:second"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter-b",
            "admission_receipt_digest": _digest("admission:second"),
        },
    )

    store.append(first)
    root_after_winner = store.snapshot("ASSUMPTION").root_digest
    with pytest.raises(RegistryStoreConflictError) as exc:
        store.append(second)

    assert exc.value.code == ASSUMPTION_SAME_HEAD_CONFLICT_CODE
    assert ASSUMPTION_SAME_HEAD_RETRY_POLICY == "REBUILD_AND_REVALIDATE"
    assert store.snapshot("ASSUMPTION").root_digest == root_after_winner
    assert store.entity_head("ASSUMPTION", "assumption:race").event_digest == first.digest


def test_append_telemetry_is_explicitly_non_digest_bearing() -> None:
    telemetry = AssumptionAppendValidationTelemetry(
        entity_events_replayed=3,
        policy_commits_traversed=2,
        authority_decisions_recomputed=3,
        dependency_nodes_examined=1,
        append_validation_duration_ns=100,
    )
    value = telemetry.to_json_value()

    assert value["schema_version"] == "assumption-append-validation-telemetry/1"
    assert not any(key.endswith("_digest") for key in value)
