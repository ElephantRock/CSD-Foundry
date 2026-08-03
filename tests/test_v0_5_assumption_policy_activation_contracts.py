from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.governance.v0_5.assumption import (
    STANDING_ADMITTED,
    Assumption,
    AssumptionChallenge,
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
from csd_foundry.governance.v0_5.assumption_policy_activation_contracts import (
    ACTIVATION_VALIDATION_ORDER,
    POLICY_APPEND_PRECEDENCE,
    AssumptionAuthorityPolicyCommitV2,
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
    AssumptionPolicyActivationProof,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicyLedgerEntryV2,
    AssumptionPolicyLedgerV2,
    AssumptionPolicySignatureProfile,
    classify_exact_idempotence,
    derive_resolution_challenge_materialities,
    validate_activatable_commit_version,
    validate_policy_overlap,
    validate_successor_position,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _approval_policy() -> AssumptionPolicyApprovalPolicy:
    standard = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=2,
        required_signer_ids=("authority:a",),
    )
    duty = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=3,
        required_signer_ids=("authority:a",),
    )
    return AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:assumptions:1",
        authority_root_digest=_digest("a"),
        rules=(standard, duty),
    )


def _signature_profile() -> AssumptionPolicySignatureProfile:
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ed25519",
                verification_profile="ed25519-rfc8032-strict/1",
            ),
        ),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("a"),
    )


def _challenge_policy() -> AssumptionChallengeClassificationPolicy:
    return AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="PROVENANCE_CONFLICT",
                materiality="MATERIAL",
            ),
        )
    )


def _grant(
    grant_id: str = "grant:1",
    *,
    action: str = "ADMIT",
    scope_ids: tuple[str, ...] = ("scope:control",),
    effective_from_sequence: int = 1,
    effective_until_sequence: int | None = None,
    challenge_materialities: tuple[str, ...] = (),
) -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=grant_id,
        action=action,
        authority_id="authority:operator",
        scope_ids=scope_ids,
        assumption_materialities=("MATERIAL",),
        challenge_materialities=challenge_materialities,
        effective_from_sequence=effective_from_sequence,
        effective_until_sequence=effective_until_sequence,
    )


def _policy(*grants: AssumptionAuthorityGrant) -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=_digest("a"),
        grants=grants or (_grant(),),
    )


def _entry(
    *,
    policy: AssumptionAuthorityPolicy | None = None,
    predecessor: AssumptionPolicyLedgerEntryV2 | None = None,
    effective_from_sequence: int = 10,
    rejected_signer_codes: tuple[str, ...] = (),
) -> AssumptionPolicyLedgerEntryV2:
    selected_policy = policy or _policy()
    approval_policy = _approval_policy()
    signature_profile = _signature_profile()
    challenge_policy = _challenge_policy()
    commit = AssumptionAuthorityPolicyCommitV2.build(
        policy=selected_policy,
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
        signature_profile_digest=signature_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = approval_policy.rule_for(commit.approval_class)
    proof = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=approval_policy.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=signature_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        authority_root_digest=selected_policy.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
        rejected_signer_codes=rejected_signer_codes,
    )
    return AssumptionPolicyLedgerEntryV2.build(
        policy=selected_policy,
        policy_commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_classification_policy=challenge_policy,
        activation_proof=proof,
    )


def _assumption() -> Assumption:
    return Assumption(
        assumption_id="assumption:1",
        proposition_id="proposition:1",
        scope_ids=("scope:control",),
        materiality="MATERIAL",
        proposer_authority_id="authority:proposer",
        admitting_authority_id="authority:admitter",
        confirming_authority_id=None,
        proposed_at_sequence=1,
        valid_from_sequence=1,
        expires_at_sequence=100,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=(),
        maximum_reuse_class="D2",
        standing=STANDING_ADMITTED,
        active_challenges=(
            AssumptionChallenge(
                challenge_id="challenge:a",
                challenger_authority_id="authority:challenger-a",
                reason_code="PROVENANCE_CONFLICT",
                challenge_receipt_digest=_digest("c"),
                opened_at_sequence=2,
                opening_event_digest=_digest("d"),
            ),
            AssumptionChallenge(
                challenge_id="challenge:b",
                challenger_authority_id="authority:challenger-b",
                reason_code="UNKNOWN_REASON",
                challenge_receipt_digest=_digest("e"),
                opened_at_sequence=3,
                opening_event_digest=_digest("f"),
            ),
        ),
        superseded_by_id=None,
        proposal_source_receipt_digest=_digest("1"),
        current_source_receipt_digest=_digest("2"),
        current_event_digest=_digest("3"),
        current_entity_sequence=3,
        last_clock_sequence=3,
    )


def test_signature_profile_pins_schema_algorithm_and_semantics() -> None:
    profile = _signature_profile()
    assert profile.signature_set_schema_version == "signature-set/1"
    assert profile.signature_record_semantics_version == "signature-record/1"
    assert profile.verification_profile_for("ed25519") == (
        "ed25519-rfc8032-strict/1"
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        profile.verification_profile_for("rsa-pss-sha256")
    assert failure.value.code == "ASSUMPTION_SIGNATURE_ALGORITHM_NOT_PINNED"


def test_legacy_commit_is_not_activatable() -> None:
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_activatable_commit_version(
            {"schema_version": "assumption-authority-policy-commit/1"}
        )
    assert failure.value.code == (
        "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
    )


def test_fail_fast_order_places_overlap_before_crypto() -> None:
    assert ACTIVATION_VALIDATION_ORDER.index("POLICY_STRUCTURE_AND_OVERLAP") < (
        ACTIVATION_VALIDATION_ORDER.index("CRYPTOGRAPHIC_VERIFICATION")
    )
    assert POLICY_APPEND_PRECEDENCE == (
        "EXACT_IDEMPOTENCE",
        "PREDECESSOR_HEAD_MATCH",
        "EFFECTIVE_SEQUENCE_MONOTONICITY",
    )


def test_overlapping_grants_are_rejected_structurally() -> None:
    policy = _policy(_grant("grant:a"), _grant("grant:b"))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_policy_overlap(policy)
    assert failure.value.code == "ASSUMPTION_AUTHORITY_GRANT_OVERLAP"
    assert failure.value.detail == "grant:a,grant:b"


def test_disjoint_materiality_grants_are_accepted() -> None:
    material = _grant("grant:material")
    advisory = AssumptionAuthorityGrant.build(
        grant_id="grant:advisory",
        action="ADMIT",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("ADVISORY",),
        effective_from_sequence=1,
    )
    validate_policy_overlap(_policy(advisory, material))


def test_full_chain_root_commits_to_complete_ordered_entries() -> None:
    first = _entry(effective_from_sequence=10)
    second = _entry(predecessor=first, effective_from_sequence=20)
    ledger = AssumptionPolicyLedgerV2.build((first, second))
    assert ledger.entries == (first, second)
    assert ledger.ledger_root_digest != AssumptionPolicyLedgerV2.build(
        (first,)
    ).ledger_root_digest


def test_exact_digest_and_bytes_define_idempotence() -> None:
    entry = _entry()
    assert classify_exact_idempotence(entry, entry) == "IDEMPOTENT_APPEND"
    divergent = _entry(rejected_signer_codes=("SIGNATURE_INVALID",))
    divergent = replace(
        divergent,
        policy_commit=entry.policy_commit,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        classify_exact_idempotence(entry, divergent)
    assert failure.value.code == "ASSUMPTION_POLICY_ENTRY_DIVERGENCE"


def test_position_precedence_distinguishes_fork_and_equal_sequence() -> None:
    head = _entry(effective_from_sequence=10)
    equal = _entry(predecessor=head, effective_from_sequence=10)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_successor_position(head, equal)
    assert failure.value.code == (
        "ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING"
    )

    wrong_predecessor = _entry(effective_from_sequence=20)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_successor_position(head, wrong_predecessor)
    assert failure.value.code == "ASSUMPTION_POLICY_CHAIN_FORK"


def test_resolution_materiality_is_derived_from_current_challenges() -> None:
    assumption = _assumption()
    event = build_assumption_event(
        assumption_id=assumption.assumption_id,
        entity_sequence=4,
        previous_entity_event_digest=assumption.current_event_digest,
        clock_sequence=4,
        source_receipt_digest=_digest("4"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest("5"),
            "resolution_basis_code": "ADJUDICATED",
            "resolved_challenge_ids": ["challenge:a", "challenge:b"],
            "replacement_assumption_id": None,
        },
    )
    challenge_ids, materialities = derive_resolution_challenge_materialities(
        assumption,
        event,
        _challenge_policy(),
    )
    assert challenge_ids == ("challenge:a", "challenge:b")
    assert materialities == ("CRITICAL", "MATERIAL")


def test_resolution_unknown_challenge_fails_closed() -> None:
    assumption = _assumption()
    event = build_assumption_event(
        assumption_id=assumption.assumption_id,
        entity_sequence=4,
        previous_entity_event_digest=assumption.current_event_digest,
        clock_sequence=4,
        source_receipt_digest=_digest("4"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest("5"),
            "resolution_basis_code": "ADJUDICATED",
            "resolved_challenge_ids": ["challenge:missing"],
            "replacement_assumption_id": None,
        },
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        derive_resolution_challenge_materialities(
            assumption,
            event,
            _challenge_policy(),
        )
    assert failure.value.code == "ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN"
