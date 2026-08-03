from __future__ import annotations

import pytest

from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_contracts import (
    MAX_INTEROPERABLE_JSON_INTEGER,
    AssumptionAuthorityPolicyCommitV2,
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
    AssumptionPolicyActivationProof,
    AssumptionPolicyActivationResult,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicyLedgerEntryV2,
    AssumptionPolicyLedgerV2,
    AssumptionPolicyPublicationConflict,
    AssumptionPolicySignatureProfile,
    ExpectedPolicyLedgerState,
    PreparedPolicyActivation,
    classify_exact_idempotence,
    compare_and_append_policy_entry,
    parse_policy_commit_v2,
    validate_stored_policy_entry_object,
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


def _signature_profile(
    verification_profile: str = "ed25519-rfc8032-strict/1",
) -> AssumptionPolicySignatureProfile:
    algorithm = AssumptionPolicyAlgorithmProfile(
        algorithm="ed25519",
        verification_profile=verification_profile,
    )
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(algorithm,),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("a"),
    )


def _challenge_policy() -> AssumptionChallengeClassificationPolicy:
    rule = AssumptionChallengeClassificationRule(
        reason_code="PROVENANCE_CONFLICT",
        materiality="MATERIAL",
    )
    return AssumptionChallengeClassificationPolicy.build(reason_rules=(rule,))


def _policy() -> AssumptionAuthorityPolicy:
    grant = AssumptionAuthorityGrant.build(
        grant_id="grant:1",
        action="ADMIT",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=(),
        effective_from_sequence=1,
    )
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=_digest("a"),
        grants=(grant,),
    )


def _entry(
    *,
    predecessor: AssumptionPolicyLedgerEntryV2 | None = None,
    effective_from_sequence: int = 10,
    rejected_signer_codes: tuple[str, ...] = (),
    proof_signature_profile: AssumptionPolicySignatureProfile | None = None,
) -> AssumptionPolicyLedgerEntryV2:
    policy = _policy()
    approval_policy = _approval_policy()
    signature_profile = _signature_profile()
    challenge_policy = _challenge_policy()
    commit = AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=(predecessor.policy.policy_digest if predecessor else None),
        predecessor_commit_receipt_digest=(
            predecessor.policy_commit.commit_receipt_digest if predecessor else None
        ),
        effective_from_sequence=effective_from_sequence,
        approval_policy_digest=approval_policy.approval_policy_digest,
        signature_profile_digest=signature_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = approval_policy.rule_for(commit.approval_class)
    selected_proof_profile = proof_signature_profile or signature_profile
    proof = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=approval_policy.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=selected_proof_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        authority_root_digest=policy.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
        rejected_signer_codes=rejected_signer_codes,
    )
    return AssumptionPolicyLedgerEntryV2.build(
        policy=policy,
        policy_commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_classification_policy=challenge_policy,
        activation_proof=proof,
    )


def test_commit_parser_returns_frozen_typed_commit() -> None:
    commit = _entry().policy_commit
    parsed = parse_policy_commit_v2(commit.to_json_value())
    assert parsed == commit


@pytest.mark.parametrize(
    "field,value,code",
    [
        (
            "effective_from_sequence",
            1.5,
            "ASSUMPTION_POLICY_COMMIT_INTEGER_INVALID",
        ),
        (
            "effective_from_sequence",
            True,
            "ASSUMPTION_POLICY_COMMIT_INTEGER_INVALID",
        ),
        (
            "effective_from_sequence",
            MAX_INTEROPERABLE_JSON_INTEGER + 1,
            "ASSUMPTION_POLICY_COMMIT_INTEGER_INVALID",
        ),
        (
            "policy_id",
            ["policy:assumptions:1"],
            "ASSUMPTION_POLICY_COMMIT_FIELD_TYPE_INVALID",
        ),
    ],
)
def test_commit_parser_rejects_noncanonical_values(
    field: str,
    value: object,
    code: str,
) -> None:
    serialized = _entry().policy_commit.to_json_value()
    serialized[field] = value
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        parse_policy_commit_v2(serialized)
    assert failure.value.code == code


def test_commit_parser_rejects_unknown_fields_and_legacy_version() -> None:
    serialized = _entry().policy_commit.to_json_value()
    serialized["unexpected"] = "value"
    with pytest.raises(AssumptionPolicyActivationContractError) as unknown:
        parse_policy_commit_v2(serialized)
    assert unknown.value.code == "ASSUMPTION_POLICY_COMMIT_UNKNOWN_FIELD"

    legacy = _entry().policy_commit.to_json_value()
    legacy["schema_version"] = "assumption-authority-policy-commit/1"
    with pytest.raises(AssumptionPolicyActivationContractError) as version:
        parse_policy_commit_v2(legacy)
    assert version.value.code == "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"


def test_empty_expectation_is_exact_not_blind() -> None:
    empty = ExpectedPolicyLedgerState.empty()
    assert empty == ExpectedPolicyLedgerState.from_ledger(AssumptionPolicyLedgerV2.build(()))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        ExpectedPolicyLedgerState(
            ledger_root_digest=_digest("f"),
            head_entry_digest=None,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_BLIND_EMPTY_EXPECTATION_FORBIDDEN"


def test_activation_proof_must_bind_exact_signature_profile() -> None:
    wrong_profile = _signature_profile("ed25519-rfc8032-strict/2")
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        _entry(proof_signature_profile=wrong_profile)
    assert failure.value.code == "ASSUMPTION_POLICY_ACTIVATION_PROOF_BINDING_MISMATCH"


def test_same_snapshot_competing_append_has_one_winner() -> None:
    genesis = _entry()
    initial = AssumptionPolicyLedgerV2.build((genesis,))
    observed = ExpectedPolicyLedgerState.from_ledger(initial)
    candidate_a = _entry(predecessor=genesis, effective_from_sequence=20)
    candidate_b = _entry(predecessor=genesis, effective_from_sequence=21)

    after_a, result_a = compare_and_append_policy_entry(
        ledger=initial,
        expected_state=observed,
        candidate=candidate_a,
    )
    assert result_a.append_result == "COMMITTED"
    with pytest.raises(AssumptionPolicyPublicationConflict) as loser_b:
        compare_and_append_policy_entry(
            ledger=after_a,
            expected_state=observed,
            candidate=candidate_b,
        )
    assert loser_b.value.code == "ASSUMPTION_POLICY_CHAIN_FORK"

    after_b, result_b = compare_and_append_policy_entry(
        ledger=initial,
        expected_state=observed,
        candidate=candidate_b,
    )
    assert result_b.append_result == "COMMITTED"
    with pytest.raises(AssumptionPolicyPublicationConflict) as loser_a:
        compare_and_append_policy_entry(
            ledger=after_b,
            expected_state=observed,
            candidate=candidate_a,
        )
    assert loser_a.value.code == "ASSUMPTION_POLICY_CHAIN_FORK"


def test_exact_retry_is_idempotent_even_with_original_expectation() -> None:
    genesis = _entry()
    initial = AssumptionPolicyLedgerV2.build((genesis,))
    observed = ExpectedPolicyLedgerState.from_ledger(initial)
    candidate = _entry(predecessor=genesis, effective_from_sequence=20)
    committed, _ = compare_and_append_policy_entry(
        ledger=initial,
        expected_state=observed,
        candidate=candidate,
    )
    unchanged, retry = compare_and_append_policy_entry(
        ledger=committed,
        expected_state=observed,
        candidate=candidate,
    )
    assert unchanged == committed
    assert retry.append_result == "IDEMPOTENT_APPEND"


def test_same_commit_different_entry_is_not_idempotent() -> None:
    first = _entry()
    second = _entry(rejected_signer_codes=("SIGNATURE:IGNORED",))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        classify_exact_idempotence(first, second)
    assert failure.value.code == "ASSUMPTION_POLICY_ENTRY_DIVERGENCE"


def test_stored_object_validation_detects_corruption_not_hash_collision() -> None:
    entry = _entry()
    validate_stored_policy_entry_object(
        claimed_digest=entry.ledger_entry_digest,
        stored_bytes=entry.canonical_bytes,
        parsed_entry=entry,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_stored_policy_entry_object(
            claimed_digest=entry.ledger_entry_digest,
            stored_bytes=entry.canonical_bytes + b"corrupt",
            parsed_entry=entry,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_STORED_OBJECT_DIGEST_MISMATCH"


def test_activation_result_is_success_only() -> None:
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyActivationResult.build(
            append_result="DENIED",
            policy_commit_receipt_digest=_digest("1"),
            ledger_entry_digest=_digest("2"),
            predecessor_ledger_root=_digest("3"),
            resulting_ledger_root=_digest("4"),
        )
    assert failure.value.code == "ASSUMPTION_POLICY_ACTIVATION_RESULT_CODE_INVALID"


def test_prepared_activation_claims_no_resulting_root() -> None:
    prepared = PreparedPolicyActivation.build(_entry())
    assert prepared.ledger_entry.ledger_entry_digest in prepared._unsigned_value().values()
    assert "resulting_ledger_root" not in prepared._unsigned_value()
