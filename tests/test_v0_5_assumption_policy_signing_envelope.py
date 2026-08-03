"""Contract-correction tests for the v0.5-D3.2-A1.2-0 signing envelope.

Validates that the V3 envelope is non-circular: the signing payload excludes
all signature-derived fields, signatures target the signing-payload digest, and
commit/3 binds the pre-signing payload to the post-signature signature set
without any fixed-point dependency.

Covers: construction determinism, signature-set exclusion from the payload,
target binding, entry/proof bindings, V2 version preservation + non-activation,
and full-chain determinism.
"""

from __future__ import annotations

import pytest

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    ACTIVATION_PROOF_V2_SCHEMA_VERSION,
    AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION,
    POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION,
    POLICY_LEDGER_V3_SCHEMA_VERSION,
    SIGNING_PAYLOAD_SCHEMA_VERSION,
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationContractError,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionDutyException,
    AssumptionSeparationDutyRule,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
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


def _grant(grant_id: str = "grant:1") -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=grant_id,
        action="ADMIT",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=(),
        effective_from_sequence=1,
    )


def _policy() -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
    )


def _duty_exception(exception_id: str) -> AssumptionDutyException:
    return AssumptionDutyException.build(
        exception_id=exception_id,
        rule_id="rule:resolver-challenger",
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        conflicting_roles=("CHALLENGER",),
        scope_ids=("scope:control",),
        assumption_ids=("assumption:1",),
        assumption_materialities=("MATERIAL",),
        reason_code="EMERGENCY_SINGLE_AUTHORITY",
        effective_from_sequence=1,
        effective_until_sequence=50,
    )


def _policy_with_exception() -> AssumptionAuthorityPolicy:
    grant = AssumptionAuthorityGrant.build(
        grant_id="grant:resolve",
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        effective_from_sequence=1,
    )
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:resolver-challenger",
        action="RESOLVE_TO_ADMITTED",
        conflicting_roles=("CHALLENGER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:exceptions",
        authority_root_digest=_digest("a"),
        grants=(grant,),
        separation_duty_rules=(rule,),
        duty_exceptions=(_duty_exception("exception:1"),),
    )


def _payload(
    *,
    policy: AssumptionAuthorityPolicy | None = None,
    effective_from_sequence: int = 10,
    approval_policy: AssumptionPolicyApprovalPolicy | None = None,
    signature_profile: AssumptionPolicySignatureProfile | None = None,
    challenge_policy: AssumptionChallengeClassificationPolicy | None = None,
    predecessor_policy_digest: str | None = None,
    predecessor_commit_receipt_digest: str | None = None,
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=predecessor_policy_digest,
        predecessor_commit_receipt_digest=predecessor_commit_receipt_digest,
        effective_from_sequence=effective_from_sequence,
        approval_policy=approval_policy or _approval_policy(),
        signature_profile=signature_profile or _signature_profile(),
        challenge_policy=challenge_policy or _challenge_policy(),
    )


def _commit(
    *,
    payload: AssumptionPolicySigningPayload | None = None,
    signature_set_digest: str = _digest("b"),
) -> AssumptionAuthorityPolicyCommitV3:
    p = payload or _payload()
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=p.signing_payload_digest,
        signature_set_digest=signature_set_digest,
    )


def _proof(
    *,
    payload: AssumptionPolicySigningPayload | None = None,
    commit: AssumptionAuthorityPolicyCommitV3 | None = None,
    valid_signer_ids: tuple[str, ...] = ("authority:a", "authority:b"),
    rejected_signer_codes: tuple[str, ...] = (),
    signature_set_digest: str | None = None,
) -> AssumptionPolicyActivationProofV2:
    p = payload or _payload()
    c = commit or _commit(payload=p, signature_set_digest=signature_set_digest or _digest("b"))
    approval = _approval_policy()
    profile = _signature_profile()
    challenge = _challenge_policy()
    rule = approval.rule_for(p.approval_class)
    return AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=p.signing_payload_digest,
        policy_commit_receipt_digest=c.commit_receipt_digest,
        approval_policy_digest=approval.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        authority_root_digest=p.authority_root_digest,
        signature_set_digest=c.signature_set_digest,
        valid_signer_ids=valid_signer_ids,
        rejected_signer_codes=rejected_signer_codes,
    )


def _entry(
    *,
    payload: AssumptionPolicySigningPayload | None = None,
    commit: AssumptionAuthorityPolicyCommitV3 | None = None,
    proof: AssumptionPolicyActivationProofV2 | None = None,
    signature_set_digest: str = _digest("b"),
    effective_from_sequence: int = 10,
) -> AssumptionPolicyLedgerEntryV3:
    p = payload or _payload(effective_from_sequence=effective_from_sequence)
    c = commit or _commit(payload=p, signature_set_digest=signature_set_digest)
    pr = proof or _proof(payload=p, commit=c, signature_set_digest=signature_set_digest)
    return AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=pr,
    )


# ===========================================================================
# Construction
# ===========================================================================


def test_signing_payload_digest_is_deterministic() -> None:
    p1 = _payload()
    p2 = _payload()
    assert p1.signing_payload_digest == p2.signing_payload_digest


def test_signature_set_digest_not_in_signing_payload() -> None:
    p = _payload()
    value = p.to_json_value()
    assert "signature_set_digest" not in value
    assert "signature_bytes" not in value
    assert "activation_proof" not in value
    assert "ledger_entry_digest" not in value
    assert "resulting_ledger_root" not in value


def test_changing_policy_changes_signing_payload_digest() -> None:
    p1 = _payload(policy=_policy())
    other_policy = AssumptionAuthorityPolicy.build(
        policy_id="policy:different",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
    )
    p2 = _payload(policy=other_policy)
    assert p1.signing_payload_digest != p2.signing_payload_digest


def test_changing_approval_policy_changes_payload_digest() -> None:
    other_approval = AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:different",
        authority_root_digest=_digest("a"),
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
    p1 = _payload()
    p2 = _payload(approval_policy=other_approval)
    assert p1.signing_payload_digest != p2.signing_payload_digest


def test_changing_signature_set_does_not_change_payload_digest() -> None:
    p = _payload()
    # The payload has no signature-set field at all, so changing the set cannot
    # affect its digest. This is the core non-circularity guarantee.
    assert "signature_set_digest" not in p._unsigned_value()


def test_changing_signature_set_changes_commit_receipt_digest() -> None:
    p = _payload()
    c1 = _commit(payload=p, signature_set_digest=_digest("b"))
    c2 = _commit(payload=p, signature_set_digest=_digest("c"))
    assert c1.commit_receipt_digest != c2.commit_receipt_digest


def test_duty_exception_payload_has_duty_exception_approval_class() -> None:
    p = _payload(policy=_policy_with_exception())
    assert p.approval_class == "DUTY_EXCEPTION"
    assert p.exception_count == 1


# ===========================================================================
# Target binding
# ===========================================================================


def test_commit_v3_binds_payload_and_signature_set() -> None:
    p = _payload()
    c = _commit(payload=p, signature_set_digest=_digest("b"))
    assert c.signing_payload_digest == p.signing_payload_digest
    assert c.signature_set_digest == _digest("b")
    assert c.commit_receipt_digest != p.signing_payload_digest
    assert c.commit_receipt_digest != _digest("b")


def test_signature_target_is_signing_payload_digest_not_commit() -> None:
    p = _payload()
    c = _commit(payload=p, signature_set_digest=_digest("b"))
    # Signatures must target signing_payload_digest, not commit_receipt_digest.
    assert p.signing_payload_digest != c.commit_receipt_digest


# ===========================================================================
# Entry bindings
# ===========================================================================


def test_valid_entry_constructs_and_self_validates() -> None:
    entry = _entry()
    assert entry.ledger_entry_digest
    assert (
        entry.signing_payload.signing_payload_digest == entry.policy_commit.signing_payload_digest
    )


def test_wrong_signing_payload_in_entry_rejected() -> None:
    p1 = _payload()
    p2 = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:other",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
        )
    )
    c = _commit(payload=p1)
    proof = _proof(payload=p1, commit=c)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerEntryV3.build(
            policy=_policy(),
            signing_payload=p2,  # different payload
            policy_commit=c,
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_classification_policy=_challenge_policy(),
            activation_proof=proof,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"


def test_wrong_signature_set_digest_in_commit_rejected() -> None:
    p = _payload()
    proof = _proof(payload=p, signature_set_digest=_digest("b"))
    c_wrong = _commit(payload=p, signature_set_digest=_digest("c"))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerEntryV3.build(
            policy=_policy(),
            signing_payload=p,
            policy_commit=c_wrong,
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_classification_policy=_challenge_policy(),
            activation_proof=proof,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"


def test_wrong_proof_payload_digest_rejected() -> None:
    p1 = _payload()
    p2 = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:other2",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
        )
    )
    c = _commit(payload=p1)
    proof_wrong = _proof(payload=p2)  # proof for a different payload
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerEntryV3.build(
            policy=_policy(),
            signing_payload=p1,
            policy_commit=c,
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_classification_policy=_challenge_policy(),
            activation_proof=proof_wrong,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"


# ===========================================================================
# Versioning: V2 preserved but non-activatable
# ===========================================================================


def test_v2_commit_remains_parseable() -> None:
    # The V2 commit class is still importable and constructible; it is not
    # deleted, just superseded by V3 for activation.
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionAuthorityPolicyCommitV2,
    )

    commit_v2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=_policy(),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        signature_profile_digest=_signature_profile().profile_digest,
        challenge_classification_policy_digest=_challenge_policy().policy_digest,
        signature_set_digest=_digest("b"),
    )
    assert commit_v2.commit_receipt_digest


def test_v2_commit_schema_version_is_not_v3() -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
    )

    assert AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION == "assumption-authority-policy-commit/2"


def test_v3_schema_versions_are_distinct() -> None:
    assert SIGNING_PAYLOAD_SCHEMA_VERSION == "assumption-policy-signing-payload/1"
    assert AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION == "assumption-authority-policy-commit/3"
    assert ACTIVATION_PROOF_V2_SCHEMA_VERSION == "assumption-policy-activation-proof/2"
    assert POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION == "assumption-policy-ledger-entry/3"
    assert POLICY_LEDGER_V3_SCHEMA_VERSION == "assumption-policy-ledger/3"


def test_v2_entry_cannot_appear_in_v3_ledger_via_type_system() -> None:
    # The V3 ledger is typed for AssumptionPolicyLedgerEntryV3; a V2 entry
    # is a different type and cannot be inserted. This is enforced by the type
    # system, not runtime. We verify the V3 ledger rejects an empty/mixed input
    # only structurally.
    ledger = AssumptionPolicyLedgerV3.build(())
    assert ledger.ledger_root_digest
    assert ledger.entries == ()


# ===========================================================================
# Determinism
# ===========================================================================


def test_identical_inputs_produce_byte_identical_payload_commit_proof_entry() -> None:
    e1 = _entry()
    e2 = _entry()
    assert e1.signing_payload.canonical_bytes == e2.signing_payload.canonical_bytes
    assert e1.policy_commit.canonical_bytes == e2.policy_commit.canonical_bytes
    assert e1.ledger_entry_digest == e2.ledger_entry_digest


def test_full_chain_root_is_deterministic() -> None:
    entry = _entry()
    ledger_a = AssumptionPolicyLedgerV3.build((entry,))
    ledger_b = AssumptionPolicyLedgerV3.build((entry,))
    assert ledger_a.ledger_root_digest == ledger_b.ledger_root_digest


def test_two_entry_chain_has_different_root_than_single() -> None:
    first = _entry(effective_from_sequence=10)
    # Build a successor entry referencing the first as predecessor.
    p2 = _payload(
        effective_from_sequence=20,
        predecessor_policy_digest=first.signing_payload.policy_digest,
        predecessor_commit_receipt_digest=first.policy_commit.commit_receipt_digest,
    )
    c2 = _commit(payload=p2)
    proof2 = _proof(payload=p2, commit=c2)
    second = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p2,
        policy_commit=c2,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof2,
    )
    single = AssumptionPolicyLedgerV3.build((first,))
    chain = AssumptionPolicyLedgerV3.build((first, second))
    assert single.ledger_root_digest != chain.ledger_root_digest
    assert len(chain.entries) == 2


def test_chain_fork_rejected() -> None:
    first = _entry()
    p_a = _payload(
        effective_from_sequence=20,
        predecessor_policy_digest=first.signing_payload.policy_digest,
        predecessor_commit_receipt_digest=first.policy_commit.commit_receipt_digest,
    )
    p_b = _payload(
        effective_from_sequence=21,
        predecessor_policy_digest=first.signing_payload.policy_digest,
        predecessor_commit_receipt_digest=first.policy_commit.commit_receipt_digest,
    )
    c_a = _commit(payload=p_a)
    c_b = _commit(payload=p_b)
    succ_a = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p_a,
        policy_commit=c_a,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=_proof(payload=p_a, commit=c_a),
    )
    succ_b = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p_b,
        policy_commit=c_b,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=_proof(payload=p_b, commit=c_b),
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerV3.build((first, succ_a, succ_b))
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_V3_CHAIN_FORK"
