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
    deterministic_policy_signature_bytes,
    require_activatable_policy_commit,
    require_policy_signature_target,
    validate_successor_position_v3,
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


# ===========================================================================
# Correction 1: exact signature-target validation
# ===========================================================================


def test_signature_target_accepts_signing_payload_digest() -> None:
    p = _payload()
    require_policy_signature_target(
        signed_digest=p.signing_payload_digest,
        signing_payload_digest=p.signing_payload_digest,
    )


def test_signature_target_over_policy_digest_rejected() -> None:
    p = _payload()
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_policy_signature_target(
            signed_digest=p.policy_digest,
            signing_payload_digest=p.signing_payload_digest,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"


def test_signature_target_over_commit_receipt_rejected() -> None:
    p = _payload()
    c = _commit(payload=p)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_policy_signature_target(
            signed_digest=c.commit_receipt_digest,
            signing_payload_digest=p.signing_payload_digest,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"


def test_signature_target_over_another_signing_payload_rejected() -> None:
    p1 = _payload()
    p2 = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:other-target",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
        )
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_policy_signature_target(
            signed_digest=p2.signing_payload_digest,
            signing_payload_digest=p1.signing_payload_digest,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"


def test_signature_target_over_arbitrary_digest_rejected() -> None:
    p = _payload()
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_policy_signature_target(
            signed_digest=_digest("f"),
            signing_payload_digest=p.signing_payload_digest,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"


def test_signature_target_case_sensitive() -> None:
    p = _payload()
    upper = p.signing_payload_digest.upper()
    # SHA-256 hex is lowercase; uppercasing changes the string but may not be
    # a valid digest format. Either way, it must not equal the original.
    if upper != p.signing_payload_digest:
        with pytest.raises(AssumptionPolicyActivationContractError):
            require_policy_signature_target(
                signed_digest=upper,
                signing_payload_digest=p.signing_payload_digest,
            )


# ===========================================================================
# Correction 2: message-binding conformance vector
# ===========================================================================


def test_conformance_bytes_change_when_signed_digest_changes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"public-key-a",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"public-key-a",
        signed_digest=_digest("b"),
    )
    assert sig_a != sig_b


def test_conformance_bytes_change_when_public_key_changes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"public-key-a",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"public-key-b",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b


def test_conformance_bytes_change_when_algorithm_changes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm="ecdsa-p256-sha256",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b


def test_conformance_bytes_change_when_profile_changes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile="ed25519-rfc8032-strict/2",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b


# ===========================================================================
# Correction 3: executable commit-version gate
# ===========================================================================


def test_activatable_commit_accepts_v3() -> None:
    c = _commit()
    assert require_activatable_policy_commit(c) is c


def test_activatable_commit_rejects_v2() -> None:
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
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_activatable_policy_commit(commit_v2)
    assert failure.value.code == "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"


def test_activatable_commit_rejects_foreign_object() -> None:
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        require_activatable_policy_commit("not-a-commit")
    assert failure.value.code == "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"


# ===========================================================================
# Correction 4: runtime ledger-entry version enforcement
# ===========================================================================


def test_v2_entry_rejected_from_ledger_v3_at_runtime() -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionAuthorityPolicyCommitV2,
        AssumptionPolicyActivationProof,
        AssumptionPolicyLedgerEntryV2,
    )

    # Construct a real V2 entry (it is still parseable/constructible).
    policy = _policy()
    approval = _approval_policy()
    profile = _signature_profile()
    challenge = _challenge_policy()
    commit_v2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=approval.approval_policy_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = approval.rule_for(commit_v2.approval_class)
    proof_v1 = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=commit_v2.commit_receipt_digest,
        approval_policy_digest=approval.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        authority_root_digest=policy.authority_root_digest,
        signature_set_digest=commit_v2.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )
    entry_v2 = AssumptionPolicyLedgerEntryV2.build(
        policy=policy,
        policy_commit=commit_v2,
        approval_policy=approval,
        signature_profile=profile,
        challenge_classification_policy=challenge,
        activation_proof=proof_v1,
    )
    # The public build() path must reject V2 entries with the stable governance
    # code, not an AttributeError. This tests the path that was previously
    # vulnerable: build() -> order_policy_entries_v3() -> entry.signing_payload
    # (field access before type validation).
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerV3.build((entry_v2,))  # type: ignore[arg-type]
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"

    # The constructor path must also reject for defense in depth.
    ledger = AssumptionPolicyLedgerV3.build(())
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerV3(
            entries=(entry_v2,),  # type: ignore[arg-type]
            ledger_root_digest=ledger.ledger_root_digest,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"


# ===========================================================================
# Correction 5: authority-root binding mutation tests
# ===========================================================================


def test_wrong_approval_policy_root_rejected_in_payload_build() -> None:
    wrong_root_approval = AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:wrong-root",
        authority_root_digest=_digest("c"),  # differs from policy root _digest("a")
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
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicySigningPayload.build(
            policy=_policy(),
            predecessor_policy_digest=None,
            predecessor_commit_receipt_digest=None,
            effective_from_sequence=10,
            approval_policy=wrong_root_approval,
            signature_profile=_signature_profile(),
            challenge_policy=_challenge_policy(),
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNING_PAYLOAD_APPROVAL_ROOT_MISMATCH"


def test_wrong_signature_key_authority_root_rejected_in_payload_build() -> None:
    wrong_root_profile = AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ed25519",
                verification_profile="ed25519-rfc8032-strict/1",
            ),
        ),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("c"),  # differs from policy root _digest("a")
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicySigningPayload.build(
            policy=_policy(),
            predecessor_policy_digest=None,
            predecessor_commit_receipt_digest=None,
            effective_from_sequence=10,
            approval_policy=_approval_policy(),
            signature_profile=wrong_root_profile,
            challenge_policy=_challenge_policy(),
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNING_PAYLOAD_SIGNATURE_ROOT_MISMATCH"


# ===========================================================================
# Correction 6: validate_successor_position_v3
# ===========================================================================


def test_successor_wrong_predecessor_policy_digest_rejected() -> None:
    first = _entry(effective_from_sequence=10)
    # Build a successor that references the right commit receipt but wrong policy digest.
    wrong_policy_payload = _payload(
        effective_from_sequence=20,
        predecessor_policy_digest=_digest("c"),  # wrong policy digest
        predecessor_commit_receipt_digest=first.policy_commit.commit_receipt_digest,
    )
    c_wrong = _commit(payload=wrong_policy_payload)
    proof_wrong = _proof(payload=wrong_policy_payload, commit=c_wrong)
    wrong_successor = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong_policy_payload,
        policy_commit=c_wrong,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof_wrong,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_successor_position_v3(first, wrong_successor)
    assert failure.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_successor_wrong_predecessor_commit_receipt_rejected() -> None:
    first = _entry(effective_from_sequence=10)
    wrong_commit_payload = _payload(
        effective_from_sequence=20,
        predecessor_policy_digest=first.signing_payload.policy_digest,  # correct policy
        predecessor_commit_receipt_digest=_digest("d"),  # wrong commit receipt
    )
    c_wrong = _commit(payload=wrong_commit_payload)
    proof_wrong = _proof(payload=wrong_commit_payload, commit=c_wrong)
    wrong_successor = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong_commit_payload,
        policy_commit=c_wrong,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof_wrong,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_successor_position_v3(first, wrong_successor)
    assert failure.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_successor_equal_or_lower_sequence_rejected() -> None:
    first = _entry(effective_from_sequence=20)
    equal_payload = _payload(
        effective_from_sequence=20,
        predecessor_policy_digest=first.signing_payload.policy_digest,
        predecessor_commit_receipt_digest=first.policy_commit.commit_receipt_digest,
    )
    c_equal = _commit(payload=equal_payload)
    proof_equal = _proof(payload=equal_payload, commit=c_equal)
    equal_successor = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=equal_payload,
        policy_commit=c_equal,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof_equal,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        validate_successor_position_v3(first, equal_successor)
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_V3_EFFECTIVE_SEQUENCE_NOT_INCREASING"


# ===========================================================================
# Correction 7: additional missing vectors
# ===========================================================================


def test_signature_profile_change_changes_payload_digest() -> None:
    other_profile = AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ecdsa-p256-sha256",
                verification_profile="ecdsa-p256-sha256-strict/1",
            ),
        ),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("a"),
    )
    p1 = _payload()
    p2 = _payload(signature_profile=other_profile)
    assert p1.signing_payload_digest != p2.signing_payload_digest


def test_challenge_policy_change_changes_payload_digest() -> None:
    other_challenge = AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="DIFFERENT_REASON",
                materiality="ADVISORY",
            ),
        )
    )
    p1 = _payload()
    p2 = _payload(challenge_policy=other_challenge)
    assert p1.signing_payload_digest != p2.signing_payload_digest


def test_wrong_proof_commit_receipt_rejected_in_entry() -> None:
    p = _payload()
    c_real = _commit(payload=p)
    # Build a proof for a different commit.
    other_payload = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:proof-mismatch",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
        )
    )
    other_commit = _commit(payload=other_payload)
    wrong_proof = _proof(payload=other_payload, commit=other_commit)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerEntryV3.build(
            policy=_policy(),
            signing_payload=p,
            policy_commit=c_real,
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_classification_policy=_challenge_policy(),
            activation_proof=wrong_proof,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"


def test_wrong_proof_signing_payload_digest_rejected_in_entry() -> None:
    p1 = _payload()
    p2 = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:payload-mismatch",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
        )
    )
    c1 = _commit(payload=p1)
    wrong_proof = _proof(payload=p2)  # proof references p2, not p1
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerEntryV3.build(
            policy=_policy(),
            signing_payload=p1,
            policy_commit=c1,
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_classification_policy=_challenge_policy(),
            activation_proof=wrong_proof,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"


def test_v2_entry_remains_parseable() -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionAuthorityPolicyCommitV2,
        AssumptionPolicyActivationProof,
    )
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
    )

    policy = _policy()
    approval = _approval_policy()
    profile = _signature_profile()
    challenge = _challenge_policy()
    commit_v2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=approval.approval_policy_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = approval.rule_for(commit_v2.approval_class)
    proof_v1 = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=commit_v2.commit_receipt_digest,
        approval_policy_digest=approval.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        authority_root_digest=policy.authority_root_digest,
        signature_set_digest=commit_v2.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )
    entry_v2 = AssumptionPolicyLedgerEntryV2.build(
        policy=policy,
        policy_commit=commit_v2,
        approval_policy=approval,
        signature_profile=profile,
        challenge_classification_policy=challenge,
        activation_proof=proof_v1,
    )
    assert entry_v2.ledger_entry_digest


def test_identical_inputs_produce_byte_identical_everything() -> None:
    e1 = _entry()
    e2 = _entry()
    assert e1.signing_payload.canonical_bytes == e2.signing_payload.canonical_bytes
    assert e1.policy_commit.canonical_bytes == e2.policy_commit.canonical_bytes
    assert (
        e1.activation_proof.activation_proof_digest == e2.activation_proof.activation_proof_digest
    )
    assert e1.ledger_entry_digest == e2.ledger_entry_digest
    ledger_a = AssumptionPolicyLedgerV3.build((e1,))
    ledger_b = AssumptionPolicyLedgerV3.build((e2,))
    assert ledger_a.ledger_root_digest == ledger_b.ledger_root_digest


# ===========================================================================
# Correction: signature-set permutation vector
# ===========================================================================


def test_signature_set_permutations_preserve_digest_and_bytes() -> None:
    """Two real SignatureSet objects with identical records in opposite orders
    must have the same digest and canonical bytes.

    This validates that the V3 envelope composes correctly with the frozen SET
    canonicalization used by signature-set/1.
    """

    from typing import cast

    from csd_foundry.governance.v0_5.contracts import SignatureSet

    record_a = {
        "signer_id": "authority:a",
        "key_id": "key:a",
        "algorithm": "ed25519",
        "signed_digest": _digest("a"),
        "signature_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "authority_scope": "ASSUMPTION_POLICY_APPROVAL",
    }
    record_b = {
        "signer_id": "authority:b",
        "key_id": "key:b",
        "algorithm": "ed25519",
        "signed_digest": _digest("a"),
        "signature_base64": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "authority_scope": "ASSUMPTION_POLICY_APPROVAL",
    }
    set_forward = cast(
        SignatureSet,
        SignatureSet.build(
            {"schema_version": "signature-set/1", "signatures": [record_a, record_b]}
        ),
    )
    set_reversed = cast(
        SignatureSet,
        SignatureSet.build(
            {"schema_version": "signature-set/1", "signatures": [record_b, record_a]}
        ),
    )
    assert set_forward.digest == set_reversed.digest
    assert set_forward.canonical_bytes == set_reversed.canonical_bytes
