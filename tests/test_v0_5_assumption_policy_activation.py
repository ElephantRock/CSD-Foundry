"""Tests for v0.5-D3.2-A1.2 assumption policy activation preparation (V3 envelope).

Validates the corrected preparation path against the non-circular V3 signing
envelope: signatures target ``signing_payload_digest``, the commit binds the
pre-signing payload to the post-signature signature set, and there is no
self-referential dependency.

The deterministic verifier is a conformance test double; these tests make no
production cryptographic claim.
"""

from __future__ import annotations

import base64
import hashlib
from typing import cast

import pytest

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicySigningPayload,
    deterministic_policy_signature_bytes,
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
from csd_foundry.governance.v0_5.assumption_policy_activation import (
    DeterministicAssumptionPolicySignatureVerifier,
    ReferenceAssumptionPolicyActivationPreparer,
    ResolvedAssumptionPolicySignerAuthority,
    ResolvedAssumptionPolicyVerificationKey,
    make_deterministic_signature,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_contracts import (
    AssumptionAuthorityPolicyCommitV2,
    AssumptionPolicyActivationDenied,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

_ALGORITHM = "ed25519"
_VERIFICATION_PROFILE = "ed25519-rfc8032-strict/1"
_REQUIRED_SCOPE = "ASSUMPTION_POLICY_APPROVAL"


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _digest_for(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"pkd\0" + payload).hexdigest()


# --- reusable frozen inputs ------------------------------------------------


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
                algorithm=_ALGORITHM,
                verification_profile=_VERIFICATION_PROFILE,
            ),
        ),
        required_authority_scope=_REQUIRED_SCOPE,
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


# --- V3 signing payload + commit ------------------------------------------


def _signing_payload(
    *,
    policy: AssumptionAuthorityPolicy | None = None,
    effective_from_sequence: int = 10,
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=effective_from_sequence,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_policy=_challenge_policy(),
    )


def _commit_v3(
    *,
    payload: AssumptionPolicySigningPayload,
    signature_set_digest: str,
) -> AssumptionAuthorityPolicyCommitV3:
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=signature_set_digest,
    )


# --- resolver fixtures -----------------------------------------------------


def _verification_key(
    key_id: str = "key:a",
    *,
    public_key_bytes: bytes = b"public-key-a",
) -> ResolvedAssumptionPolicyVerificationKey:
    return ResolvedAssumptionPolicyVerificationKey(
        key_id=key_id,
        algorithm=_ALGORITHM,
        public_key_bytes=public_key_bytes,
        public_key_digest=_digest_for(public_key_bytes),
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"keyrect:" + key_id.encode()),
    )


def _signer_authority(
    signer_id: str = "authority:a",
    *,
    key_id: str = "key:a",
    valid_from_sequence: int = 0,
    valid_until_sequence: int | None = None,
    revocation_sequence: int | None = None,
) -> ResolvedAssumptionPolicySignerAuthority:
    return ResolvedAssumptionPolicySignerAuthority(
        signer_id=signer_id,
        key_id=key_id,
        authority_root_digest=_digest("a"),
        authority_scopes=(_REQUIRED_SCOPE,),
        algorithms=(_ALGORITHM,),
        valid_from_sequence=valid_from_sequence,
        valid_until_sequence=valid_until_sequence,
        revocation_sequence=revocation_sequence,
        resolution_receipt_digest=_digest_for(b"authrect:" + signer_id.encode()),
    )


class _StaticKeyResolver:
    def __init__(self, keys: tuple[ResolvedAssumptionPolicyVerificationKey, ...]) -> None:
        self._keys = {(k.key_id, k.algorithm): k for k in keys}

    def resolve(
        self, *, key_id: str, algorithm: str, key_authority_root_digest: str
    ) -> ResolvedAssumptionPolicyVerificationKey | None:
        return self._keys.get((key_id, algorithm))


class _StaticAuthorityResolver:
    def __init__(self, authorities: tuple[ResolvedAssumptionPolicySignerAuthority, ...]) -> None:
        self._authorities = {(a.signer_id, a.key_id): a for a in authorities}

    def resolve(
        self, *, signer_id: str, key_id: str, authority_root_digest: str
    ) -> ResolvedAssumptionPolicySignerAuthority | None:
        return self._authorities.get((signer_id, key_id))


# --- signature helpers -----------------------------------------------------


def _sig_record(
    *,
    signer_id: str,
    key_id: str,
    signing_payload_digest: str,
    public_key_bytes: bytes,
    authority_scope: str = _REQUIRED_SCOPE,
    algorithm: str = _ALGORITHM,
) -> dict[str, str]:
    sig_bytes = make_deterministic_signature(
        algorithm=algorithm,
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=public_key_bytes,
        signed_digest=signing_payload_digest,
    )
    return {
        "signer_id": signer_id,
        "key_id": key_id,
        "algorithm": algorithm,
        "signed_digest": signing_payload_digest,
        "signature_base64": base64.b64encode(sig_bytes).decode("ascii"),
        "authority_scope": authority_scope,
    }


def _signature_set(records: tuple[dict[str, str], ...]) -> SignatureSet:
    return cast(
        SignatureSet,
        SignatureSet.build({"schema_version": "signature-set/1", "signatures": list(records)}),
    )


# --- full fixture bundle ---------------------------------------------------
# No fixpoint needed: the signing payload is built first, signatures target
# its digest, and the commit binds both independently.


def _bundle(
    *,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
    policy: AssumptionAuthorityPolicy | None = None,
):
    selected_policy = policy or _policy()
    payload = _signing_payload(policy=selected_policy)
    records = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in signers
    )
    sig_set = _signature_set(records)
    commit = _commit_v3(payload=payload, signature_set_digest=sig_set.digest)
    keys = tuple(
        _verification_key(
            key_id=f"key:{s[-1]}",
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in signers
    )
    authorities = tuple(_signer_authority(signer_id=s, key_id=f"key:{s[-1]}") for s in signers)
    preparer = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(keys),
        authority_resolver=_StaticAuthorityResolver(authorities),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    return (
        selected_policy,
        payload,
        commit,
        _approval_policy(),
        _signature_profile(),
        _challenge_policy(),
        sig_set,
        preparer,
    )


def _prepare(bundle) -> object:
    policy, payload, commit, ap, sp, cp, ss, prep = bundle
    return prep.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=ss,
    )


def _deny(bundle) -> AssumptionPolicyActivationDenied:
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        _prepare(bundle)
    return failure.value


# ===========================================================================
# Successful preparation
# ===========================================================================


def test_valid_standard_preparation_succeeds() -> None:
    prepared = _prepare(_bundle())
    assert prepared.ledger_entry.activation_proof.valid_signer_ids == (
        "authority:a",
        "authority:b",
    )
    assert prepared.ledger_entry.activation_proof.rejected_signer_codes == ()


def test_valid_duty_exception_preparation_succeeds() -> None:
    prepared = _prepare(
        _bundle(
            signers=("authority:a", "authority:b", "authority:c"),
            policy=_policy_with_exception(),
        )
    )
    assert prepared.ledger_entry.policy_commit.signing_payload_digest


def test_exact_threshold_succeeds() -> None:
    prepared = _prepare(_bundle(signers=("authority:a", "authority:b")))
    assert len(prepared.ledger_entry.activation_proof.valid_signer_ids) == 2


def test_permuted_signatures_produce_identical_prepared_bytes() -> None:
    bundle = _bundle(signers=("authority:a", "authority:b"))
    prepared_a = _prepare(bundle)
    policy, payload, commit, ap, sp, cp, _, prep = bundle
    records_rev = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in ("authority:b", "authority:a")
    )
    sig_rev = _signature_set(records_rev)
    prepared_b = prep.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=sig_rev,
    )
    assert prepared_a.prepared_digest == prepared_b.prepared_digest


def test_identical_inputs_produce_identical_output() -> None:
    a = _prepare(_bundle())
    b = _prepare(_bundle())
    assert a.prepared_digest == b.prepared_digest


def test_extra_rejected_signer_recorded_while_threshold_succeeds() -> None:
    # a + b valid; d has wrong key bytes (signature won't verify).
    policy = _policy()
    payload = _signing_payload(policy=policy)
    records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-a",
        ),
        _sig_record(
            signer_id="authority:b",
            key_id="key:b",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-b",
        ),
        _sig_record(
            signer_id="authority:d",
            key_id="key:d",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-d-wrong",
        ),
    )
    sig_set = _signature_set(records)
    commit = _commit_v3(payload=payload, signature_set_digest=sig_set.digest)
    keys = (
        _verification_key("key:a", public_key_bytes=b"pk-a"),
        _verification_key("key:b", public_key_bytes=b"pk-b"),
        _verification_key("key:d", public_key_bytes=b"pk-d-real"),
    )
    authorities = (
        _signer_authority("authority:a", key_id="key:a"),
        _signer_authority("authority:b", key_id="key:b"),
        _signer_authority("authority:d", key_id="key:d"),
    )
    prep = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(keys),
        authority_resolver=_StaticAuthorityResolver(authorities),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    prepared = prep.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_policy=_challenge_policy(),
        signature_set=sig_set,
    )
    assert prepared.ledger_entry.activation_proof.valid_signer_ids == (
        "authority:a",
        "authority:b",
    )
    assert prepared.ledger_entry.activation_proof.rejected_signer_codes == (
        "ASSUMPTION_POLICY_SIGNATURE_INVALID",
    )


# ===========================================================================
# Structural denials
# ===========================================================================


def test_commit_v2_rejected_before_cryptography() -> None:
    policy = _policy()
    payload = _signing_payload(policy=policy)
    # Build a V2 commit (the old self-referential shape).
    commit_v2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        signature_profile_digest=_signature_profile().profile_digest,
        challenge_classification_policy_digest=_challenge_policy().policy_digest,
        signature_set_digest=_digest("b"),
    )
    prep = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(()),
        authority_resolver=_StaticAuthorityResolver(()),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=commit_v2,  # type: ignore[arg-type]
            approval_policy=_approval_policy(),
            signature_profile=_signature_profile(),
            challenge_policy=_challenge_policy(),
            signature_set=_signature_set(
                (
                    _sig_record(
                        signer_id="authority:a",
                        key_id="key:a",
                        signing_payload_digest=payload.signing_payload_digest,
                        public_key_bytes=b"pk-a",
                    ),
                )
            ),
        )
    assert failure.value.code == "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
    assert failure.value.stage == "PARSE_AND_SELF_DIGESTS"


def test_commit_payload_mismatch_denied() -> None:
    bundle = list(_bundle())
    policy, payload, _, ap, sp, cp, ss, prep = bundle
    other_payload = _signing_payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:other", authority_root_digest=_digest("a"), grants=(_grant(),)
        )
    )
    wrong_commit = _commit_v3(payload=other_payload, signature_set_digest=ss.digest)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=wrong_commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=ss,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_COMMIT_PAYLOAD_MISMATCH"


def test_commit_signature_set_mismatch_denied() -> None:
    bundle = list(_bundle())
    policy, payload, commit, ap, sp, cp, _, prep = bundle
    # Build a different signature set.
    other_records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"different-pk",
        ),
    )
    other_set = _signature_set(other_records)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=other_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_MISMATCH"


def test_wrong_signed_target_rejected_before_key_resolution() -> None:
    bundle = list(_bundle())
    policy, payload, commit, ap, sp, cp, _, prep = bundle
    wrong_records = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            signing_payload_digest=_digest("f"),  # wrong target
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in ("authority:a", "authority:b")
    )
    wrong_set = _signature_set(wrong_records)
    wrong_commit = _commit_v3(payload=payload, signature_set_digest=wrong_set.digest)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=wrong_commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=wrong_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"
    assert failure.value.stage == "SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM"


def test_duplicate_signer_denied() -> None:
    bundle = list(_bundle(signers=("authority:a",)))
    policy, payload, commit, ap, sp, cp, _, prep = bundle
    dup_records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-a",
        ),
        _sig_record(
            signer_id="authority:a",
            key_id="key:a2",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-a2",
        ),
    )
    dup_set = _signature_set(dup_records)
    dup_commit = _commit_v3(payload=payload, signature_set_digest=dup_set.digest)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=dup_commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=dup_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_DUPLICATE_SIGNER_RECORD"


def test_malformed_base64_denied() -> None:
    bundle = list(_bundle())
    policy, payload, commit, ap, sp, cp, _, prep = bundle
    bad_records = (
        {
            "signer_id": "authority:a",
            "key_id": "key:a",
            "algorithm": _ALGORITHM,
            "signed_digest": payload.signing_payload_digest,
            "signature_base64": "!!!not-base64!!!",
            "authority_scope": _REQUIRED_SCOPE,
        },
        _sig_record(
            signer_id="authority:b",
            key_id="key:b",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-b",
        ),
    )
    bad_set = _signature_set(bad_records)
    bad_commit = _commit_v3(payload=payload, signature_set_digest=bad_set.digest)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=bad_commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=bad_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_ENCODING_INVALID"


def test_algorithm_not_pinned_denied() -> None:
    bundle = list(_bundle())
    policy, payload, _, ap, sp, cp, _, prep = bundle
    unpinned_records = tuple(
        {
            "signer_id": s,
            "key_id": f"key:{s[-1]}",
            "algorithm": "rsa-pss-sha256",
            "signed_digest": payload.signing_payload_digest,
            "signature_base64": base64.b64encode(b"x" * 32).decode("ascii"),
            "authority_scope": _REQUIRED_SCOPE,
        }
        for s in ("authority:a", "authority:b")
    )
    unpinned_set = _signature_set(unpinned_records)
    unpinned_commit = _commit_v3(payload=payload, signature_set_digest=unpinned_set.digest)
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=unpinned_commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=unpinned_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_ALGORITHM_NOT_PINNED"


# ===========================================================================
# Approval failures
# ===========================================================================


def test_threshold_minus_one_denied() -> None:
    denied = _deny(_bundle(signers=("authority:a",)))
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_missing_mandatory_signer_denied() -> None:
    denied = _deny(_bundle(signers=("authority:b", "authority:c")))
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_REQUIRED_SIGNER_MISSING"
    assert denied.detail == "authority:a"


def test_ineligible_signer_denied() -> None:
    bundle = list(_bundle())
    policy, payload, _, ap, sp, cp, _, prep = bundle
    records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-a",
        ),
        _sig_record(
            signer_id="authority:d",
            key_id="key:d",
            signing_payload_digest=payload.signing_payload_digest,
            public_key_bytes=b"pk-d",
        ),
    )
    sig_set = _signature_set(records)
    commit = _commit_v3(payload=payload, signature_set_digest=sig_set.digest)
    keys = (
        _verification_key("key:a", public_key_bytes=b"pk-a"),
        _verification_key("key:d", public_key_bytes=b"pk-d"),
    )
    authorities = (
        _signer_authority("authority:a", key_id="key:a"),
        _signer_authority("authority:d", key_id="key:d"),
    )
    prep_d = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(keys),
        authority_resolver=_StaticAuthorityResolver(authorities),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied_prep = _deny_with(prep_d, policy, payload, commit, ap, sp, cp, sig_set)
    assert denied_prep.code == "ASSUMPTION_POLICY_APPROVAL_SIGNER_INELIGIBLE"


def _deny_with(prep, policy, payload, commit, ap, sp, cp, ss) -> AssumptionPolicyActivationDenied:
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        prep.prepare(
            policy=policy,
            signing_payload=payload,
            commit=commit,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=ss,
        )
    return failure.value


# ===========================================================================
# Signer-authority failures (record-level rejections)
# ===========================================================================


def test_unknown_key_recorded_as_rejected() -> None:
    bundle = list(_bundle(signers=("authority:a", "authority:b")))
    policy, payload, commit, ap, sp, cp, ss, prep = bundle
    prep_no_b = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(
            (_verification_key("key:a", public_key_bytes=b"public-key-a"),)
        ),
        authority_resolver=prep.authority_resolver,  # type: ignore[attr-defined]
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with(prep_no_b, policy, payload, commit, ap, sp, cp, ss)
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_authority_expired_recorded_as_rejected() -> None:
    bundle = list(_bundle(signers=("authority:a", "authority:b")))
    policy, payload, commit, ap, sp, cp, ss, prep = bundle
    expired = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=prep.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (
                _signer_authority("authority:a", key_id="key:a"),
                _signer_authority("authority:b", key_id="key:b", valid_until_sequence=5),
            )
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with(expired, policy, payload, commit, ap, sp, cp, ss)
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_authority_revoked_recorded_as_rejected() -> None:
    bundle = list(_bundle(signers=("authority:a", "authority:b")))
    policy, payload, commit, ap, sp, cp, ss, prep = bundle
    revoked = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=prep.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (
                _signer_authority("authority:a", key_id="key:a"),
                _signer_authority("authority:b", key_id="key:b", revocation_sequence=5),
            )
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with(revoked, policy, payload, commit, ap, sp, cp, ss)
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


# ===========================================================================
# V3 integration: proof/2 binds payload + commit/3; entry/3 produced
# ===========================================================================


def test_proof_v2_binds_signing_payload_and_commit() -> None:
    prepared = _prepare(_bundle())
    proof = prepared.ledger_entry.activation_proof
    payload = prepared.ledger_entry.signing_payload
    commit = prepared.ledger_entry.policy_commit
    assert proof.signing_payload_digest == payload.signing_payload_digest
    assert proof.policy_commit_receipt_digest == commit.commit_receipt_digest


def test_entry_v3_is_produced() -> None:
    prepared = _prepare(_bundle())
    assert type(prepared.ledger_entry) is AssumptionPolicyLedgerEntryV3


def test_entry_v2_is_never_produced() -> None:
    prepared = _prepare(_bundle())
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
    )

    assert not isinstance(prepared.ledger_entry, AssumptionPolicyLedgerEntryV2)


# ===========================================================================
# Boundary guarantee
# ===========================================================================


def test_preparer_has_no_store_or_publisher() -> None:
    bundle = _bundle()
    prep = bundle[7]
    assert not hasattr(prep, "store")
    assert not hasattr(prep, "publisher")
    assert not hasattr(prep, "ledger")


# ===========================================================================
# Deterministic verifier message-binding
# ===========================================================================


def test_changed_signed_digest_changes_expected_bytes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk",
        signed_digest=_digest("b"),
    )
    assert sig_a != sig_b


def test_changed_key_changes_expected_bytes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk-a",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk-b",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b


def test_changed_algorithm_changes_expected_bytes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm="ecdsa-p256-sha256",
        verification_profile=_VERIFICATION_PROFILE,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b


def test_changed_profile_changes_expected_bytes() -> None:
    sig_a = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    sig_b = deterministic_policy_signature_bytes(
        algorithm=_ALGORITHM,
        verification_profile="ed25519-rfc8032-strict/2",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert sig_a != sig_b
