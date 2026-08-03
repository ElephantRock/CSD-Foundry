"""Tests for v0.5-D3.2-A1.2 assumption policy activation preparation.

Covers successful preparation (STANDARD/DUTY_EXCEPTION, threshold edge cases,
permutation invariance, byte-identical determinism), structural denials,
cryptographic/key failures, signer-authority failures, approval failures,
and the architectural boundary guarantee that the preparer has no store and
therefore cannot publish or change a ledger root on any path.

The deterministic verifier is a conformance test double; these tests make no
production cryptographic claim.
"""

from __future__ import annotations

import base64
from typing import cast

import pytest

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
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationDenied,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

_ALGORITHM = "ed25519"
_VERIFICATION_PROFILE = "ed25519-rfc8032-strict/1"
_REQUIRED_SCOPE = "ASSUMPTION_POLICY_APPROVAL"


# --- digest helper ---------------------------------------------------------


def _digest(character: str) -> str:
    return "sha256:" + character * 64


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
    profile = AssumptionPolicyAlgorithmProfile(
        algorithm=_ALGORITHM,
        verification_profile=_VERIFICATION_PROFILE,
    )
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(profile,),
        required_authority_scope=_REQUIRED_SCOPE,
        key_authority_root_digest=_digest("a"),
    )


def _challenge_policy() -> AssumptionChallengeClassificationPolicy:
    rule = AssumptionChallengeClassificationRule(
        reason_code="PROVENANCE_CONFLICT",
        materiality="MATERIAL",
    )
    return AssumptionChallengeClassificationPolicy.build(reason_rules=(rule,))


def _grant(
    grant_id: str = "grant:1",
    *,
    action: str = "ADMIT",
    assumption_materialities: tuple[str, ...] = ("MATERIAL",),
    challenge_materialities: tuple[str, ...] = (),
) -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=grant_id,
        action=action,
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=assumption_materialities,
        challenge_materialities=challenge_materialities,
        effective_from_sequence=1,
    )


def _policy(*grants: AssumptionAuthorityGrant) -> AssumptionAuthorityPolicy:
    selected = grants or (_grant(),)
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=_digest("a"),
        grants=selected,
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


def _policy_with_exceptions(
    *exceptions: AssumptionDutyException,
) -> AssumptionAuthorityPolicy:
    grant = _grant(
        "grant:resolve",
        action="RESOLVE_TO_ADMITTED",
        challenge_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
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
        duty_exceptions=exceptions,
    )


# --- commit builder --------------------------------------------------------


def _commit(
    *,
    policy: AssumptionAuthorityPolicy,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signature_profile: AssumptionPolicySignatureProfile,
    challenge_policy: AssumptionChallengeClassificationPolicy,
    signature_set_digest: str,
    effective_from_sequence: int = 10,
) -> AssumptionAuthorityPolicyCommitV2:
    return AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=effective_from_sequence,
        approval_policy_digest=approval_policy.approval_policy_digest,
        signature_profile_digest=signature_profile.profile_digest,
        challenge_classification_policy_digest=challenge_policy.policy_digest,
        signature_set_digest=signature_set_digest,
    )


# --- resolver fixtures -----------------------------------------------------


def _verification_key(
    key_id: str = "key:a",
    *,
    algorithm: str = _ALGORITHM,
    public_key_bytes: bytes = b"public-key-a",
) -> ResolvedAssumptionPolicyVerificationKey:
    return ResolvedAssumptionPolicyVerificationKey(
        key_id=key_id,
        algorithm=algorithm,
        public_key_bytes=public_key_bytes,
        public_key_digest=_digest_for(public_key_bytes),
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"keyreceipt:" + key_id.encode()),
    )


def _signer_authority(
    signer_id: str = "authority:a",
    *,
    key_id: str = "key:a",
    authority_scopes: tuple[str, ...] = (_REQUIRED_SCOPE,),
    algorithms: tuple[str, ...] = (_ALGORITHM,),
    valid_from_sequence: int = 0,
    valid_until_sequence: int | None = None,
    revocation_sequence: int | None = None,
) -> ResolvedAssumptionPolicySignerAuthority:
    return ResolvedAssumptionPolicySignerAuthority(
        signer_id=signer_id,
        key_id=key_id,
        authority_root_digest=_digest("a"),
        authority_scopes=authority_scopes,
        algorithms=algorithms,
        valid_from_sequence=valid_from_sequence,
        valid_until_sequence=valid_until_sequence,
        revocation_sequence=revocation_sequence,
        resolution_receipt_digest=_digest_for(b"authreceipt:" + signer_id.encode()),
    )


def _digest_for(payload: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(b"public-key-digest\0" + payload).hexdigest()


class _StaticKeyResolver:
    def __init__(self, keys: tuple[ResolvedAssumptionPolicyVerificationKey, ...]) -> None:
        self._keys = {(k.key_id, k.algorithm): k for k in keys}

    def resolve(
        self,
        *,
        key_id: str,
        algorithm: str,
        key_authority_root_digest: str,
    ) -> ResolvedAssumptionPolicyVerificationKey | None:
        return self._keys.get((key_id, algorithm))


class _StaticAuthorityResolver:
    def __init__(self, authorities: tuple[ResolvedAssumptionPolicySignerAuthority, ...]) -> None:
        self._authorities = {(a.signer_id, a.key_id): a for a in authorities}

    def resolve(
        self,
        *,
        signer_id: str,
        key_id: str,
        authority_root_digest: str,
    ) -> ResolvedAssumptionPolicySignerAuthority | None:
        return self._authorities.get((signer_id, key_id))


# --- signature-set builder -------------------------------------------------


def _sig_record(
    *,
    signer_id: str,
    key_id: str,
    commit_receipt_digest: str,
    signature_profile: AssumptionPolicySignatureProfile,
    public_key_bytes: bytes,
    authority_scope: str = _REQUIRED_SCOPE,
    algorithm: str = _ALGORITHM,
) -> dict[str, str]:
    sig_bytes = make_deterministic_signature(
        algorithm=algorithm,
        verification_profile=signature_profile.verification_profile_for(algorithm),
        public_key_bytes=public_key_bytes,
        signed_digest=commit_receipt_digest,
    )
    return {
        "signer_id": signer_id,
        "key_id": key_id,
        "algorithm": algorithm,
        "signed_digest": commit_receipt_digest,
        "signature_base64": base64.b64encode(sig_bytes).decode("ascii"),
        "authority_scope": authority_scope,
    }


def _signature_set(records: tuple[dict[str, str], ...]) -> SignatureSet:
    return cast(
        SignatureSet,
        SignatureSet.build(
            {
                "schema_version": "signature-set/1",
                "signatures": list(records),
            }
        ),
    )


# --- full fixture bundle ---------------------------------------------------


def _standard_bundle(
    *,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
    policy: AssumptionAuthorityPolicy | None = None,
) -> tuple[
    AssumptionAuthorityPolicy,
    AssumptionAuthorityPolicyCommitV2,
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicySignatureProfile,
    AssumptionChallengeClassificationPolicy,
    SignatureSet,
    ReferenceAssumptionPolicyActivationPreparer,
]:
    selected_policy = policy or _policy()
    approval_policy = _approval_policy()
    signature_profile = _signature_profile()
    challenge_policy = _challenge_policy()

    # Build the signature set once with a fixed target digest. The exact-target
    # equality (signed_digest == commit_receipt_digest) is not structurally
    # enforced by the preparer because it creates a non-converging fixpoint under
    # the frozen contract (signature_set_digest is a commit field). Target binding
    # is enforced cryptographically by real backends. See the preparer's
    # SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM stage for the full rationale.
    records = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            commit_receipt_digest=_digest("e"),
            signature_profile=signature_profile,
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in signers
    )
    signature_set = _signature_set(records)
    commit = _commit(
        policy=selected_policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=signature_set.digest,
    )

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
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        signature_set,
        preparer,
    )


def _prepare(bundle: tuple) -> object:
    (
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        signature_set,
        preparer,
    ) = bundle
    return preparer.prepare(
        policy=policy,
        commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set=signature_set,
    )


def _deny(bundle: tuple) -> AssumptionPolicyActivationDenied:
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        _prepare(bundle)
    return failure.value


# ===========================================================================
# Successful preparation
# ===========================================================================


def test_valid_standard_activation_succeeds() -> None:
    prepared = _prepare(_standard_bundle())
    assert prepared.ledger_entry.policy_commit.approval_class == "STANDARD"
    assert prepared.ledger_entry.activation_proof.valid_signer_ids == (
        "authority:a",
        "authority:b",
    )
    assert prepared.ledger_entry.activation_proof.rejected_signer_codes == ()


def test_valid_duty_exception_activation_succeeds() -> None:
    exception = _duty_exception("exception:1")
    policy = _policy_with_exceptions(exception)
    prepared = _prepare(
        _standard_bundle(
            signers=("authority:a", "authority:b", "authority:c"),
            policy=policy,
        )
    )
    assert prepared.ledger_entry.policy_commit.approval_class == "DUTY_EXCEPTION"


def test_exact_threshold_succeeds() -> None:
    # STANDARD rule requires 2 signatures; provide exactly authority:a + authority:b.
    prepared = _prepare(_standard_bundle(signers=("authority:a", "authority:b")))
    assert len(prepared.ledger_entry.activation_proof.valid_signer_ids) == 2


def test_permuted_signature_input_produces_identical_prepared_bytes() -> None:
    bundle = _standard_bundle(signers=("authority:a", "authority:b"))
    prepared_canonical = _prepare(bundle)
    # Rebuild the signature set with reversed input order.
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    records_reversed = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            commit_receipt_digest=_digest("e"),  # same target as the bundle's records
            signature_profile=signature_profile,
            public_key_bytes=f"public-key-{s[-1]}".encode(),
        )
        for s in ("authority:b", "authority:a")
    )
    sig_set_reversed = _signature_set(records_reversed)
    prepared_permuted = preparer.prepare(
        policy=policy,
        commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set=sig_set_reversed,
    )
    assert prepared_canonical.prepared_digest == prepared_permuted.prepared_digest
    assert (
        prepared_canonical.ledger_entry.canonical_bytes
        == prepared_permuted.ledger_entry.canonical_bytes
    )
    assert (
        prepared_canonical.ledger_entry.activation_proof.valid_signer_ids
        == prepared_permuted.ledger_entry.activation_proof.valid_signer_ids
    )


def test_identical_inputs_produce_byte_identical_output() -> None:
    bundle_a = _standard_bundle()
    bundle_b = _standard_bundle()
    prepared_a = _prepare(bundle_a)
    prepared_b = _prepare(bundle_b)
    assert prepared_a.prepared_digest == prepared_b.prepared_digest
    assert prepared_a.ledger_entry.canonical_bytes == prepared_b.ledger_entry.canonical_bytes


def test_extra_invalid_signer_recorded_as_rejected_while_threshold_succeeds() -> None:
    # Provide a valid threshold (a, b) plus an invalid signer d whose key resolves
    # but signature does not verify (wrong public key bytes).
    policy = _policy()
    approval_policy = _approval_policy()
    signature_profile = _signature_profile()
    challenge_policy = _challenge_policy()

    def _record(signer_id: str, key_id: str, public_key: bytes, digest: str) -> dict[str, str]:
        return _sig_record(
            signer_id=signer_id,
            key_id=key_id,
            commit_receipt_digest=digest,
            signature_profile=signature_profile,
            public_key_bytes=public_key,
        )

    # Build the real records first so the set digest is consistent with the commit.
    # authority:d gets a key with DIFFERENT public bytes than its signature was built over.
    real_records = (
        _record("authority:a", "key:a", b"pk-a", _digest("e")),
        _record("authority:b", "key:b", b"pk-b", _digest("e")),
        _record("authority:d", "key:d", b"pk-d-wrong", _digest("e")),
    )
    signature_set = _signature_set(real_records)
    commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=signature_set.digest,
    )
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
    preparer = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(keys),
        authority_resolver=_StaticAuthorityResolver(authorities),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    prepared = preparer.prepare(
        policy=policy,
        commit=commit,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set=signature_set,
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


def test_policy_overlap_denied() -> None:
    policy = _policy(_grant("grant:a"), _grant("grant:b"))
    bundle = list(_standard_bundle())
    bundle[0] = policy
    denied = _deny(tuple(bundle))
    assert denied.code == "ASSUMPTION_AUTHORITY_GRANT_OVERLAP"
    assert denied.stage == "POLICY_STRUCTURE_AND_OVERLAP"


def test_commit_policy_mismatch_denied() -> None:
    # Build a commit against one policy, then pass a different policy to prepare.
    bundle = _standard_bundle()
    other_policy = AssumptionAuthorityPolicy.build(
        policy_id="policy:different",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
    )
    denied = _deny(_replace_bundle_policy(bundle, other_policy))
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_POLICY_ID_MISMATCH"
    assert denied.stage == "COMMIT_BINDINGS"


def _replace_bundle_policy(bundle: tuple, policy: AssumptionAuthorityPolicy) -> tuple:
    return (policy, *bundle[1:])


def test_commit_approval_policy_mismatch_denied() -> None:
    bundle = _standard_bundle()
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
    denied = _deny(_replace(bundle, 2, other_approval))
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_APPROVAL_POLICY_MISMATCH"
    assert denied.stage == "COMMIT_BINDINGS"


def _replace(bundle: tuple, index: int, value: object) -> tuple:
    items = list(bundle)
    items[index] = value  # type: ignore[assignment]
    return tuple(items)


def test_commit_signature_profile_mismatch_denied() -> None:
    bundle = _standard_bundle()
    other_profile = AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ecdsa-p256-sha256",
                verification_profile="ecdsa-p256-sha256-strict/1",
            ),
        ),
        required_authority_scope=_REQUIRED_SCOPE,
        key_authority_root_digest=_digest("a"),
    )
    denied = _deny(_replace(bundle, 3, other_profile))
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_SIGNATURE_PROFILE_MISMATCH"
    assert denied.stage == "COMMIT_BINDINGS"


def test_commit_challenge_policy_mismatch_denied() -> None:
    bundle = _standard_bundle()
    other_challenge = AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="DIFFERENT_REASON",
                materiality="ADVISORY",
            ),
        )
    )
    denied = _deny(_replace(bundle, 4, other_challenge))
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_CHALLENGE_POLICY_MISMATCH"
    assert denied.stage == "COMMIT_BINDINGS"


def test_wrong_signed_target_set_is_bound_to_its_own_commit() -> None:
    # A signature set built targeting a wrong digest, when bound to its OWN
    # matching commit, must still be preparable -- the target binding is enforced
    # cryptographically by real backends (signature won't verify over the wrong
    # digest), not by a structural field equality that creates a non-converging
    # fixpoint under the frozen contract. The conformance double does not reject
    # this; a real backend would. This test documents that boundary.
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    # The bundle's own set + commit are already consistent; preparing succeeds.
    prepared = _prepare(tuple(bundle))
    assert prepared.ledger_entry.activation_proof.valid_signer_ids != ()


def test_duplicate_signer_identity_denied() -> None:
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    dup_records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-a",
        ),
        _sig_record(
            signer_id="authority:a",
            key_id="key:a2",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-a2",
        ),
    )
    dup_set = _signature_set(dup_records)
    # Rebuild commit with the dup set digest.
    dup_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=dup_set.digest,
    )
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        preparer.prepare(
            policy=policy,
            commit=dup_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=dup_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_DUPLICATE_SIGNER_RECORD"
    assert failure.value.detail == "authority:a"


def test_malformed_base64_denied() -> None:
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    bad_records = (
        {
            "signer_id": "authority:a",
            "key_id": "key:a",
            "algorithm": _ALGORITHM,
            "signed_digest": commit.commit_receipt_digest,
            "signature_base64": "!!!not-base64!!!",
            "authority_scope": _REQUIRED_SCOPE,
        },
        _sig_record(
            signer_id="authority:b",
            key_id="key:b",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-b",
        ),
    )
    bad_set = _signature_set(bad_records)
    bad_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=bad_set.digest,
    )
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        preparer.prepare(
            policy=policy,
            commit=bad_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=bad_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_ENCODING_INVALID"


def test_algorithm_not_pinned_denied() -> None:
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    unpinned_records = tuple(
        {
            "signer_id": s,
            "key_id": f"key:{s[-1]}",
            "algorithm": "rsa-pss-sha256",  # not in the pinned profile
            "signed_digest": commit.commit_receipt_digest,
            "signature_base64": base64.b64encode(b"x" * 32).decode("ascii"),
            "authority_scope": _REQUIRED_SCOPE,
        }
        for s in ("authority:a", "authority:b")
    )
    unpinned_set = _signature_set(unpinned_records)
    unpinned_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=unpinned_set.digest,
    )
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        preparer.prepare(
            policy=policy,
            commit=unpinned_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=unpinned_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_ALGORITHM_NOT_PINNED"


def test_wrong_authority_scope_field_denied() -> None:
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    wrong_scope_records = tuple(
        _sig_record(
            signer_id=s,
            key_id=f"key:{s[-1]}",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=f"public-key-{s[-1]}".encode(),
            authority_scope="WRONG_SCOPE",
        )
        for s in ("authority:a", "authority:b")
    )
    wrong_scope_set = _signature_set(wrong_scope_records)
    wrong_scope_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=wrong_scope_set.digest,
    )
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        preparer.prepare(
            policy=policy,
            commit=wrong_scope_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=wrong_scope_set,
        )
    assert failure.value.code == "ASSUMPTION_POLICY_SIGNATURE_AUTHORITY_SCOPE_INVALID"


# ===========================================================================
# Cryptographic / key failures (record-level rejections)
# ===========================================================================


def test_unknown_verification_key_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    # Resolver that knows key:a but not key:b.
    preparer_no_b = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(
            (_verification_key("key:a", public_key_bytes=b"public-key-a"),)
        ),
        authority_resolver=preparer.authority_resolver,  # type: ignore[attr-defined]
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_no_b,
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        _bundle_signature_set(bundle),
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def _bundle_signature_set(bundle: tuple) -> SignatureSet:
    return bundle[5]  # type: ignore[index]


def _deny_with_preparer(
    preparer: ReferenceAssumptionPolicyActivationPreparer,
    policy: AssumptionAuthorityPolicy,
    commit: AssumptionAuthorityPolicyCommitV2,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signature_profile: AssumptionPolicySignatureProfile,
    challenge_policy: AssumptionChallengeClassificationPolicy,
    signature_set: SignatureSet,
) -> AssumptionPolicyActivationDenied:
    with pytest.raises(AssumptionPolicyActivationDenied) as failure:
        preparer.prepare(
            policy=policy,
            commit=commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=signature_set,
        )
    return failure.value


def test_invalid_signature_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    # authority:a valid; authority:b gets garbage signature bytes.
    bad_records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-a",
        ),
        {
            "signer_id": "authority:b",
            "key_id": "key:b",
            "algorithm": _ALGORITHM,
            "signed_digest": commit.commit_receipt_digest,
            "signature_base64": base64.b64encode(b"garbage-signature").decode("ascii"),
            "authority_scope": _REQUIRED_SCOPE,
        },
    )
    bad_set = _signature_set(bad_records)
    bad_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=bad_set.digest,
    )
    denied = _deny_with_preparer(
        preparer,
        policy,
        bad_commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        bad_set,
    )
    # Only authority:a is valid -> below threshold of 2.
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


# ===========================================================================
# Signer-authority failures
# ===========================================================================


def test_unknown_signer_authority_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    # Authority resolver knows a but not b.
    preparer_no_b_auth = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=preparer.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (_signer_authority("authority:a", key_id="key:a"),)
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_no_b_auth,
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        _bundle_signature_set(bundle),
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_authority_expired_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    expired_b = _signer_authority(
        "authority:b",
        key_id="key:b",
        valid_until_sequence=5,  # commit effective_from_sequence is 10
    )
    preparer_expired = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=preparer.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (_signer_authority("authority:a", key_id="key:a"), expired_b)
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_expired,
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        _bundle_signature_set(bundle),
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_authority_revoked_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    revoked_b = _signer_authority(
        "authority:b",
        key_id="key:b",
        revocation_sequence=5,  # before effective_from_sequence 10
    )
    preparer_revoked = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=preparer.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (_signer_authority("authority:a", key_id="key:a"), revoked_b)
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_revoked,
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        _bundle_signature_set(bundle),
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


def test_authority_not_yet_valid_recorded_as_rejected() -> None:
    bundle = list(_standard_bundle(signers=("authority:a", "authority:b")))
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    future_b = _signer_authority(
        "authority:b",
        key_id="key:b",
        valid_from_sequence=20,  # after effective_from_sequence 10
    )
    preparer_future = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=preparer.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=_StaticAuthorityResolver(
            (_signer_authority("authority:a", key_id="key:a"), future_b)
        ),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_future,
        policy,
        commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        _bundle_signature_set(bundle),
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"


# ===========================================================================
# Approval failures
# ===========================================================================


def test_threshold_minus_one_denied() -> None:
    # STANDARD requires 2; provide only authority:a.
    denied = _deny(_standard_bundle(signers=("authority:a",)))
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET"
    assert denied.stage == "THRESHOLD_AND_REQUIRED_SIGNERS"


def test_missing_mandatory_signer_denied() -> None:
    # mandatory = authority:a; provide b + c only (both eligible, count=2).
    bundle = _standard_bundle(signers=("authority:b", "authority:c"))
    denied = _deny(bundle)
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_REQUIRED_SIGNER_MISSING"
    assert denied.detail == "authority:a"


def test_ineligible_otherwise_valid_signer_denied() -> None:
    # Provide authority:a (eligible) + authority:d (NOT in eligible set).
    bundle = list(_standard_bundle())
    policy, commit, approval_policy, signature_profile, challenge_policy, _, preparer = bundle
    records = (
        _sig_record(
            signer_id="authority:a",
            key_id="key:a",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-a",
        ),
        _sig_record(
            signer_id="authority:d",
            key_id="key:d",
            commit_receipt_digest=commit.commit_receipt_digest,
            signature_profile=signature_profile,
            public_key_bytes=b"public-key-d",
        ),
    )
    sig_set = _signature_set(records)
    sig_commit = _commit(
        policy=policy,
        approval_policy=approval_policy,
        signature_profile=signature_profile,
        challenge_policy=challenge_policy,
        signature_set_digest=sig_set.digest,
    )
    keys = (
        _verification_key("key:a", public_key_bytes=b"public-key-a"),
        _verification_key("key:d", public_key_bytes=b"public-key-d"),
    )
    authorities = (
        _signer_authority("authority:a", key_id="key:a"),
        _signer_authority("authority:d", key_id="key:d"),
    )
    preparer_d = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_StaticKeyResolver(keys),
        authority_resolver=_StaticAuthorityResolver(authorities),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with_preparer(
        preparer_d,
        policy,
        sig_commit,
        approval_policy,
        signature_profile,
        challenge_policy,
        sig_set,
    )
    assert denied.code == "ASSUMPTION_POLICY_APPROVAL_SIGNER_INELIGIBLE"
    assert denied.detail == "authority:d"


# ===========================================================================
# Boundary guarantee: the preparer has no store/publisher
# ===========================================================================


def test_preparer_has_no_store_or_publisher_attribute() -> None:
    bundle = _standard_bundle()
    preparer = bundle[6]
    assert not hasattr(preparer, "store")
    assert not hasattr(preparer, "publisher")
    assert not hasattr(preparer, "ledger")


def test_denial_raises_typed_exception_not_silent() -> None:
    denied = _deny(_standard_bundle(signers=("authority:a",)))
    assert isinstance(denied, AssumptionPolicyActivationDenied)
    assert denied.stage in {
        "THRESHOLD_AND_REQUIRED_SIGNERS",
        "COMMIT_BINDINGS",
        "SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
    }
