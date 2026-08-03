"""Tests for v0.5-D3.2-A1.3-A V3 publication contracts and in-memory execution.

Validates the publication half of the activation order against the non-circular
V3 signing envelope: expected ledger state, exact idempotence, compare-and-append
with deterministic conflict semantics, in-memory atomic publication, and
complete service composition (preparer + publisher).
"""

from __future__ import annotations

import base64
import hashlib
from typing import cast

import pytest

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
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
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
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
from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
    AssumptionPolicyPublicationConflict,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_publication import (
    ExpectedPolicyLedgerStateV3,
    InMemoryAssumptionPolicyPublisher,
    ReferenceAssumptionPolicyActivationService,
    classify_exact_idempotence_v3,
    compare_and_append_policy_entry_v3,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

_ALGO = "ed25519"
_VP = "ed25519-rfc8032-strict/1"
_SCOPE = "ASSUMPTION_POLICY_APPROVAL"


def _digest(c: str) -> str:
    return "sha256:" + c * 64


def _digest_for(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"pkd\0" + b).hexdigest()


def _approval_policy() -> AssumptionPolicyApprovalPolicy:
    s = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=("authority:a", "authority:b"),
        required_signature_count=1,
        required_signer_ids=("authority:a",),
    )
    d = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=("authority:a", "authority:b"),
        required_signature_count=2,
        required_signer_ids=("authority:a",),
    )
    return AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:1",
        authority_root_digest=_digest("a"),
        rules=(s, d),
    )


def _sig_profile() -> AssumptionPolicySignatureProfile:
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(algorithm=_ALGO, verification_profile=_VP),
        ),
        required_authority_scope=_SCOPE,
        key_authority_root_digest=_digest("a"),
    )


def _chal_policy() -> AssumptionChallengeClassificationPolicy:
    return AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="PROVENANCE_CONFLICT", materiality="MATERIAL"
            ),
        )
    )


def _grant(gid: str = "grant:1") -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=gid,
        action="ADMIT",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=(),
        effective_from_sequence=1,
    )


def _policy() -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:1",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
    )


# --- V3 entry fixtures -----------------------------------------------------


def _payload(
    policy: AssumptionAuthorityPolicy | None = None,
    seq: int = 10,
    pred_policy: str | None = None,
    pred_commit: str | None = None,
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=pred_policy,
        predecessor_commit_receipt_digest=pred_commit,
        effective_from_sequence=seq,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
    )


def _commit(payload: AssumptionPolicySigningPayload, ssd: str) -> AssumptionAuthorityPolicyCommitV3:
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=ssd,
    )


def _proof(
    payload: AssumptionPolicySigningPayload,
    commit: AssumptionAuthorityPolicyCommitV3,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
) -> AssumptionPolicyActivationProofV2:
    rule = _approval_policy().rule_for(payload.approval_class)
    return AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=payload.signing_payload_digest,
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=_sig_profile().profile_digest,
        challenge_classification_policy_digest=_chal_policy().policy_digest,
        authority_root_digest=payload.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=signers,
    )


def _entry(
    payload: AssumptionPolicySigningPayload | None = None,
    seq: int = 10,
    pred_policy: str | None = None,
    pred_commit: str | None = None,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
) -> AssumptionPolicyLedgerEntryV3:
    p = payload or _payload(seq=seq, pred_policy=pred_policy, pred_commit=pred_commit)
    c = _commit(p, _digest("b"))
    proof = _proof(p, c, signers)
    return AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=proof,
    )


def _successor_entry(
    predecessor: AssumptionPolicyLedgerEntryV3, seq: int = 20
) -> AssumptionPolicyLedgerEntryV3:
    """Build an entry that is a valid V3 successor of ``predecessor``."""

    payload = _payload(
        seq=seq,
        pred_policy=predecessor.signing_payload.policy_digest,
        pred_commit=predecessor.policy_commit.commit_receipt_digest,
    )
    c = _commit(payload, _digest("c"))
    proof = _proof(payload, c)
    return AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=payload,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=proof,
    )


# --- full activation bundle (preparer + publisher) -------------------------


class _SKR:
    def __init__(self, keys):
        self._m = {(k.key_id, k.algorithm): k for k in keys}

    def resolve(self, *, key_id, algorithm, key_authority_root_digest):
        return self._m.get((key_id, algorithm))


class _SAR:
    def __init__(self, auths):
        self._m = {(a.signer_id, a.key_id): a for a in auths}

    def resolve(self, *, signer_id, key_id, authority_root_digest):
        return self._m.get((signer_id, key_id))


def _vkey(kid: str = "key:a", pk: bytes = b"pk-a") -> ResolvedAssumptionPolicyVerificationKey:
    return ResolvedAssumptionPolicyVerificationKey(
        key_id=kid,
        algorithm=_ALGO,
        public_key_bytes=pk,
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"kr:" + kid.encode()),
    )


def _auth(sid: str = "authority:a", kid: str = "key:a") -> ResolvedAssumptionPolicySignerAuthority:
    return ResolvedAssumptionPolicySignerAuthority(
        signer_id=sid,
        key_id=kid,
        authority_root_digest=_digest("a"),
        authority_scopes=(_SCOPE,),
        algorithms=(_ALGO,),
        valid_from_sequence=0,
        valid_until_sequence=None,
        revocation_sequence=None,
        resolution_receipt_digest=_digest_for(b"ar:" + sid.encode()),
    )


def _sig_record(sid, kid, target, pk):
    sb = make_deterministic_signature(
        algorithm=_ALGO,
        verification_profile=_VP,
        public_key_bytes=pk,
        signed_digest=target,
    )
    return {
        "signer_id": sid,
        "key_id": kid,
        "algorithm": _ALGO,
        "signed_digest": target,
        "signature_base64": base64.b64encode(sb).decode("ascii"),
        "authority_scope": _SCOPE,
    }


def _sig_set(records):
    return cast(
        SignatureSet,
        SignatureSet.build({"schema_version": "signature-set/1", "signatures": list(records)}),
    )


def _prepared_activation(signers=("authority:a", "authority:b"), seq=10):
    """Build a full prepared activation via the preparer."""
    policy = _policy()
    payload = _payload(policy=policy, seq=seq)
    pks = {s: f"pk-{s[-1]}".encode() for s in signers}
    kids = {s: f"key:{s[-1]}" for s in signers}
    records = tuple(
        _sig_record(s, kids[s], payload.signing_payload_digest, pks[s]) for s in signers
    )
    ss = _sig_set(records)
    commit = _commit(payload, ss.digest)
    keys = tuple(_vkey(kids[s], pks[s]) for s in signers)
    auths = tuple(_auth(s, kids[s]) for s in signers)
    prep = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_SKR(keys),
        authority_resolver=_SAR(auths),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    prepared = prep.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
        signature_set=ss,
    )
    return prepared


# ===========================================================================
# ExpectedPolicyLedgerStateV3
# ===========================================================================


def test_empty_expected_state_matches_empty_ledger_v3() -> None:
    empty = ExpectedPolicyLedgerStateV3.empty()
    assert empty == ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    assert empty.head_entry_digest is None


def test_blind_empty_expectation_forbidden() -> None:
    with pytest.raises(AssumptionPolicyActivationContractError) as f:
        ExpectedPolicyLedgerStateV3(
            ledger_root_digest=_digest("f"),
            head_entry_digest=None,
        )
    assert f.value.code == "ASSUMPTION_POLICY_BLIND_EMPTY_EXPECTATION_V3_FORBIDDEN"


def test_from_ledger_v3_has_correct_head() -> None:
    e = _entry()
    ledger = AssumptionPolicyLedgerV3.build((e,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    assert state.head_entry_digest == e.ledger_entry_digest
    assert state.ledger_root_digest == ledger.ledger_root_digest


# ===========================================================================
# Exact idempotence V3
# ===========================================================================


def test_exact_idempotent_retry() -> None:
    e = _entry()
    assert classify_exact_idempotence_v3(e, e) == "IDEMPOTENT_APPEND"


def test_same_commit_divergent_bytes_rejected() -> None:
    e = _entry()
    # Build a divergent entry with the same commit but different proof signers.
    payload = e.signing_payload
    c = e.policy_commit
    proof = AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=payload.signing_payload_digest,
        policy_commit_receipt_digest=c.commit_receipt_digest,
        approval_policy_digest=e.approval_policy.approval_policy_digest,
        approval_rule_digest=e.approval_policy.rule_for(payload.approval_class).rule_digest,
        signature_profile_digest=e.signature_profile.profile_digest,
        challenge_classification_policy_digest=e.challenge_classification_policy.policy_digest,
        authority_root_digest=payload.authority_root_digest,
        signature_set_digest=c.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
        rejected_signer_codes=("SIGNATURE_INVALID",),
    )
    divergent = AssumptionPolicyLedgerEntryV3.build(
        policy=e.policy,
        signing_payload=payload,
        policy_commit=c,
        approval_policy=e.approval_policy,
        signature_profile=e.signature_profile,
        challenge_classification_policy=e.challenge_classification_policy,
        activation_proof=proof,
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as f:
        classify_exact_idempotence_v3(e, divergent)
    assert f.value.code == "ASSUMPTION_POLICY_ENTRY_V3_DIVERGENCE"


def test_distinct_entry_classified() -> None:
    e1 = _entry(seq=10)
    e2 = _successor_entry(e1, seq=20)
    assert classify_exact_idempotence_v3(e1, e2) == "DISTINCT_ENTRY"


# ===========================================================================
# Compare-and-append V3
# ===========================================================================


def test_empty_ledger_first_append() -> None:
    e = _entry()
    ledger = AssumptionPolicyLedgerV3.build(())
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    updated, result = compare_and_append_policy_entry_v3(
        ledger=ledger,
        expected_state=state,
        candidate=e,
    )
    assert result.append_result == "COMMITTED"
    assert len(updated.entries) == 1
    assert updated.ledger_root_digest == result.resulting_ledger_root


def test_nonempty_successor_append() -> None:
    first = _entry(seq=10)
    successor = _successor_entry(first, seq=20)
    ledger = AssumptionPolicyLedgerV3.build((first,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    updated, result = compare_and_append_policy_entry_v3(
        ledger=ledger,
        expected_state=state,
        candidate=successor,
    )
    assert result.append_result == "COMMITTED"
    assert len(updated.entries) == 2


def test_idempotent_retry_returns_same_ledger() -> None:
    e = _entry()
    ledger = AssumptionPolicyLedgerV3.build((e,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    unchanged, result = compare_and_append_policy_entry_v3(
        ledger=ledger,
        expected_state=state,
        candidate=e,
    )
    assert result.append_result == "IDEMPOTENT_APPEND"
    assert unchanged == ledger


def test_expected_root_mismatch_conflict() -> None:
    e = _entry()
    ledger = AssumptionPolicyLedgerV3.build(())
    wrong_state = ExpectedPolicyLedgerStateV3(
        ledger_root_digest=_digest("f"),
        head_entry_digest=e.ledger_entry_digest,
    )
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=wrong_state,
            candidate=e,
        )
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_expected_head_mismatch_conflict() -> None:
    first = _entry(seq=10)
    successor = _successor_entry(first, seq=20)
    ledger = AssumptionPolicyLedgerV3.build((first,))
    stale_state = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=stale_state,
            candidate=successor,
        )
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_predecessor_policy_mismatch_conflict() -> None:
    first = _entry(seq=10)
    wrong_pred_payload = _payload(
        seq=20,
        pred_policy=_digest("f"),  # wrong predecessor policy
        pred_commit=first.policy_commit.commit_receipt_digest,
    )
    wrong_c = _commit(wrong_pred_payload, _digest("c"))
    wrong_proof = _proof(wrong_pred_payload, wrong_c)
    wrong_succ = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong_pred_payload,
        policy_commit=wrong_c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=wrong_proof,
    )
    ledger = AssumptionPolicyLedgerV3.build((first,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=state,
            candidate=wrong_succ,
        )
    assert f.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_predecessor_commit_mismatch_conflict() -> None:
    first = _entry(seq=10)
    wrong_pred_payload = _payload(
        seq=20,
        pred_policy=first.signing_payload.policy_digest,
        pred_commit=_digest("d"),  # wrong predecessor commit
    )
    wrong_c = _commit(wrong_pred_payload, _digest("c"))
    wrong_proof = _proof(wrong_pred_payload, wrong_c)
    wrong_succ = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong_pred_payload,
        policy_commit=wrong_c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=wrong_proof,
    )
    ledger = AssumptionPolicyLedgerV3.build((first,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=state,
            candidate=wrong_succ,
        )
    assert f.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_non_monotonic_effective_sequence_conflict() -> None:
    first = _entry(seq=20)
    equal = _successor_entry(first, seq=20)  # equal, not strictly greater
    # The successor has the right predecessor pair but equal sequence.
    # But _successor_entry builds with a different payload that has seq=20
    # equal to first's seq=20. validate_successor_position_v3 rejects this.
    ledger = AssumptionPolicyLedgerV3.build((first,))
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=state,
            candidate=equal,
        )
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_V3_EFFECTIVE_SEQUENCE_NOT_INCREASING"


def test_genesis_with_predecessor_conflict() -> None:
    e = _entry(seq=10, pred_policy=_digest("e"), pred_commit=_digest("c"))
    ledger = AssumptionPolicyLedgerV3.build(())
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        compare_and_append_policy_entry_v3(
            ledger=ledger,
            expected_state=state,
            candidate=e,
        )
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_GENESIS_INVALID"


def test_resulting_root_equals_rebuilt_ledger_root() -> None:
    e = _entry()
    ledger = AssumptionPolicyLedgerV3.build(())
    state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    updated, result = compare_and_append_policy_entry_v3(
        ledger=ledger,
        expected_state=state,
        candidate=e,
    )
    rebuilt = AssumptionPolicyLedgerV3.build((e,))
    assert result.resulting_ledger_root == rebuilt.ledger_root_digest


# ===========================================================================
# In-memory publisher
# ===========================================================================


def test_publisher_empty_first_publish() -> None:
    pub = InMemoryAssumptionPolicyPublisher()
    prepared = _prepared_activation()
    state = pub.read_state()
    result = pub.publish(prepared=prepared, expected_state=state)
    assert result.append_result == "COMMITTED"


def test_publisher_idempotent_retry() -> None:
    pub = InMemoryAssumptionPolicyPublisher()
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)
    # Retry with the same expected_state (stale); but the entry is already in.
    retry_state = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    result = pub.publish(prepared=prepared, expected_state=retry_state)
    # The publisher checks idempotence before expected_state, so it returns IDEMPOTENT.
    assert result.append_result == "IDEMPOTENT_APPEND"


def test_same_snapshot_competing_writers() -> None:
    pub = InMemoryAssumptionPolicyPublisher()
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    # Both see the same empty state.
    state = pub.read_state()
    result_a = pub.publish(prepared=pa, expected_state=state)
    assert result_a.append_result == "COMMITTED"
    # b uses the same stale state; the ledger has advanced.
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=pb, expected_state=state)
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_no_clobber_state_preserved_on_conflict() -> None:
    pub = InMemoryAssumptionPolicyPublisher()
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    state = pub.read_state()
    pub.publish(prepared=pa, expected_state=state)
    state_after = pub.read_state()
    # Attempt with stale state fails.
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=pb, expected_state=state)
    # State unchanged after conflict.
    assert pub.read_state() == state_after


def test_failed_publication_no_resulting_root() -> None:
    pub = InMemoryAssumptionPolicyPublisher()
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    state = pub.read_state()
    pub.publish(prepared=pa, expected_state=state)
    # Second attempt with stale state raises; no result is returned.
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=pb, expected_state=state)


# ===========================================================================
# Entry/2 rejected from publication
# ===========================================================================


def test_entry_v2_rejected_from_publication() -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionAuthorityPolicyCommitV2,
        AssumptionPolicyActivationProof,
    )
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
    )
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation as PPA2,
    )

    policy = _policy()
    approval = _approval_policy()
    profile = _sig_profile()
    challenge = _chal_policy()
    c2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=approval.approval_policy_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = approval.rule_for(c2.approval_class)
    proof_v1 = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=c2.commit_receipt_digest,
        approval_policy_digest=approval.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        authority_root_digest=policy.authority_root_digest,
        signature_set_digest=c2.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )
    e2 = AssumptionPolicyLedgerEntryV2.build(
        policy=policy,
        policy_commit=c2,
        approval_policy=approval,
        signature_profile=profile,
        challenge_classification_policy=challenge,
        activation_proof=proof_v1,
    )
    prepared_v2 = PPA2.build(e2)
    pub = InMemoryAssumptionPolicyPublisher()
    state = pub.read_state()
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=prepared_v2, expected_state=state)
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"


# ===========================================================================
# Complete service composition
# ===========================================================================


def test_service_prepare_and_publish() -> None:
    policy = _policy()
    payload = _payload(policy=policy)
    signers = ("authority:a", "authority:b")
    pks = {s: f"pk-{s[-1]}".encode() for s in signers}
    kids = {s: f"key:{s[-1]}" for s in signers}
    records = tuple(
        _sig_record(s, kids[s], payload.signing_payload_digest, pks[s]) for s in signers
    )
    ss = _sig_set(records)
    commit = _commit(payload, ss.digest)
    keys = tuple(_vkey(kids[s], pks[s]) for s in signers)
    auths = tuple(_auth(s, kids[s]) for s in signers)
    prep = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_SKR(keys),
        authority_resolver=_SAR(auths),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    pub = InMemoryAssumptionPolicyPublisher()
    service = ReferenceAssumptionPolicyActivationService(preparer=prep, publisher=pub)

    prepared = service.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
        signature_set=ss,
    )
    state = pub.read_state()
    result = service.publish(prepared=prepared, expected_state=state)
    assert result.append_result == "COMMITTED"


def test_identical_inputs_produce_byte_identical_activation_result() -> None:
    def _full_publish():
        pub = InMemoryAssumptionPolicyPublisher()
        prepared = _prepared_activation()
        state = pub.read_state()
        return pub.publish(prepared=prepared, expected_state=state)

    r1 = _full_publish()
    r2 = _full_publish()
    assert r1.result_digest == r2.result_digest
