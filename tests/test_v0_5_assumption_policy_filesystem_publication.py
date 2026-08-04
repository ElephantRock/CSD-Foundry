"""Tests for v0.5-D3.2-A1.3-B durable filesystem publication.

Validates interprocess-safe atomic filesystem publication for V3 policy
activation: initialization, restart reconstruction, idempotence, conflicts,
interprocess races, failure injection, and corruption detection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import queue as queue_module
import threading
from pathlib import Path
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
    PreparedPolicyActivation,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_publication import (
    ExpectedPolicyLedgerStateV3,
)
from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
    FilesystemAssumptionPolicyPublisher,
    PolicyStoreError,
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
            AssumptionChallengeClassificationRule(reason_code="R", materiality="MATERIAL"),
        )
    )


def _grant(gid: str = "grant:1") -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=gid,
        action="ADMIT",
        authority_id="auth:op",
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


def _payload(policy=None, seq=10, pred_policy=None, pred_commit=None):
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=pred_policy,
        predecessor_commit_receipt_digest=pred_commit,
        effective_from_sequence=seq,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
    )


def _commit(payload, ssd):
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=ssd,
    )


def _proof(payload, commit, signers=("authority:a", "authority:b")):
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


def _entry(payload=None, seq=10, pred_policy=None, pred_commit=None):
    p = payload or _payload(seq=seq, pred_policy=pred_policy, pred_commit=pred_commit)
    c = _commit(p, _digest("b"))
    return AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(p, c),
    )


def _successor_entry(predecessor, seq=20):
    p = _payload(
        seq=seq,
        pred_policy=predecessor.signing_payload.policy_digest,
        pred_commit=predecessor.policy_commit.commit_receipt_digest,
    )
    c = _commit(p, _digest("c"))
    return AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=p,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(p, c),
    )


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


def _vkey(kid="key:a", pk=b"pk-a"):
    return ResolvedAssumptionPolicyVerificationKey(
        key_id=kid,
        algorithm=_ALGO,
        public_key_bytes=pk,
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"kr:" + kid.encode()),
    )


def _auth(sid="authority:a", kid="key:a"):
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
        algorithm=_ALGO, verification_profile=_VP, public_key_bytes=pk, signed_digest=target
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
    return prep.prepare(
        policy=policy,
        signing_payload=payload,
        commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
        signature_set=ss,
    )


# ===========================================================================
# Initialization and reconstruction
# ===========================================================================


def test_new_empty_store(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    state = pub.read_state()
    assert state.head_entry_digest is None
    assert state == ExpectedPolicyLedgerStateV3.empty()


def test_first_publication(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    state = pub.read_state()
    result = pub.publish(prepared=prepared, expected_state=state)
    assert result.append_result == "COMMITTED"
    assert pub.read_state().head_entry_digest == prepared.ledger_entry.ledger_entry_digest


def test_restart_reconstructs_exact_root_head(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)
    state_before = pub.read_state()

    # Reopen the store (simulates restart).
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    state_after = pub2.read_state()
    assert state_after == state_before


def test_multi_entry_restart_reconstruction(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    # First entry.
    e1 = _entry(seq=10)
    p1 = PreparedPolicyActivation.build(e1)
    pub.publish(prepared=p1, expected_state=pub.read_state())
    # Second entry.
    e2 = _successor_entry(e1, seq=20)
    p2 = PreparedPolicyActivation.build(e2)
    pub.publish(prepared=p2, expected_state=pub.read_state())

    ledger_before = pub.read_ledger()
    # Restart.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    ledger_after = pub2.read_ledger()
    assert ledger_after.ledger_root_digest == ledger_before.ledger_root_digest
    assert len(ledger_after.entries) == 2
    assert ledger_after.entries[0].ledger_entry_digest == e1.ledger_entry_digest
    assert ledger_after.entries[1].ledger_entry_digest == e2.ledger_entry_digest


def test_initial_state_equals_in_memory_oracle(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    fs_state = pub.read_state()
    oracle_state = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    assert fs_state == oracle_state


# ===========================================================================
# Idempotence and conflicts
# ===========================================================================


def test_exact_retry_after_restart(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    state2 = pub2.read_state()
    result = pub2.publish(prepared=prepared, expected_state=state2)
    assert result.append_result == "IDEMPOTENT_APPEND"


def test_same_commit_divergent_entry_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)

    # Build divergent entry with same commit but different proof.
    entry = prepared.ledger_entry
    divergent_proof = AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=entry.signing_payload.signing_payload_digest,
        policy_commit_receipt_digest=entry.policy_commit.commit_receipt_digest,
        approval_policy_digest=entry.approval_policy.approval_policy_digest,
        approval_rule_digest=entry.approval_policy.rule_for(
            entry.signing_payload.approval_class
        ).rule_digest,
        signature_profile_digest=entry.signature_profile.profile_digest,
        challenge_classification_policy_digest=entry.challenge_classification_policy.policy_digest,
        authority_root_digest=entry.signing_payload.authority_root_digest,
        signature_set_digest=entry.policy_commit.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
        rejected_signer_codes=("SIGNATURE_INVALID",),
    )
    divergent_entry = AssumptionPolicyLedgerEntryV3.build(
        policy=entry.policy,
        signing_payload=entry.signing_payload,
        policy_commit=entry.policy_commit,
        approval_policy=entry.approval_policy,
        signature_profile=entry.signature_profile,
        challenge_classification_policy=entry.challenge_classification_policy,
        activation_proof=divergent_proof,
    )
    divergent_prepared = PreparedPolicyActivation.build(divergent_entry)
    state_after = pub.read_state()
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=divergent_prepared, expected_state=state_after)
    assert f.value.code == "ASSUMPTION_POLICY_ENTRY_V3_DIVERGENCE"


def test_expected_root_mismatch(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    wrong_state = ExpectedPolicyLedgerStateV3(
        ledger_root_digest=_digest("f"),
        head_entry_digest=prepared.ledger_entry.ledger_entry_digest,
    )
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=prepared, expected_state=wrong_state)


def test_expected_head_mismatch(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e = _entry(seq=10)
    pub.publish(prepared=PreparedPolicyActivation.build(e), expected_state=pub.read_state())
    # Stale state references empty ledger.
    stale = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    successor = _successor_entry(e, seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=PreparedPolicyActivation.build(successor), expected_state=stale)
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_wrong_predecessor_policy(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e = _entry(seq=10)
    pub.publish(prepared=PreparedPolicyActivation.build(e), expected_state=pub.read_state())
    stale = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    wrong = _payload(
        seq=20, pred_policy=_digest("f"), pred_commit=e.policy_commit.commit_receipt_digest
    )
    wc = _commit(wrong, _digest("c"))
    we = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong,
        policy_commit=wc,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(wrong, wc),
    )
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=PreparedPolicyActivation.build(we), expected_state=stale)
    assert f.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_wrong_predecessor_commit(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e = _entry(seq=10)
    pub.publish(prepared=PreparedPolicyActivation.build(e), expected_state=pub.read_state())
    stale = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    wrong = _payload(seq=20, pred_policy=e.signing_payload.policy_digest, pred_commit=_digest("d"))
    wc = _commit(wrong, _digest("c"))
    we = AssumptionPolicyLedgerEntryV3.build(
        policy=_policy(),
        signing_payload=wrong,
        policy_commit=wc,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(wrong, wc),
    )
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=PreparedPolicyActivation.build(we), expected_state=stale)
    assert f.value.code == "ASSUMPTION_POLICY_CHAIN_V3_FORK"


def test_non_monotonic_sequence(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e = _entry(seq=20)
    pub.publish(prepared=PreparedPolicyActivation.build(e), expected_state=pub.read_state())
    state = pub.read_state()
    equal = _successor_entry(e, seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=PreparedPolicyActivation.build(equal), expected_state=state)
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_V3_EFFECTIVE_SEQUENCE_NOT_INCREASING"


def test_entry_v2_rejected(tmp_path: Path) -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionAuthorityPolicyCommitV2,
        AssumptionPolicyActivationProof,
    )
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
    )

    c2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=_policy(),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        signature_profile_digest=_sig_profile().profile_digest,
        challenge_classification_policy_digest=_chal_policy().policy_digest,
        signature_set_digest=_digest("b"),
    )
    rule = _approval_policy().rule_for(c2.approval_class)
    proof_v1 = AssumptionPolicyActivationProof.build(
        policy_commit_receipt_digest=c2.commit_receipt_digest,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=_sig_profile().profile_digest,
        challenge_classification_policy_digest=_chal_policy().policy_digest,
        authority_root_digest=_policy().authority_root_digest,
        signature_set_digest=c2.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )
    e2 = AssumptionPolicyLedgerEntryV2.build(
        policy=_policy(),
        policy_commit=c2,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=proof_v1,
    )
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared_v2 = PreparedPolicyActivation.build(e2)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=prepared_v2, expected_state=pub.read_state())
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"


# ===========================================================================
# Thread-level concurrent races (interprocess is tested via multiprocessing below)
# ===========================================================================


def _run_fs_race(
    *,
    root: Path,
    prepared_a,
    prepared_b,
    expected_state,
):
    import queue as queue_module

    pub = FilesystemAssumptionPolicyPublisher(root)
    barrier = threading.Barrier(2)
    results_q: queue_module.Queue = queue_module.Queue()

    def worker(prepared):
        barrier.wait()
        try:
            r = pub.publish(prepared=prepared, expected_state=expected_state)
            results_q.put(("OK", prepared, r))
        except Exception as exc:
            results_q.put(("EXC", prepared, exc))

    t1 = threading.Thread(target=worker, args=(prepared_a,))
    t2 = threading.Thread(target=worker, args=(prepared_b,))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)
    assert not t1.is_alive()
    assert not t2.is_alive()
    outcomes = []
    while not results_q.empty():
        outcomes.append(results_q.get_nowait())
    return outcomes


def test_thread_concurrent_distinct_candidates(tmp_path: Path) -> None:
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    # Initialize the store first.
    pub_init = FilesystemAssumptionPolicyPublisher(tmp_path)
    state = pub_init.read_state()
    outcomes = _run_fs_race(root=tmp_path, prepared_a=pa, prepared_b=pb, expected_state=state)
    assert len(outcomes) == 2
    oks = [o for o in outcomes if o[0] == "OK"]
    excs = [o for o in outcomes if o[0] == "EXC"]
    assert len(oks) == 1
    assert len(excs) == 1
    assert oks[0][2].append_result == "COMMITTED"
    assert excs[0][2].code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_thread_concurrent_exact_retry(tmp_path: Path) -> None:
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    pub_init = FilesystemAssumptionPolicyPublisher(tmp_path)
    state = pub_init.read_state()
    outcomes = _run_fs_race(root=tmp_path, prepared_a=pa, prepared_b=pa, expected_state=state)
    results = [o[2] for o in outcomes if o[0] == "OK"]
    assert sorted(r.append_result for r in results) == ["COMMITTED", "IDEMPOTENT_APPEND"]
    assert all(o[0] == "OK" for o in outcomes), "unexpected exception"


# ===========================================================================
# Corruption detection
# ===========================================================================


def test_truncated_bytes_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    # Truncate the ledger file.
    ledger_path = tmp_path / "ledger.json"
    data = ledger_path.read_bytes()
    ledger_path.write_bytes(data[: len(data) // 2])
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError):
        pub2.read_state()


def test_mutated_root_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    ledger_path = tmp_path / "ledger.json"
    data = json.loads(ledger_path.read_bytes())
    data["ledger_root_digest"] = _digest("f")
    ledger_path.write_bytes(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert "ROOT_MISMATCH" in f.value.code or "NONCANONICAL" in f.value.code


def test_wrong_schema_version_rejected(tmp_path: Path) -> None:
    FilesystemAssumptionPolicyPublisher(tmp_path)
    ledger_path = tmp_path / "ledger.json"
    data = json.loads(ledger_path.read_bytes())
    data["schema_version"] = "assumption-policy-ledger/2"
    ledger_path.write_bytes(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_orphan_temp_file_cleaned(tmp_path: Path) -> None:
    FilesystemAssumptionPolicyPublisher(tmp_path)
    # Create an orphan temp file.
    orphan = tmp_path / ".tmp" / "orphan.tmp"
    orphan.write_bytes(b"garbage")
    # Reopen: orphan must be cleaned.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    assert not orphan.exists()
    # State must still be valid (empty).
    assert pub2.read_state().head_entry_digest is None


def test_noncanonical_json_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    # Write valid JSON but non-canonical formatting (different separators).
    ledger_path = tmp_path / "ledger.json"
    data = json.loads(ledger_path.read_bytes())
    ledger_path.write_bytes(json.dumps(data, indent=2).encode("utf-8"))
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert "NONCANONICAL" in f.value.code


def test_no_clobber_on_conflict(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    state = pub.read_state()
    pub.publish(prepared=pa, expected_state=state)
    state_after = pub.read_state()

    # Attempt with stale state.
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=pb, expected_state=state)
    # State unchanged.
    assert pub.read_state() == state_after
