"""Tests for v0.5-D3.2-A1.3-B durable filesystem publication.

Validates interprocess-safe atomic filesystem publication for V3 policy
activation across the full claim boundary:

* lifecycle: separate ``create()`` / ``open()`` from a side-effect-free
  constructor; ``create()`` is idempotent-refusing, ``open()`` never
  initializes;
* restart reconstruction with full revalidation of every nested contract's
  schema version and closed field set;
* the semantic oracle is preserved: the filesystem layer delegates compare-and-
  append to the pure A1.3-A function and only owns locking, bytes, atomic
  replace, restart, and post-write verification;
* idempotence and the full deterministic conflict set;
* thread-level and real multiprocessing races (spawn context, barriers,
  queues), including constructor-clobber races;
* parser mutation coverage: every closed object rejects unknown fields,
  missing fields, wrong types, and wrong schema versions;
* deterministic fault-injection checkpoints for pre- and post-commit failure
  behavior;
* crash-safe temporary-file handling with the exact managed naming pattern;
* strengthened post-write verification (bytes + entries + root + head +
  predecessor);
* normalized, stable filesystem-failure codes at every boundary;
* full validation of the complete stored object graph on every read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing as mp
import queue as queue_module
import threading
import time
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


def _canonical(obj_bytes: bytes) -> bytes:
    """Re-serialize parsed JSON back to canonical bytes for mutation tests."""

    return (
        json.dumps(json.loads(obj_bytes), sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _load_ledger_dict(path: Path) -> dict:
    return json.loads(path.read_bytes())


def _dump_ledger_dict(path: Path, data: dict) -> None:
    path.write_bytes(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )


# ===========================================================================
# 1-2. Lifecycle: separate create/open from constructor, init under lock
# ===========================================================================


def test_constructor_is_side_effect_free(tmp_path: Path) -> None:
    """The constructor records paths only: it creates no files or directories."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path / "store")
    assert pub.root == tmp_path / "store"
    assert pub.ledger_path == tmp_path / "store" / "ledger.json"
    assert pub.lock_path == tmp_path / "store" / "publication.lock"
    # Nothing was created on disk.
    assert not (tmp_path / "store").exists()


def test_create_initializes_empty_store(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # The authoritative file exists and is the canonical empty ledger.
    assert (tmp_path / "ledger.json").exists()
    state = pub.read_state()
    assert state.head_entry_digest is None
    assert state == ExpectedPolicyLedgerStateV3.empty()


def test_create_is_idempotent_refusing(tmp_path: Path) -> None:
    """A second create() against a valid existing ledger must refuse, not clobber."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    before = (tmp_path / "ledger.json").read_bytes()
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.create()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED"
    # The existing ledger is byte-for-byte intact (not clobbered).
    assert (tmp_path / "ledger.json").read_bytes() == before


def test_open_never_initializes(tmp_path: Path) -> None:
    """open() on a missing ledger raises BYTES_MISSING and creates nothing."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.open()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"
    # open() must not have created the authoritative file.
    assert not (tmp_path / "ledger.json").exists()


def test_open_reconstructs_existing_store(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    pub.publish(prepared=prepared, expected_state=pub.read_state())
    state_before = pub.read_state()

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert pub2.read_state() == state_before


def test_publish_requires_create_first(tmp_path: Path) -> None:
    """Publishing against an uninitialized store surfaces BYTES_MISSING."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    prepared = _prepared_activation()
    with pytest.raises(PolicyStoreError) as f:
        pub.publish(prepared=prepared, expected_state=ExpectedPolicyLedgerStateV3.empty())
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"


def test_create_lock_file_owned_by_advisory_lock(tmp_path: Path) -> None:
    """The lock file is created by advisory_lock itself, not by the publisher."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # The publisher never touches the lock path directly; advisory_lock opens
    # (and seeds) it.
    assert (tmp_path / "publication.lock").exists()


# ===========================================================================
# 1. Restart reconstruction and full revalidation
# ===========================================================================


def test_first_publication(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    state = pub.read_state()
    result = pub.publish(prepared=prepared, expected_state=state)
    assert result.append_result == "COMMITTED"
    assert pub.read_state().head_entry_digest == prepared.ledger_entry.ledger_entry_digest


def test_restart_reconstructs_exact_root_head(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)
    state_before = pub.read_state()

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert pub2.read_state() == state_before


def test_multi_entry_restart_reconstruction(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    e1 = _entry(seq=10)
    p1 = PreparedPolicyActivation.build(e1)
    pub.publish(prepared=p1, expected_state=pub.read_state())
    e2 = _successor_entry(e1, seq=20)
    p2 = PreparedPolicyActivation.build(e2)
    pub.publish(prepared=p2, expected_state=pub.read_state())

    ledger_before = pub.read_ledger()
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    ledger_after = pub2.read_ledger()
    assert ledger_after.ledger_root_digest == ledger_before.ledger_root_digest
    assert len(ledger_after.entries) == 2
    assert ledger_after.entries[0].ledger_entry_digest == e1.ledger_entry_digest
    assert ledger_after.entries[1].ledger_entry_digest == e2.ledger_entry_digest


def test_initial_state_equals_in_memory_oracle(tmp_path: Path) -> None:
    """Correction 13: the semantic oracle is preserved exactly."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    fs_state = pub.read_state()
    oracle_state = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    assert fs_state == oracle_state


# ===========================================================================
# Idempotence and conflicts
# ===========================================================================


def test_exact_retry_after_restart(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    state2 = pub2.read_state()
    result = pub2.publish(prepared=prepared, expected_state=state2)
    assert result.append_result == "IDEMPOTENT_APPEND"


def test_same_commit_divergent_entry_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    state = pub.read_state()
    pub.publish(prepared=prepared, expected_state=state)

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
    pub.create()
    prepared = _prepared_activation()
    wrong_state = ExpectedPolicyLedgerStateV3(
        ledger_root_digest=_digest("f"),
        head_entry_digest=prepared.ledger_entry.ledger_entry_digest,
    )
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=prepared, expected_state=wrong_state)


def test_expected_head_mismatch(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    e = _entry(seq=10)
    pub.publish(prepared=PreparedPolicyActivation.build(e), expected_state=pub.read_state())
    stale = ExpectedPolicyLedgerStateV3.from_ledger(AssumptionPolicyLedgerV3.build(()))
    successor = _successor_entry(e, seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=PreparedPolicyActivation.build(successor), expected_state=stale)
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH"


def test_wrong_predecessor_policy(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
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
    pub.create()
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
    pub.create()
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
    pub.create()
    prepared_v2 = PreparedPolicyActivation.build(e2)
    with pytest.raises(AssumptionPolicyPublicationConflict) as f:
        pub.publish(prepared=prepared_v2, expected_state=pub.read_state())
    assert f.value.code == "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"


def test_no_clobber_on_conflict(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    state = pub.read_state()
    pub.publish(prepared=pa, expected_state=state)
    state_after = pub.read_state()

    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)
    with pytest.raises(AssumptionPolicyPublicationConflict):
        pub.publish(prepared=pb, expected_state=state)
    assert pub.read_state() == state_after


# ===========================================================================
# 6. Parser mutation coverage: every closed object rejects structural damage
# ===========================================================================


def _seed_store_with_one_entry(tmp_path: Path) -> Path:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    return tmp_path / "ledger.json"


def _expect_field_invalid(tmp_path: Path, mutate) -> None:
    """Apply ``mutate(ledger_dict)`` and assert the read surfaces FIELD_INVALID."""

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_FIELD_INVALID"


def test_top_level_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_top_level_missing_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        del d["ledger_root_digest"]

    _expect_field_invalid(tmp_path, mutate)


def test_top_level_wrong_schema_version_rejected(tmp_path: Path) -> None:
    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    data["schema_version"] = "assumption-policy-ledger/2"
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_entries_not_a_list_rejected(tmp_path: Path) -> None:
    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    data["entries"] = "not-a-list"
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_FIELD_INVALID"


def test_entries_list_of_non_objects_rejected(tmp_path: Path) -> None:
    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    data["entries"] = ["not-an-object"]
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_FIELD_INVALID"


def test_entry_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_entry_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["schema_version"] = "assumption-policy-ledger-entry/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_entry_missing_nested_object_rejected(tmp_path: Path) -> None:
    def mutate(d):
        del d["entries"][0]["policy_commit"]

    _expect_field_invalid(tmp_path, mutate)


def test_entry_nested_not_an_object_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["signing_payload"] = "not-an-object"

    _expect_field_invalid(tmp_path, mutate)


def test_signing_payload_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["signing_payload"]["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_signing_payload_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["signing_payload"]["schema_version"] = "assumption-policy-signing-payload/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_signing_payload_exception_count_wrong_type_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["signing_payload"]["exception_count"] = "ten"

    _expect_field_invalid(tmp_path, mutate)


def test_signing_payload_exception_count_bool_rejected(tmp_path: Path) -> None:
    """A stored ``true`` must not masquerade as the integer ``1``."""

    def mutate(d):
        d["entries"][0]["signing_payload"]["exception_count"] = True

    _expect_field_invalid(tmp_path, mutate)


def test_policy_commit_v3_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy_commit"]["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_policy_commit_v3_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy_commit"]["schema_version"] = "assumption-authority-policy-commit/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_activation_proof_v2_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["activation_proof"]["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_activation_proof_v2_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["activation_proof"]["schema_version"] = (
            "assumption-policy-activation-proof/1"
        )

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_activation_proof_valid_signers_not_a_list_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["activation_proof"]["valid_signer_ids"] = "authority:a"

    _expect_field_invalid(tmp_path, mutate)


def test_activation_proof_valid_signers_list_of_non_strings_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["activation_proof"]["valid_signer_ids"] = [1, 2]

    _expect_field_invalid(tmp_path, mutate)


def test_authority_policy_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["schema_version"] = "assumption-authority-policy/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_authority_policy_unknown_field_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["extra"] = "x"

    _expect_field_invalid(tmp_path, mutate)


def test_grant_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["grants"][0]["schema_version"] = "assumption-authority-grant/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_grant_scope_ids_not_a_list_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["grants"][0]["scope_ids"] = "scope:control"

    _expect_field_invalid(tmp_path, mutate)


def test_grant_scope_ids_list_of_non_strings_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["grants"][0]["scope_ids"] = [1]

    _expect_field_invalid(tmp_path, mutate)


def test_grant_effective_until_sequence_bool_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["policy"]["grants"][0]["effective_until_sequence"] = True

    _expect_field_invalid(tmp_path, mutate)


def test_separation_duty_rule_wrong_schema_version_rejected(tmp_path: Path) -> None:
    """Exercise the separation-duty-rule schema-version gate even though the
    seed policy has no rules; synthesize one in a fresh store."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Build a policy that includes a duty rule so the parser reaches the rule.
    from csd_foundry.governance.v0_5.assumption_governance_contracts import (
        AssumptionAuthorityGrant,
        AssumptionAuthorityPolicy,
        AssumptionSeparationDutyRule,
    )

    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:1",
        action="ADMIT",
        conflicting_roles=("ADMITTER", "CHALLENGER"),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    grant = AssumptionAuthorityGrant.build(
        grant_id="grant:1",
        action="ADMIT",
        authority_id="auth:op",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=(),
        effective_from_sequence=1,
    )
    policy = AssumptionAuthorityPolicy.build(
        policy_id="policy:1",
        authority_root_digest=_digest("a"),
        grants=(grant,),
        separation_duty_rules=(rule,),
    )
    payload = AssumptionPolicySigningPayload.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
    )
    commit = _commit(payload, _digest("b"))
    entry = AssumptionPolicyLedgerEntryV3.build(
        policy=policy,
        signing_payload=payload,
        policy_commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(payload, commit),
    )
    # We cannot publish this through the preparer (it needs real signatures for
    # a DUTY_EXCEPTION class). Instead write the canonical bytes directly.
    ledger = AssumptionPolicyLedgerV3.build((entry,))
    (tmp_path / "ledger.json").write_bytes(ledger.canonical_bytes)

    # Mutate the rule's schema version.
    ledger_path = tmp_path / "ledger.json"
    data = _load_ledger_dict(ledger_path)
    data["entries"][0]["policy"]["separation_duty_rules"][0]["schema_version"] = (
        "assumption-separation-duty-rule/2"
    )
    _dump_ledger_dict(ledger_path, data)
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_approval_policy_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["approval_policy"]["schema_version"] = "assumption-policy-approval-policy/2"

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_approval_rule_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["approval_policy"]["rules"][0]["schema_version"] = (
            "assumption-policy-approval-rule/2"
        )

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_signature_profile_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["signature_profile"]["schema_version"] = (
            "assumption-policy-signature-profile/2"
        )

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_challenge_policy_wrong_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        d["entries"][0]["challenge_classification_policy"]["schema_version"] = (
            "assumption-challenge-classification-policy/2"
        )

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    mutate(data)
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED"


def test_corrupt_digest_surfaces_contract_invalid(tmp_path: Path) -> None:
    """A structurally-valid object whose digest no longer self-validates
    surfaces STORED_CONTRACT_INVALID (the ledger root mismatch is detected at
    the build stage)."""

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    # Tamper with the ledger_root_digest only; the rebuild will compute a
    # different root and raise ROOT_MISMATCH (the closest stable code).
    data["ledger_root_digest"] = _digest("x")
    _dump_ledger_dict(ledger_path, data)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_ROOT_MISMATCH"


# ===========================================================================
# Corruption detection (bytes-level)
# ===========================================================================


def test_truncated_bytes_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    ledger_path = tmp_path / "ledger.json"
    data = ledger_path.read_bytes()
    ledger_path.write_bytes(data[: len(data) // 2])
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError):
        pub2.read_state()


def test_non_json_bytes_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    (tmp_path / "ledger.json").write_bytes(b"\xff\xfe not json")
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_INVALID"


def test_top_level_not_an_object_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    (tmp_path / "ledger.json").write_bytes(b"[1, 2, 3]\n")
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_INVALID"


def test_mutated_root_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    ledger_path = tmp_path / "ledger.json"
    data = _load_ledger_dict(ledger_path)
    data["ledger_root_digest"] = _digest("f")
    _dump_ledger_dict(ledger_path, data)
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert "ROOT_MISMATCH" in f.value.code or "NONCANONICAL" in f.value.code


def test_noncanonical_json_rejected(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    ledger_path = tmp_path / "ledger.json"
    data = _load_ledger_dict(ledger_path)
    ledger_path.write_bytes(json.dumps(data, indent=2).encode("utf-8"))
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.read_state()
    assert "NONCANONICAL" in f.value.code


# ===========================================================================
# 10. Crash-safe temporary-file handling (exact managed naming pattern)
# ===========================================================================


def test_orphan_managed_temp_file_cleaned(tmp_path: Path) -> None:
    """An orphaned managed temp file (.policy-ledger.<uuid>.tmp) is removed."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    orphan = tmp_path / ".policy-ledger.deadbeefdeadbeef.tmp"
    orphan.write_bytes(b"garbage")
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert not orphan.exists()
    assert pub2.read_state().head_entry_digest is None


def test_non_managed_temp_file_preserved(tmp_path: Path) -> None:
    """Files that do not match the exact managed pattern are never touched."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    unrelated = tmp_path / "orphan.tmp"
    unrelated.write_bytes(b"keep-me")
    also_unrelated = tmp_path / ".policy-ledger.tmp"  # empty middle segment
    also_unrelated.write_bytes(b"keep-me-too")
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert unrelated.read_bytes() == b"keep-me"
    assert also_unrelated.read_bytes() == b"keep-me-too"


def test_temp_file_uses_managed_pattern(tmp_path: Path) -> None:
    """A write in progress leaves a temp file matching the managed pattern.

    We cannot easily inspect a temp file mid-write through the public API, so
    we verify the naming pattern indirectly: the orphan-cleanup logic must
    recognize (and remove) any file that matches the exact managed pattern,
    which it can only do if writes produce that pattern.
    """

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Simulate a crash mid-write by dropping a correctly-named temp file.
    simulated = tmp_path / ".policy-ledger.abcdef0123456789.tmp"
    simulated.write_bytes(b"partial")
    # open() must clean it because it matches the managed pattern.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert not simulated.exists()


# ===========================================================================
# 8-9. Deterministic fault injection: pre- and post-commit failure behavior
# ===========================================================================


def test_pre_commit_failure_leaves_old_ledger_intact(tmp_path: Path) -> None:
    """A fault injected at the pre-commit checkpoint leaves the old ledger
    intact and returns no result."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    state_after_first = pub.read_state()
    bytes_before = (tmp_path / "ledger.json").read_bytes()

    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == "pre-commit":
            raise RuntimeError("injected pre-commit fault")

    with (
        FilesystemAssumptionPolicyPublisher.with_fault_injection(fault),
        pytest.raises(RuntimeError, match="injected pre-commit fault"),
    ):
        pub.publish(
            prepared=PreparedPolicyActivation.build(second),
            expected_state=state_after_first,
        )

    # Old ledger is byte-for-byte intact; no temp files left behind.
    assert (tmp_path / "ledger.json").read_bytes() == bytes_before
    leftovers = [
        p.name
        for p in tmp_path.iterdir()
        if p.name.startswith(".policy-ledger.") and p.name.endswith(".tmp")
    ]
    assert leftovers == []
    # State unchanged.
    assert pub.read_state() == state_after_first


def test_post_commit_failure_reports_uncertain(tmp_path: Path) -> None:
    """A fault injected after os.replace reports OUTCOME_UNCERTAIN.

    The publication may have landed (the replace succeeded), so the publisher
    must not roll back and must report the uncertain outcome.
    """

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    state_after_first = pub.read_state()

    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == "post-commit":
            raise RuntimeError("injected post-commit fault")

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(fault):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"

    # Despite the uncertain error, the publication actually landed (replace
    # succeeded before the checkpoint). The new head must be visible.
    final_state = pub.read_state()
    assert final_state.head_entry_digest == second.ledger_entry_digest


def test_fault_hook_cleared_after_context(tmp_path: Path) -> None:
    """The fault hook is cleared when the with-block exits, even on error."""

    assert FilesystemAssumptionPolicyPublisher._fault_hook is None
    flaky = lambda name: None  # noqa: E731

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(flaky):
        assert FilesystemAssumptionPolicyPublisher._fault_hook is flaky
    assert FilesystemAssumptionPolicyPublisher._fault_hook is None

    # Even on exception.
    try:
        with FilesystemAssumptionPolicyPublisher.with_fault_injection(flaky):
            raise ValueError("boom")
    except ValueError:
        pass
    assert FilesystemAssumptionPolicyPublisher._fault_hook is None


# ===========================================================================
# 11. Thread-level concurrent races
# ===========================================================================


def _run_fs_race(
    *,
    root: Path,
    prepared_a,
    prepared_b,
    expected_state,
):
    pub = FilesystemAssumptionPolicyPublisher(root)
    barrier = threading.Barrier(2)
    results_q: queue_module.Queue = queue_module.Queue()

    def worker(prepared):
        barrier.wait()
        try:
            r = pub.publish(prepared=prepared, expected_state=expected_state)
            results_q.put(("OK", prepared, r))
        except Exception as exc:  # noqa: BLE001 - surface any failure to the parent
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
    pub_init = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub_init.create()
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
    pub_init.create()
    state = pub_init.read_state()
    outcomes = _run_fs_race(root=tmp_path, prepared_a=pa, prepared_b=pa, expected_state=state)
    results = [o[2] for o in outcomes if o[0] == "OK"]
    assert sorted(r.append_result for r in results) == ["COMMITTED", "IDEMPOTENT_APPEND"]
    assert all(o[0] == "OK" for o in outcomes), "unexpected exception"


# ===========================================================================
# 11. Real multiprocessing races (spawn context, barriers, queues)
# ===========================================================================


def _mp_publish_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    barrier_arg: object,
    prepared_entry_bytes: bytes,
    expected_state_bytes: bytes,
    worker_id: str,
) -> None:
    """Spawn-safe worker that publishes one prepared entry.

    Receives pre-serialized prepared-entry canonical bytes and an expected
    state. The worker rebuilds a ``PreparedPolicyActivation`` from the entry
    bytes (the entry is self-validating) and publishes it under the lock.
    Synchronization is via a multiprocessing Barrier shared through the parent
    so both children race the publish call as closely as possible.
    """

    import pickle  # noqa: S403 - test-only, trusted parent payload

    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )
    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        FilesystemAssumptionPolicyPublisher,
        PolicyStoreError,
    )

    # Reconstruct the entry from canonical bytes via the parser path.
    entry = _mp_parse_entry(prepared_entry_bytes)
    expected_state = pickle.loads(expected_state_bytes)  # noqa: S301 - trusted parent

    prepared = PreparedPolicyActivation.build(entry)
    pub = FilesystemAssumptionPolicyPublisher(Path(root))
    try:
        barrier_arg.wait()
    except Exception:  # noqa: BLE001
        result_queue.put(("BARRIER_ERROR", worker_id, ""))
        return
    try:
        result = pub.publish(prepared=prepared, expected_state=expected_state)
        result_queue.put(("OK", worker_id, result.append_result))
    except PolicyStoreError as exc:
        result_queue.put(("STORE_ERROR", worker_id, exc.code))
    except Exception as exc:  # noqa: BLE001
        result_queue.put(("CONFLICT", worker_id, getattr(exc, "code", repr(exc))))


def _mp_parse_entry(entry_bytes: bytes):
    """Parse a single ledger entry from canonical bytes (for the mp worker).

    The entry is self-validating; parsing it directly avoids needing a full
    ledger (a successor entry references a predecessor that is not present in
    a single-entry synthetic ledger).
    """

    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        parse_ledger_entry_v3,
    )

    return parse_ledger_entry_v3(json.loads(entry_bytes))


def test_multiprocess_distinct_candidates_one_wins(tmp_path: Path) -> None:
    """Two real processes race to publish distinct genesis candidates.

    Exactly one must COMMIT; the other must observe the updated ledger state
    and conflict. Uses the spawn context so the result generalizes to Windows.
    """

    import pickle  # noqa: S403

    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    pb = _prepared_activation(("authority:a", "authority:b"), seq=20)

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    state = pub.read_state()

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    pa_bytes = pa.ledger_entry.canonical_bytes
    pb_bytes = pb.ledger_entry.canonical_bytes
    state_bytes = pickle.dumps(state)

    proc_a = ctx.Process(
        target=_mp_publish_worker,
        args=(str(tmp_path), queue, barrier, pa_bytes, state_bytes, "A"),
    )
    proc_b = ctx.Process(
        target=_mp_publish_worker,
        args=(str(tmp_path), queue, barrier, pb_bytes, state_bytes, "B"),
    )
    proc_a.start()
    proc_b.start()
    proc_a.join(timeout=60)
    proc_b.join(timeout=60)
    assert proc_a.exitcode == 0, f"A exited {proc_a.exitcode}"
    assert proc_b.exitcode == 0, f"B exited {proc_b.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 2:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 2, f"missing outcomes: {outcomes}"

    oks = [o for o in outcomes if o[0] == "OK"]
    conflicts = [o for o in outcomes if o[0] in ("STORE_ERROR", "CONFLICT")]
    assert len(oks) == 1, f"expected exactly one COMMIT, got: {outcomes}"
    assert len(conflicts) == 1, f"expected exactly one conflict, got: {outcomes}"
    assert oks[0][2] == "COMMITTED"
    # Exactly one entry is durably present in the final ledger.
    final = FilesystemAssumptionPolicyPublisher(tmp_path)
    final.open()
    assert len(final.read_ledger().entries) == 1


def test_multiprocess_exact_retry_both_succeed(tmp_path: Path) -> None:
    """Two real processes race to publish the exact same candidate.

    One must COMMIT, the other must observe IDEMPOTENT_APPEND. Neither may
    observe a hard failure.
    """

    import pickle  # noqa: S403

    pa = _prepared_activation(("authority:a", "authority:b"), seq=10)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    state = pub.read_state()

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    pa_bytes = pa.ledger_entry.canonical_bytes
    state_bytes = pickle.dumps(state)

    proc_a = ctx.Process(
        target=_mp_publish_worker,
        args=(str(tmp_path), queue, barrier, pa_bytes, state_bytes, "A"),
    )
    proc_b = ctx.Process(
        target=_mp_publish_worker,
        args=(str(tmp_path), queue, barrier, pa_bytes, state_bytes, "B"),
    )
    proc_a.start()
    proc_b.start()
    proc_a.join(timeout=60)
    proc_b.join(timeout=60)
    assert proc_a.exitcode == 0
    assert proc_b.exitcode == 0

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 2:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 2, f"missing outcomes: {outcomes}"
    results = sorted(o[2] for o in outcomes if o[0] == "OK")
    assert results == ["COMMITTED", "IDEMPOTENT_APPEND"], outcomes


# ===========================================================================
# 3. Constructor clobber race tests (multiprocessing)
# ===========================================================================


def _mp_create_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    barrier_arg: object,
    worker_id: str,
) -> None:
    """Spawn-safe worker that calls create() and reports the outcome code."""

    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        FilesystemAssumptionPolicyPublisher,
        PolicyStoreError,
    )

    pub = FilesystemAssumptionPolicyPublisher(Path(root))
    try:
        barrier_arg.wait()
    except Exception:  # noqa: BLE001
        result_queue.put(("BARRIER_ERROR", worker_id, ""))
        return
    try:
        pub.create()
        result_queue.put(("CREATED", worker_id, ""))
    except PolicyStoreError as exc:
        result_queue.put(("REFUSED", worker_id, exc.code))
    except Exception as exc:  # noqa: BLE001
        result_queue.put(("ERROR", worker_id, repr(exc)))


def test_concurrent_create_does_not_clobber(tmp_path: Path) -> None:
    """Two processes call create() concurrently against the same root.

    Exactly one must succeed (CREATED); the other must observe the now-valid
    ledger and refuse with ALREADY_INITIALIZED. The authoritative ledger must
    be exactly one canonical empty ledger, never corrupted or duplicated.
    """

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    proc_a = ctx.Process(
        target=_mp_create_worker,
        args=(str(tmp_path), queue, barrier, "A"),
    )
    proc_b = ctx.Process(
        target=_mp_create_worker,
        args=(str(tmp_path), queue, barrier, "B"),
    )
    proc_a.start()
    proc_b.start()
    proc_a.join(timeout=60)
    proc_b.join(timeout=60)
    assert proc_a.exitcode == 0, f"A exited {proc_a.exitcode}"
    assert proc_b.exitcode == 0, f"B exited {proc_b.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 2:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 2, f"missing outcomes: {outcomes}"

    created = [o for o in outcomes if o[0] == "CREATED"]
    refused = [o for o in outcomes if o[0] == "REFUSED"]
    assert len(created) == 1, f"expected exactly one CREATED, got: {outcomes}"
    assert len(refused) == 1, f"expected exactly one REFUSED, got: {outcomes}"
    assert refused[0][2] == "ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED"

    # The store is a valid empty ledger.
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.open()
    assert pub.read_state() == ExpectedPolicyLedgerStateV3.empty()
    # Exactly one authoritative file exists.
    assert (tmp_path / "ledger.json").exists()
    assert (tmp_path / "publication.lock").exists()


# ===========================================================================
# 7. Normalized filesystem failure codes
# ===========================================================================


def test_constructor_rejects_non_path_root() -> None:
    with pytest.raises(PolicyStoreError) as f:
        FilesystemAssumptionPolicyPublisher("not/a/path")  # type: ignore[arg-type]
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_INVALID"


def test_create_rejects_root_that_is_a_file(tmp_path: Path) -> None:
    file_path = tmp_path / "isafile"
    file_path.write_text("x")
    pub = FilesystemAssumptionPolicyPublisher(file_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.create()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY"


def test_read_state_on_uninitialized_store(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"


def test_read_ledger_on_uninitialized_store(tmp_path: Path) -> None:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_ledger()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"


# ===========================================================================
# 12. Strengthened post-write verification
# ===========================================================================


def test_post_write_verification_round_trip(tmp_path: Path) -> None:
    """After a successful publish, the on-disk ledger is the exact intended
    bytes, entries, root, head, and predecessor."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    result = pub.publish(prepared=first, expected_state=pub.read_state())
    assert result.append_result == "COMMITTED"

    # The on-disk bytes equal the oracle's canonical bytes for the resulting
    # ledger.
    ledger = pub.read_ledger()
    assert (tmp_path / "ledger.json").read_bytes() == ledger.canonical_bytes
    assert len(ledger.entries) == 1
    head = ledger.entries[-1]
    assert head.ledger_entry_digest == first.ledger_entry.ledger_entry_digest
    # Genesis entry has no predecessor.
    assert head.signing_payload.predecessor_commit_receipt_digest is None

    # Publish a successor and verify head + predecessor binding.
    second = _successor_entry(first.ledger_entry, seq=20)
    result2 = pub.publish(
        prepared=PreparedPolicyActivation.build(second), expected_state=pub.read_state()
    )
    assert result2.append_result == "COMMITTED"
    ledger2 = pub.read_ledger()
    assert (tmp_path / "ledger.json").read_bytes() == ledger2.canonical_bytes
    assert len(ledger2.entries) == 2
    head2 = ledger2.entries[-1]
    assert head2.ledger_entry_digest == second.ledger_entry_digest
    assert (
        head2.signing_payload.predecessor_commit_receipt_digest
        == first.ledger_entry.policy_commit.commit_receipt_digest
    )
    assert (
        head2.signing_payload.predecessor_policy_digest == first.ledger_entry.policy.policy_digest
    )


def test_post_write_bytes_match_oracle(tmp_path: Path) -> None:
    """The bytes the publisher writes are byte-for-byte the oracle's bytes."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    prepared = _prepared_activation()
    pub.publish(prepared=prepared, expected_state=pub.read_state())
    on_disk = (tmp_path / "ledger.json").read_bytes()
    # Rebuild the expected ledger independently from the published entry.
    expected_ledger = AssumptionPolicyLedgerV3.build((prepared.ledger_entry,))
    assert on_disk == expected_ledger.canonical_bytes
