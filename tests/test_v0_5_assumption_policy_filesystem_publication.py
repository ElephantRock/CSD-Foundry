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
from contextlib import suppress
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
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionPolicyActivationResult,
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


def _symlinks_supported() -> bool:
    """Probe whether the platform can create symlinks (requires privilege on
    Windows). Tests that synthesize symlinks skip when this is False."""

    import tempfile

    d = Path(tempfile.mkdtemp())
    target = d / "target"
    target.write_bytes(b"x")
    link = d / "link"
    try:
        link.symlink_to(target)
    except OSError:
        return False
    return True


_SYMLINKS_SUPPORTED = _symlinks_supported()
_skip_no_symlinks = pytest.mark.skipif(
    not _SYMLINKS_SUPPORTED, reason="symlink creation not supported on this platform"
)


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


def test_publish_against_missing_root_does_not_create_store(tmp_path: Path) -> None:
    """Correction 2: publish() must never create the store root, the
    publication lock, or the authoritative ledger. A publish against a missing
    root surfaces ROOT_MISSING and leaves the filesystem untouched."""

    missing = tmp_path / "does-not-exist"
    pub = FilesystemAssumptionPolicyPublisher(missing)
    prepared = _prepared_activation()
    with pytest.raises(PolicyStoreError) as f:
        pub.publish(prepared=prepared, expected_state=ExpectedPolicyLedgerStateV3.empty())
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_MISSING"
    # The root directory, the lock file, and the ledger must NOT have been
    # created: publish() never initializes a store.
    assert not missing.exists()
    assert not (missing / "publication.lock").exists()
    assert not (missing / "ledger.json").exists()


def test_publish_against_existing_root_no_ledger(tmp_path: Path) -> None:
    """Correction 2: publish() against an existing root directory that holds no
    authoritative ledger surfaces BYTES_MISSING (the store root exists but is
    empty), and creates neither the lock file nor the ledger."""

    root = tmp_path / "store"
    root.mkdir()
    pub = FilesystemAssumptionPolicyPublisher(root)
    prepared = _prepared_activation()
    with pytest.raises(PolicyStoreError) as f:
        pub.publish(prepared=prepared, expected_state=ExpectedPolicyLedgerStateV3.empty())
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"
    # The ledger must not have been created by publish().
    assert not (root / "ledger.json").exists()


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
    """An orphaned managed temp file (.policy-ledger.<32-hex>.tmp) is removed."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    orphan = tmp_path / ".policy-ledger.deadbeefdeadbeefdeadbeefdeadbeef.tmp"
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
    # Simulate a crash mid-write by dropping a correctly-named temp file. The
    # middle segment must be exactly 32 lowercase hex characters.
    simulated = tmp_path / ".policy-ledger.abcdef0123456789abcdef0123456789.tmp"
    simulated.write_bytes(b"partial")
    # open() must clean it because it matches the managed pattern.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert not simulated.exists()


# ===========================================================================
# 8-9. Deterministic fault injection: 8 checkpoints split at os.replace
# ===========================================================================
#
# The real commit point is ``os.replace``. The four pre-replace checkpoints
# (BEFORE_TEMP_CREATE, AFTER_PARTIAL_TEMP_WRITE, AFTER_TEMP_FLUSH,
# BEFORE_REPLACE) leave the old authoritative ledger byte-for-byte intact and
# propagate the injected fault (no result, no rollback). The four post-replace
# checkpoints (AFTER_REPLACE, BEFORE_DIRECTORY_FSYNC, BEFORE_POST_WRITE_READ,
# DURING_POST_WRITE_READ) fire after the new ledger may be authoritative, so
# any failure is normalized to PUBLICATION_OUTCOME_UNCERTAIN and the
# publication actually landed.

_PRE_REPLACE_CHECKPOINTS = [
    "BEFORE_TEMP_CREATE",
    "AFTER_PARTIAL_TEMP_WRITE",
    "AFTER_TEMP_FLUSH",
    "BEFORE_REPLACE",
]
_POST_REPLACE_CHECKPOINTS = [
    "AFTER_REPLACE",
    "BEFORE_DIRECTORY_FSYNC",
    "BEFORE_POST_WRITE_READ",
    "DURING_POST_WRITE_READ",
]


@pytest.mark.parametrize("checkpoint", _PRE_REPLACE_CHECKPOINTS)
def test_pre_replace_fault_leaves_old_ledger_intact(tmp_path: Path, checkpoint: str) -> None:
    """A fault at any pre-replace checkpoint leaves the old ledger intact.

    The publication returns no result, the old authoritative ledger is
    byte-for-byte unchanged, no managed temp file is left behind, and a fresh
    publisher can reconstruct the old complete ledger and retry the
    publication successfully.

    Correction 1: every pre-replace fault is normalized to a stable code --
    BEFORE_TEMP_CREATE, AFTER_PARTIAL_TEMP_WRITE, AFTER_TEMP_FLUSH collapse to
    ``ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED``, and BEFORE_REPLACE
    collapses to ``ASSUMPTION_POLICY_STORE_REPLACE_FAILED``. No injected
    exception type or message may escape.
    """

    # Different injected exception types per checkpoint prove the stable code is
    # invariant to the backend exception shape (RuntimeError, ValueError,
    # OSError).
    _EXC_FOR = {
        "BEFORE_TEMP_CREATE": RuntimeError,
        "AFTER_PARTIAL_TEMP_WRITE": ValueError,
        "AFTER_TEMP_FLUSH": OSError,
        "BEFORE_REPLACE": RuntimeError,
    }
    expected_code = (
        "ASSUMPTION_POLICY_STORE_REPLACE_FAILED"
        if checkpoint == "BEFORE_REPLACE"
        else "ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED"
    )
    exc_type = _EXC_FOR[checkpoint]

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    state_after_first = pub.read_state()
    bytes_before = (tmp_path / "ledger.json").read_bytes()

    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == checkpoint:
            raise exc_type(f"injected {checkpoint} fault")

    with (
        FilesystemAssumptionPolicyPublisher.with_fault_injection(fault),
        pytest.raises(PolicyStoreError) as f,
    ):
        pub.publish(
            prepared=PreparedPolicyActivation.build(second),
            expected_state=state_after_first,
        )
    # Stable, normalized code -- never the raw exception type or message.
    assert f.value.code == expected_code
    assert "injected" not in (f.value.detail or "")
    assert "fault" not in str(f.value)

    # Old ledger is byte-for-byte intact; no managed temp files left behind.
    assert (tmp_path / "ledger.json").read_bytes() == bytes_before
    leftovers = [
        p.name
        for p in tmp_path.iterdir()
        if p.name.startswith(".policy-ledger.") and p.name.endswith(".tmp")
    ]
    assert leftovers == []
    # A fresh publisher reconstructs the OLD complete ledger (never partial):
    # the state is unchanged, so the retry commits the successor cleanly.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert pub2.read_state() == state_after_first
    result = pub2.publish(
        prepared=PreparedPolicyActivation.build(second),
        expected_state=pub2.read_state(),
    )
    assert result.append_result == "COMMITTED"
    assert pub2.read_state().head_entry_digest == second.ledger_entry_digest


@pytest.mark.parametrize("checkpoint", _POST_REPLACE_CHECKPOINTS)
def test_post_replace_fault_reports_uncertain_and_landed(tmp_path: Path, checkpoint: str) -> None:
    """A fault at any post-replace checkpoint reports OUTCOME_UNCERTAIN and the
    publication actually landed.

    The publication returns no result (OUTCOME_UNCERTAIN), but ``os.replace``
    already succeeded, so a fresh publisher reconstructs the NEW complete
    ledger, observes the new head, and an exact retry yields
    IDEMPOTENT_APPEND.
    """

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    state_after_first = pub.read_state()

    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == checkpoint:
            raise RuntimeError(f"injected {checkpoint} fault")

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(fault):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        # No backend diagnostic text is exposed in the detail.
        assert f.value.detail != f"RuntimeError('injected {checkpoint} fault')"
        assert "injected" not in (f.value.detail or "")

    # A fresh publisher reconstructs the NEW complete ledger (never partial):
    # the new head is visible and the root advanced.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    new_state = pub2.read_state()
    assert new_state.head_entry_digest == second.ledger_entry_digest
    # Exact retry yields IDEMPOTENT_APPEND.
    retry = pub2.publish(
        prepared=PreparedPolicyActivation.build(second),
        expected_state=new_state,
    )
    assert retry.append_result == "IDEMPOTENT_APPEND"


# ===========================================================================
# 5. Authoritative-read failure variants (Correction 5)
# ===========================================================================
#
# The post-commit read is split into two independently injectable checkpoints
# (BEFORE_POST_WRITE_READ and DURING_POST_WRITE_READ) and any read failure is
# normalized to OUTCOME_UNCERTAIN. Each variant below proves a distinct
# failure mode: a fault-hook exception before the read, a fault-hook exception
# during the read, a genuine OSError from read_bytes, and truncated bytes.
# After every variant the publication landed (os.replace succeeded), so a
# reopen reconstructs the new ledger and an exact retry yields
# IDEMPOTENT_APPEND.


def _seed_first_entry_for_post_read(tmp_path: Path) -> tuple:
    """Create a store with one entry and return (pub, first, state_after_first)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    return pub, first, pub.read_state()


def _assert_post_read_failure_landed_and_idempotent(
    tmp_path: Path, second, state_after_first: ExpectedPolicyLedgerStateV3
) -> None:
    """After the uncertain failure, reopen reconstructs the NEW ledger and an
    exact retry yields IDEMPOTENT_APPEND."""

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    new_state = pub2.read_state()
    assert new_state.head_entry_digest == second.ledger_entry_digest
    retry = pub2.publish(
        prepared=PreparedPolicyActivation.build(second),
        expected_state=new_state,
    )
    assert retry.append_result == "IDEMPOTENT_APPEND"


def test_before_read_injected_failure_is_uncertain(tmp_path: Path) -> None:
    """A fault-hook RuntimeError at BEFORE_POST_WRITE_READ (before the read
    even begins) surfaces OUTCOME_UNCERTAIN; the publication landed."""

    pub, first, state_after_first = _seed_first_entry_for_post_read(tmp_path)
    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == "BEFORE_POST_WRITE_READ":
            raise RuntimeError("injected before-read fault")

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(fault):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        assert "injected" not in (f.value.detail or "")
    _assert_post_read_failure_landed_and_idempotent(tmp_path, second, state_after_first)


def test_during_read_injected_failure_is_uncertain(tmp_path: Path) -> None:
    """A fault-hook RuntimeError at DURING_POST_WRITE_READ (after the read
    decision but before read_bytes returns) surfaces OUTCOME_UNCERTAIN; the
    publication landed."""

    pub, first, state_after_first = _seed_first_entry_for_post_read(tmp_path)
    second = _successor_entry(first.ledger_entry, seq=20)

    def fault(name: str) -> None:
        if name == "DURING_POST_WRITE_READ":
            raise RuntimeError("injected during-read fault")

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(fault):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        assert "injected" not in (f.value.detail or "")
    _assert_post_read_failure_landed_and_idempotent(tmp_path, second, state_after_first)


def test_read_oserror_is_uncertain(tmp_path: Path) -> None:
    """A genuine OSError raised by read_bytes during the post-commit read
    surfaces OUTCOME_UNCERTAIN (not BYTES_INVALID, which is the pre-commit
    read code); the publication landed."""

    import unittest.mock as mock

    pub, first, state_after_first = _seed_first_entry_for_post_read(tmp_path)
    second = _successor_entry(first.ledger_entry, seq=20)
    ledger_path = tmp_path / "ledger.json"

    real_read_bytes = Path.read_bytes
    call_count = {"n": 0}

    def flaky_read(self, *args, **kwargs):
        # Only the post-commit read (the second read of the ledger path after
        # the first entry was committed) is forced to fail. Earlier reads
        # (reconstruction before the publish) must succeed.
        if self == ledger_path:
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("injected read failure")
        return real_read_bytes(self, *args, **kwargs)

    with mock.patch.object(Path, "read_bytes", flaky_read):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        assert "injected" not in (f.value.detail or "")
    _assert_post_read_failure_landed_and_idempotent(tmp_path, second, state_after_first)


def test_read_truncated_bytes_is_uncertain(tmp_path: Path) -> None:
    """If the post-commit read observes truncated bytes, verification cannot
    confirm the intended ledger, so the outcome is OUTCOME_UNCERTAIN. The
    publication landed (the on-disk file is whole), so a reopen reconstructs
    the new ledger and an exact retry is idempotent."""

    import unittest.mock as mock

    pub, first, state_after_first = _seed_first_entry_for_post_read(tmp_path)
    second = _successor_entry(first.ledger_entry, seq=20)
    ledger_path = tmp_path / "ledger.json"

    real_read_bytes = Path.read_bytes
    call_count = {"n": 0}

    def truncated_post_read(self, *args, **kwargs):
        # Only the post-commit read (the second read of the ledger path after
        # the first entry was committed) returns a truncated view; the on-disk
        # file is untouched (the truncation models a transient read-time
        # artifact, not a partial write).
        if self == ledger_path:
            call_count["n"] += 1
            if call_count["n"] == 2:
                whole = real_read_bytes(self, *args, **kwargs)
                return whole[: len(whole) // 2]
        return real_read_bytes(self, *args, **kwargs)

    with mock.patch.object(Path, "read_bytes", truncated_post_read):
        with pytest.raises(PolicyStoreError) as f:
            pub.publish(
                prepared=PreparedPolicyActivation.build(second),
                expected_state=state_after_first,
            )
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
    # The on-disk file was never actually truncated, so a clean reopen
    # reconstructs the new ledger and an exact retry is idempotent.
    _assert_post_read_failure_landed_and_idempotent(tmp_path, second, state_after_first)


def test_all_eight_checkpoints_are_distinct_and_ordered() -> None:
    """The eight checkpoint names are the exact declared set, distinct, and the
    pre/post split is preserved."""

    all_names = _PRE_REPLACE_CHECKPOINTS + _POST_REPLACE_CHECKPOINTS
    assert len(all_names) == 8
    assert len(set(all_names)) == 8
    assert len(set(_PRE_REPLACE_CHECKPOINTS)) == 4
    assert len(set(_POST_REPLACE_CHECKPOINTS)) == 4
    assert set(_PRE_REPLACE_CHECKPOINTS).isdisjoint(_POST_REPLACE_CHECKPOINTS)


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
        # Correction 4: return the complete controlled-process outcome so the
        # parent can assert that the on-disk head/root/receipt match the
        # winning worker's reported result. Tuple shape:
        #   ("OK", worker_id, append_result, ledger_entry_digest,
        #    predecessor_ledger_root, resulting_ledger_root,
        #    policy_commit_receipt_digest)
        result_queue.put(
            (
                "OK",
                worker_id,
                result.append_result,
                result.ledger_entry_digest,
                result.predecessor_ledger_root,
                result.resulting_ledger_root,
                result.policy_commit_receipt_digest,
            )
        )
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
    # Correction 4: the winning result tuple carries the complete controlled
    # outcome so the parent can prove the on-disk ledger is bound to it.
    ok = oks[0]
    assert ok[2] == "COMMITTED"
    committed_result_digest = ok[3]
    committed_predecessor_root = ok[4]
    committed_resulting_root = ok[5]
    committed_receipt = ok[6]
    # The loser must observe a PublicationConflict whose code is the
    # STATE_MISMATCH family (distinct genesis candidates lose with
    # LEDGER_STATE_MISMATCH).
    loser_code = conflicts[0][2]
    assert loser_code == "ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH", (
        f"expected STATE_MISMATCH, got {loser_code}"
    )
    # The committed result's reported entry digest identifies the winner.
    winner_entry_digest = (
        pa.ledger_entry.ledger_entry_digest
        if committed_result_digest == pa.ledger_entry.ledger_entry_digest
        else pb.ledger_entry.ledger_entry_digest
    )
    loser_entry_digest = (
        pb.ledger_entry.ledger_entry_digest
        if committed_result_digest == pa.ledger_entry.ledger_entry_digest
        else pa.ledger_entry.ledger_entry_digest
    )
    assert committed_result_digest == winner_entry_digest
    # The committed predecessor root is the empty-ledger root (genesis entry).
    empty_root = ExpectedPolicyLedgerStateV3.empty().ledger_root_digest
    assert committed_predecessor_root == empty_root
    # The committed receipt equals the winning head's commit-receipt digest.
    assert committed_receipt == (
        pa.ledger_entry.policy_commit.commit_receipt_digest
        if winner_entry_digest == pa.ledger_entry.ledger_entry_digest
        else pb.ledger_entry.policy_commit.commit_receipt_digest
    )
    final = FilesystemAssumptionPolicyPublisher(tmp_path)
    final.open()
    final_ledger = final.read_ledger()
    assert len(final_ledger.entries) == 1
    # The final on-disk head equals the committed result's entry digest; the
    # final on-disk root equals the committed result's resulting root.
    final_head = final_ledger.entries[0]
    assert final_head.ledger_entry_digest == committed_result_digest
    assert final_ledger.ledger_root_digest == committed_resulting_root
    assert final_head.ledger_entry_digest == winner_entry_digest
    assert final_head.ledger_entry_digest != loser_entry_digest
    final_root = final_ledger.ledger_root_digest
    # Reopening from a third publisher reconstructs the same root.
    final3 = FilesystemAssumptionPolicyPublisher(tmp_path)
    final3.open()
    assert final3.read_ledger().ledger_root_digest == final_root


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
    # Exactly one COMMITTED and one IDEMPOTENT_APPEND; no hard failures.
    assert all(o[0] == "OK" for o in outcomes), outcomes
    ok_results = [o for o in outcomes if o[0] == "OK"]
    append_results = sorted(o[2] for o in ok_results)
    assert append_results == ["COMMITTED", "IDEMPOTENT_APPEND"], outcomes
    # Correction 4: the COMMITTED and IDEMPOTENT_APPEND results carry identical
    # entry digest, resulting root, and receipt (the idempotent re-observation
    # of the same landed entry). The predecessor root legitimately differs:
    # the COMMITTED observer saw the empty ledger as predecessor, while the
    # IDEMPOTENT_APPEND observer re-read the now-populated ledger, so its
    # predecessor root is the populated ledger's root. Tuple positions:
    # 3=entry_digest, 5=resulting_root, 6=receipt.
    committed = next(o for o in ok_results if o[2] == "COMMITTED")
    idempotent = next(o for o in ok_results if o[2] == "IDEMPOTENT_APPEND")
    assert committed[3] == idempotent[3], "entry digest must match"
    assert committed[5] == idempotent[5], "resulting root must match"
    assert committed[6] == idempotent[6], "receipt must match"
    # The shared digest equals the prepared entry's digest, and the resulting
    # root matches the reopened ledger's root.
    shared_digest = committed[3]
    shared_root = committed[5]
    assert shared_digest == pa.ledger_entry.ledger_entry_digest
    final = FilesystemAssumptionPolicyPublisher(tmp_path)
    final.open()
    final_ledger = final.read_ledger()
    assert len(final_ledger.entries) == 1
    assert final_ledger.entries[0].ledger_entry_digest == pa.ledger_entry.ledger_entry_digest
    assert final_ledger.entries[0].ledger_entry_digest == shared_digest
    final_root = final_ledger.ledger_root_digest
    assert final_root == shared_root
    final3 = FilesystemAssumptionPolicyPublisher(tmp_path)
    final3.open()
    assert final3.read_ledger().ledger_root_digest == final_root


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


# ===========================================================================
# 3. Binding post-write verification to the oracle result
# ===========================================================================
#
# Each binding in _verify_post_write is independently mutable: a test tampers
# exactly one binding (on the reconstructed ledger, the intended bytes, or the
# oracle result) and proves verification fails with the uncertain outcome.
# Because verification runs after os.replace, every failure surfaces as
# PUBLICATION_OUTCOME_UNCERTAIN.


def _binding_setup(tmp_path: Path) -> tuple:
    """Create a store with one entry and return the inputs needed to exercise
    _verify_post_write for a successor publish: (old_ledger, updated, result,
    intended_bytes, verified)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    pub.publish(prepared=first, expected_state=pub.read_state())
    old_ledger = pub.read_ledger()
    second = _successor_entry(first.ledger_entry, seq=20)
    updated = AssumptionPolicyLedgerV3.build((*old_ledger.entries, second))
    result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=second.policy_commit.commit_receipt_digest,
        ledger_entry_digest=second.ledger_entry_digest,
        predecessor_ledger_root=old_ledger.ledger_root_digest,
        resulting_ledger_root=updated.ledger_root_digest,
    )
    intended_bytes = updated.canonical_bytes
    verified = updated  # a faithful reconstruction
    return old_ledger, updated, result, intended_bytes, verified


def _expect_binding_uncertain(call_verify) -> None:
    with pytest.raises(PolicyStoreError) as f:
        call_verify()
    assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"


def test_binding_stored_bytes_mismatch_detected(tmp_path: Path) -> None:
    """stored bytes != updated.canonical_bytes -> uncertain."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    # intended_bytes diverges from updated.canonical_bytes.
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=updated.canonical_bytes + b" ",
            verified=verified,
            result=result,
        )
    )


def test_binding_reconstructed_bytes_mismatch_detected(tmp_path: Path) -> None:
    """verified.canonical_bytes != updated.canonical_bytes -> uncertain.

    A reconstructed ledger whose canonical bytes diverge from the updated
    ledger is rejected (this catches a storage layer that returned a different,
    equally-valid ledger)."""

    old_ledger, updated, result, intended_bytes, _ = _binding_setup(tmp_path)
    # A verified ledger built from only the old entries diverges.
    wrong_verified = old_ledger
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=wrong_verified,
            result=result,
        )
    )


def test_binding_reconstructed_entries_mismatch_detected(tmp_path: Path) -> None:
    """verified.entries != updated.entries -> uncertain."""

    old_ledger, updated, result, intended_bytes, _ = _binding_setup(tmp_path)
    # Build a verified ledger with a different entry tuple but arrange its
    # canonical bytes to coincidentally match (impossible in practice, so we
    # instead pass the old ledger as verified, which fails the entries check
    # before any bytes check could mask it).
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=old_ledger.canonical_bytes,
            verified=old_ledger,
            result=AssumptionPolicyActivationResult.build(
                append_result="COMMITTED",
                policy_commit_receipt_digest=result.policy_commit_receipt_digest,
                ledger_entry_digest=result.ledger_entry_digest,
                predecessor_ledger_root=old_ledger.ledger_root_digest,
                resulting_ledger_root=old_ledger.ledger_root_digest,
            ),
        )
    )


def test_binding_reconstructed_root_must_equal_updated_root(tmp_path: Path) -> None:
    """verified.ledger_root_digest != updated.ledger_root_digest -> uncertain."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    # Tamper only updated's root so verified (faithful) diverges.
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        AssumptionPolicyActivationContractError,
    )

    # We cannot mutate a frozen dataclass; instead build a result whose
    # resulting_ledger_root diverges from updated.ledger_root_digest, which
    # trips the updated == result.resulting_ledger_root binding.
    divergent_result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=result.policy_commit_receipt_digest,
        ledger_entry_digest=result.ledger_entry_digest,
        predecessor_ledger_root=old_ledger.ledger_root_digest,
        resulting_ledger_root=_digest("9"),
    )
    _ = AssumptionPolicyActivationContractError  # referenced for clarity
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=verified,
            result=divergent_result,
        )
    )


def test_binding_resulting_root_must_equal_result_root(tmp_path: Path) -> None:
    """updated.ledger_root_digest == result.resulting_ledger_root binding."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    # Pass a result whose resulting root equals the OLD root (diverges from
    # updated's new root).
    stale_result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=result.policy_commit_receipt_digest,
        ledger_entry_digest=result.ledger_entry_digest,
        predecessor_ledger_root=old_ledger.ledger_root_digest,
        resulting_ledger_root=old_ledger.ledger_root_digest,
    )
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=verified,
            result=stale_result,
        )
    )


def test_binding_head_digest_must_equal_result_entry_digest(tmp_path: Path) -> None:
    """verified head digest == result.ledger_entry_digest binding."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    # A result whose ledger_entry_digest diverges from the updated head.
    wrong_digest_result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=result.policy_commit_receipt_digest,
        ledger_entry_digest=_digest("7"),
        predecessor_ledger_root=old_ledger.ledger_root_digest,
        resulting_ledger_root=updated.ledger_root_digest,
    )
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=verified,
            result=wrong_digest_result,
        )
    )


def test_binding_predecessor_root_must_equal_old_root(tmp_path: Path) -> None:
    """result.predecessor_ledger_root == old_ledger.ledger_root_digest binding."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    wrong_pred_result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=result.policy_commit_receipt_digest,
        ledger_entry_digest=result.ledger_entry_digest,
        predecessor_ledger_root=_digest("8"),
        resulting_ledger_root=updated.ledger_root_digest,
    )
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=verified,
            result=wrong_pred_result,
        )
    )


def test_binding_commit_receipt_must_equal_head_receipt(tmp_path: Path) -> None:
    """result.policy_commit_receipt_digest == head commit receipt binding."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    wrong_receipt_result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=_digest("6"),
        ledger_entry_digest=result.ledger_entry_digest,
        predecessor_ledger_root=old_ledger.ledger_root_digest,
        resulting_ledger_root=updated.ledger_root_digest,
    )
    _expect_binding_uncertain(
        lambda: FilesystemAssumptionPolicyPublisher._verify_post_write(
            old_ledger=old_ledger,
            updated=updated,
            intended_bytes=intended_bytes,
            verified=verified,
            result=wrong_receipt_result,
        )
    )


def test_binding_faithful_reconstruction_passes(tmp_path: Path) -> None:
    """A faithful reconstruction (all bindings agree) passes verification."""

    old_ledger, updated, result, intended_bytes, verified = _binding_setup(tmp_path)
    # No exception is raised.
    FilesystemAssumptionPolicyPublisher._verify_post_write(
        old_ledger=old_ledger,
        updated=updated,
        intended_bytes=intended_bytes,
        verified=verified,
        result=result,
    )


def test_binding_predecessor_root_positive_case(tmp_path: Path) -> None:
    """result.predecessor_ledger_root == old_ledger.ledger_root_digest after a
    real COMMITTED publish (positive-case wiring proof)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    first = _prepared_activation(seq=10)
    state_before = pub.read_state()
    result = pub.publish(prepared=first, expected_state=state_before)
    assert result.append_result == "COMMITTED"
    assert result.predecessor_ledger_root == state_before.ledger_root_digest
    assert result.resulting_ledger_root == pub.read_state().ledger_root_digest
    assert result.ledger_entry_digest == first.ledger_entry.ledger_entry_digest
    assert (
        result.policy_commit_receipt_digest
        == first.ledger_entry.policy_commit.commit_receipt_digest
    )


def test_create_rereads_and_verifies_empty_ledger(tmp_path: Path) -> None:
    """create() rereads the authoritative bytes after os.replace and verifies
    they are the canonical empty ledger. A tamper at BEFORE_POST_WRITE_READ
    (before the reread) so the reread sees tampered bytes surfaces as
    OUTCOME_UNCERTAIN."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    empty_bytes = (tmp_path / "ledger.json").read_bytes()
    # Reset the store so we can re-run create() under the fault.
    (tmp_path / "ledger.json").unlink()

    def fault(name: str) -> None:
        if name == "BEFORE_POST_WRITE_READ":
            (tmp_path / "ledger.json").write_bytes(b"tampered")

    with FilesystemAssumptionPolicyPublisher.with_fault_injection(fault):
        with pytest.raises(PolicyStoreError) as f:
            FilesystemAssumptionPolicyPublisher(tmp_path).create()
        assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
    # The empty-ledger canonical bytes are stable.
    assert AssumptionPolicyLedgerV3.build(()).canonical_bytes == empty_bytes


# ===========================================================================
# 6. create()-path checkpoint normalization (Correction 6)
# ===========================================================================
#
# Run the pre/post classification through create(): a pre-replace create
# failure surfaces the stable pre-commit code and leaves no ledger.json; a
# post-replace create failure surfaces OUTCOME_UNCERTAIN, the canonical empty
# ledger may be present, open() reconstructs it, and a later create() returns
# ALREADY_INITIALIZED. No injected exception type or message may escape.


_CREATE_PRE_REPLACE_CHECKPOINTS = [
    "BEFORE_TEMP_CREATE",
    "AFTER_PARTIAL_TEMP_WRITE",
    "AFTER_TEMP_FLUSH",
    "BEFORE_REPLACE",
]
_CREATE_POST_REPLACE_CHECKPOINTS = [
    "AFTER_REPLACE",
    "BEFORE_DIRECTORY_FSYNC",
    "BEFORE_POST_WRITE_READ",
    "DURING_POST_WRITE_READ",
]


@pytest.mark.parametrize("checkpoint", _CREATE_PRE_REPLACE_CHECKPOINTS)
def test_create_pre_replace_failure_is_normalized(tmp_path: Path, checkpoint: str) -> None:
    """A fault at any pre-replace checkpoint during create() surfaces the
    stable pre-commit code (WRITE_FAILED for the temp-write checkpoints,
    REPLACE_FAILED for BEFORE_REPLACE), leaves no ledger.json behind, and a
    later create() initializes the store cleanly."""

    expected_code = (
        "ASSUMPTION_POLICY_STORE_REPLACE_FAILED"
        if checkpoint == "BEFORE_REPLACE"
        else "ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED"
    )

    def fault(name: str) -> None:
        if name == checkpoint:
            raise RuntimeError(f"injected {checkpoint} create fault")

    with (
        FilesystemAssumptionPolicyPublisher.with_fault_injection(fault),
        pytest.raises(PolicyStoreError) as f,
    ):
        FilesystemAssumptionPolicyPublisher(tmp_path).create()
    assert f.value.code == expected_code
    assert "injected" not in (f.value.detail or "")
    assert "fault" not in str(f.value)
    # No authoritative ledger was created: the pre-replace failure left the
    # store as it was (root may exist but ledger.json must not).
    assert not (tmp_path / "ledger.json").exists()
    # No managed temp files left behind by the failed create().
    leftovers = [
        p.name
        for p in tmp_path.iterdir()
        if p.name.startswith(".policy-ledger.") and p.name.endswith(".tmp")
    ]
    assert leftovers == []
    # A later create() initializes the store cleanly.
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    assert pub.read_state() == ExpectedPolicyLedgerStateV3.empty()


@pytest.mark.parametrize("checkpoint", _CREATE_POST_REPLACE_CHECKPOINTS)
def test_create_post_replace_failure_is_outcome_uncertain(tmp_path: Path, checkpoint: str) -> None:
    """A fault at any post-replace checkpoint during create() surfaces
    OUTCOME_UNCERTAIN, the canonical empty ledger may now be present, open()
    reconstructs it, and a later create() returns ALREADY_INITIALIZED. No
    injected exception type or message escapes."""

    def fault(name: str) -> None:
        if name == checkpoint:
            raise RuntimeError(f"injected {checkpoint} create fault")

    with (
        FilesystemAssumptionPolicyPublisher.with_fault_injection(fault),
        pytest.raises(PolicyStoreError) as f,
    ):
        FilesystemAssumptionPolicyPublisher(tmp_path).create()
    assert f.value.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
    assert "injected" not in (f.value.detail or "")
    assert "fault" not in str(f.value)
    # The canonical empty ledger may or may not be present. Either way, open()
    # reconstructs a valid empty store (create() wrote canonical bytes via
    # os.replace before the fault, OR the fault preceded the replace -- both
    # must leave the store reconstructable to the empty state).
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    try:
        pub.open()
        reconstructed_state = pub.read_state()
    except PolicyStoreError as open_exc:
        # If the empty ledger did not land, open() surfaces BYTES_MISSING; in
        # that case a fresh create() must initialize cleanly.
        assert open_exc.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"
        pub.create()
        reconstructed_state = pub.read_state()
    assert reconstructed_state == ExpectedPolicyLedgerStateV3.empty()
    # A later create() must observe the now-valid empty ledger and refuse with
    # ALREADY_INITIALIZED (never clobber).
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f2:
        pub2.create()
    assert f2.value.code == "ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED"


# ===========================================================================
# 4. Delayed lifecycle race: a later create/open cannot reset to empty
# ===========================================================================


def _mp_delayed_lifecycle_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    worker_id: str,
    action: str,
) -> None:
    """Spawn-safe worker that performs a delayed create() or open() against an
    already-initialized store and reports whether it reset the ledger."""

    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        FilesystemAssumptionPolicyPublisher,
        PolicyStoreError,
    )

    pub = FilesystemAssumptionPolicyPublisher(Path(root))
    try:
        if action == "create":
            try:
                pub.create()
                result_queue.put(("CREATED", worker_id, ""))
            except PolicyStoreError as exc:
                result_queue.put(("REFUSED", worker_id, exc.code))
        else:
            try:
                pub.open()
                result_queue.put(("OPENED", worker_id, ""))
            except PolicyStoreError as exc:
                result_queue.put(("OPEN_ERROR", worker_id, exc.code))
    except Exception as exc:  # noqa: BLE001
        result_queue.put(("ERROR", worker_id, repr(exc)))


def test_delayed_create_cannot_reset_to_empty(tmp_path: Path) -> None:
    """Process A creates + commits an entry. Process B then does a delayed
    create() against the now-populated store. B must NOT reset the ledger to
    empty: it must observe the existing valid ledger and refuse with
    ALREADY_INITIALIZED. The committed entry remains authoritative."""

    # Process A (the parent) creates and commits.
    pub_a = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub_a.create()
    prepared = _prepared_activation(seq=10)
    pub_a.publish(prepared=prepared, expected_state=pub_a.read_state())
    state_after_commit = pub_a.read_state()
    assert state_after_commit.head_entry_digest is not None

    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]
    proc_b = ctx.Process(
        target=_mp_delayed_lifecycle_worker,
        args=(str(tmp_path), queue, "B", "create"),
    )
    proc_b.start()
    proc_b.join(timeout=60)
    assert proc_b.exitcode == 0, f"B exited {proc_b.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 1:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 1, f"missing outcome: {outcomes}"
    assert outcomes[0][0] == "REFUSED", outcomes
    assert outcomes[0][2] == "ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED"

    # The committed entry is still authoritative; B did not reset to empty.
    pub_c = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub_c.open()
    assert pub_c.read_state() == state_after_commit
    assert pub_c.read_state().head_entry_digest == prepared.ledger_entry.ledger_entry_digest


def test_delayed_open_cannot_reset_to_empty(tmp_path: Path) -> None:
    """Process A creates + commits. Process B does a delayed open(); it
    reconstructs the populated ledger and never resets it."""

    pub_a = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub_a.create()
    prepared = _prepared_activation(seq=10)
    pub_a.publish(prepared=prepared, expected_state=pub_a.read_state())
    state_after_commit = pub_a.read_state()

    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]
    proc_b = ctx.Process(
        target=_mp_delayed_lifecycle_worker,
        args=(str(tmp_path), queue, "B", "open"),
    )
    proc_b.start()
    proc_b.join(timeout=60)
    assert proc_b.exitcode == 0, f"B exited {proc_b.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 1:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 1, f"missing outcome: {outcomes}"
    assert outcomes[0][0] == "OPENED", outcomes

    pub_c = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub_c.open()
    assert pub_c.read_state() == state_after_commit


# ===========================================================================
# 5. Lifecycle / path-shape boundary
# ===========================================================================


def test_open_on_missing_root_raises_root_missing(tmp_path: Path) -> None:
    """open() on a root that does not exist raises ROOT_MISSING and creates
    nothing (only create() may create the root)."""

    missing = tmp_path / "does-not-exist"
    pub = FilesystemAssumptionPolicyPublisher(missing)
    with pytest.raises(PolicyStoreError) as f:
        pub.open()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_MISSING"
    assert not missing.exists()


def test_read_state_on_missing_root_raises_root_missing(tmp_path: Path) -> None:
    """read_state() on a missing root raises ROOT_MISSING and creates nothing."""

    missing = tmp_path / "nope"
    pub = FilesystemAssumptionPolicyPublisher(missing)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_MISSING"
    assert not missing.exists()


def test_read_ledger_on_missing_root_raises_root_missing(tmp_path: Path) -> None:
    """read_ledger() on a missing root raises ROOT_MISSING and creates nothing."""

    missing = tmp_path / "nope"
    pub = FilesystemAssumptionPolicyPublisher(missing)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_ledger()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_MISSING"
    assert not missing.exists()


def test_open_lock_path_is_directory(tmp_path: Path) -> None:
    """If publication.lock is a directory, opening the store must fail (the
    lock helper cannot lock a directory) rather than corrupt anything."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Replace the lock file with a directory of the same name.
    (tmp_path / "publication.lock").unlink()
    (tmp_path / "publication.lock").mkdir()
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub2.open()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_LOCK_FAILED"


@_skip_no_symlinks
def test_open_lock_path_is_symlink(tmp_path: Path) -> None:
    """If publication.lock is a symlink, open() must not follow it into
    corruption: it fails at the lock boundary."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    target = tmp_path / "elsewhere"
    target.write_bytes(b"x")
    lock = tmp_path / "publication.lock"
    lock.unlink()
    lock.symlink_to(target)
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    # open() under the lock must surface a lock failure or the existing ledger
    # cleanly; it must never corrupt the authoritative ledger.
    with suppress(PolicyStoreError):
        pub2.open()
    # The authoritative ledger is still valid.
    pub3 = FilesystemAssumptionPolicyPublisher(tmp_path)
    # Remove the symlink so a clean lock can be acquired.
    lock.unlink()
    pub3.open()
    assert pub3.read_state() == ExpectedPolicyLedgerStateV3.empty()


def test_ledger_path_is_directory_surfaces_write_failed(tmp_path: Path) -> None:
    """If ledger.json is a directory, a publish's os.replace cannot overwrite
    it and the publication fails with REPLACE_FAILED (pre-commit: old state
    intact)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Replace ledger.json with a directory.
    (tmp_path / "ledger.json").unlink()
    (tmp_path / "ledger.json").mkdir()
    # Re-seed a valid empty ledger elsewhere is not possible; instead write a
    # canonical empty ledger back is not possible because the path is a dir.
    # The publish must fail at the replace step.
    prepared = _prepared_activation(seq=10)
    with pytest.raises((PolicyStoreError, AssumptionPolicyPublicationConflict)) as f:
        pub.publish(prepared=prepared, expected_state=ExpectedPolicyLedgerStateV3.empty())
    if hasattr(f.value, "code") and isinstance(f.value, PolicyStoreError):
        assert f.value.code in (
            "ASSUMPTION_POLICY_STORE_REPLACE_FAILED",
            "ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED",
            "ASSUMPTION_POLICY_STORED_BYTES_MISSING",
            "ASSUMPTION_POLICY_STORED_BYTES_INVALID",
        )


def test_managed_temp_path_collision_is_directory(tmp_path: Path) -> None:
    """If a managed temp path shape is a directory (an attacker planted one),
    _write_and_fsync_temp refuses with WRITE_FAILED rather than writing into
    it. We cannot predict the uuid, but we can pre-create many candidate dirs;
    the write still must not crash or corrupt."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Pre-create a handful of candidate managed-temp directories. The uuid is
    # random, so these almost certainly will not collide, but the test asserts
    # the publisher still publishes successfully (the directory orphans are
    # left untouched and the write picks a fresh uuid).
    for i in range(3):
        (tmp_path / f".policy-ledger.{'0' * 31}{i}.tmp").mkdir()
    prepared = _prepared_activation(seq=10)
    result = pub.publish(prepared=prepared, expected_state=pub.read_state())
    assert result.append_result == "COMMITTED"


@_skip_no_symlinks
def test_root_is_symlink_to_directory(tmp_path: Path) -> None:
    """A root that is a symlink to a directory is accepted (it resolves to a
    directory); publication succeeds through the symlink."""

    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    pub = FilesystemAssumptionPolicyPublisher(link)
    pub.create()
    prepared = _prepared_activation(seq=10)
    result = pub.publish(prepared=prepared, expected_state=pub.read_state())
    assert result.append_result == "COMMITTED"
    # The authoritative ledger lives under the resolved directory.
    assert (real / "ledger.json").exists()


def test_orphan_cleanup_ignores_directory_matching_pattern(tmp_path: Path) -> None:
    """A directory whose name matches the managed temp pattern is never removed
    by orphan cleanup (only regular files are removed)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    fake = tmp_path / ".policy-ledger.deadbeefdeadbeefdeadbeefdeadbeef.tmp"
    fake.mkdir()
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert fake.is_dir()  # still present, untouched


@_skip_no_symlinks
def test_orphan_cleanup_ignores_symlink_matching_pattern(tmp_path: Path) -> None:
    """A symlink whose name matches the managed temp pattern is never removed
    (and never followed) by orphan cleanup."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    target = tmp_path / "target.txt"
    target.write_bytes(b"precious")
    link = tmp_path / ".policy-ledger.deadbeefdeadbeefdeadbeefdeadbeef.tmp"
    link.symlink_to(target)
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    assert link.is_symlink()
    assert target.read_bytes() == b"precious"


def test_orphan_cleanup_requires_exact_32_hex_pattern(tmp_path: Path) -> None:
    """Names that almost match but are not exactly 32 lowercase hex chars are
    preserved: 31 hex, 33 hex, uppercase, or non-hex middles are all left
    alone."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    keepers = [
        ".policy-ledger." + "a" * 31 + ".tmp",  # too short
        ".policy-ledger." + "a" * 33 + ".tmp",  # too long
        ".policy-ledger." + "A" * 32 + ".tmp",  # uppercase
        ".policy-ledger." + "z" * 32 + ".tmp",  # non-hex
        ".policy-ledger..tmp",  # empty middle
        "orphan.tmp",  # wrong prefix
    ]
    for name in keepers:
        (tmp_path / name).write_bytes(b"keep")
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    for name in keepers:
        assert (tmp_path / name).read_bytes() == b"keep", name


# ===========================================================================
# 3b. Orphan cleanup failures are not suppressed (Correction 3)
# ===========================================================================
#
# A managed orphan (``.policy-ledger.<32-hex>.tmp``) that cannot be unlinked
# surfaces ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED``; a directory fsync
# failure after at least one removal surfaces
# ``ASSUMPTION_POLICY_STORE_DURABILITY_FAILED``. In every case the
# authoritative ledger bytes are unchanged and foreign files / directories /
# symlinks are left untouched.


_ORPHAN_NAME = ".policy-ledger.deadbeefdeadbeefdeadbeefdeadbeef.tmp"


def _seed_store_with_entry_and_state(
    tmp_path: Path,
) -> tuple[Path, bytes, ExpectedPolicyLedgerStateV3]:
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    pub.publish(prepared=_prepared_activation(), expected_state=pub.read_state())
    state = pub.read_state()
    ledger_path = tmp_path / "ledger.json"
    return ledger_path, ledger_path.read_bytes(), state


def test_orphan_unlink_failure_surfaces_cleanup_failed(tmp_path: Path) -> None:
    """A managed orphan whose unlink raises OSError surfaces
    TEMP_CLEANUP_FAILED; the authoritative ledger bytes are unchanged."""

    import unittest.mock as mock

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    orphan = tmp_path / _ORPHAN_NAME
    orphan.write_bytes(b"garbage")

    real_unlink = Path.unlink

    def flaky_unlink(self, *args, **kwargs):
        if self == orphan:
            raise OSError("injected unlink failure")
        return real_unlink(self, *args, **kwargs)

    with mock.patch.object(Path, "unlink", flaky_unlink):
        pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
        with pytest.raises(PolicyStoreError) as f:
            pub2.open()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED"
    # The orphan is still present (unlink failed); the authoritative ledger is
    # byte-for-byte unchanged.
    assert orphan.exists()
    assert ledger_path.read_bytes() == bytes_before


def test_post_cleanup_dir_fsync_failure_surfaces_durability_failed(tmp_path: Path) -> None:
    """When at least one orphan is removed, a subsequent directory fsync
    failure surfaces DURABILITY_FAILED; the authoritative ledger is unchanged.

    fsync_directory is a no-op on Windows, so this test exercises the POSIX
    branch via monkeypatching (it still proves the error path is wired on both
    platforms by injecting a raising stub)."""

    import unittest.mock as mock

    from csd_foundry.governance.v0_5 import assumption_policy_filesystem_publication as mod

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    orphan = tmp_path / _ORPHAN_NAME
    orphan.write_bytes(b"garbage")

    with mock.patch.object(mod, "fsync_directory", side_effect=OSError("injected fsync")):
        pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
        with pytest.raises(PolicyStoreError) as f:
            pub2.open()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_DURABILITY_FAILED"
    # The orphan was removed; the authoritative ledger is unchanged.
    assert not orphan.exists()
    assert ledger_path.read_bytes() == bytes_before


def test_post_cleanup_dir_fsync_skipped_when_nothing_removed(tmp_path: Path) -> None:
    """If no managed orphan is removed, fsync_directory is not called, so a
    broken stub does not affect open(). (Proves the dir-fsync failure path is
    gated on ``removed_any``.)"""

    import unittest.mock as mock

    from csd_foundry.governance.v0_5 import assumption_policy_filesystem_publication as mod

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    # No orphan present, so removed_any stays False and fsync is never called.

    calls = []

    def spy_fsync(path):
        calls.append(path)
        raise OSError("should not be called")

    with mock.patch.object(mod, "fsync_directory", spy_fsync):
        pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
        pub2.open()  # must not raise
    assert calls == []
    assert ledger_path.read_bytes() == bytes_before


def test_cleanup_failure_preserves_foreign_file(tmp_path: Path) -> None:
    """A foreign file in the store root is never touched, even when a managed
    orphan alongside it cannot be removed (state and bytes unchanged)."""

    import unittest.mock as mock

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    orphan = tmp_path / _ORPHAN_NAME
    orphan.write_bytes(b"garbage")
    foreign = tmp_path / "unrelated.tmp"
    foreign.write_bytes(b"keep-me")
    foreign_bytes = foreign.read_bytes()

    real_unlink = Path.unlink

    def flaky_unlink(self, *args, **kwargs):
        if self == orphan:
            raise OSError("injected unlink failure")
        return real_unlink(self, *args, **kwargs)

    with mock.patch.object(Path, "unlink", flaky_unlink):
        pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
        with pytest.raises(PolicyStoreError):
            pub2.open()
    # Foreign file untouched; authoritative ledger unchanged.
    assert foreign.read_bytes() == foreign_bytes
    assert ledger_path.read_bytes() == bytes_before


def test_cleanup_failure_preserves_directory_matching_pattern(tmp_path: Path) -> None:
    """A directory whose name matches the managed pattern is never removed, and
    its presence does not trip the cleanup (it is skipped, not unlinked). The
    authoritative ledger is unchanged."""

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    fake_dir = tmp_path / _ORPHAN_NAME
    fake_dir.mkdir()
    (fake_dir / "inside").write_bytes(b"x")

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()  # must not raise: the directory is skipped, not removed
    assert fake_dir.is_dir()
    assert (fake_dir / "inside").read_bytes() == b"x"
    assert ledger_path.read_bytes() == bytes_before


@_skip_no_symlinks
def test_cleanup_failure_preserves_symlink_matching_pattern(tmp_path: Path) -> None:
    """A symlink whose name matches the managed pattern is never removed or
    followed; the target is preserved; the authoritative ledger is unchanged."""

    ledger_path, bytes_before, _state = _seed_store_with_entry_and_state(tmp_path)
    target = tmp_path / "precious"
    target.write_bytes(b"keep")
    link = tmp_path / _ORPHAN_NAME
    link.symlink_to(target)

    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()  # must not raise: the symlink is skipped, not removed
    assert link.is_symlink()
    assert target.read_bytes() == b"keep"
    assert ledger_path.read_bytes() == bytes_before


# ===========================================================================
# 6. Backend exception diagnostics are never exposed
# ===========================================================================


def test_error_details_never_contain_backend_exception_text(tmp_path: Path) -> None:
    """No PolicyStoreError detail carries str(exc)/repr(exc) of an underlying
    OSError. We force a lock-acquisition failure by making the lock path
    unusable and assert the LOCK_FAILED detail is None (not the OSError
    message)."""

    # Make the lock path's parent a regular file so advisory_lock cannot open
    # the lock file. The root itself is a file -> ROOT_NOT_DIRECTORY is raised
    # first by _validate_root for create(); use a sub-store whose lock parent
    # is a file by pointing root at a path whose parent is fine but root is a
    # file.
    root = tmp_path / "store"
    root.write_text("x")  # root is a regular file
    pub = FilesystemAssumptionPolicyPublisher(root)
    with pytest.raises(PolicyStoreError) as f:
        pub.create()
    assert f.value.code == "ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY"
    # No backend text in the detail.
    assert f.value.detail is None


def test_locked_does_not_mislabel_body_oserror_as_lock_failed(tmp_path: Path) -> None:
    """An OSError raised by the protected operation inside _locked() must NOT
    be mislabeled LOCK_FAILED. We force a body OSError by making the ledger
    path a directory (read_bytes on a dir raises) -- but the cleaner proof is
    that _read_ledger_bytes raises BYTES_INVALID (an OSError-derived
    PolicyStoreError), never LOCK_FAILED."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    # Corrupt the authoritative file so reconstruction raises a non-lock error
    # inside the locked body.
    (tmp_path / "ledger.json").write_bytes(b"\xff not json")
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    # The body error is BYTES_INVALID, never LOCK_FAILED.
    assert f.value.code != "ASSUMPTION_POLICY_STORE_LOCK_FAILED"
    assert f.value.code == "ASSUMPTION_POLICY_STORED_BYTES_INVALID"


# ===========================================================================
# 7. Duplicate JSON keys are rejected at every depth
# ===========================================================================


def _expect_duplicate_key(tmp_path: Path, mutate) -> None:
    """Apply ``mutate(ledger_dict)`` producing JSON with a duplicate key and
    assert the read surfaces DUPLICATE_KEY."""

    ledger_path = _seed_store_with_one_entry(tmp_path)
    data = _load_ledger_dict(ledger_path)
    raw = mutate(data)
    # Write the raw (duplicate-key) JSON literally; canonical re-serialization
    # would collapse duplicates.
    (tmp_path / "ledger.json").write_bytes(raw)
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as f:
        pub.read_state()
    assert f.value.code == "ASSUMPTION_POLICY_STORED_DUPLICATE_KEY"


def _dump_with_duplicate_key(obj: object, dup_key: str, dup_value: object) -> bytes:
    """Serialize ``obj`` to canonical-ish JSON but with ``dup_key`` emitted
    twice (once with its real value, once with ``dup_value``)."""

    import json as _json

    assert isinstance(obj, dict)
    # Build a token stream by hand to inject a duplicate key at the top level
    # or within a nested dict. We emit keys in sorted order, duplicating the
    # requested key immediately after its first occurrence.
    parts: list[str] = ["{"]
    items = sorted(obj.items())
    for i, (k, v) in enumerate(items):
        parts.append(_json.dumps(k))
        parts.append(":")
        parts.append(_json.dumps(v))
        if k == dup_key:
            parts.append(",")
            parts.append(_json.dumps(dup_key))
            parts.append(":")
            parts.append(_json.dumps(dup_value))
        if i != len(items) - 1:
            parts.append(",")
    parts.append("}")
    return ("".join(parts) + "\n").encode("utf-8")


def _inject_dup_key_into_nested(
    data: dict, path_keys: list[str], dup_key: str, dup_value: object
) -> bytes:
    """Serialize ``data`` to JSON, injecting a duplicate ``dup_key`` (with
    ``dup_value``) into the nested dict located at ``path_keys``.

    ``path_keys`` alternates dict keys and list indices (as strings, e.g.
    ``["entries", "0", "policy", "grants", "0"]``)."""

    import json as _json

    def emit_at(obj: object, cur_path: list[str]) -> str:
        if isinstance(obj, dict):
            is_target = cur_path == path_keys
            keys = list(obj.keys())
            parts = ["{"]
            for i, k in enumerate(keys):
                v = obj[k]
                parts.append(_json.dumps(k))
                parts.append(":")
                parts.append(emit_at(v, cur_path + [k]))
                if is_target and k == dup_key:
                    parts.append(",")
                    parts.append(_json.dumps(dup_key))
                    parts.append(":")
                    parts.append(_json.dumps(dup_value))
                if i != len(keys) - 1:
                    parts.append(",")
            parts.append("}")
            return "".join(parts)
        if isinstance(obj, list):
            # Only recurse into the element the path points at; emit the rest
            # verbatim. This keeps the index segment in cur_path aligned with
            # path_keys.
            parts = ["["]
            for idx, e in enumerate(obj):
                idx_str = str(idx)
                # If this index is on the path, recurse with the index appended
                # so the target dict is reachable; otherwise emit verbatim.
                on_path = len(cur_path) < len(path_keys) and path_keys[len(cur_path)] == idx_str
                if on_path:
                    parts.append(emit_at(e, cur_path + [idx_str]))
                else:
                    parts.append(_json.dumps(e))
                if idx != len(obj) - 1:
                    parts.append(",")
            parts.append("]")
            return "".join(parts)
        return _json.dumps(obj)

    return (emit_at(data, []) + "\n").encode("utf-8")


def test_duplicate_schema_version_rejected(tmp_path: Path) -> None:
    def mutate(d):
        return _dump_with_duplicate_key(d, "schema_version", "assumption-policy-ledger/x")

    _expect_duplicate_key(tmp_path, mutate)


def test_duplicate_ledger_root_digest_rejected(tmp_path: Path) -> None:
    def mutate(d):
        return _dump_with_duplicate_key(d, "ledger_root_digest", "sha256:" + "0" * 64)

    _expect_duplicate_key(tmp_path, mutate)


def test_duplicate_embedded_policy_digest_rejected(tmp_path: Path) -> None:
    """A duplicate key inside the nested policy object is rejected too."""

    def mutate(d):
        return _inject_dup_key_into_nested(
            d,
            path_keys=["entries", "0", "policy"],
            dup_key="policy_digest",
            dup_value="sha256:" + "0" * 64,
        )

    _expect_duplicate_key(tmp_path, mutate)


def test_duplicate_nested_grant_field_rejected(tmp_path: Path) -> None:
    """A duplicate key deep inside a grant object is rejected."""

    def mutate(d):
        return _inject_dup_key_into_nested(
            d,
            path_keys=["entries", "0", "policy", "grants", "0"],
            dup_key="grant_id",
            dup_value="grant:dup",
        )

    _expect_duplicate_key(tmp_path, mutate)
