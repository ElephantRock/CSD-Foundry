"""Tests for v0.5-D3.2-A1.2 assumption policy activation preparation (V3 envelope).

Uses a 3-signer pattern: authority:a and authority:b are always valid and
satisfy the STANDARD threshold (2). authority:c is mutated or failing, so
preparation succeeds and the exact rejection code for c is visible in:

    prepared.ledger_entry.activation_proof.rejected_signer_codes

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
    AssumptionPolicyActivationContractError,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
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

_ALGO = "ed25519"
_VP = "ed25519-rfc8032-strict/1"
_SCOPE = "ASSUMPTION_POLICY_APPROVAL"
_SIGNERS = ("authority:a", "authority:b", "authority:c")


def _digest(c: str) -> str:
    return "sha256:" + c * 64


def _digest_for(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"pkd\0" + b).hexdigest()


# --- frozen inputs ---------------------------------------------------------


def _approval_policy() -> AssumptionPolicyApprovalPolicy:
    s = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=2,
        required_signer_ids=("authority:a",),
    )
    d = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=3,
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


def _duty_exception(eid: str) -> AssumptionDutyException:
    return AssumptionDutyException.build(
        exception_id=eid,
        rule_id="rule:1",
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        conflicting_roles=("CHALLENGER",),
        scope_ids=("scope:control",),
        assumption_ids=("assumption:1",),
        assumption_materialities=("MATERIAL",),
        reason_code="EMERGENCY",
        effective_from_sequence=1,
        effective_until_sequence=50,
    )


def _policy_with_exception() -> AssumptionAuthorityPolicy:
    g = AssumptionAuthorityGrant.build(
        grant_id="grant:r",
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        effective_from_sequence=1,
    )
    r = AssumptionSeparationDutyRule.build(
        rule_id="rule:1",
        action="RESOLVE_TO_ADMITTED",
        conflicting_roles=("CHALLENGER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:exc",
        authority_root_digest=_digest("a"),
        grants=(g,),
        separation_duty_rules=(r,),
        duty_exceptions=(_duty_exception("exc:1"),),
    )


# --- V3 payload + commit ---------------------------------------------------


def _payload(
    policy: AssumptionAuthorityPolicy | None = None, seq: int = 10
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
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


# --- key/authority fixtures ------------------------------------------------


def _vkey(kid: str = "key:a", pk: bytes = b"pk-a") -> ResolvedAssumptionPolicyVerificationKey:
    return ResolvedAssumptionPolicyVerificationKey(
        key_id=kid,
        algorithm=_ALGO,
        public_key_bytes=pk,
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"kr:" + kid.encode()),
    )


def _auth(
    sid: str = "authority:a", kid: str = "key:a", **kw
) -> ResolvedAssumptionPolicySignerAuthority:
    defaults = dict(
        authority_root_digest=_digest("a"),
        authority_scopes=(_SCOPE,),
        algorithms=(_ALGO,),
        valid_from_sequence=0,
        valid_until_sequence=None,
        revocation_sequence=None,
        resolution_receipt_digest=_digest_for(b"ar:" + sid.encode()),
    )
    defaults.update(kw)
    return ResolvedAssumptionPolicySignerAuthority(signer_id=sid, key_id=kid, **defaults)


class _SKR:
    """Static key resolver."""

    def __init__(self, keys):
        self._m = {(k.key_id, k.algorithm): k for k in keys}

    def resolve(self, *, key_id, algorithm, key_authority_root_digest):
        return self._m.get((key_id, algorithm))


class _SAR:
    """Static authority resolver."""

    def __init__(self, auths):
        self._m = {(a.signer_id, a.key_id): a for a in auths}

    def resolve(self, *, signer_id, key_id, authority_root_digest):
        return self._m.get((signer_id, key_id))


# --- 3-signer bundle -------------------------------------------------------
# a+b always valid; c is the mutation target. Threshold=2, so a+b satisfies it.


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


def _bundle3(
    policy: AssumptionAuthorityPolicy | None = None,
    signers: tuple[str, ...] = _SIGNERS,
):
    p = policy or _policy()
    payload = _payload(policy=p)
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
    return p, payload, commit, _approval_policy(), _sig_profile(), _chal_policy(), ss, prep


def _do_prepare(bundle):
    p, pl, c, ap, sp, cp, ss, prep = bundle
    return prep.prepare(
        policy=p,
        signing_payload=pl,
        commit=c,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=ss,
    )


def _do_deny(bundle):
    with pytest.raises(AssumptionPolicyActivationDenied) as f:
        _do_prepare(bundle)
    return f.value


def _deny_with(prep, bundle):
    p, pl, c, ap, sp, cp, ss, _ = bundle
    with pytest.raises(AssumptionPolicyActivationDenied) as f:
        prep.prepare(
            policy=p,
            signing_payload=pl,
            commit=c,
            approval_policy=ap,
            signature_profile=sp,
            challenge_policy=cp,
            signature_set=ss,
        )
    return f.value


def _prep_with(prep, bundle):
    """Prepare with a custom preparer; returns the prepared activation."""
    p, pl, c, ap, sp, cp, ss, _ = bundle
    return prep.prepare(
        policy=p,
        signing_payload=pl,
        commit=c,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=ss,
    )


def _replace_c_resolver(bundle, *, key_resolver=None, authority_resolver=None, verifier=None):
    """Return a new preparer with c's resolver/verifier replaced."""
    _, _, _, _, _, _, _, orig = bundle
    return ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=key_resolver or orig.key_resolver,  # type: ignore[attr-defined]
        authority_resolver=authority_resolver or orig.authority_resolver,  # type: ignore[attr-defined]
        signature_verifier=verifier or orig.signature_verifier,  # type: ignore[attr-defined]
    )


# ===========================================================================
# Successful preparation
# ===========================================================================


def test_valid_standard_preparation_succeeds() -> None:
    prepared = _do_prepare(_bundle3())
    assert set(prepared.ledger_entry.activation_proof.valid_signer_ids) == set(_SIGNERS)
    assert prepared.ledger_entry.activation_proof.rejected_signer_codes == ()


def test_valid_duty_exception_preparation_succeeds() -> None:
    prepared = _do_prepare(_bundle3(policy=_policy_with_exception(), signers=_SIGNERS))
    assert prepared.ledger_entry.policy_commit.signing_payload_digest


def test_exact_threshold_succeeds() -> None:
    prepared = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    assert len(prepared.ledger_entry.activation_proof.valid_signer_ids) == 2


def test_permuted_signatures_produce_identical_prepared_bytes() -> None:
    b1 = _bundle3(signers=("authority:a", "authority:b"))
    pa = _do_prepare(b1)
    p, pl, c, ap, sp, cp, _, prep = b1
    recs_rev = tuple(
        _sig_record(s, f"key:{s[-1]}", pl.signing_payload_digest, f"pk-{s[-1]}".encode())
        for s in ("authority:b", "authority:a")
    )
    pb = prep.prepare(
        policy=p,
        signing_payload=pl,
        commit=c,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=_sig_set(recs_rev),
    )
    assert pa.prepared_digest == pb.prepared_digest


def test_identical_inputs_produce_identical_output() -> None:
    a = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    b = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    assert a.prepared_digest == b.prepared_digest


def test_extra_rejected_signer_recorded_while_threshold_succeeds() -> None:
    # c has wrong public key -> signature won't verify; a+b still valid.
    bundle = _bundle3()
    p, pl, c, ap, sp, cp, _, prep = bundle
    pks = {"authority:a": b"pk-a", "authority:b": b"pk-b", "authority:c": b"pk-c-wrong"}
    kids = {"authority:a": "key:a", "authority:b": "key:b", "authority:c": "key:c"}
    records = tuple(_sig_record(s, kids[s], pl.signing_payload_digest, pks[s]) for s in _SIGNERS)
    ss = _sig_set(records)
    commit = _commit(pl, ss.digest)
    keys = tuple(_vkey(kids[s], f"pk-{s[-1]}".encode()) for s in _SIGNERS)
    # c's resolver returns the REAL key, but the signature was built over pk-c-wrong.
    prep3 = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_SKR(keys),
        authority_resolver=_SAR(tuple(_auth(s, kids[s]) for s in _SIGNERS)),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    prepared = prep3.prepare(
        policy=p,
        signing_payload=pl,
        commit=commit,
        approval_policy=ap,
        signature_profile=sp,
        challenge_policy=cp,
        signature_set=ss,
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
    p = _policy()
    pl = _payload(policy=p)
    c2 = AssumptionAuthorityPolicyCommitV2.build(
        policy=p,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=10,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        signature_profile_digest=_sig_profile().profile_digest,
        challenge_classification_policy_digest=_chal_policy().policy_digest,
        signature_set_digest=_digest("b"),
    )
    prep = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_SKR(()),
        authority_resolver=_SAR(()),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    rec = (_sig_record("authority:a", "key:a", pl.signing_payload_digest, b"pk-a"),)
    with pytest.raises(AssumptionPolicyActivationDenied) as f:
        prep.prepare(
            policy=p,
            signing_payload=pl,
            commit=c2,  # type: ignore[arg-type]
            approval_policy=_approval_policy(),
            signature_profile=_sig_profile(),
            challenge_policy=_chal_policy(),
            signature_set=_sig_set(rec),
        )
    assert f.value.code == "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
    assert f.value.stage == "PARSE_AND_SELF_DIGESTS"


def test_policy_overlap_denied() -> None:
    p = AssumptionAuthorityPolicy.build(
        policy_id="policy:overlap",
        authority_root_digest=_digest("a"),
        grants=(_grant("g:a"), _grant("g:b")),
    )
    denied = _do_deny(_bundle3(policy=p))
    assert denied.stage == "POLICY_STRUCTURE_AND_OVERLAP"


def test_commit_payload_mismatch_denied() -> None:
    bundle = _bundle3()
    p, pl, _, ap, sp, cp, ss, prep = bundle
    other_pl = _payload(
        policy=AssumptionAuthorityPolicy.build(
            policy_id="policy:other", authority_root_digest=_digest("a"), grants=(_grant(),)
        )
    )
    wrong_c = _commit(other_pl, ss.digest)
    denied = _deny_with(
        ReferenceAssumptionPolicyActivationPreparer(
            key_resolver=prep.key_resolver,  # type: ignore[attr-defined]
            authority_resolver=prep.authority_resolver,  # type: ignore[attr-defined]
            signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
        ),
        (p, pl, wrong_c, ap, sp, cp, ss, prep),
    )
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_PAYLOAD_MISMATCH"


def test_commit_signature_set_mismatch_denied() -> None:
    bundle = _bundle3()
    p, pl, c, ap, sp, cp, _, prep = bundle
    other_recs = (_sig_record("authority:a", "key:a", pl.signing_payload_digest, b"other-pk"),)
    denied = _deny_with(
        ReferenceAssumptionPolicyActivationPreparer(
            key_resolver=prep.key_resolver,  # type: ignore[attr-defined]
            authority_resolver=prep.authority_resolver,  # type: ignore[attr-defined]
            signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
        ),
        (p, pl, c, ap, sp, cp, _sig_set(other_recs), prep),
    )
    assert denied.code == "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_MISMATCH"


def test_wrong_signed_target_rejected_before_key_resolution() -> None:
    bundle = _bundle3()
    p, pl, _, ap, sp, cp, _, prep = bundle
    wrong_recs = tuple(
        _sig_record(s, f"key:{s[-1]}", _digest("f"), f"pk-{s[-1]}".encode())
        for s in ("authority:a", "authority:b")
    )
    wrong_ss = _sig_set(wrong_recs)
    wrong_c = _commit(pl, wrong_ss.digest)
    denied = _deny_with(
        ReferenceAssumptionPolicyActivationPreparer(
            key_resolver=prep.key_resolver,  # type: ignore[attr-defined]
            authority_resolver=prep.authority_resolver,  # type: ignore[attr-defined]
            signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
        ),
        (p, pl, wrong_c, ap, sp, cp, wrong_ss, prep),
    )
    assert denied.code == "ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH"


def test_duplicate_signer_denied() -> None:
    bundle = _bundle3(signers=("authority:a",))
    p, pl, _, ap, sp, cp, _, prep = bundle
    dup = (
        _sig_record("authority:a", "key:a", pl.signing_payload_digest, b"pk-a"),
        _sig_record("authority:a", "key:a2", pl.signing_payload_digest, b"pk-a2"),
    )
    dup_ss = _sig_set(dup)
    dup_c = _commit(pl, dup_ss.digest)
    denied = _deny_with(prep, (p, pl, dup_c, ap, sp, cp, dup_ss, prep))
    assert denied.code == "ASSUMPTION_POLICY_DUPLICATE_SIGNER_RECORD"


def test_malformed_base64_denied() -> None:
    bundle = _bundle3(signers=("authority:a", "authority:b"))
    p, pl, _, ap, sp, cp, _, prep = bundle
    bad = (
        {
            "signer_id": "authority:a",
            "key_id": "key:a",
            "algorithm": _ALGO,
            "signed_digest": pl.signing_payload_digest,
            "signature_base64": "!!!!",
            "authority_scope": _SCOPE,
        },
        _sig_record("authority:b", "key:b", pl.signing_payload_digest, b"pk-b"),
    )
    bad_ss = _sig_set(bad)
    bad_c = _commit(pl, bad_ss.digest)
    denied = _deny_with(prep, (p, pl, bad_c, ap, sp, cp, bad_ss, prep))
    assert denied.code == "ASSUMPTION_POLICY_SIGNATURE_ENCODING_INVALID"


def test_algorithm_not_pinned_denied() -> None:
    bundle = _bundle3(signers=("authority:a", "authority:b"))
    p, pl, _, ap, sp, cp, _, prep = bundle
    unp = tuple(
        {
            "signer_id": s,
            "key_id": f"key:{s[-1]}",
            "algorithm": "rsa-pss-sha256",
            "signed_digest": pl.signing_payload_digest,
            "signature_base64": base64.b64encode(b"x" * 32).decode("ascii"),
            "authority_scope": _SCOPE,
        }
        for s in ("authority:a", "authority:b")
    )
    unp_ss = _sig_set(unp)
    denied = _deny_with(prep, (p, pl, _commit(pl, unp_ss.digest), ap, sp, cp, unp_ss, prep))
    assert denied.code == "ASSUMPTION_POLICY_SIGNATURE_ALGORITHM_NOT_PINNED"


# ===========================================================================
# Approval failures (whole-attempt denials)
# ===========================================================================


def test_threshold_minus_one_denied() -> None:
    denied = _do_deny(_bundle3(signers=("authority:a",)))
    assert denied.code == "ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET"


def test_missing_mandatory_signer_denied() -> None:
    denied = _do_deny(_bundle3(signers=("authority:b", "authority:c")))
    assert denied.code == "ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING"
    assert denied.detail == "authority:a"


def test_ineligible_signer_denied() -> None:
    bundle = _bundle3(signers=("authority:a", "authority:b"))
    p, pl, _, ap, sp, cp, _, prep = bundle
    recs = (
        _sig_record("authority:a", "key:a", pl.signing_payload_digest, b"pk-a"),
        _sig_record("authority:d", "key:d", pl.signing_payload_digest, b"pk-d"),
    )
    ss = _sig_set(recs)
    keys = (_vkey("key:a", b"pk-a"), _vkey("key:d", b"pk-d"))
    auths = (_auth("authority:a", "key:a"), _auth("authority:d", "key:d"))
    prep_d = ReferenceAssumptionPolicyActivationPreparer(
        key_resolver=_SKR(keys),
        authority_resolver=_SAR(auths),
        signature_verifier=DeterministicAssumptionPolicySignatureVerifier(),
    )
    denied = _deny_with(prep_d, (p, pl, _commit(pl, ss.digest), ap, sp, cp, ss, prep))
    assert denied.code == "ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE"


# ===========================================================================
# Record-level rejections via 3-signer pattern
# a+b valid, c mutated; preparation succeeds, rejected_signer_codes exposes the code.
# ===========================================================================


class _COnlyKeyResolver:
    """Returns a correct key for a+b, and a custom value for c."""

    def __init__(self, c_value):
        self._ab = _SKR((_vkey("key:a", b"pk-a"), _vkey("key:b", b"pk-b")))
        self._c_value = c_value

    def resolve(self, *, key_id, algorithm, key_authority_root_digest):
        if key_id == "key:c":
            return self._c_value
        return self._ab.resolve(
            key_id=key_id,
            algorithm=algorithm,
            key_authority_root_digest=key_authority_root_digest,
        )


class _COnlyAuthResolver:
    """Returns a correct authority for a+b, and a custom value for c."""

    def __init__(self, c_value):
        self._ab = _SAR((_auth("authority:a", "key:a"), _auth("authority:b", "key:b")))
        self._c_value = c_value

    def resolve(self, *, signer_id, key_id, authority_root_digest):
        if signer_id == "authority:c":
            return self._c_value
        return self._ab.resolve(
            signer_id=signer_id,
            key_id=key_id,
            authority_root_digest=authority_root_digest,
        )


class _COnlyVerifier:
    """Real verifier for a+b (first 2 calls), delegates to c_verifier for c (3rd call).

    Records are processed in canonical (sorted) order, so authority:c is always
    the third record. supports() calls are counted the same way.
    """

    def __init__(self, c_verifier):
        self._real = DeterministicAssumptionPolicySignatureVerifier()
        self._c = c_verifier
        self._call = 0

    def supports(self, *, algorithm, verification_profile):
        self._call += 1
        if self._call == 3:
            return self._c.supports(algorithm=algorithm, verification_profile=verification_profile)
        return self._real.supports(algorithm=algorithm, verification_profile=verification_profile)

    def verify(
        self, *, algorithm, verification_profile, public_key_bytes, signed_digest, signature_bytes
    ):
        if public_key_bytes == b"pk-c":
            return self._c.verify(
                algorithm=algorithm,
                verification_profile=verification_profile,
                public_key_bytes=public_key_bytes,
                signed_digest=signed_digest,
                signature_bytes=signature_bytes,
            )
        return self._real.verify(
            algorithm=algorithm,
            verification_profile=verification_profile,
            public_key_bytes=public_key_bytes,
            signed_digest=signed_digest,
            signature_bytes=signature_bytes,
        )


def _assert_c_rejected(bundle, c_resolver, expected_code):
    """Prepare with c's resolver mutated; assert c's exact rejection code."""
    prep = _replace_c_resolver(bundle, **c_resolver)
    prepared = _prep_with(prep, bundle)
    codes = prepared.ledger_entry.activation_proof.rejected_signer_codes
    assert codes == (expected_code,), f"expected ({expected_code!r}), got {codes!r}"
    assert set(prepared.ledger_entry.activation_proof.valid_signer_ids) == {
        "authority:a",
        "authority:b",
    }


# --- key-level rejections ---


def test_key_id_mismatch() -> None:
    b = _bundle3()
    wrong = _vkey("key:wrong", b"pk-c")
    _assert_c_rejected(
        b,
        {"key_resolver": _COnlyKeyResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_ID_MISMATCH",
    )


def test_key_algorithm_mismatch() -> None:
    b = _bundle3()
    wrong = ResolvedAssumptionPolicyVerificationKey(
        key_id="key:c",
        algorithm="ecdsa-p256-sha256",
        public_key_bytes=b"pk-c",
        key_authority_root_digest=_digest("a"),
        resolution_receipt_digest=_digest_for(b"kr:key:c"),
    )
    _assert_c_rejected(
        b,
        {"key_resolver": _COnlyKeyResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_ALGORITHM_INCOMPATIBLE",
    )


def test_key_root_mismatch() -> None:
    b = _bundle3()
    wrong = ResolvedAssumptionPolicyVerificationKey(
        key_id="key:c",
        algorithm=_ALGO,
        public_key_bytes=b"pk-c",
        key_authority_root_digest=_digest("c"),
        resolution_receipt_digest=_digest_for(b"kr:key:c"),
    )
    _assert_c_rejected(
        b,
        {"key_resolver": _COnlyKeyResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_AUTHORITY_ROOT_MISMATCH",
    )


def test_unknown_key() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"key_resolver": _COnlyKeyResolver(None)},
        "ASSUMPTION_POLICY_SIGNER_UNKNOWN",
    )


# --- authority-level rejections ---


def test_signer_key_mismatch() -> None:
    b = _bundle3()
    wrong = _auth("authority:wrong", "key:c")
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_SIGNER_KEY_MISMATCH",
    )


def test_authority_root_mismatch() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", authority_root_digest=_digest("c"))
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_SIGNER_AUTHORITY_ROOT_MISMATCH",
    )


def test_scope_absent() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", authority_scopes=("OTHER",))
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_SIGNER_SCOPE_INVALID",
    )


def test_algorithm_unauthorized() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", algorithms=("ecdsa-p256-sha256",))
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_SIGNER_ALGORITHM_UNAUTHORIZED",
    )


def test_not_yet_valid() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", valid_from_sequence=20)
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_NOT_YET_VALID",
    )


def test_expired() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", valid_until_sequence=5)
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_EXPIRED",
    )


def test_revoked() -> None:
    b = _bundle3()
    wrong = _auth("authority:c", "key:c", revocation_sequence=5)
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(wrong)},
        "ASSUMPTION_POLICY_KEY_REVOKED",
    )


def test_unknown_authority() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(None)},
        "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED",
    )


# ===========================================================================
# Backend exception normalization (3-signer pattern, exact codes)
# ===========================================================================


class _ExcKeyResolver:
    """Valid for a+b; raises for c."""

    def __init__(self, exc):
        self._ab = _SKR((_vkey("key:a", b"pk-a"), _vkey("key:b", b"pk-b")))
        self._exc = exc

    def resolve(self, *, key_id, algorithm, key_authority_root_digest):
        if key_id == "key:c":
            raise self._exc
        return self._ab.resolve(
            key_id=key_id,
            algorithm=algorithm,
            key_authority_root_digest=key_authority_root_digest,
        )


class _ExcAuthResolver:
    def __init__(self, exc):
        self._ab = _SAR((_auth("authority:a", "key:a"), _auth("authority:b", "key:b")))
        self._exc = exc

    def resolve(self, *, signer_id, key_id, authority_root_digest):
        if signer_id == "authority:c":
            raise self._exc
        return self._ab.resolve(
            signer_id=signer_id,
            key_id=key_id,
            authority_root_digest=authority_root_digest,
        )


def test_key_resolver_exceptions_produce_identical_codes_and_bytes() -> None:
    b = _bundle3()
    digests = []
    for exc in (RuntimeError("A"), ValueError("B"), OSError("C")):
        prep = _replace_c_resolver(b, key_resolver=_ExcKeyResolver(exc))
        prepared = _prep_with(prep, b)
        codes = prepared.ledger_entry.activation_proof.rejected_signer_codes
        assert codes == ("ASSUMPTION_POLICY_SIGNER_UNKNOWN",)
        digests.append(prepared.prepared_digest)
    assert len(set(digests)) == 1


def test_authority_resolver_exceptions_produce_identical_codes_and_bytes() -> None:
    b = _bundle3()
    digests = []
    for exc in (RuntimeError("A"), ValueError("B")):
        prep = _replace_c_resolver(b, authority_resolver=_ExcAuthResolver(exc))
        prepared = _prep_with(prep, b)
        codes = prepared.ledger_entry.activation_proof.rejected_signer_codes
        assert codes == ("ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED",)
        digests.append(prepared.prepared_digest)
    assert len(set(digests)) == 1


# --- separate verifier doubles ---


class _SupportsRaises:
    def supports(self, *, algorithm, verification_profile):
        raise RuntimeError("diagnostic A")

    def verify(self, **kw):
        return True


class _SupportsFalse:
    def supports(self, *, algorithm, verification_profile):
        return False

    def verify(self, **kw):
        return True


class _VerifyRaises:
    def supports(self, *, algorithm, verification_profile):
        return True

    def verify(self, **kw):
        raise ValueError("diagnostic B")


class _VerifyFalse:
    def supports(self, *, algorithm, verification_profile):
        return True

    def verify(self, **kw):
        return False


def test_supports_raises_normalized() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"verifier": _COnlyVerifier(_SupportsRaises())},
        "ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED",
    )


def test_supports_false_normalized() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"verifier": _COnlyVerifier(_SupportsFalse())},
        "ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED",
    )


def test_verify_raises_normalized() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b, {"verifier": _COnlyVerifier(_VerifyRaises())}, "ASSUMPTION_POLICY_SIGNATURE_INVALID"
    )


def test_verify_false_normalized() -> None:
    b = _bundle3()
    _assert_c_rejected(
        b, {"verifier": _COnlyVerifier(_VerifyFalse())}, "ASSUMPTION_POLICY_SIGNATURE_INVALID"
    )


# ===========================================================================
# Backend return type validation (correction 4)
# ===========================================================================


@pytest.mark.parametrize("bad_value", [object(), "unexpected", {}])
def test_key_resolver_bad_return_type_rejected(bad_value) -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"key_resolver": _COnlyKeyResolver(bad_value)},
        "ASSUMPTION_POLICY_SIGNER_UNKNOWN",
    )


@pytest.mark.parametrize("bad_value", [object(), "unexpected", {}])
def test_authority_resolver_bad_return_type_rejected(bad_value) -> None:
    b = _bundle3()
    _assert_c_rejected(
        b,
        {"authority_resolver": _COnlyAuthResolver(bad_value)},
        "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED",
    )


# ===========================================================================
# Exact Boolean verifier results (correction 5)
# ===========================================================================


class _TruthySupports:
    def supports(self, *, algorithm, verification_profile):
        return 1

    def verify(self, **kw):
        return True


class _TruthyVerify:
    def supports(self, *, algorithm, verification_profile):
        return True

    def verify(self, **kw):
        return "yes"


@pytest.mark.parametrize(
    "double,code",
    [
        (_TruthySupports(), "ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED"),
        (_TruthyVerify(), "ASSUMPTION_POLICY_SIGNATURE_INVALID"),
    ],
)
def test_truthy_non_bool_rejected(double, code) -> None:
    b = _bundle3()
    _assert_c_rejected(b, {"verifier": _COnlyVerifier(double)}, code)


# ===========================================================================
# Proof/entry denial translation (correction 8)
# ===========================================================================


def test_proof_build_failure_translated_to_denial(monkeypatch) -> None:
    b = _bundle3()

    def fail(**kw):
        raise AssumptionPolicyActivationContractError("TEST_PROOF_FAILURE")

    monkeypatch.setattr(AssumptionPolicyActivationProofV2, "build", fail)
    denied = _do_deny(b)
    assert denied.code == "TEST_PROOF_FAILURE"
    assert denied.stage == "ACTIVATION_PROOF_AND_ENTRY"
    assert isinstance(denied, AssumptionPolicyActivationDenied)


def test_entry_build_failure_translated_to_denial(monkeypatch) -> None:
    b = _bundle3()

    def fail(**kw):
        raise AssumptionPolicyActivationContractError("TEST_ENTRY_FAILURE")

    monkeypatch.setattr(AssumptionPolicyLedgerEntryV3, "build", fail)
    denied = _do_deny(b)
    assert denied.code == "TEST_ENTRY_FAILURE"
    assert denied.stage == "ACTIVATION_PROOF_AND_ENTRY"
    assert isinstance(denied, AssumptionPolicyActivationDenied)


# ===========================================================================
# V3 integration
# ===========================================================================


def test_proof_v2_binds_signing_payload_and_commit() -> None:
    prepared = _do_prepare(_bundle3())
    proof = prepared.ledger_entry.activation_proof
    payload = prepared.ledger_entry.signing_payload
    commit = prepared.ledger_entry.policy_commit
    assert proof.signing_payload_digest == payload.signing_payload_digest
    assert proof.policy_commit_receipt_digest == commit.commit_receipt_digest


def test_entry_v3_is_produced() -> None:
    prepared = _do_prepare(_bundle3())
    assert type(prepared.ledger_entry) is AssumptionPolicyLedgerEntryV3


def test_entry_v2_is_never_produced() -> None:
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
    )

    prepared = _do_prepare(_bundle3())
    assert not isinstance(prepared.ledger_entry, AssumptionPolicyLedgerEntryV2)


def test_preparer_has_no_store_or_publisher() -> None:
    prep = _bundle3()[7]
    assert not hasattr(prep, "store")
    assert not hasattr(prep, "publisher")
    assert not hasattr(prep, "ledger")


# ===========================================================================
# PreparedPolicyActivation compatibility (correction 9)
# ===========================================================================


def test_prepared_activation_build_accepts_entry_v3() -> None:
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    rebuilt = PreparedPolicyActivation.build(prepared.ledger_entry)
    assert rebuilt.prepared_digest == prepared.prepared_digest


def test_prepared_activation_build_accepts_entry_v2() -> None:
    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionPolicyActivationProof,
    )
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyLedgerEntryV2,
        PreparedPolicyActivation,
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
    assert PreparedPolicyActivation.build(e2).prepared_digest


def test_prepared_v3_digest_is_deterministic() -> None:
    a = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    b = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    assert a.prepared_digest == b.prepared_digest


def test_tampered_prepared_digest_rejects() -> None:
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = _do_prepare(_bundle3(signers=("authority:a", "authority:b")))
    with pytest.raises(AssumptionPolicyActivationContractError) as f:
        PreparedPolicyActivation(
            ledger_entry=prepared.ledger_entry,
            prepared_digest=_digest("f"),
        )
    assert f.value.code == "ASSUMPTION_POLICY_PREPARED_ACTIVATION_DIGEST_MISMATCH"


# ===========================================================================
# Deterministic verifier message-binding
# ===========================================================================


def test_changed_signed_digest_changes_bytes() -> None:
    a = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile=_VP,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    b = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile=_VP,
        public_key_bytes=b"pk",
        signed_digest=_digest("b"),
    )
    assert a != b


def test_changed_key_changes_bytes() -> None:
    a = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile=_VP,
        public_key_bytes=b"pk-a",
        signed_digest=_digest("a"),
    )
    b = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile=_VP,
        public_key_bytes=b"pk-b",
        signed_digest=_digest("a"),
    )
    assert a != b


def test_changed_algorithm_changes_bytes() -> None:
    a = deterministic_policy_signature_bytes(
        algorithm="ed25519",
        verification_profile=_VP,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    b = deterministic_policy_signature_bytes(
        algorithm="ecdsa-p256-sha256",
        verification_profile=_VP,
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert a != b


def test_changed_profile_changes_bytes() -> None:
    a = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile="ed25519-rfc8032-strict/1",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    b = deterministic_policy_signature_bytes(
        algorithm=_ALGO,
        verification_profile="ed25519-rfc8032-strict/2",
        public_key_bytes=b"pk",
        signed_digest=_digest("a"),
    )
    assert a != b
