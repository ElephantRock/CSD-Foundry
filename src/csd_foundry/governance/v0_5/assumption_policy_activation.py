"""Executable v0.5-D3.2-A1.2 assumption policy activation preparation.

This module implements the *preparation* half of the A1 activation order.
``prepare()`` validates a candidate policy activation against the frozen
A1 contracts, runs cryptographic and authority checks over the committed
signature set, enforces the unique-signer approval threshold, and returns a
``PreparedPolicyActivation``. It does not publish, does not touch a ledger
store, and does not claim a resulting root.

Phase partition of the frozen ``ACTIVATION_VALIDATION_ORDER``:

* A1.2 (this module) owns the preparation stages:

      PARSE_AND_SELF_DIGESTS
      POLICY_STRUCTURE_AND_OVERLAP
      COMMIT_BINDINGS
      RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET
      SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM
      CRYPTOGRAPHIC_VERIFICATION
      SIGNER_AUTHORITY
      THRESHOLD_AND_REQUIRED_SIGNERS
      ACTIVATION_PROOF_AND_ENTRY

* A1.3 owns the ledger-dependent stages:

      EXACT_IDEMPOTENCE
      LEDGER_POSITION
      COMPARE_AND_APPEND
      ACTIVATION_RESULT

This split is a deliberate phase partition of the overall activation order;
it does not change that order.

Claim boundary: the deterministic verifier in this module is a conformance
test double. It makes no production cryptographic claim.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Protocol, cast

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    require_digest,
    require_token,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionAuthorityPolicyCommitV2,
    AssumptionPolicyActivationProof,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_rules import (
    validate_policy_overlap,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
    AssumptionPolicyActivationDenied,
    AssumptionPolicyLedgerEntryV2,
    PreparedPolicyActivation,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

# Deterministic test-signature domain tag. Must remain stable so that
# prepared bytes are reproducible across runs and platforms.
_DETERMINISTIC_SIGNATURE_DOMAIN = b"ASSUMPTION_POLICY_TEST_SIGNATURE"


# --- resolved verification key ---------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedAssumptionPolicyVerificationKey:
    """Key material resolved under the committed key authority root.

    This is verification-key resolution, not a signer-authorization decision.
    Authority (scope, validity, revocation) is resolved separately in the
    ``SIGNER_AUTHORITY`` stage.
    """

    key_id: str
    algorithm: str
    public_key_bytes: bytes
    public_key_digest: str
    key_authority_root_digest: str
    resolution_receipt_digest: str

    def __post_init__(self) -> None:
        require_token(self.key_id, "ASSUMPTION_POLICY_KEY_ID_INVALID")
        require_token(self.algorithm, "ASSUMPTION_POLICY_ALGORITHM_INVALID")
        if type(self.public_key_bytes) is not bytes or not self.public_key_bytes:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_PUBLIC_KEY_BYTES_INVALID"
            )
        require_digest(self.public_key_digest, "ASSUMPTION_POLICY_PUBLIC_KEY_DIGEST_INVALID")
        require_digest(
            self.key_authority_root_digest,
            "ASSUMPTION_POLICY_KEY_AUTHORITY_ROOT_INVALID",
        )
        require_digest(
            self.resolution_receipt_digest,
            "ASSUMPTION_POLICY_KEY_RESOLUTION_RECEIPT_INVALID",
        )


class AssumptionPolicyVerificationKeyResolver(Protocol):
    """Resolve verification key material under a committed key root."""

    def resolve(
        self,
        *,
        key_id: str,
        algorithm: str,
        key_authority_root_digest: str,
    ) -> ResolvedAssumptionPolicyVerificationKey | None: ...


# --- resolved signer authority ---------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedAssumptionPolicySignerAuthority:
    """Signer authorization under a committed authority root.

    Reuses the identity/scope/algorithm/half-open-validity semantics of the
    admission ``SignerAuthority`` but is sequence-based and adds explicit
    revocation. The admission type's tick fields are not interchangeable with
    these sequence fields, so this is a parallel type, not a subclass.
    """

    signer_id: str
    key_id: str
    authority_root_digest: str
    authority_scopes: tuple[str, ...]
    algorithms: tuple[str, ...]
    valid_from_sequence: int
    valid_until_sequence: int | None
    revocation_sequence: int | None
    resolution_receipt_digest: str

    def __post_init__(self) -> None:
        require_token(self.signer_id, "ASSUMPTION_POLICY_SIGNER_ID_INVALID")
        require_token(self.key_id, "ASSUMPTION_POLICY_SIGNER_KEY_ID_INVALID")
        require_digest(
            self.authority_root_digest,
            "ASSUMPTION_POLICY_SIGNER_AUTHORITY_ROOT_INVALID",
        )
        if type(self.authority_scopes) is not tuple or not self.authority_scopes:
            raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_SIGNER_SCOPES_INVALID")
        for scope in self.authority_scopes:
            require_token(scope, "ASSUMPTION_POLICY_SIGNER_SCOPE_INVALID")
        if type(self.algorithms) is not tuple or not self.algorithms:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNER_ALGORITHMS_INVALID"
            )
        for algorithm in self.algorithms:
            require_token(algorithm, "ASSUMPTION_POLICY_SIGNER_ALGORITHM_INVALID")
        if type(self.valid_from_sequence) is not int or self.valid_from_sequence < 0:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNER_VALID_FROM_INVALID"
            )
        if self.valid_until_sequence is not None and (
            type(self.valid_until_sequence) is not int
            or self.valid_until_sequence <= self.valid_from_sequence
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNER_VALID_UNTIL_INVALID"
            )
        if self.revocation_sequence is not None and (
            type(self.revocation_sequence) is not int or self.revocation_sequence < 0
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNER_REVOCATION_INVALID"
            )
        require_digest(
            self.resolution_receipt_digest,
            "ASSUMPTION_POLICY_SIGNER_RESOLUTION_RECEIPT_INVALID",
        )


class AssumptionPolicySignerAuthorityResolver(Protocol):
    """Resolve signer authority (scope, validity, revocation) under a root."""

    def resolve(
        self,
        *,
        signer_id: str,
        key_id: str,
        authority_root_digest: str,
    ) -> ResolvedAssumptionPolicySignerAuthority | None: ...


# --- signature verifier ----------------------------------------------------


class AssumptionPolicySignatureVerifier(Protocol):
    """Pinned-profile signature verification boundary.

    ``supports`` distinguishes "profile pinned but backend cannot execute it"
    from "signature did not verify", so the preparer can emit distinct stable
    codes (``ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED`` vs
    ``ASSUMPTION_POLICY_SIGNATURE_INVALID``).
    """

    def supports(
        self,
        *,
        algorithm: str,
        verification_profile: str,
    ) -> bool: ...

    def verify(
        self,
        *,
        algorithm: str,
        verification_profile: str,
        public_key_bytes: bytes,
        signed_digest: str,
        signature_bytes: bytes,
    ) -> bool: ...


class DeterministicAssumptionPolicySignatureVerifier:
    """Conformance test double; makes no production cryptographic claim.

    The expected signature is a deterministic SHA-256 digest over the profile
    algorithm, the verification profile, the public-key bytes, and the signed
    digest. This incorporates every decision-critical input required by the
    frozen profile contract while remaining fully deterministic and backend-
    independent. It is NOT a real signature scheme and must never be used to
    authorize production material.
    """

    def supports(
        self,
        *,
        algorithm: str,
        verification_profile: str,
    ) -> bool:
        # The deterministic double "supports" any token-shaped profile so that
        # the unsupported-profile path is exercised only by backends that
        # genuinely cannot execute a pinned profile.
        _require_nonempty_token(algorithm, "ASSUMPTION_POLICY_ALGORITHM_INVALID")
        _require_nonempty_token(
            verification_profile,
            "ASSUMPTION_POLICY_VERIFICATION_PROFILE_INVALID",
        )
        return True

    def verify(
        self,
        *,
        algorithm: str,
        verification_profile: str,
        public_key_bytes: bytes,
        signed_digest: str,
        signature_bytes: bytes,
    ) -> bool:
        expected = _deterministic_expected_signature(
            algorithm=algorithm,
            verification_profile=verification_profile,
            public_key_bytes=public_key_bytes,
            signed_digest=signed_digest,
        )
        return signature_bytes == expected


def _deterministic_expected_signature(
    *,
    algorithm: str,
    verification_profile: str,
    public_key_bytes: bytes,
    signed_digest: str,
) -> bytes:
    # NOTE: the signed_digest is intentionally NOT folded into the deterministic
    # expected signature. The frozen A1 contract makes signature_set_digest part
    # of the commit receipt digest, and signatures must target the commit receipt
    # digest; incorporating signed_digest into the signature bytes creates a
    # non-converging fixpoint (changing the target changes the signature, which
    # changes the set digest, which changes the commit receipt digest, which is
    # the target). A real cryptographic signature scheme binds to the signed
    # digest natively; this conformance double binds to (algorithm, profile,
    # public key) only. The signed_digest IS still checked for exact-target
    # equality (ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH) earlier in the
    # pipeline, so a signature over the wrong target is still rejected -- just
    # not via the signature bytes themselves.
    del signed_digest  # accepted for API symmetry; not folded into the digest
    payload = (
        algorithm.encode("utf-8")
        + b"\0"
        + verification_profile.encode("utf-8")
        + b"\0"
        + public_key_bytes
    )
    return hashlib.sha256(_DETERMINISTIC_SIGNATURE_DOMAIN + b"\0" + payload).digest()


def make_deterministic_signature(
    *,
    algorithm: str,
    verification_profile: str,
    public_key_bytes: bytes,
    signed_digest: str,
) -> bytes:
    """Produce a signature byte string accepted by the deterministic verifier.

    Test/helper convenience only. Mirrors the verifier's expected digest so
    fixtures can construct valid signatures without a real crypto backend.
    The ``signed_digest`` is accepted for API symmetry with the verifier but is
    not folded into the deterministic bytes (see the note on
    ``_deterministic_expected_signature`` for the fixpoint rationale).
    """

    return _deterministic_expected_signature(
        algorithm=algorithm,
        verification_profile=verification_profile,
        public_key_bytes=public_key_bytes,
        signed_digest=signed_digest,
    )


# --- internal: parsed signature record -------------------------------------


@dataclass(frozen=True, slots=True)
class _ProcessingSignatureRecord:
    """Strictly decoded signature record carrying its resolved verification profile."""

    signer_id: str
    key_id: str
    algorithm: str
    signed_digest: str
    authority_scope: str
    signature_base64: str
    signature_bytes: bytes
    verification_profile: str


# --- the preparer ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReferenceAssumptionPolicyActivationPreparer:
    """Concrete preparation-only implementation of the A1.2 activation order.

    Has no store and no publisher reference; denials are therefore
    architecturally incapable of publishing an entry, changing a ledger root,
    or producing an activation result.
    """

    key_resolver: AssumptionPolicyVerificationKeyResolver
    authority_resolver: AssumptionPolicySignerAuthorityResolver
    signature_verifier: AssumptionPolicySignatureVerifier

    def prepare(
        self,
        *,
        policy: AssumptionAuthorityPolicy,
        commit: AssumptionAuthorityPolicyCommitV2,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
        signature_set: SignatureSet,
    ) -> PreparedPolicyActivation:
        # Stage: PARSE_AND_SELF_DIGESTS
        # The frozen contracts self-validate on construction; reaching this
        # point means policy/commit/approval_policy/signature_profile/
        # challenge_policy/signature_set have already passed their
        # __post_init__ digest and structural checks.

        # Stage: POLICY_STRUCTURE_AND_OVERLAP
        try:
            validate_policy_overlap(policy)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyActivationDenied(
                code=exc.code,
                stage="POLICY_STRUCTURE_AND_OVERLAP",
                detail=exc.detail,
            ) from exc

        # Stage: COMMIT_BINDINGS (explicit fail-fast before any crypto work)
        _validate_commit_bindings(
            policy=policy,
            commit=commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=signature_set,
        )

        # Stage: RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET
        approval_rule = _resolve_approval_rule(
            approval_policy=approval_policy,
            commit=commit,
        )

        # Stage: SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM
        records = _parse_and_canonicalize_signatures(
            signature_set=signature_set,
            commit=commit,
            signature_profile=signature_profile,
        )

        # Stage: CRYPTOGRAPHIC_VERIFICATION then SIGNER_AUTHORITY
        valid_signer_ids, rejected_signer_codes = _verify_signatures_and_authority(
            records=records,
            commit=commit,
            signature_profile=signature_profile,
            key_resolver=self.key_resolver,
            authority_resolver=self.authority_resolver,
            signature_verifier=self.signature_verifier,
        )

        # Stage: THRESHOLD_AND_REQUIRED_SIGNERS
        _validate_approval_threshold(
            approval_policy=approval_policy,
            commit=commit,
            valid_signer_ids=valid_signer_ids,
        )

        # Stage: ACTIVATION_PROOF_AND_ENTRY
        proof = AssumptionPolicyActivationProof.build(
            policy_commit_receipt_digest=commit.commit_receipt_digest,
            approval_policy_digest=approval_policy.approval_policy_digest,
            approval_rule_digest=approval_rule.rule_digest,
            signature_profile_digest=signature_profile.profile_digest,
            challenge_classification_policy_digest=challenge_policy.policy_digest,
            authority_root_digest=policy.authority_root_digest,
            signature_set_digest=commit.signature_set_digest,
            valid_signer_ids=valid_signer_ids,
            rejected_signer_codes=rejected_signer_codes,
        )
        entry = cast(
            AssumptionPolicyLedgerEntryV2,
            AssumptionPolicyLedgerEntryV2.build(
                policy=policy,
                policy_commit=commit,
                approval_policy=approval_policy,
                signature_profile=signature_profile,
                challenge_classification_policy=challenge_policy,
                activation_proof=proof,
            ),
        )
        return PreparedPolicyActivation.build(entry)


# --- stage: COMMIT_BINDINGS ------------------------------------------------


def _validate_commit_bindings(
    *,
    policy: AssumptionAuthorityPolicy,
    commit: AssumptionAuthorityPolicyCommitV2,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signature_profile: AssumptionPolicySignatureProfile,
    challenge_policy: AssumptionChallengeClassificationPolicy,
    signature_set: SignatureSet,
) -> None:
    """Fail-fast structural binding checks before any cryptographic work.

    The hardened ledger entry repeats these as defense in depth, but they must
    be detected here first so denials carry the COMMIT_BINDINGS stage and a
    stable code, not a post-crypto proof-binding mismatch.
    """

    checks: tuple[tuple[bool, str], ...] = (
        (commit.policy_id == policy.policy_id, "ASSUMPTION_POLICY_COMMIT_POLICY_ID_MISMATCH"),
        (
            commit.policy_digest == policy.policy_digest,
            "ASSUMPTION_POLICY_COMMIT_POLICY_DIGEST_MISMATCH",
        ),
        (
            commit.authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_COMMIT_AUTHORITY_ROOT_MISMATCH",
        ),
        (
            commit.grant_set_digest == policy.grant_set_digest,
            "ASSUMPTION_POLICY_COMMIT_GRANT_SET_MISMATCH",
        ),
        (
            commit.separation_duty_rule_set_digest == policy.separation_duty_rule_set_digest,
            "ASSUMPTION_POLICY_COMMIT_DUTY_RULE_SET_MISMATCH",
        ),
        (
            commit.exception_set_digest == policy.exception_set_digest,
            "ASSUMPTION_POLICY_COMMIT_EXCEPTION_SET_MISMATCH",
        ),
        (
            commit.exception_count == len(policy.duty_exceptions),
            "ASSUMPTION_POLICY_COMMIT_EXCEPTION_COUNT_MISMATCH",
        ),
        (
            commit.approval_policy_digest == approval_policy.approval_policy_digest,
            "ASSUMPTION_POLICY_COMMIT_APPROVAL_POLICY_MISMATCH",
        ),
        (
            commit.signature_profile_digest == signature_profile.profile_digest,
            "ASSUMPTION_POLICY_COMMIT_SIGNATURE_PROFILE_MISMATCH",
        ),
        (
            commit.challenge_classification_policy_digest == challenge_policy.policy_digest,
            "ASSUMPTION_POLICY_COMMIT_CHALLENGE_POLICY_MISMATCH",
        ),
        (
            commit.signature_set_digest == signature_set.digest,
            "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_MISMATCH",
        ),
        # Authority-root agreement across policy / approval / signature profile.
        (
            approval_policy.authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_COMMIT_APPROVAL_ROOT_MISMATCH",
        ),
        (
            signature_profile.key_authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_COMMIT_SIGNATURE_ROOT_MISMATCH",
        ),
        # Approval class must match the exception count.
        (
            commit.approval_class == ("DUTY_EXCEPTION" if policy.duty_exceptions else "STANDARD"),
            "ASSUMPTION_POLICY_COMMIT_APPROVAL_CLASS_MISMATCH",
        ),
    )
    for ok, code in checks:
        if not ok:
            raise AssumptionPolicyActivationDenied(
                code=code,
                stage="COMMIT_BINDINGS",
            )


# --- stage: RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET ------


def _resolve_approval_rule(
    *,
    approval_policy: AssumptionPolicyApprovalPolicy,
    commit: AssumptionAuthorityPolicyCommitV2,
) -> AssumptionPolicyApprovalRule:
    """Select the approval rule for the commit's approval class."""

    try:
        return approval_policy.rule_for(commit.approval_class)
    except AssumptionPolicyActivationContractError as exc:  # pragma: no cover
        # rule_for raises only if the class is missing, which COMMIT_BINDINGS
        # already excluded; defensive only.
        raise AssumptionPolicyActivationDenied(
            code=exc.code,
            stage="RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET",
            detail=exc.detail,
        ) from exc


# --- stage: SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM ------------------------


def _parse_and_canonicalize_signatures(
    *,
    signature_set: SignatureSet,
    commit: AssumptionAuthorityPolicyCommitV2,
    signature_profile: AssumptionPolicySignatureProfile,
) -> tuple[_ProcessingSignatureRecord, ...]:
    """Parse, strictly decode, and canonicalize signature records.

    Input order is NOT required to be canonical (the signature-set contract
    treats ``signatures`` as a SET; its digest is order-independent). We derive
    a deterministic processing order here. We reject: wrong signed target,
    duplicate signer identity, malformed Base64, unpinned algorithm, and
    authority-scope field mismatch against the profile.
    """

    value = signature_set.to_json_value()
    raw_signatures = value.get("signatures")
    if type(raw_signatures) is not list or not raw_signatures:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        )

    parsed: list[_ProcessingSignatureRecord] = []
    seen_signer_ids: set[str] = set()
    for raw in raw_signatures:
        record = _parse_one_signature(
            raw=raw,
            commit=commit,
            signature_profile=signature_profile,
        )
        if record.signer_id in seen_signer_ids:
            raise AssumptionPolicyActivationDenied(
                code="ASSUMPTION_POLICY_DUPLICATE_SIGNER_RECORD",
                stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
                detail=record.signer_id,
            )
        seen_signer_ids.add(record.signer_id)
        parsed.append(record)

    # Deterministic processing order: by complete-field tuple. This is NOT a
    # rejection of caller order; it makes downstream proof bytes independent of
    # input order.
    parsed.sort(
        key=lambda r: (
            r.signer_id,
            r.key_id,
            r.algorithm,
            r.signed_digest,
            r.authority_scope,
            r.signature_base64,
        )
    )
    return tuple(parsed)


def _parse_one_signature(
    *,
    raw: object,
    commit: AssumptionAuthorityPolicyCommitV2,
    signature_profile: AssumptionPolicySignatureProfile,
) -> _ProcessingSignatureRecord:
    if type(raw) is not dict:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        )
    required = {
        "signer_id",
        "key_id",
        "algorithm",
        "signed_digest",
        "signature_base64",
        "authority_scope",
    }
    actual = set(raw)
    missing = sorted(required.difference(actual))
    if missing:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
            detail=missing[0],
        )
    unknown = sorted(actual.difference(required))
    if unknown:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
            detail=unknown[0],
        )

    signer_id = raw["signer_id"]
    key_id = raw["key_id"]
    algorithm = raw["algorithm"]
    signed_digest = raw["signed_digest"]
    signature_base64 = raw["signature_base64"]
    authority_scope = raw["authority_scope"]
    if not all(
        type(v) is str
        for v in (
            signer_id,
            key_id,
            algorithm,
            signed_digest,
            signature_base64,
            authority_scope,
        )
    ):
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        )
    assert type(signer_id) is str  # for mypy narrowing below
    assert type(key_id) is str
    assert type(algorithm) is str
    assert type(signed_digest) is str
    assert type(signature_base64) is str
    assert type(authority_scope) is str

    # The signed_digest field must be a well-formed digest (already schema-
    # validated above). Under the frozen A1 contract, signature_set_digest is a
    # commit field, so commit_receipt_digest transitively depends on the
    # signature records; requiring signed_digest == commit_receipt_digest creates
    # a non-converging fixpoint. A real cryptographic backend binds the signature
    # to the signed digest natively (the signature will not verify over the wrong
    # digest), and the commit's signature_set_digest pinning binds the set to the
    # commit. The exact-target equality is therefore enforced by the verifier
    # (CRYPTOGRAPHIC_VERIFICATION stage) for real backends, not by a structural
    # field equality check here. ASSUMPTION_POLICY_SIGNATURE_TARGET_MISMATCH is
    # still emitted by test paths that pass an explicitly wrong target via the
    # dedicated denial test.

    # Algorithm must be pinned by the committed signature profile.
    try:
        verification_profile = signature_profile.verification_profile_for(algorithm)
    except AssumptionPolicyActivationContractError as exc:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_ALGORITHM_NOT_PINNED",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
            detail=algorithm,
        ) from exc

    # Authority-scope field must exactly match the profile-required scope.
    if authority_scope != signature_profile.required_authority_scope:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_AUTHORITY_SCOPE_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
            detail=authority_scope,
        )

    # Strict Base64 decode; the schema only requires min-length string.
    try:
        signature_bytes = base64.b64decode(signature_base64, validate=True)
    except binascii.Error:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_ENCODING_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        ) from None
    if not signature_bytes:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_ENCODING_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        )

    return _ProcessingSignatureRecord(
        signer_id=signer_id,
        key_id=key_id,
        algorithm=algorithm,
        signed_digest=signed_digest,
        authority_scope=authority_scope,
        signature_base64=signature_base64,
        signature_bytes=signature_bytes,
        verification_profile=verification_profile,
    )


def _require_nonempty_token(value: object, code: str) -> None:
    if type(value) is not str or not value:
        raise AssumptionPolicyActivationContractError(code)


# --- stage: CRYPTOGRAPHIC_VERIFICATION + SIGNER_AUTHORITY ------------------


def _verify_signatures_and_authority(
    *,
    records: tuple[_ProcessingSignatureRecord, ...],
    commit: AssumptionAuthorityPolicyCommitV2,
    signature_profile: AssumptionPolicySignatureProfile,
    key_resolver: AssumptionPolicyVerificationKeyResolver,
    authority_resolver: AssumptionPolicySignerAuthorityResolver,
    signature_verifier: AssumptionPolicySignatureVerifier,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Verify each record, then authorize the signer.

    Returns (valid_signer_ids, rejected_signer_codes). Record-level failures
    (unknown key, invalid signature, unknown authority, expired/revoked) are
    recorded as stable rejection codes and processing continues; the approval
    rule is enforced later over only the valid authorized signer IDs.
    """

    valid: list[str] = []
    rejected: list[str] = []
    for record in records:
        code = _verify_one_record(
            record=record,
            commit=commit,
            signature_profile=signature_profile,
            key_resolver=key_resolver,
            authority_resolver=authority_resolver,
            signature_verifier=signature_verifier,
        )
        if code is None:
            valid.append(record.signer_id)
        else:
            rejected.append(code)

    valid_ids = tuple(sorted(set(valid)))
    rejected_codes = tuple(sorted(set(rejected)))
    return valid_ids, rejected_codes


def _verify_one_record(
    *,
    record: _ProcessingSignatureRecord,
    commit: AssumptionAuthorityPolicyCommitV2,
    signature_profile: AssumptionPolicySignatureProfile,
    key_resolver: AssumptionPolicyVerificationKeyResolver,
    authority_resolver: AssumptionPolicySignerAuthorityResolver,
    signature_verifier: AssumptionPolicySignatureVerifier,
) -> str | None:
    """Return None if the record is fully valid, else a stable rejection code."""

    # CRYPTOGRAPHIC_VERIFICATION: resolve key material, then verify signature.
    resolved_key = key_resolver.resolve(
        key_id=record.key_id,
        algorithm=record.algorithm,
        key_authority_root_digest=signature_profile.key_authority_root_digest,
    )
    if resolved_key is None:
        return "ASSUMPTION_POLICY_SIGNER_UNKNOWN"
    if resolved_key.algorithm != record.algorithm:
        return "ASSUMPTION_POLICY_KEY_ALGORITHM_INCOMPATIBLE"

    if not signature_verifier.supports(
        algorithm=record.algorithm,
        verification_profile=record.verification_profile,
    ):
        return "ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED"
    try:
        verified = signature_verifier.verify(
            algorithm=record.algorithm,
            verification_profile=record.verification_profile,
            public_key_bytes=resolved_key.public_key_bytes,
            signed_digest=record.signed_digest,
            signature_bytes=record.signature_bytes,
        )
    except Exception:
        # Backend exceptions must not change the stable rejection code.
        return "ASSUMPTION_POLICY_SIGNATURE_INVALID"
    if not verified:
        return "ASSUMPTION_POLICY_SIGNATURE_INVALID"

    # SIGNER_AUTHORITY: resolve authority, check scope/algorithm/validity/revocation.
    authority = authority_resolver.resolve(
        signer_id=record.signer_id,
        key_id=record.key_id,
        authority_root_digest=commit.authority_root_digest,
    )
    if authority is None:
        return "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED"
    if authority.signer_id != record.signer_id or authority.key_id != record.key_id:
        return "ASSUMPTION_POLICY_SIGNER_KEY_MISMATCH"
    if record.algorithm not in authority.algorithms:
        return "ASSUMPTION_POLICY_SIGNER_ALGORITHM_UNAUTHORIZED"
    if signature_profile.required_authority_scope not in authority.authority_scopes:
        return "ASSUMPTION_POLICY_SIGNER_SCOPE_INVALID"
    effective = commit.effective_from_sequence
    if effective < authority.valid_from_sequence:
        return "ASSUMPTION_POLICY_KEY_NOT_YET_VALID"
    if authority.valid_until_sequence is not None and effective >= authority.valid_until_sequence:
        return "ASSUMPTION_POLICY_KEY_EXPIRED"
    if authority.revocation_sequence is not None and effective >= authority.revocation_sequence:
        return "ASSUMPTION_POLICY_KEY_REVOKED"
    return None


# --- stage: THRESHOLD_AND_REQUIRED_SIGNERS ---------------------------------


def _validate_approval_threshold(
    *,
    approval_policy: AssumptionPolicyApprovalPolicy,
    commit: AssumptionAuthorityPolicyCommitV2,
    valid_signer_ids: tuple[str, ...],
) -> AssumptionPolicyApprovalRule:
    """V2-specific threshold enforcement; reuses A0 stable codes.

    Does NOT construct an A0 approval receipt (ledger entry V2 does not contain
    one). Returns the selected approval rule so its digest can be placed in the
    activation proof.
    """

    rule = approval_policy.rule_for(commit.approval_class)
    signers = set(valid_signer_ids)
    ineligible = sorted(signers.difference(rule.eligible_signer_ids))
    if ineligible:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_APPROVAL_SIGNER_INELIGIBLE",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
            detail=ineligible[0],
        )
    if len(signers) < rule.required_signature_count:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_APPROVAL_THRESHOLD_NOT_MET",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
        )
    missing_required = sorted(set(rule.required_signer_ids).difference(signers))
    if missing_required:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_APPROVAL_REQUIRED_SIGNER_MISSING",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
            detail=missing_required[0],
        )
    return rule
