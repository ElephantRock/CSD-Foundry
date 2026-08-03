"""Executable v0.5-D3.2-A1.2 assumption policy activation preparation.

Implements the preparation half of the A1 activation order against the
non-circular V3 signing envelope. ``prepare()`` validates a candidate policy
activation, runs cryptographic and authority checks over the committed
signature set targeting ``signing_payload_digest``, enforces the unique-signer
approval threshold, and returns a ``PreparedPolicyActivation`` carrying a
validated ``AssumptionPolicyLedgerEntryV3``.

It does not publish, does not touch a ledger store, and does not claim a
resulting root.

Phase partition of the frozen ``ACTIVATION_VALIDATION_ORDER``:

* A1.2 (this module) owns the preparation stages.
* A1.3 owns the ledger-dependent stages (idempotence, ledger position,
  compare-and-append, activation result).

Claim boundary: the deterministic verifier is a conformance test double. It
makes no production cryptographic claim.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Protocol

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    require_digest,
    require_token,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicySigningPayload,
    deterministic_policy_signature_bytes,
    require_activatable_policy_commit,
    require_policy_signature_target,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_rules import (
    validate_policy_overlap,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionGovernanceExecutionContractError,
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
    AssumptionPolicyActivationDenied,
    PreparedPolicyActivation,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

# --- resolved verification key ---------------------------------------------


@dataclass(frozen=True, slots=True)
class ResolvedAssumptionPolicyVerificationKey:
    """Key material resolved under the committed key authority root."""

    key_id: str
    algorithm: str
    public_key_bytes: bytes
    key_authority_root_digest: str
    resolution_receipt_digest: str

    def __post_init__(self) -> None:
        require_token(self.key_id, "ASSUMPTION_POLICY_KEY_ID_INVALID")
        require_token(self.algorithm, "ASSUMPTION_POLICY_ALGORITHM_INVALID")
        if type(self.public_key_bytes) is not bytes or not self.public_key_bytes:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_PUBLIC_KEY_BYTES_INVALID"
            )
        require_digest(
            self.key_authority_root_digest,
            "ASSUMPTION_POLICY_KEY_AUTHORITY_ROOT_INVALID",
        )
        require_digest(
            self.resolution_receipt_digest,
            "ASSUMPTION_POLICY_KEY_RESOLUTION_RECEIPT_INVALID",
        )


class AssumptionPolicyVerificationKeyResolver(Protocol):
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
    """Signer authorization under a committed authority root."""

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
    def resolve(
        self,
        *,
        signer_id: str,
        key_id: str,
        authority_root_digest: str,
    ) -> ResolvedAssumptionPolicySignerAuthority | None: ...


# --- signature verifier ----------------------------------------------------


class AssumptionPolicySignatureVerifier(Protocol):
    """Pinned-profile signature verification boundary."""

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

    Uses the merged ``deterministic_policy_signature_bytes`` helper which
    commits to algorithm, verification_profile, public_key_bytes, AND
    signed_digest. Changing only signed_digest changes the expected bytes.
    """

    def supports(
        self,
        *,
        algorithm: str,
        verification_profile: str,
    ) -> bool:
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
        expected = deterministic_policy_signature_bytes(
            algorithm=algorithm,
            verification_profile=verification_profile,
            public_key_bytes=public_key_bytes,
            signed_digest=signed_digest,
        )
        return signature_bytes == expected


def make_deterministic_signature(
    *,
    algorithm: str,
    verification_profile: str,
    public_key_bytes: bytes,
    signed_digest: str,
) -> bytes:
    """Produce signature bytes accepted by the deterministic verifier."""

    return deterministic_policy_signature_bytes(
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
        signing_payload: AssumptionPolicySigningPayload,
        commit: AssumptionAuthorityPolicyCommitV3,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
        signature_set: SignatureSet,
    ) -> PreparedPolicyActivation:
        # Stage: PARSE_AND_SELF_DIGESTS + executable version gate
        try:
            commit = require_activatable_policy_commit(commit)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyActivationDenied(
                code=exc.code,
                stage="PARSE_AND_SELF_DIGESTS",
            ) from exc

        # Stage: POLICY_STRUCTURE_AND_OVERLAP
        try:
            validate_policy_overlap(policy)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyActivationDenied(
                code=exc.code,
                stage="POLICY_STRUCTURE_AND_OVERLAP",
                detail=exc.detail,
            ) from exc

        # Stage: COMMIT_BINDINGS (V3 envelope, fail-fast before crypto)
        _validate_v3_envelope_bindings(
            policy=policy,
            signing_payload=signing_payload,
            commit=commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=signature_set,
        )

        # Stage: RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET
        approval_rule = _resolve_approval_rule(
            approval_policy=approval_policy,
            signing_payload=signing_payload,
        )

        # Stage: SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM
        records = _parse_and_canonicalize_signatures(
            signature_set=signature_set,
            signing_payload=signing_payload,
            signature_profile=signature_profile,
        )

        # Stage: CRYPTOGRAPHIC_VERIFICATION + SIGNER_AUTHORITY
        valid_signer_ids, rejected_signer_codes = _verify_signatures_and_authority(
            records=records,
            signing_payload=signing_payload,
            signature_profile=signature_profile,
            key_resolver=self.key_resolver,
            authority_resolver=self.authority_resolver,
            signature_verifier=self.signature_verifier,
        )

        # Stage: THRESHOLD_AND_REQUIRED_SIGNERS
        _validate_approval_threshold(
            approval_policy=approval_policy,
            signing_payload=signing_payload,
            valid_signer_ids=valid_signer_ids,
        )

        # Stage: ACTIVATION_PROOF_AND_ENTRY
        try:
            proof = AssumptionPolicyActivationProofV2.build(
                signing_payload_digest=signing_payload.signing_payload_digest,
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
            entry = AssumptionPolicyLedgerEntryV3.build(
                policy=policy,
                signing_payload=signing_payload,
                policy_commit=commit,
                approval_policy=approval_policy,
                signature_profile=signature_profile,
                challenge_classification_policy=challenge_policy,
                activation_proof=proof,
            )
            return PreparedPolicyActivation.build(entry)
        except AssumptionPolicyActivationDenied:
            raise
        except (
            AssumptionPolicyActivationContractError,
            AssumptionGovernanceExecutionContractError,
        ) as exc:
            raise AssumptionPolicyActivationDenied(
                code=exc.code,
                stage="ACTIVATION_PROOF_AND_ENTRY",
                detail=exc.detail,
            ) from exc


# --- stage helpers ---------------------------------------------------------


def _validate_v3_envelope_bindings(
    *,
    policy: AssumptionAuthorityPolicy,
    signing_payload: AssumptionPolicySigningPayload,
    commit: AssumptionAuthorityPolicyCommitV3,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signature_profile: AssumptionPolicySignatureProfile,
    challenge_policy: AssumptionChallengeClassificationPolicy,
    signature_set: SignatureSet,
) -> None:
    checks: tuple[tuple[bool, str], ...] = (
        (
            signing_payload.policy_id == policy.policy_id,
            "ASSUMPTION_POLICY_PAYLOAD_POLICY_ID_MISMATCH",
        ),
        (
            signing_payload.policy_digest == policy.policy_digest,
            "ASSUMPTION_POLICY_PAYLOAD_POLICY_DIGEST_MISMATCH",
        ),
        (
            signing_payload.authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_PAYLOAD_AUTHORITY_ROOT_MISMATCH",
        ),
        (
            signing_payload.grant_set_digest == policy.grant_set_digest,
            "ASSUMPTION_POLICY_PAYLOAD_GRANT_SET_MISMATCH",
        ),
        (
            signing_payload.separation_duty_rule_set_digest
            == policy.separation_duty_rule_set_digest,
            "ASSUMPTION_POLICY_PAYLOAD_DUTY_RULE_SET_MISMATCH",
        ),
        (
            signing_payload.exception_set_digest == policy.exception_set_digest,
            "ASSUMPTION_POLICY_PAYLOAD_EXCEPTION_SET_MISMATCH",
        ),
        (
            signing_payload.exception_count == len(policy.duty_exceptions),
            "ASSUMPTION_POLICY_PAYLOAD_EXCEPTION_COUNT_MISMATCH",
        ),
        (
            signing_payload.approval_policy_digest == approval_policy.approval_policy_digest,
            "ASSUMPTION_POLICY_PAYLOAD_APPROVAL_POLICY_MISMATCH",
        ),
        (
            signing_payload.signature_profile_digest == signature_profile.profile_digest,
            "ASSUMPTION_POLICY_PAYLOAD_SIGNATURE_PROFILE_MISMATCH",
        ),
        (
            signing_payload.challenge_classification_policy_digest
            == challenge_policy.policy_digest,
            "ASSUMPTION_POLICY_PAYLOAD_CHALLENGE_POLICY_MISMATCH",
        ),
        (
            approval_policy.authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_PAYLOAD_APPROVAL_ROOT_MISMATCH",
        ),
        (
            signature_profile.key_authority_root_digest == policy.authority_root_digest,
            "ASSUMPTION_POLICY_PAYLOAD_SIGNATURE_ROOT_MISMATCH",
        ),
        (
            commit.signing_payload_digest == signing_payload.signing_payload_digest,
            "ASSUMPTION_POLICY_COMMIT_PAYLOAD_MISMATCH",
        ),
        (
            commit.signature_set_digest == signature_set.digest,
            "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_MISMATCH",
        ),
    )
    for ok, code in checks:
        if not ok:
            raise AssumptionPolicyActivationDenied(
                code=code,
                stage="COMMIT_BINDINGS",
            )


def _resolve_approval_rule(
    *,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signing_payload: AssumptionPolicySigningPayload,
) -> AssumptionPolicyApprovalRule:
    try:
        return approval_policy.rule_for(signing_payload.approval_class)
    except (
        AssumptionPolicyActivationContractError,
        AssumptionGovernanceExecutionContractError,
    ) as exc:
        raise AssumptionPolicyActivationDenied(
            code=exc.code,
            stage="RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET",
            detail=exc.detail,
        ) from exc


def _parse_and_canonicalize_signatures(
    *,
    signature_set: SignatureSet,
    signing_payload: AssumptionPolicySigningPayload,
    signature_profile: AssumptionPolicySignatureProfile,
) -> tuple[_ProcessingSignatureRecord, ...]:
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
            signing_payload=signing_payload,
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
    signing_payload: AssumptionPolicySigningPayload,
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
        for v in (signer_id, key_id, algorithm, signed_digest, signature_base64, authority_scope)
    ):
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_POLICY_SIGNATURE_SET_INVALID",
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        )
    assert type(signer_id) is str
    assert type(key_id) is str
    assert type(algorithm) is str
    assert type(signed_digest) is str
    assert type(signature_base64) is str
    assert type(authority_scope) is str

    # Exact signed target: must be signing_payload_digest.
    try:
        require_policy_signature_target(
            signed_digest=signed_digest,
            signing_payload_digest=signing_payload.signing_payload_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise AssumptionPolicyActivationDenied(
            code=exc.code,
            stage="SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
        ) from exc

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

    # Strict Base64 decode.
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


def _verify_signatures_and_authority(
    *,
    records: tuple[_ProcessingSignatureRecord, ...],
    signing_payload: AssumptionPolicySigningPayload,
    signature_profile: AssumptionPolicySignatureProfile,
    key_resolver: AssumptionPolicyVerificationKeyResolver,
    authority_resolver: AssumptionPolicySignerAuthorityResolver,
    signature_verifier: AssumptionPolicySignatureVerifier,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    valid: list[str] = []
    rejected: list[str] = []
    for record in records:
        code = _verify_one_record(
            record=record,
            signing_payload=signing_payload,
            signature_profile=signature_profile,
            key_resolver=key_resolver,
            authority_resolver=authority_resolver,
            signature_verifier=signature_verifier,
        )
        if code is None:
            valid.append(record.signer_id)
        else:
            rejected.append(code)
    return tuple(sorted(set(valid))), tuple(sorted(set(rejected)))


def _verify_one_record(
    *,
    record: _ProcessingSignatureRecord,
    signing_payload: AssumptionPolicySigningPayload,
    signature_profile: AssumptionPolicySignatureProfile,
    key_resolver: AssumptionPolicyVerificationKeyResolver,
    authority_resolver: AssumptionPolicySignerAuthorityResolver,
    signature_verifier: AssumptionPolicySignatureVerifier,
) -> str | None:
    # CRYPTOGRAPHIC_VERIFICATION: resolve key material, type-check, revalidate, then verify.
    try:
        resolved_key = key_resolver.resolve(
            key_id=record.key_id,
            algorithm=record.algorithm,
            key_authority_root_digest=signature_profile.key_authority_root_digest,
        )
    except Exception:
        return "ASSUMPTION_POLICY_SIGNER_UNKNOWN"
    if resolved_key is None:
        return "ASSUMPTION_POLICY_SIGNER_UNKNOWN"
    if type(resolved_key) is not ResolvedAssumptionPolicyVerificationKey:
        return "ASSUMPTION_POLICY_SIGNER_UNKNOWN"
    # Revalidate resolver output against the request parameters.
    if resolved_key.key_id != record.key_id:
        return "ASSUMPTION_POLICY_KEY_ID_MISMATCH"
    if resolved_key.algorithm != record.algorithm:
        return "ASSUMPTION_POLICY_KEY_ALGORITHM_INCOMPATIBLE"
    if resolved_key.key_authority_root_digest != signature_profile.key_authority_root_digest:
        return "ASSUMPTION_POLICY_KEY_AUTHORITY_ROOT_MISMATCH"

    try:
        supported = signature_verifier.supports(
            algorithm=record.algorithm,
            verification_profile=record.verification_profile,
        )
    except Exception:
        return "ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED"
    if type(supported) is not bool or supported is not True:
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
        return "ASSUMPTION_POLICY_SIGNATURE_INVALID"
    if type(verified) is not bool or verified is not True:
        return "ASSUMPTION_POLICY_SIGNATURE_INVALID"

    # SIGNER_AUTHORITY: resolve authority, type-check, revalidate,
    # check scope/algorithm/validity/revocation.
    try:
        authority = authority_resolver.resolve(
            signer_id=record.signer_id,
            key_id=record.key_id,
            authority_root_digest=signing_payload.authority_root_digest,
        )
    except Exception:
        return "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED"
    if authority is None:
        return "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED"
    if type(authority) is not ResolvedAssumptionPolicySignerAuthority:
        return "ASSUMPTION_POLICY_SIGNER_UNAUTHORIZED"
    # Revalidate resolver output against the request parameters.
    if authority.signer_id != record.signer_id or authority.key_id != record.key_id:
        return "ASSUMPTION_POLICY_SIGNER_KEY_MISMATCH"
    if authority.authority_root_digest != signing_payload.authority_root_digest:
        return "ASSUMPTION_POLICY_SIGNER_AUTHORITY_ROOT_MISMATCH"
    if record.algorithm not in authority.algorithms:
        return "ASSUMPTION_POLICY_SIGNER_ALGORITHM_UNAUTHORIZED"
    if signature_profile.required_authority_scope not in authority.authority_scopes:
        return "ASSUMPTION_POLICY_SIGNER_SCOPE_INVALID"
    effective = signing_payload.effective_from_sequence
    if effective < authority.valid_from_sequence:
        return "ASSUMPTION_POLICY_KEY_NOT_YET_VALID"
    if authority.valid_until_sequence is not None and effective >= authority.valid_until_sequence:
        return "ASSUMPTION_POLICY_KEY_EXPIRED"
    if authority.revocation_sequence is not None and effective >= authority.revocation_sequence:
        return "ASSUMPTION_POLICY_KEY_REVOKED"
    return None


def _validate_approval_threshold(
    *,
    approval_policy: AssumptionPolicyApprovalPolicy,
    signing_payload: AssumptionPolicySigningPayload,
    valid_signer_ids: tuple[str, ...],
) -> None:
    try:
        rule = approval_policy.rule_for(signing_payload.approval_class)
    except AssumptionGovernanceExecutionContractError as exc:
        raise AssumptionPolicyActivationDenied(
            code=exc.code,
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
            detail=exc.detail,
        ) from exc
    signers = set(valid_signer_ids)
    ineligible = sorted(signers.difference(rule.eligible_signer_ids))
    if ineligible:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
            detail=ineligible[0],
        )
    if len(signers) < rule.required_signature_count:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
        )
    missing_required = sorted(set(rule.required_signer_ids).difference(signers))
    if missing_required:
        raise AssumptionPolicyActivationDenied(
            code="ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING",
            stage="THRESHOLD_AND_REQUIRED_SIGNERS",
            detail=missing_required[0],
        )


def _require_nonempty_token(value: object, code: str) -> None:
    if type(value) is not str or not value:
        raise AssumptionPolicyActivationContractError(code)
