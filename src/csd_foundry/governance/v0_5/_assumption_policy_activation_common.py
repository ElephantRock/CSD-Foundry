"""Common frozen contracts for v0.5-D3.2-A1 activation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

SIGNATURE_PROFILE_SCHEMA_VERSION = "assumption-policy-signature-profile/1"
CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION = (
    "assumption-challenge-classification-policy/1"
)
AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION = "assumption-authority-policy-commit/2"
ACTIVATION_PROOF_SCHEMA_VERSION = "assumption-policy-activation-proof/1"
POLICY_LEDGER_ENTRY_V2_SCHEMA_VERSION = "assumption-policy-ledger-entry/2"
POLICY_LEDGER_V2_SCHEMA_VERSION = "assumption-policy-ledger/2"
POLICY_ACTIVATION_RESULT_SCHEMA_VERSION = "assumption-policy-activation-result/1"

ACTIVATION_VALIDATION_ORDER = (
    "PARSE_AND_SELF_DIGESTS",
    "EXACT_IDEMPOTENCE",
    "POLICY_STRUCTURE_AND_OVERLAP",
    "COMMIT_BINDINGS",
    "LEDGER_POSITION",
    "RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET",
    "SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM",
    "CRYPTOGRAPHIC_VERIFICATION",
    "SIGNER_AUTHORITY",
    "THRESHOLD_AND_REQUIRED_SIGNERS",
    "ACTIVATION_PROOF_AND_ENTRY",
    "COMPARE_AND_APPEND",
    "ACTIVATION_RESULT",
)

POLICY_APPEND_PRECEDENCE = (
    "EXACT_IDEMPOTENCE",
    "PREDECESSOR_HEAD_MATCH",
    "EFFECTIVE_SEQUENCE_MONOTONICITY",
)

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MATERIALITIES = {"ADVISORY", "MATERIAL", "CRITICAL"}


class AssumptionPolicyActivationContractError(ValueError):
    """Stable fail-closed error for A1 contracts."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class AssumptionPolicyAlgorithmProfile:
    algorithm: str
    verification_profile: str

    def __post_init__(self) -> None:
        require_token(self.algorithm, "ASSUMPTION_SIGNATURE_ALGORITHM_INVALID")
        require_token(
            self.verification_profile,
            "ASSUMPTION_SIGNATURE_VERIFICATION_PROFILE_INVALID",
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "verification_profile": self.verification_profile,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicySignatureProfile:
    signature_set_schema_version: str
    signature_record_semantics_version: str
    algorithm_profiles: tuple[AssumptionPolicyAlgorithmProfile, ...]
    required_authority_scope: str
    key_authority_root_digest: str
    duplicate_signer_rule: str
    profile_digest: str

    def __post_init__(self) -> None:
        if self.signature_set_schema_version != "signature-set/1":
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_SET_SCHEMA_UNSUPPORTED"
            )
        if self.signature_record_semantics_version != "signature-record/1":
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_RECORD_SEMANTICS_UNSUPPORTED"
            )
        canonical = tuple(
            sorted(self.algorithm_profiles, key=lambda item: item.algorithm)
        )
        if not canonical or canonical != self.algorithm_profiles:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_PROFILE_ALGORITHMS_NOT_CANONICAL"
            )
        if len({item.algorithm for item in canonical}) != len(canonical):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_PROFILE_ALGORITHM_DUPLICATE"
            )
        require_token(
            self.required_authority_scope,
            "ASSUMPTION_SIGNATURE_AUTHORITY_SCOPE_INVALID",
        )
        require_digest(
            self.key_authority_root_digest,
            "ASSUMPTION_SIGNATURE_KEY_ROOT_INVALID",
        )
        if self.duplicate_signer_rule != "ONE_SIGNER_ONE_VOTE":
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_DUPLICATE_RULE_UNSUPPORTED"
            )
        require_self_digest(
            "ASSUMPTION_POLICY_SIGNATURE_PROFILE",
            self._unsigned_value(),
            self.profile_digest,
            "ASSUMPTION_SIGNATURE_PROFILE_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        algorithm_profiles: tuple[AssumptionPolicyAlgorithmProfile, ...],
        required_authority_scope: str,
        key_authority_root_digest: str,
        signature_set_schema_version: str = "signature-set/1",
        signature_record_semantics_version: str = "signature-record/1",
        duplicate_signer_rule: str = "ONE_SIGNER_ONE_VOTE",
    ) -> AssumptionPolicySignatureProfile:
        canonical = tuple(
            sorted(algorithm_profiles, key=lambda item: item.algorithm)
        )
        unsigned = {
            "schema_version": SIGNATURE_PROFILE_SCHEMA_VERSION,
            "algorithm_profiles": [
                item.to_json_value() for item in canonical
            ],
            "duplicate_signer_rule": duplicate_signer_rule,
            "key_authority_root_digest": key_authority_root_digest,
            "required_authority_scope": required_authority_scope,
            "signature_record_semantics_version": (
                signature_record_semantics_version
            ),
            "signature_set_schema_version": signature_set_schema_version,
        }
        return cls(
            signature_set_schema_version=signature_set_schema_version,
            signature_record_semantics_version=(
                signature_record_semantics_version
            ),
            algorithm_profiles=canonical,
            required_authority_scope=required_authority_scope,
            key_authority_root_digest=key_authority_root_digest,
            duplicate_signer_rule=duplicate_signer_rule,
            profile_digest=domain_digest(
                "ASSUMPTION_POLICY_SIGNATURE_PROFILE",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": SIGNATURE_PROFILE_SCHEMA_VERSION,
            "algorithm_profiles": [
                item.to_json_value() for item in self.algorithm_profiles
            ],
            "duplicate_signer_rule": self.duplicate_signer_rule,
            "key_authority_root_digest": self.key_authority_root_digest,
            "required_authority_scope": self.required_authority_scope,
            "signature_record_semantics_version": (
                self.signature_record_semantics_version
            ),
            "signature_set_schema_version": self.signature_set_schema_version,
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "profile_digest": self.profile_digest,
        }

    def verification_profile_for(self, algorithm: str) -> str:
        for item in self.algorithm_profiles:
            if item.algorithm == algorithm:
                return item.verification_profile
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_SIGNATURE_ALGORITHM_NOT_PINNED",
            algorithm,
        )


@dataclass(frozen=True, slots=True, order=True)
class AssumptionChallengeClassificationRule:
    reason_code: str
    materiality: str

    def __post_init__(self) -> None:
        require_token(
            self.reason_code,
            "ASSUMPTION_CHALLENGE_CLASSIFICATION_REASON_INVALID",
        )
        if self.materiality not in _MATERIALITIES:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_CHALLENGE_CLASSIFICATION_MATERIALITY_INVALID"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "materiality": self.materiality,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class AssumptionChallengeClassificationPolicy:
    reason_rules: tuple[AssumptionChallengeClassificationRule, ...]
    unknown_reason_behavior: str
    policy_digest: str

    def __post_init__(self) -> None:
        canonical = tuple(
            sorted(self.reason_rules, key=lambda item: item.reason_code)
        )
        if canonical != self.reason_rules:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_CHALLENGE_CLASSIFICATION_RULES_NOT_CANONICAL"
            )
        if len({item.reason_code for item in canonical}) != len(canonical):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_CHALLENGE_CLASSIFICATION_REASON_DUPLICATE"
            )
        if self.unknown_reason_behavior != "FAIL_CLOSED_AS_CRITICAL":
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_CHALLENGE_UNKNOWN_BEHAVIOR_UNSUPPORTED"
            )
        require_self_digest(
            "ASSUMPTION_CHALLENGE_CLASSIFICATION_POLICY",
            self._unsigned_value(),
            self.policy_digest,
            "ASSUMPTION_CHALLENGE_CLASSIFICATION_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        reason_rules: tuple[AssumptionChallengeClassificationRule, ...],
        unknown_reason_behavior: str = "FAIL_CLOSED_AS_CRITICAL",
    ) -> AssumptionChallengeClassificationPolicy:
        canonical = tuple(
            sorted(reason_rules, key=lambda item: item.reason_code)
        )
        unsigned = {
            "schema_version": CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION,
            "reason_rules": [item.to_json_value() for item in canonical],
            "unknown_reason_behavior": unknown_reason_behavior,
        }
        return cls(
            reason_rules=canonical,
            unknown_reason_behavior=unknown_reason_behavior,
            policy_digest=domain_digest(
                "ASSUMPTION_CHALLENGE_CLASSIFICATION_POLICY",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION,
            "reason_rules": [
                item.to_json_value() for item in self.reason_rules
            ],
            "unknown_reason_behavior": self.unknown_reason_behavior,
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "policy_digest": self.policy_digest,
        }

    def classify(self, reason_code: str) -> str:
        for rule in self.reason_rules:
            if rule.reason_code == reason_code:
                return rule.materiality
        return "CRITICAL"


def require_token(value: object, code: str) -> None:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise AssumptionPolicyActivationContractError(code)


def require_digest(value: object, code: str) -> None:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise AssumptionPolicyActivationContractError(code)


def require_sorted_tokens(
    values: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool,
) -> None:
    if type(values) is not tuple or (not allow_empty and not values):
        raise AssumptionPolicyActivationContractError(code)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise AssumptionPolicyActivationContractError(code)
    for value in values:
        require_token(value, code)


def require_self_digest(
    domain: str,
    unsigned: object,
    actual: str,
    code: str,
) -> None:
    require_digest(actual, code)
    if actual != domain_digest(domain, unsigned):
        raise AssumptionPolicyActivationContractError(code)


def domain_digest(domain: str, value: object) -> str:
    payload = domain.encode("utf-8") + b"\0" + json_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def json_bytes(value: object) -> bytes:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return (rendered + "\n").encode("utf-8")
