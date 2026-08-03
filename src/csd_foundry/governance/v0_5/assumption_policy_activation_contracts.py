"""Frozen D3.2-A1 policy-activation and exact grant-selection contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.assumption import Assumption
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    GLOBAL_ASSUMPTION_SCOPE,
    RESOLUTION_AUTHORITY_ACTIONS,
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent

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
    """Stable fail-closed error for frozen A1 contracts."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class AssumptionPolicyAlgorithmProfile:
    algorithm: str
    verification_profile: str

    def __post_init__(self) -> None:
        _require_token(self.algorithm, "ASSUMPTION_SIGNATURE_ALGORITHM_INVALID")
        _require_token(
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
        canonical = tuple(sorted(self.algorithm_profiles, key=lambda item: item.algorithm))
        if not canonical or canonical != self.algorithm_profiles:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_PROFILE_ALGORITHMS_NOT_CANONICAL"
            )
        if len({item.algorithm for item in canonical}) != len(canonical):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_PROFILE_ALGORITHM_DUPLICATE"
            )
        _require_token(
            self.required_authority_scope,
            "ASSUMPTION_SIGNATURE_AUTHORITY_SCOPE_INVALID",
        )
        _require_digest(
            self.key_authority_root_digest,
            "ASSUMPTION_SIGNATURE_KEY_ROOT_INVALID",
        )
        if self.duplicate_signer_rule != "ONE_SIGNER_ONE_VOTE":
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_SIGNATURE_DUPLICATE_RULE_UNSUPPORTED"
            )
        _require_self_digest(
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
        canonical = tuple(sorted(algorithm_profiles, key=lambda item: item.algorithm))
        unsigned = {
            "schema_version": SIGNATURE_PROFILE_SCHEMA_VERSION,
            "algorithm_profiles": [item.to_json_value() for item in canonical],
            "duplicate_signer_rule": duplicate_signer_rule,
            "key_authority_root_digest": key_authority_root_digest,
            "required_authority_scope": required_authority_scope,
            "signature_record_semantics_version": signature_record_semantics_version,
            "signature_set_schema_version": signature_set_schema_version,
        }
        return cls(
            signature_set_schema_version=signature_set_schema_version,
            signature_record_semantics_version=signature_record_semantics_version,
            algorithm_profiles=canonical,
            required_authority_scope=required_authority_scope,
            key_authority_root_digest=key_authority_root_digest,
            duplicate_signer_rule=duplicate_signer_rule,
            profile_digest=_domain_digest(
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
        return {**self._unsigned_value(), "profile_digest": self.profile_digest}

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
        _require_token(
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
        canonical = tuple(sorted(self.reason_rules, key=lambda item: item.reason_code))
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
        _require_self_digest(
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
        canonical = tuple(sorted(reason_rules, key=lambda item: item.reason_code))
        unsigned = {
            "schema_version": CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION,
            "reason_rules": [item.to_json_value() for item in canonical],
            "unknown_reason_behavior": unknown_reason_behavior,
        }
        return cls(
            reason_rules=canonical,
            unknown_reason_behavior=unknown_reason_behavior,
            policy_digest=_domain_digest(
                "ASSUMPTION_CHALLENGE_CLASSIFICATION_POLICY",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION,
            "reason_rules": [item.to_json_value() for item in self.reason_rules],
            "unknown_reason_behavior": self.unknown_reason_behavior,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "policy_digest": self.policy_digest}

    def classify(self, reason_code: str) -> str:
        for rule in self.reason_rules:
            if rule.reason_code == reason_code:
                return rule.materiality
        return "CRITICAL"


@dataclass(frozen=True, slots=True)
class AssumptionAuthorityPolicyCommitV2:
    policy_id: str
    policy_digest: str
    predecessor_policy_digest: str | None
    predecessor_commit_receipt_digest: str | None
    authority_root_digest: str
    grant_set_digest: str
    separation_duty_rule_set_digest: str
    exception_set_digest: str
    exception_count: int
    approval_class: str
    effective_from_sequence: int
    approval_policy_digest: str
    signature_profile_digest: str
    challenge_classification_policy_digest: str
    signature_set_digest: str
    commit_receipt_digest: str

    def __post_init__(self) -> None:
        _require_token(self.policy_id, "ASSUMPTION_POLICY_COMMIT_POLICY_ID_INVALID")
        for value, code in (
            (self.policy_digest, "ASSUMPTION_POLICY_COMMIT_POLICY_DIGEST_INVALID"),
            (self.authority_root_digest, "ASSUMPTION_POLICY_COMMIT_ROOT_INVALID"),
            (self.grant_set_digest, "ASSUMPTION_POLICY_COMMIT_GRANT_SET_INVALID"),
            (
                self.separation_duty_rule_set_digest,
                "ASSUMPTION_POLICY_COMMIT_RULE_SET_INVALID",
            ),
            (self.exception_set_digest, "ASSUMPTION_POLICY_COMMIT_EXCEPTION_SET_INVALID"),
            (
                self.approval_policy_digest,
                "ASSUMPTION_POLICY_COMMIT_APPROVAL_POLICY_INVALID",
            ),
            (
                self.signature_profile_digest,
                "ASSUMPTION_POLICY_COMMIT_SIGNATURE_PROFILE_INVALID",
            ),
            (
                self.challenge_classification_policy_digest,
                "ASSUMPTION_POLICY_COMMIT_CHALLENGE_POLICY_INVALID",
            ),
            (self.signature_set_digest, "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_INVALID"),
        ):
            _require_digest(value, code)
        predecessor_none = self.predecessor_policy_digest is None
        receipt_none = self.predecessor_commit_receipt_digest is None
        if predecessor_none != receipt_none:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_PREDECESSOR_INCOMPLETE"
            )
        if self.predecessor_policy_digest is not None:
            _require_digest(
                self.predecessor_policy_digest,
                "ASSUMPTION_POLICY_COMMIT_PREDECESSOR_POLICY_INVALID",
            )
            _require_digest(
                self.predecessor_commit_receipt_digest,
                "ASSUMPTION_POLICY_COMMIT_PREDECESSOR_RECEIPT_INVALID",
            )
        if type(self.exception_count) is not int or self.exception_count < 0:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_EXCEPTION_COUNT_INVALID"
            )
        expected_class = "DUTY_EXCEPTION" if self.exception_count else "STANDARD"
        if self.approval_class != expected_class:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_APPROVAL_CLASS_DOWNGRADE"
            )
        if (
            type(self.effective_from_sequence) is not int
            or self.effective_from_sequence < 0
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_EFFECTIVE_SEQUENCE_INVALID"
            )
        _require_self_digest(
            "ASSUMPTION_AUTHORITY_POLICY_COMMIT_V2",
            self._unsigned_value(),
            self.commit_receipt_digest,
            "ASSUMPTION_POLICY_COMMIT_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy: AssumptionAuthorityPolicy,
        predecessor_policy_digest: str | None,
        predecessor_commit_receipt_digest: str | None,
        effective_from_sequence: int,
        approval_policy_digest: str,
        signature_profile_digest: str,
        challenge_classification_policy_digest: str,
        signature_set_digest: str,
    ) -> AssumptionAuthorityPolicyCommitV2:
        approval_class = "DUTY_EXCEPTION" if policy.duty_exceptions else "STANDARD"
        unsigned = {
            "schema_version": AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
            "approval_class": approval_class,
            "approval_policy_digest": approval_policy_digest,
            "authority_root_digest": policy.authority_root_digest,
            "challenge_classification_policy_digest": (
                challenge_classification_policy_digest
            ),
            "effective_from_sequence": effective_from_sequence,
            "exception_count": len(policy.duty_exceptions),
            "exception_set_digest": policy.exception_set_digest,
            "grant_set_digest": policy.grant_set_digest,
            "policy_digest": policy.policy_digest,
            "policy_id": policy.policy_id,
            "predecessor_commit_receipt_digest": (
                predecessor_commit_receipt_digest
            ),
            "predecessor_policy_digest": predecessor_policy_digest,
            "separation_duty_rule_set_digest": (
                policy.separation_duty_rule_set_digest
            ),
            "signature_profile_digest": signature_profile_digest,
            "signature_set_digest": signature_set_digest,
        }
        return cls(
            policy_id=policy.policy_id,
            policy_digest=policy.policy_digest,
            predecessor_policy_digest=predecessor_policy_digest,
            predecessor_commit_receipt_digest=predecessor_commit_receipt_digest,
            authority_root_digest=policy.authority_root_digest,
            grant_set_digest=policy.grant_set_digest,
            separation_duty_rule_set_digest=policy.separation_duty_rule_set_digest,
            exception_set_digest=policy.exception_set_digest,
            exception_count=len(policy.duty_exceptions),
            approval_class=approval_class,
            effective_from_sequence=effective_from_sequence,
            approval_policy_digest=approval_policy_digest,
            signature_profile_digest=signature_profile_digest,
            challenge_classification_policy_digest=(
                challenge_classification_policy_digest
            ),
            signature_set_digest=signature_set_digest,
            commit_receipt_digest=_domain_digest(
                "ASSUMPTION_AUTHORITY_POLICY_COMMIT_V2",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
            "approval_class": self.approval_class,
            "approval_policy_digest": self.approval_policy_digest,
            "authority_root_digest": self.authority_root_digest,
            "challenge_classification_policy_digest": (
                self.challenge_classification_policy_digest
            ),
            "effective_from_sequence": self.effective_from_sequence,
            "exception_count": self.exception_count,
            "exception_set_digest": self.exception_set_digest,
            "grant_set_digest": self.grant_set_digest,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "predecessor_commit_receipt_digest": (
                self.predecessor_commit_receipt_digest
            ),
            "predecessor_policy_digest": self.predecessor_policy_digest,
            "separation_duty_rule_set_digest": (
                self.separation_duty_rule_set_digest
            ),
            "signature_profile_digest": self.signature_profile_digest,
            "signature_set_digest": self.signature_set_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "commit_receipt_digest": self.commit_receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicyActivationProof:
    policy_commit_receipt_digest: str
    approval_policy_digest: str
    approval_rule_digest: str
    signature_profile_digest: str
    challenge_classification_policy_digest: str
    authority_root_digest: str
    signature_set_digest: str
    valid_signer_ids: tuple[str, ...]
    rejected_signer_codes: tuple[str, ...]
    activation_proof_digest: str

    def __post_init__(self) -> None:
        for value, code in (
            (
                self.policy_commit_receipt_digest,
                "ASSUMPTION_ACTIVATION_PROOF_COMMIT_INVALID",
            ),
            (
                self.approval_policy_digest,
                "ASSUMPTION_ACTIVATION_PROOF_APPROVAL_POLICY_INVALID",
            ),
            (
                self.approval_rule_digest,
                "ASSUMPTION_ACTIVATION_PROOF_APPROVAL_RULE_INVALID",
            ),
            (
                self.signature_profile_digest,
                "ASSUMPTION_ACTIVATION_PROOF_SIGNATURE_PROFILE_INVALID",
            ),
            (
                self.challenge_classification_policy_digest,
                "ASSUMPTION_ACTIVATION_PROOF_CHALLENGE_POLICY_INVALID",
            ),
            (self.authority_root_digest, "ASSUMPTION_ACTIVATION_PROOF_ROOT_INVALID"),
            (
                self.signature_set_digest,
                "ASSUMPTION_ACTIVATION_PROOF_SIGNATURE_SET_INVALID",
            ),
        ):
            _require_digest(value, code)
        _require_sorted_tokens(
            self.valid_signer_ids,
            "ASSUMPTION_ACTIVATION_PROOF_SIGNERS_INVALID",
            allow_empty=False,
        )
        _require_sorted_tokens(
            self.rejected_signer_codes,
            "ASSUMPTION_ACTIVATION_PROOF_REJECTIONS_INVALID",
            allow_empty=True,
        )
        _require_self_digest(
            "ASSUMPTION_POLICY_ACTIVATION_PROOF",
            self._unsigned_value(),
            self.activation_proof_digest,
            "ASSUMPTION_ACTIVATION_PROOF_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy_commit_receipt_digest: str,
        approval_policy_digest: str,
        approval_rule_digest: str,
        signature_profile_digest: str,
        challenge_classification_policy_digest: str,
        authority_root_digest: str,
        signature_set_digest: str,
        valid_signer_ids: tuple[str, ...],
        rejected_signer_codes: tuple[str, ...] = (),
    ) -> AssumptionPolicyActivationProof:
        signers = tuple(sorted(set(valid_signer_ids)))
        rejected = tuple(sorted(set(rejected_signer_codes)))
        unsigned = {
            "schema_version": ACTIVATION_PROOF_SCHEMA_VERSION,
            "approval_policy_digest": approval_policy_digest,
            "approval_rule_digest": approval_rule_digest,
            "authority_root_digest": authority_root_digest,
            "challenge_classification_policy_digest": (
                challenge_classification_policy_digest
            ),
            "policy_commit_receipt_digest": policy_commit_receipt_digest,
            "rejected_signer_codes": list(rejected),
            "signature_profile_digest": signature_profile_digest,
            "signature_set_digest": signature_set_digest,
            "valid_signer_ids": list(signers),
        }
        return cls(
            policy_commit_receipt_digest=policy_commit_receipt_digest,
            approval_policy_digest=approval_policy_digest,
            approval_rule_digest=approval_rule_digest,
            signature_profile_digest=signature_profile_digest,
            challenge_classification_policy_digest=(
                challenge_classification_policy_digest
            ),
            authority_root_digest=authority_root_digest,
            signature_set_digest=signature_set_digest,
            valid_signer_ids=signers,
            rejected_signer_codes=rejected,
            activation_proof_digest=_domain_digest(
                "ASSUMPTION_POLICY_ACTIVATION_PROOF",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVATION_PROOF_SCHEMA_VERSION,
            "approval_policy_digest": self.approval_policy_digest,
            "approval_rule_digest": self.approval_rule_digest,
            "authority_root_digest": self.authority_root_digest,
            "challenge_classification_policy_digest": (
                self.challenge_classification_policy_digest
            ),
            "policy_commit_receipt_digest": self.policy_commit_receipt_digest,
            "rejected_signer_codes": list(self.rejected_signer_codes),
            "signature_profile_digest": self.signature_profile_digest,
            "signature_set_digest": self.signature_set_digest,
            "valid_signer_ids": list(self.valid_signer_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "activation_proof_digest": self.activation_proof_digest,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedgerEntryV2:
    policy: AssumptionAuthorityPolicy
    policy_commit: AssumptionAuthorityPolicyCommitV2
    approval_policy: AssumptionPolicyApprovalPolicy
    signature_profile: AssumptionPolicySignatureProfile
    challenge_classification_policy: AssumptionChallengeClassificationPolicy
    activation_proof: AssumptionPolicyActivationProof
    ledger_entry_digest: str

    def __post_init__(self) -> None:
        commit = self.policy_commit
        bindings = (
            (commit.policy_id, self.policy.policy_id),
            (commit.policy_digest, self.policy.policy_digest),
            (commit.authority_root_digest, self.policy.authority_root_digest),
            (commit.grant_set_digest, self.policy.grant_set_digest),
            (
                commit.separation_duty_rule_set_digest,
                self.policy.separation_duty_rule_set_digest,
            ),
            (commit.exception_set_digest, self.policy.exception_set_digest),
            (
                commit.approval_policy_digest,
                self.approval_policy.approval_policy_digest,
            ),
            (
                commit.signature_profile_digest,
                self.signature_profile.profile_digest,
            ),
            (
                commit.challenge_classification_policy_digest,
                self.challenge_classification_policy.policy_digest,
            ),
            (
                self.activation_proof.policy_commit_receipt_digest,
                commit.commit_receipt_digest,
            ),
            (
                self.activation_proof.signature_set_digest,
                commit.signature_set_digest,
            ),
        )
        if any(left != right for left, right in bindings):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_BINDING_MISMATCH"
            )
        _require_self_digest(
            "ASSUMPTION_POLICY_LEDGER_ENTRY_V2",
            self._unsigned_value(),
            self.ledger_entry_digest,
            "ASSUMPTION_POLICY_LEDGER_ENTRY_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy: AssumptionAuthorityPolicy,
        policy_commit: AssumptionAuthorityPolicyCommitV2,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_classification_policy: AssumptionChallengeClassificationPolicy,
        activation_proof: AssumptionPolicyActivationProof,
    ) -> AssumptionPolicyLedgerEntryV2:
        unsigned = {
            "schema_version": POLICY_LEDGER_ENTRY_V2_SCHEMA_VERSION,
            "activation_proof": activation_proof.to_json_value(),
            "approval_policy": approval_policy.to_json_value(),
            "challenge_classification_policy": (
                challenge_classification_policy.to_json_value()
            ),
            "policy": policy.to_json_value(),
            "policy_commit": policy_commit.to_json_value(),
            "signature_profile": signature_profile.to_json_value(),
        }
        return cls(
            policy=policy,
            policy_commit=policy_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_classification_policy=challenge_classification_policy,
            activation_proof=activation_proof,
            ledger_entry_digest=_domain_digest(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_V2",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_ENTRY_V2_SCHEMA_VERSION,
            "activation_proof": self.activation_proof.to_json_value(),
            "approval_policy": self.approval_policy.to_json_value(),
            "challenge_classification_policy": (
                self.challenge_classification_policy.to_json_value()
            ),
            "policy": self.policy.to_json_value(),
            "policy_commit": self.policy_commit.to_json_value(),
            "signature_profile": self.signature_profile.to_json_value(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "ledger_entry_digest": self.ledger_entry_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedgerV2:
    entries: tuple[AssumptionPolicyLedgerEntryV2, ...]
    ledger_root_digest: str

    def __post_init__(self) -> None:
        ordered = order_policy_entries(self.entries)
        if ordered != self.entries:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_ENTRIES_NOT_CANONICAL"
            )
        _require_self_digest(
            "ASSUMPTION_POLICY_LEDGER",
            self._unsigned_value(),
            self.ledger_root_digest,
            "ASSUMPTION_POLICY_LEDGER_ROOT_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        entries: tuple[AssumptionPolicyLedgerEntryV2, ...],
    ) -> AssumptionPolicyLedgerV2:
        ordered = order_policy_entries(entries)
        unsigned = {
            "schema_version": POLICY_LEDGER_V2_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in ordered],
        }
        return cls(
            entries=ordered,
            ledger_root_digest=_domain_digest(
                "ASSUMPTION_POLICY_LEDGER",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_V2_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in self.entries],
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "ledger_root_digest": self.ledger_root_digest,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicyActivationResult:
    append_result: str
    policy_commit_receipt_digest: str
    ledger_entry_digest: str
    predecessor_ledger_root: str
    resulting_ledger_root: str
    result_digest: str

    def __post_init__(self) -> None:
        if self.append_result not in {"COMMITTED", "IDEMPOTENT_APPEND"}:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_ACTIVATION_RESULT_CODE_INVALID"
            )
        for value, code in (
            (
                self.policy_commit_receipt_digest,
                "ASSUMPTION_POLICY_ACTIVATION_RESULT_COMMIT_INVALID",
            ),
            (
                self.ledger_entry_digest,
                "ASSUMPTION_POLICY_ACTIVATION_RESULT_ENTRY_INVALID",
            ),
            (
                self.predecessor_ledger_root,
                "ASSUMPTION_POLICY_ACTIVATION_RESULT_PREDECESSOR_ROOT_INVALID",
            ),
            (
                self.resulting_ledger_root,
                "ASSUMPTION_POLICY_ACTIVATION_RESULT_ROOT_INVALID",
            ),
        ):
            _require_digest(value, code)
        _require_self_digest(
            "ASSUMPTION_POLICY_ACTIVATION_RESULT",
            self._unsigned_value(),
            self.result_digest,
            "ASSUMPTION_POLICY_ACTIVATION_RESULT_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        append_result: str,
        policy_commit_receipt_digest: str,
        ledger_entry_digest: str,
        predecessor_ledger_root: str,
        resulting_ledger_root: str,
    ) -> AssumptionPolicyActivationResult:
        unsigned = {
            "schema_version": POLICY_ACTIVATION_RESULT_SCHEMA_VERSION,
            "append_result": append_result,
            "ledger_entry_digest": ledger_entry_digest,
            "policy_commit_receipt_digest": policy_commit_receipt_digest,
            "predecessor_ledger_root": predecessor_ledger_root,
            "resulting_ledger_root": resulting_ledger_root,
        }
        return cls(
            append_result=append_result,
            policy_commit_receipt_digest=policy_commit_receipt_digest,
            ledger_entry_digest=ledger_entry_digest,
            predecessor_ledger_root=predecessor_ledger_root,
            resulting_ledger_root=resulting_ledger_root,
            result_digest=_domain_digest(
                "ASSUMPTION_POLICY_ACTIVATION_RESULT",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_ACTIVATION_RESULT_SCHEMA_VERSION,
            "append_result": self.append_result,
            "ledger_entry_digest": self.ledger_entry_digest,
            "policy_commit_receipt_digest": self.policy_commit_receipt_digest,
            "predecessor_ledger_root": self.predecessor_ledger_root,
            "resulting_ledger_root": self.resulting_ledger_root,
        }


def validate_activatable_commit_version(value: dict[str, Any]) -> None:
    if value.get("schema_version") != AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
        )


def validate_policy_overlap(policy: AssumptionAuthorityPolicy) -> None:
    for index, left in enumerate(policy.grants):
        for right in policy.grants[index + 1 :]:
            if grants_overlap(left, right):
                pair = ",".join(sorted((left.grant_id, right.grant_id)))
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_AUTHORITY_GRANT_OVERLAP",
                    pair,
                )


def grants_overlap(
    left: AssumptionAuthorityGrant,
    right: AssumptionAuthorityGrant,
) -> bool:
    if left.authority_id != right.authority_id or left.action != right.action:
        return False
    if not _intervals_overlap(
        left.effective_from_sequence,
        left.effective_until_sequence,
        right.effective_from_sequence,
        right.effective_until_sequence,
    ):
        return False
    if not _scopes_intersect(left.scope_ids, right.scope_ids):
        return False
    if not set(left.assumption_materialities).intersection(
        right.assumption_materialities
    ):
        return False
    if left.action in RESOLUTION_AUTHORITY_ACTIONS:
        return bool(
            set(left.challenge_materialities).intersection(
                right.challenge_materialities
            )
        )
    return True


def classify_exact_idempotence(
    existing: AssumptionPolicyLedgerEntryV2,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> str:
    if (
        existing.ledger_entry_digest == candidate.ledger_entry_digest
        and existing.canonical_bytes == candidate.canonical_bytes
    ):
        return "IDEMPOTENT_APPEND"
    if (
        existing.policy_commit.commit_receipt_digest
        == candidate.policy_commit.commit_receipt_digest
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_ENTRY_DIVERGENCE"
        )
    return "DISTINCT_ENTRY"


def validate_successor_position(
    head: AssumptionPolicyLedgerEntryV2,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> None:
    commit = candidate.policy_commit
    if (
        commit.predecessor_policy_digest != head.policy.policy_digest
        or commit.predecessor_commit_receipt_digest
        != head.policy_commit.commit_receipt_digest
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_CHAIN_FORK"
        )
    if (
        commit.effective_from_sequence
        <= head.policy_commit.effective_from_sequence
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING"
        )


def order_policy_entries(
    entries: tuple[AssumptionPolicyLedgerEntryV2, ...],
) -> tuple[AssumptionPolicyLedgerEntryV2, ...]:
    if not entries:
        return ()
    children: dict[str, list[AssumptionPolicyLedgerEntryV2]] = {}
    genesis: list[AssumptionPolicyLedgerEntryV2] = []
    for entry in entries:
        predecessor = entry.policy_commit.predecessor_commit_receipt_digest
        if predecessor is None:
            genesis.append(entry)
        else:
            children.setdefault(predecessor, []).append(entry)
    if len(genesis) != 1:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_LEDGER_GENESIS_INVALID"
        )
    ordered: list[AssumptionPolicyLedgerEntryV2] = []
    visited: set[str] = set()
    current = genesis[0]
    while True:
        digest = current.policy_commit.commit_receipt_digest
        if digest in visited:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_CYCLE"
            )
        visited.add(digest)
        ordered.append(current)
        successors = children.get(digest, [])
        if len(successors) > 1:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_CHAIN_FORK"
            )
        if not successors:
            break
        successor = successors[0]
        validate_successor_position(current, successor)
        current = successor
    if len(visited) != len(entries):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_LEDGER_DISCONNECTED"
        )
    return tuple(ordered)


def derive_resolution_challenge_materialities(
    assumption: Assumption,
    candidate_event: RegistryEvent,
    classification_policy: AssumptionChallengeClassificationPolicy,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    value = candidate_event.to_json_value()
    if value.get("entity_id") != assumption.assumption_id:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_IDENTITY_MISMATCH"
        )
    if value.get("previous_entity_event_digest") != assumption.current_event_digest:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_HEAD_MISMATCH"
        )
    payload = cast(dict[str, Any], value.get("payload"))
    if payload.get("operation") != "RESOLVE_CHALLENGES":
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_OPERATION_INVALID"
        )
    raw_ids = payload.get("resolved_challenge_ids")
    if type(raw_ids) is not list or not raw_ids:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLVED_CHALLENGES_INVALID"
        )
    resolved_ids = tuple(sorted(cast(list[str], raw_ids)))
    if len(set(resolved_ids)) != len(resolved_ids):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLVED_CHALLENGES_INVALID"
        )
    current = {item.challenge_id: item for item in assumption.active_challenges}
    unknown = sorted(set(resolved_ids).difference(current))
    if unknown:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN",
            unknown[0],
        )
    materialities = tuple(
        sorted(
            classification_policy.classify(current[item].reason_code)
            for item in resolved_ids
        )
    )
    return resolved_ids, materialities


def _intervals_overlap(
    left_start: int,
    left_end: int | None,
    right_start: int,
    right_end: int | None,
) -> bool:
    left_limit = float("inf") if left_end is None else left_end
    right_limit = float("inf") if right_end is None else right_end
    return left_start < right_limit and right_start < left_limit


def _scopes_intersect(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    if GLOBAL_ASSUMPTION_SCOPE in left or GLOBAL_ASSUMPTION_SCOPE in right:
        return True
    return bool(set(left).intersection(right))


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise AssumptionPolicyActivationContractError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise AssumptionPolicyActivationContractError(code)


def _require_sorted_tokens(
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
        _require_token(value, code)


def _require_self_digest(
    domain: str,
    unsigned: object,
    actual: str,
    code: str,
) -> None:
    _require_digest(actual, code)
    if actual != _domain_digest(domain, unsigned):
        raise AssumptionPolicyActivationContractError(code)


def _domain_digest(domain: str, value: object) -> str:
    return "sha256:" + hashlib.sha256(
        domain.encode("utf-8") + b"\0" + _json_bytes(value)
    ).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
