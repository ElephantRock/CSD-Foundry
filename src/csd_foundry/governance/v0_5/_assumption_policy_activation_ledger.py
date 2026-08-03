"""Frozen ledger contracts for v0.5-D3.2-A1 activation."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    ACTIVATION_PROOF_SCHEMA_VERSION,
    AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
    POLICY_ACTIVATION_RESULT_SCHEMA_VERSION,
    POLICY_LEDGER_ENTRY_V2_SCHEMA_VERSION,
    POLICY_LEDGER_V2_SCHEMA_VERSION,
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    domain_digest,
    json_bytes,
    require_digest,
    require_self_digest,
    require_sorted_tokens,
    require_token,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
)


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
        require_token(self.policy_id, "ASSUMPTION_POLICY_COMMIT_POLICY_ID_INVALID")
        digest_fields = (
            (self.policy_digest, "ASSUMPTION_POLICY_COMMIT_POLICY_DIGEST_INVALID"),
            (self.authority_root_digest, "ASSUMPTION_POLICY_COMMIT_ROOT_INVALID"),
            (self.grant_set_digest, "ASSUMPTION_POLICY_COMMIT_GRANT_SET_INVALID"),
            (
                self.separation_duty_rule_set_digest,
                "ASSUMPTION_POLICY_COMMIT_RULE_SET_INVALID",
            ),
            (
                self.exception_set_digest,
                "ASSUMPTION_POLICY_COMMIT_EXCEPTION_SET_INVALID",
            ),
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
            (
                self.signature_set_digest,
                "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_INVALID",
            ),
        )
        for value, code in digest_fields:
            require_digest(value, code)
        predecessor_none = self.predecessor_policy_digest is None
        receipt_none = self.predecessor_commit_receipt_digest is None
        if predecessor_none != receipt_none:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_PREDECESSOR_INCOMPLETE"
            )
        if self.predecessor_policy_digest is not None:
            require_digest(
                self.predecessor_policy_digest,
                "ASSUMPTION_POLICY_COMMIT_PREDECESSOR_POLICY_INVALID",
            )
            require_digest(
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
        if type(self.effective_from_sequence) is not int or self.effective_from_sequence < 0:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_COMMIT_EFFECTIVE_SEQUENCE_INVALID"
            )
        require_self_digest(
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
            "predecessor_commit_receipt_digest": (predecessor_commit_receipt_digest),
            "predecessor_policy_digest": predecessor_policy_digest,
            "separation_duty_rule_set_digest": (policy.separation_duty_rule_set_digest),
            "signature_profile_digest": signature_profile_digest,
            "signature_set_digest": signature_set_digest,
        }
        return cls(
            policy_id=policy.policy_id,
            policy_digest=policy.policy_digest,
            predecessor_policy_digest=predecessor_policy_digest,
            predecessor_commit_receipt_digest=(predecessor_commit_receipt_digest),
            authority_root_digest=policy.authority_root_digest,
            grant_set_digest=policy.grant_set_digest,
            separation_duty_rule_set_digest=(policy.separation_duty_rule_set_digest),
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
            commit_receipt_digest=domain_digest(
                "ASSUMPTION_AUTHORITY_POLICY_COMMIT_V2", unsigned
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
            "separation_duty_rule_set_digest": (self.separation_duty_rule_set_digest),
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
        digest_fields = (
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
        )
        for value, code in digest_fields:
            require_digest(value, code)
        require_sorted_tokens(
            self.valid_signer_ids,
            "ASSUMPTION_ACTIVATION_PROOF_SIGNERS_INVALID",
            allow_empty=False,
        )
        require_sorted_tokens(
            self.rejected_signer_codes,
            "ASSUMPTION_ACTIVATION_PROOF_REJECTIONS_INVALID",
            allow_empty=True,
        )
        require_self_digest(
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
            activation_proof_digest=domain_digest(
                "ASSUMPTION_POLICY_ACTIVATION_PROOF", unsigned
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
            (commit.signature_profile_digest, self.signature_profile.profile_digest),
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
        require_self_digest(
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
            "challenge_classification_policy": (challenge_classification_policy.to_json_value()),
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
            ledger_entry_digest=domain_digest(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_V2", unsigned
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
        return json_bytes(self.to_json_value())


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
        require_self_digest(
            "ASSUMPTION_POLICY_LEDGER",
            self._unsigned_value(),
            self.ledger_root_digest,
            "ASSUMPTION_POLICY_LEDGER_ROOT_MISMATCH",
        )

    @classmethod
    def build(
        cls, entries: tuple[AssumptionPolicyLedgerEntryV2, ...]
    ) -> AssumptionPolicyLedgerV2:
        ordered = order_policy_entries(entries)
        unsigned = {
            "schema_version": POLICY_LEDGER_V2_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in ordered],
        }
        return cls(
            entries=ordered,
            ledger_root_digest=domain_digest("ASSUMPTION_POLICY_LEDGER", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_V2_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in self.entries],
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "ledger_root_digest": self.ledger_root_digest}


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
        digest_fields = (
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
        )
        for value, code in digest_fields:
            require_digest(value, code)
        require_self_digest(
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
            result_digest=domain_digest(
                "ASSUMPTION_POLICY_ACTIVATION_RESULT", unsigned
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


def classify_exact_idempotence(
    existing: AssumptionPolicyLedgerEntryV2,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> str:
    digest_equal = existing.ledger_entry_digest == candidate.ledger_entry_digest
    bytes_equal = existing.canonical_bytes == candidate.canonical_bytes
    if digest_equal and bytes_equal:
        return "IDEMPOTENT_APPEND"
    same_commit = (
        existing.policy_commit.commit_receipt_digest
        == candidate.policy_commit.commit_receipt_digest
    )
    if same_commit:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_ENTRY_DIVERGENCE")
    return "DISTINCT_ENTRY"


def validate_successor_position(
    head: AssumptionPolicyLedgerEntryV2,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> None:
    commit = candidate.policy_commit
    predecessor_matches = (
        commit.predecessor_policy_digest == head.policy.policy_digest
        and commit.predecessor_commit_receipt_digest == head.policy_commit.commit_receipt_digest
    )
    if not predecessor_matches:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_CHAIN_FORK")
    if commit.effective_from_sequence <= head.policy_commit.effective_from_sequence:
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
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_GENESIS_INVALID")
    ordered: list[AssumptionPolicyLedgerEntryV2] = []
    visited: set[str] = set()
    current = genesis[0]
    while True:
        digest = current.policy_commit.commit_receipt_digest
        if digest in visited:
            raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_CYCLE")
        visited.add(digest)
        ordered.append(current)
        successors = children.get(digest, [])
        if len(successors) > 1:
            raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_CHAIN_FORK")
        if not successors:
            break
        successor = successors[0]
        validate_successor_position(current, successor)
        current = successor
    if len(visited) != len(entries):
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_DISCONNECTED")
    return tuple(ordered)
