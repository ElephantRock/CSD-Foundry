"""Hardening contracts for executable v0.5-D3.2-A1 policy activation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, TypeAlias

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    domain_digest,
    require_digest,
    require_self_digest,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionAuthorityPolicyCommitV2,
    AssumptionPolicyActivationResult,
    AssumptionPolicyLedgerEntryV2 as _BaseAssumptionPolicyLedgerEntryV2,
    AssumptionPolicyLedgerV2,
    classify_exact_idempotence,
    validate_successor_position,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

EXPECTED_LEDGER_STATE_SCHEMA_VERSION = "assumption-policy-ledger-state-expectation/1"
PREPARED_POLICY_ACTIVATION_SCHEMA_VERSION = "prepared-assumption-policy-activation/1"
MAX_INTEROPERABLE_JSON_INTEGER = (1 << 53) - 1

JsonScalar: TypeAlias = str | int | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_COMMIT_FIELDS = {
    "schema_version",
    "approval_class",
    "approval_policy_digest",
    "authority_root_digest",
    "challenge_classification_policy_digest",
    "commit_receipt_digest",
    "effective_from_sequence",
    "exception_count",
    "exception_set_digest",
    "grant_set_digest",
    "policy_digest",
    "policy_id",
    "predecessor_commit_receipt_digest",
    "predecessor_policy_digest",
    "separation_duty_rule_set_digest",
    "signature_profile_digest",
    "signature_set_digest",
}


class AssumptionPolicyActivationDenied(RuntimeError):
    """Typed governance denial from pure activation preparation."""

    def __init__(self, code: str, stage: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.stage = stage
        self.detail = detail


class AssumptionPolicyPublicationConflict(RuntimeError):
    """Typed atomic-publication conflict; never a successful activation result."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class AssumptionPolicyLedgerEntryV2(_BaseAssumptionPolicyLedgerEntryV2):
    """Executable entry with complete activation-proof bindings."""

    __slots__ = ()

    def __post_init__(self) -> None:
        _BaseAssumptionPolicyLedgerEntryV2.__post_init__(self)
        commit = self.policy_commit
        proof = self.activation_proof
        approval_rule = self.approval_policy.rule_for(commit.approval_class)
        proof_bindings = (
            (proof.policy_commit_receipt_digest, commit.commit_receipt_digest),
            (proof.approval_policy_digest, commit.approval_policy_digest),
            (proof.approval_policy_digest, self.approval_policy.approval_policy_digest),
            (proof.approval_rule_digest, approval_rule.rule_digest),
            (proof.signature_profile_digest, commit.signature_profile_digest),
            (proof.signature_profile_digest, self.signature_profile.profile_digest),
            (
                proof.challenge_classification_policy_digest,
                commit.challenge_classification_policy_digest,
            ),
            (
                proof.challenge_classification_policy_digest,
                self.challenge_classification_policy.policy_digest,
            ),
            (proof.authority_root_digest, commit.authority_root_digest),
            (proof.authority_root_digest, self.policy.authority_root_digest),
            (proof.authority_root_digest, self.approval_policy.authority_root_digest),
            (proof.authority_root_digest, self.signature_profile.key_authority_root_digest),
            (proof.signature_set_digest, commit.signature_set_digest),
        )
        if any(left != right for left, right in proof_bindings):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_ACTIVATION_PROOF_BINDING_MISMATCH"
            )


@dataclass(frozen=True, slots=True)
class ExpectedPolicyLedgerState:
    """Exact observed ledger state; ``None`` is valid only for the empty ledger."""

    ledger_root_digest: str
    head_entry_digest: str | None

    def __post_init__(self) -> None:
        require_digest(
            self.ledger_root_digest,
            "ASSUMPTION_POLICY_EXPECTED_LEDGER_ROOT_INVALID",
        )
        if self.head_entry_digest is None:
            if self.ledger_root_digest != AssumptionPolicyLedgerV2.build(()).ledger_root_digest:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_POLICY_BLIND_EMPTY_EXPECTATION_FORBIDDEN"
                )
            return
        require_digest(
            self.head_entry_digest,
            "ASSUMPTION_POLICY_EXPECTED_LEDGER_HEAD_INVALID",
        )

    @classmethod
    def empty(cls) -> ExpectedPolicyLedgerState:
        ledger = AssumptionPolicyLedgerV2.build(())
        return cls(ledger_root_digest=ledger.ledger_root_digest, head_entry_digest=None)

    @classmethod
    def from_ledger(cls, ledger: AssumptionPolicyLedgerV2) -> ExpectedPolicyLedgerState:
        head = ledger.entries[-1].ledger_entry_digest if ledger.entries else None
        return cls(ledger_root_digest=ledger.ledger_root_digest, head_entry_digest=head)

    @classmethod
    def observed(
        cls,
        *,
        ledger_root_digest: str,
        head_entry_digest: str,
    ) -> ExpectedPolicyLedgerState:
        return cls(
            ledger_root_digest=ledger_root_digest,
            head_entry_digest=head_entry_digest,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": EXPECTED_LEDGER_STATE_SCHEMA_VERSION,
            "head_entry_digest": self.head_entry_digest,
            "ledger_root_digest": self.ledger_root_digest,
        }


@dataclass(frozen=True, slots=True)
class PreparedPolicyActivation:
    """Purely validated entry that makes no publication claim."""

    ledger_entry: AssumptionPolicyLedgerEntryV2
    prepared_digest: str

    def __post_init__(self) -> None:
        require_self_digest(
            "PREPARED_ASSUMPTION_POLICY_ACTIVATION",
            self._unsigned_value(),
            self.prepared_digest,
            "ASSUMPTION_POLICY_PREPARED_ACTIVATION_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        ledger_entry: AssumptionPolicyLedgerEntryV2,
    ) -> PreparedPolicyActivation:
        unsigned = {
            "schema_version": PREPARED_POLICY_ACTIVATION_SCHEMA_VERSION,
            "ledger_entry_digest": ledger_entry.ledger_entry_digest,
        }
        return cls(
            ledger_entry=ledger_entry,
            prepared_digest=domain_digest("PREPARED_ASSUMPTION_POLICY_ACTIVATION", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": PREPARED_POLICY_ACTIVATION_SCHEMA_VERSION,
            "ledger_entry_digest": self.ledger_entry.ledger_entry_digest,
        }


class AssumptionPolicyActivationService(Protocol):
    """Success-only prepare/publish API for the executable A1 implementation."""

    def prepare(
        self,
        *,
        policy: AssumptionAuthorityPolicy,
        commit: AssumptionAuthorityPolicyCommitV2,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
        signature_set: SignatureSet,
    ) -> PreparedPolicyActivation: ...

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerState,
    ) -> AssumptionPolicyActivationResult: ...


def parse_policy_commit_v2(
    value: Mapping[str, JsonValue],
) -> AssumptionAuthorityPolicyCommitV2:
    """Parse an untrusted closed JSON object into the frozen typed commit."""

    if not isinstance(value, Mapping):
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_COMMIT_JSON_INVALID")
    actual_fields = set(value)
    unknown = sorted(actual_fields.difference(_COMMIT_FIELDS))
    missing = sorted(_COMMIT_FIELDS.difference(actual_fields))
    if unknown:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_UNKNOWN_FIELD",
            unknown[0],
        )
    if missing:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_MISSING_FIELD",
            missing[0],
        )
    schema_version = _required_string(value, "schema_version")
    if schema_version != AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
        )
    return AssumptionAuthorityPolicyCommitV2(
        policy_id=_required_string(value, "policy_id"),
        policy_digest=_required_string(value, "policy_digest"),
        predecessor_policy_digest=_optional_string(value, "predecessor_policy_digest"),
        predecessor_commit_receipt_digest=_optional_string(
            value,
            "predecessor_commit_receipt_digest",
        ),
        authority_root_digest=_required_string(value, "authority_root_digest"),
        grant_set_digest=_required_string(value, "grant_set_digest"),
        separation_duty_rule_set_digest=_required_string(
            value,
            "separation_duty_rule_set_digest",
        ),
        exception_set_digest=_required_string(value, "exception_set_digest"),
        exception_count=_required_json_integer(value, "exception_count"),
        approval_class=_required_string(value, "approval_class"),
        effective_from_sequence=_required_json_integer(value, "effective_from_sequence"),
        approval_policy_digest=_required_string(value, "approval_policy_digest"),
        signature_profile_digest=_required_string(value, "signature_profile_digest"),
        challenge_classification_policy_digest=_required_string(
            value,
            "challenge_classification_policy_digest",
        ),
        signature_set_digest=_required_string(value, "signature_set_digest"),
        commit_receipt_digest=_required_string(value, "commit_receipt_digest"),
    )


def compare_and_append_policy_entry(
    *,
    ledger: AssumptionPolicyLedgerV2,
    expected_state: ExpectedPolicyLedgerState,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> tuple[AssumptionPolicyLedgerV2, AssumptionPolicyActivationResult]:
    """Pure reference compare-and-append with deterministic conflict semantics."""

    for existing in ledger.entries:
        classification = classify_exact_idempotence(existing, candidate)
        if classification == "IDEMPOTENT_APPEND":
            result = AssumptionPolicyActivationResult.build(
                append_result="IDEMPOTENT_APPEND",
                policy_commit_receipt_digest=candidate.policy_commit.commit_receipt_digest,
                ledger_entry_digest=candidate.ledger_entry_digest,
                predecessor_ledger_root=ledger.ledger_root_digest,
                resulting_ledger_root=ledger.ledger_root_digest,
            )
            return ledger, result

    actual_state = ExpectedPolicyLedgerState.from_ledger(ledger)
    if expected_state != actual_state:
        if ledger.entries:
            current_head = ledger.entries[-1]
            if (
                candidate.policy_commit.predecessor_commit_receipt_digest
                != current_head.policy_commit.commit_receipt_digest
            ):
                raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_CHAIN_FORK")
        raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH")

    if ledger.entries:
        try:
            validate_successor_position(ledger.entries[-1], candidate)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyPublicationConflict(exc.code, exc.detail) from exc
    elif (
        candidate.policy_commit.predecessor_policy_digest is not None
        or candidate.policy_commit.predecessor_commit_receipt_digest is not None
    ):
        raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_LEDGER_GENESIS_INVALID")

    updated = AssumptionPolicyLedgerV2.build((*ledger.entries, candidate))
    result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=candidate.policy_commit.commit_receipt_digest,
        ledger_entry_digest=candidate.ledger_entry_digest,
        predecessor_ledger_root=ledger.ledger_root_digest,
        resulting_ledger_root=updated.ledger_root_digest,
    )
    return updated, result


def validate_stored_policy_entry_object(
    *,
    claimed_digest: str,
    stored_bytes: bytes,
    parsed_entry: AssumptionPolicyLedgerEntryV2,
) -> None:
    """Reject corrupted storage metadata or bytes without invoking collision claims."""

    require_digest(claimed_digest, "ASSUMPTION_POLICY_STORED_OBJECT_DIGEST_INVALID")
    if (
        claimed_digest != parsed_entry.ledger_entry_digest
        or stored_bytes != parsed_entry.canonical_bytes
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_STORED_OBJECT_DIGEST_MISMATCH"
        )


def _required_string(value: Mapping[str, JsonValue], field: str) -> str:
    selected = value[field]
    if type(selected) is not str:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_FIELD_TYPE_INVALID",
            field,
        )
    return selected


def _optional_string(value: Mapping[str, JsonValue], field: str) -> str | None:
    selected = value[field]
    if selected is None:
        return None
    if type(selected) is not str:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_FIELD_TYPE_INVALID",
            field,
        )
    return selected


def _required_json_integer(value: Mapping[str, JsonValue], field: str) -> int:
    selected = value[field]
    if (
        type(selected) is not int
        or selected < 0
        or selected > MAX_INTEROPERABLE_JSON_INTEGER
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_INTEGER_INVALID",
            field,
        )
    return selected
