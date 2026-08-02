"""D3.2-A0 execution contracts for assumption policy and admission governance."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    POLICY_APPROVAL_CLASSES,
    AssumptionAuthorityPolicy,
    AssumptionAuthorityPolicyCommit,
)
from csd_foundry.governance.v0_5.evidence import (
    EvidenceRegistryError,
    EvidenceUnit,
    project_evidence_history,
)
from csd_foundry.governance.v0_5.registry import RegistryStore, RegistryStoreError

APPROVAL_RULE_SCHEMA_VERSION = "assumption-policy-approval-rule/1"
APPROVAL_POLICY_SCHEMA_VERSION = "assumption-policy-approval-policy/1"
APPROVAL_RECEIPT_SCHEMA_VERSION = "assumption-policy-approval-receipt/1"
POLICY_LEDGER_ENTRY_SCHEMA_VERSION = "assumption-policy-ledger-entry/1"
POLICY_LEDGER_SCHEMA_VERSION = "assumption-policy-ledger/1"
EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION = "evidence-admission-eligibility/1"
APPEND_VALIDATION_TELEMETRY_SCHEMA_VERSION = "assumption-append-validation-telemetry/1"

ASSUMPTION_SAME_HEAD_CONFLICT_CODE = "REGISTRY_SEQUENCE_CONFLICT"
ASSUMPTION_SAME_HEAD_RETRY_POLICY = "REBUILD_AND_REVALIDATE"

EVIDENCE_ADMISSION_CODES = (
    "ASSUMPTION_EVIDENCE_DEPENDENCY_MISSING",
    "ASSUMPTION_EVIDENCE_HISTORY_INVALID",
    "ASSUMPTION_EVIDENCE_NOT_VERIFIED",
    "ASSUMPTION_EVIDENCE_CHALLENGED",
    "ASSUMPTION_EVIDENCE_NOT_YET_VALID",
    "ASSUMPTION_EVIDENCE_EXPIRED",
    "ASSUMPTION_EVIDENCE_TERMINAL",
    "EVIDENCE_ADMISSION_ELIGIBLE",
)

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AssumptionGovernanceExecutionContractError(ValueError):
    """Stable fail-closed error for D3.2-A0 execution contracts."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class AssumptionPolicyApprovalRule:
    """One deterministic unweighted approval rule."""

    approval_class: str
    eligible_signer_ids: tuple[str, ...]
    required_signature_count: int
    required_signer_ids: tuple[str, ...]
    rule_digest: str

    def __post_init__(self) -> None:
        if self.approval_class not in POLICY_APPROVAL_CLASSES:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RULE_CLASS_INVALID"
            )
        _require_sorted_tokens(
            self.eligible_signer_ids,
            "ASSUMPTION_APPROVAL_RULE_ELIGIBLE_SIGNERS_INVALID",
            allow_empty=False,
        )
        if (
            type(self.required_signature_count) is not int
            or self.required_signature_count < 1
            or self.required_signature_count > len(self.eligible_signer_ids)
        ):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RULE_THRESHOLD_INVALID"
            )
        _require_sorted_tokens(
            self.required_signer_ids,
            "ASSUMPTION_APPROVAL_RULE_REQUIRED_SIGNERS_INVALID",
            allow_empty=True,
        )
        if not set(self.required_signer_ids).issubset(self.eligible_signer_ids):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RULE_REQUIRED_SIGNER_INELIGIBLE"
            )
        if len(self.required_signer_ids) > self.required_signature_count:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RULE_REQUIRED_SIGNERS_EXCEED_THRESHOLD"
            )
        _require_self_digest(
            "ASSUMPTION_POLICY_APPROVAL_RULE",
            self._unsigned_value(),
            self.rule_digest,
            "ASSUMPTION_APPROVAL_RULE_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        approval_class: str,
        eligible_signer_ids: tuple[str, ...],
        required_signature_count: int,
        required_signer_ids: tuple[str, ...] = (),
    ) -> AssumptionPolicyApprovalRule:
        eligible = tuple(sorted(eligible_signer_ids))
        required = tuple(sorted(required_signer_ids))
        unsigned = {
            "schema_version": APPROVAL_RULE_SCHEMA_VERSION,
            "approval_class": approval_class,
            "eligible_signer_ids": list(eligible),
            "required_signature_count": required_signature_count,
            "required_signer_ids": list(required),
        }
        return cls(
            approval_class=approval_class,
            eligible_signer_ids=eligible,
            required_signature_count=required_signature_count,
            required_signer_ids=required,
            rule_digest=_domain_digest("ASSUMPTION_POLICY_APPROVAL_RULE", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": APPROVAL_RULE_SCHEMA_VERSION,
            "approval_class": self.approval_class,
            "eligible_signer_ids": list(self.eligible_signer_ids),
            "required_signature_count": self.required_signature_count,
            "required_signer_ids": list(self.required_signer_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "rule_digest": self.rule_digest}


@dataclass(frozen=True, slots=True)
class AssumptionPolicyApprovalPolicy:
    """Closed approval policy with one STANDARD and one DUTY_EXCEPTION rule."""

    approval_policy_id: str
    authority_root_digest: str
    rules: tuple[AssumptionPolicyApprovalRule, ...]
    approval_policy_digest: str

    def __post_init__(self) -> None:
        _require_token(
            self.approval_policy_id,
            "ASSUMPTION_APPROVAL_POLICY_ID_INVALID",
        )
        _require_digest(
            self.authority_root_digest,
            "ASSUMPTION_APPROVAL_POLICY_ROOT_INVALID",
        )
        if type(self.rules) is not tuple:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_RULES_INVALID"
            )
        canonical = tuple(sorted(self.rules, key=lambda item: item.approval_class))
        if self.rules != canonical:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_RULES_NOT_CANONICAL"
            )
        by_class = {item.approval_class: item for item in self.rules}
        if len(by_class) != len(self.rules):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_RULE_DUPLICATE"
            )
        if set(by_class) != set(POLICY_APPROVAL_CLASSES):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_RULE_SET_INCOMPLETE"
            )
        standard = by_class["STANDARD"]
        duty = by_class["DUTY_EXCEPTION"]
        if duty.required_signature_count <= standard.required_signature_count:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_DUTY_THRESHOLD_NOT_STRONGER"
            )
        if not set(duty.required_signer_ids).issuperset(standard.required_signer_ids):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_DUTY_REQUIRED_SIGNERS_NOT_STRONGER"
            )
        if not set(duty.eligible_signer_ids).issubset(standard.eligible_signer_ids):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_POLICY_DUTY_ELIGIBILITY_WIDENED"
            )
        _require_self_digest(
            "ASSUMPTION_POLICY_APPROVAL_POLICY",
            self._unsigned_value(),
            self.approval_policy_digest,
            "ASSUMPTION_APPROVAL_POLICY_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        approval_policy_id: str,
        authority_root_digest: str,
        rules: tuple[AssumptionPolicyApprovalRule, ...],
    ) -> AssumptionPolicyApprovalPolicy:
        canonical = tuple(sorted(rules, key=lambda item: item.approval_class))
        unsigned = {
            "schema_version": APPROVAL_POLICY_SCHEMA_VERSION,
            "approval_policy_id": approval_policy_id,
            "authority_root_digest": authority_root_digest,
            "rules": [item.to_json_value() for item in canonical],
        }
        return cls(
            approval_policy_id=approval_policy_id,
            authority_root_digest=authority_root_digest,
            rules=canonical,
            approval_policy_digest=_domain_digest(
                "ASSUMPTION_POLICY_APPROVAL_POLICY",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": APPROVAL_POLICY_SCHEMA_VERSION,
            "approval_policy_id": self.approval_policy_id,
            "authority_root_digest": self.authority_root_digest,
            "rules": [item.to_json_value() for item in self.rules],
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "approval_policy_digest": self.approval_policy_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())

    def rule_for(self, approval_class: str) -> AssumptionPolicyApprovalRule:
        for rule in self.rules:
            if rule.approval_class == approval_class:
                return rule
        raise AssumptionGovernanceExecutionContractError(
            "ASSUMPTION_APPROVAL_POLICY_RULE_MISSING",
            approval_class,
        )


@dataclass(frozen=True, slots=True)
class AssumptionPolicyApprovalReceipt:
    """Receipt for unique verified signers satisfying one exact approval rule."""

    approval_policy_digest: str
    authority_root_digest: str
    policy_commit_receipt_digest: str
    approval_class: str
    valid_signer_ids: tuple[str, ...]
    signature_set_digest: str
    approval_receipt_digest: str

    def __post_init__(self) -> None:
        _require_digest(
            self.approval_policy_digest,
            "ASSUMPTION_APPROVAL_RECEIPT_POLICY_INVALID",
        )
        _require_digest(
            self.authority_root_digest,
            "ASSUMPTION_APPROVAL_RECEIPT_ROOT_INVALID",
        )
        _require_digest(
            self.policy_commit_receipt_digest,
            "ASSUMPTION_APPROVAL_RECEIPT_COMMIT_INVALID",
        )
        if self.approval_class not in POLICY_APPROVAL_CLASSES:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RECEIPT_CLASS_INVALID"
            )
        _require_sorted_tokens(
            self.valid_signer_ids,
            "ASSUMPTION_APPROVAL_RECEIPT_SIGNERS_INVALID",
            allow_empty=False,
        )
        _require_digest(
            self.signature_set_digest,
            "ASSUMPTION_APPROVAL_RECEIPT_SIGNATURE_SET_INVALID",
        )
        _require_self_digest(
            "ASSUMPTION_POLICY_APPROVAL_RECEIPT",
            self._unsigned_value(),
            self.approval_receipt_digest,
            "ASSUMPTION_APPROVAL_RECEIPT_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        approval_policy: AssumptionPolicyApprovalPolicy,
        policy_commit: AssumptionAuthorityPolicyCommit,
        valid_signer_ids: tuple[str, ...],
        signature_set_digest: str,
    ) -> AssumptionPolicyApprovalReceipt:
        if policy_commit.approval_policy_digest != approval_policy.approval_policy_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RECEIPT_POLICY_MISMATCH"
            )
        if policy_commit.authority_root_digest != approval_policy.authority_root_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RECEIPT_ROOT_MISMATCH"
            )
        if policy_commit.signature_set_digest != signature_set_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_RECEIPT_SIGNATURE_SET_MISMATCH"
            )
        rule = approval_policy.rule_for(policy_commit.approval_class)
        signers = tuple(sorted(set(valid_signer_ids)))
        _require_sorted_tokens(
            signers,
            "ASSUMPTION_APPROVAL_RECEIPT_SIGNERS_INVALID",
            allow_empty=False,
        )
        ineligible = sorted(set(signers).difference(rule.eligible_signer_ids))
        if ineligible:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE",
                ineligible[0],
            )
        if len(signers) < rule.required_signature_count:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET"
            )
        missing_required = sorted(set(rule.required_signer_ids).difference(signers))
        if missing_required:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING",
                missing_required[0],
            )
        unsigned = {
            "schema_version": APPROVAL_RECEIPT_SCHEMA_VERSION,
            "approval_class": policy_commit.approval_class,
            "approval_policy_digest": approval_policy.approval_policy_digest,
            "authority_root_digest": approval_policy.authority_root_digest,
            "policy_commit_receipt_digest": policy_commit.commit_receipt_digest,
            "signature_set_digest": signature_set_digest,
            "valid_signer_ids": list(signers),
        }
        return cls(
            approval_policy_digest=approval_policy.approval_policy_digest,
            authority_root_digest=approval_policy.authority_root_digest,
            policy_commit_receipt_digest=policy_commit.commit_receipt_digest,
            approval_class=policy_commit.approval_class,
            valid_signer_ids=signers,
            signature_set_digest=signature_set_digest,
            approval_receipt_digest=_domain_digest(
                "ASSUMPTION_POLICY_APPROVAL_RECEIPT",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": APPROVAL_RECEIPT_SCHEMA_VERSION,
            "approval_class": self.approval_class,
            "approval_policy_digest": self.approval_policy_digest,
            "authority_root_digest": self.authority_root_digest,
            "policy_commit_receipt_digest": self.policy_commit_receipt_digest,
            "signature_set_digest": self.signature_set_digest,
            "valid_signer_ids": list(self.valid_signer_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "approval_receipt_digest": self.approval_receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedgerEntry:
    """One activated policy generation and its approval proof."""

    policy: AssumptionAuthorityPolicy
    policy_commit: AssumptionAuthorityPolicyCommit
    approval_policy: AssumptionPolicyApprovalPolicy
    approval_receipt: AssumptionPolicyApprovalReceipt
    ledger_entry_digest: str

    def __post_init__(self) -> None:
        commit = self.policy_commit
        if commit.policy_id != self.policy.policy_id:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_POLICY_ID_MISMATCH"
            )
        if commit.policy_digest != self.policy.policy_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_POLICY_DIGEST_MISMATCH"
            )
        if commit.authority_root_digest != self.policy.authority_root_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_AUTHORITY_ROOT_MISMATCH"
            )
        if commit.grant_set_digest != self.policy.grant_set_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_GRANT_SET_MISMATCH"
            )
        if commit.separation_duty_rule_set_digest != self.policy.separation_duty_rule_set_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_DUTY_RULE_SET_MISMATCH"
            )
        if commit.exception_set_digest != self.policy.exception_set_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_EXCEPTION_SET_MISMATCH"
            )
        if commit.exception_count != len(self.policy.duty_exceptions):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_EXCEPTION_COUNT_MISMATCH"
            )
        if commit.approval_policy_digest != self.approval_policy.approval_policy_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_APPROVAL_POLICY_MISMATCH"
            )
        receipt = self.approval_receipt
        if receipt.policy_commit_receipt_digest != commit.commit_receipt_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_APPROVAL_COMMIT_MISMATCH"
            )
        if receipt.approval_policy_digest != commit.approval_policy_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_APPROVAL_RECEIPT_POLICY_MISMATCH"
            )
        if receipt.approval_class != commit.approval_class:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_APPROVAL_CLASS_MISMATCH"
            )
        if receipt.signature_set_digest != commit.signature_set_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_SIGNATURE_SET_MISMATCH"
            )
        _validate_receipt_threshold(self.approval_policy, receipt)
        _require_self_digest(
            "ASSUMPTION_POLICY_LEDGER_ENTRY",
            self._unsigned_value(),
            self.ledger_entry_digest,
            "ASSUMPTION_POLICY_LEDGER_ENTRY_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy: AssumptionAuthorityPolicy,
        policy_commit: AssumptionAuthorityPolicyCommit,
        approval_policy: AssumptionPolicyApprovalPolicy,
        approval_receipt: AssumptionPolicyApprovalReceipt,
    ) -> AssumptionPolicyLedgerEntry:
        unsigned = {
            "schema_version": POLICY_LEDGER_ENTRY_SCHEMA_VERSION,
            "approval_policy": approval_policy.to_json_value(),
            "approval_receipt": approval_receipt.to_json_value(),
            "policy": policy.to_json_value(),
            "policy_commit": policy_commit.to_json_value(),
        }
        return cls(
            policy=policy,
            policy_commit=policy_commit,
            approval_policy=approval_policy,
            approval_receipt=approval_receipt,
            ledger_entry_digest=_domain_digest(
                "ASSUMPTION_POLICY_LEDGER_ENTRY",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_ENTRY_SCHEMA_VERSION,
            "approval_policy": self.approval_policy.to_json_value(),
            "approval_receipt": self.approval_receipt.to_json_value(),
            "policy": self.policy.to_json_value(),
            "policy_commit": self.policy_commit.to_json_value(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "ledger_entry_digest": self.ledger_entry_digest,
        }


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedger:
    """Validated linear policy chain with half-open policy-at-event lookup."""

    entries: tuple[AssumptionPolicyLedgerEntry, ...]
    ledger_root_digest: str

    def __post_init__(self) -> None:
        ordered = _order_policy_entries(self.entries)
        if self.entries != ordered:
            raise AssumptionGovernanceExecutionContractError(
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
        entries: tuple[AssumptionPolicyLedgerEntry, ...],
    ) -> AssumptionPolicyLedger:
        ordered = _order_policy_entries(entries)
        unsigned = {
            "schema_version": POLICY_LEDGER_SCHEMA_VERSION,
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
            "schema_version": POLICY_LEDGER_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in self.entries],
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "ledger_root_digest": self.ledger_root_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())

    @property
    def current_entry(self) -> AssumptionPolicyLedgerEntry:
        return self.entries[-1]

    def resolve_at(self, clock_sequence: int) -> AssumptionPolicyLedgerEntry:
        if type(clock_sequence) is not int or clock_sequence < 0:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"
            )
        for entry in reversed(self.entries):
            if entry.policy_commit.effective_from_sequence <= clock_sequence:
                return entry
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_NOT_ACTIVE")


@dataclass(frozen=True, slots=True)
class EvidenceAdmissionEligibilityDecision:
    """Structural and current-status evidence gate for assumption admission."""

    eligible: bool
    code: str
    evidence_id: str
    evaluated_at_sequence: int
    evidence_registry_root: str
    current_event_digest: str | None
    current_status: str | None
    decision_digest: str

    def __post_init__(self) -> None:
        if type(self.eligible) is not bool:
            raise AssumptionGovernanceExecutionContractError(
                "EVIDENCE_ADMISSION_ELIGIBILITY_FLAG_INVALID"
            )
        if self.code not in EVIDENCE_ADMISSION_CODES:
            raise AssumptionGovernanceExecutionContractError(
                "EVIDENCE_ADMISSION_ELIGIBILITY_CODE_INVALID"
            )
        if self.eligible != (self.code == "EVIDENCE_ADMISSION_ELIGIBLE"):
            raise AssumptionGovernanceExecutionContractError(
                "EVIDENCE_ADMISSION_ELIGIBILITY_RESULT_MISMATCH"
            )
        _require_token(
            self.evidence_id,
            "EVIDENCE_ADMISSION_ELIGIBILITY_ID_INVALID",
        )
        if type(self.evaluated_at_sequence) is not int or self.evaluated_at_sequence < 0:
            raise AssumptionGovernanceExecutionContractError(
                "EVIDENCE_ADMISSION_ELIGIBILITY_SEQUENCE_INVALID"
            )
        _require_digest(
            self.evidence_registry_root,
            "EVIDENCE_ADMISSION_ELIGIBILITY_ROOT_INVALID",
        )
        if self.current_event_digest is not None:
            _require_digest(
                self.current_event_digest,
                "EVIDENCE_ADMISSION_ELIGIBILITY_EVENT_INVALID",
            )
        if self.current_status is not None:
            _require_token(
                self.current_status,
                "EVIDENCE_ADMISSION_ELIGIBILITY_STATUS_INVALID",
            )
        _require_self_digest(
            "EVIDENCE_ADMISSION_ELIGIBILITY",
            self._unsigned_value(),
            self.decision_digest,
            "EVIDENCE_ADMISSION_ELIGIBILITY_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        eligible: bool,
        code: str,
        evidence_id: str,
        evaluated_at_sequence: int,
        evidence_registry_root: str,
        current_event_digest: str | None,
        current_status: str | None,
    ) -> EvidenceAdmissionEligibilityDecision:
        unsigned = {
            "schema_version": EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION,
            "code": code,
            "current_event_digest": current_event_digest,
            "current_status": current_status,
            "eligible": eligible,
            "evaluated_at_sequence": evaluated_at_sequence,
            "evidence_id": evidence_id,
            "evidence_registry_root": evidence_registry_root,
        }
        return cls(
            eligible=eligible,
            code=code,
            evidence_id=evidence_id,
            evaluated_at_sequence=evaluated_at_sequence,
            evidence_registry_root=evidence_registry_root,
            current_event_digest=current_event_digest,
            current_status=current_status,
            decision_digest=_domain_digest(
                "EVIDENCE_ADMISSION_ELIGIBILITY",
                unsigned,
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_ADMISSION_ELIGIBILITY_SCHEMA_VERSION,
            "code": self.code,
            "current_event_digest": self.current_event_digest,
            "current_status": self.current_status,
            "eligible": self.eligible,
            "evaluated_at_sequence": self.evaluated_at_sequence,
            "evidence_id": self.evidence_id,
            "evidence_registry_root": self.evidence_registry_root,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "decision_digest": self.decision_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssumptionAppendValidationTelemetry:
    """Non-normative append-path measurements excluded from receipt digests."""

    entity_events_replayed: int
    policy_commits_traversed: int
    authority_decisions_recomputed: int
    dependency_nodes_examined: int
    append_validation_duration_ns: int

    def __post_init__(self) -> None:
        for value in (
            self.entity_events_replayed,
            self.policy_commits_traversed,
            self.authority_decisions_recomputed,
            self.dependency_nodes_examined,
            self.append_validation_duration_ns,
        ):
            if type(value) is not int or value < 0:
                raise AssumptionGovernanceExecutionContractError(
                    "ASSUMPTION_APPEND_TELEMETRY_VALUE_INVALID"
                )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": APPEND_VALIDATION_TELEMETRY_SCHEMA_VERSION,
            "append_validation_duration_ns": self.append_validation_duration_ns,
            "authority_decisions_recomputed": self.authority_decisions_recomputed,
            "dependency_nodes_examined": self.dependency_nodes_examined,
            "entity_events_replayed": self.entity_events_replayed,
            "policy_commits_traversed": self.policy_commits_traversed,
        }


def evaluate_evidence_admission_eligibility(
    *,
    store: RegistryStore,
    evidence_id: str,
    evaluated_at_sequence: int,
) -> EvidenceAdmissionEligibilityDecision:
    """Evaluate the D3.2-A structural/current-status evidence admission gate."""

    _require_token(evidence_id, "EVIDENCE_ADMISSION_ELIGIBILITY_ID_INVALID")
    if type(evaluated_at_sequence) is not int or evaluated_at_sequence < 0:
        raise AssumptionGovernanceExecutionContractError(
            "EVIDENCE_ADMISSION_ELIGIBILITY_SEQUENCE_INVALID"
        )
    root = store.snapshot("EVIDENCE_UNIT").root_digest
    history = store.reconstruct_entity("EVIDENCE_UNIT", evidence_id)
    if not history:
        return EvidenceAdmissionEligibilityDecision.build(
            eligible=False,
            code="ASSUMPTION_EVIDENCE_DEPENDENCY_MISSING",
            evidence_id=evidence_id,
            evaluated_at_sequence=evaluated_at_sequence,
            evidence_registry_root=root,
            current_event_digest=None,
            current_status=None,
        )
    try:
        current = project_evidence_history(history)
    except (EvidenceRegistryError, RegistryStoreError):
        return EvidenceAdmissionEligibilityDecision.build(
            eligible=False,
            code="ASSUMPTION_EVIDENCE_HISTORY_INVALID",
            evidence_id=evidence_id,
            evaluated_at_sequence=evaluated_at_sequence,
            evidence_registry_root=root,
            current_event_digest=history[-1].digest,
            current_status=None,
        )
    if current is None:
        return EvidenceAdmissionEligibilityDecision.build(
            eligible=False,
            code="ASSUMPTION_EVIDENCE_HISTORY_INVALID",
            evidence_id=evidence_id,
            evaluated_at_sequence=evaluated_at_sequence,
            evidence_registry_root=root,
            current_event_digest=history[-1].digest,
            current_status=None,
        )
    return _evaluate_current_evidence(
        current=current,
        evaluated_at_sequence=evaluated_at_sequence,
        evidence_registry_root=root,
    )


def _evaluate_current_evidence(
    *,
    current: EvidenceUnit,
    evaluated_at_sequence: int,
    evidence_registry_root: str,
) -> EvidenceAdmissionEligibilityDecision:
    code: str
    eligible = False
    if current.status == "REGISTERED":
        code = "ASSUMPTION_EVIDENCE_NOT_VERIFIED"
    elif current.status == "CHALLENGED":
        code = "ASSUMPTION_EVIDENCE_CHALLENGED"
    elif current.status == "EXPIRED":
        code = "ASSUMPTION_EVIDENCE_EXPIRED"
    elif current.status in {"INVALIDATED", "REJECTED", "SUPERSEDED"}:
        code = "ASSUMPTION_EVIDENCE_TERMINAL"
    elif current.status != "VERIFIED":
        code = "ASSUMPTION_EVIDENCE_HISTORY_INVALID"
    elif evaluated_at_sequence < current.valid_from_sequence:
        code = "ASSUMPTION_EVIDENCE_NOT_YET_VALID"
    elif (
        current.expires_at_sequence is not None
        and evaluated_at_sequence >= current.expires_at_sequence
    ):
        code = "ASSUMPTION_EVIDENCE_EXPIRED"
    else:
        eligible = True
        code = "EVIDENCE_ADMISSION_ELIGIBLE"
    return EvidenceAdmissionEligibilityDecision.build(
        eligible=eligible,
        code=code,
        evidence_id=current.evidence_id,
        evaluated_at_sequence=evaluated_at_sequence,
        evidence_registry_root=evidence_registry_root,
        current_event_digest=current.current_event_digest,
        current_status=current.status,
    )


def _validate_receipt_threshold(
    approval_policy: AssumptionPolicyApprovalPolicy,
    receipt: AssumptionPolicyApprovalReceipt,
) -> None:
    rule = approval_policy.rule_for(receipt.approval_class)
    signers = set(receipt.valid_signer_ids)
    if not signers.issubset(rule.eligible_signer_ids):
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE")
    if len(signers) < rule.required_signature_count:
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET")
    if not set(rule.required_signer_ids).issubset(signers):
        raise AssumptionGovernanceExecutionContractError(
            "ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING"
        )


def _order_policy_entries(
    entries: tuple[AssumptionPolicyLedgerEntry, ...],
) -> tuple[AssumptionPolicyLedgerEntry, ...]:
    if type(entries) is not tuple or not entries:
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_LEDGER_EMPTY")
    by_commit: dict[str, AssumptionPolicyLedgerEntry] = {}
    for entry in entries:
        digest = entry.policy_commit.commit_receipt_digest
        if digest in by_commit:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_LEDGER_COMMIT_DUPLICATE"
            )
        by_commit[digest] = entry

    genesis = [
        entry for entry in entries if entry.policy_commit.predecessor_commit_receipt_digest is None
    ]
    if len(genesis) != 1:
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_CHAIN_GENESIS_INVALID")

    children: dict[str, list[AssumptionPolicyLedgerEntry]] = {}
    for entry in entries:
        commit = entry.policy_commit
        predecessor = commit.predecessor_commit_receipt_digest
        if predecessor is None:
            if commit.predecessor_policy_digest is not None:
                raise AssumptionGovernanceExecutionContractError(
                    "ASSUMPTION_POLICY_PREDECESSOR_CONFLICT"
                )
            continue
        parent = by_commit.get(predecessor)
        if parent is None:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_PREDECESSOR_MISSING"
            )
        if commit.predecessor_policy_digest != parent.policy.policy_digest:
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_PREDECESSOR_CONFLICT"
            )
        children.setdefault(predecessor, []).append(entry)

    for sibling_set in children.values():
        if len(sibling_set) > 1:
            raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_CHAIN_FORK")

    ordered: list[AssumptionPolicyLedgerEntry] = []
    current = genesis[0]
    seen: set[str] = set()
    while True:
        digest = current.policy_commit.commit_receipt_digest
        if digest in seen:
            raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_CHAIN_INVALID")
        seen.add(digest)
        ordered.append(current)
        child_set = children.get(digest, [])
        if not child_set:
            break
        child = child_set[0]
        if (
            child.policy_commit.effective_from_sequence
            <= current.policy_commit.effective_from_sequence
        ):
            raise AssumptionGovernanceExecutionContractError(
                "ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING"
            )
        current = child

    if len(seen) != len(entries):
        raise AssumptionGovernanceExecutionContractError("ASSUMPTION_POLICY_CHAIN_INVALID")
    return tuple(ordered)


def _require_sorted_tokens(
    values: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool,
) -> None:
    if type(values) is not tuple:
        raise AssumptionGovernanceExecutionContractError(code)
    if not allow_empty and not values:
        raise AssumptionGovernanceExecutionContractError(code)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise AssumptionGovernanceExecutionContractError(code)
    for value in values:
        _require_token(value, code)


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AssumptionGovernanceExecutionContractError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AssumptionGovernanceExecutionContractError(code)


def _require_self_digest(
    domain: str,
    value: object,
    observed: str,
    code: str,
) -> None:
    _require_digest(observed, code)
    if observed != _domain_digest(domain, value):
        raise AssumptionGovernanceExecutionContractError(code)


def _domain_digest(domain: str, value: object) -> str:
    return (
        "sha256:" + hashlib.sha256(domain.encode("utf-8") + b"\0" + _json_bytes(value)).hexdigest()
    )


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
