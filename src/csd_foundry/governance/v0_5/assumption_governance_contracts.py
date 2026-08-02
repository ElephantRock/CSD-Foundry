"""Frozen internal governance contracts for the v0.5-D3.2 assumption registry."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

AUTHORITY_GRANT_SCHEMA_VERSION = "assumption-authority-grant/1"
SEPARATION_DUTY_RULE_SCHEMA_VERSION = "assumption-separation-duty-rule/1"
DUTY_EXCEPTION_SCHEMA_VERSION = "assumption-duty-exception/1"
AUTHORITY_POLICY_SCHEMA_VERSION = "assumption-authority-policy/1"
AUTHORITY_POLICY_COMMIT_SCHEMA_VERSION = "assumption-authority-policy-commit/1"
DECISION_ASSUMPTION_BINDING_SCHEMA_VERSION = "decision-assumption-binding/1"
ASSUMPTION_EVALUATION_WORK_SCHEMA_VERSION = "assumption-evaluation-work/1"
RESOLUTION_AUTHORITY_BINDING_SCHEMA_VERSION = "assumption-resolution-authority-binding/1"

ASSUMPTION_EVALUATION_PHASES = (
    "SELF_HISTORY",
    "ACTIVE_CHALLENGES",
    "ASSUMPTION_DEPENDENCIES",
    "EVIDENCE_DEPENDENCIES",
)

ASSUMPTION_AUTHORITY_ACTIONS = (
    "ADMIT",
    "CHALLENGE",
    "CONFIRM",
    "EXPIRE",
    "PROPOSE",
    "REJECT",
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
    "SUPERSEDE",
)

RESOLUTION_AUTHORITY_ACTIONS = (
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
)

ASSUMPTION_GOVERNANCE_ROLES = (
    "ADMITTER",
    "CHALLENGER",
    "CONFIRMER",
    "EXPIRY_AUTHORITY",
    "PROPOSER",
    "REJECTOR",
    "RESOLVER",
    "SUPERSEDER",
)

ASSUMPTION_MATERIALITIES = ("ADVISORY", "MATERIAL", "CRITICAL")
GLOBAL_ASSUMPTION_SCOPE = "scope:*"

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MATERIALITY_RANK = {value: index for index, value in enumerate(ASSUMPTION_MATERIALITIES)}


class AssumptionGovernanceContractError(ValueError):
    """Stable fail-closed error raised by the D3.2-0 contract layer."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class AssumptionAuthorityGrant:
    """Exact authority, action, scope, materiality, and logical-time grant."""

    grant_id: str
    action: str
    authority_id: str
    scope_ids: tuple[str, ...]
    assumption_materialities: tuple[str, ...]
    challenge_materialities: tuple[str, ...]
    effective_from_sequence: int
    effective_until_sequence: int | None
    grant_digest: str

    def __post_init__(self) -> None:
        _require_token(self.grant_id, "ASSUMPTION_AUTHORITY_GRANT_ID_INVALID")
        _require_action(self.action, "ASSUMPTION_AUTHORITY_GRANT_ACTION_INVALID")
        _require_token(self.authority_id, "ASSUMPTION_AUTHORITY_GRANT_AUTHORITY_INVALID")
        _require_canonical_scopes(self.scope_ids, "ASSUMPTION_AUTHORITY_GRANT_SCOPE_INVALID")
        _require_materialities(
            self.assumption_materialities,
            "ASSUMPTION_AUTHORITY_GRANT_MATERIALITY_INVALID",
            allow_empty=False,
        )
        _require_materialities(
            self.challenge_materialities,
            "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_INVALID",
            allow_empty=self.action not in RESOLUTION_AUTHORITY_ACTIONS,
        )
        if self.action in RESOLUTION_AUTHORITY_ACTIONS and not self.challenge_materialities:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_REQUIRED"
            )
        if self.action not in RESOLUTION_AUTHORITY_ACTIONS and self.challenge_materialities:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_UNEXPECTED"
            )
        _require_effective_interval(
            self.effective_from_sequence,
            self.effective_until_sequence,
            "ASSUMPTION_AUTHORITY_GRANT_INTERVAL_INVALID",
        )
        _require_self_digest(
            "ASSUMPTION_AUTHORITY_GRANT",
            self._unsigned_value(),
            self.grant_digest,
            "ASSUMPTION_AUTHORITY_GRANT_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        grant_id: str,
        action: str,
        authority_id: str,
        scope_ids: tuple[str, ...],
        assumption_materialities: tuple[str, ...],
        challenge_materialities: tuple[str, ...] = (),
        effective_from_sequence: int,
        effective_until_sequence: int | None = None,
    ) -> AssumptionAuthorityGrant:
        canonical_scopes = _canonical_scopes(scope_ids)
        canonical_assumption_materialities = _canonical_materialities(assumption_materialities)
        canonical_challenge_materialities = _canonical_materialities(challenge_materialities)
        unsigned = {
            "schema_version": AUTHORITY_GRANT_SCHEMA_VERSION,
            "action": action,
            "assumption_materialities": list(canonical_assumption_materialities),
            "authority_id": authority_id,
            "challenge_materialities": list(canonical_challenge_materialities),
            "effective_from_sequence": effective_from_sequence,
            "effective_until_sequence": effective_until_sequence,
            "grant_id": grant_id,
            "scope_ids": list(canonical_scopes),
        }
        return cls(
            grant_id=grant_id,
            action=action,
            authority_id=authority_id,
            scope_ids=canonical_scopes,
            assumption_materialities=canonical_assumption_materialities,
            challenge_materialities=canonical_challenge_materialities,
            effective_from_sequence=effective_from_sequence,
            effective_until_sequence=effective_until_sequence,
            grant_digest=_domain_digest("ASSUMPTION_AUTHORITY_GRANT", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_GRANT_SCHEMA_VERSION,
            "action": self.action,
            "assumption_materialities": list(self.assumption_materialities),
            "authority_id": self.authority_id,
            "challenge_materialities": list(self.challenge_materialities),
            "effective_from_sequence": self.effective_from_sequence,
            "effective_until_sequence": self.effective_until_sequence,
            "grant_id": self.grant_id,
            "scope_ids": list(self.scope_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "grant_digest": self.grant_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssumptionSeparationDutyRule:
    """One policy rule prohibiting an action actor from conflicting prior roles."""

    rule_id: str
    action: str
    conflicting_roles: tuple[str, ...]
    scope_ids: tuple[str, ...]
    assumption_materialities: tuple[str, ...]
    rule_digest: str

    def __post_init__(self) -> None:
        _require_token(self.rule_id, "ASSUMPTION_DUTY_RULE_ID_INVALID")
        _require_action(self.action, "ASSUMPTION_DUTY_RULE_ACTION_INVALID")
        _require_sorted_members(
            self.conflicting_roles,
            ASSUMPTION_GOVERNANCE_ROLES,
            "ASSUMPTION_DUTY_RULE_ROLE_INVALID",
            allow_empty=False,
        )
        _require_canonical_scopes(self.scope_ids, "ASSUMPTION_DUTY_RULE_SCOPE_INVALID")
        _require_materialities(
            self.assumption_materialities,
            "ASSUMPTION_DUTY_RULE_MATERIALITY_INVALID",
            allow_empty=False,
        )
        _require_self_digest(
            "ASSUMPTION_SEPARATION_DUTY_RULE",
            self._unsigned_value(),
            self.rule_digest,
            "ASSUMPTION_DUTY_RULE_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        rule_id: str,
        action: str,
        conflicting_roles: tuple[str, ...],
        scope_ids: tuple[str, ...],
        assumption_materialities: tuple[str, ...],
    ) -> AssumptionSeparationDutyRule:
        canonical_roles = tuple(sorted(conflicting_roles))
        canonical_scopes = _canonical_scopes(scope_ids)
        canonical_materialities = _canonical_materialities(assumption_materialities)
        unsigned = {
            "schema_version": SEPARATION_DUTY_RULE_SCHEMA_VERSION,
            "action": action,
            "assumption_materialities": list(canonical_materialities),
            "conflicting_roles": list(canonical_roles),
            "rule_id": rule_id,
            "scope_ids": list(canonical_scopes),
        }
        return cls(
            rule_id=rule_id,
            action=action,
            conflicting_roles=canonical_roles,
            scope_ids=canonical_scopes,
            assumption_materialities=canonical_materialities,
            rule_digest=_domain_digest("ASSUMPTION_SEPARATION_DUTY_RULE", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": SEPARATION_DUTY_RULE_SCHEMA_VERSION,
            "action": self.action,
            "assumption_materialities": list(self.assumption_materialities),
            "conflicting_roles": list(self.conflicting_roles),
            "rule_id": self.rule_id,
            "scope_ids": list(self.scope_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "rule_digest": self.rule_digest}


@dataclass(frozen=True, slots=True)
class AssumptionDutyException:
    """Narrow, logical-time-bounded exception to a separation-of-duty rule."""

    exception_id: str
    rule_id: str
    action: str
    authority_id: str
    conflicting_roles: tuple[str, ...]
    scope_ids: tuple[str, ...]
    assumption_ids: tuple[str, ...]
    assumption_materialities: tuple[str, ...]
    reason_code: str
    effective_from_sequence: int
    effective_until_sequence: int
    exception_digest: str

    def __post_init__(self) -> None:
        _require_token(self.exception_id, "ASSUMPTION_DUTY_EXCEPTION_ID_INVALID")
        _require_token(self.rule_id, "ASSUMPTION_DUTY_EXCEPTION_RULE_ID_INVALID")
        _require_action(self.action, "ASSUMPTION_DUTY_EXCEPTION_ACTION_INVALID")
        _require_token(self.authority_id, "ASSUMPTION_DUTY_EXCEPTION_AUTHORITY_INVALID")
        _require_sorted_members(
            self.conflicting_roles,
            ASSUMPTION_GOVERNANCE_ROLES,
            "ASSUMPTION_DUTY_EXCEPTION_ROLE_INVALID",
            allow_empty=False,
        )
        _require_canonical_scopes(self.scope_ids, "ASSUMPTION_DUTY_EXCEPTION_SCOPE_INVALID")
        _require_sorted_tokens(
            self.assumption_ids,
            "ASSUMPTION_DUTY_EXCEPTION_ASSUMPTION_INVALID",
            allow_empty=True,
        )
        _require_materialities(
            self.assumption_materialities,
            "ASSUMPTION_DUTY_EXCEPTION_MATERIALITY_INVALID",
            allow_empty=False,
        )
        _require_token(self.reason_code, "ASSUMPTION_DUTY_EXCEPTION_REASON_INVALID")
        _require_effective_interval(
            self.effective_from_sequence,
            self.effective_until_sequence,
            "ASSUMPTION_DUTY_EXCEPTION_INTERVAL_INVALID",
        )
        _require_self_digest(
            "ASSUMPTION_DUTY_EXCEPTION",
            self._unsigned_value(),
            self.exception_digest,
            "ASSUMPTION_DUTY_EXCEPTION_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        exception_id: str,
        rule_id: str,
        action: str,
        authority_id: str,
        conflicting_roles: tuple[str, ...],
        scope_ids: tuple[str, ...],
        assumption_ids: tuple[str, ...],
        assumption_materialities: tuple[str, ...],
        reason_code: str,
        effective_from_sequence: int,
        effective_until_sequence: int,
    ) -> AssumptionDutyException:
        canonical_roles = tuple(sorted(conflicting_roles))
        canonical_scopes = _canonical_scopes(scope_ids)
        canonical_assumption_ids = tuple(sorted(assumption_ids))
        canonical_materialities = _canonical_materialities(assumption_materialities)
        unsigned = {
            "schema_version": DUTY_EXCEPTION_SCHEMA_VERSION,
            "action": action,
            "assumption_ids": list(canonical_assumption_ids),
            "assumption_materialities": list(canonical_materialities),
            "authority_id": authority_id,
            "conflicting_roles": list(canonical_roles),
            "effective_from_sequence": effective_from_sequence,
            "effective_until_sequence": effective_until_sequence,
            "exception_id": exception_id,
            "reason_code": reason_code,
            "rule_id": rule_id,
            "scope_ids": list(canonical_scopes),
        }
        return cls(
            exception_id=exception_id,
            rule_id=rule_id,
            action=action,
            authority_id=authority_id,
            conflicting_roles=canonical_roles,
            scope_ids=canonical_scopes,
            assumption_ids=canonical_assumption_ids,
            assumption_materialities=canonical_materialities,
            reason_code=reason_code,
            effective_from_sequence=effective_from_sequence,
            effective_until_sequence=effective_until_sequence,
            exception_digest=_domain_digest("ASSUMPTION_DUTY_EXCEPTION", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": DUTY_EXCEPTION_SCHEMA_VERSION,
            "action": self.action,
            "assumption_ids": list(self.assumption_ids),
            "assumption_materialities": list(self.assumption_materialities),
            "authority_id": self.authority_id,
            "conflicting_roles": list(self.conflicting_roles),
            "effective_from_sequence": self.effective_from_sequence,
            "effective_until_sequence": self.effective_until_sequence,
            "exception_id": self.exception_id,
            "reason_code": self.reason_code,
            "rule_id": self.rule_id,
            "scope_ids": list(self.scope_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "exception_digest": self.exception_digest}


@dataclass(frozen=True, slots=True)
class AssumptionAuthorityPolicy:
    """Canonical policy content; activation requires a separate commit receipt."""

    policy_id: str
    authority_root_digest: str
    grants: tuple[AssumptionAuthorityGrant, ...]
    separation_duty_rules: tuple[AssumptionSeparationDutyRule, ...]
    duty_exceptions: tuple[AssumptionDutyException, ...]
    grant_set_digest: str
    separation_duty_rule_set_digest: str
    exception_set_digest: str
    policy_digest: str

    def __post_init__(self) -> None:
        _require_token(self.policy_id, "ASSUMPTION_AUTHORITY_POLICY_ID_INVALID")
        _require_digest(self.authority_root_digest, "ASSUMPTION_AUTHORITY_ROOT_INVALID")
        _require_canonical_objects(
            self.grants,
            lambda item: item.grant_id,
            "ASSUMPTION_AUTHORITY_GRANTS_NOT_CANONICAL",
            allow_empty=False,
        )
        _require_canonical_objects(
            self.separation_duty_rules,
            lambda item: item.rule_id,
            "ASSUMPTION_DUTY_RULES_NOT_CANONICAL",
            allow_empty=True,
        )
        _require_canonical_objects(
            self.duty_exceptions,
            lambda item: item.exception_id,
            "ASSUMPTION_DUTY_EXCEPTIONS_NOT_CANONICAL",
            allow_empty=True,
        )
        expected_grants = _set_digest(
            "ASSUMPTION_AUTHORITY_GRANT_SET",
            [item.to_json_value() for item in self.grants],
        )
        if self.grant_set_digest != expected_grants:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_AUTHORITY_GRANT_SET_DIGEST_MISMATCH"
            )
        expected_rules = _set_digest(
            "ASSUMPTION_SEPARATION_DUTY_RULE_SET",
            [item.to_json_value() for item in self.separation_duty_rules],
        )
        if self.separation_duty_rule_set_digest != expected_rules:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_DUTY_RULE_SET_DIGEST_MISMATCH"
            )
        expected_exceptions = _set_digest(
            "ASSUMPTION_DUTY_EXCEPTION_SET",
            [item.to_json_value() for item in self.duty_exceptions],
        )
        if self.exception_set_digest != expected_exceptions:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_DUTY_EXCEPTION_SET_DIGEST_MISMATCH"
            )
        rules_by_id = {item.rule_id: item for item in self.separation_duty_rules}
        for exception in self.duty_exceptions:
            rule = rules_by_id.get(exception.rule_id)
            if rule is None:
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_DUTY_EXCEPTION_RULE_MISSING",
                    exception.rule_id,
                )
            if exception.action != rule.action:
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_DUTY_EXCEPTION_ACTION_MISMATCH",
                    exception.exception_id,
                )
            if not set(exception.conflicting_roles).issubset(rule.conflicting_roles):
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_DUTY_EXCEPTION_ROLE_WIDENING",
                    exception.exception_id,
                )
            if not _scope_is_subset(exception.scope_ids, rule.scope_ids):
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_DUTY_EXCEPTION_SCOPE_WIDENING",
                    exception.exception_id,
                )
            if not set(exception.assumption_materialities).issubset(
                rule.assumption_materialities
            ):
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_DUTY_EXCEPTION_MATERIALITY_WIDENING",
                    exception.exception_id,
                )
        _require_self_digest(
            "ASSUMPTION_AUTHORITY_POLICY",
            self._unsigned_value(),
            self.policy_digest,
            "ASSUMPTION_AUTHORITY_POLICY_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy_id: str,
        authority_root_digest: str,
        grants: tuple[AssumptionAuthorityGrant, ...],
        separation_duty_rules: tuple[AssumptionSeparationDutyRule, ...] = (),
        duty_exceptions: tuple[AssumptionDutyException, ...] = (),
    ) -> AssumptionAuthorityPolicy:
        canonical_grants = tuple(sorted(grants, key=lambda item: item.grant_id))
        canonical_rules = tuple(
            sorted(separation_duty_rules, key=lambda item: item.rule_id)
        )
        canonical_exceptions = tuple(
            sorted(duty_exceptions, key=lambda item: item.exception_id)
        )
        grant_set_digest = _set_digest(
            "ASSUMPTION_AUTHORITY_GRANT_SET",
            [item.to_json_value() for item in canonical_grants],
        )
        rule_set_digest = _set_digest(
            "ASSUMPTION_SEPARATION_DUTY_RULE_SET",
            [item.to_json_value() for item in canonical_rules],
        )
        exception_set_digest = _set_digest(
            "ASSUMPTION_DUTY_EXCEPTION_SET",
            [item.to_json_value() for item in canonical_exceptions],
        )
        unsigned = {
            "schema_version": AUTHORITY_POLICY_SCHEMA_VERSION,
            "authority_root_digest": authority_root_digest,
            "duty_exceptions": [item.to_json_value() for item in canonical_exceptions],
            "exception_set_digest": exception_set_digest,
            "grant_set_digest": grant_set_digest,
            "grants": [item.to_json_value() for item in canonical_grants],
            "policy_id": policy_id,
            "separation_duty_rule_set_digest": rule_set_digest,
            "separation_duty_rules": [item.to_json_value() for item in canonical_rules],
        }
        return cls(
            policy_id=policy_id,
            authority_root_digest=authority_root_digest,
            grants=canonical_grants,
            separation_duty_rules=canonical_rules,
            duty_exceptions=canonical_exceptions,
            grant_set_digest=grant_set_digest,
            separation_duty_rule_set_digest=rule_set_digest,
            exception_set_digest=exception_set_digest,
            policy_digest=_domain_digest("ASSUMPTION_AUTHORITY_POLICY", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_POLICY_SCHEMA_VERSION,
            "authority_root_digest": self.authority_root_digest,
            "duty_exceptions": [item.to_json_value() for item in self.duty_exceptions],
            "exception_set_digest": self.exception_set_digest,
            "grant_set_digest": self.grant_set_digest,
            "grants": [item.to_json_value() for item in self.grants],
            "policy_id": self.policy_id,
            "separation_duty_rule_set_digest": self.separation_duty_rule_set_digest,
            "separation_duty_rules": [
                item.to_json_value() for item in self.separation_duty_rules
            ],
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "policy_digest": self.policy_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssumptionAuthorityPolicyCommit:
    """Independently authorized activation receipt for one policy version."""

    policy_id: str
    policy_digest: str
    predecessor_policy_digest: str | None
    predecessor_commit_receipt_digest: str | None
    authority_root_digest: str
    grant_set_digest: str
    separation_duty_rule_set_digest: str
    exception_set_digest: str
    effective_from_sequence: int
    approval_policy_digest: str
    signature_set_digest: str
    commit_receipt_digest: str

    def __post_init__(self) -> None:
        _require_token(self.policy_id, "ASSUMPTION_POLICY_COMMIT_POLICY_ID_INVALID")
        _require_digest(self.policy_digest, "ASSUMPTION_POLICY_COMMIT_POLICY_DIGEST_INVALID")
        if (self.predecessor_policy_digest is None) != (
            self.predecessor_commit_receipt_digest is None
        ):
            raise AssumptionGovernanceContractError(
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
        _require_digest(self.authority_root_digest, "ASSUMPTION_POLICY_COMMIT_ROOT_INVALID")
        _require_digest(self.grant_set_digest, "ASSUMPTION_POLICY_COMMIT_GRANT_SET_INVALID")
        _require_digest(
            self.separation_duty_rule_set_digest,
            "ASSUMPTION_POLICY_COMMIT_RULE_SET_INVALID",
        )
        _require_digest(
            self.exception_set_digest,
            "ASSUMPTION_POLICY_COMMIT_EXCEPTION_SET_INVALID",
        )
        if type(self.effective_from_sequence) is not int or self.effective_from_sequence < 0:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_POLICY_COMMIT_EFFECTIVE_SEQUENCE_INVALID"
            )
        _require_digest(
            self.approval_policy_digest,
            "ASSUMPTION_POLICY_COMMIT_APPROVAL_POLICY_INVALID",
        )
        _require_digest(
            self.signature_set_digest,
            "ASSUMPTION_POLICY_COMMIT_SIGNATURE_SET_INVALID",
        )
        _require_self_digest(
            "ASSUMPTION_AUTHORITY_POLICY_COMMIT",
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
        signature_set_digest: str,
    ) -> AssumptionAuthorityPolicyCommit:
        unsigned = {
            "schema_version": AUTHORITY_POLICY_COMMIT_SCHEMA_VERSION,
            "approval_policy_digest": approval_policy_digest,
            "authority_root_digest": policy.authority_root_digest,
            "effective_from_sequence": effective_from_sequence,
            "exception_set_digest": policy.exception_set_digest,
            "grant_set_digest": policy.grant_set_digest,
            "policy_digest": policy.policy_digest,
            "policy_id": policy.policy_id,
            "predecessor_commit_receipt_digest": predecessor_commit_receipt_digest,
            "predecessor_policy_digest": predecessor_policy_digest,
            "separation_duty_rule_set_digest": policy.separation_duty_rule_set_digest,
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
            effective_from_sequence=effective_from_sequence,
            approval_policy_digest=approval_policy_digest,
            signature_set_digest=signature_set_digest,
            commit_receipt_digest=_domain_digest(
                "ASSUMPTION_AUTHORITY_POLICY_COMMIT", unsigned
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_POLICY_COMMIT_SCHEMA_VERSION,
            "approval_policy_digest": self.approval_policy_digest,
            "authority_root_digest": self.authority_root_digest,
            "effective_from_sequence": self.effective_from_sequence,
            "exception_set_digest": self.exception_set_digest,
            "grant_set_digest": self.grant_set_digest,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "predecessor_commit_receipt_digest": self.predecessor_commit_receipt_digest,
            "predecessor_policy_digest": self.predecessor_policy_digest,
            "separation_duty_rule_set_digest": self.separation_duty_rule_set_digest,
            "signature_set_digest": self.signature_set_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "commit_receipt_digest": self.commit_receipt_digest}


@dataclass(frozen=True, slots=True)
class DecisionAssumptionBinding:
    """Exact decision, semantic receipt, registry roots, clock, and assumptions binding."""

    decision_id: str
    validated_event_digest: str
    semantic_projection_receipt_digest: str
    control_state_digest: str
    assumption_registry_root: str
    evidence_registry_root: str
    logical_clock_sequence: int
    required_assumption_ids: tuple[str, ...]
    binding_digest: str

    def __post_init__(self) -> None:
        _require_token(self.decision_id, "DECISION_ASSUMPTION_BINDING_DECISION_ID_INVALID")
        _require_digest(
            self.validated_event_digest,
            "DECISION_ASSUMPTION_BINDING_EVENT_INVALID",
        )
        _require_digest(
            self.semantic_projection_receipt_digest,
            "DECISION_ASSUMPTION_BINDING_SEMANTIC_RECEIPT_INVALID",
        )
        _require_digest(
            self.control_state_digest,
            "DECISION_ASSUMPTION_BINDING_CONTROL_STATE_INVALID",
        )
        _require_digest(
            self.assumption_registry_root,
            "DECISION_ASSUMPTION_BINDING_ASSUMPTION_ROOT_INVALID",
        )
        _require_digest(
            self.evidence_registry_root,
            "DECISION_ASSUMPTION_BINDING_EVIDENCE_ROOT_INVALID",
        )
        if type(self.logical_clock_sequence) is not int or self.logical_clock_sequence < 0:
            raise AssumptionGovernanceContractError(
                "DECISION_ASSUMPTION_BINDING_CLOCK_INVALID"
            )
        _require_sorted_tokens(
            self.required_assumption_ids,
            "DECISION_ASSUMPTION_BINDING_ASSUMPTIONS_INVALID",
            allow_empty=False,
        )
        _require_self_digest(
            "DECISION_ASSUMPTION_BINDING",
            self._unsigned_value(),
            self.binding_digest,
            "DECISION_ASSUMPTION_BINDING_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        decision_id: str,
        validated_event_digest: str,
        semantic_projection_receipt_digest: str,
        control_state_digest: str,
        assumption_registry_root: str,
        evidence_registry_root: str,
        logical_clock_sequence: int,
        required_assumption_ids: tuple[str, ...],
    ) -> DecisionAssumptionBinding:
        canonical_ids = tuple(sorted(required_assumption_ids))
        unsigned = {
            "schema_version": DECISION_ASSUMPTION_BINDING_SCHEMA_VERSION,
            "assumption_registry_root": assumption_registry_root,
            "control_state_digest": control_state_digest,
            "decision_id": decision_id,
            "evidence_registry_root": evidence_registry_root,
            "logical_clock_sequence": logical_clock_sequence,
            "required_assumption_ids": list(canonical_ids),
            "semantic_projection_receipt_digest": semantic_projection_receipt_digest,
            "validated_event_digest": validated_event_digest,
        }
        return cls(
            decision_id=decision_id,
            validated_event_digest=validated_event_digest,
            semantic_projection_receipt_digest=semantic_projection_receipt_digest,
            control_state_digest=control_state_digest,
            assumption_registry_root=assumption_registry_root,
            evidence_registry_root=evidence_registry_root,
            logical_clock_sequence=logical_clock_sequence,
            required_assumption_ids=canonical_ids,
            binding_digest=_domain_digest("DECISION_ASSUMPTION_BINDING", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": DECISION_ASSUMPTION_BINDING_SCHEMA_VERSION,
            "assumption_registry_root": self.assumption_registry_root,
            "control_state_digest": self.control_state_digest,
            "decision_id": self.decision_id,
            "evidence_registry_root": self.evidence_registry_root,
            "logical_clock_sequence": self.logical_clock_sequence,
            "required_assumption_ids": list(self.required_assumption_ids),
            "semantic_projection_receipt_digest": self.semantic_projection_receipt_digest,
            "validated_event_digest": self.validated_event_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "binding_digest": self.binding_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AssumptionEvaluationWork:
    """Normative semantic work counts; excludes bytes, time, allocation, and I/O."""

    assumption_histories_reconstructed: int
    assumption_events_replayed: int
    authority_decisions_evaluated: int
    unique_assumption_nodes_evaluated: int
    assumption_dependency_edges_examined: int
    evidence_dependency_references_evaluated: int
    active_challenges_evaluated: int
    separation_duty_rules_evaluated: int
    work_digest: str

    def __post_init__(self) -> None:
        for name, value in self._counter_values().items():
            if type(value) is not int or value < 0:
                raise AssumptionGovernanceContractError(
                    "ASSUMPTION_EVALUATION_WORK_COUNTER_INVALID",
                    name,
                )
        _require_self_digest(
            "ASSUMPTION_EVALUATION_WORK",
            self._unsigned_value(),
            self.work_digest,
            "ASSUMPTION_EVALUATION_WORK_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        assumption_histories_reconstructed: int,
        assumption_events_replayed: int,
        authority_decisions_evaluated: int,
        unique_assumption_nodes_evaluated: int,
        assumption_dependency_edges_examined: int,
        evidence_dependency_references_evaluated: int,
        active_challenges_evaluated: int,
        separation_duty_rules_evaluated: int,
    ) -> AssumptionEvaluationWork:
        unsigned = {
            "schema_version": ASSUMPTION_EVALUATION_WORK_SCHEMA_VERSION,
            "active_challenges_evaluated": active_challenges_evaluated,
            "assumption_dependency_edges_examined": assumption_dependency_edges_examined,
            "assumption_events_replayed": assumption_events_replayed,
            "assumption_histories_reconstructed": assumption_histories_reconstructed,
            "authority_decisions_evaluated": authority_decisions_evaluated,
            "evidence_dependency_references_evaluated": (
                evidence_dependency_references_evaluated
            ),
            "separation_duty_rules_evaluated": separation_duty_rules_evaluated,
            "unique_assumption_nodes_evaluated": unique_assumption_nodes_evaluated,
        }
        return cls(
            assumption_histories_reconstructed=assumption_histories_reconstructed,
            assumption_events_replayed=assumption_events_replayed,
            authority_decisions_evaluated=authority_decisions_evaluated,
            unique_assumption_nodes_evaluated=unique_assumption_nodes_evaluated,
            assumption_dependency_edges_examined=assumption_dependency_edges_examined,
            evidence_dependency_references_evaluated=(
                evidence_dependency_references_evaluated
            ),
            active_challenges_evaluated=active_challenges_evaluated,
            separation_duty_rules_evaluated=separation_duty_rules_evaluated,
            work_digest=_domain_digest("ASSUMPTION_EVALUATION_WORK", unsigned),
        )

    def _counter_values(self) -> dict[str, int]:
        return {
            "active_challenges_evaluated": self.active_challenges_evaluated,
            "assumption_dependency_edges_examined": (
                self.assumption_dependency_edges_examined
            ),
            "assumption_events_replayed": self.assumption_events_replayed,
            "assumption_histories_reconstructed": self.assumption_histories_reconstructed,
            "authority_decisions_evaluated": self.authority_decisions_evaluated,
            "evidence_dependency_references_evaluated": (
                self.evidence_dependency_references_evaluated
            ),
            "separation_duty_rules_evaluated": self.separation_duty_rules_evaluated,
            "unique_assumption_nodes_evaluated": self.unique_assumption_nodes_evaluated,
        }

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": ASSUMPTION_EVALUATION_WORK_SCHEMA_VERSION,
            **self._counter_values(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "work_digest": self.work_digest}


@dataclass(frozen=True, slots=True)
class AssumptionResolutionAuthorityBinding:
    """Bind an authorized targeted resolution to exact pre/post challenge sets."""

    assumption_id: str
    action: str
    resolver_authority_id: str
    event_digest: str
    resolved_challenge_ids: tuple[str, ...]
    pre_active_challenge_ids: tuple[str, ...]
    post_active_challenge_ids: tuple[str, ...]
    policy_digest: str
    policy_commit_receipt_digest: str
    grant_id: str
    grant_digest: str
    binding_digest: str

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "ASSUMPTION_RESOLUTION_BINDING_ID_INVALID")
        if self.action not in RESOLUTION_AUTHORITY_ACTIONS:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_RESOLUTION_BINDING_ACTION_INVALID"
            )
        _require_token(
            self.resolver_authority_id,
            "ASSUMPTION_RESOLUTION_BINDING_AUTHORITY_INVALID",
        )
        _require_digest(self.event_digest, "ASSUMPTION_RESOLUTION_BINDING_EVENT_INVALID")
        _require_sorted_tokens(
            self.resolved_challenge_ids,
            "ASSUMPTION_RESOLUTION_BINDING_RESOLVED_INVALID",
            allow_empty=False,
        )
        _require_sorted_tokens(
            self.pre_active_challenge_ids,
            "ASSUMPTION_RESOLUTION_BINDING_PRE_SET_INVALID",
            allow_empty=False,
        )
        _require_sorted_tokens(
            self.post_active_challenge_ids,
            "ASSUMPTION_RESOLUTION_BINDING_POST_SET_INVALID",
            allow_empty=True,
        )
        pre = set(self.pre_active_challenge_ids)
        resolved = set(self.resolved_challenge_ids)
        if not resolved.issubset(pre):
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_RESOLUTION_BINDING_UNKNOWN_CHALLENGE"
            )
        if tuple(sorted(pre - resolved)) != self.post_active_challenge_ids:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_RESOLUTION_BINDING_POST_SET_MISMATCH"
            )
        _require_digest(self.policy_digest, "ASSUMPTION_RESOLUTION_BINDING_POLICY_INVALID")
        _require_digest(
            self.policy_commit_receipt_digest,
            "ASSUMPTION_RESOLUTION_BINDING_POLICY_COMMIT_INVALID",
        )
        _require_token(self.grant_id, "ASSUMPTION_RESOLUTION_BINDING_GRANT_ID_INVALID")
        _require_digest(self.grant_digest, "ASSUMPTION_RESOLUTION_BINDING_GRANT_INVALID")
        _require_self_digest(
            "ASSUMPTION_RESOLUTION_AUTHORITY_BINDING",
            self._unsigned_value(),
            self.binding_digest,
            "ASSUMPTION_RESOLUTION_BINDING_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        assumption_id: str,
        action: str,
        resolver_authority_id: str,
        event_digest: str,
        resolved_challenge_ids: tuple[str, ...],
        pre_active_challenge_ids: tuple[str, ...],
        post_active_challenge_ids: tuple[str, ...],
        policy_digest: str,
        policy_commit_receipt_digest: str,
        grant_id: str,
        grant_digest: str,
    ) -> AssumptionResolutionAuthorityBinding:
        canonical_resolved = tuple(sorted(resolved_challenge_ids))
        canonical_pre = tuple(sorted(pre_active_challenge_ids))
        canonical_post = tuple(sorted(post_active_challenge_ids))
        unsigned = {
            "schema_version": RESOLUTION_AUTHORITY_BINDING_SCHEMA_VERSION,
            "action": action,
            "assumption_id": assumption_id,
            "event_digest": event_digest,
            "grant_digest": grant_digest,
            "grant_id": grant_id,
            "policy_commit_receipt_digest": policy_commit_receipt_digest,
            "policy_digest": policy_digest,
            "post_active_challenge_ids": list(canonical_post),
            "pre_active_challenge_ids": list(canonical_pre),
            "resolved_challenge_ids": list(canonical_resolved),
            "resolver_authority_id": resolver_authority_id,
        }
        return cls(
            assumption_id=assumption_id,
            action=action,
            resolver_authority_id=resolver_authority_id,
            event_digest=event_digest,
            resolved_challenge_ids=canonical_resolved,
            pre_active_challenge_ids=canonical_pre,
            post_active_challenge_ids=canonical_post,
            policy_digest=policy_digest,
            policy_commit_receipt_digest=policy_commit_receipt_digest,
            grant_id=grant_id,
            grant_digest=grant_digest,
            binding_digest=_domain_digest(
                "ASSUMPTION_RESOLUTION_AUTHORITY_BINDING", unsigned
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": RESOLUTION_AUTHORITY_BINDING_SCHEMA_VERSION,
            "action": self.action,
            "assumption_id": self.assumption_id,
            "event_digest": self.event_digest,
            "grant_digest": self.grant_digest,
            "grant_id": self.grant_id,
            "policy_commit_receipt_digest": self.policy_commit_receipt_digest,
            "policy_digest": self.policy_digest,
            "post_active_challenge_ids": list(self.post_active_challenge_ids),
            "pre_active_challenge_ids": list(self.pre_active_challenge_ids),
            "resolved_challenge_ids": list(self.resolved_challenge_ids),
            "resolver_authority_id": self.resolver_authority_id,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "binding_digest": self.binding_digest}


def canonical_cycle_witness(cycle_path: tuple[str, ...]) -> tuple[str, ...]:
    """Canonicalize a directed cycle by rotating its smallest identity to the front."""

    _require_sorted_input_type(cycle_path, "ASSUMPTION_CYCLE_WITNESS_INVALID")
    if len(cycle_path) < 2 or cycle_path[0] != cycle_path[-1]:
        raise AssumptionGovernanceContractError("ASSUMPTION_CYCLE_WITNESS_NOT_CLOSED")
    ring = cycle_path[:-1]
    if not ring:
        raise AssumptionGovernanceContractError("ASSUMPTION_CYCLE_WITNESS_EMPTY")
    for identity in ring:
        _require_token(identity, "ASSUMPTION_CYCLE_WITNESS_ID_INVALID")
    if len(set(ring)) != len(ring):
        raise AssumptionGovernanceContractError("ASSUMPTION_CYCLE_WITNESS_REPEATED_NODE")
    smallest = min(range(len(ring)), key=lambda index: ring[index])
    rotated = ring[smallest:] + ring[:smallest]
    return rotated + (rotated[0],)


def _require_action(value: object, code: str) -> None:
    if type(value) is not str or value not in ASSUMPTION_AUTHORITY_ACTIONS:
        raise AssumptionGovernanceContractError(code)


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AssumptionGovernanceContractError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AssumptionGovernanceContractError(code)


def _require_sorted_input_type(value: object, code: str) -> None:
    if type(value) is not tuple or not all(type(item) is str for item in value):
        raise AssumptionGovernanceContractError(code)


def _require_sorted_tokens(value: object, code: str, *, allow_empty: bool) -> None:
    _require_sorted_input_type(value, code)
    items = value
    if not allow_empty and not items:
        raise AssumptionGovernanceContractError(code)
    if items != tuple(sorted(items)) or len(set(items)) != len(items):
        raise AssumptionGovernanceContractError(code)
    for item in items:
        _require_token(item, code)


def _require_sorted_members(
    value: object,
    allowed: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool,
) -> None:
    _require_sorted_input_type(value, code)
    items = value
    if not allow_empty and not items:
        raise AssumptionGovernanceContractError(code)
    if items != tuple(sorted(items)) or len(set(items)) != len(items):
        raise AssumptionGovernanceContractError(code)
    if not set(items).issubset(allowed):
        raise AssumptionGovernanceContractError(code)


def _canonical_scopes(scope_ids: tuple[str, ...]) -> tuple[str, ...]:
    if GLOBAL_ASSUMPTION_SCOPE in scope_ids:
        return (GLOBAL_ASSUMPTION_SCOPE,)
    return tuple(sorted(scope_ids))


def _require_canonical_scopes(value: object, code: str) -> None:
    _require_sorted_input_type(value, code)
    items = value
    if not items or len(set(items)) != len(items):
        raise AssumptionGovernanceContractError(code)
    if GLOBAL_ASSUMPTION_SCOPE in items:
        if items != (GLOBAL_ASSUMPTION_SCOPE,):
            raise AssumptionGovernanceContractError(code)
        return
    if items != tuple(sorted(items)):
        raise AssumptionGovernanceContractError(code)
    for item in items:
        _require_token(item, code)


def _canonical_materialities(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(values, key=lambda item: _MATERIALITY_RANK.get(item, 99)))


def _require_materialities(value: object, code: str, *, allow_empty: bool) -> None:
    _require_sorted_input_type(value, code)
    items = value
    if not allow_empty and not items:
        raise AssumptionGovernanceContractError(code)
    if len(set(items)) != len(items) or not set(items).issubset(ASSUMPTION_MATERIALITIES):
        raise AssumptionGovernanceContractError(code)
    if items != _canonical_materialities(items):
        raise AssumptionGovernanceContractError(code)


def _require_effective_interval(
    effective_from_sequence: object,
    effective_until_sequence: object,
    code: str,
) -> None:
    if type(effective_from_sequence) is not int or effective_from_sequence < 0:
        raise AssumptionGovernanceContractError(code)
    if effective_until_sequence is not None:
        if type(effective_until_sequence) is not int:
            raise AssumptionGovernanceContractError(code)
        if effective_until_sequence <= effective_from_sequence:
            raise AssumptionGovernanceContractError(code)


def _require_canonical_objects(
    values: object,
    key: object,
    code: str,
    *,
    allow_empty: bool,
) -> None:
    if type(values) is not tuple:
        raise AssumptionGovernanceContractError(code)
    if not allow_empty and not values:
        raise AssumptionGovernanceContractError(code)
    keys = [key(item) for item in values]  # type: ignore[operator]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise AssumptionGovernanceContractError(code)


def _scope_is_subset(candidate: tuple[str, ...], boundary: tuple[str, ...]) -> bool:
    if boundary == (GLOBAL_ASSUMPTION_SCOPE,):
        return True
    if candidate == (GLOBAL_ASSUMPTION_SCOPE,):
        return False
    return set(candidate).issubset(boundary)


def _require_self_digest(domain: str, unsigned: dict[str, object], actual: str, code: str) -> None:
    _require_digest(actual, code)
    if actual != _domain_digest(domain, unsigned):
        raise AssumptionGovernanceContractError(code)


def _set_digest(domain: str, values: list[dict[str, object]]) -> str:
    return _domain_digest(domain, {"members": values})


def _domain_digest(domain: str, value: dict[str, object]) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + _json_bytes(value)).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
