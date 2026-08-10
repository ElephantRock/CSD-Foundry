"""Committed evidence authority and deterministic admissibility for v0.5-D2.2."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.evidence import (
    EVIDENCE_PAYLOAD_SCHEMA_VERSION,
    EvidenceRegistry,
    EvidenceUnit,
    project_evidence_history,
    reduce_evidence,
)
from csd_foundry.governance.v0_5.registry import RegistryStore

AUTHORITY_POLICY_SCHEMA_VERSION = "evidence-authority-policy/1"
AUTHORITY_DECISION_SCHEMA_VERSION = "evidence-authority-decision/1"
CHALLENGE_POLICY_SCHEMA_VERSION = "evidence-challenge-policy/1"
EVIDENCE_USE_REQUEST_SCHEMA_VERSION = "evidence-use-request/1"
ADMISSIBILITY_RECEIPT_SCHEMA_VERSION = "evidence-admissibility-receipt/1"

_OPERATION_AUTHORITY_FIELD = {
    "REGISTER": "issuer_authority_id",
    "VERIFY": "verifier_authority_id",
    "REJECT": "rejecting_authority_id",
    "CHALLENGE": "challenger_authority_id",
    "RESOLVE_CHALLENGE": "resolver_authority_id",
    "EXPIRE": "expiry_authority_id",
    "INVALIDATE": "invalidating_authority_id",
    "SUPERSEDE": "superseding_authority_id",
}
_REUSE_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}
_MATERIALITIES = {"ADVISORY", "MATERIAL"}
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class EvidenceGovernanceError(RuntimeError):
    """Raised when authority or evidence-use governance fails closed."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True, order=True)
class EvidenceAuthorityGrant:
    """One operation-specific authority grant; empty scope means all scopes."""

    operation: str
    authority_id: str
    scope_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.operation not in _OPERATION_AUTHORITY_FIELD:
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_OPERATION_INVALID")
        _require_token(self.authority_id, "EVIDENCE_AUTHORITY_ID_INVALID")
        _require_sorted_tokens(self.scope_ids, "EVIDENCE_AUTHORITY_SCOPE_INVALID")

    def to_json_value(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "operation": self.operation,
            "scope_ids": list(self.scope_ids),
        }


@dataclass(frozen=True, slots=True)
class EvidenceAuthorityPolicy:
    """Immutable authority policy committed under one authority root."""

    policy_id: str
    committed_at_sequence: int
    authority_root_digest: str
    grants: tuple[EvidenceAuthorityGrant, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        _require_token(self.policy_id, "EVIDENCE_AUTHORITY_POLICY_ID_INVALID")
        if type(self.committed_at_sequence) is not int or self.committed_at_sequence < 0:
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_POLICY_SEQUENCE_INVALID")
        _require_digest(
            self.authority_root_digest,
            "EVIDENCE_AUTHORITY_ROOT_DIGEST_INVALID",
        )
        if type(self.grants) is not tuple or self.grants != tuple(sorted(self.grants)):
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_GRANTS_NOT_CANONICAL")
        if len(set(self.grants)) != len(self.grants):
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_GRANT_DUPLICATE")
        if not self.grants:
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_GRANTS_EMPTY")
        expected = _domain_digest("EVIDENCE_AUTHORITY_POLICY", self._unsigned_value())
        if self.policy_digest != expected:
            raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_POLICY_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        policy_id: str,
        committed_at_sequence: int,
        authority_root_digest: str,
        grants: tuple[EvidenceAuthorityGrant, ...],
    ) -> EvidenceAuthorityPolicy:
        canonical = tuple(sorted(grants))
        unsigned = {
            "schema_version": AUTHORITY_POLICY_SCHEMA_VERSION,
            "authority_root_digest": authority_root_digest,
            "committed_at_sequence": committed_at_sequence,
            "grants": [item.to_json_value() for item in canonical],
            "policy_id": policy_id,
        }
        return cls(
            policy_id=policy_id,
            committed_at_sequence=committed_at_sequence,
            authority_root_digest=authority_root_digest,
            grants=canonical,
            policy_digest=_domain_digest("EVIDENCE_AUTHORITY_POLICY", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_POLICY_SCHEMA_VERSION,
            "authority_root_digest": self.authority_root_digest,
            "committed_at_sequence": self.committed_at_sequence,
            "grants": [item.to_json_value() for item in self.grants],
            "policy_id": self.policy_id,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "policy_digest": self.policy_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())

    def permits(
        self,
        *,
        operation: str,
        authority_id: str,
        scope_ids: tuple[str, ...],
    ) -> bool:
        requested = set(scope_ids)
        for grant in self.grants:
            if grant.operation != operation or grant.authority_id != authority_id:
                continue
            if not grant.scope_ids or requested.issubset(grant.scope_ids):
                return True
        return False


@dataclass(frozen=True, slots=True)
class EvidenceAuthorityDecision:
    """Deterministic internal receipt for one authority check."""

    allowed: bool
    code: str
    operation: str
    evidence_id: str
    authority_id: str
    scope_ids: tuple[str, ...]
    event_digest: str
    policy_digest: str
    authority_root_digest: str
    decision_digest: str

    @classmethod
    def build(
        cls,
        *,
        allowed: bool,
        code: str,
        operation: str,
        evidence_id: str,
        authority_id: str,
        scope_ids: tuple[str, ...],
        event_digest: str,
        policy: EvidenceAuthorityPolicy,
    ) -> EvidenceAuthorityDecision:
        unsigned = {
            "schema_version": AUTHORITY_DECISION_SCHEMA_VERSION,
            "allowed": allowed,
            "authority_id": authority_id,
            "authority_root_digest": policy.authority_root_digest,
            "code": code,
            "event_digest": event_digest,
            "evidence_id": evidence_id,
            "operation": operation,
            "policy_digest": policy.policy_digest,
            "scope_ids": list(scope_ids),
        }
        return cls(
            allowed=allowed,
            code=code,
            operation=operation,
            evidence_id=evidence_id,
            authority_id=authority_id,
            scope_ids=scope_ids,
            event_digest=event_digest,
            policy_digest=policy.policy_digest,
            authority_root_digest=policy.authority_root_digest,
            decision_digest=_domain_digest("EVIDENCE_AUTHORITY_DECISION", unsigned),
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_DECISION_SCHEMA_VERSION,
            "allowed": self.allowed,
            "authority_id": self.authority_id,
            "authority_root_digest": self.authority_root_digest,
            "code": self.code,
            "decision_digest": self.decision_digest,
            "event_digest": self.event_digest,
            "evidence_id": self.evidence_id,
            "operation": self.operation,
            "policy_digest": self.policy_digest,
            "scope_ids": list(self.scope_ids),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


class EvidenceAuthorityResolver:
    """Resolve event authority against one immutable committed policy."""

    def __init__(self, policy: EvidenceAuthorityPolicy) -> None:
        self.policy = policy

    def evaluate(
        self,
        event: RegistryEvent,
        previous: EvidenceUnit | None,
    ) -> EvidenceAuthorityDecision:
        value = _event_value(event)
        payload = _payload(value)
        operation = _required_token(payload, "operation", "EVIDENCE_OPERATION_INVALID")
        evidence_id = cast(str, value["entity_id"])
        authority_field = _OPERATION_AUTHORITY_FIELD.get(operation)
        if authority_field is None:
            return self._decision(
                False,
                "EVIDENCE_AUTHORITY_OPERATION_UNSUPPORTED",
                operation,
                evidence_id,
                "authority:unknown",
                (),
                event,
            )
        authority_id = _required_token(
            payload,
            authority_field,
            "EVIDENCE_OPERATION_AUTHORITY_MISSING",
        )
        if operation == "REGISTER":
            scope_ids = _required_token_tuple(
                payload,
                "scope_ids",
                "EVIDENCE_SCOPE_INVALID",
                allow_empty=False,
            )
        elif previous is None:
            return self._decision(
                False,
                "EVIDENCE_AUTHORITY_PREVIOUS_STATE_MISSING",
                operation,
                evidence_id,
                authority_id,
                (),
                event,
            )
        else:
            scope_ids = previous.scope_ids
        if cast(int, value["clock_sequence"]) < self.policy.committed_at_sequence:
            return self._decision(
                False,
                "EVIDENCE_AUTHORITY_POLICY_NOT_EFFECTIVE",
                operation,
                evidence_id,
                authority_id,
                scope_ids,
                event,
            )
        allowed = self.policy.permits(
            operation=operation,
            authority_id=authority_id,
            scope_ids=scope_ids,
        )
        return self._decision(
            allowed,
            "EVIDENCE_AUTHORITY_PERMITTED" if allowed else "EVIDENCE_AUTHORITY_DENIED",
            operation,
            evidence_id,
            authority_id,
            scope_ids,
            event,
        )

    def require(
        self,
        event: RegistryEvent,
        previous: EvidenceUnit | None,
    ) -> EvidenceAuthorityDecision:
        decision = self.evaluate(event, previous)
        if not decision.allowed:
            raise EvidenceGovernanceError(decision.code, decision.authority_id)
        return decision

    def _decision(
        self,
        allowed: bool,
        code: str,
        operation: str,
        evidence_id: str,
        authority_id: str,
        scope_ids: tuple[str, ...],
        event: RegistryEvent,
    ) -> EvidenceAuthorityDecision:
        return EvidenceAuthorityDecision.build(
            allowed=allowed,
            code=code,
            operation=operation,
            evidence_id=evidence_id,
            authority_id=authority_id,
            scope_ids=scope_ids,
            event_digest=event.digest,
            policy=self.policy,
        )


@dataclass(frozen=True, slots=True)
class GovernedEvidenceApplyResult:
    evidence: EvidenceUnit
    authority_decision: EvidenceAuthorityDecision


class GovernedEvidenceRegistry:
    """Authority-gated wrapper around the deterministic D2.1 reducer."""

    def __init__(self, store: RegistryStore, policy: EvidenceAuthorityPolicy) -> None:
        self.store = store
        self.registry = EvidenceRegistry(store)
        self.authority = EvidenceAuthorityResolver(policy)

    def current(self, evidence_id: str) -> EvidenceUnit | None:
        return self.registry.current(evidence_id)

    def apply(self, event: RegistryEvent) -> GovernedEvidenceApplyResult:
        value = _event_value(event)
        evidence_id = cast(str, value["entity_id"])
        previous = self.registry.current(evidence_id)
        decision = self.authority.require(event, previous)
        evidence = self.registry.apply(event)
        return GovernedEvidenceApplyResult(evidence, decision)


@dataclass(frozen=True, slots=True, order=True)
class ChallengeMaterialityRule:
    reason_code: str
    materiality: str

    def __post_init__(self) -> None:
        _require_token(self.reason_code, "EVIDENCE_CHALLENGE_REASON_INVALID")
        if self.materiality not in _MATERIALITIES:
            raise EvidenceGovernanceError("EVIDENCE_CHALLENGE_MATERIALITY_INVALID")

    def to_json_value(self) -> dict[str, str]:
        return {"materiality": self.materiality, "reason_code": self.reason_code}


@dataclass(frozen=True, slots=True)
class EvidenceChallengePolicy:
    """Classify active challenge reasons; unknown reasons fail closed as material."""

    rules: tuple[ChallengeMaterialityRule, ...]
    policy_digest: str

    def __post_init__(self) -> None:
        if type(self.rules) is not tuple or self.rules != tuple(sorted(self.rules)):
            raise EvidenceGovernanceError("EVIDENCE_CHALLENGE_RULES_NOT_CANONICAL")
        if len({item.reason_code for item in self.rules}) != len(self.rules):
            raise EvidenceGovernanceError("EVIDENCE_CHALLENGE_RULE_DUPLICATE")
        expected = _domain_digest("EVIDENCE_CHALLENGE_POLICY", self._unsigned_value())
        if self.policy_digest != expected:
            raise EvidenceGovernanceError("EVIDENCE_CHALLENGE_POLICY_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        rules: tuple[ChallengeMaterialityRule, ...],
    ) -> EvidenceChallengePolicy:
        canonical = tuple(sorted(rules))
        unsigned = {
            "schema_version": CHALLENGE_POLICY_SCHEMA_VERSION,
            "rules": [item.to_json_value() for item in canonical],
        }
        return cls(
            rules=canonical,
            policy_digest=_domain_digest("EVIDENCE_CHALLENGE_POLICY", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": CHALLENGE_POLICY_SCHEMA_VERSION,
            "rules": [item.to_json_value() for item in self.rules],
        }

    def materiality(self, reason_code: str) -> str:
        for rule in self.rules:
            if rule.reason_code == reason_code:
                return rule.materiality
        return "MATERIAL"


@dataclass(frozen=True, slots=True)
class EvidenceUseRequest:
    """Decision-specific request to use one evidence identity."""

    decision_id: str
    evidence_id: str
    proposition_id: str
    scope_ids: tuple[str, ...]
    required_reuse_class: str
    clock_sequence: int
    accepted_limitation_codes: tuple[str, ...]
    request_digest: str

    def __post_init__(self) -> None:
        _require_token(self.decision_id, "EVIDENCE_USE_DECISION_ID_INVALID")
        _require_token(self.evidence_id, "EVIDENCE_USE_EVIDENCE_ID_INVALID")
        _require_token(self.proposition_id, "EVIDENCE_USE_PROPOSITION_INVALID")
        _require_sorted_tokens(self.scope_ids, "EVIDENCE_USE_SCOPE_INVALID", allow_empty=False)
        if self.required_reuse_class not in _REUSE_RANK:
            raise EvidenceGovernanceError("EVIDENCE_USE_REUSE_CLASS_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 0:
            raise EvidenceGovernanceError("EVIDENCE_USE_CLOCK_INVALID")
        _require_sorted_tokens(
            self.accepted_limitation_codes,
            "EVIDENCE_USE_LIMITATIONS_INVALID",
        )
        expected = _domain_digest("EVIDENCE_USE_REQUEST", self._unsigned_value())
        if self.request_digest != expected:
            raise EvidenceGovernanceError("EVIDENCE_USE_REQUEST_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        decision_id: str,
        evidence_id: str,
        proposition_id: str,
        scope_ids: tuple[str, ...],
        required_reuse_class: str,
        clock_sequence: int,
        accepted_limitation_codes: tuple[str, ...] = (),
    ) -> EvidenceUseRequest:
        canonical_scope = tuple(sorted(scope_ids))
        canonical_limitations = tuple(sorted(accepted_limitation_codes))
        unsigned = {
            "schema_version": EVIDENCE_USE_REQUEST_SCHEMA_VERSION,
            "accepted_limitation_codes": list(canonical_limitations),
            "clock_sequence": clock_sequence,
            "decision_id": decision_id,
            "evidence_id": evidence_id,
            "proposition_id": proposition_id,
            "required_reuse_class": required_reuse_class,
            "scope_ids": list(canonical_scope),
        }
        return cls(
            decision_id=decision_id,
            evidence_id=evidence_id,
            proposition_id=proposition_id,
            scope_ids=canonical_scope,
            required_reuse_class=required_reuse_class,
            clock_sequence=clock_sequence,
            accepted_limitation_codes=canonical_limitations,
            request_digest=_domain_digest("EVIDENCE_USE_REQUEST", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_USE_REQUEST_SCHEMA_VERSION,
            "accepted_limitation_codes": list(self.accepted_limitation_codes),
            "clock_sequence": self.clock_sequence,
            "decision_id": self.decision_id,
            "evidence_id": self.evidence_id,
            "proposition_id": self.proposition_id,
            "required_reuse_class": self.required_reuse_class,
            "scope_ids": list(self.scope_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return self._unsigned_value()


@dataclass(frozen=True, slots=True)
class EvidenceAdmissibilityReceipt:
    """Deterministic internal receipt for one evidence-use evaluation."""

    allowed: bool
    code: str
    request_digest: str
    evidence_id: str
    evidence_event_digest: str | None
    authority_policy_digest: str
    challenge_policy_digest: str
    dependency_event_digests: tuple[str, ...]
    advisory_codes: tuple[str, ...]
    receipt_digest: str

    @classmethod
    def build(
        cls,
        *,
        allowed: bool,
        code: str,
        request: EvidenceUseRequest,
        evidence_event_digest: str | None,
        authority_policy_digest: str,
        challenge_policy_digest: str,
        dependency_event_digests: tuple[str, ...],
        advisory_codes: tuple[str, ...],
    ) -> EvidenceAdmissibilityReceipt:
        canonical_dependencies = tuple(sorted(dependency_event_digests))
        canonical_advisories = tuple(sorted(set(advisory_codes)))
        unsigned = {
            "schema_version": ADMISSIBILITY_RECEIPT_SCHEMA_VERSION,
            "advisory_codes": list(canonical_advisories),
            "allowed": allowed,
            "authority_policy_digest": authority_policy_digest,
            "challenge_policy_digest": challenge_policy_digest,
            "code": code,
            "dependency_event_digests": list(canonical_dependencies),
            "evidence_event_digest": evidence_event_digest,
            "evidence_id": request.evidence_id,
            "request_digest": request.request_digest,
        }
        return cls(
            allowed=allowed,
            code=code,
            request_digest=request.request_digest,
            evidence_id=request.evidence_id,
            evidence_event_digest=evidence_event_digest,
            authority_policy_digest=authority_policy_digest,
            challenge_policy_digest=challenge_policy_digest,
            dependency_event_digests=canonical_dependencies,
            advisory_codes=canonical_advisories,
            receipt_digest=_domain_digest("EVIDENCE_ADMISSIBILITY_RECEIPT", unsigned),
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": ADMISSIBILITY_RECEIPT_SCHEMA_VERSION,
            "advisory_codes": list(self.advisory_codes),
            "allowed": self.allowed,
            "authority_policy_digest": self.authority_policy_digest,
            "challenge_policy_digest": self.challenge_policy_digest,
            "code": self.code,
            "dependency_event_digests": list(self.dependency_event_digests),
            "evidence_event_digest": self.evidence_event_digest,
            "evidence_id": self.evidence_id,
            "receipt_digest": self.receipt_digest,
            "request_digest": self.request_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


class EvidenceAdmissibilityEvaluator:
    """Evaluate evidence use, authority history, dependencies, and challenges."""

    def __init__(
        self,
        store: RegistryStore,
        authority_policy: EvidenceAuthorityPolicy,
        challenge_policy: EvidenceChallengePolicy,
    ) -> None:
        self.store = store
        self.authority = EvidenceAuthorityResolver(authority_policy)
        self.challenge_policy = challenge_policy

    def evaluate(self, request: EvidenceUseRequest) -> EvidenceAdmissibilityReceipt:
        dependency_digests: set[str] = set()
        advisories: list[str] = []
        try:
            root = self._evaluate_node(
                request.evidence_id,
                request,
                visiting=set(),
                dependency_digests=dependency_digests,
                advisories=advisories,
                root=True,
            )
        except EvidenceGovernanceError as exc:
            current = project_evidence_history(
                self.store.reconstruct_entity("EVIDENCE_UNIT", request.evidence_id)
            )
            return EvidenceAdmissibilityReceipt.build(
                allowed=False,
                code=exc.code,
                request=request,
                evidence_event_digest=None if current is None else current.current_event_digest,
                authority_policy_digest=self.authority.policy.policy_digest,
                challenge_policy_digest=self.challenge_policy.policy_digest,
                dependency_event_digests=tuple(dependency_digests),
                advisory_codes=tuple(advisories),
            )
        return EvidenceAdmissibilityReceipt.build(
            allowed=True,
            code="EVIDENCE_ADMISSIBLE",
            request=request,
            evidence_event_digest=root.current_event_digest,
            authority_policy_digest=self.authority.policy.policy_digest,
            challenge_policy_digest=self.challenge_policy.policy_digest,
            dependency_event_digests=tuple(dependency_digests),
            advisory_codes=tuple(advisories),
        )

    def _evaluate_node(
        self,
        evidence_id: str,
        request: EvidenceUseRequest,
        *,
        visiting: set[str],
        dependency_digests: set[str],
        advisories: list[str],
        root: bool,
    ) -> EvidenceUnit:
        if evidence_id in visiting:
            raise EvidenceGovernanceError("EVIDENCE_DEPENDENCY_CYCLE", evidence_id)
        visiting.add(evidence_id)
        history = self.store.reconstruct_entity("EVIDENCE_UNIT", evidence_id)
        if not history:
            code = "EVIDENCE_DEPENDENCY_MISSING" if not root else "EVIDENCE_MISSING"
            raise EvidenceGovernanceError(code)
        evidence = self._validate_authority_history(history)
        if root and evidence.proposition_id != request.proposition_id:
            raise EvidenceGovernanceError("EVIDENCE_PROPOSITION_MISMATCH")
        if not set(request.scope_ids).issubset(evidence.scope_ids):
            raise EvidenceGovernanceError("EVIDENCE_SCOPE_INSUFFICIENT", evidence_id)
        if request.clock_sequence < evidence.valid_from_sequence:
            raise EvidenceGovernanceError("EVIDENCE_NOT_YET_VALID", evidence_id)
        if (
            evidence.expires_at_sequence is not None
            and request.clock_sequence >= evidence.expires_at_sequence
        ):
            raise EvidenceGovernanceError("EVIDENCE_EXPIRED_BY_TIME", evidence_id)
        if _REUSE_RANK[request.required_reuse_class] > _REUSE_RANK[evidence.maximum_reuse_class]:
            raise EvidenceGovernanceError("EVIDENCE_REUSE_CLASS_INSUFFICIENT", evidence_id)
        if not set(evidence.limitations).issubset(request.accepted_limitation_codes):
            raise EvidenceGovernanceError("EVIDENCE_LIMITATION_NOT_ACCEPTED", evidence_id)
        if evidence.status == "CHALLENGED":
            reason = _active_challenge_reason(history)
            if self.challenge_policy.materiality(reason) == "MATERIAL":
                raise EvidenceGovernanceError("EVIDENCE_CHALLENGE_MATERIAL", evidence_id)
            advisories.append(f"EVIDENCE_CHALLENGE_ADVISORY:{evidence_id}:{reason}")
        elif evidence.status != "VERIFIED":
            raise EvidenceGovernanceError("EVIDENCE_STATUS_INADMISSIBLE", evidence.status)
        for dependency_id in evidence.dependency_ids:
            dependency = self._evaluate_node(
                dependency_id,
                request,
                visiting=visiting,
                dependency_digests=dependency_digests,
                advisories=advisories,
                root=False,
            )
            dependency_digests.add(dependency.current_event_digest)
        visiting.remove(evidence_id)
        return evidence

    def _validate_authority_history(self, history: tuple[RegistryEvent, ...]) -> EvidenceUnit:
        previous: EvidenceUnit | None = None
        for event in history:
            decision = self.authority.evaluate(event, previous)
            if not decision.allowed:
                raise EvidenceGovernanceError("EVIDENCE_AUTHORITY_HISTORY_INVALID", decision.code)
            previous = reduce_evidence(previous, event)
        if previous is None:
            raise EvidenceGovernanceError("EVIDENCE_HISTORY_EMPTY")
        return previous


def _active_challenge_reason(history: tuple[RegistryEvent, ...]) -> str:
    for event in reversed(history):
        value = _event_value(event)
        payload = _payload(value)
        if payload.get("operation") == "CHALLENGE":
            return _required_token(
                payload,
                "challenge_reason_code",
                "EVIDENCE_CHALLENGE_REASON_INVALID",
            )
    raise EvidenceGovernanceError("EVIDENCE_ACTIVE_CHALLENGE_NOT_FOUND")


def _event_value(event: RegistryEvent) -> dict[str, Any]:
    if type(event) is not RegistryEvent:
        raise EvidenceGovernanceError("EVIDENCE_EVENT_TYPE_INVALID")
    value = event.to_json_value()
    if value.get("registry_type") != "EVIDENCE_UNIT":
        raise EvidenceGovernanceError("EVIDENCE_REGISTRY_TYPE_INVALID")
    if value.get("payload_schema_version") != EVIDENCE_PAYLOAD_SCHEMA_VERSION:
        raise EvidenceGovernanceError("EVIDENCE_PAYLOAD_SCHEMA_INVALID")
    return value


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get("payload")
    if type(payload) is not dict:
        raise EvidenceGovernanceError("EVIDENCE_PAYLOAD_NOT_OBJECT")
    return cast(dict[str, Any], payload)


def _required_token(payload: dict[str, Any], field: str, code: str) -> str:
    value = payload.get(field)
    _require_token(value, code)
    return cast(str, value)


def _required_token_tuple(
    payload: dict[str, Any],
    field: str,
    code: str,
    *,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    value = payload.get(field)
    if type(value) is not list or any(type(item) is not str for item in value):
        raise EvidenceGovernanceError(code)
    result = tuple(cast(list[str], value))
    _require_sorted_tokens(result, code, allow_empty=allow_empty)
    return result


def _require_sorted_tokens(
    values: tuple[str, ...],
    code: str,
    *,
    allow_empty: bool = True,
) -> None:
    if type(values) is not tuple or (not allow_empty and not values):
        raise EvidenceGovernanceError(code)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise EvidenceGovernanceError(code)
    for value in values:
        _require_token(value, code)


def _require_token(value: object, code: str) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise EvidenceGovernanceError(code)


def _require_digest(value: object, code: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvidenceGovernanceError(code)


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


def _domain_digest(domain: str, value: object) -> str:
    payload = domain.encode("ascii") + b"\0" + _json_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()
