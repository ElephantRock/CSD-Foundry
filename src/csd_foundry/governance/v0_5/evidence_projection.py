"""Deterministic expiry planning, impact receipts, and staged evidence projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.evidence import (
    EvidenceUnit,
    build_evidence_event,
    project_evidence_history,
    reduce_evidence,
)
from csd_foundry.governance.v0_5.evidence_governance import (
    EvidenceAuthorityDecision,
    EvidenceAuthorityPolicy,
    EvidenceAuthorityResolver,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStore

EXPIRY_PLAN_SCHEMA_VERSION = "evidence-expiry-plan/1"
IMPACT_RECEIPT_SCHEMA_VERSION = "evidence-impact-receipt/1"
PROJECTION_PLAN_SCHEMA_VERSION = "evidence-projection-plan/1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_TERMINAL_STATUSES = {"EXPIRED", "INVALIDATED", "REJECTED", "SUPERSEDED"}
_IMPACT_OPERATIONS = {"CHALLENGE", "EXPIRE", "INVALIDATE", "SUPERSEDE"}


class EvidenceProjectionError(RuntimeError):
    """Stable fail-closed error for staged evidence projection."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class EvidenceIntentResolver(Protocol):
    def resolve(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        store: RegistryStore,
    ) -> tuple[RegistryEvent, ...]: ...


class EvidenceImpactResolver(Protocol):
    def resolve(
        self,
        *,
        evidence: EvidenceUnit,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]: ...


class EmptyEvidenceIntentResolver:
    def resolve(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        store: RegistryStore,
    ) -> tuple[RegistryEvent, ...]:
        del claim, validated_event, semantic_receipt, store
        return ()


class EmptyEvidenceImpactResolver:
    def resolve(
        self,
        *,
        evidence: EvidenceUnit,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        del evidence, trigger_event, store
        return (), ()


@dataclass(frozen=True, slots=True)
class EvidenceExpiryPlan:
    clock_sequence: int
    predecessor_root_digest: str
    authority_policy_digest: str
    expiry_authority_id: str
    source_receipt_digest: str
    events: tuple[RegistryEvent, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        if type(self.clock_sequence) is not int or self.clock_sequence < 0:
            raise EvidenceProjectionError("EVIDENCE_EXPIRY_CLOCK_INVALID")
        _require_digest(self.predecessor_root_digest, "EVIDENCE_EXPIRY_ROOT_INVALID")
        _require_digest(self.authority_policy_digest, "EVIDENCE_EXPIRY_POLICY_INVALID")
        _require_token(self.expiry_authority_id, "EVIDENCE_EXPIRY_AUTHORITY_INVALID")
        _require_digest(self.source_receipt_digest, "EVIDENCE_EXPIRY_SOURCE_INVALID")
        identities = tuple(_event_entity_id(event) for event in self.events)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise EvidenceProjectionError("EVIDENCE_EXPIRY_EVENT_ORDER_INVALID")
        if self.plan_digest != _digest_object("EVIDENCE_EXPIRY_PLAN", self._unsigned()):
            raise EvidenceProjectionError("EVIDENCE_EXPIRY_PLAN_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        clock_sequence: int,
        predecessor_root_digest: str,
        authority_policy_digest: str,
        expiry_authority_id: str,
        source_receipt_digest: str,
        events: tuple[RegistryEvent, ...],
    ) -> EvidenceExpiryPlan:
        unsigned: dict[str, object] = {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
            "authority_policy_digest": authority_policy_digest,
            "clock_sequence": clock_sequence,
            "event_digests": [event.digest for event in events],
            "expiry_authority_id": expiry_authority_id,
            "predecessor_root_digest": predecessor_root_digest,
            "source_receipt_digest": source_receipt_digest,
        }
        return cls(
            clock_sequence=clock_sequence,
            predecessor_root_digest=predecessor_root_digest,
            authority_policy_digest=authority_policy_digest,
            expiry_authority_id=expiry_authority_id,
            source_receipt_digest=source_receipt_digest,
            events=events,
            plan_digest=_digest_object("EVIDENCE_EXPIRY_PLAN", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
            "authority_policy_digest": self.authority_policy_digest,
            "clock_sequence": self.clock_sequence,
            "event_digests": [event.digest for event in self.events],
            "expiry_authority_id": self.expiry_authority_id,
            "predecessor_root_digest": self.predecessor_root_digest,
            "source_receipt_digest": self.source_receipt_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "plan_digest": self.plan_digest}


class EvidenceExpiryPlanner:
    """Plan logical-clock EXPIRE events without mutating the supplied store."""

    def __init__(
        self,
        *,
        authority_policy: EvidenceAuthorityPolicy,
        expiry_authority_id: str,
    ) -> None:
        self.authority = EvidenceAuthorityResolver(authority_policy)
        self.expiry_authority_id = _require_token(
            expiry_authority_id,
            "EVIDENCE_EXPIRY_AUTHORITY_INVALID",
        )

    def plan(
        self,
        *,
        store: RegistryStore,
        clock_sequence: int,
        source_receipt_digest: str,
    ) -> EvidenceExpiryPlan:
        if type(clock_sequence) is not int or clock_sequence < 0:
            raise EvidenceProjectionError("EVIDENCE_EXPIRY_CLOCK_INVALID")
        _require_digest(source_receipt_digest, "EVIDENCE_EXPIRY_SOURCE_INVALID")
        predecessor_root = store.snapshot("EVIDENCE_UNIT").root_digest
        planned: list[RegistryEvent] = []
        for history in store.reconstruct_snapshot("EVIDENCE_UNIT"):
            evidence = project_evidence_history(history)
            if not _eligible_for_expiry(evidence, clock_sequence):
                continue
            assert evidence is not None
            event = build_evidence_event(
                evidence_id=evidence.evidence_id,
                entity_sequence=evidence.current_entity_sequence + 1,
                previous_entity_event_digest=evidence.current_event_digest,
                clock_sequence=clock_sequence,
                source_receipt_digest=source_receipt_digest,
                payload={
                    "operation": "EXPIRE",
                    "expiry_authority_id": self.expiry_authority_id,
                },
            )
            self.authority.require(event, evidence)
            reduce_evidence(evidence, event)
            planned.append(event)
        events = tuple(sorted(planned, key=_event_entity_id))
        return EvidenceExpiryPlan.build(
            clock_sequence=clock_sequence,
            predecessor_root_digest=predecessor_root,
            authority_policy_digest=self.authority.policy.policy_digest,
            expiry_authority_id=self.expiry_authority_id,
            source_receipt_digest=source_receipt_digest,
            events=events,
        )


def _eligible_for_expiry(evidence: EvidenceUnit | None, clock_sequence: int) -> bool:
    if evidence is None or evidence.status in _TERMINAL_STATUSES:
        return False
    if evidence.status not in {"VERIFIED", "CHALLENGED"}:
        return False
    if evidence.last_clock_sequence >= clock_sequence:
        return False
    return (
        evidence.expires_at_sequence is not None and clock_sequence >= evidence.expires_at_sequence
    )


@dataclass(frozen=True, slots=True)
class EvidenceImpactReceipt:
    evidence_id: str
    previous_status: str
    current_status: str
    trigger_event_digest: str
    affected_dependency_ids: tuple[str, ...]
    candidate_basis_ids: tuple[str, ...]
    candidate_semantic_object_ids: tuple[str, ...]
    impact_kind: str
    evidence_registry_root_digest: str
    completeness_boundary: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_token(self.evidence_id, "EVIDENCE_IMPACT_ID_INVALID")
        _require_token(self.previous_status, "EVIDENCE_IMPACT_PREVIOUS_STATUS_INVALID")
        _require_token(self.current_status, "EVIDENCE_IMPACT_CURRENT_STATUS_INVALID")
        _require_digest(self.trigger_event_digest, "EVIDENCE_IMPACT_EVENT_INVALID")
        _require_tokens(self.affected_dependency_ids, "EVIDENCE_IMPACT_DEPENDENCIES_INVALID")
        _require_tokens(self.candidate_basis_ids, "EVIDENCE_IMPACT_BASES_INVALID")
        _require_tokens(self.candidate_semantic_object_ids, "EVIDENCE_IMPACT_OBJECTS_INVALID")
        _require_token(self.impact_kind, "EVIDENCE_IMPACT_KIND_INVALID")
        _require_digest(self.evidence_registry_root_digest, "EVIDENCE_IMPACT_ROOT_INVALID")
        if type(self.completeness_boundary) is not str or not self.completeness_boundary:
            raise EvidenceProjectionError("EVIDENCE_IMPACT_BOUNDARY_INVALID")
        if self.receipt_digest != _digest_object("EVIDENCE_IMPACT_RECEIPT", self._unsigned()):
            raise EvidenceProjectionError("EVIDENCE_IMPACT_RECEIPT_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        evidence_id: str,
        previous_status: str,
        current_status: str,
        trigger_event_digest: str,
        affected_dependency_ids: tuple[str, ...],
        candidate_basis_ids: tuple[str, ...],
        candidate_semantic_object_ids: tuple[str, ...],
        evidence_registry_root_digest: str,
    ) -> EvidenceImpactReceipt:
        dependencies = tuple(sorted(set(affected_dependency_ids)))
        bases = tuple(sorted(set(candidate_basis_ids)))
        objects = tuple(sorted(set(candidate_semantic_object_ids)))
        boundary = (
            "Known transitive evidence dependents plus resolver-supplied candidate CSD "
            "references; substantive survival is decided by the semantic projector."
        )
        unsigned: dict[str, object] = {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_dependency_ids": list(dependencies),
            "candidate_basis_ids": list(bases),
            "candidate_semantic_object_ids": list(objects),
            "completeness_boundary": boundary,
            "current_status": current_status,
            "evidence_id": evidence_id,
            "evidence_registry_root_digest": evidence_registry_root_digest,
            "impact_kind": "REASSESSMENT_REQUIRED",
            "previous_status": previous_status,
            "trigger_event_digest": trigger_event_digest,
        }
        return cls(
            evidence_id=evidence_id,
            previous_status=previous_status,
            current_status=current_status,
            trigger_event_digest=trigger_event_digest,
            affected_dependency_ids=dependencies,
            candidate_basis_ids=bases,
            candidate_semantic_object_ids=objects,
            impact_kind="REASSESSMENT_REQUIRED",
            evidence_registry_root_digest=evidence_registry_root_digest,
            completeness_boundary=boundary,
            receipt_digest=_digest_object("EVIDENCE_IMPACT_RECEIPT", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_dependency_ids": list(self.affected_dependency_ids),
            "candidate_basis_ids": list(self.candidate_basis_ids),
            "candidate_semantic_object_ids": list(self.candidate_semantic_object_ids),
            "completeness_boundary": self.completeness_boundary,
            "current_status": self.current_status,
            "evidence_id": self.evidence_id,
            "evidence_registry_root_digest": self.evidence_registry_root_digest,
            "impact_kind": self.impact_kind,
            "previous_status": self.previous_status,
            "trigger_event_digest": self.trigger_event_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "receipt_digest": self.receipt_digest}


@dataclass(frozen=True, slots=True)
class EvidenceProjectionPlan:
    clock_claim_digest: str
    validated_event_digest: str
    semantic_receipt_digest: str
    clock_sequence: int
    predecessor_root_digest: str
    projected_root_digest: str
    authority_policy_digest: str
    expiry_plan_digest: str
    events: tuple[RegistryEvent, ...]
    authority_decisions: tuple[EvidenceAuthorityDecision, ...]
    impact_receipts: tuple[EvidenceImpactReceipt, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.clock_claim_digest,
            self.validated_event_digest,
            self.semantic_receipt_digest,
            self.predecessor_root_digest,
            self.projected_root_digest,
            self.authority_policy_digest,
            self.expiry_plan_digest,
            self.plan_digest,
        ):
            _require_digest(value, "EVIDENCE_PROJECTION_DIGEST_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 1:
            raise EvidenceProjectionError("EVIDENCE_PROJECTION_CLOCK_INVALID")
        if self.plan_digest != _digest_object("EVIDENCE_PROJECTION_PLAN", self._unsigned()):
            raise EvidenceProjectionError("EVIDENCE_PROJECTION_PLAN_DIGEST_MISMATCH")

    @property
    def event_digests(self) -> tuple[str, ...]:
        return tuple(event.digest for event in self.events)

    @property
    def authority_decision_digests(self) -> tuple[str, ...]:
        return tuple(item.decision_digest for item in self.authority_decisions)

    @property
    def impact_receipt_digests(self) -> tuple[str, ...]:
        return tuple(item.receipt_digest for item in self.impact_receipts)

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": PROJECTION_PLAN_SCHEMA_VERSION,
            "authority_decision_digests": list(self.authority_decision_digests),
            "authority_policy_digest": self.authority_policy_digest,
            "clock_claim_digest": self.clock_claim_digest,
            "clock_sequence": self.clock_sequence,
            "event_digests": list(self.event_digests),
            "expiry_plan_digest": self.expiry_plan_digest,
            "impact_receipt_digests": list(self.impact_receipt_digests),
            "predecessor_root_digest": self.predecessor_root_digest,
            "projected_root_digest": self.projected_root_digest,
            "semantic_receipt_digest": self.semantic_receipt_digest,
            "validated_event_digest": self.validated_event_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "plan_digest": self.plan_digest}


class StagedEvidenceProjectionAdapter:
    """Project in an isolated store; D5 remains responsible for publication."""

    def __init__(
        self,
        *,
        authority_policy: EvidenceAuthorityPolicy,
        expiry_authority_id: str,
        intent_resolver: EvidenceIntentResolver | None = None,
        impact_resolver: EvidenceImpactResolver | None = None,
    ) -> None:
        self.authority = EvidenceAuthorityResolver(authority_policy)
        self.expiry_planner = EvidenceExpiryPlanner(
            authority_policy=authority_policy,
            expiry_authority_id=expiry_authority_id,
        )
        self.intent_resolver = intent_resolver or EmptyEvidenceIntentResolver()
        self.impact_resolver = impact_resolver or EmptyEvidenceImpactResolver()

    def project(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        committed_store: RegistryStore,
    ) -> EvidenceProjectionPlan:
        sequence = _claim_sequence(claim)
        _verify_context(claim, validated_event, semantic_receipt)
        predecessor_root = committed_store.snapshot("EVIDENCE_UNIT").root_digest
        staged = _clone_store(committed_store)
        source_digest = _projection_source_digest(claim, validated_event, semantic_receipt)

        explicit = _canonical_events(
            self.intent_resolver.resolve(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                store=staged,
            )
        )
        _verify_event_bindings(explicit, sequence, source_digest)
        decisions: list[EvidenceAuthorityDecision] = []
        impacts: list[EvidenceImpactReceipt] = []
        _apply_events(
            explicit,
            staged,
            self.authority,
            self.impact_resolver,
            decisions,
            impacts,
        )

        expiry = self.expiry_planner.plan(
            store=staged,
            clock_sequence=sequence,
            source_receipt_digest=source_digest,
        )
        _apply_events(
            expiry.events,
            staged,
            self.authority,
            self.impact_resolver,
            decisions,
            impacts,
        )

        events = explicit + expiry.events
        projected_root = staged.snapshot("EVIDENCE_UNIT").root_digest
        unsigned: dict[str, object] = {
            "schema_version": PROJECTION_PLAN_SCHEMA_VERSION,
            "authority_decision_digests": [item.decision_digest for item in decisions],
            "authority_policy_digest": self.authority.policy.policy_digest,
            "clock_claim_digest": claim.digest,
            "clock_sequence": sequence,
            "event_digests": [event.digest for event in events],
            "expiry_plan_digest": expiry.plan_digest,
            "impact_receipt_digests": [item.receipt_digest for item in impacts],
            "predecessor_root_digest": predecessor_root,
            "projected_root_digest": projected_root,
            "semantic_receipt_digest": semantic_receipt.digest,
            "validated_event_digest": validated_event.digest,
        }
        return EvidenceProjectionPlan(
            clock_claim_digest=claim.digest,
            validated_event_digest=validated_event.digest,
            semantic_receipt_digest=semantic_receipt.digest,
            clock_sequence=sequence,
            predecessor_root_digest=predecessor_root,
            projected_root_digest=projected_root,
            authority_policy_digest=self.authority.policy.policy_digest,
            expiry_plan_digest=expiry.plan_digest,
            events=events,
            authority_decisions=tuple(decisions),
            impact_receipts=tuple(impacts),
            plan_digest=_digest_object("EVIDENCE_PROJECTION_PLAN", unsigned),
        )


def _apply_events(
    events: tuple[RegistryEvent, ...],
    store: RegistryStore,
    authority: EvidenceAuthorityResolver,
    impact_resolver: EvidenceImpactResolver,
    decisions: list[EvidenceAuthorityDecision],
    impacts: list[EvidenceImpactReceipt],
) -> None:
    for event in events:
        evidence_id = _event_entity_id(event)
        previous = project_evidence_history(store.reconstruct_entity("EVIDENCE_UNIT", evidence_id))
        decision = authority.require(event, previous)
        current = reduce_evidence(previous, event)
        store.append(event)
        decisions.append(decision)
        if previous is None or _event_operation(event) not in _IMPACT_OPERATIONS:
            continue
        bases, objects = impact_resolver.resolve(
            evidence=current,
            trigger_event=event,
            store=store,
        )
        impacts.append(
            EvidenceImpactReceipt.build(
                evidence_id=evidence_id,
                previous_status=previous.status,
                current_status=current.status,
                trigger_event_digest=event.digest,
                affected_dependency_ids=_dependent_ids(store, evidence_id),
                candidate_basis_ids=bases,
                candidate_semantic_object_ids=objects,
                evidence_registry_root_digest=store.snapshot("EVIDENCE_UNIT").root_digest,
            )
        )


def _clone_store(source: RegistryStore) -> InMemoryRegistryStore:
    target = InMemoryRegistryStore()
    for history in source.reconstruct_snapshot("EVIDENCE_UNIT"):
        for event in history:
            target.append(event)
    return target


def _canonical_events(events: tuple[RegistryEvent, ...]) -> tuple[RegistryEvent, ...]:
    keyed = [((_event_entity_id(event), _event_sequence(event)), event) for event in events]
    positions = [position for position, _ in keyed]
    if len(positions) != len(set(positions)):
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_DUPLICATE_EVENT_POSITION")
    return tuple(event for _, event in sorted(keyed, key=lambda item: item[0]))


def _verify_event_bindings(
    events: tuple[RegistryEvent, ...],
    sequence: int,
    source_digest: str,
) -> None:
    for event in events:
        value = event.to_json_value()
        if value.get("clock_sequence") != sequence:
            raise EvidenceProjectionError("EVIDENCE_PROJECTION_EVENT_CLOCK_MISMATCH")
        if value.get("source_receipt_digest") != source_digest:
            raise EvidenceProjectionError("EVIDENCE_PROJECTION_EVENT_SOURCE_MISMATCH")


def _dependent_ids(store: RegistryStore, evidence_id: str) -> tuple[str, ...]:
    projections: dict[str, EvidenceUnit] = {}
    for history in store.reconstruct_snapshot("EVIDENCE_UNIT"):
        current = project_evidence_history(history)
        if current is not None:
            projections[current.evidence_id] = current
    affected: set[str] = set()
    frontier = {evidence_id}
    while frontier:
        next_frontier: set[str] = set()
        for current in projections.values():
            if current.evidence_id in affected:
                continue
            if any(dependency in frontier for dependency in current.dependency_ids):
                affected.add(current.evidence_id)
                next_frontier.add(current.evidence_id)
        frontier = next_frontier
    return tuple(sorted(affected))


def _claim_sequence(claim: ClockClaim) -> int:
    value = claim.to_json_value().get("proposed_sequence")
    if type(value) is not int or value < 1:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_CLAIM_SEQUENCE_INVALID")
    return value


def _verify_context(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> None:
    claim_value = claim.to_json_value()
    semantic_value = semantic_receipt.to_json_value()
    if claim_value.get("validated_event_digest") != validated_event.digest:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_EVENT_MISMATCH")
    if semantic_value.get("clock_claim_digest") != claim.digest:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_SEMANTIC_CLAIM_MISMATCH")
    if semantic_value.get("validated_event_digest") != validated_event.digest:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_SEMANTIC_EVENT_MISMATCH")
    if semantic_value.get("projection_sequence") != claim_value.get("proposed_sequence"):
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_SEMANTIC_SEQUENCE_MISMATCH")


def _projection_source_digest(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> str:
    return _digest_object(
        "EVIDENCE_PROJECTION_SOURCE",
        {
            "clock_claim_digest": claim.digest,
            "semantic_receipt_digest": semantic_receipt.digest,
            "validated_event_digest": validated_event.digest,
        },
    )


def _event_entity_id(event: RegistryEvent) -> str:
    return _require_token(
        event.to_json_value().get("entity_id"),
        "EVIDENCE_PROJECTION_EVENT_ID_INVALID",
    )


def _event_sequence(event: RegistryEvent) -> int:
    value = event.to_json_value().get("entity_sequence")
    if type(value) is not int or value < 1:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_EVENT_SEQUENCE_INVALID")
    return value


def _event_operation(event: RegistryEvent) -> str:
    payload = event.to_json_value().get("payload")
    if type(payload) is not dict:
        raise EvidenceProjectionError("EVIDENCE_PROJECTION_EVENT_PAYLOAD_INVALID")
    return _require_token(
        payload.get("operation"),
        "EVIDENCE_PROJECTION_EVENT_OPERATION_INVALID",
    )


def _require_token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise EvidenceProjectionError(code)
    return value


def _require_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise EvidenceProjectionError(code)
    return value


def _require_tokens(values: tuple[str, ...], code: str) -> None:
    if type(values) is not tuple or values != tuple(sorted(values)):
        raise EvidenceProjectionError(code)
    if len(values) != len(set(values)):
        raise EvidenceProjectionError(code)
    for value in values:
        _require_token(value, code)


def _digest_object(domain: str, value: object) -> str:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()
