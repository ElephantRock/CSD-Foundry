"""Deterministic expiry planning, impact receipts, and staged assumption projection.

This module mirrors :mod:`csd_foundry.governance.v0_5.evidence_projection` exactly,
adapted for the assumption lifecycle (P3.2). It produces fully self-digesting
``AssumptionProjectionPlan`` artifacts without ever mutating the committed store.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from csd_foundry.governance.v0_5.assumption import (
    STANDING_ADMITTED,
    STANDING_CONFIRMED,
    Assumption,
    build_assumption_event,
    project_assumption_history,
    reduce_assumption,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStore

EXPIRY_PLAN_SCHEMA_VERSION = "assumption-expiry-plan/1"
IMPACT_RECEIPT_SCHEMA_VERSION = "assumption-impact-receipt/1"
PROJECTION_PLAN_SCHEMA_VERSION = "assumption-projection-plan/1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_EXPIRABLE_STANDINGS = {STANDING_ADMITTED, STANDING_CONFIRMED}
_IMPACT_OPERATIONS = {
    "CHALLENGE",
    "RESOLVE_CHALLENGES",
    "CONFIRM",
    "REJECT",
    "EXPIRE",
    "SUPERSEDE",
}


class AssumptionProjectionError(RuntimeError):
    """Stable fail-closed error for staged assumption projection."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class AssumptionIntentResolver(Protocol):
    """Resolve explicit intent events from claim/event/semantic context."""

    def resolve(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        store: RegistryStore,
        evidence_root: str,
    ) -> tuple[RegistryEvent, ...]: ...


class AssumptionExpiryAuthority(Protocol):
    """Provide the expiry authority identity and per-assumption receipt digest."""

    @property
    def expiry_authority_id(self) -> str: ...

    def expiry_receipt_digest(self, *, assumption_id: str, clock_sequence: int) -> str: ...


class AssumptionImpactResolver(Protocol):
    """Optional hook for resolver-supplied candidate references (unused by default)."""

    def resolve(
        self,
        *,
        assumption: Assumption,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]: ...


class EmptyAssumptionIntentResolver:
    def resolve(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        store: RegistryStore,
        evidence_root: str,
    ) -> tuple[RegistryEvent, ...]:
        del claim, validated_event, semantic_receipt, store, evidence_root
        return ()


class EmptyAssumptionImpactResolver:
    def resolve(
        self,
        *,
        assumption: Assumption,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        del assumption, trigger_event, store
        return (), ()


@dataclass(frozen=True, slots=True)
class AssumptionExpiryPlan:
    """Self-digesting, read-only expiry plan produced by ``AssumptionExpiryPlanner``."""

    clock_sequence: int
    predecessor_root_digest: str
    expiry_authority_id: str
    source_receipt_digest: str
    events: tuple[RegistryEvent, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        if type(self.clock_sequence) is not int or self.clock_sequence < 0:
            raise AssumptionProjectionError("ASSUMPTION_EXPIRY_CLOCK_INVALID")
        _require_digest(self.predecessor_root_digest, "ASSUMPTION_EXPIRY_ROOT_INVALID")
        _require_token(self.expiry_authority_id, "ASSUMPTION_EXPIRY_AUTHORITY_INVALID")
        _require_digest(self.source_receipt_digest, "ASSUMPTION_EXPIRY_SOURCE_INVALID")
        identities = tuple(_event_entity_id(event) for event in self.events)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise AssumptionProjectionError("ASSUMPTION_EXPIRY_EVENT_ORDER_INVALID")
        if self.plan_digest != _digest_object("ASSUMPTION_EXPIRY_PLAN", self._unsigned()):
            raise AssumptionProjectionError("ASSUMPTION_EXPIRY_PLAN_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        clock_sequence: int,
        predecessor_root_digest: str,
        expiry_authority_id: str,
        source_receipt_digest: str,
        events: tuple[RegistryEvent, ...],
    ) -> AssumptionExpiryPlan:
        unsigned: dict[str, object] = {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
            "authority_policy_digest": None,
            "clock_sequence": clock_sequence,
            "event_digests": [event.digest for event in events],
            "expiry_authority_id": expiry_authority_id,
            "predecessor_root_digest": predecessor_root_digest,
            "source_receipt_digest": source_receipt_digest,
        }
        return cls(
            clock_sequence=clock_sequence,
            predecessor_root_digest=predecessor_root_digest,
            expiry_authority_id=expiry_authority_id,
            source_receipt_digest=source_receipt_digest,
            events=events,
            plan_digest=_digest_object("ASSUMPTION_EXPIRY_PLAN", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
            "authority_policy_digest": None,
            "clock_sequence": self.clock_sequence,
            "event_digests": [event.digest for event in self.events],
            "expiry_authority_id": self.expiry_authority_id,
            "predecessor_root_digest": self.predecessor_root_digest,
            "source_receipt_digest": self.source_receipt_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "plan_digest": self.plan_digest}


class AssumptionExpiryPlanner:
    """Plan logical-clock EXPIRE events without mutating the supplied store."""

    def __init__(self, *, expiry_authority: AssumptionExpiryAuthority) -> None:
        self.expiry_authority = expiry_authority

    def plan(
        self,
        *,
        store: RegistryStore,
        clock_sequence: int,
        source_receipt_digest: str,
    ) -> AssumptionExpiryPlan:
        if type(clock_sequence) is not int or clock_sequence < 0:
            raise AssumptionProjectionError("ASSUMPTION_EXPIRY_CLOCK_INVALID")
        _require_digest(source_receipt_digest, "ASSUMPTION_EXPIRY_SOURCE_INVALID")
        predecessor_root = store.snapshot("ASSUMPTION").root_digest
        planned: list[RegistryEvent] = []
        for history in store.reconstruct_snapshot("ASSUMPTION"):
            assumption = project_assumption_history(history)
            if not _eligible_for_expiry(assumption, clock_sequence):
                continue
            assert assumption is not None
            event = build_assumption_event(
                assumption_id=assumption.assumption_id,
                entity_sequence=assumption.current_entity_sequence + 1,
                previous_entity_event_digest=assumption.current_event_digest,
                clock_sequence=clock_sequence,
                source_receipt_digest=source_receipt_digest,
                payload={
                    "operation": "EXPIRE",
                    "expiry_authority_id": self.expiry_authority.expiry_authority_id,
                    "expiry_receipt_digest": self.expiry_authority.expiry_receipt_digest(
                        assumption_id=assumption.assumption_id,
                        clock_sequence=clock_sequence,
                    ),
                },
            )
            reduce_assumption(assumption, event)
            planned.append(event)
        events = tuple(sorted(planned, key=_event_entity_id))
        return AssumptionExpiryPlan.build(
            clock_sequence=clock_sequence,
            predecessor_root_digest=predecessor_root,
            expiry_authority_id=self.expiry_authority.expiry_authority_id,
            source_receipt_digest=source_receipt_digest,
            events=events,
        )


def _eligible_for_expiry(assumption: Assumption | None, clock_sequence: int) -> bool:
    if assumption is None:
        return False
    if assumption.standing not in _EXPIRABLE_STANDINGS:
        return False
    if assumption.last_clock_sequence >= clock_sequence:
        return False
    return (
        assumption.expires_at_sequence is not None
        and clock_sequence >= assumption.expires_at_sequence
    )


@dataclass(frozen=True, slots=True)
class AssumptionImpactReceipt:
    """Self-digesting impact receipt for one assumption impact operation."""

    assumption_id: str
    previous_status: str
    current_status: str
    trigger_event_digest: str
    affected_assumption_ids: tuple[str, ...]
    assumption_registry_root_digest: str
    completeness_boundary: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "ASSUMPTION_IMPACT_ID_INVALID")
        _require_token(self.previous_status, "ASSUMPTION_IMPACT_PREVIOUS_STATUS_INVALID")
        _require_token(self.current_status, "ASSUMPTION_IMPACT_CURRENT_STATUS_INVALID")
        _require_digest(self.trigger_event_digest, "ASSUMPTION_IMPACT_EVENT_INVALID")
        _require_tokens(self.affected_assumption_ids, "ASSUMPTION_IMPACT_DEPENDENCIES_INVALID")
        _require_digest(self.assumption_registry_root_digest, "ASSUMPTION_IMPACT_ROOT_INVALID")
        if type(self.completeness_boundary) is not str or not self.completeness_boundary:
            raise AssumptionProjectionError("ASSUMPTION_IMPACT_BOUNDARY_INVALID")
        if self.receipt_digest != _digest_object("ASSUMPTION_IMPACT_RECEIPT", self._unsigned()):
            raise AssumptionProjectionError("ASSUMPTION_IMPACT_RECEIPT_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        assumption_id: str,
        previous_status: str,
        current_status: str,
        trigger_event_digest: str,
        affected_assumption_ids: tuple[str, ...],
        assumption_registry_root_digest: str,
    ) -> AssumptionImpactReceipt:
        dependencies = tuple(sorted(set(affected_assumption_ids)))
        boundary = (
            "Reverse transitive closure over assumption_dependency_ids; substantive "
            "survival is decided by the semantic projector."
        )
        unsigned: dict[str, object] = {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_assumption_ids": list(dependencies),
            "assumption_id": assumption_id,
            "assumption_registry_root_digest": assumption_registry_root_digest,
            "completeness_boundary": boundary,
            "current_status": current_status,
            "impact_kind": "REASSESSMENT_REQUIRED",
            "previous_status": previous_status,
            "trigger_event_digest": trigger_event_digest,
        }
        return cls(
            assumption_id=assumption_id,
            previous_status=previous_status,
            current_status=current_status,
            trigger_event_digest=trigger_event_digest,
            affected_assumption_ids=dependencies,
            assumption_registry_root_digest=assumption_registry_root_digest,
            completeness_boundary=boundary,
            receipt_digest=_digest_object("ASSUMPTION_IMPACT_RECEIPT", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_assumption_ids": list(self.affected_assumption_ids),
            "assumption_id": self.assumption_id,
            "assumption_registry_root_digest": self.assumption_registry_root_digest,
            "completeness_boundary": self.completeness_boundary,
            "current_status": self.current_status,
            "impact_kind": "REASSESSMENT_REQUIRED",
            "previous_status": self.previous_status,
            "trigger_event_digest": self.trigger_event_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "receipt_digest": self.receipt_digest}


@dataclass(frozen=True, slots=True)
class AssumptionProjectionPlan:
    """Self-digesting staged assumption projection plan."""

    clock_claim_digest: str
    validated_event_digest: str
    semantic_receipt_digest: str
    clock_sequence: int
    predecessor_root_digest: str
    projected_root_digest: str
    events: tuple[RegistryEvent, ...]
    impact_receipts: tuple[AssumptionImpactReceipt, ...]
    expiry_plan_digest: str
    plan_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.clock_claim_digest,
            self.validated_event_digest,
            self.semantic_receipt_digest,
            self.predecessor_root_digest,
            self.projected_root_digest,
            self.expiry_plan_digest,
            self.plan_digest,
        ):
            _require_digest(value, "ASSUMPTION_PROJECTION_DIGEST_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 1:
            raise AssumptionProjectionError("ASSUMPTION_PROJECTION_CLOCK_INVALID")
        if self.plan_digest != _digest_object("ASSUMPTION_PROJECTION_PLAN", self._unsigned()):
            raise AssumptionProjectionError("ASSUMPTION_PROJECTION_PLAN_DIGEST_MISMATCH")

    @property
    def event_digests(self) -> tuple[str, ...]:
        return tuple(event.digest for event in self.events)

    @property
    def impact_receipt_digests(self) -> tuple[str, ...]:
        return tuple(item.receipt_digest for item in self.impact_receipts)

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": PROJECTION_PLAN_SCHEMA_VERSION,
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


class StagedAssumptionProjectionAdapter:
    """Project assumption impacts/expiry in an isolated store; D5 publishes."""

    def __init__(
        self,
        *,
        expiry_authority: AssumptionExpiryAuthority,
        intent_resolver: AssumptionIntentResolver | None = None,
        impact_resolver: AssumptionImpactResolver | None = None,
    ) -> None:
        self.expiry_planner = AssumptionExpiryPlanner(expiry_authority=expiry_authority)
        self.intent_resolver = intent_resolver or EmptyAssumptionIntentResolver()
        self.impact_resolver = impact_resolver or EmptyAssumptionImpactResolver()

    def project(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        committed_store: RegistryStore,
        evidence_root_digest: str,
    ) -> AssumptionProjectionPlan:
        sequence = _claim_sequence(claim)
        _verify_context(claim, validated_event, semantic_receipt)
        _require_digest(evidence_root_digest, "ASSUMPTION_PROJECTION_EVIDENCE_ROOT_INVALID")
        predecessor_root = committed_store.snapshot("ASSUMPTION").root_digest
        staged = _clone_store(committed_store)
        source_digest = _projection_source_digest(claim, validated_event, semantic_receipt)

        explicit = _canonical_events(
            self.intent_resolver.resolve(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                store=staged,
                evidence_root=evidence_root_digest,
            )
        )
        _verify_event_bindings(explicit, sequence, source_digest)
        impacts: list[AssumptionImpactReceipt] = []
        _apply_events(
            explicit,
            staged,
            self.impact_resolver,
            impacts,
        )

        # Expiry is planned against the staged clone AFTER explicit events have
        # been applied. An assumption explicitly expired by intent has had its
        # ``last_clock_sequence`` advanced to the current clock, so it is no
        # longer eligible (``last_clock_sequence >= clock_sequence``) and will
        # not receive a duplicate planned expiry event.
        expiry = self.expiry_planner.plan(
            store=staged,
            clock_sequence=sequence,
            source_receipt_digest=source_digest,
        )
        _apply_events(
            expiry.events,
            staged,
            self.impact_resolver,
            impacts,
        )

        events = explicit + expiry.events
        projected_root = staged.snapshot("ASSUMPTION").root_digest
        unsigned: dict[str, object] = {
            "schema_version": PROJECTION_PLAN_SCHEMA_VERSION,
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
        return AssumptionProjectionPlan(
            clock_claim_digest=claim.digest,
            validated_event_digest=validated_event.digest,
            semantic_receipt_digest=semantic_receipt.digest,
            clock_sequence=sequence,
            predecessor_root_digest=predecessor_root,
            projected_root_digest=projected_root,
            events=events,
            impact_receipts=tuple(impacts),
            expiry_plan_digest=expiry.plan_digest,
            plan_digest=_digest_object("ASSUMPTION_PROJECTION_PLAN", unsigned),
        )


def _apply_events(
    events: tuple[RegistryEvent, ...],
    store: RegistryStore,
    impact_resolver: AssumptionImpactResolver,
    impacts: list[AssumptionImpactReceipt],
) -> None:
    for event in events:
        assumption_id = _event_entity_id(event)
        previous = project_assumption_history(store.reconstruct_entity("ASSUMPTION", assumption_id))
        current = reduce_assumption(previous, event)
        store.append(event)
        if previous is None or _event_operation(event) not in _IMPACT_OPERATIONS:
            continue
        # The impact resolver is consulted for parity with the evidence projection
        # adapter; its candidate references are reserved for future semantic-layer
        # consumption and do not alter the assumption impact receipt itself.
        impact_resolver.resolve(
            assumption=current,
            trigger_event=event,
            store=store,
        )
        impacts.append(
            AssumptionImpactReceipt.build(
                assumption_id=assumption_id,
                previous_status=previous.status,
                current_status=current.status,
                trigger_event_digest=event.digest,
                affected_assumption_ids=_dependent_ids(store, assumption_id),
                assumption_registry_root_digest=store.snapshot("ASSUMPTION").root_digest,
            )
        )


def _clone_store(source: RegistryStore) -> InMemoryRegistryStore:
    target = InMemoryRegistryStore()
    for history in source.reconstruct_snapshot("ASSUMPTION"):
        for event in history:
            target.append(event)
    # Also clone EVIDENCE_UNIT histories so evidence_root_digest can be verified
    # against the staged clone if a caller/intent resolver needs it.
    for history in source.reconstruct_snapshot("EVIDENCE_UNIT"):
        for event in history:
            target.append(event)
    return target


def _canonical_events(events: tuple[RegistryEvent, ...]) -> tuple[RegistryEvent, ...]:
    keyed = [((_event_entity_id(event), _event_sequence(event)), event) for event in events]
    positions = [position for position, _ in keyed]
    if len(positions) != len(set(positions)):
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_DUPLICATE_EVENT_POSITION")
    return tuple(event for _, event in sorted(keyed, key=lambda item: item[0]))


def _verify_event_bindings(
    events: tuple[RegistryEvent, ...],
    sequence: int,
    source_digest: str,
) -> None:
    for event in events:
        value = event.to_json_value()
        if value.get("clock_sequence") != sequence:
            raise AssumptionProjectionError("ASSUMPTION_PROJECTION_EVENT_CLOCK_MISMATCH")
        if value.get("source_receipt_digest") != source_digest:
            raise AssumptionProjectionError("ASSUMPTION_PROJECTION_EVENT_SOURCE_MISMATCH")


def _dependent_ids(store: RegistryStore, assumption_id: str) -> tuple[str, ...]:
    """Reverse transitive closure over ``assumption_dependency_ids``.

    If A.assumption_dependency_ids contains B, then an event on B affects A.
    Transitively expands: dependents of B, dependents of dependents of B, etc.
    Excludes the trigger ``assumption_id`` itself; returns sorted unique ids.
    """
    projections: dict[str, Assumption] = {}
    for history in store.reconstruct_snapshot("ASSUMPTION"):
        current = project_assumption_history(history)
        if current is not None:
            projections[current.assumption_id] = current
    affected: set[str] = set()
    frontier = {assumption_id}
    while frontier:
        next_frontier: set[str] = set()
        for current in projections.values():
            if current.assumption_id in affected:
                continue
            if any(dependency in frontier for dependency in current.assumption_dependency_ids):
                affected.add(current.assumption_id)
                next_frontier.add(current.assumption_id)
        frontier = next_frontier
    affected.discard(assumption_id)
    return tuple(sorted(affected))


def _claim_sequence(claim: ClockClaim) -> int:
    value = claim.to_json_value().get("proposed_sequence")
    if type(value) is not int or value < 1:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_CLAIM_SEQUENCE_INVALID")
    return value


def _verify_context(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> None:
    claim_value = claim.to_json_value()
    semantic_value = semantic_receipt.to_json_value()
    if claim_value.get("validated_event_digest") != validated_event.digest:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_EVENT_MISMATCH")
    if semantic_value.get("clock_claim_digest") != claim.digest:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_SEMANTIC_CLAIM_MISMATCH")
    if semantic_value.get("validated_event_digest") != validated_event.digest:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_SEMANTIC_EVENT_MISMATCH")
    if semantic_value.get("projection_sequence") != claim_value.get("proposed_sequence"):
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_SEMANTIC_SEQUENCE_MISMATCH")


def _projection_source_digest(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> str:
    return _digest_object(
        "ASSUMPTION_PROJECTION_SOURCE",
        {
            "clock_claim_digest": claim.digest,
            "semantic_receipt_digest": semantic_receipt.digest,
            "validated_event_digest": validated_event.digest,
        },
    )


def _event_entity_id(event: RegistryEvent) -> str:
    return _require_token(
        event.to_json_value().get("entity_id"),
        "ASSUMPTION_PROJECTION_EVENT_ID_INVALID",
    )


def _event_sequence(event: RegistryEvent) -> int:
    value = event.to_json_value().get("entity_sequence")
    if type(value) is not int or value < 1:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_EVENT_SEQUENCE_INVALID")
    return value


def _event_operation(event: RegistryEvent) -> str:
    payload = event.to_json_value().get("payload")
    if type(payload) is not dict:
        raise AssumptionProjectionError("ASSUMPTION_PROJECTION_EVENT_PAYLOAD_INVALID")
    return _require_token(
        payload.get("operation"),
        "ASSUMPTION_PROJECTION_EVENT_OPERATION_INVALID",
    )


def _require_token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AssumptionProjectionError(code)
    return value


def _require_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AssumptionProjectionError(code)
    return value


def _require_tokens(values: tuple[str, ...], code: str) -> None:
    if type(values) is not tuple or values != tuple(sorted(values)):
        raise AssumptionProjectionError(code)
    if len(values) != len(set(values)):
        raise AssumptionProjectionError(code)
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
