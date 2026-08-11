"""Deterministic expiry planning, impact receipts, and staged alternative-model projection.

This module mirrors :mod:`csd_foundry.governance.v0_5._assumption_projection`
exactly, adapted for the alternative-model lifecycle (P3.5). It produces fully
self-digesting :class:`AlternativeModelProjectionPlan` artifacts without ever
mutating the committed store.

Binding model (P3.5 review corrections):

* Explicit intent events carry their own operation-specific receipt bindings.
  The adapter validates they are well-formed (correct registry type, clock
  consistency) but does NOT require a generic source digest.
* Governed ADMIT events are validated against caller-supplied
  :class:`GovernedAlternativeModelAuthorization` + :class:`ComparisonReceipt`
  evidence: the event's ``source_receipt_digest`` must equal the
  ``authorization.authorization_digest``, and the comparison receipt's
  structural-difference set must match the authorization's.
* The expiry authority returns a self-digesting
  :class:`AlternativeModelExpiryAuthorization` per model; the planner does not
  invent or trust arbitrary authority/receipt strings.
* The alternative-model staging clone carries ALTERNATIVE_MODEL events only.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from csd_foundry.governance.v0_5._governed_alternative_model import (
    ComparisonReceipt,
    GovernedAlternativeModelAuthorization,
)
from csd_foundry.governance.v0_5.alternative_model import (
    STANDING_ADMITTED,
    STANDING_CONFIRMED,
    AlternativeModel,
    build_alternative_model_event,
    project_alternative_model_history,
    reduce_alternative_model,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStore

EXPIRY_PLAN_SCHEMA_VERSION = "alternative-model-expiry-plan/1"
EXPIRY_AUTHORIZATION_SCHEMA_VERSION = "alternative-model-expiry-authorization/1"
IMPACT_RECEIPT_SCHEMA_VERSION = "alternative-model-impact-receipt/1"
PROJECTION_PLAN_SCHEMA_VERSION = "alternative-model-projection-plan/1"

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


class AlternativeModelProjectionError(RuntimeError):
    """Stable fail-closed error for staged alternative-model projection."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


class AlternativeModelIntentResolver(Protocol):
    """Resolve explicit intent events from claim/event/semantic context."""

    def resolve(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        store: RegistryStore,
    ) -> tuple[RegistryEvent, ...]: ...


class AlternativeModelExpiryAuthority(Protocol):
    """Provide the expiry authority identity and per-model authorization.

    The authority identity (``expiry_authority_id``) labels the plan. The
    per-model :meth:`expiry_authorization` returns a self-digesting
    :class:`AlternativeModelExpiryAuthorization` whose ``expiry_receipt_digest``
    is the trust root for each planned EXPIRE event.
    """

    @property
    def expiry_authority_id(self) -> str: ...

    def expiry_authorization(
        self, *, model_id: str, clock_sequence: int
    ) -> AlternativeModelExpiryAuthorization | None: ...


class AlternativeModelImpactResolver(Protocol):
    """Optional hook for resolver-supplied candidate references (unused by default)."""

    def resolve(
        self,
        *,
        model: AlternativeModel,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]: ...


class EmptyAlternativeModelIntentResolver:
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


class EmptyAlternativeModelImpactResolver:
    def resolve(
        self,
        *,
        model: AlternativeModel,
        trigger_event: RegistryEvent,
        store: RegistryStore,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        del model, trigger_event, store
        return (), ()


@dataclass(frozen=True, slots=True)
class AlternativeModelExpiryAuthorization:
    """Self-digesting per-model expiry authorization.

    Binds the expiry authority identity, the per-model expiry receipt, the target
    model, and the logical clock at which the expiry is authorized. The planner
    builds each EXPIRE event's payload from this object's fields; the
    ``authorization_digest`` is the trust root.
    """

    model_id: str
    clock_sequence: int
    expiry_authority_id: str
    expiry_receipt_digest: str
    authorization_digest: str

    def __post_init__(self) -> None:
        _require_token(self.model_id, "ALT_MODEL_EXPIRY_AUTH_ID_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 1:
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_CLOCK_INVALID")
        _require_token(self.expiry_authority_id, "ALT_MODEL_EXPIRY_AUTH_AUTHORITY_INVALID")
        _require_digest(self.expiry_receipt_digest, "ALT_MODEL_EXPIRY_AUTH_RECEIPT_INVALID")
        if self.authorization_digest != _digest_object(
            "ALTERNATIVE_MODEL_EXPIRY_AUTHORIZATION", self._unsigned()
        ):
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        model_id: str,
        clock_sequence: int,
        expiry_authority_id: str,
        expiry_receipt_digest: str,
    ) -> AlternativeModelExpiryAuthorization:
        if type(clock_sequence) is not int or clock_sequence < 1:
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_CLOCK_INVALID")
        _require_token(model_id, "ALT_MODEL_EXPIRY_AUTH_ID_INVALID")
        _require_token(expiry_authority_id, "ALT_MODEL_EXPIRY_AUTH_AUTHORITY_INVALID")
        _require_digest(expiry_receipt_digest, "ALT_MODEL_EXPIRY_AUTH_RECEIPT_INVALID")
        unsigned: dict[str, object] = {
            "schema_version": EXPIRY_AUTHORIZATION_SCHEMA_VERSION,
            "model_id": model_id,
            "clock_sequence": clock_sequence,
            "expiry_authority_id": expiry_authority_id,
            "expiry_receipt_digest": expiry_receipt_digest,
        }
        return cls(
            model_id=model_id,
            clock_sequence=clock_sequence,
            expiry_authority_id=expiry_authority_id,
            expiry_receipt_digest=expiry_receipt_digest,
            authorization_digest=_digest_object("ALTERNATIVE_MODEL_EXPIRY_AUTHORIZATION", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": EXPIRY_AUTHORIZATION_SCHEMA_VERSION,
            "model_id": self.model_id,
            "clock_sequence": self.clock_sequence,
            "expiry_authority_id": self.expiry_authority_id,
            "expiry_receipt_digest": self.expiry_receipt_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "authorization_digest": self.authorization_digest}


@dataclass(frozen=True, slots=True)
class AlternativeModelExpiryPlan:
    """Self-digesting, read-only expiry plan produced by the planner."""

    clock_sequence: int
    predecessor_root_digest: str
    expiry_authority_id: str
    source_receipt_digest: str
    events: tuple[RegistryEvent, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        if type(self.clock_sequence) is not int or self.clock_sequence < 0:
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_CLOCK_INVALID")
        _require_digest(self.predecessor_root_digest, "ALT_MODEL_EXPIRY_ROOT_INVALID")
        _require_token(self.expiry_authority_id, "ALT_MODEL_EXPIRY_AUTHORITY_INVALID")
        _require_digest(self.source_receipt_digest, "ALT_MODEL_EXPIRY_SOURCE_INVALID")
        identities = tuple(_event_entity_id(event) for event in self.events)
        if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_EVENT_ORDER_INVALID")
        if self.plan_digest != _digest_object("ALTERNATIVE_MODEL_EXPIRY_PLAN", self._unsigned()):
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_PLAN_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        clock_sequence: int,
        predecessor_root_digest: str,
        expiry_authority_id: str,
        source_receipt_digest: str,
        events: tuple[RegistryEvent, ...],
    ) -> AlternativeModelExpiryPlan:
        unsigned: dict[str, object] = {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
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
            plan_digest=_digest_object("ALTERNATIVE_MODEL_EXPIRY_PLAN", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": EXPIRY_PLAN_SCHEMA_VERSION,
            "clock_sequence": self.clock_sequence,
            "event_digests": [event.digest for event in self.events],
            "expiry_authority_id": self.expiry_authority_id,
            "predecessor_root_digest": self.predecessor_root_digest,
            "source_receipt_digest": self.source_receipt_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "plan_digest": self.plan_digest}


class AlternativeModelExpiryPlanner:
    """Plan logical-clock EXPIRE events without mutating the supplied store.

    Each EXPIRE event's ``expiry_authority_id`` and ``expiry_receipt_digest`` come
    from a self-digesting :class:`AlternativeModelExpiryAuthorization` supplied by
    the expiry authority.
    """

    def __init__(self, *, expiry_authority: AlternativeModelExpiryAuthority) -> None:
        self.expiry_authority = expiry_authority

    def plan(
        self,
        *,
        store: RegistryStore,
        clock_sequence: int,
        source_receipt_digest: str,
    ) -> AlternativeModelExpiryPlan:
        if type(clock_sequence) is not int or clock_sequence < 0:
            raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_CLOCK_INVALID")
        _require_digest(source_receipt_digest, "ALT_MODEL_EXPIRY_SOURCE_INVALID")
        authority_id = self.expiry_authority.expiry_authority_id
        predecessor_root = store.snapshot("ALTERNATIVE_MODEL").root_digest
        planned: list[RegistryEvent] = []
        for history in store.reconstruct_snapshot("ALTERNATIVE_MODEL"):
            model = project_alternative_model_history(history)
            if not _eligible_for_expiry(model, clock_sequence):
                continue
            assert model is not None
            authorization = self.expiry_authority.expiry_authorization(
                model_id=model.model_id,
                clock_sequence=clock_sequence,
            )
            if authorization is None:
                continue
            if type(authorization) is not AlternativeModelExpiryAuthorization:
                raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_TYPE_INVALID")
            if authorization.model_id != model.model_id:
                raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_MODEL_MISMATCH")
            if authorization.clock_sequence != clock_sequence:
                raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_CLOCK_MISMATCH")
            if authorization.expiry_authority_id != authority_id:
                raise AlternativeModelProjectionError("ALT_MODEL_EXPIRY_AUTH_AUTHORITY_MISMATCH")
            event = build_alternative_model_event(
                model_id=model.model_id,
                entity_sequence=model.current_entity_sequence + 1,
                previous_entity_event_digest=model.current_event_digest,
                clock_sequence=clock_sequence,
                source_receipt_digest=source_receipt_digest,
                payload={
                    "operation": "EXPIRE",
                    "expiry_authority_id": authorization.expiry_authority_id,
                    "expiry_receipt_digest": authorization.expiry_receipt_digest,
                },
            )
            reduce_alternative_model(model, event)
            planned.append(event)
        events = tuple(sorted(planned, key=_event_entity_id))
        return AlternativeModelExpiryPlan.build(
            clock_sequence=clock_sequence,
            predecessor_root_digest=predecessor_root,
            expiry_authority_id=authority_id,
            source_receipt_digest=source_receipt_digest,
            events=events,
        )


def _eligible_for_expiry(model: AlternativeModel | None, clock_sequence: int) -> bool:
    if model is None:
        return False
    if model.separation_status not in _EXPIRABLE_STANDINGS:
        return False
    if model.last_clock_sequence >= clock_sequence:
        return False
    return model.expires_at_sequence is not None and clock_sequence >= model.expires_at_sequence


@dataclass(frozen=True, slots=True)
class AlternativeModelImpactReceipt:
    """Self-digesting impact receipt for one alternative-model impact operation."""

    model_id: str
    previous_status: str
    current_status: str
    trigger_event_digest: str
    affected_model_ids: tuple[str, ...]
    alternative_model_registry_root_digest: str
    completeness_boundary: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_token(self.model_id, "ALT_MODEL_IMPACT_ID_INVALID")
        _require_token(self.previous_status, "ALT_MODEL_IMPACT_PREVIOUS_STATUS_INVALID")
        _require_token(self.current_status, "ALT_MODEL_IMPACT_CURRENT_STATUS_INVALID")
        _require_digest(self.trigger_event_digest, "ALT_MODEL_IMPACT_EVENT_INVALID")
        _require_tokens(self.affected_model_ids, "ALT_MODEL_IMPACT_DEPENDENCIES_INVALID")
        _require_digest(
            self.alternative_model_registry_root_digest, "ALT_MODEL_IMPACT_ROOT_INVALID"
        )
        if type(self.completeness_boundary) is not str or not self.completeness_boundary:
            raise AlternativeModelProjectionError("ALT_MODEL_IMPACT_BOUNDARY_INVALID")
        if self.receipt_digest != _digest_object(
            "ALTERNATIVE_MODEL_IMPACT_RECEIPT", self._unsigned()
        ):
            raise AlternativeModelProjectionError("ALT_MODEL_IMPACT_RECEIPT_DIGEST_MISMATCH")

    @classmethod
    def build(
        cls,
        *,
        model_id: str,
        previous_status: str,
        current_status: str,
        trigger_event_digest: str,
        affected_model_ids: tuple[str, ...],
        alternative_model_registry_root_digest: str,
    ) -> AlternativeModelImpactReceipt:
        dependencies = tuple(sorted(set(affected_model_ids)))
        boundary = (
            "Reverse transitive closure over primary_model_id links; substantive "
            "survival is decided by the semantic projector."
        )
        unsigned: dict[str, object] = {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_model_ids": list(dependencies),
            "alternative_model_registry_root_digest": alternative_model_registry_root_digest,
            "completeness_boundary": boundary,
            "current_status": current_status,
            "impact_kind": "REASSESSMENT_REQUIRED",
            "model_id": model_id,
            "previous_status": previous_status,
            "trigger_event_digest": trigger_event_digest,
        }
        return cls(
            model_id=model_id,
            previous_status=previous_status,
            current_status=current_status,
            trigger_event_digest=trigger_event_digest,
            affected_model_ids=dependencies,
            alternative_model_registry_root_digest=alternative_model_registry_root_digest,
            completeness_boundary=boundary,
            receipt_digest=_digest_object("ALTERNATIVE_MODEL_IMPACT_RECEIPT", unsigned),
        )

    def _unsigned(self) -> dict[str, object]:
        return {
            "schema_version": IMPACT_RECEIPT_SCHEMA_VERSION,
            "affected_model_ids": list(self.affected_model_ids),
            "alternative_model_registry_root_digest": self.alternative_model_registry_root_digest,
            "completeness_boundary": self.completeness_boundary,
            "current_status": self.current_status,
            "impact_kind": "REASSESSMENT_REQUIRED",
            "model_id": self.model_id,
            "previous_status": self.previous_status,
            "trigger_event_digest": self.trigger_event_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned(), "receipt_digest": self.receipt_digest}


@dataclass(frozen=True, slots=True)
class AlternativeModelProjectionPlan:
    """Self-digesting staged alternative-model projection plan."""

    clock_claim_digest: str
    validated_event_digest: str
    semantic_receipt_digest: str
    clock_sequence: int
    predecessor_root_digest: str
    projected_root_digest: str
    events: tuple[RegistryEvent, ...]
    impact_receipts: tuple[AlternativeModelImpactReceipt, ...]
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
            _require_digest(value, "ALT_MODEL_PROJECTION_DIGEST_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 1:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_CLOCK_INVALID")
        if self.plan_digest != _digest_object(
            "ALTERNATIVE_MODEL_PROJECTION_PLAN", self._unsigned()
        ):
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_PLAN_DIGEST_MISMATCH")

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


class StagedAlternativeModelProjectionAdapter:
    """Project alternative-model impacts/expiry in an isolated store; D5 publishes.

    The staging clone is produced by ``staging_store_factory`` (default
    :class:`InMemoryRegistryStore`) so callers can inject a fault boundary for
    testing partial-failure isolation.
    """

    def __init__(
        self,
        *,
        expiry_authority: AlternativeModelExpiryAuthority,
        intent_resolver: AlternativeModelIntentResolver | None = None,
        impact_resolver: AlternativeModelImpactResolver | None = None,
        staging_store_factory: Callable[[], RegistryStore] | None = None,
    ) -> None:
        self.expiry_planner = AlternativeModelExpiryPlanner(expiry_authority=expiry_authority)
        self.intent_resolver = intent_resolver or EmptyAlternativeModelIntentResolver()
        self.impact_resolver = impact_resolver or EmptyAlternativeModelImpactResolver()
        self.staging_store_factory = staging_store_factory or (lambda: InMemoryRegistryStore())

    def project(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        committed_store: RegistryStore,
        governed_admit_evidence: tuple[
            tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt | None], ...
        ] = (),
    ) -> AlternativeModelProjectionPlan:
        sequence = _claim_sequence(claim)
        _verify_context(claim, validated_event, semantic_receipt)
        predecessor_root = committed_store.snapshot("ALTERNATIVE_MODEL").root_digest
        staged = _clone_store(committed_store, self.staging_store_factory)
        source_digest = _projection_source_digest(claim, validated_event, semantic_receipt)

        explicit = _canonical_events(
            self.intent_resolver.resolve(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                store=staged,
            )
        )
        _verify_event_bindings(explicit, sequence)
        _verify_governed_admit_bindings(explicit, governed_admit_evidence, predecessor_root)
        impacts: list[AlternativeModelImpactReceipt] = []
        _apply_events(
            explicit,
            staged,
            self.impact_resolver,
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
            self.impact_resolver,
            impacts,
        )

        events = explicit + expiry.events
        projected_root = staged.snapshot("ALTERNATIVE_MODEL").root_digest
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
        return AlternativeModelProjectionPlan(
            clock_claim_digest=claim.digest,
            validated_event_digest=validated_event.digest,
            semantic_receipt_digest=semantic_receipt.digest,
            clock_sequence=sequence,
            predecessor_root_digest=predecessor_root,
            projected_root_digest=projected_root,
            events=events,
            impact_receipts=tuple(impacts),
            expiry_plan_digest=expiry.plan_digest,
            plan_digest=_digest_object("ALTERNATIVE_MODEL_PROJECTION_PLAN", unsigned),
        )


def _apply_events(
    events: tuple[RegistryEvent, ...],
    store: RegistryStore,
    impact_resolver: AlternativeModelImpactResolver,
    impacts: list[AlternativeModelImpactReceipt],
) -> None:
    for event in events:
        model_id = _event_entity_id(event)
        previous = project_alternative_model_history(
            store.reconstruct_entity("ALTERNATIVE_MODEL", model_id)
        )
        current = reduce_alternative_model(previous, event)
        store.append(event)
        if previous is None or _event_operation(event) not in _IMPACT_OPERATIONS:
            continue
        impact_resolver.resolve(
            model=current,
            trigger_event=event,
            store=store,
        )
        impacts.append(
            AlternativeModelImpactReceipt.build(
                model_id=model_id,
                previous_status=previous.status,
                current_status=current.status,
                trigger_event_digest=event.digest,
                affected_model_ids=_dependent_ids(store, model_id),
                alternative_model_registry_root_digest=store.snapshot(
                    "ALTERNATIVE_MODEL"
                ).root_digest,
            )
        )


def _clone_store(source: RegistryStore, factory: Callable[[], RegistryStore]) -> RegistryStore:
    """Clone ALTERNATIVE_MODEL histories from ``source`` into a fresh staging store."""
    target = factory()
    for history in source.reconstruct_snapshot("ALTERNATIVE_MODEL"):
        for event in history:
            target.append(event)
    return target


def _canonical_events(events: tuple[RegistryEvent, ...]) -> tuple[RegistryEvent, ...]:
    keyed = [((_event_entity_id(event), _event_sequence(event)), event) for event in events]
    positions = [position for position, _ in keyed]
    if len(positions) != len(set(positions)):
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_DUPLICATE_EVENT_POSITION")
    return tuple(event for _, event in sorted(keyed, key=lambda item: item[0]))


def _verify_event_bindings(
    events: tuple[RegistryEvent, ...],
    sequence: int,
) -> None:
    """Validate that explicit events are well-formed for staging."""
    for event in events:
        value = event.to_json_value()
        if value.get("registry_type") != "ALTERNATIVE_MODEL":
            raise AlternativeModelProjectionError(
                "ALT_MODEL_PROJECTION_EVENT_REGISTRY_TYPE_INVALID"
            )
        if value.get("clock_sequence") != sequence:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_EVENT_CLOCK_MISMATCH")


def _verify_governed_admit_bindings(
    events: tuple[RegistryEvent, ...],
    governed_admit_evidence: tuple[
        tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt | None], ...
    ],
    predecessor_root_digest: str,
) -> None:
    """Validate the real production binding for each explicit ADMIT event.

    Cross-binds the event against the authorization's identity, predecessor,
    sequence, authority, root, and source-receipt digest. When a comparison
    receipt is supplied, cross-binds its structural-difference set against the
    authorization's structural-difference receipt.
    """
    auth_by_id: dict[str, GovernedAlternativeModelAuthorization] = {}
    comparison_by_id: dict[str, ComparisonReceipt | None] = {}
    if type(governed_admit_evidence) is not tuple:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_GOVERNED_EVIDENCE_INVALID")
    seen: set[str] = set()
    for authorization, comparison in governed_admit_evidence:
        if type(authorization) is not GovernedAlternativeModelAuthorization:
            raise AlternativeModelProjectionError(
                "ALT_MODEL_PROJECTION_GOVERNED_EVIDENCE_TYPE_INVALID"
            )
        if authorization.model_id in seen:
            raise AlternativeModelProjectionError(
                "ALT_MODEL_PROJECTION_GOVERNED_EVIDENCE_DUPLICATE"
            )
        seen.add(authorization.model_id)
        auth_by_id[authorization.model_id] = authorization
        if comparison is not None and type(comparison) is not ComparisonReceipt:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_COMPARISON_TYPE_INVALID")
        comparison_by_id[authorization.model_id] = comparison

    for event in events:
        payload = event.to_json_value().get("payload")
        if type(payload) is not dict:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_EVENT_PAYLOAD_INVALID")
        if payload.get("operation") != "ADMIT":
            continue
        model_id = _event_entity_id(event)
        auth: GovernedAlternativeModelAuthorization | None = auth_by_id.get(model_id)
        if auth is None:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_EVIDENCE_MISSING")
        value = event.to_json_value()

        if model_id != auth.model_id:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_IDENTITY_MISMATCH")
        if value.get("entity_sequence") != auth.candidate_entity_sequence:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_SEQUENCE_MISMATCH")
        if value.get("previous_entity_event_digest") != auth.candidate_predecessor_event_digest:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_PREDECESSOR_MISMATCH")
        if value.get("clock_sequence") != auth.event_sequence:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_CLOCK_MISMATCH")
        if payload.get("admitting_authority_id") != auth.admitting_authority_id:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_AUTHORITY_MISMATCH")
        if predecessor_root_digest != auth.alternative_model_registry_root:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_ROOT_MISMATCH")
        if value.get("source_receipt_digest") != auth.authorization_digest:
            raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_ADMIT_SOURCE_MISMATCH")

        comparison = comparison_by_id.get(model_id)
        if comparison is not None:
            diff = comparison.structural_difference_receipt
            if diff.primary_graph_digest != auth.primary_graph_digest:
                raise AlternativeModelProjectionError(
                    "ALT_MODEL_PROJECTION_COMPARISON_PRIMARY_GRAPH_MISMATCH"
                )
            if diff.shadow_graph_digest != auth.shadow_graph_digest:
                raise AlternativeModelProjectionError(
                    "ALT_MODEL_PROJECTION_COMPARISON_SHADOW_GRAPH_MISMATCH"
                )
            if (
                diff.declared_difference_digest
                != auth.structural_difference_receipt.declared_difference_digest
            ):
                raise AlternativeModelProjectionError(
                    "ALT_MODEL_PROJECTION_COMPARISON_DIFFERENCE_MISMATCH"
                )


def _dependent_ids(store: RegistryStore, model_id: str) -> tuple[str, ...]:
    """Reverse transitive closure over primary_model_id links.

    Alternative models do not carry an explicit dependency-id tuple (unlike
    assumptions). The impact closure is therefore empty by default: an event on
    one alternative model does not mechanically affect any other. The semantic
    projector may still re-derive dependencies. Returns sorted unique ids.
    """
    del store, model_id
    return ()


def _claim_sequence(claim: ClockClaim) -> int:
    value = claim.to_json_value().get("proposed_sequence")
    if type(value) is not int or value < 1:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_CLAIM_SEQUENCE_INVALID")
    return value


def _verify_context(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> None:
    claim_value = claim.to_json_value()
    semantic_value = semantic_receipt.to_json_value()
    if claim_value.get("validated_event_digest") != validated_event.digest:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_EVENT_MISMATCH")
    if semantic_value.get("clock_claim_digest") != claim.digest:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_SEMANTIC_CLAIM_MISMATCH")
    if semantic_value.get("validated_event_digest") != validated_event.digest:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_SEMANTIC_EVENT_MISMATCH")
    if semantic_value.get("projection_sequence") != claim_value.get("proposed_sequence"):
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_SEMANTIC_SEQUENCE_MISMATCH")


def _projection_source_digest(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
) -> str:
    return _digest_object(
        "ALTERNATIVE_MODEL_PROJECTION_SOURCE",
        {
            "clock_claim_digest": claim.digest,
            "semantic_receipt_digest": semantic_receipt.digest,
            "validated_event_digest": validated_event.digest,
        },
    )


def _event_entity_id(event: RegistryEvent) -> str:
    return _require_token(
        event.to_json_value().get("entity_id"),
        "ALT_MODEL_PROJECTION_EVENT_ID_INVALID",
    )


def _event_sequence(event: RegistryEvent) -> int:
    value = event.to_json_value().get("entity_sequence")
    if type(value) is not int or value < 1:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_EVENT_SEQUENCE_INVALID")
    return value


def _event_operation(event: RegistryEvent) -> str:
    payload = event.to_json_value().get("payload")
    if type(payload) is not dict:
        raise AlternativeModelProjectionError("ALT_MODEL_PROJECTION_EVENT_PAYLOAD_INVALID")
    return _require_token(
        payload.get("operation"),
        "ALT_MODEL_PROJECTION_EVENT_OPERATION_INVALID",
    )


def _require_token(value: object, code: str) -> str:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise AlternativeModelProjectionError(code)
    return value


def _require_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AlternativeModelProjectionError(code)
    return value


def _require_tokens(values: tuple[str, ...], code: str) -> None:
    if type(values) is not tuple or values != tuple(sorted(values)):
        raise AlternativeModelProjectionError(code)
    if len(values) != len(set(values)):
        raise AlternativeModelProjectionError(code)
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


__all__ = [
    "AlternativeModelExpiryAuthorization",
    "AlternativeModelExpiryAuthority",
    "AlternativeModelExpiryPlan",
    "AlternativeModelExpiryPlanner",
    "AlternativeModelImpactReceipt",
    "AlternativeModelImpactResolver",
    "AlternativeModelIntentResolver",
    "AlternativeModelProjectionError",
    "AlternativeModelProjectionPlan",
    "EmptyAlternativeModelImpactResolver",
    "EmptyAlternativeModelIntentResolver",
    "StagedAlternativeModelProjectionAdapter",
]
