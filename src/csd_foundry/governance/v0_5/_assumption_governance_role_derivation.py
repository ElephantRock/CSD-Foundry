"""Frozen authoritative derivation from assumption lifecycle events to governance roles.

This module closes the I1-B0 contract gap: it defines the single mechanically
frozen mapping from canonical assumption-history events to the eight
``ASSUMPTION_GOVERNANCE_ROLES`` values that the separation-of-duty evaluator
(I1-B / D3.2-A2) will later consume.

The mapping is not a new ontology. It completes the correspondence between the
already-frozen eight-role vocabulary and the eight actor-bearing lifecycle
operations. Every lifecycle operation carries exactly one authority-identity
field; this module derives exactly one ``(authority_id, governance_role)`` fact
per event.

Semantic boundaries (frozen):

* Operation -> role is a total function over the eight recognized lifecycle
  operations. Unknown operations fail closed; no event yields "no role".
* ``RESOLVE_CHALLENGES`` always derives ``RESOLVER`` regardless of
  ``resolution_outcome`` (``RETURN_TO_ADMITTED`` / ``CONFIRM`` / ``REJECT`` /
  ``SUPERSEDE``). The outcome changes the authority action required for a
  candidate event; it does not retroactively create four historical roles.
* History-level derivation consumes canonical, ascending, chain-validated
  events produced by the registry store. It does NOT accept attacker-supplied
  event tuples; it replays the chain through the existing lifecycle reducer to
  prove canonical order and integrity before deriving any role.
* "Prior" means: events at ``entity_sequence`` strictly less than the
  candidate position, within the same ``assumption_id``. Not global actor
  history, not cross-assumption scope, not events at or after the candidate.
* The derivation performs no registry write, policy write, root advancement,
  assumption append, or temporal staging. It is a pure read-side projection.

No public v0.5 schema, vector, or digest changes. The
``AssumptionGovernanceRoleFact`` is an internal D3.2 receipt that carries event
identity and the derived role; it is self-digesting under its own domain.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    ASSUMPTION_GOVERNANCE_ROLES,
    GOVERNANCE_ROLE_FACT_SCHEMA_VERSION,
    AssumptionGovernanceContractError,
    _domain_digest,
    _json_bytes,
    _require_digest,
    _require_self_digest,
    _require_token,
)
from csd_foundry.governance.v0_5.assumption import (
    ASSUMPTION_PAYLOAD_SCHEMA_VERSION,
    reduce_assumption,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import _REGISTRY_PHASE

# The frozen operation -> (authority-id payload field, governance role) mapping.
# This is the load-bearing correspondence. Every recognized lifecycle operation
# appears here exactly once; every role in ASSUMPTION_GOVERNANCE_ROLES is the
# image of exactly one operation.
_OPERATION_TO_ROLE: Mapping[str, tuple[str, str]] = {
    "PROPOSE": ("proposer_authority_id", "PROPOSER"),
    "ADMIT": ("admitting_authority_id", "ADMITTER"),
    "CONFIRM": ("confirming_authority_id", "CONFIRMER"),
    "CHALLENGE": ("challenger_authority_id", "CHALLENGER"),
    "RESOLVE_CHALLENGES": ("resolver_authority_id", "RESOLVER"),
    "REJECT": ("rejecting_authority_id", "REJECTOR"),
    "EXPIRE": ("expiry_authority_id", "EXPIRY_AUTHORITY"),
    "SUPERSEDE": ("superseding_authority_id", "SUPERSEDER"),
}

# Defensive invariant: the mapping covers every role in the frozen vocabulary
# exactly once. This is checked at import time so a future edit that breaks the
# correspondence fails immediately rather than silently producing wrong roles.
# The check is an explicit raise, NOT an ``assert``, because the mapping is a
# frozen fail-closed governance invariant and must survive optimized execution
# (``python -O``). Set equality alone proves coverage; the cardinality checks
# independently encode the "exactly once" property if the mapping is later
# expanded.
_ROLE_IMAGE = frozenset(role for _, role in _OPERATION_TO_ROLE.values())
if (
    frozenset(ASSUMPTION_GOVERNANCE_ROLES) != _ROLE_IMAGE
    or len(_OPERATION_TO_ROLE) != len(_ROLE_IMAGE)
    or len(_ROLE_IMAGE) != len(ASSUMPTION_GOVERNANCE_ROLES)
):
    raise AssumptionGovernanceContractError(
        "ASSUMPTION_ROLE_MAPPING_COVERAGE_INVALID",
        detail=(f"image={sorted(_ROLE_IMAGE)} vocabulary={list(ASSUMPTION_GOVERNANCE_ROLES)}"),
    )

_ASSUMPTION_REGISTRY_PHASE = _REGISTRY_PHASE["ASSUMPTION"]


@dataclass(frozen=True, slots=True)
class AssumptionGovernanceRoleFact:
    """One derived ``(authority_id, governance_role)`` fact from one lifecycle event.

    Carries the event identity (assumption id, entity sequence, clock sequence,
    event digest, operation) plus the derived authority and role. The fact is
    self-digesting under the ``ASSUMPTION_GOVERNANCE_ROLE_FACT`` domain.

    A standalone single-event fact proves deterministic event -> actor -> role
    extraction. It does NOT prove full lifecycle admissibility of the source
    event: the single-event extractor does not run the lifecycle transition
    validator. Authoritative separation-of-duty use must go through the
    history-level replay path (``derive_prior_governance_roles``), which re-proves
    canonical order and chain integrity via ``reduce_assumption`` before deriving
    any role.
    """

    assumption_id: str
    entity_sequence: int
    clock_sequence: int
    event_digest: str
    operation: str
    authority_id: str
    governance_role: str
    role_fact_digest: str

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "ASSUMPTION_ROLE_FACT_ASSUMPTION_ID_INVALID")
        if type(self.entity_sequence) is not int or isinstance(self.entity_sequence, bool):
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_ENTITY_SEQUENCE_INVALID")
        if self.entity_sequence < 1:
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_ENTITY_SEQUENCE_INVALID")
        if type(self.clock_sequence) is not int or isinstance(self.clock_sequence, bool):
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_CLOCK_SEQUENCE_INVALID")
        if self.clock_sequence < 1:
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_CLOCK_SEQUENCE_INVALID")
        # event_digest must be an exact ``sha256:[0-9a-f]{64}`` digest. This is
        # the same shape enforced everywhere else in the governance contract
        # layer; the prefix-only check was weaker than the rest of the layer and
        # could carry a malformed-but-self-consistent value.
        _require_digest(self.event_digest, "ASSUMPTION_ROLE_FACT_EVENT_DIGEST_INVALID")
        if self.operation not in _OPERATION_TO_ROLE:
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_OPERATION_UNSUPPORTED")
        _require_token(self.authority_id, "ASSUMPTION_ROLE_FACT_AUTHORITY_ID_INVALID")
        if self.governance_role not in ASSUMPTION_GOVERNANCE_ROLES:
            raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_FACT_ROLE_INVALID")
        # The derived role must match the frozen operation -> role mapping. This
        # prevents a caller from constructing a fact with a mismatched pair even
        # if both the operation and role are individually valid.
        expected_role = _OPERATION_TO_ROLE[self.operation][1]
        if self.governance_role != expected_role:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_ROLE_FACT_ROLE_OPERATION_MISMATCH",
            )
        _require_self_digest(
            "ASSUMPTION_GOVERNANCE_ROLE_FACT",
            self._unsigned_value(),
            self.role_fact_digest,
            "ASSUMPTION_ROLE_FACT_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": GOVERNANCE_ROLE_FACT_SCHEMA_VERSION,
            "assumption_id": self.assumption_id,
            "authority_id": self.authority_id,
            "clock_sequence": self.clock_sequence,
            "entity_sequence": self.entity_sequence,
            "event_digest": self.event_digest,
            "governance_role": self.governance_role,
            "operation": self.operation,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "role_fact_digest": self.role_fact_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def derive_assumption_governance_role(event: RegistryEvent) -> AssumptionGovernanceRoleFact:
    """Derive the single ``(authority_id, governance_role)`` fact from one event.

    The event must be a valid ``registry-event/1`` envelope with payload schema
    ``assumption-event/1`` and registry phase ``ASSUMPTION_REGISTRY``. The
    operation must be one of the eight recognized lifecycle operations; unknown
    operations raise ``ASSUMPTION_ROLE_DERIVATION_OPERATION_UNSUPPORTED``.

    The authority identity is read from the operation-specific payload field
    (e.g. ``proposer_authority_id`` for ``PROPOSE``). It is never accepted as a
    caller parameter.
    """
    value = _event_value(event)
    _require_assumption_envelope(value, event)
    payload = _payload(value)
    operation = _required_str(payload, "operation", "ASSUMPTION_ROLE_DERIVATION_OPERATION_MISSING")
    if operation not in _OPERATION_TO_ROLE:
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_OPERATION_UNSUPPORTED",
        )
    authority_field, role = _OPERATION_TO_ROLE[operation]
    authority_id = _required_str(
        payload,
        authority_field,
        "ASSUMPTION_ROLE_DERIVATION_AUTHORITY_MISSING",
    )
    assumption_id = cast(str, value["entity_id"])
    entity_sequence = cast(int, value["entity_sequence"])
    clock_sequence = cast(int, value["clock_sequence"])
    event_digest = event.digest
    unsigned = {
        "schema_version": GOVERNANCE_ROLE_FACT_SCHEMA_VERSION,
        "assumption_id": assumption_id,
        "authority_id": authority_id,
        "clock_sequence": clock_sequence,
        "entity_sequence": entity_sequence,
        "event_digest": event_digest,
        "governance_role": role,
        "operation": operation,
    }
    return AssumptionGovernanceRoleFact(
        assumption_id=assumption_id,
        entity_sequence=entity_sequence,
        clock_sequence=clock_sequence,
        event_digest=event_digest,
        operation=operation,
        authority_id=authority_id,
        governance_role=role,
        role_fact_digest=_domain_digest("ASSUMPTION_GOVERNANCE_ROLE_FACT", unsigned),
    )


def derive_prior_governance_roles(
    history: tuple[RegistryEvent, ...],
    *,
    candidate_entity_sequence: int,
    authority_id: str,
) -> tuple[str, ...]:
    """Return the canonical set of governance roles an authority performed prior to a candidate.



    "Prior" means events at ``entity_sequence`` strictly less than
    ``candidate_entity_sequence``, within the same assumption identity. The
    history tuple MUST be the canonical ascending chain produced by the registry
    store (``reconstruct_entity``); this function replays it through the
    lifecycle reducer to prove canonical order and chain integrity before
    deriving any role.

    The result is a tuple of unique roles in frozen ``ASSUMPTION_GOVERNANCE_ROLES``
    order. Repeated performance of a role is deduplicated and does not alter the
    SoD-relevant result.

    Raises:
        AssumptionGovernanceContractError: if the history is empty, the chain is
            malformed, events span multiple assumption identities, or the
            candidate sequence is out of range.
        AssumptionRegistryError: if the canonical replay through
            ``reduce_assumption`` detects a chain defect (re-raised unchanged so
            callers see the lifecycle's own error codes).
    """
    if type(candidate_entity_sequence) is not int or isinstance(candidate_entity_sequence, bool):
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_CANDIDATE_SEQUENCE_INVALID",
        )
    if candidate_entity_sequence < 1:
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_CANDIDATE_SEQUENCE_INVALID",
        )
    _require_token(authority_id, "ASSUMPTION_ROLE_DERIVATION_AUTHORITY_ID_INVALID")
    if len(history) == 0:
        raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_DERIVATION_HISTORY_EMPTY")

    # Canonical replay: fold the chain through the lifecycle reducer. This
    # proves contiguous successor identity, exact predecessor digest, and
    # advancing logical clock via _verify_chain inside reduce_assumption. We do
    # not trust the tuple's superficial validity; we re-prove it. The loop
    # replays history[0] from state=None (genesis must be valid standalone), so
    # no separate genesis precheck is needed.
    state: Any = None
    assumption_id: str | None = None
    for event in history:
        value = _event_value(event)
        _require_assumption_envelope(value, event)
        eid = cast(str, value["entity_id"])
        if assumption_id is None:
            assumption_id = eid
        elif eid != assumption_id:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_ROLE_DERIVATION_HISTORY_IDENTITY_MIXED",
            )
        # reduce_assumption performs full _verify_chain validation and raises
        # AssumptionRegistryError on any chain defect.
        state = reduce_assumption(state, event)

    if state is None or assumption_id is None:  # history is non-empty; replay succeeded
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_HISTORY_UNRECONSTRUCTED"
        )

    # The candidate position must be within or at the head of this chain's
    # sequence space. Prior roles are defined for candidate positions >= 2
    # (position 1 is genesis, which has no predecessors). A candidate beyond the
    # observed chain head is rejected because we cannot prove what the canonical
    # predecessor history would contain without the actual events.
    head_sequence = cast(int, _event_value(history[-1])["entity_sequence"])
    if candidate_entity_sequence > head_sequence + 1:
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_CANDIDATE_BEYOND_HISTORY",
        )

    # Derive roles only from strictly-prior events, in frozen
    # ASSUMPTION_GOVERNANCE_ROLES order. The tuple is the authority for output
    # ordering; the order happens to be alphabetical today, but correctness
    # depends on tuple order, not on sorting.
    observed: set[str] = set()
    for event in history:
        value = _event_value(event)
        seq = cast(int, value["entity_sequence"])
        if seq >= candidate_entity_sequence:
            break
        fact = derive_assumption_governance_role(event)
        if fact.authority_id == authority_id:
            observed.add(fact.governance_role)

    return tuple(role for role in ASSUMPTION_GOVERNANCE_ROLES if role in observed)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _event_value(event: RegistryEvent) -> dict[str, Any]:
    # Strict exact-type check, matching the authoritative lifecycle reducer
    # (``type(event) is not RegistryEvent`` in reduce_assumption). isinstance
    # would admit a foreign subclass that mimics the envelope shape; this is a
    # fail-closed derivation and must not be more permissive than the lifecycle
    # it derives from.
    if type(event) is not RegistryEvent:
        raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_DERIVATION_EVENT_TYPE_INVALID")
    return event.to_json_value()


def _payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise AssumptionGovernanceContractError("ASSUMPTION_ROLE_DERIVATION_PAYLOAD_INVALID")
    return cast(dict[str, Any], payload)


def _required_str(mapping: dict[str, Any], field: str, code: str) -> str:
    if field not in mapping:
        raise AssumptionGovernanceContractError(code)
    value = mapping[field]
    if not isinstance(value, str) or not value:
        raise AssumptionGovernanceContractError(code)
    return value


def _require_assumption_envelope(value: dict[str, Any], event: RegistryEvent) -> None:
    schema = value.get("schema_version")
    if schema != "registry-event/1":
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_ENVELOPE_SCHEMA_UNSUPPORTED",
        )
    phase = value.get("projection_phase")
    if phase != _ASSUMPTION_REGISTRY_PHASE:
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_REGISTRY_PHASE_INVALID",
        )
    payload_schema = value.get("payload_schema_version")
    if payload_schema != ASSUMPTION_PAYLOAD_SCHEMA_VERSION:
        raise AssumptionGovernanceContractError(
            "ASSUMPTION_ROLE_DERIVATION_PAYLOAD_SCHEMA_UNSUPPORTED",
        )
    # Re-prove the event digest is well-formed (the envelope's own __post_init__
    # already enforced this at construction, but we defend against a foreign
    # object masquerading as a RegistryEvent).
    _ = event.digest
