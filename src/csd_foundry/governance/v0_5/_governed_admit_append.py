"""Frozen governed ADMIT append for assumption governance (D3.2-A3.2).

Atomically append one ADMIT event for an authoritative PROPOSED assumption only
when historical grant authority (I1-A via I1-B), separation-of-duty (I1-B), and
admission-time dependencies (I1-C) all permit that exact admission. Every denial,
stale-state condition, or compare-and-append conflict leaves the assumption
head/root unadvanced.

The entire operation runs under one single-host registry lock via a
``LockedRegistryView``. The view provides non-relocking read access for I1-B
and I1-C, and a ``_commit_prepared`` primitive for the governed commit.

Transaction shape::

    store.locked_view() as view
        read current candidate head
        if seq-2 ADMIT: exact retry path
        otherwise reconstruct PROPOSE, require PROPOSED seq 1
        capture both roots
        I1-B ADMIT for every scope
        I1-C PASS
        build GovernedAdmitAuthorization
        build ADMIT event (clock_sequence = event_sequence)
        reduce to projected ADMITTED
        predict head + post-root
        construct + validate GovernedAdmitResult
        _commit_prepared (os.replace = commit point)
        return prebuilt result
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5._assumption_dependency_validator import (
    DependencyValidationReceipt,
    validate_assumption_dependencies,
)
from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    ASSUMPTION_MATERIALITIES,
    AssumptionGovernanceContractError,
    _domain_digest,
    _require_digest,
    _require_self_digest,
    _require_token,
)
from csd_foundry.governance.v0_5._assumption_separation_duty_evaluator import (
    SeparationOfDutyDecision,
    evaluate_separation_of_duty,
)
from csd_foundry.governance.v0_5.assumption import (
    Assumption,
    AssumptionRegistryError,
    build_assumption_event,
    project_assumption_history,
    reduce_assumption,
)
from csd_foundry.governance.v0_5.registry import (
    GovernedRegistryStore,
    LockedRegistryView,
    RegistryEntityHead,
    _snapshot_root,
)

_AUTHORIZATION_SCHEMA_VERSION = "assumption-governed-admit-authorization/1"
_AUTHORIZATION_DOMAIN = "ASSUMPTION_GOVERNED_ADMIT_AUTHORIZATION"


def _require_canonical_scope_tuple(value: object, code: str) -> tuple[str, ...]:
    """Require a canonical scope-ID tuple."""
    if type(value) is not tuple:
        raise AssumptionGovernanceContractError(code)
    for item in value:
        if type(item) is not str:
            raise AssumptionGovernanceContractError(code)
        _require_token(item, code)
    if tuple(sorted(value)) != value:
        raise AssumptionGovernanceContractError(code)
    if len(set(value)) != len(value):
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


@dataclass(frozen=True, slots=True)
class GovernedAdmitAuthorization:
    """Cross-bound composite authorization for one governed ADMIT.

    Mechanically cross-validates that every child receipt (per-scope SoD
    decisions + dependency validation receipt) describes the same admission
    against the same policy generation, ledger root, and candidate state.
    """

    assumption_id: str
    candidate_predecessor_event_digest: str
    candidate_entity_sequence: int
    event_sequence: int
    admitting_authority_id: str
    assumption_registry_root: str
    evidence_registry_root: str
    scope_ids: tuple[str, ...]
    assumption_materiality: str
    sod_decisions: tuple[SeparationOfDutyDecision, ...]
    dependency_validation_receipt: DependencyValidationReceipt
    authorization_digest: str

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "GOVERNED_ADMIT_AUTH_ASSUMPTION_ID_INVALID")
        _require_digest(
            self.candidate_predecessor_event_digest,
            "GOVERNED_ADMIT_AUTH_PREDECESSOR_DIGEST_INVALID",
        )
        if (
            type(self.candidate_entity_sequence) is not int
            or isinstance(self.candidate_entity_sequence, bool)
            or self.candidate_entity_sequence != 2
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_AUTH_CANDIDATE_SEQUENCE_INVALID"
            )
        if (
            type(self.event_sequence) is not int
            or isinstance(self.event_sequence, bool)
            or self.event_sequence < 1
        ):
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_EVENT_SEQUENCE_INVALID")
        _require_token(self.admitting_authority_id, "GOVERNED_ADMIT_AUTH_AUTHORITY_ID_INVALID")
        _require_digest(
            self.assumption_registry_root, "GOVERNED_ADMIT_AUTH_ASSUMPTION_ROOT_INVALID"
        )
        _require_digest(self.evidence_registry_root, "GOVERNED_ADMIT_AUTH_EVIDENCE_ROOT_INVALID")
        # Validate canonical-sorted scope_ids WITHOUT reassigning: the dataclass
        # is frozen, and the constructor input is required to already be canonical
        # (callers pass ``propose_state.scope_ids``). Validation-only matches the
        # frozen/self-digesting receipt contract model used throughout this layer.
        _require_canonical_scope_tuple(self.scope_ids, "GOVERNED_ADMIT_AUTH_SCOPE_IDS_INVALID")
        if self.assumption_materiality not in ASSUMPTION_MATERIALITIES:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_MATERIALITY_INVALID")
        if type(self.sod_decisions) is not tuple:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_DECISIONS_INVALID")
        for dec in self.sod_decisions:
            if type(dec) is not SeparationOfDutyDecision:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_DECISION_TYPE_INVALID"
                )
        if type(self.dependency_validation_receipt) is not DependencyValidationReceipt:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_DEP_RECEIPT_TYPE_INVALID")

        # --- Cross-validate dependency receipt ---
        dep = self.dependency_validation_receipt
        if dep.validation_result != "PASS":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_DEP_NOT_PASS")
        if dep.assumption_id != self.assumption_id:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_DEP_ASSUMPTION_MISMATCH")
        if dep.candidate_predecessor_event_digest != self.candidate_predecessor_event_digest:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_DEP_PREDECESSOR_MISMATCH")
        if dep.candidate_entity_sequence != 2:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_DEP_SEQUENCE_MISMATCH")
        if dep.event_sequence != self.event_sequence:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_AUTH_DEP_EVENT_SEQUENCE_MISMATCH"
            )
        if dep.assumption_registry_root != self.assumption_registry_root:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_AUTH_DEP_ASSUMPTION_ROOT_MISMATCH"
            )
        if dep.evidence_registry_root != self.evidence_registry_root:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_AUTH_DEP_EVIDENCE_ROOT_MISMATCH"
            )

        # --- Cross-validate SoD decisions ---
        if len(self.sod_decisions) != len(self.scope_ids):
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_COUNT_MISMATCH")
        decision_scopes = tuple(dec.scope_id for dec in self.sod_decisions)
        if decision_scopes != self.scope_ids:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_SCOPE_ORDER_MISMATCH")
        seen_scopes: set[str] = set()
        for dec in self.sod_decisions:
            if dec.scope_id in seen_scopes:
                raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_DUPLICATE_SCOPE")
            seen_scopes.add(dec.scope_id)
            if dec.decision != "ALLOW":
                raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_NOT_ALLOW")
            if dec.action != "ADMIT":
                raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_ACTION_MISMATCH")
            if dec.assumption_id != self.assumption_id:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_ASSUMPTION_MISMATCH"
                )
            if dec.authority_id != self.admitting_authority_id:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_AUTHORITY_MISMATCH"
                )
            if dec.assumption_materiality != self.assumption_materiality:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_MATERIALITY_MISMATCH"
                )
            if dec.candidate_entity_sequence != 2:
                raise AssumptionGovernanceContractError("GOVERNED_ADMIT_AUTH_SOD_SEQUENCE_MISMATCH")
            if dec.event_sequence != self.event_sequence:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_EVENT_SEQUENCE_MISMATCH"
                )
            if dec.challenge_materiality is not None:
                raise AssumptionGovernanceContractError(
                    "GOVERNED_ADMIT_AUTH_SOD_CHALLENGE_UNEXPECTED"
                )
        # All decisions must bind the same policy generation.
        if self.sod_decisions:
            first = self.sod_decisions[0]
            for dec in self.sod_decisions[1:]:
                if dec.ledger_root_digest != first.ledger_root_digest:
                    raise AssumptionGovernanceContractError(
                        "GOVERNED_ADMIT_AUTH_LEDGER_ROOT_MISMATCH"
                    )
                if dec.policy_digest != first.policy_digest:
                    raise AssumptionGovernanceContractError(
                        "GOVERNED_ADMIT_AUTH_POLICY_DIGEST_MISMATCH"
                    )
                if dec.commit_receipt_digest != first.commit_receipt_digest:
                    raise AssumptionGovernanceContractError(
                        "GOVERNED_ADMIT_AUTH_COMMIT_RECEIPT_MISMATCH"
                    )

        # --- Self-digest ---
        _require_self_digest(
            _AUTHORIZATION_DOMAIN,
            self._unsigned_value(),
            self.authorization_digest,
            "GOVERNED_ADMIT_AUTH_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        # NOTE: authorization_digest is intentionally NOT included here. The
        # self-digest is computed over the unsigned value (see ``__post_init__``);
        # including the digest would make it self-referential and unverifiable.
        # ``to_json_value`` re-adds the digest for external serialization. This
        # matches the ``DependencyValidationReceipt`` pattern in this layer.
        return {
            "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
            "admitting_authority_id": self.admitting_authority_id,
            "assumption_id": self.assumption_id,
            "assumption_materiality": self.assumption_materiality,
            "assumption_registry_root": self.assumption_registry_root,
            "candidate_entity_sequence": self.candidate_entity_sequence,
            "candidate_predecessor_event_digest": self.candidate_predecessor_event_digest,
            "dependency_validation_receipt": self.dependency_validation_receipt.to_json_value(),
            "event_sequence": self.event_sequence,
            "evidence_registry_root": self.evidence_registry_root,
            "scope_ids": list(self.scope_ids),
            "sod_decisions": [dec.to_json_value() for dec in self.sod_decisions],
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "authorization_digest": self.authorization_digest}


@dataclass(frozen=True, slots=True)
class GovernedAdmitResult:
    """Output of a governed ADMIT append.

    Mechanically validates event/head/roots/projected/authorization consistency.
    Fully constructed and validated BEFORE the ``os.replace`` commit point.
    """

    event: Any  # RegistryEvent — typed as Any to avoid circular import
    head: RegistryEntityHead
    applied: bool
    reason: str
    assumption_registry_root: str
    evidence_registry_root: str
    projected: Assumption
    authorization: GovernedAdmitAuthorization

    def __post_init__(self) -> None:
        from csd_foundry.governance.v0_5.contracts import RegistryEvent

        if type(self.event) is not RegistryEvent:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVENT_TYPE_INVALID")
        if type(self.head) is not RegistryEntityHead:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_HEAD_TYPE_INVALID")
        if type(self.projected) is not Assumption:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_PROJECTED_TYPE_INVALID")
        if type(self.authorization) is not GovernedAdmitAuthorization:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_AUTH_TYPE_INVALID")

        value = self.event.to_json_value()
        # Event binding.
        if value["registry_type"] != "ASSUMPTION":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVENT_TYPE_MISMATCH")
        if value["entity_id"] != self.authorization.assumption_id:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVENT_ID_MISMATCH")
        if value["entity_sequence"] != 2:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVENT_SEQUENCE_MISMATCH")
        if (
            value["previous_entity_event_digest"]
            != self.authorization.candidate_predecessor_event_digest
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_EVENT_PREDECESSOR_MISMATCH"
            )
        if value["clock_sequence"] != self.authorization.event_sequence:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVENT_CLOCK_MISMATCH")
        if (
            value["source_receipt_digest"]
            != self.authorization.dependency_validation_receipt.receipt_digest
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_EVENT_SOURCE_RECEIPT_MISMATCH"
            )

        payload = value["payload"]
        if type(payload) is not dict:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_PAYLOAD_INVALID")
        if payload.get("operation") != "ADMIT":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_OPERATION_MISMATCH")
        if payload.get("admitting_authority_id") != self.authorization.admitting_authority_id:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_AUTHORITY_MISMATCH")
        if payload.get("admission_receipt_digest") != self.authorization.authorization_digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_ADMISSION_RECEIPT_MISMATCH"
            )

        # Head binding.
        if self.head.registry_type != "ASSUMPTION":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_HEAD_TYPE_MISMATCH")
        if self.head.entity_id != self.authorization.assumption_id:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_HEAD_ID_MISMATCH")
        if self.head.entity_sequence != 2:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_HEAD_SEQUENCE_MISMATCH")
        if self.head.event_digest != self.event.digest:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_HEAD_DIGEST_MISMATCH")

        # Projected binding.
        if self.projected.standing != "ADMITTED":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_NOT_ADMITTED")
        if self.projected.admitting_authority_id != self.authorization.admitting_authority_id:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_PROJECTED_AUTHORITY_MISMATCH"
            )
        if self.projected.current_event_digest != self.event.digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_PROJECTED_DIGEST_MISMATCH"
            )
        if self.projected.current_entity_sequence != 2:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_PROJECTED_SEQUENCE_MISMATCH"
            )

        # Root binding: evidence root unchanged by ADMIT.
        if self.evidence_registry_root != self.authorization.evidence_registry_root:
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_EVIDENCE_ROOT_MISMATCH")

        # applied/reason consistency.
        if self.applied and self.reason != "APPENDED":
            raise AssumptionGovernanceContractError("GOVERNED_ADMIT_RESULT_APPLIED_REASON_MISMATCH")
        if not self.applied and self.reason != "IDEMPOTENT_APPEND":
            raise AssumptionGovernanceContractError(
                "GOVERNED_ADMIT_RESULT_NOT_APPLIED_REASON_MISMATCH"
            )


class GovernedAdmitError(Exception):
    """Stable error for governed ADMIT failures."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


def _build_admit_event(
    authorization: GovernedAdmitAuthorization,
) -> Any:
    """Build the exact ADMIT RegistryEvent from the authorization."""
    return build_assumption_event(
        assumption_id=authorization.assumption_id,
        entity_sequence=2,
        previous_entity_event_digest=authorization.candidate_predecessor_event_digest,
        clock_sequence=authorization.event_sequence,
        source_receipt_digest=authorization.dependency_validation_receipt.receipt_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": authorization.admitting_authority_id,
            "admission_receipt_digest": authorization.authorization_digest,
        },
    )


def _compute_predicted_post_root(
    view: LockedRegistryView,
    assumption_id: str,
    predicted_head: RegistryEntityHead,
) -> str:
    """Compute the predicted post-append assumption root from the locked snapshot."""
    snap = view.snapshot("ASSUMPTION")
    heads = list(snap.heads)
    # Replace or insert the candidate's head.
    new_heads: list[RegistryEntityHead] = []
    replaced = False
    for h in heads:
        if h.entity_id == assumption_id:
            new_heads.append(predicted_head)
            replaced = True
        else:
            new_heads.append(h)
    if not replaced:
        new_heads.append(predicted_head)
    new_heads.sort(key=lambda item: item.entity_id)
    return _snapshot_root("ASSUMPTION", tuple(new_heads))


def append_governed_admit_assumption(
    *,
    store: GovernedRegistryStore,
    ledger: Any,
    assumption_id: str,
    admitting_authority_id: str,
    event_sequence: int,
    retry_authorization: GovernedAdmitAuthorization | None = None,
) -> GovernedAdmitResult:
    """Atomically append one governed ADMIT event.

    The entire operation runs under one registry lock via ``store.locked_view()``.
    I1-B is evaluated per scope; I1-C is evaluated against the same locked view.
    All semantic work and result construction completes before the ``os.replace``
    commit point.

    Raises:
        GovernedAdmitError: on semantic denial, already-admitted, retry mismatch,
            or internal conflict.
        RegistryStoreError: on commit durability uncertainty or locked-view
            violation.
    """
    if (
        retry_authorization is not None
        and type(retry_authorization) is not GovernedAdmitAuthorization
    ):
        raise GovernedAdmitError("GOVERNED_ADMIT_AUTHORIZATION_INVALID")

    with store.locked_view() as view:
        # --- Read current candidate head ---
        current_head = view.entity_head("ASSUMPTION", assumption_id)

        # --- Exact retry check (before PROPOSED requirement) ---
        if current_head is not None and current_head.entity_sequence == 2:
            if retry_authorization is not None:
                return _handle_retry(
                    view,
                    assumption_id,
                    admitting_authority_id,
                    event_sequence,
                    retry_authorization,
                    current_head,
                )
            raise GovernedAdmitError("GOVERNED_ADMIT_ALREADY_ADMITTED", detail=assumption_id)

        # --- Reconstruct PROPOSE ---
        candidate_history = view.reconstruct_entity("ASSUMPTION", assumption_id)
        if not candidate_history:
            raise GovernedAdmitError("GOVERNED_ADMIT_NOT_PROPOSED", detail="no history")
        try:
            propose_state = project_assumption_history(candidate_history)
        except AssumptionRegistryError as exc:
            raise GovernedAdmitError("GOVERNED_ADMIT_NOT_PROPOSED", detail=str(exc)) from exc
        if propose_state is None:
            raise GovernedAdmitError("GOVERNED_ADMIT_NOT_PROPOSED", detail="empty projection")
        if propose_state.standing != "PROPOSED" or propose_state.current_entity_sequence != 1:
            raise GovernedAdmitError(
                "GOVERNED_ADMIT_NOT_PROPOSED",
                detail=(
                    f"standing={propose_state.standing} seq={propose_state.current_entity_sequence}"
                ),
            )
        if event_sequence <= propose_state.last_clock_sequence:
            raise GovernedAdmitError(
                "GOVERNED_ADMIT_NOT_PROPOSED",
                detail=(
                    f"event_sequence={event_sequence} <= clock={propose_state.last_clock_sequence}"
                ),
            )

        # --- Capture both roots ---
        assumption_root = view.snapshot_root("ASSUMPTION")
        evidence_root = view.snapshot_root("EVIDENCE_UNIT")

        # --- I1-B: per-scope SoD evaluation ---
        sod_decisions: list[SeparationOfDutyDecision] = []
        for scope_id in propose_state.scope_ids:
            decision = evaluate_separation_of_duty(
                ledger=ledger,
                event_sequence=event_sequence,
                action="ADMIT",
                authority_id=admitting_authority_id,
                scope_id=scope_id,
                assumption_materiality=propose_state.materiality,
                challenge_materiality=None,
                assumption_id=assumption_id,
                candidate_entity_sequence=2,
                assumption_history=candidate_history,
            )
            if decision.decision != "ALLOW":
                raise GovernedAdmitError(
                    "GOVERNED_ADMIT_SOD_DENIED",
                    detail=f"scope={scope_id} code={decision.selection_decision_type}",
                )
            sod_decisions.append(decision)

        # --- I1-C: dependency validation ---
        dep_receipt = validate_assumption_dependencies(
            store=view,
            candidate_history=candidate_history,
            event_sequence=event_sequence,
        )
        if dep_receipt.validation_result != "PASS":
            raise GovernedAdmitError(
                "GOVERNED_ADMIT_DEPENDENCY_DENIED",
                detail=dep_receipt.validation_code,
            )

        # --- Build authorization ---
        unsigned_auth = {
            "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
            "admitting_authority_id": admitting_authority_id,
            "assumption_id": assumption_id,
            "assumption_materiality": propose_state.materiality,
            "assumption_registry_root": assumption_root,
            "candidate_entity_sequence": 2,
            "candidate_predecessor_event_digest": propose_state.current_event_digest,
            "dependency_validation_receipt": dep_receipt.to_json_value(),
            "event_sequence": event_sequence,
            "evidence_registry_root": evidence_root,
            "scope_ids": list(propose_state.scope_ids),
            "sod_decisions": [dec.to_json_value() for dec in sod_decisions],
        }
        authorization = GovernedAdmitAuthorization(
            assumption_id=assumption_id,
            candidate_predecessor_event_digest=propose_state.current_event_digest,
            candidate_entity_sequence=2,
            event_sequence=event_sequence,
            admitting_authority_id=admitting_authority_id,
            assumption_registry_root=assumption_root,
            evidence_registry_root=evidence_root,
            scope_ids=propose_state.scope_ids,
            assumption_materiality=propose_state.materiality,
            sod_decisions=tuple(sod_decisions),
            dependency_validation_receipt=dep_receipt,
            authorization_digest=_domain_digest(_AUTHORIZATION_DOMAIN, unsigned_auth),
        )

        # --- Build ADMIT event ---
        event = _build_admit_event(authorization)

        # --- Project ADMITTED state ---
        projected = reduce_assumption(propose_state, event)

        # --- Predict head + post-root ---
        predicted_head = RegistryEntityHead(
            "ASSUMPTION",
            assumption_id,
            2,
            event.digest,
        )
        predicted_post_root = _compute_predicted_post_root(view, assumption_id, predicted_head)

        # --- Construct + validate result (BEFORE commit) ---
        result = GovernedAdmitResult(
            event=event,
            head=predicted_head,
            applied=True,
            reason="APPENDED",
            assumption_registry_root=predicted_post_root,
            evidence_registry_root=evidence_root,
            projected=projected,
            authorization=authorization,
        )

        # --- Commit ---
        view._commit_prepared(
            event=event,
            expected_current_head=current_head,
            predicted_head=predicted_head,
        )

        return result


def _handle_retry(
    view: LockedRegistryView,
    assumption_id: str,
    admitting_authority_id: str,
    event_sequence: int,
    retry_auth: GovernedAdmitAuthorization,
    current_head: RegistryEntityHead,
) -> GovernedAdmitResult:
    """Handle exact snapshot-equivalent retry for an already-committed ADMIT."""
    # Request must match authorization.
    if retry_auth.assumption_id != assumption_id:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="assumption_id")
    if retry_auth.admitting_authority_id != admitting_authority_id:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="authority_id")
    if retry_auth.event_sequence != event_sequence:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="event_sequence")

    # Rebuild exact event from authorization.
    rebuilt_event = _build_admit_event(retry_auth)
    if rebuilt_event.canonical_bytes != current_head.event_digest:
        # Need the actual stored event to compare canonical bytes.
        existing_event = view.get_event(current_head.event_digest)
        if existing_event is None:
            raise GovernedAdmitError(
                "GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="event missing"
            )
        if rebuilt_event.canonical_bytes != existing_event.canonical_bytes:
            raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="event bytes")

    # Evidence root must match.
    current_evidence_root = view.snapshot_root("EVIDENCE_UNIT")
    if current_evidence_root != retry_auth.evidence_registry_root:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="evidence root")

    # Reconstruct hypothetical pre-root.
    snap = view.snapshot("ASSUMPTION")
    heads = list(snap.heads)
    # Find the candidate's current head and replace with its seq-1 predecessor.
    existing_event = view.get_event(current_head.event_digest)
    if existing_event is None:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="event missing")
    existing_value = existing_event.to_json_value()
    predecessor_digest = existing_value["previous_entity_event_digest"]
    if predecessor_digest is None:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="no predecessor")
    predecessor_head = RegistryEntityHead(
        "ASSUMPTION", assumption_id, 1, cast(str, predecessor_digest)
    )
    new_heads: list[RegistryEntityHead] = []
    for h in heads:
        if h.entity_id == assumption_id:
            new_heads.append(predecessor_head)
        else:
            new_heads.append(h)
    new_heads.sort(key=lambda item: item.entity_id)
    hypothetical_pre_root = _snapshot_root("ASSUMPTION", tuple(new_heads))
    if hypothetical_pre_root != retry_auth.assumption_registry_root:
        raise GovernedAdmitError("GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH", detail="assumption root")

    # Build idempotent result.
    projected = reduce_assumption(
        project_assumption_history(view.reconstruct_entity("ASSUMPTION", assumption_id)[:1]),
        existing_event,
    )
    return GovernedAdmitResult(
        event=existing_event,
        head=current_head,
        applied=False,
        reason="IDEMPOTENT_APPEND",
        assumption_registry_root=snap.root_digest,
        evidence_registry_root=current_evidence_root,
        projected=projected,
        authorization=retry_auth,
    )
