"""Frozen authoritative separation-of-duty authority evaluator (I1-B / D3.2-A2).

Given an authoritative I1-A grant-selection decision, the authoritative policy
that produced it, and B0-reconstructed prior governance roles for the same
assumption, deterministically decide whether separation-of-duty permits the
candidate governance action, including only exactly applicable bounded duty
exceptions.

The evaluator is authoritative **relative to its supplied validated V3 ledger
snapshot**. It recomputes the I1-A selection from that ledger and the
decision-bound request, accesses the source policy through the I1-A source
binding helper, and never trusts caller-supplied selection, grant, policy, rule,
or exception material. A later filesystem/publisher composite is responsible
for sourcing the ledger snapshot from authoritative storage; the pure evaluator
detects inconsistent objects inside one supplied snapshot through the existing
I1-A binding path.

Semantic boundaries (frozen):

* Conflicts and exception waivers are evaluated **per rule**, not against a
  global conflict union. A duty exception relaxes one named separation rule; it
  does not waive a governance role globally. A role may therefore appear in both
  ``waived_roles`` and ``remaining_conflicts`` when it was waived under one rule
  but remains prohibited under another.
* ``event_sequence`` is governance / policy time (from the I1-A resolution).
  ``candidate_entity_sequence`` is the position inside one assumption's event
  chain. They are distinct domains; the evaluator additionally requires every
  entity-predecessor history event to carry ``clock_sequence < event_sequence``.
* An I1-A denial (``NO_APPLICABLE_GRANT`` / ``AMBIGUOUS_GRANTS``) short-circuits
  to DENY without evaluating B0 history, rules, or exceptions. An exception
  never creates authority.
* The output ordering authority is the frozen ``ASSUMPTION_GOVERNANCE_ROLES``
  tuple, not alphabetical sorting.

No public v0.5 schema, catalog, or vector changes. The
``SeparationOfDutyDecision`` is an internal D3.2 receipt that carries the
per-rule evaluation evidence and the final ALLOW/DENY; it is self-digesting
under its own domain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    ASSUMPTION_AUTHORITY_ACTIONS,
    ASSUMPTION_GOVERNANCE_ROLES,
    ASSUMPTION_MATERIALITIES,
    GLOBAL_ASSUMPTION_SCOPE,
    AssumptionGovernanceContractError,
    _domain_digest,
    _json_bytes,
    _require_digest,
    _require_self_digest,
    _require_token,
)
from csd_foundry.governance.v0_5._assumption_governance_role_derivation import (
    derive_prior_governance_roles,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionPolicyLedgerV3,
)
from csd_foundry.governance.v0_5.assumption_policy_resolution import (
    DECISION_TYPES,
    _source_entry_for_resolution,
    resolve_policy_at_v3,
    select_applicable_grant_v3,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent

_SOD_DECISION_SCHEMA_VERSION = "assumption-separation-of-duty-decision/1"
_SOD_DOMAIN = "ASSUMPTION_SEPARATION_OF_DUTY_DECISION"


def _ordered_roles(roles: set[str]) -> tuple[str, ...]:
    """Return roles in frozen ``ASSUMPTION_GOVERNANCE_ROLES`` order."""
    return tuple(role for role in ASSUMPTION_GOVERNANCE_ROLES if role in roles)


def _scope_covers_request(scope_id: str, scopes: tuple[str, ...]) -> bool:
    """Return True if the request scope is covered by the scope set.

    A global scope set covers any request scope. Otherwise the request scope
    must be an exact member. Used identically for rules and exceptions.
    """
    return scopes == (GLOBAL_ASSUMPTION_SCOPE,) or scope_id in scopes


def _require_role_tuple(value: object, code: str) -> tuple[str, ...]:
    """Require a tuple of roles in canonical ``ASSUMPTION_GOVERNANCE_ROLES`` order."""
    if not isinstance(value, tuple):
        raise AssumptionGovernanceContractError(code)
    items = list(value)
    canonical = [role for role in ASSUMPTION_GOVERNANCE_ROLES if role in set(items)]
    if items != canonical:
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


@dataclass(frozen=True, slots=True)
class SeparationOfDutyRuleEvaluation:
    """Per-rule evaluation evidence: conflicts, waivers, and remaining conflicts.

    Records the exact conflict set (``prior_roles ∩ rule.conflicting_roles``),
    the exceptions that contributed waivers under this exact rule, the roles
    waived under this rule, and the remaining conflicts after waiver. An
    exception contributes to this record only if its intersection with the
    rule's actual conflicts is non-empty.

    This record is decision-bearing evidence. It does not have its own
    self-digest; it is serialized into the top-level decision's unsigned value,
    so the decision digest is the single receipt authority.
    """

    rule_id: str
    rule_digest: str
    conflicting_roles: tuple[str, ...]
    waiving_exceptions: tuple[tuple[str, str], ...]
    waived_roles: tuple[str, ...]
    remaining_conflicts: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_token(self.rule_id, "SOD_RULE_EVALUATION_RULE_ID_INVALID")
        _require_digest(self.rule_digest, "SOD_RULE_EVALUATION_RULE_DIGEST_INVALID")
        _require_role_tuple(self.conflicting_roles, "SOD_RULE_EVALUATION_CONFLICTS_INVALID")
        _require_role_tuple(self.waived_roles, "SOD_RULE_EVALUATION_WAIVED_INVALID")
        _require_role_tuple(self.remaining_conflicts, "SOD_RULE_EVALUATION_REMAINING_INVALID")
        # waived_roles must be a subset of conflicting_roles.
        if not set(self.waived_roles).issubset(set(self.conflicting_roles)):
            raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVED_NOT_SUBSET")
        # remaining_conflicts must equal conflicting_roles - waived_roles.
        expected_remaining = set(self.conflicting_roles) - set(self.waived_roles)
        if set(self.remaining_conflicts) != expected_remaining:
            raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_REMAINING_MISMATCH")
        # waiving_exceptions: canonical unique exception_id order, each a (id, digest) pair.
        if not isinstance(self.waiving_exceptions, tuple):
            raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVING_INVALID")
        seen: set[str] = set()
        prev: str | None = None
        for pair in self.waiving_exceptions:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVING_INVALID")
            eid, edigest = pair
            _require_token(eid, "SOD_RULE_EVALUATION_WAIVING_ID_INVALID")
            _require_digest(edigest, "SOD_RULE_EVALUATION_WAIVING_DIGEST_INVALID")
            if eid in seen:
                raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVING_DUPLICATE")
            if prev is not None and eid <= prev:
                raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVING_UNORDERED")
            seen.add(eid)
            prev = eid
        # waiving_exceptions is non-empty iff waived_roles is non-empty.
        if bool(self.waiving_exceptions) != bool(self.waived_roles):
            raise AssumptionGovernanceContractError("SOD_RULE_EVALUATION_WAIVING_INCONSISTENT")

    def to_json_value(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "rule_digest": self.rule_digest,
            "conflicting_roles": list(self.conflicting_roles),
            "waiving_exceptions": [list(pair) for pair in self.waiving_exceptions],
            "waived_roles": list(self.waived_roles),
            "remaining_conflicts": list(self.remaining_conflicts),
        }


@dataclass(frozen=True, slots=True)
class SeparationOfDutyDecision:
    """The authoritative separation-of-duty decision for one candidate action.

    Carries the full evaluation context (candidate identity, authoritative I1-A
    selection bindings, B0 prior roles), the per-rule evaluation evidence, and
    the final ALLOW/DENY result. The per-rule evidence in ``rule_evaluations``
    is the authoritative record; the aggregate fields are mechanically derived
    and validated from it in ``__post_init__``.

    A role may appear in both ``waived_roles`` and ``remaining_conflicts`` when
    it was waived under one rule but remains prohibited under another. The
    decision is ``ALLOW`` iff ``selection_decision_type == "SELECTED"`` and every
    per-rule ``remaining_conflicts`` is empty.
    """

    # Decision context
    assumption_id: str
    candidate_entity_sequence: int
    action: str
    authority_id: str
    scope_id: str
    assumption_materiality: str
    challenge_materiality: str | None
    event_sequence: int
    # Authoritative I1-A bindings
    selection_decision_type: str
    selection_digest: str
    selected_grant_id: str | None
    grant_digest: str | None
    ledger_root_digest: str
    policy_digest: str
    commit_receipt_digest: str
    # B0 reconstruction
    prior_roles: tuple[str, ...]
    # Per-rule evidence
    rule_evaluations: tuple[SeparationOfDutyRuleEvaluation, ...]
    # Aggregate convenience (mechanically derived from rule_evaluations)
    evaluated_rule_digests: tuple[str, ...]
    conflicting_roles: tuple[str, ...]
    waiving_exception_digests: tuple[str, ...]
    waived_roles: tuple[str, ...]
    remaining_conflicts: tuple[str, ...]
    # Result
    decision: str
    decision_digest: str

    def __post_init__(self) -> None:
        # --- Scalar validation (ordinary fail-closed pattern) ---
        _require_token(self.assumption_id, "SOD_DECISION_ASSUMPTION_ID_INVALID")
        if (
            type(self.candidate_entity_sequence) is not int
            or isinstance(self.candidate_entity_sequence, bool)
            or self.candidate_entity_sequence < 1
        ):
            raise AssumptionGovernanceContractError("SOD_DECISION_CANDIDATE_SEQUENCE_INVALID")
        if self.action not in ASSUMPTION_AUTHORITY_ACTIONS:
            raise AssumptionGovernanceContractError("SOD_DECISION_ACTION_INVALID")
        _require_token(self.authority_id, "SOD_DECISION_AUTHORITY_ID_INVALID")
        _require_token(self.scope_id, "SOD_DECISION_SCOPE_ID_INVALID")
        if self.assumption_materiality not in ASSUMPTION_MATERIALITIES:
            raise AssumptionGovernanceContractError("SOD_DECISION_ASSUMPTION_MATERIALITY_INVALID")
        if (
            self.challenge_materiality is not None
            and self.challenge_materiality not in ASSUMPTION_MATERIALITIES
        ):
            raise AssumptionGovernanceContractError("SOD_DECISION_CHALLENGE_MATERIALITY_INVALID")
        if (
            type(self.event_sequence) is not int
            or isinstance(self.event_sequence, bool)
            or self.event_sequence < 0
        ):
            raise AssumptionGovernanceContractError("SOD_DECISION_EVENT_SEQUENCE_INVALID")
        # Resolution-action / challenge-materiality consistency.
        is_resolution = self.action in (
            "RESOLVE_TO_ADMITTED",
            "RESOLVE_TO_CONFIRMED",
            "RESOLVE_TO_REJECTED",
            "RESOLVE_TO_SUPERSEDED",
        )
        if is_resolution and self.challenge_materiality is None:
            raise AssumptionGovernanceContractError("SOD_DECISION_CHALLENGE_MATERIALITY_REQUIRED")
        if not is_resolution and self.challenge_materiality is not None:
            raise AssumptionGovernanceContractError("SOD_DECISION_CHALLENGE_MATERIALITY_UNEXPECTED")
        # I1-A decision type.
        if self.selection_decision_type not in DECISION_TYPES:
            raise AssumptionGovernanceContractError("SOD_DECISION_SELECTION_TYPE_INVALID")
        _require_digest(self.selection_digest, "SOD_DECISION_SELECTION_DIGEST_INVALID")
        _require_digest(self.ledger_root_digest, "SOD_DECISION_LEDGER_ROOT_INVALID")
        _require_digest(self.policy_digest, "SOD_DECISION_POLICY_DIGEST_INVALID")
        _require_digest(self.commit_receipt_digest, "SOD_DECISION_COMMIT_RECEIPT_INVALID")
        _require_role_tuple(self.prior_roles, "SOD_DECISION_PRIOR_ROLES_INVALID")

        # --- I1-A outcome consistency ---
        if self.selection_decision_type != "SELECTED":
            if self.selected_grant_id is not None or self.grant_digest is not None:
                raise AssumptionGovernanceContractError("SOD_DECISION_DENIAL_GRANT_PRESENT")
            if self.prior_roles != ():
                raise AssumptionGovernanceContractError("SOD_DECISION_DENIAL_PRIOR_ROLES_PRESENT")
            if self.rule_evaluations != ():
                raise AssumptionGovernanceContractError(
                    "SOD_DECISION_DENIAL_RULE_EVALUATIONS_PRESENT"
                )
        else:
            if self.selected_grant_id is None:
                raise AssumptionGovernanceContractError("SOD_DECISION_SELECTED_GRANT_MISSING")
            _require_token(self.selected_grant_id, "SOD_DECISION_SELECTED_GRANT_ID_INVALID")
            if self.grant_digest is None:
                raise AssumptionGovernanceContractError(
                    "SOD_DECISION_SELECTED_GRANT_DIGEST_MISSING"
                )
            _require_digest(self.grant_digest, "SOD_DECISION_SELECTED_GRANT_DIGEST_INVALID")

        # --- rule_evaluations integrity ---
        if not isinstance(self.rule_evaluations, tuple):
            raise AssumptionGovernanceContractError("SOD_DECISION_RULE_EVALUATIONS_INVALID")
        eval_rule_ids: list[str] = []
        for re_ in self.rule_evaluations:
            if type(re_) is not SeparationOfDutyRuleEvaluation:
                raise AssumptionGovernanceContractError("SOD_DECISION_RULE_EVALUATION_TYPE_INVALID")
            eval_rule_ids.append(re_.rule_id)
            # Each rule's conflicts must be a subset of prior_roles.
            if not set(re_.conflicting_roles).issubset(set(self.prior_roles)):
                raise AssumptionGovernanceContractError("SOD_DECISION_RULE_CONFLICT_NOT_PRIOR")
        # Sorted + unique by rule_id.
        if eval_rule_ids != sorted(eval_rule_ids):
            raise AssumptionGovernanceContractError("SOD_DECISION_RULE_EVALUATIONS_UNORDERED")
        if len(set(eval_rule_ids)) != len(eval_rule_ids):
            raise AssumptionGovernanceContractError("SOD_DECISION_RULE_EVALUATIONS_DUPLICATE")

        # No duplicate exception_id across rule evaluations (one exception -> one rule_id).
        cross_exception_ids: set[str] = set()
        for re_ in self.rule_evaluations:
            for eid, _ in re_.waiving_exceptions:
                if eid in cross_exception_ids:
                    raise AssumptionGovernanceContractError(
                        "SOD_DECISION_CROSS_RULE_EXCEPTION_DUPLICATE"
                    )
                cross_exception_ids.add(eid)

        # --- Aggregate mechanical re-derivation ---
        agg_rule_digests = tuple(re_.rule_digest for re_ in self.rule_evaluations)
        agg_conflicts = _ordered_roles(
            set().union(*(set(re_.conflicting_roles) for re_ in self.rule_evaluations))
            if self.rule_evaluations
            else set()
        )
        agg_waived = _ordered_roles(
            set().union(*(set(re_.waived_roles) for re_ in self.rule_evaluations))
            if self.rule_evaluations
            else set()
        )
        agg_remaining = _ordered_roles(
            set().union(*(set(re_.remaining_conflicts) for re_ in self.rule_evaluations))
            if self.rule_evaluations
            else set()
        )
        # waiving_exception_digests: globally unique, canonical exception_id order.
        exception_pairs: list[tuple[str, str]] = []
        for re_ in self.rule_evaluations:
            exception_pairs.extend(re_.waiving_exceptions)
        exception_pairs.sort(key=lambda pair: pair[0])
        agg_exception_digests = tuple(digest for _, digest in exception_pairs)

        if self.evaluated_rule_digests != agg_rule_digests:
            raise AssumptionGovernanceContractError("SOD_DECISION_RULE_DIGESTS_MISMATCH")
        if self.conflicting_roles != agg_conflicts:
            raise AssumptionGovernanceContractError("SOD_DECISION_CONFLICTING_ROLES_MISMATCH")
        if self.waived_roles != agg_waived:
            raise AssumptionGovernanceContractError("SOD_DECISION_WAIVED_ROLES_MISMATCH")
        if self.remaining_conflicts != agg_remaining:
            raise AssumptionGovernanceContractError("SOD_DECISION_REMAINING_CONFLICTS_MISMATCH")
        if self.waiving_exception_digests != agg_exception_digests:
            raise AssumptionGovernanceContractError(
                "SOD_DECISION_WAIVING_EXCEPTION_DIGESTS_MISMATCH"
            )

        # --- Decision consistency ---
        if self.selection_decision_type == "SELECTED":
            expected_decision = (
                "ALLOW"
                if all(re_.remaining_conflicts == () for re_ in self.rule_evaluations)
                else "DENY"
            )
        else:
            expected_decision = "DENY"
        if self.decision != expected_decision:
            raise AssumptionGovernanceContractError("SOD_DECISION_RESULT_INCONSISTENT")

        # --- Self-digest ---
        _require_self_digest(
            _SOD_DOMAIN,
            self._unsigned_value(),
            self.decision_digest,
            "SOD_DECISION_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _SOD_DECISION_SCHEMA_VERSION,
            "action": self.action,
            "assumption_id": self.assumption_id,
            "assumption_materiality": self.assumption_materiality,
            "candidate_entity_sequence": self.candidate_entity_sequence,
            "challenge_materiality": self.challenge_materiality,
            "commit_receipt_digest": self.commit_receipt_digest,
            "conflicting_roles": list(self.conflicting_roles),
            "decision": self.decision,
            "event_sequence": self.event_sequence,
            "authority_id": self.authority_id,
            "evaluated_rule_digests": list(self.evaluated_rule_digests),
            "grant_digest": self.grant_digest,
            "ledger_root_digest": self.ledger_root_digest,
            "policy_digest": self.policy_digest,
            "prior_roles": list(self.prior_roles),
            "remaining_conflicts": list(self.remaining_conflicts),
            "rule_evaluations": [re_.to_json_value() for re_ in self.rule_evaluations],
            "scope_id": self.scope_id,
            "selected_grant_id": self.selected_grant_id,
            "selection_decision_type": self.selection_decision_type,
            "selection_digest": self.selection_digest,
            "waived_roles": list(self.waived_roles),
            "waiving_exception_digests": list(self.waiving_exception_digests),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "decision_digest": self.decision_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def evaluate_separation_of_duty(
    *,
    ledger: AssumptionPolicyLedgerV3,
    event_sequence: int,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    assumption_id: str,
    candidate_entity_sequence: int,
    assumption_history: tuple[RegistryEvent, ...],
) -> SeparationOfDutyDecision:
    """Evaluate separation-of-duty for a candidate governance action.

    Recomputes the I1-A grant selection from the supplied validated V3 ledger
    snapshot and the decision-bound request, reconstructs prior roles via B0,
    and evaluates every applicable SoD rule with its exact exceptions. Returns
    a single self-digesting :class:`SeparationOfDutyDecision`.

    The evaluator is authoritative relative to the supplied ledger. It does not
    independently source the ledger from authoritative storage.

    Raises:
        AssumptionGovernanceContractError: on any evaluator-level contract
            violation (history identity mismatch, logical-time inconsistency,
            invalid inputs).
        AssumptionPolicyActivationContractError: if the I1-A resolution or
            source binding detects a ledger/resolution inconsistency (re-raised
            from the I1-A layer).
    """
    # --- STEP 1: One authoritative resolution + selection ---
    resolved = resolve_policy_at_v3(ledger, event_sequence)
    selection = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
    )

    # --- STEP 2: Grant-denial short-circuit ---
    if selection.decision_type != "SELECTED":
        return _build_denial_decision(
            assumption_id=assumption_id,
            candidate_entity_sequence=candidate_entity_sequence,
            action=action,
            authority_id=authority_id,
            scope_id=scope_id,
            assumption_materiality=assumption_materiality,
            challenge_materiality=challenge_materiality,
            event_sequence=event_sequence,
            selection=selection,
            resolved=resolved,
        )

    # --- STEP 3: Access authoritative source policy (after short-circuit) ---
    source_entry = _source_entry_for_resolution(ledger=ledger, resolved_policy=resolved)
    rules = source_entry.policy.separation_duty_rules
    exceptions = source_entry.policy.duty_exceptions

    # --- STEP 4: B0 prior-role reconstruction ---
    prior_roles = derive_prior_governance_roles(
        assumption_history,
        candidate_entity_sequence=candidate_entity_sequence,
        authority_id=authority_id,
    )

    # --- STEP 5: Same-assumption identity binding ---
    if len(assumption_history) > 0:
        first_value = assumption_history[0].to_json_value()
        first_entity_id = cast(str, first_value["entity_id"])
        if first_entity_id != assumption_id:
            raise AssumptionGovernanceContractError("SOD_HISTORY_ASSUMPTION_IDENTITY_MISMATCH")

    # --- STEP 6: Logical-time binding of predecessor history ---
    for event in assumption_history:
        value = event.to_json_value()
        entity_seq = cast(int, value["entity_sequence"])
        if entity_seq < candidate_entity_sequence:
            clock_seq = cast(int, value["clock_sequence"])
            if clock_seq >= event_sequence:
                raise AssumptionGovernanceContractError("SOD_HISTORY_CLOCK_NOT_PRIOR")

    # --- STEP 7: Per-rule conflict + per-rule exception evaluation ---
    prior_set = set(prior_roles)
    rule_evaluations: list[SeparationOfDutyRuleEvaluation] = []
    for rule in rules:
        if not _rule_applies(rule, action, scope_id, assumption_materiality):
            continue
        rule_conflicts = prior_set & set(rule.conflicting_roles)
        rule_waived: set[str] = set()
        rule_waiving: list[tuple[str, str]] = []
        for exception in exceptions:
            if not _exception_applies(
                exception,
                rule,
                action,
                authority_id,
                scope_id,
                assumption_materiality,
                assumption_id,
                event_sequence,
            ):
                continue
            waived_by_this = set(exception.conflicting_roles) & rule_conflicts
            if waived_by_this:
                rule_waived |= waived_by_this
                rule_waiving.append((exception.exception_id, exception.exception_digest))
        rule_remaining = rule_conflicts - rule_waived
        rule_waiving.sort(key=lambda pair: pair[0])
        rule_evaluations.append(
            SeparationOfDutyRuleEvaluation(
                rule_id=rule.rule_id,
                rule_digest=rule.rule_digest,
                conflicting_roles=_ordered_roles(rule_conflicts),
                waiving_exceptions=tuple(rule_waiving),
                waived_roles=_ordered_roles(rule_waived),
                remaining_conflicts=_ordered_roles(rule_remaining),
            )
        )

    decision_result = (
        "ALLOW" if all(re_.remaining_conflicts == () for re_ in rule_evaluations) else "DENY"
    )

    # Build aggregates.
    evaluated_rule_digests = tuple(re_.rule_digest for re_ in rule_evaluations)
    conflicting_roles = _ordered_roles(
        set().union(*(set(re_.conflicting_roles) for re_ in rule_evaluations))
        if rule_evaluations
        else set()
    )
    waived_roles = _ordered_roles(
        set().union(*(set(re_.waived_roles) for re_ in rule_evaluations))
        if rule_evaluations
        else set()
    )
    remaining_conflicts = _ordered_roles(
        set().union(*(set(re_.remaining_conflicts) for re_ in rule_evaluations))
        if rule_evaluations
        else set()
    )
    all_exception_pairs: list[tuple[str, str]] = []
    for re_ in rule_evaluations:
        all_exception_pairs.extend(re_.waiving_exceptions)
    all_exception_pairs.sort(key=lambda pair: pair[0])
    waiving_exception_digests = tuple(digest for _, digest in all_exception_pairs)

    unsigned = {
        "schema_version": _SOD_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_id": assumption_id,
        "assumption_materiality": assumption_materiality,
        "candidate_entity_sequence": candidate_entity_sequence,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "conflicting_roles": list(conflicting_roles),
        "decision": decision_result,
        "event_sequence": event_sequence,
        "authority_id": authority_id,
        "evaluated_rule_digests": list(evaluated_rule_digests),
        "grant_digest": selection.grant_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "prior_roles": list(prior_roles),
        "remaining_conflicts": list(remaining_conflicts),
        "rule_evaluations": [re_.to_json_value() for re_ in rule_evaluations],
        "scope_id": scope_id,
        "selected_grant_id": selection.selected_grant_id,
        "selection_decision_type": selection.decision_type,
        "selection_digest": selection.selection_digest,
        "waived_roles": list(waived_roles),
        "waiving_exception_digests": list(waiving_exception_digests),
    }
    decision_digest = _domain_digest(_SOD_DOMAIN, unsigned)

    return SeparationOfDutyDecision(
        assumption_id=assumption_id,
        candidate_entity_sequence=candidate_entity_sequence,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        selection_decision_type=selection.decision_type,
        selection_digest=selection.selection_digest,
        selected_grant_id=selection.selected_grant_id,
        grant_digest=selection.grant_digest,
        ledger_root_digest=resolved.ledger_root_digest,
        policy_digest=resolved.policy_digest,
        commit_receipt_digest=resolved.commit_receipt_digest,
        prior_roles=prior_roles,
        rule_evaluations=tuple(rule_evaluations),
        evaluated_rule_digests=evaluated_rule_digests,
        conflicting_roles=conflicting_roles,
        waiving_exception_digests=waiving_exception_digests,
        waived_roles=waived_roles,
        remaining_conflicts=remaining_conflicts,
        decision=decision_result,
        decision_digest=decision_digest,
    )


def _build_denial_decision(
    *,
    assumption_id: str,
    candidate_entity_sequence: int,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    selection: Any,
    resolved: Any,
) -> SeparationOfDutyDecision:
    """Build the DENY short-circuit receipt for an I1-A authority denial.

    Binds the I1-A selection bindings and the DENY result but leaves all SoD
    evidence fields empty. An exception cannot create authority.
    """
    unsigned = {
        "schema_version": _SOD_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_id": assumption_id,
        "assumption_materiality": assumption_materiality,
        "candidate_entity_sequence": candidate_entity_sequence,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "conflicting_roles": [],
        "decision": "DENY",
        "event_sequence": event_sequence,
        "authority_id": authority_id,
        "evaluated_rule_digests": [],
        "grant_digest": None,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "prior_roles": [],
        "remaining_conflicts": [],
        "rule_evaluations": [],
        "scope_id": scope_id,
        "selected_grant_id": None,
        "selection_decision_type": selection.decision_type,
        "selection_digest": selection.selection_digest,
        "waived_roles": [],
        "waiving_exception_digests": [],
    }
    decision_digest = _domain_digest(_SOD_DOMAIN, unsigned)
    return SeparationOfDutyDecision(
        assumption_id=assumption_id,
        candidate_entity_sequence=candidate_entity_sequence,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        selection_decision_type=selection.decision_type,
        selection_digest=selection.selection_digest,
        selected_grant_id=None,
        grant_digest=None,
        ledger_root_digest=resolved.ledger_root_digest,
        policy_digest=resolved.policy_digest,
        commit_receipt_digest=resolved.commit_receipt_digest,
        prior_roles=(),
        rule_evaluations=(),
        evaluated_rule_digests=(),
        conflicting_roles=(),
        waiving_exception_digests=(),
        waived_roles=(),
        remaining_conflicts=(),
        decision="DENY",
        decision_digest=decision_digest,
    )


def _rule_applies(rule: Any, action: str, scope_id: str, assumption_materiality: str) -> bool:
    return (
        rule.action == action
        and _scope_covers_request(scope_id, rule.scope_ids)
        and assumption_materiality in rule.assumption_materialities
    )


def _exception_applies(
    exception: Any,
    rule: Any,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    assumption_id: str,
    event_sequence: int,
) -> bool:
    return (
        exception.rule_id == rule.rule_id
        and exception.action == action
        and exception.authority_id == authority_id
        and _scope_covers_request(scope_id, exception.scope_ids)
        and assumption_materiality in exception.assumption_materialities
        and (exception.assumption_ids == () or assumption_id in exception.assumption_ids)
        and exception.effective_from_sequence <= event_sequence < exception.effective_until_sequence
    )
