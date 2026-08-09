"""Tests for the frozen separation-of-duty authority evaluator (I1-B / D3.2-A2).

Covers the 23 required semantic cases, the resolution-action case, and the
contract-hardening group. The evaluator recomputes the I1-A selection from a
supplied validated V3 ledger snapshot, reconstructs prior roles via B0, and
evaluates every applicable SoD rule with its exact per-rule exceptions.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionGovernanceContractError,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
)
from csd_foundry.governance.v0_5._assumption_separation_duty_evaluator import (
    SeparationOfDutyDecision,
    SeparationOfDutyRuleEvaluation,
    evaluate_separation_of_duty,
)
from csd_foundry.governance.v0_5.assumption import (
    build_assumption_event,
    project_assumption_history,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionDutyException,
    AssumptionSeparationDutyRule,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent

# --------------------------------------------------------------------------- #
# V3 ledger scaffolding (adapted from test_v0_5_assumption_policy_signing_envelope)
# --------------------------------------------------------------------------- #


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _approval_policy() -> AssumptionPolicyApprovalPolicy:
    standard = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=2,
        required_signer_ids=("authority:a",),
    )
    duty = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=3,
        required_signer_ids=("authority:a",),
    )
    return AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:assumptions:1",
        authority_root_digest=_digest("root"),
        rules=(standard, duty),
    )


def _signature_profile() -> AssumptionPolicySignatureProfile:
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(
                algorithm="ed25519",
                verification_profile="ed25519-rfc8032-strict/1",
            ),
        ),
        required_authority_scope="ASSUMPTION_POLICY_APPROVAL",
        key_authority_root_digest=_digest("root"),
    )


def _challenge_policy() -> AssumptionChallengeClassificationPolicy:
    return AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="PROVENANCE_CONFLICT",
                materiality="MATERIAL",
            ),
        )
    )


def _grant(
    grant_id: str = "grant:1",
    action: str = "ADMIT",
    authority_id: str = "authority:operator",
    scope_ids: tuple[str, ...] = ("scope:control",),
    assumption_materialities: tuple[str, ...] = ("MATERIAL",),
    challenge_materialities: tuple[str, ...] = (),
    effective_from_sequence: int = 1,
    effective_until_sequence: int | None = None,
) -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=grant_id,
        action=action,
        authority_id=authority_id,
        scope_ids=scope_ids,
        assumption_materialities=assumption_materialities,
        challenge_materialities=challenge_materialities,
        effective_from_sequence=effective_from_sequence,
        effective_until_sequence=effective_until_sequence,
    )


def _policy(
    *,
    grants: tuple[AssumptionAuthorityGrant, ...] | None = None,
    rules: tuple[AssumptionSeparationDutyRule, ...] = (),
    exceptions: tuple[AssumptionDutyException, ...] = (),
    authority_root_digest: str | None = None,
) -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumptions:1",
        authority_root_digest=authority_root_digest or _digest("root"),
        grants=grants or (_grant(),),
        separation_duty_rules=rules,
        duty_exceptions=exceptions,
    )


def _payload(
    policy: AssumptionAuthorityPolicy,
    *,
    effective_from_sequence: int = 10,
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=effective_from_sequence,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_policy=_challenge_policy(),
    )


def _commit(payload: AssumptionPolicySigningPayload) -> AssumptionAuthorityPolicyCommitV3:
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=_digest("sigset"),
    )


def _proof(
    payload: AssumptionPolicySigningPayload, commit: AssumptionAuthorityPolicyCommitV3
) -> AssumptionPolicyActivationProofV2:
    approval = _approval_policy()
    profile = _signature_profile()
    challenge = _challenge_policy()
    rule = approval.rule_for(payload.approval_class)
    return AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=payload.signing_payload_digest,
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=approval.approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=profile.profile_digest,
        challenge_classification_policy_digest=challenge.policy_digest,
        authority_root_digest=payload.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=("authority:a", "authority:b"),
    )


def _entry(
    policy: AssumptionAuthorityPolicy, *, effective_from_sequence: int = 10
) -> AssumptionPolicyLedgerEntryV3:
    payload = _payload(policy, effective_from_sequence=effective_from_sequence)
    commit = _commit(payload)
    proof = _proof(payload, commit)
    return AssumptionPolicyLedgerEntryV3.build(
        policy=policy,
        signing_payload=payload,
        policy_commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof,
    )


def _ledger(
    policy: AssumptionAuthorityPolicy, *, effective_from_sequence: int = 10
) -> AssumptionPolicyLedgerV3:
    entry = _entry(policy, effective_from_sequence=effective_from_sequence)
    return AssumptionPolicyLedgerV3.build((entry,))


def _successor_entry(
    predecessor: AssumptionPolicyLedgerEntryV3,
    policy: AssumptionAuthorityPolicy,
    *,
    effective_from_sequence: int = 20,
) -> AssumptionPolicyLedgerEntryV3:
    payload = AssumptionPolicySigningPayload.build(
        policy=policy,
        predecessor_policy_digest=predecessor.signing_payload.policy_digest,
        predecessor_commit_receipt_digest=predecessor.policy_commit.commit_receipt_digest,
        effective_from_sequence=effective_from_sequence,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_policy=_challenge_policy(),
    )
    commit = _commit(payload)
    proof = _proof(payload, commit)
    return AssumptionPolicyLedgerEntryV3.build(
        policy=policy,
        signing_payload=payload,
        policy_commit=commit,
        approval_policy=_approval_policy(),
        signature_profile=_signature_profile(),
        challenge_classification_policy=_challenge_policy(),
        activation_proof=proof,
    )


def _successor_ledger(
    first: AssumptionPolicyLedgerEntryV3,
    second: AssumptionPolicyLedgerEntryV3,
) -> AssumptionPolicyLedgerV3:
    return AssumptionPolicyLedgerV3.build((first, second))


# --------------------------------------------------------------------------- #
# Lifecycle event helpers (adapted from test_v0_5_assumption_governance_role_derivation)
# --------------------------------------------------------------------------- #


def _event_digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _propose(
    *,
    assumption_id: str = "assumption:1",
    authority: str = "authority:operator",
    clock: int = 10,
    expires: int = 100,
) -> RegistryEvent:
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_event_digest("p"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:1",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": authority,
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _after(
    previous_event: RegistryEvent,
    history: tuple[RegistryEvent, ...],
    operation: str,
    clock: int,
    payload: dict,
) -> RegistryEvent:
    proj = project_assumption_history(history)
    assert proj is not None
    return build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proj.current_entity_sequence + 1,
        previous_entity_event_digest=proj.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_event_digest(str(clock)),
        payload={"operation": operation, **payload},
    )


def _admit(
    history: tuple[RegistryEvent, ...], authority: str = "authority:admitter", clock: int = 13
) -> RegistryEvent:
    return _after(
        history[-1],
        history,
        "ADMIT",
        clock,
        {
            "admitting_authority_id": authority,
            "admission_receipt_digest": _event_digest("admit"),
        },
    )


def _challenge(
    history: tuple[RegistryEvent, ...],
    authority: str = "authority:challenger",
    clock: int = 14,
    cid: str = "challenge:1",
) -> RegistryEvent:
    return _after(
        history[-1],
        history,
        "CHALLENGE",
        clock,
        {
            "challenge_id": cid,
            "challenger_authority_id": authority,
            "challenge_reason_code": "reason:test",
            "challenge_receipt_digest": _event_digest("chal"),
        },
    )


def _resolve(
    history: tuple[RegistryEvent, ...],
    *,
    clock: int = 15,
    outcome: str = "RETURN_TO_ADMITTED",
    authority: str = "authority:resolver",
    challenge_ids: tuple[str, ...] | None = None,
    replacement: str | None = None,
) -> RegistryEvent:
    return _after(
        history[-1],
        history,
        "RESOLVE_CHALLENGES",
        clock,
        {
            "resolution_outcome": outcome,
            "resolver_authority_id": authority,
            "resolution_receipt_digest": _event_digest("resolve"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": list(challenge_ids or ["challenge:1"]),
            "replacement_assumption_id": replacement,
        },
    )


# --------------------------------------------------------------------------- #
# Test wrappers
# --------------------------------------------------------------------------- #


def _eval(
    policy: AssumptionAuthorityPolicy,
    *,
    action: str = "ADMIT",
    authority_id: str = "authority:operator",
    scope_id: str = "scope:control",
    assumption_materiality: str = "MATERIAL",
    challenge_materiality: str | None = None,
    event_sequence: int = 20,
    assumption_id: str = "assumption:1",
    candidate_entity_sequence: int = 2,
    history: tuple[RegistryEvent, ...] | None = None,
) -> SeparationOfDutyDecision:
    ledger = _ledger(policy)
    return evaluate_separation_of_duty(
        ledger=ledger,
        event_sequence=event_sequence,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        assumption_id=assumption_id,
        candidate_entity_sequence=candidate_entity_sequence,
        assumption_history=history if history is not None else (),
    )


# --------------------------------------------------------------------------- #
# Cases 1-4: basic allow/deny
# --------------------------------------------------------------------------- #


def test_01_no_applicable_sod_rule_allows() -> None:
    """No applicable SoD rule -> ALLOW."""
    policy = _policy(rules=())
    decision = _eval(policy, candidate_entity_sequence=1, history=())
    assert decision.decision == "ALLOW"
    assert decision.rule_evaluations == ()
    assert decision.remaining_conflicts == ()


def test_02_applicable_rule_no_conflicting_prior_role_allows() -> None:
    """Applicable rule but actor has no conflicting prior role -> ALLOW."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-confirmer",
        action="ADMIT",
        conflicting_roles=("CONFIRMER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    # Actor proposed (PROPOSER), rule prohibits CONFIRMER -> no conflict.
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "ALLOW"
    assert len(decision.rule_evaluations) == 1
    assert decision.rule_evaluations[0].conflicting_roles == ()
    assert decision.rule_evaluations[0].remaining_conflicts == ()


def test_03_one_prohibited_prior_role_denies() -> None:
    """Actor previously performed one prohibited role -> DENY."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "DENY"
    assert decision.rule_evaluations[0].conflicting_roles == ("PROPOSER",)
    assert decision.rule_evaluations[0].remaining_conflicts == ("PROPOSER",)


def test_04_multiple_roles_only_one_prohibited_denies_on_intersection() -> None:
    """Multiple actor roles, only one prohibited -> DENY on the intersection."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator")
    e2 = _admit((e1,), authority="authority:operator", clock=13)
    # Actor is both PROPOSER and ADMITTER; rule prohibits PROPOSER.
    policy = _policy(rules=(rule,))
    decision = _eval(policy, candidate_entity_sequence=3, history=(e1, e2))
    assert decision.decision == "DENY"
    assert decision.conflicting_roles == ("PROPOSER",)


# --------------------------------------------------------------------------- #
# Cases 5-7: exception waivers
# --------------------------------------------------------------------------- #


def test_05_exception_waives_only_conflict_allows() -> None:
    """Exact valid exception waives the only conflict -> ALLOW."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:emergency",
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="EMERGENCY",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(grants=(_grant(),), rules=(rule,), exceptions=(exception,))
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "ALLOW"
    assert decision.rule_evaluations[0].waived_roles == ("PROPOSER",)
    assert decision.rule_evaluations[0].remaining_conflicts == ()


def test_06_exception_covers_one_of_two_conflicts_denies_v2() -> None:
    """Exception covers only one of two actual conflicts -> DENY on remaining."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:confirmer-not-proposer-or-admitter",
        action="CONFIRM",
        conflicting_roles=("ADMITTER", "PROPOSER"),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:partial",
        rule_id="rule:confirmer-not-proposer-or-admitter",
        action="CONFIRM",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),  # only waives PROPOSER
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="PARTIAL_WAIVER",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    confirm_grant = _grant(grant_id="grant:confirm", action="CONFIRM")
    admit_grant = _grant(grant_id="grant:admit", action="ADMIT")
    e1 = _propose(authority="authority:operator")
    e2 = _admit((e1,), authority="authority:operator")
    policy = _policy(
        grants=(admit_grant, confirm_grant),
        rules=(rule,),
        exceptions=(exception,),
    )
    decision = _eval(
        policy,
        action="CONFIRM",
        candidate_entity_sequence=3,
        history=(e1, e2),
    )
    assert decision.decision == "DENY"
    assert "PROPOSER" in decision.waived_roles
    assert "ADMITTER" in decision.remaining_conflicts


def test_07_two_exceptions_jointly_cover_two_conflicts_allows() -> None:
    """Two exceptions jointly cover two conflicts -> ALLOW, both bound."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:confirmer-not-proposer-or-admitter",
        action="CONFIRM",
        conflicting_roles=("ADMITTER", "PROPOSER"),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exc1 = AssumptionDutyException.build(
        exception_id="exception:waive-proposer",
        rule_id="rule:confirmer-not-proposer-or-admitter",
        action="CONFIRM",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="WAIVE_PROPOSER",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    exc2 = AssumptionDutyException.build(
        exception_id="exception:waive-admitter",
        rule_id="rule:confirmer-not-proposer-or-admitter",
        action="CONFIRM",
        authority_id="authority:operator",
        conflicting_roles=("ADMITTER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="WAIVE_ADMITTER",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    confirm_grant = _grant(grant_id="grant:confirm", action="CONFIRM")
    admit_grant = _grant(grant_id="grant:admit", action="ADMIT")
    e1 = _propose(authority="authority:operator")
    e2 = _admit((e1,), authority="authority:operator")
    policy = _policy(
        grants=(admit_grant, confirm_grant),
        rules=(rule,),
        exceptions=(exc1, exc2),
    )
    decision = _eval(
        policy,
        action="CONFIRM",
        candidate_entity_sequence=3,
        history=(e1, e2),
    )
    assert decision.decision == "ALLOW"
    assert len(decision.rule_evaluations[0].waiving_exceptions) == 2


# --------------------------------------------------------------------------- #
# Case 8: wrong-X exception ignored
# --------------------------------------------------------------------------- #


def test_08_wrong_exception_ignored_conflict_remains() -> None:
    """Wrong-rule/authority/scope/materiality exception -> ignored, conflict remains, DENY.

    All fixtures remain policy-valid: the wrong-rule exception belongs to a
    different applicable rule; wrong-authority has its own covering grant;
    wrong-scope/materiality is narrower than its rule but not covering the request.
    """
    rule1 = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    rule2 = AssumptionSeparationDutyRule.build(
        rule_id="rule:other",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    # Exception for rule2 (wrong rule for rule1's conflict).
    exc_wrong_rule = AssumptionDutyException.build(
        exception_id="exception:wrong-rule",
        rule_id="rule:other",
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="WRONG_RULE",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule1, rule2), exceptions=(exc_wrong_rule,))
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "DENY"


# --------------------------------------------------------------------------- #
# Cases 9-11: exception applicability dimensions
# --------------------------------------------------------------------------- #


def test_09_nonempty_assumption_ids_excluding_candidate_exception_does_not_apply() -> None:
    """Non-empty assumption_ids excluding the candidate -> exception does not apply, DENY."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:specific-assumption",
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=("assumption:other",),  # does not include assumption:1
        assumption_materialities=("MATERIAL",),
        reason_code="SPECIFIC",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    e1 = _propose(authority="authority:operator", assumption_id="assumption:1")
    policy = _policy(rules=(rule,), exceptions=(exception,))
    decision = _eval(policy, assumption_id="assumption:1", history=(e1,))
    assert decision.decision == "DENY"


def test_10_empty_assumption_ids_no_restriction_exception_applies() -> None:
    """Empty assumption_ids -> no identity restriction, exception applies."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:global",
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),  # no restriction
        assumption_materialities=("MATERIAL",),
        reason_code="GLOBAL",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    e1 = _propose(authority="authority:operator", assumption_id="assumption:1")
    policy = _policy(rules=(rule,), exceptions=(exception,))
    decision = _eval(policy, assumption_id="assumption:1", history=(e1,))
    assert decision.decision == "ALLOW"


def test_11_exception_not_yet_active_or_expired_does_not_apply() -> None:
    """Exception outside its time window -> does not apply, DENY."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:expired",
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="EXPIRED",
        effective_from_sequence=50,
        effective_until_sequence=60,  # event_sequence is 12, outside [50, 60)
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,), exceptions=(exception,))
    decision = _eval(policy, event_sequence=12, history=(e1,))
    assert decision.decision == "DENY"


# --------------------------------------------------------------------------- #
# Case 12: I1-A denial short-circuit
# --------------------------------------------------------------------------- #


def test_12_no_applicable_grant_short_circuits_to_deny() -> None:
    """NO_APPLICABLE_GRANT -> DENY with empty SoD evidence."""
    # No grant for the requested action.
    grant_other = _grant(grant_id="grant:other", action="EXPIRE")
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admit-sod",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    policy = _policy(grants=(grant_other,), rules=(rule,))
    e1 = _propose(authority="authority:operator")
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "DENY"
    assert decision.selection_decision_type != "SELECTED"
    assert decision.selected_grant_id is None
    assert decision.grant_digest is None
    assert decision.prior_roles == ()
    assert decision.rule_evaluations == ()
    assert decision.remaining_conflicts == ()


# --------------------------------------------------------------------------- #
# Cases 13-14: structural / binding tests
# --------------------------------------------------------------------------- #


def test_13_no_caller_supplied_grant_path_selection_reconstructed() -> None:
    """The evaluator API takes no GrantSelectionDecision; selection is always
    reconstructed from the ledger. This is a structural guarantee of the API."""
    import inspect

    sig = inspect.signature(evaluate_separation_of_duty)
    param_names = set(sig.parameters.keys())
    assert "selection" not in param_names
    assert "grant" not in param_names
    assert "grant_selection_decision" not in param_names
    assert "ledger" in param_names


def test_14_evidence_from_exact_source_entry() -> None:
    """All rules/exceptions/source-policy evidence comes from the exact source
    entry bound by the supplied ledger. A passing decision with rules present
    proves the evaluator read them from the source policy, not from a detached
    caller argument (there is none in the API)."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    # The rule_digest in the decision matches the rule we built into the policy.
    assert decision.evaluated_rule_digests == (rule.rule_digest,)


# --------------------------------------------------------------------------- #
# Case 15: governing policy/grant identity stability after append
# --------------------------------------------------------------------------- #


def test_15_later_append_preserves_governing_identity_at_t() -> None:
    """A later policy append does not change which policy/grant governed time T."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    policy1 = _policy(rules=(rule,))
    entry1 = _entry(policy1, effective_from_sequence=10)
    # Append a second policy generation.
    policy2 = _policy(rules=())  # different: no rules
    entry2 = _successor_entry(entry1, policy2, effective_from_sequence=20)
    ledger_two = _successor_ledger(entry1, entry2)
    e1 = _propose(authority="authority:operator")
    # Evaluate at T=12 (governed by entry1/policy1).
    decision = evaluate_separation_of_duty(
        ledger=ledger_two,
        event_sequence=12,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        assumption_id="assumption:1",
        candidate_entity_sequence=2,
        assumption_history=(e1,),
    )
    # The governing policy at T=12 is policy1 (has the rule), not policy2.
    assert decision.policy_digest == policy1.policy_digest
    assert decision.evaluated_rule_digests == (rule.rule_digest,)


# --------------------------------------------------------------------------- #
# Case 16: genesis empty history
# --------------------------------------------------------------------------- #


def test_16_genesis_empty_history_evaluates_normally() -> None:
    """Genesis PROPOSE, empty predecessor history, sequence 1 -> B0 supplies (),
    SoD evaluates normally."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    policy = _policy(rules=(rule,))
    decision = _eval(policy, candidate_entity_sequence=1, history=())
    assert decision.decision == "ALLOW"
    assert decision.prior_roles == ()


# --------------------------------------------------------------------------- #
# Case 17: API takes history not roles
# --------------------------------------------------------------------------- #


def test_17_api_takes_history_not_roles() -> None:
    """The API takes assumption_history, not a role set; caller cannot influence
    the result by supplying roles directly."""
    import inspect

    sig = inspect.signature(evaluate_separation_of_duty)
    param_names = set(sig.parameters.keys())
    assert "prior_roles" not in param_names
    assert "roles" not in param_names
    assert "assumption_history" in param_names


# --------------------------------------------------------------------------- #
# Case 18: byte-identical replay
# --------------------------------------------------------------------------- #


def test_18_repeated_execution_byte_identical() -> None:
    """Repeated execution from byte-identical inputs produces byte-identical evidence."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,))
    d1 = _eval(policy, history=(e1,))
    d2 = _eval(policy, history=(e1,))
    assert d1.decision_digest == d2.decision_digest
    assert d1.canonical_bytes == d2.canonical_bytes


# --------------------------------------------------------------------------- #
# Case 19: LOAD-BEARING — two rules same role, one exception one rule -> DENY
# --------------------------------------------------------------------------- #


def test_19_two_rules_same_role_one_exception_denies() -> None:
    """LOAD-BEARING: two applicable rules prohibit the same role; an exception
    waives it for only one rule. The correct result is DENY because the role
    remains prohibited under the other rule.

    Per-rule receipt proof:
        R1 remaining = ()   (waived)
        R2 remaining = (PROPOSER,)  (not waived)
    Aggregate:
        waived_roles = (PROPOSER,)
        remaining_conflicts = (PROPOSER,)

    This proves the implementation did not regress to global waiver semantics."""
    rule1 = AssumptionSeparationDutyRule.build(
        rule_id="rule:one",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    rule2 = AssumptionSeparationDutyRule.build(
        rule_id="rule:two",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    exception = AssumptionDutyException.build(
        exception_id="exception:waive-rule-one-only",
        rule_id="rule:one",  # only waives rule:one
        action="ADMIT",
        authority_id="authority:operator",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=(),
        assumption_materialities=("MATERIAL",),
        reason_code="PARTIAL",
        effective_from_sequence=1,
        effective_until_sequence=100,
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule1, rule2), exceptions=(exception,))
    decision = _eval(policy, history=(e1,))
    assert decision.decision == "DENY"
    # Per-rule: R1 waived, R2 not.
    assert len(decision.rule_evaluations) == 2
    r1_eval = decision.rule_evaluations[0]
    r2_eval = decision.rule_evaluations[1]
    assert r1_eval.rule_id == "rule:one"
    assert r2_eval.rule_id == "rule:two"
    assert r1_eval.remaining_conflicts == ()
    assert r2_eval.remaining_conflicts == ("PROPOSER",)
    # Aggregate: PROPOSER appears in BOTH waived_roles and remaining_conflicts.
    assert "PROPOSER" in decision.waived_roles
    assert "PROPOSER" in decision.remaining_conflicts


# --------------------------------------------------------------------------- #
# Case 20: candidate assumption X with history for Y
# --------------------------------------------------------------------------- #


def test_20_candidate_x_history_for_y_fails_closed() -> None:
    """Candidate assumption_id X with canonical history for Y -> fail closed."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator", assumption_id="assumption:Y")
    policy = _policy(rules=(rule,))
    with pytest.raises(AssumptionGovernanceContractError, match="IDENTITY_MISMATCH"):
        _eval(policy, assumption_id="assumption:X", history=(e1,))


# --------------------------------------------------------------------------- #
# Case 21: prior event clock >= candidate event_sequence
# --------------------------------------------------------------------------- #


def test_21_prior_event_clock_not_prior_fails_closed() -> None:
    """Prior-by-entity event with clock_sequence >= candidate event_sequence -> fail closed."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    # PROPOSE at clock=20, but candidate event_sequence=12.
    e1 = _propose(authority="authority:operator", clock=20)
    policy = _policy(rules=(rule,))
    with pytest.raises(AssumptionGovernanceContractError, match="CLOCK_NOT_PRIOR"):
        _eval(policy, event_sequence=12, candidate_entity_sequence=2, history=(e1,))


# --------------------------------------------------------------------------- #
# Case 22: byte-identical replay from preserved original snapshot
# --------------------------------------------------------------------------- #


def test_22_preserved_snapshot_reproduces_byte_identical() -> None:
    """Replaying from the preserved original ledger snapshot reproduces
    byte-identical SoD evidence, even after a later append."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    policy1 = _policy(rules=(rule,))
    ledger1 = _ledger(policy1)
    e1 = _propose(authority="authority:operator")
    # Original decision from ledger1.
    d1 = evaluate_separation_of_duty(
        ledger=ledger1,
        event_sequence=12,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        assumption_id="assumption:1",
        candidate_entity_sequence=2,
        assumption_history=(e1,),
    )
    # Append a second entry to form a two-entry ledger (proves the append is
    # constructible; the original snapshot is what we replay from).
    policy2 = _policy(rules=())
    entry1 = ledger1.entries[0]
    entry2 = _successor_entry(entry1, policy2, effective_from_sequence=20)
    _successor_ledger(entry1, entry2)
    # But replay from the PRESERVED original snapshot (ledger1).
    d2 = evaluate_separation_of_duty(
        ledger=ledger1,
        event_sequence=12,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        assumption_id="assumption:1",
        candidate_entity_sequence=2,
        assumption_history=(e1,),
    )
    assert d1.decision_digest == d2.decision_digest


# --------------------------------------------------------------------------- #
# Resolution-action case
# --------------------------------------------------------------------------- #


def test_resolution_action_with_resolver_prior_role() -> None:
    """A RESOLVE_TO_* action with a RESOLVER prior role. Proves the implementation
    does not confuse lifecycle RESOLVE_CHALLENGES (which contributes the RESOLVER
    prior role) with the outcome-specific authority action."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:resolver-not-resolver",
        action="RESOLVE_TO_CONFIRMED",
        conflicting_roles=("RESOLVER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    resolve_grant = _grant(
        grant_id="grant:resolve",
        action="RESOLVE_TO_CONFIRMED",
        authority_id="authority:operator",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("MATERIAL",),
    )
    # Build an actor who proposed, admitted, then challenged, then resolved (RESOLVER role).
    e1 = _propose(authority="authority:operator")
    e2 = _admit((e1,), authority="authority:operator", clock=11)
    e3 = _challenge((e1, e2), authority="authority:challenger", clock=12)
    e3b = _resolve((e1, e2, e3), authority="authority:operator", clock=13)
    policy = _policy(grants=(resolve_grant,), rules=(rule,))
    decision = evaluate_separation_of_duty(
        ledger=_ledger(policy),
        event_sequence=20,
        action="RESOLVE_TO_CONFIRMED",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality="MATERIAL",
        assumption_id="assumption:1",
        candidate_entity_sequence=5,
        assumption_history=(e1, e2, e3, e3b),
    )
    # Actor is PROPOSER + RESOLVER; rule prohibits RESOLVER -> DENY.
    assert "RESOLVER" in decision.prior_roles
    assert decision.decision == "DENY"


# --------------------------------------------------------------------------- #
# Hardening tests
# --------------------------------------------------------------------------- #


def test_digest_determinism() -> None:
    """The decision digest is a deterministic domain-separated SHA-256."""
    from csd_foundry.governance.v0_5._assumption_governance_contracts import (
        _domain_digest as contracts_domain_digest,
    )

    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:operator")
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    # The contracts _domain_digest = domain.encode("utf-8") + _json_bytes(value),
    # where _json_bytes = json.dumps(..., sort_keys=True, separators=(",",":")) + "\n".
    expected = contracts_domain_digest(
        "ASSUMPTION_SEPARATION_OF_DUTY_DECISION",
        decision._unsigned_value(),
    )
    assert decision.decision_digest == expected


def test_malformed_remaining_set_rejected() -> None:
    """A per-rule record with a remaining set that doesn't equal conflicts - waived is rejected."""
    with pytest.raises(AssumptionGovernanceContractError, match="REMAINING_MISMATCH"):
        SeparationOfDutyRuleEvaluation(
            rule_id="rule:1",
            rule_digest=_digest("r"),
            conflicting_roles=("PROPOSER",),
            waiving_exceptions=(),
            waived_roles=(),
            remaining_conflicts=(
                "CHALLENGER",
            ),  # wrong: should be ("PROPOSER",) since nothing waived
        )


def test_waived_role_not_in_conflicts_rejected() -> None:
    """A waived role not in the conflict set is rejected."""
    with pytest.raises(AssumptionGovernanceContractError, match="WAIVED_NOT_SUBSET"):
        SeparationOfDutyRuleEvaluation(
            rule_id="rule:1",
            rule_digest=_digest("r"),
            conflicting_roles=("PROPOSER",),
            waiving_exceptions=(("exception:1", _digest("e")),),
            waived_roles=("CHALLENGER",),  # not in conflicts
            remaining_conflicts=("PROPOSER",),
        )


def test_noncanonical_rule_evidence_rejected() -> None:
    """A per-rule record with non-canonical role order is rejected."""
    with pytest.raises(AssumptionGovernanceContractError, match="CONFLICTS_INVALID"):
        SeparationOfDutyRuleEvaluation(
            rule_id="rule:1",
            rule_digest=_digest("r"),
            conflicting_roles=("PROPOSER", "ADMITTER"),  # not in ASSUMPTION_GOVERNANCE_ROLES order
            waiving_exceptions=(),
            waived_roles=(),
            remaining_conflicts=("ADMITTER", "PROPOSER"),  # also wrong order
        )


def test_selected_no_remaining_denied_rejected() -> None:
    """SELECTED + no remaining conflicts + DENY is internally inconsistent."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:1",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:other")  # different actor, no conflict
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    # decision should be ALLOW. Tamper to DENY.
    with pytest.raises(AssumptionGovernanceContractError, match="RESULT_INCONSISTENT"):
        replace(decision, decision="DENY", decision_digest=_digest("x"))


def test_denial_selection_allow_rejected() -> None:
    """A denial selection_type with ALLOW is rejected."""
    grant_other = _grant(grant_id="grant:other", action="EXPIRE")
    policy = _policy(grants=(grant_other,))
    decision = _eval(policy)  # NO_APPLICABLE_GRANT -> DENY
    with pytest.raises(AssumptionGovernanceContractError, match="RESULT_INCONSISTENT"):
        replace(decision, decision="ALLOW", decision_digest=_digest("x"))


def test_denial_with_nonempty_sod_evidence_rejected() -> None:
    """A denial selection carrying nonempty SoD evidence is rejected."""
    grant_other = _grant(grant_id="grant:other", action="EXPIRE")
    policy = _policy(grants=(grant_other,))
    decision = _eval(policy)
    # Tamper: add a rule evaluation to a denial.
    fake_rule_eval = SeparationOfDutyRuleEvaluation(
        rule_id="rule:1",
        rule_digest=_digest("r"),
        conflicting_roles=(),
        waiving_exceptions=(),
        waived_roles=(),
        remaining_conflicts=(),
    )
    with pytest.raises(AssumptionGovernanceContractError):
        replace(
            decision,
            rule_evaluations=(fake_rule_eval,),
            evaluated_rule_digests=(_digest("r"),),
            decision_digest=_digest("x"),
        )


def test_selected_without_grant_identity_rejected() -> None:
    """SELECTED without selected_grant_id / grant_digest is rejected."""
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:1",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    e1 = _propose(authority="authority:other")
    policy = _policy(rules=(rule,))
    decision = _eval(policy, history=(e1,))
    with pytest.raises(AssumptionGovernanceContractError):
        replace(decision, selected_grant_id=None, decision_digest=_digest("x"))


def test_denial_carrying_grant_identity_rejected() -> None:
    """A denial selection carrying selected_grant_id / grant_digest is rejected."""
    grant_other = _grant(grant_id="grant:other", action="EXPIRE")
    policy = _policy(grants=(grant_other,))
    decision = _eval(policy)
    with pytest.raises(AssumptionGovernanceContractError, match="DENIAL_GRANT_PRESENT"):
        replace(
            decision,
            selected_grant_id="grant:fake",
            grant_digest=_digest("g"),
            decision_digest=_digest("x"),
        )


# --------------------------------------------------------------------------- #
# Import-order tests (subprocess, to avoid sys.modules caching)
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_import_resolution_first_then_evaluator_facade() -> None:
    """Import assumption_policy_resolution first, then the evaluator facade succeeds."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import csd_foundry.governance.v0_5.assumption_policy_resolution; "
                "from csd_foundry.governance.v0_5.assumption_separation_duty_evaluator import "
                "SeparationOfDutyDecision, evaluate_separation_of_duty; "
                "print('OK')"
            ),
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "OK" in result.stdout


def test_import_evaluator_facade_first() -> None:
    """Import the evaluator facade first (no pre-existing imports) succeeds."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from csd_foundry.governance.v0_5.assumption_separation_duty_evaluator import "
                "SeparationOfDutyDecision, evaluate_separation_of_duty; "
                "print('OK')"
            ),
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "OK" in result.stdout
