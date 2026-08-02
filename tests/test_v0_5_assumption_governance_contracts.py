from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    ASSUMPTION_AUTHORITY_ACTIONS,
    ASSUMPTION_EVALUATION_PHASES,
    GLOBAL_ASSUMPTION_SCOPE,
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionAuthorityPolicyCommit,
    AssumptionDutyException,
    AssumptionEvaluationWork,
    AssumptionGovernanceContractError,
    AssumptionResolutionAuthorityBinding,
    AssumptionSeparationDutyRule,
    DecisionAssumptionBinding,
    canonical_cycle_witness,
)


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _grant(
    *,
    grant_id: str = "grant:resolver",
    action: str = "RESOLVE_TO_CONFIRMED",
    authority_id: str = "authority:resolver",
    scopes: tuple[str, ...] = ("scope:control",),
    assumption_materialities: tuple[str, ...] = ("MATERIAL", "CRITICAL"),
    challenge_materialities: tuple[str, ...] = ("MATERIAL", "CRITICAL"),
) -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=grant_id,
        action=action,
        authority_id=authority_id,
        scope_ids=scopes,
        assumption_materialities=assumption_materialities,
        challenge_materialities=challenge_materialities,
        effective_from_sequence=10,
        effective_until_sequence=50,
    )


def _rule() -> AssumptionSeparationDutyRule:
    return AssumptionSeparationDutyRule.build(
        rule_id="rule:resolver-not-proposer",
        action="RESOLVE_TO_CONFIRMED",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL", "CRITICAL"),
    )


def _exception() -> AssumptionDutyException:
    return AssumptionDutyException.build(
        exception_id="exception:emergency",
        rule_id="rule:resolver-not-proposer",
        action="RESOLVE_TO_CONFIRMED",
        authority_id="authority:resolver",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=("assumption:17",),
        assumption_materialities=("CRITICAL",),
        reason_code="EMERGENCY_SINGLE_AUTHORITY",
        effective_from_sequence=20,
        effective_until_sequence=25,
    )


def _policy(*, with_exception: bool = True) -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumption-authority",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
        separation_duty_rules=(_rule(),),
        duty_exceptions=(_exception(),) if with_exception else (),
    )


def test_authority_grant_freezes_exact_semantics_and_bytes() -> None:
    first = _grant()
    second = _grant()

    assert first == second
    assert first.canonical_bytes == second.canonical_bytes
    assert first.action == "RESOLVE_TO_CONFIRMED"
    assert first.scope_ids == ("scope:control",)
    assert first.assumption_materialities == ("MATERIAL", "CRITICAL")
    assert first.challenge_materialities == ("MATERIAL", "CRITICAL")
    assert first.effective_from_sequence == 10
    assert first.effective_until_sequence == 50


def test_resolution_grant_requires_challenge_materialities() -> None:
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_REQUIRED",
    ):
        AssumptionAuthorityGrant.build(
            grant_id="grant:bad",
            action="RESOLVE_TO_CONFIRMED",
            authority_id="authority:resolver",
            scope_ids=("scope:control",),
            assumption_materialities=("MATERIAL",),
            effective_from_sequence=1,
        )


def test_nonresolution_grant_rejects_challenge_materialities() -> None:
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_AUTHORITY_GRANT_CHALLENGE_MATERIALITY_UNEXPECTED",
    ):
        AssumptionAuthorityGrant.build(
            grant_id="grant:bad",
            action="ADMIT",
            authority_id="authority:admitter",
            scope_ids=("scope:control",),
            assumption_materialities=("MATERIAL",),
            challenge_materialities=("MATERIAL",),
            effective_from_sequence=1,
        )


def test_global_scope_is_explicit_and_cannot_be_mixed() -> None:
    global_grant = _grant(scopes=(GLOBAL_ASSUMPTION_SCOPE,))
    assert global_grant.scope_ids == (GLOBAL_ASSUMPTION_SCOPE,)

    with pytest.raises(AssumptionGovernanceContractError):
        _grant(scopes=(GLOBAL_ASSUMPTION_SCOPE, "scope:control"))


def test_grant_digest_tampering_fails_closed() -> None:
    grant = _grant()
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_AUTHORITY_GRANT_DIGEST_MISMATCH",
    ):
        replace(grant, grant_digest=_digest("b"))


def test_policy_canonicalizes_sets_and_binds_exception_to_rule() -> None:
    admit = AssumptionAuthorityGrant.build(
        grant_id="grant:admit",
        action="ADMIT",
        authority_id="authority:admitter",
        scope_ids=("scope:control",),
        assumption_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        effective_from_sequence=1,
    )
    policy = AssumptionAuthorityPolicy.build(
        policy_id="policy:assumption-authority",
        authority_root_digest=_digest("a"),
        grants=(_grant(), admit),
        separation_duty_rules=(_rule(),),
        duty_exceptions=(_exception(),),
    )

    assert tuple(item.grant_id for item in policy.grants) == (
        "grant:admit",
        "grant:resolver",
    )
    assert policy.duty_exceptions[0].rule_id == policy.separation_duty_rules[0].rule_id
    assert policy.grant_set_digest.startswith("sha256:")
    assert policy.exception_set_digest.startswith("sha256:")


def test_exception_cannot_widen_rule_scope_roles_or_materiality() -> None:
    wider = AssumptionDutyException.build(
        exception_id="exception:wider",
        rule_id="rule:resolver-not-proposer",
        action="RESOLVE_TO_CONFIRMED",
        authority_id="authority:resolver",
        conflicting_roles=("ADMITTER", "PROPOSER"),
        scope_ids=(GLOBAL_ASSUMPTION_SCOPE,),
        assumption_ids=(),
        assumption_materialities=("ADVISORY", "MATERIAL", "CRITICAL"),
        reason_code="INVALID_WIDENING",
        effective_from_sequence=20,
        effective_until_sequence=25,
    )
    with pytest.raises(AssumptionGovernanceContractError):
        AssumptionAuthorityPolicy.build(
            policy_id="policy:bad",
            authority_root_digest=_digest("a"),
            grants=(_grant(),),
            separation_duty_rules=(_rule(),),
            duty_exceptions=(wider,),
        )


def test_policy_content_requires_separate_activation_commit() -> None:
    policy = _policy()
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=policy,
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=20,
        approval_policy_digest=_digest("c"),
        signature_set_digest=_digest("d"),
    )

    assert commit.policy_digest == policy.policy_digest
    assert commit.exception_set_digest == policy.exception_set_digest
    assert commit.commit_receipt_digest.startswith("sha256:")


def test_policy_commit_requires_complete_predecessor_pair() -> None:
    policy = _policy()
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_POLICY_COMMIT_PREDECESSOR_INCOMPLETE",
    ):
        AssumptionAuthorityPolicyCommit.build(
            policy=policy,
            predecessor_policy_digest=_digest("1"),
            predecessor_commit_receipt_digest=None,
            effective_from_sequence=20,
            approval_policy_digest=_digest("c"),
            signature_set_digest=_digest("d"),
        )


def test_decision_assumption_binding_replaces_opaque_context_digest() -> None:
    binding = DecisionAssumptionBinding.build(
        decision_id="decision:17",
        validated_event_digest=_digest("1"),
        semantic_projection_receipt_digest=_digest("2"),
        control_state_digest=_digest("3"),
        assumption_registry_root=_digest("4"),
        evidence_registry_root=_digest("5"),
        logical_clock_sequence=4209,
        required_assumption_ids=("assumption:b", "assumption:a"),
    )

    assert binding.required_assumption_ids == ("assumption:a", "assumption:b")
    assert binding.to_json_value()["semantic_projection_receipt_digest"] == _digest("2")
    assert binding.binding_digest.startswith("sha256:")


def test_normative_work_counts_exclude_representation_telemetry() -> None:
    work = AssumptionEvaluationWork.build(
        assumption_histories_reconstructed=3,
        assumption_events_replayed=9,
        authority_decisions_evaluated=9,
        unique_assumption_nodes_evaluated=3,
        assumption_dependency_edges_examined=2,
        evidence_dependency_references_evaluated=4,
        active_challenges_evaluated=2,
        separation_duty_rules_evaluated=3,
    )
    value = work.to_json_value()

    assert "canonical_input_bytes_examined" not in value
    assert "elapsed_time" not in value
    assert "cache_hits" not in value
    assert value["assumption_events_replayed"] == 9


def test_cycle_witness_rotates_smallest_identity_without_reversing_direction() -> None:
    assert canonical_cycle_witness(
        ("assumption:c", "assumption:a", "assumption:b", "assumption:c")
    ) == ("assumption:a", "assumption:b", "assumption:c", "assumption:a")


def test_cycle_witness_rejects_open_or_repeated_paths() -> None:
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_CYCLE_WITNESS_NOT_CLOSED",
    ):
        canonical_cycle_witness(("assumption:a", "assumption:b"))

    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_CYCLE_WITNESS_REPEATED_NODE",
    ):
        canonical_cycle_witness(("assumption:a", "assumption:b", "assumption:b", "assumption:a"))


def test_resolution_binding_preserves_unresolved_challenge_set() -> None:
    binding = AssumptionResolutionAuthorityBinding.build(
        assumption_id="assumption:17",
        action="RESOLVE_TO_ADMITTED",
        resolver_authority_id="authority:resolver",
        event_digest=_digest("1"),
        resolved_challenge_ids=("challenge:a",),
        pre_active_challenge_ids=("challenge:a", "challenge:b"),
        post_active_challenge_ids=("challenge:b",),
        policy_digest=_digest("2"),
        policy_commit_receipt_digest=_digest("3"),
        grant_id="grant:resolver",
        grant_digest=_digest("4"),
    )

    assert binding.resolved_challenge_ids == ("challenge:a",)
    assert binding.post_active_challenge_ids == ("challenge:b",)


def test_resolution_binding_rejects_suppression_of_unrelated_challenge() -> None:
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_RESOLUTION_BINDING_POST_SET_MISMATCH",
    ):
        AssumptionResolutionAuthorityBinding.build(
            assumption_id="assumption:17",
            action="RESOLVE_TO_ADMITTED",
            resolver_authority_id="authority:resolver",
            event_digest=_digest("1"),
            resolved_challenge_ids=("challenge:a",),
            pre_active_challenge_ids=("challenge:a", "challenge:b"),
            post_active_challenge_ids=(),
            policy_digest=_digest("2"),
            policy_commit_receipt_digest=_digest("3"),
            grant_id="grant:resolver",
            grant_digest=_digest("4"),
        )


def test_evaluation_phase_and_action_enums_are_frozen() -> None:
    assert ASSUMPTION_EVALUATION_PHASES == (
        "SELF_HISTORY",
        "ACTIVE_CHALLENGES",
        "ASSUMPTION_DEPENDENCIES",
        "EVIDENCE_DEPENDENCIES",
    )
    assert "RESOLVE_TO_ADMITTED" in ASSUMPTION_AUTHORITY_ACTIONS
    assert "RESOLVE_CHALLENGES" not in ASSUMPTION_AUTHORITY_ACTIONS
