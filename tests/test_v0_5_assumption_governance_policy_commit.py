from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionAuthorityPolicyCommit,
    AssumptionDutyException,
    AssumptionGovernanceContractError,
    AssumptionSeparationDutyRule,
)


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _grant(*, authority_id: str = "authority:resolver") -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=f"grant:{authority_id}",
        action="RESOLVE_TO_CONFIRMED",
        authority_id=authority_id,
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL", "CRITICAL"),
        challenge_materialities=("MATERIAL", "CRITICAL"),
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


def _exception(*, authority_id: str = "authority:resolver") -> AssumptionDutyException:
    return AssumptionDutyException.build(
        exception_id="exception:emergency",
        rule_id="rule:resolver-not-proposer",
        action="RESOLVE_TO_CONFIRMED",
        authority_id=authority_id,
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_ids=("assumption:17",),
        assumption_materialities=("CRITICAL",),
        reason_code="EMERGENCY_SINGLE_AUTHORITY",
        effective_from_sequence=20,
        effective_until_sequence=25,
    )


def _policy(*, with_exception: bool) -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:assumption-authority",
        authority_root_digest=_digest("a"),
        grants=(_grant(),),
        separation_duty_rules=(_rule(),),
        duty_exceptions=(_exception(),) if with_exception else (),
    )


def test_exception_policy_derives_stronger_approval_class() -> None:
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=_policy(with_exception=True),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=20,
        approval_policy_digest=_digest("b"),
        signature_set_digest=_digest("c"),
    )

    assert commit.exception_count == 1
    assert commit.approval_class == "DUTY_EXCEPTION"
    assert commit.to_json_value()["approval_class"] == "DUTY_EXCEPTION"


def test_policy_without_exceptions_uses_standard_approval_class() -> None:
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=_policy(with_exception=False),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=20,
        approval_policy_digest=_digest("b"),
        signature_set_digest=_digest("c"),
    )

    assert commit.exception_count == 0
    assert commit.approval_class == "STANDARD"


def test_exception_approval_class_cannot_be_downgraded() -> None:
    commit = AssumptionAuthorityPolicyCommit.build(
        policy=_policy(with_exception=True),
        predecessor_policy_digest=None,
        predecessor_commit_receipt_digest=None,
        effective_from_sequence=20,
        approval_policy_digest=_digest("b"),
        signature_set_digest=_digest("c"),
    )

    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_POLICY_COMMIT_APPROVAL_CLASS_DOWNGRADE",
    ):
        replace(commit, approval_class="STANDARD")


def test_exception_cannot_create_authority_without_matching_grant() -> None:
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ASSUMPTION_DUTY_EXCEPTION_GRANT_MISSING",
    ):
        AssumptionAuthorityPolicy.build(
            policy_id="policy:bad",
            authority_root_digest=_digest("a"),
            grants=(_grant(authority_id="authority:other"),),
            separation_duty_rules=(_rule(),),
            duty_exceptions=(_exception(authority_id="authority:resolver"),),
        )
