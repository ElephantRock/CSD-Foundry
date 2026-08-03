"""Frozen structural and challenge-derived rules for v0.5-D3.2-A1."""

from __future__ import annotations

from typing import Any, cast

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION,
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionPolicyLedgerEntryV2,
)
from csd_foundry.governance.v0_5.assumption import Assumption
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    GLOBAL_ASSUMPTION_SCOPE,
    RESOLUTION_AUTHORITY_ACTIONS,
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent


def validate_activatable_commit_version(value: dict[str, Any]) -> None:
    version = value.get("schema_version")
    if version != AUTHORITY_POLICY_COMMIT_V2_SCHEMA_VERSION:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE"
        )


def validate_policy_overlap(policy: AssumptionAuthorityPolicy) -> None:
    for index, left in enumerate(policy.grants):
        for right in policy.grants[index + 1 :]:
            if grants_overlap(left, right):
                pair = ",".join(sorted((left.grant_id, right.grant_id)))
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_AUTHORITY_GRANT_OVERLAP",
                    pair,
                )


def grants_overlap(
    left: AssumptionAuthorityGrant,
    right: AssumptionAuthorityGrant,
) -> bool:
    if left.authority_id != right.authority_id:
        return False
    if left.action != right.action:
        return False
    if not _intervals_overlap(
        left.effective_from_sequence,
        left.effective_until_sequence,
        right.effective_from_sequence,
        right.effective_until_sequence,
    ):
        return False
    if not _scopes_intersect(left.scope_ids, right.scope_ids):
        return False
    materialities = set(left.assumption_materialities)
    if not materialities.intersection(right.assumption_materialities):
        return False
    if left.action not in RESOLUTION_AUTHORITY_ACTIONS:
        return True
    challenge_materialities = set(left.challenge_materialities)
    return bool(
        challenge_materialities.intersection(right.challenge_materialities)
    )


def derive_resolution_challenge_materialities(
    assumption: Assumption,
    candidate_event: RegistryEvent,
    classification_policy: AssumptionChallengeClassificationPolicy,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    value = candidate_event.to_json_value()
    if value.get("entity_id") != assumption.assumption_id:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_IDENTITY_MISMATCH"
        )
    predecessor = value.get("previous_entity_event_digest")
    if predecessor != assumption.current_event_digest:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_HEAD_MISMATCH"
        )
    payload = cast(dict[str, Any], value.get("payload"))
    if payload.get("operation") != "RESOLVE_CHALLENGES":
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_OPERATION_INVALID"
        )
    raw_ids = payload.get("resolved_challenge_ids")
    if type(raw_ids) is not list or not raw_ids:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLVED_CHALLENGES_INVALID"
        )
    resolved_ids = tuple(sorted(cast(list[str], raw_ids)))
    if len(set(resolved_ids)) != len(resolved_ids):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLVED_CHALLENGES_INVALID"
        )
    current = {
        challenge.challenge_id: challenge
        for challenge in assumption.active_challenges
    }
    unknown = sorted(set(resolved_ids).difference(current))
    if unknown:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN",
            unknown[0],
        )
    materialities = tuple(
        sorted(
            classification_policy.classify(current[item].reason_code)
            for item in resolved_ids
        )
    )
    return resolved_ids, materialities


def validate_entry_position_sequence(
    head: AssumptionPolicyLedgerEntryV2,
    candidate: AssumptionPolicyLedgerEntryV2,
) -> None:
    predecessor_matches = (
        candidate.policy_commit.predecessor_policy_digest
        == head.policy.policy_digest
        and candidate.policy_commit.predecessor_commit_receipt_digest
        == head.policy_commit.commit_receipt_digest
    )
    if not predecessor_matches:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_CHAIN_FORK"
        )
    if (
        candidate.policy_commit.effective_from_sequence
        <= head.policy_commit.effective_from_sequence
    ):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING"
        )


def _intervals_overlap(
    left_start: int,
    left_end: int | None,
    right_start: int,
    right_end: int | None,
) -> bool:
    left_limit = float("inf") if left_end is None else left_end
    right_limit = float("inf") if right_end is None else right_end
    return left_start < right_limit and right_start < left_limit


def _scopes_intersect(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    if GLOBAL_ASSUMPTION_SCOPE in left:
        return True
    if GLOBAL_ASSUMPTION_SCOPE in right:
        return True
    return bool(set(left).intersection(right))
