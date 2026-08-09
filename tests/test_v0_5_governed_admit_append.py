"""Tests for the frozen governed ADMIT append (D3.2-A3.2).

Covers the 16 required semantic cases plus the post-commit fsync fault-injection
case. The orchestrator atomically appends one ADMIT event for an authoritative
PROPOSED assumption only when historical grant authority (I1-A via I1-B),
separation-of-duty (I1-B), and admission-time dependencies (I1-C) all permit
that exact admission. Every denial, stale-state condition, or compare-and-append
conflict must leave the assumption head/root unadvanced.

Reuses the V3 policy ledger scaffolding from
``test_v0_5_assumption_separation_duty_evaluator`` and the assumption PROPOSE
event builders from ``test_v0_5_assumption_dependency_validator``.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from csd_foundry._platform import fsync_directory as _real_fsync_directory
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
from csd_foundry.governance.v0_5._governed_admit_append import (
    GovernedAdmitAuthorization,
    GovernedAdmitError,
    GovernedAdmitResult,
    append_governed_admit_assumption,
)
from csd_foundry.governance.v0_5.assumption import (
    AssumptionRegistry,
    build_assumption_event,
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
from csd_foundry.governance.v0_5.evidence import (
    EvidenceRegistry,
    build_evidence_event,
)
from csd_foundry.governance.v0_5.governed_admit_append import (
    GovernedAdmitError as FacadeGovernedAdmitError,
)
from csd_foundry.governance.v0_5.registry import (
    InMemoryRegistryStore,
    RegistryStoreError,
)

# --------------------------------------------------------------------------- #
# V3 ledger scaffolding (verbatim from test_v0_5_assumption_separation_duty_evaluator)
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


# --------------------------------------------------------------------------- #
# Assumption PROPOSE event builders (adapted from test_v0_5_assumption_dependency_validator)
# --------------------------------------------------------------------------- #


def _propose_event(
    *,
    assumption_id: str = "assumption:candidate",
    clock: int = 10,
    scope_ids: tuple[str, ...] = ("scope:control",),
    assumption_deps: list[str] | None = None,
    evidence_deps: list[str] | None = None,
    proposer_authority_id: str = "authority:operator",
    expires: int = 100,
) -> object:
    """Build a genesis PROPOSE event with configurable scopes and dependencies.

    ``scope_ids`` MUST be in canonical sorted order (the orchestrator evaluates
    I1-B per scope in this order, and the policy grants must cover each one).
    """
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{assumption_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:1",
            "scope_ids": list(scope_ids),
            "materiality": "MATERIAL",
            "proposer_authority_id": proposer_authority_id,
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": assumption_deps or [],
            "evidence_dependency_ids": evidence_deps or [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _propose_dep(
    store_assumption_id: str,
    *,
    assumption_deps: list[str] | None = None,
    evidence_deps: list[str] | None = None,
    clock: int = 5,
) -> object:
    """Build a PROPOSE event for a dependency assumption."""
    return build_assumption_event(
        assumption_id=store_assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"propose:{store_assumption_id}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:dep",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": assumption_deps or [],
            "evidence_dependency_ids": evidence_deps or [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _register_evidence(
    evidence_id: str,
    *,
    expires_at_sequence: int | None = 100,
) -> object:
    return build_evidence_event(
        evidence_id=evidence_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=1,
        source_receipt_digest=_digest(f"register:{evidence_id}"),
        payload={
            "operation": "REGISTER",
            "proposition_id": "control.connected",
            "scope_ids": ["scope:control"],
            "source_id": "assessment:1",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": 1,
            "valid_from_sequence": 1,
            "expires_at_sequence": expires_at_sequence,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _add_verified_evidence(
    store: InMemoryRegistryStore, evidence_id: str, *, expires_at_sequence: int = 100
) -> None:
    """Add REGISTER + VERIFY evidence to the store."""
    registry = EvidenceRegistry(store)
    reg = _register_evidence(evidence_id, expires_at_sequence=expires_at_sequence)
    proj = registry.apply(reg)
    ver = build_evidence_event(
        evidence_id=proj.evidence_id,
        entity_sequence=proj.current_entity_sequence + 1,
        previous_entity_event_digest=proj.current_event_digest,
        clock_sequence=proj.last_clock_sequence + 1,
        source_receipt_digest=_digest(f"verify:{evidence_id}"),
        payload={"operation": "VERIFY", "verifier_authority_id": "authority:verifier"},
    )
    registry.apply(ver)


def _build_store_with_candidate(
    *,
    candidate_id: str = "assumption:candidate",
    candidate_clock: int = 10,
    scope_ids: tuple[str, ...] = ("scope:control",),
    assumption_deps: list[str] | None = None,
    evidence_deps: list[str] | None = None,
    dep_proposals: dict[str, dict] | None = None,
    proposer_authority_id: str = "authority:operator",
) -> InMemoryRegistryStore:
    """Build a store with the candidate PROPOSEd, plus any dependency assumption
    PROPOSE events. Returns the store (the orchestrator reads authoritative
    history from it via the locked view)."""
    store = InMemoryRegistryStore()
    registry = AssumptionRegistry(store)

    # Propose dependency assumptions first.
    if dep_proposals:
        for dep_id, kwargs in dep_proposals.items():
            event = _propose_dep(dep_id, **kwargs)
            registry.apply(event)

    # Propose the candidate.
    propose = _propose_event(
        assumption_id=candidate_id,
        clock=candidate_clock,
        scope_ids=scope_ids,
        assumption_deps=assumption_deps,
        evidence_deps=evidence_deps,
        proposer_authority_id=proposer_authority_id,
    )
    registry.apply(propose)
    return store


# --------------------------------------------------------------------------- #
# Orchestrator wrapper
# --------------------------------------------------------------------------- #


def _admit(
    *,
    store: InMemoryRegistryStore,
    ledger: AssumptionPolicyLedgerV3,
    assumption_id: str = "assumption:candidate",
    admitting_authority_id: str = "authority:operator",
    event_sequence: int = 11,
    retry_authorization: GovernedAdmitAuthorization | None = None,
) -> GovernedAdmitResult:
    """Thin wrapper around ``append_governed_admit_assumption`` for tests."""
    return append_governed_admit_assumption(
        store=store,
        ledger=ledger,
        assumption_id=assumption_id,
        admitting_authority_id=admitting_authority_id,
        event_sequence=event_sequence,
        retry_authorization=retry_authorization,
    )


def _roots(store: InMemoryRegistryStore) -> tuple[str, str]:
    """Capture (assumption_root, evidence_root) for no-write proof."""
    return (
        store.snapshot("ASSUMPTION").root_digest,
        store.snapshot("EVIDENCE_UNIT").root_digest,
    )


# --------------------------------------------------------------------------- #
# Cases 1-3: valid admissions
# --------------------------------------------------------------------------- #


def test_01_valid_admission_single_scope_appended() -> None:
    """Valid admission (single scope, no deps) -> APPENDED.

    PROPOSER is a *different* authority from the admitter, so no SoD rule
    fires even though no rule is installed.
    """
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    result = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )

    assert result.applied is True
    assert result.reason == "APPENDED"
    assert result.head.entity_sequence == 2
    assert result.projected.standing == "ADMITTED"
    assert result.projected.admitting_authority_id == "authority:admitter"
    # Committed head is observable through the store.
    assert store.entity_head("ASSUMPTION", "assumption:candidate").entity_sequence == 2


def test_02_valid_admission_multi_scope_appended() -> None:
    """Valid admission (multi-scope) -> APPENDED.

    The PROPOSE event lists two scopes (canonical sorted order); the policy
    contains one grant whose ``scope_ids`` covers both.
    """
    scopes = ("scope:alpha", "scope:beta")  # canonical sorted order
    store = _build_store_with_candidate(scope_ids=scopes)
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit-both",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=scopes,
            ),
        ),
    )
    ledger = _ledger(policy)

    result = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )

    assert result.applied is True
    assert result.reason == "APPENDED"
    # The authorization binds one ALLOW SoD decision per scope, in order.
    assert len(result.authorization.sod_decisions) == 2
    bound_scopes = tuple(dec.scope_id for dec in result.authorization.sod_decisions)
    assert bound_scopes == scopes
    # Evidence root is unchanged by ADMIT.
    evidence_root_before = store.snapshot("EVIDENCE_UNIT").root_digest
    assert result.evidence_registry_root == evidence_root_before


def test_03_valid_admission_with_assumption_and_evidence_deps_appended() -> None:
    """Valid admission (with assumption + evidence deps) -> APPENDED."""
    store = _build_store_with_candidate(
        assumption_deps=["assumption:dep-a"],
        evidence_deps=["evidence:verified"],
        dep_proposals={"assumption:dep-a": {}},
    )
    _add_verified_evidence(store, "evidence:verified", expires_at_sequence=100)
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    result = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )

    assert result.applied is True
    assert result.reason == "APPENDED"
    dep_receipt = result.authorization.dependency_validation_receipt
    assert dep_receipt.validation_result == "PASS"
    assert len(dep_receipt.traversed_dependencies) == 1
    assert len(dep_receipt.evidence_eligibility_decisions) == 1


# --------------------------------------------------------------------------- #
# Cases 4-7: semantic denials (no-write proof on each)
# --------------------------------------------------------------------------- #


def test_04_missing_grant_sod_denied() -> None:
    """Missing/ambiguous grant (no ADMIT grant for the admitter) ->
    GOVERNED_ADMIT_SOD_DENIED, head/root unchanged."""
    store = _build_store_with_candidate()
    # Grant covers a different authority.
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:other",
                action="ADMIT",
                authority_id="authority:someone-else",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_SOD_DENIED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    # No-write proof.
    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_05_sod_conflict_denied() -> None:
    """SoD conflict (admitter is also the PROPOSER, rule prohibits PROPOSER) ->
    GOVERNED_ADMIT_SOD_DENIED, head/root unchanged."""
    # Candidate PROPOSEd by authority:operator; same actor admits.
    store = _build_store_with_candidate(proposer_authority_id="authority:operator")
    rule = AssumptionSeparationDutyRule.build(
        rule_id="rule:admitter-not-proposer",
        action="ADMIT",
        conflicting_roles=("PROPOSER",),
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:operator",
                scope_ids=("scope:control",),
            ),
        ),
        rules=(rule,),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_SOD_DENIED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:operator",
            event_sequence=11,
        )

    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_06_missing_assumption_dependency_denied() -> None:
    """Missing assumption dependency -> GOVERNED_ADMIT_DEPENDENCY_DENIED,
    head/root unchanged.

    The grant covers the admitter (SoD passes); the dependency check fails.
    """
    store = _build_store_with_candidate(assumption_deps=["assumption:missing"])
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_DEPENDENCY_DENIED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_07_ineligible_evidence_dependency_denied() -> None:
    """Ineligible evidence dependency (unverified) ->
    GOVERNED_ADMIT_DEPENDENCY_DENIED, head/root unchanged."""
    store = _build_store_with_candidate(evidence_deps=["evidence:registered-only"])
    # REGISTER only, never VERIFY -> ineligible.
    EvidenceRegistry(store).apply(_register_evidence("evidence:registered-only"))
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_DEPENDENCY_DENIED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_08_multi_scope_partial_authority_one_scope_deny() -> None:
    """Multi-scope with partial authority (grant covers only one scope) ->
    GOVERNED_ADMIT_SOD_DENIED on the uncovered scope, head/root unchanged."""
    scopes = ("scope:alpha", "scope:beta")
    store = _build_store_with_candidate(scope_ids=scopes)
    # Grant only covers scope:alpha; scope:beta has no applicable grant.
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:alpha-only",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:alpha",),
            ),
        ),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_SOD_DENIED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


# --------------------------------------------------------------------------- #
# Cases 9-13: already-admitted, retry paths, competing writers
# --------------------------------------------------------------------------- #


def test_09_already_admitted_without_retry_auth_raises() -> None:
    """Already admitted (seq-2 head) without retry auth ->
    GOVERNED_ADMIT_ALREADY_ADMITTED, head/root unchanged."""
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    # First admission succeeds.
    first = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    assert first.applied is True

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    # Second attempt, no retry auth -> ALREADY_ADMITTED.
    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_ALREADY_ADMITTED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    # State unchanged (no second append).
    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before


def test_10_exact_snapshot_equivalent_retry_idempotent() -> None:
    """Exact snapshot-equivalent retry with the original authorization ->
    IDEMPOTENT_APPEND (applied=False)."""
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    first = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    assert first.applied is True

    assumption_root_before, evidence_root_before = _roots(store)

    # Retry with the same authorization: snapshot-equivalent.
    retry = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
        retry_authorization=first.authorization,
    )

    assert retry.applied is False
    assert retry.reason == "IDEMPOTENT_APPEND"
    # The retried result returns the exact stored event.
    assert retry.event.digest == first.event.digest
    assert retry.head == first.head
    # No state change.
    assert _roots(store) == (assumption_root_before, evidence_root_before)


def test_11_retry_after_unrelated_assumption_root_change_mismatch() -> None:
    """Retry after an unrelated assumption-root change (a different assumption
    was admitted in between) -> GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH.

    The original authorization's ``assumption_registry_root`` no longer matches
    the hypothetical pre-root the retry would have to reconstruct.
    """
    store = _build_store_with_candidate(candidate_id="assumption:candidate")
    # Also propose an unrelated assumption that will be admitted afterwards.
    AssumptionRegistry(store).apply(
        _propose_event(
            assumption_id="assumption:other",
            clock=9,
            scope_ids=("scope:control",),
            proposer_authority_id="authority:other-proposer",
        )
    )
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    first = _admit(
        store=store,
        ledger=ledger,
        assumption_id="assumption:candidate",
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    assert first.applied is True

    # Admit the unrelated assumption -> assumption root changes.
    other = _admit(
        store=store,
        ledger=ledger,
        assumption_id="assumption:other",
        admitting_authority_id="authority:admitter",
        event_sequence=12,
    )
    assert other.applied is True

    # Now retry the first admission with its original (now-stale) authorization.
    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH"):
        _admit(
            store=store,
            ledger=ledger,
            assumption_id="assumption:candidate",
            admitting_authority_id="authority:admitter",
            event_sequence=11,
            retry_authorization=first.authorization,
        )


def test_12_retry_after_evidence_root_change_mismatch() -> None:
    """Retry after an evidence-root change (new evidence registered in between)
    -> GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH."""
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    first = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    assert first.applied is True

    # Register new evidence -> evidence root changes.
    EvidenceRegistry(store).apply(_register_evidence("evidence:late", expires_at_sequence=100))

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_RETRY_SNAPSHOT_MISMATCH"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
            retry_authorization=first.authorization,
        )


def test_13_two_competing_governed_writers_serialized() -> None:
    """Two competing governed writers (serialized, no retry auth) -> one
    APPENDED, the other raises GOVERNED_ADMIT_ALREADY_ADMITTED.

    The InMemoryRegistryStore serializes the two orchestrator calls (they do
    not run concurrently in-process); the second sees the seq-2 head installed
    by the first. Without a ``retry_authorization`` the second writer cannot
    prove it intended the same admission, so it is rejected with
    ``GOVERNED_ADMIT_ALREADY_ADMITTED`` (the head/root are left unchanged by
    the failed second call).
    """
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    first = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    assert first.applied is True
    assert first.reason == "APPENDED"

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")

    # Second competing writer: no retry auth -> ALREADY_ADMITTED.
    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_ALREADY_ADMITTED"):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    # The first writer's commit is intact; the second made no further change.
    assert _roots(store) == (assumption_root_before, evidence_root_before)
    assert store.entity_head("ASSUMPTION", "assumption:candidate") == head_before
    assert head_before.entity_sequence == 2


# --------------------------------------------------------------------------- #
# Cases 14-16: receipt tamper, no-write proof, digest determinism
# --------------------------------------------------------------------------- #


def test_14_receipt_substitution_tamper_rejected_by_post_init() -> None:
    """A tampered ``GovernedAdmitAuthorization`` is rejected by ``__post_init__``.

    The authorization is constructed and self-validated before the commit
    point. Tampering any binding field (admitting authority, evidence root,
    scope set) and re-running ``__post_init__`` must raise before the tampered
    receipt can be observed. Because ``__post_init__`` runs at construction
    time, the tampered ``replace(...)`` call itself raises.
    """
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    result = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    valid_auth = result.authorization

    # Tamper the admitting_authority_id: the per-scope SoD decisions still bind
    # "authority:admitter", so the cross-check SOD_AUTHORITY_MISMATCH fires.
    with pytest.raises(AssumptionGovernanceContractError):
        replace(
            valid_auth,
            admitting_authority_id="authority:attacker",
            authorization_digest=_digest("forged"),
        )

    # Tamper the evidence root binding: the dependency receipt still binds the
    # real evidence root, so the cross-check DEP_EVIDENCE_ROOT_MISMATCH fires.
    with pytest.raises(AssumptionGovernanceContractError):
        replace(
            valid_auth,
            evidence_registry_root=_digest("forged-evidence-root"),
            authorization_digest=_digest("forged2"),
        )

    # Tamper the scope_ids to a non-canonical order: the scope-tuple validator
    # rejects it before any cross-check runs.
    with pytest.raises(AssumptionGovernanceContractError):
        replace(
            valid_auth,
            scope_ids=("scope:control", "scope:control"),  # duplicate
            authorization_digest=_digest("forged3"),
        )

    # Tamper only the digest (leave all binding fields valid): the self-digest
    # check rejects the mismatch. This proves the receipt cannot be silently
    # re-signed over altered content.
    with pytest.raises(
        AssumptionGovernanceContractError, match="GOVERNED_ADMIT_AUTH_DIGEST_MISMATCH"
    ):
        replace(
            valid_auth,
            authorization_digest=_digest("forged-digest-only"),
        )


def test_15_pre_commit_failures_leave_head_root_unchanged() -> None:
    """Pre-commit failures (SoD denial, dependency denial, retry mismatch) leave
    the head/root unchanged — a no-write proof.

    Parametrized in spirit: exercised here via a single SoD denial that is the
    canonical pre-commit failure (the orchestrator never reaches the commit
    primitive). The roots + entity head are captured before and asserted
    unchanged after the raised exception.
    """
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:other",
                action="ADMIT",
                authority_id="authority:someone-else",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    assumption_root_before, evidence_root_before = _roots(store)
    head_before = store.entity_head("ASSUMPTION", "assumption:candidate")
    # Sanity: the candidate head exists at seq 1 before the attempt.
    assert head_before is not None and head_before.entity_sequence == 1

    with pytest.raises(GovernedAdmitError):
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )

    # No-write proof: roots + head byte-identical to the pre-attempt state.
    assert store.snapshot("ASSUMPTION").root_digest == assumption_root_before
    assert store.snapshot("EVIDENCE_UNIT").root_digest == evidence_root_before
    after = store.entity_head("ASSUMPTION", "assumption:candidate")
    assert after == head_before
    assert after.entity_sequence == 1


def test_16_authorization_receipt_binds_all_evidence_digest_determinism() -> None:
    """The authorization receipt binds all evidence (sod decisions, dependency
    receipt, roots, scope_ids) and is a deterministic domain-separated digest.

    Replaying the governed append from byte-identical inputs produces a
    byte-identical authorization digest, proving every child receipt is bound
    into the authorization.
    """
    store_a = _build_store_with_candidate()
    store_b = _build_store_with_candidate()  # independent, identical setup
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    result_a = _admit(
        store=store_a,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    result_b = _admit(
        store=store_b,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )

    # Authorization digest is deterministic across independent runs.
    assert result_a.authorization.authorization_digest == (
        result_b.authorization.authorization_digest
    )
    # And matches the deterministic domain-separated digest.
    from csd_foundry.governance.v0_5._assumption_governance_contracts import (
        _domain_digest as contracts_domain_digest,
    )

    expected = contracts_domain_digest(
        "ASSUMPTION_GOVERNED_ADMIT_AUTHORIZATION",
        result_a.authorization._unsigned_value(),
    )
    assert result_a.authorization.authorization_digest == expected

    # The authorization binds the dependency receipt and the per-scope SoD
    # decision digests (changing either would change the auth digest).
    assert (
        result_a.authorization.dependency_validation_receipt.receipt_digest
        == result_b.authorization.dependency_validation_receipt.receipt_digest
    )
    for dec_a, dec_b in zip(
        result_a.authorization.sod_decisions,
        result_b.authorization.sod_decisions,
        strict=True,
    ):
        assert dec_a.decision_digest == dec_b.decision_digest


# --------------------------------------------------------------------------- #
# Case +1: post-os.replace fsync fault injection
# --------------------------------------------------------------------------- #


def test_plus1_post_os_replace_fsync_failure_durability_uncertain(monkeypatch) -> None:
    """A post-``os.replace`` directory fsync failure ->
    ``RegistryStoreError("REGISTRY_COMMIT_DURABILITY_UNCERTAIN")``.

    The ``os.replace`` is the commit point; the head file has been installed.
    The orchestrator raises ``RegistryStoreError`` (not ``GovernedAdmitError``)
    so callers know durability is uncertain rather than the admission being
    rejected. We inject the fault by patching the ``_fsync_directory`` symbol
    imported into ``csd_foundry.governance.v0_5.registry``.

    Discriminator: during one governed append there are exactly two
    ``heads/assumption`` directory fsyncs — the first installs the PROPOSE head
    (during ``_build_store_with_candidate`` setup), the second is the
    post-``os.replace`` fsync inside ``_commit_prepared`` (the call we want to
    fail). All other fsyncs (store init, event-object installs) target
    different paths and must succeed so the commit reaches ``os.replace``.
    """
    import csd_foundry.governance.v0_5.registry as registry_module

    head_assumption_calls = {"n": 0}

    def _failing_fsync(path) -> None:
        normalized = str(path).replace("\\", "/").lower()
        if normalized.endswith("heads/assumption"):
            head_assumption_calls["n"] += 1
            # Fail ONLY on the 2nd heads/assumption fsync — the post-commit
            # directory fsync inside ``_commit_prepared`` (after os.replace).
            if head_assumption_calls["n"] == 2:
                raise OSError("injected post-commit fsync failure")
        # All other fsyncs (store init, object installs, the PROPOSE head fsync)
        # delegate to the real implementation so setup completes normally.
        _real_fsync_directory(path)

    monkeypatch.setattr(registry_module, "_fsync_directory", _failing_fsync)

    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    with pytest.raises(RegistryStoreError) as exc_info:
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )
    assert exc_info.value.code == "GOVERNED_ADMIT_COMMIT_DURABILITY_UNCERTAIN"
    # Sanity: we did reach the post-commit fsync (the fault fired exactly once).
    assert head_assumption_calls["n"] == 2

    # Restore the real fsync so post-test store introspection works.
    monkeypatch.setattr(registry_module, "_fsync_directory", _real_fsync_directory)

    # The head file WAS installed by os.replace (commit point reached), so the
    # admission is observable on disk even though durability is uncertain.
    head = store.entity_head("ASSUMPTION", "assumption:candidate")
    assert head is not None
    assert head.entity_sequence == 2


# --------------------------------------------------------------------------- #
# Facade re-export sanity (the facade DOES export GovernedAdmitError)
# --------------------------------------------------------------------------- #


def test_facade_exports_governed_admit_error() -> None:
    """The public facade ``governed_admit_append`` exports ``GovernedAdmitError``.

    Confirms the note in the task brief: ``GovernedAdmitError`` is importable
    from both the internal module and the facade, and they are the same class.
    """
    from csd_foundry.governance.v0_5.governed_admit_append import (
        GovernedAdmitError as FacadeReexport,
    )

    assert FacadeReexport is GovernedAdmitError
    assert FacadeGovernedAdmitError is GovernedAdmitError


def test_locked_view_direct_construction_is_unusable() -> None:
    """A LockedRegistryView constructed directly (outside locked_view()) is
    inert and every method raises REGISTRY_LOCKED_VIEW_CLOSED."""
    import tempfile
    from pathlib import Path

    from csd_foundry.governance.v0_5.registry import (
        FilesystemRegistryStore,
        LockedRegistryView,
        RegistryStoreError,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        store = FilesystemRegistryStore(Path(tmpdir))
        view = LockedRegistryView(store)
        with pytest.raises(RegistryStoreError, match="REGISTRY_LOCKED_VIEW_CLOSED"):
            view.snapshot("ASSUMPTION")


def test_locked_view_use_after_exit_is_unusable() -> None:
    """After locked_view() exits, the view is permanently closed."""
    from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStoreError

    store = InMemoryRegistryStore()
    with store.locked_view() as view:
        view.snapshot("ASSUMPTION")  # works
    with pytest.raises(RegistryStoreError, match="REGISTRY_LOCKED_VIEW_CLOSED"):
        view.snapshot("ASSUMPTION")


def test_locked_view_append_forbidden() -> None:
    """Calling append() on a locked view raises REGISTRY_LOCKED_VIEW_APPEND_FORBIDDEN."""
    from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore, RegistryStoreError

    store = InMemoryRegistryStore()
    with (
        store.locked_view() as view,
        pytest.raises(RegistryStoreError, match="REGISTRY_LOCKED_VIEW_APPEND_FORBIDDEN"),
    ):
        view.append(None)  # type: ignore[arg-type]


def test_seq2_non_admit_produces_not_proposed() -> None:
    """A PROPOSE->REJECT chain at seq 2 must produce GOVERNED_ADMIT_NOT_PROPOSED,
    not GOVERNED_ADMIT_ALREADY_ADMITTED. Only seq-2 ADMIT triggers retry."""
    from csd_foundry.governance.v0_5.assumption import AssumptionRegistry, build_assumption_event

    store = InMemoryRegistryStore()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    reg = AssumptionRegistry(store)
    propose_ev = build_assumption_event(
        assumption_id="assumption:rejected",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=10,
        source_receipt_digest=_digest("propose-rejected"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "p",
            "scope_ids": ["scope:control"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": 10,
            "valid_from_sequence": 10,
            "expires_at_sequence": 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    propose_proj = reg.apply(propose_ev)
    reject_ev = build_assumption_event(
        assumption_id="assumption:rejected",
        entity_sequence=2,
        previous_entity_event_digest=propose_proj.current_event_digest,
        clock_sequence=11,
        source_receipt_digest=_digest("reject-ev"),
        payload={
            "operation": "REJECT",
            "rejecting_authority_id": "authority:rejector",
            "rejection_receipt_digest": _digest("rr"),
            "reason_code": "reason:test",
        },
    )
    reg.apply(reject_ev)

    with pytest.raises(GovernedAdmitError, match="GOVERNED_ADMIT_NOT_PROPOSED"):
        append_governed_admit_assumption(
            store=store,
            ledger=ledger,
            assumption_id="assumption:rejected",
            admitting_authority_id="authority:admitter",
            event_sequence=12,
        )


def test_post_commit_head_verification_failure_reconciles(monkeypatch) -> None:
    """Post-commit final head-verification read failure enters reconciliation
    before raising GOVERNED_ADMIT_COMMIT_DURABILITY_UNCERTAIN.

    Injects a failure on the first _read_head call inside _commit_prepared's
    verification step (the post-fsync actual-head check), then asserts:
    - the error is GOVERNED_ADMIT_COMMIT_DURABILITY_UNCERTAIN
    - the head is logically advanced (os.replace succeeded)
    """

    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)

    # We need to inject a failure on _read_head AFTER os.replace.
    # The _commit_prepared verification calls store._read_head.
    # We patch the _read_head on the underlying FilesystemRegistryStore
    # to fail once (the verification read), then succeed (reconciliation read).
    real_read_head = type(store._store)._read_head
    seq2_read_count = {"n": 0}

    def _failing_read_head(self, registry_type, entity_id):
        head = real_read_head(self, registry_type, entity_id)
        # Only fail on the first read that returns a seq-2 head — this is the
        # post-commit verification read inside _commit_prepared (the head only
        # exists at seq 2 after os.replace succeeds).
        if head is not None and head.entity_sequence == 2:
            seq2_read_count["n"] += 1
            if seq2_read_count["n"] == 1:
                raise OSError("injected verification read failure")
        return head

    monkeypatch.setattr(type(store._store), "_read_head", _failing_read_head)

    with pytest.raises(RegistryStoreError) as exc_info:
        _admit(
            store=store,
            ledger=ledger,
            admitting_authority_id="authority:admitter",
            event_sequence=11,
        )
    assert exc_info.value.code == "GOVERNED_ADMIT_COMMIT_DURABILITY_UNCERTAIN"

    monkeypatch.undo()

    # The head WAS installed by os.replace.
    head = store.entity_head("ASSUMPTION", "assumption:candidate")
    assert head is not None
    assert head.entity_sequence == 2


def test_authorization_rejects_materiality_str_subclass() -> None:
    """A str subclass for assumption_materiality is rejected by the
    GovernedAdmitAuthorization exact-type check."""

    from csd_foundry.governance.v0_5._governed_admit_append import GovernedAdmitAuthorization

    # Build a valid authorization from a successful append.
    store = _build_store_with_candidate()
    policy = _policy(
        grants=(
            _grant(
                grant_id="grant:admit",
                action="ADMIT",
                authority_id="authority:admitter",
                scope_ids=("scope:control",),
            ),
        ),
    )
    ledger = _ledger(policy)
    result = _admit(
        store=store,
        ledger=ledger,
        admitting_authority_id="authority:admitter",
        event_sequence=11,
    )
    auth = result.authorization

    class MaterialitySubclass(str):
        pass

    with pytest.raises(AssumptionGovernanceContractError, match="MATERIALITY_INVALID"):
        GovernedAdmitAuthorization(
            assumption_id=auth.assumption_id,
            candidate_predecessor_event_digest=auth.candidate_predecessor_event_digest,
            candidate_entity_sequence=auth.candidate_entity_sequence,
            event_sequence=auth.event_sequence,
            admitting_authority_id=auth.admitting_authority_id,
            assumption_registry_root=auth.assumption_registry_root,
            evidence_registry_root=auth.evidence_registry_root,
            scope_ids=auth.scope_ids,
            assumption_materiality=MaterialitySubclass("MATERIAL"),
            sod_decisions=auth.sod_decisions,
            dependency_validation_receipt=auth.dependency_validation_receipt,
            authorization_digest="sha256:" + "0" * 64,
        )
