"""Tests for v0.5-D3.2-A1.3-C historical V3 policy resolution and grant selection.

Validates the read-path half of A1 activation against the non-circular V3
signing envelope:

* :func:`resolve_policy_at_v3` -- half-open ``[s_i, s_{i+1})`` historical
  resolution, future isolation, V3-only typing, strict sequence typing,
  byte-identical repeated calls, and stability of the resolved policy
  generation across later appends;
* :func:`select_applicable_grant_v3` -- exact grant selection over every
  applicability dimension (action, authority, scope, materialities, effective
  interval) with deterministic fail-closed zero/one/multiple outcomes;
* :func:`resolve_policy_and_select_grant` -- composite reconstruction order;
* :meth:`FilesystemAssumptionPolicyPublisher.resolve_at` -- read-only lock
  scope, restart reconstruction, non-mutation proof, and interprocess
  reader/publisher serialization.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import queue as queue_module
import time
from pathlib import Path

import pytest

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
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
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    GLOBAL_ASSUMPTION_SCOPE,
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
    FilesystemAssumptionPolicyPublisher,
    PolicyStoreError,
)
from csd_foundry.governance.v0_5.assumption_policy_resolution import (
    DECISION_TYPES,
    ResolvedPolicyAtSequence,
    resolve_policy_and_select_grant,
    resolve_policy_at_v3,
    select_applicable_grant_v3,
)

_ALGO = "ed25519"
_VP = "ed25519-rfc8032-strict/1"
_SCOPE = "ASSUMPTION_POLICY_APPROVAL"


def _digest(c: str) -> str:
    return "sha256:" + c * 64


def _digest_for(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"pkd\0" + b).hexdigest()


# ---------------------------------------------------------------------------
# Shared frozen fixtures (identical pattern to the publication tests)
# ---------------------------------------------------------------------------


def _approval_policy() -> AssumptionPolicyApprovalPolicy:
    standard = AssumptionPolicyApprovalRule.build(
        approval_class="STANDARD",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=1,
        required_signer_ids=("authority:a",),
    )
    duty = AssumptionPolicyApprovalRule.build(
        approval_class="DUTY_EXCEPTION",
        eligible_signer_ids=("authority:a", "authority:b", "authority:c"),
        required_signature_count=2,
        required_signer_ids=("authority:a", "authority:b"),
    )
    return AssumptionPolicyApprovalPolicy.build(
        approval_policy_id="approval:1",
        authority_root_digest=_digest("a"),
        rules=(standard, duty),
    )


def _sig_profile() -> AssumptionPolicySignatureProfile:
    return AssumptionPolicySignatureProfile.build(
        algorithm_profiles=(
            AssumptionPolicyAlgorithmProfile(algorithm=_ALGO, verification_profile=_VP),
        ),
        required_authority_scope=_SCOPE,
        key_authority_root_digest=_digest("a"),
    )


def _chal_policy() -> AssumptionChallengeClassificationPolicy:
    return AssumptionChallengeClassificationPolicy.build(
        reason_rules=(
            AssumptionChallengeClassificationRule(
                reason_code="PROVENANCE_CONFLICT", materiality="MATERIAL"
            ),
        )
    )


def _grant(
    gid: str = "grant:1",
    *,
    action: str = "ADMIT",
    authority_id: str = "authority:operator",
    scope_ids: tuple[str, ...] = ("scope:control",),
    assumption_materialities: tuple[str, ...] = ("MATERIAL",),
    challenge_materialities: tuple[str, ...] = (),
    effective_from_sequence: int = 1,
    effective_until_sequence: int | None = None,
) -> AssumptionAuthorityGrant:
    return AssumptionAuthorityGrant.build(
        grant_id=gid,
        action=action,
        authority_id=authority_id,
        scope_ids=scope_ids,
        assumption_materialities=assumption_materialities,
        challenge_materialities=challenge_materialities,
        effective_from_sequence=effective_from_sequence,
        effective_until_sequence=effective_until_sequence,
    )


def _policy(
    grants: tuple[AssumptionAuthorityGrant, ...] | None = None,
) -> AssumptionAuthorityPolicy:
    return AssumptionAuthorityPolicy.build(
        policy_id="policy:1",
        authority_root_digest=_digest("a"),
        grants=grants or (_grant(),),
    )


def _payload(
    policy: AssumptionAuthorityPolicy | None = None,
    seq: int = 10,
    pred_policy: str | None = None,
    pred_commit: str | None = None,
) -> AssumptionPolicySigningPayload:
    return AssumptionPolicySigningPayload.build(
        policy=policy or _policy(),
        predecessor_policy_digest=pred_policy,
        predecessor_commit_receipt_digest=pred_commit,
        effective_from_sequence=seq,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_policy=_chal_policy(),
    )


def _commit(payload: AssumptionPolicySigningPayload, ssd: str) -> AssumptionAuthorityPolicyCommitV3:
    return AssumptionAuthorityPolicyCommitV3.build(
        signing_payload_digest=payload.signing_payload_digest,
        signature_set_digest=ssd,
    )


def _proof(
    payload: AssumptionPolicySigningPayload,
    commit: AssumptionAuthorityPolicyCommitV3,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
) -> AssumptionPolicyActivationProofV2:
    rule = _approval_policy().rule_for(payload.approval_class)
    return AssumptionPolicyActivationProofV2.build(
        signing_payload_digest=payload.signing_payload_digest,
        policy_commit_receipt_digest=commit.commit_receipt_digest,
        approval_policy_digest=_approval_policy().approval_policy_digest,
        approval_rule_digest=rule.rule_digest,
        signature_profile_digest=_sig_profile().profile_digest,
        challenge_classification_policy_digest=_chal_policy().policy_digest,
        authority_root_digest=payload.authority_root_digest,
        signature_set_digest=commit.signature_set_digest,
        valid_signer_ids=signers,
    )


def _entry(
    *,
    policy: AssumptionAuthorityPolicy | None = None,
    seq: int = 10,
    pred_policy: str | None = None,
    pred_commit: str | None = None,
    signers: tuple[str, ...] = ("authority:a", "authority:b"),
    ssd: str = "b",
) -> AssumptionPolicyLedgerEntryV3:
    selected_policy = policy or _policy()
    p = _payload(
        policy=selected_policy,
        seq=seq,
        pred_policy=pred_policy,
        pred_commit=pred_commit,
    )
    c = _commit(p, _digest(ssd))
    return AssumptionPolicyLedgerEntryV3.build(
        policy=selected_policy,
        signing_payload=p,
        policy_commit=c,
        approval_policy=_approval_policy(),
        signature_profile=_sig_profile(),
        challenge_classification_policy=_chal_policy(),
        activation_proof=_proof(p, c, signers),
    )


def _successor_entry(
    predecessor: AssumptionPolicyLedgerEntryV3, seq: int = 20
) -> AssumptionPolicyLedgerEntryV3:
    return _entry(
        seq=seq,
        pred_policy=predecessor.signing_payload.policy_digest,
        pred_commit=predecessor.policy_commit.commit_receipt_digest,
        ssd="c",
    )


def _ledger(*entries: AssumptionPolicyLedgerEntryV3) -> AssumptionPolicyLedgerV3:
    return AssumptionPolicyLedgerV3.build(tuple(entries))


def _policy_with_grants(*grants: AssumptionAuthorityGrant) -> AssumptionAuthorityPolicy:
    return _policy(grants=grants)


def _entry_with_policy(
    grants: tuple[AssumptionAuthorityGrant, ...],
    *,
    seq: int = 10,
    pred_policy: str | None = None,
    pred_commit: str | None = None,
) -> AssumptionPolicyLedgerEntryV3:
    return _entry(
        policy=_policy_with_grants(*grants),
        seq=seq,
        pred_policy=pred_policy,
        pred_commit=pred_commit,
    )


# ===========================================================================
# Part 1: Historical resolution (resolve_policy_at_v3)
# ===========================================================================


def test_decision_type_constants_are_the_fail_closed_triple() -> None:
    """The decision-type enumeration is exactly the three fail-closed outcomes."""

    assert DECISION_TYPES == ("SELECTED", "NO_APPLICABLE_GRANT", "AMBIGUOUS_GRANTS")


def test_empty_ledger_is_not_active() -> None:
    """An empty V3 ledger has no genesis; every query precedes genesis."""

    ledger = AssumptionPolicyLedgerV3.build(())
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(ledger, 0)
    assert failure.value.code == "ASSUMPTION_POLICY_NOT_ACTIVE"


def test_before_genesis_is_not_active() -> None:
    """A query strictly below the genesis effective_from_sequence is not active."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(ledger, 9)
    assert failure.value.code == "ASSUMPTION_POLICY_NOT_ACTIVE"


def test_exact_genesis_boundary_returns_genesis() -> None:
    """At the exact genesis effective_from_sequence the genesis policy is active.

    The half-open interval ``[s_0, s_1)`` is closed on the left, so ``s_0``
    itself resolves to the genesis entry.
    """

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 10)
    assert resolved.effective_from_sequence == 10
    assert resolved.ledger_entry_digest == e0.ledger_entry_digest


def test_between_activations_returns_preceding() -> None:
    """Strictly between two activations the preceding policy governs."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    ledger = _ledger(e0, e1)
    resolved = resolve_policy_at_v3(ledger, 15)
    assert resolved.ledger_entry_digest == e0.ledger_entry_digest


def test_exact_second_boundary_returns_second() -> None:
    """At the exact second activation boundary the new policy is active."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    ledger = _ledger(e0, e1)
    resolved = resolve_policy_at_v3(ledger, 20)
    assert resolved.ledger_entry_digest == e1.ledger_entry_digest


def test_after_latest_returns_latest() -> None:
    """A query at or above the latest effective_from_sequence returns the latest."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    ledger = _ledger(e0, e1)
    resolved = resolve_policy_at_v3(ledger, 10_000)
    assert resolved.ledger_entry_digest == e1.ledger_entry_digest


def test_three_policy_chain_future_isolation() -> None:
    """A 3-policy chain isolates each half-open interval; future entries do
    not affect an earlier query's resolved policy generation."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    e2 = _successor_entry(e1, seq=30)
    ledger = _ledger(e0, e1, e2)
    # Each interval resolves to its own generation.
    assert resolve_policy_at_v3(ledger, 10).ledger_entry_digest == e0.ledger_entry_digest
    assert resolve_policy_at_v3(ledger, 19).ledger_entry_digest == e0.ledger_entry_digest
    assert resolve_policy_at_v3(ledger, 20).ledger_entry_digest == e1.ledger_entry_digest
    assert resolve_policy_at_v3(ledger, 29).ledger_entry_digest == e1.ledger_entry_digest
    assert resolve_policy_at_v3(ledger, 30).ledger_entry_digest == e2.ledger_entry_digest
    assert resolve_policy_at_v3(ledger, 999).ledger_entry_digest == e2.ledger_entry_digest


def test_resolved_generation_unchanged_after_later_append() -> None:
    """Appending a later entry does not change an earlier query's resolved
    policy generation. The generation bindings (policy_id, policy_digest,
    effective_from_sequence, signing_payload_digest, commit_receipt_digest,
    ledger_entry_digest) are identical before and after the append.

    The ``ledger_root_digest`` and ``resolution_digest`` legitimately differ:
    they bind the ledger observed at resolution time, which grows on append.
    The future-isolation guarantee is about the resolved policy generation,
    not the enclosing ledger root.
    """

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    e2 = _successor_entry(e1, seq=30)

    ledger_before = _ledger(e0, e1)
    ledger_after = _ledger(e0, e1, e2)

    resolved_before = resolve_policy_at_v3(ledger_before, 15)
    resolved_after = resolve_policy_at_v3(ledger_after, 15)

    generation_fields = (
        "policy_id",
        "policy_digest",
        "effective_from_sequence",
        "signing_payload_digest",
        "commit_receipt_digest",
        "ledger_entry_digest",
    )
    for field in generation_fields:
        assert getattr(resolved_before, field) == getattr(resolved_after, field), field
    # The enclosing ledger root grew; the resolution digest binds it.
    assert resolved_before.ledger_root_digest != resolved_after.ledger_root_digest
    assert resolved_before.resolution_digest != resolved_after.resolution_digest


def test_future_entry_does_not_affect_earlier_query() -> None:
    """A query at a sequence below a future activation resolves identically
    whether or not the future entry is present."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    e2 = _successor_entry(e1, seq=30)

    two_entry = _ledger(e0, e1)
    three_entry = _ledger(e0, e1, e2)

    # Query at 25 is governed by e1 in both ledgers.
    r_two = resolve_policy_at_v3(two_entry, 25)
    r_three = resolve_policy_at_v3(three_entry, 25)
    assert r_two.ledger_entry_digest == e1.ledger_entry_digest
    assert r_three.ledger_entry_digest == e1.ledger_entry_digest
    assert r_two.policy_digest == r_three.policy_digest


def test_nonnegative_int_sequence_validation() -> None:
    """A negative integer event_sequence is rejected with the stable code."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(ledger, -1)
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"


def test_bool_sequence_is_rejected() -> None:
    """A ``bool`` event_sequence is rejected even though bool subclasses int.

    A stored ``True`` must never masquerade as ``1``.
    """

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(ledger, True)  # type: ignore[arg-type]
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"
    with pytest.raises(AssumptionPolicyActivationContractError) as failure_false:
        resolve_policy_at_v3(ledger, False)  # type: ignore[arg-type]
    assert failure_false.value.code == "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"


def test_non_int_sequence_is_rejected() -> None:
    """A non-int event_sequence is rejected with the stable code."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(ledger, "10")  # type: ignore[arg-type]
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"


def test_v2_ledger_is_rejected() -> None:
    """A V2 ``AssumptionPolicyLedgerV2`` is rejected by the exact type check
    before any field is read, surfacing the stable governance code."""

    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionPolicyLedgerV2,
    )

    # Build a minimal valid V2 ledger via its canonical bytes round-trip is
    # heavy; instead construct an empty V2 ledger (it self-validates).
    v2 = AssumptionPolicyLedgerV2.build(())
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3(v2, 0)  # type: ignore[arg-type]
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE"


def test_foreign_object_is_rejected() -> None:
    """Any non-V3-ledger object is rejected with the stable code."""

    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        resolve_policy_at_v3("not-a-ledger", 0)  # type: ignore[arg-type]
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE"


def test_malformed_chain_is_fail_closed() -> None:
    """A ledger whose chain cannot be ordered fails closed at construction;
    resolution never observes a malformed chain because the ledger is
    self-validating."""

    e0 = _entry(seq=10)
    # Two genesis entries: the ledger constructor rejects this.
    e1_genesis = _entry(seq=20)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        AssumptionPolicyLedgerV3.build((e0, e1_genesis))
    # The code surfaces at construction, so resolution is never reached.
    assert failure.value.code == "ASSUMPTION_POLICY_LEDGER_V3_GENESIS_INVALID"


def test_resolved_policy_bindings_match_entry() -> None:
    """Every digest and id field on the resolved binding matches the entry."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    assert resolved.event_sequence == 15
    assert resolved.policy_id == e0.policy.policy_id
    assert resolved.policy_digest == e0.policy.policy_digest
    assert resolved.effective_from_sequence == e0.signing_payload.effective_from_sequence
    assert resolved.signing_payload_digest == e0.signing_payload.signing_payload_digest
    assert resolved.commit_receipt_digest == e0.policy_commit.commit_receipt_digest
    assert resolved.ledger_entry_digest == e0.ledger_entry_digest
    assert resolved.ledger_root_digest == ledger.ledger_root_digest
    # The grants carry-through matches the entry's grant set.
    assert resolved.grants == e0.policy.grants


def test_resolution_digest_is_self_validating() -> None:
    """The resolution_digest is a domain-separated self-digest; tampering with
    any field invalidates it."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    # Re-deriving the digest from the unsigned value must match.
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        domain_digest,
    )

    expected = domain_digest("ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", resolved._unsigned_value())
    assert resolved.resolution_digest == expected
    # Direct construction with a wrong digest is rejected.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        ResolvedPolicyAtSequence(
            event_sequence=15,
            policy_id=e0.policy.policy_id,
            policy_digest=e0.policy.policy_digest,
            effective_from_sequence=10,
            signing_payload_digest=e0.signing_payload.signing_payload_digest,
            commit_receipt_digest=e0.policy_commit.commit_receipt_digest,
            ledger_entry_digest=e0.ledger_entry_digest,
            ledger_root_digest=ledger.ledger_root_digest,
            resolution_digest=_digest("0"),  # wrong
        )
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_DIGEST_MISMATCH"


def test_byte_identical_repeated_calls() -> None:
    """Repeated resolution of the same (ledger, sequence) is byte-identical."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    ledger = _ledger(e0, e1)
    first = resolve_policy_at_v3(ledger, 15)
    second = resolve_policy_at_v3(ledger, 15)
    assert first is not second  # distinct objects
    assert first.canonical_bytes == second.canonical_bytes
    assert first.resolution_digest == second.resolution_digest


def test_resolution_walks_chain_in_reverse() -> None:
    """The resolver returns the latest entry whose effective_from_sequence is
    <= the query, proving the reverse-walk semantics."""

    e0 = _entry(seq=10)
    e1 = _successor_entry(e0, seq=20)
    e2 = _successor_entry(e1, seq=30)
    ledger = _ledger(e0, e1, e2)
    # Query at 25: the reverse walk skips e2 (30 > 25), finds e1 (20 <= 25).
    resolved = resolve_policy_at_v3(ledger, 25)
    assert resolved.effective_from_sequence == 20
    assert resolved.ledger_entry_digest == e1.ledger_entry_digest


# ===========================================================================
# Part 2: Grant selection (select_applicable_grant_v3)
# ===========================================================================


def _resolved_with_grants(
    grants: tuple[AssumptionAuthorityGrant, ...],
    *,
    effective_from: int = 10,
    event_sequence: int = 15,
) -> ResolvedPolicyAtSequence:
    """Build a resolved policy binding carrying a custom grant set."""

    entry = _entry_with_policy(grants, seq=effective_from)
    ledger = _ledger(entry)
    return resolve_policy_at_v3(ledger, event_sequence)


def test_exact_action_match_selects() -> None:
    """A grant whose action exactly matches the request is selected (other
    dimensions also matching)."""

    grant = _grant(action="ADMIT")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id


def test_action_mismatch_denies() -> None:
    """A grant whose action differs from the request is not applicable."""

    grant = _grant(action="ADMIT")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="REJECT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"
    assert decision.selected_grant_id is None


def test_authority_match_selects() -> None:
    """A grant whose authority_id matches is selected."""

    grant = _grant(authority_id="authority:operator")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_authority_mismatch_denies() -> None:
    """A grant whose authority_id differs is not applicable."""

    grant = _grant(authority_id="authority:operator")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:other",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_narrow_scope_match_selects() -> None:
    """A narrow grant whose scope set contains the request scope is selected."""

    grant = _grant(scope_ids=("scope:control",))
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_narrow_scope_mismatch_denies() -> None:
    """A narrow grant whose scope set does not contain the request scope denies."""

    grant = _grant(scope_ids=("scope:alpha",))
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:beta",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_global_scope_matches_narrow_request() -> None:
    """A global grant (``scope:*``) matches any narrow request scope."""

    grant = _grant(scope_ids=(GLOBAL_ASSUMPTION_SCOPE,))
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:anything-narrow",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_narrow_grant_does_not_match_global_request() -> None:
    """A narrow grant never matches a global request scope.

    ``scope:*`` as a request is rejected upstream as an invalid token-shape
    scope, but defense-in-depth: even if it reached the matcher, a narrow
    grant must not authorize a global request.
    """

    grant = _grant(scope_ids=("scope:control",))
    resolved = _resolved_with_grants((grant,))
    # scope:* is an invalid request scope and is rejected at the gate.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id=GLOBAL_ASSUMPTION_SCOPE,
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            event_sequence=15,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID"


def test_assumption_materiality_match_selects() -> None:
    """A grant whose assumption_materialities contains the request materiality."""

    grant = _grant(assumption_materialities=("MATERIAL",))
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_assumption_materiality_mismatch_denies() -> None:
    """A grant whose assumption_materialities does not contain the request."""

    grant = _grant(assumption_materialities=("ADVISORY",))
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_challenge_materiality_match_selects() -> None:
    """A resolution-action grant whose challenge_materialities matches."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("MATERIAL", "CRITICAL"),
    )
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality="CRITICAL",
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_challenge_materiality_mismatch_denies() -> None:
    """A resolution-action grant whose challenge_materialities does not match."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("ADVISORY",),
    )
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality="CRITICAL",
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_effective_lower_boundary_inclusive() -> None:
    """The grant's effective_from_sequence is inclusive: at exactly that
    sequence the grant is active."""

    grant = _grant(effective_from_sequence=15)
    resolved = _resolved_with_grants((grant,), effective_from=10, event_sequence=15)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"


def test_immediately_before_lower_boundary_denies() -> None:
    """One sequence before the grant's effective_from_sequence the grant is
    not yet active."""

    grant = _grant(effective_from_sequence=16)
    resolved = _resolved_with_grants((grant,), effective_from=10, event_sequence=15)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_upper_boundary_exclusive() -> None:
    """The grant's effective_until_sequence is exclusive: at exactly that
    sequence the grant has expired."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=20)
    resolved = _resolved_with_grants((grant,), effective_from=10, event_sequence=20)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=20,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_immediately_before_upper_boundary_selects() -> None:
    """One sequence before the grant's effective_until_sequence the grant is
    still active (half-open upper bound)."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=20)
    resolved = _resolved_with_grants((grant,), effective_from=10, event_sequence=19)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=19,
    )
    assert decision.decision_type == "SELECTED"


def test_unbounded_interval_selects_at_far_future() -> None:
    """A grant with effective_until_sequence=None never expires."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=None)
    resolved = _resolved_with_grants((grant,), effective_from=10, event_sequence=10_000)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=10_000,
    )
    assert decision.decision_type == "SELECTED"


def test_no_applicable_grant_returns_denial_decision() -> None:
    """Zero applicable grants yield a NO_APPLICABLE_GRANT denial (not an error)."""

    grant = _grant(action="ADMIT", authority_id="authority:operator")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="SUPERSEDE",  # no grant covers SUPERSEDE
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"
    assert decision.selected_grant_id is None
    assert decision.grant_digest is None


def test_multiple_matches_fail_closed() -> None:
    """Two applicable grants yield an AMBIGUOUS_GRANTS fail-closed denial."""

    # Two grants that both cover the same request. (The policy overlap
    # validator would normally reject this at construction for grants in the
    # same policy, but the resolution layer must still fail closed if it ever
    # observes two applicable grants.)
    grant_a = _grant(
        "grant:a",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL",),
    )
    grant_b = _grant(
        "grant:b",
        scope_ids=("scope:control",),
        assumption_materialities=("MATERIAL", "ADVISORY"),
    )
    # The grant set must be canonical (sorted by grant_id) for the policy to
    # construct; grant_a < grant_b lexicographically.
    resolved = _resolved_with_grants((grant_a, grant_b))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "AMBIGUOUS_GRANTS"
    assert decision.selected_grant_id is None


def test_grant_id_and_digest_bindings() -> None:
    """A SELECTED decision carries the exact grant_id and grant_digest."""

    grant = _grant("grant:unique")
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id
    assert decision.grant_digest == grant.grant_digest


def test_selection_digest_is_self_validating() -> None:
    """The selection_digest is a domain-separated self-digest."""

    grant = _grant()
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        domain_digest,
    )

    expected = domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", decision._unsigned_value())
    assert decision.selection_digest == expected


def test_historical_selection_not_current_head() -> None:
    """Grant selection against a historical (non-head) policy generation
    selects from that generation's grants, not the head's."""

    # Generation 0 (effective 10) has a grant for authority:legacy.
    legacy_grant = _grant(
        "grant:legacy", authority_id="authority:legacy", effective_from_sequence=10
    )
    e0 = _entry_with_policy((legacy_grant,), seq=10)
    # Generation 1 (effective 20) has a grant for authority:current.
    current_grant = _grant(
        "grant:current", authority_id="authority:current", effective_from_sequence=20
    )
    e1 = _successor_entry_with_policy(e0, (current_grant,), seq=20)
    ledger = _ledger(e0, e1)

    # Query at 15 (governed by generation 0): the legacy grant applies, the
    # current grant does not (it lives in a future generation).
    decision = resolve_policy_and_select_grant(
        ledger=ledger,
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:legacy",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == "grant:legacy"

    # The current authority has no grant in generation 0.
    decision_current = resolve_policy_and_select_grant(
        ledger=ledger,
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:current",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision_current.decision_type == "NO_APPLICABLE_GRANT"


def _successor_entry_with_policy(
    predecessor: AssumptionPolicyLedgerEntryV3,
    grants: tuple[AssumptionAuthorityGrant, ...],
    *,
    seq: int = 20,
) -> AssumptionPolicyLedgerEntryV3:
    return _entry_with_policy(
        grants,
        seq=seq,
        pred_policy=predecessor.signing_payload.policy_digest,
        pred_commit=predecessor.policy_commit.commit_receipt_digest,
    )


def test_deterministic_ordering_of_matched_grants() -> None:
    """The grant scan is deterministic because the policy's grant tuple is
    canonical (sorted by grant_id). The same request always selects the same
    single grant or yields the same ambiguity."""

    grant_m = _grant("grant:m", assumption_materialities=("MATERIAL",))
    grant_a = _grant("grant:a", assumption_materialities=("ADVISORY",))
    # The policy canonicalizes grants sorted by id: grant:a, grant:m.
    resolved = _resolved_with_grants((grant_m, grant_a))
    # A MATERIAL request matches only grant:m.
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == "grant:m"


def test_bad_action_raises_not_denies() -> None:
    """An unknown action raises a contract error, not a denial."""

    resolved = _resolved_with_grants((_grant(),))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="NOT_AN_ACTION",  # type: ignore[arg-type]
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            event_sequence=15,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_ACTION_INVALID"


def test_bad_assumption_materiality_raises() -> None:
    """An unknown assumption materiality raises a contract error."""

    resolved = _resolved_with_grants((_grant(),))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="NOT_A_MATERIALITY",  # type: ignore[arg-type]
            challenge_materiality=None,
            event_sequence=15,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_ASSUMPTION_MATERIALITY_INVALID"


def test_resolution_action_requires_challenge_materiality() -> None:
    """A resolution action without a challenge materiality raises."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("MATERIAL",),
    )
    resolved = _resolved_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="RESOLVE_TO_ADMITTED",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            event_sequence=15,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_REQUIRED"


def test_non_resolution_action_forbids_challenge_materiality() -> None:
    """A non-resolution action with a challenge materiality raises."""

    grant = _grant(action="ADMIT")
    resolved = _resolved_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality="MATERIAL",
            event_sequence=15,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_UNEXPECTED"


def test_negative_event_sequence_raises() -> None:
    """A negative event_sequence raises a contract error."""

    resolved = _resolved_with_grants((_grant(),))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            event_sequence=-1,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_SEQUENCE_INVALID"


def test_composite_resolve_and_select_order() -> None:
    """The composite resolves then selects from the resolved generation's grants."""

    grant = _grant()
    e0 = _entry_with_policy((grant,), seq=10)
    e1 = _successor_entry_with_policy(e0, (_grant("grant:other"),), seq=20)
    ledger = _ledger(e0, e1)
    decision = resolve_policy_and_select_grant(
        ledger=ledger,
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id
    # The decision carries the resolved generation-0 bindings.
    assert decision.ledger_entry_digest == e0.ledger_entry_digest


def test_decision_dataclass_is_frozen() -> None:
    """The GrantSelectionDecision dataclass is frozen."""

    grant = _grant()
    resolved = _resolved_with_grants((grant,))
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises
        decision.decision_type = "NO_APPLICABLE_GRANT"  # type: ignore[misc]


def test_resolved_policy_dataclass_is_frozen() -> None:
    """The ResolvedPolicyAtSequence dataclass is frozen."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    with pytest.raises(Exception):  # noqa: B017 - frozen dataclass raises
        resolved.event_sequence = 99  # type: ignore[misc]


# ===========================================================================
# Part 3: Filesystem / restart tests (FilesystemAssumptionPolicyPublisher.resolve_at)
# ===========================================================================


def _populate_store(pub: FilesystemAssumptionPolicyPublisher) -> AssumptionPolicyLedgerEntryV3:
    """Create and publish one entry to a fresh store; return the entry."""

    pub.create()
    state = pub.read_state()
    entry = _entry(seq=10)
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(entry)
    pub.publish(prepared=prepared, expected_state=state)
    return entry


def test_resolve_at_reconstructs_from_stored_bytes(tmp_path: Path) -> None:
    """resolve_at reconstructs the ledger from stored bytes and resolves."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    entry = _populate_store(pub)
    resolved = pub.resolve_at(15)
    assert resolved.ledger_entry_digest == entry.ledger_entry_digest
    assert resolved.effective_from_sequence == 10


def test_resolve_at_restart_resolution_from_stored_bytes(tmp_path: Path) -> None:
    """A fresh publisher process opening the same store resolves identically."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    entry = _populate_store(pub)
    resolved_before = pub.resolve_at(15)

    # Simulate a restart: a brand-new publisher object over the same root.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    resolved_after = pub2.resolve_at(15)
    assert resolved_before.canonical_bytes == resolved_after.canonical_bytes
    assert resolved_after.ledger_entry_digest == entry.ledger_entry_digest


def test_resolve_at_restart_grant_selection(tmp_path: Path) -> None:
    """A fresh publisher process can run grant selection after restart."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    grant = _grant()
    entry = _entry_with_policy((grant,), seq=10)
    pub.create()
    state = pub.read_state()
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(entry)
    pub.publish(prepared=prepared, expected_state=state)

    # Restart.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    resolved = pub2.resolve_at(15)
    decision = select_applicable_grant_v3(
        resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
        event_sequence=15,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id


def test_resolve_at_leaves_authoritative_bytes_unchanged(tmp_path: Path) -> None:
    """resolve_at performs no writes: the authoritative bytes are identical
    before and after."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store(pub)
    before = (tmp_path / "ledger.json").read_bytes()
    pub.resolve_at(15)
    pub.resolve_at(20)
    pub.resolve_at(10_000)
    after = (tmp_path / "ledger.json").read_bytes()
    assert before == after


def test_resolve_at_state_root_head_unchanged_after_denial(tmp_path: Path) -> None:
    """A denial (NO_APPLICABLE_GRANT or NOT_ACTIVE) leaves the store state,
    root, and head unchanged. A NOT_ACTIVE resolution still performs no writes."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store(pub)
    state_before = pub.read_state()
    bytes_before = (tmp_path / "ledger.json").read_bytes()

    # A before-genesis query raises NOT_ACTIVE but must not mutate the store.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        pub.resolve_at(5)
    assert failure.value.code == "ASSUMPTION_POLICY_NOT_ACTIVE"

    state_after = pub.read_state()
    bytes_after = (tmp_path / "ledger.json").read_bytes()
    assert state_before == state_after
    assert bytes_before == bytes_after


def test_resolve_at_creates_no_temp_files(tmp_path: Path) -> None:
    """Repeated read-only queries do not create managed temp files."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store(pub)
    # Snapshot the directory listing.
    files_before = {p.name for p in tmp_path.iterdir()}
    for seq in (10, 15, 20, 100, 10_000):
        pub.resolve_at(seq)
    files_after = {p.name for p in tmp_path.iterdir()}
    assert files_before == files_after
    # No managed temp file was created.
    assert not any(name.startswith(".policy-ledger.") for name in files_after)


def test_resolve_at_missing_store_raises(tmp_path: Path) -> None:
    """resolve_at on an uninitialized store raises BYTES_MISSING."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    with pytest.raises(PolicyStoreError) as failure:
        pub.resolve_at(15)
    assert failure.value.code == "ASSUMPTION_POLICY_STORED_BYTES_MISSING"


# ---------------------------------------------------------------------------
# Multiprocess reader/publisher serialization
# ---------------------------------------------------------------------------


def _mp_reader_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    barrier_arg: object,
    iterations: int,
) -> None:
    """Spawn-safe reader worker: resolves at several sequences after the barrier.

    Each resolution captures the observed ledger root so the parent can prove
    the reader saw a complete (old or new) snapshot, never a torn read. The
    outcome tuple is tagged ``("READER", label, payload)`` so the parent can
    distinguish reader outcomes from publisher outcomes (both use label
    ``"OK"`` on success).
    """

    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        AssumptionPolicyActivationContractError,
    )
    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        FilesystemAssumptionPolicyPublisher,
        PolicyStoreError,
    )

    pub = FilesystemAssumptionPolicyPublisher(Path(root))
    try:
        barrier_arg.wait()
    except Exception:  # noqa: BLE001
        result_queue.put(("READER", "BARRIER_ERROR", ""))
        return
    observed_roots: list[str] = []
    errors: list[str] = []
    for _ in range(iterations):
        try:
            resolved = pub.resolve_at(15)
            observed_roots.append(resolved.ledger_root_digest)
        except PolicyStoreError as exc:
            errors.append(f"STORE:{exc.code}")
        except AssumptionPolicyActivationContractError as exc:
            errors.append(f"CONTRACT:{exc.code}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"UNEXPECTED:{type(exc).__name__}")
    result_queue.put(("READER", "OK", (observed_roots, errors)))


def _mp_publisher_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    barrier_arg: object,
    successor_entry_bytes: bytes,
    expected_state_bytes: bytes,
) -> None:
    """Spawn-safe publisher worker: publishes one successor entry.

    The outcome tuple is tagged ``("PUBLISHER", label, payload)`` so the
    parent can distinguish it from the reader outcome.
    """

    import json  # noqa: PLC0415
    import pickle  # noqa: S403 - test-only, trusted parent payload

    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        AssumptionPolicyPublicationConflict,
        PreparedPolicyActivation,
    )
    from csd_foundry.governance.v0_5.assumption_policy_filesystem_publication import (
        FilesystemAssumptionPolicyPublisher,
        PolicyStoreError,
        parse_ledger_entry_v3,
    )

    entry = parse_ledger_entry_v3(json.loads(successor_entry_bytes))
    expected_state = pickle.loads(expected_state_bytes)  # noqa: S301 - trusted parent
    prepared = PreparedPolicyActivation.build(entry)
    pub = FilesystemAssumptionPolicyPublisher(Path(root))
    try:
        barrier_arg.wait()
    except Exception:  # noqa: BLE001
        result_queue.put(("PUBLISHER", "BARRIER_ERROR", ""))
        return
    try:
        result = pub.publish(prepared=prepared, expected_state=expected_state)
        result_queue.put(("PUBLISHER", "OK", (result.append_result, result.resulting_ledger_root)))
    except AssumptionPolicyPublicationConflict as exc:
        result_queue.put(("PUBLISHER", "PUBLICATION_CONFLICT", exc.code))
    except PolicyStoreError as exc:
        result_queue.put(("PUBLISHER", "STORE_ERROR", exc.code))
    except Exception as exc:  # noqa: BLE001
        result_queue.put(("PUBLISHER", "UNEXPECTED", type(exc).__name__))


def test_concurrent_reader_and_publisher_serialize(tmp_path: Path) -> None:
    """A reader process and a publisher process race against the same store.

    The strict publication lock serializes them: the reader observes either
    the complete old ledger (one entry, root R0) or the complete new ledger
    (two entries, root R1), never a torn read. Both processes must exit
    cleanly within a bounded join.
    """

    import pickle  # noqa: S403

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e0 = _populate_store(pub)
    state_before = pub.read_state()
    r0 = state_before.ledger_root_digest

    # Build a successor entry to publish.
    e1 = _successor_entry(e0, seq=20)
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(e1)
    e1_bytes = prepared.ledger_entry.canonical_bytes
    state_bytes = pickle.dumps(state_before)

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    reader = ctx.Process(
        target=_mp_reader_worker,
        args=(str(tmp_path), queue, barrier, 20),
    )
    publisher = ctx.Process(
        target=_mp_publisher_worker,
        args=(str(tmp_path), queue, barrier, e1_bytes, state_bytes),
    )
    reader.start()
    publisher.start()
    reader.join(timeout=60)
    publisher.join(timeout=60)
    assert reader.exitcode == 0, f"reader exited {reader.exitcode}"
    assert publisher.exitcode == 0, f"publisher exited {publisher.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(outcomes) < 2:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert len(outcomes) == 2, f"missing outcomes: {outcomes}"

    # Distinguish reader and publisher outcomes by the role tag (both use
    # label "OK" on success, so the tag is required).
    pub_outcomes = [o for o in outcomes if o[0] == "PUBLISHER"]
    read_outcomes = [o for o in outcomes if o[0] == "READER"]
    assert len(pub_outcomes) == 1, f"expected one publisher outcome: {outcomes}"
    assert len(read_outcomes) == 1, f"expected one reader outcome: {outcomes}"

    # The publisher must have committed (no concurrent contention from the
    # reader because the reader only resolves, which shares the same lock and
    # is therefore serialized).
    _role, pub_label, pub_payload = pub_outcomes[0]
    assert pub_label == "OK", f"publisher failed: {pub_label} {pub_payload}"
    append_result, resulting_root = pub_payload
    assert append_result == "COMMITTED"
    r1 = resulting_root
    assert r0 != r1  # the append changed the root

    # The reader observed only complete snapshots: every observed root is
    # either R0 (old) or R1 (new), never anything else, and no errors.
    _role, read_label, read_payload = read_outcomes[0]
    assert read_label == "OK", f"reader barrier error: {read_payload}"
    observed_roots, errors = read_payload
    assert errors == [], f"reader observed errors: {errors}"
    assert observed_roots, "reader observed no roots"
    for observed in observed_roots:
        assert observed in (r0, r1), f"torn read: {observed} not in ({r0}, {r1})"

    # The final on-disk state reflects the committed publication.
    final_state = pub.read_state()
    assert final_state.ledger_root_digest == r1


def test_reader_sees_complete_old_or_new_ledger(tmp_path: Path) -> None:
    """Even under repeated concurrent reads during a publish burst, every
    read sees a complete ledger (root matches a known committed state)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e0 = _populate_store(pub)
    known_roots = {pub.read_state().ledger_root_digest}

    # Publish several successors sequentially; readers run concurrently.
    entries = [_successor_entry(e0, seq=20)]
    for i in range(1, 3):
        entries.append(_successor_entry(entries[-1], seq=20 + 10 * i))

    ctx = mp.get_context("spawn")
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]

    # Single reader doing many reads.
    barrier = ctx.Barrier(1)
    reader = ctx.Process(
        target=_mp_reader_worker,
        args=(str(tmp_path), queue, barrier, 50),
    )
    reader.start()

    # Parent publishes sequentially while the reader runs.
    current_state = pub.read_state()
    for entry in entries:
        from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
            PreparedPolicyActivation,
        )

        prepared = PreparedPolicyActivation.build(entry)
        result = pub.publish(prepared=prepared, expected_state=current_state)
        known_roots.add(result.resulting_ledger_root)
        current_state = pub.read_state()

    reader.join(timeout=60)
    assert reader.exitcode == 0, f"reader exited {reader.exitcode}"

    outcomes: list[tuple] = []
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and not outcomes:
        try:
            outcomes.append(queue.get(timeout=1.0))
        except queue_module.Empty:
            break
    assert outcomes, "no reader outcome"
    role, label, payload = outcomes[0]
    assert role == "READER", f"unexpected role: {role}"
    assert label == "OK", f"reader failed: {label} {payload}"
    observed_roots, errors = payload
    assert errors == [], f"reader errors: {errors}"
    for observed in observed_roots:
        assert observed in known_roots, f"torn read: {observed} not in known roots"


def test_multiprocess_bounded_join(tmp_path: Path) -> None:
    """Reader and publisher processes join within a bounded timeout on a
    healthy store (no hang, no deadlock from lock contention)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    e0 = _populate_store(pub)
    state_before = pub.read_state()

    e1 = _successor_entry(e0, seq=20)
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(e1)
    import pickle  # noqa: S403

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(2)
    queue: mp.Queue = ctx.Queue()  # type: ignore[type-arg]
    reader = ctx.Process(
        target=_mp_reader_worker,
        args=(str(tmp_path), queue, barrier, 5),
    )
    publisher = ctx.Process(
        target=_mp_publisher_worker,
        args=(
            str(tmp_path),
            queue,
            barrier,
            prepared.ledger_entry.canonical_bytes,
            pickle.dumps(state_before),
        ),
    )
    reader.start()
    publisher.start()
    # Bounded joins: both must finish well within 60s on a healthy host.
    reader.join(timeout=60)
    publisher.join(timeout=60)
    assert reader.exitcode == 0
    assert publisher.exitcode == 0
    # Drain the queue so child resources are released.
    try:
        while True:
            queue.get_nowait()
    except queue_module.Empty:
        pass
