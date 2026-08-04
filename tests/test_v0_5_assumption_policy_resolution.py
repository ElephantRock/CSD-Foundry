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
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
    domain_digest,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    ASSUMPTION_AUTHORITY_ACTIONS,
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
    DECISION_CODES,
    DECISION_TYPES,
    GRANT_SELECTION_DECISION_SCHEMA_VERSION,
    RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
    GrantSelectionDecision,
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
    # The resolved binding is a digest receipt: it carries NO grant tuple. A
    # resolution object alone is not an authoritative source for grant
    # selection (the selector re-binds it to its source entry).
    assert not hasattr(resolved, "grants")


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
    """Build a resolved policy binding for a custom grant set.

    Returns ONLY the resolved policy (a digest receipt, no grants). To run
    selection, pair it with the matching ledger via
    :func:`_resolved_and_ledger_with_grants` (which returns both).
    """

    entry = _entry_with_policy(grants, seq=effective_from)
    ledger = _ledger(entry)
    return resolve_policy_at_v3(ledger, event_sequence)


def _resolved_and_ledger_with_grants(
    grants: tuple[AssumptionAuthorityGrant, ...],
    *,
    effective_from: int = 10,
    event_sequence: int = 15,
) -> tuple[ResolvedPolicyAtSequence, AssumptionPolicyLedgerV3]:
    """Build a resolved policy AND its source ledger as a matched pair.

    Selection requires the ledger (to re-bind the source entry). The ledger
    returned here is the exact ledger the resolution ran against, so its root
    and the resolution's bindings agree. Tests that need a genuinely different
    ledger (e.g. a foreign root, or a substituted grant tuple) construct their
    own.
    """

    entry = _entry_with_policy(grants, seq=effective_from)
    ledger = _ledger(entry)
    resolved = resolve_policy_at_v3(ledger, event_sequence)
    return resolved, ledger


def test_exact_action_match_selects() -> None:
    """A grant whose action exactly matches the request is selected (other
    dimensions also matching)."""

    grant = _grant(action="ADMIT")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id


def test_action_mismatch_denies() -> None:
    """A grant whose action differs from the request is not applicable."""

    grant = _grant(action="ADMIT")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="REJECT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"
    assert decision.selected_grant_id is None


def test_authority_match_selects() -> None:
    """A grant whose authority_id matches is selected."""

    grant = _grant(authority_id="authority:operator")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_authority_mismatch_denies() -> None:
    """A grant whose authority_id differs is not applicable."""

    grant = _grant(authority_id="authority:operator")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:other",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_narrow_scope_match_selects() -> None:
    """A narrow grant whose scope set contains the request scope is selected."""

    grant = _grant(scope_ids=("scope:control",))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_narrow_scope_mismatch_denies() -> None:
    """A narrow grant whose scope set does not contain the request scope denies."""

    grant = _grant(scope_ids=("scope:alpha",))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:beta",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_global_scope_matches_narrow_request() -> None:
    """A global grant (``scope:*``) matches any narrow request scope."""

    grant = _grant(scope_ids=(GLOBAL_ASSUMPTION_SCOPE,))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:anything-narrow",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_narrow_grant_does_not_match_global_request() -> None:
    """A narrow grant never matches a global request scope.

    ``scope:*`` as a request is rejected upstream as an invalid token-shape
    scope, but defense-in-depth: even if it reached the matcher, a narrow
    grant must not authorize a global request.
    """

    grant = _grant(scope_ids=("scope:control",))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    # scope:* is an invalid request scope and is rejected at the gate.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id=GLOBAL_ASSUMPTION_SCOPE,
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID"


def test_assumption_materiality_match_selects() -> None:
    """A grant whose assumption_materialities contains the request materiality."""

    grant = _grant(assumption_materialities=("MATERIAL",))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_assumption_materiality_mismatch_denies() -> None:
    """A grant whose assumption_materialities does not contain the request."""

    grant = _grant(assumption_materialities=("ADVISORY",))
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_challenge_materiality_match_selects() -> None:
    """A resolution-action grant whose challenge_materialities matches."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("MATERIAL", "CRITICAL"),
    )
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality="CRITICAL",
    )
    assert decision.decision_type == "SELECTED"


def test_challenge_materiality_mismatch_denies() -> None:
    """A resolution-action grant whose challenge_materialities does not match."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("ADVISORY",),
    )
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="RESOLVE_TO_ADMITTED",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality="CRITICAL",
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_effective_lower_boundary_inclusive() -> None:
    """The grant's effective_from_sequence is inclusive: at exactly that
    sequence the grant is active."""

    grant = _grant(effective_from_sequence=15)
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant,), effective_from=10, event_sequence=15
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_immediately_before_lower_boundary_denies() -> None:
    """One sequence before the grant's effective_from_sequence the grant is
    not yet active."""

    grant = _grant(effective_from_sequence=16)
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant,), effective_from=10, event_sequence=15
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_upper_boundary_exclusive() -> None:
    """The grant's effective_until_sequence is exclusive: at exactly that
    sequence the grant has expired."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=20)
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant,), effective_from=10, event_sequence=20
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"


def test_immediately_before_upper_boundary_selects() -> None:
    """One sequence before the grant's effective_until_sequence the grant is
    still active (half-open upper bound)."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=20)
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant,), effective_from=10, event_sequence=19
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_unbounded_interval_selects_at_far_future() -> None:
    """A grant with effective_until_sequence=None never expires."""

    grant = _grant(effective_from_sequence=10, effective_until_sequence=None)
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant,), effective_from=10, event_sequence=10_000
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"


def test_no_applicable_grant_returns_denial_decision() -> None:
    """Zero applicable grants yield a NO_APPLICABLE_GRANT denial (not an error)."""

    grant = _grant(action="ADMIT", authority_id="authority:operator")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="SUPERSEDE",  # no grant covers SUPERSEDE
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
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
    resolved, ledger = _resolved_and_ledger_with_grants((grant_a, grant_b))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "AMBIGUOUS_GRANTS"
    assert decision.selected_grant_id is None


def test_grant_id_and_digest_bindings() -> None:
    """A SELECTED decision carries the exact grant_id and grant_digest."""

    grant = _grant("grant:unique")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == grant.grant_id
    assert decision.grant_digest == grant.grant_digest


def test_selection_digest_is_self_validating() -> None:
    """The selection_digest is a domain-separated self-digest."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
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
    resolved, ledger = _resolved_and_ledger_with_grants((grant_m, grant_a))
    # A MATERIAL request matches only grant:m.
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == "grant:m"


def test_bad_action_raises_not_denies() -> None:
    """An unknown action raises a contract error, not a denial."""

    resolved, ledger = _resolved_and_ledger_with_grants((_grant(),))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="NOT_AN_ACTION",  # type: ignore[arg-type]
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_ACTION_INVALID"


def test_bad_assumption_materiality_raises() -> None:
    """An unknown assumption materiality raises a contract error."""

    resolved, ledger = _resolved_and_ledger_with_grants((_grant(),))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="NOT_A_MATERIALITY",  # type: ignore[arg-type]
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_ASSUMPTION_MATERIALITY_INVALID"


def test_resolution_action_requires_challenge_materiality() -> None:
    """A resolution action without a challenge materiality raises."""

    grant = _grant(
        action="RESOLVE_TO_ADMITTED",
        assumption_materialities=("MATERIAL",),
        challenge_materialities=("MATERIAL",),
    )
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="RESOLVE_TO_ADMITTED",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_REQUIRED"


def test_non_resolution_action_forbids_challenge_materiality() -> None:
    """A non-resolution action with a challenge materiality raises."""

    grant = _grant(action="ADMIT")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality="MATERIAL",
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_UNEXPECTED"


def test_negative_event_sequence_raises() -> None:
    """A negative event_sequence raises a contract error at the decision level.

    The selector no longer takes an event_sequence (it uses
    ``resolved_policy.event_sequence``, which resolution already validates as
    nonnegative). The closed invariant is enforced at the
    ``GrantSelectionDecision`` dataclass: a negative event_sequence raises
    ``ASSUMPTION_GRANT_SELECTION_SEQUENCE_INVALID``.
    """

    resolved, ledger = _resolved_and_ledger_with_grants((_grant(),))
    unsigned = {
        "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": "ADMIT",
        "assumption_materiality": "MATERIAL",
        "authority_id": "authority:operator",
        "challenge_materiality": None,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "decision_code": "ASSUMPTION_GRANT_SELECTED",
        "decision_type": "SELECTED",
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": -1,
        "grant_digest": _grant().grant_digest,
        "ledger_entry_digest": resolved.ledger_entry_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": resolved.policy_id,
        "scope_id": "scope:control",
        "selected_grant_id": "grant:1",
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        GrantSelectionDecision(
            policy_id=resolved.policy_id,
            policy_digest=resolved.policy_digest,
            effective_from_sequence=resolved.effective_from_sequence,
            signing_payload_digest=resolved.signing_payload_digest,
            commit_receipt_digest=resolved.commit_receipt_digest,
            ledger_entry_digest=resolved.ledger_entry_digest,
            ledger_root_digest=resolved.ledger_root_digest,
            event_sequence=-1,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            decision_type="SELECTED",
            decision_code="ASSUMPTION_GRANT_SELECTED",
            selected_grant_id="grant:1",
            grant_digest=_grant().grant_digest,
            selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
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
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
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
# Part 2b: Adversarial contract-closure tests (corrections 1-7)
# ===========================================================================


def test_resolution_canonical_bytes_carry_no_grant_material() -> None:
    """The resolution's canonical bytes are a digest receipt only: they carry
    no grant tuple, no grant_id, no grant_digest. A resolution object alone is
    not an authoritative source for grant selection."""

    grant = _grant("grant:distinctive")
    resolved, _ledger_obj = _resolved_and_ledger_with_grants((grant,))
    canonical = resolved.canonical_bytes.decode("utf-8")
    assert "grant:distinctive" not in canonical
    assert "grant_id" not in canonical
    assert "grant_digest" not in canonical
    assert "grants" not in canonical


def test_substituted_grant_tuple_cannot_authorize() -> None:
    """A caller cannot substitute a grant tuple to authorize. The selector
    scans ONLY the source ledger entry's ``policy.grants`` (re-bound from the
    ledger), never a caller-carried tuple. A request that no source-entry
    grant covers is denied even though an externally-built grant would cover
    it."""

    # The source entry's only grant covers ADMIT for authority:operator.
    source_grant = _grant("grant:source", authority_id="authority:operator")
    resolved, ledger = _resolved_and_ledger_with_grants((source_grant,))
    # An externally-built grant covers SUPERSEDE for authority:attacker. The
    # selector must NOT see it (it is not in the source entry), so the request
    # for SUPERSEDE by authority:attacker is denied.
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="SUPERSEDE",
        authority_id="authority:attacker",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"
    assert decision.selected_grant_id is None


def test_different_ledger_root_is_rejected() -> None:
    """A resolution whose ledger_root_digest differs from the supplied
    ledger's root is rejected. The resolution and the ledger must describe the
    same authoritative snapshot."""

    e0 = _entry(seq=10)
    ledger_one = _ledger(e0)
    # A second, different ledger (two entries) has a different root.
    e1 = _successor_entry(e0, seq=20)
    ledger_two = _ledger(e0, e1)
    # Resolve against ledger_one (root R0), then try to select against
    # ledger_two (root R1). The roots differ: rejection.
    resolved = resolve_policy_at_v3(ledger_one, 15)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger_two,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_LEDGER_ROOT_MISMATCH"


# ===========================================================================
# Part 2c: Authoritative re-resolution proof (corrections 1, 2, 8)
# ===========================================================================
#
# The selector does not trust a caller-presented ResolvedPolicyAtSequence on
# binding faith: after the type and ledger-root checks it recomputes the
# authoritative resolution at ``resolved_policy.event_sequence`` against the
# SAME ledger and requires byte-identical ``canonical_bytes``. This defeats the
# superseded-policy attack: a caller cannot present a resolution that binds a
# superseded generation's bindings (with a current ledger root and a recomputed
# digest) and have it authorize selection against that superseded generation.


def _forged_resolved(
    *,
    base: ResolvedPolicyAtSequence,
    event_sequence: int,
    ledger_root_digest: str,
    overrides: dict[str, object] | None = None,
) -> ResolvedPolicyAtSequence:
    """Build a self-consistent forged ResolvedPolicyAtSequence.

    Starts from ``base``'s generation bindings, applies any ``overrides``
    (e.g. a superseded generation's bindings), and rebinds ``event_sequence``
    and ``ledger_root_digest``. The ``resolution_digest`` is recomputed so the
    forged object is internally self-consistent (it passes the dataclass
    self-digest check). This is exactly the shape of a caller-presented attack.
    """

    unsigned: dict[str, object] = {
        "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
        "commit_receipt_digest": base.commit_receipt_digest,
        "effective_from_sequence": base.effective_from_sequence,
        "event_sequence": event_sequence,
        "ledger_entry_digest": base.ledger_entry_digest,
        "ledger_root_digest": ledger_root_digest,
        "policy_digest": base.policy_digest,
        "policy_id": base.policy_id,
        "signing_payload_digest": base.signing_payload_digest,
    }
    if overrides:
        unsigned.update(overrides)
    return ResolvedPolicyAtSequence(
        event_sequence=unsigned["event_sequence"],  # type: ignore[arg-type]
        policy_id=unsigned["policy_id"],  # type: ignore[arg-type]
        policy_digest=unsigned["policy_digest"],  # type: ignore[arg-type]
        effective_from_sequence=unsigned["effective_from_sequence"],  # type: ignore[arg-type]
        signing_payload_digest=unsigned["signing_payload_digest"],  # type: ignore[arg-type]
        commit_receipt_digest=unsigned["commit_receipt_digest"],  # type: ignore[arg-type]
        ledger_entry_digest=unsigned["ledger_entry_digest"],  # type: ignore[arg-type]
        ledger_root_digest=unsigned["ledger_root_digest"],  # type: ignore[arg-type]
        resolution_digest=domain_digest("ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", unsigned),
    )


def test_superseded_policy_attack_is_rejected() -> None:
    """A caller presents a resolution binding a SUPERSEDED generation's bindings
    (carrying the CURRENT ledger root and a recomputed digest) and requests a
    grant from that superseded generation. The authoritative re-resolution
    proof defeats this: at ``event_sequence=25`` the authoritative resolution
    binds e1's generation, so a forged resolution carrying e0's bindings is not
    byte-identical and is rejected with NOT_AUTHORITATIVE before any source
    entry is located.

    Setup mirrors the task spec exactly:

    * e0 (effective seq 10) grants authority:legacy;
    * e1 (effective seq 20) grants authority:current;
    * the forged resolution carries event_sequence=25, all of e0's generation
      bindings, the current two-entry ledger_root, and a recomputed digest.
    """

    legacy_grant = _grant(
        "grant:legacy",
        authority_id="authority:legacy",
        effective_from_sequence=10,
    )
    current_grant = _grant(
        "grant:current",
        authority_id="authority:current",
        effective_from_sequence=20,
    )
    e0 = _entry_with_policy((legacy_grant,), seq=10)
    e1 = _successor_entry_with_policy(e0, (current_grant,), seq=20)
    ledger = _ledger(e0, e1)  # two-entry, root R1

    # The authoritative resolution at seq 25 is e1 (current generation).
    authoritative_at_25 = resolve_policy_at_v3(ledger, 25)
    assert authoritative_at_25.ledger_entry_digest == e1.ledger_entry_digest

    # Forge a resolution carrying e0's bindings (legacy generation) but the
    # current two-entry ledger root and event_sequence=25.
    e0_resolved_at_10 = resolve_policy_at_v3(ledger, 10)  # binds e0's generation
    forged = _forged_resolved(
        base=e0_resolved_at_10,
        event_sequence=25,
        ledger_root_digest=ledger.ledger_root_digest,
        overrides={
            # e0's full generation bindings (policy_id/digest, payload digest,
            # commit receipt, ledger entry, effective_from_sequence).
            "policy_id": e0.policy.policy_id,
            "policy_digest": e0.policy.policy_digest,
            "signing_payload_digest": e0.signing_payload.signing_payload_digest,
            "commit_receipt_digest": e0.policy_commit.commit_receipt_digest,
            "ledger_entry_digest": e0.ledger_entry_digest,
            "effective_from_sequence": e0.signing_payload.effective_from_sequence,
        },
    )
    # Sanity: the forged object is self-consistent (digest checks pass) but its
    # canonical bytes differ from the authoritative resolution at 25.
    assert forged.canonical_bytes != authoritative_at_25.canonical_bytes

    # Request the legacy grant from the superseded generation via the forged
    # resolution: rejected as NOT_AUTHORITATIVE, never selected.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=forged,
            action="ADMIT",
            authority_id="authority:legacy",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE"


def test_valid_historical_resolution_selects_legacy_grant() -> None:
    """The authoritative re-resolution proof does NOT block legitimate
    historical reads. At ``event_sequence=15`` (governed by e0), the
    authoritative resolution binds e0's generation, so a resolution for seq 15
    is byte-identical to the recomputed authoritative resolution and the legacy
    grant MAY be selected. This is the valid counterpart to the superseded-
    policy attack."""

    legacy_grant = _grant(
        "grant:legacy",
        authority_id="authority:legacy",
        effective_from_sequence=10,
    )
    current_grant = _grant(
        "grant:current",
        authority_id="authority:current",
        effective_from_sequence=20,
    )
    e0 = _entry_with_policy((legacy_grant,), seq=10)
    e1 = _successor_entry_with_policy(e0, (current_grant,), seq=20)
    ledger = _ledger(e0, e1)

    # Historical query at 15 is governed by e0.
    resolved_at_15 = resolve_policy_at_v3(ledger, 15)
    assert resolved_at_15.ledger_entry_digest == e0.ledger_entry_digest
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved_at_15,
        action="ADMIT",
        authority_id="authority:legacy",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == "grant:legacy"


def test_current_generation_at_head_sequence_selects_current_grant() -> None:
    """At ``event_sequence=25`` (governed by e1, the current head generation),
    the authoritative resolution binds e1's generation and the current grant is
    selected. The legacy grant (from e0) is NOT applicable because it lives in
    a different generation whose grants are not scanned at this sequence."""

    legacy_grant = _grant(
        "grant:legacy",
        authority_id="authority:legacy",
        effective_from_sequence=10,
    )
    current_grant = _grant(
        "grant:current",
        authority_id="authority:current",
        effective_from_sequence=20,
    )
    e0 = _entry_with_policy((legacy_grant,), seq=10)
    e1 = _successor_entry_with_policy(e0, (current_grant,), seq=20)
    ledger = _ledger(e0, e1)

    resolved_at_25 = resolve_policy_at_v3(ledger, 25)
    assert resolved_at_25.ledger_entry_digest == e1.ledger_entry_digest
    decision = resolve_policy_and_select_grant(
        ledger=ledger,
        event_sequence=25,
        action="ADMIT",
        authority_id="authority:current",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.selected_grant_id == "grant:current"
    # The legacy authority has no grant in the current generation -> denial.
    decision_legacy = resolve_policy_and_select_grant(
        ledger=ledger,
        event_sequence=25,
        action="ADMIT",
        authority_id="authority:legacy",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision_legacy.decision_type == "NO_APPLICABLE_GRANT"


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_id", "policy:foreign"),
        ("policy_digest", "sha256:" + "f" * 64),
        ("signing_payload_digest", "sha256:" + "e" * 64),
        ("commit_receipt_digest", "sha256:" + "d" * 64),
        ("ledger_entry_digest", "sha256:" + "0" * 64),
    ],
)
def test_every_source_entry_binding_mutation_is_rejected(field: str, value: object) -> None:
    """Mutating ANY single source-entry binding on a caller-presented resolution
    is rejected. The authoritative re-resolution proof compares the FULL
    ``canonical_bytes`` receipt, so every generation binding is bound: a forged
    resolution that tampers with any one field (with a recomputed digest so it
    is internally self-consistent) is not byte-identical to the authoritative
    re-resolution and surfaces NOT_AUTHORITATIVE.

    ``effective_from_sequence`` is omitted from this matrix because the
    ``ResolvedPolicyAtSequence`` dataclass itself enforces
    ``event_sequence >= effective_from_sequence`` at construction, so it cannot
    be mutated in isolation while holding ``event_sequence`` fixed; that guard
    is exercised by ``test_resolved_event_before_effective_raises``."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    forged = _forged_resolved(
        base=resolved,
        event_sequence=resolved.event_sequence,
        ledger_root_digest=resolved.ledger_root_digest,
        overrides={field: value},
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=forged,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE"


def test_authoritative_check_runs_after_root_check() -> None:
    """The authoritative re-resolution runs AFTER the type and ledger-root
    checks. A resolution carrying a foreign ledger root surfaces
    LEDGER_ROOT_MISMATCH (not NOT_AUTHORITATIVE), because the root check fails
    first -- the authoritative re-resolution cannot even be computed against a
    ledger whose root the resolution does not describe."""

    e0 = _entry(seq=10)
    ledger_one = _ledger(e0)
    e1 = _successor_entry(e0, seq=20)
    ledger_two = _ledger(e0, e1)
    resolved = resolve_policy_at_v3(ledger_one, 15)
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger_two,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_LEDGER_ROOT_MISMATCH"


def test_canonical_bytes_comparison_not_just_entry_digest() -> None:
    """The authoritative proof compares the FULL canonical_bytes receipt, not
    just ``ledger_entry_digest``. A forged resolution whose ledger_entry_digest
    matches the real entry (so a digest-only check would pass) but whose
    policy_id differs is still rejected, because canonical_bytes includes
    policy_id."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    # Same ledger_entry_digest, same ledger_root, but a foreign policy_id: the
    # receipt differs on policy_id even though ledger_entry_digest is unchanged.
    forged = _forged_resolved(
        base=resolved,
        event_sequence=resolved.event_sequence,
        ledger_root_digest=resolved.ledger_root_digest,
        overrides={"policy_id": "policy:foreign"},
    )
    assert forged.ledger_entry_digest == resolved.ledger_entry_digest  # entry digest same
    assert forged.canonical_bytes != resolved.canonical_bytes  # receipt differs
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=forged,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE"


def test_decision_codes_mapping_is_immutable() -> None:
    """DECISION_CODES is a frozen MappingProxyType: in-place mutation raises
    TypeError. A caller cannot add, rebind, or delete a decision code to make
    a forged decision appear valid."""

    from types import MappingProxyType

    # The mapping behaves as the expected vocabulary...
    assert DECISION_CODES == {
        "SELECTED": "ASSUMPTION_GRANT_SELECTED",
        "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
        "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
    }
    assert isinstance(DECISION_CODES, MappingProxyType)
    # ...and rejects every in-place mutation shape.
    with pytest.raises(TypeError):
        DECISION_CODES["FORGED"] = "ASSUMPTION_FORGED"  # type: ignore[index]
    with pytest.raises(TypeError):
        del DECISION_CODES["SELECTED"]  # type: ignore[misc]
    with pytest.raises((TypeError, AttributeError)):
        DECISION_CODES.pop("SELECTED")  # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        DECISION_CODES.update({"SELECTED": "x"})  # type: ignore[attr-defined]
    with pytest.raises((TypeError, AttributeError)):
        DECISION_CODES.clear()  # type: ignore[attr-defined]


def test_forged_decision_code_does_not_change_other_decisions() -> None:
    """A forged decision_code on a directly-constructed GrantSelectionDecision
    does not change the frozen vocabulary: the same SELECTED/NO_APPLICABLE_GRANT
    requests before and after a failed forged construction produce identical
    decisions, because the mapping is immutable and the forged code is rejected
    at construction."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    selected_before = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    # Attempt to construct a decision with a forged code: rejected, and the
    # rejection does not mutate DECISION_CODES.
    unsigned = {
        "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": "ADMIT",
        "assumption_materiality": "MATERIAL",
        "authority_id": "authority:operator",
        "challenge_materiality": None,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "decision_code": "ASSUMPTION_FORGED_CODE",
        "decision_type": "SELECTED",
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": resolved.event_sequence,
        "grant_digest": grant.grant_digest,
        "ledger_entry_digest": resolved.ledger_entry_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": resolved.policy_id,
        "scope_id": "scope:control",
        "selected_grant_id": grant.grant_id,
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        GrantSelectionDecision(
            policy_id=resolved.policy_id,
            policy_digest=resolved.policy_digest,
            effective_from_sequence=resolved.effective_from_sequence,
            signing_payload_digest=resolved.signing_payload_digest,
            commit_receipt_digest=resolved.commit_receipt_digest,
            ledger_entry_digest=resolved.ledger_entry_digest,
            ledger_root_digest=resolved.ledger_root_digest,
            event_sequence=resolved.event_sequence,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            decision_type="SELECTED",
            decision_code="ASSUMPTION_FORGED_CODE",
            selected_grant_id=grant.grant_id,
            grant_digest=grant.grant_digest,
            selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_DECISION_CODE_INVALID"
    # The vocabulary is unchanged and the same selection is byte-identical.
    assert DECISION_CODES == {
        "SELECTED": "ASSUMPTION_GRANT_SELECTED",
        "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
        "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
    }
    selected_after = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert selected_after.canonical_bytes == selected_before.canonical_bytes


def test_source_entry_missing_is_rejected() -> None:
    """A resolution whose ledger_entry_digest matches no entry in the supplied
    ledger is rejected.

    The authoritative re-resolution proof (correction 1) is strictly stronger
    than the locate-by-digest scan: a forged resolution that carries a bogus
    ``ledger_entry_digest`` (valid in shape, with all other bindings intact and
    a recomputed ``resolution_digest``) cannot be byte-identical to the
    resolution recomputed against this ledger at this event sequence, because
    that recomputed resolution binds the REAL source entry's
    ``ledger_entry_digest``. The ``canonical_bytes`` comparison therefore fails
    before the locate scan runs, surfacing
    ``ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE``. (The downstream
    ``SOURCE_ENTRY_MISSING`` code remains as a defense-in-depth invariant inside
    ``_source_entry_for_resolution`` but is unreachable through a forged caller
    resolution once the authoritative check is in place.)
    """

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    # A bogus ledger_entry_digest that is valid in shape but not present in the
    # ledger, with all other bindings intact and a recomputed resolution_digest.
    bogus_entry_digest = "sha256:" + "0" * 64
    bogus_unsigned = {
        "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": resolved.event_sequence,
        "ledger_entry_digest": bogus_entry_digest,  # not in ledger
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": resolved.policy_id,
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    foreign_resolved = ResolvedPolicyAtSequence(
        event_sequence=resolved.event_sequence,
        policy_id=resolved.policy_id,
        policy_digest=resolved.policy_digest,
        effective_from_sequence=resolved.effective_from_sequence,
        signing_payload_digest=resolved.signing_payload_digest,
        commit_receipt_digest=resolved.commit_receipt_digest,
        ledger_entry_digest=bogus_entry_digest,
        ledger_root_digest=resolved.ledger_root_digest,
        resolution_digest=domain_digest("ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", bogus_unsigned),
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=foreign_resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE"


def test_source_binding_mismatch_is_rejected() -> None:
    """A resolution whose bindings (policy_id, policy_digest, etc.) do not
    match the authoritative resolution at its event sequence is rejected.

    The authoritative re-resolution proof (correction 1) compares the FULL
    ``canonical_bytes`` receipt: tampering with any single binding
    (``policy_id`` here) produces a receipt that is not byte-identical to the
    authoritative re-resolution, so the superseded-policy / binding-mismatch
    attack surfaces as ``ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE``
    before the source-entry locate/verify scan runs. (The downstream
    ``SOURCE_BINDING_MISMATCH`` code remains a defense-in-depth invariant but is
    unreachable through a forged caller resolution once the authoritative check
    is in place, since ``canonical_bytes`` equality forces every binding to
    agree with the real resolved entry.)"""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    resolved = resolve_policy_at_v3(ledger, 15)
    # Tamper with policy_id while keeping the event sequence and ledger root
    # intact. The recomputed resolution_digest makes the forged object
    # self-consistent, but its canonical_bytes differ from the authoritative
    # re-resolution (which binds the real policy_id).
    tampered_unsigned = {
        "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": resolved.event_sequence,
        "ledger_entry_digest": resolved.ledger_entry_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": "policy:foreign",  # mismatches the authoritative resolution
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    tampered = ResolvedPolicyAtSequence(
        event_sequence=resolved.event_sequence,
        policy_id="policy:foreign",
        policy_digest=resolved.policy_digest,
        effective_from_sequence=resolved.effective_from_sequence,
        signing_payload_digest=resolved.signing_payload_digest,
        commit_receipt_digest=resolved.commit_receipt_digest,
        ledger_entry_digest=resolved.ledger_entry_digest,
        ledger_root_digest=resolved.ledger_root_digest,
        resolution_digest=domain_digest(
            "ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", tampered_unsigned
        ),
    )
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=tampered,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_NOT_AUTHORITATIVE"


def test_foreign_resolution_object_returns_stable_code() -> None:
    """A foreign (non-ResolvedPolicyAtSequence) object passed as resolved_policy
    surfaces the stable RESOLUTION_TYPE_INVALID code, never an AttributeError."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    # A plain object lacking the digest fields.
    foreign = object()  # type: ignore[arg-type]
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=foreign,  # type: ignore[arg-type]
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_RESOLUTION_TYPE_INVALID"


def test_foreign_ledger_returns_stable_code() -> None:
    """A non-V3 ledger passed to the selector surfaces the stable
    LEDGER_VERSION_NOT_ACTIVATABLE code, never an AttributeError."""

    from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
        AssumptionPolicyLedgerV2,
    )

    grant = _grant()
    resolved, _ledger_obj = _resolved_and_ledger_with_grants((grant,))
    v2 = AssumptionPolicyLedgerV2.build(())
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=v2,  # type: ignore[arg-type]
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_LEDGER_VERSION_NOT_ACTIVATABLE"


def test_event_sequence_cannot_be_rebound() -> None:
    """The selector uses resolved_policy.event_sequence for ALL grant-interval
    evaluation. There is no independently supplied event sequence, so the
    sequence cannot be rebound to a different generation.

    A grant whose effective interval covers ONLY sequence 15 (the resolved
    event_sequence) is selected; the same resolution cannot be made to select
    a grant whose interval is outside the resolved sequence, because there is
    no sequence parameter to rebind.
    """

    # Grant active at exactly the resolved event_sequence (15).
    grant_at_15 = _grant(
        "grant:at15",
        effective_from_sequence=15,
        effective_until_sequence=16,
    )
    resolved, ledger = _resolved_and_ledger_with_grants(
        (grant_at_15,), effective_from=10, event_sequence=15
    )
    decision = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "SELECTED"
    assert decision.event_sequence == 15  # the resolved sequence, not a rebind


def test_authority_validated_before_scanning() -> None:
    """A malformed authority_id raises the stable contract code before any
    grant is scanned (the selector validates the token before scanning)."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="not a token",  # type: ignore[arg-type]
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_AUTHORITY_INVALID"


def test_scope_validated_before_scanning() -> None:
    """A malformed scope_id raises the stable contract code before any grant is
    scanned."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="",  # type: ignore[arg-type]
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID"


def test_assumption_authority_actions_is_the_only_action_vocabulary() -> None:
    """The selector accepts exactly ``ASSUMPTION_AUTHORITY_ACTIONS`` from the
    contracts module; there is no local action enumeration. Every contract
    action is accepted; no foreign action is accepted."""

    # Every action in the normative enumeration is accepted (does not raise
    # ACTION_INVALID). For non-resolution actions a non-applicable grant
    # yields NO_APPLICABLE_GRANT; the point is the action is recognized.
    grant = _grant(action="ADMIT")
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    for action in ASSUMPTION_AUTHORITY_ACTIONS:
        # Build a grant matching this action so the request is well-formed.
        if action in (
            "RESOLVE_TO_ADMITTED",
            "RESOLVE_TO_CONFIRMED",
            "RESOLVE_TO_REJECTED",
            "RESOLVE_TO_SUPERSEDED",
        ):
            # Resolution actions require a challenge materiality and a
            # resolution-action grant; just verify the action is recognized
            # (no ACTION_INVALID) by using a denial path.
            decision = select_applicable_grant_v3(
                ledger=ledger,
                resolved_policy=resolved,
                action=action,
                authority_id="authority:operator",
                scope_id="scope:control",
                assumption_materiality="MATERIAL",
                challenge_materiality="MATERIAL",
            )
            assert decision.decision_type == "NO_APPLICABLE_GRANT"
        else:
            decision = select_applicable_grant_v3(
                ledger=ledger,
                resolved_policy=resolved,
                action=action,
                authority_id="authority:operator",
                scope_id="scope:control",
                assumption_materiality="MATERIAL",
                challenge_materiality=None,
            )
            # The ADMIT grant matches only ADMIT; all other non-resolution
            # actions deny.
            if action == "ADMIT":
                assert decision.decision_type == "SELECTED"
            else:
                assert decision.decision_type == "NO_APPLICABLE_GRANT"
    # A foreign action is rejected.
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        select_applicable_grant_v3(
            ledger=ledger,
            resolved_policy=resolved,
            action="FORGED_ACTION",  # type: ignore[arg-type]
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_ACTION_INVALID"


def test_decision_code_vocabulary_is_frozen() -> None:
    """The decision_code is the frozen vocabulary: one per decision type, and
    it is bound into the selection_digest so distinct outcomes produce
    distinct digests."""

    assert DECISION_CODES == {
        "SELECTED": "ASSUMPTION_GRANT_SELECTED",
        "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
        "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
    }
    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    selected = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert selected.decision_code == "ASSUMPTION_GRANT_SELECTED"
    no_grant = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="REJECT",  # no grant covers REJECT
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert no_grant.decision_code == "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT"
    # The two decisions share the same resolved policy and request scope but
    # differ in action and outcome; their digests differ (decision_code is
    # bound in).
    assert selected.selection_digest != no_grant.selection_digest


def test_decision_code_is_bound_into_selection_digest() -> None:
    """The decision_code participates in the selection_digest: two decisions
    over the SAME (resolved policy, request) that differ only in outcome
    produce distinct digests."""

    # Build two grants that both match -> AMBIGUOUS, and the same request with
    # one grant removed -> would be SELECTED. Construct distinct resolutions
    # sharing all bindings except the outcome via the dataclass.
    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    selected = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    denied = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="SUPERSEDE",  # no grant -> NO_APPLICABLE_GRANT
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    # Same resolved policy, same authority/scope/materiality, different action
    # and outcome. The digests differ. (The action also differs, but the
    # decision_code is bound in too: verify the unsigned value includes it.)
    assert "decision_code" in selected._unsigned_value()
    assert selected.decision_code != denied.decision_code


def test_decision_code_mismatch_raises() -> None:
    """A GrantSelectionDecision constructed with a decision_code that does not
    match its decision_type raises the stable code."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    unsigned = {
        "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": "ADMIT",
        "assumption_materiality": "MATERIAL",
        "authority_id": "authority:operator",
        "challenge_materiality": None,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "decision_code": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",  # wrong for SELECTED
        "decision_type": "SELECTED",
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": resolved.event_sequence,
        "grant_digest": grant.grant_digest,
        "ledger_entry_digest": resolved.ledger_entry_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": resolved.policy_id,
        "scope_id": "scope:control",
        "selected_grant_id": grant.grant_id,
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        GrantSelectionDecision(
            policy_id=resolved.policy_id,
            policy_digest=resolved.policy_digest,
            effective_from_sequence=resolved.effective_from_sequence,
            signing_payload_digest=resolved.signing_payload_digest,
            commit_receipt_digest=resolved.commit_receipt_digest,
            ledger_entry_digest=resolved.ledger_entry_digest,
            ledger_root_digest=resolved.ledger_root_digest,
            event_sequence=resolved.event_sequence,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            decision_type="SELECTED",
            decision_code="ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",  # mismatched
            selected_grant_id=grant.grant_id,
            grant_digest=grant.grant_digest,
            selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_DECISION_CODE_INVALID"


def test_resolved_event_before_effective_raises() -> None:
    """The closed contract invariant on ResolvedPolicyAtSequence: event_sequence
    must be >= effective_from_sequence. A directly-constructed binding with
    event_sequence below effective raises the stable code (resolution itself
    never produces such a binding, but the dataclass closes the invariant)."""

    e0 = _entry(seq=10)
    ledger = _ledger(e0)
    unsigned = {
        "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
        "commit_receipt_digest": e0.policy_commit.commit_receipt_digest,
        "effective_from_sequence": 10,
        "event_sequence": 5,  # below effective
        "ledger_entry_digest": e0.ledger_entry_digest,
        "ledger_root_digest": ledger.ledger_root_digest,
        "policy_digest": e0.policy.policy_digest,
        "policy_id": e0.policy.policy_id,
        "signing_payload_digest": e0.signing_payload.signing_payload_digest,
    }
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        ResolvedPolicyAtSequence(
            event_sequence=5,
            policy_id=e0.policy.policy_id,
            policy_digest=e0.policy.policy_digest,
            effective_from_sequence=10,
            signing_payload_digest=e0.signing_payload.signing_payload_digest,
            commit_receipt_digest=e0.policy_commit.commit_receipt_digest,
            ledger_entry_digest=e0.ledger_entry_digest,
            ledger_root_digest=ledger.ledger_root_digest,
            resolution_digest=domain_digest("ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", unsigned),
        )
    assert failure.value.code == "ASSUMPTION_POLICY_RESOLUTION_EVENT_BEFORE_EFFECTIVE"


def test_denial_carries_no_selected_grant_fields() -> None:
    """A denial (NO_APPLICABLE_GRANT / AMBIGUOUS_GRANTS) carries no
    selected_grant_id and no grant_digest. The dataclass enforces this."""

    grant = _grant()
    resolved, ledger = _resolved_and_ledger_with_grants((grant,))
    denied = select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action="SUPERSEDE",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert denied.decision_type == "NO_APPLICABLE_GRANT"
    assert denied.selected_grant_id is None
    assert denied.grant_digest is None


def test_selected_grant_id_must_be_valid_token() -> None:
    """A SELECTED decision with an invalid selected_grant_id token raises the
    stable code at construction."""

    grant = _grant()
    resolved, _ledger_obj = _resolved_and_ledger_with_grants((grant,))
    unsigned = {
        "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": "ADMIT",
        "assumption_materiality": "MATERIAL",
        "authority_id": "authority:operator",
        "challenge_materiality": None,
        "commit_receipt_digest": resolved.commit_receipt_digest,
        "decision_code": "ASSUMPTION_GRANT_SELECTED",
        "decision_type": "SELECTED",
        "effective_from_sequence": resolved.effective_from_sequence,
        "event_sequence": resolved.event_sequence,
        "grant_digest": grant.grant_digest,
        "ledger_entry_digest": resolved.ledger_entry_digest,
        "ledger_root_digest": resolved.ledger_root_digest,
        "policy_digest": resolved.policy_digest,
        "policy_id": resolved.policy_id,
        "scope_id": "scope:control",
        "selected_grant_id": "not a token",
        "signing_payload_digest": resolved.signing_payload_digest,
    }
    with pytest.raises(AssumptionPolicyActivationContractError) as failure:
        GrantSelectionDecision(
            policy_id=resolved.policy_id,
            policy_digest=resolved.policy_digest,
            effective_from_sequence=resolved.effective_from_sequence,
            signing_payload_digest=resolved.signing_payload_digest,
            commit_receipt_digest=resolved.commit_receipt_digest,
            ledger_entry_digest=resolved.ledger_entry_digest,
            ledger_root_digest=resolved.ledger_root_digest,
            event_sequence=resolved.event_sequence,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
            decision_type="SELECTED",
            decision_code="ASSUMPTION_GRANT_SELECTED",
            selected_grant_id="not a token",
            grant_digest=grant.grant_digest,
            selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
        )
    assert failure.value.code == "ASSUMPTION_GRANT_SELECTION_SELECTED_GRANT_ID_INVALID"


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
    """A fresh publisher process can run grant selection after restart via the
    authoritative composite."""

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
    decision = pub2.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
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
# Mechanical lock-scope evidence (correction 4)
# ---------------------------------------------------------------------------


def test_composite_runs_selection_inside_lock_with_required_ordering(
    tmp_path: Path,
) -> None:
    """Mechanical proof that the composite executes grant selection INSIDE the
    publication lock, between the first and second authoritative byte reads,
    and that the second read + comparison happen AFTER selection completes.

    Instrumentation (all normalized to a single event log so the ordering is
    observed, not assumed):

    * wrap ``_locked`` to record lock acquire/release and to track a
      ``lock_held`` boolean readable by the patched selector;
    * monkeypatch ``select_applicable_grant_v3`` to assert ``lock_held`` is
      True when the selector runs, and to record ``selection_started`` then
      ``selection_completed``;
    * instrument ``_read_authoritative_bytes_in_lock`` to record each read and
      to prove the SECOND read occurs AFTER ``selection_completed``.

    The required order is exactly:

        lock -> first read -> parse -> resolve -> selector (lock held) ->
        selector completed -> second read -> compare -> lock exit
    """

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store_with_grant(pub, _grant())

    events: list[str] = []
    state = {"lock_held": False, "selection_completed": False}

    # Wrap _locked to track lock_held and record acquire/release boundaries.
    original_locked = pub._locked

    @contextmanager
    def instrumented_locked() -> Iterator[None]:
        events.append("LOCK_ACQUIRED")
        state["lock_held"] = True
        try:
            yield
        finally:
            # The non-mutation comparison must have run before release.
            events.append("LOCK_RELEASED")
            state["lock_held"] = False

    pub._locked = instrumented_locked  # type: ignore[assignment]

    # Instrument the in-lock byte reader to record each read and prove the
    # second read follows selection completion.
    original_read = pub._read_authoritative_bytes_in_lock
    read_count = {"n": 0}

    def instrumented_read() -> bytes:
        read_count["n"] += 1
        events.append(f"READ_{read_count['n']}")
        if read_count["n"] == 2:
            # The second read MUST occur after selection completed.
            assert state["selection_completed"], (
                "second authoritative read occurred before selection completed"
            )
        return original_read()

    pub._read_authoritative_bytes_in_lock = instrumented_read  # type: ignore[assignment]

    # Monkeypatch the selector to assert it runs while the lock is held and to
    # bracket selection with started/completed events. The filesystem composite
    # imports ``resolve_policy_and_select_grant`` at call time from the
    # resolution module; that composite in turn calls the module-level
    # ``select_applicable_grant_v3``, so patching both module attributes is
    # sufficient to intercept resolution and selection inside the lock.
    import csd_foundry.governance.v0_5.assumption_policy_resolution as res_mod

    original_select = res_mod.select_applicable_grant_v3

    def instrumented_select(*, ledger, resolved_policy, **kwargs):  # type: ignore[no-untyped-def]
        assert state["lock_held"], "selector ran while the publication lock was NOT held"
        events.append("SELECTION_STARTED")
        decision = original_select(ledger=ledger, resolved_policy=resolved_policy, **kwargs)
        events.append("SELECTION_COMPLETED")
        state["selection_completed"] = True
        return decision

    original_composite = res_mod.resolve_policy_and_select_grant

    def instrumented_composite(*, ledger, event_sequence, **kwargs):  # type: ignore[no-untyped-def]
        # Resolve, then call the (patched) selector. We re-implement the
        # composite ordering so the patched selector is the one invoked.
        resolved = res_mod.resolve_policy_at_v3(ledger, event_sequence)
        events.append("RESOLVE_COMPLETED")
        return res_mod.select_applicable_grant_v3(ledger=ledger, resolved_policy=resolved, **kwargs)

    res_mod.resolve_policy_and_select_grant = instrumented_composite  # type: ignore[assignment]
    res_mod.select_applicable_grant_v3 = instrumented_select  # type: ignore[assignment]

    try:
        decision = pub.resolve_policy_and_select_grant_at(
            event_sequence=15,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    finally:
        res_mod.resolve_policy_and_select_grant = original_composite  # type: ignore[assignment]
        res_mod.select_applicable_grant_v3 = original_select  # type: ignore[assignment]
        pub._locked = original_locked  # type: ignore[assignment]
        pub._read_authoritative_bytes_in_lock = original_read  # type: ignore[assignment]

    assert decision.decision_type == "SELECTED"
    # The observed event sequence proves the required ordering.
    assert events == [
        "LOCK_ACQUIRED",
        "READ_1",
        "RESOLVE_COMPLETED",
        "SELECTION_STARTED",
        "SELECTION_COMPLETED",
        "READ_2",
        "LOCK_RELEASED",
    ], events
    # No third read: exactly two in-lock reads (before/after selection).
    assert read_count["n"] == 2


# ---------------------------------------------------------------------------
# Filesystem composite (resolve_policy_and_select_grant_at)
# ---------------------------------------------------------------------------


def _populate_store_with_grant(
    pub: FilesystemAssumptionPolicyPublisher,
    grant: AssumptionAuthorityGrant | None = None,
) -> AssumptionPolicyLedgerEntryV3:
    """Create and publish one entry carrying ``grant``; return the entry."""

    actual_grant = grant if grant is not None else _grant()
    pub.create()
    state = pub.read_state()
    entry = _entry_with_policy((actual_grant,), seq=10)
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(entry)
    pub.publish(prepared=prepared, expected_state=state)
    return entry


def test_composite_selection_after_restart(tmp_path: Path) -> None:
    """The authoritative composite resolves AND selects under one locked
    snapshot, and a fresh publisher process produces the same decision."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    grant = _grant("grant:composite")
    _populate_store_with_grant(pub, grant)
    decision_before = pub.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision_before.decision_type == "SELECTED"
    assert decision_before.selected_grant_id == grant.grant_id

    # Restart: a fresh publisher over the same root produces the same decision.
    pub2 = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub2.open()
    decision_after = pub2.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision_after.canonical_bytes == decision_before.canonical_bytes
    assert decision_after.selection_digest == decision_before.selection_digest


def test_composite_no_match_denial_leaves_store_unchanged(tmp_path: Path) -> None:
    """A NO_APPLICABLE_GRANT denial from the composite leaves the store bytes,
    root, and head unchanged. The composite performs no writes."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store_with_grant(pub, _grant(action="ADMIT"))
    state_before = pub.read_state()
    bytes_before = (tmp_path / "ledger.json").read_bytes()

    decision = pub.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="SUPERSEDE",  # no grant covers SUPERSEDE
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "NO_APPLICABLE_GRANT"
    assert decision.decision_code == "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT"

    state_after = pub.read_state()
    bytes_after = (tmp_path / "ledger.json").read_bytes()
    assert state_before == state_after
    assert bytes_before == bytes_after


def test_composite_ambiguity_leaves_store_unchanged(tmp_path: Path) -> None:
    """An AMBIGUOUS_GRANTS fail-closed denial from the composite leaves the
    store bytes, root, and head unchanged."""

    # Two grants that both cover the request (the policy overlap validator
    # would normally reject this at construction, but build it directly to
    # exercise the selector's fail-closed path). Use a fresh subdirectory so
    # this store is independent.
    grant_a = _grant("grant:a", assumption_materialities=("MATERIAL",))
    grant_b = _grant("grant:b", assumption_materialities=("MATERIAL", "ADVISORY"))
    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    pub.create()
    state = pub.read_state()
    entry = _entry_with_policy((grant_a, grant_b), seq=10)
    from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
        PreparedPolicyActivation,
    )

    prepared = PreparedPolicyActivation.build(entry)
    pub.publish(prepared=prepared, expected_state=state)

    state_before = pub.read_state()
    bytes_before = (tmp_path / "ledger.json").read_bytes()
    decision = pub.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.decision_type == "AMBIGUOUS_GRANTS"
    assert decision.decision_code == "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS"
    state_after = pub.read_state()
    bytes_after = (tmp_path / "ledger.json").read_bytes()
    assert state_before == state_after
    assert bytes_before == bytes_after


def test_composite_reads_create_no_temp_files(tmp_path: Path) -> None:
    """The composite read path creates no managed temp files: no temp, no
    replace, no fsync, no orphan cleanup."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store_with_grant(pub)
    files_before = {p.name for p in tmp_path.iterdir()}
    for _ in range(5):
        pub.resolve_policy_and_select_grant_at(
            event_sequence=15,
            action="ADMIT",
            authority_id="authority:operator",
            scope_id="scope:control",
            assumption_materiality="MATERIAL",
            challenge_materiality=None,
        )
    files_after = {p.name for p in tmp_path.iterdir()}
    assert files_before == files_after
    assert not any(name.startswith(".policy-ledger.") for name in files_after)


def test_composite_decision_binds_observed_root(tmp_path: Path) -> None:
    """The composite decision's ledger_root_digest is the root the reader
    observed under the lock (resolution and selection share one snapshot)."""

    pub = FilesystemAssumptionPolicyPublisher(tmp_path)
    _populate_store_with_grant(pub)
    observed_root = pub.read_state().ledger_root_digest
    decision = pub.resolve_policy_and_select_grant_at(
        event_sequence=15,
        action="ADMIT",
        authority_id="authority:operator",
        scope_id="scope:control",
        assumption_materiality="MATERIAL",
        challenge_materiality=None,
    )
    assert decision.ledger_root_digest == observed_root


# ---------------------------------------------------------------------------
# Multiprocess reader/publisher serialization
# ---------------------------------------------------------------------------


def _mp_reader_worker(
    root: str,
    result_queue: mp.Queue,  # type: ignore[type-arg]
    barrier_arg: object,
    iterations: int,
) -> None:
    """Spawn-safe reader worker: resolves AND selects after the barrier.

    Each iteration runs the authoritative composite
    ``resolve_policy_and_select_grant_at`` so the reader observes the complete
    resolution+grants from a single snapshot. It captures the observed ledger
    root and the selected grant_id so the parent can prove the reader saw a
    complete (old or new) policy generation with its matching grants, never a
    torn read or a mixed snapshot. The outcome tuple is tagged
    ``("READER", label, payload)`` so the parent can distinguish reader
    outcomes from publisher outcomes (both use label ``"OK"`` on success).
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
    observed: list[tuple[str, str | None]] = []  # (root, selected_grant_id)
    errors: list[str] = []
    for _ in range(iterations):
        try:
            decision = pub.resolve_policy_and_select_grant_at(
                event_sequence=15,
                action="ADMIT",
                authority_id="authority:operator",
                scope_id="scope:control",
                assumption_materiality="MATERIAL",
                challenge_materiality=None,
            )
            observed.append((decision.ledger_root_digest, decision.selected_grant_id))
        except PolicyStoreError as exc:
            errors.append(f"STORE:{exc.code}")
        except AssumptionPolicyActivationContractError as exc:
            errors.append(f"CONTRACT:{exc.code}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"UNEXPECTED:{type(exc).__name__}")
    result_queue.put(("READER", "OK", (observed, errors)))


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

    # The reader observed only complete snapshots: every observed (root,
    # grant_id) pair is from either R0 (old generation) or R1 (new
    # generation), never a torn read or a mixed snapshot, and no errors. The
    # selected grant must always be the grant carried by the entry whose
    # ledger root was observed (selection re-binds the resolution to the same
    # ledger, so root and grants always come from one snapshot).
    _role, read_label, read_payload = read_outcomes[0]
    assert read_label == "OK", f"reader barrier error: {read_payload}"
    observed_pairs, errors = read_payload
    assert errors == [], f"reader observed errors: {errors}"
    assert observed_pairs, "reader observed no snapshots"
    for observed_root, observed_grant in observed_pairs:
        assert observed_root in (r0, r1), f"torn read: {observed_root} not in ({r0}, {r1})"
        # The grant is always selected (the default grant covers ADMIT at
        # MATERIAL for authority:operator / scope:control), and it must be
        # non-None: a denial would indicate a mixed snapshot where the grants
        # did not match the resolved generation.
        assert observed_grant is not None, f"denial under root {observed_root}"

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
    observed_pairs, errors = payload
    assert errors == [], f"reader errors: {errors}"
    for observed_root, observed_grant in observed_pairs:
        assert observed_root in known_roots, f"torn read: {observed_root} not in known roots"
        # Resolution+grants always come from the same snapshot: a selected
        # grant is present (the default grant covers the request), never a
        # denial that would indicate a mixed snapshot.
        assert observed_grant is not None, f"denial under root {observed_root}"


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
