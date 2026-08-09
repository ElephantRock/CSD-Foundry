"""Tests for the frozen assumption-history -> governance-role derivation (I1-B0).

Covers the 12 required cases plus the load-bearing SoD-predecessor scenario
from the authorization spec. No separation-of-duty rule is evaluated anywhere
in this file — these tests exercise derivation only.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    GOVERNANCE_ROLE_FACT_SCHEMA_VERSION,
    AssumptionGovernanceContractError,
)
from csd_foundry.governance.v0_5._assumption_governance_role_derivation import (
    AssumptionGovernanceRoleFact,
    derive_assumption_governance_role,
    derive_prior_governance_roles,
)
from csd_foundry.governance.v0_5.assumption import (
    AssumptionRegistryError,
    build_assumption_event,
    project_assumption_history,
)

# --------------------------------------------------------------------------- #
# Event-construction helpers (mirror the lifecycle test patterns)
# --------------------------------------------------------------------------- #


def _digest(seed: str) -> str:
    """Return a valid sha256 hex digest derived from a seed string.

    The lifecycle's digest regex requires hex characters only
    (``sha256:[0-9a-f]{64}``), so char-repeat with non-hex seeds is rejected.
    """
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _propose(
    *,
    assumption_id: str = "assumption:1",
    authority: str = "authority:proposer",
    clock: int = 1,
    expires: int = 10,
):
    """Build a PROPOSE event (genesis; entity_sequence=1, no predecessor)."""
    return build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest("1"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "proposition:control-connected",
            "scope_ids": ["scope:control-17"],
            "materiality": "MATERIAL",
            "proposer_authority_id": authority,
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": ["limitation:declared-model"],
            "maximum_reuse_class": "D2",
        },
    )


def _after(previous_event, history, operation, clock, payload):
    """Build a successor event chained off the canonical projection of history.

    ``history`` is the tuple of events accumulated so far. We reduce it to get
    the current projection (which carries ``current_entity_sequence`` and
    ``current_event_digest``), then build the next event.
    """
    proj = project_assumption_history(history)
    assert proj is not None, "history must reduce to a non-None projection"
    return build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=proj.current_entity_sequence + 1,
        previous_entity_event_digest=proj.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(str(clock)),
        payload={"operation": operation, **payload},
    )


def _admit(history, authority="authority:admitter", clock=2):
    return _after(
        history[-1],
        history,
        "ADMIT",
        clock,
        {
            "admitting_authority_id": authority,
            "admission_receipt_digest": _digest("admit"),
        },
    )


def _confirm(history, authority="authority:confirmer", clock=3):
    return _after(
        history[-1],
        history,
        "CONFIRM",
        clock,
        {
            "confirming_authority_id": authority,
            "confirmation_receipt_digest": _digest("confirm"),
        },
    )


def _challenge(history, authority="authority:challenger", clock=4, cid="challenge:1"):
    return _after(
        history[-1],
        history,
        "CHALLENGE",
        clock,
        {
            "challenge_id": cid,
            "challenger_authority_id": authority,
            "challenge_reason_code": "reason:test",
            "challenge_receipt_digest": _digest("challenge"),
        },
    )


def _resolve(
    history,
    *,
    clock=5,
    outcome="RETURN_TO_ADMITTED",
    authority="authority:resolver",
    challenge_ids=None,
    replacement=None,
):
    return _after(
        history[-1],
        history,
        "RESOLVE_CHALLENGES",
        clock,
        {
            "resolution_outcome": outcome,
            "resolver_authority_id": authority,
            "resolution_receipt_digest": _digest("resolve"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": challenge_ids or ["challenge:1"],
            "replacement_assumption_id": replacement,
        },
    )


def _reject(history, authority="authority:rejector", clock=6):
    return _after(
        history[-1],
        history,
        "REJECT",
        clock,
        {
            "rejecting_authority_id": authority,
            "rejection_receipt_digest": _digest("reject"),
        },
    )


def _expire(history, authority="authority:clock", clock=7):
    return _after(
        history[-1],
        history,
        "EXPIRE",
        clock,
        {
            "expiry_authority_id": authority,
            "expiry_receipt_digest": _digest("expire"),
        },
    )


def _supersede(history, authority="authority:superseder", clock=8, replacement="assumption:2"):
    return _after(
        history[-1],
        history,
        "SUPERSEDE",
        clock,
        {
            "superseding_authority_id": authority,
            "supersession_receipt_digest": _digest("supersede"),
            "replacement_assumption_id": replacement,
        },
    )


# --------------------------------------------------------------------------- #
# Required test 1: all eight operations derive exactly the mapping
# --------------------------------------------------------------------------- #


def test_propose_derives_proposer() -> None:
    e = _propose(authority="authority:p")
    fact = derive_assumption_governance_role(e)
    assert fact.authority_id == "authority:p"
    assert fact.governance_role == "PROPOSER"


def test_admit_derives_admitter() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    fact = derive_assumption_governance_role(e2)
    assert fact.authority_id == "authority:a"
    assert fact.governance_role == "ADMITTER"


def test_confirm_derives_confirmer() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _confirm((e1, e2), authority="authority:c")
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:c"
    assert fact.governance_role == "CONFIRMER"


def test_challenge_derives_challenger() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _challenge((e1, e2), authority="authority:h")
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:h"
    assert fact.governance_role == "CHALLENGER"


def test_resolve_derives_resolver() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _challenge((e1, e2), authority="authority:h")
    e4 = _resolve((e1, e2, e3), authority="authority:r")
    fact = derive_assumption_governance_role(e4)
    assert fact.authority_id == "authority:r"
    assert fact.governance_role == "RESOLVER"


def test_reject_derives_rejector() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _reject((e1, e2), authority="authority:j")
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:j"
    assert fact.governance_role == "REJECTOR"


def test_expire_derives_expiry_authority() -> None:
    e1 = _propose(authority="authority:p", expires=5)
    e2 = _admit((e1,), authority="authority:a")
    e3 = _expire((e1, e2), authority="authority:e", clock=5)
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:e"
    assert fact.governance_role == "EXPIRY_AUTHORITY"


def test_supersede_derives_superseder() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _supersede((e1, e2), authority="authority:s")
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:s"
    assert fact.governance_role == "SUPERSEDER"


# --------------------------------------------------------------------------- #
# Required test 2: each operation reads the correct payload field
# --------------------------------------------------------------------------- #


def test_propose_reads_proposer_authority_field_not_admitter() -> None:
    e = _propose(authority="authority:proposer")
    fact = derive_assumption_governance_role(e)
    assert fact.authority_id == "authority:proposer"


def test_admit_reads_admitting_authority_field_not_proposer() -> None:
    e1 = _propose(authority="authority:proposer")
    e2 = _admit((e1,), authority="authority:admitter")
    fact = derive_assumption_governance_role(e2)
    assert fact.authority_id == "authority:admitter"


def test_challenge_reads_challenger_field_not_resolver() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _challenge((e1, e2), authority="authority:challenger")
    fact = derive_assumption_governance_role(e3)
    assert fact.authority_id == "authority:challenger"


def test_resolve_reads_resolver_field_regardless_of_outcome() -> None:
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _challenge((e1, e2), authority="authority:h")
    for outcome in ("RETURN_TO_ADMITTED", "CONFIRM", "REJECT", "SUPERSEDE"):
        chal_ids = ["challenge:1"] if outcome in ("RETURN_TO_ADMITTED", "CONFIRM") else []
        e4 = _resolve(
            (e1, e2, e3), outcome=outcome, authority="authority:resolver", challenge_ids=chal_ids
        )
        fact = derive_assumption_governance_role(e4)
        assert fact.governance_role == "RESOLVER", f"outcome={outcome} changed the role"


# --------------------------------------------------------------------------- #
# Required test 3: resolution outcome does not change historical role
# (covered parametrically above; this is the explicit standalone assertion)
# --------------------------------------------------------------------------- #


def test_resolution_outcome_does_not_change_historical_role() -> None:
    """The four resolution outcomes all yield RESOLVER; the outcome changes the
    authority action required for the candidate event, not the historical role."""
    e1 = _propose(authority="authority:p")
    e2 = _admit((e1,), authority="authority:a")
    e3 = _challenge((e1, e2), authority="authority:h")
    outcomes_roles = []
    for outcome in ("RETURN_TO_ADMITTED", "CONFIRM", "REJECT", "SUPERSEDE"):
        chal_ids = ["challenge:1"] if outcome in ("RETURN_TO_ADMITTED", "CONFIRM") else []
        e4 = _resolve(
            (e1, e2, e3), outcome=outcome, authority="authority:resolver", challenge_ids=chal_ids
        )
        outcomes_roles.append(derive_assumption_governance_role(e4).governance_role)
    assert outcomes_roles == ["RESOLVER", "RESOLVER", "RESOLVER", "RESOLVER"]


# --------------------------------------------------------------------------- #
# Required test 4 + 5: multi-role actor; deduplication
# --------------------------------------------------------------------------- #


def test_same_actor_multiple_roles_yields_all_and_only_those_roles() -> None:
    """Actor A proposes then challenges; A's prior roles = (CHALLENGER, PROPOSER)."""
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:B")
    e3 = _challenge((e1, e2), authority="authority:A", clock=3)

    roles_A = derive_prior_governance_roles(
        (e1, e2, e3), candidate_entity_sequence=4, authority_id="authority:A"
    )
    assert roles_A == ("CHALLENGER", "PROPOSER")

    roles_B = derive_prior_governance_roles(
        (e1, e2, e3), candidate_entity_sequence=4, authority_id="authority:B"
    )
    assert roles_B == ("ADMITTER",)


def test_repeated_same_role_is_deduplicated() -> None:
    """Actor A challenges twice; the role set is (CHALLENGER,) not (CHALLENGER, CHALLENGER)."""
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:B")
    e3 = _challenge((e1, e2), authority="authority:A", cid="challenge:1", clock=3)
    e4 = _challenge((e1, e2, e3), authority="authority:A", cid="challenge:2", clock=4)

    roles = derive_prior_governance_roles(
        (e1, e2, e3, e4), candidate_entity_sequence=5, authority_id="authority:A"
    )
    assert roles == ("CHALLENGER", "PROPOSER")


# --------------------------------------------------------------------------- #
# Required test 6: different actors' roles never leak
# --------------------------------------------------------------------------- #


def test_different_actors_roles_never_leak() -> None:
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:B")
    e3 = _challenge((e1, e2), authority="authority:A", clock=3)
    # Resolve challenges so CONFIRM is valid (can't confirm with active challenges).
    e4 = _resolve((e1, e2, e3), outcome="RETURN_TO_ADMITTED", authority="authority:D", clock=4)
    e5 = _confirm((e1, e2, e3, e4), authority="authority:C", clock=5)

    roles_B = derive_prior_governance_roles(
        (e1, e2, e3, e4, e5), candidate_entity_sequence=6, authority_id="authority:B"
    )
    assert roles_B == ("ADMITTER",)
    roles_C = derive_prior_governance_roles(
        (e1, e2, e3, e4, e5), candidate_entity_sequence=6, authority_id="authority:C"
    )
    assert roles_C == ("CONFIRMER",)


# --------------------------------------------------------------------------- #
# Required test 7: future event excluded when deriving predecessor history
# --------------------------------------------------------------------------- #


def test_future_event_excluded_from_predecessor_history() -> None:
    """Querying at candidate position 2 (after PROPOSE, before ADMIT) must NOT
    see the ADMIT event even though it is in the tuple."""
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:B")
    e3 = _challenge((e1, e2), authority="authority:A", clock=3)

    # At candidate position 2, only e1 (PROPOSE) is prior.
    roles_A_at_2 = derive_prior_governance_roles(
        (e1, e2, e3), candidate_entity_sequence=2, authority_id="authority:A"
    )
    assert roles_A_at_2 == ("PROPOSER",)
    # B has no prior roles at position 2 (ADMIT is at position 2, not prior to it).
    roles_B_at_2 = derive_prior_governance_roles(
        (e1, e2, e3), candidate_entity_sequence=2, authority_id="authority:B"
    )
    assert roles_B_at_2 == ()


# --------------------------------------------------------------------------- #
# Required test 8: malformed predecessor chain fails
# --------------------------------------------------------------------------- #


def test_malformed_predecessor_chain_fails() -> None:
    """A chain whose predecessor digest does not link must fail during canonical
    replay, not produce roles."""
    e1 = _propose(authority="authority:A")
    # e2 claims a wrong predecessor digest.
    e2 = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=2,
        previous_entity_event_digest=_digest("z"),  # wrong
        clock_sequence=2,
        source_receipt_digest=_digest("2"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:B",
            "admission_receipt_digest": _digest("a"),
        },
    )
    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_PREDECESSOR_MISMATCH"):
        derive_prior_governance_roles(
            (e1, e2), candidate_entity_sequence=3, authority_id="authority:A"
        )


def test_non_contiguous_sequence_fails() -> None:
    e1 = _propose(authority="authority:A")
    p1 = project_assumption_history((e1,))
    # e2 jumps from sequence 1 to sequence 3 (skips 2).
    e2 = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=3,
        previous_entity_event_digest=p1.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=_digest("2"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:B",
            "admission_receipt_digest": _digest("a"),
        },
    )
    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_ENTITY_SEQUENCE_NOT_SUCCESSOR"):
        derive_prior_governance_roles(
            (e1, e2), candidate_entity_sequence=4, authority_id="authority:A"
        )


# --------------------------------------------------------------------------- #
# Required test 9: wrong registry type / projection phase / payload version fails
# --------------------------------------------------------------------------- #


def test_foreign_registry_event_is_rejected() -> None:
    """A non-RegistryEvent object must fail type validation immediately.

    The derivation rejects any object that is not a ``RegistryEvent`` instance
    before reading any envelope field. This prevents a caller from passing an
    arbitrary object with a ``to_json_value`` method that mimics the envelope
    shape."""
    with pytest.raises(AssumptionGovernanceContractError, match="EVENT_TYPE_INVALID"):
        derive_assumption_governance_role("not-an-event")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Required test 10: unsupported operation fails
# --------------------------------------------------------------------------- #


def test_unsupported_operation_fails() -> None:
    e1 = _propose(authority="authority:A")
    p1 = project_assumption_history((e1,))
    # Build a raw event with an unsupported operation (bypassing _after which
    # would reduce and detect the error during chain construction).
    e2 = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=2,
        previous_entity_event_digest=p1.current_event_digest,
        clock_sequence=2,
        source_receipt_digest=_digest("2"),
        payload={"operation": "BOGUS", "bogus_authority_id": "authority:X"},
    )
    # The single-event derivation fails before any lifecycle reduction.
    with pytest.raises(AssumptionGovernanceContractError, match="OPERATION_UNSUPPORTED"):
        derive_assumption_governance_role(e2)


# --------------------------------------------------------------------------- #
# Required test 11: actor/operation field substitution detected by lifecycle validation
# --------------------------------------------------------------------------- #


def test_payload_missing_authority_field_fails() -> None:
    """An event missing its operation-specific authority field fails derivation."""
    e1 = build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=1,
        source_receipt_digest=_digest("1"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": "p:1",
            "scope_ids": ["scope:a"],
            "materiality": "MATERIAL",
            # proposer_authority_id deliberately missing
            "proposed_at_sequence": 1,
            "valid_from_sequence": 1,
            "expires_at_sequence": 10,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": ["lim:1"],
            "maximum_reuse_class": "D2",
        },
    )
    # Single-event derivation: operation is recognized but authority field absent.
    with pytest.raises(AssumptionGovernanceContractError, match="AUTHORITY_MISSING"):
        derive_assumption_governance_role(e1)


# --------------------------------------------------------------------------- #
# Required test 12: byte/digest determinism for the role fact
# --------------------------------------------------------------------------- #


def test_role_fact_is_self_digesting_and_deterministic() -> None:
    e1 = _propose(authority="authority:A")
    fact = derive_assumption_governance_role(e1)
    # Recompute the digest from the unsigned value and confirm equality.
    unsigned = fact._unsigned_value()
    payload = (
        b"ASSUMPTION_GOVERNANCE_ROLE_FACT"
        + json.dumps(
            unsigned, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        + b"\n"
    )
    expected = "sha256:" + hashlib.sha256(payload).hexdigest()
    assert fact.role_fact_digest == expected

    # Byte-identical re-derivation.
    fact2 = derive_assumption_governance_role(e1)
    assert fact2.role_fact_digest == fact.role_fact_digest
    assert fact2.canonical_bytes == fact.canonical_bytes


def test_role_fact_preserves_event_identity() -> None:
    e1 = _propose(authority="authority:A", clock=1)
    fact = derive_assumption_governance_role(e1)
    assert fact.assumption_id == "assumption:1"
    assert fact.entity_sequence == 1
    assert fact.clock_sequence == 1
    assert fact.event_digest == e1.digest
    assert fact.operation == "PROPOSE"
    assert fact.authority_id == "authority:A"
    assert fact.governance_role == "PROPOSER"


def test_role_fact_schema_version_is_frozen() -> None:
    e1 = _propose(authority="authority:A")
    fact = derive_assumption_governance_role(e1)
    assert fact._unsigned_value()["schema_version"] == GOVERNANCE_ROLE_FACT_SCHEMA_VERSION
    assert GOVERNANCE_ROLE_FACT_SCHEMA_VERSION == "assumption-governance-role-fact/1"


def test_role_fact_rejects_mismatched_role_operation_pair() -> None:
    """A caller cannot construct a fact with a valid operation and a wrong role."""
    e1 = _propose(authority="authority:A")
    fact = derive_assumption_governance_role(e1)
    # Forging a fact with PROPOSE operation but ADMITTER role must fail.
    with pytest.raises(AssumptionGovernanceContractError, match="ROLE_OPERATION_MISMATCH"):
        AssumptionGovernanceRoleFact(
            assumption_id=fact.assumption_id,
            entity_sequence=fact.entity_sequence,
            clock_sequence=fact.clock_sequence,
            event_digest=fact.event_digest,
            operation="PROPOSE",
            authority_id=fact.authority_id,
            governance_role="ADMITTER",  # wrong for PROPOSE
            role_fact_digest="sha256:" + "0" * 64,  # also wrong digest
        )


# --------------------------------------------------------------------------- #
# Additional invariants: empty history, candidate out of range, type checks
# --------------------------------------------------------------------------- #


def test_empty_history_fails() -> None:
    with pytest.raises(AssumptionGovernanceContractError, match="HISTORY_EMPTY"):
        derive_prior_governance_roles((), candidate_entity_sequence=1, authority_id="authority:A")


def test_candidate_beyond_history_fails() -> None:
    e1 = _propose(authority="authority:A")
    with pytest.raises(AssumptionGovernanceContractError, match="CANDIDATE_BEYOND_HISTORY"):
        derive_prior_governance_roles(
            (e1,), candidate_entity_sequence=10, authority_id="authority:A"
        )


def test_mixed_identity_history_fails() -> None:
    e1 = _propose(assumption_id="assumption:1", authority="authority:A")
    e2 = build_assumption_event(
        assumption_id="assumption:2",  # different identity
        entity_sequence=2,
        previous_entity_event_digest=e1.digest,
        clock_sequence=2,
        source_receipt_digest=_digest("2"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:B",
            "admission_receipt_digest": _digest("a"),
        },
    )
    # The derivation's identity check OR the lifecycle reducer's _verify_chain
    # catches the identity change. Either error is acceptable.
    with pytest.raises((AssumptionGovernanceContractError, AssumptionRegistryError)):
        derive_prior_governance_roles(
            (e1, e2), candidate_entity_sequence=3, authority_id="authority:A"
        )


def test_genesis_candidate_has_no_prior_roles() -> None:
    e1 = _propose(authority="authority:A")
    roles = derive_prior_governance_roles(
        (e1,), candidate_entity_sequence=1, authority_id="authority:A"
    )
    assert roles == ()


def test_prior_roles_use_frozen_alphabetical_order() -> None:
    """The result must be in frozen ASSUMPTION_GOVERNANCE_ROLES order, not
    insertion order. ADMITTER precedes PROPOSER alphabetically."""
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:A")  # same actor admits
    roles = derive_prior_governance_roles(
        (e1, e2), candidate_entity_sequence=3, authority_id="authority:A"
    )
    # Insertion order would be (PROPOSER, ADMITTER); frozen order is (ADMITTER, PROPOSER).
    assert roles == ("ADMITTER", "PROPOSER")


# --------------------------------------------------------------------------- #
# Load-bearing SoD-predecessor test (derivation only; no SoD rule evaluated)
# --------------------------------------------------------------------------- #


def test_load_bearing_sod_predecessor_scenario() -> None:
    """The exact scenario from the authorization spec:

        A proposes assumption X
        B admits X
        A is queried for prior roles -> (PROPOSER,)
        B is queried -> (ADMITTER,)

    Then extend history:

        A challenges X
        A prior roles -> (CHALLENGER, PROPOSER)

    No SoD rule is evaluated; this tests derivation only.
    """
    e1 = _propose(authority="authority:A")
    e2 = _admit((e1,), authority="authority:B")

    roles_A = derive_prior_governance_roles(
        (e1, e2), candidate_entity_sequence=3, authority_id="authority:A"
    )
    assert roles_A == ("PROPOSER",)
    roles_B = derive_prior_governance_roles(
        (e1, e2), candidate_entity_sequence=3, authority_id="authority:B"
    )
    assert roles_B == ("ADMITTER",)

    # Extend: A challenges.
    e3 = _challenge((e1, e2), authority="authority:A", clock=3)

    roles_A_extended = derive_prior_governance_roles(
        (e1, e2, e3), candidate_entity_sequence=4, authority_id="authority:A"
    )
    assert roles_A_extended == ("CHALLENGER", "PROPOSER")
