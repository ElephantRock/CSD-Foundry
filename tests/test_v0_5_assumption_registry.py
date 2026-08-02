from __future__ import annotations

from pathlib import Path

import pytest

from csd_foundry.governance.v0_5.assumption import (
    DERIVED_CHALLENGED,
    STANDING_ADMITTED,
    STANDING_CONFIRMED,
    STANDING_EXPIRED,
    STANDING_SUPERSEDED,
    AssumptionRegistry,
    AssumptionRegistryError,
    build_assumption_event,
    project_assumption_history,
)
from csd_foundry.governance.v0_5.registry import FilesystemRegistryStore, InMemoryRegistryStore


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _propose(
    *,
    assumption_id: str = "assumption:1",
    clock: int = 1,
    expires: int | None = 10,
    assumption_dependencies: list[str] | None = None,
    evidence_dependencies: list[str] | None = None,
):
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
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": expires,
            "assumption_dependency_ids": assumption_dependencies or [],
            "evidence_dependency_ids": evidence_dependencies or [],
            "limitations": ["limitation:declared-model"],
            "maximum_reuse_class": "D2",
        },
    )


def _event(previous, operation: str, clock: int, payload: dict[str, object]):
    return build_assumption_event(
        assumption_id="assumption:1",
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock,
        source_receipt_digest=_digest(str(clock % 10)),
        payload={"operation": operation, **payload},
    )


def _admit(previous, clock: int = 2):
    return _event(
        previous,
        "ADMIT",
        clock,
        {
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _digest("a"),
        },
    )


def _challenge(previous, challenge_id: str, clock: int, reason: str):
    return _event(
        previous,
        "CHALLENGE",
        clock,
        {
            "challenge_id": challenge_id,
            "challenger_authority_id": f"authority:{challenge_id}",
            "challenge_reason_code": reason,
            "challenge_receipt_digest": _digest(str(clock % 10)),
        },
    )


def _resolve(
    previous,
    *,
    clock: int,
    outcome: str,
    challenge_ids: list[str],
    replacement: str | None = None,
):
    return _event(
        previous,
        "RESOLVE_CHALLENGES",
        clock,
        {
            "resolution_outcome": outcome,
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _digest("f"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": challenge_ids,
            "replacement_assumption_id": replacement,
        },
    )


def test_multiple_challenges_are_folded_in_order_then_stored_canonically() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose())
    current = registry.apply(_admit(current))
    current = registry.apply(_challenge(current, "challenge:z", 3, "reason:z"))
    current = registry.apply(_challenge(current, "challenge:a", 4, "reason:a"))

    assert current.standing == STANDING_ADMITTED
    assert current.status == DERIVED_CHALLENGED
    assert current.active_challenge_ids == ("challenge:a", "challenge:z")
    assert current.current_entity_sequence == 4


def test_targeted_resolution_preserves_unresolved_challenges() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose())
    current = registry.apply(_admit(current))
    current = registry.apply(_challenge(current, "challenge:a", 3, "reason:a"))
    current = registry.apply(_challenge(current, "challenge:b", 4, "reason:b"))
    current = registry.apply(
        _resolve(
            current,
            clock=5,
            outcome="RETURN_TO_ADMITTED",
            challenge_ids=["challenge:a"],
        )
    )

    assert current.standing == STANDING_ADMITTED
    assert current.status == DERIVED_CHALLENGED
    assert current.active_challenge_ids == ("challenge:b",)


def test_confirm_resolution_can_leave_other_challenge_overlay_active() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose())
    current = registry.apply(_admit(current))
    current = registry.apply(_challenge(current, "challenge:a", 3, "reason:a"))
    current = registry.apply(_challenge(current, "challenge:b", 4, "reason:b"))
    current = registry.apply(
        _resolve(
            current,
            clock=5,
            outcome="CONFIRM",
            challenge_ids=["challenge:a"],
        )
    )

    assert current.standing == STANDING_CONFIRMED
    assert current.status == DERIVED_CHALLENGED
    assert current.active_challenge_ids == ("challenge:b",)


def test_resolution_rejects_unknown_challenge_identity() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose())
    current = registry.apply(_admit(current))
    current = registry.apply(_challenge(current, "challenge:a", 3, "reason:a"))

    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN"):
        registry.apply(
            _resolve(
                current,
                clock=4,
                outcome="RETURN_TO_ADMITTED",
                challenge_ids=["challenge:missing"],
            )
        )


def test_expiry_is_terminal_and_distinct_from_supersession() -> None:
    expiry_registry = AssumptionRegistry(InMemoryRegistryStore())
    expired = expiry_registry.apply(_propose(expires=5))
    expired = expiry_registry.apply(_admit(expired))
    expired = expiry_registry.apply(
        _event(
            expired,
            "EXPIRE",
            5,
            {
                "expiry_authority_id": "authority:clock",
                "expiry_receipt_digest": _digest("e"),
            },
        )
    )
    assert expired.standing == STANDING_EXPIRED
    assert expired.superseded_by_id is None

    supersession_registry = AssumptionRegistry(InMemoryRegistryStore())
    superseded = supersession_registry.apply(_propose())
    superseded = supersession_registry.apply(_admit(superseded))
    superseded = supersession_registry.apply(
        _event(
            superseded,
            "SUPERSEDE",
            3,
            {
                "replacement_assumption_id": "assumption:2",
                "superseding_authority_id": "authority:reviewer",
                "supersession_receipt_digest": _digest("s"),
                "reason_code": "reason:replacement",
            },
        )
    )
    assert superseded.standing == STANDING_SUPERSEDED
    assert superseded.superseded_by_id == "assumption:2"


def test_expiry_before_declared_sequence_fails_closed() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose(expires=8))
    current = registry.apply(_admit(current))
    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_EXPIRY_PREMATURE"):
        registry.apply(
            _event(
                current,
                "EXPIRE",
                7,
                {
                    "expiry_authority_id": "authority:clock",
                    "expiry_receipt_digest": _digest("e"),
                },
            )
        )


def test_terminal_identity_cannot_be_reactivated() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(_propose(expires=5))
    current = registry.apply(_admit(current))
    current = registry.apply(
        _event(
            current,
            "EXPIRE",
            5,
            {
                "expiry_authority_id": "authority:clock",
                "expiry_receipt_digest": _digest("e"),
            },
        )
    )
    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_TERMINAL_IDENTITY_REUSE"):
        registry.apply(_admit(current, clock=6))


def test_self_dependency_is_rejected_at_proposal() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    with pytest.raises(AssumptionRegistryError, match="ASSUMPTION_SELF_DEPENDENCY"):
        registry.apply(_propose(assumption_dependencies=["assumption:1"]))


def test_dependency_types_and_reuse_boundary_are_immutable() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    current = registry.apply(
        _propose(
            assumption_dependencies=["assumption:dependency"],
            evidence_dependencies=["evidence:dependency"],
        )
    )
    current = registry.apply(_admit(current))

    assert current.assumption_dependency_ids == ("assumption:dependency",)
    assert current.evidence_dependency_ids == ("evidence:dependency",)
    assert current.maximum_reuse_class == "D2"
    assert current.limitations == ("limitation:declared-model",)


def test_order_sensitive_history_rejects_swapped_events() -> None:
    proposed = _propose()
    initial = project_assumption_history((proposed,))
    assert initial is not None
    admitted = _admit(initial)
    admitted_state = project_assumption_history((proposed, admitted))
    assert admitted_state is not None
    challenged = _challenge(admitted_state, "challenge:a", 3, "reason:a")

    with pytest.raises(AssumptionRegistryError):
        project_assumption_history((proposed, challenged, admitted))


def test_filesystem_restart_reconstructs_challenge_overlay(tmp_path: Path) -> None:
    store = FilesystemRegistryStore(tmp_path)
    registry = AssumptionRegistry(store)
    current = registry.apply(_propose())
    current = registry.apply(_admit(current))
    current = registry.apply(_challenge(current, "challenge:b", 3, "reason:b"))
    current = registry.apply(_challenge(current, "challenge:a", 4, "reason:a"))
    expected_root = store.snapshot("ASSUMPTION").root_digest

    restarted_store = FilesystemRegistryStore(tmp_path)
    restarted = AssumptionRegistry(restarted_store).current("assumption:1")
    assert restarted is not None
    assert restarted.status == DERIVED_CHALLENGED
    assert restarted.active_challenge_ids == ("challenge:a", "challenge:b")
    assert restarted_store.snapshot("ASSUMPTION").root_digest == expected_root


def test_idempotent_append_returns_same_projection() -> None:
    registry = AssumptionRegistry(InMemoryRegistryStore())
    event = _propose()
    first = registry.apply(event)
    second = registry.apply(event)
    assert second == first
