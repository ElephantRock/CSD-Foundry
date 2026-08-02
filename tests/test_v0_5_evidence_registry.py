from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from csd_foundry.governance.v0_5.evidence import (
    EvidenceRegistry,
    EvidenceRegistryError,
    build_evidence_event,
    project_evidence_history,
    reduce_evidence,
)
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    InMemoryRegistryStore,
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _register(
    evidence_id: str = "evidence:1",
    *,
    clock_sequence: int = 1,
    expires_at_sequence: int | None = 10,
    scope_ids: list[str] | None = None,
    dependency_ids: list[str] | None = None,
):
    return build_evidence_event(
        evidence_id=evidence_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock_sequence,
        source_receipt_digest=_digest(f"register:{evidence_id}"),
        payload={
            "operation": "REGISTER",
            "proposition_id": "control.connected",
            "scope_ids": ["control:17"] if scope_ids is None else scope_ids,
            "source_id": "assessment:42",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": clock_sequence,
            "valid_from_sequence": clock_sequence,
            "expires_at_sequence": expires_at_sequence,
            "dependency_ids": [] if dependency_ids is None else dependency_ids,
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _next(previous, operation: str, clock_sequence: int, **payload: object):
    return build_evidence_event(
        evidence_id=previous.evidence_id,
        entity_sequence=previous.current_entity_sequence + 1,
        previous_entity_event_digest=previous.current_event_digest,
        clock_sequence=clock_sequence,
        source_receipt_digest=_digest(f"{operation}:{clock_sequence}"),
        payload={"operation": operation, **payload},
    )


def _verified(registry: EvidenceRegistry):
    registered = registry.apply(_register())
    verified = registry.apply(
        _next(
            registered,
            "VERIFY",
            2,
            verifier_authority_id="authority:verifier",
        )
    )
    return registered, verified


def test_register_and_verify_are_deterministic_and_reconstructable() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    registered, verified = _verified(registry)

    assert registered.status == "REGISTERED"
    assert registered.verifier_authority_id is None
    assert verified.status == "VERIFIED"
    assert verified.verifier_authority_id == "authority:verifier"
    assert verified.proposition_id == registered.proposition_id
    assert verified.scope_ids == registered.scope_ids
    assert verified.registration_source_receipt_digest == (
        registered.registration_source_receipt_digest
    )
    assert registry.current("evidence:1") == verified


def test_exact_event_replay_is_idempotent() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    event = _register()

    first = registry.apply(event)
    second = registry.apply(event)

    assert first == second
    assert second.current_entity_sequence == 1


def test_challenge_can_be_upheld_without_rewriting_registration() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    _, verified = _verified(registry)
    challenged = registry.apply(
        _next(
            verified,
            "CHALLENGE",
            3,
            challenger_authority_id="authority:challenger",
            challenge_reason_code="SOURCE_RELIABILITY_DISPUTED",
            challenge_receipt_digest=_digest("challenge"),
        )
    )
    upheld = registry.apply(
        _next(
            challenged,
            "RESOLVE_CHALLENGE",
            4,
            resolution="UPHOLD",
            resolver_authority_id="authority:resolver",
            resolution_receipt_digest=_digest("resolution:uphold"),
        )
    )

    assert challenged.status == "CHALLENGED"
    assert challenged.active_challenge_digest == _digest("challenge")
    assert upheld.status == "VERIFIED"
    assert upheld.active_challenge_digest is None
    assert upheld.proposition_id == verified.proposition_id
    assert upheld.registration_source_receipt_digest == (
        verified.registration_source_receipt_digest
    )


def test_challenge_can_terminate_as_invalidated() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    _, verified = _verified(registry)
    challenged = registry.apply(
        _next(
            verified,
            "CHALLENGE",
            3,
            challenger_authority_id="authority:challenger",
            challenge_reason_code="PROVENANCE_CONFLICT",
            challenge_receipt_digest=_digest("challenge:invalidate"),
        )
    )
    invalidated = registry.apply(
        _next(
            challenged,
            "RESOLVE_CHALLENGE",
            4,
            resolution="INVALIDATE",
            resolver_authority_id="authority:resolver",
            resolution_receipt_digest=_digest("resolution:invalidate"),
        )
    )

    assert invalidated.status == "INVALIDATED"
    assert invalidated.terminal
    resurrection = _next(
        invalidated,
        "VERIFY",
        5,
        verifier_authority_id="authority:verifier",
    )
    with pytest.raises(EvidenceRegistryError) as exc:
        registry.apply(resurrection)
    assert exc.value.code == "EVIDENCE_TERMINAL_IDENTITY_REUSE"


def test_expiry_requires_declared_due_sequence_and_is_terminal() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    _, verified = _verified(registry)
    premature = _next(
        verified,
        "EXPIRE",
        9,
        expiry_authority_id="authority:clock",
    )
    with pytest.raises(EvidenceRegistryError) as exc:
        registry.apply(premature)
    assert exc.value.code == "EVIDENCE_EXPIRY_PREMATURE"

    expired = registry.apply(
        _next(
            verified,
            "EXPIRE",
            10,
            expiry_authority_id="authority:clock",
        )
    )
    assert expired.status == "EXPIRED"
    assert expired.terminal


def test_supersession_uses_distinct_replacement_identity() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    _, verified = _verified(registry)
    superseded = registry.apply(
        _next(
            verified,
            "SUPERSEDE",
            3,
            replacement_evidence_id="evidence:2",
            superseding_authority_id="authority:issuer",
            reason_code="REASSESSMENT_COMPLETED",
        )
    )
    replacement = registry.apply(_register("evidence:2", clock_sequence=4))

    assert superseded.status == "SUPERSEDED"
    assert superseded.superseded_by_id == "evidence:2"
    assert superseded.terminal
    assert replacement.status == "REGISTERED"
    assert replacement.evidence_id != superseded.evidence_id


def test_reject_is_terminal_and_only_valid_from_registered() -> None:
    registry = EvidenceRegistry(InMemoryRegistryStore())
    registered = registry.apply(_register())
    rejected = registry.apply(
        _next(
            registered,
            "REJECT",
            2,
            rejecting_authority_id="authority:verifier",
            reason_code="SOURCE_UNACCEPTABLE",
        )
    )
    assert rejected.status == "REJECTED"
    assert rejected.terminal


def test_registration_requires_sorted_unique_scope_and_no_self_dependency() -> None:
    with pytest.raises(EvidenceRegistryError) as scope_exc:
        reduce_evidence(None, _register(scope_ids=["scope:b", "scope:a"]))
    assert scope_exc.value.code == "EVIDENCE_SCOPE_INVALID"

    with pytest.raises(EvidenceRegistryError) as dependency_exc:
        reduce_evidence(None, _register(dependency_ids=["evidence:1"]))
    assert dependency_exc.value.code == "EVIDENCE_SELF_DEPENDENCY"


def test_registration_clock_and_validity_are_bound() -> None:
    event = build_evidence_event(
        evidence_id="evidence:clock",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=3,
        source_receipt_digest=_digest("register:clock"),
        payload={
            "operation": "REGISTER",
            "proposition_id": "control.connected",
            "scope_ids": ["control:17"],
            "source_id": "assessment:42",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": 2,
            "valid_from_sequence": 2,
            "expires_at_sequence": 10,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    with pytest.raises(EvidenceRegistryError) as exc:
        reduce_evidence(None, event)
    assert exc.value.code == "EVIDENCE_ISSUANCE_CLOCK_MISMATCH"


def test_payload_fields_are_operation_specific_and_closed() -> None:
    registered = reduce_evidence(None, _register())
    event = _next(
        registered,
        "VERIFY",
        2,
        verifier_authority_id="authority:verifier",
        unexpected="field",
    )
    with pytest.raises(EvidenceRegistryError) as exc:
        reduce_evidence(registered, event)
    assert exc.value.code == "EVIDENCE_PAYLOAD_KEYS_INVALID"


def test_history_projection_is_byte_order_stable_across_restart(tmp_path: Path) -> None:
    store = FilesystemRegistryStore(tmp_path)
    registry = EvidenceRegistry(store)
    _, verified = _verified(registry)
    challenged = registry.apply(
        _next(
            verified,
            "CHALLENGE",
            3,
            challenger_authority_id="authority:challenger",
            challenge_reason_code="SOURCE_RELIABILITY_DISPUTED",
            challenge_receipt_digest=_digest("challenge:restart"),
        )
    )
    first_root = store.snapshot("EVIDENCE_UNIT").root_digest
    history = store.reconstruct_entity("EVIDENCE_UNIT", "evidence:1")

    restarted_store = FilesystemRegistryStore(tmp_path)
    restarted_registry = EvidenceRegistry(restarted_store)

    assert restarted_store.snapshot("EVIDENCE_UNIT").root_digest == first_root
    assert project_evidence_history(history) == challenged
    assert restarted_registry.current("evidence:1") == challenged
