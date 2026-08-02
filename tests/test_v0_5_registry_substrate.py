from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    InMemoryRegistryStore,
    RegistryStoreConflictError,
    RegistryStoreError,
    build_registry_event,
)


def test_registry_append_reconstruct_and_restart(tmp_path: Path) -> None:
    store = FilesystemRegistryStore(tmp_path)
    first = _event("EVIDENCE_UNIT", "evidence-1", 1, None, "REGISTERED")
    second = _event("EVIDENCE_UNIT", "evidence-1", 2, first.digest, "VERIFIED")

    assert store.append(first).applied
    assert store.append(second).applied
    duplicate = store.append(second)
    assert not duplicate.applied
    assert duplicate.reason == "IDEMPOTENT_APPEND"

    chain = store.reconstruct_entity("EVIDENCE_UNIT", "evidence-1")
    assert tuple(item.digest for item in chain) == (first.digest, second.digest)

    restarted = FilesystemRegistryStore(tmp_path)
    assert restarted.snapshot("EVIDENCE_UNIT") == store.snapshot("EVIDENCE_UNIT")
    assert restarted.reconstruct_entity("EVIDENCE_UNIT", "evidence-1") == chain


def test_registry_root_is_independent_of_entity_append_order() -> None:
    events = (
        _event("ASSUMPTION", "assumption-a", 1, None, "PROPOSED"),
        _event("ASSUMPTION", "assumption-b", 1, None, "PROPOSED"),
        _event("ASSUMPTION", "assumption-c", 1, None, "PROPOSED"),
    )
    left = InMemoryRegistryStore()
    right = InMemoryRegistryStore()
    for event in events:
        left.append(event)
    for event in reversed(events):
        right.append(event)
    assert left.snapshot("ASSUMPTION") == right.snapshot("ASSUMPTION")
    assert left.reconstruct_snapshot("ASSUMPTION") == right.reconstruct_snapshot("ASSUMPTION")


def test_registry_rejects_sequence_and_predecessor_conflicts() -> None:
    store = InMemoryRegistryStore()
    first = _event("ALTERNATIVE_MODEL", "model-1", 1, None, "ADMITTED")
    store.append(first)

    with pytest.raises(RegistryStoreConflictError) as sequence:
        store.append(_event("ALTERNATIVE_MODEL", "model-1", 3, first.digest, "CHALLENGED"))
    assert sequence.value.code == "REGISTRY_SEQUENCE_CONFLICT"

    with pytest.raises(RegistryStoreConflictError) as predecessor:
        store.append(
            _event(
                "ALTERNATIVE_MODEL",
                "model-1",
                2,
                _digest("wrong-predecessor"),
                "CHALLENGED",
            )
        )
    assert predecessor.value.code == "REGISTRY_PREDECESSOR_CONFLICT"


def test_registry_type_and_projection_phase_are_bound() -> None:
    event = _event("EVIDENCE_UNIT", "evidence-1", 1, None, "REGISTERED")
    malformed = cast(
        RegistryEvent,
        event.with_updates(projection_phase="ASSUMPTION_REGISTRY"),
    )
    with pytest.raises(RegistryStoreError) as exc:
        InMemoryRegistryStore().append(malformed)
    assert exc.value.code == "REGISTRY_PROJECTION_PHASE_MISMATCH"


def test_entity_ids_cannot_escape_registry_root(tmp_path: Path) -> None:
    store = FilesystemRegistryStore(tmp_path)
    entity_id = "entity/../../../../registry-path-escape-sentinel"
    event = _event("EVIDENCE_UNIT", entity_id, 1, None, "REGISTERED")
    store.append(event)

    unsafe = store.heads / "evidence_unit" / entity_id
    assert not unsafe.exists()
    paths = list((store.heads / "evidence_unit").glob("*.json"))
    assert len(paths) == 1
    assert paths[0].resolve().is_relative_to(store.heads.resolve())


def test_corrupted_head_fails_closed(tmp_path: Path) -> None:
    store = FilesystemRegistryStore(tmp_path)
    event = _event("ASSUMPTION", "assumption-1", 1, None, "PROPOSED")
    store.append(event)
    head_path = next((store.heads / "assumption").glob("*.json"))
    value = json.loads(head_path.read_text(encoding="utf-8"))
    value["entity_sequence"] = 2
    head_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(RegistryStoreConflictError) as exc:
        store.snapshot("ASSUMPTION")
    assert exc.value.code == "REGISTRY_HEAD_DIGEST_INVALID"


def test_registry_types_have_independent_roots() -> None:
    store = InMemoryRegistryStore()
    store.append(_event("EVIDENCE_UNIT", "shared-id", 1, None, "REGISTERED"))
    store.append(_event("ASSUMPTION", "shared-id", 1, None, "PROPOSED"))
    store.append(_event("ALTERNATIVE_MODEL", "shared-id", 1, None, "ADMITTED"))
    roots = {
        store.snapshot("EVIDENCE_UNIT").root_digest,
        store.snapshot("ASSUMPTION").root_digest,
        store.snapshot("ALTERNATIVE_MODEL").root_digest,
    }
    assert len(roots) == 3


def _event(
    registry_type: str,
    entity_id: str,
    sequence: int,
    previous: str | None,
    operation: str,
) -> RegistryEvent:
    return build_registry_event(
        registry_type=registry_type,
        entity_id=entity_id,
        entity_sequence=sequence,
        previous_entity_event_digest=previous,
        clock_sequence=sequence,
        source_receipt_digest=_digest(f"source:{registry_type}:{entity_id}:{sequence}"),
        payload_schema_version="registry-test-payload/1",
        payload={"operation": operation, "authority_id": "authority-I3"},
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
