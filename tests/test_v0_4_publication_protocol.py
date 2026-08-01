from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from csd_foundry.synthesis.v0_4.publication_protocol import (
    AttemptCompletionEnvelope,
    InventoryCompletionReference,
    OperationalPublicationReceipt,
    PublicationDisposition,
    PublicationObjectKind,
    PublicationProtocolError,
    validate_publication_receipt_chain,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    InjectedPublicationCrash,
    PublicationCorruptionError,
)
from csd_foundry.synthesis.v0_4.publication_validation import (
    generate_publication_protocol_digests,
    publication_fixture_accepted,
    publication_fixture_inventory,
    publication_fixture_rejected,
    validate_publication_protocol,
)
from csd_foundry.synthesis.v0_4.publication_vectors import (
    EXPECTED_PUBLICATION_DIGESTS,
    FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST,
    publication_vector_catalog_commitment,
    validate_publication_vector_catalog,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


def test_completion_envelope_is_topology_independent() -> None:
    inventory = publication_fixture_inventory()
    completion = publication_fixture_accepted()
    first = AttemptCompletionEnvelope.from_completion(completion)
    second = AttemptCompletionEnvelope.from_completion(completion)
    assert first == second
    assert first.canonical_bytes == second.canonical_bytes
    assert {
        "execution_run_id",
        "inventory_digest",
        "worker_id",
        "retry_count",
        "timestamp",
        "shard_index",
        "publication_state",
    }.isdisjoint(first.to_json_value())

    receipt_a = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-a",
        inventory_digest=inventory.digest,
        attempt_key=first.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=first.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    receipt_b = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-b",
        inventory_digest=inventory.digest,
        attempt_key=first.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=first.digest,
        disposition=PublicationDisposition.EXISTING_IDENTICAL,
    )
    assert receipt_a.digest != receipt_b.digest
    assert AttemptCompletionEnvelope.from_completion(completion).digest == first.digest


def test_completion_envelope_accepts_only_semantic_completion_contracts() -> None:
    accepted = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    rejected = AttemptCompletionEnvelope.from_completion(publication_fixture_rejected())
    assert accepted.completion_status.value == "accepted"
    assert rejected.completion_status.value == "rejected"
    with pytest.raises(PublicationProtocolError):
        AttemptCompletionEnvelope.from_completion(object())  # type: ignore[arg-type]


def test_inventory_reference_binds_authority_without_changing_envelope() -> None:
    inventory = publication_fixture_inventory()
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    reference = InventoryCompletionReference.from_inventory(inventory, envelope)
    reference.validate_against(inventory, envelope)
    assert reference.inventory_digest == inventory.digest
    assert reference.global_ordinal == 0
    assert reference.completion_envelope_digest == envelope.digest
    assert (
        envelope.digest
        == AttemptCompletionEnvelope.from_completion(publication_fixture_accepted()).digest
    )


def test_publication_receipts_are_append_only_operational_evidence() -> None:
    inventory = publication_fixture_inventory()
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    reference = InventoryCompletionReference.from_inventory(inventory, envelope)
    first = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-publication",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=envelope.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    second = OperationalPublicationReceipt.append(
        previous=first,
        execution_run_id="run-publication",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
        object_digest=reference.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    assert validate_publication_receipt_chain((first, second)) == (first, second)
    with pytest.raises(PublicationProtocolError):
        validate_publication_receipt_chain(
            (
                first,
                replace(
                    second,
                    previous_publication_receipt_digest=canonical_sha256({"broken": True}),
                ),
            )
        )


def test_content_addressed_store_is_no_clobber_and_idempotent(tmp_path: Path) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)
    first = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)
    second = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)
    assert first.disposition is PublicationDisposition.PUBLISHED
    assert second.disposition is PublicationDisposition.EXISTING_IDENTICAL
    assert first.relative_path == f"objects/{envelope.digest[:2]}/{envelope.digest[2:]}"
    assert store.read_verified(envelope.digest) == envelope.canonical_bytes


def test_store_fsyncs_new_directory_ancestors_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr(
        ContentAddressedPublicationStore,
        "_fsync_directory",
        staticmethod(synced.append),
    )
    root = tmp_path / "publication"
    store = ContentAddressedPublicationStore(root)
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    final_parent = store.object_path(envelope.digest).parent
    assert root in synced
    assert root.parent in synced
    assert store.objects_root in synced
    assert final_parent in synced


def test_duplicate_existing_success_fsyncs_authoritative_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)
    store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    synced: list[Path] = []
    monkeypatch.setattr(
        ContentAddressedPublicationStore,
        "_fsync_directory",
        staticmethod(synced.append),
    )
    result = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    assert result.disposition is PublicationDisposition.EXISTING_IDENTICAL
    assert store.object_path(envelope.digest).parent in synced


def test_concurrent_duplicate_race_fsyncs_authoritative_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)
    original_link = os.link

    def racing_link(source: Path, destination: Path) -> None:
        original_link(source, destination)
        raise FileExistsError(destination)

    synced: list[Path] = []
    monkeypatch.setattr(os, "link", racing_link)
    monkeypatch.setattr(
        ContentAddressedPublicationStore,
        "_fsync_directory",
        staticmethod(synced.append),
    )
    result = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    assert result.disposition is PublicationDisposition.EXISTING_IDENTICAL
    assert store.object_path(envelope.digest).parent in synced
    assert store.read_verified(envelope.digest) == envelope.canonical_bytes


def test_content_addressed_store_rejects_corrupted_existing_object(tmp_path: Path) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)
    path = store.object_path(envelope.digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"corrupt\n")
    with pytest.raises(PublicationCorruptionError):
        store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)


@pytest.mark.parametrize(
    "stage",
    ("temporary-created", "content-written", "file-synced", "object-installed"),
)
def test_crash_recovery_never_exposes_partial_authority(tmp_path: Path, stage: str) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)

    def inject(current: str) -> None:
        if current == stage:
            raise InjectedPublicationCrash(current)

    with pytest.raises(InjectedPublicationCrash):
        store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
            fault_injector=inject,
        )

    report = store.recover()
    assert not tuple(store.temporary_root.glob("*.tmp"))
    if stage == "object-installed":
        assert store.read_verified(envelope.digest) == envelope.canonical_bytes
        assert report.authoritative_objects_verified == 1
    else:
        assert not store.object_path(envelope.digest).exists()


def test_publication_vectors_and_report_are_frozen() -> None:
    validate_publication_vector_catalog()
    assert generate_publication_protocol_digests() == EXPECTED_PUBLICATION_DIGESTS
    report = validate_publication_protocol("v0.4")
    assert report.success
    assert report.vectors_passed == report.vector_count == 5
    assert report.semantic_envelope_topology_independent
    assert report.no_clobber_enforced
    assert report.crash_debris_recoverable


def test_publication_catalog_commitment_covers_expected_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST
    monkeypatch.setitem(
        EXPECTED_PUBLICATION_DIGESTS,
        "accepted-completion-envelope",
        "0" * 64,
    )
    assert canonical_sha256(publication_vector_catalog_commitment()) != original
    with pytest.raises(ValueError, match="catalog digest changed"):
        validate_publication_vector_catalog()
