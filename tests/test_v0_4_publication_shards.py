from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest
from jsonschema import Draft202012Validator

from csd_foundry.synthesis.v0_4.publication_protocol import AttemptCompletionEnvelope
from csd_foundry.synthesis.v0_4.publication_shards import (
    SealedShardManifest,
    ShardIndex,
    ShardPublicationCoordinator,
    ShardPublicationError,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    InjectedPublicationCrash,
    PublicationStoreError,
)
from csd_foundry.synthesis.v0_4.publication_validation import (
    publication_fixture_accepted,
    publication_fixture_inventory,
)


def _publications(
    store: ContentAddressedPublicationStore,
    *,
    shard_count: int = 2,
    sample_count: int = 3,
):
    inventory = publication_fixture_inventory(
        shard_count=shard_count,
        sample_count=sample_count,
    )
    coordinator = ShardPublicationCoordinator(store)
    publications = tuple(
        coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(sample_index),
            execution_run_id=f"run-shard-test-{sample_index}",
        )
        for sample_index in range(sample_count)
    )
    return inventory, coordinator, publications


def test_cross_run_duplicate_receipts_report_existing_identical(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    coordinator = ShardPublicationCoordinator(store)
    first = coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id="run-first",
    )
    duplicate = coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id="run-duplicate",
    )

    assert all(receipt.disposition.value == "published" for receipt in first.receipts)
    assert all(receipt.disposition.value == "existing-identical" for receipt in duplicate.receipts)
    assert first.envelope.digest == duplicate.envelope.digest
    assert first.reference.digest == duplicate.reference.digest
    assert tuple(receipt.digest for receipt in first.receipts) != tuple(
        receipt.digest for receipt in duplicate.receipts
    )


def test_concurrent_same_run_retries_converge_on_one_receipt_chain(
    tmp_path: Path,
) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    coordinator = ShardPublicationCoordinator(store)
    worker_count = 8
    barrier = Barrier(worker_count)

    def publish() -> tuple[str, str]:
        barrier.wait()
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id="run-concurrent-same",
        )
        return tuple(receipt.digest for receipt in publication.receipts)  # type: ignore[return-value]

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        receipt_chains = tuple(executor.map(lambda _: publish(), range(worker_count)))

    assert len(set(receipt_chains)) == 1


def test_same_run_reused_receipts_are_directory_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    coordinator = ShardPublicationCoordinator(store)
    first = coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id="run-durable-reuse",
    )

    synced: list[Path] = []
    monkeypatch.setattr(
        ContentAddressedPublicationStore,
        "_fsync_directory",
        staticmethod(synced.append),
    )
    second = coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id="run-durable-reuse",
    )

    assert tuple(receipt.digest for receipt in first.receipts) == tuple(
        receipt.digest for receipt in second.receipts
    )
    for receipt in second.receipts:
        assert store.object_path(receipt.digest).parent in synced


def test_shard_index_is_completion_order_independent(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory, _, publications = _publications(store)
    shard_zero = tuple(
        publication
        for publication in publications
        if publication.reference.global_ordinal % inventory.shard_count == 0
    )
    first = ShardIndex.from_publications(inventory, 0, shard_zero)
    second = ShardIndex.from_publications(inventory, 0, tuple(reversed(shard_zero)))
    assert first == second
    assert first.digest == second.digest
    assert tuple(entry.global_ordinal for entry in first.entries) == (0, 2)


def test_shard_index_deduplicates_identical_and_rejects_conflict(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory, _, publications = _publications(store)
    shard_zero = tuple(
        publication
        for publication in publications
        if publication.reference.global_ordinal % inventory.shard_count == 0
    )
    index = ShardIndex.from_publications(inventory, 0, shard_zero)
    duplicate = ShardIndex.from_entries(
        inventory,
        0,
        index.entries + (index.entries[0],),
    )
    assert duplicate == index
    conflict = replace(index.entries[0], completion_envelope_digest="0" * 64)
    with pytest.raises(ShardPublicationError, match="conflicting completions"):
        ShardIndex.from_entries(inventory, 0, index.entries + (conflict,))


def test_manifest_seal_requires_durable_verified_index_and_objects(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory, coordinator, publications = _publications(store)
    shard_zero = tuple(
        publication
        for publication in publications
        if publication.reference.global_ordinal % inventory.shard_count == 0
    )
    index = ShardIndex.from_publications(inventory, 0, shard_zero)
    with pytest.raises((ShardPublicationError, PublicationStoreError)):
        SealedShardManifest.seal(inventory, index, shard_zero, store)

    published = coordinator.publish_shard(inventory, 0, shard_zero)
    assert published.manifest.sealed
    assert published.manifest.shard_index_digest == published.index.digest
    assert store.reference_exists_verified(
        category="seals",
        inventory_digest=inventory.digest,
        shard_index=0,
        digest=published.manifest.digest,
    )


def test_shard_manifest_schema_accepts_factory_sealed_manifest(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory, coordinator, publications = _publications(store)
    shard_zero = tuple(
        publication
        for publication in publications
        if publication.reference.global_ordinal % inventory.shard_count == 0
    )
    manifest = coordinator.publish_shard(inventory, 0, shard_zero).manifest
    schema_path = Path(__file__).resolve().parents[1] / "specs/v0.4/shard_manifest.schema.json"
    import json

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest.to_json_value())


def test_semantic_envelope_is_stable_across_1_2_7_shard_inventories() -> None:
    completion = publication_fixture_accepted(0)
    expected = AttemptCompletionEnvelope.from_completion(completion).digest
    for shard_count in (1, 2, 7):
        inventory = publication_fixture_inventory(shard_count=shard_count)
        envelope = AttemptCompletionEnvelope.from_completion(completion)
        assert envelope.digest == expected
        assert inventory.generation_namespace_digest == envelope.generation_namespace_digest


@pytest.mark.parametrize(
    "stage",
    (
        "completion-claim-persisted",
        "completion-object-persisted",
        "completion-receipt-persisted",
        "reference-claim-persisted",
        "reference-object-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
        "shard-manifest-persisted",
        "shard-seal-published",
    ),
)
def test_staged_publication_is_crash_idempotent(tmp_path: Path, stage: str) -> None:
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    run_id = f"run-{stage}"

    baseline_store = ContentAddressedPublicationStore(tmp_path / "baseline")
    baseline_coordinator = ShardPublicationCoordinator(baseline_store)
    baseline_publication = baseline_coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id=run_id,
    )
    baseline_shard = baseline_coordinator.publish_shard(
        inventory,
        0,
        (baseline_publication,),
    )

    store = ContentAddressedPublicationStore(tmp_path / "subject")
    coordinator = ShardPublicationCoordinator(store)

    def inject(current: str) -> None:
        if current == stage:
            raise InjectedPublicationCrash(current)

    completion_stages = {
        "completion-claim-persisted",
        "completion-object-persisted",
        "completion-receipt-persisted",
        "reference-claim-persisted",
        "reference-object-persisted",
        "reference-receipt-persisted",
    }
    if stage in completion_stages:
        with suppress(InjectedPublicationCrash):
            coordinator.publish_completion(
                inventory,
                publication_fixture_accepted(0),
                execution_run_id=run_id,
                fault_injector=inject,
            )
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id=run_id,
        )
    else:
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id=run_id,
        )
        with suppress(InjectedPublicationCrash):
            coordinator.publish_shard(
                inventory,
                0,
                (publication,),
                fault_injector=inject,
            )

    assert tuple(receipt.digest for receipt in publication.receipts) == tuple(
        receipt.digest for receipt in baseline_publication.receipts
    )
    published = coordinator.publish_shard(inventory, 0, (publication,))
    assert published.index.digest == baseline_shard.index.digest
    assert published.manifest.digest == baseline_shard.manifest.digest
    assert store.reference_exists_verified(
        category="seals",
        inventory_digest=inventory.digest,
        shard_index=0,
        digest=published.manifest.digest,
    )
