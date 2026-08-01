"""One-shot patch for nonowner completion and exact recovery validation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"expected block not found in {path}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_store.py",
    '''        if not owned and not object_path.exists():
            raise PublicationStoreError(
                "publication object is claimed by another execution run but not installed"
            )
        result = self.publish_bytes(payload, expected_digest=digest)
''',
    '''        result = self.publish_bytes(payload, expected_digest=digest)
''',
)

old_validation = '''    recovery_idempotent = True
    for stage in stages:
        with TemporaryDirectory() as directory:
            store = ContentAddressedPublicationStore(Path(directory))
            coordinator = ShardPublicationCoordinator(store)

            def inject(current: str, *, expected: str = stage) -> None:
                if current == expected:
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
                        execution_run_id=f"run-recovery-{stage}",
                        fault_injector=inject,
                    )
                publication = coordinator.publish_completion(
                    inventory,
                    publication_fixture_accepted(0),
                    execution_run_id=f"run-recovery-{stage}",
                )
                recovery_idempotent = recovery_idempotent and (
                    publication.envelope.digest
                    == AttemptCompletionEnvelope.from_completion(
                        publication_fixture_accepted(0)
                    ).digest
                )
            else:
                publication = coordinator.publish_completion(
                    inventory,
                    publication_fixture_accepted(0),
                    execution_run_id=f"run-recovery-{stage}",
                )
                with suppress(InjectedPublicationCrash):
                    coordinator.publish_shard(
                        inventory,
                        0,
                        (publication,),
                        fault_injector=inject,
                    )
                published = coordinator.publish_shard(inventory, 0, (publication,))
                recovery_idempotent = recovery_idempotent and store.reference_exists_verified(
                    category="seals",
                    inventory_digest=inventory.digest,
                    shard_index=0,
                    digest=published.manifest.digest,
                )
'''
new_validation = '''    recovery_idempotent = True
    for stage in stages:
        with (
            TemporaryDirectory() as baseline_directory,
            TemporaryDirectory() as recovery_directory,
        ):
            run_id = f"run-recovery-{stage}"
            baseline_store = ContentAddressedPublicationStore(Path(baseline_directory))
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

            store = ContentAddressedPublicationStore(Path(recovery_directory))
            coordinator = ShardPublicationCoordinator(store)

            def inject(current: str, *, expected: str = stage) -> None:
                if current == expected:
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
            published = coordinator.publish_shard(inventory, 0, (publication,))
            recovery_idempotent = recovery_idempotent and (
                tuple(receipt.digest for receipt in publication.receipts)
                == tuple(receipt.digest for receipt in baseline_publication.receipts)
                and published.index.digest == baseline_shard.index.digest
                and published.manifest.digest == baseline_shard.manifest.digest
                and store.reference_exists_verified(
                    category="seals",
                    inventory_digest=inventory.digest,
                    shard_index=0,
                    digest=published.manifest.digest,
                )
            )
'''
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_validation.py",
    old_validation,
    new_validation,
)

replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''def test_concurrent_same_run_retries_converge_on_one_receipt_chain(
''',
    '''def test_nonowner_finishes_an_abandoned_claim(tmp_path: Path) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    coordinator = ShardPublicationCoordinator(store)

    def crash_after_claim(stage: str) -> None:
        if stage == "completion-claim-persisted":
            raise InjectedPublicationCrash(stage)

    with suppress(InjectedPublicationCrash):
        coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id="run-abandoned-owner",
            fault_injector=crash_after_claim,
        )

    recovered = coordinator.publish_completion(
        inventory,
        publication_fixture_accepted(0),
        execution_run_id="run-finishing-nonowner",
    )

    assert recovered.receipts[0].disposition.value == "existing-identical"
    assert store.read_verified(recovered.envelope.digest) == recovered.envelope.canonical_bytes
    published = coordinator.publish_shard(inventory, 0, (recovered,))
    assert store.reference_exists_verified(
        category="seals",
        inventory_digest=inventory.digest,
        shard_index=0,
        digest=published.manifest.digest,
    )


def test_concurrent_same_run_retries_converge_on_one_receipt_chain(
''',
)

replace_once(
    "docs/publication_protocol_v0.4.md",
    '''object-to-receipt gap reproduces the uninterrupted receipt chain. Reused receipt objects
are routed through the durable-existing path before success is returned.
''',
    '''object-to-receipt gap reproduces the uninterrupted receipt chain. A different run may
finish installing verified bytes under an abandoned claim while retaining an
`existing-identical` disposition, so a lost owner cannot permanently wedge publication.
Reused receipt objects are routed through the durable-existing path before success is returned.
''',
)
