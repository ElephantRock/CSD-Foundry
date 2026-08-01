"""One-shot hardening for concurrent directories and crash-stable receipts."""

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
    '''        for directory in reversed(missing):
            directory.mkdir()
            cls._fsync_directory(directory)
            cls._fsync_directory(directory.parent)
''',
    '''        for directory in reversed(missing):
            try:
                directory.mkdir()
            except FileExistsError:
                if not directory.is_dir():
                    raise PublicationStoreError(
                        "publication path was concurrently created as a non-directory"
                    )
            cls._fsync_directory(directory)
            cls._fsync_directory(directory.parent)
''',
)

replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''    OperationalPublicationReceipt,
    PublicationObjectKind,
    validate_publication_receipt_chain,
''',
    '''    OperationalPublicationReceipt,
    PublicationDisposition,
    PublicationObjectKind,
    validate_publication_receipt_chain,
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''    FaultInjector,
    PublicationResult,
)
''',
    '''    FaultInjector,
    PublicationResult,
    PublicationStoreError,
)
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''    except ValueError as exc:
        raise ShardPublicationError(f"invalid {field_name}") from exc
''',
    '''    except PublicationStoreError as exc:
        raise ShardPublicationError(f"invalid {field_name}") from exc
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        envelope_result = self.store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
        )
''',
    '''        self.store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
        )
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''            disposition=envelope_result.disposition,
''',
    '''            disposition=PublicationDisposition.PUBLISHED,
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        reference_result = self.store.publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
        )
''',
    '''        self.store.publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
        )
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''            disposition=reference_result.disposition,
''',
    '''            disposition=PublicationDisposition.PUBLISHED,
''',
)

replace_once(
    "tests/test_v0_4_publication_protocol.py",
    '''    assert final_parent in synced


def test_duplicate_existing_success_fsyncs_authoritative_directory(
''',
    '''    assert final_parent in synced


def test_concurrent_directory_creation_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    store = ContentAddressedPublicationStore(tmp_path)
    target = store.object_path(envelope.digest).parent
    original_mkdir = Path.mkdir
    raced = False

    def racing_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal raced
        if path == target and not raced:
            original_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]
            raced = True
            raise FileExistsError(path)
        original_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "mkdir", racing_mkdir)
    result = store.publish_bytes(envelope.canonical_bytes, expected_digest=envelope.digest)

    assert raced
    assert result.disposition is PublicationDisposition.PUBLISHED
    assert store.read_verified(envelope.digest) == envelope.canonical_bytes


def test_duplicate_existing_success_fsyncs_authoritative_directory(
''',
)

old_staged_test = '''def test_staged_publication_is_crash_idempotent(tmp_path: Path, stage: str) -> None:
    store = ContentAddressedPublicationStore(tmp_path)
    inventory = publication_fixture_inventory(shard_count=2, sample_count=1)
    coordinator = ShardPublicationCoordinator(store)

    def inject(current: str) -> None:
        if current == stage:
            raise InjectedPublicationCrash(current)

    if stage in {"completion-receipt-persisted", "reference-receipt-persisted"}:
        with suppress(InjectedPublicationCrash):
            coordinator.publish_completion(
                inventory,
                publication_fixture_accepted(0),
                execution_run_id=f"run-{stage}",
                fault_injector=inject,
            )
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id=f"run-{stage}",
        )
    else:
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id=f"run-{stage}",
        )
        with suppress(InjectedPublicationCrash):
            coordinator.publish_shard(
                inventory,
                0,
                (publication,),
                fault_injector=inject,
            )

    published = coordinator.publish_shard(inventory, 0, (publication,))
    assert store.reference_exists_verified(
        category="seals",
        inventory_digest=inventory.digest,
        shard_index=0,
        digest=published.manifest.digest,
    )
'''
new_staged_test = '''def test_staged_publication_is_crash_idempotent(tmp_path: Path, stage: str) -> None:
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

    if stage in {"completion-receipt-persisted", "reference-receipt-persisted"}:
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
'''
replace_once(
    "tests/test_v0_4_publication_shards.py",
    old_staged_test,
    new_staged_test,
)

replace_once(
    "docs/publication_protocol_v0.4.md",
    '''Operational receipt bytes never enter completion-envelope identity.
''',
    '''Operational receipt bytes never enter completion-envelope identity. Coordinator-issued
receipts describe the stable authoritative `published` state, while per-call storage results
separately distinguish newly installed from `existing-identical`. Repeating recovery with the
same execution-run ID therefore reproduces the exact receipt chain.
''',
)
