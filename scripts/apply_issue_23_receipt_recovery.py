"""One-shot patch for truthful, crash-stable publication receipt recovery."""

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
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''    def publish_completion(
        self,
        inventory: ExecutionInventory,
        completion: AttemptAccepted | AttemptRejected,
        *,
        execution_run_id: str,
        fault_injector: FaultInjector | None = None,
    ) -> PublishedCompletion:
''',
    '''    def _publish_or_reuse_receipt(
        self,
        *,
        previous: OperationalPublicationReceipt | None,
        execution_run_id: str,
        inventory_digest: str,
        attempt_key: AttemptKey,
        object_kind: PublicationObjectKind,
        object_digest: str,
        actual_disposition: PublicationDisposition,
    ) -> OperationalPublicationReceipt:
        published_candidate = OperationalPublicationReceipt.append(
            previous=previous,
            execution_run_id=execution_run_id,
            inventory_digest=inventory_digest,
            attempt_key=attempt_key,
            object_kind=object_kind,
            object_digest=object_digest,
            disposition=PublicationDisposition.PUBLISHED,
        )
        candidate_path = self.store.object_path(published_candidate.digest)
        if candidate_path.is_file():
            if self.store.read_verified(published_candidate.digest) != published_candidate.canonical_bytes:
                raise ShardPublicationError(
                    "persisted publication receipt does not match its canonical bytes"
                )
            return published_candidate
        receipt = (
            published_candidate
            if actual_disposition is PublicationDisposition.PUBLISHED
            else OperationalPublicationReceipt.append(
                previous=previous,
                execution_run_id=execution_run_id,
                inventory_digest=inventory_digest,
                attempt_key=attempt_key,
                object_kind=object_kind,
                object_digest=object_digest,
                disposition=actual_disposition,
            )
        )
        self.store.publish_bytes(
            receipt.canonical_bytes,
            expected_digest=receipt.digest,
        )
        return receipt

    def publish_completion(
        self,
        inventory: ExecutionInventory,
        completion: AttemptAccepted | AttemptRejected,
        *,
        execution_run_id: str,
        fault_injector: FaultInjector | None = None,
    ) -> PublishedCompletion:
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        self.store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
        )
        envelope_receipt = OperationalPublicationReceipt.append(
            previous=None,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
            object_digest=envelope.digest,
            disposition=PublicationDisposition.PUBLISHED,
        )
        self.store.publish_bytes(
            envelope_receipt.canonical_bytes,
            expected_digest=envelope_receipt.digest,
        )
''',
    '''        envelope_result = self.store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
        )
        envelope_receipt = self._publish_or_reuse_receipt(
            previous=None,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
            object_digest=envelope.digest,
            actual_disposition=envelope_result.disposition,
        )
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        self.store.publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
        )
        reference_receipt = OperationalPublicationReceipt.append(
            previous=envelope_receipt,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
            object_digest=reference.digest,
            disposition=PublicationDisposition.PUBLISHED,
        )
        self.store.publish_bytes(
            reference_receipt.canonical_bytes,
            expected_digest=reference_receipt.digest,
        )
''',
    '''        reference_result = self.store.publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
        )
        reference_receipt = self._publish_or_reuse_receipt(
            previous=envelope_receipt,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
            object_digest=reference.digest,
            actual_disposition=reference_result.disposition,
        )
''',
)

replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''def test_shard_index_is_completion_order_independent(tmp_path: Path) -> None:
''',
    '''def test_cross_run_duplicate_receipts_report_existing_identical(tmp_path: Path) -> None:
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

    assert all(
        receipt.disposition.value == "published" for receipt in first.receipts
    )
    assert all(
        receipt.disposition.value == "existing-identical"
        for receipt in duplicate.receipts
    )
    assert first.envelope.digest == duplicate.envelope.digest
    assert first.reference.digest == duplicate.reference.digest
    assert tuple(receipt.digest for receipt in first.receipts) != tuple(
        receipt.digest for receipt in duplicate.receipts
    )


def test_shard_index_is_completion_order_independent(tmp_path: Path) -> None:
''',
)

replace_once(
    "docs/publication_protocol_v0.4.md",
    '''Operational receipt bytes never enter completion-envelope identity. Coordinator-issued
receipts describe the stable authoritative `published` state, while per-call storage results
separately distinguish newly installed from `existing-identical`. Repeating recovery with the
same execution-run ID therefore reproduces the exact receipt chain.
''',
    '''Operational receipt bytes never enter completion-envelope identity. Receipts truthfully
record whether that execution run installed new authority or encountered `existing-identical`
bytes. During same-run recovery, an already persisted canonical `published` receipt is reused
rather than regenerated from the retry's storage disposition. This preserves exact receipt
chains after receipt-boundary crashes without misclassifying duplicates from another run.
''',
)
