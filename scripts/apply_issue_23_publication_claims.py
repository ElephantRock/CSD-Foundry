"""One-shot patch for atomic publication ownership claims and receipt convergence."""

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
    '_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")\n',
    '_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")\n_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")\n',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_store.py",
    '''        self.objects_root = root / "objects"
        self.references_root = root / "references"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.references_root)
        self._ensure_directory(self.temporary_root)
''',
    '''        self.objects_root = root / "objects"
        self.claims_root = root / "claims"
        self.references_root = root / "references"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.claims_root)
        self._ensure_directory(self.references_root)
        self._ensure_directory(self.temporary_root)
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_store.py",
    '''    def object_path(self, digest: str) -> Path:
''',
    '''    @staticmethod
    def _require_token(value: object, field_name: str) -> str:
        if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
            raise PublicationStoreError(
                f"{field_name} must be a lowercase ASCII token"
            )
        return value

    def object_path(self, digest: str) -> Path:
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_store.py",
    '''    def publish_bytes(
''',
    '''    def publication_claim_path(self, object_kind: str, digest: str) -> Path:
        kind = self._require_token(object_kind, "object_kind")
        object_digest = self._require_digest(digest)
        return self.claims_root / kind / object_digest[:2] / object_digest[2:]

    @classmethod
    def _publication_claim_bytes(cls, owner_digest: str) -> bytes:
        return (cls._require_digest(owner_digest) + "\\n").encode("ascii")

    def _read_publication_claim_owner(self, path: Path) -> str:
        payload = path.read_bytes()
        if len(payload) != 65 or payload[-1:] != b"\\n":
            raise PublicationCorruptionError(
                "publication claim does not contain one canonical owner digest"
            )
        try:
            owner = payload[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise PublicationCorruptionError(
                "publication claim owner is not ASCII"
            ) from exc
        self._require_digest(owner)
        self._fsync_directory(path.parent)
        return owner

    def claim_publication(
        self,
        *,
        object_kind: str,
        digest: str,
        owner_digest: str,
        fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> bool:
        claim_path = self.publication_claim_path(object_kind, digest)
        claim_payload = self._publication_claim_bytes(owner_digest)
        self._ensure_directory(claim_path.parent)
        if claim_path.exists():
            return self._read_publication_claim_owner(claim_path) == owner_digest

        temporary_path = self.temporary_root / (
            f"claim.{digest}.{uuid.uuid4().hex}.tmp"
        )
        with temporary_path.open("xb") as handle:
            handle.write(claim_payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, claim_path)
        except FileExistsError:
            owned = self._read_publication_claim_owner(claim_path) == owner_digest
            temporary_path.unlink(missing_ok=True)
            self._fsync_directory(self.temporary_root)
            return owned

        self._fsync_directory(claim_path.parent)
        if fault_stage is not None:
            self._invoke(fault_injector, fault_stage)
        temporary_path.unlink(missing_ok=True)
        self._fsync_directory(self.temporary_root)
        return True

    def claim_and_publish_bytes(
        self,
        payload: bytes,
        *,
        expected_digest: str,
        object_kind: str,
        owner_digest: str,
        claim_fault_stage: str | None = None,
        object_fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        if type(payload) is not bytes:
            raise PublicationStoreError("publication payload must use the exact bytes type")
        digest = hashlib.sha256(payload).hexdigest()
        self._require_digest(expected_digest)
        if digest != expected_digest:
            raise PublicationCorruptionError(
                "publication payload does not match the expected digest"
            )
        claim_path = self.publication_claim_path(object_kind, digest)
        object_path = self.object_path(digest)

        if object_path.exists() and not claim_path.exists():
            result = self.publish_bytes(payload, expected_digest=digest)
            if object_fault_stage is not None:
                self._invoke(fault_injector, object_fault_stage)
            return result

        owned = self.claim_publication(
            object_kind=object_kind,
            digest=digest,
            owner_digest=owner_digest,
            fault_stage=claim_fault_stage,
            fault_injector=fault_injector,
        )
        if not owned and not object_path.exists():
            raise PublicationStoreError(
                "publication object is claimed by another execution run but not installed"
            )
        result = self.publish_bytes(payload, expected_digest=digest)
        if object_fault_stage is not None:
            self._invoke(fault_injector, object_fault_stage)
        return PublicationResult(
            digest=result.digest,
            relative_path=result.relative_path,
            disposition=(
                PublicationDisposition.PUBLISHED
                if owned
                else PublicationDisposition.EXISTING_IDENTICAL
            ),
        )

    def publish_bytes(
''',
)

old_coordinator_helpers = '''    def _publish_or_reuse_receipt(
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
            if (
                self.store.read_verified(published_candidate.digest)
                != published_candidate.canonical_bytes
            ):
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
'''
new_coordinator_helpers = '''    @staticmethod
    def _receipt_claim_owner_digest(
        *,
        previous: OperationalPublicationReceipt | None,
        execution_run_id: str,
        inventory_digest: str,
        attempt_key: AttemptKey,
        object_kind: PublicationObjectKind,
        object_digest: str,
    ) -> str:
        return canonical_sha256(
            {
                "attempt_key": {
                    "attempt_index": attempt_key.attempt_index,
                    "release": attempt_key.sample_key.release,
                    "sample_index": attempt_key.sample_key.sample_index,
                    "target_id": attempt_key.sample_key.target_id,
                },
                "execution_run_id": execution_run_id,
                "inventory_digest": inventory_digest,
                "object_digest": object_digest,
                "object_kind": object_kind.value,
                "previous_publication_receipt_digest": (
                    None if previous is None else previous.digest
                ),
                "publication_claim_version": 1,
                "publication_ordinal": (
                    0 if previous is None else previous.publication_ordinal + 1
                ),
            }
        )

    def _publish_or_reuse_receipt(
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
        receipt = OperationalPublicationReceipt.append(
            previous=previous,
            execution_run_id=execution_run_id,
            inventory_digest=inventory_digest,
            attempt_key=attempt_key,
            object_kind=object_kind,
            object_digest=object_digest,
            disposition=actual_disposition,
        )
        self.store.publish_bytes(
            receipt.canonical_bytes,
            expected_digest=receipt.digest,
        )
        return receipt
'''
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    old_coordinator_helpers,
    new_coordinator_helpers,
)

replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        envelope = AttemptCompletionEnvelope.from_completion(completion)
        envelope_result = self.store.publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
        )
''',
    '''        envelope = AttemptCompletionEnvelope.from_completion(completion)
        envelope_kind = PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE
        envelope_owner_digest = self._receipt_claim_owner_digest(
            previous=None,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=envelope_kind,
            object_digest=envelope.digest,
        )
        envelope_result = self.store.claim_and_publish_bytes(
            envelope.canonical_bytes,
            expected_digest=envelope.digest,
            object_kind=envelope_kind.value,
            owner_digest=envelope_owner_digest,
            claim_fault_stage="completion-claim-persisted",
            object_fault_stage="completion-object-persisted",
            fault_injector=fault_injector,
        )
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''            object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
''',
    '''            object_kind=envelope_kind,
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''        reference = InventoryCompletionReference.from_inventory(inventory, envelope)
        reference_result = self.store.publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
        )
''',
    '''        reference = InventoryCompletionReference.from_inventory(inventory, envelope)
        reference_kind = PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE
        reference_owner_digest = self._receipt_claim_owner_digest(
            previous=envelope_receipt,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=reference_kind,
            object_digest=reference.digest,
        )
        reference_result = self.store.claim_and_publish_bytes(
            reference.canonical_bytes,
            expected_digest=reference.digest,
            object_kind=reference_kind.value,
            owner_digest=reference_owner_digest,
            claim_fault_stage="reference-claim-persisted",
            object_fault_stage="reference-object-persisted",
            fault_injector=fault_injector,
        )
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''            object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
''',
    '''            object_kind=reference_kind,
''',
)

replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''from contextlib import suppress
from dataclasses import replace
from pathlib import Path
''',
    '''from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from threading import Barrier
''',
)
replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''def test_shard_index_is_completion_order_independent(tmp_path: Path) -> None:
''',
    '''def test_concurrent_same_run_retries_converge_on_one_receipt_chain(
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
''',
)
replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''    (
        "completion-receipt-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
''',
    '''    (
        "completion-claim-persisted",
        "completion-object-persisted",
        "completion-receipt-persisted",
        "reference-claim-persisted",
        "reference-object-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
''',
)
replace_once(
    "tests/test_v0_4_publication_shards.py",
    '''    if stage in {"completion-receipt-persisted", "reference-receipt-persisted"}:
''',
    '''    completion_stages = {
        "completion-claim-persisted",
        "completion-object-persisted",
        "completion-receipt-persisted",
        "reference-claim-persisted",
        "reference-object-persisted",
        "reference-receipt-persisted",
    }
    if stage in completion_stages:
''',
)

replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_validation.py",
    '''    stages = (
        "completion-receipt-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
''',
    '''    stages = (
        "completion-claim-persisted",
        "completion-object-persisted",
        "completion-receipt-persisted",
        "reference-claim-persisted",
        "reference-object-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
''',
)
replace_once(
    "src/csd_foundry/synthesis/v0_4/publication_validation.py",
    '''            if stage in {"completion-receipt-persisted", "reference-receipt-persisted"}:
''',
    '''            completion_stages = {
                "completion-claim-persisted",
                "completion-object-persisted",
                "completion-receipt-persisted",
                "reference-claim-persisted",
                "reference-object-persisted",
                "reference-receipt-persisted",
            }
            if stage in completion_stages:
''',
)

replace_once(
    "docs/publication_protocol_v0.4.md",
    '''Operational receipt bytes never enter completion-envelope identity. Receipts truthfully
record whether that execution run installed new authority or encountered `existing-identical`
bytes. During same-run recovery, an already persisted canonical `published` receipt is reused
rather than regenerated from the retry's storage disposition. This preserves exact receipt
chains after receipt-boundary crashes without misclassifying duplicates from another run.
''',
    '''Operational receipt bytes never enter completion-envelope identity. Before installing a
semantic object, the coordinator atomically installs an immutable per-kind, per-object
publication claim. The claim owner commits the execution run, inventory, attempt, object kind,
object digest, receipt ordinal, and predecessor receipt. Same-run workers therefore converge on
one `published` receipt choice even when they race; a different run observes
`existing-identical`. Because the claim is durable before object installation, recovery across
the object-to-receipt gap reproduces the uninterrupted receipt chain. Reused receipt objects
are routed through the durable-existing path before success is returned.
''',
)
