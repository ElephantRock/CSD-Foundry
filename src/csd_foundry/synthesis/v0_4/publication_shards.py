"""Canonical shard indexes, verified manifests, and append-only seal publication."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.attempts import AttemptAccepted, AttemptRejected
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey
from csd_foundry.synthesis.v0_4.execution_protocol import (
    SHARD_MANIFEST_SCHEMA_VERSION,
    SHARD_POLICY_ID,
    SHARD_POLICY_VERSION,
    ExecutionInventory,
)
from csd_foundry.synthesis.v0_4.publication_protocol import (
    AttemptCompletionEnvelope,
    InventoryCompletionReference,
    OperationalPublicationReceipt,
    PublicationDisposition,
    PublicationObjectKind,
    validate_publication_receipt_chain,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    FaultInjector,
    PublicationResult,
    PublicationStoreError,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

SHARD_INDEX_FORMAT_ID = "csd-shard-index"
SHARD_INDEX_FORMAT_VERSION = 1
_UINT32_MAX = (1 << 32) - 1


class ShardPublicationError(ValueError):
    """Raised when shard publication evidence violates the v0.4 contract."""


def _require_uint32(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= _UINT32_MAX:
        raise ShardPublicationError(f"{field_name} must be an exact uint32")
    return value


def _require_digest(value: object, field_name: str) -> str:
    try:
        return ContentAddressedPublicationStore._require_digest(value)
    except PublicationStoreError as exc:
        raise ShardPublicationError(f"invalid {field_name}") from exc


def _attempt_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey:
        raise ShardPublicationError("attempt_key must use the exact AttemptKey class")
    return {
        "attempt_index": attempt_key.attempt_index,
        "release": attempt_key.sample_key.release,
        "sample_index": attempt_key.sample_key.sample_index,
        "target_id": attempt_key.sample_key.target_id,
    }


@dataclass(frozen=True, slots=True)
class PublishedCompletion:
    """One persisted semantic completion and its inventory-bound receipt chain."""

    envelope: AttemptCompletionEnvelope
    reference: InventoryCompletionReference
    receipts: tuple[OperationalPublicationReceipt, ...]

    def __post_init__(self) -> None:
        if type(self) is not PublishedCompletion:
            raise ShardPublicationError("published completions must use the exact class")
        if type(self.envelope) is not AttemptCompletionEnvelope:
            raise ShardPublicationError("published completion requires an exact envelope")
        if type(self.reference) is not InventoryCompletionReference:
            raise ShardPublicationError("published completion requires an exact reference")
        if self.reference.completion_envelope_digest != self.envelope.digest:
            raise ShardPublicationError("reference does not identify the completion envelope")
        validate_publication_receipt_chain(self.receipts)
        if len(self.receipts) != 2:
            raise ShardPublicationError("completion publication requires exactly two receipts")
        envelope_receipt, reference_receipt = self.receipts
        if (
            envelope_receipt.object_kind is not PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE
            or envelope_receipt.object_digest != self.envelope.digest
        ):
            raise ShardPublicationError("first receipt does not publish the completion envelope")
        if (
            reference_receipt.object_kind
            is not PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE
            or reference_receipt.object_digest != self.reference.digest
        ):
            raise ShardPublicationError("final receipt does not publish the inventory reference")

    @property
    def final_receipt(self) -> OperationalPublicationReceipt:
        return self.receipts[-1]


@dataclass(frozen=True, slots=True)
class ShardIndexEntry:
    """Canonical operational index entry for one inventory attempt completion."""

    inventory_digest: str
    shard_count: int
    shard_index: int
    global_ordinal: int
    attempt_key: AttemptKey
    completion_envelope_digest: str
    inventory_completion_reference_digest: str
    publication_receipt_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ShardIndexEntry:
            raise ShardPublicationError("shard index entries must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        _require_uint32(self.shard_count, "shard_count")
        if self.shard_count == 0:
            raise ShardPublicationError("shard_count must be positive")
        _require_uint32(self.shard_index, "shard_index")
        if self.shard_index >= self.shard_count:
            raise ShardPublicationError("shard_index must be less than shard_count")
        _require_uint32(self.global_ordinal, "global_ordinal")
        _attempt_value(self.attempt_key)
        _require_digest(self.completion_envelope_digest, "completion_envelope_digest")
        _require_digest(
            self.inventory_completion_reference_digest,
            "inventory_completion_reference_digest",
        )
        _require_digest(self.publication_receipt_digest, "publication_receipt_digest")
        if self.global_ordinal % self.shard_count != self.shard_index:
            raise ShardPublicationError("index entry violates shard-policy-v1 assignment")

    @classmethod
    def from_publication(
        cls,
        inventory: ExecutionInventory,
        publication: PublishedCompletion,
    ) -> ShardIndexEntry:
        if cls is not ShardIndexEntry:
            raise ShardPublicationError("index entry construction requires the exact class")
        if type(inventory) is not ExecutionInventory:
            raise ShardPublicationError("index entry requires an exact execution inventory")
        if type(publication) is not PublishedCompletion:
            raise ShardPublicationError("index entry requires an exact published completion")
        publication.reference.validate_against(inventory, publication.envelope)
        receipt = publication.final_receipt
        if receipt.inventory_digest != inventory.digest:
            raise ShardPublicationError("publication receipt belongs to another inventory")
        if receipt.attempt_key != publication.envelope.attempt_key:
            raise ShardPublicationError("publication receipt belongs to another attempt")
        return cls(
            inventory_digest=inventory.digest,
            shard_count=inventory.shard_count,
            shard_index=publication.reference.global_ordinal % inventory.shard_count,
            global_ordinal=publication.reference.global_ordinal,
            attempt_key=publication.envelope.attempt_key,
            completion_envelope_digest=publication.envelope.digest,
            inventory_completion_reference_digest=publication.reference.digest,
            publication_receipt_digest=receipt.digest,
        )

    @property
    def position_key(self) -> tuple[int, int]:
        return self.global_ordinal, self.attempt_key.attempt_index

    @property
    def sort_key(self) -> tuple[int, int, str, str, str]:
        return (
            self.global_ordinal,
            self.attempt_key.attempt_index,
            self.completion_envelope_digest,
            self.inventory_completion_reference_digest,
            self.publication_receipt_digest,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_value(self.attempt_key),
            "completion_envelope_digest": self.completion_envelope_digest,
            "global_ordinal": self.global_ordinal,
            "inventory_completion_reference_digest": (self.inventory_completion_reference_digest),
            "inventory_digest": self.inventory_digest,
            "publication_receipt_digest": self.publication_receipt_digest,
            "shard_count": self.shard_count,
            "shard_index": self.shard_index,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True, init=False)
class ShardIndex:
    """Immutable canonical snapshot of one logical shard index."""

    inventory_digest: str
    shard_count: int
    shard_index: int
    entries: tuple[ShardIndexEntry, ...]
    format_id: str = SHARD_INDEX_FORMAT_ID
    format_version: int = SHARD_INDEX_FORMAT_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ShardIndex:
            raise ShardPublicationError("shard indexes must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        _require_uint32(self.shard_count, "shard_count")
        if self.shard_count == 0:
            raise ShardPublicationError("shard_count must be positive")
        _require_uint32(self.shard_index, "shard_index")
        if self.shard_index >= self.shard_count:
            raise ShardPublicationError("shard_index must be less than shard_count")
        if type(self.entries) is not tuple:
            raise ShardPublicationError("shard index entries must use an immutable tuple")
        if not all(type(entry) is ShardIndexEntry for entry in self.entries):
            raise ShardPublicationError("shard index contains a derived entry")
        if tuple(sorted(self.entries, key=lambda entry: entry.sort_key)) != self.entries:
            raise ShardPublicationError("shard index entries must use canonical ordering")
        if len({entry.position_key for entry in self.entries}) != len(self.entries):
            raise ShardPublicationError("shard index contains duplicate inventory positions")
        for entry in self.entries:
            if entry.inventory_digest != self.inventory_digest:
                raise ShardPublicationError("shard index spans inventories")
            if entry.shard_count != self.shard_count or entry.shard_index != self.shard_index:
                raise ShardPublicationError("shard index spans shard assignments")
        if self.format_id != SHARD_INDEX_FORMAT_ID:
            raise ShardPublicationError("unknown shard index format")
        if self.format_version != SHARD_INDEX_FORMAT_VERSION:
            raise ShardPublicationError("unknown shard index format version")

    @classmethod
    def from_entries(
        cls,
        inventory: ExecutionInventory,
        shard_index: int,
        entries: tuple[ShardIndexEntry, ...],
    ) -> ShardIndex:
        if cls is not ShardIndex:
            raise ShardPublicationError("shard index construction requires the exact class")
        if type(inventory) is not ExecutionInventory:
            raise ShardPublicationError("shard index requires an exact execution inventory")
        _require_uint32(shard_index, "shard_index")
        if shard_index >= inventory.shard_count:
            raise ShardPublicationError("shard_index is outside the inventory shard range")
        if type(entries) is not tuple:
            raise ShardPublicationError("shard index input must use an immutable tuple")
        canonical: dict[tuple[int, int], ShardIndexEntry] = {}
        for entry in entries:
            if type(entry) is not ShardIndexEntry:
                raise ShardPublicationError("shard index input contains a derived entry")
            if entry.inventory_digest != inventory.digest:
                raise ShardPublicationError("shard index entry belongs to another inventory")
            if entry.shard_count != inventory.shard_count or entry.shard_index != shard_index:
                raise ShardPublicationError("shard index entry belongs to another shard")
            existing = canonical.get(entry.position_key)
            if existing is not None and existing != entry:
                raise ShardPublicationError(
                    "conflicting completions occupy one inventory attempt position"
                )
            canonical[entry.position_key] = entry
        index = object.__new__(ShardIndex)
        object.__setattr__(index, "inventory_digest", inventory.digest)
        object.__setattr__(index, "shard_count", inventory.shard_count)
        object.__setattr__(index, "shard_index", shard_index)
        object.__setattr__(
            index,
            "entries",
            tuple(sorted(canonical.values(), key=lambda entry: entry.sort_key)),
        )
        object.__setattr__(index, "format_id", SHARD_INDEX_FORMAT_ID)
        object.__setattr__(index, "format_version", SHARD_INDEX_FORMAT_VERSION)
        index.__post_init__()
        return index

    @classmethod
    def from_publications(
        cls,
        inventory: ExecutionInventory,
        shard_index: int,
        publications: tuple[PublishedCompletion, ...],
    ) -> ShardIndex:
        if type(publications) is not tuple:
            raise ShardPublicationError("published completions must use an immutable tuple")
        entries = tuple(
            ShardIndexEntry.from_publication(inventory, publication)
            for publication in publications
            if publication.reference.global_ordinal % inventory.shard_count == shard_index
        )
        if len(entries) != len(publications):
            raise ShardPublicationError("published completion belongs to another logical shard")
        return cls.from_entries(inventory, shard_index, entries)

    @classmethod
    def extend(
        cls,
        inventory: ExecutionInventory,
        previous: ShardIndex,
        additions: tuple[ShardIndexEntry, ...],
    ) -> ShardIndex:
        if type(previous) is not ShardIndex:
            raise ShardPublicationError("previous shard index must use the exact class")
        if previous.inventory_digest != inventory.digest:
            raise ShardPublicationError("previous shard index belongs to another inventory")
        return cls.from_entries(
            inventory,
            previous.shard_index,
            previous.entries + additions,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "entries": [entry.to_json_value() for entry in self.entries],
            "format_id": self.format_id,
            "format_version": self.format_version,
            "inventory_digest": self.inventory_digest,
            "shard_count": self.shard_count,
            "shard_index": self.shard_index,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True, init=False)
class SealedShardManifest:
    """Factory-constructed manifest whose creation is the shard seal."""

    inventory_digest: str
    generation_namespace_digest: str
    required_schema_versions_digest: str
    shard_policy_id: str
    shard_policy_version: int
    shard_count: int
    shard_index: int
    shard_index_digest: str
    entry_count: int
    entry_digests: tuple[str, ...]
    completion_envelope_digests: tuple[str, ...]
    inventory_completion_reference_digests: tuple[str, ...]
    publication_receipt_digests: tuple[str, ...]
    object_set_digest: str
    sealed: bool = True
    schema_version: str = SHARD_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not SealedShardManifest:
            raise ShardPublicationError("sealed manifests must use the exact class")
        for field_name, value in (
            ("inventory_digest", self.inventory_digest),
            ("generation_namespace_digest", self.generation_namespace_digest),
            ("required_schema_versions_digest", self.required_schema_versions_digest),
            ("shard_index_digest", self.shard_index_digest),
            ("object_set_digest", self.object_set_digest),
        ):
            _require_digest(value, field_name)
        if self.shard_policy_id != SHARD_POLICY_ID:
            raise ShardPublicationError("sealed manifest uses an unknown shard policy")
        if self.shard_policy_version != SHARD_POLICY_VERSION:
            raise ShardPublicationError("sealed manifest uses an unknown shard-policy version")
        _require_uint32(self.shard_count, "shard_count")
        _require_uint32(self.shard_index, "shard_index")
        if self.shard_count == 0 or self.shard_index >= self.shard_count:
            raise ShardPublicationError("sealed manifest shard assignment is invalid")
        _require_uint32(self.entry_count, "entry_count")
        for field_name, values in (
            ("entry_digests", self.entry_digests),
            ("completion_envelope_digests", self.completion_envelope_digests),
            (
                "inventory_completion_reference_digests",
                self.inventory_completion_reference_digests,
            ),
            ("publication_receipt_digests", self.publication_receipt_digests),
        ):
            if type(values) is not tuple or len(values) != self.entry_count:
                raise ShardPublicationError(
                    f"{field_name} must be an immutable entry-aligned tuple"
                )
            for value in values:
                _require_digest(value, field_name)
        if self.sealed is not True:
            raise ShardPublicationError("shard manifest must be factory sealed")
        if self.schema_version != SHARD_MANIFEST_SCHEMA_VERSION:
            raise ShardPublicationError("shard manifest schema version is not registered")

    @classmethod
    def seal(
        cls,
        inventory: ExecutionInventory,
        index: ShardIndex,
        publications: tuple[PublishedCompletion, ...],
        store: ContentAddressedPublicationStore,
    ) -> SealedShardManifest:
        if cls is not SealedShardManifest:
            raise ShardPublicationError("manifest sealing requires the exact class")
        if type(inventory) is not ExecutionInventory:
            raise ShardPublicationError("manifest sealing requires an exact inventory")
        if type(index) is not ShardIndex:
            raise ShardPublicationError("manifest sealing requires an exact shard index")
        if type(store) is not ContentAddressedPublicationStore:
            raise ShardPublicationError("manifest sealing requires the exact publication store")
        expected_index = ShardIndex.from_publications(
            inventory,
            index.shard_index,
            publications,
        )
        if index != expected_index:
            raise ShardPublicationError("shard index does not match its publications")
        if store.read_verified(index.digest) != index.canonical_bytes:
            raise ShardPublicationError("shard index is not durably published")
        if not store.reference_exists_verified(
            category="indexes",
            inventory_digest=inventory.digest,
            shard_index=index.shard_index,
            digest=index.digest,
        ):
            raise ShardPublicationError("shard index reference is not durably published")
        for publication in publications:
            if (
                store.read_verified(publication.envelope.digest)
                != publication.envelope.canonical_bytes
            ):
                raise ShardPublicationError("completion envelope object is not verified")
            if (
                store.read_verified(publication.reference.digest)
                != publication.reference.canonical_bytes
            ):
                raise ShardPublicationError("completion reference object is not verified")
            for receipt in publication.receipts:
                if store.read_verified(receipt.digest) != receipt.canonical_bytes:
                    raise ShardPublicationError("publication receipt object is not verified")
        object_set = {
            "completion_envelope_digests": [
                entry.completion_envelope_digest for entry in index.entries
            ],
            "inventory_completion_reference_digests": [
                entry.inventory_completion_reference_digest for entry in index.entries
            ],
            "publication_receipt_digests": [
                entry.publication_receipt_digest for entry in index.entries
            ],
            "shard_index_digest": index.digest,
        }
        manifest = object.__new__(SealedShardManifest)
        object.__setattr__(manifest, "inventory_digest", inventory.digest)
        object.__setattr__(
            manifest,
            "generation_namespace_digest",
            inventory.generation_namespace_digest,
        )
        object.__setattr__(
            manifest,
            "required_schema_versions_digest",
            inventory.required_schema_versions.digest,
        )
        object.__setattr__(manifest, "shard_policy_id", inventory.shard_policy_id)
        object.__setattr__(manifest, "shard_policy_version", inventory.shard_policy_version)
        object.__setattr__(manifest, "shard_count", inventory.shard_count)
        object.__setattr__(manifest, "shard_index", index.shard_index)
        object.__setattr__(manifest, "shard_index_digest", index.digest)
        object.__setattr__(manifest, "entry_count", len(index.entries))
        object.__setattr__(
            manifest, "entry_digests", tuple(entry.digest for entry in index.entries)
        )
        object.__setattr__(
            manifest,
            "completion_envelope_digests",
            tuple(entry.completion_envelope_digest for entry in index.entries),
        )
        object.__setattr__(
            manifest,
            "inventory_completion_reference_digests",
            tuple(entry.inventory_completion_reference_digest for entry in index.entries),
        )
        object.__setattr__(
            manifest,
            "publication_receipt_digests",
            tuple(entry.publication_receipt_digest for entry in index.entries),
        )
        object.__setattr__(manifest, "object_set_digest", canonical_sha256(object_set))
        object.__setattr__(manifest, "sealed", True)
        object.__setattr__(manifest, "schema_version", SHARD_MANIFEST_SCHEMA_VERSION)
        manifest.__post_init__()
        return manifest

    def to_json_value(self) -> dict[str, object]:
        return {
            "completion_envelope_digests": list(self.completion_envelope_digests),
            "entry_count": self.entry_count,
            "entry_digests": list(self.entry_digests),
            "generation_namespace_digest": self.generation_namespace_digest,
            "inventory_completion_reference_digests": list(
                self.inventory_completion_reference_digests
            ),
            "inventory_digest": self.inventory_digest,
            "object_set_digest": self.object_set_digest,
            "publication_receipt_digests": list(self.publication_receipt_digests),
            "required_schema_versions_digest": self.required_schema_versions_digest,
            "schema_version": self.schema_version,
            "sealed": self.sealed,
            "shard_count": self.shard_count,
            "shard_index": self.shard_index,
            "shard_index_digest": self.shard_index_digest,
            "shard_policy_id": self.shard_policy_id,
            "shard_policy_version": self.shard_policy_version,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class PublishedShard:
    index: ShardIndex
    manifest: SealedShardManifest
    index_result: PublicationResult
    manifest_result: PublicationResult
    seal_result: PublicationResult

    def __post_init__(self) -> None:
        if type(self) is not PublishedShard:
            raise ShardPublicationError("published shards must use the exact class")
        if type(self.index) is not ShardIndex:
            raise ShardPublicationError("published shard requires an exact index")
        if type(self.manifest) is not SealedShardManifest:
            raise ShardPublicationError("published shard requires an exact sealed manifest")
        if self.manifest.shard_index_digest != self.index.digest:
            raise ShardPublicationError("published shard manifest does not identify its index")


class ShardPublicationCoordinator:
    """Crash-idempotent publication of completion, index, manifest, and seal objects."""

    def __init__(self, store: ContentAddressedPublicationStore) -> None:
        if type(store) is not ContentAddressedPublicationStore:
            raise ShardPublicationError("coordinator requires the exact publication store")
        self.store = store

    @staticmethod
    def _invoke(fault_injector: FaultInjector | None, stage: str) -> None:
        if fault_injector is not None:
            fault_injector(stage)

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

    def publish_completion(
        self,
        inventory: ExecutionInventory,
        completion: AttemptAccepted | AttemptRejected,
        *,
        execution_run_id: str,
        fault_injector: FaultInjector | None = None,
    ) -> PublishedCompletion:
        envelope = AttemptCompletionEnvelope.from_completion(completion)
        envelope_result = self.store.publish_bytes(
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
        self._invoke(fault_injector, "completion-receipt-persisted")

        reference = InventoryCompletionReference.from_inventory(inventory, envelope)
        reference_result = self.store.publish_bytes(
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
        self._invoke(fault_injector, "reference-receipt-persisted")
        return PublishedCompletion(
            envelope=envelope,
            reference=reference,
            receipts=(envelope_receipt, reference_receipt),
        )

    def publish_shard(
        self,
        inventory: ExecutionInventory,
        shard_index: int,
        publications: tuple[PublishedCompletion, ...],
        *,
        fault_injector: FaultInjector | None = None,
    ) -> PublishedShard:
        index = ShardIndex.from_publications(inventory, shard_index, publications)
        index_result = self.store.publish_bytes(
            index.canonical_bytes,
            expected_digest=index.digest,
        )
        self.store.install_digest_reference(
            category="indexes",
            inventory_digest=inventory.digest,
            shard_index=shard_index,
            digest=index.digest,
            fault_stage="shard-index-persisted",
            fault_injector=fault_injector,
        )
        manifest = SealedShardManifest.seal(inventory, index, publications, self.store)
        manifest_result = self.store.publish_bytes(
            manifest.canonical_bytes,
            expected_digest=manifest.digest,
        )
        self.store.install_digest_reference(
            category="manifests",
            inventory_digest=inventory.digest,
            shard_index=shard_index,
            digest=manifest.digest,
            fault_stage="shard-manifest-persisted",
            fault_injector=fault_injector,
        )
        seal_result = self.store.install_digest_reference(
            category="seals",
            inventory_digest=inventory.digest,
            shard_index=shard_index,
            digest=manifest.digest,
            fault_stage="shard-seal-published",
            fault_injector=fault_injector,
        )
        return PublishedShard(
            index=index,
            manifest=manifest,
            index_result=index_result,
            manifest_result=manifest_result,
            seal_result=seal_result,
        )
