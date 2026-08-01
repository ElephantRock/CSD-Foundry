"""One-shot implementation patch for issue #23 shard indexes and sealing."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


protocol_path = ROOT / "src/csd_foundry/synthesis/v0_4/publication_protocol.py"
protocol = protocol_path.read_text(encoding="utf-8")
protocol = protocol.replace(
    '''class PublicationObjectKind(StrEnum):
    ATTEMPT_COMPLETION_ENVELOPE = "attempt-completion-envelope"
    INVENTORY_COMPLETION_REFERENCE = "inventory-completion-reference"
''',
    '''class PublicationObjectKind(StrEnum):
    ATTEMPT_COMPLETION_ENVELOPE = "attempt-completion-envelope"
    INVENTORY_COMPLETION_REFERENCE = "inventory-completion-reference"
    SHARD_INDEX = "shard-index"
    SHARD_MANIFEST = "shard-manifest"
''',
    1,
)
protocol_path.write_text(protocol, encoding="utf-8")

receipt_schema_path = ROOT / "specs/v0.4/operational_publication_receipt.schema.json"
receipt_schema = json.loads(receipt_schema_path.read_text(encoding="utf-8"))
receipt_schema["properties"]["object_kind"]["enum"] = [
    "attempt-completion-envelope",
    "inventory-completion-reference",
    "shard-index",
    "shard-manifest",
]
receipt_schema_path.write_text(
    json.dumps(receipt_schema, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

store_path = ROOT / "src/csd_foundry/synthesis/v0_4/publication_store.py"
store = store_path.read_text(encoding="utf-8")
store = store.replace(
    '''        self.objects_root = root / "objects"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.temporary_root)
''',
    '''        self.objects_root = root / "objects"
        self.references_root = root / "references"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.references_root)
        self._ensure_directory(self.temporary_root)
''',
    1,
)
marker = '''    def read_verified(self, digest: str) -> bytes:
'''
reference_methods = '''    def reference_path(
        self,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
    ) -> Path:
        if category not in {"indexes", "manifests", "seals"}:
            raise PublicationStoreError("unknown publication reference category")
        inventory = self._require_digest(inventory_digest)
        object_digest = self._require_digest(digest)
        if type(shard_index) is not int or not 0 <= shard_index <= (1 << 32) - 1:
            raise PublicationStoreError("shard_index must be an exact uint32")
        return (
            self.references_root
            / category
            / inventory
            / str(shard_index)
            / object_digest
        )

    def install_digest_reference(
        self,
        *,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
        fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        source = self.object_path(digest)
        payload = self.read_verified(digest)
        final_path = self.reference_path(
            category,
            inventory_digest,
            shard_index,
            digest,
        )
        self._ensure_directory(final_path.parent)
        if final_path.exists():
            return self._durable_existing(final_path, payload, digest)
        try:
            os.link(source, final_path)
        except FileExistsError:
            return self._durable_existing(final_path, payload, digest)
        self._fsync_directory(final_path.parent)
        if fault_stage is not None:
            self._invoke(fault_injector, fault_stage)
        return PublicationResult(
            digest=digest,
            relative_path=final_path.relative_to(self.root).as_posix(),
            disposition=PublicationDisposition.PUBLISHED,
        )

    def reference_exists_verified(
        self,
        *,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
    ) -> bool:
        path = self.reference_path(category, inventory_digest, shard_index, digest)
        if not path.is_file():
            return False
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise PublicationCorruptionError(
                "publication reference bytes do not match the referenced digest"
            )
        self._fsync_directory(path.parent)
        return True

'''
if marker not in store:
    raise RuntimeError("publication store insertion point changed")
store_path.write_text(store.replace(marker, reference_methods + marker, 1), encoding="utf-8")

write(
    "src/csd_foundry/synthesis/v0_4/publication_shards.py",
    '''"""Canonical shard indexes, verified manifests, and append-only seal publication."""

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
    PublicationObjectKind,
    PublicationProtocolError,
    validate_publication_receipt_chain,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    FaultInjector,
    PublicationResult,
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
    except ValueError as exc:
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
            envelope_receipt.object_kind
            is not PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE
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
            "inventory_completion_reference_digest": (
                self.inventory_completion_reference_digest
            ),
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
            if store.read_verified(publication.envelope.digest) != publication.envelope.canonical_bytes:
                raise ShardPublicationError("completion envelope object is not verified")
            if store.read_verified(publication.reference.digest) != publication.reference.canonical_bytes:
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
        object.__setattr__(manifest, "entry_digests", tuple(entry.digest for entry in index.entries))
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
        envelope_receipt = OperationalPublicationReceipt.append(
            previous=None,
            execution_run_id=execution_run_id,
            inventory_digest=inventory.digest,
            attempt_key=envelope.attempt_key,
            object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
            object_digest=envelope.digest,
            disposition=envelope_result.disposition,
        )
        self.store.publish_bytes(
            envelope_receipt.canonical_bytes,
            expected_digest=envelope_receipt.digest,
        )
        self._invoke(fault_injector, "completion-receipt-persisted")

        reference = InventoryCompletionReference.from_inventory(inventory, envelope)
        reference_result = self.store.publish_bytes(
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
            disposition=reference_result.disposition,
        )
        self.store.publish_bytes(
            reference_receipt.canonical_bytes,
            expected_digest=reference_receipt.digest,
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
''',
)

write(
    "specs/v0.4/shard_manifest.schema.json",
    '''{
  "$id": "urn:csd-foundry:shard-manifest:v0.4",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false,
  "properties": {
    "completion_envelope_digests": {
      "items": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
      "type": "array"
    },
    "entry_count": {"maximum": 4294967295, "minimum": 0, "type": "integer"},
    "entry_digests": {
      "items": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
      "type": "array"
    },
    "generation_namespace_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    "inventory_completion_reference_digests": {
      "items": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
      "type": "array"
    },
    "inventory_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    "object_set_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    "publication_receipt_digests": {
      "items": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
      "type": "array"
    },
    "required_schema_versions_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    "schema_version": {"const": "csd-shard-manifest/0.4"},
    "sealed": {"const": true},
    "shard_count": {"maximum": 4294967295, "minimum": 1, "type": "integer"},
    "shard_index": {"maximum": 4294967295, "minimum": 0, "type": "integer"},
    "shard_index_digest": {"pattern": "^[0-9a-f]{64}$", "type": "string"},
    "shard_policy_id": {"const": "csd-shard-contract"},
    "shard_policy_version": {"const": 1}
  },
  "required": [
    "completion_envelope_digests",
    "entry_count",
    "entry_digests",
    "generation_namespace_digest",
    "inventory_completion_reference_digests",
    "inventory_digest",
    "object_set_digest",
    "publication_receipt_digests",
    "required_schema_versions_digest",
    "schema_version",
    "sealed",
    "shard_count",
    "shard_index",
    "shard_index_digest",
    "shard_policy_id",
    "shard_policy_version"
  ],
  "type": "object"
}
''',
)

write(
    "src/csd_foundry/synthesis/v0_4/publication_validation.py",
    '''"""Validation and frozen evidence for v0.4 append-only publication."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from csd_foundry.synthesis.v0_4.attempts import (
    AttemptAccepted,
    AttemptRejected,
    AttemptRejection,
)
from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.contracts import RejectionCause
from csd_foundry.synthesis.v0_4.execution_protocol import (
    EXECUTION_VALIDATION_POLICY_ID,
    EXECUTION_VALIDATION_POLICY_VERSION,
    SAMPLE_KEY_ENCODING_ID,
    SAMPLE_KEY_ENCODING_VERSION,
    SHARD_POLICY_ID,
    SHARD_POLICY_VERSION,
    ExecutionInventory,
    OperationalRetryPolicy,
    RequiredSchemaVersions,
    SampleExecutionSpec,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
    shard_policy_document,
)
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.publication_protocol import (
    AttemptCompletionEnvelope,
    InventoryCompletionReference,
    OperationalPublicationReceipt,
    PublicationDisposition,
    PublicationObjectKind,
    validate_publication_receipt_chain,
)
from csd_foundry.synthesis.v0_4.publication_shards import (
    SealedShardManifest,
    ShardIndex,
    ShardIndexEntry,
    ShardPublicationCoordinator,
    ShardPublicationError,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    InjectedPublicationCrash,
    PublicationCorruptionError,
    PublicationStoreError,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_TARGET_DEFINITION_DIGEST = canonical_sha256({"target": "publication-v1-known-answer"})
_ROOT_SEED_COMMITMENT = canonical_sha256({"root_seed": "publication-v1-known-answer"})


@dataclass(frozen=True, slots=True)
class PublicationValidationReport:
    release: str
    vectors_passed: int
    vector_count: int
    vector_catalog_digest: str
    semantic_envelope_topology_independent: bool
    inventory_reference_authoritative: bool
    publication_receipts_operational: bool
    no_clobber_enforced: bool
    duplicate_publication_idempotent: bool
    corrupted_existing_rejected: bool
    crash_debris_recoverable: bool
    shard_index_canonical: bool
    duplicate_conflicts_rejected: bool
    manifest_objects_verified: bool
    seal_requires_verified_manifest: bool
    staged_shard_recovery_idempotent: bool
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_boundary": (
                "This report validates topology-independent semantic completion envelopes, "
                "inventory-authorized completion references, append-only operational "
                "publication receipts, content-addressed no-clobber object installation, "
                "durable duplicate classification, crash recovery, canonical shard-index "
                "snapshots, verified shard manifests, and append-only manifest seals. It does "
                "not establish streaming reconciliation, global lowest-valid-attempt "
                "resolution, canonical corpus merge, planner completeness, oracle validity, "
                "infeasibility, or release-scale output."
            ),
            "corrupted_existing_rejected": self.corrupted_existing_rejected,
            "crash_debris_recoverable": self.crash_debris_recoverable,
            "duplicate_conflicts_rejected": self.duplicate_conflicts_rejected,
            "duplicate_publication_idempotent": self.duplicate_publication_idempotent,
            "errors": list(self.errors),
            "inventory_reference_authoritative": self.inventory_reference_authoritative,
            "manifest_objects_verified": self.manifest_objects_verified,
            "no_clobber_enforced": self.no_clobber_enforced,
            "publication_receipts_operational": self.publication_receipts_operational,
            "release": self.release,
            "release_scale_claimed": False,
            "seal_requires_verified_manifest": self.seal_requires_verified_manifest,
            "semantic_envelope_topology_independent": (
                self.semantic_envelope_topology_independent
            ),
            "shard_index_canonical": self.shard_index_canonical,
            "staged_shard_recovery_idempotent": self.staged_shard_recovery_idempotent,
            "status": "valid" if self.success else "invalid",
            "vector_catalog_digest": self.vector_catalog_digest,
            "vector_count": self.vector_count,
            "vector_evidence_version": 1,
            "vectors_passed": self.vectors_passed,
        }


def _producer_digest() -> str:
    return canonical_sha256({"producer_contract_id": "publication-fixture", "version": 1})


def _sample_spec(sample_index: int = 0) -> SampleExecutionSpec:
    return SampleExecutionSpec(
        global_ordinal=sample_index,
        sample_key=SampleKey("v0.4", "publication-v1", sample_index),
        attempt_range=AttemptRange(3),
        producer_contract_id="publication-fixture",
        producer_contract_version=1,
        producer_contract_digest=_producer_digest(),
    )


def publication_fixture_inventory(
    *,
    shard_count: int = 7,
    sample_count: int = 1,
) -> ExecutionInventory:
    if type(sample_count) is not int or sample_count <= 0:
        raise ValueError("sample_count must be a positive exact integer")
    retry_policy = OperationalRetryPolicy(2)
    return ExecutionInventory(
        release="v0.4",
        generation_namespace=build_generation_namespace(_TARGET_DEFINITION_DIGEST),
        root_seed_commitment=_ROOT_SEED_COMMITMENT,
        sample_key_encoding_id=SAMPLE_KEY_ENCODING_ID,
        sample_key_encoding_version=SAMPLE_KEY_ENCODING_VERSION,
        sample_key_encoding_policy_digest=canonical_sha256(
            sample_key_encoding_policy_document()
        ),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_policy_document()),
        shard_count=shard_count,
        operational_retry_policy_digest=retry_policy.digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(
            execution_validation_policy_document()
        ),
        required_schema_versions=RequiredSchemaVersions(),
        samples=tuple(_sample_spec(index) for index in range(sample_count)),
    )


def _attempt_key(sample_index: int = 0, attempt_index: int = 1) -> AttemptKey:
    return AttemptKey(_sample_spec(sample_index).sample_key, attempt_index)


def publication_fixture_accepted(
    sample_index: int = 0,
    attempt_index: int = 1,
) -> AttemptAccepted:
    attempt = _attempt_key(sample_index, attempt_index)
    return AttemptAccepted(
        attempt_key=attempt,
        generation_namespace_digest=publication_fixture_inventory().generation_namespace_digest,
        attempt_input_commitment_digest=canonical_sha256(
            {
                "attempt": attempt.attempt_index,
                "input": "publication-v1",
                "sample_index": sample_index,
            }
        ),
        search_branch_digest=canonical_sha256(
            {
                "attempt": attempt.attempt_index,
                "branch": "accepted",
                "sample_index": sample_index,
            }
        ),
        choice_ledger_digest=canonical_sha256(
            {
                "attempt": attempt.attempt_index,
                "choices": "publication-v1",
                "sample_index": sample_index,
            }
        ),
        identity_ledger_digest=canonical_sha256(
            {
                "attempt": attempt.attempt_index,
                "identities": "publication-v1",
                "sample_index": sample_index,
            }
        ),
        result=CanonicalObject.from_pairs(
            (
                ("accepted", True),
                ("fixture", "publication-v1"),
                ("sample_index", sample_index),
            )
        ),
    )


def publication_fixture_rejected() -> AttemptRejected:
    attempt = _attempt_key(0, 0)
    search_branch_digest = canonical_sha256(
        {"attempt": attempt.attempt_index, "branch": "rejected"}
    )
    return AttemptRejected(
        attempt_key=attempt,
        generation_namespace_digest=publication_fixture_inventory().generation_namespace_digest,
        attempt_input_commitment_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "input": "publication-v1"}
        ),
        search_branch_digest=search_branch_digest,
        choice_ledger_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "choices": "publication-v1"}
        ),
        identity_ledger_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "identities": "publication-v1"}
        ),
        rejection=AttemptRejection(
            cause=RejectionCause.PLAN_CONSTRUCTION_FAILURE,
            detail_code="publication-fixture-rejected",
            constraint_ids=("PUBLICATION.CONSTRAINT.A",),
            normalized_facts=CanonicalObject.from_pairs(
                (("attempt_index", attempt.attempt_index), ("fixture", "publication-v1"))
            ),
            search_branch_digest=search_branch_digest,
        ),
    )


def generate_publication_protocol_digests() -> dict[str, str]:
    inventory = publication_fixture_inventory()
    accepted = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    rejected = AttemptCompletionEnvelope.from_completion(publication_fixture_rejected())
    reference = InventoryCompletionReference.from_inventory(inventory, accepted)
    first_receipt = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-publication-v1",
        inventory_digest=inventory.digest,
        attempt_key=accepted.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=accepted.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    second_receipt = OperationalPublicationReceipt.append(
        previous=first_receipt,
        execution_run_id="run-publication-v1",
        inventory_digest=inventory.digest,
        attempt_key=accepted.attempt_key,
        object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
        object_digest=reference.digest,
        disposition=PublicationDisposition.EXISTING_IDENTICAL,
    )
    digests = {
        "accepted-completion-envelope": accepted.digest,
        "inventory-completion-reference": reference.digest,
        "no-clobber-layout": canonical_sha256(
            {
                "digest": accepted.digest,
                "relative_path": f"objects/{accepted.digest[:2]}/{accepted.digest[2:]}",
            }
        ),
        "publication-receipt-chain": canonical_sha256(
            [first_receipt.digest, second_receipt.digest]
        ),
        "rejected-completion-envelope": rejected.digest,
    }

    with TemporaryDirectory() as directory:
        root = Path(directory)
        store = ContentAddressedPublicationStore(root)
        coordinator = ShardPublicationCoordinator(store)
        shard_inventory = publication_fixture_inventory(shard_count=2, sample_count=3)
        publications = tuple(
            coordinator.publish_completion(
                shard_inventory,
                publication_fixture_accepted(sample_index),
                execution_run_id=f"run-publication-v1-{sample_index}",
            )
            for sample_index in range(3)
        )
        shard_zero = tuple(
            publication
            for publication in publications
            if publication.reference.global_ordinal % shard_inventory.shard_count == 0
        )
        published_shard = coordinator.publish_shard(shard_inventory, 0, shard_zero)
        digests.update(
            {
                "completion-publication-bundle": canonical_sha256(
                    [
                        {
                            "envelope": publication.envelope.digest,
                            "receipts": [receipt.digest for receipt in publication.receipts],
                            "reference": publication.reference.digest,
                        }
                        for publication in publications
                    ]
                ),
                "sealed-shard-manifest": published_shard.manifest.digest,
                "shard-index": published_shard.index.digest,
                "shard-seal-reference": canonical_sha256(
                    {
                        "manifest_digest": published_shard.manifest.digest,
                        "relative_path": store.reference_path(
                            "seals",
                            shard_inventory.digest,
                            0,
                            published_shard.manifest.digest,
                        )
                        .relative_to(root)
                        .as_posix(),
                    }
                ),
            }
        )
    return digests


def _validate_store() -> tuple[bool, bool, bool, bool]:
    accepted = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        first = store.publish_bytes(
            accepted.canonical_bytes,
            expected_digest=accepted.digest,
        )
        second = store.publish_bytes(
            accepted.canonical_bytes,
            expected_digest=accepted.digest,
        )
        no_clobber = (
            first.disposition is PublicationDisposition.PUBLISHED
            and store.read_verified(accepted.digest) == accepted.canonical_bytes
        )
        duplicate = second.disposition is PublicationDisposition.EXISTING_IDENTICAL

    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        corrupt_path = store.object_path(accepted.digest)
        corrupt_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt_path.write_bytes(b"corrupt\n")
        try:
            store.publish_bytes(
                accepted.canonical_bytes,
                expected_digest=accepted.digest,
            )
        except PublicationCorruptionError:
            corruption_rejected = True
        else:
            corruption_rejected = False

    stages = ("temporary-created", "content-written", "file-synced", "object-installed")
    recovered = True
    for stage in stages:
        with TemporaryDirectory() as directory:
            store = ContentAddressedPublicationStore(Path(directory))

            def inject(current: str, *, expected: str = stage) -> None:
                if current == expected:
                    raise InjectedPublicationCrash(current)

            with suppress(InjectedPublicationCrash):
                store.publish_bytes(
                    accepted.canonical_bytes,
                    expected_digest=accepted.digest,
                    fault_injector=inject,
                )
            report = store.recover()
            if tuple(store.temporary_root.glob("*.tmp")):
                recovered = False
            if stage == "object-installed":
                try:
                    store.read_verified(accepted.digest)
                except PublicationStoreError:
                    recovered = False
                if report.authoritative_objects_verified != 1:
                    recovered = False
            elif store.object_path(accepted.digest).exists():
                recovered = False
    return no_clobber, duplicate, corruption_rejected, recovered


def _validate_shards() -> tuple[bool, bool, bool, bool, bool]:
    inventory = publication_fixture_inventory(shard_count=2, sample_count=3)
    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        coordinator = ShardPublicationCoordinator(store)
        publications = tuple(
            coordinator.publish_completion(
                inventory,
                publication_fixture_accepted(sample_index),
                execution_run_id=f"run-shard-{sample_index}",
            )
            for sample_index in (2, 0, 1)
        )
        shard_zero = tuple(
            publication
            for publication in publications
            if publication.reference.global_ordinal % inventory.shard_count == 0
        )
        first_index = ShardIndex.from_publications(inventory, 0, shard_zero)
        second_index = ShardIndex.from_publications(
            inventory,
            0,
            tuple(reversed(shard_zero)),
        )
        canonical = first_index == second_index
        duplicate = ShardIndex.from_entries(
            inventory,
            0,
            first_index.entries + (first_index.entries[0],),
        )
        canonical = canonical and duplicate == first_index
        conflicting = replace(
            first_index.entries[0],
            completion_envelope_digest="0" * 64,
        )
        try:
            ShardIndex.from_entries(
                inventory,
                0,
                first_index.entries + (conflicting,),
            )
        except ShardPublicationError:
            conflict_rejected = True
        else:
            conflict_rejected = False
        published = coordinator.publish_shard(inventory, 0, shard_zero)
        objects_verified = (
            store.read_verified(published.manifest.digest)
            == published.manifest.canonical_bytes
            and store.reference_exists_verified(
                category="seals",
                inventory_digest=inventory.digest,
                shard_index=0,
                digest=published.manifest.digest,
            )
        )

    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        coordinator = ShardPublicationCoordinator(store)
        publication = coordinator.publish_completion(
            inventory,
            publication_fixture_accepted(0),
            execution_run_id="run-premature-seal",
        )
        index = ShardIndex.from_publications(inventory, 0, (publication,))
        try:
            SealedShardManifest.seal(inventory, index, (publication,), store)
        except (ShardPublicationError, PublicationStoreError):
            premature_rejected = True
        else:
            premature_rejected = False

    stages = (
        "completion-receipt-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
        "shard-manifest-persisted",
        "shard-seal-published",
    )
    recovery_idempotent = True
    for stage in stages:
        with TemporaryDirectory() as directory:
            store = ContentAddressedPublicationStore(Path(directory))
            coordinator = ShardPublicationCoordinator(store)

            def inject(current: str, *, expected: str = stage) -> None:
                if current == expected:
                    raise InjectedPublicationCrash(current)

            if stage in {"completion-receipt-persisted", "reference-receipt-persisted"}:
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
    return canonical, conflict_rejected, objects_verified, premature_rejected, recovery_idempotent


def validate_publication_protocol(release: str) -> PublicationValidationReport:
    from csd_foundry.synthesis.v0_4.publication_vectors import (
        EXPECTED_PUBLICATION_DIGESTS,
        FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST,
        PUBLICATION_VECTOR_IDS,
        validate_publication_vector_catalog,
    )

    errors: list[str] = []
    if release != "v0.4":
        errors.append("publication validation supports only v0.4")
    try:
        validate_publication_vector_catalog()
    except ValueError as exc:
        errors.append(str(exc))
    actual = generate_publication_protocol_digests()
    vectors_passed = sum(
        actual.get(vector_id) == EXPECTED_PUBLICATION_DIGESTS.get(vector_id)
        for vector_id in PUBLICATION_VECTOR_IDS
    )
    if actual != EXPECTED_PUBLICATION_DIGESTS:
        errors.append("publication protocol vectors changed")

    inventory = publication_fixture_inventory()
    completion = publication_fixture_accepted()
    envelope = AttemptCompletionEnvelope.from_completion(completion)
    equivalent_envelope = AttemptCompletionEnvelope.from_completion(completion)
    topology_independent = envelope == equivalent_envelope
    reference = InventoryCompletionReference.from_inventory(inventory, envelope)
    try:
        reference.validate_against(inventory, envelope)
        inventory_authoritative = True
    except ValueError:
        inventory_authoritative = False
    first_receipt = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-a",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=envelope.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    second_receipt = OperationalPublicationReceipt.append(
        previous=first_receipt,
        execution_run_id="run-a",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.INVENTORY_COMPLETION_REFERENCE,
        object_digest=reference.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    try:
        validate_publication_receipt_chain((first_receipt, second_receipt))
        receipts_operational = (
            "execution_run_id" not in envelope.to_json_value()
            and "inventory_digest" not in envelope.to_json_value()
            and first_receipt.execution_run_id != "run-b"
        )
    except ValueError:
        receipts_operational = False

    no_clobber, duplicate, corruption_rejected, recovered = _validate_store()
    (
        shard_index_canonical,
        duplicate_conflicts_rejected,
        manifest_objects_verified,
        seal_requires_verified_manifest,
        staged_shard_recovery_idempotent,
    ) = _validate_shards()
    for condition, message in (
        (topology_independent, "semantic completion envelope is topology-dependent"),
        (inventory_authoritative, "inventory reference authority validation failed"),
        (receipts_operational, "publication receipts leaked into semantic identity"),
        (no_clobber, "no-clobber publication validation failed"),
        (duplicate, "duplicate publication was not idempotent"),
        (corruption_rejected, "corrupted existing object was accepted"),
        (recovered, "temporary publication debris was not recoverable"),
        (shard_index_canonical, "shard index is completion-order dependent"),
        (duplicate_conflicts_rejected, "conflicting shard index entry was accepted"),
        (manifest_objects_verified, "sealed manifest did not verify its object set"),
        (seal_requires_verified_manifest, "premature shard sealing was accepted"),
        (staged_shard_recovery_idempotent, "staged shard recovery was not idempotent"),
    ):
        if not condition:
            errors.append(message)

    return PublicationValidationReport(
        release=release,
        vectors_passed=vectors_passed,
        vector_count=len(PUBLICATION_VECTOR_IDS),
        vector_catalog_digest=FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST,
        semantic_envelope_topology_independent=topology_independent,
        inventory_reference_authoritative=inventory_authoritative,
        publication_receipts_operational=receipts_operational,
        no_clobber_enforced=no_clobber,
        duplicate_publication_idempotent=duplicate,
        corrupted_existing_rejected=corruption_rejected,
        crash_debris_recoverable=recovered,
        shard_index_canonical=shard_index_canonical,
        duplicate_conflicts_rejected=duplicate_conflicts_rejected,
        manifest_objects_verified=manifest_objects_verified,
        seal_requires_verified_manifest=seal_requires_verified_manifest,
        staged_shard_recovery_idempotent=staged_shard_recovery_idempotent,
        errors=tuple(errors),
    )
''',
)

write(
    "tests/test_v0_4_publication_shards.py",
    '''from __future__ import annotations

from contextlib import suppress
from dataclasses import replace
from pathlib import Path

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
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "specs/v0.4/shard_manifest.schema.json"
    )
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
        "completion-receipt-persisted",
        "reference-receipt-persisted",
        "shard-index-persisted",
        "shard-manifest-persisted",
        "shard-seal-published",
    ),
)
def test_staged_publication_is_crash_idempotent(tmp_path: Path, stage: str) -> None:
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
''',
)

protocol_test_path = ROOT / "tests/test_v0_4_publication_protocol.py"
protocol_test = protocol_test_path.read_text(encoding="utf-8")
protocol_test = protocol_test.replace(
    "assert report.vectors_passed == report.vector_count == 5",
    "assert report.vectors_passed == report.vector_count == 9",
    1,
)
protocol_test_path.write_text(protocol_test, encoding="utf-8")

docs_path = ROOT / "docs/publication_protocol_v0.4.md"
docs = docs_path.read_text(encoding="utf-8")
docs = docs.replace(
    "This first implementation slice establishes the three-record separation and the minimal\ncontent-addressed no-clobber object store. Shard indexes, manifests, seals, streaming\nreconciliation, and canonical corpus merge remain outside this slice.",
    "The protocol establishes the three-record separation, durable content-addressed no-clobber\npublication, canonical shard-index snapshots, factory-verified manifests, and append-only seal\nreferences. Streaming reconciliation and canonical corpus merge remain outside this slice.",
    1,
)
docs += '''
## Canonical shard indexes

A `ShardIndex` is an immutable content-addressed snapshot. Entries are sorted by global
ordinal, attempt index, completion-envelope digest, completion-reference digest, and final
publication-receipt digest. Construction collapses exact duplicates and fails closed when two
different completions occupy one inventory-attempt position.

Index snapshots do not commit construction order or predecessor snapshots. Old snapshots
remain addressable in the append-only store, while the final snapshot remains invariant to
worker count and completion order.

## Manifest sealing

`SealedShardManifest` has no public constructor. Its factory requires the exact execution
inventory, canonical shard index, complete published-completion set, and publication store.
Before issuing the manifest it verifies:

- shard-policy-v1 assignment for every index entry;
- the durable content-addressed index object and append-only index reference;
- every completion envelope, inventory reference, and receipt-chain object;
- exact inventory, namespace, and required-schema commitments;
- complete entry-aligned digest lists and aggregate object-set commitment.

The manifest's construction is the logical seal. Publication then installs append-only hard
links for the index, manifest, and seal under inventory-and-shard namespaces. A seal is
therefore a durable reference to verified manifest bytes, not a mutable status flag.

## Staged crash recovery

Completion receipts, inventory references, shard indexes, manifests, and seals are individually
content addressed and installed with no-clobber semantics. Re-executing after interruption
classifies already installed bytes as identical and finishes the remaining stages. Tests inject
failures after each durable stage and require convergence to the same semantic envelope and a
verified seal.
'''
docs_path.write_text(docs, encoding="utf-8")

sys.path.insert(0, str(ROOT / "src"))
importlib.invalidate_caches()
from csd_foundry.synthesis.v0_4.publication_validation import (
    generate_publication_protocol_digests,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

vector_ids = (
    "accepted-completion-envelope",
    "rejected-completion-envelope",
    "inventory-completion-reference",
    "publication-receipt-chain",
    "no-clobber-layout",
    "completion-publication-bundle",
    "shard-index",
    "sealed-shard-manifest",
    "shard-seal-reference",
)
expected = generate_publication_protocol_digests()
if set(vector_ids) != set(expected):
    raise RuntimeError("generated publication vectors do not match the frozen catalog")
commitment = {
    "evidence_version": 1,
    "expected_digests": expected,
    "vector_ids": list(vector_ids),
}
catalog_digest = canonical_sha256(commitment)
constant_lines: list[str] = []
mapping_lines = ["EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {"]
for index, key in enumerate(sorted(expected)):
    name = f"_EXPECTED_PUBLICATION_DIGEST_{index}"
    constant_lines.extend((f"{name} = (", f'    "{expected[key]}"', ")"))
    mapping_lines.append(f'    "{key}": {name},')
mapping_lines.append("}")
vectors_source = f'''"""Frozen known-answer vectors for v0.4 publication protocol version 1."""

from __future__ import annotations

from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

PUBLICATION_VECTOR_EVIDENCE_VERSION = 1
PUBLICATION_VECTOR_IDS = {vector_ids!r}
{chr(10).join(constant_lines)}

{chr(10).join(mapping_lines)}
FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST = (
    "{catalog_digest}"
)


def publication_vector_catalog_commitment() -> dict[str, object]:
    return {{
        "evidence_version": PUBLICATION_VECTOR_EVIDENCE_VERSION,
        "expected_digests": EXPECTED_PUBLICATION_DIGESTS,
        "vector_ids": list(PUBLICATION_VECTOR_IDS),
    }}


def validate_publication_vector_catalog() -> None:
    if tuple(EXPECTED_PUBLICATION_DIGESTS) != tuple(sorted(EXPECTED_PUBLICATION_DIGESTS)):
        raise ValueError("publication vector digests must use sorted vector IDs")
    if set(PUBLICATION_VECTOR_IDS) != set(EXPECTED_PUBLICATION_DIGESTS):
        raise ValueError("publication vector IDs and expected digests differ")
    if (
        canonical_sha256(publication_vector_catalog_commitment())
        != FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST
    ):
        raise ValueError("publication vector catalog digest changed")
'''
write("src/csd_foundry/synthesis/v0_4/publication_vectors.py", vectors_source)
canary = {
    "catalog_digest": catalog_digest,
    "evidence_version": 1,
    "expected_digests": dict(sorted(expected.items())),
    "release": "v0.4",
    "schema_version": "0.4.0",
    "vector_ids": list(vector_ids),
}
write(
    "data/canary/v0.4/publication-v1/publication_vectors.json",
    json.dumps(canary, indent=2, sort_keys=True) + "\n",
)
importlib.invalidate_caches()
from csd_foundry.synthesis.v0_4.publication_validation import validate_publication_protocol

report = validate_publication_protocol("v0.4").to_dict()
if report["status"] != "valid":
    raise RuntimeError(f"generated publication report is invalid: {report}")
write(
    "reports/publication_protocol_v0.4.json",
    json.dumps(report, indent=2, sort_keys=True) + "\n",
)
