"""Streaming cross-shard reconciliation and atomic canonical-merge publication."""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.synthesis.v0_4.attempts import (
    AttemptAccepted,
    AttemptCompletion,
    AttemptRejected,
)
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, SampleKey
from csd_foundry.synthesis.v0_4.publication_shards import (
    PublishedCompletion,
    ShardIndexEntry,
)
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    PublicationStoreError,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
)

RECONCILIATION_POLICY_ID = "csd-streaming-reconciliation"
RECONCILIATION_POLICY_VERSION = 1
RECONCILIATION_VALIDATION_MODE = "FULL_REPLAY"
REPLAY_ATTESTATION_SCHEMA_VERSION = "csd-replay-attestation/0.4"
SEMANTIC_CORPUS_RECORD_SCHEMA_VERSION = "csd-semantic-corpus-record/0.4"
RUN_EVIDENCE_RECORD_SCHEMA_VERSION = "csd-run-evidence-record/0.4"
MERKLE_NODE_SCHEMA_VERSION = "csd-streaming-merkle-node/0.4"
MERKLE_ROOT_SCHEMA_VERSION = "csd-streaming-merkle-root/0.4"
SEMANTIC_CORPUS_MANIFEST_SCHEMA_VERSION = "csd-semantic-corpus-manifest/0.4"
RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION = "csd-run-evidence-manifest/0.4"
CANONICAL_MERGE_SEAL_SCHEMA_VERSION = "csd-canonical-merge-seal/0.4"
_UINT32_MAX = (1 << 32) - 1


class ReconciliationError(ValueError):
    """Raised when reconciliation evidence violates the v0.4 contract."""


class ReconciliationConflictError(ReconciliationError):
    """Raised when one inventory-attempt position has conflicting completion evidence."""


class SampleResolutionStatus(StrEnum):
    ACCEPTED = "accepted"
    EXHAUSTED = "exhausted"


def _require_uint32(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= _UINT32_MAX:
        raise ReconciliationError(f"{field_name} must be an exact uint32")
    return value


def _require_digest(value: object, field_name: str) -> str:
    try:
        return ContentAddressedPublicationStore._require_digest(value)
    except PublicationStoreError as exc:
        raise ReconciliationError(f"invalid {field_name}") from exc


def _sample_key_value(sample_key: SampleKey) -> dict[str, object]:
    if type(sample_key) is not SampleKey:
        raise ReconciliationError("sample_key must use the exact SampleKey class")
    return {
        "release": sample_key.release,
        "sample_index": sample_key.sample_index,
        "target_id": sample_key.target_id,
    }


def _attempt_key_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey:
        raise ReconciliationError("attempt_key must use the exact AttemptKey class")
    return {
        **_sample_key_value(attempt_key.sample_key),
        "attempt_index": attempt_key.attempt_index,
    }


@dataclass(frozen=True, slots=True)
class ReplayAttestation:
    """Independent FULL_REPLAY attestation for one published semantic completion."""

    attempt_key: AttemptKey
    completion_envelope_digest: str
    completion_digest: str
    replay_evidence_digest: str
    attestor_id: str
    attestor_version: int
    validation_mode: str = RECONCILIATION_VALIDATION_MODE
    schema_version: str = REPLAY_ATTESTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ReplayAttestation:
            raise ReconciliationError("replay attestations must use the exact class")
        _attempt_key_value(self.attempt_key)
        _require_digest(self.completion_envelope_digest, "completion_envelope_digest")
        _require_digest(self.completion_digest, "completion_digest")
        _require_digest(self.replay_evidence_digest, "replay_evidence_digest")
        if type(self.attestor_id) is not str or not self.attestor_id:
            raise ReconciliationError("attestor_id must be a nonempty exact string")
        _require_uint32(self.attestor_version, "attestor_version")
        if self.attestor_version == 0:
            raise ReconciliationError("attestor_version must be positive")
        if self.validation_mode != RECONCILIATION_VALIDATION_MODE:
            raise ReconciliationError("reconciliation requires FULL_REPLAY")
        if self.schema_version != REPLAY_ATTESTATION_SCHEMA_VERSION:
            raise ReconciliationError("unknown replay attestation schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "attestor_id": self.attestor_id,
            "attestor_version": self.attestor_version,
            "completion_digest": self.completion_digest,
            "completion_envelope_digest": self.completion_envelope_digest,
            "replay_evidence_digest": self.replay_evidence_digest,
            "schema_version": self.schema_version,
            "validation_mode": self.validation_mode,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AttestedCompletion:
    """A published completion reconstructed and independently replayed by the caller."""

    publication: PublishedCompletion
    completion: AttemptCompletion
    attestation: ReplayAttestation

    def __post_init__(self) -> None:
        if type(self) is not AttestedCompletion:
            raise ReconciliationError("attested completions must use the exact class")
        if type(self.publication) is not PublishedCompletion:
            raise ReconciliationError("attested completion requires an exact publication")
        if type(self.completion) not in {AttemptAccepted, AttemptRejected}:
            raise ReconciliationError("attested completion requires an exact semantic completion")
        if type(self.attestation) is not ReplayAttestation:
            raise ReconciliationError("attested completion requires an exact attestation")
        self.publication.envelope.validate_completion(self.completion)
        if self.attestation.attempt_key != self.completion.attempt_key:
            raise ReconciliationError("attestation belongs to another attempt")
        if self.attestation.completion_envelope_digest != self.publication.envelope.digest:
            raise ReconciliationError("attestation identifies another completion envelope")
        if self.attestation.completion_digest != self.completion.completion_digest:
            raise ReconciliationError("attestation identifies another semantic completion")


@dataclass(frozen=True, slots=True)
class SourcedShardEntry:
    """One canonical shard entry with its sealed source-manifest identity."""

    entry: ShardIndexEntry
    source_manifest_digest: str

    def __post_init__(self) -> None:
        if type(self) is not SourcedShardEntry:
            raise ReconciliationError("sourced entries must use the exact class")
        if type(self.entry) is not ShardIndexEntry:
            raise ReconciliationError("sourced entry requires an exact shard entry")
        _require_digest(self.source_manifest_digest, "source_manifest_digest")

    @property
    def position_key(self) -> tuple[int, int]:
        return self.entry.position_key

    @property
    def sort_key(self) -> tuple[int, int, str, str, str, str]:
        return (*self.entry.sort_key, self.source_manifest_digest)


class _PeekableEntryStream:
    def __init__(self, values: Iterable[SourcedShardEntry]) -> None:
        self._iterator = iter(values)

    def next(self) -> SourcedShardEntry | None:
        try:
            return next(self._iterator)
        except StopIteration:
            return None


def merge_sorted_entry_streams(
    streams: tuple[Iterable[SourcedShardEntry], ...],
) -> Iterator[SourcedShardEntry]:
    """Merge sorted streams using O(stream-count) heap memory and fail closed on conflicts."""

    if type(streams) is not tuple or not streams:
        raise ReconciliationError("reconciliation requires a nonempty immutable stream tuple")
    cursors = tuple(_PeekableEntryStream(stream) for stream in streams)
    heap: list[tuple[tuple[int, int, str, str, str, str], int, SourcedShardEntry]] = []
    for stream_index, cursor in enumerate(cursors):
        item = cursor.next()
        if item is not None:
            heapq.heappush(heap, (item.sort_key, stream_index, item))

    previous: SourcedShardEntry | None = None
    while heap:
        _, stream_index, item = heapq.heappop(heap)
        next_item = cursors[stream_index].next()
        if next_item is not None:
            if next_item.sort_key < item.sort_key:
                raise ReconciliationError("shard entry stream is not canonically sorted")
            heapq.heappush(heap, (next_item.sort_key, stream_index, next_item))

        if previous is not None and previous.position_key == item.position_key:
            if previous.entry != item.entry:
                raise ReconciliationConflictError(
                    "conflicting completions occupy one inventory attempt position"
                )
            continue
        previous = item
        yield item
