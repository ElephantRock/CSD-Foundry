"""Streaming semantic/run records and Merkle accumulation for v0.4 reconciliation."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import SampleKey
from csd_foundry.synthesis.v0_4.publication_store import (
    ContentAddressedPublicationStore,
    PublicationResult,
)
from csd_foundry.synthesis.v0_4.reconciliation_core import (
    MERKLE_NODE_SCHEMA_VERSION,
    MERKLE_ROOT_SCHEMA_VERSION,
    RUN_EVIDENCE_RECORD_SCHEMA_VERSION,
    SEMANTIC_CORPUS_RECORD_SCHEMA_VERSION,
    ReconciliationError,
    SampleResolutionStatus,
    _require_digest,
    _require_uint32,
    _sample_key_value,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256


@dataclass(frozen=True, slots=True)
class SemanticCorpusRecord:
    global_ordinal: int
    sample_key: SampleKey
    accepted_attempt_index: int
    accepted_completion_digest: str
    rejected_prefix_completion_digests: tuple[str, ...]
    replay_attestation_digests: tuple[str, ...]
    result: CanonicalObject
    schema_version: str = SEMANTIC_CORPUS_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not SemanticCorpusRecord:
            raise ReconciliationError("semantic records must use the exact class")
        _require_uint32(self.global_ordinal, "global_ordinal")
        _sample_key_value(self.sample_key)
        _require_uint32(self.accepted_attempt_index, "accepted_attempt_index")
        _require_digest(self.accepted_completion_digest, "accepted_completion_digest")
        if type(self.rejected_prefix_completion_digests) is not tuple:
            raise ReconciliationError("rejected prefix digests must use an immutable tuple")
        if type(self.replay_attestation_digests) is not tuple:
            raise ReconciliationError("attestation digests must use an immutable tuple")
        if len(self.replay_attestation_digests) != (
            len(self.rejected_prefix_completion_digests) + 1
        ):
            raise ReconciliationError("semantic record must attest every prefix completion")
        for digest in self.rejected_prefix_completion_digests:
            _require_digest(digest, "rejected_prefix_completion_digest")
        for digest in self.replay_attestation_digests:
            _require_digest(digest, "replay_attestation_digest")
        if type(self.result) is not CanonicalObject:
            raise ReconciliationError("semantic result must use an exact CanonicalObject")
        if self.schema_version != SEMANTIC_CORPUS_RECORD_SCHEMA_VERSION:
            raise ReconciliationError("unknown semantic corpus record schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "accepted_attempt_index": self.accepted_attempt_index,
            "accepted_completion_digest": self.accepted_completion_digest,
            "global_ordinal": self.global_ordinal,
            "rejected_prefix_completion_digests": list(self.rejected_prefix_completion_digests),
            "replay_attestation_digests": list(self.replay_attestation_digests),
            "result": self.result.to_json_value(),
            "sample_key": _sample_key_value(self.sample_key),
            "schema_version": self.schema_version,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class RunEvidenceRecord:
    inventory_digest: str
    global_ordinal: int
    sample_key: SampleKey
    source_manifest_digests: tuple[str, ...]
    completion_envelope_digests: tuple[str, ...]
    completion_digests: tuple[str, ...]
    replay_attestation_digests: tuple[str, ...]
    resolution_status: SampleResolutionStatus
    selected_attempt_index: int | None
    resolution_digest: str
    schema_version: str = RUN_EVIDENCE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not RunEvidenceRecord:
            raise ReconciliationError("run evidence records must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        _require_uint32(self.global_ordinal, "global_ordinal")
        _sample_key_value(self.sample_key)
        for field_name, values in (
            ("source_manifest_digests", self.source_manifest_digests),
            ("completion_envelope_digests", self.completion_envelope_digests),
            ("completion_digests", self.completion_digests),
            ("replay_attestation_digests", self.replay_attestation_digests),
        ):
            if type(values) is not tuple:
                raise ReconciliationError(f"{field_name} must use an immutable tuple")
            for digest in values:
                _require_digest(digest, field_name)
        count = len(self.completion_digests)
        if not count or len(self.completion_envelope_digests) != count:
            raise ReconciliationError("run evidence must identify every completion envelope")
        if len(self.replay_attestation_digests) != count:
            raise ReconciliationError("run evidence must attest every completion")
        if type(self.resolution_status) is not SampleResolutionStatus:
            raise ReconciliationError("resolution_status must use the exact enum")
        if self.resolution_status is SampleResolutionStatus.ACCEPTED:
            _require_uint32(self.selected_attempt_index, "selected_attempt_index")
        elif self.selected_attempt_index is not None:
            raise ReconciliationError("exhausted sample cannot select an attempt")
        _require_digest(self.resolution_digest, "resolution_digest")
        if self.schema_version != RUN_EVIDENCE_RECORD_SCHEMA_VERSION:
            raise ReconciliationError("unknown run evidence record schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "completion_digests": list(self.completion_digests),
            "completion_envelope_digests": list(self.completion_envelope_digests),
            "global_ordinal": self.global_ordinal,
            "inventory_digest": self.inventory_digest,
            "replay_attestation_digests": list(self.replay_attestation_digests),
            "resolution_digest": self.resolution_digest,
            "resolution_status": self.resolution_status.value,
            "sample_key": _sample_key_value(self.sample_key),
            "schema_version": self.schema_version,
            "selected_attempt_index": self.selected_attempt_index,
            "source_manifest_digests": list(self.source_manifest_digests),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class MerklePeak:
    level: int
    digest: str
    leaf_count: int

    def __post_init__(self) -> None:
        _require_uint32(self.level, "level")
        _require_digest(self.digest, "peak_digest")
        _require_uint32(self.leaf_count, "leaf_count")
        if self.leaf_count == 0:
            raise ReconciliationError("merkle peak must contain at least one leaf")

    def to_json_value(self) -> dict[str, object]:
        return {"digest": self.digest, "leaf_count": self.leaf_count, "level": self.level}


class StreamingMerkleAccumulator:
    """Append-only Merkle-forest accumulator using O(log(record-count)) memory."""

    def __init__(self, store: ContentAddressedPublicationStore, *, domain: str) -> None:
        if type(store) is not ContentAddressedPublicationStore:
            raise ReconciliationError("merkle accumulator requires the exact publication store")
        if type(domain) is not str or not domain:
            raise ReconciliationError("merkle domain must be a nonempty exact string")
        self._store = store
        self._domain = domain
        self._peaks: dict[int, MerklePeak] = {}
        self._record_count = 0

    @property
    def record_count(self) -> int:
        return self._record_count

    def add_record(self, canonical_bytes: bytes, digest: str) -> PublicationResult:
        if type(canonical_bytes) is not bytes:
            raise ReconciliationError("record bytes must use the exact bytes type")
        _require_digest(digest, "record_digest")
        result = self._store.publish_bytes(canonical_bytes, expected_digest=digest)
        current = MerklePeak(level=0, digest=digest, leaf_count=1)
        while current.level in self._peaks:
            left = self._peaks.pop(current.level)
            node = {
                "domain": self._domain,
                "leaf_count": left.leaf_count + current.leaf_count,
                "left_digest": left.digest,
                "level": current.level + 1,
                "right_digest": current.digest,
                "schema_version": MERKLE_NODE_SCHEMA_VERSION,
            }
            node_bytes = canonical_json_bytes(node)
            node_digest = canonical_sha256(node)
            self._store.publish_bytes(node_bytes, expected_digest=node_digest)
            current = MerklePeak(
                level=current.level + 1,
                digest=node_digest,
                leaf_count=left.leaf_count + current.leaf_count,
            )
        self._peaks[current.level] = current
        self._record_count += 1
        return result

    def finalize(self) -> tuple[str, int, int]:
        ordered = tuple(self._peaks[level] for level in sorted(self._peaks, reverse=True))
        root = {
            "domain": self._domain,
            "peak_count": len(ordered),
            "peaks": [peak.to_json_value() for peak in ordered],
            "record_count": self._record_count,
            "schema_version": MERKLE_ROOT_SCHEMA_VERSION,
        }
        root_bytes = canonical_json_bytes(root)
        root_digest = canonical_sha256(root)
        self._store.publish_bytes(root_bytes, expected_digest=root_digest)
        return root_digest, self._record_count, len(ordered)
