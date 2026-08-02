"""Canonical manifests, final seal, and result contracts for v0.4 reconciliation."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.publication_store import PublicationResult
from csd_foundry.synthesis.v0_4.reconciliation_core import (
    CANONICAL_MERGE_SEAL_SCHEMA_VERSION,
    RECONCILIATION_POLICY_ID,
    RECONCILIATION_POLICY_VERSION,
    RECONCILIATION_VALIDATION_MODE,
    RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
    SEMANTIC_CORPUS_MANIFEST_SCHEMA_VERSION,
    ReconciliationError,
    _require_digest,
    _require_uint32,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256


@dataclass(frozen=True, slots=True)
class SemanticCorpusManifest:
    generation_namespace_digest: str
    merkle_root_digest: str
    record_count: int
    peak_count: int
    validation_mode: str = RECONCILIATION_VALIDATION_MODE
    schema_version: str = SEMANTIC_CORPUS_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not SemanticCorpusManifest:
            raise ReconciliationError("semantic manifests must use the exact class")
        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")
        _require_digest(self.merkle_root_digest, "merkle_root_digest")
        _require_uint32(self.record_count, "record_count")
        _require_uint32(self.peak_count, "peak_count")
        if self.validation_mode != RECONCILIATION_VALIDATION_MODE:
            raise ReconciliationError("semantic manifest requires FULL_REPLAY")
        if self.schema_version != SEMANTIC_CORPUS_MANIFEST_SCHEMA_VERSION:
            raise ReconciliationError("unknown semantic corpus manifest schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "generation_namespace_digest": self.generation_namespace_digest,
            "merkle_root_digest": self.merkle_root_digest,
            "peak_count": self.peak_count,
            "record_count": self.record_count,
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
class RunEvidenceManifest:
    inventory_digest: str
    shard_count: int
    source_manifest_digests: tuple[str, ...]
    merkle_root_digest: str
    record_count: int
    replay_attestation_count: int
    peak_count: int
    conflict_count: int = 0
    reconciliation_policy_id: str = RECONCILIATION_POLICY_ID
    reconciliation_policy_version: int = RECONCILIATION_POLICY_VERSION
    schema_version: str = RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not RunEvidenceManifest:
            raise ReconciliationError("run evidence manifests must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        _require_uint32(self.shard_count, "shard_count")
        if self.shard_count == 0:
            raise ReconciliationError("shard_count must be positive")
        if type(self.source_manifest_digests) is not tuple:
            raise ReconciliationError("source manifest digests must use an immutable tuple")
        for digest in self.source_manifest_digests:
            _require_digest(digest, "source_manifest_digest")
        if tuple(sorted(self.source_manifest_digests)) != self.source_manifest_digests:
            raise ReconciliationError("source manifest digests must use canonical ordering")
        if len(self.source_manifest_digests) != self.shard_count:
            raise ReconciliationError("run manifest must identify every logical shard")
        _require_digest(self.merkle_root_digest, "merkle_root_digest")
        for field_name, value in (
            ("record_count", self.record_count),
            ("replay_attestation_count", self.replay_attestation_count),
            ("peak_count", self.peak_count),
            ("conflict_count", self.conflict_count),
            ("reconciliation_policy_version", self.reconciliation_policy_version),
        ):
            _require_uint32(value, field_name)
        if self.conflict_count != 0:
            raise ReconciliationError("conflicted runs cannot produce a sealed manifest")
        if self.reconciliation_policy_id != RECONCILIATION_POLICY_ID:
            raise ReconciliationError("unknown reconciliation policy")
        if self.reconciliation_policy_version != RECONCILIATION_POLICY_VERSION:
            raise ReconciliationError("unknown reconciliation policy version")
        if self.schema_version != RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION:
            raise ReconciliationError("unknown run evidence manifest schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "conflict_count": self.conflict_count,
            "inventory_digest": self.inventory_digest,
            "merkle_root_digest": self.merkle_root_digest,
            "peak_count": self.peak_count,
            "reconciliation_policy_id": self.reconciliation_policy_id,
            "reconciliation_policy_version": self.reconciliation_policy_version,
            "record_count": self.record_count,
            "replay_attestation_count": self.replay_attestation_count,
            "schema_version": self.schema_version,
            "shard_count": self.shard_count,
            "source_manifest_digests": list(self.source_manifest_digests),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class CanonicalMergeSeal:
    inventory_digest: str
    semantic_corpus_manifest_digest: str
    run_evidence_manifest_digest: str
    source_manifest_digests: tuple[str, ...]
    sealed: bool = True
    schema_version: str = CANONICAL_MERGE_SEAL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not CanonicalMergeSeal:
            raise ReconciliationError("merge seals must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        _require_digest(
            self.semantic_corpus_manifest_digest,
            "semantic_corpus_manifest_digest",
        )
        _require_digest(self.run_evidence_manifest_digest, "run_evidence_manifest_digest")
        if type(self.source_manifest_digests) is not tuple:
            raise ReconciliationError("source manifest digests must use an immutable tuple")
        for digest in self.source_manifest_digests:
            _require_digest(digest, "source_manifest_digest")
        if tuple(sorted(self.source_manifest_digests)) != self.source_manifest_digests:
            raise ReconciliationError("source manifests must use canonical ordering")
        if self.sealed is not True:
            raise ReconciliationError("canonical merge seal must be final")
        if self.schema_version != CANONICAL_MERGE_SEAL_SCHEMA_VERSION:
            raise ReconciliationError("unknown canonical merge seal schema version")

    def to_json_value(self) -> dict[str, object]:
        return {
            "inventory_digest": self.inventory_digest,
            "run_evidence_manifest_digest": self.run_evidence_manifest_digest,
            "schema_version": self.schema_version,
            "sealed": self.sealed,
            "semantic_corpus_manifest_digest": self.semantic_corpus_manifest_digest,
            "source_manifest_digests": list(self.source_manifest_digests),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    semantic_manifest: SemanticCorpusManifest
    run_evidence_manifest: RunEvidenceManifest
    seal: CanonicalMergeSeal
    semantic_manifest_publication: PublicationResult
    run_evidence_manifest_publication: PublicationResult
    seal_publication: PublicationResult
    sample_count: int
    accepted_sample_count: int
    exhausted_sample_count: int
    replay_attestation_count: int
    peak_buffered_entries: int

    def __post_init__(self) -> None:
        if type(self) is not ReconciliationResult:
            raise ReconciliationError("reconciliation results must use the exact class")
        for field_name, value in (
            ("sample_count", self.sample_count),
            ("accepted_sample_count", self.accepted_sample_count),
            ("exhausted_sample_count", self.exhausted_sample_count),
            ("replay_attestation_count", self.replay_attestation_count),
            ("peak_buffered_entries", self.peak_buffered_entries),
        ):
            _require_uint32(value, field_name)
        if self.accepted_sample_count + self.exhausted_sample_count != self.sample_count:
            raise ReconciliationError("sample counts do not reconcile")
