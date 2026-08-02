"""Fail-closed streaming reconciliation over factory-sealed v0.4 shard publications."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from csd_foundry.synthesis.v0_4.attempts import (
    AcceptedSampleReplay,
    IncompleteAttemptPrefix,
    resolve_attempt_prefix,
)
from csd_foundry.synthesis.v0_4.choice_paths import AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.execution_protocol import ExecutionInventory
from csd_foundry.synthesis.v0_4.exhaustion import ExhaustionEvidence
from csd_foundry.synthesis.v0_4.publication_protocol import reference_spec
from csd_foundry.synthesis.v0_4.publication_shards import (
    PublishedCompletion,
    PublishedShard,
    ShardIndexEntry,
)
from csd_foundry.synthesis.v0_4.publication_store import ContentAddressedPublicationStore
from csd_foundry.synthesis.v0_4.reconciliation_core import (
    AttestedCompletion,
    ReconciliationError,
    SampleResolutionStatus,
    SourcedShardEntry,
    merge_sorted_entry_streams,
)
from csd_foundry.synthesis.v0_4.reconciliation_manifests import (
    CanonicalMergeSeal,
    ReconciliationResult,
    RunEvidenceManifest,
    SemanticCorpusManifest,
)
from csd_foundry.synthesis.v0_4.reconciliation_records import (
    RunEvidenceRecord,
    SemanticCorpusRecord,
    StreamingMerkleAccumulator,
)

CompletionResolver = Callable[[ShardIndexEntry], PublishedCompletion]
ReplayAttestor = Callable[[PublishedCompletion], AttestedCompletion]


class StreamingReconciler:
    """Fail-closed streaming reconciliation over factory-sealed shard publications."""

    def __init__(
        self,
        inventory: ExecutionInventory,
        shards: tuple[PublishedShard, ...],
        store: ContentAddressedPublicationStore,
        *,
        completion_resolver: CompletionResolver,
        replay_attestor: ReplayAttestor,
    ) -> None:
        if type(inventory) is not ExecutionInventory:
            raise ReconciliationError("reconciler requires an exact execution inventory")
        if type(shards) is not tuple:
            raise ReconciliationError("shards must use an immutable tuple")
        if type(store) is not ContentAddressedPublicationStore:
            raise ReconciliationError("reconciler requires the exact publication store")
        if not callable(completion_resolver) or not callable(replay_attestor):
            raise ReconciliationError("reconciliation callbacks must be callable")
        self.inventory = inventory
        self.shards = shards
        self.store = store
        self.completion_resolver = completion_resolver
        self.replay_attestor = replay_attestor
        self._verify_shards()

    def _verify_shards(self) -> None:
        if len(self.shards) != self.inventory.shard_count:
            raise ReconciliationError("reconciliation requires every logical shard")
        if not all(type(shard) is PublishedShard for shard in self.shards):
            raise ReconciliationError("shards must use the exact PublishedShard class")
        ordered = tuple(sorted(self.shards, key=lambda shard: shard.index.shard_index))
        if tuple(shard.index.shard_index for shard in ordered) != tuple(
            range(self.inventory.shard_count)
        ):
            raise ReconciliationError("logical shard set is incomplete or duplicated")
        for shard in ordered:
            if shard.index.inventory_digest != self.inventory.digest:
                raise ReconciliationError("shard index belongs to another inventory")
            if shard.manifest.inventory_digest != self.inventory.digest:
                raise ReconciliationError("shard manifest belongs to another inventory")
            if shard.index.shard_count != self.inventory.shard_count:
                raise ReconciliationError("shard index uses another shard topology")
            if shard.manifest.shard_count != self.inventory.shard_count:
                raise ReconciliationError("shard manifest uses another shard topology")
            if self.store.read_verified(shard.index.digest) != shard.index.canonical_bytes:
                raise ReconciliationError("shard index object is not verified")
            if self.store.read_verified(shard.manifest.digest) != shard.manifest.canonical_bytes:
                raise ReconciliationError("shard manifest object is not verified")
            if not self.store.reference_exists_verified(
                category="seals",
                inventory_digest=self.inventory.digest,
                shard_index=shard.index.shard_index,
                digest=shard.manifest.digest,
            ):
                raise ReconciliationError("shard is not durably sealed")
        self.shards = ordered

    def _streams(self) -> tuple[Iterable[SourcedShardEntry], ...]:
        return tuple(
            (
                SourcedShardEntry(entry, shard.manifest.digest)
                for entry in shard.index.entries
            )
            for shard in self.shards
        )

    def _resolve_sample(
        self,
        global_ordinal: int,
        sourced_entries: tuple[SourcedShardEntry, ...],
    ) -> tuple[SemanticCorpusRecord | None, RunEvidenceRecord, int]:
        if not sourced_entries:
            raise ReconciliationError("sample resolution requires completion evidence")
        attested: list[AttestedCompletion] = []
        source_manifests: set[str] = set()
        sample_key: SampleKey | None = None
        attempt_range: AttemptRange | None = None
        for sourced in sourced_entries:
            publication = self.completion_resolver(sourced.entry)
            if type(publication) is not PublishedCompletion:
                raise ReconciliationError("completion resolver returned a derived value")
            if publication.envelope.digest != sourced.entry.completion_envelope_digest:
                raise ReconciliationError("resolved publication does not match shard entry")
            if publication.reference.digest != sourced.entry.inventory_completion_reference_digest:
                raise ReconciliationError("resolved reference does not match shard entry")
            publication.reference.validate_against(self.inventory, publication.envelope)
            spec = reference_spec(self.inventory, publication.reference)
            if spec.global_ordinal != global_ordinal:
                raise ReconciliationError("resolved publication belongs to another sample ordinal")
            if sample_key is None:
                sample_key = spec.sample_key
                attempt_range = spec.attempt_range
            elif sample_key != spec.sample_key or attempt_range != spec.attempt_range:
                raise ReconciliationError("one sample ordinal resolved to incompatible authority")
            replayed = self.replay_attestor(publication)
            if type(replayed) is not AttestedCompletion:
                raise ReconciliationError("replay attestor returned a derived value")
            if replayed.publication != publication:
                raise ReconciliationError("replay attestor returned another publication")
            attested.append(replayed)
            source_manifests.add(sourced.source_manifest_digest)

        if sample_key is None or attempt_range is None:
            raise ReconciliationError("sample authority could not be resolved")
        ordered = tuple(
            sorted(attested, key=lambda item: item.completion.attempt_key.attempt_index)
        )
        completions = tuple(item.completion for item in ordered)
        resolution = resolve_attempt_prefix(attempt_range, completions)
        if type(resolution) is IncompleteAttemptPrefix:
            raise ReconciliationError("incomplete attempt prefix cannot enter canonical merge")

        semantic: SemanticCorpusRecord | None
        if type(resolution) is AcceptedSampleReplay:
            semantic = SemanticCorpusRecord(
                global_ordinal=global_ordinal,
                sample_key=sample_key,
                accepted_attempt_index=resolution.accepted_attempt.attempt_key.attempt_index,
                accepted_completion_digest=resolution.accepted_attempt.completion_digest,
                rejected_prefix_completion_digests=tuple(
                    item.completion_digest for item in resolution.rejected_prefix
                ),
                replay_attestation_digests=tuple(item.attestation.digest for item in ordered),
                result=resolution.accepted_attempt.result,
            )
            status = SampleResolutionStatus.ACCEPTED
            selected_attempt_index: int | None = semantic.accepted_attempt_index
            resolution_digest = resolution.replay_digest
        elif type(resolution) is ExhaustionEvidence:
            semantic = None
            status = SampleResolutionStatus.EXHAUSTED
            selected_attempt_index = None
            resolution_digest = resolution.exhaustion_digest
        else:
            raise ReconciliationError("unsupported attempt resolution")

        run_evidence = RunEvidenceRecord(
            inventory_digest=self.inventory.digest,
            global_ordinal=global_ordinal,
            sample_key=sample_key,
            source_manifest_digests=tuple(sorted(source_manifests)),
            completion_envelope_digests=tuple(
                item.publication.envelope.digest for item in ordered
            ),
            completion_digests=tuple(item.completion.completion_digest for item in ordered),
            replay_attestation_digests=tuple(item.attestation.digest for item in ordered),
            resolution_status=status,
            selected_attempt_index=selected_attempt_index,
            resolution_digest=resolution_digest,
        )
        return semantic, run_evidence, len(ordered)

    def reconcile(self) -> ReconciliationResult:
        semantic_merkle = StreamingMerkleAccumulator(self.store, domain="semantic-corpus-v1")
        run_merkle = StreamingMerkleAccumulator(self.store, domain="run-evidence-v1")
        current_ordinal: int | None = None
        current_entries: list[SourcedShardEntry] = []
        expected_ordinal = 0
        sample_count = 0
        accepted_count = 0
        exhausted_count = 0
        replay_count = 0
        peak_buffered_entries = len(self.shards)

        def flush() -> None:
            nonlocal sample_count, accepted_count, exhausted_count, replay_count
            nonlocal expected_ordinal, peak_buffered_entries
            if current_ordinal is None:
                return
            if current_ordinal != expected_ordinal:
                raise ReconciliationError("inventory sample completion coverage is not contiguous")
            semantic, run_evidence, replayed = self._resolve_sample(
                current_ordinal,
                tuple(current_entries),
            )
            if semantic is not None:
                semantic_merkle.add_record(semantic.canonical_bytes, semantic.digest)
                accepted_count += 1
            else:
                exhausted_count += 1
            run_merkle.add_record(run_evidence.canonical_bytes, run_evidence.digest)
            sample_count += 1
            replay_count += replayed
            expected_ordinal += 1
            peak_buffered_entries = max(
                peak_buffered_entries,
                len(self.shards) + len(current_entries),
            )

        for sourced in merge_sorted_entry_streams(self._streams()):
            ordinal = sourced.entry.global_ordinal
            if current_ordinal is None:
                current_ordinal = ordinal
            elif ordinal != current_ordinal:
                flush()
                current_entries.clear()
                current_ordinal = ordinal
            current_entries.append(sourced)
        flush()

        if sample_count != len(self.inventory.samples):
            raise ReconciliationError("not every inventory sample reached a terminal resolution")

        semantic_root, semantic_record_count, semantic_peak_count = semantic_merkle.finalize()
        run_root, run_record_count, run_peak_count = run_merkle.finalize()
        semantic_manifest = SemanticCorpusManifest(
            generation_namespace_digest=self.inventory.generation_namespace_digest,
            merkle_root_digest=semantic_root,
            record_count=semantic_record_count,
            peak_count=semantic_peak_count,
        )
        source_manifests = tuple(sorted(shard.manifest.digest for shard in self.shards))
        run_manifest = RunEvidenceManifest(
            inventory_digest=self.inventory.digest,
            shard_count=self.inventory.shard_count,
            source_manifest_digests=source_manifests,
            merkle_root_digest=run_root,
            record_count=run_record_count,
            replay_attestation_count=replay_count,
            peak_count=run_peak_count,
        )
        semantic_result = self.store.publish_bytes(
            semantic_manifest.canonical_bytes,
            expected_digest=semantic_manifest.digest,
        )
        run_result = self.store.publish_bytes(
            run_manifest.canonical_bytes,
            expected_digest=run_manifest.digest,
        )
        seal = CanonicalMergeSeal(
            inventory_digest=self.inventory.digest,
            semantic_corpus_manifest_digest=semantic_manifest.digest,
            run_evidence_manifest_digest=run_manifest.digest,
            source_manifest_digests=source_manifests,
        )
        seal_result = self.store.publish_bytes(seal.canonical_bytes, expected_digest=seal.digest)
        self.store.install_digest_reference(
            category="seals",
            inventory_digest=self.inventory.digest,
            shard_index=0,
            digest=seal.digest,
        )
        return ReconciliationResult(
            semantic_manifest=semantic_manifest,
            run_evidence_manifest=run_manifest,
            seal=seal,
            semantic_manifest_publication=semantic_result,
            run_evidence_manifest_publication=run_result,
            seal_publication=seal_result,
            sample_count=sample_count,
            accepted_sample_count=accepted_count,
            exhausted_sample_count=exhausted_count,
            replay_attestation_count=replay_count,
            peak_buffered_entries=peak_buffered_entries,
        )
