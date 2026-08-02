"""Validation and frozen evidence for v0.4 streaming reconciliation."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from csd_foundry.synthesis.v0_4.choice_paths import AttemptRange, SampleKey
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
from csd_foundry.synthesis.v0_4.publication_shards import (
    PublishedCompletion,
    ShardIndexEntry,
    ShardPublicationCoordinator,
)
from csd_foundry.synthesis.v0_4.publication_store import ContentAddressedPublicationStore
from csd_foundry.synthesis.v0_4.reconciliation_core import (
    AttestedCompletion,
    ReconciliationConflictError,
    ReplayAttestation,
    SourcedShardEntry,
    merge_sorted_entry_streams,
)
from csd_foundry.synthesis.v0_4.reconciliation_protocol import StreamingReconciler
from csd_foundry.synthesis.v0_4.replay_validation import _bundle, _namespace, _seed
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


@dataclass(frozen=True, slots=True)
class ReconciliationValidationReport:
    release: str
    vectors_passed: int
    vector_count: int
    vector_catalog_digest: str
    semantic_manifest_topology_independent: bool
    run_evidence_topology_specific: bool
    bounded_k_way_merge: bool
    full_replay_enforced: bool
    lowest_valid_attempt_enforced: bool
    complete_exhaustion_nonsemantic: bool
    exact_duplicates_collapsed: bool
    conflicts_rejected: bool
    atomic_final_seal_verified: bool
    actual_digests: dict[str, str]
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "actual_digests": self.actual_digests,
            "atomic_final_seal_verified": self.atomic_final_seal_verified,
            "bounded_k_way_merge": self.bounded_k_way_merge,
            "claim_boundary": (
                "Validates bounded k-way reconciliation, lowest-valid resolution, FULL_REPLAY, "
                "conflict rejection, topology-independent semantic output, topology-specific run "
                "evidence, and final sealing. It does not establish planner completeness, "
                "trajectory validity, infeasibility, SLOs, or release-scale readiness."
            ),
            "complete_exhaustion_nonsemantic": self.complete_exhaustion_nonsemantic,
            "conflicts_rejected": self.conflicts_rejected,
            "errors": list(self.errors),
            "exact_duplicates_collapsed": self.exact_duplicates_collapsed,
            "full_replay_enforced": self.full_replay_enforced,
            "lowest_valid_attempt_enforced": self.lowest_valid_attempt_enforced,
            "release": self.release,
            "release_scale_claimed": False,
            "run_evidence_topology_specific": self.run_evidence_topology_specific,
            "semantic_manifest_topology_independent": self.semantic_manifest_topology_independent,
            "status": "valid" if self.success else "invalid",
            "vector_catalog_digest": self.vector_catalog_digest,
            "vector_count": self.vector_count,
            "vectors_passed": self.vectors_passed,
        }


def _inventory(shards: int) -> ExecutionInventory:
    retry = OperationalRetryPolicy(2)
    producer = canonical_sha256(
        {"producer_contract_id": "reconciliation-fixture", "version": 1}
    )
    return ExecutionInventory(
        release="v0.4",
        generation_namespace=_namespace(),
        root_seed_commitment=_seed().commitment,
        sample_key_encoding_id=SAMPLE_KEY_ENCODING_ID,
        sample_key_encoding_version=SAMPLE_KEY_ENCODING_VERSION,
        sample_key_encoding_policy_digest=canonical_sha256(
            sample_key_encoding_policy_document()
        ),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_policy_document()),
        shard_count=shards,
        operational_retry_policy_digest=retry.digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=tuple(
            SampleExecutionSpec(
                i,
                SampleKey("v0.4", "replay-v1", i),
                AttemptRange(3),
                "reconciliation-fixture",
                1,
                producer,
            )
            for i in range(5)
        ),
    )


def _bundles() -> tuple[object, ...]:
    plan = (
        (0, False),
        (0, True),
        (1, True),
        (2, False),
        (2, False),
        (2, True),
        (3, False),
        (3, False),
        (3, False),
        (4, False),
        (4, True),
    )
    counters: dict[int, int] = {}
    values = []
    for sample, accepted in plan:
        index = counters.get(sample, 0)
        values.append(_bundle(index, accepted=accepted, sample_index=sample))
        counters[sample] = index + 1
    return tuple(values)


def _run(shards: int) -> dict[str, object]:
    inventory, bundles = _inventory(shards), _bundles()
    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        coordinator = ShardPublicationCoordinator(store)
        by_envelope: dict[str, tuple[PublishedCompletion, object]] = {}
        publications = []
        for bundle in bundles:
            completion = bundle.completion  # type: ignore[attr-defined]
            publication = coordinator.publish_completion(
                inventory,
                completion,
                execution_run_id=(
                    f"run-{shards}-{completion.attempt_key.sample_key.sample_index}-"
                    f"{completion.attempt_key.attempt_index}"
                ),
            )
            publications.append(publication)
            by_envelope[publication.envelope.digest] = (publication, bundle)
        published_shards = tuple(
            coordinator.publish_shard(
                inventory,
                shard,
                tuple(
                    publication
                    for publication in publications
                    if publication.reference.global_ordinal % shards == shard
                ),
            )
            for shard in range(shards)
        )

        def resolve(entry: ShardIndexEntry) -> PublishedCompletion:
            return by_envelope[entry.completion_envelope_digest][0]

        def attest(publication: PublishedCompletion) -> AttestedCompletion:
            bundle = by_envelope[publication.envelope.digest][1]
            evidence = bundle.validate(_seed(), _namespace())  # type: ignore[attr-defined]
            completion = bundle.completion  # type: ignore[attr-defined]
            attestation = ReplayAttestation(
                completion.attempt_key,
                publication.envelope.digest,
                completion.completion_digest,
                evidence,
                "independent-replay-fixture",
                1,
            )
            store.publish_bytes(
                attestation.canonical_bytes,
                expected_digest=attestation.digest,
            )
            return AttestedCompletion(publication, completion, attestation)

        result = StreamingReconciler(
            inventory,
            tuple(reversed(published_shards)),
            store,
            completion_resolver=resolve,
            replay_attestor=attest,
        ).reconcile()
        atomic = (
            store.read_verified(result.semantic_manifest.digest)
            == result.semantic_manifest.canonical_bytes
            and store.read_verified(result.run_evidence_manifest.digest)
            == result.run_evidence_manifest.canonical_bytes
            and store.read_verified(result.seal.digest) == result.seal.canonical_bytes
        )
        return {
            "accepted": result.accepted_sample_count,
            "atomic": atomic,
            "exhausted": result.exhausted_sample_count,
            "peak": result.peak_buffered_entries,
            "replays": result.replay_attestation_count,
            "run": result.run_evidence_manifest.digest,
            "samples": result.sample_count,
            "seal": result.seal.digest,
            "semantic": result.semantic_manifest.digest,
            "semantic_root": result.semantic_manifest.merkle_root_digest,
            "shards": shards,
        }


def _merge_checks() -> tuple[bool, bool]:
    inventory, bundle = _inventory(1), _bundles()[0]
    with TemporaryDirectory() as directory:
        store = ContentAddressedPublicationStore(Path(directory))
        coordinator = ShardPublicationCoordinator(store)
        publication = coordinator.publish_completion(
            inventory,
            bundle.completion,  # type: ignore[attr-defined]
            execution_run_id="run-conflict",
        )
        shard = coordinator.publish_shard(inventory, 0, (publication,))
        entry = shard.index.entries[0]
        sourced = SourcedShardEntry(entry, shard.manifest.digest)
        duplicate = tuple(
            merge_sorted_entry_streams(((sourced,), (sourced,)))
        ) == (sourced,)
        try:
            conflict = replace(entry, completion_envelope_digest="0" * 64)
            tuple(
                merge_sorted_entry_streams(
                    (
                        (sourced,),
                        (SourcedShardEntry(conflict, shard.manifest.digest),),
                    )
                )
            )
        except ReconciliationConflictError:
            rejected = True
        else:
            rejected = False
    return duplicate, rejected


def generate_reconciliation_digests() -> tuple[
    dict[str, str], tuple[dict[str, object], ...]
]:
    runs = tuple(_run(count) for count in (1, 2, 7))
    if len({run["semantic"] for run in runs}) != 1:
        raise RuntimeError("semantic manifest changed across shard topologies")
    actual = {
        "semantic-manifest": str(runs[0]["semantic"]),
        "semantic-merkle-root": str(runs[0]["semantic_root"]),
        "topology-run-manifests": canonical_sha256(
            [{"run": run["run"], "shards": run["shards"]} for run in runs]
        ),
        "topology-seals": canonical_sha256(
            [{"seal": run["seal"], "shards": run["shards"]} for run in runs]
        ),
        "full-replay-summary": canonical_sha256(
            {
                "accepted": 4,
                "exhausted": 1,
                "mode": "FULL_REPLAY",
                "replays": 11,
                "samples": 5,
            }
        ),
        "streaming-memory-bound": canonical_sha256(
            [{"peak": run["peak"], "shards": run["shards"]} for run in runs]
        ),
    }
    return actual, runs


def validate_reconciliation(release: str = "v0.4") -> ReconciliationValidationReport:
    from csd_foundry.synthesis.v0_4.reconciliation_vectors import (
        EXPECTED_RECONCILIATION_DIGESTS,
        FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST,
        RECONCILIATION_VECTOR_IDS,
        validate_reconciliation_vector_catalog,
    )

    errors: list[str] = []
    if release != "v0.4":
        errors.append("reconciliation supports only v0.4")
    try:
        validate_reconciliation_vector_catalog()
    except ValueError as exc:
        errors.append(str(exc))
    try:
        actual, runs = generate_reconciliation_digests()
    except Exception as exc:
        actual, runs = {}, ()
        errors.append(f"reconciliation generation failed: {type(exc).__name__}: {exc}")
    passed = sum(
        actual.get(key) == EXPECTED_RECONCILIATION_DIGESTS.get(key)
        for key in RECONCILIATION_VECTOR_IDS
    )
    if actual != EXPECTED_RECONCILIATION_DIGESTS:
        errors.append("reconciliation vectors changed")
    duplicate, conflict = _merge_checks()
    semantic = bool(runs) and len({run["semantic"] for run in runs}) == 1
    run_specific = bool(runs) and len({run["run"] for run in runs}) == 3
    bounded = bool(runs) and all(
        int(run["peak"]) <= int(run["shards"]) + 3 for run in runs
    )
    replay = bool(runs) and all(run["replays"] == 11 for run in runs)
    lowest = bool(runs) and all(
        run["accepted"] == 4 and run["samples"] == 5 for run in runs
    )
    exhaustion = bool(runs) and all(run["exhausted"] == 1 for run in runs)
    atomic = bool(runs) and all(bool(run["atomic"]) for run in runs)
    for condition, message in (
        (duplicate, "duplicates not collapsed"),
        (conflict, "conflict accepted"),
        (semantic, "semantic topology drift"),
        (run_specific, "run topology lost"),
        (bounded, "streaming memory bound failed"),
        (replay, "FULL_REPLAY missing"),
        (lowest, "lowest-valid resolution failed"),
        (exhaustion, "exhaustion became semantic"),
        (atomic, "final seal incomplete"),
    ):
        if not condition:
            errors.append(message)
    return ReconciliationValidationReport(
        release,
        passed,
        len(RECONCILIATION_VECTOR_IDS),
        FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST,
        semantic,
        run_specific,
        bounded,
        replay,
        lowest,
        exhaustion,
        duplicate,
        conflict,
        atomic,
        actual,
        tuple(errors),
    )
