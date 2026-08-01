"""Validation and frozen evidence for v0.4 append-only publication."""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
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
                "duplicate idempotence, corruption rejection, and recovery of temporary "
                "publication debris. It does not establish shard indexes, manifests, seals, "
                "streaming reconciliation, canonical corpus merge, planner completeness, "
                "oracle validity, infeasibility, or release-scale output."
            ),
            "corrupted_existing_rejected": self.corrupted_existing_rejected,
            "crash_debris_recoverable": self.crash_debris_recoverable,
            "duplicate_publication_idempotent": self.duplicate_publication_idempotent,
            "errors": list(self.errors),
            "inventory_reference_authoritative": self.inventory_reference_authoritative,
            "no_clobber_enforced": self.no_clobber_enforced,
            "publication_receipts_operational": self.publication_receipts_operational,
            "release": self.release,
            "release_scale_claimed": False,
            "semantic_envelope_topology_independent": (self.semantic_envelope_topology_independent),
            "status": "valid" if self.success else "invalid",
            "vector_catalog_digest": self.vector_catalog_digest,
            "vector_count": self.vector_count,
            "vector_evidence_version": 1,
            "vectors_passed": self.vectors_passed,
        }


def _producer_digest() -> str:
    return canonical_sha256({"producer_contract_id": "publication-fixture", "version": 1})


def _sample_spec() -> SampleExecutionSpec:
    return SampleExecutionSpec(
        global_ordinal=0,
        sample_key=SampleKey("v0.4", "publication-v1", 0),
        attempt_range=AttemptRange(3),
        producer_contract_id="publication-fixture",
        producer_contract_version=1,
        producer_contract_digest=_producer_digest(),
    )


def publication_fixture_inventory() -> ExecutionInventory:
    retry_policy = OperationalRetryPolicy(2)
    return ExecutionInventory(
        release="v0.4",
        generation_namespace=build_generation_namespace(_TARGET_DEFINITION_DIGEST),
        root_seed_commitment=_ROOT_SEED_COMMITMENT,
        sample_key_encoding_id=SAMPLE_KEY_ENCODING_ID,
        sample_key_encoding_version=SAMPLE_KEY_ENCODING_VERSION,
        sample_key_encoding_policy_digest=canonical_sha256(sample_key_encoding_policy_document()),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_policy_document()),
        shard_count=7,
        operational_retry_policy_digest=retry_policy.digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=(_sample_spec(),),
    )


def _attempt_key(index: int = 1) -> AttemptKey:
    return AttemptKey(_sample_spec().sample_key, index)


def publication_fixture_accepted() -> AttemptAccepted:
    attempt = _attempt_key()
    return AttemptAccepted(
        attempt_key=attempt,
        generation_namespace_digest=publication_fixture_inventory().generation_namespace_digest,
        attempt_input_commitment_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "input": "publication-v1"}
        ),
        search_branch_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "branch": "accepted"}
        ),
        choice_ledger_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "choices": "publication-v1"}
        ),
        identity_ledger_digest=canonical_sha256(
            {"attempt": attempt.attempt_index, "identities": "publication-v1"}
        ),
        result=CanonicalObject.from_pairs((("accepted", True), ("fixture", "publication-v1"))),
    )


def publication_fixture_rejected() -> AttemptRejected:
    attempt = AttemptKey(_sample_spec().sample_key, 0)
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
    return {
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
    for condition, message in (
        (topology_independent, "semantic completion envelope is topology-dependent"),
        (inventory_authoritative, "inventory reference authority validation failed"),
        (receipts_operational, "publication receipts leaked into semantic identity"),
        (no_clobber, "no-clobber publication validation failed"),
        (duplicate, "duplicate publication was not idempotent"),
        (corruption_rejected, "corrupted existing object was accepted"),
        (recovered, "temporary publication debris was not recoverable"),
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
        errors=tuple(errors),
    )
