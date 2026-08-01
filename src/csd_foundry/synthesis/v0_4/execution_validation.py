"""Validation and immutable evidence for v0.4 execution protocol version 1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.execution_protocol import (
    DEFAULT_MAXIMUM_OPERATIONAL_RETRIES,
    EXECUTION_VALIDATION_POLICY_ID,
    EXECUTION_VALIDATION_POLICY_VERSION,
    SAMPLE_KEY_ENCODING_ID,
    SAMPLE_KEY_ENCODING_VERSION,
    SHARD_POLICY_ID,
    SHARD_POLICY_VERSION,
    ExecutionInventory,
    ExecutionProtocolError,
    InventorySupersessionRecord,
    OperationalExhaustionRecord,
    OperationalFailureReceipt,
    OperationalRetryPolicy,
    RequiredSchemaVersions,
    SampleExecutionSpec,
    append_inventory_supersession,
    assigned_shard,
    canonical_sample_key_bytes,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
    shard_policy_document,
    validate_failure_chain,
)
from csd_foundry.synthesis.v0_4.execution_vectors import (
    EXECUTION_VECTOR_IDS,
    EXPECTED_EXECUTION_DIGESTS,
    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,
    validate_execution_vector_catalog,
)
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_TARGET_ALPHA_DEFINITION_DIGEST = "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
_TARGET_ALPHA_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
_RELEASE_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"


@dataclass(frozen=True, slots=True)
class ExecutionProtocolValidationReport:
    release: str
    vector_count: int
    vectors_passed: int
    vector_catalog_digest: str
    sample_key_encoding_stable: bool
    shard_policy_compatible: bool
    shard_assignment_stable: bool
    inventory_immutable: bool
    retry_ceiling_enforced: bool
    failure_chain_enforced: bool
    operational_exhaustion_nonsemantic: bool
    supersession_append_only: bool
    mixed_versions_rejected: bool
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "errors": list(self.errors),
            "failure_chain_enforced": self.failure_chain_enforced,
            "inventory_immutable": self.inventory_immutable,
            "mixed_versions_rejected": self.mixed_versions_rejected,
            "operational_exhaustion_nonsemantic": self.operational_exhaustion_nonsemantic,
            "release": self.release,
            "release_scale_claimed": False,
            "retry_ceiling_enforced": self.retry_ceiling_enforced,
            "sample_key_encoding_id": SAMPLE_KEY_ENCODING_ID,
            "sample_key_encoding_stable": self.sample_key_encoding_stable,
            "sample_key_encoding_version": SAMPLE_KEY_ENCODING_VERSION,
            "shard_assignment_stable": self.shard_assignment_stable,
            "shard_policy_compatible": self.shard_policy_compatible,
            "shard_policy_id": SHARD_POLICY_ID,
            "shard_policy_version": SHARD_POLICY_VERSION,
            "status": "valid" if self.success else "invalid",
            "supersession_append_only": self.supersession_append_only,
            "vector_catalog_digest": self.vector_catalog_digest,
            "vector_count": self.vector_count,
            "vectors_passed": self.vectors_passed,
            "claim_boundary": (
                "This report validates immutable execution inventories, canonical sample-key "
                "encoding, frozen shard-policy-v1 assignment, bounded operational retries, "
                "terminal operational exhaustion evidence, and append-only supersession. It "
                "does not establish durable publication, streaming merge, planner completeness, "
                "oracle validity, infeasibility, or release-scale output."
            ),
        }


def _producer_digest() -> str:
    return canonical_sha256({"producer_contract_id": "execution-fixture", "version": 1})


def _retry_policy() -> OperationalRetryPolicy:
    return OperationalRetryPolicy(DEFAULT_MAXIMUM_OPERATIONAL_RETRIES)


def _sample_specs() -> tuple[SampleExecutionSpec, ...]:
    return tuple(
        SampleExecutionSpec(
            global_ordinal=index,
            sample_key=SampleKey("v0.4", "execution-v1", index),
            attempt_range=AttemptRange(3),
            producer_contract_id="execution-fixture",
            producer_contract_version=1,
            producer_contract_digest=_producer_digest(),
        )
        for index in range(3)
    )


def _inventory() -> ExecutionInventory:
    return ExecutionInventory(
        release="v0.4",
        generation_namespace=build_generation_namespace(_TARGET_ALPHA_DEFINITION_DIGEST),
        root_seed_commitment=_RELEASE_ROOT_SEED_COMMITMENT,
        sample_key_encoding_id=SAMPLE_KEY_ENCODING_ID,
        sample_key_encoding_version=SAMPLE_KEY_ENCODING_VERSION,
        sample_key_encoding_policy_digest=canonical_sha256(sample_key_encoding_policy_document()),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_policy_document()),
        shard_count=2,
        operational_retry_policy_digest=_retry_policy().digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=_sample_specs(),
    )


def _failure_chain() -> tuple[OperationalFailureReceipt, ...]:
    inventory = _inventory()
    attempt_key = AttemptKey(inventory.samples[0].sample_key, 0)
    receipts: list[OperationalFailureReceipt] = []
    for execution_ordinal, reason_code in enumerate(("timeout", "timeout", "process-exit")):
        receipts.append(
            OperationalFailureReceipt(
                execution_run_id="run-v1",
                inventory_digest=inventory.digest,
                attempt_key=attempt_key,
                execution_ordinal=execution_ordinal,
                worker_id="worker-a",
                reason_code=reason_code,
                reason_facts=CanonicalObject.from_pairs(
                    (("execution_ordinal", execution_ordinal), ("reason", reason_code))
                ),
                previous_failure_receipt_digest=(
                    None if execution_ordinal == 0 else receipts[-1].digest
                ),
            )
        )
    return tuple(receipts)


def _supersession() -> InventorySupersessionRecord:
    return InventorySupersessionRecord(
        superseded_inventory_digest=_inventory().digest,
        replacement_inventory_digest=canonical_sha256({"replacement": "inventory-v2"}),
        superseding_run_id="run-v2",
        reason_code="target-change",
        reason_facts=CanonicalObject.from_pairs((("reason", "coverage-target-changed"),)),
    )


def generate_execution_protocol_digests() -> dict[str, str]:
    inventory = _inventory()
    policy = _retry_policy()
    exhaustion = OperationalExhaustionRecord.from_failure_chain(inventory, policy, _failure_chain())
    return {
        "execution-inventory": inventory.digest,
        "inventory-supersession": _supersession().digest,
        "operational-exhaustion": exhaustion.digest,
        "required-schema-versions": RequiredSchemaVersions().digest,
        "retry-policy": policy.digest,
        "sample-key-encoding": hashlib.sha256(
            canonical_sample_key_bytes(inventory.samples[0].sample_key)
        ).hexdigest(),
        "shard-assignment": canonical_sha256(
            [assigned_shard(spec, inventory.shard_count) for spec in inventory.samples]
        ),
    }


def validate_execution_protocol(release: str) -> ExecutionProtocolValidationReport:
    errors: list[str] = []
    if release != "v0.4":
        errors.append("execution protocol validation supports only v0.4")

    generated: dict[str, str] = {}
    try:
        validate_execution_vector_catalog()
        generated = generate_execution_protocol_digests()
    except (ExecutionProtocolError, ValueError) as exc:
        errors.append(str(exc))

    vectors_passed = sum(
        generated.get(vector_id) == EXPECTED_EXECUTION_DIGESTS[vector_id]
        for vector_id in EXECUTION_VECTOR_IDS
    )

    sample_key_encoding_stable = False
    try:
        sample_key_encoding_stable = (
            canonical_sample_key_bytes(SampleKey("v0.4", "execution-v1", 0))
            == b'{"release":"v0.4","sample_index":0,"target_id":"execution-v1"}\n'
        )
    except ExecutionProtocolError as exc:
        errors.append(str(exc))

    shard_policy_compatible = False
    try:
        from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace

        namespace = build_generation_namespace(_TARGET_ALPHA_DEFINITION_DIGEST)
        shard_policy_compatible = (
            namespace.digest == _TARGET_ALPHA_NAMESPACE_DIGEST
            and namespace.shard_policy_id == SHARD_POLICY_ID
            and namespace.shard_policy_version == SHARD_POLICY_VERSION
            and namespace.shard_policy_digest == canonical_sha256(shard_policy_document())
        )
    except (ExecutionProtocolError, ValueError) as exc:
        errors.append(str(exc))

    inventory = _inventory()
    shard_assignment_stable = tuple(
        assigned_shard(spec, inventory.shard_count) for spec in inventory.samples
    ) == (0, 1, 0)

    inventory_immutable = False
    try:
        replace(inventory, samples=tuple(reversed(inventory.samples)))
    except ExecutionProtocolError:
        inventory_immutable = True

    retry_ceiling_enforced = False
    try:
        OperationalRetryPolicy(256)
    except ExecutionProtocolError:
        retry_ceiling_enforced = True

    failure_chain_enforced = False
    receipts = _failure_chain()
    try:
        validate_failure_chain(_retry_policy(), receipts)
        broken = replace(
            receipts[1],
            previous_failure_receipt_digest=canonical_sha256({"broken": True}),
        )
        validate_failure_chain(_retry_policy(), (receipts[0], broken))
    except ExecutionProtocolError:
        failure_chain_enforced = True

    exhaustion = OperationalExhaustionRecord.from_failure_chain(
        inventory, _retry_policy(), receipts
    )
    operational_exhaustion_nonsemantic = not any(
        hasattr(exhaustion, field_name)
        for field_name in ("rejection", "planner_handoff", "to_infeasibility_witness")
    )

    supersession_append_only = False
    first_supersession = _supersession()
    reactivation = InventorySupersessionRecord(
        superseded_inventory_digest=first_supersession.replacement_inventory_digest,
        replacement_inventory_digest=first_supersession.superseded_inventory_digest,
        superseding_run_id="run-v3",
        reason_code="reactivation-attempt",
        reason_facts=CanonicalObject.from_pairs((("reason", "cycle"),)),
    )
    try:
        append_inventory_supersession((first_supersession,), reactivation)
    except ExecutionProtocolError:
        supersession_append_only = True

    mixed_versions_rejected = False
    try:
        RequiredSchemaVersions(attempt_completion_envelope="csd-attempt-completion-envelope/0.5")
    except ExecutionProtocolError:
        mixed_versions_rejected = True

    checks = {
        "failure-chain enforcement": failure_chain_enforced,
        "inventory immutability": inventory_immutable,
        "mixed-version rejection": mixed_versions_rejected,
        "operational exhaustion separation": operational_exhaustion_nonsemantic,
        "retry ceiling": retry_ceiling_enforced,
        "sample-key encoding": sample_key_encoding_stable,
        "shard assignment": shard_assignment_stable,
        "shard policy compatibility": shard_policy_compatible,
        "supersession append-only behavior": supersession_append_only,
    }
    errors.extend(name for name, passed in checks.items() if not passed)
    if vectors_passed != len(EXECUTION_VECTOR_IDS):
        errors.append("frozen execution-protocol vectors changed")

    return ExecutionProtocolValidationReport(
        release=release,
        vector_count=len(EXECUTION_VECTOR_IDS),
        vectors_passed=vectors_passed,
        vector_catalog_digest=FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,
        sample_key_encoding_stable=sample_key_encoding_stable,
        shard_policy_compatible=shard_policy_compatible,
        shard_assignment_stable=shard_assignment_stable,
        inventory_immutable=inventory_immutable,
        retry_ceiling_enforced=retry_ceiling_enforced,
        failure_chain_enforced=failure_chain_enforced,
        operational_exhaustion_nonsemantic=operational_exhaustion_nonsemantic,
        supersession_append_only=supersession_append_only,
        mixed_versions_rejected=mixed_versions_rejected,
        errors=tuple(errors),
    )
