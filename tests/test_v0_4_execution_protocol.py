from __future__ import annotations

from dataclasses import replace

import pytest

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
    assigned_shard,
    canonical_sample_key_bytes,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
    shard_policy_document,
    validate_failure_chain,
)
from csd_foundry.synthesis.v0_4.execution_validation import (
    generate_execution_protocol_digests,
    validate_execution_protocol,
)
from csd_foundry.synthesis.v0_4.execution_vectors import (
    EXPECTED_EXECUTION_DIGESTS,
    validate_execution_vector_catalog,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"


def _producer_digest() -> str:
    return canonical_sha256({"producer_contract_id": "execution-fixture", "version": 1})


def _spec(index: int, target_id: str) -> SampleExecutionSpec:
    return SampleExecutionSpec(
        global_ordinal=index,
        sample_key=SampleKey("v0.4", target_id, index),
        attempt_range=AttemptRange(3),
        producer_contract_id="execution-fixture",
        producer_contract_version=1,
        producer_contract_digest=_producer_digest(),
    )


def _policy() -> OperationalRetryPolicy:
    return OperationalRetryPolicy(DEFAULT_MAXIMUM_OPERATIONAL_RETRIES)


def _inventory() -> ExecutionInventory:
    return ExecutionInventory(
        release="v0.4",
        generation_namespace_digest=_NAMESPACE_DIGEST,
        root_seed_commitment=_ROOT_SEED_COMMITMENT,
        sample_key_encoding_id=SAMPLE_KEY_ENCODING_ID,
        sample_key_encoding_version=SAMPLE_KEY_ENCODING_VERSION,
        sample_key_encoding_policy_digest=canonical_sha256(sample_key_encoding_policy_document()),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_policy_document()),
        shard_count=2,
        operational_retry_policy_digest=_policy().digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=(
            _spec(0, "execution-a"),
            _spec(1, "execution-b"),
            _spec(2, "execution-c"),
        ),
    )


def _receipts() -> tuple[OperationalFailureReceipt, ...]:
    inventory = _inventory()
    attempt_key = AttemptKey(inventory.samples[0].sample_key, 0)
    receipts: list[OperationalFailureReceipt] = []
    for execution_ordinal, reason_code in enumerate(("timeout", "timeout", "process-exit")):
        receipts.append(
            OperationalFailureReceipt(
                execution_run_id="run-test",
                inventory_digest=inventory.digest,
                attempt_key=attempt_key,
                execution_ordinal=execution_ordinal,
                worker_id="worker-a",
                reason_code=reason_code,
                reason_facts=CanonicalObject.from_pairs(
                    (("execution_ordinal", execution_ordinal),)
                ),
                previous_failure_receipt_digest=(
                    None if execution_ordinal == 0 else receipts[-1].digest
                ),
            )
        )
    return tuple(receipts)


def test_sample_key_encoding_is_exact_and_versioned() -> None:
    sample_key = SampleKey("v0.4", "execution-a", 0)
    assert canonical_sample_key_bytes(sample_key) == (
        b'{"release":"v0.4","sample_index":0,"target_id":"execution-a"}\n'
    )

    class DerivedSampleKey(SampleKey):
        pass

    with pytest.raises(ExecutionProtocolError):
        canonical_sample_key_bytes(DerivedSampleKey("v0.4", "execution-a", 0))


def test_inventory_enforces_canonical_order_and_contiguous_ordinals() -> None:
    inventory = _inventory()
    assert tuple(assigned_shard(spec, inventory.shard_count) for spec in inventory.samples) == (
        0,
        1,
        0,
    )

    with pytest.raises(ExecutionProtocolError):
        replace(inventory, samples=tuple(reversed(inventory.samples)))

    with pytest.raises(ExecutionProtocolError):
        replace(
            inventory,
            samples=(replace(inventory.samples[0], global_ordinal=1), *inventory.samples[1:]),
        )


def test_inventory_rejects_duplicate_sample_keys_and_policy_drift() -> None:
    inventory = _inventory()
    duplicate = replace(inventory.samples[1], sample_key=inventory.samples[0].sample_key)
    with pytest.raises(ExecutionProtocolError):
        replace(inventory, samples=(inventory.samples[0], duplicate, inventory.samples[2]))
    with pytest.raises(ExecutionProtocolError):
        replace(inventory, shard_policy_version=2)
    with pytest.raises(ExecutionProtocolError):
        replace(inventory, sample_key_encoding_policy_digest=canonical_sha256({"bad": True}))


def test_required_schema_registry_rejects_mixed_versions() -> None:
    registry = RequiredSchemaVersions()
    assert len(registry.digest) == 64
    with pytest.raises(ExecutionProtocolError):
        RequiredSchemaVersions(attempt_completion_envelope="csd-attempt-completion-envelope/0.5")


def test_operational_retry_policy_has_explicit_ceiling() -> None:
    policy = _policy()
    assert policy.maximum_operational_retries == 2
    assert policy.maximum_total_executions == 3
    OperationalRetryPolicy(0)
    OperationalRetryPolicy(255)
    with pytest.raises(ExecutionProtocolError):
        OperationalRetryPolicy(256)
    with pytest.raises(ExecutionProtocolError):
        OperationalRetryPolicy(-1)


def test_failure_receipts_form_one_contiguous_hash_chain() -> None:
    receipts = _receipts()
    assert validate_failure_chain(_policy(), receipts) == receipts
    broken = replace(
        receipts[1],
        previous_failure_receipt_digest=canonical_sha256({"broken": True}),
    )
    with pytest.raises(ExecutionProtocolError):
        validate_failure_chain(_policy(), (receipts[0], broken))
    cross_attempt = replace(
        receipts[1],
        attempt_key=AttemptKey(receipts[1].attempt_key.sample_key, 1),
    )
    with pytest.raises(ExecutionProtocolError):
        validate_failure_chain(_policy(), (receipts[0], cross_attempt))


def test_operational_exhaustion_requires_every_permitted_execution() -> None:
    receipts = _receipts()
    exhaustion = OperationalExhaustionRecord.from_failure_chain(_inventory(), _policy(), receipts)
    exhaustion.validate_against(_inventory(), _policy(), receipts)
    assert exhaustion.total_execution_count == 3
    assert exhaustion.final_reason_code == "process-exit"
    assert not hasattr(exhaustion, "rejection")
    assert not hasattr(exhaustion, "planner_handoff")
    assert not hasattr(exhaustion, "to_infeasibility_witness")

    with pytest.raises(ExecutionProtocolError):
        OperationalExhaustionRecord.from_failure_chain(
            _inventory(),
            _policy(),
            receipts[:-1],
        )


def test_inventory_supersession_is_append_only_and_nonreflexive() -> None:
    inventory = _inventory()
    replacement_digest = canonical_sha256({"replacement": "inventory-v2"})
    record = InventorySupersessionRecord(
        superseded_inventory_digest=inventory.digest,
        replacement_inventory_digest=replacement_digest,
        superseding_run_id="run-v2",
        reason_code="target-change",
        reason_facts=CanonicalObject.from_pairs((("reason", "coverage-target-changed"),)),
    )
    assert len(record.digest) == 64
    with pytest.raises(ExecutionProtocolError):
        replace(record, replacement_inventory_digest=record.superseded_inventory_digest)


def test_execution_vectors_and_report_are_frozen() -> None:
    validate_execution_vector_catalog()
    assert generate_execution_protocol_digests() == EXPECTED_EXECUTION_DIGESTS
    report = validate_execution_protocol("v0.4")
    assert report.success
    assert report.vectors_passed == report.vector_count == 7
    assert report.shard_policy_compatible
    assert report.operational_exhaustion_nonsemantic
