from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.execution_protocol import (
    EXECUTION_VALIDATION_POLICY_ID,
    EXECUTION_VALIDATION_POLICY_VERSION,
    SAMPLE_KEY_ENCODING_ID,
    SAMPLE_KEY_ENCODING_VERSION,
    SHARD_POLICY_ID,
    SHARD_POLICY_VERSION,
    ExecutionInventory,
    InventorySupersessionRecord,
    ExecutionProtocolError,
    OperationalExhaustionRecord,
    OperationalFailureReceipt,
    OperationalRetryPolicy,
    RequiredSchemaVersions,
    SampleExecutionSpec,
    append_inventory_supersession,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
    shard_policy_document,
)
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_TARGET_DEFINITION_DIGEST = "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"


def _inventory(policy: OperationalRetryPolicy) -> ExecutionInventory:
    spec = SampleExecutionSpec(
        global_ordinal=0,
        sample_key=SampleKey("v0.4", "review-sample", 0),
        attempt_range=AttemptRange(2),
        producer_contract_id="execution-fixture",
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256({"producer": "execution-fixture"}),
    )
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
        shard_count=1,
        operational_retry_policy_digest=policy.digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=(spec,),
    )


def _receipts(
    inventory: ExecutionInventory,
    policy: OperationalRetryPolicy,
    attempt_key: AttemptKey,
) -> tuple[OperationalFailureReceipt, ...]:
    receipts: list[OperationalFailureReceipt] = []
    for execution_ordinal in range(policy.maximum_total_executions):
        receipts.append(
            OperationalFailureReceipt(
                execution_run_id="review-run",
                inventory_digest=inventory.digest,
                attempt_key=attempt_key,
                execution_ordinal=execution_ordinal,
                worker_id="worker-a",
                reason_code="timeout",
                reason_facts=CanonicalObject.from_pairs(
                    (("execution_ordinal", execution_ordinal),)
                ),
                previous_failure_receipt_digest=(
                    None if execution_ordinal == 0 else receipts[-1].digest
                ),
            )
        )
    return tuple(receipts)


def test_exhaustion_factory_requires_inventory_retry_policy() -> None:
    committed_policy = OperationalRetryPolicy(2)
    inventory = _inventory(committed_policy)
    short_policy = OperationalRetryPolicy(0)
    attempt_key = AttemptKey(inventory.samples[0].sample_key, 0)
    receipts = _receipts(inventory, short_policy, attempt_key)

    with pytest.raises(ExecutionProtocolError, match="inventory commitment"):
        OperationalExhaustionRecord.from_failure_chain(
            inventory,
            short_policy,
            receipts,
        )


def test_exhaustion_factory_rejects_absent_and_out_of_range_attempts() -> None:
    policy = OperationalRetryPolicy(0)
    inventory = _inventory(policy)

    absent_attempt = AttemptKey(SampleKey("v0.4", "absent-sample", 0), 0)
    with pytest.raises(ExecutionProtocolError, match="absent from the inventory"):
        OperationalExhaustionRecord.from_failure_chain(
            inventory,
            policy,
            _receipts(inventory, policy, absent_attempt),
        )

    out_of_range = AttemptKey(inventory.samples[0].sample_key, 2)
    with pytest.raises(ExecutionProtocolError, match="outside the inventory attempt range"):
        OperationalExhaustionRecord.from_failure_chain(
            inventory,
            policy,
            _receipts(inventory, policy, out_of_range),
        )


def test_exhaustion_record_cannot_be_directly_constructed() -> None:
    policy = OperationalRetryPolicy(0)
    inventory = _inventory(policy)
    attempt_key = AttemptKey(inventory.samples[0].sample_key, 0)
    receipt = _receipts(inventory, policy, attempt_key)[0]

    with pytest.raises(TypeError):
        OperationalExhaustionRecord(
            execution_run_id="review-run",
            inventory_digest=inventory.digest,
            attempt_key=attempt_key,
            retry_policy_digest=policy.digest,
            maximum_operational_retries=0,
            failure_receipt_digests=(receipt.digest,),
            total_execution_count=1,
            final_reason_code="timeout",
        )


def test_exhaustion_factory_rejects_receipts_from_another_inventory() -> None:
    policy = OperationalRetryPolicy(0)
    inventory = _inventory(policy)
    other = replace(inventory, shard_count=2)
    attempt_key = AttemptKey(inventory.samples[0].sample_key, 0)

    with pytest.raises(ExecutionProtocolError, match="committed inventory"):
        OperationalExhaustionRecord.from_failure_chain(
            inventory,
            policy,
            _receipts(other, policy, attempt_key),
        )


def test_inventory_rejects_generation_namespace_shard_policy_drift() -> None:
    policy = OperationalRetryPolicy(0)
    inventory = _inventory(policy)
    incompatible_namespace = replace(
        inventory.generation_namespace,
        shard_policy_version=2,
        shard_policy_digest=canonical_sha256({"shard-policy": 2}),
    )
    with pytest.raises(ExecutionProtocolError, match="generation namespace"):
        replace(inventory, generation_namespace=incompatible_namespace)


def test_supersession_history_rejects_reactivation_cycles() -> None:
    first = InventorySupersessionRecord(
        superseded_inventory_digest=canonical_sha256({"inventory": "a"}),
        replacement_inventory_digest=canonical_sha256({"inventory": "b"}),
        superseding_run_id="run-b",
        reason_code="replacement",
        reason_facts=CanonicalObject.from_pairs((("reason", "a-to-b"),)),
    )
    reactivation = InventorySupersessionRecord(
        superseded_inventory_digest=first.replacement_inventory_digest,
        replacement_inventory_digest=first.superseded_inventory_digest,
        superseding_run_id="run-a",
        reason_code="reactivation",
        reason_facts=CanonicalObject.from_pairs((("reason", "b-to-a"),)),
    )
    with pytest.raises(ExecutionProtocolError, match="cannot be reactivated"):
        append_inventory_supersession((first,), reactivation)
