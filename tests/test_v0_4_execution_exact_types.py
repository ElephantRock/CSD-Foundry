from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.execution_protocol import (
    EXECUTION_VALIDATION_POLICY_ID,
    EXECUTION_VALIDATION_POLICY_VERSION,
    SAMPLE_KEY_ENCODING_ID,
    SAMPLE_KEY_ENCODING_VERSION,
    SHARD_POLICY_ID,
    SHARD_POLICY_VERSION,
    ExecutionInventory,
    ExecutionProtocolError,
    OperationalExhaustionRecord,
    OperationalRetryPolicy,
    RequiredSchemaVersions,
    SampleExecutionSpec,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
    shard_policy_document,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
_ROOT_SEED_COMMITMENT = "6e5306d9779ade6c6e8bdf5d3d88431e8a4a9fb5ea2e4526949923319400661e"


class DerivedString(str):
    pass


def _inventory() -> ExecutionInventory:
    retry_policy = OperationalRetryPolicy(2)
    spec = SampleExecutionSpec(
        global_ordinal=0,
        sample_key=SampleKey("v0.4", "exact-types", 0),
        attempt_range=AttemptRange(1),
        producer_contract_id="execution-fixture",
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256({"producer": "execution-fixture"}),
    )
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
        shard_count=1,
        operational_retry_policy_digest=retry_policy.digest,
        validation_policy_id=EXECUTION_VALIDATION_POLICY_ID,
        validation_policy_version=EXECUTION_VALIDATION_POLICY_VERSION,
        validation_policy_digest=canonical_sha256(execution_validation_policy_document()),
        required_schema_versions=RequiredSchemaVersions(),
        samples=(spec,),
    )


def test_constant_versions_reject_subclasses_and_booleans() -> None:
    with pytest.raises(ExecutionProtocolError):
        OperationalRetryPolicy(
            2,
            schema_version=DerivedString("csd-operational-retry-policy/0.4"),
        )
    with pytest.raises(ExecutionProtocolError):
        RequiredSchemaVersions(schema_version=DerivedString("csd-required-schema-versions/0.4"))
    with pytest.raises(ExecutionProtocolError):
        replace(_inventory(), sample_key_encoding_version=True)
    with pytest.raises(ExecutionProtocolError):
        replace(_inventory(), shard_policy_version=True)
    with pytest.raises(ExecutionProtocolError):
        replace(_inventory(), validation_policy_version=True)


def test_direct_operational_exhaustion_requires_validated_evidence() -> None:
    policy = OperationalRetryPolicy(0)
    attempt_key = AttemptKey(SampleKey("v0.4", "exact-types", 0), 0)
    receipt_digest = canonical_sha256({"receipt": 0})

    with pytest.raises(TypeError):
        OperationalExhaustionRecord(
            execution_run_id="run-v1",
            inventory_digest=canonical_sha256({"inventory": 1}),
            attempt_key=attempt_key,
            retry_policy_digest=policy.digest,
            maximum_operational_retries=0,
            failure_receipt_digests=(receipt_digest,),
            total_execution_count=1,
            final_reason_code="timeout",
        )
