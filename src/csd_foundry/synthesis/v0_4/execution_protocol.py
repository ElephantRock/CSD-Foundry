"""Immutable v0.4 execution inventory and bounded operational retry contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

SAMPLE_KEY_ENCODING_ID = "csd-sample-key-canonical-json"
SAMPLE_KEY_ENCODING_VERSION = 1
SHARD_POLICY_ID = "csd-shard-contract"
SHARD_POLICY_VERSION = 1
SHARD_SEMANTIC_ASSIGNMENT = "global-ordinal-modulo-shard-count"
EXECUTION_VALIDATION_POLICY_ID = "csd-execution-validation"
EXECUTION_VALIDATION_POLICY_VERSION = 1

REQUIRED_SCHEMA_VERSIONS_SCHEMA_VERSION = "csd-required-schema-versions/0.4"
SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION = "csd-sample-execution-spec/0.4"
EXECUTION_INVENTORY_SCHEMA_VERSION = "csd-execution-inventory/0.4"
OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION = "csd-operational-retry-policy/0.4"
OPERATIONAL_FAILURE_SCHEMA_VERSION = "csd-operational-failure/0.4"
OPERATIONAL_EXHAUSTION_SCHEMA_VERSION = "csd-operational-exhaustion/0.4"
INVENTORY_SUPERSESSION_SCHEMA_VERSION = "csd-inventory-supersession/0.4"

ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION = "csd-attempt-completion-envelope/0.4"
INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION = "csd-inventory-completion-reference/0.4"
OPERATIONAL_PUBLICATION_SCHEMA_VERSION = "csd-operational-publication/0.4"
REPLAY_VALIDATION_RECEIPT_SCHEMA_VERSION = "csd-replay-validation-receipt/0.4"
SHARD_MANIFEST_SCHEMA_VERSION = "csd-shard-manifest/0.4"
CORPUS_SEMANTIC_MANIFEST_SCHEMA_VERSION = "csd-corpus-semantic-manifest/0.4"
RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION = "csd-run-evidence-manifest/0.4"

OPERATIONAL_RETRY_UINT8_MAX = 255
DEFAULT_MAXIMUM_OPERATIONAL_RETRIES = 2
MAX_SHARD_COUNT = (1 << 32) - 1

_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ExecutionProtocolError(ValueError):
    """Raised when v0.4 execution-protocol evidence violates its contract."""


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise ExecutionProtocolError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise ExecutionProtocolError(f"{field_name} must be a lowercase ASCII token")
    return value


def _require_positive_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ExecutionProtocolError(f"{field_name} must be a positive exact integer")
    return value


def _sample_key_value(sample_key: SampleKey) -> dict[str, object]:
    if type(sample_key) is not SampleKey:
        raise ExecutionProtocolError("sample_key must use the exact SampleKey class")
    return {
        "release": sample_key.release,
        "sample_index": sample_key.sample_index,
        "target_id": sample_key.target_id,
    }


def _attempt_key_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey or type(attempt_key.sample_key) is not SampleKey:
        raise ExecutionProtocolError("attempt_key must use exact AttemptKey and SampleKey classes")
    return {
        **_sample_key_value(attempt_key.sample_key),
        "attempt_index": attempt_key.attempt_index,
    }


def sample_key_encoding_policy_document() -> dict[str, object]:
    return {
        "canonical_fields": ["release", "sample_index", "target_id"],
        "canonical_serialization": "canonical-json-with-terminal-newline",
        "policy_id": SAMPLE_KEY_ENCODING_ID,
        "policy_version": SAMPLE_KEY_ENCODING_VERSION,
    }


def shard_policy_document() -> dict[str, object]:
    return {
        "policy_id": SHARD_POLICY_ID,
        "policy_version": SHARD_POLICY_VERSION,
        "semantic_assignment": SHARD_SEMANTIC_ASSIGNMENT,
    }


def execution_validation_policy_document() -> dict[str, object]:
    return {
        "attested_commitment_enabled": False,
        "policy_id": EXECUTION_VALIDATION_POLICY_ID,
        "policy_version": EXECUTION_VALIDATION_POLICY_VERSION,
        "release_validation_mode": "full-replay",
    }


def canonical_sample_key_bytes(sample_key: SampleKey) -> bytes:
    """Return the independently versioned canonical routing bytes for one sample key."""

    return canonical_json_bytes(_sample_key_value(sample_key))


def sample_key_sort_key(sample_key: SampleKey) -> bytes:
    return canonical_sample_key_bytes(sample_key)


@dataclass(frozen=True, slots=True)
class RequiredSchemaVersions:
    sample_execution_spec: str = SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION
    execution_inventory: str = EXECUTION_INVENTORY_SCHEMA_VERSION
    operational_retry_policy: str = OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION
    operational_failure_receipt: str = OPERATIONAL_FAILURE_SCHEMA_VERSION
    operational_exhaustion: str = OPERATIONAL_EXHAUSTION_SCHEMA_VERSION
    inventory_supersession: str = INVENTORY_SUPERSESSION_SCHEMA_VERSION
    attempt_completion_envelope: str = ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION
    inventory_completion_reference: str = INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION
    operational_publication_receipt: str = OPERATIONAL_PUBLICATION_SCHEMA_VERSION
    replay_validation_receipt: str = REPLAY_VALIDATION_RECEIPT_SCHEMA_VERSION
    shard_manifest: str = SHARD_MANIFEST_SCHEMA_VERSION
    corpus_semantic_manifest: str = CORPUS_SEMANTIC_MANIFEST_SCHEMA_VERSION
    run_evidence_manifest: str = RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION
    schema_version: str = REQUIRED_SCHEMA_VERSIONS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not RequiredSchemaVersions:
            raise ExecutionProtocolError("required schema versions must use the exact class")
        expected = {
            "attempt_completion_envelope": ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION,
            "corpus_semantic_manifest": CORPUS_SEMANTIC_MANIFEST_SCHEMA_VERSION,
            "execution_inventory": EXECUTION_INVENTORY_SCHEMA_VERSION,
            "inventory_completion_reference": INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION,
            "inventory_supersession": INVENTORY_SUPERSESSION_SCHEMA_VERSION,
            "operational_exhaustion": OPERATIONAL_EXHAUSTION_SCHEMA_VERSION,
            "operational_failure_receipt": OPERATIONAL_FAILURE_SCHEMA_VERSION,
            "operational_publication_receipt": OPERATIONAL_PUBLICATION_SCHEMA_VERSION,
            "operational_retry_policy": OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION,
            "replay_validation_receipt": REPLAY_VALIDATION_RECEIPT_SCHEMA_VERSION,
            "run_evidence_manifest": RUN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            "sample_execution_spec": SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION,
            "schema_version": REQUIRED_SCHEMA_VERSIONS_SCHEMA_VERSION,
            "shard_manifest": SHARD_MANIFEST_SCHEMA_VERSION,
        }
        if self.to_json_value() != expected:
            raise ExecutionProtocolError("required schema versions must match the frozen registry")

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_completion_envelope": self.attempt_completion_envelope,
            "corpus_semantic_manifest": self.corpus_semantic_manifest,
            "execution_inventory": self.execution_inventory,
            "inventory_completion_reference": self.inventory_completion_reference,
            "inventory_supersession": self.inventory_supersession,
            "operational_exhaustion": self.operational_exhaustion,
            "operational_failure_receipt": self.operational_failure_receipt,
            "operational_publication_receipt": self.operational_publication_receipt,
            "operational_retry_policy": self.operational_retry_policy,
            "replay_validation_receipt": self.replay_validation_receipt,
            "run_evidence_manifest": self.run_evidence_manifest,
            "sample_execution_spec": self.sample_execution_spec,
            "schema_version": self.schema_version,
            "shard_manifest": self.shard_manifest,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def current_required_schema_versions() -> RequiredSchemaVersions:
    return RequiredSchemaVersions()


@dataclass(frozen=True, slots=True)
class SampleExecutionSpec:
    global_ordinal: int
    sample_key: SampleKey
    attempt_range: AttemptRange
    producer_contract_id: str
    producer_contract_version: int
    producer_contract_digest: str
    schema_version: str = SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not SampleExecutionSpec:
            raise ExecutionProtocolError("sample execution specs must use the exact class")
        if type(self.global_ordinal) is not int or self.global_ordinal < 0:
            raise ExecutionProtocolError("global_ordinal must be a nonnegative exact integer")
        _sample_key_value(self.sample_key)
        if type(self.attempt_range) is not AttemptRange:
            raise ExecutionProtocolError("attempt_range must use the exact AttemptRange class")
        _require_token(self.producer_contract_id, "producer_contract_id")
        _require_positive_integer(self.producer_contract_version, "producer_contract_version")
        _require_digest(self.producer_contract_digest, "producer_contract_digest")
        if self.schema_version != SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"sample execution spec schema must be {SAMPLE_EXECUTION_SPEC_SCHEMA_VERSION}"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_range": self.attempt_range.maximum_attempts,
            "global_ordinal": self.global_ordinal,
            "producer_contract_digest": self.producer_contract_digest,
            "producer_contract_id": self.producer_contract_id,
            "producer_contract_version": self.producer_contract_version,
            "sample_key": _sample_key_value(self.sample_key),
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class OperationalRetryPolicy:
    maximum_operational_retries: int
    schema_version: str = OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not OperationalRetryPolicy:
            raise ExecutionProtocolError("retry policies must use the exact class")
        if (
            type(self.maximum_operational_retries) is not int
            or not 0 <= self.maximum_operational_retries <= OPERATIONAL_RETRY_UINT8_MAX
        ):
            raise ExecutionProtocolError(
                "maximum_operational_retries must be an exact uint8 in "
                f"0..{OPERATIONAL_RETRY_UINT8_MAX}"
            )
        if self.schema_version != OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"retry policy schema must be {OPERATIONAL_RETRY_POLICY_SCHEMA_VERSION}"
            )

    @property
    def maximum_total_executions(self) -> int:
        return self.maximum_operational_retries + 1

    def to_json_value(self) -> dict[str, object]:
        return {
            "maximum_operational_retries": self.maximum_operational_retries,
            "maximum_total_executions": self.maximum_total_executions,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class ExecutionInventory:
    release: str
    generation_namespace_digest: str
    root_seed_commitment: str
    sample_key_encoding_id: str
    sample_key_encoding_version: int
    sample_key_encoding_policy_digest: str
    shard_policy_id: str
    shard_policy_version: int
    shard_policy_digest: str
    shard_count: int
    operational_retry_policy_digest: str
    validation_policy_id: str
    validation_policy_version: int
    validation_policy_digest: str
    required_schema_versions: RequiredSchemaVersions
    samples: tuple[SampleExecutionSpec, ...]
    schema_version: str = EXECUTION_INVENTORY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ExecutionInventory:
            raise ExecutionProtocolError("execution inventories must use the exact class")
        if self.release != "v0.4":
            raise ExecutionProtocolError("execution inventory release must be v0.4")
        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")
        _require_digest(self.root_seed_commitment, "root_seed_commitment")
        if self.sample_key_encoding_id != SAMPLE_KEY_ENCODING_ID:
            raise ExecutionProtocolError("sample-key encoding ID does not match version 1")
        if self.sample_key_encoding_version != SAMPLE_KEY_ENCODING_VERSION:
            raise ExecutionProtocolError("sample-key encoding version does not match version 1")
        expected_sample_policy = canonical_sha256(sample_key_encoding_policy_document())
        if self.sample_key_encoding_policy_digest != expected_sample_policy:
            raise ExecutionProtocolError(
                "sample-key encoding policy digest does not match version 1"
            )
        if self.shard_policy_id != SHARD_POLICY_ID:
            raise ExecutionProtocolError("shard policy ID does not match generation namespace v1")
        if self.shard_policy_version != SHARD_POLICY_VERSION:
            raise ExecutionProtocolError(
                "shard policy version does not match generation namespace v1"
            )
        if self.shard_policy_digest != canonical_sha256(shard_policy_document()):
            raise ExecutionProtocolError("shard policy digest does not match version 1")
        if type(self.shard_count) is not int or not 1 <= self.shard_count <= MAX_SHARD_COUNT:
            raise ExecutionProtocolError("shard_count must be an exact uint32 in 1..2^32-1")
        _require_digest(self.operational_retry_policy_digest, "operational_retry_policy_digest")
        if self.validation_policy_id != EXECUTION_VALIDATION_POLICY_ID:
            raise ExecutionProtocolError("validation policy ID does not match version 1")
        if self.validation_policy_version != EXECUTION_VALIDATION_POLICY_VERSION:
            raise ExecutionProtocolError("validation policy version does not match version 1")
        if self.validation_policy_digest != canonical_sha256(
            execution_validation_policy_document()
        ):
            raise ExecutionProtocolError("validation policy digest does not match version 1")
        if type(self.required_schema_versions) is not RequiredSchemaVersions:
            raise ExecutionProtocolError("required_schema_versions must use the exact class")
        if type(self.samples) is not tuple or not self.samples:
            raise ExecutionProtocolError("execution inventory requires a nonempty immutable tuple")
        if not all(type(item) is SampleExecutionSpec for item in self.samples):
            raise ExecutionProtocolError(
                "inventory samples must use exact SampleExecutionSpec values"
            )
        ordinals = tuple(item.global_ordinal for item in self.samples)
        if ordinals != tuple(range(len(self.samples))):
            raise ExecutionProtocolError("inventory global ordinals must be contiguous from zero")
        keys = tuple(item.sample_key for item in self.samples)
        if len(keys) != len(set(keys)):
            raise ExecutionProtocolError("inventory sample keys must be unique")
        expected_keys = tuple(sorted(keys, key=sample_key_sort_key))
        if keys != expected_keys:
            raise ExecutionProtocolError(
                "inventory samples must use canonical sample-key byte order"
            )
        if self.schema_version != EXECUTION_INVENTORY_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"execution inventory schema must be {EXECUTION_INVENTORY_SCHEMA_VERSION}"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "generation_namespace_digest": self.generation_namespace_digest,
            "operational_retry_policy_digest": self.operational_retry_policy_digest,
            "release": self.release,
            "required_schema_versions": self.required_schema_versions.to_json_value(),
            "root_seed_commitment": self.root_seed_commitment,
            "sample_key_encoding_id": self.sample_key_encoding_id,
            "sample_key_encoding_policy_digest": self.sample_key_encoding_policy_digest,
            "sample_key_encoding_version": self.sample_key_encoding_version,
            "samples": [item.to_json_value() for item in self.samples],
            "schema_version": self.schema_version,
            "shard_count": self.shard_count,
            "shard_policy_digest": self.shard_policy_digest,
            "shard_policy_id": self.shard_policy_id,
            "shard_policy_version": self.shard_policy_version,
            "validation_policy_digest": self.validation_policy_digest,
            "validation_policy_id": self.validation_policy_id,
            "validation_policy_version": self.validation_policy_version,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def assigned_shard(spec: SampleExecutionSpec, shard_count: int) -> int:
    if type(spec) is not SampleExecutionSpec:
        raise ExecutionProtocolError("assigned shard requires an exact SampleExecutionSpec")
    if type(shard_count) is not int or not 1 <= shard_count <= MAX_SHARD_COUNT:
        raise ExecutionProtocolError("shard_count must be an exact uint32 in 1..2^32-1")
    return spec.global_ordinal % shard_count


@dataclass(frozen=True, slots=True)
class OperationalFailureReceipt:
    execution_run_id: str
    inventory_digest: str
    attempt_key: AttemptKey
    execution_ordinal: int
    worker_id: str
    reason_code: str
    reason_facts: CanonicalObject
    previous_failure_receipt_digest: str | None
    schema_version: str = OPERATIONAL_FAILURE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not OperationalFailureReceipt:
            raise ExecutionProtocolError("operational failures must use the exact class")
        _require_token(self.execution_run_id, "execution_run_id")
        _require_digest(self.inventory_digest, "inventory_digest")
        _attempt_key_value(self.attempt_key)
        if (
            type(self.execution_ordinal) is not int
            or not 0 <= self.execution_ordinal <= OPERATIONAL_RETRY_UINT8_MAX
        ):
            raise ExecutionProtocolError("execution_ordinal must be an exact uint8")
        _require_token(self.worker_id, "worker_id")
        _require_token(self.reason_code, "reason_code")
        if type(self.reason_facts) is not CanonicalObject:
            raise ExecutionProtocolError("reason_facts must use the exact CanonicalObject class")
        if self.execution_ordinal == 0:
            if self.previous_failure_receipt_digest is not None:
                raise ExecutionProtocolError("initial execution cannot reference a prior failure")
        else:
            _require_digest(
                self.previous_failure_receipt_digest,
                "previous_failure_receipt_digest",
            )
        if self.schema_version != OPERATIONAL_FAILURE_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"operational failure schema must be {OPERATIONAL_FAILURE_SCHEMA_VERSION}"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "execution_ordinal": self.execution_ordinal,
            "execution_run_id": self.execution_run_id,
            "inventory_digest": self.inventory_digest,
            "previous_failure_receipt_digest": self.previous_failure_receipt_digest,
            "reason_code": self.reason_code,
            "reason_facts": self.reason_facts.to_json_value(),
            "schema_version": self.schema_version,
            "worker_id": self.worker_id,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def validate_failure_chain(
    policy: OperationalRetryPolicy,
    receipts: tuple[OperationalFailureReceipt, ...],
) -> tuple[OperationalFailureReceipt, ...]:
    if type(policy) is not OperationalRetryPolicy:
        raise ExecutionProtocolError("failure-chain policy must use the exact class")
    if type(receipts) is not tuple or not receipts:
        raise ExecutionProtocolError("failure chain requires a nonempty immutable tuple")
    if not all(type(item) is OperationalFailureReceipt for item in receipts):
        raise ExecutionProtocolError("failure chain must contain exact receipt values")
    if len(receipts) > policy.maximum_total_executions:
        raise ExecutionProtocolError("failure chain exceeds the operational retry policy")
    first = receipts[0]
    for index, receipt in enumerate(receipts):
        if receipt.execution_run_id != first.execution_run_id:
            raise ExecutionProtocolError("failure chain spans multiple execution runs")
        if receipt.inventory_digest != first.inventory_digest:
            raise ExecutionProtocolError("failure chain spans multiple inventories")
        if receipt.attempt_key != first.attempt_key:
            raise ExecutionProtocolError("failure chain spans multiple attempts")
        if receipt.execution_ordinal != index:
            raise ExecutionProtocolError("failure receipt ordinals must be contiguous from zero")
        expected_previous = None if index == 0 else receipts[index - 1].digest
        if receipt.previous_failure_receipt_digest != expected_previous:
            raise ExecutionProtocolError("failure receipt previous-digest chain is broken")
    return receipts


@dataclass(frozen=True, slots=True)
class OperationalExhaustionRecord:
    execution_run_id: str
    inventory_digest: str
    attempt_key: AttemptKey
    retry_policy_digest: str
    maximum_operational_retries: int
    failure_receipt_digests: tuple[str, ...]
    total_execution_count: int
    final_reason_code: str
    schema_version: str = OPERATIONAL_EXHAUSTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not OperationalExhaustionRecord:
            raise ExecutionProtocolError("operational exhaustion must use the exact class")
        _require_token(self.execution_run_id, "execution_run_id")
        _require_digest(self.inventory_digest, "inventory_digest")
        _attempt_key_value(self.attempt_key)
        _require_digest(self.retry_policy_digest, "retry_policy_digest")
        if (
            type(self.maximum_operational_retries) is not int
            or not 0
            <= self.maximum_operational_retries
            <= OPERATIONAL_RETRY_UINT8_MAX
        ):
            raise ExecutionProtocolError("maximum_operational_retries must be an exact uint8")
        if type(self.failure_receipt_digests) is not tuple or not self.failure_receipt_digests:
            raise ExecutionProtocolError("operational exhaustion requires receipt digests")
        for value in self.failure_receipt_digests:
            _require_digest(value, "failure_receipt_digest")
        if len(self.failure_receipt_digests) != len(set(self.failure_receipt_digests)):
            raise ExecutionProtocolError("operational exhaustion receipt digests must be unique")
        expected_count = self.maximum_operational_retries + 1
        if self.total_execution_count != expected_count:
            raise ExecutionProtocolError(
                "operational exhaustion total count must equal retries plus one"
            )
        if len(self.failure_receipt_digests) != expected_count:
            raise ExecutionProtocolError(
                "operational exhaustion must commit the complete failure chain"
            )
        _require_token(self.final_reason_code, "final_reason_code")
        if self.schema_version != OPERATIONAL_EXHAUSTION_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"operational exhaustion schema must be {OPERATIONAL_EXHAUSTION_SCHEMA_VERSION}"
            )

    @classmethod
    def from_failure_chain(
        cls,
        policy: OperationalRetryPolicy,
        receipts: tuple[OperationalFailureReceipt, ...],
    ) -> OperationalExhaustionRecord:
        if cls is not OperationalExhaustionRecord:
            raise ExecutionProtocolError("operational exhaustion construction requires exact class")
        validated = validate_failure_chain(policy, receipts)
        if len(validated) != policy.maximum_total_executions:
            raise ExecutionProtocolError(
                "operational exhaustion requires every permitted execution"
            )
        final = validated[-1]
        return cls(
            execution_run_id=final.execution_run_id,
            inventory_digest=final.inventory_digest,
            attempt_key=final.attempt_key,
            retry_policy_digest=policy.digest,
            maximum_operational_retries=policy.maximum_operational_retries,
            failure_receipt_digests=tuple(item.digest for item in validated),
            total_execution_count=len(validated),
            final_reason_code=final.reason_code,
        )

    def validate_against(
        self,
        policy: OperationalRetryPolicy,
        receipts: tuple[OperationalFailureReceipt, ...],
    ) -> None:
        expected = type(self).from_failure_chain(policy, receipts)
        if self != expected:
            raise ExecutionProtocolError(
                "operational exhaustion record does not match its evidence"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "execution_run_id": self.execution_run_id,
            "failure_receipt_digests": list(self.failure_receipt_digests),
            "final_reason_code": self.final_reason_code,
            "inventory_digest": self.inventory_digest,
            "maximum_operational_retries": self.maximum_operational_retries,
            "retry_policy_digest": self.retry_policy_digest,
            "schema_version": self.schema_version,
            "total_execution_count": self.total_execution_count,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class InventorySupersessionRecord:
    superseded_inventory_digest: str
    replacement_inventory_digest: str
    superseding_run_id: str
    reason_code: str
    reason_facts: CanonicalObject
    schema_version: str = INVENTORY_SUPERSESSION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not InventorySupersessionRecord:
            raise ExecutionProtocolError("inventory supersession must use the exact class")
        _require_digest(self.superseded_inventory_digest, "superseded_inventory_digest")
        _require_digest(self.replacement_inventory_digest, "replacement_inventory_digest")
        if self.superseded_inventory_digest == self.replacement_inventory_digest:
            raise ExecutionProtocolError("an inventory cannot supersede itself")
        _require_token(self.superseding_run_id, "superseding_run_id")
        _require_token(self.reason_code, "reason_code")
        if type(self.reason_facts) is not CanonicalObject:
            raise ExecutionProtocolError("reason_facts must use the exact CanonicalObject class")
        if self.schema_version != INVENTORY_SUPERSESSION_SCHEMA_VERSION:
            raise ExecutionProtocolError(
                f"inventory supersession schema must be {INVENTORY_SUPERSESSION_SCHEMA_VERSION}"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "reason_code": self.reason_code,
            "reason_facts": self.reason_facts.to_json_value(),
            "replacement_inventory_digest": self.replacement_inventory_digest,
            "schema_version": self.schema_version,
            "superseded_inventory_digest": self.superseded_inventory_digest,
            "superseding_run_id": self.superseding_run_id,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())
