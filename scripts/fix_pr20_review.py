from __future__ import annotations

import json
from pathlib import Path


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one replacement, found {count}: {old[:80]!r}")
    return text.replace(old, new)


def patch_protocol() -> None:
    path = Path("src/csd_foundry/synthesis/v0_4/execution_protocol.py")
    text = path.read_text(encoding="utf-8")
    start_marker = "@dataclass(frozen=True, slots=True)\nclass OperationalExhaustionRecord:"
    end_marker = "\n\n@dataclass(frozen=True, slots=True)\nclass InventorySupersessionRecord:"
    start = text.index(start_marker)
    end = text.index(end_marker, start)
    replacement = '''@dataclass(frozen=True, slots=True, init=False)
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
            or not 0 <= self.maximum_operational_retries <= OPERATIONAL_RETRY_UINT8_MAX
        ):
            raise ExecutionProtocolError("maximum_operational_retries must be an exact uint8")
        expected_policy_digest = OperationalRetryPolicy(
            self.maximum_operational_retries
        ).digest
        if self.retry_policy_digest != expected_policy_digest:
            raise ExecutionProtocolError(
                "retry_policy_digest does not match maximum_operational_retries"
            )
        if type(self.failure_receipt_digests) is not tuple or not self.failure_receipt_digests:
            raise ExecutionProtocolError("operational exhaustion requires receipt digests")
        for value in self.failure_receipt_digests:
            _require_digest(value, "failure_receipt_digest")
        if len(self.failure_receipt_digests) != len(set(self.failure_receipt_digests)):
            raise ExecutionProtocolError("operational exhaustion receipt digests must be unique")
        expected_count = self.maximum_operational_retries + 1
        if type(self.total_execution_count) is not int:
            raise ExecutionProtocolError("total_execution_count must be an exact integer")
        if self.total_execution_count != expected_count:
            raise ExecutionProtocolError(
                "operational exhaustion total count must equal retries plus one"
            )
        if len(self.failure_receipt_digests) != expected_count:
            raise ExecutionProtocolError(
                "operational exhaustion must commit the complete failure chain"
            )
        _require_token(self.final_reason_code, "final_reason_code")
        _require_constant(
            self.schema_version, OPERATIONAL_EXHAUSTION_SCHEMA_VERSION, "schema_version"
        )

    @classmethod
    def _from_validated_evidence(
        cls,
        *,
        execution_run_id: str,
        inventory_digest: str,
        attempt_key: AttemptKey,
        retry_policy_digest: str,
        maximum_operational_retries: int,
        failure_receipt_digests: tuple[str, ...],
        total_execution_count: int,
        final_reason_code: str,
    ) -> OperationalExhaustionRecord:
        if cls is not OperationalExhaustionRecord:
            raise ExecutionProtocolError("operational exhaustion construction requires exact class")
        record = object.__new__(OperationalExhaustionRecord)
        object.__setattr__(record, "execution_run_id", execution_run_id)
        object.__setattr__(record, "inventory_digest", inventory_digest)
        object.__setattr__(record, "attempt_key", attempt_key)
        object.__setattr__(record, "retry_policy_digest", retry_policy_digest)
        object.__setattr__(
            record, "maximum_operational_retries", maximum_operational_retries
        )
        object.__setattr__(record, "failure_receipt_digests", failure_receipt_digests)
        object.__setattr__(record, "total_execution_count", total_execution_count)
        object.__setattr__(record, "final_reason_code", final_reason_code)
        object.__setattr__(
            record, "schema_version", OPERATIONAL_EXHAUSTION_SCHEMA_VERSION
        )
        record.__post_init__()
        return record

    @classmethod
    def from_failure_chain(
        cls,
        inventory: ExecutionInventory,
        policy: OperationalRetryPolicy,
        receipts: tuple[OperationalFailureReceipt, ...],
    ) -> OperationalExhaustionRecord:
        if cls is not OperationalExhaustionRecord:
            raise ExecutionProtocolError("operational exhaustion construction requires exact class")
        if type(inventory) is not ExecutionInventory:
            raise ExecutionProtocolError("operational exhaustion requires an exact inventory")
        if type(policy) is not OperationalRetryPolicy:
            raise ExecutionProtocolError("operational exhaustion requires an exact retry policy")
        if inventory.operational_retry_policy_digest != policy.digest:
            raise ExecutionProtocolError(
                "retry policy does not match the inventory commitment"
            )
        validated = validate_failure_chain(policy, receipts)
        if len(validated) != policy.maximum_total_executions:
            raise ExecutionProtocolError(
                "operational exhaustion requires every permitted execution"
            )
        final = validated[-1]
        if final.inventory_digest != inventory.digest:
            raise ExecutionProtocolError(
                "failure chain does not belong to the committed inventory"
            )
        matching_specs = tuple(
            spec for spec in inventory.samples if spec.sample_key == final.attempt_key.sample_key
        )
        if len(matching_specs) != 1:
            raise ExecutionProtocolError(
                "operational exhaustion attempt is absent from the inventory"
            )
        sample_spec = matching_specs[0]
        if not sample_spec.attempt_range.contains(final.attempt_key.attempt_index):
            raise ExecutionProtocolError(
                "operational exhaustion attempt is outside the inventory attempt range"
            )
        return cls._from_validated_evidence(
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
        inventory: ExecutionInventory,
        policy: OperationalRetryPolicy,
        receipts: tuple[OperationalFailureReceipt, ...],
    ) -> None:
        expected = type(self).from_failure_chain(inventory, policy, receipts)
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
'''
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


def patch_calls() -> None:
    path = Path("src/csd_foundry/synthesis/v0_4/execution_validation.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "OperationalExhaustionRecord.from_failure_chain(policy, _failure_chain())",
        "OperationalExhaustionRecord.from_failure_chain(inventory, policy, _failure_chain())",
    )
    text = replace_once(
        text,
        "OperationalExhaustionRecord.from_failure_chain(_retry_policy(), receipts)",
        "OperationalExhaustionRecord.from_failure_chain(inventory, _retry_policy(), receipts)",
    )
    path.write_text(text, encoding="utf-8")

    path = Path("tests/test_v0_4_execution_protocol.py")
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "OperationalExhaustionRecord.from_failure_chain(_policy(), receipts)",
        "OperationalExhaustionRecord.from_failure_chain(_inventory(), _policy(), receipts)",
    )
    text = text.replace(
        "exhaustion.validate_against(_policy(), receipts)",
        "exhaustion.validate_against(_inventory(), _policy(), receipts)",
    )
    path.write_text(text, encoding="utf-8")


def patch_exact_type_test() -> None:
    path = Path("tests/test_v0_4_execution_exact_types.py")
    text = path.read_text(encoding="utf-8")
    marker = "def test_direct_operational_exhaustion_binds_retry_policy_digest() -> None:"
    start = text.index(marker)
    replacement = '''def test_direct_operational_exhaustion_requires_validated_evidence() -> None:
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
'''
    path.write_text(text[:start] + replacement, encoding="utf-8")


def patch_schema() -> None:
    path = Path("specs/v0.4/execution_protocol.schema.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    definitions = document["$defs"]
    definitions["attemptKey"]["properties"]["attempt_index"]["maximum"] = 4294967295
    definitions["canonicalValue"] = {
        "oneOf": [
            {"type": "null"},
            {"type": "boolean"},
            {"type": "integer"},
            {"type": "string"},
            {"items": {"$ref": "#/$defs/canonicalValue"}, "type": "array"},
            {
                "additionalProperties": {"$ref": "#/$defs/canonicalValue"},
                "type": "object",
            },
        ]
    }
    definitions["inventorySupersession"]["properties"]["reason_facts"] = {
        "$ref": "#/$defs/canonicalValue"
    }
    definitions["operationalFailure"]["properties"]["reason_facts"] = {
        "$ref": "#/$defs/canonicalValue"
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def patch_artifact_tests() -> None:
    path = Path("tests/test_v0_4_execution_artifacts.py")
    text = path.read_text(encoding="utf-8")
    addition = '''


def test_execution_schema_matches_runtime_bounds_and_canonical_values() -> None:
    document = _load("specs/v0.4/execution_protocol.schema.json")
    assert type(document) is dict
    definitions = document["$defs"]
    assert type(definitions) is dict
    attempt_index = definitions["attemptKey"]["properties"]["attempt_index"]
    assert attempt_index == {"maximum": 4294967295, "minimum": 0, "type": "integer"}
    assert definitions["operationalFailure"]["properties"]["reason_facts"] == {
        "$ref": "#/$defs/canonicalValue"
    }
    assert definitions["inventorySupersession"]["properties"]["reason_facts"] == {
        "$ref": "#/$defs/canonicalValue"
    }
    canonical_variants = definitions["canonicalValue"]["oneOf"]
    assert {variant.get("type") for variant in canonical_variants} == {
        "array",
        "boolean",
        "integer",
        "null",
        "object",
        "string",
    }
    assert all(variant.get("type") != "number" for variant in canonical_variants)
'''
    if "test_execution_schema_matches_runtime_bounds_and_canonical_values" not in text:
        text += addition
    path.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    path = Path("docs/execution_protocol_v0.4.md")
    text = path.read_text(encoding="utf-8")
    old = (
        "After every permitted execution fails, the system emits an "
        "`OperationalExhaustionRecord`\ncommitting the complete failure-receipt chain."
    )
    new = (
        "After every permitted execution fails, the system constructs an\n"
        "`OperationalExhaustionRecord` only through the inventory-bound failure-chain factory. "
        "The\nfactory verifies the inventory digest, committed retry policy, sample membership, "
        "attempt\nrange, and complete previous-digest chain before evidence can be serialized or committed."
    )
    text = replace_once(text, old, new)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_protocol()
    patch_calls()
    patch_exact_type_test()
    patch_schema()
    patch_artifact_tests()
    patch_docs()


if __name__ == "__main__":
    main()
