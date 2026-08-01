from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from csd_foundry.synthesis.v0_4.execution_protocol import (
    DEFAULT_MAXIMUM_OPERATIONAL_RETRIES,
    OperationalRetryPolicy,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
)
from csd_foundry.synthesis.v0_4.execution_validation import (
    EXECUTION_SCHEMA_DOCUMENT_VERSION,
    validate_execution_protocol,
)
from csd_foundry.synthesis.v0_4.execution_vectors import (
    EXECUTION_VECTOR_EVIDENCE_VERSION,
    EXECUTION_VECTOR_IDS,
    EXPECTED_EXECUTION_DIGESTS,
    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,
    execution_vector_catalog_commitment,
)

_ROOT = Path(__file__).resolve().parents[1]
_CURRENT_EXECUTION_SCHEMA = "specs/v0.4/execution_protocol_v2.schema.json"
_V1_EXECUTION_SCHEMA_SHA256 = "f2c08484af668aeb647825a5639fbc0f66b0fd07dbe1a16e97039b9b3c750d47"
_V1_EXECUTION_CANARY_SHA256 = "875d5af490bf3b10142419a5c0f1b2ad8bb66092426e4ff15bc6c75dc971b5bd"


def _load(path: str) -> object:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def test_packaged_execution_policy_documents_are_exact() -> None:
    assert _load("specs/v0.4/sample_key_encoding.json") == sample_key_encoding_policy_document()
    assert (
        _load("specs/v0.4/execution_validation_policy.json")
        == execution_validation_policy_document()
    )
    assert (
        _load("specs/v0.4/operational_retry_policy.json")
        == OperationalRetryPolicy(DEFAULT_MAXIMUM_OPERATIONAL_RETRIES).to_json_value()
    )


def test_execution_canary_catalog_is_exact() -> None:
    document = _load("data/canary/v0.4/execution-v2/execution_vectors.json")
    assert type(document) is dict
    assert document["evidence_version"] == EXECUTION_VECTOR_EVIDENCE_VERSION
    assert document["vector_ids"] == list(EXECUTION_VECTOR_IDS)
    assert document["expected_digests"] == EXPECTED_EXECUTION_DIGESTS
    assert document["catalog_digest"] == FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST
    assert execution_vector_catalog_commitment() == {
        "evidence_version": document["evidence_version"],
        "expected_digests": document["expected_digests"],
        "vector_ids": document["vector_ids"],
    }


def test_execution_report_matches_validator() -> None:
    assert (
        _load("reports/execution_protocol_v0.4.json")
        == validate_execution_protocol("v0.4").to_dict()
    )


def test_execution_schema_contains_every_current_contract() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    definitions = document["$defs"]
    assert type(definitions) is dict
    assert {
        "executionInventory",
        "inventorySupersession",
        "operationalExhaustion",
        "operationalFailure",
        "operationalRetryPolicy",
        "requiredSchemaVersions",
        "sampleExecutionSpec",
    } <= set(definitions)


def test_execution_schema_matches_runtime_bounds_and_canonical_values() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
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


def test_execution_schema_pins_policies_and_exhaustion_cardinality() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    definitions = document["$defs"]
    inventory_properties = definitions["executionInventory"]["properties"]
    assert inventory_properties["sample_key_encoding_policy_digest"] == {
        "const": "b035f20b7e9c8232798b5409c14d7559742e32051d924db01fec01fa995f4e25"
    }
    assert inventory_properties["shard_policy_digest"] == {
        "const": "625417f57640b047bf26f87c17311a86da97dd0a5defcb746ece1c9d19a40114"
    }
    assert inventory_properties["validation_policy_digest"] == {
        "const": "f318b92ac128a35d16123559353f28dd8a2255d2c767e98e2e27035bca382569"
    }
    branches = definitions["operationalExhaustion"]["allOf"][0]["oneOf"]
    assert len(branches) == 256
    retry_two = branches[2]["properties"]
    assert retry_two["maximum_operational_retries"] == {"const": 2}
    assert retry_two["total_execution_count"] == {"const": 3}
    assert retry_two["failure_receipt_digests"] == {
        "maxItems": 3,
        "minItems": 3,
    }


def test_v1_execution_artifacts_remain_byte_identical() -> None:
    assert (
        hashlib.sha256(
            (_ROOT / "specs/v0.4/execution_protocol.schema.json").read_bytes()
        ).hexdigest()
        == _V1_EXECUTION_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256(
            (_ROOT / "data/canary/v0.4/execution-v1/execution_vectors.json").read_bytes()
        ).hexdigest()
        == _V1_EXECUTION_CANARY_SHA256
    )


def test_current_execution_schema_is_versioned_and_well_formed() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    assert document["$id"] == "urn:csd-foundry:execution-protocol-schema:v0.4:2"
    assert EXECUTION_SCHEMA_DOCUMENT_VERSION == 2
    Draft202012Validator.check_schema(document)


def test_retry_policy_schema_enforces_every_derived_execution_count() -> None:
    document = _load(_CURRENT_EXECUTION_SCHEMA)
    assert type(document) is dict
    retry_schema = document["$defs"]["operationalRetryPolicy"]
    branches = retry_schema["allOf"][0]["oneOf"]
    assert len(branches) == 256
    for retries, branch in enumerate(branches):
        assert branch["properties"] == {
            "maximum_operational_retries": {"const": retries},
            "maximum_total_executions": {"const": retries + 1},
        }
        assert branch["required"] == [
            "maximum_operational_retries",
            "maximum_total_executions",
        ]

    validator = Draft202012Validator(retry_schema)
    validator.validate(
        {
            "maximum_operational_retries": 2,
            "maximum_total_executions": 3,
            "schema_version": "csd-operational-retry-policy/0.4",
        }
    )
    with pytest.raises(ValidationError):
        validator.validate(
            {
                "maximum_operational_retries": 2,
                "maximum_total_executions": 1,
                "schema_version": "csd-operational-retry-policy/0.4",
            }
        )
