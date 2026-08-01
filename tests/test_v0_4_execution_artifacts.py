from __future__ import annotations

import json
from pathlib import Path

from csd_foundry.synthesis.v0_4.execution_protocol import (
    DEFAULT_MAXIMUM_OPERATIONAL_RETRIES,
    OperationalRetryPolicy,
    execution_validation_policy_document,
    sample_key_encoding_policy_document,
)
from csd_foundry.synthesis.v0_4.execution_validation import validate_execution_protocol
from csd_foundry.synthesis.v0_4.execution_vectors import (
    EXECUTION_VECTOR_IDS,
    EXPECTED_EXECUTION_DIGESTS,
    FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST,
)

_ROOT = Path(__file__).resolve().parents[1]


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
    document = _load("data/canary/v0.4/execution-v1/execution_vectors.json")
    assert type(document) is dict
    assert document["vector_ids"] == list(EXECUTION_VECTOR_IDS)
    assert document["expected_digests"] == EXPECTED_EXECUTION_DIGESTS
    assert document["catalog_digest"] == FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST


def test_execution_report_matches_validator() -> None:
    assert (
        _load("reports/execution_protocol_v0.4.json")
        == validate_execution_protocol("v0.4").to_dict()
    )


def test_execution_schema_contains_every_current_contract() -> None:
    document = _load("specs/v0.4/execution_protocol.schema.json")
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


def test_execution_schema_pins_policies_and_exhaustion_cardinality() -> None:
    document = _load("specs/v0.4/execution_protocol.schema.json")
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
