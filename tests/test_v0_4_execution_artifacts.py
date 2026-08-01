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
    assert _load(
        "specs/v0.4/execution_validation_policy.json"
    ) == execution_validation_policy_document()
    assert _load("specs/v0.4/operational_retry_policy.json") == OperationalRetryPolicy(
        DEFAULT_MAXIMUM_OPERATIONAL_RETRIES
    ).to_json_value()


def test_execution_canary_catalog_is_exact() -> None:
    document = _load("data/canary/v0.4/execution-v1/execution_vectors.json")
    assert type(document) is dict
    assert document["vector_ids"] == list(EXECUTION_VECTOR_IDS)
    assert document["expected_digests"] == EXPECTED_EXECUTION_DIGESTS
    assert document["catalog_digest"] == FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST


def test_execution_report_matches_validator() -> None:
    assert _load("reports/execution_protocol_v0.4.json") == validate_execution_protocol(
        "v0.4"
    ).to_dict()


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
