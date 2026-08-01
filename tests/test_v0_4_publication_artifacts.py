from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from csd_foundry.synthesis.v0_4.publication_protocol import (
    AttemptCompletionEnvelope,
    InventoryCompletionReference,
    OperationalPublicationReceipt,
    PublicationDisposition,
    PublicationObjectKind,
)
from csd_foundry.synthesis.v0_4.publication_validation import (
    publication_fixture_accepted,
    publication_fixture_inventory,
    validate_publication_protocol,
)
from csd_foundry.synthesis.v0_4.publication_vectors import (
    EXPECTED_PUBLICATION_DIGESTS,
    FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST,
    PUBLICATION_VECTOR_EVIDENCE_VERSION,
    PUBLICATION_VECTOR_IDS,
)

_ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> object:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def test_publication_canary_catalog_is_exact() -> None:
    document = _load("data/canary/v0.4/publication-v1/publication_vectors.json")
    assert type(document) is dict
    assert document["evidence_version"] == PUBLICATION_VECTOR_EVIDENCE_VERSION
    assert document["vector_ids"] == list(PUBLICATION_VECTOR_IDS)
    assert document["expected_digests"] == EXPECTED_PUBLICATION_DIGESTS
    assert document["catalog_digest"] == FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST


def test_publication_report_matches_validator() -> None:
    assert (
        _load("reports/publication_protocol_v0.4.json")
        == validate_publication_protocol("v0.4").to_dict()
    )


def test_publication_schemas_are_well_formed_and_accept_fixtures() -> None:
    inventory = publication_fixture_inventory()
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    reference = InventoryCompletionReference.from_inventory(inventory, envelope)
    receipt = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-schema",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=envelope.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    fixtures = (
        (
            "specs/v0.4/attempt_completion_envelope.schema.json",
            envelope.to_json_value(),
        ),
        (
            "specs/v0.4/inventory_completion_reference.schema.json",
            reference.to_json_value(),
        ),
        (
            "specs/v0.4/operational_publication_receipt.schema.json",
            receipt.to_json_value(),
        ),
    )
    for path, value in fixtures:
        schema = _load(path)
        assert type(schema) is dict
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)


def test_completion_envelope_schema_rejects_topology_leakage() -> None:
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    schema = _load("specs/v0.4/attempt_completion_envelope.schema.json")
    assert type(schema) is dict
    leaked = {**envelope.to_json_value(), "execution_run_id": "run-leak"}
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(leaked)


def test_publication_receipt_schema_enforces_initial_chain_boundary() -> None:
    inventory = publication_fixture_inventory()
    envelope = AttemptCompletionEnvelope.from_completion(publication_fixture_accepted())
    receipt = OperationalPublicationReceipt.append(
        previous=None,
        execution_run_id="run-schema",
        inventory_digest=inventory.digest,
        attempt_key=envelope.attempt_key,
        object_kind=PublicationObjectKind.ATTEMPT_COMPLETION_ENVELOPE,
        object_digest=envelope.digest,
        disposition=PublicationDisposition.PUBLISHED,
    )
    schema = _load("specs/v0.4/operational_publication_receipt.schema.json")
    assert type(schema) is dict
    invalid = {
        **receipt.to_json_value(),
        "previous_publication_receipt_digest": "0" * 64,
    }
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(invalid)
