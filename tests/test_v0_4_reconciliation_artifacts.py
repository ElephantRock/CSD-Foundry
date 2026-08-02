from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from csd_foundry.synthesis.v0_4.reconciliation_validation import validate_reconciliation
from csd_foundry.synthesis.v0_4.reconciliation_vectors import (
    EXPECTED_RECONCILIATION_DIGESTS,
    FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST,
    RECONCILIATION_VECTOR_IDS,
)

_ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> object:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def test_reconciliation_canary_catalog_is_exact() -> None:
    document = _load("data/canary/v0.4/reconciliation-v1/reconciliation_vectors.json")
    assert type(document) is dict
    assert document["evidence_version"] == 1
    assert document["vector_ids"] == list(RECONCILIATION_VECTOR_IDS)
    assert document["expected_digests"] == EXPECTED_RECONCILIATION_DIGESTS
    assert document["catalog_digest"] == FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST


def test_reconciliation_report_matches_validator() -> None:
    assert (
        _load("reports/reconciliation_protocol_v0.4.json")
        == validate_reconciliation("v0.4").to_dict()
    )


def test_reconciliation_schemas_are_well_formed() -> None:
    paths = (
        "specs/v0.4/replay_attestation.schema.json",
        "specs/v0.4/semantic_corpus_record.schema.json",
        "specs/v0.4/run_evidence_record.schema.json",
        "specs/v0.4/semantic_corpus_manifest.schema.json",
        "specs/v0.4/run_evidence_manifest.schema.json",
        "specs/v0.4/canonical_merge_seal.schema.json",
        "specs/v0.4/streaming_merkle_node.schema.json",
        "specs/v0.4/streaming_merkle_root.schema.json",
    )
    for path in paths:
        schema = _load(path)
        assert type(schema) is dict
        Draft202012Validator.check_schema(schema)
