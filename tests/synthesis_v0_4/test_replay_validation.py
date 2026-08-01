from __future__ import annotations

import json
from pathlib import Path

from csd_foundry.synthesis.v0_4.replay_validation import validate_replay
from csd_foundry.synthesis.v0_4.replay_vectors import (
    EXPECTED_REPLAY_DIGESTS,
    FROZEN_REPLAY_VECTOR_CATALOG_DIGEST,
    REPLAY_VECTOR_IDS,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "data" / "canary" / "v0.4" / "replay-v1" / "replay_vectors.json"


def test_frozen_replay_validation_passes() -> None:
    report = validate_replay("v0.4")

    assert report.success, report.errors
    assert report.replay_vectors == len(REPLAY_VECTOR_IDS) == 7
    assert report.replay_vectors_passed == 7
    assert report.tamper_cases == report.tamper_cases_rejected
    assert not report.exhaustion_converted_to_infeasibility
    assert not report.operational_abort_has_semantic_completion


def test_replay_vector_artifact_matches_frozen_code_evidence() -> None:
    artifact = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    catalog = {
        "release": artifact["release"],
        "schema_version": artifact["schema_version"],
        "vector_ids": artifact["vector_ids"],
    }
    assert canonical_sha256(catalog) == FROZEN_REPLAY_VECTOR_CATALOG_DIGEST
    assert artifact["catalog_digest"] == FROZEN_REPLAY_VECTOR_CATALOG_DIGEST
    assert tuple(artifact["vector_ids"]) == REPLAY_VECTOR_IDS
    assert artifact["expected_digests"] == EXPECTED_REPLAY_DIGESTS
