"""Frozen known-answer vector catalog for v0.4 streaming reconciliation."""

from __future__ import annotations

from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

RECONCILIATION_VECTOR_IDS = (
    "semantic-manifest",
    "semantic-merkle-root",
    "topology-run-manifests",
    "topology-seals",
    "full-replay-summary",
    "streaming-memory-bound",
)

EXPECTED_RECONCILIATION_DIGESTS: dict[str, str] = {
    vector_id: "0" * 64 for vector_id in RECONCILIATION_VECTOR_IDS
}


def reconciliation_vector_catalog_commitment() -> dict[str, object]:
    return {
        "evidence_version": 1,
        "expected_digests": EXPECTED_RECONCILIATION_DIGESTS,
        "release": "v0.4",
        "schema_version": "0.4.0",
        "vector_ids": list(RECONCILIATION_VECTOR_IDS),
    }


FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST = canonical_sha256(
    reconciliation_vector_catalog_commitment()
)


def validate_reconciliation_vector_catalog() -> None:
    if tuple(EXPECTED_RECONCILIATION_DIGESTS) != RECONCILIATION_VECTOR_IDS:
        raise ValueError("reconciliation vector IDs changed")
    if canonical_sha256(reconciliation_vector_catalog_commitment()) != (
        FROZEN_RECONCILIATION_VECTOR_CATALOG_DIGEST
    ):
        raise ValueError("reconciliation vector catalog digest changed")
