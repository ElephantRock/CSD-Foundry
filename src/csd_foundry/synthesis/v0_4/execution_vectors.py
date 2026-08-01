"""Frozen known-answer vectors for v0.4 execution-protocol evidence version 2."""

from __future__ import annotations

from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

EXECUTION_VECTOR_EVIDENCE_VERSION = 2
EXECUTION_VECTOR_IDS = (
    "sample-key-encoding",
    "shard-assignment",
    "required-schema-versions",
    "retry-policy",
    "execution-inventory",
    "operational-exhaustion",
    "inventory-supersession",
)

EXPECTED_EXECUTION_DIGESTS: dict[str, str] = {
    "execution-inventory": "24318c3f24ffa6ce8c5e2c57ddcb40634d472bde5f1152093a4ff9449ef152e9",
    "inventory-supersession": "d48582ce74f7a9705b4140e5d4137cc22bd123117dd7562ceacdb4b032420e2b",
    "operational-exhaustion": "251e31ca0c559bf28bd3a58aa20c3a7a19eea592a3b54beeb4f6fdcfa85831e3",
    "required-schema-versions": "4cd4c074fed2955a9004df64de0979239ff135cc93b1f6e6e1a6d58bf0a6531a",
    "retry-policy": "30320e0bb4bba10b71b8862157bc3a3b27356e940dcf36f0a1e601b7355795f7",
    "sample-key-encoding": "897a55e7039c5cc98c52497bf3a7656bdaf00424765ff1f0a30ab2da77e9d5fa",
    "shard-assignment": "ba5111604090596f7ac8591f5b10954dfd10650877711f80d5c7990bff2c3367",
}

LEGACY_EXECUTION_VECTOR_V1_CATALOG_DIGEST = (
    "ae40bcce9e169c5bc11c9a3e83ab582124e973c1c7afafefdb99a74e2833a341"
)
FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST = (
    "5a9bbee3603ed72bf5eb1b6b2ac324469262b5f1aee31cdd8b638d318966418f"
)


def execution_vector_catalog_commitment() -> dict[str, object]:
    return {
        "evidence_version": EXECUTION_VECTOR_EVIDENCE_VERSION,
        "expected_digests": EXPECTED_EXECUTION_DIGESTS,
        "vector_ids": list(EXECUTION_VECTOR_IDS),
    }


def validate_execution_vector_catalog() -> None:
    if tuple(EXPECTED_EXECUTION_DIGESTS) != tuple(sorted(EXPECTED_EXECUTION_DIGESTS)):
        raise ValueError("execution vector digests must use sorted vector IDs")
    if set(EXECUTION_VECTOR_IDS) != set(EXPECTED_EXECUTION_DIGESTS):
        raise ValueError("execution vector IDs and expected digests differ")
    if (
        canonical_sha256(execution_vector_catalog_commitment())
        != FROZEN_EXECUTION_VECTOR_CATALOG_DIGEST
    ):
        raise ValueError("execution vector catalog digest changed")
