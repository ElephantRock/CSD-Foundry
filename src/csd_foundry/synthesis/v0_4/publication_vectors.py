"""Frozen known-answer vectors for v0.4 publication protocol version 1."""

from __future__ import annotations

from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

PUBLICATION_VECTOR_EVIDENCE_VERSION = 1
PUBLICATION_VECTOR_IDS = (
    "accepted-completion-envelope",
    "rejected-completion-envelope",
    "inventory-completion-reference",
    "publication-receipt-chain",
    "no-clobber-layout",
)
_EXPECTED_PUBLICATION_DIGEST_0 = "ccc9916213583526dfb4a0df590622741a723fc657fc4d2b9f48ceae6e17d94e"
_EXPECTED_PUBLICATION_DIGEST_1 = "09252fb469206e4fae82a9bc24f6fa4cb16d5e758e947f519eb9d9f320605dc6"
_EXPECTED_PUBLICATION_DIGEST_2 = "f5a4264264927a30babb1052de0ef3835d860e74806e232a70a120faae1d76e1"
_EXPECTED_PUBLICATION_DIGEST_3 = "ac542a8de0360a2a8a2004ae34e901fd46e5fb1b751c097683fd0d38678daa74"
_EXPECTED_PUBLICATION_DIGEST_4 = "0f0ee7df7230dccf5db2be3cf789c2cbb8b0b5eb7ef1ed1299f25c65e2260507"

EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {
    "accepted-completion-envelope": _EXPECTED_PUBLICATION_DIGEST_0,
    "inventory-completion-reference": _EXPECTED_PUBLICATION_DIGEST_1,
    "no-clobber-layout": _EXPECTED_PUBLICATION_DIGEST_2,
    "publication-receipt-chain": _EXPECTED_PUBLICATION_DIGEST_3,
    "rejected-completion-envelope": _EXPECTED_PUBLICATION_DIGEST_4,
}
FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST = (
    "955da9ed90735187574dbf0cbf9813447f34658e22643abbe4f148f06976448a"
)


def publication_vector_catalog_commitment() -> dict[str, object]:
    return {
        "evidence_version": PUBLICATION_VECTOR_EVIDENCE_VERSION,
        "expected_digests": EXPECTED_PUBLICATION_DIGESTS,
        "vector_ids": list(PUBLICATION_VECTOR_IDS),
    }


def validate_publication_vector_catalog() -> None:
    if tuple(EXPECTED_PUBLICATION_DIGESTS) != tuple(sorted(EXPECTED_PUBLICATION_DIGESTS)):
        raise ValueError("publication vector digests must use sorted vector IDs")
    if set(PUBLICATION_VECTOR_IDS) != set(EXPECTED_PUBLICATION_DIGESTS):
        raise ValueError("publication vector IDs and expected digests differ")
    if (
        canonical_sha256(publication_vector_catalog_commitment())
        != FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST
    ):
        raise ValueError("publication vector catalog digest changed")
