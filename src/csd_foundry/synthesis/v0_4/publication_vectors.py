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
    "completion-publication-bundle",
    "shard-index",
    "sealed-shard-manifest",
    "shard-seal-reference",
)
_EXPECTED_PUBLICATION_DIGEST_0 = "ee6d98a10b21e73ba6219efc969fd8b64573408f777b3a95583d7f890c8853fe"
_EXPECTED_PUBLICATION_DIGEST_1 = "d0124538dc9237cd397153946eeb4d813f4e43ea74ff89f4b36bdd4b65672921"
_EXPECTED_PUBLICATION_DIGEST_2 = "85c36eae8033984a2115536eb7ae31564d561de19d67d3ca70424806f9776d77"
_EXPECTED_PUBLICATION_DIGEST_3 = "62db3d6acae257a89492588408dde1c1a0dbb2c0688bb093dd2c1445ebb2229e"
_EXPECTED_PUBLICATION_DIGEST_4 = "4f530dbf3c95d33f21147a9588e326e3a908fee38dec0b5491ba4a2da8b69b86"
_EXPECTED_PUBLICATION_DIGEST_5 = "0f0ee7df7230dccf5db2be3cf789c2cbb8b0b5eb7ef1ed1299f25c65e2260507"
_EXPECTED_PUBLICATION_DIGEST_6 = "44d268d8f2ec1c808d5ea84173f48436ef6e3fc81be8ab7c31ccbc860a081fcc"
_EXPECTED_PUBLICATION_DIGEST_7 = "b3d5093138fe3d21290b49cb775d0f33b7e38ca0d1943aa65333d0ba6d072979"
_EXPECTED_PUBLICATION_DIGEST_8 = "3c497063dfb17ad0e20a06927b1e3931758cafe0e082247a26006a733e9e17b7"

EXPECTED_PUBLICATION_DIGESTS: dict[str, str] = {
    "accepted-completion-envelope": _EXPECTED_PUBLICATION_DIGEST_0,
    "completion-publication-bundle": _EXPECTED_PUBLICATION_DIGEST_1,
    "inventory-completion-reference": _EXPECTED_PUBLICATION_DIGEST_2,
    "no-clobber-layout": _EXPECTED_PUBLICATION_DIGEST_3,
    "publication-receipt-chain": _EXPECTED_PUBLICATION_DIGEST_4,
    "rejected-completion-envelope": _EXPECTED_PUBLICATION_DIGEST_5,
    "sealed-shard-manifest": _EXPECTED_PUBLICATION_DIGEST_6,
    "shard-index": _EXPECTED_PUBLICATION_DIGEST_7,
    "shard-seal-reference": _EXPECTED_PUBLICATION_DIGEST_8,
}
FROZEN_PUBLICATION_VECTOR_CATALOG_DIGEST = (
    "221fcaed0db2a97a5ef4694aa958776b6d270c3137b38943c28ead759076d224"
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
