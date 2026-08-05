"""Exact immutable CSD Reasoning Seed v0.1 identity binding for E0-H."""

from __future__ import annotations

from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError
from csd_foundry.empirical.e0h.run_release import (
    SeedDatasetBinding as _BaseSeedDatasetBinding,
)

_EXPECTED_SEED_DIGESTS = {
    "manifest": "7afcd7a7c50496467b56530a3b6d326c0b5daae7ae16764ebd4b678e1befe5b8",
    "sft": "02903221be8aff0f5e667dbde556040f049bf386c84722a032101ae02879aaa9",
    "preference": "18f7d612041d2769d138a51165d5b55f73bd12e95578e4e012f45bbdd981aa5c",
}


class SeedDatasetBinding(_BaseSeedDatasetBinding):
    """Seed binding that accepts only the exact immutable v0.1 artifact digests."""

    def __post_init__(self) -> None:
        super().__post_init__()
        observed = {
            "manifest": self.manifest_digest,
            "sft": self.sft_digest,
            "preference": self.preference_digest,
        }
        if observed != _EXPECTED_SEED_DIGESTS:
            raise E0HRunReleaseError(
                "dataset digests must equal the immutable v0.1 seed digests; "
                f"expected={_EXPECTED_SEED_DIGESTS}, observed={observed}"
            )
