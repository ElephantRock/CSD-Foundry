from __future__ import annotations

import pytest

from csd_foundry.synthesis.v0_4.reconciliation_core import (
    ReconciliationError,
    ReplayAttestation,
)
from csd_foundry.synthesis.v0_4.reconciliation_validation import (
    generate_reconciliation_digests,
    validate_reconciliation,
)
from csd_foundry.synthesis.v0_4.replay_validation import _bundle


def test_reconciliation_is_topology_independent_and_full_replay() -> None:
    actual, runs = generate_reconciliation_digests()
    assert actual["semantic-manifest"]
    assert len({run["semantic"] for run in runs}) == 1
    assert len({run["run"] for run in runs}) == 3
    assert all(run["replays"] == 11 for run in runs)
    assert all(run["accepted"] == 4 for run in runs)
    assert all(run["exhausted"] == 1 for run in runs)
    assert all(int(run["peak"]) <= int(run["shards"]) + 3 for run in runs)


def test_reconciliation_report_exposes_frozen_boundary() -> None:
    report = validate_reconciliation("v0.4")
    assert report.semantic_manifest_topology_independent
    assert report.run_evidence_topology_specific
    assert report.bounded_k_way_merge
    assert report.full_replay_enforced
    assert report.lowest_valid_attempt_enforced
    assert report.complete_exhaustion_nonsemantic
    assert report.exact_duplicates_collapsed
    assert report.conflicts_rejected
    assert report.atomic_final_seal_verified


def test_replay_attestation_rejects_non_full_replay() -> None:
    completion = _bundle(0, accepted=True, sample_index=99).completion
    with pytest.raises(ReconciliationError, match="FULL_REPLAY"):
        ReplayAttestation(
            completion.attempt_key,
            "0" * 64,
            completion.completion_digest,
            "1" * 64,
            "attestor",
            1,
            validation_mode="PRUNED_REPLAY",
        )
