from __future__ import annotations

import json
from pathlib import Path

import pytest

from csd_foundry.synthesis.v0_4.attempts import (
    AcceptedSampleReplay,
    AttemptAccepted,
    AttemptRejected,
    AttemptRejection,
    AttemptReplayError,
)
from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_ledger import ChoiceBudget, ChoiceSession
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    AttemptRange,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.contracts import RejectionCause
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.replay_bundle import AttemptReplayBundle
from csd_foundry.synthesis.v0_4.replay_policy import (
    AttemptInputCommitment,
    SearchBranchCommitment,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
ATTEMPT_INPUT_SCHEMA = ROOT / "specs" / "v0.4" / "attempt_input.schema.json"


def _seed() -> RootSeed:
    return RootSeed.from_text(
        "replay-second-review-regressions",
        SeedProvenance.KNOWN_ANSWER_FIXTURE,
    )


def _namespace():
    return build_generation_namespace(
        canonical_sha256({"target": "replay-second-review-regressions"})
    )


def _sample(target_id: str = "second-review") -> SampleKey:
    return SampleKey("v0.4", target_id, 0)


def _attempt(index: int, target_id: str = "second-review") -> AttemptKey:
    return AttemptKey(_sample(target_id), index)


def _input(attempt: AttemptKey, producer_contract_id: str) -> AttemptInputCommitment:
    return AttemptInputCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        producer_contract_id=producer_contract_id,
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256(
            {"producer_contract_id": producer_contract_id, "version": 1}
        ),
        payload=CanonicalObject.from_pairs((("fixture", "second-review"),)),
    )


def _accepted_completion(
    attempt: AttemptKey,
    *,
    namespace_digest: str,
    input_digest: str,
    branch_digest: str,
    ledger_digest: str,
) -> AttemptAccepted:
    return AttemptAccepted(
        attempt_key=attempt,
        generation_namespace_digest=namespace_digest,
        attempt_input_commitment_digest=input_digest,
        search_branch_digest=branch_digest,
        choice_ledger_digest=ledger_digest,
        identity_ledger_digest=canonical_sha256([]),
        result=CanonicalObject.from_pairs((("accepted", True),)),
    )


def _rejected_completion(
    attempt: AttemptKey,
    *,
    namespace_digest: str,
) -> AttemptRejected:
    branch_digest = canonical_sha256(
        {"attempt": attempt.attempt_index, "target": attempt.sample_key.target_id}
    )
    rejection = AttemptRejection(
        cause=RejectionCause.PLAN_CONSTRUCTION_FAILURE,
        detail_code="second-review-rejected",
        constraint_ids=("SECOND_REVIEW.CONSTRAINT",),
        normalized_facts=CanonicalObject.from_pairs((("accepted", False),)),
        search_branch_digest=branch_digest,
    )
    return AttemptRejected(
        attempt_key=attempt,
        generation_namespace_digest=namespace_digest,
        attempt_input_commitment_digest=canonical_sha256(
            {"input": attempt.attempt_index, "target": attempt.sample_key.target_id}
        ),
        search_branch_digest=branch_digest,
        choice_ledger_digest=canonical_sha256(
            {"ledger": attempt.attempt_index, "target": attempt.sample_key.target_id}
        ),
        identity_ledger_digest=canonical_sha256([]),
        rejection=rejection,
    )


def test_replay_bundle_rejects_mismatched_producer_attribution() -> None:
    attempt = _attempt(0)
    ledger = ChoiceSession(
        seed=_seed(),
        generation_namespace=_namespace(),
        attempt_key=attempt,
        producer_contract_id="choice-producer",
        allowed_namespace_prefix="fixture",
        budget=ChoiceBudget(4, 100_000),
    ).freeze()
    input_commitment = _input(attempt, "different-producer")
    branch = SearchBranchCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        attempt_input_commitment_digest=input_commitment.digest,
        choice_ledger_digest=ledger.canonical_digest,
        branch_facts=CanonicalObject.from_pairs((("attempt", 0),)),
    )
    completion = _accepted_completion(
        attempt,
        namespace_digest=_namespace().digest,
        input_digest=input_commitment.digest,
        branch_digest=branch.digest,
        ledger_digest=ledger.canonical_digest,
    )

    with pytest.raises(AttemptReplayError, match="producer contracts must match"):
        AttemptReplayBundle(
            input_commitment=input_commitment,
            completion=completion,
            search_branch=branch,
            choice_ledger=ledger,
            identity_records=(),
        )


def test_direct_accepted_replay_rejects_mixed_sample_prefix() -> None:
    namespace_digest = _namespace().digest
    rejected = _rejected_completion(
        _attempt(0, "sample-a"),
        namespace_digest=namespace_digest,
    )
    accepted_attempt = _attempt(1, "sample-b")
    accepted = _accepted_completion(
        accepted_attempt,
        namespace_digest=namespace_digest,
        input_digest=canonical_sha256({"input": "sample-b"}),
        branch_digest=canonical_sha256({"branch": "sample-b"}),
        ledger_digest=canonical_sha256({"ledger": "sample-b"}),
    )

    with pytest.raises(AttemptReplayError, match="different sample"):
        AcceptedSampleReplay(
            sample_key=accepted_attempt.sample_key,
            attempt_range=AttemptRange(3),
            rejected_prefix=(rejected,),
            accepted_attempt=accepted,
        )


def test_direct_accepted_replay_rejects_mixed_namespace_prefix() -> None:
    sample = _sample()
    rejected = _rejected_completion(
        AttemptKey(sample, 0),
        namespace_digest=canonical_sha256({"namespace": "other"}),
    )
    accepted_attempt = AttemptKey(sample, 1)
    accepted = _accepted_completion(
        accepted_attempt,
        namespace_digest=_namespace().digest,
        input_digest=canonical_sha256({"input": "accepted"}),
        branch_digest=canonical_sha256({"branch": "accepted"}),
        ledger_digest=canonical_sha256({"ledger": "accepted"}),
    )

    with pytest.raises(AttemptReplayError, match="different namespace"):
        AcceptedSampleReplay(
            sample_key=sample,
            attempt_range=AttemptRange(3),
            rejected_prefix=(rejected,),
            accepted_attempt=accepted,
        )


def test_direct_accepted_replay_rejects_out_of_range_acceptance() -> None:
    attempt = _attempt(2)
    accepted = _accepted_completion(
        attempt,
        namespace_digest=_namespace().digest,
        input_digest=canonical_sha256({"input": "out-of-range"}),
        branch_digest=canonical_sha256({"branch": "out-of-range"}),
        ledger_digest=canonical_sha256({"ledger": "out-of-range"}),
    )

    with pytest.raises(AttemptReplayError, match="outside the declared range"):
        AcceptedSampleReplay(
            sample_key=attempt.sample_key,
            attempt_range=AttemptRange(2),
            rejected_prefix=(),
            accepted_attempt=accepted,
        )


def test_attempt_input_schema_covers_full_emitted_value() -> None:
    value = _input(_attempt(0), "choice-producer").to_json_value()
    schema = json.loads(ATTEMPT_INPUT_SCHEMA.read_text(encoding="utf-8"))

    assert set(value) <= set(schema["properties"])
    assert set(schema["required"]) <= set(value)
    assert {"payload", "commitment_digest"} <= set(schema["required"])
