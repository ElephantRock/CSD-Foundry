from __future__ import annotations

from dataclasses import replace

import pytest

from csd_foundry.synthesis.v0_4.attempts import (
    AcceptedSampleReplay,
    AttemptAccepted,
    AttemptRejected,
    AttemptRejection,
    AttemptReplayError,
    IncompleteAttemptPrefix,
    PostAcceptanceCompletionError,
    resolve_attempt_prefix,
)
from csd_foundry.synthesis.v0_4.canonical_values import CanonicalArray, CanonicalObject
from csd_foundry.synthesis.v0_4.choice_ledger import (
    ChoiceBudgetExceeded,
    ChoiceSession,
    ChoiceSessionError,
    ChoiceSessionState,
)
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    AttemptRange,
    ChoicePath,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.contracts import RejectionCause
from csd_foundry.synthesis.v0_4.exhaustion import ExhaustionEvidence
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.replay import ReplayMismatchError, replay_choice_ledger
from csd_foundry.synthesis.v0_4.replay_bundle import AttemptReplayBundle
from csd_foundry.synthesis.v0_4.replay_policy import (
    AttemptInputCommitment,
    ChoiceBudget,
    SearchBranchCommitment,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


def _seed() -> RootSeed:
    return RootSeed.from_text("replay-contract-tests", SeedProvenance.KNOWN_ANSWER_FIXTURE)


def _namespace():
    return build_generation_namespace(canonical_sha256({"target": "replay-contract-tests"}))


def _attempt(index: int = 0) -> AttemptKey:
    return AttemptKey(SampleKey("v0.4", "replay-contract-tests", 4), index)


def _path(attempt: AttemptKey, *segments: str | int) -> ChoicePath:
    return ChoicePath(attempt, "fixture", tuple(segments))


def _session(attempt: AttemptKey, *, maximum_choices: int = 16, maximum_bytes: int = 100_000):
    return ChoiceSession(
        seed=_seed(),
        generation_namespace=_namespace(),
        attempt_key=attempt,
        producer_contract_id="replay-fixture",
        allowed_namespace_prefix="fixture",
        budget=ChoiceBudget(maximum_choices, maximum_bytes),
    )


def _empty_object() -> CanonicalObject:
    return CanonicalObject.from_pairs(())


def _input(attempt: AttemptKey) -> AttemptInputCommitment:
    namespace = _namespace()
    return AttemptInputCommitment(
        attempt_key=attempt,
        generation_namespace_digest=namespace.digest,
        producer_contract_id="replay-fixture",
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256({"producer": "fixture", "version": 1}),
        payload=CanonicalObject.from_pairs((("target", "fixture"),)),
    )


def _rejection(branch_digest: str, code: str = "fixture-rejected") -> AttemptRejection:
    return AttemptRejection(
        cause=RejectionCause.PLAN_CONSTRUCTION_FAILURE,
        detail_code=code,
        constraint_ids=("FIXTURE.CONSTRAINT.A", "FIXTURE.CONSTRAINT.B"),
        normalized_facts=CanonicalObject.from_pairs((("reason", code),)),
        search_branch_digest=branch_digest,
    )


def _completion(index: int, *, accepted: bool):
    attempt = _attempt(index)
    namespace = _namespace()
    ledger = _session(attempt).freeze()
    input_commitment = _input(attempt)
    branch = SearchBranchCommitment(
        attempt_key=attempt,
        generation_namespace_digest=namespace.digest,
        attempt_input_commitment_digest=input_commitment.digest,
        choice_ledger_digest=ledger.canonical_digest,
        branch_facts=CanonicalObject.from_pairs((("attempt", index),)),
    )
    identity_digest = canonical_sha256([])
    if accepted:
        completion = AttemptAccepted(
            attempt_key=attempt,
            generation_namespace_digest=namespace.digest,
            attempt_input_commitment_digest=input_commitment.digest,
            search_branch_digest=branch.digest,
            choice_ledger_digest=ledger.canonical_digest,
            identity_ledger_digest=identity_digest,
            result=CanonicalObject.from_pairs((("accepted", True),)),
        )
    else:
        completion = AttemptRejected(
            attempt_key=attempt,
            generation_namespace_digest=namespace.digest,
            attempt_input_commitment_digest=input_commitment.digest,
            search_branch_digest=branch.digest,
            choice_ledger_digest=ledger.canonical_digest,
            identity_ledger_digest=identity_digest,
            rejection=_rejection(branch.digest, f"fixture-rejected-{index}"),
        )
    return completion, ledger, input_commitment, branch


def test_choice_ledger_is_call_order_independent_and_typed() -> None:
    attempt = _attempt()
    forward = _session(attempt)
    reverse = _session(attempt)
    values = CanonicalArray((1, "1", True))

    forward.bounded_integer(_path(attempt, "bounded"), 17)
    forward.weighted_choice(_path(attempt, "weighted"), values, (1, 2, 3))
    forward.choose_ratio(_path(attempt, "ratio"), 2, 5)

    reverse.choose_ratio(_path(attempt, "ratio"), 2, 5)
    reverse.weighted_choice(_path(attempt, "weighted"), values, (1, 2, 3))
    reverse.bounded_integer(_path(attempt, "bounded"), 17)

    forward_ledger = forward.freeze()
    reverse_ledger = reverse.freeze()
    assert forward_ledger.canonical_digest == reverse_ledger.canonical_digest
    assert len({canonical_sha256(item) for item in values.to_json_value()}) == 3
    assert replay_choice_ledger(_seed(), _namespace(), forward_ledger) == (
        forward_ledger.canonical_digest
    )


def test_post_reservation_failure_poisons_the_session() -> None:
    attempt = _attempt()
    session = _session(attempt)
    path = _path(attempt, "invalid-weight")
    with pytest.raises(Exception):
        session.weighted_choice(path, CanonicalArray(("a", "b")), (1, 0))
    assert session.state is ChoiceSessionState.POISONED
    with pytest.raises(ChoiceSessionError):
        session.freeze()
    with pytest.raises(ChoiceSessionError):
        session.bounded_integer(_path(attempt, "later"), 2)


def test_choice_count_and_byte_budgets_fail_closed() -> None:
    attempt = _attempt()
    count_limited = _session(attempt, maximum_choices=1)
    count_limited.bounded_integer(_path(attempt, "first"), 2)
    with pytest.raises(ChoiceBudgetExceeded):
        count_limited.bounded_integer(_path(attempt, "second"), 2)
    assert count_limited.state is ChoiceSessionState.POISONED

    byte_limited = _session(attempt, maximum_bytes=1)
    with pytest.raises(ChoiceBudgetExceeded):
        byte_limited.bounded_integer(_path(attempt, "bytes"), 2)
    assert byte_limited.state is ChoiceSessionState.POISONED


def test_choice_replay_detects_tampered_bound() -> None:
    attempt = _attempt()
    session = _session(attempt)
    session.bounded_integer(_path(attempt, "bounded"), 17)
    ledger = session.freeze()
    record = ledger.records[0]
    tampered_record = replace(record, upper_exclusive=19)
    tampered_ledger = replace(ledger, records=(tampered_record,))
    with pytest.raises(ReplayMismatchError):
        replay_choice_ledger(_seed(), _namespace(), tampered_ledger)


def test_attempt_prefix_requires_lowest_valid_and_no_later_completion() -> None:
    rejected_zero = _completion(0, accepted=False)[0]
    accepted_one = _completion(1, accepted=True)[0]
    result = resolve_attempt_prefix(AttemptRange(4), (accepted_one, rejected_zero))
    assert type(result) is AcceptedSampleReplay
    assert result.accepted_attempt.attempt_key.attempt_index == 1

    missing = resolve_attempt_prefix(AttemptRange(4), (accepted_one,))
    assert type(missing) is IncompleteAttemptPrefix
    assert missing.first_missing_attempt_index == 0

    rejected_two = _completion(2, accepted=False)[0]
    with pytest.raises(PostAcceptanceCompletionError):
        resolve_attempt_prefix(
            AttemptRange(4),
            (rejected_zero, accepted_one, rejected_two),
        )


def test_complete_exhaustion_is_structured_and_not_infeasibility() -> None:
    completions = tuple(_completion(index, accepted=False)[0] for index in range(3))
    result = resolve_attempt_prefix(AttemptRange(3), completions)
    assert type(result) is ExhaustionEvidence
    assert result.candidate_constraint_ids == (
        "FIXTURE.CONSTRAINT.A",
        "FIXTURE.CONSTRAINT.B",
    )
    handoff = result.planner_handoff()
    assert handoff.exhaustion_digest == result.exhaustion_digest
    assert not hasattr(result, "to_infeasibility_witness")


def test_attempt_replay_bundle_recomputes_all_commitments() -> None:
    completion, ledger, input_commitment, branch = _completion(0, accepted=True)
    bundle = AttemptReplayBundle(
        input_commitment=input_commitment,
        completion=completion,
        search_branch=branch,
        choice_ledger=ledger,
        identity_records=(),
    )
    assert bundle.validate(_seed(), _namespace()) == bundle.evidence_digest

    with pytest.raises(AttemptReplayError):
        AttemptReplayBundle(
            input_commitment=input_commitment,
            completion=replace(completion, search_branch_digest=canonical_sha256({"bad": 1})),
            search_branch=branch,
            choice_ledger=ledger,
            identity_records=(),
        )
