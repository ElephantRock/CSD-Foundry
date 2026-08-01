from __future__ import annotations

import pytest

from csd_foundry.synthesis.v0_4.attempts import AttemptAccepted, AttemptReplayError
from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_ledger import (
    ChoiceBudget,
    ChoiceSession,
    ChoiceSessionError,
    ChoiceSessionState,
    DuplicateChoicePathError,
)
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    ChoicePath,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.identities import (
    EntityKind,
    IdentityLedger,
    IdentityRequest,
)
from csd_foundry.synthesis.v0_4.replay_bundle import AttemptReplayBundle
from csd_foundry.synthesis.v0_4.replay_policy import (
    AttemptInputCommitment,
    SearchBranchCommitment,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


def _seed() -> RootSeed:
    return RootSeed.from_text("replay-review-regressions", SeedProvenance.KNOWN_ANSWER_FIXTURE)


def _namespace():
    return build_generation_namespace(canonical_sha256({"target": "review-regressions"}))


def _attempt(index: int) -> AttemptKey:
    return AttemptKey(SampleKey("v0.4", "review-regressions", 0), index)


def _choice_ledger(attempt: AttemptKey):
    return ChoiceSession(
        seed=_seed(),
        generation_namespace=_namespace(),
        attempt_key=attempt,
        producer_contract_id="review-fixture",
        allowed_namespace_prefix="fixture",
        budget=ChoiceBudget(8, 100_000),
    ).freeze()


def _input(attempt: AttemptKey) -> AttemptInputCommitment:
    return AttemptInputCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        producer_contract_id="review-fixture",
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256({"producer": "review-fixture"}),
        payload=CanonicalObject.from_pairs((("sample", "review-regressions"),)),
    )


def _identity_ledger(attempt: AttemptKey) -> IdentityLedger:
    ledger = IdentityLedger(_seed(), _namespace())
    for ordinal in (0, 1):
        ledger.allocate(
            IdentityRequest(
                attempt_key=attempt,
                entity_kind=EntityKind.EVIDENCE,
                role_segments=("review", ordinal),
                ordinal=ordinal,
            )
        )
    return ledger


def _bundle(attempt: AttemptKey, identity_ledger: IdentityLedger) -> AttemptReplayBundle:
    choice_ledger = _choice_ledger(attempt)
    input_commitment = _input(attempt)
    branch = SearchBranchCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        attempt_input_commitment_digest=input_commitment.digest,
        choice_ledger_digest=choice_ledger.canonical_digest,
        branch_facts=CanonicalObject.from_pairs((("attempt", attempt.attempt_index),)),
    )
    completion = AttemptAccepted(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        attempt_input_commitment_digest=input_commitment.digest,
        search_branch_digest=branch.digest,
        choice_ledger_digest=choice_ledger.canonical_digest,
        identity_ledger_digest=identity_ledger.canonical_digest,
        result=CanonicalObject.from_pairs((("accepted", True),)),
    )
    return AttemptReplayBundle(
        input_commitment=input_commitment,
        completion=completion,
        search_branch=branch,
        choice_ledger=choice_ledger,
        identity_records=identity_ledger.records(),
    )


def test_duplicate_choice_path_poisons_session_and_blocks_freeze() -> None:
    attempt = _attempt(0)
    session = ChoiceSession(
        seed=_seed(),
        generation_namespace=_namespace(),
        attempt_key=attempt,
        producer_contract_id="review-fixture",
        allowed_namespace_prefix="fixture",
        budget=ChoiceBudget(8, 100_000),
    )
    path = ChoicePath(attempt, "fixture", ("duplicate",))
    session.bounded_integer(path, 2)

    with pytest.raises(DuplicateChoicePathError):
        session.bounded_integer(path, 2)
    assert session.state is ChoiceSessionState.POISONED
    with pytest.raises(ChoiceSessionError):
        session.freeze()


def test_replay_bundle_rejects_identity_records_from_another_attempt() -> None:
    attempt_zero = _attempt(0)
    attempt_one_identities = _identity_ledger(_attempt(1))

    with pytest.raises(AttemptReplayError, match="different attempt"):
        _bundle(attempt_zero, attempt_one_identities)


def test_identity_record_transport_order_does_not_change_bundle_digest() -> None:
    attempt = _attempt(0)
    identity_ledger = _identity_ledger(attempt)
    canonical_bundle = _bundle(attempt, identity_ledger)
    reversed_bundle = AttemptReplayBundle(
        input_commitment=canonical_bundle.input_commitment,
        completion=canonical_bundle.completion,
        search_branch=canonical_bundle.search_branch,
        choice_ledger=canonical_bundle.choice_ledger,
        identity_records=tuple(reversed(canonical_bundle.identity_records)),
    )

    assert canonical_bundle.replay_evidence_digest == reversed_bundle.replay_evidence_digest
    assert canonical_bundle.evidence_digest == reversed_bundle.evidence_digest
    assert canonical_bundle.to_json_value() == reversed_bundle.to_json_value()
