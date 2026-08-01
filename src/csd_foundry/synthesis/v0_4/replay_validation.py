"""Validation and immutable evidence for deterministic v0.4 attempt replay."""

from __future__ import annotations

from dataclasses import dataclass, replace

from csd_foundry.synthesis.v0_4.attempts import (
    AcceptedSampleReplay,
    AttemptAccepted,
    AttemptRejected,
    AttemptRejection,
    AttemptReplayError,
    IncompleteAttemptPrefix,
    OperationalAttemptBlock,
    PostAcceptanceCompletionError,
    resolve_attempt_prefix,
)
from csd_foundry.synthesis.v0_4.canonical_values import CanonicalArray, CanonicalObject
from csd_foundry.synthesis.v0_4.choice_ledger import (
    ChoiceLedger,
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
from csd_foundry.synthesis.v0_4.choice_records import (
    BoundedIntegerChoiceRecord,
    WeightedChoiceRecord,
)
from csd_foundry.synthesis.v0_4.contracts import RejectionCause
from csd_foundry.synthesis.v0_4.exhaustion import ExhaustionEvidence
from csd_foundry.synthesis.v0_4.generation_namespace import (
    GenerationNamespace,
    build_generation_namespace,
)
from csd_foundry.synthesis.v0_4.identities import (
    EntityKind,
    IdentityLedger,
    IdentityRequest,
)
from csd_foundry.synthesis.v0_4.replay import ReplayMismatchError, replay_choice_ledger
from csd_foundry.synthesis.v0_4.replay_bundle import AttemptReplayBundle
from csd_foundry.synthesis.v0_4.replay_policy import (
    REPLAY_POLICY_ID,
    REPLAY_POLICY_VERSION,
    AttemptInputCommitment,
    ChoiceBudget,
    SearchBranchCommitment,
    replay_policy_document,
)
from csd_foundry.synthesis.v0_4.replay_vectors import (
    EXPECTED_REPLAY_DIGESTS,
    FROZEN_REPLAY_VECTOR_CATALOG_DIGEST,
    REPLAY_VECTOR_CATALOG,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_FIXTURE_SEED_TEXT = "csd-replay-v1-known-answer-fixture"
_FIXTURE_TARGET_DIGEST = canonical_sha256({"target": "replay-v1-known-answer"})


@dataclass(frozen=True, slots=True)
class ReplayValidationReport:
    release: str
    replay_vectors: int
    replay_vectors_passed: int
    vector_catalog_digest: str
    choice_records_replayed: int
    choice_ledger_order_stable: bool
    duplicate_choice_paths_rejected: bool
    choice_budget_enforced: bool
    poisoned_session_enforced: bool
    lowest_valid_attempt_enforced: bool
    incomplete_prefixes_nonsemantic: bool
    post_acceptance_rejected: bool
    complete_exhaustion_verified: bool
    exhaustion_converted_to_infeasibility: bool
    operational_abort_has_semantic_completion: bool
    tamper_cases: int
    tamper_cases_rejected: int
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "replay_policy_id": REPLAY_POLICY_ID,
            "replay_policy_version": REPLAY_POLICY_VERSION,
            "replay_vectors": self.replay_vectors,
            "replay_vectors_passed": self.replay_vectors_passed,
            "vector_catalog_digest": self.vector_catalog_digest,
            "choice_records_replayed": self.choice_records_replayed,
            "choice_ledger_order_stable": self.choice_ledger_order_stable,
            "duplicate_choice_paths_rejected": self.duplicate_choice_paths_rejected,
            "choice_budget_enforced": self.choice_budget_enforced,
            "poisoned_session_enforced": self.poisoned_session_enforced,
            "lowest_valid_attempt_enforced": self.lowest_valid_attempt_enforced,
            "incomplete_prefixes_nonsemantic": self.incomplete_prefixes_nonsemantic,
            "post_acceptance_rejected": self.post_acceptance_rejected,
            "complete_exhaustion_verified": self.complete_exhaustion_verified,
            "exhaustion_converted_to_infeasibility": (
                self.exhaustion_converted_to_infeasibility
            ),
            "operational_abort_has_semantic_completion": (
                self.operational_abort_has_semantic_completion
            ),
            "tamper_cases": self.tamper_cases,
            "tamper_cases_rejected": self.tamper_cases_rejected,
            "tamper_escapes": self.tamper_cases - self.tamper_cases_rejected,
            "errors": list(self.errors),
            "release_scale_claimed": False,
            "claim_boundary": (
                "This report validates bounded single-producer choice sessions, immutable "
                "choice ledgers, exact attempt replay, lowest-valid prefixes, and structured "
                "search exhaustion. It does not establish shard execution, planner "
                "completeness, state construction, oracle validity, infeasibility, or "
                "release-scale output."
            ),
        }


def _seed() -> RootSeed:
    return RootSeed.from_text(_FIXTURE_SEED_TEXT, SeedProvenance.KNOWN_ANSWER_FIXTURE)


def _namespace() -> GenerationNamespace:
    return build_generation_namespace(_FIXTURE_TARGET_DIGEST)


def _attempt(index: int, *, sample_index: int = 0) -> AttemptKey:
    return AttemptKey(SampleKey("v0.4", "replay-v1", sample_index), index)


def _path(attempt: AttemptKey, *segments: str | int) -> ChoicePath:
    return ChoicePath(attempt, "fixture", tuple(segments))


def _session(attempt: AttemptKey, *, maximum_choices: int = 32) -> ChoiceSession:
    return ChoiceSession(
        seed=_seed(),
        generation_namespace=_namespace(),
        attempt_key=attempt,
        producer_contract_id="replay-fixture",
        allowed_namespace_prefix="fixture",
        budget=ChoiceBudget(maximum_choices, 250_000),
    )


def _ledger(attempt: AttemptKey, order: tuple[str, ...] = ("bounded", "weighted", "ratio")):
    session = _session(attempt)
    typed_values = CanonicalArray((1, "1", True))
    for operation in order:
        if operation == "bounded":
            session.bounded_integer(_path(attempt, "bounded"), 257)
        elif operation == "weighted":
            session.weighted_choice(
                _path(attempt, "weighted"),
                typed_values,
                (2, 3, 5),
            )
        elif operation == "ratio":
            session.choose_ratio(_path(attempt, "ratio"), 2, 7)
        else:
            raise ValueError(f"unknown fixture operation: {operation}")
    return session.freeze()


def _identity_evidence(attempt: AttemptKey):
    ledger = IdentityLedger(_seed(), _namespace())
    ledger.allocate(
        IdentityRequest(
            attempt_key=attempt,
            entity_kind=EntityKind.EVIDENCE,
            role_segments=("replay", attempt.attempt_index),
            ordinal=0,
        )
    )
    return ledger.records(), ledger.canonical_digest


def _input_commitment(attempt: AttemptKey) -> AttemptInputCommitment:
    return AttemptInputCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        producer_contract_id="replay-fixture",
        producer_contract_version=1,
        producer_contract_digest=canonical_sha256(
            {"producer_contract_id": "replay-fixture", "version": 1}
        ),
        payload=CanonicalObject.from_pairs(
            (("fixture", "replay-v1"), ("sample_index", attempt.sample_key.sample_index))
        ),
    )


def _bundle(index: int, *, accepted: bool, sample_index: int) -> AttemptReplayBundle:
    attempt = _attempt(index, sample_index=sample_index)
    ledger = _ledger(attempt)
    identity_records, identity_digest = _identity_evidence(attempt)
    input_commitment = _input_commitment(attempt)
    branch = SearchBranchCommitment(
        attempt_key=attempt,
        generation_namespace_digest=_namespace().digest,
        attempt_input_commitment_digest=input_commitment.digest,
        choice_ledger_digest=ledger.canonical_digest,
        branch_facts=CanonicalObject.from_pairs(
            (("accepted", accepted), ("attempt_index", index))
        ),
    )
    if accepted:
        completion = AttemptAccepted(
            attempt_key=attempt,
            generation_namespace_digest=_namespace().digest,
            attempt_input_commitment_digest=input_commitment.digest,
            search_branch_digest=branch.digest,
            choice_ledger_digest=ledger.canonical_digest,
            identity_ledger_digest=identity_digest,
            result=CanonicalObject.from_pairs(
                (("accepted", True), ("attempt_index", index))
            ),
        )
    else:
        rejection = AttemptRejection(
            cause=RejectionCause.PLAN_CONSTRUCTION_FAILURE,
            detail_code=f"fixture-rejected-{index}",
            constraint_ids=("FIXTURE.CONSTRAINT.A", "FIXTURE.CONSTRAINT.B"),
            normalized_facts=CanonicalObject.from_pairs(
                (("attempt_index", index), ("reason", "fixture"))
            ),
            search_branch_digest=branch.digest,
        )
        completion = AttemptRejected(
            attempt_key=attempt,
            generation_namespace_digest=_namespace().digest,
            attempt_input_commitment_digest=input_commitment.digest,
            search_branch_digest=branch.digest,
            choice_ledger_digest=ledger.canonical_digest,
            identity_ledger_digest=identity_digest,
            rejection=rejection,
        )
    bundle = AttemptReplayBundle(
        input_commitment=input_commitment,
        completion=completion,
        search_branch=branch,
        choice_ledger=ledger,
        identity_records=identity_records,
    )
    bundle.validate(_seed(), _namespace())
    return bundle


def _forced_redraw_record() -> BoundedIntegerChoiceRecord:
    for sample_index in range(256):
        attempt = _attempt(0, sample_index=1000 + sample_index)
        session = _session(attempt, maximum_choices=1)
        session.bounded_integer(_path(attempt, "forced-redraw"), 129)
        ledger = session.freeze()
        record = ledger.records[0]
        if type(record) is BoundedIntegerChoiceRecord and record.evidence.draw_index > 0:
            return record
    raise RuntimeError("bounded forced-redraw canary was not found in the finite fixture domain")


def generate_replay_digests() -> dict[str, str]:
    """Generate independently reviewable digest outputs for replay-vector version 1."""

    accepted_zero = _bundle(0, accepted=True, sample_index=10)
    rejected_prefix = tuple(
        _bundle(index, accepted=index == 2, sample_index=11).completion
        for index in range(3)
    )
    accepted_replay = resolve_attempt_prefix(AttemptRange(4), rejected_prefix)
    if type(accepted_replay) is not AcceptedSampleReplay:
        raise RuntimeError("accepted-prefix fixture did not resolve")

    exhausted_completions = tuple(
        _bundle(index, accepted=False, sample_index=12).completion
        for index in range(3)
    )
    exhausted = resolve_attempt_prefix(AttemptRange(3), exhausted_completions)
    if type(exhausted) is not ExhaustionEvidence:
        raise RuntimeError("exhaustion fixture did not resolve")

    attempt = _attempt(0, sample_index=13)
    forward = _ledger(attempt, ("bounded", "weighted", "ratio"))
    reverse = _ledger(attempt, ("ratio", "weighted", "bounded"))
    if forward.canonical_digest != reverse.canonical_digest:
        raise RuntimeError("call-order canary diverged")
    weighted = next(
        record for record in forward.records if type(record) is WeightedChoiceRecord
    )
    forced = _forced_redraw_record()

    return {
        "accepted-attempt-zero": accepted_zero.completion.completion_digest,
        "rejected-prefix-then-accepted": accepted_replay.replay_digest,
        "complete-exhaustion": exhausted.exhaustion_digest,
        "call-order-independence": forward.canonical_digest,
        "typed-weighted-domain": weighted.digest,
        "forced-redraw": forced.digest,
        "identity-commitment": accepted_zero.completion.identity_ledger_digest,
    }


def _tamper_campaign() -> tuple[int, int, bool, bool, bool, bool]:
    rejected = 0
    cases = 0

    accepted = _bundle(0, accepted=True, sample_index=20)

    cases += 1
    try:
        bad_completion = replace(
            accepted.completion,
            choice_ledger_digest=canonical_sha256({"tampered": "ledger"}),
        )
        AttemptReplayBundle(
            accepted.input_commitment,
            bad_completion,
            accepted.search_branch,
            accepted.choice_ledger,
            accepted.identity_records,
        )
    except AttemptReplayError:
        rejected += 1

    cases += 1
    try:
        bad_input = replace(
            accepted.input_commitment,
            payload=CanonicalObject.from_pairs((("tampered", True),)),
        )
        AttemptReplayBundle(
            bad_input,
            accepted.completion,
            accepted.search_branch,
            accepted.choice_ledger,
            accepted.identity_records,
        )
    except AttemptReplayError:
        rejected += 1

    cases += 1
    try:
        bad_branch = replace(
            accepted.search_branch,
            branch_facts=CanonicalObject.from_pairs((("tampered", True),)),
        )
        AttemptReplayBundle(
            accepted.input_commitment,
            accepted.completion,
            bad_branch,
            accepted.choice_ledger,
            accepted.identity_records,
        )
    except AttemptReplayError:
        rejected += 1

    cases += 1
    first_record = accepted.choice_ledger.records[0]
    if type(first_record) is BoundedIntegerChoiceRecord:
        tampered_record = replace(first_record, upper_exclusive=first_record.upper_exclusive + 1)
    else:
        tampered_record = replace(first_record, schema_version="bad")
    try:
        tampered_ledger = replace(
            accepted.choice_ledger,
            records=(tampered_record, *accepted.choice_ledger.records[1:]),
        )
        replay_choice_ledger(_seed(), _namespace(), tampered_ledger)
    except (ReplayMismatchError, ValueError):
        rejected += 1

    cases += 1
    try:
        replace(
            accepted.choice_ledger,
            records=(
                accepted.choice_ledger.records[0],
                accepted.choice_ledger.records[0],
            ),
        )
    except ValueError:
        rejected += 1

    cases += 1
    try:
        replay_choice_ledger(
            RootSeed.from_text("different-seed", SeedProvenance.KNOWN_ANSWER_FIXTURE),
            _namespace(),
            accepted.choice_ledger,
        )
    except ReplayMismatchError:
        rejected += 1

    rejected_zero = _bundle(0, accepted=False, sample_index=21).completion
    accepted_one = _bundle(1, accepted=True, sample_index=21).completion
    rejected_two = _bundle(2, accepted=False, sample_index=21).completion

    cases += 1
    post_acceptance_rejected = False
    try:
        resolve_attempt_prefix(
            AttemptRange(4),
            (rejected_zero, accepted_one, rejected_two),
        )
    except PostAcceptanceCompletionError:
        rejected += 1
        post_acceptance_rejected = True

    cases += 1
    incomplete = resolve_attempt_prefix(AttemptRange(4), (accepted_one,))
    incomplete_nonsemantic = type(incomplete) is IncompleteAttemptPrefix
    if incomplete_nonsemantic:
        rejected += 1

    cases += 1
    try:
        ExhaustionEvidence(
            sample_key=rejected_zero.attempt_key.sample_key,
            generation_namespace_digest=rejected_zero.generation_namespace_digest,
            attempt_range=AttemptRange(2),
            rejected_attempts=(rejected_zero,),
        )
    except AttemptReplayError:
        rejected += 1

    cases += 1
    session = _session(_attempt(0, sample_index=22))
    try:
        session.weighted_choice(
            _path(session._attempt_key, "invalid"),  # type: ignore[attr-defined]
            CanonicalArray(("a", "b")),
            (1, 0),
        )
    except Exception:
        pass
    poisoned_session_enforced = session.state is ChoiceSessionState.POISONED
    if poisoned_session_enforced:
        try:
            session.freeze()
        except ChoiceSessionError:
            rejected += 1

    cases += 1
    operational = OperationalAttemptBlock(_attempt(0, sample_index=23), "worker-timeout", 1)
    operational_has_semantic_completion = isinstance(
        operational,
        (AttemptAccepted, AttemptRejected),
    )
    if not operational_has_semantic_completion:
        rejected += 1

    cases += 1
    try:
        replace(
            accepted.completion,
            identity_ledger_digest=canonical_sha256({"tampered": "identity"}),
        )
        accepted.validate(_seed(), _namespace())
    except (AttemptReplayError, ReplayMismatchError):
        rejected += 1

    return (
        cases,
        rejected,
        poisoned_session_enforced,
        incomplete_nonsemantic,
        post_acceptance_rejected,
        operational_has_semantic_completion,
    )


def validate_replay(release: str = "v0.4") -> ReplayValidationReport:
    errors: list[str] = []
    if release != "v0.4":
        errors.append("only replay release v0.4 is supported")

    catalog_digest = canonical_sha256(REPLAY_VECTOR_CATALOG)
    if catalog_digest != FROZEN_REPLAY_VECTOR_CATALOG_DIGEST:
        errors.append("replay vector catalog does not match the frozen version-1 digest")

    policy = replay_policy_document()
    if policy != {
        "policy_id": "csd-replay-contract",
        "policy_version": 1,
        "semantic_execution_mode": "lowest-valid-attempt",
    }:
        errors.append("replay policy version 1 changed")

    actual_digests: dict[str, str] = {}
    try:
        actual_digests = generate_replay_digests()
    except Exception as exc:
        errors.append(f"replay vector generation failed: {type(exc).__name__}: {exc}")

    vectors_passed = 0
    if not EXPECTED_REPLAY_DIGESTS:
        errors.append("replay version-1 expected digests are not frozen")
    else:
        for vector_id in REPLAY_VECTOR_CATALOG["vector_ids"]:
            if type(vector_id) is not str:
                errors.append("replay vector IDs must be exact strings")
                continue
            if actual_digests.get(vector_id) == EXPECTED_REPLAY_DIGESTS.get(vector_id):
                vectors_passed += 1
            else:
                errors.append(f"replay vector {vector_id} diverged")

    order_stable = False
    duplicate_rejected = False
    budget_enforced = False
    choice_records_replayed = 0
    try:
        attempt = _attempt(0, sample_index=30)
        forward = _ledger(attempt, ("bounded", "weighted", "ratio"))
        reverse = _ledger(attempt, ("ratio", "weighted", "bounded"))
        order_stable = forward.canonical_digest == reverse.canonical_digest
        replay_choice_ledger(_seed(), _namespace(), forward)
        choice_records_replayed = len(forward.records)
        try:
            replace(forward, records=(forward.records[0], forward.records[0]))
        except ValueError:
            duplicate_rejected = True
        limited = ChoiceSession(
            seed=_seed(),
            generation_namespace=_namespace(),
            attempt_key=_attempt(0, sample_index=31),
            producer_contract_id="replay-fixture",
            allowed_namespace_prefix="fixture",
            budget=ChoiceBudget(1, 250_000),
        )
        limited.bounded_integer(_path(limited._attempt_key, "one"), 2)  # type: ignore[attr-defined]
        try:
            limited.bounded_integer(
                _path(limited._attempt_key, "two"),  # type: ignore[attr-defined]
                2,
            )
        except Exception:
            budget_enforced = limited.state is ChoiceSessionState.POISONED
    except Exception as exc:
        errors.append(f"choice-ledger assurance failed: {type(exc).__name__}: {exc}")

    (
        tamper_cases,
        tamper_rejected,
        poisoned_session_enforced,
        incomplete_nonsemantic,
        post_acceptance_rejected,
        operational_has_semantic_completion,
    ) = _tamper_campaign()

    lowest_valid = False
    exhaustion_verified = False
    try:
        prefix = tuple(
            _bundle(index, accepted=index == 2, sample_index=40).completion
            for index in range(3)
        )
        accepted = resolve_attempt_prefix(AttemptRange(4), prefix)
        lowest_valid = (
            type(accepted) is AcceptedSampleReplay
            and accepted.accepted_attempt.attempt_key.attempt_index == 2
        )
        exhausted = resolve_attempt_prefix(
            AttemptRange(3),
            tuple(
                _bundle(index, accepted=False, sample_index=41).completion
                for index in range(3)
            ),
        )
        exhaustion_verified = (
            type(exhausted) is ExhaustionEvidence
            and len(exhausted.rejected_attempts) == 3
            and not hasattr(exhausted, "to_infeasibility_witness")
        )
    except Exception as exc:
        errors.append(f"attempt-prefix assurance failed: {type(exc).__name__}: {exc}")

    checks = {
        "choice ledger call order diverged": order_stable,
        "duplicate choice paths were accepted": duplicate_rejected,
        "choice budget was not enforced": budget_enforced,
        "poisoned session was reusable": poisoned_session_enforced,
        "lowest-valid attempt was not enforced": lowest_valid,
        "incomplete prefix became semantic": incomplete_nonsemantic,
        "post-acceptance completion was accepted": post_acceptance_rejected,
        "complete exhaustion was not verified": exhaustion_verified,
        "operational abort entered semantic completion": (
            not operational_has_semantic_completion
        ),
        "tamper campaign had escapes": tamper_rejected == tamper_cases,
    }
    for message, passed in checks.items():
        if not passed:
            errors.append(message)

    vector_ids = REPLAY_VECTOR_CATALOG["vector_ids"]
    replay_vector_count = len(vector_ids) if isinstance(vector_ids, list) else 0
    return ReplayValidationReport(
        release=release,
        replay_vectors=replay_vector_count,
        replay_vectors_passed=vectors_passed,
        vector_catalog_digest=catalog_digest,
        choice_records_replayed=choice_records_replayed,
        choice_ledger_order_stable=order_stable,
        duplicate_choice_paths_rejected=duplicate_rejected,
        choice_budget_enforced=budget_enforced,
        poisoned_session_enforced=poisoned_session_enforced,
        lowest_valid_attempt_enforced=lowest_valid,
        incomplete_prefixes_nonsemantic=incomplete_nonsemantic,
        post_acceptance_rejected=post_acceptance_rejected,
        complete_exhaustion_verified=exhaustion_verified,
        exhaustion_converted_to_infeasibility=False,
        operational_abort_has_semantic_completion=operational_has_semantic_completion,
        tamper_cases=tamper_cases,
        tamper_cases_rejected=tamper_rejected,
        errors=tuple(errors),
    )
