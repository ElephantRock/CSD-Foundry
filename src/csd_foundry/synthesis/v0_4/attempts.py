"""Schema-versioned attempt completions and strict lowest-valid prefix resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeAlias

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.contracts import RejectionCause, RejectionOwner
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

ATTEMPT_REPLAY_SCHEMA_VERSION = "csd-attempt-replay/0.4"
ATTEMPT_REJECTION_SCHEMA_VERSION = "csd-attempt-rejection/0.4"
_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class AttemptReplayError(ValueError):
    """Raised when attempt replay evidence violates the v0.4 contract."""


class PostAcceptanceCompletionError(AttemptReplayError):
    """Raised when semantic evidence appears after an accepted attempt."""


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise AttemptReplayError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise AttemptReplayError(f"{field_name} must be a lowercase ASCII token")
    return value


def _attempt_key_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey:
        raise AttemptReplayError("attempt_key must use the exact AttemptKey class")
    sample = attempt_key.sample_key
    return {
        "attempt_index": attempt_key.attempt_index,
        "release": sample.release,
        "sample_index": sample.sample_index,
        "target_id": sample.target_id,
    }


def _constraint_sort_key(value: str) -> bytes:
    return value.encode("utf-8")


@dataclass(frozen=True, slots=True)
class AttemptRejection:
    cause: RejectionCause
    detail_code: str
    constraint_ids: tuple[str, ...]
    normalized_facts: CanonicalObject
    search_branch_digest: str
    schema_version: str = ATTEMPT_REJECTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttemptRejection:
            raise AttemptReplayError("attempt rejections must use the exact contract class")
        if type(self.cause) is not RejectionCause:
            raise AttemptReplayError("cause must be an exact RejectionCause")
        _require_token(self.detail_code, "detail_code")
        if type(self.constraint_ids) is not tuple:
            raise AttemptReplayError("constraint_ids must be an immutable tuple")
        if not self.constraint_ids:
            raise AttemptReplayError("attempt rejection requires at least one constraint ID")
        for value in self.constraint_ids:
            if type(value) is not str or not value:
                raise AttemptReplayError("constraint IDs must be nonempty exact strings")
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AttemptReplayError("constraint IDs must be valid UTF-8") from exc
        if len(self.constraint_ids) != len(set(self.constraint_ids)):
            raise AttemptReplayError("constraint IDs must be unique")
        if self.constraint_ids != tuple(sorted(self.constraint_ids, key=_constraint_sort_key)):
            raise AttemptReplayError("constraint IDs must use unsigned UTF-8 byte order")
        if type(self.normalized_facts) is not CanonicalObject:
            raise AttemptReplayError("normalized_facts must be an exact CanonicalObject")
        _require_digest(self.search_branch_digest, "search_branch_digest")
        if self.schema_version != ATTEMPT_REJECTION_SCHEMA_VERSION:
            raise AttemptReplayError(
                f"attempt rejection schema must be {ATTEMPT_REJECTION_SCHEMA_VERSION}"
            )

    @property
    def owner(self) -> RejectionOwner:
        return self.cause.owner

    def to_json_value(self) -> dict[str, object]:
        return {
            "cause": self.cause.value,
            "constraint_ids": list(self.constraint_ids),
            "detail_code": self.detail_code,
            "normalized_facts": self.normalized_facts.to_json_value(),
            "owner": self.owner.value,
            "schema_version": self.schema_version,
            "search_branch_digest": self.search_branch_digest,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AttemptAccepted:
    attempt_key: AttemptKey
    generation_namespace_digest: str
    attempt_input_commitment_digest: str
    search_branch_digest: str
    choice_ledger_digest: str
    identity_ledger_digest: str
    result: CanonicalObject
    schema_version: str = ATTEMPT_REPLAY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttemptAccepted:
            raise AttemptReplayError("accepted attempts must use the exact contract class")
        _attempt_key_value(self.attempt_key)
        for field_name, value in (
            ("generation_namespace_digest", self.generation_namespace_digest),
            ("attempt_input_commitment_digest", self.attempt_input_commitment_digest),
            ("search_branch_digest", self.search_branch_digest),
            ("choice_ledger_digest", self.choice_ledger_digest),
            ("identity_ledger_digest", self.identity_ledger_digest),
        ):
            _require_digest(value, field_name)
        if type(self.result) is not CanonicalObject:
            raise AttemptReplayError("accepted result must be an exact CanonicalObject")
        if self.schema_version != ATTEMPT_REPLAY_SCHEMA_VERSION:
            raise AttemptReplayError(
                f"attempt replay schema must be {ATTEMPT_REPLAY_SCHEMA_VERSION}"
            )

    @property
    def result_digest(self) -> str:
        return canonical_sha256(self.result.to_json_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_input_commitment_digest": self.attempt_input_commitment_digest,
            "attempt_key": _attempt_key_value(self.attempt_key),
            "choice_ledger_digest": self.choice_ledger_digest,
            "generation_namespace_digest": self.generation_namespace_digest,
            "identity_ledger_digest": self.identity_ledger_digest,
            "result": self.result.to_json_value(),
            "result_digest": self.result_digest,
            "schema_version": self.schema_version,
            "search_branch_digest": self.search_branch_digest,
            "status": "accepted",
        }

    @property
    def completion_digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class AttemptRejected:
    attempt_key: AttemptKey
    generation_namespace_digest: str
    attempt_input_commitment_digest: str
    search_branch_digest: str
    choice_ledger_digest: str
    identity_ledger_digest: str
    rejection: AttemptRejection
    schema_version: str = ATTEMPT_REPLAY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttemptRejected:
            raise AttemptReplayError("rejected attempts must use the exact contract class")
        _attempt_key_value(self.attempt_key)
        for field_name, value in (
            ("generation_namespace_digest", self.generation_namespace_digest),
            ("attempt_input_commitment_digest", self.attempt_input_commitment_digest),
            ("search_branch_digest", self.search_branch_digest),
            ("choice_ledger_digest", self.choice_ledger_digest),
            ("identity_ledger_digest", self.identity_ledger_digest),
        ):
            _require_digest(value, field_name)
        if type(self.rejection) is not AttemptRejection:
            raise AttemptReplayError("rejection must use the exact AttemptRejection class")
        if self.rejection.search_branch_digest != self.search_branch_digest:
            raise AttemptReplayError("rejection and completion branch digests must match")
        if self.schema_version != ATTEMPT_REPLAY_SCHEMA_VERSION:
            raise AttemptReplayError(
                f"attempt replay schema must be {ATTEMPT_REPLAY_SCHEMA_VERSION}"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_input_commitment_digest": self.attempt_input_commitment_digest,
            "attempt_key": _attempt_key_value(self.attempt_key),
            "choice_ledger_digest": self.choice_ledger_digest,
            "generation_namespace_digest": self.generation_namespace_digest,
            "identity_ledger_digest": self.identity_ledger_digest,
            "rejection": self.rejection.to_json_value(),
            "rejection_digest": self.rejection.digest,
            "schema_version": self.schema_version,
            "search_branch_digest": self.search_branch_digest,
            "status": "rejected",
        }

    @property
    def completion_digest(self) -> str:
        return canonical_sha256(self.to_json_value())


AttemptCompletion: TypeAlias = AttemptAccepted | AttemptRejected


@dataclass(frozen=True, slots=True)
class OperationalAttemptBlock:
    attempt_key: AttemptKey
    reason_code: str
    operational_retry_count: int

    def __post_init__(self) -> None:
        if type(self) is not OperationalAttemptBlock:
            raise AttemptReplayError("operational blocks must use the exact contract class")
        _attempt_key_value(self.attempt_key)
        _require_token(self.reason_code, "reason_code")
        if type(self.operational_retry_count) is not int or self.operational_retry_count < 0:
            raise AttemptReplayError(
                "operational_retry_count must be a nonnegative exact integer"
            )


@dataclass(frozen=True, slots=True)
class AcceptedSampleReplay:
    sample_key: SampleKey
    attempt_range: AttemptRange
    rejected_prefix: tuple[AttemptRejected, ...]
    accepted_attempt: AttemptAccepted

    def __post_init__(self) -> None:
        if type(self) is not AcceptedSampleReplay:
            raise AttemptReplayError("accepted replay must use the exact contract class")
        if type(self.sample_key) is not SampleKey:
            raise AttemptReplayError("sample_key must use the exact SampleKey class")
        if type(self.attempt_range) is not AttemptRange:
            raise AttemptReplayError("attempt_range must use the exact AttemptRange class")
        if type(self.rejected_prefix) is not tuple or not all(
            type(item) is AttemptRejected for item in self.rejected_prefix
        ):
            raise AttemptReplayError("rejected_prefix must contain exact rejections")
        if type(self.accepted_attempt) is not AttemptAccepted:
            raise AttemptReplayError("accepted_attempt must use the exact contract class")
        expected = tuple(range(self.accepted_attempt.attempt_key.attempt_index))
        if tuple(item.attempt_key.attempt_index for item in self.rejected_prefix) != expected:
            raise AttemptReplayError("rejected prefix must cover every lower attempt")
        if self.accepted_attempt.attempt_key.sample_key != self.sample_key:
            raise AttemptReplayError("accepted attempt belongs to a different sample")

    def to_json_value(self) -> dict[str, object]:
        return {
            "accepted_attempt_digest": self.accepted_attempt.completion_digest,
            "attempt_range": self.attempt_range.maximum_attempts,
            "rejected_prefix_digests": [
                attempt.completion_digest for attempt in self.rejected_prefix
            ],
            "sample_key": {
                "release": self.sample_key.release,
                "sample_index": self.sample_key.sample_index,
                "target_id": self.sample_key.target_id,
            },
            "status": "accepted",
        }

    @property
    def replay_digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class IncompleteAttemptPrefix:
    sample_key: SampleKey
    attempt_range: AttemptRange
    first_missing_attempt_index: int
    supplied_attempt_indices: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self) is not IncompleteAttemptPrefix:
            raise AttemptReplayError("incomplete prefixes must use the exact contract class")
        if type(self.sample_key) is not SampleKey or type(self.attempt_range) is not AttemptRange:
            raise AttemptReplayError("incomplete prefix context must use exact classes")
        if (
            type(self.first_missing_attempt_index) is not int
            or not self.attempt_range.contains(self.first_missing_attempt_index)
        ):
            raise AttemptReplayError("first missing attempt must be inside the attempt range")
        if type(self.supplied_attempt_indices) is not tuple or any(
            type(index) is not int for index in self.supplied_attempt_indices
        ):
            raise AttemptReplayError("supplied indices must be an immutable integer tuple")


def resolve_attempt_prefix(
    attempt_range: AttemptRange,
    completions: tuple[AttemptCompletion, ...],
) -> AcceptedSampleReplay | IncompleteAttemptPrefix | object:
    """Resolve an exact lowest-valid prefix without ignoring malformed evidence."""

    if type(attempt_range) is not AttemptRange:
        raise AttemptReplayError("attempt_range must use the exact contract class")
    if type(completions) is not tuple or not completions:
        raise AttemptReplayError("attempt completions must be a nonempty immutable tuple")
    if not all(type(item) in {AttemptAccepted, AttemptRejected} for item in completions):
        raise AttemptReplayError("completions must use exact semantic completion classes")

    ordered = tuple(sorted(completions, key=lambda item: item.attempt_key.attempt_index))
    sample_key = ordered[0].attempt_key.sample_key
    namespace_digest = ordered[0].generation_namespace_digest
    indices = tuple(item.attempt_key.attempt_index for item in ordered)
    if len(indices) != len(set(indices)):
        raise AttemptReplayError("attempt completions contain duplicate indices")
    if any(not attempt_range.contains(index) for index in indices):
        raise AttemptReplayError("attempt completion index is outside the declared range")
    if any(item.attempt_key.sample_key != sample_key for item in ordered):
        raise AttemptReplayError("attempt completions span multiple samples")
    if any(item.generation_namespace_digest != namespace_digest for item in ordered):
        raise AttemptReplayError("attempt completions span multiple namespaces")

    accepted_positions = tuple(
        position for position, item in enumerate(ordered) if type(item) is AttemptAccepted
    )
    if len(accepted_positions) > 1:
        raise AttemptReplayError("attempt prefix contains multiple accepted completions")
    if accepted_positions and accepted_positions[0] != len(ordered) - 1:
        raise PostAcceptanceCompletionError(
            "semantic completions after acceptance are prohibited"
        )

    first_missing = next(
        (
            expected
            for expected, actual in enumerate(indices)
            if expected != actual
        ),
        len(indices),
    )
    if first_missing < len(indices) or indices[0] != 0:
        missing = 0 if indices[0] != 0 else first_missing
        return IncompleteAttemptPrefix(
            sample_key=sample_key,
            attempt_range=attempt_range,
            first_missing_attempt_index=missing,
            supplied_attempt_indices=indices,
        )

    if accepted_positions:
        accepted = ordered[-1]
        if type(accepted) is not AttemptAccepted:
            raise AttemptReplayError("accepted position does not contain an accepted attempt")
        rejected = ordered[:-1]
        if not all(type(item) is AttemptRejected for item in rejected):
            raise AttemptReplayError("lower attempt prefix must contain only rejections")
        return AcceptedSampleReplay(
            sample_key=sample_key,
            attempt_range=attempt_range,
            rejected_prefix=tuple(rejected),
            accepted_attempt=accepted,
        )

    if len(ordered) < attempt_range.maximum_attempts:
        return IncompleteAttemptPrefix(
            sample_key=sample_key,
            attempt_range=attempt_range,
            first_missing_attempt_index=len(ordered),
            supplied_attempt_indices=indices,
        )

    from csd_foundry.synthesis.v0_4.exhaustion import ExhaustionEvidence

    rejected_attempts = tuple(ordered)
    if not all(type(item) is AttemptRejected for item in rejected_attempts):
        raise AttemptReplayError("complete exhaustion may contain only rejections")
    return ExhaustionEvidence(
        sample_key=sample_key,
        generation_namespace_digest=namespace_digest,
        attempt_range=attempt_range,
        rejected_attempts=rejected_attempts,
    )
