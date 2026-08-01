"""Compact deterministic search-exhaustion evidence and planner handoff."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.attempts import AttemptRejected, AttemptReplayError
from csd_foundry.synthesis.v0_4.canonical_values import (
    CanonicalArray,
    CanonicalObject,
)
from csd_foundry.synthesis.v0_4.choice_paths import AttemptRange, SampleKey
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

EXHAUSTION_SCHEMA_VERSION = "csd-exhaustion-evidence/0.4"


def _counter_object(counter: Counter[str]) -> CanonicalObject:
    return CanonicalObject.from_pairs(
        tuple((key, counter[key]) for key in sorted(counter, key=lambda item: item.encode("utf-8")))
    )


@dataclass(frozen=True, slots=True)
class PlannerExhaustionHandoff:
    exhaustion_digest: str
    rejection_causes: CanonicalObject
    rejection_owners: CanonicalObject
    detail_codes: CanonicalObject
    candidate_constraint_ids: tuple[str, ...]
    normalized_rejection_facts: CanonicalArray

    def __post_init__(self) -> None:
        if type(self) is not PlannerExhaustionHandoff:
            raise AttemptReplayError("planner handoffs must use the exact contract class")
        if type(self.exhaustion_digest) is not str or len(self.exhaustion_digest) != 64:
            raise AttemptReplayError("exhaustion_digest must be a lowercase SHA-256 digest")
        if not all(
            type(value) is CanonicalObject
            for value in (self.rejection_causes, self.rejection_owners, self.detail_codes)
        ):
            raise AttemptReplayError("planner handoff histograms must be canonical objects")
        if type(self.candidate_constraint_ids) is not tuple:
            raise AttemptReplayError("candidate constraint IDs must be an immutable tuple")
        expected = tuple(
            sorted(self.candidate_constraint_ids, key=lambda item: item.encode("utf-8"))
        )
        if self.candidate_constraint_ids != expected or len(expected) != len(set(expected)):
            raise AttemptReplayError("candidate constraint IDs must be unique and ordered")
        if type(self.normalized_rejection_facts) is not CanonicalArray:
            raise AttemptReplayError(
                "normalized rejection facts must use an exact CanonicalArray"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "candidate_constraint_ids": list(self.candidate_constraint_ids),
            "detail_codes": self.detail_codes.to_json_value(),
            "exhaustion_digest": self.exhaustion_digest,
            "normalized_rejection_facts": self.normalized_rejection_facts.to_json_value(),
            "rejection_causes": self.rejection_causes.to_json_value(),
            "rejection_owners": self.rejection_owners.to_json_value(),
        }


@dataclass(frozen=True, slots=True)
class ExhaustionEvidence:
    sample_key: SampleKey
    generation_namespace_digest: str
    attempt_range: AttemptRange
    rejected_attempts: tuple[AttemptRejected, ...]
    schema_version: str = EXHAUSTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ExhaustionEvidence:
            raise AttemptReplayError("exhaustion evidence must use the exact contract class")
        if type(self.sample_key) is not SampleKey:
            raise AttemptReplayError("sample_key must use the exact SampleKey class")
        if type(self.generation_namespace_digest) is not str or len(
            self.generation_namespace_digest
        ) != 64:
            raise AttemptReplayError(
                "generation_namespace_digest must be a lowercase SHA-256 digest"
            )
        if type(self.attempt_range) is not AttemptRange:
            raise AttemptReplayError("attempt_range must use the exact AttemptRange class")
        if type(self.rejected_attempts) is not tuple or not all(
            type(item) is AttemptRejected for item in self.rejected_attempts
        ):
            raise AttemptReplayError("rejected_attempts must contain exact rejections")
        if len(self.rejected_attempts) != self.attempt_range.maximum_attempts:
            raise AttemptReplayError("exhaustion must cover the complete attempt range")
        expected_indices = tuple(range(self.attempt_range.maximum_attempts))
        actual_indices = tuple(
            item.attempt_key.attempt_index for item in self.rejected_attempts
        )
        if actual_indices != expected_indices:
            raise AttemptReplayError("exhaustion attempts must be contiguous from zero")
        for item in self.rejected_attempts:
            if item.attempt_key.sample_key != self.sample_key:
                raise AttemptReplayError("exhaustion evidence spans multiple samples")
            if item.generation_namespace_digest != self.generation_namespace_digest:
                raise AttemptReplayError("exhaustion evidence spans multiple namespaces")
        if self.schema_version != EXHAUSTION_SCHEMA_VERSION:
            raise AttemptReplayError(
                f"exhaustion schema must be {EXHAUSTION_SCHEMA_VERSION}"
            )

    @property
    def cause_histogram(self) -> CanonicalObject:
        return _counter_object(
            Counter(item.rejection.cause.value for item in self.rejected_attempts)
        )

    @property
    def owner_histogram(self) -> CanonicalObject:
        return _counter_object(
            Counter(item.rejection.owner.value for item in self.rejected_attempts)
        )

    @property
    def detail_code_histogram(self) -> CanonicalObject:
        return _counter_object(
            Counter(item.rejection.detail_code for item in self.rejected_attempts)
        )

    @property
    def constraint_frequency(self) -> CanonicalObject:
        return _counter_object(
            Counter(
                constraint_id
                for item in self.rejected_attempts
                for constraint_id in item.rejection.constraint_ids
            )
        )

    @property
    def candidate_constraint_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    constraint_id
                    for item in self.rejected_attempts
                    for constraint_id in item.rejection.constraint_ids
                },
                key=lambda item: item.encode("utf-8"),
            )
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_range": self.attempt_range.maximum_attempts,
            "cause_histogram": self.cause_histogram.to_json_value(),
            "choice_ledger_digest_aggregate": canonical_sha256(
                [item.choice_ledger_digest for item in self.rejected_attempts]
            ),
            "constraint_frequency": self.constraint_frequency.to_json_value(),
            "detail_code_histogram": self.detail_code_histogram.to_json_value(),
            "generation_namespace_digest": self.generation_namespace_digest,
            "identity_ledger_digest_aggregate": canonical_sha256(
                [item.identity_ledger_digest for item in self.rejected_attempts]
            ),
            "owner_histogram": self.owner_histogram.to_json_value(),
            "rejected_attempt_digests": [
                item.completion_digest for item in self.rejected_attempts
            ],
            "sample_key": {
                "release": self.sample_key.release,
                "sample_index": self.sample_key.sample_index,
                "target_id": self.sample_key.target_id,
            },
            "schema_version": self.schema_version,
            "status": "exhausted",
        }

    @property
    def exhaustion_digest(self) -> str:
        return canonical_sha256(self.to_json_value())

    def planner_handoff(self) -> PlannerExhaustionHandoff:
        return PlannerExhaustionHandoff(
            exhaustion_digest=self.exhaustion_digest,
            rejection_causes=self.cause_histogram,
            rejection_owners=self.owner_histogram,
            detail_codes=self.detail_code_histogram,
            candidate_constraint_ids=self.candidate_constraint_ids,
            normalized_rejection_facts=CanonicalArray(
                tuple(item.rejection.normalized_facts for item in self.rejected_attempts)
            ),
        )
