"""Bounded single-producer choice sessions and immutable attempt ledgers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalArray, CanonicalValue
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    ChoicePath,
    RootSeed,
    SampleKey,
)
from csd_foundry.synthesis.v0_4.choice_records import (
    BooleanRatioChoiceRecord,
    BoundedIntegerChoiceRecord,
    ChoiceRecord,
    ChoiceRecordError,
    WeightedChoiceRecord,
    choice_record_bytes,
    record_from_boolean_result,
    record_from_bounded_result,
    record_from_weighted_result,
)
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    bounded_integer,
    choose_ratio,
    weighted_choice,
)
from csd_foundry.synthesis.v0_4.generation_namespace import GenerationNamespace
from csd_foundry.synthesis.v0_4.replay_policy import ChoiceBudget, ChoiceBudgetExceeded
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

CHOICE_LEDGER_SCHEMA_VERSION = "csd-choice-ledger/0.4"
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ChoiceSessionError(RuntimeError):
    """Raised when a choice session cannot continue or freeze."""


class DuplicateChoicePathError(ChoiceSessionError):
    """Raised when one semantic path is used more than once in an attempt."""


class ChoiceSessionState(StrEnum):
    OPEN = "open"
    FROZEN = "frozen"
    POISONED = "poisoned"


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise ChoiceSessionError(f"{field_name} must be a lowercase ASCII token")
    return value


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise ChoiceRecordError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _path_bytes(path: ChoicePath) -> bytes:
    if type(path) is not ChoicePath:
        raise ChoiceSessionError("choice paths must use the exact ChoicePath class")
    if type(path.attempt_key) is not AttemptKey:
        raise ChoiceSessionError("choice path attempt_key must use the exact AttemptKey class")
    if type(path.attempt_key.sample_key) is not SampleKey:
        raise ChoiceSessionError("choice path sample_key must use the exact SampleKey class")
    return canonical_json_bytes(path.to_json_value())


def _record_type_valid(record: object) -> bool:
    return type(record) in {
        BoundedIntegerChoiceRecord,
        WeightedChoiceRecord,
        BooleanRatioChoiceRecord,
    }


def _ledger_value(
    *,
    schema_version: str,
    seed_commitment: str,
    generation_namespace_digest: str,
    attempt_key: AttemptKey,
    producer_contract_id: str,
    allowed_namespace_prefix: str,
    records: tuple[ChoiceRecord, ...],
) -> dict[str, object]:
    sample = attempt_key.sample_key
    return {
        "allowed_namespace_prefix": allowed_namespace_prefix,
        "attempt_key": {
            "attempt_index": attempt_key.attempt_index,
            "release": sample.release,
            "sample_index": sample.sample_index,
            "target_id": sample.target_id,
        },
        "generation_namespace_digest": generation_namespace_digest,
        "producer_contract_id": producer_contract_id,
        "records": [record.to_json_value() for record in records],
        "schema_version": schema_version,
        "seed_commitment": seed_commitment,
    }


@dataclass(frozen=True, slots=True)
class ChoiceLedger:
    seed_commitment: str
    generation_namespace_digest: str
    attempt_key: AttemptKey
    producer_contract_id: str
    allowed_namespace_prefix: str
    records: tuple[ChoiceRecord, ...]
    schema_version: str = CHOICE_LEDGER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ChoiceLedger:
            raise ChoiceRecordError("choice ledgers must use the exact contract class")
        _require_digest(self.seed_commitment, "seed_commitment")
        _require_digest(
            self.generation_namespace_digest,
            "generation_namespace_digest",
        )
        if type(self.attempt_key) is not AttemptKey:
            raise ChoiceRecordError("attempt_key must use the exact AttemptKey class")
        if type(self.attempt_key.sample_key) is not SampleKey:
            raise ChoiceRecordError("sample_key must use the exact SampleKey class")
        _require_token(self.producer_contract_id, "producer_contract_id")
        _require_token(self.allowed_namespace_prefix, "allowed_namespace_prefix")
        if type(self.records) is not tuple:
            raise ChoiceRecordError("choice ledger records must be an immutable tuple")
        if not all(_record_type_valid(record) for record in self.records):
            raise ChoiceRecordError("choice ledger records must use exact record variants")
        expected_order = tuple(sorted(self.records, key=lambda record: _path_bytes(record.path)))
        if self.records != expected_order:
            raise ChoiceRecordError("choice ledger records must use canonical path order")
        seen: set[bytes] = set()
        for record in self.records:
            path_bytes = _path_bytes(record.path)
            if path_bytes in seen:
                raise ChoiceRecordError("choice ledger contains a duplicate path")
            seen.add(path_bytes)
            if record.path.attempt_key != self.attempt_key:
                raise ChoiceRecordError("choice record belongs to a different attempt")
            if record.seed_commitment != self.seed_commitment:
                raise ChoiceRecordError("choice record has a different seed commitment")
            if record.generation_namespace_digest != self.generation_namespace_digest:
                raise ChoiceRecordError("choice record has a different generation namespace")
            namespace = record.path.namespace
            if namespace != self.allowed_namespace_prefix and not namespace.startswith(
                self.allowed_namespace_prefix + "."
            ):
                raise ChoiceRecordError("choice record uses an undeclared namespace prefix")
        if self.schema_version != CHOICE_LEDGER_SCHEMA_VERSION:
            raise ChoiceRecordError(f"choice ledger schema must be {CHOICE_LEDGER_SCHEMA_VERSION}")

    def to_json_value(self) -> dict[str, object]:
        return _ledger_value(
            schema_version=self.schema_version,
            seed_commitment=self.seed_commitment,
            generation_namespace_digest=self.generation_namespace_digest,
            attempt_key=self.attempt_key,
            producer_contract_id=self.producer_contract_id,
            allowed_namespace_prefix=self.allowed_namespace_prefix,
            records=self.records,
        )

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def canonical_digest(self) -> str:
        return canonical_sha256(self.to_json_value())


class ChoiceSession:
    """One bounded, fail-closed choice producer for one deterministic attempt."""

    def __init__(
        self,
        *,
        seed: RootSeed,
        generation_namespace: GenerationNamespace,
        attempt_key: AttemptKey,
        producer_contract_id: str,
        allowed_namespace_prefix: str,
        budget: ChoiceBudget,
    ) -> None:
        if type(seed) is not RootSeed:
            raise ChoiceSessionError("choice session seed must be an exact RootSeed")
        if type(generation_namespace) is not GenerationNamespace:
            raise ChoiceSessionError(
                "choice session namespace must be an exact GenerationNamespace"
            )
        if type(attempt_key) is not AttemptKey:
            raise ChoiceSessionError("choice session attempt_key must be exact")
        if type(attempt_key.sample_key) is not SampleKey:
            raise ChoiceSessionError("choice session sample_key must be exact")
        if type(budget) is not ChoiceBudget:
            raise ChoiceSessionError("choice session budget must be exact")
        self._seed = seed
        self._generation_namespace = generation_namespace
        self._attempt_key = attempt_key
        self._producer_contract_id = _require_token(
            producer_contract_id,
            "producer_contract_id",
        )
        self._allowed_namespace_prefix = _require_token(
            allowed_namespace_prefix,
            "allowed_namespace_prefix",
        )
        self._budget = budget
        self._state = ChoiceSessionState.OPEN
        self._reserved_paths: set[bytes] = set()
        self._records: list[ChoiceRecord] = []

    @property
    def state(self) -> ChoiceSessionState:
        return self._state

    @property
    def attempt_key(self) -> AttemptKey:
        return self._attempt_key

    @property
    def choice_count(self) -> int:
        return len(self._records)

    def _require_open_path(self, path: ChoicePath) -> bytes:
        if self._state is not ChoiceSessionState.OPEN:
            raise ChoiceSessionError(f"choice session is {self._state.value}")
        path_bytes = _path_bytes(path)
        if path.attempt_key != self._attempt_key:
            raise ChoiceSessionError("choice path belongs to a different attempt")
        if path.namespace != self._allowed_namespace_prefix and not path.namespace.startswith(
            self._allowed_namespace_prefix + "."
        ):
            raise ChoiceSessionError("choice path uses an undeclared namespace prefix")
        if path_bytes in self._reserved_paths:
            raise DuplicateChoicePathError("choice path has already been reserved")
        return path_bytes

    def _reserve(self, path: ChoicePath) -> None:
        self._reserved_paths.add(self._require_open_path(path))

    def _ledger_bytes_for(self, records: tuple[ChoiceRecord, ...]) -> int:
        ordered = tuple(sorted(records, key=lambda item: _path_bytes(item.path)))
        value = _ledger_value(
            schema_version=CHOICE_LEDGER_SCHEMA_VERSION,
            seed_commitment=self._seed.commitment,
            generation_namespace_digest=self._generation_namespace.digest,
            attempt_key=self._attempt_key,
            producer_contract_id=self._producer_contract_id,
            allowed_namespace_prefix=self._allowed_namespace_prefix,
            records=ordered,
        )
        return len(canonical_json_bytes(value))

    def _preflight_choice_count(self) -> None:
        choice_count = len(self._records) + 1
        if choice_count > self._budget.maximum_choices_per_attempt:
            raise ChoiceBudgetExceeded(
                choice_count=choice_count,
                maximum_choices=self._budget.maximum_choices_per_attempt,
                canonical_bytes=self._ledger_bytes_for(tuple(self._records)),
                maximum_canonical_bytes=self._budget.maximum_canonical_ledger_bytes,
            )

    def _commit(self, record: ChoiceRecord) -> None:
        records = (*self._records, record)
        canonical_bytes = self._ledger_bytes_for(records)
        if canonical_bytes > self._budget.maximum_canonical_ledger_bytes:
            raise ChoiceBudgetExceeded(
                choice_count=len(records),
                maximum_choices=self._budget.maximum_choices_per_attempt,
                canonical_bytes=canonical_bytes,
                maximum_canonical_bytes=self._budget.maximum_canonical_ledger_bytes,
            )
        self._records.append(record)

    def _poison_if_open(self) -> None:
        if self._state is ChoiceSessionState.OPEN:
            self._state = ChoiceSessionState.POISONED

    def bounded_integer(self, path: ChoicePath, upper_exclusive: int) -> int:
        try:
            self._reserve(path)
            self._preflight_choice_count()
            result = bounded_integer(self._seed, path, upper_exclusive)
            record = record_from_bounded_result(
                path=path,
                generation_namespace_digest=self._generation_namespace.digest,
                seed_commitment=self._seed.commitment,
                upper_exclusive=upper_exclusive,
                result=result,
            )
            self._commit(record)
            return record.evidence.value
        except Exception:
            self._poison_if_open()
            raise

    def weighted_choice(
        self,
        path: ChoicePath,
        values: CanonicalArray,
        weights: tuple[int, ...],
    ) -> CanonicalValue:
        try:
            self._reserve(path)
            self._preflight_choice_count()
            if type(values) is not CanonicalArray:
                raise ChoiceRecordError("weighted values must be an exact CanonicalArray")
            if type(weights) is not tuple:
                raise ChoiceRecordError("weighted weights must be an immutable tuple")
            primitive_values = values.to_json_value()
            result = weighted_choice(self._seed, path, primitive_values, weights)
            record = record_from_weighted_result(
                path=path,
                generation_namespace_digest=self._generation_namespace.digest,
                seed_commitment=self._seed.commitment,
                values=values,
                weights=weights,
                result=result,
            )
            self._commit(record)
            return record.selected_value
        except Exception:
            self._poison_if_open()
            raise

    def choose_ratio(
        self,
        path: ChoicePath,
        numerator: int,
        denominator: int,
    ) -> bool:
        try:
            self._reserve(path)
            self._preflight_choice_count()
            result = choose_ratio(self._seed, path, numerator, denominator)
            record = record_from_boolean_result(
                path=path,
                generation_namespace_digest=self._generation_namespace.digest,
                seed_commitment=self._seed.commitment,
                numerator=numerator,
                denominator=denominator,
                result=result,
            )
            self._commit(record)
            return record.selected
        except Exception:
            self._poison_if_open()
            raise

    def freeze(self) -> ChoiceLedger:
        if self._state is not ChoiceSessionState.OPEN:
            raise ChoiceSessionError(f"cannot freeze a {self._state.value} choice session")
        try:
            records = tuple(sorted(self._records, key=lambda record: _path_bytes(record.path)))
            ledger = ChoiceLedger(
                seed_commitment=self._seed.commitment,
                generation_namespace_digest=self._generation_namespace.digest,
                attempt_key=self._attempt_key,
                producer_contract_id=self._producer_contract_id,
                allowed_namespace_prefix=self._allowed_namespace_prefix,
                records=records,
            )
            canonical_bytes = len(ledger.canonical_bytes)
            if canonical_bytes > self._budget.maximum_canonical_ledger_bytes:
                raise ChoiceBudgetExceeded(
                    choice_count=len(records),
                    maximum_choices=self._budget.maximum_choices_per_attempt,
                    canonical_bytes=canonical_bytes,
                    maximum_canonical_bytes=self._budget.maximum_canonical_ledger_bytes,
                )
            self._state = ChoiceSessionState.FROZEN
            return ledger
        except Exception:
            self._poison_if_open()
            raise

    def diagnostic_record_bytes(self) -> tuple[bytes, ...]:
        """Return immutable diagnostic bytes only while the session remains open."""

        if self._state is not ChoiceSessionState.OPEN:
            raise ChoiceSessionError("diagnostic records are available only on an open session")
        return tuple(choice_record_bytes(record) for record in self._records)
