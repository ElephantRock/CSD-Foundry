"""Operation-specific immutable records for deterministic v0.4 choices."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeAlias

from csd_foundry.synthesis.v0_4.canonical_values import (
    CanonicalArray,
    CanonicalValue,
    canonical_to_json_value,
    canonical_value_bytes,
    validate_canonical_value,
)
from csd_foundry.synthesis.v0_4.choice_paths import ChoiceOperation, ChoicePath
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    BooleanChoiceResult,
    BoundedIntegerResult,
    WeightedChoiceResult,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

CHOICE_RECORD_SCHEMA_VERSION = "csd-choice-record/0.4"
_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_BYTES_PATTERN = re.compile(r"^(?:[0-9a-f]{2})+$")


class ChoiceRecordError(ValueError):
    """Raised when a deterministic choice record is malformed."""


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise ChoiceRecordError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_nonnegative_int(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ChoiceRecordError(f"{field_name} must be a nonnegative exact integer")
    return value


def _path_value(path: ChoicePath) -> dict[str, object]:
    if type(path) is not ChoicePath:
        raise ChoiceRecordError("choice record path must use the exact ChoicePath class")
    return path.to_json_value()


@dataclass(frozen=True, slots=True)
class CandidateDrawRecord:
    draw_index: int
    candidate_hex: str
    block_count: int

    def __post_init__(self) -> None:
        if type(self) is not CandidateDrawRecord:
            raise ChoiceRecordError("draw records must use the exact contract class")
        _require_nonnegative_int(self.draw_index, "draw_index")
        if (
            type(self.candidate_hex) is not str
            or _HEX_BYTES_PATTERN.fullmatch(self.candidate_hex) is None
        ):
            raise ChoiceRecordError("candidate_hex must be nonempty lowercase hexadecimal bytes")
        if type(self.block_count) is not int or self.block_count <= 0:
            raise ChoiceRecordError("block_count must be a positive exact integer")

    def to_json_value(self) -> dict[str, object]:
        return {
            "block_count": self.block_count,
            "candidate_hex": self.candidate_hex,
            "draw_index": self.draw_index,
        }


@dataclass(frozen=True, slots=True)
class BoundedIntegerEvidence:
    value: int
    draw_index: int
    candidate_hex: str
    candidate: int
    limit: int
    width: int
    block_count: int
    draws: tuple[CandidateDrawRecord, ...]
    domain_digest: str
    material_digest: str

    def __post_init__(self) -> None:
        if type(self) is not BoundedIntegerEvidence:
            raise ChoiceRecordError("bounded evidence must use the exact contract class")
        for name, value in (
            ("value", self.value),
            ("draw_index", self.draw_index),
            ("candidate", self.candidate),
            ("limit", self.limit),
            ("width", self.width),
            ("block_count", self.block_count),
        ):
            _require_nonnegative_int(value, name)
        if self.width <= 0 or self.block_count <= 0:
            raise ChoiceRecordError("width and block_count must be positive")
        if type(self.candidate_hex) is not str or len(self.candidate_hex) != self.width * 2:
            raise ChoiceRecordError("candidate_hex length must equal the declared width")
        if _HEX_BYTES_PATTERN.fullmatch(self.candidate_hex) is None:
            raise ChoiceRecordError("candidate_hex must be lowercase hexadecimal")
        if type(self.draws) is not tuple or not self.draws:
            raise ChoiceRecordError("bounded evidence requires an immutable draw tuple")
        if not all(type(draw) is CandidateDrawRecord for draw in self.draws):
            raise ChoiceRecordError("draws must contain exact CandidateDrawRecord values")
        expected_indices = tuple(range(len(self.draws)))
        if tuple(draw.draw_index for draw in self.draws) != expected_indices:
            raise ChoiceRecordError("draw indices must be contiguous from zero")
        final = self.draws[-1]
        if self.draw_index != final.draw_index:
            raise ChoiceRecordError("draw_index must identify the final accepted draw")
        if self.candidate_hex != final.candidate_hex or self.block_count != final.block_count:
            raise ChoiceRecordError("accepted draw metadata must match the final draw")
        if self.candidate != int(self.candidate_hex, 16):
            raise ChoiceRecordError("candidate integer must match candidate_hex")
        if any(int(draw.candidate_hex, 16) < self.limit for draw in self.draws[:-1]):
            raise ChoiceRecordError("every nonfinal draw must be rejected")
        if self.candidate >= self.limit:
            raise ChoiceRecordError("the final draw must be inside the acceptance region")
        _require_digest(self.domain_digest, "domain_digest")
        _require_digest(self.material_digest, "material_digest")

    @classmethod
    def from_result(cls, result: BoundedIntegerResult) -> BoundedIntegerEvidence:
        if type(result) is not BoundedIntegerResult:
            raise ChoiceRecordError("bounded results must use the exact primitive result class")
        return cls(
            value=result.value,
            draw_index=result.draw_index,
            candidate_hex=result.candidate_hex,
            candidate=result.candidate,
            limit=result.limit,
            width=result.width,
            block_count=result.block_count,
            draws=tuple(
                CandidateDrawRecord(
                    draw_index=draw.draw_index,
                    candidate_hex=draw.candidate_hex,
                    block_count=draw.block_count,
                )
                for draw in result.draws
            ),
            domain_digest=result.domain_digest,
            material_digest=result.material_digest,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "block_count": self.block_count,
            "candidate": self.candidate,
            "candidate_hex": self.candidate_hex,
            "domain_digest": self.domain_digest,
            "draw_index": self.draw_index,
            "draws": [draw.to_json_value() for draw in self.draws],
            "limit": self.limit,
            "material_digest": self.material_digest,
            "value": self.value,
            "width": self.width,
        }


@dataclass(frozen=True, slots=True)
class BoundedIntegerChoiceRecord:
    path: ChoicePath
    generation_namespace_digest: str
    seed_commitment: str
    upper_exclusive: int
    evidence: BoundedIntegerEvidence
    schema_version: str = CHOICE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not BoundedIntegerChoiceRecord:
            raise ChoiceRecordError("bounded choice records must use the exact contract class")
        _path_value(self.path)
        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")
        _require_digest(self.seed_commitment, "seed_commitment")
        if type(self.upper_exclusive) is not int or self.upper_exclusive <= 0:
            raise ChoiceRecordError("upper_exclusive must be a positive exact integer")
        if type(self.evidence) is not BoundedIntegerEvidence:
            raise ChoiceRecordError("evidence must be exact BoundedIntegerEvidence")
        if not 0 <= self.evidence.value < self.upper_exclusive:
            raise ChoiceRecordError("selected value is outside the declared bound")
        if self.evidence.value != self.evidence.candidate % self.upper_exclusive:
            raise ChoiceRecordError("selected value must derive from the accepted candidate")
        if self.schema_version != CHOICE_RECORD_SCHEMA_VERSION:
            raise ChoiceRecordError(f"choice record schema must be {CHOICE_RECORD_SCHEMA_VERSION}")

    @property
    def operation(self) -> ChoiceOperation:
        return ChoiceOperation.BOUNDED_INTEGER

    def to_json_value(self) -> dict[str, object]:
        return {
            "evidence": self.evidence.to_json_value(),
            "generation_namespace_digest": self.generation_namespace_digest,
            "operation": self.operation.value,
            "path": _path_value(self.path),
            "schema_version": self.schema_version,
            "seed_commitment": self.seed_commitment,
            "upper_exclusive": self.upper_exclusive,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class WeightedChoiceRecord:
    path: ChoicePath
    generation_namespace_digest: str
    seed_commitment: str
    values: CanonicalArray
    weights: tuple[int, ...]
    selected_index: int
    ticket: BoundedIntegerEvidence
    schema_version: str = CHOICE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not WeightedChoiceRecord:
            raise ChoiceRecordError("weighted choice records must use the exact contract class")
        _path_value(self.path)
        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")
        _require_digest(self.seed_commitment, "seed_commitment")
        if type(self.values) is not CanonicalArray or not self.values.values:
            raise ChoiceRecordError("values must be a nonempty exact CanonicalArray")
        if type(self.weights) is not tuple or len(self.weights) != len(self.values.values):
            raise ChoiceRecordError("weights must be an equal-length immutable tuple")
        if any(type(weight) is not int or weight <= 0 for weight in self.weights):
            raise ChoiceRecordError("weights must be positive exact integers")
        encoded = tuple(canonical_value_bytes(value) for value in self.values.values)
        if len(encoded) != len(set(encoded)):
            raise ChoiceRecordError("weighted values must be canonically unique")
        if type(self.selected_index) is not int or not 0 <= self.selected_index < len(self.weights):
            raise ChoiceRecordError("selected_index is outside the weighted domain")
        if type(self.ticket) is not BoundedIntegerEvidence:
            raise ChoiceRecordError("ticket must be exact BoundedIntegerEvidence")
        if self.ticket.value >= sum(self.weights):
            raise ChoiceRecordError("weighted ticket is outside total weight")
        cumulative = 0
        expected_index = 0
        for index, weight in enumerate(self.weights):
            cumulative += weight
            if self.ticket.value < cumulative:
                expected_index = index
                break
        if self.selected_index != expected_index:
            raise ChoiceRecordError("selected_index does not match the weighted ticket")
        if self.schema_version != CHOICE_RECORD_SCHEMA_VERSION:
            raise ChoiceRecordError(f"choice record schema must be {CHOICE_RECORD_SCHEMA_VERSION}")

    @property
    def operation(self) -> ChoiceOperation:
        return ChoiceOperation.INTEGER_WEIGHTED_INDEX

    @property
    def selected_value(self) -> CanonicalValue:
        return self.values.values[self.selected_index]

    def to_json_value(self) -> dict[str, object]:
        return {
            "generation_namespace_digest": self.generation_namespace_digest,
            "operation": self.operation.value,
            "path": _path_value(self.path),
            "schema_version": self.schema_version,
            "seed_commitment": self.seed_commitment,
            "selected_index": self.selected_index,
            "selected_value": canonical_to_json_value(self.selected_value),
            "ticket": self.ticket.to_json_value(),
            "values": self.values.to_json_value(),
            "weights": list(self.weights),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class BooleanRatioChoiceRecord:
    path: ChoicePath
    generation_namespace_digest: str
    seed_commitment: str
    numerator: int
    denominator: int
    selected: bool
    ticket: BoundedIntegerEvidence
    schema_version: str = CHOICE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not BooleanRatioChoiceRecord:
            raise ChoiceRecordError("Boolean ratio records must use the exact contract class")
        _path_value(self.path)
        _require_digest(self.generation_namespace_digest, "generation_namespace_digest")
        _require_digest(self.seed_commitment, "seed_commitment")
        if type(self.numerator) is not int or type(self.denominator) is not int:
            raise ChoiceRecordError("ratio operands must be exact integers")
        if self.denominator <= 0 or not 0 <= self.numerator <= self.denominator:
            raise ChoiceRecordError("ratio must satisfy 0 <= numerator <= denominator")
        if type(self.selected) is not bool:
            raise ChoiceRecordError("selected must be an exact Boolean")
        if type(self.ticket) is not BoundedIntegerEvidence:
            raise ChoiceRecordError("ticket must be exact BoundedIntegerEvidence")
        if self.ticket.value >= self.denominator:
            raise ChoiceRecordError("ratio ticket is outside its denominator")
        if self.selected is not (self.ticket.value < self.numerator):
            raise ChoiceRecordError("selected Boolean does not match the ratio ticket")
        if self.schema_version != CHOICE_RECORD_SCHEMA_VERSION:
            raise ChoiceRecordError(f"choice record schema must be {CHOICE_RECORD_SCHEMA_VERSION}")

    @property
    def operation(self) -> ChoiceOperation:
        return ChoiceOperation.BOOLEAN_RATIO

    def to_json_value(self) -> dict[str, object]:
        return {
            "denominator": self.denominator,
            "generation_namespace_digest": self.generation_namespace_digest,
            "numerator": self.numerator,
            "operation": self.operation.value,
            "path": _path_value(self.path),
            "schema_version": self.schema_version,
            "seed_commitment": self.seed_commitment,
            "selected": self.selected,
            "ticket": self.ticket.to_json_value(),
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


ChoiceRecord: TypeAlias = (
    BoundedIntegerChoiceRecord | WeightedChoiceRecord | BooleanRatioChoiceRecord
)


def choice_record_bytes(record: ChoiceRecord) -> bytes:
    if type(record) not in {
        BoundedIntegerChoiceRecord,
        WeightedChoiceRecord,
        BooleanRatioChoiceRecord,
    }:
        raise ChoiceRecordError("choice records must use an exact operation-specific class")
    return canonical_json_bytes(record.to_json_value())


def record_from_bounded_result(
    *,
    path: ChoicePath,
    generation_namespace_digest: str,
    seed_commitment: str,
    upper_exclusive: int,
    result: BoundedIntegerResult,
) -> BoundedIntegerChoiceRecord:
    return BoundedIntegerChoiceRecord(
        path=path,
        generation_namespace_digest=generation_namespace_digest,
        seed_commitment=seed_commitment,
        upper_exclusive=upper_exclusive,
        evidence=BoundedIntegerEvidence.from_result(result),
    )


def record_from_weighted_result(
    *,
    path: ChoicePath,
    generation_namespace_digest: str,
    seed_commitment: str,
    values: CanonicalArray,
    weights: tuple[int, ...],
    result: WeightedChoiceResult[object],
) -> WeightedChoiceRecord:
    if type(result) is not WeightedChoiceResult:
        raise ChoiceRecordError("weighted results must use the exact primitive result class")
    validate_canonical_value(values.values[result.selected_index])
    return WeightedChoiceRecord(
        path=path,
        generation_namespace_digest=generation_namespace_digest,
        seed_commitment=seed_commitment,
        values=values,
        weights=weights,
        selected_index=result.selected_index,
        ticket=BoundedIntegerEvidence.from_result(result.ticket),
    )


def record_from_boolean_result(
    *,
    path: ChoicePath,
    generation_namespace_digest: str,
    seed_commitment: str,
    numerator: int,
    denominator: int,
    result: BooleanChoiceResult,
) -> BooleanRatioChoiceRecord:
    if type(result) is not BooleanChoiceResult:
        raise ChoiceRecordError("Boolean results must use the exact primitive result class")
    return BooleanRatioChoiceRecord(
        path=path,
        generation_namespace_digest=generation_namespace_digest,
        seed_commitment=seed_commitment,
        numerator=numerator,
        denominator=denominator,
        selected=result.selected,
        ticket=BoundedIntegerEvidence.from_result(result.ticket),
    )
