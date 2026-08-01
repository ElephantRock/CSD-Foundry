"""Typed path, seed, and attempt contracts for deterministic v0.4 choices."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

MAX_ATTEMPT_INDEX = (1 << 32) - 1
MAX_UINT64 = (1 << 64) - 1
ROOT_SEED_BYTES = 32

_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ChoiceValidationError(ValueError):
    """Raised when deterministic-choice input violates the v0.4 contract."""


class AttemptBudgetExhausted(RuntimeError):
    """Raised when no valid attempt exists inside the declared deterministic range."""


class SeedProvenance(StrEnum):
    UNIFORM_RANDOM_256 = "uniform-random-256"
    DEVELOPER_TEXT = "developer-text"
    KNOWN_ANSWER_FIXTURE = "known-answer-fixture"


class ChoiceOperation(StrEnum):
    BOUNDED_INTEGER = "bounded_integer"
    INTEGER_WEIGHTED_INDEX = "integer_weighted_index"
    BOOLEAN_RATIO = "boolean_ratio"


ChoiceSegment: TypeAlias = str | int


def _require_token(value: str, field_name: str) -> None:
    if _TOKEN_PATTERN.fullmatch(value) is None:
        raise ChoiceValidationError(
            f"{field_name} must match [a-z0-9][a-z0-9._-]* using ASCII lowercase tokens"
        )


def _require_nonnegative_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ChoiceValidationError(f"{field_name} must be a nonnegative integer")
    return value


@dataclass(frozen=True, slots=True)
class RootSeed:
    material: bytes
    provenance: SeedProvenance

    def __post_init__(self) -> None:
        if len(self.material) != ROOT_SEED_BYTES:
            raise ChoiceValidationError("root seed must contain exactly 32 bytes")
        if (
            self.provenance is SeedProvenance.UNIFORM_RANDOM_256
            and (self.material == bytes(ROOT_SEED_BYTES) or len(set(self.material)) == 1)
        ):
            raise ChoiceValidationError(
                "release seed cannot use all-zero or repeated-byte fixture material"
            )

    @classmethod
    def from_hex(cls, value: str, provenance: SeedProvenance) -> RootSeed:
        if _HEX_256_PATTERN.fullmatch(value) is None:
            raise ChoiceValidationError(
                "hex root seed must be exactly 64 lowercase hexadecimal characters"
            )
        return cls(bytes.fromhex(value), provenance)

    @classmethod
    def from_text(cls, value: str, provenance: SeedProvenance) -> RootSeed:
        if provenance is SeedProvenance.UNIFORM_RANDOM_256:
            raise ChoiceValidationError("release seed provenance cannot be derived from text")
        if not value:
            raise ChoiceValidationError("text seed must be nonempty")
        material = hashlib.sha256(
            b"csd-root-seed-text/v1\x00" + value.encode("utf-8")
        ).digest()
        return cls(material, provenance)

    @property
    def release_eligible(self) -> bool:
        return self.provenance is SeedProvenance.UNIFORM_RANDOM_256

    @property
    def commitment(self) -> str:
        return hashlib.sha256(
            b"csd-root-seed-commitment/v1\x00" + self.material
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class SampleKey:
    release: str
    target_id: str
    sample_index: int

    def __post_init__(self) -> None:
        if self.release != "v0.4":
            raise ChoiceValidationError("sample release must be v0.4")
        _require_token(self.target_id, "target_id")
        _require_nonnegative_integer(self.sample_index, "sample_index")


@dataclass(frozen=True, slots=True)
class AttemptKey:
    sample_key: SampleKey
    attempt_index: int

    def __post_init__(self) -> None:
        attempt_index = _require_nonnegative_integer(self.attempt_index, "attempt_index")
        if attempt_index > MAX_ATTEMPT_INDEX:
            raise ChoiceValidationError(
                f"attempt_index must be between 0 and {MAX_ATTEMPT_INDEX}"
            )


@dataclass(frozen=True, slots=True)
class AttemptRange:
    maximum_attempts: int

    def __post_init__(self) -> None:
        maximum_attempts = _require_nonnegative_integer(
            self.maximum_attempts, "maximum_attempts"
        )
        if not 1 <= maximum_attempts <= MAX_ATTEMPT_INDEX + 1:
            raise ChoiceValidationError(
                f"maximum_attempts must be between 1 and {MAX_ATTEMPT_INDEX + 1}"
            )

    def contains(self, attempt_index: int) -> bool:
        return type(attempt_index) is int and 0 <= attempt_index < self.maximum_attempts

    def indices(self) -> range:
        return range(self.maximum_attempts)


@dataclass(frozen=True, slots=True)
class ChoicePath:
    attempt_key: AttemptKey
    namespace: str
    segments: tuple[ChoiceSegment, ...]

    def __post_init__(self) -> None:
        _require_token(self.namespace, "namespace")
        if not self.segments:
            raise ChoiceValidationError("choice path requires at least one segment")
        for segment in self.segments:
            if type(segment) is int:
                if segment < 0:
                    raise ChoiceValidationError(
                        "integer choice-path segments must be nonnegative"
                    )
            elif isinstance(segment, str):
                _require_token(segment, "choice path string segment")
            else:
                raise ChoiceValidationError(
                    "choice-path segments must be exact integers or ASCII token strings"
                )

    def to_json_value(self) -> dict[str, object]:
        sample = self.attempt_key.sample_key
        return {
            "release": sample.release,
            "target_id": sample.target_id,
            "sample_index": sample.sample_index,
            "attempt_index": self.attempt_key.attempt_index,
            "namespace": self.namespace,
            "segments": list(self.segments),
        }
