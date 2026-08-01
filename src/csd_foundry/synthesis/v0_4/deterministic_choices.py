"""Normative HMAC-SHA-256 deterministic choice primitives for CSD Foundry v0.4."""

from __future__ import annotations

import bisect
import hashlib
import hmac
from dataclasses import dataclass
from typing import Generic, Literal, Sequence, TypeVar

from csd_foundry.synthesis.v0_4.choice_paths import (
    MAX_UINT64,
    ChoiceOperation,
    ChoicePath,
    ChoiceValidationError,
    RootSeed,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
)

ALGORITHM_ID = "csd-choice-hmac-sha256-rejection"
ALGORITHM_VERSION = 1
DIGEST_PRIMITIVE = "hmac-sha256"
PATH_SCHEMA_VERSION = "csd-choice-path/0.4"
IDENTITY_SCHEMA_VERSION = "csd-identity/0.4"
COUNTER_ENCODING = "uint64-big-endian"
CANDIDATE_BYTE_ORDER = "big-endian"
_CANDIDATE_BYTEORDER_LITERAL: Literal["big"] = "big"

_PREFIX = b"csd-choice-hmac-sha256-rejection/v1\x00"

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ChoiceAlgorithm:
    algorithm_id: str = ALGORITHM_ID
    algorithm_version: int = ALGORITHM_VERSION
    digest_primitive: str = DIGEST_PRIMITIVE
    path_schema_version: str = PATH_SCHEMA_VERSION
    identity_schema_version: str = IDENTITY_SCHEMA_VERSION
    draw_counter_encoding: str = COUNTER_ENCODING
    block_counter_encoding: str = COUNTER_ENCODING
    candidate_byte_order: str = CANDIDATE_BYTE_ORDER


ALGORITHM = ChoiceAlgorithm()


@dataclass(frozen=True, slots=True)
class CandidateDraw:
    draw_index: int
    candidate_hex: str
    candidate: int
    block_count: int


@dataclass(frozen=True, slots=True)
class BoundedIntegerResult:
    value: int
    draw_index: int
    candidate_hex: str
    candidate: int
    limit: int
    width: int
    block_count: int
    draws: tuple[CandidateDraw, ...]
    domain_digest: str
    material_digest: str


@dataclass(frozen=True, slots=True)
class WeightedChoiceResult(Generic[T]):
    selected_index: int
    selected_value: T
    ticket: BoundedIntegerResult
    cumulative_weights: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class BooleanChoiceResult:
    selected: bool
    ticket: BoundedIntegerResult


def _require_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChoiceValidationError(f"{field_name} must be an integer")


def _uint64(value: int, field_name: str) -> bytes:
    _require_integer(value, field_name)
    if not 0 <= value <= MAX_UINT64:
        raise ChoiceValidationError(f"{field_name} exceeds unsigned 64-bit range")
    return value.to_bytes(8, "big")


def _choice_material(
    path: ChoicePath,
    operation: ChoiceOperation,
    domain_digest: str,
) -> bytes:
    sample = path.attempt_key.sample_key
    return canonical_json_bytes(
        {
            "algorithm_id": ALGORITHM_ID,
            "algorithm_version": ALGORITHM_VERSION,
            "attempt_index": path.attempt_key.attempt_index,
            "domain_digest": domain_digest,
            "namespace": path.namespace,
            "operation": operation.value,
            "path_schema_version": PATH_SCHEMA_VERSION,
            "release": sample.release,
            "sample_index": sample.sample_index,
            "segments": list(path.segments),
            "target_id": sample.target_id,
        }
    )


def canonical_choice_material(
    path: ChoicePath,
    operation: ChoiceOperation,
    domain: object,
) -> bytes:
    """Return the exact canonical material covered by algorithm version 1."""

    return _choice_material(path, operation, canonical_sha256(domain))


def _hmac_block(
    seed: RootSeed,
    material: bytes,
    draw_index: int,
    block_index: int,
) -> bytes:
    message = (
        _PREFIX
        + _uint64(len(material), "material length")
        + material
        + _uint64(draw_index, "draw_index")
        + _uint64(block_index, "block_index")
    )
    return hmac.new(seed.material, message, hashlib.sha256).digest()


def _candidate_bytes(
    seed: RootSeed,
    material: bytes,
    draw_index: int,
    width: int,
) -> tuple[bytes, int]:
    output = bytearray()
    block_index = 0
    while len(output) < width:
        if block_index > MAX_UINT64:
            raise ChoiceValidationError("block counter exhausted")
        output.extend(_hmac_block(seed, material, draw_index, block_index))
        block_index += 1
    return bytes(output[:width]), block_index


def _bounded_integer_for_domain(
    seed: RootSeed,
    path: ChoicePath,
    operation: ChoiceOperation,
    upper_exclusive: int,
    domain: object,
) -> BoundedIntegerResult:
    _require_integer(upper_exclusive, "upper_exclusive")
    if upper_exclusive <= 0:
        raise ChoiceValidationError("upper_exclusive must be positive")

    domain_digest = canonical_sha256(domain)
    material = _choice_material(path, operation, domain_digest)
    width = max(1, ((upper_exclusive - 1).bit_length() + 7) // 8)
    space = 1 << (width * 8)
    limit = space - (space % upper_exclusive)

    draws: list[CandidateDraw] = []
    draw_index = 0
    while draw_index <= MAX_UINT64:
        candidate_bytes, block_count = _candidate_bytes(
            seed,
            material,
            draw_index,
            width,
        )
        candidate = int.from_bytes(candidate_bytes, _CANDIDATE_BYTEORDER_LITERAL)
        draw = CandidateDraw(
            draw_index=draw_index,
            candidate_hex=candidate_bytes.hex(),
            candidate=candidate,
            block_count=block_count,
        )
        draws.append(draw)
        if candidate < limit:
            return BoundedIntegerResult(
                value=candidate % upper_exclusive,
                draw_index=draw_index,
                candidate_hex=draw.candidate_hex,
                candidate=candidate,
                limit=limit,
                width=width,
                block_count=block_count,
                draws=tuple(draws),
                domain_digest=domain_digest,
                material_digest=hashlib.sha256(material).hexdigest(),
            )
        draw_index += 1

    raise ChoiceValidationError("draw counter exhausted")


def bounded_integer(
    seed: RootSeed,
    path: ChoicePath,
    upper_exclusive: int,
) -> BoundedIntegerResult:
    """Select an unbiased integer in ``[0, upper_exclusive)``."""

    return _bounded_integer_for_domain(
        seed,
        path,
        ChoiceOperation.BOUNDED_INTEGER,
        upper_exclusive,
        {"upper_exclusive": upper_exclusive},
    )


def weighted_choice(
    seed: RootSeed,
    path: ChoicePath,
    values: Sequence[T],
    weights: Sequence[int],
) -> WeightedChoiceResult[T]:
    """Select from an explicitly ordered domain using positive integer weights."""

    if not values:
        raise ChoiceValidationError("weighted choice domain must be nonempty")
    if len(values) != len(weights):
        raise ChoiceValidationError("weighted values and weights must have equal length")

    canonical_values = tuple(canonical_json_bytes(value) for value in values)
    if len(canonical_values) != len(set(canonical_values)):
        raise ChoiceValidationError("weighted choice values must be canonically unique")

    cumulative: list[int] = []
    total = 0
    for weight in weights:
        _require_integer(weight, "weight")
        if weight <= 0:
            raise ChoiceValidationError("weights must be positive integers")
        total += weight
        cumulative.append(total)

    ticket = _bounded_integer_for_domain(
        seed,
        path,
        ChoiceOperation.INTEGER_WEIGHTED_INDEX,
        total,
        {"values": list(values), "weights": list(weights)},
    )
    selected_index = bisect.bisect_right(cumulative, ticket.value)
    return WeightedChoiceResult(
        selected_index=selected_index,
        selected_value=values[selected_index],
        ticket=ticket,
        cumulative_weights=tuple(cumulative),
    )


def choose_ratio(
    seed: RootSeed,
    path: ChoicePath,
    numerator: int,
    denominator: int,
) -> BooleanChoiceResult:
    """Choose an exact Boolean ratio without floating-point arithmetic."""

    _require_integer(numerator, "numerator")
    _require_integer(denominator, "denominator")
    if denominator <= 0:
        raise ChoiceValidationError("denominator must be positive")
    if not 0 <= numerator <= denominator:
        raise ChoiceValidationError("numerator must be between zero and denominator")

    ticket = _bounded_integer_for_domain(
        seed,
        path,
        ChoiceOperation.BOOLEAN_RATIO,
        denominator,
        {"numerator": numerator, "denominator": denominator},
    )
    return BooleanChoiceResult(selected=ticket.value < numerator, ticket=ticket)
