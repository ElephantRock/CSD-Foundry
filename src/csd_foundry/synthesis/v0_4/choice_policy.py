"""Normative algorithm policy for deterministic v0.4 choices."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import cast

from csd_foundry.synthesis.v0_4.choice_paths import (
    MAX_ATTEMPT_INDEX,
    ROOT_SEED_BYTES,
    ChoiceValidationError,
)
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    ALGORITHM_ID,
    ALGORITHM_VERSION,
    CANDIDATE_BYTE_ORDER,
    COUNTER_ENCODING,
    DIGEST_PRIMITIVE,
    IDENTITY_SCHEMA_VERSION,
    PATH_SCHEMA_VERSION,
)
from csd_foundry.synthesis.v0_4.specs import CHOICE_ALGORITHM_SPEC

EXPECTED_SCHEMA_VERSION = "0.4.0"
DISPLAY_DIGEST_BITS = 128
DESIGN_IDENTITY_CEILING = 10_000_000
COLLISION_RISK_CEILING_NUMERATOR = 15
COLLISION_RISK_CEILING_DENOMINATOR = 100_000_000_000_000_000_000_000_000


@dataclass(frozen=True, slots=True)
class ChoiceAlgorithmPolicy:
    release: str
    schema_version: str
    algorithm_id: str
    algorithm_version: int
    digest_primitive: str
    root_seed_bytes: int
    release_seed_encoding: str
    release_seed_provenance: str
    path_schema_version: str
    identity_schema_version: str
    draw_counter_encoding: str
    block_counter_encoding: str
    attempt_index_encoding: str
    maximum_attempt_index: int
    candidate_byte_order: str
    display_digest_bits: int
    design_identity_ceiling: int
    collision_risk_ceiling_numerator: int
    collision_risk_ceiling_denominator: int
    semantic_floating_point_permitted: bool

    def __post_init__(self) -> None:
        expected = {
            "release": "v0.4",
            "schema_version": EXPECTED_SCHEMA_VERSION,
            "algorithm_id": ALGORITHM_ID,
            "algorithm_version": ALGORITHM_VERSION,
            "digest_primitive": DIGEST_PRIMITIVE,
            "root_seed_bytes": ROOT_SEED_BYTES,
            "release_seed_encoding": "lowercase-hex",
            "release_seed_provenance": "uniform-random-256",
            "path_schema_version": PATH_SCHEMA_VERSION,
            "identity_schema_version": IDENTITY_SCHEMA_VERSION,
            "draw_counter_encoding": COUNTER_ENCODING,
            "block_counter_encoding": COUNTER_ENCODING,
            "attempt_index_encoding": "uint32",
            "maximum_attempt_index": MAX_ATTEMPT_INDEX,
            "candidate_byte_order": CANDIDATE_BYTE_ORDER,
            "display_digest_bits": DISPLAY_DIGEST_BITS,
            "design_identity_ceiling": DESIGN_IDENTITY_CEILING,
            "collision_risk_ceiling_numerator": COLLISION_RISK_CEILING_NUMERATOR,
            "collision_risk_ceiling_denominator": COLLISION_RISK_CEILING_DENOMINATOR,
            "semantic_floating_point_permitted": False,
        }
        for field_name, expected_value in expected.items():
            if getattr(self, field_name) != expected_value:
                raise ChoiceValidationError(
                    f"{field_name} must equal the algorithm-v1 normative value {expected_value!r}"
                )
        if self.collision_probability_upper_bound > self.collision_risk_ceiling:
            raise ChoiceValidationError(
                "display identity prefix does not satisfy the declared collision-risk ceiling"
            )

    @property
    def collision_probability_upper_bound(self) -> Fraction:
        count = self.design_identity_ceiling
        return Fraction(count * (count - 1), 1 << (self.display_digest_bits + 1))

    @property
    def collision_risk_ceiling(self) -> Fraction:
        return Fraction(
            self.collision_risk_ceiling_numerator,
            self.collision_risk_ceiling_denominator,
        )


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(type(key) is str for key in value):
        raise ChoiceValidationError("choice algorithm policy must be an object")
    return cast(dict[str, object], value)


def _string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if type(value) is not str:
        raise ChoiceValidationError(f"{key} must be a string")
    return value


def _integer(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if type(value) is not int:
        raise ChoiceValidationError(f"{key} must be an integer")
    return value


def _boolean(data: dict[str, object], key: str) -> bool:
    value = data.get(key)
    if type(value) is not bool:
        raise ChoiceValidationError(f"{key} must be a boolean")
    return value


def load_choice_algorithm_policy() -> ChoiceAlgorithmPolicy:
    data = _mapping(CHOICE_ALGORITHM_SPEC)
    return ChoiceAlgorithmPolicy(
        release=_string(data, "release"),
        schema_version=_string(data, "schema_version"),
        algorithm_id=_string(data, "algorithm_id"),
        algorithm_version=_integer(data, "algorithm_version"),
        digest_primitive=_string(data, "digest_primitive"),
        root_seed_bytes=_integer(data, "root_seed_bytes"),
        release_seed_encoding=_string(data, "release_seed_encoding"),
        release_seed_provenance=_string(data, "release_seed_provenance"),
        path_schema_version=_string(data, "path_schema_version"),
        identity_schema_version=_string(data, "identity_schema_version"),
        draw_counter_encoding=_string(data, "draw_counter_encoding"),
        block_counter_encoding=_string(data, "block_counter_encoding"),
        attempt_index_encoding=_string(data, "attempt_index_encoding"),
        maximum_attempt_index=_integer(data, "maximum_attempt_index"),
        candidate_byte_order=_string(data, "candidate_byte_order"),
        display_digest_bits=_integer(data, "display_digest_bits"),
        design_identity_ceiling=_integer(data, "design_identity_ceiling"),
        collision_risk_ceiling_numerator=_integer(data, "collision_risk_ceiling_numerator"),
        collision_risk_ceiling_denominator=_integer(data, "collision_risk_ceiling_denominator"),
        semantic_floating_point_permitted=_boolean(data, "semantic_floating_point_permitted"),
    )
