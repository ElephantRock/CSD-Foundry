"""Unified immutable generation namespace for v0.4 artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import ChoiceValidationError
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise ChoiceValidationError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise ChoiceValidationError(f"{field_name} must be a lowercase ASCII token")
    return value


def _require_version(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ChoiceValidationError(f"{field_name} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class GenerationNamespace:
    release: str
    choice_algorithm_id: str
    choice_algorithm_version: int
    identity_algorithm_id: str
    identity_algorithm_version: int
    identity_schema_version: str
    target_definition_digest: str
    release_policy_digest: str
    arithmetic_policy_digest: str
    replay_policy_id: str
    replay_policy_version: int
    replay_policy_digest: str
    shard_policy_id: str
    shard_policy_version: int
    shard_policy_digest: str

    def __post_init__(self) -> None:
        if self.release != "v0.4":
            raise ChoiceValidationError("generation namespace release must be v0.4")
        _require_token(self.choice_algorithm_id, "choice_algorithm_id")
        _require_version(self.choice_algorithm_version, "choice_algorithm_version")
        _require_token(self.identity_algorithm_id, "identity_algorithm_id")
        _require_version(self.identity_algorithm_version, "identity_algorithm_version")
        if type(self.identity_schema_version) is not str or self.identity_schema_version != (
            "csd-identity/0.4"
        ):
            raise ChoiceValidationError("identity_schema_version must be csd-identity/0.4")
        _require_digest(self.target_definition_digest, "target_definition_digest")
        _require_digest(self.release_policy_digest, "release_policy_digest")
        _require_digest(self.arithmetic_policy_digest, "arithmetic_policy_digest")
        _require_token(self.replay_policy_id, "replay_policy_id")
        _require_version(self.replay_policy_version, "replay_policy_version")
        _require_digest(self.replay_policy_digest, "replay_policy_digest")
        _require_token(self.shard_policy_id, "shard_policy_id")
        _require_version(self.shard_policy_version, "shard_policy_version")
        _require_digest(self.shard_policy_digest, "shard_policy_digest")

    def to_canonical_object(self) -> CanonicalObject:
        return CanonicalObject.from_pairs(
            (
                ("arithmetic_policy_digest", self.arithmetic_policy_digest),
                ("choice_algorithm_id", self.choice_algorithm_id),
                ("choice_algorithm_version", self.choice_algorithm_version),
                ("identity_algorithm_id", self.identity_algorithm_id),
                ("identity_algorithm_version", self.identity_algorithm_version),
                ("identity_schema_version", self.identity_schema_version),
                ("release", self.release),
                ("release_policy_digest", self.release_policy_digest),
                ("replay_policy_digest", self.replay_policy_digest),
                ("replay_policy_id", self.replay_policy_id),
                ("replay_policy_version", self.replay_policy_version),
                ("shard_policy_digest", self.shard_policy_digest),
                ("shard_policy_id", self.shard_policy_id),
                ("shard_policy_version", self.shard_policy_version),
                ("target_definition_digest", self.target_definition_digest),
            )
        )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_canonical_object().to_json_value())


def build_generation_namespace(target_definition_digest: str) -> GenerationNamespace:
    """Build the exact namespace bound to packaged v0.4 policies."""

    from csd_foundry.synthesis.v0_4.deterministic_choices import (
        ALGORITHM_ID,
        ALGORITHM_VERSION,
    )
    from csd_foundry.synthesis.v0_4.identity_policy import (
        IDENTITY_ALGORITHM_ID,
        IDENTITY_ALGORITHM_VERSION,
        IDENTITY_SCHEMA_VERSION,
        REPLAY_POLICY_ID,
        REPLAY_POLICY_VERSION,
        SHARD_POLICY_ID,
        SHARD_POLICY_VERSION,
    )
    from csd_foundry.synthesis.v0_4.specs import (
        DETERMINISTIC_ARITHMETIC_POLICY_SPEC,
        RELEASE_POLICY_SPEC,
        REPLAY_POLICY_SPEC,
    )

    shard_contract = {
        "policy_id": SHARD_POLICY_ID,
        "policy_version": SHARD_POLICY_VERSION,
        "semantic_assignment": "global-ordinal-modulo-shard-count",
    }
    return GenerationNamespace(
        release="v0.4",
        choice_algorithm_id=ALGORITHM_ID,
        choice_algorithm_version=ALGORITHM_VERSION,
        identity_algorithm_id=IDENTITY_ALGORITHM_ID,
        identity_algorithm_version=IDENTITY_ALGORITHM_VERSION,
        identity_schema_version=IDENTITY_SCHEMA_VERSION,
        target_definition_digest=_require_digest(
            target_definition_digest,
            "target_definition_digest",
        ),
        release_policy_digest=canonical_sha256(RELEASE_POLICY_SPEC),
        arithmetic_policy_digest=canonical_sha256(DETERMINISTIC_ARITHMETIC_POLICY_SPEC),
        replay_policy_id=REPLAY_POLICY_ID,
        replay_policy_version=REPLAY_POLICY_VERSION,
        replay_policy_digest=canonical_sha256(REPLAY_POLICY_SPEC),
        shard_policy_id=SHARD_POLICY_ID,
        shard_policy_version=SHARD_POLICY_VERSION,
        shard_policy_digest=canonical_sha256(shard_contract),
    )
