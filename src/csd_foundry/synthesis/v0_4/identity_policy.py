"""Normative deterministic-identity policy and exact collision assurance."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.choice_paths import ChoiceValidationError

IDENTITY_ALGORITHM_ID = "csd-identity-hmac-sha256"
IDENTITY_ALGORITHM_VERSION = 1
IDENTITY_SCHEMA_VERSION = "csd-identity/0.4"
IDENTITY_DIGEST_PRIMITIVE = "hmac-sha256"
FULL_DIGEST_BITS = 256
DISPLAY_DIGEST_BITS = 128
MAX_ROLE_ORDINAL = (1 << 32) - 1
PROVISIONAL_DESIGN_IDENTITY_CEILING = 10_000_000
COLLISION_RISK_CEILING_NUMERATOR = 15
COLLISION_RISK_CEILING_DENOMINATOR = 100_000_000_000_000_000_000_000_000
REPLAY_POLICY_ID = "csd-replay-contract"
REPLAY_POLICY_VERSION = 1
SHARD_POLICY_ID = "csd-shard-contract"
SHARD_POLICY_VERSION = 1


@dataclass(frozen=True, slots=True)
class RationalBound:
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if type(self) is not RationalBound:
            raise ChoiceValidationError("rational bounds must use the exact contract class")
        if type(self.numerator) is not int or self.numerator < 0:
            raise ChoiceValidationError("rational numerator must be a nonnegative integer")
        if type(self.denominator) is not int or self.denominator <= 0:
            raise ChoiceValidationError("rational denominator must be a positive integer")

    def no_greater_than(self, other: RationalBound) -> bool:
        if type(other) is not RationalBound:
            raise ChoiceValidationError("comparison bound must be an exact RationalBound")
        return self.numerator * other.denominator <= other.numerator * self.denominator


@dataclass(frozen=True, slots=True)
class IdentityKindVolume:
    entity_kind: str
    projected_count: int

    def __post_init__(self) -> None:
        if type(self) is not IdentityKindVolume:
            raise ChoiceValidationError("identity kind volumes must use the exact contract class")
        if type(self.entity_kind) is not str or not self.entity_kind:
            raise ChoiceValidationError("identity volume kind must be a nonempty string")
        if type(self.projected_count) is not int or self.projected_count < 0:
            raise ChoiceValidationError("identity projected count must be nonnegative")


@dataclass(frozen=True, slots=True)
class IdentityVolumeEnvelope:
    per_kind: tuple[IdentityKindVolume, ...]
    safety_margin_numerator: int
    safety_margin_denominator: int
    status: str = "provisional"

    def __post_init__(self) -> None:
        if type(self) is not IdentityVolumeEnvelope:
            raise ChoiceValidationError(
                "identity volume envelopes must use the exact contract class"
            )
        if type(self.per_kind) is not tuple or not self.per_kind:
            raise ChoiceValidationError("identity volume envelope requires immutable per-kind data")
        if not all(type(item) is IdentityKindVolume for item in self.per_kind):
            raise ChoiceValidationError(
                "identity volume entries must be exact IdentityKindVolume values"
            )
        kinds = tuple(item.entity_kind for item in self.per_kind)
        if len(kinds) != len(set(kinds)):
            raise ChoiceValidationError("identity volume kinds must be unique")
        if (
            type(self.safety_margin_numerator) is not int
            or type(self.safety_margin_denominator) is not int
        ):
            raise ChoiceValidationError("identity safety margin must use exact integers")
        if self.safety_margin_denominator <= 0:
            raise ChoiceValidationError("identity safety-margin denominator must be positive")
        if self.safety_margin_numerator < self.safety_margin_denominator:
            raise ChoiceValidationError("identity safety margin cannot reduce projected volume")
        if type(self.status) is not str or self.status != "provisional":
            raise ChoiceValidationError("PR 2A identity volume status must remain provisional")

    @property
    def raw_projected_count(self) -> int:
        return sum(item.projected_count for item in self.per_kind)

    @property
    def projected_count_with_margin(self) -> int:
        numerator = self.raw_projected_count * self.safety_margin_numerator
        return (numerator + self.safety_margin_denominator - 1) // self.safety_margin_denominator


def birthday_collision_bound(identity_count: int, digest_bits: int) -> RationalBound:
    """Return n(n-1)/2^(b+1) using exact integer arithmetic."""

    if type(identity_count) is not int or identity_count < 0:
        raise ChoiceValidationError("identity count must be a nonnegative integer")
    if type(digest_bits) is not int or digest_bits <= 0:
        raise ChoiceValidationError("digest bits must be a positive integer")
    return RationalBound(
        numerator=identity_count * max(0, identity_count - 1),
        denominator=1 << (digest_bits + 1),
    )


def per_kind_collision_bound(
    envelope: IdentityVolumeEnvelope,
    digest_bits: int,
) -> RationalBound:
    """Return the union bound across entity-kind display-prefix domains."""

    if type(envelope) is not IdentityVolumeEnvelope:
        raise ChoiceValidationError("envelope must be an exact IdentityVolumeEnvelope")
    if type(digest_bits) is not int or digest_bits <= 0:
        raise ChoiceValidationError("digest bits must be a positive integer")
    numerator = sum(
        item.projected_count * max(0, item.projected_count - 1) for item in envelope.per_kind
    )
    return RationalBound(numerator=numerator, denominator=1 << (digest_bits + 1))


PROVISIONAL_VOLUME_ENVELOPE = IdentityVolumeEnvelope(
    per_kind=(
        IdentityKindVolume("audit-event", 3_000_000),
        IdentityKindVolume("basis", 1_500_000),
        IdentityKindVolume("control", 100_000),
        IdentityKindVolume("event", 800_000),
        IdentityKindVolume("evidence", 2_500_000),
        IdentityKindVolume("mutation", 900_000),
        IdentityKindVolume("plan", 100_000),
        IdentityKindVolume("profile", 500_000),
        IdentityKindVolume("request", 500_000),
        IdentityKindVolume("trajectory", 100_000),
    ),
    safety_margin_numerator=1,
    safety_margin_denominator=1,
)

COLLISION_RISK_CEILING = RationalBound(
    COLLISION_RISK_CEILING_NUMERATOR,
    COLLISION_RISK_CEILING_DENOMINATOR,
)


def expected_identity_policy_spec() -> dict[str, object]:
    return {
        "release": "v0.4",
        "schema_version": "0.4.0",
        "algorithm_id": IDENTITY_ALGORITHM_ID,
        "algorithm_version": IDENTITY_ALGORITHM_VERSION,
        "identity_schema_version": IDENTITY_SCHEMA_VERSION,
        "digest_primitive": IDENTITY_DIGEST_PRIMITIVE,
        "full_digest_bits": FULL_DIGEST_BITS,
        "display_digest_bits": DISPLAY_DIGEST_BITS,
        "role_ordinal_encoding": "uint32",
        "volume_policy_status": "provisional",
        "design_identity_ceiling": PROVISIONAL_DESIGN_IDENTITY_CEILING,
        "collision_risk_ceiling_numerator": COLLISION_RISK_CEILING_NUMERATOR,
        "collision_risk_ceiling_denominator": COLLISION_RISK_CEILING_DENOMINATOR,
        "replay_policy_id": REPLAY_POLICY_ID,
        "replay_policy_version": REPLAY_POLICY_VERSION,
        "shard_policy_id": SHARD_POLICY_ID,
        "shard_policy_version": SHARD_POLICY_VERSION,
        "per_kind_projected_counts": [
            {
                "entity_kind": item.entity_kind,
                "projected_count": item.projected_count,
            }
            for item in PROVISIONAL_VOLUME_ENVELOPE.per_kind
        ],
    }


def validate_identity_policy_document() -> None:
    from csd_foundry.synthesis.v0_4.specs import IDENTITY_POLICY_SPEC

    if expected_identity_policy_spec() != IDENTITY_POLICY_SPEC:
        raise ChoiceValidationError(
            "packaged identity policy does not match normative algorithm version 1"
        )
