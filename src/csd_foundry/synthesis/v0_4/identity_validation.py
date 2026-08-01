"""Validation and immutable evidence for deterministic v0.4 identities."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.canonical_values import (
    CanonicalField,
    CanonicalObject,
    CanonicalValueError,
    canonical_value_bytes,
    validate_canonical_value,
)
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    ChoiceSegment,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.identities import (
    DuplicateIdentityRoleError,
    EntityKind,
    IdentityCollisionError,
    IdentityLedger,
    IdentityRequest,
    UnknownIdentityRoleError,
    _identity_from_digest,
    canonical_identity_material,
    derive_identity,
)
from csd_foundry.synthesis.v0_4.identity_policy import (
    COLLISION_RISK_CEILING,
    DISPLAY_DIGEST_BITS,
    IDENTITY_ALGORITHM_ID,
    IDENTITY_ALGORITHM_VERSION,
    PROVISIONAL_DESIGN_IDENTITY_CEILING,
    PROVISIONAL_VOLUME_ENVELOPE,
    birthday_collision_bound,
    per_kind_collision_bound,
    validate_identity_policy_document,
)
from csd_foundry.synthesis.v0_4.identity_vectors import (
    FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST,
    KNOWN_ANSWER_IDENTITY_SEED_HEX,
    KNOWN_ANSWER_IDENTITY_VECTORS,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


@dataclass(frozen=True, slots=True)
class IdentityValidationReport:
    release: str
    known_answer_vectors: int
    vectors_passed: int
    vector_catalog_digest: str
    canonical_type_separation: bool
    invalid_canonical_values_rejected: int
    allocation_order_stable: bool
    duplicate_role_rejected: bool
    unknown_role_rejected: bool
    full_collision_rejected: bool
    display_collision_rejected: bool
    provisional_identity_count: int
    display_digest_bits: int
    collision_bound_numerator: int
    collision_bound_denominator: int
    per_kind_collision_bound_numerator: int
    per_kind_collision_bound_denominator: int
    collision_policy_satisfied: bool
    volume_policy_status: str
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "algorithm_id": IDENTITY_ALGORITHM_ID,
            "algorithm_version": IDENTITY_ALGORITHM_VERSION,
            "known_answer_vectors": self.known_answer_vectors,
            "vectors_passed": self.vectors_passed,
            "vector_catalog_digest": self.vector_catalog_digest,
            "canonical_type_separation": self.canonical_type_separation,
            "invalid_canonical_values_rejected": self.invalid_canonical_values_rejected,
            "allocation_order_stable": self.allocation_order_stable,
            "duplicate_role_rejected": self.duplicate_role_rejected,
            "unknown_role_rejected": self.unknown_role_rejected,
            "full_collision_rejected": self.full_collision_rejected,
            "display_collision_rejected": self.display_collision_rejected,
            "provisional_identity_count": self.provisional_identity_count,
            "display_digest_bits": self.display_digest_bits,
            "collision_bound_numerator": self.collision_bound_numerator,
            "collision_bound_denominator": self.collision_bound_denominator,
            "per_kind_collision_bound_numerator": self.per_kind_collision_bound_numerator,
            "per_kind_collision_bound_denominator": self.per_kind_collision_bound_denominator,
            "collision_policy_satisfied": self.collision_policy_satisfied,
            "volume_policy_status": self.volume_policy_status,
            "errors": list(self.errors),
            "release_scale_claimed": False,
            "claim_boundary": (
                "This report validates canonical digest payloads, generation namespaces, "
                "deterministic concrete identities, and provisional collision assurance. It "
                "does not establish attempt replay, shard merging, planner completeness, "
                "state construction, structural identity, or release-scale output."
            ),
        }


def _vector_catalog() -> dict[str, object]:
    return {
        "release": "v0.4",
        "schema_version": "0.4.0",
        "algorithm_id": IDENTITY_ALGORITHM_ID,
        "algorithm_version": IDENTITY_ALGORITHM_VERSION,
        "vectors": list(KNOWN_ANSWER_IDENTITY_VECTORS),
    }


def _exact_int(data: dict[str, object], key: str) -> int:
    value = data[key]
    if type(value) is not int:
        raise ValueError(f"identity vector {key} must be an exact integer")
    return value


def _exact_str(data: dict[str, object], key: str) -> str:
    value = data[key]
    if type(value) is not str:
        raise ValueError(f"identity vector {key} must be an exact string")
    return value


def _role_segments(data: dict[str, object]) -> tuple[ChoiceSegment, ...]:
    value = data["role_segments"]
    if not isinstance(value, list):
        raise ValueError("identity vector role_segments must be an array")
    segments: list[ChoiceSegment] = []
    for segment in value:
        if type(segment) is int or type(segment) is str:
            segments.append(segment)
        else:
            raise ValueError("identity vector role segment has an invalid type")
    return tuple(segments)


def _request_from_vector(data: dict[str, object]) -> IdentityRequest:
    sample_key = SampleKey(
        release="v0.4",
        target_id=_exact_str(data, "target_id"),
        sample_index=_exact_int(data, "sample_index"),
    )
    return IdentityRequest(
        attempt_key=AttemptKey(sample_key, _exact_int(data, "attempt_index")),
        entity_kind=EntityKind(_exact_str(data, "entity_kind")),
        role_segments=_role_segments(data),
        ordinal=_exact_int(data, "ordinal"),
    )


def _canonical_assurance() -> tuple[bool, int]:
    values = (
        canonical_value_bytes(1),
        canonical_value_bytes("1"),
        canonical_value_bytes(True),
    )
    separated = len(set(values)) == 3
    invalid_values: tuple[object, ...] = (
        1.5,
        [],
        {},
        set(),
        b"bytes",
        bytearray(b"mutable"),
    )
    rejected = 0
    for value in invalid_values:
        try:
            validate_canonical_value(value)
        except CanonicalValueError:
            rejected += 1
    try:
        CanonicalObject(
            (
                CanonicalField("duplicate", 1),
                CanonicalField("duplicate", 2),
            )
        )
    except CanonicalValueError:
        rejected += 1
    try:
        CanonicalObject(
            (
                CanonicalField("z", 1),
                CanonicalField("a", 2),
            )
        )
    except CanonicalValueError:
        rejected += 1
    return separated, rejected


def _synthetic_identity(
    namespace_digest_source: object,
    request: IdentityRequest,
    digest: bytes,
) -> object:
    del namespace_digest_source
    namespace = build_generation_namespace(
        _exact_str(KNOWN_ANSWER_IDENTITY_VECTORS[0], "target_definition_digest")
    )
    return _identity_from_digest(
        namespace,
        request,
        canonical_identity_material(namespace, request),
        digest,
    )


def _ledger_assurance(seed: RootSeed) -> tuple[bool, bool, bool, bool, bool]:
    target_digest = _exact_str(KNOWN_ANSWER_IDENTITY_VECTORS[0], "target_definition_digest")
    namespace = build_generation_namespace(target_digest)
    requests = tuple(_request_from_vector(vector) for vector in KNOWN_ANSWER_IDENTITY_VECTORS[:3])
    forward = IdentityLedger(seed, namespace)
    reverse = IdentityLedger(seed, namespace)
    for request in requests:
        forward.allocate(request)
    for request in reversed(requests):
        reverse.allocate(request)
    allocation_order_stable = forward.canonical_digest == reverse.canonical_digest

    duplicate_role_rejected = False
    try:
        forward.allocate(requests[0])
    except DuplicateIdentityRoleError:
        duplicate_role_rejected = True

    unknown_role_rejected = False
    unknown = IdentityRequest(
        requests[0].attempt_key,
        requests[0].entity_kind,
        ("unknown",),
        999,
    )
    try:
        forward.resolve(unknown)
    except UnknownIdentityRoleError:
        unknown_role_rejected = True

    collision_a = IdentityRequest(requests[0].attempt_key, EntityKind.EVIDENCE, ("a",), 0)
    collision_b = IdentityRequest(requests[0].attempt_key, EntityKind.EVIDENCE, ("b",), 0)

    full_ledger = IdentityLedger(seed, namespace)
    full_ledger._record_identity(
        collision_a,
        _identity_from_digest(
            namespace,
            collision_a,
            canonical_identity_material(namespace, collision_a),
            b"\x11" * 32,
        ),
    )
    full_collision_rejected = False
    try:
        full_ledger._record_identity(
            collision_b,
            _identity_from_digest(
                namespace,
                collision_b,
                canonical_identity_material(namespace, collision_b),
                b"\x11" * 32,
            ),
        )
    except IdentityCollisionError:
        full_collision_rejected = True

    display_ledger = IdentityLedger(seed, namespace)
    display_ledger._record_identity(
        collision_a,
        _identity_from_digest(
            namespace,
            collision_a,
            canonical_identity_material(namespace, collision_a),
            b"\xaa" * 16 + b"\x22" * 16,
        ),
    )
    display_collision_rejected = False
    try:
        display_ledger._record_identity(
            collision_b,
            _identity_from_digest(
                namespace,
                collision_b,
                canonical_identity_material(namespace, collision_b),
                b"\xaa" * 16 + b"\x33" * 16,
            ),
        )
    except IdentityCollisionError:
        display_collision_rejected = True

    return (
        allocation_order_stable,
        duplicate_role_rejected,
        unknown_role_rejected,
        full_collision_rejected,
        display_collision_rejected,
    )


def validate_identities(release: str = "v0.4") -> IdentityValidationReport:
    errors: list[str] = []
    vectors_passed = 0
    canonical_type_separation = False
    invalid_rejected = 0
    allocation_order_stable = False
    duplicate_role_rejected = False
    unknown_role_rejected = False
    full_collision_rejected = False
    display_collision_rejected = False

    catalog_digest = canonical_sha256(_vector_catalog())
    global_bound = birthday_collision_bound(
        PROVISIONAL_DESIGN_IDENTITY_CEILING,
        DISPLAY_DIGEST_BITS,
    )
    kind_bound = per_kind_collision_bound(
        PROVISIONAL_VOLUME_ENVELOPE,
        DISPLAY_DIGEST_BITS,
    )
    policy_satisfied = global_bound.no_greater_than(COLLISION_RISK_CEILING)

    if release != "v0.4":
        errors.append(f"unsupported deterministic identity release: {release}")
    else:
        try:
            validate_identity_policy_document()
            if catalog_digest != FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST:
                raise ValueError("identity vector catalog differs from frozen version-1 digest")
            seed = RootSeed.from_hex(
                KNOWN_ANSWER_IDENTITY_SEED_HEX,
                SeedProvenance.KNOWN_ANSWER_FIXTURE,
            )
            for vector in KNOWN_ANSWER_IDENTITY_VECTORS:
                namespace = build_generation_namespace(
                    _exact_str(vector, "target_definition_digest")
                )
                actual = derive_identity(seed, namespace, _request_from_vector(vector))
                expected = vector["expected"]
                if not isinstance(expected, dict) or actual.to_json_value() != expected:
                    raise ValueError(f"identity vector failed: {_exact_str(vector, 'vector_id')}")
                vectors_passed += 1
            canonical_type_separation, invalid_rejected = _canonical_assurance()
            (
                allocation_order_stable,
                duplicate_role_rejected,
                unknown_role_rejected,
                full_collision_rejected,
                display_collision_rejected,
            ) = _ledger_assurance(seed)
        except ValueError as exc:
            errors.append(str(exc))

    if not canonical_type_separation:
        errors.append("canonical integer, string, and Boolean values are not separated")
    if invalid_rejected != 8:
        errors.append("canonical-value rejection campaign did not kill every invalid input")
    if not allocation_order_stable:
        errors.append("identity ledger digest depends on allocation order")
    if not duplicate_role_rejected:
        errors.append("duplicate semantic identity allocation was accepted")
    if not unknown_role_rejected:
        errors.append("unknown identity role resolution was accepted")
    if not full_collision_rejected:
        errors.append("injected full identity collision was accepted")
    if not display_collision_rejected:
        errors.append("injected display identity collision was accepted")
    if not policy_satisfied:
        errors.append("128-bit display identity exceeds the exact collision-risk ceiling")
    if PROVISIONAL_VOLUME_ENVELOPE.raw_projected_count != PROVISIONAL_DESIGN_IDENTITY_CEILING:
        errors.append("provisional per-kind identity counts do not match the design envelope")

    return IdentityValidationReport(
        release=release,
        known_answer_vectors=len(KNOWN_ANSWER_IDENTITY_VECTORS),
        vectors_passed=vectors_passed,
        vector_catalog_digest=catalog_digest,
        canonical_type_separation=canonical_type_separation,
        invalid_canonical_values_rejected=invalid_rejected,
        allocation_order_stable=allocation_order_stable,
        duplicate_role_rejected=duplicate_role_rejected,
        unknown_role_rejected=unknown_role_rejected,
        full_collision_rejected=full_collision_rejected,
        display_collision_rejected=display_collision_rejected,
        provisional_identity_count=PROVISIONAL_VOLUME_ENVELOPE.raw_projected_count,
        display_digest_bits=DISPLAY_DIGEST_BITS,
        collision_bound_numerator=global_bound.numerator,
        collision_bound_denominator=global_bound.denominator,
        per_kind_collision_bound_numerator=kind_bound.numerator,
        per_kind_collision_bound_denominator=kind_bound.denominator,
        collision_policy_satisfied=policy_satisfied,
        volume_policy_status=PROVISIONAL_VOLUME_ENVELOPE.status,
        errors=tuple(dict.fromkeys(errors)),
    )
