from __future__ import annotations

from dataclasses import fields

import pytest

from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    ChoiceValidationError,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.generation_namespace import (
    GenerationNamespace,
    build_generation_namespace,
)
from csd_foundry.synthesis.v0_4.identities import (
    EntityIdentity,
    EntityKind,
    IdentityError,
    IdentityRecord,
    IdentityRequest,
    canonical_identity_material,
    derive_identity,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


class IdentityRequestSubclass(IdentityRequest):
    __slots__ = ()


class AttemptKeySubclass(AttemptKey):
    __slots__ = ()


class SampleKeySubclass(SampleKey):
    __slots__ = ()


class RootSeedSubclass(RootSeed):
    __slots__ = ()


class GenerationNamespaceSubclass(GenerationNamespace):
    __slots__ = ()


class EntityIdentitySubclass(EntityIdentity):
    __slots__ = ()


class IdentityRecordSubclass(IdentityRecord):
    __slots__ = ()


def _seed() -> RootSeed:
    return RootSeed.from_text("identity-exact-types", SeedProvenance.KNOWN_ANSWER_FIXTURE)


def _namespace() -> GenerationNamespace:
    return build_generation_namespace(canonical_sha256({"target": "exact-types"}))


def _request() -> IdentityRequest:
    return IdentityRequest(
        AttemptKey(SampleKey("v0.4", "exact-types", 0), 0),
        EntityKind.EVIDENCE,
        ("primary",),
        0,
    )


def test_identity_request_subclasses_are_rejected_at_construction_and_use() -> None:
    attempt = AttemptKey(SampleKey("v0.4", "exact-types", 0), 0)
    with pytest.raises(ChoiceValidationError):
        IdentityRequestSubclass(
            attempt,
            EntityKind.EVIDENCE,
            ("primary",),
            0,
        )

    bypassed = object.__new__(IdentityRequestSubclass)
    object.__setattr__(bypassed, "attempt_key", attempt)
    object.__setattr__(bypassed, "entity_kind", EntityKind.EVIDENCE)
    object.__setattr__(bypassed, "role_segments", ("primary",))
    object.__setattr__(bypassed, "ordinal", 0)
    with pytest.raises(ChoiceValidationError):
        canonical_identity_material(_namespace(), bypassed)


def test_nested_attempt_and_sample_subclasses_are_rejected() -> None:
    sample = SampleKey("v0.4", "exact-types", 0)
    subclass_attempt = AttemptKeySubclass(sample, 0)
    with pytest.raises(ChoiceValidationError):
        IdentityRequest(
            subclass_attempt,
            EntityKind.EVIDENCE,
            ("primary",),
            0,
        )

    subclass_sample = SampleKeySubclass("v0.4", "exact-types", 0)
    attempt = AttemptKey(subclass_sample, 0)
    with pytest.raises(ChoiceValidationError):
        IdentityRequest(
            attempt,
            EntityKind.EVIDENCE,
            ("primary",),
            0,
        )


def test_seed_and_namespace_subclasses_cannot_enter_derivation() -> None:
    seed = _seed()
    subclass_seed = RootSeedSubclass(seed.material, seed.provenance)
    with pytest.raises(ChoiceValidationError):
        derive_identity(subclass_seed, _namespace(), _request())

    namespace = _namespace()
    values = tuple(getattr(namespace, field.name) for field in fields(GenerationNamespace))
    subclass_namespace = GenerationNamespaceSubclass(*values)
    with pytest.raises(ChoiceValidationError):
        derive_identity(_seed(), subclass_namespace, _request())


def test_identity_and_record_subclasses_are_rejected() -> None:
    identity = derive_identity(_seed(), _namespace(), _request())
    with pytest.raises(IdentityError):
        EntityIdentitySubclass(
            identity.entity_kind,
            identity.full_digest,
            identity.display_id,
            identity.material_digest,
            identity.generation_namespace_digest,
        )
    with pytest.raises(IdentityError):
        IdentityRecordSubclass(_request(), identity)
