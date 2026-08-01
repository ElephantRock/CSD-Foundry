"""Deterministic concrete entity identities for CSD Foundry v0.4."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    ChoiceSegment,
    ChoiceValidationError,
    RootSeed,
    SampleKey,
)
from csd_foundry.synthesis.v0_4.generation_namespace import GenerationNamespace
from csd_foundry.synthesis.v0_4.identity_policy import (
    DISPLAY_DIGEST_BITS,
    FULL_DIGEST_BITS,
    IDENTITY_ALGORITHM_ID,
    IDENTITY_ALGORITHM_VERSION,
    MAX_ROLE_ORDINAL,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

_PREFIX = b"csd-identity-hmac-sha256/v1\x00"
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IdentityError(ValueError):
    """Base class for deterministic identity failures."""


class DuplicateIdentityRoleError(IdentityError):
    """Raised when one semantic identity role is allocated twice."""


class UnknownIdentityRoleError(IdentityError):
    """Raised when resolving a semantic role that has not been allocated."""


class IdentityCollisionError(IdentityError):
    """Raised when distinct semantic roles collide on a full or display digest."""


class EntityKind(StrEnum):
    TRAJECTORY = "trajectory"
    PLAN = "plan"
    CONTROL = "control"
    EVIDENCE = "evidence"
    BASIS = "basis"
    REQUEST = "request"
    PROFILE = "profile"
    EVENT = "event"
    AUDIT_EVENT = "audit-event"
    MUTATION = "mutation"


_DISPLAY_PREFIXES: dict[EntityKind, str] = {
    EntityKind.TRAJECTORY: "trj-v04",
    EntityKind.PLAN: "pln-v04",
    EntityKind.CONTROL: "ctl-v04",
    EntityKind.EVIDENCE: "evd-v04",
    EntityKind.BASIS: "bas-v04",
    EntityKind.REQUEST: "req-v04",
    EntityKind.PROFILE: "prf-v04",
    EntityKind.EVENT: "evt-v04",
    EntityKind.AUDIT_EVENT: "aud-v04",
    EntityKind.MUTATION: "mut-v04",
}

RoleSegment: TypeAlias = ChoiceSegment


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise IdentityError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_role_segment(value: object) -> RoleSegment:
    if type(value) is int:
        if value < 0:
            raise ChoiceValidationError("integer identity-role segments must be nonnegative")
        return value
    if type(value) is str and _TOKEN_PATTERN.fullmatch(value) is not None:
        return value
    raise ChoiceValidationError(
        "identity-role segments must be exact nonnegative integers or lowercase ASCII tokens"
    )


@dataclass(frozen=True, slots=True)
class IdentityRequest:
    attempt_key: AttemptKey
    entity_kind: EntityKind
    role_segments: tuple[RoleSegment, ...]
    ordinal: int

    def __post_init__(self) -> None:
        if type(self) is not IdentityRequest:
            raise ChoiceValidationError("identity requests must use the exact contract class")
        if type(self.attempt_key) is not AttemptKey:
            raise ChoiceValidationError("identity attempt_key must be an exact AttemptKey")
        if type(self.attempt_key.sample_key) is not SampleKey:
            raise ChoiceValidationError("identity sample_key must be an exact SampleKey")
        if type(self.entity_kind) is not EntityKind:
            raise ChoiceValidationError("identity entity_kind must be an exact EntityKind")
        if type(self.role_segments) is not tuple or not self.role_segments:
            raise ChoiceValidationError("identity role_segments require a nonempty tuple")
        for segment in self.role_segments:
            _require_role_segment(segment)
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= MAX_ROLE_ORDINAL:
            raise ChoiceValidationError(
                f"identity ordinal must be an unsigned 32-bit integer up to {MAX_ROLE_ORDINAL}"
            )

    def to_json_value(self) -> dict[str, object]:
        sample = self.attempt_key.sample_key
        return {
            "attempt_index": self.attempt_key.attempt_index,
            "entity_kind": self.entity_kind.value,
            "ordinal": self.ordinal,
            "release": sample.release,
            "role_segments": list(self.role_segments),
            "sample_index": sample.sample_index,
            "target_id": sample.target_id,
        }


@dataclass(frozen=True, slots=True)
class EntityIdentity:
    entity_kind: EntityKind
    full_digest: str
    display_id: str
    material_digest: str
    generation_namespace_digest: str

    def __post_init__(self) -> None:
        if type(self) is not EntityIdentity:
            raise IdentityError("entity identities must use the exact contract class")
        if type(self.entity_kind) is not EntityKind:
            raise IdentityError("entity identity kind must be an exact EntityKind")
        full_digest = _require_digest(self.full_digest, "identity full_digest")
        _require_digest(self.material_digest, "identity material_digest")
        _require_digest(
            self.generation_namespace_digest,
            "identity generation_namespace_digest",
        )
        display_hex_length = DISPLAY_DIGEST_BITS // 4
        expected_display = (
            f"{_DISPLAY_PREFIXES[self.entity_kind]}-{full_digest[:display_hex_length]}"
        )
        if type(self.display_id) is not str or self.display_id != expected_display:
            raise IdentityError("display identity must match its kind and full-digest prefix")

    def to_json_value(self) -> dict[str, object]:
        return {
            "display_id": self.display_id,
            "entity_kind": self.entity_kind.value,
            "full_digest": self.full_digest,
            "generation_namespace_digest": self.generation_namespace_digest,
            "material_digest": self.material_digest,
        }


@dataclass(frozen=True, slots=True)
class IdentityRecord:
    request: IdentityRequest
    identity: EntityIdentity

    def __post_init__(self) -> None:
        if type(self) is not IdentityRecord:
            raise IdentityError("identity records must use the exact contract class")
        if type(self.request) is not IdentityRequest:
            raise IdentityError("identity record request must be an exact IdentityRequest")
        if type(self.identity) is not EntityIdentity:
            raise IdentityError("identity record identity must be an exact EntityIdentity")
        if self.request.entity_kind is not self.identity.entity_kind:
            raise IdentityError("identity record request and identity kinds must match")

    def to_json_value(self) -> dict[str, object]:
        return {
            "identity": self.identity.to_json_value(),
            "request": self.request.to_json_value(),
        }


def canonical_identity_material(
    namespace: GenerationNamespace,
    request: IdentityRequest,
) -> bytes:
    if type(namespace) is not GenerationNamespace:
        raise ChoiceValidationError("identity namespace must be an exact GenerationNamespace")
    if type(request) is not IdentityRequest:
        raise ChoiceValidationError("identity request must be an exact IdentityRequest")
    return canonical_json_bytes(
        {
            "algorithm_id": IDENTITY_ALGORITHM_ID,
            "algorithm_version": IDENTITY_ALGORITHM_VERSION,
            "generation_namespace": namespace.to_canonical_object().to_json_value(),
            "request": request.to_json_value(),
        }
    )


def _identity_digest(seed: RootSeed, material: bytes) -> bytes:
    if type(seed) is not RootSeed:
        raise ChoiceValidationError("identity seed must be an exact RootSeed")
    if type(material) is not bytes:
        raise IdentityError("identity material must be immutable bytes")
    message = _PREFIX + len(material).to_bytes(8, "big") + material
    return hmac.new(seed.material, message, hashlib.sha256).digest()


def _identity_from_digest(
    namespace: GenerationNamespace,
    request: IdentityRequest,
    material: bytes,
    digest: bytes,
) -> EntityIdentity:
    if type(namespace) is not GenerationNamespace:
        raise ChoiceValidationError("identity namespace must be an exact GenerationNamespace")
    if type(request) is not IdentityRequest:
        raise ChoiceValidationError("identity request must be an exact IdentityRequest")
    if type(material) is not bytes:
        raise IdentityError("identity material must be immutable bytes")
    if type(digest) is not bytes or len(digest) * 8 != FULL_DIGEST_BITS:
        raise IdentityError("identity digest must contain exactly 256 immutable bits")
    full_digest = digest.hex()
    display_hex_length = DISPLAY_DIGEST_BITS // 4
    display_id = f"{_DISPLAY_PREFIXES[request.entity_kind]}-{full_digest[:display_hex_length]}"
    return EntityIdentity(
        entity_kind=request.entity_kind,
        full_digest=full_digest,
        display_id=display_id,
        material_digest=hashlib.sha256(material).hexdigest(),
        generation_namespace_digest=namespace.digest,
    )


def derive_identity(
    seed: RootSeed,
    namespace: GenerationNamespace,
    request: IdentityRequest,
) -> EntityIdentity:
    """Derive one identity using the sole normative identity algorithm."""

    if type(seed) is not RootSeed:
        raise ChoiceValidationError("identity seed must be an exact RootSeed")
    material = canonical_identity_material(namespace, request)
    return _identity_from_digest(
        namespace,
        request,
        material,
        _identity_digest(seed, material),
    )


class IdentityLedger:
    """Fail-closed allocation ledger with order-independent commitments."""

    def __init__(self, seed: RootSeed, namespace: GenerationNamespace) -> None:
        if type(seed) is not RootSeed:
            raise ChoiceValidationError("identity ledger seed must be an exact RootSeed")
        if type(namespace) is not GenerationNamespace:
            raise ChoiceValidationError(
                "identity ledger namespace must be an exact GenerationNamespace"
            )
        self._seed = seed
        self._namespace = namespace
        self._records: dict[str, IdentityRecord] = {}
        self._full_digests: dict[str, str] = {}
        self._display_ids: dict[str, str] = {}

    def _request_key(self, request: IdentityRequest) -> str:
        if type(request) is not IdentityRequest:
            raise ChoiceValidationError("identity ledger request must be an exact IdentityRequest")
        return canonical_sha256(request.to_json_value())

    def _record_identity(
        self,
        request: IdentityRequest,
        identity: EntityIdentity,
    ) -> EntityIdentity:
        if type(identity) is not EntityIdentity:
            raise IdentityError("identity ledger requires an exact EntityIdentity")
        request_key = self._request_key(request)
        if request_key in self._records:
            raise DuplicateIdentityRoleError("semantic identity role has already been allocated")
        if identity.generation_namespace_digest != self._namespace.digest:
            raise IdentityError("identity belongs to a different generation namespace")
        full_owner = self._full_digests.get(identity.full_digest)
        if full_owner is not None and full_owner != request_key:
            raise IdentityCollisionError("distinct identity roles share a full digest")
        display_owner = self._display_ids.get(identity.display_id)
        if display_owner is not None and display_owner != request_key:
            raise IdentityCollisionError("distinct identity roles share a display identifier")
        self._records[request_key] = IdentityRecord(request=request, identity=identity)
        self._full_digests[identity.full_digest] = request_key
        self._display_ids[identity.display_id] = request_key
        return identity

    def allocate(self, request: IdentityRequest) -> EntityIdentity:
        return self._record_identity(
            request,
            derive_identity(self._seed, self._namespace, request),
        )

    def resolve(self, request: IdentityRequest) -> EntityIdentity:
        request_key = self._request_key(request)
        record = self._records.get(request_key)
        if record is None:
            raise UnknownIdentityRoleError("semantic identity role has not been allocated")
        return record.identity

    def records(self) -> tuple[IdentityRecord, ...]:
        return tuple(
            sorted(
                self._records.values(),
                key=lambda record: canonical_json_bytes(record.request.to_json_value()),
            )
        )

    @property
    def canonical_digest(self) -> str:
        return canonical_sha256([record.to_json_value() for record in self.records()])
