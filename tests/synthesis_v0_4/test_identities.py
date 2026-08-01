from __future__ import annotations

from pathlib import Path

import pytest

from csd_foundry.synthesis.v0_4.canonical_values import (
    CanonicalField,
    CanonicalObject,
    CanonicalValueError,
    canonical_value_bytes,
    validate_canonical_value,
)
from csd_foundry.synthesis.v0_4.choice_paths import (
    AttemptKey,
    RootSeed,
    SampleKey,
    SeedProvenance,
)
from csd_foundry.synthesis.v0_4.generation_namespace import (
    GenerationNamespace,
    build_generation_namespace,
)
from csd_foundry.synthesis.v0_4.identities import (
    DuplicateIdentityRoleError,
    EntityKind,
    IdentityCollisionError,
    IdentityLedger,
    IdentityRequest,
    UnknownIdentityRoleError,
    derive_identity,
)
from csd_foundry.synthesis.v0_4.identity_policy import (
    COLLISION_RISK_CEILING,
    DISPLAY_DIGEST_BITS,
    PROVISIONAL_DESIGN_IDENTITY_CEILING,
    PROVISIONAL_VOLUME_ENVELOPE,
    birthday_collision_bound,
    per_kind_collision_bound,
)
from csd_foundry.synthesis.v0_4.identity_validation import validate_identities
from csd_foundry.synthesis.v0_4.identity_vectors import (
    FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST,
    KNOWN_ANSWER_IDENTITY_SEED_HEX,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256, load_json_text

ROOT = Path(__file__).resolve().parents[2]


def _seed() -> RootSeed:
    return RootSeed.from_hex(
        KNOWN_ANSWER_IDENTITY_SEED_HEX,
        SeedProvenance.KNOWN_ANSWER_FIXTURE,
    )


def _request(role: tuple[str | int, ...], ordinal: int = 0) -> IdentityRequest:
    return IdentityRequest(
        AttemptKey(SampleKey("v0.4", "identity-test", 3), 1),
        EntityKind.EVIDENCE,
        role,
        ordinal,
    )


def test_identity_release_report_is_valid_and_provisional() -> None:
    report = validate_identities("v0.4")
    assert report.success
    assert report.known_answer_vectors == 6
    assert report.vectors_passed == 6
    assert report.vector_catalog_digest == FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST
    assert report.canonical_type_separation
    assert report.invalid_canonical_values_rejected == 8
    assert report.volume_policy_status == "provisional"
    assert not report.to_dict()["release_scale_claimed"]


def test_canonical_values_preserve_types_and_reject_mutability() -> None:
    assert len(
        {
            canonical_value_bytes(1),
            canonical_value_bytes("1"),
            canonical_value_bytes(True),
        }
    ) == 3
    for value in (1.5, [], {}, set(), b"bytes", bytearray(b"mutable")):
        with pytest.raises(CanonicalValueError):
            validate_canonical_value(value)
    with pytest.raises(CanonicalValueError):
        CanonicalObject(
            (
                CanonicalField("duplicate", 1),
                CanonicalField("duplicate", 2),
            )
        )
    with pytest.raises(CanonicalValueError):
        CanonicalObject((CanonicalField("z", 1), CanonicalField("a", 2)))


def test_identity_derivation_is_namespace_and_role_sensitive() -> None:
    seed = _seed()
    left_namespace = build_generation_namespace(canonical_sha256({"target": "left"}))
    right_namespace = build_generation_namespace(canonical_sha256({"target": "right"}))
    integer_role = derive_identity(seed, left_namespace, _request(("evidence", 1)))
    string_role = derive_identity(seed, left_namespace, _request(("evidence", "1")))
    new_namespace = derive_identity(seed, right_namespace, _request(("evidence", 1)))
    assert integer_role.full_digest != string_role.full_digest
    assert integer_role.full_digest != new_namespace.full_digest
    assert integer_role.generation_namespace_digest != new_namespace.generation_namespace_digest


def test_identity_ledger_is_order_independent_and_fail_closed() -> None:
    seed = _seed()
    namespace = build_generation_namespace(canonical_sha256({"target": "ledger"}))
    requests = (_request(("a",), 0), _request(("b",), 1), _request(("c",), 2))
    forward = IdentityLedger(seed, namespace)
    reverse = IdentityLedger(seed, namespace)
    for request in requests:
        forward.allocate(request)
    for request in reversed(requests):
        reverse.allocate(request)
    assert forward.canonical_digest == reverse.canonical_digest
    assert forward.resolve(requests[1]) == reverse.resolve(requests[1])
    with pytest.raises(DuplicateIdentityRoleError):
        forward.allocate(requests[0])
    with pytest.raises(UnknownIdentityRoleError):
        forward.resolve(_request(("missing",), 99))


def test_identity_collision_injection_fails_closed() -> None:
    seed = _seed()
    namespace = build_generation_namespace(canonical_sha256({"target": "collisions"}))

    def full_collision(
        seed_value: RootSeed,
        namespace_value: GenerationNamespace,
        request_value: IdentityRequest,
    ) -> bytes:
        del seed_value, namespace_value, request_value
        return b"\x11" * 32

    ledger = IdentityLedger(seed, namespace, digest_provider=full_collision)
    ledger.allocate(_request(("a",)))
    with pytest.raises(IdentityCollisionError):
        ledger.allocate(_request(("b",)))

    def display_collision(
        seed_value: RootSeed,
        namespace_value: GenerationNamespace,
        request_value: IdentityRequest,
    ) -> bytes:
        del seed_value, namespace_value
        suffix = b"\x22" * 16 if request_value.role_segments == ("a",) else b"\x33" * 16
        return b"\xaa" * 16 + suffix

    display_ledger = IdentityLedger(seed, namespace, digest_provider=display_collision)
    display_ledger.allocate(_request(("a",)))
    with pytest.raises(IdentityCollisionError):
        display_ledger.allocate(_request(("b",)))


def test_collision_policy_uses_exact_integer_bounds() -> None:
    global_bound = birthday_collision_bound(
        PROVISIONAL_DESIGN_IDENTITY_CEILING,
        DISPLAY_DIGEST_BITS,
    )
    kind_bound = per_kind_collision_bound(
        PROVISIONAL_VOLUME_ENVELOPE,
        DISPLAY_DIGEST_BITS,
    )
    assert global_bound.numerator == 99_999_990_000_000
    assert global_bound.denominator == 1 << 129
    assert global_bound.no_greater_than(COLLISION_RISK_CEILING)
    assert kind_bound.numerator == 19_479_990_000_000
    assert PROVISIONAL_VOLUME_ENVELOPE.raw_projected_count == 10_000_000
    assert PROVISIONAL_VOLUME_ENVELOPE.status == "provisional"


def test_frozen_identity_vector_catalog_detects_in_place_edits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from csd_foundry.synthesis.v0_4 import identity_validation

    changed = list(identity_validation.KNOWN_ANSWER_IDENTITY_VECTORS)
    changed[0] = dict(changed[0], vector_id="changed-in-place")
    monkeypatch.setattr(
        identity_validation,
        "KNOWN_ANSWER_IDENTITY_VECTORS",
        tuple(changed),
    )
    report = identity_validation.validate_identities("v0.4")
    assert not report.success
    assert any("frozen version-1 digest" in error for error in report.errors)


def test_repository_identity_evidence_matches_runtime_validation() -> None:
    report = load_json_text(
        (ROOT / "reports/deterministic_identities_v0.4.json").read_text(encoding="utf-8")
    )
    assert report == validate_identities("v0.4").to_dict()
    vectors = load_json_text(
        (ROOT / "data/canary/v0.4/identity-v1/identity_vectors.json").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(vectors, dict)
    assert canonical_sha256(vectors) == FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST
