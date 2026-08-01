"""Frozen known-answer vectors for deterministic identity algorithm version 1."""

from __future__ import annotations

KNOWN_ANSWER_IDENTITY_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

FROZEN_IDENTITY_VECTOR_CATALOG_DIGEST = (
    "6f8aa335efe4210e833612a6be25a61e038f0f76cf48b8d3e4e93da379fac256"
)

KNOWN_ANSWER_IDENTITY_VECTORS: tuple[dict[str, object], ...] = (
    {
        "vector_id": "trajectory-base",
        "target_id": "target-alpha",
        "sample_index": 0,
        "attempt_index": 0,
        "entity_kind": "trajectory",
        "role_segments": ["trajectory"],
        "ordinal": 0,
        "target_definition_digest": (
            "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
        ),
        "expected": {
            "display_id": "trj-v04-deab5346ac5e0645eec74ca36caf5e5d",
            "entity_kind": "trajectory",
            "full_digest": ("deab5346ac5e0645eec74ca36caf5e5d0086ca4db7c3f2a777f077ea728ab8ab"),
            "generation_namespace_digest": (
                "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
            ),
            "material_digest": ("6c98d4d5042c30e593e9f46a82ca60310177f305d8754c5d53e236ccb497799d"),
        },
    },
    {
        "vector_id": "evidence-primary",
        "target_id": "target-alpha",
        "sample_index": 0,
        "attempt_index": 0,
        "entity_kind": "evidence",
        "role_segments": ["source-primary", "supporting"],
        "ordinal": 1,
        "target_definition_digest": (
            "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
        ),
        "expected": {
            "display_id": "evd-v04-89c0e7595c14757c1d776b83e590c845",
            "entity_kind": "evidence",
            "full_digest": ("89c0e7595c14757c1d776b83e590c845be15ad3461fb0957a2231706155356ef"),
            "generation_namespace_digest": (
                "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
            ),
            "material_digest": ("61125e40027143cde29d1425f95ec9b3e446844db924963198f96197f5c201b1"),
        },
    },
    {
        "vector_id": "basis-integer-role",
        "target_id": "target-alpha",
        "sample_index": 1,
        "attempt_index": 0,
        "entity_kind": "basis",
        "role_segments": ["basis", 1],
        "ordinal": 0,
        "target_definition_digest": (
            "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
        ),
        "expected": {
            "display_id": "bas-v04-11f82b02d498fe611be4d80e5187cd6b",
            "entity_kind": "basis",
            "full_digest": ("11f82b02d498fe611be4d80e5187cd6bcc87b6380483a5c08a6527e8624acb0f"),
            "generation_namespace_digest": (
                "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
            ),
            "material_digest": ("520e15634af36bce674b9f9dcc545d236dc9d4de88e1be8b8e5f3a80ef47eaf1"),
        },
    },
    {
        "vector_id": "basis-string-role",
        "target_id": "target-alpha",
        "sample_index": 1,
        "attempt_index": 0,
        "entity_kind": "basis",
        "role_segments": ["basis", "1"],
        "ordinal": 0,
        "target_definition_digest": (
            "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
        ),
        "expected": {
            "display_id": "bas-v04-9849adc294354f6f6b411a57e233be70",
            "entity_kind": "basis",
            "full_digest": ("9849adc294354f6f6b411a57e233be7020e695e97541a81aa60df9012e503e35"),
            "generation_namespace_digest": (
                "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
            ),
            "material_digest": ("1537c1807c455cf4ae11944cfc459df7ebe60efbccfc0a013926fe6be796e30f"),
        },
    },
    {
        "vector_id": "request-later-attempt",
        "target_id": "target-alpha",
        "sample_index": 2,
        "attempt_index": 3,
        "entity_kind": "request",
        "role_segments": ["reassessment"],
        "ordinal": 2,
        "target_definition_digest": (
            "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
        ),
        "expected": {
            "display_id": "req-v04-6700528538b3701a3a162e768467d09f",
            "entity_kind": "request",
            "full_digest": ("6700528538b3701a3a162e768467d09f7bf793d6825c29d4f55cd48d30e01c59"),
            "generation_namespace_digest": (
                "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"
            ),
            "material_digest": ("8ce99fba4c2629592e131f780baede2bd168da0135cc3544f13d45e7acc2c59e"),
        },
    },
    {
        "vector_id": "event-new-target-definition",
        "target_id": "target-beta",
        "sample_index": 2,
        "attempt_index": 0,
        "entity_kind": "event",
        "role_segments": ["event", 0],
        "ordinal": 0,
        "target_definition_digest": (
            "f175743ed656697a1d146a6ab1641bfe60b947db856950379eb7594866e312cd"
        ),
        "expected": {
            "display_id": "evt-v04-096d1b074a08fb32f41fbfe65fdf2f42",
            "entity_kind": "event",
            "full_digest": ("096d1b074a08fb32f41fbfe65fdf2f42ff5a76370932ab3161133b07bf7973e8"),
            "generation_namespace_digest": (
                "8ed6eefeda369d60c1da89b77ed82ad09fd630fb3bd9f0736b52e84c060f330c"
            ),
            "material_digest": ("6b64d277c633be20ae54afa54e5258783eda6ea05ddd03e33630bad26c8d4b02"),
        },
    },
)
