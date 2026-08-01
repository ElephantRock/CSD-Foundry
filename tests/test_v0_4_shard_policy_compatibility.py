from __future__ import annotations

import json
from pathlib import Path

from csd_foundry.synthesis.v0_4.execution_protocol import shard_policy_document
from csd_foundry.synthesis.v0_4.generation_namespace import build_generation_namespace
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_ROOT = Path(__file__).resolve().parents[1]
_TARGET_ALPHA_DEFINITION_DIGEST = "0c249247fe8fe1bc74c067a535846dedf0df922e69688ac20f726289f78901c5"
_TARGET_ALPHA_NAMESPACE_DIGEST = "5694c16e26537f95c870bcf1671cefd0c926846751b8b9558301031873f53e85"


def test_packaged_shard_policy_matches_frozen_generation_namespace() -> None:
    document = json.loads(
        (_ROOT / "specs/v0.4/shard_policy.json").read_text(encoding="utf-8")
    )
    assert document == shard_policy_document()

    namespace = build_generation_namespace(_TARGET_ALPHA_DEFINITION_DIGEST)
    assert namespace.digest == _TARGET_ALPHA_NAMESPACE_DIGEST
    assert namespace.shard_policy_digest == canonical_sha256(document)
