"""Tests for canonical E1 token inventory parsing and derived-count binding."""

import pytest

from csd_foundry.empirical.e1.control_paired_compiler import (
    E1ControlArtifactError,
    E1TokenCountInventory,
    TokenizedRecordCount,
)
from csd_foundry.empirical.e1.token_inventory_io import load_token_inventory
from csd_foundry.synthesis.v0_4.serialization import canonical_json_text, canonical_sha256

_CONTROL_DIGEST = canonical_sha256({"artifact": "control"})
_FOUNDRY_DIGEST = canonical_sha256({"artifact": "foundry"})
_TOKENIZER_DIGEST = canonical_sha256({"tokenizer": "candidate/1"})
_COMMAND_DIGEST = canonical_sha256({"command": "count"})


def _inventory() -> E1TokenCountInventory:
    return E1TokenCountInventory(
        tokenizer_revision_digest=_TOKENIZER_DIGEST,
        counting_command_digest=_COMMAND_DIGEST,
        control_artifact_digest=_CONTROL_DIGEST,
        foundry_artifact_digest=_FOUNDRY_DIGEST,
        context_length=64,
        control=(TokenizedRecordCount("e1-control/train/M-01/case", 12),),
        foundry=(TokenizedRecordCount("e1-foundry/train/M-01/case", 12),),
    )


def test_token_inventory_round_trips_its_canonical_serializer() -> None:
    inventory = _inventory()

    loaded = load_token_inventory(canonical_json_text(inventory.to_dict()))

    assert loaded == inventory
    assert loaded.token_count_per_arm == 12


def test_token_inventory_rejects_tampered_derived_token_total() -> None:
    payload = _inventory().to_dict()
    payload["token_count_per_arm"] = 13

    with pytest.raises(E1ControlArtifactError, match="does not match"):
        load_token_inventory(canonical_json_text(payload))


def test_token_inventory_rejects_noncanonical_bytes() -> None:
    content = canonical_json_text(_inventory().to_dict()).rstrip("\n")

    with pytest.raises(E1ControlArtifactError, match="not canonical"):
        load_token_inventory(content)
