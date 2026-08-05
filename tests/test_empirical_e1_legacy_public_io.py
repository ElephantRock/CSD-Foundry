"""Regression tests for legacy public I/O imports from the E1 compiler module."""

from pathlib import Path

import pytest

from csd_foundry.empirical.e1 import (
    E1ArtifactSetError,
    E1ControlArtifactError,
    E1TokenCountInventory,
    TokenizedRecordCount,
)
from csd_foundry.empirical.e1 import control_paired_compiler as compiler_module
from csd_foundry.empirical.e1.artifact_set_io import write_artifact_files
from csd_foundry.empirical.e1.control_response_io import load_conventional_responses
from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile
from csd_foundry.empirical.e1.token_inventory_io import load_token_inventory
from csd_foundry.synthesis.v0_4.serialization import canonical_json_text, canonical_sha256


def test_legacy_compiler_helpers_are_the_hardened_public_implementations() -> None:
    assert compiler_module.write_artifact_files is write_artifact_files
    assert compiler_module.load_conventional_responses is load_conventional_responses
    assert compiler_module.load_token_inventory is load_token_inventory


def test_legacy_compiler_writer_rejects_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(E1ArtifactSetError, match="flat relative name"):
        compiler_module.write_artifact_files(
            (ArtifactFile("../escape.json", "escape", b"{}\n"),),
            tmp_path / "artifacts",
        )


def test_legacy_compiler_token_parser_round_trips_current_schema() -> None:
    inventory = E1TokenCountInventory(
        tokenizer_revision_digest=canonical_sha256({"tokenizer": "candidate/1"}),
        counting_command_digest=canonical_sha256({"command": "count"}),
        control_artifact_digest=canonical_sha256({"artifact": "control"}),
        foundry_artifact_digest=canonical_sha256({"artifact": "foundry"}),
        context_length=64,
        control=(TokenizedRecordCount("e1-control/train/M-01/case", 12),),
        foundry=(TokenizedRecordCount("e1-foundry/train/M-01/case", 12),),
    )

    loaded = compiler_module.load_token_inventory(canonical_json_text(inventory.to_dict()))

    assert loaded == inventory


def test_legacy_response_parser_rejects_noncanonical_jsonl() -> None:
    with pytest.raises(E1ControlArtifactError, match="LF-terminated"):
        compiler_module.load_conventional_responses(b'{"record_id":"x","target":"x"}')
