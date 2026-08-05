"""Canonical parser for artifact-bound E1 token-count inventories."""

from __future__ import annotations

from typing import cast

from csd_foundry.empirical.e1.control_paired_compiler import (
    E1ControlArtifactError,
    E1TokenCountInventory,
    TokenizedRecordCount,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_text, load_json_text


def load_token_inventory(content: str) -> E1TokenCountInventory:
    """Load and verify one closed canonical token-count inventory object."""

    parsed = load_json_text(content)
    if not isinstance(parsed, dict):
        raise E1ControlArtifactError("token inventory is not an object")
    if canonical_json_text(parsed) != content:
        raise E1ControlArtifactError("token inventory bytes are not canonical JSON")
    expected_fields = {
        "schema_version",
        "tokenizer_revision_digest",
        "counting_command_digest",
        "control_artifact_digest",
        "foundry_artifact_digest",
        "context_length",
        "token_count_per_arm",
        "control",
        "foundry",
    }
    if set(parsed) != expected_fields:
        raise E1ControlArtifactError("token inventory fields do not match schema")
    if parsed.get("schema_version") != "e1-token-count-inventory/1":
        raise E1ControlArtifactError("token inventory schema_version is unsupported")

    def load_side(value: object, *, field: str) -> tuple[TokenizedRecordCount, ...]:
        if not isinstance(value, list):
            raise E1ControlArtifactError(f"token inventory {field} is not a list")
        result: list[TokenizedRecordCount] = []
        for index, item in enumerate(value):
            if not isinstance(item, dict) or set(item) != {"record_id", "raw_token_count"}:
                raise E1ControlArtifactError(f"token inventory {field}[{index}] has invalid fields")
            record_id = item["record_id"]
            raw_token_count = item["raw_token_count"]
            if not isinstance(record_id, str):
                raise E1ControlArtifactError(
                    f"token inventory {field}[{index}].record_id must be a string"
                )
            if isinstance(raw_token_count, bool) or not isinstance(raw_token_count, int):
                raise E1ControlArtifactError(
                    f"token inventory {field}[{index}].raw_token_count must be an integer"
                )
            result.append(TokenizedRecordCount(record_id, raw_token_count))
        return tuple(result)

    inventory = E1TokenCountInventory(
        tokenizer_revision_digest=cast(str, parsed["tokenizer_revision_digest"]),
        counting_command_digest=cast(str, parsed["counting_command_digest"]),
        control_artifact_digest=cast(str, parsed["control_artifact_digest"]),
        foundry_artifact_digest=cast(str, parsed["foundry_artifact_digest"]),
        context_length=cast(int, parsed["context_length"]),
        control=load_side(parsed["control"], field="control"),
        foundry=load_side(parsed["foundry"], field="foundry"),
    )
    declared_token_count = parsed["token_count_per_arm"]
    if isinstance(declared_token_count, bool) or not isinstance(declared_token_count, int):
        raise E1ControlArtifactError("token_count_per_arm must be an integer")
    if declared_token_count != inventory.token_count_per_arm:
        raise E1ControlArtifactError("token_count_per_arm does not match the exact record totals")
    return inventory
