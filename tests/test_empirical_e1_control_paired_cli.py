"""End-to-end tests for E1 control and paired artifact CLI reconstruction."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from csd_foundry.empirical.e1.control_paired_cli import main
from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
    load_artifact_records,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
)

_SOURCE_COMMIT = "2eb623a2cc2e1984af198a15be600d019bb91416"
_SELECTION_RELEASE = "e1-candidate/1"
_FOUNDRY_RELEASE = "e1-foundry-artifacts/1"
_CONTROL_RELEASE = "e1-control-artifacts/1"
_PAIRED_RELEASE = "e1-paired-artifacts/1"
_GENERATOR_DIGEST = canonical_sha256({"generator": "conventional-synthetic/1"})
_GENERATION_COMMAND_DIGEST = canonical_sha256({"command": "generate-control"})
_VALIDATION_COMMAND_DIGEST = canonical_sha256({"command": "validate-control"})
_TOKENIZER_DIGEST = canonical_sha256({"tokenizer": "candidate/1"})
_TOKEN_COUNT_COMMAND_DIGEST = canonical_sha256({"command": "count-tokens"})
_PRIMARY_METRIC_DIGEST = canonical_sha256({"metric": "primary/1"})
_SAFETY_METRIC_DIGEST = canonical_sha256({"metric": "safety/1"})


def _source_args() -> list[str]:
    return [
        "--source-commit",
        _SOURCE_COMMIT,
        "--selection-release",
        _SELECTION_RELEASE,
        "--foundry-release",
        _FOUNDRY_RELEASE,
    ]


def _control_args(responses: Path) -> list[str]:
    return [
        "--responses",
        str(responses),
        "--control-release",
        _CONTROL_RELEASE,
        "--generator-revision-digest",
        _GENERATOR_DIGEST,
        "--generation-command-digest",
        _GENERATION_COMMAND_DIGEST,
        "--validation-command-digest",
        _VALIDATION_COMMAND_DIGEST,
    ]


def _paired_args(inventory: Path) -> list[str]:
    return [
        "--token-inventory",
        str(inventory),
        "--paired-release",
        _PAIRED_RELEASE,
        "--primary-metric-implementation-digest",
        _PRIMARY_METRIC_DIGEST,
        "--safety-metric-implementation-digest",
        _SAFETY_METRIC_DIGEST,
    ]


def _invoke(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
    monkeypatch.setattr(sys, "argv", ["control_paired_cli", *arguments])
    try:
        main()
    except SystemExit as exc:
        if exc.code != 0:
            raise


def _foundry():
    selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )
    return compile_e1_foundry_artifacts(
        SCENARIOS,
        selection,
        release=_FOUNDRY_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _write_responses(prompt_file: Path, response_file: Path) -> None:
    prompts = load_artifact_records(prompt_file.read_bytes())
    response_file.write_bytes(
        b"".join(
            canonical_json_bytes(
                {
                    "record_id": prompt["record_id"],
                    "target": canonical_json_text(
                        {
                            "schema_version": "conventional-synthetic-label/1",
                            "decision": "generated_without_executable_validation",
                            "record_id": prompt["record_id"],
                        }
                    ),
                }
            )
            for prompt in prompts
        )
    )


def _write_inventory(control_file: Path, inventory_file: Path) -> None:
    foundry = _foundry()
    control_records = load_artifact_records(control_file.read_bytes())
    foundry_records = load_artifact_records(foundry.file("foundry_train.jsonl").content)
    inventory_file.write_text(
        canonical_json_text(
            {
                "schema_version": "e1-token-count-inventory/1",
                "tokenizer_revision_digest": _TOKENIZER_DIGEST,
                "counting_command_digest": _TOKEN_COUNT_COMMAND_DIGEST,
                "control_artifact_digest": hashlib.sha256(control_file.read_bytes()).hexdigest(),
                "foundry_artifact_digest": foundry.file("foundry_train.jsonl").sha256,
                "context_length": 128,
                "token_count_per_arm": len(control_records) * 40,
                "control": [
                    {"record_id": record["record_id"], "raw_token_count": 40}
                    for record in control_records
                ],
                "foundry": [
                    {"record_id": record["record_id"], "raw_token_count": 40}
                    for record in foundry_records
                ],
            }
        ),
        encoding="utf-8",
    )


def test_cli_compiles_and_reconstructs_control_and_paired_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompts_dir = tmp_path / "prompts"
    responses = tmp_path / "responses.jsonl"
    control_dir = tmp_path / "control"
    inventory = tmp_path / "token-inventory.json"
    paired_dir = tmp_path / "paired"

    _invoke(
        monkeypatch,
        "prompts",
        *_source_args(),
        "--output-dir",
        str(prompts_dir),
    )
    _write_responses(prompts_dir / "control_prompts.jsonl", responses)
    _invoke(
        monkeypatch,
        "compile-control",
        *_source_args(),
        *_control_args(responses),
        "--output-dir",
        str(control_dir),
    )
    _invoke(
        monkeypatch,
        "validate-control",
        *_source_args(),
        *_control_args(responses),
        "--output-dir",
        str(control_dir),
    )
    _write_inventory(control_dir / "control_train.jsonl", inventory)
    _invoke(
        monkeypatch,
        "finalize",
        *_source_args(),
        *_control_args(responses),
        *_paired_args(inventory),
        "--output-dir",
        str(paired_dir),
    )
    _invoke(
        monkeypatch,
        "validate-paired",
        *_source_args(),
        *_control_args(responses),
        *_paired_args(inventory),
        "--output-dir",
        str(paired_dir),
    )

    contract_path = paired_dir / "paired_e1_contract.json"
    contract_path.write_bytes(contract_path.read_bytes() + b" ")
    with pytest.raises(SystemExit) as exc_info:
        _invoke(
            monkeypatch,
            "validate-paired",
            *_source_args(),
            *_control_args(responses),
            *_paired_args(inventory),
            "--output-dir",
            str(paired_dir),
        )
    assert exc_info.value.code == 1
