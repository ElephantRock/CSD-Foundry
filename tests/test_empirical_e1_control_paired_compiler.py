"""Tests for conventional-control compilation and paired E1 finalization."""

import pytest

from csd_foundry.empirical.e1.control_paired_compiler import (
    ConventionalControlResponse,
    E1ControlArtifactError,
    E1TokenCountInventory,
    TokenizedRecordCount,
    compile_e1_control_prompts,
    compile_e1_conventional_control,
    finalize_e1_paired_artifacts,
)
from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
    load_artifact_records,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_text,
    canonical_sha256,
    load_json_text,
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


def _selection():
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _foundry():
    return compile_e1_foundry_artifacts(
        SCENARIOS,
        _selection(),
        release=_FOUNDRY_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _responses(foundry):
    prompts = load_artifact_records(compile_e1_control_prompts(foundry).content)
    return tuple(
        ConventionalControlResponse(
            str(prompt["record_id"]),
            canonical_json_text(
                {
                    "schema_version": "conventional-synthetic-label/1",
                    "decision": "generated_without_executable_validation",
                    "record_id": prompt["record_id"],
                }
            ),
        )
        for prompt in prompts
    )


def _control(foundry):
    return compile_e1_conventional_control(
        foundry,
        _responses(foundry),
        release=_CONTROL_RELEASE,
        generator_revision_digest=_GENERATOR_DIGEST,
        generation_command_digest=_GENERATION_COMMAND_DIGEST,
        validation_command_digest=_VALIDATION_COMMAND_DIGEST,
    )


def _token_inventory(foundry, control, *, context_length: int = 128):
    foundry_records = load_artifact_records(foundry.file("foundry_train.jsonl").content)
    control_records = load_artifact_records(control.file("control_train.jsonl").content)
    return E1TokenCountInventory(
        tokenizer_revision_digest=_TOKENIZER_DIGEST,
        counting_command_digest=_TOKEN_COUNT_COMMAND_DIGEST,
        context_length=context_length,
        control=tuple(
            TokenizedRecordCount(str(record["record_id"]), 32) for record in control_records
        ),
        foundry=tuple(
            TokenizedRecordCount(str(record["record_id"]), 40) for record in foundry_records
        ),
    )


def test_control_prompt_inventory_copies_exact_foundry_prompts_without_labels() -> None:
    foundry = _foundry()
    foundry_records = load_artifact_records(foundry.file("foundry_train.jsonl").content)
    prompts = load_artifact_records(compile_e1_control_prompts(foundry).content)

    assert len(prompts) == len(foundry_records)
    for foundry_record, prompt in zip(foundry_records, prompts, strict=True):
        assert prompt["record_id"] == str(foundry_record["record_id"]).replace(
            "e1-foundry/", "e1-control/", 1
        )
        assert prompt["paired_foundry_record_id"] == foundry_record["record_id"]
        assert prompt["prompt_messages"] == foundry_record["prompt_messages"]
        assert prompt["task_format_digest"] == foundry.task_format_digest
        assert "target" not in prompt
        assert "reference_label" not in prompt
        assert "executable_oracle_receipt_digest" not in prompt
        assert "independent_verification_receipt_digest" not in prompt


def test_control_compiler_binds_conventional_targets_without_foundry_evidence() -> None:
    foundry = _foundry()
    control = _control(foundry)
    records = load_artifact_records(control.file("control_train.jsonl").content)
    manifest = load_json_text(
        control.file("control_curriculum_manifest.json").content.decode("utf-8")
    )

    assert records
    assert control.record_count == foundry.training_record_count
    assert control.scenario_ids == foundry.training_scenario_ids
    assert all(record["schema_version"] == "e1-conventional-control-record/1" for record in records)
    assert all(record["label_authority"] == "conventional_synthetic" for record in records)
    assert all("reference_label" not in record for record in records)
    assert all("executable_oracle_receipt_digest" not in record for record in records)
    assert all("independent_verification_receipt_digest" not in record for record in records)
    assert isinstance(manifest, dict)
    assert manifest["executable_oracle_evidence"] is None
    assert manifest["independent_verification_evidence"] is None


def test_control_compiler_fails_closed_on_missing_response() -> None:
    foundry = _foundry()
    responses = _responses(foundry)

    with pytest.raises(E1ControlArtifactError, match="exactly cover prompts"):
        compile_e1_conventional_control(
            foundry,
            responses[:-1],
            release=_CONTROL_RELEASE,
            generator_revision_digest=_GENERATOR_DIGEST,
            generation_command_digest=_GENERATION_COMMAND_DIGEST,
            validation_command_digest=_VALIDATION_COMMAND_DIGEST,
        )


def test_control_response_requires_canonical_json_target() -> None:
    with pytest.raises(E1ControlArtifactError, match="canonical JSON"):
        ConventionalControlResponse("e1-control/train/M-01/case", '{"x":1}')


def test_paired_finalizer_instantiates_real_contract_with_equal_processed_budget() -> None:
    selection = _selection()
    foundry = _foundry()
    control = _control(foundry)
    inventory = _token_inventory(foundry, control)

    paired = finalize_e1_paired_artifacts(
        selection,
        foundry,
        control,
        inventory,
        release=_PAIRED_RELEASE,
        source_commit=_SOURCE_COMMIT,
        primary_metric_implementation_digest=_PRIMARY_METRIC_DIGEST,
        safety_metric_implementation_digest=_SAFETY_METRIC_DIGEST,
    )

    assert paired.contract.control.token_count == paired.contract.foundry.token_count
    assert paired.contract.control.token_count == control.record_count * inventory.context_length
    assert paired.contract.control.record_count == paired.contract.foundry.record_count
    assert paired.contract.control.scenario_ids == paired.contract.foundry.scenario_ids
    assert paired.contract.tokenizer_revision_digest == _TOKENIZER_DIGEST
    assert paired.contract.control.executable_oracle_evidence_digest is None
    assert paired.contract.foundry.executable_oracle_evidence_digest is not None
    assert paired.file("paired_e1_contract.json").sha256 != paired.file(
        "paired_e1_manifest.json"
    ).sha256


def test_token_inventory_rejects_any_record_that_would_be_truncated() -> None:
    foundry = _foundry()
    control = _control(foundry)
    control_records = load_artifact_records(control.file("control_train.jsonl").content)
    foundry_records = load_artifact_records(foundry.file("foundry_train.jsonl").content)

    with pytest.raises(E1ControlArtifactError, match="would be truncated"):
        E1TokenCountInventory(
            tokenizer_revision_digest=_TOKENIZER_DIGEST,
            counting_command_digest=_TOKEN_COUNT_COMMAND_DIGEST,
            context_length=64,
            control=tuple(
                TokenizedRecordCount(str(record["record_id"]), 65)
                for record in control_records
            ),
            foundry=tuple(
                TokenizedRecordCount(str(record["record_id"]), 40)
                for record in foundry_records
            ),
        )
