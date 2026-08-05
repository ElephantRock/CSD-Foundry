"""Tests for the paired E1 curriculum and evaluation contract."""

from dataclasses import replace
from typing import cast

import pytest

from csd_foundry.empirical.e1 import (
    E1CurriculumArm,
    E1CurriculumArtifact,
    E1CurriculumEvaluationContract,
    E1EvaluationArtifact,
    E1ExperimentContract,
    E1LabelAuthority,
    E1Split,
    FamilySplitError,
    compile_e1_curriculum_evaluation_contract,
    compile_e1_experiment_contract,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_SOURCE_COMMIT = "1be23fa10df2b8a18646f8d91cc16e6cd920c33a"
_RELEASE = "e1-curriculum-evaluation/1"


def _digest(label: str) -> str:
    return canonical_sha256({"label": label})


_TOKENIZER_REVISION_DIGEST = _digest("tokenizer-revision")


def _selection() -> E1ExperimentContract:
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release="e1-selection/1",
        source_commit=_SOURCE_COMMIT,
    )


def _scenario_ids(selection: E1ExperimentContract, split: E1Split) -> tuple[str, ...]:
    return tuple(
        sorted(
            scenario_id
            for assignment in selection.split_manifest.assignments
            if assignment.split is split
            for scenario_id in assignment.scenario_ids
        )
    )


def _artifacts() -> tuple[
    E1ExperimentContract,
    E1CurriculumArtifact,
    E1CurriculumArtifact,
    E1EvaluationArtifact,
]:
    selection = _selection()
    training_ids = _scenario_ids(selection, E1Split.TRAIN)
    development_ids = _scenario_ids(selection, E1Split.DEVELOPMENT)
    task_format_digest = _digest("shared-task-format")
    control = E1CurriculumArtifact(
        arm=E1CurriculumArm.CONTROL,
        label_authority=E1LabelAuthority.CONVENTIONAL_SYNTHETIC,
        artifact_digest=_digest("control-artifact"),
        manifest_digest=_digest("control-manifest"),
        generation_command_digest=_digest("control-generation-command"),
        validation_command_digest=_digest("control-validation-command"),
        task_format_digest=task_format_digest,
        scenario_ids=training_ids,
        record_count=100,
        token_count=4096,
    )
    foundry = E1CurriculumArtifact(
        arm=E1CurriculumArm.FOUNDRY,
        label_authority=E1LabelAuthority.EXECUTABLE_SEMANTICS,
        artifact_digest=_digest("foundry-artifact"),
        manifest_digest=_digest("foundry-manifest"),
        generation_command_digest=_digest("foundry-generation-command"),
        validation_command_digest=_digest("foundry-validation-command"),
        task_format_digest=task_format_digest,
        scenario_ids=training_ids,
        record_count=120,
        token_count=4096,
        executable_oracle_evidence_digest=_digest("oracle-evidence"),
        independent_verification_evidence_digest=_digest("independent-verification"),
    )
    evaluation = E1EvaluationArtifact(
        split=E1Split.DEVELOPMENT,
        artifact_digest=_digest("evaluation-artifact"),
        manifest_digest=_digest("evaluation-manifest"),
        generation_command_digest=_digest("evaluation-generation-command"),
        validation_command_digest=_digest("evaluation-validation-command"),
        scenario_ids=development_ids,
        record_count=40,
        family_count=len(
            [
                assignment
                for assignment in selection.split_manifest.assignments
                if assignment.split is E1Split.DEVELOPMENT
            ]
        ),
        primary_metric_implementation_digest=_digest("primary-metric"),
        safety_metric_implementation_digest=_digest("safety-metric"),
    )
    return selection, control, foundry, evaluation


def _compile(
    *,
    control: E1CurriculumArtifact | None = None,
    foundry: E1CurriculumArtifact | None = None,
    evaluation: E1EvaluationArtifact | None = None,
    source_commit: str = _SOURCE_COMMIT,
    tokenizer_revision_digest: str = _TOKENIZER_REVISION_DIGEST,
) -> E1CurriculumEvaluationContract:
    selection, default_control, default_foundry, default_evaluation = _artifacts()
    return compile_e1_curriculum_evaluation_contract(
        selection,
        release=_RELEASE,
        source_commit=source_commit,
        tokenizer_revision_digest=tokenizer_revision_digest,
        control=default_control if control is None else control,
        foundry=default_foundry if foundry is None else foundry,
        evaluation=default_evaluation if evaluation is None else evaluation,
    )


def test_contract_binds_two_arms_development_evaluation_and_no_peeking() -> None:
    contract = _compile()
    payload = contract.to_dict()
    digest = payload.pop("contract_digest")

    assert contract.control.arm is E1CurriculumArm.CONTROL
    assert contract.foundry.arm is E1CurriculumArm.FOUNDRY
    assert contract.tokenizer_revision_digest == _TOKENIZER_REVISION_DIGEST
    assert contract.control.token_count == contract.foundry.token_count
    assert contract.control.artifact_digest != contract.foundry.artifact_digest
    assert contract.control.manifest_digest != contract.foundry.manifest_digest
    assert contract.foundry.executable_oracle_evidence_digest is not None
    assert contract.foundry.independent_verification_evidence_digest is not None
    assert contract.evaluation.split is E1Split.DEVELOPMENT
    assert contract.development_family_count == contract.evaluation.family_count == 4
    assert set(contract.training_scenario_ids).isdisjoint(contract.development_scenario_ids)
    assert {"H-01", "L-01", "M-15"}.isdisjoint(contract.training_scenario_ids)
    assert {"H-01", "L-01", "M-15"}.isdisjoint(contract.development_scenario_ids)
    assert payload["primary_metric_id"] == (
        "structural-holdout-exact-semantic-decision-accuracy/family-macro/1"
    )
    assert payload["safety_metric_id"] == "clean-case-regression/base-and-control/1"
    assert payload["primary_aggregation_unit"] == "symbolic_scenario_family"
    assert payload["protected_metric_visibility"] == (
        "after_all_predetermined_checkpoints_complete"
    )
    assert "training_loss" in payload["permitted_live_telemetry"]
    assert canonical_sha256(payload) == digest


def test_contract_rejects_token_or_task_format_mismatch() -> None:
    _, control, foundry, _ = _artifacts()

    with pytest.raises(FamilySplitError, match="token matched"):
        _compile(foundry=replace(foundry, token_count=foundry.token_count + 1))

    with pytest.raises(FamilySplitError, match="task-format matched"):
        _compile(foundry=replace(foundry, task_format_digest=_digest("other-format")))


def test_contract_rejects_identical_control_and_foundry_artifacts() -> None:
    _, control, foundry, _ = _artifacts()

    with pytest.raises(FamilySplitError, match="artifacts must differ"):
        _compile(foundry=replace(foundry, artifact_digest=control.artifact_digest))

    with pytest.raises(FamilySplitError, match="manifests must differ"):
        _compile(foundry=replace(foundry, manifest_digest=control.manifest_digest))


def test_contract_rejects_curriculum_or_evaluation_scenario_drift() -> None:
    _, control, foundry, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="control curriculum does not match"):
        _compile(control=replace(control, scenario_ids=control.scenario_ids[1:]))

    with pytest.raises(FamilySplitError, match="Foundry curriculum does not match"):
        _compile(foundry=replace(foundry, scenario_ids=foundry.scenario_ids[1:]))

    drifted_evaluation = replace(
        evaluation,
        scenario_ids=evaluation.scenario_ids[1:],
        family_count=evaluation.family_count - 1,
    )
    with pytest.raises(FamilySplitError, match="evaluation artifact does not match"):
        _compile(evaluation=drifted_evaluation)


def test_contract_rejects_family_count_drift_and_wrong_runtime_artifacts() -> None:
    contract = _compile()

    with pytest.raises(FamilySplitError, match="family count does not match"):
        replace(contract, development_family_count=contract.development_family_count - 1)

    with pytest.raises(FamilySplitError, match="control must be"):
        replace(contract, control=cast(E1CurriculumArtifact, object()))

    with pytest.raises(FamilySplitError, match="foundry must be"):
        replace(contract, foundry=cast(E1CurriculumArtifact, object()))

    with pytest.raises(FamilySplitError, match="evaluation must be"):
        replace(contract, evaluation=cast(E1EvaluationArtifact, object()))


def test_label_authority_and_verification_evidence_are_arm_specific() -> None:
    _, control, foundry, _ = _artifacts()

    with pytest.raises(FamilySplitError, match="control labels"):
        replace(control, label_authority=E1LabelAuthority.EXECUTABLE_SEMANTICS)

    with pytest.raises(FamilySplitError, match="may not cite executable-oracle"):
        replace(control, executable_oracle_evidence_digest=_digest("forbidden"))

    with pytest.raises(FamilySplitError, match="may not cite Foundry independent"):
        replace(
            control,
            independent_verification_evidence_digest=_digest("forbidden-verification"),
        )

    with pytest.raises(FamilySplitError, match="Foundry labels"):
        replace(foundry, label_authority=E1LabelAuthority.CONVENTIONAL_SYNTHETIC)

    with pytest.raises(FamilySplitError, match="requires executable-oracle"):
        replace(foundry, executable_oracle_evidence_digest=None)

    with pytest.raises(FamilySplitError, match="requires independent-verification"):
        replace(foundry, independent_verification_evidence_digest=None)

    with pytest.raises(FamilySplitError, match="evidence must differ"):
        replace(
            foundry,
            independent_verification_evidence_digest=(foundry.executable_oracle_evidence_digest),
        )


def test_raw_runtime_types_fail_closed() -> None:
    selection, control, _, evaluation = _artifacts()
    contract = _compile()

    with pytest.raises(FamilySplitError, match="arm must be an E1CurriculumArm"):
        replace(control, arm=cast(E1CurriculumArm, "control"))

    with pytest.raises(FamilySplitError, match="evaluation split must be an E1Split"):
        replace(evaluation, split=cast(E1Split, "development"))

    with pytest.raises(FamilySplitError, match="lowercase SHA-256"):
        replace(control, artifact_digest=cast(str, object()))

    with pytest.raises(FamilySplitError, match="nonempty tuple"):
        replace(control, scenario_ids=cast(tuple[str, ...], ["M-01"]))

    with pytest.raises(FamilySplitError, match="positive integer"):
        replace(control, record_count=cast(int, True))

    with pytest.raises(FamilySplitError, match="nonempty string"):
        replace(contract, release=cast(str, object()))

    with pytest.raises(FamilySplitError, match="tokenizer_revision_digest"):
        replace(contract, tokenizer_revision_digest=cast(str, object()))

    with pytest.raises(FamilySplitError, match="selection_contract must be"):
        compile_e1_curriculum_evaluation_contract(
            cast(E1ExperimentContract, object()),
            release=_RELEASE,
            source_commit=_SOURCE_COMMIT,
            tokenizer_revision_digest=_TOKENIZER_REVISION_DIGEST,
            control=contract.control,
            foundry=contract.foundry,
            evaluation=contract.evaluation,
        )

    assert selection.source_commit == _SOURCE_COMMIT


def test_metric_bearing_evaluation_is_development_only() -> None:
    _, _, _, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="development only"):
        replace(evaluation, split=E1Split.TRAIN)


def test_source_commit_must_match_selection_contract() -> None:
    with pytest.raises(FamilySplitError, match="source commits must match"):
        _compile(source_commit="0" * 40)


def test_contract_digest_changes_with_artifact_metric_or_tokenizer() -> None:
    baseline = _compile()
    _, control, _, evaluation = _artifacts()

    changed_control = _compile(
        control=replace(control, artifact_digest=_digest("changed-control-artifact"))
    )
    changed_metric = _compile(
        evaluation=replace(
            evaluation,
            primary_metric_implementation_digest=_digest("changed-primary-metric"),
        )
    )
    changed_tokenizer = _compile(tokenizer_revision_digest=_digest("changed-tokenizer-revision"))

    assert changed_control.contract_digest != baseline.contract_digest
    assert changed_metric.contract_digest != baseline.contract_digest
    assert changed_tokenizer.contract_digest != baseline.contract_digest


def test_digest_fields_and_identifier_sequences_are_canonical() -> None:
    _, control, _, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="lowercase SHA-256"):
        replace(control, artifact_digest="not-a-digest")

    with pytest.raises(FamilySplitError, match="must be sorted"):
        replace(control, scenario_ids=tuple(reversed(control.scenario_ids)))

    with pytest.raises(FamilySplitError, match="must contain unique"):
        replace(
            evaluation,
            scenario_ids=(evaluation.scenario_ids[0], evaluation.scenario_ids[0]),
        )
