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


def _selection(*, release: str = "e1-selection/1") -> E1ExperimentContract:
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=release,
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
    selection: E1ExperimentContract | None = None,
    control: E1CurriculumArtifact | None = None,
    foundry: E1CurriculumArtifact | None = None,
    evaluation: E1EvaluationArtifact | None = None,
    source_commit: str = _SOURCE_COMMIT,
    tokenizer_revision_digest: str = _TOKENIZER_REVISION_DIGEST,
) -> E1CurriculumEvaluationContract:
    default_selection, default_control, default_foundry, default_evaluation = _artifacts()
    return compile_e1_curriculum_evaluation_contract(
        default_selection if selection is None else selection,
        release=_RELEASE,
        source_commit=source_commit,
        tokenizer_revision_digest=tokenizer_revision_digest,
        control=default_control if control is None else control,
        foundry=default_foundry if foundry is None else foundry,
        evaluation=default_evaluation if evaluation is None else evaluation,
    )


def test_contract_embeds_selection_and_binds_no_peeking_policy() -> None:
    contract = _compile()
    payload = contract.to_dict()
    digest = payload.pop("contract_digest")
    nested_selection = payload["selection_contract"]

    assert isinstance(nested_selection, dict)
    assert nested_selection["contract_digest"] == contract.selection_contract_digest
    assert payload["selection_contract_digest"] == contract.selection_contract_digest
    assert contract.training_scenario_ids == _scenario_ids(
        contract.selection_contract, E1Split.TRAIN
    )
    assert contract.development_scenario_ids == _scenario_ids(
        contract.selection_contract, E1Split.DEVELOPMENT
    )
    assert contract.development_family_count == contract.evaluation.family_count == 4
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


def test_contract_binds_tokenizer_and_paired_arm_comparability() -> None:
    contract = _compile()
    _, _, foundry, _ = _artifacts()

    assert contract.tokenizer_revision_digest == _TOKENIZER_REVISION_DIGEST
    assert contract.control.token_count == contract.foundry.token_count
    assert contract.control.task_format_digest == contract.foundry.task_format_digest

    with pytest.raises(FamilySplitError, match="token matched"):
        _compile(foundry=replace(foundry, token_count=foundry.token_count + 1))

    with pytest.raises(FamilySplitError, match="task-format matched"):
        _compile(foundry=replace(foundry, task_format_digest=_digest("other-format")))


def test_reconstructed_contract_is_bound_to_embedded_selection_families() -> None:
    contract = _compile()
    altered_scenarios = tuple(
        replace(item, split="validation") if item.scenario_id == "M-01" else item
        for item in SCENARIOS.values()
    )
    altered_selection = compile_e1_experiment_contract(
        altered_scenarios,
        release="e1-selection/altered",
        source_commit=_SOURCE_COMMIT,
    )

    with pytest.raises(FamilySplitError, match="control curriculum does not match selection"):
        replace(contract, selection_contract=altered_selection)

    same_membership_new_identity = _selection(release="e1-selection/2")
    rebound = replace(contract, selection_contract=same_membership_new_identity)
    assert rebound.training_scenario_ids == contract.training_scenario_ids
    assert rebound.contract_digest != contract.contract_digest


def test_contract_rejects_curriculum_or_evaluation_membership_drift() -> None:
    _, control, foundry, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="control curriculum does not match selection"):
        _compile(control=replace(control, scenario_ids=control.scenario_ids[1:]))

    with pytest.raises(FamilySplitError, match="Foundry curriculum does not match selection"):
        _compile(foundry=replace(foundry, scenario_ids=foundry.scenario_ids[1:]))

    drifted_evaluation = replace(
        evaluation,
        scenario_ids=evaluation.scenario_ids[1:],
        family_count=evaluation.family_count - 1,
    )
    with pytest.raises(FamilySplitError, match="evaluation artifact does not match selection"):
        _compile(evaluation=drifted_evaluation)

    with pytest.raises(FamilySplitError, match="family count does not match"):
        _compile(evaluation=replace(evaluation, family_count=evaluation.family_count - 1))


def test_label_authority_and_evidence_roles_are_separate() -> None:
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

    with pytest.raises(FamilySplitError, match="oracle, and verification digests must differ"):
        replace(foundry, executable_oracle_evidence_digest=foundry.artifact_digest)

    with pytest.raises(FamilySplitError, match="oracle, and verification digests must differ"):
        replace(foundry, independent_verification_evidence_digest=foundry.manifest_digest)

    with pytest.raises(FamilySplitError, match="oracle, and verification digests must differ"):
        replace(
            foundry,
            independent_verification_evidence_digest=(foundry.executable_oracle_evidence_digest),
        )


def test_all_artifact_manifest_and_foundry_evidence_roles_are_globally_distinct() -> None:
    contract = _compile()
    _, control, foundry, evaluation = _artifacts()
    oracle_digest = contract.foundry.executable_oracle_evidence_digest
    verification_digest = contract.foundry.independent_verification_evidence_digest
    assert oracle_digest is not None
    assert verification_digest is not None

    role_digests = {
        contract.control.artifact_digest,
        contract.control.manifest_digest,
        contract.foundry.artifact_digest,
        contract.foundry.manifest_digest,
        contract.evaluation.artifact_digest,
        contract.evaluation.manifest_digest,
        oracle_digest,
        verification_digest,
    }
    assert len(role_digests) == 8

    with pytest.raises(FamilySplitError, match="globally distinct"):
        _compile(evaluation=replace(evaluation, manifest_digest=control.artifact_digest))

    with pytest.raises(FamilySplitError, match="globally distinct"):
        _compile(evaluation=replace(evaluation, artifact_digest=foundry.manifest_digest))

    with pytest.raises(FamilySplitError, match="globally distinct"):
        _compile(foundry=replace(foundry, manifest_digest=control.artifact_digest))

    with pytest.raises(FamilySplitError, match="globally distinct"):
        _compile(
            foundry=replace(
                foundry,
                executable_oracle_evidence_digest=control.artifact_digest,
            )
        )

    with pytest.raises(FamilySplitError, match="globally distinct"):
        _compile(
            foundry=replace(
                foundry,
                independent_verification_evidence_digest=evaluation.manifest_digest,
            )
        )


def test_each_artifact_is_distinct_from_its_manifest() -> None:
    _, control, _, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="curriculum artifact and manifest"):
        replace(control, manifest_digest=control.artifact_digest)

    with pytest.raises(FamilySplitError, match="evaluation artifact and manifest"):
        replace(evaluation, manifest_digest=evaluation.artifact_digest)


def test_raw_runtime_types_and_exact_source_commit_fail_closed() -> None:
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

    with pytest.raises(FamilySplitError, match="Git commit digest"):
        replace(contract, source_commit="main")

    with pytest.raises(FamilySplitError, match="tokenizer_revision_digest"):
        replace(contract, tokenizer_revision_digest=cast(str, object()))

    with pytest.raises(FamilySplitError, match="selection_contract must be"):
        replace(contract, selection_contract=cast(E1ExperimentContract, object()))

    with pytest.raises(FamilySplitError, match="source commits must match"):
        _compile(source_commit="0" * 40)

    assert selection.source_commit == _SOURCE_COMMIT


def test_metric_bearing_evaluation_is_development_only() -> None:
    _, _, _, evaluation = _artifacts()

    with pytest.raises(FamilySplitError, match="development only"):
        replace(evaluation, split=E1Split.TRAIN)


def test_contract_digest_binds_artifacts_metrics_tokenizer_and_selection() -> None:
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
    changed_selection = _compile(selection=_selection(release="e1-selection/changed"))

    assert changed_control.contract_digest != baseline.contract_digest
    assert changed_metric.contract_digest != baseline.contract_digest
    assert changed_tokenizer.contract_digest != baseline.contract_digest
    assert changed_selection.contract_digest != baseline.contract_digest


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
