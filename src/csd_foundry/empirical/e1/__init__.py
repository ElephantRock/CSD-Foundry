"""E1 executable-semantics experiment contracts and artifact compilation."""

from csd_foundry.empirical.e1.curriculum_evaluation_contract import (
    E1CurriculumArm,
    E1CurriculumArtifact,
    E1CurriculumEvaluationContract,
    E1EvaluationArtifact,
    E1LabelAuthority,
    compile_e1_curriculum_evaluation_contract,
)
from csd_foundry.empirical.e1.execution_splits import (
    E1Split,
    FamilySplitAssignment,
    FamilySplitError,
    FamilySplitManifest,
    ScenarioFamilyIdentity,
    compile_family_split_manifest,
    derive_scenario_family_identity,
)
from csd_foundry.empirical.e1.experiment_contract import (
    E1ExperimentContract,
    compile_e1_experiment_contract,
)
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    ArtifactFile,
    E1ArtifactError,
    E1ArtifactValidationReport,
    E1FoundryArtifactBundle,
    compile_e1_foundry_artifacts,
    e1_task_format,
    e1_task_format_digest,
    load_artifact_records,
    validate_e1_foundry_artifacts,
    write_e1_foundry_artifacts,
)

__all__ = [
    "ArtifactFile",
    "E1ArtifactError",
    "E1ArtifactValidationReport",
    "E1CurriculumArm",
    "E1CurriculumArtifact",
    "E1CurriculumEvaluationContract",
    "E1EvaluationArtifact",
    "E1ExperimentContract",
    "E1FoundryArtifactBundle",
    "E1LabelAuthority",
    "E1Split",
    "FamilySplitAssignment",
    "FamilySplitError",
    "FamilySplitManifest",
    "ScenarioFamilyIdentity",
    "compile_e1_curriculum_evaluation_contract",
    "compile_e1_experiment_contract",
    "compile_e1_foundry_artifacts",
    "compile_family_split_manifest",
    "derive_scenario_family_identity",
    "e1_task_format",
    "e1_task_format_digest",
    "load_artifact_records",
    "validate_e1_foundry_artifacts",
    "write_e1_foundry_artifacts",
]
