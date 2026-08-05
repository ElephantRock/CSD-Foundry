"""E1 executable-semantics experiment contracts."""

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

__all__ = [
    "E1CurriculumArm",
    "E1CurriculumArtifact",
    "E1CurriculumEvaluationContract",
    "E1EvaluationArtifact",
    "E1ExperimentContract",
    "E1LabelAuthority",
    "E1Split",
    "FamilySplitAssignment",
    "FamilySplitError",
    "FamilySplitManifest",
    "ScenarioFamilyIdentity",
    "compile_e1_curriculum_evaluation_contract",
    "compile_e1_experiment_contract",
    "compile_family_split_manifest",
    "derive_scenario_family_identity",
]
