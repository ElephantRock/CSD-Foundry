"""Paired curriculum and evaluation contract for the bounded E1 learning probe."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.empirical.e1.execution_splits import E1Split, FamilySplitError
from csd_foundry.empirical.e1.experiment_contract import E1ExperimentContract
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_CONTRACT_SCHEMA_VERSION = "e1-curriculum-evaluation-contract/1"
_PRIMARY_METRIC_ID = "structural-holdout-exact-semantic-decision-accuracy/family-macro/1"
_SAFETY_METRIC_ID = "clean-case-regression/base-and-control/1"
_PERMITTED_LIVE_TELEMETRY = (
    "checkpoint_creation",
    "crashes_and_non_finite_values",
    "gpu_memory",
    "gpu_utilization",
    "storage_and_publication_failures",
    "throughput",
    "training_loss",
)
_PROTECTED_METRIC_VISIBILITY = "after_all_predetermined_checkpoints_complete"
_CLAIM_BOUNDARY = (
    "This contract fixes the paired E1 curriculum and development-evaluation identities, "
    "comparison invariants, metric identities, and no-peeking boundary. It does not "
    "authorize GPU execution, establish that any artifact is pedagogically effective, "
    "represent the external Phase 10 blind holdout, or establish general reasoning transfer."
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class E1CurriculumArm(StrEnum):
    """The two initial E1 training conditions."""

    CONTROL = "control"
    FOUNDRY = "foundry"


class E1LabelAuthority(StrEnum):
    """The permitted source of curriculum labels for each arm."""

    CONVENTIONAL_SYNTHETIC = "conventional_synthetic"
    EXECUTABLE_SEMANTICS = "executable_semantics"


def _require_digest(value: str, *, field: str) -> None:
    if _SHA256_HEX.fullmatch(value) is None:
        raise FamilySplitError(f"{field} must be a lowercase SHA-256 hex digest")


def _require_canonical_ids(values: tuple[str, ...], *, field: str) -> None:
    if not values:
        raise FamilySplitError(f"{field} must be nonempty")
    if any(not value.strip() for value in values):
        raise FamilySplitError(f"{field} must contain only nonempty identifiers")
    if len(values) != len(set(values)):
        raise FamilySplitError(f"{field} must contain unique identifiers")
    if values != tuple(sorted(values)):
        raise FamilySplitError(f"{field} must be sorted")


@dataclass(frozen=True, slots=True)
class E1CurriculumArtifact:
    """One digest-bound E1 training curriculum."""

    arm: E1CurriculumArm
    label_authority: E1LabelAuthority
    artifact_digest: str
    manifest_digest: str
    generation_command_digest: str
    validation_command_digest: str
    task_format_digest: str
    scenario_ids: tuple[str, ...]
    record_count: int
    token_count: int
    executable_oracle_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.arm, E1CurriculumArm):
            raise FamilySplitError("curriculum arm must be an E1CurriculumArm")
        if not isinstance(self.label_authority, E1LabelAuthority):
            raise FamilySplitError("label authority must be an E1LabelAuthority")
        for field, value in (
            ("artifact_digest", self.artifact_digest),
            ("manifest_digest", self.manifest_digest),
            ("generation_command_digest", self.generation_command_digest),
            ("validation_command_digest", self.validation_command_digest),
            ("task_format_digest", self.task_format_digest),
        ):
            _require_digest(value, field=field)
        _require_canonical_ids(self.scenario_ids, field="curriculum scenario_ids")
        if self.record_count <= 0:
            raise FamilySplitError("curriculum record_count must be positive")
        if self.token_count <= 0:
            raise FamilySplitError("curriculum token_count must be positive")

        if self.arm is E1CurriculumArm.CONTROL:
            if self.label_authority is not E1LabelAuthority.CONVENTIONAL_SYNTHETIC:
                raise FamilySplitError("control labels must be conventional synthetic labels")
            if self.executable_oracle_evidence_digest is not None:
                raise FamilySplitError("control curriculum may not cite executable-oracle evidence")
        else:
            if self.label_authority is not E1LabelAuthority.EXECUTABLE_SEMANTICS:
                raise FamilySplitError("Foundry labels must come from executable semantics")
            if self.executable_oracle_evidence_digest is None:
                raise FamilySplitError("Foundry curriculum requires executable-oracle evidence")
            _require_digest(
                self.executable_oracle_evidence_digest,
                field="executable_oracle_evidence_digest",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm.value,
            "label_authority": self.label_authority.value,
            "artifact_digest": self.artifact_digest,
            "manifest_digest": self.manifest_digest,
            "generation_command_digest": self.generation_command_digest,
            "validation_command_digest": self.validation_command_digest,
            "task_format_digest": self.task_format_digest,
            "scenario_ids": list(self.scenario_ids),
            "record_count": self.record_count,
            "token_count": self.token_count,
            "executable_oracle_evidence_digest": self.executable_oracle_evidence_digest,
        }


@dataclass(frozen=True, slots=True)
class E1EvaluationArtifact:
    """Shared, development-only metric-bearing evaluation artifact."""

    split: E1Split
    artifact_digest: str
    manifest_digest: str
    generation_command_digest: str
    validation_command_digest: str
    scenario_ids: tuple[str, ...]
    record_count: int
    family_count: int
    primary_metric_implementation_digest: str
    safety_metric_implementation_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.split, E1Split):
            raise FamilySplitError("evaluation split must be an E1Split")
        if self.split is not E1Split.DEVELOPMENT:
            raise FamilySplitError("E1 metric-bearing evaluation must use development only")
        for field, value in (
            ("artifact_digest", self.artifact_digest),
            ("manifest_digest", self.manifest_digest),
            ("generation_command_digest", self.generation_command_digest),
            ("validation_command_digest", self.validation_command_digest),
            (
                "primary_metric_implementation_digest",
                self.primary_metric_implementation_digest,
            ),
            (
                "safety_metric_implementation_digest",
                self.safety_metric_implementation_digest,
            ),
        ):
            _require_digest(value, field=field)
        _require_canonical_ids(self.scenario_ids, field="evaluation scenario_ids")
        if self.record_count <= 0:
            raise FamilySplitError("evaluation record_count must be positive")
        if self.family_count <= 0:
            raise FamilySplitError("evaluation family_count must be positive")
        if self.family_count > len(self.scenario_ids):
            raise FamilySplitError("evaluation family_count may not exceed scenario count")

    def to_dict(self) -> dict[str, object]:
        return {
            "split": self.split.value,
            "artifact_digest": self.artifact_digest,
            "manifest_digest": self.manifest_digest,
            "generation_command_digest": self.generation_command_digest,
            "validation_command_digest": self.validation_command_digest,
            "scenario_ids": list(self.scenario_ids),
            "record_count": self.record_count,
            "family_count": self.family_count,
            "primary_metric_implementation_digest": self.primary_metric_implementation_digest,
            "safety_metric_implementation_digest": self.safety_metric_implementation_digest,
        }


@dataclass(frozen=True, slots=True)
class E1CurriculumEvaluationContract:
    """Digest-bound paired-curriculum and development-evaluation contract."""

    release: str
    source_commit: str
    selection_contract_digest: str
    training_scenario_ids: tuple[str, ...]
    development_scenario_ids: tuple[str, ...]
    control: E1CurriculumArtifact
    foundry: E1CurriculumArtifact
    evaluation: E1EvaluationArtifact

    def __post_init__(self) -> None:
        if not self.release.strip():
            raise FamilySplitError("E1 curriculum/evaluation release must be nonempty")
        if not self.source_commit.strip():
            raise FamilySplitError("E1 curriculum/evaluation source_commit must be nonempty")
        _require_digest(self.selection_contract_digest, field="selection_contract_digest")
        _require_canonical_ids(self.training_scenario_ids, field="training_scenario_ids")
        _require_canonical_ids(
            self.development_scenario_ids,
            field="development_scenario_ids",
        )
        overlap = sorted(set(self.training_scenario_ids) & set(self.development_scenario_ids))
        if overlap:
            raise FamilySplitError(
                f"training and development scenario identifiers overlap: {overlap}"
            )
        if self.control.arm is not E1CurriculumArm.CONTROL:
            raise FamilySplitError("control field must contain the control curriculum")
        if self.foundry.arm is not E1CurriculumArm.FOUNDRY:
            raise FamilySplitError("foundry field must contain the Foundry curriculum")
        if self.control.scenario_ids != self.training_scenario_ids:
            raise FamilySplitError("control curriculum does not match training scenarios")
        if self.foundry.scenario_ids != self.training_scenario_ids:
            raise FamilySplitError("Foundry curriculum does not match training scenarios")
        if self.evaluation.scenario_ids != self.development_scenario_ids:
            raise FamilySplitError("evaluation artifact does not match development scenarios")
        if self.control.token_count != self.foundry.token_count:
            raise FamilySplitError("control and Foundry curricula must be token matched")
        if self.control.task_format_digest != self.foundry.task_format_digest:
            raise FamilySplitError("control and Foundry curricula must be task-format matched")

    def _digest_payload(self) -> dict[str, object]:
        return {
            "schema_version": _CONTRACT_SCHEMA_VERSION,
            "release": self.release,
            "source_commit": self.source_commit,
            "selection_contract_digest": self.selection_contract_digest,
            "training_scenario_ids": list(self.training_scenario_ids),
            "development_scenario_ids": list(self.development_scenario_ids),
            "control": self.control.to_dict(),
            "foundry": self.foundry.to_dict(),
            "evaluation": self.evaluation.to_dict(),
            "primary_metric_id": _PRIMARY_METRIC_ID,
            "safety_metric_id": _SAFETY_METRIC_ID,
            "primary_aggregation_unit": "symbolic_scenario_family",
            "permitted_live_telemetry": list(_PERMITTED_LIVE_TELEMETRY),
            "protected_metric_visibility": _PROTECTED_METRIC_VISIBILITY,
            "claim_boundary": _CLAIM_BOUNDARY,
        }

    @property
    def contract_digest(self) -> str:
        return canonical_sha256(self._digest_payload())

    def to_dict(self) -> dict[str, object]:
        return {**self._digest_payload(), "contract_digest": self.contract_digest}


def _scenario_ids_for_split(
    selection_contract: E1ExperimentContract,
    split: E1Split,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            scenario_id
            for assignment in selection_contract.split_manifest.assignments
            if assignment.split is split
            for scenario_id in assignment.scenario_ids
        )
    )


def compile_e1_curriculum_evaluation_contract(
    selection_contract: E1ExperimentContract,
    *,
    release: str,
    source_commit: str,
    control: E1CurriculumArtifact,
    foundry: E1CurriculumArtifact,
    evaluation: E1EvaluationArtifact,
) -> E1CurriculumEvaluationContract:
    """Bind paired curricula and shared development evaluation to one E1 selection."""

    if source_commit != selection_contract.source_commit:
        raise FamilySplitError("curriculum/evaluation and selection source commits must match")
    training_scenario_ids = _scenario_ids_for_split(selection_contract, E1Split.TRAIN)
    development_scenario_ids = _scenario_ids_for_split(
        selection_contract,
        E1Split.DEVELOPMENT,
    )
    return E1CurriculumEvaluationContract(
        release=release,
        source_commit=source_commit,
        selection_contract_digest=selection_contract.contract_digest,
        training_scenario_ids=training_scenario_ids,
        development_scenario_ids=development_scenario_ids,
        control=control,
        foundry=foundry,
        evaluation=evaluation,
    )
