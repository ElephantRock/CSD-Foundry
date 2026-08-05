"""Compile conventional-control artifacts and finalize the paired E1 contract."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e1.curriculum_evaluation_contract import (
    E1CurriculumArm,
    E1CurriculumArtifact,
    E1CurriculumEvaluationContract,
    E1EvaluationArtifact,
    E1LabelAuthority,
    compile_e1_curriculum_evaluation_contract,
)
from csd_foundry.empirical.e1.execution_splits import E1Split
from csd_foundry.empirical.e1.experiment_contract import E1ExperimentContract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    ArtifactFile,
    E1FoundryArtifactBundle,
    load_artifact_records,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    load_json_text,
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_CONTROL_PREFIX = "e1-control/"
_FOUNDRY_PREFIX = "e1-foundry/"
_CLAIM_BOUNDARY = (
    "The conventional-control artifact preserves the exact Foundry prompt inventory and task "
    "format while accepting externally generated canonical-JSON targets without executable-"
    "oracle, invariant, or mutation-derived semantic validation. Paired finalization establishes "
    "artifact identity, prompt pairing, tokenizer-count coverage, no-truncation eligibility, and "
    "equal exact token budgets under one tokenizer revision. It does not establish control label "
    "correctness, authorize GPU execution, expose protected metrics, or establish learning value."
)
_CONTROL_FILES = {
    "prompts": "control_prompts.jsonl",
    "train": "control_train.jsonl",
    "generation": "conventional_generation_evidence.json",
    "manifest": "control_curriculum_manifest.json",
}
_PAIRED_FILES = {
    "contract": "paired_e1_contract.json",
    "manifest": "paired_e1_manifest.json",
}
_PROHIBITED_CONTROL_FIELDS = {
    "reference_label",
    "executable_oracle_receipt_digest",
    "independent_verification_receipt_digest",
}


class E1ControlArtifactError(ValueError):
    """Raised when conventional-control or paired artifacts fail closed validation."""


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise E1ControlArtifactError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise E1ControlArtifactError(f"{field} must be a positive integer")
    return value


def _control_record_id(foundry_record_id: str) -> str:
    if not foundry_record_id.startswith(_FOUNDRY_PREFIX):
        raise E1ControlArtifactError(
            f"Foundry record identifier has wrong prefix: {foundry_record_id}"
        )
    return _CONTROL_PREFIX + foundry_record_id.removeprefix(_FOUNDRY_PREFIX)


def _canonical_target(target: object, *, record_id: str) -> str:
    if not isinstance(target, str) or not target:
        raise E1ControlArtifactError(f"{record_id}: target must be a nonempty string")
    try:
        parsed = load_json_text(target)
    except (TypeError, ValueError) as exc:
        raise E1ControlArtifactError(f"{record_id}: target is not canonical JSON") from exc
    if canonical_json_text(parsed) != target:
        raise E1ControlArtifactError(f"{record_id}: target bytes are not canonical JSON")
    return target


def _jsonl(records: tuple[dict[str, object], ...]) -> bytes:
    return b"".join(canonical_json_bytes(record) for record in records)


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ConventionalControlResponse:
    """One externally generated conventional target for an exact control prompt."""

    record_id: str
    target: str

    def __post_init__(self) -> None:
        if not self.record_id.startswith(_CONTROL_PREFIX):
            raise E1ControlArtifactError("control response record_id has the wrong prefix")
        _canonical_target(self.target, record_id=self.record_id)

    def to_dict(self) -> dict[str, object]:
        return {"record_id": self.record_id, "target": self.target}


@dataclass(frozen=True, slots=True)
class TokenizedRecordCount:
    """Exact raw tokenizer count for one serialized training record."""

    record_id: str
    raw_token_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.record_id, str) or not self.record_id:
            raise E1ControlArtifactError("tokenized record_id must be nonempty")
        _require_positive_int(self.raw_token_count, field="raw_token_count")

    def to_dict(self) -> dict[str, object]:
        return {"record_id": self.record_id, "raw_token_count": self.raw_token_count}


@dataclass(frozen=True, slots=True)
class E1TokenCountInventory:
    """Artifact- and tokenizer-bound no-truncation evidence for both E1 arms."""

    tokenizer_revision_digest: str
    counting_command_digest: str
    control_artifact_digest: str
    foundry_artifact_digest: str
    context_length: int
    control: tuple[TokenizedRecordCount, ...]
    foundry: tuple[TokenizedRecordCount, ...]

    def __post_init__(self) -> None:
        _require_digest(self.tokenizer_revision_digest, field="tokenizer_revision_digest")
        _require_digest(self.counting_command_digest, field="counting_command_digest")
        _require_digest(self.control_artifact_digest, field="control_artifact_digest")
        _require_digest(self.foundry_artifact_digest, field="foundry_artifact_digest")
        if self.control_artifact_digest == self.foundry_artifact_digest:
            raise E1ControlArtifactError("control and Foundry artifact digests must differ")
        _require_positive_int(self.context_length, field="context_length")
        self._validate_side(self.control, prefix=_CONTROL_PREFIX, field="control")
        self._validate_side(self.foundry, prefix=_FOUNDRY_PREFIX, field="foundry")
        if len(self.control) != len(self.foundry):
            raise E1ControlArtifactError(
                "control and Foundry token inventories must contain the same record count"
            )
        if self.control_token_count != self.foundry_token_count:
            raise E1ControlArtifactError(
                "control and Foundry token inventories must have equal exact token counts"
            )

    def _validate_side(
        self,
        values: tuple[TokenizedRecordCount, ...],
        *,
        prefix: str,
        field: str,
    ) -> None:
        if not isinstance(values, tuple) or not values:
            raise E1ControlArtifactError(f"{field} token counts must be a nonempty tuple")
        if any(not isinstance(item, TokenizedRecordCount) for item in values):
            raise E1ControlArtifactError(f"{field} token counts contain an invalid record")
        ids = tuple(item.record_id for item in values)
        if any(not record_id.startswith(prefix) for record_id in ids):
            raise E1ControlArtifactError(f"{field} token counts use a wrong record prefix")
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise E1ControlArtifactError(f"{field} token record IDs must be sorted and unique")
        too_long = tuple(
            item.record_id for item in values if item.raw_token_count > self.context_length
        )
        if too_long:
            raise E1ControlArtifactError(
                f"{field} records exceed context_length and would be truncated: {too_long}"
            )

    @property
    def control_token_count(self) -> int:
        return sum(item.raw_token_count for item in self.control)

    @property
    def foundry_token_count(self) -> int:
        return sum(item.raw_token_count for item in self.foundry)

    @property
    def token_count_per_arm(self) -> int:
        if self.control_token_count != self.foundry_token_count:
            raise E1ControlArtifactError("token inventories are not exactly matched")
        return self.control_token_count

    @property
    def inventory_digest(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e1-token-count-inventory/1",
            "tokenizer_revision_digest": self.tokenizer_revision_digest,
            "counting_command_digest": self.counting_command_digest,
            "control_artifact_digest": self.control_artifact_digest,
            "foundry_artifact_digest": self.foundry_artifact_digest,
            "context_length": self.context_length,
            "token_count_per_arm": self.token_count_per_arm,
            "control": [item.to_dict() for item in self.control],
            "foundry": [item.to_dict() for item in self.foundry],
        }


@dataclass(frozen=True, slots=True)
class E1ControlArtifactBundle:
    """Deterministic conventional-control prompts, responses, and curriculum bytes."""

    release: str
    source_commit: str
    selection_contract_digest: str
    generator_revision_digest: str
    generation_command_digest: str
    validation_command_digest: str
    task_format_digest: str
    scenario_ids: tuple[str, ...]
    record_ids: tuple[str, ...]
    files: tuple[ArtifactFile, ...]

    def file(self, path: str) -> ArtifactFile:
        for item in self.files:
            if item.path == path:
                return item
        raise KeyError(path)

    @property
    def record_count(self) -> int:
        return len(self.record_ids)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e1-control-artifact-bundle/1",
            "release": self.release,
            "source_commit": self.source_commit,
            "selection_contract_digest": self.selection_contract_digest,
            "generator_revision_digest": self.generator_revision_digest,
            "generation_command_digest": self.generation_command_digest,
            "validation_command_digest": self.validation_command_digest,
            "task_format_digest": self.task_format_digest,
            "scenario_ids": list(self.scenario_ids),
            "record_ids": list(self.record_ids),
            "record_count": self.record_count,
            "files": [item.receipt() for item in self.files],
            "claim_boundary": _CLAIM_BOUNDARY,
        }


@dataclass(frozen=True, slots=True)
class E1PairedArtifactBundle:
    """Final paired contract plus tokenizer and artifact evidence."""

    contract: E1CurriculumEvaluationContract
    token_inventory: E1TokenCountInventory
    files: tuple[ArtifactFile, ...]

    def file(self, path: str) -> ArtifactFile:
        for item in self.files:
            if item.path == path:
                return item
        raise KeyError(path)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e1-paired-artifact-bundle/1",
            "contract_digest": self.contract.contract_digest,
            "token_inventory_digest": self.token_inventory.inventory_digest,
            "token_inventory": self.token_inventory.to_dict(),
            "files": [item.receipt() for item in self.files],
            "claim_boundary": _CLAIM_BOUNDARY,
        }


def _prompt_records(
    foundry: E1FoundryArtifactBundle,
) -> tuple[dict[str, object], ...]:
    records = load_artifact_records(foundry.file("foundry_train.jsonl").content)
    prompts: list[dict[str, object]] = []
    for record in records:
        foundry_record_id = str(record.get("record_id", ""))
        if record.get("label_authority") != "executable_semantics":
            raise E1ControlArtifactError(
                f"{foundry_record_id}: Foundry label authority is not executable semantics"
            )
        prompt_messages = record.get("prompt_messages")
        if not isinstance(prompt_messages, list):
            raise E1ControlArtifactError(f"{foundry_record_id}: prompt_messages is not a list")
        prompts.append(
            {
                "schema_version": "e1-conventional-control-prompt/1",
                "record_id": _control_record_id(foundry_record_id),
                "paired_foundry_record_id": foundry_record_id,
                "split": record.get("split"),
                "scenario_id": record.get("scenario_id"),
                "family_digest": record.get("family_digest"),
                "case_id": record.get("case_id"),
                "case_type": record.get("case_type"),
                "task_format_digest": record.get("task_format_digest"),
                "prompt_messages": prompt_messages,
            }
        )
    return tuple(sorted(prompts, key=lambda item: str(item["record_id"])))


def compile_e1_control_prompts(
    foundry: E1FoundryArtifactBundle,
) -> ArtifactFile:
    """Compile the exact conventional-control prompt inventory from Foundry prompts."""

    prompts = _prompt_records(foundry)
    if not prompts:
        raise E1ControlArtifactError("Foundry training artifact contains no prompts")
    return ArtifactFile(
        _CONTROL_FILES["prompts"],
        "conventional_control_prompt_inventory",
        _jsonl(prompts),
        len(prompts),
    )


def compile_e1_conventional_control(
    foundry: E1FoundryArtifactBundle,
    responses: tuple[ConventionalControlResponse, ...],
    *,
    release: str,
    generator_revision_digest: str,
    generation_command_digest: str,
    validation_command_digest: str,
) -> E1ControlArtifactBundle:
    """Bind externally generated conventional labels to the exact Foundry prompts."""

    if not release.strip():
        raise E1ControlArtifactError("control release must be nonempty")
    _require_digest(generator_revision_digest, field="generator_revision_digest")
    _require_digest(generation_command_digest, field="generation_command_digest")
    _require_digest(validation_command_digest, field="validation_command_digest")
    prompt_file = compile_e1_control_prompts(foundry)
    prompt_records = load_artifact_records(prompt_file.content)
    prompt_by_id = {str(record["record_id"]): record for record in prompt_records}
    response_ids = tuple(response.record_id for response in responses)
    if response_ids != tuple(sorted(response_ids)) or len(response_ids) != len(set(response_ids)):
        raise E1ControlArtifactError("control response IDs must be sorted and unique")
    expected_ids = tuple(sorted(prompt_by_id))
    if response_ids != expected_ids:
        missing = tuple(sorted(set(expected_ids) - set(response_ids)))
        extra = tuple(sorted(set(response_ids) - set(expected_ids)))
        raise E1ControlArtifactError(
            f"control responses do not exactly cover prompts; missing={missing}, extra={extra}"
        )

    records: list[dict[str, object]] = []
    response_evidence: list[dict[str, object]] = []
    for response in responses:
        prompt = prompt_by_id[response.record_id]
        target = _canonical_target(response.target, record_id=response.record_id)
        records.append(
            {
                **prompt,
                "schema_version": "e1-conventional-control-record/1",
                "label_authority": "conventional_synthetic",
                "target": target,
            }
        )
        response_evidence.append(
            {
                "record_id": response.record_id,
                "target_digest": canonical_sha256(load_json_text(target)),
            }
        )
    control_records = tuple(sorted(records, key=lambda item: str(item["record_id"])))
    train_file = ArtifactFile(
        _CONTROL_FILES["train"],
        "conventional_control_training_curriculum",
        _jsonl(control_records),
        len(control_records),
    )
    generation_file = ArtifactFile(
        _CONTROL_FILES["generation"],
        "conventional_generation_evidence",
        canonical_json_bytes(
            {
                "schema_version": "e1-conventional-generation-evidence/1",
                "release": release,
                "source_commit": foundry.source_commit,
                "selection_contract_digest": foundry.selection_contract_digest,
                "generator_revision_digest": generator_revision_digest,
                "generation_command_digest": generation_command_digest,
                "record_count": len(response_evidence),
                "responses": response_evidence,
                "semantic_validation": "not_performed_by_design",
            }
        ),
    )
    scenario_ids = tuple(sorted({str(record["scenario_id"]) for record in control_records}))
    record_ids = tuple(str(record["record_id"]) for record in control_records)
    manifest_payload = {
        "schema_version": "e1-control-curriculum-manifest/1",
        "release": release,
        "source_commit": foundry.source_commit,
        "selection_contract_digest": foundry.selection_contract_digest,
        "generator_revision_digest": generator_revision_digest,
        "generation_command_digest": generation_command_digest,
        "validation_command_digest": validation_command_digest,
        "task_format_digest": foundry.task_format_digest,
        "scenario_ids": list(scenario_ids),
        "scenario_count": len(scenario_ids),
        "record_ids": list(record_ids),
        "record_count": len(record_ids),
        "label_authority": "conventional_synthetic",
        "prompt_inventory": prompt_file.receipt(),
        "artifact": train_file.receipt(),
        "generation_evidence": generation_file.receipt(),
        "executable_oracle_evidence": None,
        "independent_verification_evidence": None,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    manifest_file = ArtifactFile(
        _CONTROL_FILES["manifest"],
        "conventional_control_curriculum_manifest",
        canonical_json_bytes(manifest_payload),
    )
    role_digests = {
        prompt_file.sha256,
        train_file.sha256,
        generation_file.sha256,
        manifest_file.sha256,
    }
    if len(role_digests) != 4:
        raise E1ControlArtifactError(
            "control prompt, artifact, evidence, and manifest digests must differ"
        )
    return E1ControlArtifactBundle(
        release=release,
        source_commit=foundry.source_commit,
        selection_contract_digest=foundry.selection_contract_digest,
        generator_revision_digest=generator_revision_digest,
        generation_command_digest=generation_command_digest,
        validation_command_digest=validation_command_digest,
        task_format_digest=foundry.task_format_digest,
        scenario_ids=scenario_ids,
        record_ids=record_ids,
        files=tuple(
            sorted(
                (prompt_file, train_file, generation_file, manifest_file),
                key=lambda item: item.path,
            )
        ),
    )


def _token_ids(values: tuple[TokenizedRecordCount, ...]) -> tuple[str, ...]:
    return tuple(item.record_id for item in values)


def _validate_paired_records(
    foundry_records: tuple[dict[str, object], ...],
    control_records: tuple[dict[str, object], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    foundry_ids = tuple(str(record.get("record_id", "")) for record in foundry_records)
    control_ids = tuple(str(record.get("record_id", "")) for record in control_records)
    expected_control_ids = tuple(_control_record_id(record_id) for record_id in foundry_ids)
    if control_ids != expected_control_ids:
        raise E1ControlArtifactError("control records do not pair one-to-one with Foundry records")
    paired_fields = (
        "split",
        "scenario_id",
        "family_digest",
        "case_id",
        "case_type",
        "task_format_digest",
        "prompt_messages",
    )
    for foundry_record, control_record in zip(
        foundry_records, control_records, strict=True
    ):
        control_id = str(control_record["record_id"])
        if control_record.get("paired_foundry_record_id") != foundry_record["record_id"]:
            raise E1ControlArtifactError(f"{control_id}: paired Foundry record ID mismatch")
        if control_record.get("label_authority") != "conventional_synthetic":
            raise E1ControlArtifactError(f"{control_id}: control label authority mismatch")
        prohibited = sorted(_PROHIBITED_CONTROL_FIELDS & set(control_record))
        if prohibited:
            raise E1ControlArtifactError(
                f"{control_id}: control record carries prohibited Foundry fields: {prohibited}"
            )
        for field in paired_fields:
            if control_record.get(field) != foundry_record.get(field):
                raise E1ControlArtifactError(f"{control_id}: paired field mismatch: {field}")
        _canonical_target(control_record.get("target"), record_id=control_id)
    return foundry_ids, control_ids


def finalize_e1_paired_artifacts(
    selection: E1ExperimentContract,
    foundry: E1FoundryArtifactBundle,
    control: E1ControlArtifactBundle,
    token_inventory: E1TokenCountInventory,
    *,
    release: str,
    source_commit: str,
    primary_metric_implementation_digest: str,
    safety_metric_implementation_digest: str,
) -> E1PairedArtifactBundle:
    """Instantiate the paired PR #74 contract from real arm and evaluation digests."""

    _require_digest(
        primary_metric_implementation_digest,
        field="primary_metric_implementation_digest",
    )
    _require_digest(
        safety_metric_implementation_digest,
        field="safety_metric_implementation_digest",
    )
    if source_commit != selection.source_commit or source_commit != foundry.source_commit:
        raise E1ControlArtifactError("selection, Foundry, and paired source commits must match")
    if control.source_commit != source_commit:
        raise E1ControlArtifactError("control and paired source commits must match")
    if foundry.selection_contract_digest != selection.contract_digest:
        raise E1ControlArtifactError("Foundry selection contract digest mismatch")
    if control.selection_contract_digest != selection.contract_digest:
        raise E1ControlArtifactError("control selection contract digest mismatch")
    if control.task_format_digest != foundry.task_format_digest:
        raise E1ControlArtifactError("control and Foundry task formats differ")

    foundry_train = foundry.file("foundry_train.jsonl")
    control_train = control.file("control_train.jsonl")
    if token_inventory.control_artifact_digest != control_train.sha256:
        raise E1ControlArtifactError("control tokenizer inventory artifact digest mismatch")
    if token_inventory.foundry_artifact_digest != foundry_train.sha256:
        raise E1ControlArtifactError("Foundry tokenizer inventory artifact digest mismatch")
    foundry_records = load_artifact_records(foundry_train.content)
    control_records = load_artifact_records(control_train.content)
    foundry_ids, control_ids = _validate_paired_records(foundry_records, control_records)
    if _token_ids(token_inventory.control) != control_ids:
        raise E1ControlArtifactError("control tokenizer inventory does not cover exact records")
    if _token_ids(token_inventory.foundry) != foundry_ids:
        raise E1ControlArtifactError("Foundry tokenizer inventory does not cover exact records")
    token_count = token_inventory.token_count_per_arm

    training_scenario_ids = foundry.training_scenario_ids
    if control.scenario_ids != training_scenario_ids:
        raise E1ControlArtifactError("control scenario membership differs from Foundry")
    control_artifact = E1CurriculumArtifact(
        arm=E1CurriculumArm.CONTROL,
        label_authority=E1LabelAuthority.CONVENTIONAL_SYNTHETIC,
        artifact_digest=control_train.sha256,
        manifest_digest=control.file("control_curriculum_manifest.json").sha256,
        generation_command_digest=control.generation_command_digest,
        validation_command_digest=control.validation_command_digest,
        task_format_digest=control.task_format_digest,
        scenario_ids=control.scenario_ids,
        record_count=control.record_count,
        token_count=token_count,
    )
    foundry_artifact = E1CurriculumArtifact(
        arm=E1CurriculumArm.FOUNDRY,
        label_authority=E1LabelAuthority.EXECUTABLE_SEMANTICS,
        artifact_digest=foundry_train.sha256,
        manifest_digest=foundry.file("foundry_curriculum_manifest.json").sha256,
        generation_command_digest=foundry.generation_command_digest,
        validation_command_digest=foundry.validation_command_digest,
        task_format_digest=foundry.task_format_digest,
        scenario_ids=foundry.training_scenario_ids,
        record_count=foundry.training_record_count,
        token_count=token_count,
        executable_oracle_evidence_digest=foundry.file(
            "executable_oracle_evidence.json"
        ).sha256,
        independent_verification_evidence_digest=foundry.file(
            "independent_verification_evidence.json"
        ).sha256,
    )
    evaluation = E1EvaluationArtifact(
        split=E1Split.DEVELOPMENT,
        artifact_digest=foundry.file("development_evaluation.jsonl").sha256,
        manifest_digest=foundry.file("development_evaluation_manifest.json").sha256,
        generation_command_digest=foundry.generation_command_digest,
        validation_command_digest=foundry.validation_command_digest,
        scenario_ids=foundry.development_scenario_ids,
        record_count=foundry.development_record_count,
        family_count=foundry.development_family_count,
        primary_metric_implementation_digest=primary_metric_implementation_digest,
        safety_metric_implementation_digest=safety_metric_implementation_digest,
    )
    contract = compile_e1_curriculum_evaluation_contract(
        selection,
        release=release,
        source_commit=source_commit,
        tokenizer_revision_digest=token_inventory.tokenizer_revision_digest,
        control=control_artifact,
        foundry=foundry_artifact,
        evaluation=evaluation,
    )
    contract_file = ArtifactFile(
        _PAIRED_FILES["contract"],
        "paired_e1_contract",
        canonical_json_bytes(contract.to_dict()),
    )
    manifest_file = ArtifactFile(
        _PAIRED_FILES["manifest"],
        "paired_e1_manifest",
        canonical_json_bytes(
            {
                "schema_version": "e1-paired-artifact-manifest/1",
                "release": release,
                "source_commit": source_commit,
                "selection_contract_digest": selection.contract_digest,
                "contract": contract_file.receipt(),
                "control_artifact": control_train.receipt(),
                "control_manifest": control.file(
                    "control_curriculum_manifest.json"
                ).receipt(),
                "foundry_artifact": foundry_train.receipt(),
                "foundry_manifest": foundry.file(
                    "foundry_curriculum_manifest.json"
                ).receipt(),
                "development_evaluation": foundry.file(
                    "development_evaluation.jsonl"
                ).receipt(),
                "development_manifest": foundry.file(
                    "development_evaluation_manifest.json"
                ).receipt(),
                "executable_oracle_evidence": foundry.file(
                    "executable_oracle_evidence.json"
                ).receipt(),
                "independent_verification_evidence": foundry.file(
                    "independent_verification_evidence.json"
                ).receipt(),
                "token_inventory": token_inventory.to_dict(),
                "token_inventory_digest": token_inventory.inventory_digest,
                "token_count_per_arm": token_count,
                "protected_metric_visibility": (
                    "after_all_predetermined_checkpoints_complete"
                ),
                "claim_boundary": _CLAIM_BOUNDARY,
            }
        ),
    )
    if contract_file.sha256 == manifest_file.sha256:
        raise E1ControlArtifactError("paired contract and manifest digests must differ")
    return E1PairedArtifactBundle(
        contract=contract,
        token_inventory=token_inventory,
        files=tuple(sorted((contract_file, manifest_file), key=lambda item: item.path)),
    )


def write_artifact_files(files: tuple[ArtifactFile, ...], directory: Path) -> None:
    """Write one fail-closed artifact set to an empty directory."""

    if directory.exists() and any(directory.iterdir()):
        raise E1ControlArtifactError(f"output directory is not empty: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    for item in files:
        path = directory / item.path
        path.write_bytes(item.content)
        if _file_digest(path) != item.sha256:
            raise E1ControlArtifactError(f"post-write digest mismatch: {item.path}")


def load_conventional_responses(content: bytes) -> tuple[ConventionalControlResponse, ...]:
    """Load canonical JSONL conventional responses."""

    responses: list[ConventionalControlResponse] = []
    for line_number, line in enumerate(content.decode("utf-8").splitlines(), start=1):
        parsed = load_json_text(line)
        if not isinstance(parsed, dict):
            raise E1ControlArtifactError(f"response line {line_number} is not an object")
        if canonical_json_text(parsed).removesuffix("\n") != line:
            raise E1ControlArtifactError(f"response line {line_number} is not canonical JSON")
        record_id = parsed.get("record_id")
        target = parsed.get("target")
        if not isinstance(record_id, str) or not isinstance(target, str):
            raise E1ControlArtifactError(
                f"response line {line_number} requires string record_id and target"
            )
        responses.append(ConventionalControlResponse(record_id, target))
    return tuple(responses)


def load_token_inventory(content: str) -> E1TokenCountInventory:
    """Load one closed canonical token-count inventory object."""

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
                raise E1ControlArtifactError(
                    f"token inventory {field}[{index}] has invalid fields"
                )
            result.append(
                TokenizedRecordCount(
                    record_id=cast(str, item["record_id"]),
                    raw_token_count=cast(int, item["raw_token_count"]),
                )
            )
        return tuple(result)

    return E1TokenCountInventory(
        tokenizer_revision_digest=cast(str, parsed["tokenizer_revision_digest"]),
        counting_command_digest=cast(str, parsed["counting_command_digest"]),
        control_artifact_digest=cast(str, parsed["control_artifact_digest"]),
        foundry_artifact_digest=cast(str, parsed["foundry_artifact_digest"]),
        context_length=cast(int, parsed["context_length"]),
        control=load_side(parsed["control"], field="control"),
        foundry=load_side(parsed["foundry"], field="foundry"),
    )
