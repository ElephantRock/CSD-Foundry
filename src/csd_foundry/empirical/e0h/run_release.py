"""Compile immutable E0-H empirical harness run releases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e1.artifact_set_io import (
    E1ArtifactSetValidationReport,
    validate_artifact_files,
    write_artifact_files,
)
from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    load_json_text,
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_GIT_REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_EXACT_VERSION = re.compile(r"[0-9]+(?:\.[0-9A-Za-z]+)+(?:[-+][0-9A-Za-z.-]+)?")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_PLACEHOLDER_TERMS = ("TODO", "TBD", "PLACEHOLDER", "UNKNOWN", "<", ">")
_PROTECTED_COMMAND_TERMS = (
    "accuracy",
    "holdout",
    "mutation",
    "subgroup",
    "primary_metric",
    "safety_metric",
    "forbidden_inference_rate",
)
_EXPECTED_SEED_PATHS = {
    "manifest": "data/seed/v0.1/csd_reasoning_manifest_v0.1.json",
    "sft": "data/seed/v0.1/csd_reasoning_sft_v0.1.jsonl",
    "preference": "data/seed/v0.1/csd_reasoning_preference_v0.1.jsonl",
}
_ALLOWED_HEALTH_METRICS = (
    "checkpoint_creation",
    "gpu_memory",
    "gpu_utilization",
    "non_finite_values",
    "publication_failures",
    "storage_failures",
    "throughput",
    "training_loss",
)
_FILES = {
    "contract": "e0h_run_contract.json",
    "environment": "environment_lock.json",
    "recipe": "training_recipe.json",
    "budget": "budget_contract.json",
    "checkpoint": "checkpoint_contract.json",
    "evaluation": "evaluation_access_contract.json",
    "commands": "launch_commands.json",
    "manifest": "artifact_manifest.json",
    "receipt": "reconstruction_receipt.json",
}
_CLAIM_BOUNDARY = (
    "This release establishes only that the E0-H inputs are immutable, complete, internally "
    "consistent, budget bounded, protected-metric isolated, and reconstructable. It does not "
    "authorize GPU execution by itself and cannot establish reasoning improvement, curriculum "
    "efficacy, transfer, statistical power, or scale readiness."
)


class E0HRunReleaseError(ValueError):
    """Raised when an E0-H run release fails closed validation."""


def _require_nonempty(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise E0HRunReleaseError(f"{field} must be a nonempty string")
    if any(term in value for term in _PLACEHOLDER_TERMS):
        raise E0HRunReleaseError(f"{field} contains a placeholder or unresolved marker")
    return value


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise E0HRunReleaseError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_git_revision(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _GIT_REVISION.fullmatch(value) is None:
        raise E0HRunReleaseError(f"{field} must be an exact lowercase git revision")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise E0HRunReleaseError(f"{field} must be a positive integer")
    return value


def _require_nonnegative_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise E0HRunReleaseError(f"{field} must be a nonnegative integer")
    return value


def _require_exact_version(value: object, *, field: str) -> str:
    text = _require_nonempty(value, field=field)
    if _EXACT_VERSION.fullmatch(text) is None:
        raise E0HRunReleaseError(f"{field} must be one exact version without ranges")
    return text


def _require_decimal(value: object, *, field: str, allow_zero: bool = False) -> str:
    text = _require_nonempty(value, field=field)
    if _DECIMAL.fullmatch(text) is None:
        raise E0HRunReleaseError(f"{field} must be a canonical nonnegative decimal string")
    numeric = float(text)
    if numeric < 0 or (numeric == 0 and not allow_zero):
        qualifier = "nonnegative" if allow_zero else "positive"
        raise E0HRunReleaseError(f"{field} must be {qualifier}")
    return text


def _require_command(value: object, *, field: str) -> str:
    command = _require_nonempty(value, field=field)
    lowered = command.lower()
    prohibited = tuple(term for term in _PROTECTED_COMMAND_TERMS if term in lowered)
    if prohibited:
        raise E0HRunReleaseError(f"{field} references protected evaluation terms: {prohibited}")
    return command


def _closed_object(
    value: object,
    *,
    field: str,
    expected_fields: set[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise E0HRunReleaseError(f"{field} must be an object")
    if set(value) != expected_fields:
        missing = sorted(expected_fields - set(value))
        extra = sorted(set(value) - expected_fields)
        raise E0HRunReleaseError(
            f"{field} fields do not match schema; missing={missing}, extra={extra}"
        )
    return cast(dict[str, object], value)


@dataclass(frozen=True, slots=True)
class ImmutableComponent:
    """One externally hosted component pinned by exact revision and content digest."""

    role: str
    locator: str
    revision: str
    content_digest: str

    def __post_init__(self) -> None:
        _require_nonempty(self.role, field="component.role")
        _require_nonempty(self.locator, field=f"{self.role}.locator")
        _require_git_revision(self.revision, field=f"{self.role}.revision")
        _require_digest(self.content_digest, field=f"{self.role}.content_digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role,
            "locator": self.locator,
            "revision": self.revision,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class SeedDatasetBinding:
    """Exact CSD Reasoning Seed v0.1 paths, digests, and record counts."""

    source_commit: str
    manifest_path: str
    manifest_digest: str
    sft_path: str
    sft_digest: str
    sft_records: int
    preference_path: str
    preference_digest: str
    preference_records: int

    def __post_init__(self) -> None:
        _require_git_revision(self.source_commit, field="dataset.source_commit")
        expected = _EXPECTED_SEED_PATHS
        observed = {
            "manifest": self.manifest_path,
            "sft": self.sft_path,
            "preference": self.preference_path,
        }
        if observed != expected:
            raise E0HRunReleaseError(
                "dataset paths must bind the immutable v0.1 seed; "
                f"expected={expected}, observed={observed}"
            )
        _require_digest(self.manifest_digest, field="dataset.manifest_digest")
        _require_digest(self.sft_digest, field="dataset.sft_digest")
        _require_digest(self.preference_digest, field="dataset.preference_digest")
        if self.sft_records != 252 or self.preference_records != 63:
            raise E0HRunReleaseError(
                "dataset record counts must match the immutable seed: sft=252, preference=63"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-seed-dataset-binding/1",
            "source_commit": self.source_commit,
            "manifest": {
                "path": self.manifest_path,
                "sha256": self.manifest_digest,
            },
            "sft": {
                "path": self.sft_path,
                "sha256": self.sft_digest,
                "records": self.sft_records,
            },
            "preference": {
                "path": self.preference_path,
                "sha256": self.preference_digest,
                "records": self.preference_records,
            },
        }


@dataclass(frozen=True, slots=True)
class SoftwareEnvironment:
    """Immutable software and hardware envelope for the bounded smoke run."""

    container_image: str
    python_version: str
    cuda_version: str
    torch_version: str
    transformers_version: str
    accelerate_version: str
    hardware_model: str
    gpu_count: int

    def __post_init__(self) -> None:
        image = _require_nonempty(self.container_image, field="environment.container_image")
        if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) is None:
            raise E0HRunReleaseError(
                "environment.container_image must be pinned by an @sha256 digest"
            )
        _require_exact_version(self.python_version, field="environment.python_version")
        _require_exact_version(self.cuda_version, field="environment.cuda_version")
        _require_exact_version(self.torch_version, field="environment.torch_version")
        _require_exact_version(
            self.transformers_version,
            field="environment.transformers_version",
        )
        _require_exact_version(self.accelerate_version, field="environment.accelerate_version")
        _require_nonempty(self.hardware_model, field="environment.hardware_model")
        _require_positive_int(self.gpu_count, field="environment.gpu_count")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-software-environment/1",
            "container_image": self.container_image,
            "python_version": self.python_version,
            "cuda_version": self.cuda_version,
            "torch_version": self.torch_version,
            "transformers_version": self.transformers_version,
            "accelerate_version": self.accelerate_version,
            "hardware_model": self.hardware_model,
            "gpu_count": self.gpu_count,
        }


@dataclass(frozen=True, slots=True)
class TrainingRecipe:
    """Fixed bounded training recipe for E0-H infrastructure qualification."""

    seed: int
    context_length: int
    precision: str
    optimizer: str
    scheduler: str
    learning_rate: str
    warmup_steps: int
    micro_batch_size: int
    gradient_accumulation_steps: int
    max_steps: int
    checkpoint_interval_steps: int
    max_grad_norm: str
    sequence_packing: bool
    deterministic_dataloader: bool

    def __post_init__(self) -> None:
        _require_nonnegative_int(self.seed, field="recipe.seed")
        _require_positive_int(self.context_length, field="recipe.context_length")
        if self.precision not in {"fp32", "fp16", "bf16"}:
            raise E0HRunReleaseError("recipe.precision must be fp32, fp16, or bf16")
        _require_nonempty(self.optimizer, field="recipe.optimizer")
        _require_nonempty(self.scheduler, field="recipe.scheduler")
        _require_decimal(self.learning_rate, field="recipe.learning_rate")
        _require_nonnegative_int(self.warmup_steps, field="recipe.warmup_steps")
        _require_positive_int(self.micro_batch_size, field="recipe.micro_batch_size")
        _require_positive_int(
            self.gradient_accumulation_steps,
            field="recipe.gradient_accumulation_steps",
        )
        _require_positive_int(self.max_steps, field="recipe.max_steps")
        _require_positive_int(
            self.checkpoint_interval_steps,
            field="recipe.checkpoint_interval_steps",
        )
        if self.checkpoint_interval_steps > self.max_steps:
            raise E0HRunReleaseError("checkpoint interval cannot exceed max_steps")
        if self.warmup_steps >= self.max_steps:
            raise E0HRunReleaseError("warmup_steps must be less than max_steps")
        _require_decimal(self.max_grad_norm, field="recipe.max_grad_norm", allow_zero=True)
        if not self.deterministic_dataloader:
            raise E0HRunReleaseError("E0-H requires deterministic_dataloader=true")

    @property
    def effective_batch_size(self) -> int:
        return self.micro_batch_size * self.gradient_accumulation_steps

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-training-recipe/1",
            "seed": self.seed,
            "context_length": self.context_length,
            "precision": self.precision,
            "optimizer": self.optimizer,
            "scheduler": self.scheduler,
            "learning_rate": self.learning_rate,
            "warmup_steps": self.warmup_steps,
            "micro_batch_size": self.micro_batch_size,
            "gradient_accumulation_steps": self.gradient_accumulation_steps,
            "effective_batch_size": self.effective_batch_size,
            "max_steps": self.max_steps,
            "checkpoint_interval_steps": self.checkpoint_interval_steps,
            "max_grad_norm": self.max_grad_norm,
            "sequence_packing": self.sequence_packing,
            "deterministic_dataloader": self.deterministic_dataloader,
        }


@dataclass(frozen=True, slots=True)
class BudgetContract:
    """Numeric aggregate and E0-H resource limits."""

    aggregate_gpu_minutes: int
    e0h_gpu_minutes: int
    max_reruns: int
    max_checkpoint_gib: int
    artifact_retention_days: int
    checkpoint_retention_days: int

    def __post_init__(self) -> None:
        _require_positive_int(self.aggregate_gpu_minutes, field="budget.aggregate_gpu_minutes")
        _require_positive_int(self.e0h_gpu_minutes, field="budget.e0h_gpu_minutes")
        if self.e0h_gpu_minutes > self.aggregate_gpu_minutes:
            raise E0HRunReleaseError("E0-H allocation exceeds the aggregate GPU budget")
        _require_nonnegative_int(self.max_reruns, field="budget.max_reruns")
        if self.max_reruns > 1:
            raise E0HRunReleaseError("E0-H permits at most one infrastructure-invalid rerun")
        _require_positive_int(self.max_checkpoint_gib, field="budget.max_checkpoint_gib")
        _require_positive_int(
            self.artifact_retention_days,
            field="budget.artifact_retention_days",
        )
        _require_positive_int(
            self.checkpoint_retention_days,
            field="budget.checkpoint_retention_days",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-budget-contract/1",
            "aggregate_gpu_minutes": self.aggregate_gpu_minutes,
            "e0h_gpu_minutes": self.e0h_gpu_minutes,
            "max_reruns": self.max_reruns,
            "max_checkpoint_gib": self.max_checkpoint_gib,
            "artifact_retention_days": self.artifact_retention_days,
            "checkpoint_retention_days": self.checkpoint_retention_days,
        }


@dataclass(frozen=True, slots=True)
class StorageContract:
    """Durable GitHub-managed publication destinations."""

    checkpoint_uri: str
    evidence_uri: str

    def __post_init__(self) -> None:
        for field, value in (
            ("checkpoint_uri", self.checkpoint_uri),
            ("evidence_uri", self.evidence_uri),
        ):
            uri = _require_nonempty(value, field=f"storage.{field}")
            if not uri.startswith("github-release://ElephantRock/CSD-Foundry/"):
                raise E0HRunReleaseError(
                    f"storage.{field} must use the durable github-release channel"
                )
        if self.checkpoint_uri == self.evidence_uri:
            raise E0HRunReleaseError("checkpoint and evidence destinations must be distinct")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-storage-contract/1",
            "checkpoint_uri": self.checkpoint_uri,
            "evidence_uri": self.evidence_uri,
        }


@dataclass(frozen=True, slots=True)
class EvaluationAccessContract:
    """Protected-metric denial and deterministic smoke-fixture authorization."""

    smoke_fixture_digest: str
    allowed_health_metrics: tuple[str, ...]
    protected_metrics_access: bool

    def __post_init__(self) -> None:
        _require_digest(self.smoke_fixture_digest, field="evaluation.smoke_fixture_digest")
        if self.allowed_health_metrics != _ALLOWED_HEALTH_METRICS:
            raise E0HRunReleaseError(
                "evaluation.allowed_health_metrics must equal the frozen infrastructure metric set"
            )
        if self.protected_metrics_access:
            raise E0HRunReleaseError("protected metrics must be inaccessible during E0-H")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-evaluation-access-contract/1",
            "smoke_fixture_digest": self.smoke_fixture_digest,
            "allowed_health_metrics": list(self.allowed_health_metrics),
            "protected_metrics_access": self.protected_metrics_access,
            "prohibited_outputs": [
                "protected_task_accuracy",
                "structural_holdout_metrics",
                "mutation_efficacy_metrics",
                "subgroup_efficacy_metrics",
                "comparative_curriculum_conclusions",
                "reasoning_improvement_claims",
            ],
        }


@dataclass(frozen=True, slots=True)
class E0HRunReleaseInputs:
    """Complete immutable input set required to compile an E0-H run release."""

    release: str
    source_commit: str
    dataset: SeedDatasetBinding
    model: ImmutableComponent
    tokenizer: ImmutableComponent
    environment: SoftwareEnvironment
    recipe: TrainingRecipe
    budget: BudgetContract
    storage: StorageContract
    evaluation: EvaluationAccessContract
    tokenization_command: str
    training_command: str
    reload_command: str
    inference_command: str
    smoke_evaluation_command: str

    def __post_init__(self) -> None:
        _require_nonempty(self.release, field="release")
        _require_git_revision(self.source_commit, field="source_commit")
        if self.dataset.source_commit != self.source_commit:
            raise E0HRunReleaseError("dataset source commit must equal the release source commit")
        if self.model.role != "model":
            raise E0HRunReleaseError("model component role must be 'model'")
        if self.tokenizer.role != "tokenizer":
            raise E0HRunReleaseError("tokenizer component role must be 'tokenizer'")
        if self.model.content_digest == self.tokenizer.content_digest:
            raise E0HRunReleaseError("model and tokenizer content digests must be distinct")
        for field, value in (
            ("tokenization_command", self.tokenization_command),
            ("training_command", self.training_command),
            ("reload_command", self.reload_command),
            ("inference_command", self.inference_command),
            ("smoke_evaluation_command", self.smoke_evaluation_command),
        ):
            _require_command(value, field=field)

    @property
    def command_digests(self) -> dict[str, str]:
        return {
            "tokenization": canonical_sha256({"command": self.tokenization_command}),
            "training": canonical_sha256({"command": self.training_command}),
            "reload": canonical_sha256({"command": self.reload_command}),
            "inference": canonical_sha256({"command": self.inference_command}),
            "smoke_evaluation": canonical_sha256({"command": self.smoke_evaluation_command}),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-run-release-inputs/1",
            "release": self.release,
            "source_commit": self.source_commit,
            "dataset": self.dataset.to_dict(),
            "model": self.model.to_dict(),
            "tokenizer": self.tokenizer.to_dict(),
            "environment": self.environment.to_dict(),
            "recipe": self.recipe.to_dict(),
            "budget": self.budget.to_dict(),
            "storage": self.storage.to_dict(),
            "evaluation": self.evaluation.to_dict(),
            "commands": {
                "tokenization": self.tokenization_command,
                "training": self.training_command,
                "reload": self.reload_command,
                "inference": self.inference_command,
                "smoke_evaluation": self.smoke_evaluation_command,
            },
            "command_digests": self.command_digests,
        }


@dataclass(frozen=True, slots=True)
class E0HRunReleaseBundle:
    """Deterministic E0-H release bytes and evidence receipts."""

    release: str
    source_commit: str
    run_contract_digest: str
    files: tuple[ArtifactFile, ...]

    def file(self, path: str) -> ArtifactFile:
        for item in self.files:
            if item.path == path:
                return item
        raise KeyError(path)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-run-release-bundle/1",
            "release": self.release,
            "source_commit": self.source_commit,
            "run_contract_digest": self.run_contract_digest,
            "files": [item.receipt() for item in self.files],
            "claim_boundary": _CLAIM_BOUNDARY,
        }


def _artifact(path: str, role: str, payload: dict[str, object]) -> ArtifactFile:
    return ArtifactFile(path, role, canonical_json_bytes(payload))


def compile_e0h_run_release(inputs: E0HRunReleaseInputs) -> E0HRunReleaseBundle:
    """Compile one deterministic, non-authorizing E0-H run release."""

    contract_payload = {
        "schema_version": "e0h-run-contract/1",
        "release": inputs.release,
        "source_commit": inputs.source_commit,
        "dataset_digest": canonical_sha256(inputs.dataset.to_dict()),
        "model_digest": canonical_sha256(inputs.model.to_dict()),
        "tokenizer_digest": canonical_sha256(inputs.tokenizer.to_dict()),
        "environment_digest": canonical_sha256(inputs.environment.to_dict()),
        "recipe_digest": canonical_sha256(inputs.recipe.to_dict()),
        "budget_digest": canonical_sha256(inputs.budget.to_dict()),
        "storage_digest": canonical_sha256(inputs.storage.to_dict()),
        "evaluation_access_digest": canonical_sha256(inputs.evaluation.to_dict()),
        "command_digests": inputs.command_digests,
        "gpu_execution_authorized": False,
        "required_terminal_classification": ["HARNESS_PASSED", "HARNESS_FAILED"],
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    run_contract_digest = canonical_sha256(contract_payload)

    primary_files = (
        _artifact(_FILES["contract"], "e0h_run_contract", contract_payload),
        _artifact(_FILES["environment"], "environment_lock", inputs.environment.to_dict()),
        _artifact(_FILES["recipe"], "training_recipe", inputs.recipe.to_dict()),
        _artifact(_FILES["budget"], "budget_contract", inputs.budget.to_dict()),
        _artifact(
            _FILES["checkpoint"],
            "checkpoint_contract",
            {
                "schema_version": "e0h-checkpoint-contract/1",
                "checkpoint_uri": inputs.storage.checkpoint_uri,
                "max_checkpoint_gib": inputs.budget.max_checkpoint_gib,
                "retention_days": inputs.budget.checkpoint_retention_days,
                "save_required": True,
                "reload_required": True,
                "digest_publication_required": True,
            },
        ),
        _artifact(
            _FILES["evaluation"],
            "evaluation_access_contract",
            inputs.evaluation.to_dict(),
        ),
        _artifact(
            _FILES["commands"],
            "launch_commands",
            {
                "schema_version": "e0h-launch-commands/1",
                "commands": {
                    "tokenization": inputs.tokenization_command,
                    "training": inputs.training_command,
                    "reload": inputs.reload_command,
                    "inference": inputs.inference_command,
                    "smoke_evaluation": inputs.smoke_evaluation_command,
                },
                "command_digests": inputs.command_digests,
            },
        ),
    )
    manifest_payload = {
        "schema_version": "e0h-artifact-manifest/1",
        "release": inputs.release,
        "source_commit": inputs.source_commit,
        "run_contract_digest": run_contract_digest,
        "files": [item.receipt() for item in primary_files],
        "file_count": len(primary_files),
        "evidence_uri": inputs.storage.evidence_uri,
    }
    manifest_file = _artifact(_FILES["manifest"], "artifact_manifest", manifest_payload)
    receipt_payload = {
        "schema_version": "e0h-reconstruction-receipt/1",
        "release": inputs.release,
        "source_commit": inputs.source_commit,
        "input_digest": canonical_sha256(inputs.to_dict()),
        "run_contract_digest": run_contract_digest,
        "artifact_manifest_digest": manifest_file.sha256,
        "generation_command": (
            "python -m csd_foundry.empirical.e0h.run_release_cli compile "
            "--inputs <canonical-inputs.json> --output-dir <empty-output-directory>"
        ),
        "validation_command": (
            "python -m csd_foundry.empirical.e0h.run_release_cli validate "
            "--inputs <canonical-inputs.json> --output-dir <compiled-output-directory>"
        ),
        "gpu_execution_authorized": False,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    receipt_file = _artifact(_FILES["receipt"], "reconstruction_receipt", receipt_payload)
    files = tuple(sorted((*primary_files, manifest_file, receipt_file), key=lambda item: item.path))
    return E0HRunReleaseBundle(
        release=inputs.release,
        source_commit=inputs.source_commit,
        run_contract_digest=run_contract_digest,
        files=files,
    )


def write_e0h_run_release(bundle: E0HRunReleaseBundle, directory: Path) -> None:
    """Write one exact E0-H run release using hardened no-clobber artifact I/O."""

    write_artifact_files(bundle.files, directory)


def validate_e0h_run_release(
    directory: Path,
    inputs: E0HRunReleaseInputs,
) -> E1ArtifactSetValidationReport:
    """Recompile and require exact file-set and byte identity."""

    return validate_artifact_files(directory, compile_e0h_run_release(inputs).files)


def load_e0h_run_release_inputs(content: str) -> E0HRunReleaseInputs:
    """Load one closed, canonical E0-H release-input object."""

    try:
        parsed = load_json_text(content)
    except (TypeError, ValueError) as exc:
        raise E0HRunReleaseError("release inputs are not valid JSON") from exc
    if canonical_json_text(parsed) != content:
        raise E0HRunReleaseError("release input bytes are not canonical JSON")
    root = _closed_object(
        parsed,
        field="release_inputs",
        expected_fields={
            "schema_version",
            "release",
            "source_commit",
            "dataset",
            "model",
            "tokenizer",
            "environment",
            "recipe",
            "budget",
            "storage",
            "evaluation",
            "commands",
        },
    )
    if root["schema_version"] != "e0h-run-release-inputs/1":
        raise E0HRunReleaseError("unsupported release-input schema_version")

    dataset = _closed_object(
        root["dataset"],
        field="dataset",
        expected_fields={
            "source_commit",
            "manifest_path",
            "manifest_digest",
            "sft_path",
            "sft_digest",
            "sft_records",
            "preference_path",
            "preference_digest",
            "preference_records",
        },
    )

    def component(value: object, *, field: str) -> ImmutableComponent:
        item = _closed_object(
            value,
            field=field,
            expected_fields={"role", "locator", "revision", "content_digest"},
        )
        return ImmutableComponent(
            role=cast(str, item["role"]),
            locator=cast(str, item["locator"]),
            revision=cast(str, item["revision"]),
            content_digest=cast(str, item["content_digest"]),
        )

    environment = _closed_object(
        root["environment"],
        field="environment",
        expected_fields={
            "container_image",
            "python_version",
            "cuda_version",
            "torch_version",
            "transformers_version",
            "accelerate_version",
            "hardware_model",
            "gpu_count",
        },
    )
    recipe = _closed_object(
        root["recipe"],
        field="recipe",
        expected_fields={
            "seed",
            "context_length",
            "precision",
            "optimizer",
            "scheduler",
            "learning_rate",
            "warmup_steps",
            "micro_batch_size",
            "gradient_accumulation_steps",
            "max_steps",
            "checkpoint_interval_steps",
            "max_grad_norm",
            "sequence_packing",
            "deterministic_dataloader",
        },
    )
    budget = _closed_object(
        root["budget"],
        field="budget",
        expected_fields={
            "aggregate_gpu_minutes",
            "e0h_gpu_minutes",
            "max_reruns",
            "max_checkpoint_gib",
            "artifact_retention_days",
            "checkpoint_retention_days",
        },
    )
    storage = _closed_object(
        root["storage"],
        field="storage",
        expected_fields={"checkpoint_uri", "evidence_uri"},
    )
    evaluation = _closed_object(
        root["evaluation"],
        field="evaluation",
        expected_fields={
            "smoke_fixture_digest",
            "allowed_health_metrics",
            "protected_metrics_access",
        },
    )
    metrics = evaluation["allowed_health_metrics"]
    if not isinstance(metrics, list) or any(not isinstance(item, str) for item in metrics):
        raise E0HRunReleaseError("evaluation.allowed_health_metrics must be a string list")
    commands = _closed_object(
        root["commands"],
        field="commands",
        expected_fields={
            "tokenization",
            "training",
            "reload",
            "inference",
            "smoke_evaluation",
        },
    )
    return E0HRunReleaseInputs(
        release=cast(str, root["release"]),
        source_commit=cast(str, root["source_commit"]),
        dataset=SeedDatasetBinding(
            source_commit=cast(str, dataset["source_commit"]),
            manifest_path=cast(str, dataset["manifest_path"]),
            manifest_digest=cast(str, dataset["manifest_digest"]),
            sft_path=cast(str, dataset["sft_path"]),
            sft_digest=cast(str, dataset["sft_digest"]),
            sft_records=cast(int, dataset["sft_records"]),
            preference_path=cast(str, dataset["preference_path"]),
            preference_digest=cast(str, dataset["preference_digest"]),
            preference_records=cast(int, dataset["preference_records"]),
        ),
        model=component(root["model"], field="model"),
        tokenizer=component(root["tokenizer"], field="tokenizer"),
        environment=SoftwareEnvironment(
            container_image=cast(str, environment["container_image"]),
            python_version=cast(str, environment["python_version"]),
            cuda_version=cast(str, environment["cuda_version"]),
            torch_version=cast(str, environment["torch_version"]),
            transformers_version=cast(str, environment["transformers_version"]),
            accelerate_version=cast(str, environment["accelerate_version"]),
            hardware_model=cast(str, environment["hardware_model"]),
            gpu_count=cast(int, environment["gpu_count"]),
        ),
        recipe=TrainingRecipe(
            seed=cast(int, recipe["seed"]),
            context_length=cast(int, recipe["context_length"]),
            precision=cast(str, recipe["precision"]),
            optimizer=cast(str, recipe["optimizer"]),
            scheduler=cast(str, recipe["scheduler"]),
            learning_rate=cast(str, recipe["learning_rate"]),
            warmup_steps=cast(int, recipe["warmup_steps"]),
            micro_batch_size=cast(int, recipe["micro_batch_size"]),
            gradient_accumulation_steps=cast(int, recipe["gradient_accumulation_steps"]),
            max_steps=cast(int, recipe["max_steps"]),
            checkpoint_interval_steps=cast(int, recipe["checkpoint_interval_steps"]),
            max_grad_norm=cast(str, recipe["max_grad_norm"]),
            sequence_packing=cast(bool, recipe["sequence_packing"]),
            deterministic_dataloader=cast(bool, recipe["deterministic_dataloader"]),
        ),
        budget=BudgetContract(
            aggregate_gpu_minutes=cast(int, budget["aggregate_gpu_minutes"]),
            e0h_gpu_minutes=cast(int, budget["e0h_gpu_minutes"]),
            max_reruns=cast(int, budget["max_reruns"]),
            max_checkpoint_gib=cast(int, budget["max_checkpoint_gib"]),
            artifact_retention_days=cast(int, budget["artifact_retention_days"]),
            checkpoint_retention_days=cast(int, budget["checkpoint_retention_days"]),
        ),
        storage=StorageContract(
            checkpoint_uri=cast(str, storage["checkpoint_uri"]),
            evidence_uri=cast(str, storage["evidence_uri"]),
        ),
        evaluation=EvaluationAccessContract(
            smoke_fixture_digest=cast(str, evaluation["smoke_fixture_digest"]),
            allowed_health_metrics=tuple(cast(list[str], metrics)),
            protected_metrics_access=cast(bool, evaluation["protected_metrics_access"]),
        ),
        tokenization_command=cast(str, commands["tokenization"]),
        training_command=cast(str, commands["training"]),
        reload_command=cast(str, commands["reload"]),
        inference_command=cast(str, commands["inference"]),
        smoke_evaluation_command=cast(str, commands["smoke_evaluation"]),
    )
