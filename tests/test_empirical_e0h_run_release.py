"""Tests for deterministic E0-H run-release compilation."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from csd_foundry.empirical.e0h.run_release import (
    BudgetContract,
    E0HRunReleaseError,
    E0HRunReleaseInputs,
    EvaluationAccessContract,
    ImmutableComponent,
    SeedDatasetBinding,
    SoftwareEnvironment,
    StorageContract,
    TrainingRecipe,
    compile_e0h_run_release,
    load_e0h_run_release_inputs,
    validate_e0h_run_release,
    write_e0h_run_release,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_text


def _inputs() -> E0HRunReleaseInputs:
    source_commit = "f80aee9405956d6f14a839c519157d91e69e1db8"
    return E0HRunReleaseInputs(
        release="e0h-run-release/1",
        source_commit=source_commit,
        dataset=SeedDatasetBinding(
            source_commit=source_commit,
            manifest_path="data/seed/v0.1/csd_reasoning_manifest_v0.1.json",
            manifest_digest="1" * 64,
            sft_path="data/seed/v0.1/csd_reasoning_sft_v0.1.jsonl",
            sft_digest="02903221be8aff0f5e667dbde556040f049bf386c84722a032101ae02879aaa9",
            sft_records=252,
            preference_path="data/seed/v0.1/csd_reasoning_preference_v0.1.jsonl",
            preference_digest="18f7d612041d2769d138a51165d5b55f73bd12e95578e4e012f45bbdd981aa5c",
            preference_records=63,
        ),
        model=ImmutableComponent(
            role="model",
            locator="model-registry://small-reference-model",
            revision="2" * 40,
            content_digest="3" * 64,
        ),
        tokenizer=ImmutableComponent(
            role="tokenizer",
            locator="model-registry://small-reference-tokenizer",
            revision="4" * 40,
            content_digest="5" * 64,
        ),
        environment=SoftwareEnvironment(
            container_image=f"registry.example/csd-e0h@sha256:{'6' * 64}",
            python_version="3.11.15",
            cuda_version="12.8.1",
            torch_version="2.8.0",
            transformers_version="4.55.0",
            accelerate_version="1.10.0",
            hardware_model="NVIDIA-L4-24GB",
            gpu_count=1,
        ),
        recipe=TrainingRecipe(
            seed=1729,
            context_length=2048,
            precision="bf16",
            optimizer="adamw_torch",
            scheduler="linear",
            learning_rate="0.00002",
            warmup_steps=1,
            micro_batch_size=1,
            gradient_accumulation_steps=4,
            max_steps=8,
            checkpoint_interval_steps=4,
            max_grad_norm="1.0",
            sequence_packing=False,
            deterministic_dataloader=True,
        ),
        budget=BudgetContract(
            aggregate_gpu_minutes=600,
            e0h_gpu_minutes=60,
            max_reruns=1,
            max_checkpoint_gib=10,
            artifact_retention_days=365,
            checkpoint_retention_days=90,
        ),
        storage=StorageContract(
            checkpoint_uri="github-release://ElephantRock/CSD-Foundry/e0h-v1-checkpoint",
            evidence_uri="github-release://ElephantRock/CSD-Foundry/e0h-v1-evidence",
        ),
        evaluation=EvaluationAccessContract(
            smoke_fixture_digest="7" * 64,
            allowed_health_metrics=(
                "checkpoint_creation",
                "gpu_memory",
                "gpu_utilization",
                "non_finite_values",
                "publication_failures",
                "storage_failures",
                "throughput",
                "training_loss",
            ),
            protected_metrics_access=False,
        ),
        tokenization_command="python -m harness.tokenize --contract e0h_run_contract.json",
        training_command="python -m harness.train --contract e0h_run_contract.json",
        reload_command="python -m harness.reload --contract e0h_run_contract.json",
        inference_command="python -m harness.infer --contract e0h_run_contract.json",
        smoke_evaluation_command="python -m harness.smoke_eval --contract e0h_run_contract.json",
    )


def _raw(inputs: E0HRunReleaseInputs) -> dict[str, object]:
    return {
        "schema_version": "e0h-run-release-inputs/1",
        "release": inputs.release,
        "source_commit": inputs.source_commit,
        "dataset": {
            "source_commit": inputs.dataset.source_commit,
            "manifest_path": inputs.dataset.manifest_path,
            "manifest_digest": inputs.dataset.manifest_digest,
            "sft_path": inputs.dataset.sft_path,
            "sft_digest": inputs.dataset.sft_digest,
            "sft_records": inputs.dataset.sft_records,
            "preference_path": inputs.dataset.preference_path,
            "preference_digest": inputs.dataset.preference_digest,
            "preference_records": inputs.dataset.preference_records,
        },
        "model": inputs.model.to_dict(),
        "tokenizer": inputs.tokenizer.to_dict(),
        "environment": {
            key: value
            for key, value in inputs.environment.to_dict().items()
            if key != "schema_version"
        },
        "recipe": {
            key: value
            for key, value in inputs.recipe.to_dict().items()
            if key not in {"schema_version", "effective_batch_size"}
        },
        "budget": {
            key: value for key, value in inputs.budget.to_dict().items() if key != "schema_version"
        },
        "storage": {
            key: value for key, value in inputs.storage.to_dict().items() if key != "schema_version"
        },
        "evaluation": {
            "smoke_fixture_digest": inputs.evaluation.smoke_fixture_digest,
            "allowed_health_metrics": list(inputs.evaluation.allowed_health_metrics),
            "protected_metrics_access": inputs.evaluation.protected_metrics_access,
        },
        "commands": {
            "tokenization": inputs.tokenization_command,
            "training": inputs.training_command,
            "reload": inputs.reload_command,
            "inference": inputs.inference_command,
            "smoke_evaluation": inputs.smoke_evaluation_command,
        },
    }


def test_e0h_run_release_is_deterministic_and_non_authorizing() -> None:
    inputs = _inputs()

    first = compile_e0h_run_release(inputs)
    second = compile_e0h_run_release(inputs)

    assert first == second
    assert len(first.files) == 9
    assert (
        first.file("e0h_run_contract.json").content == second.file("e0h_run_contract.json").content
    )
    assert b'"gpu_execution_authorized":false' in first.file("e0h_run_contract.json").content


def test_e0h_run_release_round_trips_and_reconstructs(tmp_path: Path) -> None:
    inputs = _inputs()
    loaded = load_e0h_run_release_inputs(canonical_json_text(_raw(inputs)))
    assert loaded == inputs

    output = tmp_path / "release"
    bundle = compile_e0h_run_release(loaded)
    write_e0h_run_release(bundle, output)
    report = validate_e0h_run_release(output, loaded)

    assert report.success
    (output / "training_recipe.json").write_bytes(b"{}\n")
    assert not validate_e0h_run_release(output, loaded).success


def test_e0h_rejects_mutable_or_placeholder_component_revisions() -> None:
    with pytest.raises(E0HRunReleaseError, match="exact lowercase git revision"):
        replace(_inputs().model, revision="main")
    with pytest.raises(E0HRunReleaseError, match="placeholder"):
        replace(_inputs().tokenizer, locator="TBD")


def test_e0h_rejects_budget_expansion_and_protected_metric_commands() -> None:
    with pytest.raises(E0HRunReleaseError, match="exceeds"):
        replace(_inputs().budget, e0h_gpu_minutes=601)
    with pytest.raises(E0HRunReleaseError, match="protected evaluation"):
        replace(
            _inputs(),
            smoke_evaluation_command="python -m harness.accuracy --contract contract.json",
        )


def test_e0h_requires_exact_seed_boundary_and_metric_denial() -> None:
    with pytest.raises(E0HRunReleaseError, match="record counts"):
        replace(_inputs().dataset, sft_records=251)
    with pytest.raises(E0HRunReleaseError, match="inaccessible"):
        replace(_inputs().evaluation, protected_metrics_access=True)


def test_e0h_loader_rejects_noncanonical_and_unknown_fields() -> None:
    raw = _raw(_inputs())
    raw["unexpected"] = True
    with pytest.raises(E0HRunReleaseError, match="fields do not match"):
        load_e0h_run_release_inputs(canonical_json_text(raw))

    canonical = canonical_json_text(_raw(_inputs()))
    with pytest.raises(E0HRunReleaseError, match="not canonical"):
        load_e0h_run_release_inputs(canonical + "\n")
