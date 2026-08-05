"""E0-H empirical harness qualification release contracts."""

from csd_foundry.empirical.e0h import run_release as _run_release
from csd_foundry.empirical.e0h.run_release import (
    BudgetContract,
    E0HRunReleaseBundle,
    E0HRunReleaseError,
    E0HRunReleaseInputs,
    EvaluationAccessContract,
    ImmutableComponent,
    SoftwareEnvironment,
    StorageContract,
    TrainingRecipe,
    compile_e0h_run_release,
    load_e0h_run_release_inputs,
    validate_e0h_run_release,
    write_e0h_run_release,
)
from csd_foundry.empirical.e0h.seed_binding import SeedDatasetBinding

# Preserve direct submodule imports while enforcing one exact seed-identity implementation.
_run_release.SeedDatasetBinding = SeedDatasetBinding  # type: ignore[misc]

__all__ = [
    "BudgetContract",
    "E0HRunReleaseBundle",
    "E0HRunReleaseError",
    "E0HRunReleaseInputs",
    "EvaluationAccessContract",
    "ImmutableComponent",
    "SeedDatasetBinding",
    "SoftwareEnvironment",
    "StorageContract",
    "TrainingRecipe",
    "compile_e0h_run_release",
    "load_e0h_run_release_inputs",
    "validate_e0h_run_release",
    "write_e0h_run_release",
]
