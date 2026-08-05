"""Strict runtime scalar and immutability checks for E0-H release inputs."""

from __future__ import annotations

import re

from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError
from csd_foundry.empirical.e0h.run_release import (
    EvaluationAccessContract as _BaseEvaluationAccessContract,
)
from csd_foundry.empirical.e0h.run_release import (
    SoftwareEnvironment as _BaseSoftwareEnvironment,
)
from csd_foundry.empirical.e0h.run_release import StorageContract as _BaseStorageContract
from csd_foundry.empirical.e0h.run_release import TrainingRecipe as _BaseTrainingRecipe

_MUTABLE_VERSION_TOKENS = {"dev", "head", "latest", "main", "master", "nightly", "stable"}
_RELEASE_PREFIX = "github-release://ElephantRock/CSD-Foundry/"


def _reject_mutable_version(value: str, *, field: str) -> None:
    tokens = set(re.split(r"[.+-]", value.casefold()))
    mutable = tuple(sorted(tokens & _MUTABLE_VERSION_TOKENS))
    if mutable:
        raise E0HRunReleaseError(f"{field} contains mutable version tokens: {mutable}")


class SoftwareEnvironment(_BaseSoftwareEnvironment):
    """Environment lock that rejects mutable-looking exact-version aliases."""

    def __post_init__(self) -> None:
        super().__post_init__()
        for field, value in (
            ("python_version", self.python_version),
            ("cuda_version", self.cuda_version),
            ("torch_version", self.torch_version),
            ("transformers_version", self.transformers_version),
            ("accelerate_version", self.accelerate_version),
        ):
            _reject_mutable_version(value, field=f"environment.{field}")


class TrainingRecipe(_BaseTrainingRecipe):
    """Training recipe with exact JSON boolean semantics."""

    def __post_init__(self) -> None:
        if type(self.sequence_packing) is not bool:
            raise E0HRunReleaseError("recipe.sequence_packing must be a boolean")
        if type(self.deterministic_dataloader) is not bool:
            raise E0HRunReleaseError("recipe.deterministic_dataloader must be a boolean")
        super().__post_init__()


class StorageContract(_BaseStorageContract):
    """Durable storage binding with concrete nonempty release identifiers."""

    def __post_init__(self) -> None:
        super().__post_init__()
        for field, uri in (
            ("checkpoint_uri", self.checkpoint_uri),
            ("evidence_uri", self.evidence_uri),
        ):
            release_id = uri.removeprefix(_RELEASE_PREFIX)
            if not release_id or release_id.startswith("/") or release_id.endswith("/"):
                raise E0HRunReleaseError(f"storage.{field} must name a concrete release identifier")
            if any(character.isspace() for character in release_id):
                raise E0HRunReleaseError(f"storage.{field} release identifier contains whitespace")


class EvaluationAccessContract(_BaseEvaluationAccessContract):
    """Evaluation access contract with exact JSON boolean denial semantics."""

    def __post_init__(self) -> None:
        if type(self.protected_metrics_access) is not bool:
            raise E0HRunReleaseError("evaluation.protected_metrics_access must be a boolean")
        super().__post_init__()
