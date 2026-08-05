"""Fail-closed filesystem validation for deterministic E1 artifact sets."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile


@dataclass(frozen=True, slots=True)
class E1ArtifactSetValidationReport:
    """Exact filesystem reconstruction result for one deterministic artifact set."""

    success: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"status": "valid" if self.success else "invalid", "errors": list(self.errors)}


def validate_artifact_files(
    directory: Path,
    expected_files: tuple[ArtifactFile, ...],
) -> E1ArtifactSetValidationReport:
    """Require the exact file set, regular non-symlink paths, and byte identity."""

    expected_paths = tuple(item.path for item in expected_files)
    if len(expected_paths) != len(set(expected_paths)):
        return E1ArtifactSetValidationReport(False, ("expected artifact paths are not unique",))
    if not directory.is_dir():
        return E1ArtifactSetValidationReport(False, (f"missing directory: {directory}",))

    errors: list[str] = []
    expected_path_set = set(expected_paths)
    actual_paths = {item.name for item in directory.iterdir()}
    if expected_path_set != actual_paths:
        errors.append(
            f"file-set mismatch; missing={sorted(expected_path_set - actual_paths)}, "
            f"extra={sorted(actual_paths - expected_path_set)}"
        )
    for item in expected_files:
        path = directory / item.path
        if path.is_symlink() or not path.is_file():
            errors.append(f"{item.path}: expected a regular non-symlink file")
            continue
        observed_bytes = path.read_bytes()
        if observed_bytes != item.content:
            observed_digest = hashlib.sha256(observed_bytes).hexdigest()
            errors.append(f"{item.path}: expected {item.sha256}, observed {observed_digest}")
    return E1ArtifactSetValidationReport(not errors, tuple(errors))
