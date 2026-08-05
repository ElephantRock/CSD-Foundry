"""Fail-closed filesystem I/O for deterministic E1 artifact sets."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePath

from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile


class E1ArtifactSetError(ValueError):
    """Raised when an E1 artifact set cannot be written safely."""


@dataclass(frozen=True, slots=True)
class E1ArtifactSetValidationReport:
    """Exact filesystem reconstruction result for one deterministic artifact set."""

    success: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"status": "valid" if self.success else "invalid", "errors": list(self.errors)}


def _validate_expected_files(expected_files: tuple[ArtifactFile, ...]) -> tuple[str, ...]:
    paths = tuple(item.path for item in expected_files)
    if len(paths) != len(set(paths)):
        raise E1ArtifactSetError("expected artifact paths are not unique")
    for path in paths:
        pure_path = PurePath(path)
        if not path or pure_path.is_absolute() or pure_path.name != path or path in {".", ".."}:
            raise E1ArtifactSetError(f"artifact path must be one flat relative name: {path!r}")
    return paths


def write_artifact_files(files: tuple[ArtifactFile, ...], directory: Path) -> None:
    """Write exact artifact bytes with flat paths and no-clobber file creation."""

    _validate_expected_files(files)
    if directory.exists() or directory.is_symlink():
        if directory.is_symlink() or not directory.is_dir():
            raise E1ArtifactSetError(f"output path is not a regular directory: {directory}")
        if any(directory.iterdir()):
            raise E1ArtifactSetError(f"output directory is not empty: {directory}")
    else:
        directory.mkdir(parents=True)
    if directory.is_symlink() or not directory.is_dir():
        raise E1ArtifactSetError(f"output path is not a regular directory: {directory}")

    for item in files:
        path = directory / item.path
        try:
            with path.open("xb") as handle:
                handle.write(item.content)
        except FileExistsError as exc:
            raise E1ArtifactSetError(f"artifact path already exists: {item.path}") from exc
        observed_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed_digest != item.sha256:
            raise E1ArtifactSetError(f"post-write digest mismatch: {item.path}")


def validate_artifact_files(
    directory: Path,
    expected_files: tuple[ArtifactFile, ...],
) -> E1ArtifactSetValidationReport:
    """Require the exact file set, regular non-symlink paths, and byte identity."""

    try:
        expected_paths = _validate_expected_files(expected_files)
    except E1ArtifactSetError as exc:
        return E1ArtifactSetValidationReport(False, (str(exc),))
    if directory.is_symlink() or not directory.is_dir():
        return E1ArtifactSetValidationReport(
            False,
            (f"missing or non-regular directory: {directory}",),
        )

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
