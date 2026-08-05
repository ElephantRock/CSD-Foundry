"""Adversarial path-shape tests for E1 artifact validation."""

from pathlib import Path

import pytest

from csd_foundry.empirical.e1 import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
    validate_e1_foundry_artifacts,
    write_e1_foundry_artifacts,
)
from csd_foundry.scenarios.registry import SCENARIOS

_SOURCE_COMMIT = "2eb623a2cc2e1984af198a15be600d019bb91416"
_SELECTION_RELEASE = "e1-candidate/1"
_ARTIFACT_RELEASE = "e1-foundry-artifacts/1"


def _selection():
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _bundle():
    return compile_e1_foundry_artifacts(
        SCENARIOS,
        _selection(),
        release=_ARTIFACT_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _validate(directory: Path):
    return validate_e1_foundry_artifacts(
        directory,
        SCENARIOS,
        _selection(),
        release=_ARTIFACT_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def test_validator_rejects_directories_named_like_every_expected_artifact(
    tmp_path: Path,
) -> None:
    bundle = _bundle()
    output = tmp_path / "foundry"
    output.mkdir()
    for item in bundle.files:
        (output / item.path).mkdir()

    report = _validate(output)

    assert not report.success
    assert len(report.errors) == len(bundle.files)
    assert all("expected a regular non-symlink file" in error for error in report.errors)


def test_validator_rejects_symlink_even_when_target_bytes_match(tmp_path: Path) -> None:
    bundle = _bundle()
    output = tmp_path / "foundry"
    write_e1_foundry_artifacts(bundle, output)

    artifact = bundle.files[0]
    artifact_path = output / artifact.path
    matching_target = tmp_path / "matching-target"
    matching_target.write_bytes(artifact.content)
    artifact_path.unlink()
    try:
        artifact_path.symlink_to(matching_target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    report = _validate(output)

    assert not report.success
    assert report.errors == (
        f"{artifact.path}: expected a regular non-symlink file",
    )
