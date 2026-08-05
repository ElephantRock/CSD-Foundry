"""Tests for fail-closed E1 artifact-set filesystem I/O."""

from pathlib import Path

import pytest

from csd_foundry.empirical.e1.artifact_set_io import (
    E1ArtifactSetError,
    validate_artifact_files,
    write_artifact_files,
)
from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile


def _files() -> tuple[ArtifactFile, ...]:
    return (
        ArtifactFile("a.json", "a", b'{"a":1}\n'),
        ArtifactFile("b.jsonl", "b", b'{"b":2}\n', 1),
    )


def test_artifact_set_round_trip_is_exact(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    files = _files()
    write_artifact_files(files, output)

    report = validate_artifact_files(output, files)

    assert report.success
    assert not report.errors


def test_artifact_set_rejects_non_file_paths_with_expected_names(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    for item in _files():
        (output / item.path).mkdir()

    report = validate_artifact_files(output, _files())

    assert not report.success
    assert len(report.errors) == len(_files())
    assert all("expected a regular non-symlink file" in error for error in report.errors)


def test_artifact_set_rejects_byte_tampering_and_extra_files(tmp_path: Path) -> None:
    output = tmp_path / "artifacts"
    files = _files()
    write_artifact_files(files, output)
    (output / "a.json").write_bytes(b'{"a":3}\n')
    (output / "extra.json").write_text("{}\n", encoding="utf-8")

    report = validate_artifact_files(output, files)

    assert not report.success
    assert any("file-set mismatch" in error for error in report.errors)
    assert any("a.json: expected" in error for error in report.errors)


def test_artifact_set_rejects_symlinked_output_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "artifacts"
    try:
        output.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(E1ArtifactSetError, match="not a regular directory"):
        write_artifact_files(_files(), output)

    report = validate_artifact_files(output, _files())
    assert not report.success
    assert "non-regular directory" in report.errors[0]


def test_artifact_set_rejects_path_traversal_and_existing_files(tmp_path: Path) -> None:
    traversal = (ArtifactFile("../escape.json", "escape", b"{}\n"),)
    with pytest.raises(E1ArtifactSetError, match="flat relative name"):
        write_artifact_files(traversal, tmp_path / "traversal")

    output = tmp_path / "artifacts"
    output.mkdir()
    (output / "a.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(E1ArtifactSetError, match="not empty"):
        write_artifact_files(_files(), output)
