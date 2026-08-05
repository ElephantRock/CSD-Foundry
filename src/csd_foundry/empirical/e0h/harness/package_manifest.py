"""Verify every execution-critical byte in the concrete E0-H package."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import cast

from csd_foundry.empirical.e0h import E0HRunReleaseInputs
from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    read_json_object,
    sha256_file,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError

_SHA256 = re.compile(r"[0-9a-f]{64}")
_CLAIM_BOUNDARY = (
    "The execution-package manifest binds repository bytes needed to reconstruct and run E0-H. "
    "It does not authorize GPU execution, protected metrics, E1 execution, or a reasoning claim."
)
_EXPECTED_PATHS = frozenset(
    {
        "README.md",
        "pyproject.toml",
        "experiments/e0h/v1/README.md",
        "experiments/e0h/v1/container/Dockerfile",
        "experiments/e0h/v1/model_snapshot_manifest.json",
        "experiments/e0h/v1/python_lock.json",
        "experiments/e0h/v1/requirements-cu128.lock",
        "experiments/e0h/v1/run_inputs.json",
        "experiments/e0h/v1/smoke_fixture.jsonl",
        "experiments/e0h/v1/compiled_release/artifact_manifest.json",
        "experiments/e0h/v1/compiled_release/budget_contract.json",
        "experiments/e0h/v1/compiled_release/checkpoint_contract.json",
        "experiments/e0h/v1/compiled_release/e0h_run_contract.json",
        "experiments/e0h/v1/compiled_release/environment_lock.json",
        "experiments/e0h/v1/compiled_release/evaluation_access_contract.json",
        "experiments/e0h/v1/compiled_release/launch_commands.json",
        "experiments/e0h/v1/compiled_release/reconstruction_receipt.json",
        "experiments/e0h/v1/compiled_release/run_inputs_lock.json",
        "experiments/e0h/v1/compiled_release/training_recipe.json",
        "src/csd_foundry/empirical/e0h/__init__.py",
        "src/csd_foundry/empirical/e0h/locked_release.py",
        "src/csd_foundry/empirical/e0h/run_release.py",
        "src/csd_foundry/empirical/e0h/run_release_cli.py",
        "src/csd_foundry/empirical/e0h/seed_binding.py",
        "src/csd_foundry/empirical/e0h/strict_inputs.py",
        "src/csd_foundry/empirical/e0h/harness/__init__.py",
        "src/csd_foundry/empirical/e0h/harness/common.py",
        "src/csd_foundry/empirical/e0h/harness/fetch_assets.py",
        "src/csd_foundry/empirical/e0h/harness/finalize.py",
        "src/csd_foundry/empirical/e0h/harness/infer.py",
        "src/csd_foundry/empirical/e0h/harness/package_lock.py",
        "src/csd_foundry/empirical/e0h/harness/package_manifest.py",
        "src/csd_foundry/empirical/e0h/harness/preflight.py",
        "src/csd_foundry/empirical/e0h/harness/reload.py",
        "src/csd_foundry/empirical/e0h/harness/smoke_eval.py",
        "src/csd_foundry/empirical/e0h/harness/tokenize.py",
        "src/csd_foundry/empirical/e0h/harness/train.py",
        "src/csd_foundry/empirical/e1/artifact_set_io.py",
        "src/csd_foundry/empirical/e1/foundry_artifact_compiler.py",
        "src/csd_foundry/synthesis/v0_4/serialization.py",
    }
)


def expected_execution_package_paths() -> frozenset[str]:
    """Return the closed execution-critical repository file set."""

    return _EXPECTED_PATHS


def _receipts(manifest: dict[str, object]) -> tuple[dict[str, object], ...]:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise E0HRunReleaseError("execution-package files must be a list")
    receipts: list[dict[str, object]] = []
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise E0HRunReleaseError("execution-package file receipt must be an object")
        receipt = cast(dict[str, object], raw)
        if set(receipt) != {"path", "sha256", "size_bytes"}:
            raise E0HRunReleaseError("execution-package file receipt fields do not match schema")
        path = receipt["path"]
        digest = receipt["sha256"]
        size = receipt["size_bytes"]
        if not isinstance(path, str):
            raise E0HRunReleaseError("execution-package path must be a string")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != path:
            raise E0HRunReleaseError(f"execution-package path is not canonical: {path}")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise E0HRunReleaseError("execution-package digest must be lowercase SHA-256")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise E0HRunReleaseError("execution-package size must be a positive integer")
        receipts.append(receipt)
    paths = [cast(str, receipt["path"]) for receipt in receipts]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise E0HRunReleaseError("execution-package paths must be unique and sorted")
    if set(paths) != _EXPECTED_PATHS:
        raise E0HRunReleaseError(
            "execution-package file set mismatch; "
            f"missing={sorted(_EXPECTED_PATHS - set(paths))}, "
            f"extra={sorted(set(paths) - _EXPECTED_PATHS)}"
        )
    return tuple(receipts)


def verify_execution_package_manifest(
    paths: RunPaths,
    inputs: E0HRunReleaseInputs,
) -> dict[str, object]:
    """Fail unless every execution-critical file equals its committed receipt."""

    manifest = read_json_object(paths.run_root / "execution_package_manifest.json")
    expected_fields = {
        "claim_boundary",
        "compiler_base_commit",
        "file_count",
        "files",
        "gpu_execution_authorized",
        "python_lock_digest",
        "run_contract_digest",
        "schema_version",
    }
    if set(manifest) != expected_fields:
        raise E0HRunReleaseError("execution-package manifest fields do not match schema")
    if manifest["schema_version"] != "e0h-execution-package-manifest/1":
        raise E0HRunReleaseError("unexpected execution-package manifest schema")
    if manifest["claim_boundary"] != _CLAIM_BOUNDARY:
        raise E0HRunReleaseError("execution-package claim boundary mismatch")
    if manifest["compiler_base_commit"] != inputs.source_commit:
        raise E0HRunReleaseError("execution-package compiler base does not match run inputs")
    if type(manifest["gpu_execution_authorized"]) is not bool:
        raise E0HRunReleaseError("execution-package GPU authorization must be a boolean")
    if manifest["gpu_execution_authorized"] is not False:
        raise E0HRunReleaseError("execution-package manifest cannot authorize GPU execution")

    receipts = _receipts(manifest)
    if manifest["file_count"] != len(receipts):
        raise E0HRunReleaseError("execution-package file count mismatch")
    for receipt in receipts:
        relative = cast(str, receipt["path"])
        target = paths.repository_root / relative
        if target.is_symlink() or not target.is_file():
            raise E0HRunReleaseError(f"execution-package member is not a regular file: {relative}")
        if target.stat().st_size != cast(int, receipt["size_bytes"]):
            raise E0HRunReleaseError(f"execution-package size mismatch: {relative}")
        if sha256_file(target) != cast(str, receipt["sha256"]):
            raise E0HRunReleaseError(f"execution-package digest mismatch: {relative}")

    run_contract_digest = sha256_file(paths.compiled_release / "e0h_run_contract.json")
    if manifest["run_contract_digest"] != run_contract_digest:
        raise E0HRunReleaseError("execution-package run-contract digest mismatch")
    python_lock = read_json_object(paths.run_root / "python_lock.json")
    if manifest["python_lock_digest"] != python_lock.get("lock_digest"):
        raise E0HRunReleaseError("execution-package Python-lock digest mismatch")
    return manifest
