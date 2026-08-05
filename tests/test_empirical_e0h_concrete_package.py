from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from csd_foundry.empirical.e0h import (
    compile_e0h_run_release,
    validate_e0h_run_release,
)
from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    load_inputs,
    verify_static_inputs,
)
from csd_foundry.empirical.e0h.harness.finalize import (
    _gpu_minutes,
    finalize_execution,
)
from csd_foundry.empirical.e0h.harness.package_lock import (
    _lock_digest,
    verify_python_lock,
)
from csd_foundry.empirical.e0h.harness.package_manifest import (
    expected_execution_package_paths,
    verify_execution_package_manifest,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RUN_ROOT = _REPOSITORY_ROOT / "experiments" / "e0h" / "v1"


def _paths() -> RunPaths:
    return RunPaths.resolve(_RUN_ROOT)


def _copy_lock_files(tmp_path: Path) -> RunPaths:
    run_root = tmp_path / "repository" / "experiments" / "e0h" / "v1"
    run_root.mkdir(parents=True)
    for name in ("python_lock.json", "requirements-cu128.lock"):
        shutil.copy2(_RUN_ROOT / name, run_root / name)
    return RunPaths.resolve(run_root)


def test_concrete_package_reconstructs_and_remains_non_authorizing() -> None:
    paths = _paths()
    inputs = verify_static_inputs(paths, require_snapshot=False)
    python_lock = verify_python_lock(paths, inputs)
    package_manifest = verify_execution_package_manifest(paths, inputs)
    bundle = compile_e0h_run_release(inputs)
    report = validate_e0h_run_release(paths.compiled_release, inputs)

    assert report.success, report.errors
    assert bundle.run_contract_digest == package_manifest["run_contract_digest"]
    assert python_lock["lock_digest"] == package_manifest["python_lock_digest"]
    assert package_manifest["file_count"] == len(expected_execution_package_paths())
    assert package_manifest["gpu_execution_authorized"] is False
    assert inputs.evaluation.protected_metrics_access is False
    assert (
        b'"gpu_execution_authorized":false'
        in (paths.compiled_release / "e0h_run_contract.json").read_bytes()
    )


def test_python_requirements_tamper_fails_closed(tmp_path: Path) -> None:
    paths = _copy_lock_files(tmp_path)
    inputs = load_inputs(_paths())
    verify_python_lock(paths, inputs)

    requirements = paths.run_root / "requirements-cu128.lock"
    requirements.write_text(
        requirements.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    with pytest.raises(E0HRunReleaseError, match="requirements do not match"):
        verify_python_lock(paths, inputs)


def test_python_lock_rejects_boolean_package_size(tmp_path: Path) -> None:
    paths = _copy_lock_files(tmp_path)
    inputs = load_inputs(_paths())
    lock_path = paths.run_root / "python_lock.json"
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    payload["packages"][0]["size_bytes"] = True
    payload["lock_digest"] = _lock_digest(payload)
    lock_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(E0HRunReleaseError, match="size must be a positive integer"):
        verify_python_lock(paths, inputs)


def test_execution_package_member_tamper_fails_closed(tmp_path: Path) -> None:
    temporary_root = tmp_path / "repository"
    for relative in expected_execution_package_paths():
        source = _REPOSITORY_ROOT / relative
        destination = temporary_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    manifest_source = _RUN_ROOT / "execution_package_manifest.json"
    manifest_destination = temporary_root / "experiments" / "e0h" / "v1" / manifest_source.name
    shutil.copy2(manifest_source, manifest_destination)

    paths = RunPaths.resolve(temporary_root / "experiments" / "e0h" / "v1")
    inputs = load_inputs(paths)
    verify_execution_package_manifest(paths, inputs)

    target = temporary_root / "src" / "csd_foundry" / "empirical" / "e0h" / "harness" / "common.py"
    content = bytearray(target.read_bytes())
    content[0] ^= 1
    target.write_bytes(content)
    with pytest.raises(E0HRunReleaseError, match="digest mismatch"):
        verify_execution_package_manifest(paths, inputs)


@pytest.mark.parametrize("value", ["", "01", "-1", "1e1", "nan"])
def test_gpu_minutes_reject_noncanonical_values(value: str) -> None:
    with pytest.raises(E0HRunReleaseError, match="canonical nonnegative decimal"):
        _gpu_minutes(value, maximum=60)


def test_gpu_minutes_reject_budget_overrun() -> None:
    assert _gpu_minutes("60", maximum=60) == "60"
    with pytest.raises(E0HRunReleaseError, match="exceed E0-H budget"):
        _gpu_minutes("60.1", maximum=60)


def test_passed_finalization_requires_complete_evidence() -> None:
    with pytest.raises(E0HRunReleaseError, match="expected a regular file"):
        finalize_execution(
            _paths(),
            classification="HARNESS_PASSED",
            actual_gpu_minutes="0",
            failure_reason=None,
        )
