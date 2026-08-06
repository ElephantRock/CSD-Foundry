from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from csd_foundry.empirical.e0h.windows_native import (
    EXPECTED_ARCHITECTURE,
    EXPECTED_CUDA_RUNTIME,
    EXPECTED_EXECUTION_MODE,
    EXPECTED_GPU_MODEL,
    EXPECTED_OS_FAMILY,
    EXPECTED_PYTHON_IMPLEMENTATION,
    EXPECTED_PYTHON_VERSION,
    EXPECTED_TORCH_VERSION,
    HOST_INVENTORY_DIGEST,
    DependencyPin,
    WindowsNativeE0HError,
    WindowsNativeEnvironment,
    canonical_json_text,
    canonical_sha256,
    dependency_lock,
    deterministic_zip,
    executable_command,
    run_process,
)

ROOT = Path(__file__).parents[1]
RELEASE_ROOT = ROOT / "experiments" / "e0h" / "windows_native_v1"
DEPENDENCY_DIGEST = "d9656823adaa1ce856c871a446a5f2f16d0db5a190137527a3158e5b66009531"


def _load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _environment(**overrides: object) -> WindowsNativeEnvironment:
    values: dict[str, object] = {
        "execution_mode": EXPECTED_EXECUTION_MODE,
        "os_family": EXPECTED_OS_FAMILY,
        "os_build": "26200",
        "architecture": EXPECTED_ARCHITECTURE,
        "python_implementation": EXPECTED_PYTHON_IMPLEMENTATION,
        "python_version": EXPECTED_PYTHON_VERSION,
        "python_executable_sha256": "4" * 64,
        "torch_version": EXPECTED_TORCH_VERSION,
        "torch_cuda_runtime": EXPECTED_CUDA_RUNTIME,
        "transformers_version": "4.50.0",
        "accelerate_version": "1.1.1",
        "gpu_model": EXPECTED_GPU_MODEL,
        "gpu_count": 1,
        "nvidia_driver_version": "610.47",
        "dependency_lock_digest": DEPENDENCY_DIGEST,
        "host_inventory_digest": HOST_INVENTORY_DIGEST,
    }
    values.update(overrides)
    return WindowsNativeEnvironment(**values)  # type: ignore[arg-type]


def test_windows_native_environment_accepts_exact_profile() -> None:
    environment = _environment()
    assert environment.execution_mode == EXPECTED_EXECUTION_MODE
    assert environment.to_dict()["hardware"] == {
        "gpu_model": EXPECTED_GPU_MODEL,
        "gpu_count": 1,
        "nvidia_driver_version": "610.47",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("os_family", "Linux"),
        ("architecture", "x86_64"),
        ("python_version", "3.12.9"),
        ("torch_version", "2.6.0"),
        ("torch_cuda_runtime", "12.6"),
        ("gpu_model", "NVIDIA T4"),
        ("gpu_count", 2),
    ],
)
def test_windows_native_environment_rejects_mismatch(field: str, value: object) -> None:
    with pytest.raises(WindowsNativeE0HError):
        _environment(**{field: value})


def test_dependency_lock_is_ordered_and_digest_bound() -> None:
    lock_path = RELEASE_ROOT / "dependency_lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert canonical_json_text(lock) == lock_path.read_text(encoding="utf-8")
    assert canonical_sha256(lock) == DEPENDENCY_DIGEST
    pins = [DependencyPin(**item) for item in reversed(lock["packages"])]
    assert dependency_lock(pins) == lock


def test_compiled_release_reconstructs_exactly() -> None:
    compiler = _load_script(RELEASE_ROOT / "compile_release.py", "e0h_windows_compiler")
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    dependency = json.loads((RELEASE_ROOT / "dependency_lock.json").read_text(encoding="utf-8"))
    files = compiler.compile_files(inputs, dependency)
    compiler.validate_release(files, RELEASE_ROOT / "compiled_release")
    assert set(files) == {
        "artifact_manifest.json",
        "budget_contract.json",
        "checkpoint_contract.json",
        "dependency_lock.json",
        "e0h_run_contract.json",
        "environment_lock.json",
        "evaluation_access_contract.json",
        "launch_commands.json",
        "run_inputs_lock.json",
        "training_recipe.json",
    }


def test_compiled_release_denies_gpu_execution() -> None:
    contract = json.loads(
        (RELEASE_ROOT / "compiled_release" / "e0h_run_contract.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["gpu_execution_authorized"] is False
    assert contract["required_terminal_classification"] == [
        "HARNESS_PASSED",
        "HARNESS_FAILED",
    ]


def test_deterministic_zip_reproduces_digest(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"first\n")
    second.write_bytes(b"second\n")
    members = {"nested/second.txt": second, "first.txt": first}
    digest_one = deterministic_zip(tmp_path / "one.zip", members)
    digest_two = deterministic_zip(tmp_path / "two.zip", members)
    assert digest_one == digest_two
    assert (tmp_path / "one.zip").read_bytes() == (tmp_path / "two.zip").read_bytes()


def test_deterministic_zip_rejects_path_escape(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("value", encoding="utf-8")
    with pytest.raises(WindowsNativeE0HError):
        deterministic_zip(tmp_path / "out.zip", {"../source.txt": source})


def test_process_timeout_is_fail_closed(tmp_path: Path) -> None:
    result = run_process(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        cwd=tmp_path,
        stdout_path=tmp_path / "stdout.log",
        stderr_path=tmp_path / "stderr.log",
        timeout_seconds=1,
    )
    assert result.timed_out is True
    assert result.exit_code != 0


def test_commands_bind_to_active_interpreter() -> None:
    assert executable_command(Path("script.py"), "--flag") == [
        sys.executable,
        "script.py",
        "--flag",
    ]


def test_candidate_reference_is_sanitized() -> None:
    reference = json.loads(
        (RELEASE_ROOT / "environment_candidate_reference.json").read_text(encoding="utf-8")
    )
    serialized = canonical_json_text(reference)
    assert "GPU-" not in serialized
    assert "Users\\" not in serialized
    assert reference["artifact_committed"] is False
    assert reference["package_count"] == 444
    assert reference["package_inventory_digest"] == HOST_INVENTORY_DIGEST
