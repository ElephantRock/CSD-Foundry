"""Governed Windows-native E0-H environment and execution utilities."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence

EXPECTED_EXECUTION_MODE = "windows_native_shared"
EXPECTED_OS_FAMILY = "Windows"
EXPECTED_ARCHITECTURE = "AMD64"
EXPECTED_PYTHON_IMPLEMENTATION = "CPython"
EXPECTED_PYTHON_VERSION = "3.12.10"
EXPECTED_TORCH_VERSION = "2.6.0+cu124"
EXPECTED_CUDA_RUNTIME = "12.4"
EXPECTED_GPU_MODEL = "NVIDIA GeForce RTX 3080 Ti"
EXPECTED_GPU_COUNT = 1
RELEASE = "e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1"
CANDIDATE_SHA256 = "d5c1f39ffdc5eb2ca74c602a33fe1673bce36490348094d29f83635de88fdf54"
HOST_INVENTORY_DIGEST = "e1243681291029469be549df70fb7bc4b8949200f7a2687257fe063c068a1554"


class WindowsNativeE0HError(ValueError):
    """Raised when the Windows-native E0-H boundary is violated."""


def canonical_json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_text(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_canonical_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json_text(value))


@dataclass(frozen=True, slots=True)
class DependencyPin:
    """One exact package version in the E0-H runtime closure."""

    name: str
    version: str

    def __post_init__(self) -> None:
        if not self.name or any(character.isspace() for character in self.name):
            raise WindowsNativeE0HError("dependency name must be nonempty and whitespace-free")
        if not self.version or any(character.isspace() for character in self.version):
            raise WindowsNativeE0HError("dependency version must be exact and whitespace-free")

    @property
    def normalized_name(self) -> str:
        return self.name.casefold().replace("_", "-")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True, slots=True)
class WindowsNativeEnvironment:
    """Exact native Windows software and hardware envelope for E0-H."""

    execution_mode: str
    os_family: str
    os_build: str
    architecture: str
    python_implementation: str
    python_version: str
    python_executable_sha256: str
    torch_version: str
    torch_cuda_runtime: str
    transformers_version: str
    accelerate_version: str
    gpu_model: str
    gpu_count: int
    nvidia_driver_version: str
    dependency_lock_digest: str
    host_inventory_digest: str

    def __post_init__(self) -> None:
        expected = {
            "execution_mode": EXPECTED_EXECUTION_MODE,
            "os_family": EXPECTED_OS_FAMILY,
            "architecture": EXPECTED_ARCHITECTURE,
            "python_implementation": EXPECTED_PYTHON_IMPLEMENTATION,
            "python_version": EXPECTED_PYTHON_VERSION,
            "torch_version": EXPECTED_TORCH_VERSION,
            "torch_cuda_runtime": EXPECTED_CUDA_RUNTIME,
            "gpu_model": EXPECTED_GPU_MODEL,
            "host_inventory_digest": HOST_INVENTORY_DIGEST,
        }
        observed = {
            "execution_mode": self.execution_mode,
            "os_family": self.os_family,
            "architecture": self.architecture,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "torch_version": self.torch_version,
            "torch_cuda_runtime": self.torch_cuda_runtime,
            "gpu_model": self.gpu_model,
            "host_inventory_digest": self.host_inventory_digest,
        }
        mismatches = {
            field: {"expected": expected[field], "observed": observed[field]}
            for field in expected
            if observed[field] != expected[field]
        }
        if mismatches:
            raise WindowsNativeE0HError(f"environment mismatch: {mismatches}")
        if self.gpu_count != EXPECTED_GPU_COUNT:
            raise WindowsNativeE0HError(
                f"gpu_count must be {EXPECTED_GPU_COUNT}, observed {self.gpu_count}"
            )
        for field, value in (
            ("os_build", self.os_build),
            ("transformers_version", self.transformers_version),
            ("accelerate_version", self.accelerate_version),
            ("nvidia_driver_version", self.nvidia_driver_version),
        ):
            if not value or any(character.isspace() for character in value):
                raise WindowsNativeE0HError(f"{field} must be an exact nonempty scalar")
        for field, value in (
            ("python_executable_sha256", self.python_executable_sha256),
            ("dependency_lock_digest", self.dependency_lock_digest),
            ("host_inventory_digest", self.host_inventory_digest),
        ):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise WindowsNativeE0HError(f"{field} must be a lowercase SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e0h-windows-native-environment/1",
            "execution_mode": self.execution_mode,
            "operating_system": {
                "family": self.os_family,
                "build": self.os_build,
                "architecture": self.architecture,
            },
            "python": {
                "implementation": self.python_implementation,
                "version": self.python_version,
                "executable_sha256": self.python_executable_sha256,
            },
            "framework": {
                "torch_version": self.torch_version,
                "torch_cuda_runtime": self.torch_cuda_runtime,
                "transformers_version": self.transformers_version,
                "accelerate_version": self.accelerate_version,
            },
            "hardware": {
                "gpu_model": self.gpu_model,
                "gpu_count": self.gpu_count,
                "nvidia_driver_version": self.nvidia_driver_version,
            },
            "dependency_lock_digest": self.dependency_lock_digest,
            "host_inventory_digest": self.host_inventory_digest,
        }


def dependency_lock(pins: Iterable[DependencyPin]) -> dict[str, object]:
    ordered = sorted(pins, key=lambda pin: pin.normalized_name)
    normalized = [pin.normalized_name for pin in ordered]
    if len(normalized) != len(set(normalized)):
        raise WindowsNativeE0HError("dependency lock contains duplicate normalized names")
    return {
        "schema_version": "e0h-windows-native-dependency-lock/1",
        "scope": "normative_e0h_runtime_closure",
        "packages": [pin.to_dict() for pin in ordered],
    }


def validate_installed_dependencies(lock: Mapping[str, object]) -> dict[str, str]:
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise WindowsNativeE0HError("dependency lock packages must be a list")
    observed: dict[str, str] = {}
    for raw in packages:
        if not isinstance(raw, dict):
            raise WindowsNativeE0HError("dependency lock entries must be objects")
        pin = DependencyPin(name=str(raw.get("name", "")), version=str(raw.get("version", "")))
        try:
            version = importlib.metadata.version(pin.name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise WindowsNativeE0HError(f"missing dependency: {pin.name}") from exc
        if version != pin.version:
            raise WindowsNativeE0HError(
                f"dependency mismatch for {pin.name}: {version} != {pin.version}"
            )
        observed[pin.normalized_name] = version
    return observed


def require_source_import(repo_root: Path) -> str:
    import csd_foundry

    package_file = csd_foundry.__file__
    if package_file is None:
        raise WindowsNativeE0HError("csd_foundry package has no source file")
    package_path = Path(package_file).resolve()
    expected_root = (repo_root / "src" / "csd_foundry").resolve()
    try:
        package_path.relative_to(expected_root)
    except ValueError as exc:
        raise WindowsNativeE0HError(
            f"csd_foundry imported outside checked-out source tree: {package_path}"
        ) from exc
    return package_path.as_posix()


def observed_environment(
    repo_root: Path, dependency_lock_value: Mapping[str, object]
) -> dict[str, object]:
    import accelerate
    import torch
    import transformers

    python_path = Path(sys.executable)
    return {
        "schema_version": "e0h-windows-native-observed-environment/1",
        "execution_mode": EXPECTED_EXECUTION_MODE,
        "operating_system": {
            "family": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "build": platform.version().split(".")[-1],
            "architecture": platform.machine(),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "executable_sha256": file_sha256(python_path),
        },
        "framework": {
            "torch_version": str(torch.__version__),
            "torch_cuda_runtime": str(torch.version.cuda),
            "transformers_version": str(transformers.__version__),
            "accelerate_version": str(accelerate.__version__),
            "cuda_available": bool(torch.cuda.is_available()),
        },
        "hardware": {
            "gpu_count": int(torch.cuda.device_count()),
            "gpu_model": str(torch.cuda.get_device_name(0)) if torch.cuda.is_available() else None,
        },
        "dependency_lock_digest": canonical_sha256(dependency_lock_value),
        "source_import": require_source_import(repo_root),
    }


def validate_observed_environment(
    observed: Mapping[str, object], expected: WindowsNativeEnvironment
) -> None:
    operating_system = observed.get("operating_system")
    python = observed.get("python")
    framework = observed.get("framework")
    hardware = observed.get("hardware")
    shaped_values = (operating_system, python, framework, hardware)
    if not all(isinstance(item, Mapping) for item in shaped_values):
        raise WindowsNativeE0HError("observed environment has an invalid shape")
    assert isinstance(operating_system, Mapping)
    assert isinstance(python, Mapping)
    assert isinstance(framework, Mapping)
    assert isinstance(hardware, Mapping)
    checks = {
        "execution_mode": (observed.get("execution_mode"), expected.execution_mode),
        "os_family": (operating_system.get("family"), expected.os_family),
        "architecture": (operating_system.get("architecture"), expected.architecture),
        "python_implementation": (
            python.get("implementation"),
            expected.python_implementation,
        ),
        "python_version": (python.get("version"), expected.python_version),
        "python_executable_sha256": (
            python.get("executable_sha256"),
            expected.python_executable_sha256,
        ),
        "torch_version": (framework.get("torch_version"), expected.torch_version),
        "torch_cuda_runtime": (
            framework.get("torch_cuda_runtime"),
            expected.torch_cuda_runtime,
        ),
        "transformers_version": (
            framework.get("transformers_version"),
            expected.transformers_version,
        ),
        "accelerate_version": (
            framework.get("accelerate_version"),
            expected.accelerate_version,
        ),
        "cuda_available": (framework.get("cuda_available"), True),
        "gpu_count": (hardware.get("gpu_count"), expected.gpu_count),
        "gpu_model": (hardware.get("gpu_model"), expected.gpu_model),
        "dependency_lock_digest": (
            observed.get("dependency_lock_digest"),
            expected.dependency_lock_digest,
        ),
    }
    mismatches = {
        field: {"observed": pair[0], "expected": pair[1]}
        for field, pair in checks.items()
        if pair[0] != pair[1]
    }
    if mismatches:
        raise WindowsNativeE0HError(f"observed native environment mismatch: {mismatches}")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    exit_code: int
    elapsed_seconds_ceil: int
    timed_out: bool
    stdout_path: str
    stderr_path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "exit_code": self.exit_code,
            "elapsed_seconds_ceil": self.elapsed_seconds_ceil,
            "timed_out": self.timed_out,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
        }


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return


def run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
) -> ProcessResult:
    if timeout_seconds <= 0:
        raise WindowsNativeE0HError("timeout_seconds must be positive")
    if stdout_path.exists() or stderr_path.exists():
        raise WindowsNativeE0HError("process logs are no-clobber outputs")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    start_new_session = os.name != "nt"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
        timed_out = False
        try:
            exit_code = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_tree(process)
            try:
                exit_code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                exit_code = process.wait()
    elapsed = int(time.monotonic() - started)
    if time.monotonic() - started > elapsed:
        elapsed += 1
    return ProcessResult(
        argv=tuple(str(item) for item in argv),
        exit_code=int(exit_code),
        elapsed_seconds_ceil=elapsed,
        timed_out=timed_out,
        stdout_path=stdout_path.as_posix(),
        stderr_path=stderr_path.as_posix(),
    )


def deterministic_zip(output_path: Path, members: Mapping[str, Path]) -> str:
    """Create a deterministic deflated ZIP archive from relative POSIX member names."""

    if output_path.exists():
        raise WindowsNativeE0HError("archive output already exists")
    normalized: list[tuple[str, Path]] = []
    for archive_name, source in members.items():
        name = PurePosixPath(archive_name)
        if name.is_absolute() or ".." in name.parts or str(name) in {"", "."}:
            raise WindowsNativeE0HError(f"invalid archive member path: {archive_name}")
        if not source.is_file():
            raise WindowsNativeE0HError(f"archive source is not a file: {source}")
        normalized.append((str(name), source))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output_path,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for archive_name, source in sorted(normalized):
            info = zipfile.ZipInfo(archive_name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    return file_sha256(output_path)


def executable_command(script: Path, *arguments: str) -> list[str]:
    return [sys.executable, str(script), *arguments]


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
