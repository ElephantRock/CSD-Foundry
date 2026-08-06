#!/usr/bin/env python3
"""Read-only preflight for the repaired Windows-native E0-H v2 release."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType

from packaging.requirements import Requirement

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
    observed_environment,
    validate_installed_dependencies,
    write_canonical_json,
)

_EXPECTED_RELEASE = "e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2"
_EXPECTED_ENVIRONMENT = {
    "execution_mode": "windows_native_shared",
    "os_family": "Windows",
    "os_build": "26200",
    "architecture": "AMD64",
    "python_implementation": "CPython",
    "python_version": "3.12.10",
    "python_executable_sha256": "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a",
    "torch_version": "2.6.0+cu124",
    "torch_cuda_runtime": "12.4",
    "transformers_version": "4.50.0",
    "accelerate_version": "1.1.1",
    "gpu_model": "NVIDIA GeForce RTX 3080 Ti",
    "gpu_count": 1,
    "nvidia_driver_version": "610.47",
    "host_inventory_digest": "c0dcea8f66b042d2a6bd6d676c4c72c5fc955962e254045abc1f37bd8fda6d10",
}


def _load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_base_preflight() -> ModuleType:
    return _load_module(
        Path(__file__).parents[1] / "v1" / "preflight.py",
        "e0h_base_preflight_windows_native_v2",
    )


def _load_base_harness() -> ModuleType:
    return _load_module(
        Path(__file__).parents[1] / "v1" / "harness.py",
        "e0h_base_harness_windows_native_v2",
    )


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _normalized_name(name: str) -> str:
    return name.casefold().replace("_", "-")


def _pip_inventory() -> tuple[list[dict[str, str]], str]:
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format=json"],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    raw = json.loads(completed.stdout)
    if not isinstance(raw, list):
        raise RuntimeError("pip list did not return an array")
    inventory: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise RuntimeError("pip inventory entry is not an object")
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise RuntimeError("pip inventory entry lacks name/version")
        inventory.append({"name": name, "version": version})
    inventory.sort(key=lambda item: item["name"])
    return inventory, canonical_sha256(inventory)


def _validate_environment(
    observed: Mapping[str, object],
    expected_raw: Mapping[str, object],
    inventory_digest: str,
) -> None:
    operating_system = observed.get("operating_system")
    python = observed.get("python")
    framework = observed.get("framework")
    hardware = observed.get("hardware")
    if not all(
        isinstance(value, Mapping) for value in (operating_system, python, framework, hardware)
    ):
        raise RuntimeError("observed environment has an invalid shape")
    assert isinstance(operating_system, Mapping)
    assert isinstance(python, Mapping)
    assert isinstance(framework, Mapping)
    assert isinstance(hardware, Mapping)
    checks = {
        "execution_mode": (
            observed.get("execution_mode"),
            expected_raw["execution_mode"],
        ),
        "os_family": (operating_system.get("family"), expected_raw["os_family"]),
        "os_build": (operating_system.get("build"), expected_raw["os_build"]),
        "architecture": (
            operating_system.get("architecture"),
            expected_raw["architecture"],
        ),
        "python_implementation": (
            python.get("implementation"),
            expected_raw["python_implementation"],
        ),
        "python_version": (python.get("version"), expected_raw["python_version"]),
        "python_executable_sha256": (
            python.get("executable_sha256"),
            expected_raw["python_executable_sha256"],
        ),
        "torch_version": (
            framework.get("torch_version"),
            expected_raw["torch_version"],
        ),
        "torch_cuda_runtime": (
            framework.get("torch_cuda_runtime"),
            expected_raw["torch_cuda_runtime"],
        ),
        "transformers_version": (
            framework.get("transformers_version"),
            expected_raw["transformers_version"],
        ),
        "accelerate_version": (
            framework.get("accelerate_version"),
            expected_raw["accelerate_version"],
        ),
        "cuda_available": (framework.get("cuda_available"), True),
        "gpu_count": (hardware.get("gpu_count"), expected_raw["gpu_count"]),
        "gpu_model": (hardware.get("gpu_model"), expected_raw["gpu_model"]),
        "dependency_lock_digest": (
            observed.get("dependency_lock_digest"),
            expected_raw["dependency_lock_digest"],
        ),
        "host_inventory_digest": (
            inventory_digest,
            expected_raw["host_inventory_digest"],
        ),
    }
    mismatches = {
        field: {"observed": pair[0], "expected": pair[1]}
        for field, pair in checks.items()
        if pair[0] != pair[1]
    }
    if mismatches:
        raise RuntimeError(f"observed native environment mismatch: {mismatches}")


def _validate_distribution_requirements(
    distribution: str, lock: Mapping[str, object]
) -> list[dict[str, str]]:
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise RuntimeError("dependency lock packages must be an array")
    pins = {
        _normalized_name(str(item["name"])): str(item["version"])
        for item in packages
        if isinstance(item, dict) and "name" in item and "version" in item
    }
    requirements = importlib.metadata.requires(distribution)
    if requirements is None:
        raise RuntimeError(f"{distribution} has no requirement metadata")
    checked: list[dict[str, str]] = []
    for raw in requirements:
        requirement = Requirement(raw)
        if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
            continue
        normalized = _normalized_name(requirement.name)
        if normalized not in pins:
            raise RuntimeError(
                f"{distribution} dependency {requirement.name} is absent from the lock"
            )
        installed = importlib.metadata.version(requirement.name)
        if requirement.specifier and installed not in requirement.specifier:
            raise RuntimeError(
                f"{distribution} dependency {requirement.name}=={installed} "
                f"does not satisfy {requirement.specifier}"
            )
        if installed != pins[normalized]:
            raise RuntimeError(
                f"{distribution} dependency {requirement.name}=={installed} "
                f"does not match locked {pins[normalized]}"
            )
        checked.append(
            {
                "name": requirement.name,
                "specifier": str(requirement.specifier),
                "version": installed,
            }
        )
    checked.sort(key=lambda item: _normalized_name(item["name"]))
    return checked


def _training_stack_receipt() -> dict[str, object]:
    harness = _load_base_harness()
    torch, auto_model, auto_tokenizer, trainer_types = harness._load_stack()
    trainer_class, training_arguments_class = trainer_types
    import datasets
    import pyarrow

    return {
        "schema_version": "e0h-windows-native-training-stack-preflight/1",
        "training_stack_import_complete": True,
        "torch_version": str(torch.__version__),
        "datasets_version": str(datasets.__version__),
        "pyarrow_version": str(pyarrow.__version__),
        "trainer_class": f"{trainer_class.__module__}.{trainer_class.__name__}",
        "training_arguments_class": (
            f"{training_arguments_class.__module__}.{training_arguments_class.__name__}"
        ),
        "auto_model_class": f"{auto_model.__module__}.{auto_model.__name__}",
        "auto_tokenizer_class": (f"{auto_tokenizer.__module__}.{auto_tokenizer.__name__}"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    if inputs.get("release") != _EXPECTED_RELEASE:
        raise ValueError("run input release does not match repaired preflight")
    lock = _load_canonical(args.dependency_lock)
    environment_raw = inputs.get("environment")
    if not isinstance(environment_raw, dict):
        raise ValueError("run inputs environment must be an object")
    mismatches = {
        field: {"expected": expected, "observed": environment_raw.get(field)}
        for field, expected in _EXPECTED_ENVIRONMENT.items()
        if environment_raw.get(field) != expected
    }
    if mismatches:
        raise RuntimeError(f"frozen environment mismatch: {mismatches}")

    repo_root = Path(__file__).resolve().parents[3]
    installed = validate_installed_dependencies(lock)
    inventory, inventory_digest = _pip_inventory()
    observed = observed_environment(repo_root, lock)
    _validate_environment(observed, environment_raw, inventory_digest)
    requirement_receipt = _validate_distribution_requirements("datasets", lock)
    training_stack = _training_stack_receipt()

    base = _load_base_preflight()
    compatibility_inputs = dict(inputs)
    compatibility_environment = dict(environment_raw)
    compatibility_environment.update(
        {
            "container_image": "native-windows://shared-bare-metal-v2",
            "cuda_version": environment_raw["torch_cuda_runtime"],
            "hardware_model": environment_raw["gpu_model"],
        }
    )
    compatibility_inputs["environment"] = compatibility_environment

    args.output_dir.mkdir(parents=True, exist_ok=False)
    asset_receipt = base.verify_assets(compatibility_inputs, args.cache_dir)
    asset_receipt.pop("container_image", None)
    asset_receipt.pop("container_platform", None)
    asset_receipt["execution_mode"] = "windows_native_shared"

    write_canonical_json(args.output_dir / "external_asset_receipt.json", asset_receipt)
    write_canonical_json(
        args.output_dir / "environment_receipt.json",
        {
            "schema_version": "e0h-windows-native-environment-receipt/2",
            "expected": environment_raw,
            "observed": observed,
            "installed_dependency_versions": installed,
        },
    )
    write_canonical_json(
        args.output_dir / "host_inventory_receipt.json",
        {
            "schema_version": "e0h-windows-native-host-inventory-receipt/1",
            "package_count": len(inventory),
            "package_inventory_digest": inventory_digest,
            "expected_package_count": inputs["candidate_evidence"]["package_count"],
            "expected_package_inventory_digest": environment_raw["host_inventory_digest"],
        },
    )
    write_canonical_json(
        args.output_dir / "dependency_requirements_receipt.json",
        {
            "schema_version": "e0h-dependency-requirements-receipt/1",
            "distribution": "datasets",
            "requirements": requirement_receipt,
        },
    )
    write_canonical_json(args.output_dir / "training_stack_preflight.json", training_stack)
    write_canonical_json(
        args.output_dir / "tokenization_receipt.json",
        base.tokenize(compatibility_inputs),
    )
    write_canonical_json(
        args.output_dir / "minimal_device_preflight.json",
        base.preflight(compatibility_inputs),
    )


if __name__ == "__main__":
    main()
