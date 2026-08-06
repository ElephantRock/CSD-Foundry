#!/usr/bin/env python3
"""Read-only preflight for the governed Windows-native E0-H release."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from types import ModuleType

from csd_foundry.empirical.e0h.windows_native import (
    WindowsNativeEnvironment,
    canonical_json_text,
    observed_environment,
    validate_installed_dependencies,
    validate_observed_environment,
    write_canonical_json,
)


def _load_base_preflight() -> ModuleType:
    path = Path(__file__).parents[1] / "v1" / "preflight.py"
    spec = importlib.util.spec_from_file_location("e0h_base_preflight_windows_native", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load base E0-H preflight from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _expected_environment(value: dict[str, object]) -> WindowsNativeEnvironment:
    return WindowsNativeEnvironment(
        execution_mode=str(value["execution_mode"]),
        os_family=str(value["os_family"]),
        os_build=str(value["os_build"]),
        architecture=str(value["architecture"]),
        python_implementation=str(value["python_implementation"]),
        python_version=str(value["python_version"]),
        python_executable_sha256=str(value["python_executable_sha256"]),
        torch_version=str(value["torch_version"]),
        torch_cuda_runtime=str(value["torch_cuda_runtime"]),
        transformers_version=str(value["transformers_version"]),
        accelerate_version=str(value["accelerate_version"]),
        gpu_model=str(value["gpu_model"]),
        gpu_count=int(value["gpu_count"]),
        nvidia_driver_version=str(value["nvidia_driver_version"]),
        dependency_lock_digest=str(value["dependency_lock_digest"]),
        host_inventory_digest=str(value["host_inventory_digest"]),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    lock = _load_canonical(args.dependency_lock)
    environment_raw = inputs.get("environment")
    if not isinstance(environment_raw, dict):
        raise ValueError("run inputs environment must be an object")
    expected = _expected_environment(environment_raw)

    repo_root = Path(__file__).resolve().parents[3]
    installed = validate_installed_dependencies(lock)
    observed = observed_environment(repo_root, lock)
    validate_observed_environment(observed, expected)

    base = _load_base_preflight()
    compatibility_inputs = dict(inputs)
    compatibility_environment = dict(environment_raw)
    compatibility_environment.update(
        {
            "container_image": "native-windows://shared-bare-metal",
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
            "schema_version": "e0h-windows-native-environment-receipt/1",
            "expected": expected.to_dict(),
            "observed": observed,
            "installed_dependency_versions": installed,
        },
    )
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
