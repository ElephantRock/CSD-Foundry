#!/usr/bin/env python3
"""Native Windows adapter for the reviewed E0-H harness."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import platform
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from csd_foundry.empirical.e0h.windows_native import (
    EXPECTED_ARCHITECTURE,
    EXPECTED_CUDA_RUNTIME,
    EXPECTED_EXECUTION_MODE,
    EXPECTED_GPU_COUNT,
    EXPECTED_GPU_MODEL,
    EXPECTED_OS_FAMILY,
    EXPECTED_PYTHON_VERSION,
    EXPECTED_TORCH_VERSION,
    file_sha256,
)


def _load_base_harness() -> ModuleType:
    path = Path(__file__).parents[1] / "v1" / "harness.py"
    spec = importlib.util.spec_from_file_location("e0h_base_harness_windows_native", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load base E0-H harness from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_cuda_envelope(torch: Any, inputs: dict[str, Any]) -> None:
    environment = inputs.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("environment input must be an object")
    expected = {
        "execution_mode": EXPECTED_EXECUTION_MODE,
        "os_family": EXPECTED_OS_FAMILY,
        "architecture": EXPECTED_ARCHITECTURE,
        "python_version": EXPECTED_PYTHON_VERSION,
        "python_executable_sha256": str(environment["python_executable_sha256"]),
        "torch_version": EXPECTED_TORCH_VERSION,
        "torch_cuda_runtime": EXPECTED_CUDA_RUNTIME,
        "transformers_version": str(environment["transformers_version"]),
        "accelerate_version": str(environment["accelerate_version"]),
        "gpu_model": EXPECTED_GPU_MODEL,
        "gpu_count": EXPECTED_GPU_COUNT,
    }
    observed = {
        "execution_mode": environment.get("execution_mode"),
        "os_family": platform.system(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable_sha256": file_sha256(Path(sys.executable)),
        "torch_version": str(torch.__version__),
        "torch_cuda_runtime": str(torch.version.cuda),
        "transformers_version": importlib.metadata.version("transformers"),
        "accelerate_version": importlib.metadata.version("accelerate"),
        "gpu_model": str(torch.cuda.get_device_name(0)) if torch.cuda.is_available() else None,
        "gpu_count": int(torch.cuda.device_count()),
    }
    mismatches = {
        field: {"expected": expected[field], "observed": observed[field]}
        for field in expected
        if observed[field] != expected[field]
    }
    if not torch.cuda.is_available():
        mismatches["cuda_available"] = {"expected": True, "observed": False}
    if mismatches:
        raise RuntimeError(f"Windows-native E0-H environment mismatch: {mismatches}")


def main() -> None:
    harness = _load_base_harness()
    harness._require_cuda_envelope = _require_cuda_envelope
    harness.main()


if __name__ == "__main__":
    main()
