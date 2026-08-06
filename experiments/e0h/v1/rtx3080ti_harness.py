#!/usr/bin/env python3
"""RTX 3080 Ti hardware adapter for the frozen E0-H harness."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

EXPECTED_GPU_NAME = "NVIDIA GeForce RTX 3080 Ti"


def _load_base_harness() -> ModuleType:
    path = Path(__file__).with_name("harness.py")
    spec = importlib.util.spec_from_file_location("e0h_base_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load base E0-H harness from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_cuda_envelope(torch: Any, inputs: dict[str, Any]) -> None:
    environment = inputs.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("environment input must be an object")
    if not torch.cuda.is_available():
        raise RuntimeError("E0-H training requires CUDA")

    expected_gpu_count = int(environment["gpu_count"])
    observed_gpu_count = int(torch.cuda.device_count())
    if observed_gpu_count != expected_gpu_count:
        raise RuntimeError(f"GPU count mismatch: {observed_gpu_count} != {expected_gpu_count}")

    expected_name = str(environment["hardware_model"])
    if expected_name != EXPECTED_GPU_NAME:
        raise RuntimeError(
            f"frozen GPU model mismatch: {expected_name!r} != {EXPECTED_GPU_NAME!r}"
        )

    observed_name = str(torch.cuda.get_device_name(0))
    if observed_name != expected_name:
        raise RuntimeError(
            f"GPU model mismatch: observed {observed_name!r}, expected {expected_name!r}"
        )


def main() -> None:
    harness = _load_base_harness()
    harness._require_cuda_envelope = _require_cuda_envelope
    harness.main()


if __name__ == "__main__":
    main()
