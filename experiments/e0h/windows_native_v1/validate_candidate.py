#!/usr/bin/env python3
"""Validate and sanitize a private Windows-native environment candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.empirical.e0h.windows_native import (
    CANDIDATE_SHA256,
    EXPECTED_ARCHITECTURE,
    EXPECTED_CUDA_RUNTIME,
    EXPECTED_GPU_COUNT,
    EXPECTED_GPU_MODEL,
    EXPECTED_OS_FAMILY,
    EXPECTED_PYTHON_IMPLEMENTATION,
    EXPECTED_PYTHON_VERSION,
    EXPECTED_TORCH_VERSION,
    HOST_INVENTORY_DIGEST,
    canonical_json_text,
    canonical_sha256,
    file_sha256,
    write_canonical_json,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    text = args.candidate.read_text(encoding="utf-8")
    candidate = json.loads(text)
    if not isinstance(candidate, dict) or canonical_json_text(candidate) != text:
        raise ValueError("candidate must be canonical UTF-8 LF JSON")
    if file_sha256(args.candidate) != CANDIDATE_SHA256:
        raise ValueError("candidate artifact digest mismatch")
    inventory = candidate.get("package_inventory")
    if not isinstance(inventory, list):
        raise ValueError("candidate package inventory must be a list")
    if canonical_sha256(inventory) != HOST_INVENTORY_DIGEST:
        raise ValueError("candidate package inventory digest mismatch")

    operating_system = candidate["operating_system"]
    python = candidate["python"]
    torch = candidate["torch"]
    gpu = candidate["gpu"]
    checks = {
        "execution_mode": (candidate["execution_mode"], "native"),
        "os_family": (operating_system["family"], EXPECTED_OS_FAMILY),
        "architecture": (operating_system["architecture"], EXPECTED_ARCHITECTURE),
        "python_implementation": (
            python["implementation"],
            EXPECTED_PYTHON_IMPLEMENTATION,
        ),
        "python_version": (python["version"], EXPECTED_PYTHON_VERSION),
        "torch_version": (torch["version"], EXPECTED_TORCH_VERSION),
        "torch_cuda_runtime": (torch["cuda_runtime"], EXPECTED_CUDA_RUNTIME),
        "cuda_available": (torch["cuda_available"], True),
        "gpu_count": (gpu["count"], EXPECTED_GPU_COUNT),
        "gpu_model": (gpu["name"], EXPECTED_GPU_MODEL),
        "host_inventory_digest": (
            candidate["package_inventory_digest"],
            HOST_INVENTORY_DIGEST,
        ),
    }
    mismatches = {
        field: {"observed": values[0], "expected": values[1]}
        for field, values in checks.items()
        if values[0] != values[1]
    }
    if mismatches:
        raise ValueError(f"candidate mismatch: {mismatches}")

    write_canonical_json(
        args.output,
        {
            "schema_version": "e0h-windows-native-candidate-reference/1",
            "artifact_committed": False,
            "artifact_sha256": CANDIDATE_SHA256,
            "package_count": len(inventory),
            "package_inventory_digest": HOST_INVENTORY_DIGEST,
            "powershell_semantic": False,
            "powershell_version_observed": candidate["powershell_version"],
            "observed": {
                "os_family": operating_system["family"],
                "os_build": operating_system["build"],
                "architecture": operating_system["architecture"],
                "python_implementation": python["implementation"],
                "python_version": python["version"],
                "torch_version": torch["version"],
                "torch_cuda_runtime": torch["cuda_runtime"],
                "cuda_available": torch["cuda_available"],
                "gpu_count": gpu["count"],
                "gpu_model": gpu["name"],
                "nvidia_driver_version": gpu["driver_version"],
            },
        },
    )


if __name__ == "__main__":
    main()
