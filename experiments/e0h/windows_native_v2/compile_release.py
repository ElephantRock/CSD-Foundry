#!/usr/bin/env python3
"""Compile and validate the repaired Windows-native E0-H v2 release."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
    write_canonical_json,
)

RELEASE = "e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2"
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
_CLAIM_BOUNDARY = (
    "This release qualifies only the repaired native Windows E0-H infrastructure boundary. "
    "It does not authorize GPU execution by itself and cannot establish reasoning improvement, "
    "curriculum efficacy, transfer, statistical power, or scale readiness."
)


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _environment_lock(raw: Mapping[str, object], candidate_evidence: object) -> dict[str, object]:
    observed = {field: raw.get(field) for field in _EXPECTED_ENVIRONMENT}
    mismatches = {
        field: {"expected": expected, "observed": observed[field]}
        for field, expected in _EXPECTED_ENVIRONMENT.items()
        if observed[field] != expected
    }
    if mismatches:
        raise ValueError(f"environment mismatch: {mismatches}")
    dependency_digest = raw.get("dependency_lock_digest")
    if not isinstance(dependency_digest, str) or len(dependency_digest) != 64:
        raise ValueError("dependency_lock_digest must be a SHA-256 string")
    return {
        "schema_version": "e0h-windows-native-environment/2",
        "execution_mode": raw["execution_mode"],
        "operating_system": {
            "family": raw["os_family"],
            "build": raw["os_build"],
            "architecture": raw["architecture"],
        },
        "python": {
            "implementation": raw["python_implementation"],
            "version": raw["python_version"],
            "executable_sha256": raw["python_executable_sha256"],
        },
        "framework": {
            "torch_version": raw["torch_version"],
            "torch_cuda_runtime": raw["torch_cuda_runtime"],
            "transformers_version": raw["transformers_version"],
            "accelerate_version": raw["accelerate_version"],
        },
        "hardware": {
            "gpu_model": raw["gpu_model"],
            "gpu_count": raw["gpu_count"],
            "nvidia_driver_version": raw["nvidia_driver_version"],
        },
        "dependency_lock_digest": dependency_digest,
        "host_inventory_digest": raw["host_inventory_digest"],
        "candidate_evidence": candidate_evidence,
        "powershell_semantic": False,
        "candidate_artifact_committed": False,
    }


def compile_files(inputs: dict[str, object], dependency: dict[str, object]) -> dict[str, object]:
    if inputs.get("release") != RELEASE:
        raise ValueError("release identity mismatch")
    environment_raw = inputs.get("environment")
    if not isinstance(environment_raw, dict):
        raise ValueError("environment must be an object")
    dependency_digest = canonical_sha256(dependency)
    if dependency_digest != environment_raw.get("dependency_lock_digest"):
        raise ValueError("dependency lock digest mismatch")
    candidate_evidence = inputs.get("candidate_evidence")
    if not isinstance(candidate_evidence, dict):
        raise ValueError("candidate_evidence must be an object")
    environment_lock = _environment_lock(environment_raw, candidate_evidence)

    commands = inputs.get("commands")
    if not isinstance(commands, dict):
        raise ValueError("commands must be an object")
    command_digests = {name: canonical_sha256(argv) for name, argv in sorted(commands.items())}
    launch_commands = {
        "schema_version": "e0h-windows-native-launch-commands/2",
        "interpreter_binding": "sys.executable",
        "shell": False,
        "commands": commands,
        "command_digests": command_digests,
    }
    storage = inputs.get("storage")
    budget = inputs.get("budget")
    if not isinstance(storage, dict) or not isinstance(budget, dict):
        raise ValueError("storage and budget must be objects")
    checkpoint = {
        "schema_version": "e0h-checkpoint-contract/1",
        "checkpoint_uri": storage["checkpoint_uri"],
        "save_required": True,
        "reload_required": True,
        "digest_publication_required": True,
        "max_checkpoint_gib": budget["max_checkpoint_gib"],
        "retention_days": budget["checkpoint_retention_days"],
    }
    preliminary = {
        "run_inputs_lock.json": inputs,
        "environment_lock.json": environment_lock,
        "dependency_lock.json": dependency,
        "training_recipe.json": inputs["recipe"],
        "budget_contract.json": budget,
        "checkpoint_contract.json": checkpoint,
        "evaluation_access_contract.json": inputs["evaluation"],
        "launch_commands.json": launch_commands,
    }
    run_contract = {
        "schema_version": "e0h-windows-native-run-contract/2",
        "release": RELEASE,
        "source_commit": inputs["source_commit"],
        "run_inputs_lock_digest": canonical_sha256(inputs),
        "environment_digest": canonical_sha256(environment_lock),
        "dependency_lock_digest": dependency_digest,
        "recipe_digest": canonical_sha256(inputs["recipe"]),
        "budget_digest": canonical_sha256(budget),
        "checkpoint_digest": canonical_sha256(checkpoint),
        "evaluation_access_digest": canonical_sha256(inputs["evaluation"]),
        "launch_commands_digest": canonical_sha256(launch_commands),
        "model_digest": canonical_sha256(inputs["model"]),
        "tokenizer_digest": canonical_sha256(inputs["tokenizer"]),
        "gpu_execution_authorized": False,
        "required_terminal_classification": ["HARNESS_PASSED", "HARNESS_FAILED"],
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    preliminary["e0h_run_contract.json"] = run_contract
    manifest_files = [
        {
            "path": path,
            "sha256": canonical_sha256(value),
            "byte_count": len(canonical_json_text(value).encode("utf-8")),
        }
        for path, value in sorted(preliminary.items())
    ]
    manifest = {
        "schema_version": "e0h-windows-native-artifact-manifest/2",
        "release": RELEASE,
        "file_count": len(preliminary),
        "files": manifest_files,
        "run_contract_digest": canonical_sha256(run_contract),
    }
    return {**preliminary, "artifact_manifest.json": manifest}


def write_release(files: Mapping[str, object], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    for name, value in sorted(files.items()):
        write_canonical_json(output_dir / name, value)


def validate_release(files: Mapping[str, object], output_dir: Path) -> None:
    expected_names = set(files)
    observed_names = {path.name for path in output_dir.iterdir() if path.is_file()}
    if observed_names != expected_names:
        raise ValueError(
            f"compiled release file mismatch: expected={sorted(expected_names)}, "
            f"observed={sorted(observed_names)}"
        )
    for name, expected in files.items():
        observed = (output_dir / name).read_text(encoding="utf-8")
        if observed != canonical_json_text(expected):
            raise ValueError(f"compiled release mismatch: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    files = compile_files(_load_canonical(args.inputs), _load_canonical(args.dependency_lock))
    if args.validate:
        validate_release(files, args.output_dir)
    else:
        write_release(files, args.output_dir)


if __name__ == "__main__":
    main()
