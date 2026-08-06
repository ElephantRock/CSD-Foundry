#!/usr/bin/env python3
"""Compile and validate the Windows-native E0-H qualification release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

from csd_foundry.empirical.e0h.windows_native import (
    RELEASE,
    WindowsNativeEnvironment,
    canonical_json_text,
    canonical_sha256,
    write_canonical_json,
)

_CLAIM_BOUNDARY = (
    "This release qualifies only the native Windows E0-H infrastructure boundary. It does not "
    "authorize GPU execution by itself and cannot establish reasoning improvement, curriculum "
    "efficacy, transfer, statistical power, or scale readiness."
)


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _environment(raw: Mapping[str, object]) -> WindowsNativeEnvironment:
    return WindowsNativeEnvironment(
        execution_mode=str(raw["execution_mode"]),
        os_family=str(raw["os_family"]),
        os_build=str(raw["os_build"]),
        architecture=str(raw["architecture"]),
        python_implementation=str(raw["python_implementation"]),
        python_version=str(raw["python_version"]),
        python_executable_sha256=str(raw["python_executable_sha256"]),
        torch_version=str(raw["torch_version"]),
        torch_cuda_runtime=str(raw["torch_cuda_runtime"]),
        transformers_version=str(raw["transformers_version"]),
        accelerate_version=str(raw["accelerate_version"]),
        gpu_model=str(raw["gpu_model"]),
        gpu_count=int(raw["gpu_count"]),
        nvidia_driver_version=str(raw["nvidia_driver_version"]),
        dependency_lock_digest=str(raw["dependency_lock_digest"]),
        host_inventory_digest=str(raw["host_inventory_digest"]),
    )


def compile_files(inputs: dict[str, object], dependency: dict[str, object]) -> dict[str, object]:
    if inputs.get("release") != RELEASE:
        raise ValueError("release identity mismatch")
    environment_raw = inputs.get("environment")
    if not isinstance(environment_raw, dict):
        raise ValueError("environment must be an object")
    environment = _environment(environment_raw)
    dependency_digest = canonical_sha256(dependency)
    if dependency_digest != environment.dependency_lock_digest:
        raise ValueError("dependency lock digest mismatch")

    commands = inputs.get("commands")
    if not isinstance(commands, dict):
        raise ValueError("commands must be an object")
    command_digests = {name: canonical_sha256(argv) for name, argv in sorted(commands.items())}
    launch_commands = {
        "schema_version": "e0h-windows-native-launch-commands/1",
        "interpreter_binding": "sys.executable",
        "shell": False,
        "commands": commands,
        "command_digests": command_digests,
    }
    environment_lock = environment.to_dict()
    environment_lock["candidate_evidence"] = inputs["candidate_evidence"]
    environment_lock["powershell_semantic"] = False
    environment_lock["candidate_artifact_committed"] = False

    checkpoint = {
        "schema_version": "e0h-checkpoint-contract/1",
        "checkpoint_uri": inputs["storage"]["checkpoint_uri"],  # type: ignore[index]
        "save_required": True,
        "reload_required": True,
        "digest_publication_required": True,
        "max_checkpoint_gib": inputs["budget"]["max_checkpoint_gib"],  # type: ignore[index]
        "retention_days": inputs["budget"]["checkpoint_retention_days"],  # type: ignore[index]
    }
    preliminary = {
        "run_inputs_lock.json": inputs,
        "environment_lock.json": environment_lock,
        "dependency_lock.json": dependency,
        "training_recipe.json": inputs["recipe"],
        "budget_contract.json": inputs["budget"],
        "checkpoint_contract.json": checkpoint,
        "evaluation_access_contract.json": inputs["evaluation"],
        "launch_commands.json": launch_commands,
    }
    run_contract = {
        "schema_version": "e0h-windows-native-run-contract/1",
        "release": RELEASE,
        "source_commit": inputs["source_commit"],
        "run_inputs_lock_digest": canonical_sha256(inputs),
        "environment_digest": canonical_sha256(environment_lock),
        "dependency_lock_digest": dependency_digest,
        "recipe_digest": canonical_sha256(inputs["recipe"]),
        "budget_digest": canonical_sha256(inputs["budget"]),
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
        "schema_version": "e0h-windows-native-artifact-manifest/1",
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
