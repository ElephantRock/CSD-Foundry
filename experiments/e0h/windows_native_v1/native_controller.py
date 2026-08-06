#!/usr/bin/env python3
"""Shell-free Windows-native controller for the five-stage E0-H protocol."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from csd_foundry.empirical.e0h.windows_native import (
    RELEASE,
    ProcessResult,
    canonical_json_text,
    run_process,
    write_canonical_json,
)

_TIMEOUTS = {
    "preflight": 900,
    "training": 1800,
    "reload": 300,
    "inference": 300,
    "smoke_evaluation": 300,
}
_ORDER = ("preflight", "training", "reload", "inference", "smoke_evaluation")


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _current_commit(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _require_authorization(path: Path, repo_root: Path) -> dict[str, object]:
    value = _load_canonical(path)
    expected_fields = {"gpu_execution_authorized", "release", "source_commit"}
    if set(value) != expected_fields:
        raise ValueError("authorization file has unexpected fields")
    if value["gpu_execution_authorized"] is not True:
        raise ValueError("GPU execution is not authorized")
    if value["release"] != RELEASE:
        raise ValueError("authorization release does not match the native E0-H release")
    observed_commit = _current_commit(repo_root)
    if value["source_commit"] != observed_commit:
        raise ValueError(
            f"authorization source commit {value['source_commit']} != checked-out {observed_commit}"
        )
    return value


def _command_argv(commands: Mapping[str, object], name: str) -> list[str]:
    raw = commands.get(name)
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"commands.{name} must be a nonempty string array")
    if raw[0] != "python":
        raise ValueError(f"commands.{name} must be bound to the active Python interpreter")
    return [sys.executable, *raw[1:]]


def _classify(
    results: Mapping[str, ProcessResult],
    required_outputs: Mapping[str, object],
    repo_root: Path,
) -> str:
    if set(results) != set(_ORDER):
        return "HARNESS_FAILED"
    if any(result.exit_code != 0 or result.timed_out for result in results.values()):
        return "HARNESS_FAILED"
    for name, raw_path in required_outputs.items():
        path = repo_root / str(raw_path)
        if name.endswith("_directory"):
            if not path.is_dir():
                return "HARNESS_FAILED"
        elif not path.is_file() or path.stat().st_size == 0:
            return "HARNESS_FAILED"
    return "HARNESS_PASSED"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--authorization-file", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    if inputs.get("release") != RELEASE:
        raise ValueError("run input release does not match native controller")
    commands = inputs.get("commands")
    required_outputs = inputs.get("required_outputs")
    if not isinstance(commands, dict) or not isinstance(required_outputs, dict):
        raise ValueError("run inputs commands and required_outputs must be objects")

    repo_root = Path(__file__).resolve().parents[3]
    artifact_root = args.artifact_root.resolve()
    if artifact_root.exists():
        raise FileExistsError(f"artifact root already exists: {artifact_root}")
    log_root = artifact_root / "logs"
    log_root.mkdir(parents=True)

    results: dict[str, ProcessResult] = {}
    preflight = run_process(
        _command_argv(commands, "preflight"),
        cwd=repo_root,
        stdout_path=log_root / "01-preflight.stdout.log",
        stderr_path=log_root / "01-preflight.stderr.log",
        timeout_seconds=_TIMEOUTS["preflight"],
    )
    results["preflight"] = preflight
    if args.preflight_only:
        write_canonical_json(
            artifact_root / "controller_receipt.json",
            {
                "schema_version": "e0h-windows-native-controller-receipt/1",
                "release": RELEASE,
                "mode": "preflight_only",
                "results": {"preflight": preflight.to_dict()},
                "gpu_training_executed": False,
                "terminal_classification": None,
            },
        )
        if preflight.exit_code != 0 or preflight.timed_out:
            raise SystemExit(1)
        return

    if args.authorization_file is None:
        raise ValueError("full execution requires --authorization-file")
    authorization = _require_authorization(args.authorization_file, repo_root)
    if preflight.exit_code != 0 or preflight.timed_out:
        classification = "HARNESS_FAILED"
    else:
        classification = "HARNESS_FAILED"
        for index, name in enumerate(_ORDER[1:], 2):
            result = run_process(
                _command_argv(commands, name),
                cwd=repo_root,
                stdout_path=log_root / f"{index:02d}-{name}.stdout.log",
                stderr_path=log_root / f"{index:02d}-{name}.stderr.log",
                timeout_seconds=_TIMEOUTS[name],
            )
            results[name] = result
            if result.exit_code != 0 or result.timed_out:
                break
        classification = _classify(results, required_outputs, repo_root)

    write_canonical_json(
        artifact_root / "controller_receipt.json",
        {
            "schema_version": "e0h-windows-native-controller-receipt/1",
            "release": RELEASE,
            "mode": "full_execution",
            "authorization": authorization,
            "results": {name: result.to_dict() for name, result in results.items()},
            "gpu_training_executed": "training" in results,
            "terminal_classification": classification,
        },
    )
    print(classification)
    if classification != "HARNESS_PASSED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
