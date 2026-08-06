#!/usr/bin/env python3
"""Shell-free Windows-native controller for the five-stage E0-H protocol."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from csd_foundry.empirical.e0h.windows_native import (
    RELEASE,
    ProcessResult,
    canonical_json_text,
    file_sha256,
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


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _required_path(
    required_outputs: Mapping[str, object],
    *,
    field: str,
    repo_root: Path,
) -> Path:
    raw = required_outputs.get(field)
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"required_outputs.{field} must be a nonempty path")
    return repo_root / raw


def _append(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def _classify(
    results: Mapping[str, ProcessResult],
    required_outputs: Mapping[str, object],
    repo_root: Path,
    inputs: Mapping[str, object],
) -> tuple[str, list[str]]:
    failures: list[str] = []

    _append(set(results) == set(_ORDER), failures, "not all five protocol stages executed")
    for name in _ORDER:
        result = results.get(name)
        if result is None:
            continue
        _append(result.exit_code == 0, failures, f"{name} exited with {result.exit_code}")
        _append(not result.timed_out, failures, f"{name} timed out")

    try:
        checkpoint_dir = _required_path(
            required_outputs,
            field="checkpoint_directory",
            repo_root=repo_root,
        )
        training_health_path = _required_path(
            required_outputs,
            field="training_health_file",
            repo_root=repo_root,
        )
        reload_receipt_path = _required_path(
            required_outputs,
            field="reload_receipt_file",
            repo_root=repo_root,
        )
        inference_path = _required_path(
            required_outputs,
            field="inference_file",
            repo_root=repo_root,
        )
        smoke_receipt_path = _required_path(
            required_outputs,
            field="smoke_receipt_file",
            repo_root=repo_root,
        )
    except ValueError as exc:
        failures.append(str(exc))
        return "HARNESS_FAILED", failures

    _append(checkpoint_dir.is_dir(), failures, "final checkpoint directory is missing")
    for path, label in (
        (training_health_path, "training health receipt"),
        (reload_receipt_path, "reload receipt"),
        (inference_path, "inference output"),
        (smoke_receipt_path, "smoke receipt"),
    ):
        _append(
            path.is_file() and path.stat().st_size > 0,
            failures,
            f"{label} is missing or empty",
        )

    environment = _mapping(inputs.get("environment"), field="environment")
    recipe = _mapping(inputs.get("recipe"), field="recipe")
    budget = _mapping(inputs.get("budget"), field="budget")
    evaluation = _mapping(inputs.get("evaluation"), field="evaluation")

    if evaluation.get("protected_metrics_access") is not False:
        failures.append("protected_metrics_access must remain false")

    max_steps = int(recipe.get("max_steps", 0))
    checkpoint_interval = int(recipe.get("checkpoint_interval_steps", 0))
    if max_steps <= 0 or checkpoint_interval <= 0:
        failures.append("training recipe has invalid step or checkpoint interval values")
    else:
        for step in range(checkpoint_interval, max_steps + 1, checkpoint_interval):
            _append(
                (checkpoint_dir.parent / f"checkpoint-{step}").is_dir(),
                failures,
                f"required checkpoint-{step} directory is missing",
            )

    max_gpu_seconds = int(budget.get("e0h_gpu_minutes", 0)) * 60
    training_result = results.get("training")
    if training_result is not None:
        _append(
            0 < training_result.elapsed_seconds_ceil <= max_gpu_seconds,
            failures,
            "controller-observed training duration exceeded the E0-H budget",
        )

    if checkpoint_dir.is_dir():
        checkpoint_bytes = sum(
            path.stat().st_size for path in checkpoint_dir.rglob("*") if path.is_file()
        )
        max_checkpoint_bytes = int(budget.get("max_checkpoint_gib", 0)) * 1024**3
        _append(
            0 < checkpoint_bytes <= max_checkpoint_bytes,
            failures,
            "final checkpoint is empty or exceeds the size budget",
        )

    if training_health_path.is_file() and training_health_path.stat().st_size > 0:
        try:
            health = _load_canonical(training_health_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"invalid training health receipt: {exc}")
        else:
            _append(
                health.get("schema_version") == "e0h-training-health/1",
                failures,
                "training health schema mismatch",
            )
            _append(
                health.get("global_steps") == max_steps,
                failures,
                "training global_steps does not equal the frozen max_steps",
            )
            training_loss = health.get("training_loss")
            finite_loss = (
                isinstance(training_loss, (int, float))
                and not isinstance(training_loss, bool)
                and math.isfinite(float(training_loss))
            )
            _append(finite_loss, failures, "training loss is non-finite")
            _append(health.get("cuda_available") is True, failures, "CUDA was unavailable")
            _append(
                health.get("gpu_count") == environment.get("gpu_count"),
                failures,
                "training GPU count mismatch",
            )
            _append(
                health.get("gpu_name") == environment.get("gpu_model"),
                failures,
                "training GPU model mismatch",
            )
            _append(
                health.get("checkpoint_created") is True,
                failures,
                "training did not report checkpoint creation",
            )
            elapsed = health.get("elapsed_seconds_ceil")
            _append(
                isinstance(elapsed, int)
                and not isinstance(elapsed, bool)
                and 0 < elapsed <= max_gpu_seconds,
                failures,
                "training health duration exceeded the E0-H budget",
            )

    if reload_receipt_path.is_file() and reload_receipt_path.stat().st_size > 0:
        try:
            reload_receipt = _load_canonical(reload_receipt_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"invalid reload receipt: {exc}")
        else:
            _append(
                reload_receipt.get("schema_version") == "e0h-reload-receipt/1",
                failures,
                "reload receipt schema mismatch",
            )
            _append(
                isinstance(reload_receipt.get("parameter_count"), int)
                and int(reload_receipt["parameter_count"]) > 0,
                failures,
                "reload parameter count is invalid",
            )
            _append(
                isinstance(reload_receipt.get("vocabulary_size"), int)
                and int(reload_receipt["vocabulary_size"]) > 0,
                failures,
                "reload vocabulary size is invalid",
            )

    if smoke_receipt_path.is_file() and smoke_receipt_path.stat().st_size > 0:
        try:
            smoke = _load_canonical(smoke_receipt_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failures.append(f"invalid smoke receipt: {exc}")
        else:
            _append(
                smoke.get("schema_version") == "e0h-smoke-receipt/1",
                failures,
                "smoke receipt schema mismatch",
            )
            _append(
                smoke.get("fixture_sha256") == evaluation.get("smoke_fixture_digest"),
                failures,
                "smoke fixture digest mismatch",
            )
            if inference_path.is_file() and inference_path.stat().st_size > 0:
                _append(
                    smoke.get("inference_sha256") == file_sha256(inference_path),
                    failures,
                    "smoke inference digest mismatch",
                )
            _append(smoke.get("execution_complete") is True, failures, "smoke execution incomplete")
            _append(smoke.get("missing_ids") == [], failures, "smoke receipt has missing IDs")
            _append(smoke.get("extra_ids") == [], failures, "smoke receipt has extra IDs")
            record_count = smoke.get("record_count")
            exact_matches = smoke.get("exact_text_matches")
            _append(
                isinstance(record_count, int)
                and not isinstance(record_count, bool)
                and record_count > 0,
                failures,
                "smoke record_count is invalid",
            )
            _append(
                isinstance(exact_matches, int)
                and not isinstance(exact_matches, bool)
                and isinstance(record_count, int)
                and 0 <= exact_matches <= record_count,
                failures,
                "smoke exact_text_matches is invalid",
            )

    classification = "HARNESS_PASSED" if not failures else "HARNESS_FAILED"
    return classification, failures


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
    failures: list[str] = []
    if preflight.exit_code != 0 or preflight.timed_out:
        classification = "HARNESS_FAILED"
        failures.append("preflight did not complete successfully")
    else:
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
        classification, failures = _classify(results, required_outputs, repo_root, inputs)

    write_canonical_json(
        artifact_root / "controller_receipt.json",
        {
            "schema_version": "e0h-windows-native-controller-receipt/1",
            "release": RELEASE,
            "mode": "full_execution",
            "authorization": authorization,
            "results": {name: result.to_dict() for name, result in results.items()},
            "gpu_training_executed": "training" in results,
            "classification_failures": failures,
            "terminal_classification": classification,
        },
    )
    print(classification)
    if classification != "HARNESS_PASSED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
