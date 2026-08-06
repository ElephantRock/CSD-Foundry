from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from csd_foundry.empirical.e0h.windows_native import (
    EXPECTED_GPU_MODEL,
    ProcessResult,
    canonical_json_text,
    file_sha256,
)

ROOT = Path(__file__).parents[1]
CONTROLLER_PATH = ROOT / "experiments" / "e0h" / "windows_native_v1" / "native_controller.py"


def _controller() -> ModuleType:
    spec = importlib.util.spec_from_file_location("e0h_windows_native_controller", CONTROLLER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value), encoding="utf-8", newline="\n")


def _result(name: str, *, exit_code: int = 0, timed_out: bool = False) -> ProcessResult:
    return ProcessResult(
        argv=("python", name),
        exit_code=exit_code,
        elapsed_seconds_ceil=10,
        timed_out=timed_out,
        stdout_path=f"{name}.stdout.log",
        stderr_path=f"{name}.stderr.log",
    )


def _fixture(
    tmp_path: Path,
) -> tuple[dict[str, ProcessResult], dict[str, object], dict[str, object]]:
    artifact_root = tmp_path / "artifacts" / "e0h-windows-native"
    train_root = artifact_root / "train"
    checkpoint = train_root / "checkpoint-final"
    checkpoint.mkdir(parents=True)
    (train_root / "checkpoint-4").mkdir()
    (train_root / "checkpoint-8").mkdir()
    (checkpoint / "model.safetensors").write_bytes(b"weights")

    training_health = train_root / "training_health.json"
    _write_json(
        training_health,
        {
            "schema_version": "e0h-training-health/1",
            "elapsed_seconds_ceil": 8,
            "global_steps": 8,
            "training_loss": 10.0,
            "cuda_available": True,
            "gpu_count": 1,
            "gpu_name": EXPECTED_GPU_MODEL,
            "checkpoint_created": True,
        },
    )
    reload_receipt = checkpoint / "reload_receipt.json"
    _write_json(
        reload_receipt,
        {
            "schema_version": "e0h-reload-receipt/1",
            "parameter_count": 102714,
            "vocabulary_size": 50257,
            "device": "cuda",
        },
    )
    inference = artifact_root / "inference.jsonl"
    inference.write_text('{"generated_text":"","id":"e0h-smoke-001"}\n', encoding="utf-8")
    smoke = artifact_root / "smoke_receipt.json"
    fixture_digest = "5" * 64
    _write_json(
        smoke,
        {
            "schema_version": "e0h-smoke-receipt/1",
            "fixture_sha256": fixture_digest,
            "inference_sha256": file_sha256(inference),
            "record_count": 1,
            "missing_ids": [],
            "extra_ids": [],
            "execution_complete": True,
            "exact_text_matches": 0,
            "claim_boundary": (
                "Infrastructure smoke execution only; no protected capability conclusion."
            ),
        },
    )

    required_outputs: dict[str, object] = {
        "checkpoint_directory": checkpoint.relative_to(tmp_path).as_posix(),
        "training_health_file": training_health.relative_to(tmp_path).as_posix(),
        "reload_receipt_file": reload_receipt.relative_to(tmp_path).as_posix(),
        "inference_file": inference.relative_to(tmp_path).as_posix(),
        "smoke_receipt_file": smoke.relative_to(tmp_path).as_posix(),
    }
    inputs: dict[str, object] = {
        "environment": {"gpu_count": 1, "gpu_model": EXPECTED_GPU_MODEL},
        "recipe": {"max_steps": 8, "checkpoint_interval_steps": 4},
        "budget": {"e0h_gpu_minutes": 30, "max_checkpoint_gib": 1},
        "evaluation": {
            "protected_metrics_access": False,
            "smoke_fixture_digest": fixture_digest,
        },
    }
    results = {
        name: _result(name)
        for name in ("preflight", "training", "reload", "inference", "smoke_evaluation")
    }
    return results, required_outputs, inputs


def test_classification_accepts_complete_infrastructure_smoke(tmp_path: Path) -> None:
    controller = _controller()
    results, required_outputs, inputs = _fixture(tmp_path)

    classification, failures = controller._classify(
        results,
        required_outputs,
        tmp_path,
        inputs,
    )

    assert classification == "HARNESS_PASSED"
    assert failures == []


def test_classification_rejects_incomplete_smoke_receipt(tmp_path: Path) -> None:
    controller = _controller()
    results, required_outputs, inputs = _fixture(tmp_path)
    smoke_path = tmp_path / str(required_outputs["smoke_receipt_file"])
    smoke = controller._load_canonical(smoke_path)
    smoke["execution_complete"] = False
    smoke["missing_ids"] = ["e0h-smoke-002"]
    smoke_path.write_text(canonical_json_text(smoke), encoding="utf-8", newline="\n")

    classification, failures = controller._classify(
        results,
        required_outputs,
        tmp_path,
        inputs,
    )

    assert classification == "HARNESS_FAILED"
    assert "smoke execution incomplete" in failures
    assert "smoke receipt has missing IDs" in failures


def test_classification_rejects_nonfinite_training_loss(tmp_path: Path) -> None:
    controller = _controller()
    results, required_outputs, inputs = _fixture(tmp_path)
    health_path = tmp_path / str(required_outputs["training_health_file"])
    health = controller._load_canonical(health_path)
    health["training_loss"] = float("inf")
    health_path.write_text(canonical_json_text(health), encoding="utf-8", newline="\n")

    classification, failures = controller._classify(
        results,
        required_outputs,
        tmp_path,
        inputs,
    )

    assert classification == "HARNESS_FAILED"
    assert "training loss is non-finite" in failures


def test_classification_rejects_missing_stage_and_checkpoint(tmp_path: Path) -> None:
    controller = _controller()
    results, required_outputs, inputs = _fixture(tmp_path)
    del results["reload"]
    checkpoint_four = (
        tmp_path / str(required_outputs["checkpoint_directory"])
    ).parent / "checkpoint-4"
    checkpoint_four.rmdir()

    classification, failures = controller._classify(
        results,
        required_outputs,
        tmp_path,
        inputs,
    )

    assert classification == "HARNESS_FAILED"
    assert "not all five protocol stages executed" in failures
    assert "required checkpoint-4 directory is missing" in failures
