from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
)

ROOT = Path(__file__).parents[1]
RELEASE_ROOT = ROOT / "experiments" / "e0h" / "windows_native_v2"
DEPENDENCY_DIGEST = "16756dfd91503ef8b30362426c48ec0dfdb0a61ace3a7519962753c9118c1932"
INVENTORY_DIGEST = "c0dcea8f66b042d2a6bd6d676c4c72c5fc955962e254045abc1f37bd8fda6d10"
RELEASE = "e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2"


def _load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repaired_dependency_lock_binds_trainer_import_closure() -> None:
    path = RELEASE_ROOT / "dependency_lock.json"
    lock = json.loads(path.read_text(encoding="utf-8"))
    assert canonical_json_text(lock) == path.read_text(encoding="utf-8")
    assert canonical_sha256(lock) == DEPENDENCY_DIGEST
    pins = {item["name"].casefold().replace("_", "-"): item["version"] for item in lock["packages"]}
    assert pins["datasets"] == "3.4.1"
    assert pins["pyarrow"] == "19.0.1"
    assert pins["dill"] == "0.3.8"
    assert pins["multiprocess"] == "0.70.16"
    assert pins["pandas"] == "3.0.2"
    assert pins["xxhash"] == "3.6.0"
    assert pins["aiohttp"] == "3.13.3"
    artifacts = {item["name"]: item for item in lock["wheel_artifacts"]}
    assert artifacts["datasets"]["sha256"] == (
        "b91cf257bd64132fa9d953dd4768ab6d63205597301f132a74271cfcce8b5dd3"
    )
    assert artifacts["pyarrow"]["filename"] == ("pyarrow-19.0.1-cp312-cp312-win_amd64.whl")
    assert artifacts["pyarrow"]["sha256"] == (
        "5bd1618ae5e5476b7654c7b55a6364ae87686d4724538c24185bbb2952679960"
    )


def test_repaired_candidate_reference_is_sanitized_and_delta_bound() -> None:
    reference = json.loads(
        (RELEASE_ROOT / "environment_candidate_reference.json").read_text(encoding="utf-8")
    )
    serialized = canonical_json_text(reference)
    assert "GPU-" not in serialized
    assert "Users\\" not in serialized
    assert reference["artifact_committed"] is False
    assert reference["package_count"] == 445
    assert reference["package_inventory_digest"] == INVENTORY_DIGEST
    assert reference["repair_delta"]["added_distribution"] == {
        "name": "pyarrow",
        "version": "19.0.1",
    }


def test_repaired_release_reconstructs_exactly() -> None:
    compiler = _load_script(RELEASE_ROOT / "compile_release.py", "e0h_windows_v2_compiler")
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    dependency = json.loads((RELEASE_ROOT / "dependency_lock.json").read_text(encoding="utf-8"))
    files = compiler.compile_files(inputs, dependency)
    compiler.validate_release(files, RELEASE_ROOT / "compiled_release")
    assert set(files) == {
        "artifact_manifest.json",
        "budget_contract.json",
        "checkpoint_contract.json",
        "dependency_lock.json",
        "e0h_run_contract.json",
        "environment_lock.json",
        "evaluation_access_contract.json",
        "launch_commands.json",
        "run_inputs_lock.json",
        "training_recipe.json",
    }


def test_repaired_release_is_distinct_and_execution_denied() -> None:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    contract = json.loads(
        (RELEASE_ROOT / "compiled_release" / "e0h_run_contract.json").read_text(encoding="utf-8")
    )
    assert inputs["release"] == RELEASE
    assert inputs["repair_lineage"]["failed_run_id"] == ("e0h-windows-native-20260806T081010Z")
    assert inputs["repair_lineage"]["failure_classification"] == "HARNESS_FAILED"
    assert inputs["repair_lineage"]["rerun_consumed"] is False
    assert "windows_native_v2" in inputs["commands"]["preflight"][1]
    assert "e0h-windows-native-v2" in inputs["required_outputs"]["inference_file"]
    assert contract["release"] == RELEASE
    assert contract["gpu_execution_authorized"] is False


def test_repaired_preflight_exercises_exact_training_import_path() -> None:
    source = (RELEASE_ROOT / "native_preflight.py").read_text(encoding="utf-8")
    assert "_load_stack()" in source
    assert "import datasets" in source
    assert "import pyarrow" in source
    base_harness = (ROOT / "experiments" / "e0h" / "v1" / "harness.py").read_text(encoding="utf-8")
    assert "Trainer" in base_harness
    assert "TrainingArguments" in base_harness
    assert 'pip", "list", "--format=json"' in source
    assert "host_inventory_digest" in source
    assert "dependency_requirements_receipt.json" in source
    assert "training_stack_preflight.json" in source


def test_repaired_runtime_reuses_reviewed_v1_implementation() -> None:
    controller = (RELEASE_ROOT / "native_controller.py").read_text(encoding="utf-8")
    harness = (RELEASE_ROOT / "native_harness.py").read_text(encoding="utf-8")
    archiver = (RELEASE_ROOT / "archive_artifacts.py").read_text(encoding="utf-8")
    assert "windows_native_v1" in controller
    assert "module.RELEASE = RELEASE" in controller
    assert "windows_native_v1" in harness
    assert "windows_native_v1" in archiver


def test_repair_requirement_is_hash_locked() -> None:
    requirement = (RELEASE_ROOT / "repair_requirements.txt").read_text(encoding="utf-8")
    assert requirement == (
        "pyarrow==19.0.1 "
        "--hash=sha256:5bd1618ae5e5476b7654c7b55a6364ae87686d4724538c24185bbb2952679960\n"
    )
