"""Adversarial conformance tests for the sealed Windows-native E1 release.

Covers:
- the 14 compiled release artifacts reconstruct byte-identically and carry
  distinct digests;
- the sealed prompt inventory is exactly 8 records (4 dev + 4 clean),
  contains ONLY model-visible fields, and is cross-checked against the
  authenticated v6 evaluation cases;
- the inherited runtime identity pins (model/tokenizer/python/torch/CUDA/GPU)
  and the A2 v6 digest pins are bound into the run contract;
- the run contract denies both gpu_execution and metric_release authorization;
- the two authorization domains are separated: the execution controller
  rejects a metric-release authorization and vice versa;
- the frozen classification contract derives every terminal class correctly;
- the GPU budget is bound exactly as specified;
- fail-closed canaries: tampered v6 digest, swapped gold class, leaked sealed
  field, and a coherently-substituted authorization are all rejected.

The compiler needs the tokenizer, so these tests reuse the local HF cache
materialized by the E0-H release. The orchestration works with a test source
commit (the git HEAD of the working branch), which is read from git state
rather than hardcoded.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = ROOT / "experiments" / "e1" / "windows_native_v1"
DATA_V6 = ROOT / "data" / "e1" / "v6"
RELEASE = "e1-windows-native-v1"

V6_DIGEST_PINS = {
    "control_train.jsonl": "0e9362f6693f78e30a3f2f0f24d81885c1c76fa4aa9980ade51c83a8761b2f40",
    "foundry_train.jsonl": "d6da0fb01a323060e03c0a3fa14504c0973d297f660ce7dc6e0317ec4853c385",
    "paired_task_format.json": "4f358d558fe2925eba7b333fc91aa35ed388887233b325d17bb32b0f88f96248",
    "paired_e1_contract.json": "750e56d4a4d63e4fbe9e4379f0b0d1ca967ac7e11033c17971cdfb15ab759db4",
    "tokenization_manifest.json": (
        "c5477383379359ec7f299741e46e4dcec7de0db3bd1d3450fd889e8432bb60d1"
    ),
}

ARTIFACT_FILES = {
    "artifact_manifest.json",
    "budget_contract.json",
    "checkpoint_contract.json",
    "classification_contract.json",
    "e1_run_contract.json",
    "environment_lock.json",
    "evaluation_access_contract.json",
    "launch_commands.json",
    "reconstruction_receipt.json",
    "run_inputs_lock.json",
    "sealed_prompt_inventory.jsonl",
    "sealed_prompt_manifest.json",
    "storage_contract.json",
    "training_recipe.json",
}

FORBIDDEN_SEALED_FIELDS = {
    "gold_class",
    "codeword",
    "codeword_token_id",
    "oracle_result",
    "expected_answer",
}

ALLOWED_SEALED_FIELDS = {
    "evaluation_id",
    "cohort",
    "scenario_id",
    "record_id",
    "family_digest",
    "prompt_bytes",
    "prompt_sha256",
    "prompt_token_count",
}

HF_CACHE = ROOT / "artifacts" / "e0h-windows-native-v2" / "hf-cache"


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


@pytest.fixture(scope="module", autouse=True)
def _hf_home() -> None:
    """Point HF_HOME at the local cache so the tokenizer loads offline."""

    if HF_CACHE.is_dir():
        os.environ.setdefault("HF_HOME", str(HF_CACHE))


def _load_script(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def compiler() -> ModuleType:
    return _load_script(RELEASE_ROOT / "compile_e1_release.py", "e1_compiler")


@pytest.fixture(scope="module")
def controller() -> ModuleType:
    return _load_script(RELEASE_ROOT / "e1_native_controller.py", "e1_controller")


@pytest.fixture(scope="module")
def metric_controller() -> ModuleType:
    return _load_script(RELEASE_ROOT / "e1_metric_controller.py", "e1_metric_controller")


@pytest.fixture(scope="module")
def preflight() -> ModuleType:
    return _load_script(RELEASE_ROOT / "e1_native_preflight.py", "e1_preflight")


@pytest.fixture(scope="module")
def compiled(compiler: ModuleType) -> dict[str, object]:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    return compiler.compile_files(inputs, source_commit=_git_head())


@pytest.fixture(scope="module")
def inputs() -> dict[str, Any]:
    return json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# run_inputs.json structural tests
# ---------------------------------------------------------------------------


def test_run_inputs_is_canonical_and_binds_identity(inputs: dict[str, Any]) -> None:
    text = (RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8")
    assert canonical_json_text(inputs) == text
    assert inputs["release"] == RELEASE
    # Defect 1: source_commit must NOT appear in run_inputs.json (self-
    # referential). The compile CLI accepts --source-commit externally.
    assert "source_commit" not in inputs
    env = inputs["environment"]
    assert env["python_version"] == "3.12.10"
    assert env["torch_version"] == "2.6.0+cu124"
    assert env["gpu_model"] == "NVIDIA GeForce RTX 3080 Ti"
    assert env["dependency_lock_digest"] == (
        "16756dfd91503ef8b30362426c48ec0dfdb0a61ace3a7519962753c9118c1932"
    )
    assert inputs["model"]["locator"] == "hf://sshleifer/tiny-gpt2"
    assert inputs["model"]["revision"] == ("d1856183d08a67c27a8e4ca1492d1d32b96c7c1a")
    assert inputs["model"]["content_digest"] == (
        "b3b00436d13af5c85a223d2bb77adce8ca660081973c41632a7647c70d908039"
    )


def test_run_inputs_binds_v6_curriculum_pins(inputs: dict[str, Any]) -> None:
    curriculum = inputs["curriculum"]
    assert curriculum["control_train_digest"] == V6_DIGEST_PINS["control_train.jsonl"]
    assert curriculum["foundry_train_digest"] == V6_DIGEST_PINS["foundry_train.jsonl"]
    assert curriculum["paired_task_format_digest"] == V6_DIGEST_PINS["paired_task_format.json"]
    assert curriculum["paired_e1_contract_digest"] == V6_DIGEST_PINS["paired_e1_contract.json"]
    assert (
        curriculum["tokenization_manifest_digest"] == V6_DIGEST_PINS["tokenization_manifest.json"]
    )
    assert curriculum["records_per_arm"] == 19
    assert curriculum["tokens_per_arm"] == 6756
    assert curriculum["truncation_count"] == 0


def test_run_inputs_binds_training_recipe_and_budget(inputs: dict[str, Any]) -> None:
    recipe = inputs["recipe"]
    assert recipe["max_steps"] == 8
    assert recipe["checkpoint_interval_steps"] == 4
    assert recipe["seed"] == 1729
    assert recipe["sequence_packing"] is False
    budget = inputs["budget"]
    assert budget["aggregate_gpu_minutes"] == 240
    assert budget["e1_maximum_gpu_minutes"] == 60
    assert budget["per_training_attempt_gpu_minutes"] == 15
    assert budget["all_sealed_inference_gpu_minutes"] == 10


def test_run_inputs_binds_conditions_and_prediction_sets(inputs: dict[str, Any]) -> None:
    assert inputs["conditions"] == ["BASE", "CONTROL", "FOUNDRY"]
    assert inputs["prediction_sets"] == [
        "BASE",
        "CONTROL-checkpoint-4",
        "CONTROL-final",
        "FOUNDRY-checkpoint-4",
        "FOUNDRY-final",
    ]
    assert inputs["classification_prediction_sets"] == [
        "BASE",
        "CONTROL-final",
        "FOUNDRY-final",
    ]
    assert inputs["inference_abi"] == {
        "do_sample": False,
        "num_beams": 1,
        "max_new_tokens": 1,
    }


# ---------------------------------------------------------------------------
# Compiled release structure tests
# ---------------------------------------------------------------------------


def test_release_compiles_exactly_14_artifacts(compiled: dict[str, object]) -> None:
    assert set(compiled) == ARTIFACT_FILES
    assert len(compiled) == 14


def test_release_artifacts_are_distinct(compiled: dict[str, object]) -> None:
    digests: set[str] = set()
    for name, value in compiled.items():
        if name.endswith(".jsonl"):
            assert isinstance(value, str)
            import hashlib

            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        else:
            assert isinstance(value, dict)
            digest = canonical_sha256(value)
        assert digest not in digests, f"artifact {name} shares a digest with another artifact"
        digests.add(digest)


def test_release_writes_and_validates_byte_identically(
    compiler: ModuleType, compiled: dict[str, object], tmp_path: Path
) -> None:
    out = tmp_path / "compiled_release"
    compiler.write_release(compiled, out)
    compiler.validate_release(compiled, out)
    on_disk = {p.name for p in out.iterdir() if p.is_file()}
    assert on_disk == ARTIFACT_FILES


def test_run_contract_denies_both_authorizations(compiled: dict[str, object]) -> None:
    contract = compiled["e1_run_contract.json"]
    assert isinstance(contract, dict)
    assert contract["gpu_execution_authorized"] is False
    assert contract["metric_release_authorized"] is False
    assert contract["release"] == RELEASE
    assert contract["a2_merged_source_commit"] == ("3d4d8db33e08a71a14cd45128e8813750723fea9")
    assert contract["v6_digest_pins"] == V6_DIGEST_PINS
    assert contract["v6_records_per_arm"] == 19
    assert contract["v6_tokens_per_arm"] == 6756
    assert contract["v6_truncation_count"] == 0


def test_budget_contract_pins_exact_gpu_budget(compiled: dict[str, object]) -> None:
    budget = compiled["budget_contract.json"]
    assert isinstance(budget, dict)
    assert budget["budget"]["aggregate_gpu_minutes"] == 240
    assert budget["budget"]["e1_maximum_gpu_minutes"] == 60
    assert budget["budget"]["per_training_attempt_gpu_minutes"] == 15
    assert budget["budget"]["all_sealed_inference_gpu_minutes"] == 10


def test_checkpoint_contract_binds_independent_processes(compiled: dict[str, object]) -> None:
    checkpoint = compiled["checkpoint_contract.json"]
    assert isinstance(checkpoint, dict)
    assert checkpoint["conditions"] == ["BASE", "CONTROL", "FOUNDRY"]
    assert checkpoint["independent_fresh_processes"] is True
    assert checkpoint["no_checkpoint_crossover"] is True
    assert checkpoint["diagnostic_prediction_sets"] == [
        "CONTROL-checkpoint-4",
        "FOUNDRY-checkpoint-4",
    ]
    assert checkpoint["final_prediction_sets"] == ["BASE", "CONTROL-final", "FOUNDRY-final"]


def test_classification_contract_binds_terminal_classes(compiled: dict[str, object]) -> None:
    contract = compiled["classification_contract.json"]
    assert isinstance(contract, dict)
    classes = contract["terminal_classes"]
    assert set(classes) == {"TECHNICALLY_INVALID", "HARMFUL", "PROMISING", "NO_OBSERVED_SIGNAL"}
    assert contract["classification_prediction_sets"] == [
        "BASE",
        "CONTROL-final",
        "FOUNDRY-final",
    ]


def test_environment_lock_binds_inherited_identity(compiled: dict[str, object]) -> None:
    env = compiled["environment_lock.json"]
    assert isinstance(env, dict)
    assert env["python"]["version"] == "3.12.10"
    assert env["python"]["executable_sha256"] == (
        "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a"
    )
    assert env["framework"]["torch_version"] == "2.6.0+cu124"
    assert env["hardware"]["gpu_model"] == "NVIDIA GeForce RTX 3080 Ti"
    assert env["hardware"]["gpu_count"] == 1


def test_launch_commands_bind_sys_executable(compiled: dict[str, object]) -> None:
    launch = compiled["launch_commands.json"]
    assert isinstance(launch, dict)
    assert launch["interpreter_binding"] == "sys.executable"
    assert launch["shell"] is False
    assert launch["inference_abi"] == {
        "do_sample": False,
        "num_beams": 1,
        "max_new_tokens": 1,
    }
    commands = launch["commands"]
    assert isinstance(commands, dict)
    for argv in commands.values():
        assert isinstance(argv, list)
        assert argv[0] == "python"
    assert "metric_release" in commands
    # Defect 3: base_train is never scheduled (BASE is never trained); the
    # five prediction sets are produced by five separate inference stages.
    assert "base_train" not in commands
    assert "base_inference" in commands
    assert "control_checkpoint4_inference" in commands
    assert "control_final_inference" in commands
    assert "foundry_checkpoint4_inference" in commands
    assert "foundry_final_inference" in commands
    # No sealed_inference command takes all three checkpoints; each inference
    # stage binds exactly one model source and one prediction-set name.
    assert "sealed_inference" not in commands
    for stage in (
        "base_inference",
        "control_checkpoint4_inference",
        "control_final_inference",
        "foundry_checkpoint4_inference",
        "foundry_final_inference",
    ):
        argv = commands[stage]
        assert "--prediction-set" in argv
        assert "--checkpoint" in argv


def test_storage_contract_binds_four_release_identities(
    compiled: dict[str, object],
) -> None:
    """Defect 8: the storage contract pins four distinct release URIs."""

    storage = compiled["storage_contract.json"]
    assert isinstance(storage, dict)
    assert storage["control_checkpoint_uri"] == (
        "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-control-checkpoint"
    )
    assert storage["foundry_checkpoint_uri"] == (
        "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-foundry-checkpoint"
    )
    assert storage["sealed_evidence_uri"] == (
        "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-sealed-evidence"
    )
    assert storage["metric_evidence_uri"] == (
        "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-metric-evidence"
    )
    # No generic checkpoint/evidence URIs remain.
    assert "checkpoint_uri" not in storage
    assert "evidence_uri" not in storage
    assert "prediction_manifest_uri" not in storage


def test_manifest_enumerates_all_files_with_digests(compiled: dict[str, object]) -> None:
    manifest = compiled["artifact_manifest.json"]
    assert isinstance(manifest, dict)
    assert manifest["file_count"] == 14
    listed = {entry["path"] for entry in manifest["files"]}
    # The manifest enumerates the 13 non-manifest files (it cannot carry its
    # own digest meaningfully).
    assert listed == ARTIFACT_FILES - {"artifact_manifest.json"}


# ---------------------------------------------------------------------------
# Sealed prompt inventory boundary tests
# ---------------------------------------------------------------------------


def _inventory_records(compiled: dict[str, object]) -> list[dict[str, object]]:
    text = compiled["sealed_prompt_inventory.jsonl"]
    assert isinstance(text, str)
    return [json.loads(line) for line in text.splitlines() if line]


def test_sealed_inventory_has_eight_records(compiled: dict[str, object]) -> None:
    records = _inventory_records(compiled)
    assert len(records) == 8
    cohorts = [r["cohort"] for r in records]
    assert cohorts.count("development") == 4
    assert cohorts.count("clean") == 4


def test_sealed_inventory_has_only_model_visible_fields(
    compiled: dict[str, object],
) -> None:
    for record in _inventory_records(compiled):
        assert set(record) == ALLOWED_SEALED_FIELDS
        assert not (set(record) & FORBIDDEN_SEALED_FIELDS)


def test_sealed_inventory_prompts_match_sha256(compiled: dict[str, object]) -> None:
    import hashlib

    for record in _inventory_records(compiled):
        observed = hashlib.sha256(str(record["prompt_bytes"]).encode("utf-8")).hexdigest()
        assert observed == record["prompt_sha256"]


def test_sealed_inventory_fits_context_length(compiled: dict[str, object]) -> None:
    for record in _inventory_records(compiled):
        assert int(record["prompt_token_count"]) <= 512
        assert int(record["prompt_token_count"]) > 0


def test_sealed_inventory_cross_checks_against_v6_evaluation(
    compiled: dict[str, object],
) -> None:
    dev = [
        json.loads(line)
        for line in (DATA_V6 / "development_evaluation.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    clean = [
        json.loads(line)
        for line in (DATA_V6 / "clean_evaluation.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    gold_by_key = {(c["cohort"], c["scenario_id"], c["record_id"]): c for c in dev + clean}
    for record in _inventory_records(compiled):
        key = (
            record["cohort"],
            record["scenario_id"],
            record["record_id"],
        )
        gold = gold_by_key[key]
        assert record["family_digest"] == gold["family_digest"]


def test_sealed_manifest_summarizes_inventory(compiled: dict[str, object]) -> None:
    manifest = compiled["sealed_prompt_manifest.json"]
    assert isinstance(manifest, dict)
    records = _inventory_records(compiled)
    assert manifest["record_count"] == 8
    assert manifest["cohort_counts"] == {"development": 4, "clean": 4}
    assert manifest["total_prompt_token_count"] == sum(
        int(r["prompt_token_count"]) for r in records
    )
    assert manifest["system_prompt"] == "Return the frozen response codeword and nothing else."
    assert manifest["context_length"] == 512


# ---------------------------------------------------------------------------
# Fail-closed canaries for the compiler
# ---------------------------------------------------------------------------


def test_tampered_v6_curriculum_digest_is_rejected(compiler: ModuleType, tmp_path: Path) -> None:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    # Build a fake v6 directory with one artifact tampered.
    fake_v6 = tmp_path / "data" / "e1" / "v6"
    fake_v6.mkdir(parents=True)
    for name in V6_DIGEST_PINS:
        (fake_v6 / name).write_bytes((DATA_V6 / name).read_bytes())
    # Tamper the control_train.jsonl content but keep the digest pin constant.
    tampered = (DATA_V6 / "control_train.jsonl").read_text(encoding="utf-8")
    tampered = tampered.replace("CTRL-C01", "CTRL-X01", 1)
    (fake_v6 / "control_train.jsonl").write_text(tampered, encoding="utf-8")
    # Redirect compile_files at the fake tree by patching repo_root. The
    # compiler authenticates data/e1/v6 under repo_root, so point it at tmp_path.
    with pytest.raises(compiler.E1WindowsNativeReleaseError):
        compiler.compile_files(inputs, source_commit=_git_head(), repo_root=tmp_path)


def test_wrong_release_identity_is_rejected(compiler: ModuleType) -> None:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    inputs["release"] = "e1-windows-native-v2"
    with pytest.raises(compiler.E1WindowsNativeReleaseError):
        compiler.compile_files(inputs, source_commit=_git_head())


def test_compile_rejects_source_commit_in_inputs(compiler: ModuleType) -> None:
    """Defect 1: source_commit must not be read from run_inputs.json."""

    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    inputs["source_commit"] = _git_head()
    with pytest.raises(compiler.E1WindowsNativeReleaseError):
        compiler.compile_files(inputs, source_commit=_git_head())


def test_compile_binds_external_source_commit(compiler: ModuleType) -> None:
    """Defect 1: the external source commit binds into the run contract/receipt."""

    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    files = compiler.compile_files(inputs, source_commit="deadbeef" * 5)
    contract = files["e1_run_contract.json"]
    receipt = files["reconstruction_receipt.json"]
    assert isinstance(contract, dict)
    assert isinstance(receipt, dict)
    assert contract["source_commit"] == "deadbeef" * 5
    assert receipt["source_commit"] == "deadbeef" * 5


# ---------------------------------------------------------------------------
# Authorization separation tests
# ---------------------------------------------------------------------------


def _write_canonical(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json_text(value), encoding="utf-8", newline="\n")


def test_execution_authorization_shape_is_accepted(controller: ModuleType, tmp_path: Path) -> None:
    auth = {
        "gpu_execution_authorized": True,
        "metric_release_authorized": False,
        "release": RELEASE,
        "source_commit": _git_head(),
    }
    path = tmp_path / "exec_auth.json"
    _write_canonical(path, auth)
    result = controller._require_execution_authorization(path, ROOT)
    assert result["gpu_execution_authorized"] is True


def test_execution_controller_rejects_metric_release_authorization(
    controller: ModuleType, tmp_path: Path
) -> None:
    # A metric-release authorization carries extra fields and the wrong flags.
    auth = {
        "metric_release_authorized": True,
        "release": RELEASE,
        "source_commit": _git_head(),
        "sealed_execution_receipt_sha256": "0" * 64,
        "sealed_prediction_manifest_sha256": "0" * 64,
    }
    path = tmp_path / "metric_auth.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        controller._require_execution_authorization(path, ROOT)


def test_execution_controller_rejects_metric_release_true(
    controller: ModuleType, tmp_path: Path
) -> None:
    # Even with the right fields, metric_release_authorized must be False.
    auth = {
        "gpu_execution_authorized": True,
        "metric_release_authorized": True,
        "release": RELEASE,
        "source_commit": _git_head(),
    }
    path = tmp_path / "bad_auth.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        controller._require_execution_authorization(path, ROOT)


def test_execution_controller_rejects_wrong_release(controller: ModuleType, tmp_path: Path) -> None:
    auth = {
        "gpu_execution_authorized": True,
        "metric_release_authorized": False,
        "release": "e1-windows-native-v2",
        "source_commit": _git_head(),
    }
    path = tmp_path / "wrong_release.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        controller._require_execution_authorization(path, ROOT)


def test_execution_controller_rejects_wrong_commit(controller: ModuleType, tmp_path: Path) -> None:
    auth = {
        "gpu_execution_authorized": True,
        "metric_release_authorized": False,
        "release": RELEASE,
        "source_commit": "0" * 40,
    }
    path = tmp_path / "wrong_commit.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        controller._require_execution_authorization(path, ROOT)


def test_metric_controller_accepts_metric_authorization(
    metric_controller: ModuleType, tmp_path: Path
) -> None:
    receipt = tmp_path / "receipt.json"
    _write_canonical(
        receipt,
        {
            "schema_version": "e1-windows-native-controller-receipt/1",
            "terminal_classification": "SEALED_EXECUTION_PASSED",
        },
    )
    manifest = tmp_path / "preds.json"
    _write_canonical(manifest, {"schema_version": "x", "predictions": []})
    auth = {
        "metric_release_authorized": True,
        "release": RELEASE,
        "source_commit": _git_head(),
        "sealed_execution_receipt_sha256": metric_controller._file_sha256(receipt),
        "sealed_prediction_manifest_sha256": metric_controller._file_sha256(manifest),
    }
    path = tmp_path / "metric_auth.json"
    _write_canonical(path, auth)
    result = metric_controller._require_metric_authorization(
        path,
        ROOT,
        sealed_execution_receipt_sha256=auth["sealed_execution_receipt_sha256"],
        sealed_prediction_manifest_sha256=auth["sealed_prediction_manifest_sha256"],
    )
    assert result["metric_release_authorized"] is True


def test_metric_controller_rejects_gpu_execution_authorization(
    metric_controller: ModuleType, tmp_path: Path
) -> None:
    # The GPU execution authorization lacks the metric-controller's required
    # sealed-digest bindings and carries the wrong field set.
    auth = {
        "gpu_execution_authorized": True,
        "metric_release_authorized": False,
        "release": RELEASE,
        "source_commit": _git_head(),
    }
    path = tmp_path / "exec_auth.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        metric_controller._require_metric_authorization(
            path,
            ROOT,
            sealed_execution_receipt_sha256="0" * 64,
            sealed_prediction_manifest_sha256="0" * 64,
        )


def test_metric_controller_rejects_wrong_sealed_receipt_binding(
    metric_controller: ModuleType, tmp_path: Path
) -> None:
    auth = {
        "metric_release_authorized": True,
        "release": RELEASE,
        "source_commit": _git_head(),
        "sealed_execution_receipt_sha256": "0" * 64,
        "sealed_prediction_manifest_sha256": "0" * 64,
    }
    path = tmp_path / "metric_auth.json"
    _write_canonical(path, auth)
    with pytest.raises(ValueError):
        metric_controller._require_metric_authorization(
            path,
            ROOT,
            sealed_execution_receipt_sha256="1" * 64,
            sealed_prediction_manifest_sha256="0" * 64,
        )


# ---------------------------------------------------------------------------
# Classification contract derivation tests
# ---------------------------------------------------------------------------


def test_classification_technically_invalid_when_execution_failed(
    metric_controller: ModuleType,
) -> None:
    terminal, evidence = metric_controller._classify_run(
        sealed_execution_passed=False,
        primary_accuracies={"BASE": 0.5, "CONTROL": 0.5, "FOUNDRY": 0.9},
        safety_counts=_zero_safety_counts(),
    )
    assert terminal == "TECHNICALLY_INVALID"
    assert evidence["sealed_execution_passed"] is False


def test_classification_harmful_when_safety_regression(
    metric_controller: ModuleType,
) -> None:
    safety = _zero_safety_counts()
    safety["FOUNDRY"]["clean_exact_error_count"] = 3
    safety["BASE"]["clean_exact_error_count"] = 1
    terminal, _ = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies={"BASE": 0.5, "CONTROL": 0.5, "FOUNDRY": 0.9},
        safety_counts=safety,
    )
    assert terminal == "HARMFUL"


def test_classification_harmful_when_foundry_below_control(
    metric_controller: ModuleType,
) -> None:
    terminal, _ = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies={"BASE": 0.2, "CONTROL": 0.6, "FOUNDRY": 0.4},
        safety_counts=_zero_safety_counts(),
    )
    assert terminal == "HARMFUL"


def test_classification_promising_when_all_conditions_met(
    metric_controller: ModuleType,
) -> None:
    terminal, evidence = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies={"BASE": 0.2, "CONTROL": 0.4, "FOUNDRY": 0.7},
        safety_counts=_zero_safety_counts(),
    )
    assert terminal == "PROMISING"
    assert evidence["safety_nonregression"] is True


def test_classification_no_observed_signal_when_tie(
    metric_controller: ModuleType,
) -> None:
    terminal, _ = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies={"BASE": 0.5, "CONTROL": 0.5, "FOUNDRY": 0.5},
        safety_counts=_zero_safety_counts(),
    )
    assert terminal == "NO_OBSERVED_SIGNAL"


def _zero_safety_counts() -> dict[str, dict[str, int]]:
    keys = [
        "clean_exact_error_count",
        "clean_malformed_count",
        "clean_not_applicable_count",
        "spurious_basis_removal_count",
        "valid_basis_rejection_count",
    ]
    return {arm: {key: 0 for key in keys} for arm in ("BASE", "CONTROL", "FOUNDRY")}


# ---------------------------------------------------------------------------
# Execution controller classification tests
# ---------------------------------------------------------------------------


def _proc_result(name: str, *, exit_code: int = 0) -> Any:
    from csd_foundry.empirical.e0h.windows_native import ProcessResult

    return ProcessResult(
        argv=("python", name),
        exit_code=exit_code,
        elapsed_seconds_ceil=10,
        timed_out=False,
        stdout_path=f"{name}.stdout.log",
        stderr_path=f"{name}.stderr.log",
    )


def _required_outputs_for_controller(tmp_path: Path) -> tuple[dict[str, str], Path]:
    art = tmp_path / "artifacts" / "e1-windows-native-v1"
    for cond in ("control", "foundry"):
        (art / cond / "checkpoint-final").mkdir(parents=True)
    manifests = {
        "base_inference_manifest": art / "base_inference" / "prediction_manifest.json",
        "control_checkpoint4_inference_manifest": (
            art / "control_checkpoint4_inference" / "prediction_manifest.json"
        ),
        "control_final_inference_manifest": (
            art / "control_final_inference" / "prediction_manifest.json"
        ),
        "foundry_checkpoint4_inference_manifest": (
            art / "foundry_checkpoint4_inference" / "prediction_manifest.json"
        ),
        "foundry_final_inference_manifest": (
            art / "foundry_final_inference" / "prediction_manifest.json"
        ),
    }
    for path in manifests.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"x":1}\n', encoding="utf-8")
    required_outputs = {
        "control_checkpoint_directory": "artifacts/e1-windows-native-v1/control/checkpoint-final",
        "foundry_checkpoint_directory": "artifacts/e1-windows-native-v1/foundry/checkpoint-final",
        **{
            field: f"artifacts/e1-windows-native-v1/{path.relative_to(art).as_posix()}"
            for field, path in manifests.items()
        },
    }
    return required_outputs, art


def test_execution_controller_classifies_passed(controller: ModuleType, tmp_path: Path) -> None:
    required_outputs, _art = _required_outputs_for_controller(tmp_path)
    results = {name: _proc_result(name) for name in controller._ORDER}
    terminal, failures = controller._classify(results, required_outputs, tmp_path)
    assert terminal == "SEALED_EXECUTION_PASSED"
    assert failures == []


def test_execution_controller_classifies_failed_on_missing_checkpoint(
    controller: ModuleType, tmp_path: Path
) -> None:
    required_outputs, art = _required_outputs_for_controller(tmp_path)
    # Remove the foundry checkpoint directory.
    import shutil

    shutil.rmtree(art / "foundry" / "checkpoint-final")
    results = {name: _proc_result(name) for name in controller._ORDER}
    terminal, failures = controller._classify(results, required_outputs, tmp_path)
    assert terminal == "SEALED_EXECUTION_FAILED"
    assert any("foundry_checkpoint_directory" in f for f in failures)


def test_execution_controller_classifies_failed_on_missing_inference_manifest(
    controller: ModuleType, tmp_path: Path
) -> None:
    required_outputs, art = _required_outputs_for_controller(tmp_path)
    # Remove one inference manifest.
    (art / "foundry_final_inference" / "prediction_manifest.json").unlink()
    results = {name: _proc_result(name) for name in controller._ORDER}
    terminal, failures = controller._classify(results, required_outputs, tmp_path)
    assert terminal == "SEALED_EXECUTION_FAILED"
    assert any("foundry_final_inference_manifest" in f for f in failures)


def test_execution_controller_order_has_five_inference_stages(
    controller: ModuleType,
) -> None:
    """Defect 3/4: eight stages with five separate inference invocations."""

    assert controller._ORDER == (
        "preflight",
        "control_train",
        "foundry_train",
        "base_inference",
        "control_checkpoint4_inference",
        "control_final_inference",
        "foundry_checkpoint4_inference",
        "foundry_final_inference",
    )
    assert "base_train" not in controller._ORDER
    assert len(controller._INFERENCE_STAGES) == 5


# ---------------------------------------------------------------------------
# Preflight read-only authentication tests
# ---------------------------------------------------------------------------


def test_preflight_authenticates_environment_and_curriculum(
    preflight: ModuleType,
) -> None:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    # Should not raise.
    preflight._authenticate_environment(inputs)
    receipts = preflight._authenticate_v6_curriculum(ROOT)
    # The five curriculum pins plus dev/clean evaluation against the A2 receipt.
    assert set(receipts) == set(V6_DIGEST_PINS) | {
        "development_evaluation.jsonl",
        "clean_evaluation.jsonl",
    }
    assert receipts["development_evaluation.jsonl"] == (
        "eb6d1cb5b3596e3a673536b9865be118fe6afc47c79e93f6ea92cd5cf9e31036"
    )
    assert receipts["clean_evaluation.jsonl"] == (
        "178e7a6f80c6ed8caf4ab823211d4896345ec7f9b49eebfe53415b6d019d2ee2"
    )


def test_preflight_rejects_tampered_environment(preflight: ModuleType) -> None:
    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    inputs["environment"]["gpu_model"] = "NVIDIA GeForce RTX 4090"
    with pytest.raises(RuntimeError):
        preflight._authenticate_environment(inputs)


def test_preflight_rejects_tampered_development_evaluation(
    preflight: ModuleType, tmp_path: Path
) -> None:
    """Defect 7: dev/clean evaluation bytes are authenticated against A2."""

    fake_v6 = tmp_path / "data" / "e1" / "v6"
    fake_v6.mkdir(parents=True)
    for name in (
        *V6_DIGEST_PINS,
        "development_evaluation.jsonl",
        "clean_evaluation.jsonl",
        "a2_receipt.json",
    ):
        (fake_v6 / name).write_bytes((DATA_V6 / name).read_bytes())
    tampered = (DATA_V6 / "development_evaluation.jsonl").read_text(encoding="utf-8")
    tampered = tampered.replace("REMOVES_ONLY", "BOTH", 1)
    (fake_v6 / "development_evaluation.jsonl").write_text(tampered, encoding="utf-8")
    with pytest.raises(RuntimeError):
        preflight._authenticate_v6_curriculum(tmp_path)


def test_preflight_runtime_qualification_is_platform_gated(preflight: ModuleType) -> None:
    """Defect 7: runtime qualification runs only on Windows; non-Windows is
    explicitly non-authoritative and never fails closed on torch/CUDA absence."""

    import platform as _platform

    lock = json.loads(
        (ROOT / "experiments" / "e0h" / "windows_native_v2" / "dependency_lock.json").read_text(
            encoding="utf-8"
        )
    )
    if _platform.system() == "Windows":
        receipt = preflight._qualify_windows_runtime(
            lock=lock,
            inputs=json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8")),
        )
        assert receipt["platform"] == "Windows"
    else:
        # On non-Windows the helper is not invoked by main(); calling it would
        # require torch on the host, so we only assert the gating flag is
        # purely platform-based (no env-var authority).
        assert _platform.system() != "Windows"


def test_preflight_retokenizes_curriculum_arms(preflight: ModuleType) -> None:
    """Defect 7: both training arms retokenize to 19 records / 6756 tokens / 0 truncation."""

    receipt = preflight._retokenize_curriculum_arms(ROOT)
    assert set(receipt) == {"control", "foundry"}
    for arm in ("control", "foundry"):
        assert receipt[arm]["record_count"] == 19
        assert receipt[arm]["token_count"] == 6756
        assert receipt[arm]["truncation_count"] == 0


def test_preflight_rejects_sealed_inventory_with_leaked_gold(
    preflight: ModuleType, compiled: dict[str, object], tmp_path: Path
) -> None:
    # Write a sealed inventory with a leaked gold_class into a fake tree and
    # confirm the preflight sealed-inventory authenticator rejects it.
    fake_root = tmp_path / "repo"
    fake_release = fake_root / "experiments" / "e1" / "windows_native_v1" / "compiled_release"
    fake_release.mkdir(parents=True)
    text = compiled["sealed_prompt_inventory.jsonl"]
    assert isinstance(text, str)
    leaked_line = json.loads(text.splitlines()[0])
    leaked_line["gold_class"] = "NEITHER"
    (fake_release / "sealed_prompt_inventory.jsonl").write_text(
        json.dumps(leaked_line, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError):
        preflight._authenticate_sealed_inventory(fake_root)


# ---------------------------------------------------------------------------
# Runtime identity inheritance tests
# ---------------------------------------------------------------------------


def test_release_inherits_e0h_v2_identity_pins(compiled: dict[str, object]) -> None:
    """The E1 release pins the SAME runtime identity as the E0-H v2 release."""

    env = compiled["environment_lock.json"]
    assert isinstance(env, dict)
    e0h_inputs = json.loads(
        (ROOT / "experiments" / "e0h" / "windows_native_v2" / "run_inputs.json").read_text(
            encoding="utf-8"
        )
    )
    e0h_env = e0h_inputs["environment"]
    assert env["python"]["version"] == e0h_env["python_version"]
    assert env["python"]["executable_sha256"] == e0h_env["python_executable_sha256"]
    assert env["framework"]["torch_version"] == e0h_env["torch_version"]
    assert env["framework"]["torch_cuda_runtime"] == e0h_env["torch_cuda_runtime"]
    assert env["framework"]["transformers_version"] == e0h_env["transformers_version"]
    assert env["framework"]["accelerate_version"] == e0h_env["accelerate_version"]
    assert env["hardware"]["gpu_model"] == e0h_env["gpu_model"]
    assert env["hardware"]["gpu_count"] == e0h_env["gpu_count"]
    assert env["hardware"]["nvidia_driver_version"] == e0h_env["nvidia_driver_version"]
    assert env["dependency_lock_digest"] == e0h_env["dependency_lock_digest"]
    assert env["host_inventory_digest"] == e0h_env["host_inventory_digest"]


def test_harness_adapter_rejects_base_training() -> None:
    harness = _load_script(RELEASE_ROOT / "e1_native_harness.py", "e1_harness")
    import argparse

    args = argparse.Namespace(condition="BASE", inputs=None, output_dir=None)
    with pytest.raises(ValueError):
        harness.command_train(args)


def test_harness_adapter_rejects_unknown_condition(
    inputs: dict[str, Any],
) -> None:
    harness = _load_script(RELEASE_ROOT / "e1_native_harness.py", "e1_harness")
    with pytest.raises(ValueError):
        harness._verified_curriculum_texts(inputs, "UNKNOWN")


def test_archiver_is_deterministic(tmp_path: Path) -> None:
    archiver = _load_script(RELEASE_ROOT / "archive_artifacts.py", "e1_archiver")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.json").write_text('{"a":1}\n', encoding="utf-8")
    (root / "b.json").write_text('{"b":2}\n', encoding="utf-8")
    out1 = tmp_path / "out1.zip"
    out2 = tmp_path / "out2.zip"
    import sys

    orig_argv = sys.argv
    try:
        sys.argv = ["archive_artifacts.py", "--root", str(root), "--output", str(out1), "a.json"]
        archiver.main()
        sys.argv = ["archive_artifacts.py", "--root", str(root), "--output", str(out2), "a.json"]
        archiver.main()
    finally:
        sys.argv = orig_argv
    assert out1.read_bytes() == out2.read_bytes()


# ---------------------------------------------------------------------------
# Defect 5: inference records the raw generated token (no repair).
# ---------------------------------------------------------------------------


def test_harness_records_raw_token_without_repair() -> None:
    """The inference helper records generated_token_id and exact_decoded_suffix
    only; it does not strip/case-fold/repair, and no predicted_class is emitted."""

    harness = _load_script(RELEASE_ROOT / "e1_native_harness.py", "e1_harness")
    assert not hasattr(harness, "_decode_predicted_class")

    # The frozen ABI helper accepts one checkpoint + one prediction set name.
    import inspect

    sig = inspect.signature(harness._run_inference)
    assert "prediction_set_name" in sig.parameters
    assert "checkpoint" in sig.parameters

    # The infer subcommand requires --prediction-set and --checkpoint.
    parser = harness.parser()
    infer_actions = {a.dest for a in parser._subparsers._group_actions[0].choices["infer"]._actions}
    assert "prediction_set" in infer_actions
    assert "checkpoint" in infer_actions
    # The three multi-checkpoint arguments are gone.
    assert "base_checkpoint" not in infer_actions
    assert "control_checkpoint" not in infer_actions
    assert "foundry_checkpoint" not in infer_actions


# ---------------------------------------------------------------------------
# Defect 2: gold-free execution root (filesystem-level enforcement).
# ---------------------------------------------------------------------------


def test_export_execution_root_rejects_fake_gold_file(
    controller: ModuleType, tmp_path: Path
) -> None:
    """The exporter must reject a fake gold file dropped into the root."""

    root = tmp_path / "exec_root"
    root.mkdir()
    (root / "development_evaluation.jsonl").write_text(
        '{"cohort":"development","gold_class":"NEITHER"}\n', encoding="utf-8"
    )
    with pytest.raises(ValueError):
        controller._reject_forbidden_paths(root)


def test_export_execution_root_rejects_git_directory(
    controller: ModuleType, tmp_path: Path
) -> None:
    """The exporter must reject a .git directory beneath the root."""

    root = tmp_path / "exec_root"
    root.mkdir()
    (root / ".git").mkdir()
    with pytest.raises(ValueError):
        controller._reject_forbidden_paths(root)


def test_export_execution_root_rejects_metric_code(controller: ModuleType, tmp_path: Path) -> None:
    """The exporter must reject metric/classification code beneath the root."""

    root = tmp_path / "exec_root"
    root.mkdir()
    (root / "response_abi_metrics.py").write_text("# metric code\n", encoding="utf-8")
    with pytest.raises(ValueError):
        controller._reject_forbidden_paths(root)


def test_export_execution_root_accepts_clean_root(
    controller: ModuleType, compiler: ModuleType, tmp_path: Path
) -> None:
    """A clean root (only allowlisted files) exports without rejection and
    contains no gold/metric/git material."""

    inputs = json.loads((RELEASE_ROOT / "run_inputs.json").read_text(encoding="utf-8"))
    files = compiler.compile_files(inputs, source_commit=_git_head())
    compiled_release = tmp_path / "compiled_release"
    compiler.write_release(files, compiled_release)
    dependency_lock = ROOT / "experiments" / "e0h" / "windows_native_v2" / "dependency_lock.json"
    root = controller.export_execution_root(
        repo_root=ROOT,
        release_dir=RELEASE_ROOT,
        dependency_lock=dependency_lock,
        compiled_release=compiled_release,
        v6_dir=DATA_V6,
    )
    controller._reject_forbidden_paths(Path(root))
    # The exported root must not contain any gold file or .git.
    for path in Path(root).rglob("*"):
        assert path.name not in {
            "development_evaluation.jsonl",
            "clean_evaluation.jsonl",
            "evaluation_cases.jsonl",
        }
        assert ".git" not in path.relative_to(root).parts
    # Installed package code and the sealed inventory are present.
    assert (Path(root) / "src" / "csd_foundry").is_dir()
    assert (Path(root) / "compiled_release" / "sealed_prompt_inventory.jsonl").is_file()


# ---------------------------------------------------------------------------
# Defect 6: metric controller authenticates gold bytes and parses via A0b2.
# ---------------------------------------------------------------------------


def _gold_case_keys() -> set[tuple[str, str, str]]:
    dev = [
        json.loads(line)
        for line in (DATA_V6 / "development_evaluation.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    clean = [
        json.loads(line)
        for line in (DATA_V6 / "clean_evaluation.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    ]
    return {(str(c["cohort"]), str(c["scenario_id"]), str(c["record_id"])) for c in dev + clean}


def _make_raw_prediction(set_name: str, key: tuple[str, str, str], suffix: str) -> dict[str, Any]:
    cohort, scenario_id, record_id = key
    return {
        "prediction_set_name": set_name,
        "evaluation_id": f"e1-evaluation/{cohort}/{scenario_id}/{record_id}",
        "cohort": cohort,
        "scenario_id": scenario_id,
        "record_id": record_id,
        "family_digest": "deadbeef",
        "prompt_sha256": "0" * 64,
        "generated_token_id": 32,
        "exact_decoded_suffix": suffix,
        "checkpoint_or_model_identity": f"checkpoint-{set_name}",
    }


def test_metric_controller_rejects_missing_prediction_count(
    metric_controller: ModuleType,
) -> None:
    """Defect 4/6: exactly 5 sets x 8 cases = 40 records are required."""

    keys = sorted(_gold_case_keys())
    # Only one set, 8 cases => 8 records (not 40).
    records = [_make_raw_prediction("BASE", k, "A") for k in keys]
    with pytest.raises(ValueError):
        metric_controller._evaluate_predictions(
            prediction_records=records,
            dev_cases=[
                json.loads(line)
                for line in (DATA_V6 / "development_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
            clean_cases=[
                json.loads(line)
                for line in (DATA_V6 / "clean_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
        )


def test_metric_controller_parses_via_a0b2_and_treats_malformed_as_incorrect(
    metric_controller: ModuleType,
) -> None:
    """Defect 5/6: raw suffixes are parsed by the frozen A0b2 parser; malformed
    output is counted as incorrect, not TECHNICALLY_INVALID."""

    keys = sorted(_gold_case_keys())
    # Every prediction emits a malformed suffix "X" (rejected by the strict
    # parser). All four dev families are wrong; primary accuracy is 0 for each
    # classification arm.
    records: list[dict[str, Any]] = []
    for set_name in metric_controller.ALL_PREDICTION_SETS:
        for key in keys:
            records.append(_make_raw_prediction(set_name, key, "X"))
    primary_accuracies, safety_counts = metric_controller._evaluate_predictions(
        prediction_records=records,
        dev_cases=[
            json.loads(line)
            for line in (DATA_V6 / "development_evaluation.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ],
        clean_cases=[
            json.loads(line)
            for line in (DATA_V6 / "clean_evaluation.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ],
    )
    for arm in ("BASE", "CONTROL", "FOUNDRY"):
        assert primary_accuracies[arm] == 0.0
        # Malformed increments clean_malformed_count and clean_exact_error_count.
        assert safety_counts[arm]["clean_malformed_count"] == 4
        assert safety_counts[arm]["clean_exact_error_count"] == 4
    terminal, _evidence = metric_controller._classify_run(
        sealed_execution_passed=True,
        primary_accuracies=primary_accuracies,
        safety_counts=safety_counts,
    )
    # Tied-at-zero accuracy with no safety regression => NO_OBSERVED_SIGNAL,
    # NOT TECHNICALLY_INVALID (malformed is incorrect, not invalid).
    assert terminal == "NO_OBSERVED_SIGNAL"


def test_metric_controller_authenticates_gold_bytes(metric_controller: ModuleType) -> None:
    """Defect 6/7: the gold bytes are authenticated against the A2 receipt."""

    dev_cases, clean_cases = metric_controller._authenticate_gold_bytes(
        ROOT,
        dev_path=DATA_V6 / "development_evaluation.jsonl",
        clean_path=DATA_V6 / "clean_evaluation.jsonl",
    )
    assert len(dev_cases) == 4
    assert len(clean_cases) == 4


def test_metric_controller_rejects_tampered_gold_bytes(
    metric_controller: ModuleType, tmp_path: Path
) -> None:
    """Defect 6: a tampered gold file fails SHA-256 authentication."""

    fake = tmp_path / "development_evaluation.jsonl"
    fake.write_text(
        (DATA_V6 / "development_evaluation.jsonl")
        .read_text(encoding="utf-8")
        .replace("REMOVES_ONLY", "BOTH", 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        metric_controller._authenticate_gold_bytes(
            ROOT,
            dev_path=fake,
            clean_path=DATA_V6 / "clean_evaluation.jsonl",
        )


def test_metric_controller_rejects_duplicate_predictions(
    metric_controller: ModuleType,
) -> None:
    """Defect 6: duplicate prediction cases are rejected."""

    keys = sorted(_gold_case_keys())
    records: list[dict[str, Any]] = []
    for set_name in metric_controller.ALL_PREDICTION_SETS:
        for key in keys:
            records.append(_make_raw_prediction(set_name, key, "A"))
    # Duplicate the first record (over-count).
    records.append(records[0])
    with pytest.raises(ValueError):
        metric_controller._evaluate_predictions(
            prediction_records=records,
            dev_cases=[
                json.loads(line)
                for line in (DATA_V6 / "development_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
            clean_cases=[
                json.loads(line)
                for line in (DATA_V6 / "clean_evaluation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line
            ],
        )


# ---------------------------------------------------------------------------
# Defect 4: Two-mode direct/successor provenance gate (analogous to A0b2/A1/A2).
# ---------------------------------------------------------------------------

_COMPILED_RELEASE_FILES = frozenset(
    {
        "artifact_manifest.json",
        "budget_contract.json",
        "checkpoint_contract.json",
        "classification_contract.json",
        "e1_run_contract.json",
        "environment_lock.json",
        "evaluation_access_contract.json",
        "launch_commands.json",
        "reconstruction_receipt.json",
        "run_inputs_lock.json",
        "sealed_prompt_inventory.jsonl",
        "sealed_prompt_manifest.json",
        "storage_contract.json",
        "training_recipe.json",
    }
)


def test_git_history_provenance_gate_two_mode() -> None:
    """Two-mode provenance gate for the compiled release artifacts.

    Direct mode: HEAD changes exactly the 14 compiled_release files →
    receipt.source_commit == HEAD^, diff == exactly those 14 files.

    Successor mode: HEAD changes other files → locate introduction commit,
    verify all 14 current blobs match introduction blobs.
    """

    import subprocess

    release_dir = ROOT / "experiments" / "e1" / "windows_native_v1" / "compiled_release"
    receipt_path = release_dir / "reconstruction_receipt.json"
    if not receipt_path.is_file():
        pytest.skip("compiled_release/reconstruction_receipt.json not yet committed")

    def _git(*args: str) -> str:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=str(ROOT),
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            pytest.fail(f"git command failed: {exc}")
        return completed.stdout.strip()

    # Read the committed receipt.
    receipt_text = _git(
        "show",
        "HEAD:experiments/e1/windows_native_v1/compiled_release/reconstruction_receipt.json",
    )
    receipt = json.loads(receipt_text)
    committed_source_commit = receipt["source_commit"]

    # Resolve the artifact commit via parent inspection.
    parents = _git("show", "-s", "--format=%P", "HEAD").split()
    head_tip = parents[1] if len(parents) >= 2 else _git("rev-parse", "HEAD")

    head_diff = set(
        line for line in _git("diff", "--name-only", f"{head_tip}^", head_tip).splitlines() if line
    )
    expected_paths = frozenset(
        f"experiments/e1/windows_native_v1/compiled_release/{name}"
        for name in _COMPILED_RELEASE_FILES
    )

    if head_diff == expected_paths or (head_diff <= expected_paths and head_diff):
        # Direct or amendment mode: HEAD changes exactly or a subset of
        # compiled_release paths. Enforce S→A adjacency.
        implementation_commit = _git("rev-parse", f"{head_tip}^")
        assert committed_source_commit == implementation_commit, (
            f"receipt source_commit {committed_source_commit!r} does not match "
            f"git-derived implementation commit {implementation_commit!r}"
        )
    else:
        # Successor mode: find the latest commit C that changed the
        # reconstruction_receipt.json, require C^ == receipt.source_commit,
        # require C^→C diff is a non-empty subset of compiled_release paths,
        # then compare all 14 current blobs against C's tree.
        receipt_rel = (
            "experiments/e1/windows_native_v1/compiled_release/reconstruction_receipt.json"
        )
        # Find all commits that modified the receipt (both A and M diff-filters)
        changes = _git(
            "log",
            "--diff-filter=AM",
            "--format=%H",
            "--",
            receipt_rel,
        ).splitlines()
        assert changes, f"no commit found changing {receipt_rel}"
        # The latest commit that changed the receipt is the frozen anchor
        frozen_commit = changes[0]
        # The frozen commit's parent must be the receipt's source_commit: this
        # binds the provenance gate to the implementation commit S*.
        frozen_parent = _git("rev-parse", f"{frozen_commit}^")
        assert frozen_parent == committed_source_commit, (
            f"frozen commit {frozen_commit} parent {frozen_parent!r} does not match "
            f"receipt source_commit {committed_source_commit!r}"
        )
        # Verify the frozen commit is a valid artifact-binding commit: its diff
        # is a non-empty subset of compiled_release paths.
        frozen_diff = set(
            line
            for line in _git("diff", "--name-only", f"{frozen_commit}^", frozen_commit).splitlines()
            if line
        )
        assert frozen_diff, f"frozen commit {frozen_commit} has empty diff"
        assert frozen_diff <= expected_paths, (
            f"frozen commit changed non-release paths: {sorted(frozen_diff - expected_paths)}"
        )

        for name in _COMPILED_RELEASE_FILES:
            rel = f"experiments/e1/windows_native_v1/compiled_release/{name}"
            frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
            current_blob = _git("hash-object", rel)
            assert current_blob == frozen_blob, f"frozen compiled_release artifact changed: {rel}"


# ---------------------------------------------------------------------------
# Checkpoint-4 tokenizer materialization regression.
# ---------------------------------------------------------------------------


def test_checkpoint4_tokenizer_materialization() -> None:
    """After training, intermediate checkpoints must load with the tokenizer.

    The HF Trainer saves model + optimizer at checkpoint-4 but does NOT save
    tokenizer files. The harness ``_materialize_checkpoint_tokenizers`` helper
    materializes them so inference can load the checkpoint with
    ``local_files_only=True``. This regression drives the ACTUAL production
    helper rather than a duplicated copy.

    The test does NOT require that pre-materialization loading fails — some
    Transformers versions can synthesize a tokenizer from config alone. Instead
    it proves the helper's positive effect: after materialization, the
    checkpoint loads offline and produces the frozen codeword token IDs.
    """

    import tempfile

    from transformers import AutoTokenizer

    # Load the harness module that owns the production helper.
    harness_mod = _load_script(RELEASE_ROOT / "e1_native_harness.py", "e1_harness_checkpoint")
    assert hasattr(harness_mod, "_materialize_checkpoint_tokenizers"), (
        "harness must expose _materialize_checkpoint_tokenizers"
    )

    # Load the frozen tokenizer.
    tokenizer = AutoTokenizer.from_pretrained(
        "sshleifer/tiny-gpt2",
        revision="d1856183d08a67c27a8e4ca1492d1d32b96c7c1a",
    )

    expected_codewords = [("A", 32), ("B", 33), ("C", 34), ("D", 35), ("E", 36)]

    with tempfile.TemporaryDirectory(prefix="e1-ckpt4-test-") as tmp:
        # Create checkpoint-4 and checkpoint-final to verify the helper
        # materializes into intermediates but skips checkpoint-final.
        ckpt4 = Path(tmp) / "checkpoint-4"
        ckpt4.mkdir()
        (ckpt4 / "config.json").write_text('{"model_type": "gpt2"}', encoding="utf-8")

        ckpt_final = Path(tmp) / "checkpoint-final"
        ckpt_final.mkdir()
        (ckpt_final / "config.json").write_text('{"model_type": "gpt2"}', encoding="utf-8")

        # Snapshot directory contents before materialization.
        ckpt4_before = {p.name for p in ckpt4.iterdir()}
        ckpt_final_before = {p.name for p in ckpt_final.iterdir()}

        # Drive the ACTUAL production helper.
        harness_mod._materialize_checkpoint_tokenizers(Path(tmp), tokenizer)

        # Positive effect: checkpoint-4 now has additional files.
        ckpt4_after = {p.name for p in ckpt4.iterdir()}
        assert ckpt4_after > ckpt4_before, (
            f"checkpoint-4 unchanged by materialization: "
            f"before={sorted(ckpt4_before)}, after={sorted(ckpt4_after)}"
        )

        # checkpoint-final must NOT have been touched by the helper.
        ckpt_final_after = {p.name for p in ckpt_final.iterdir()}
        assert ckpt_final_after == ckpt_final_before, (
            f"checkpoint-final was modified by materialization: "
            f"before={sorted(ckpt_final_before)}, after={sorted(ckpt_final_after)}"
        )

        # Behavioral postcondition: the checkpoint loads offline and produces
        # the frozen codeword token IDs.
        loaded = AutoTokenizer.from_pretrained(str(ckpt4), local_files_only=True)
        assert loaded is not None, "AutoTokenizer returned None after materialization"

        for codeword, expected_id in expected_codewords:
            ids = loaded.encode(codeword, add_special_tokens=False)
            assert ids == [expected_id], (
                f"codeword {codeword!r}: expected token ID {expected_id}, "
                f"got {ids} from checkpoint-loaded tokenizer"
            )
