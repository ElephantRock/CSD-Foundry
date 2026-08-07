#!/usr/bin/env python3
"""Compile the sealed Windows-native E1 release artifacts.

This compiler materializes 14 canonical release artifacts under
``compiled_release/``. It does NOT execute E1, allocate a GPU, expose protected
metrics, or establish learning value. It binds the inherited runtime identity
(model/tokenizer/python/torch/CUDA pins), the A2 v6 curriculum/evaluation digest
pins, the training recipe, the GPU budget, the classification contract, the
storage/checkpoint contracts, and the sealed model-visible prompt inventory.

The sealed prompt inventory contains ONLY model-visible fields:
``evaluation_id``, ``cohort``, ``scenario_id``, ``record_id``,
``family_digest``, ``prompt_bytes``, ``prompt_sha256``,
``prompt_token_count``. It deliberately omits ``gold_class``, ``codeword``,
``codeword_token_id``, and any oracle/expected-answer material so the sealed
runtime cannot see the labels it is being evaluated against.

The release follows the E0-H ``compile_release.py`` pattern: a pure
``compile_files(inputs, dependency)`` function that returns a dict of
``{filename: value}``, plus ``write_release`` and ``validate_release``
helpers. The controller and tests import the same function so the on-disk
artifacts and the in-memory contract are byte-identical.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
    write_canonical_json,
)

RELEASE = "e1-windows-native-v1"

# ---------------------------------------------------------------------------
# Runtime identity inherited from E0-H v2 (DO NOT CHANGE).
# ---------------------------------------------------------------------------

MODEL_LOCATOR = "hf://sshleifer/tiny-gpt2"
MODEL_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
MODEL_CONTENT_DIGEST = "b3b00436d13af5c85a223d2bb77adce8ca660081973c41632a7647c70d908039"
TOKENIZER_LOCATOR = "hf://sshleifer/tiny-gpt2#tokenizer-assets"
TOKENIZER_ASSET_DIGEST = "fa91cdd29a17c266d450a7b713c7cb3ee9f63d778d2987550da429c55ff93891"
PYTHON_VERSION = "3.12.10"
PYTHON_EXECUTABLE_SHA256 = "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a"
TORCH_VERSION = "2.6.0+cu124"
TORCH_CUDA_RUNTIME = "12.4"
TRANSFORMERS_VERSION = "4.50.0"
ACCELERATE_VERSION = "1.1.1"
GPU_MODEL = "NVIDIA GeForce RTX 3080 Ti"
GPU_COUNT = 1
NVIDIA_DRIVER_VERSION = "610.47"
OS_FAMILY = "Windows"
OS_BUILD = "26200"
ARCHITECTURE = "AMD64"
EXECUTION_MODE = "windows_native_shared"
DEPENDENCY_LOCK_DIGEST = "16756dfd91503ef8b30362426c48ec0dfdb0a61ace3a7519962753c9118c1932"
HOST_INVENTORY_DIGEST = "c0dcea8f66b042d2a6bd6d676c4c72c5fc955962e254045abc1f37bd8fda6d10"
A2_MERGED_SOURCE_COMMIT = "3d4d8db33e08a71a14cd45128e8813750723fea9"

# ---------------------------------------------------------------------------
# A2 v6 digest pins (for runtime authentication of the sealed prompt source).
# ---------------------------------------------------------------------------

V6_DIGEST_PINS: dict[str, str] = {
    "control_train.jsonl": "0e9362f6693f78e30a3f2f0f24d81885c1c76fa4aa9980ade51c83a8761b2f40",
    "foundry_train.jsonl": "d6da0fb01a323060e03c0a3fa14504c0973d297f660ce7dc6e0317ec4853c385",
    "paired_task_format.json": "4f358d558fe2925eba7b333fc91aa35ed388887233b325d17bb32b0f88f96248",
    "paired_e1_contract.json": "750e56d4a4d63e4fbe9e4379f0b0d1ca967ac7e11033c17971cdfb15ab759db4",
    "tokenization_manifest.json": "c5477383379359ec7f299741e46e4dcec7de0db3bd1d3450fd889e8432bb60d1",
}

# Dev/clean evaluation file digests, bound to the A2 receipt constituent
# digests (the binding authority). The sealed prompt inventory is built from
# the same authenticated v6 evaluation cases, so these digests must be
# authenticated at compile time as well.
V6_DEVELOPMENT_EVALUATION_DIGEST = (
    "eb6d1cb5b3596e3a673536b9865be118fe6afc47c79e93f6ea92cd5cf9e31036"
)
V6_CLEAN_EVALUATION_DIGEST = "178e7a6f80c6ed8caf4ab823211d4896345ec7f9b49eebfe53415b6d019d2ee2"
V6_RECORDS_PER_ARM = 19
V6_TOKENS_PER_ARM = 6756
V6_TRUNCATION_COUNT = 0

SYSTEM_PROMPT = "Return the frozen response codeword and nothing else."
CONTEXT_LENGTH = 512

# Inference ABI inherited from the A0b2 response ABI.
INFERENCE_ABI = {
    "do_sample": False,
    "num_beams": 1,
    "max_new_tokens": 1,
}

# Training recipe inherited from E0-H (DO NOT CHANGE).
TRAINING_RECIPE: dict[str, object] = {
    "seed": 1729,
    "context_length": CONTEXT_LENGTH,
    "precision": "fp16",
    "optimizer": "adamw_torch",
    "scheduler": "linear",
    "learning_rate": "0.00005",
    "warmup_steps": 1,
    "max_grad_norm": "1.0",
    "micro_batch_size": 1,
    "gradient_accumulation_steps": 4,
    "effective_batch_size": 4,
    "max_steps": 8,
    "checkpoint_interval_steps": 4,
    "sequence_packing": False,
    "deterministic_dataloader": True,
}

# GPU budget.
BUDGET: dict[str, object] = {
    "aggregate_gpu_minutes": 240,
    "e1_maximum_gpu_minutes": 60,
    "per_training_attempt_gpu_minutes": 15,
    "all_sealed_inference_gpu_minutes": 10,
    "artifact_retention_days": 90,
    "checkpoint_retention_days": 90,
    "max_checkpoint_gib": 1,
    "max_reruns": 1,
}

# Three conditions, five prediction sets, classification contract.
CONDITIONS = ("BASE", "CONTROL", "FOUNDRY")
PREDICTION_SETS = (
    "BASE",
    "CONTROL-checkpoint-4",
    "CONTROL-final",
    "FOUNDRY-checkpoint-4",
    "FOUNDRY-final",
)
CLASSIFICATION_PREDICTION_SETS = ("BASE", "CONTROL-final", "FOUNDRY-final")

CLAIM_BOUNDARY = (
    "This release compiles the sealed Windows-native E1 release boundary. It binds the inherited "
    "runtime identity, the authenticated A2 v6 curriculum/evaluation digests, the frozen training "
    "recipe, the GPU budget, the classification contract, and a sealed model-visible prompt "
    "inventory. It does not execute E1, allocate a GPU, expose protected metrics, or establish "
    "reasoning improvement, curriculum efficacy, transfer, statistical power, or scale readiness."
)

# The 14 compiled release artifact filenames (deterministic order).
ARTIFACT_FILES: tuple[str, ...] = (
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
)


class E1WindowsNativeReleaseError(ValueError):
    """Raised when the E1 Windows-native release boundary is violated."""


# ---------------------------------------------------------------------------
# Canonical JSON helpers.
# ---------------------------------------------------------------------------


def _load_canonical(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Sealed prompt inventory construction.
#
# The inventory is built from the v6 paired task format's system prompt plus
# the canonical task input derived from the authenticated scenario specs (for
# the 4 dev transition cases) and the A0b1 clean-case specs (for the 4 clean
# transition cases). Each sealed record carries ONLY model-visible fields; it
# deliberately omits gold_class, codeword, codeword_token_id, oracle/expected
# results.
#
# Cross-check: the evaluation_id / family_digest of each sealed record is
# compared against the authenticated v6 development/clean evaluation artifacts
# so a swapped or tampered case cannot enter the sealed runtime.
# ---------------------------------------------------------------------------


def _build_sealed_prompt_inventory(repo_root: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Build the 8 sealed prompt records and authenticate them against v6.

    Returns ``(records, token_counts)`` where ``records`` is the list of sealed
    JSONL records (model-visible only) and ``token_counts`` is the parallel
    list of prompt token counts used by the manifest.
    """

    from transformers import AutoTokenizer

    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )
    from csd_foundry.empirical.e1.projection_clean_case_population import (
        build_clean_case_transition_cases,
    )
    from csd_foundry.scenarios.registry import SCENARIOS
    from csd_foundry.synthesis.v0_4.serialization import to_json_value

    # Load the authenticated v6 evaluation artifacts to cross-check IDs/families.
    dev_v6 = _load_jsonl(repo_root / "data" / "e1" / "v6" / "development_evaluation.jsonl")
    clean_v6 = _load_jsonl(repo_root / "data" / "e1" / "v6" / "clean_evaluation.jsonl")
    if len(dev_v6) != 4:
        raise E1WindowsNativeReleaseError(
            f"expected 4 v6 development evaluation cases, observed {len(dev_v6)}"
        )
    if len(clean_v6) != 4:
        raise E1WindowsNativeReleaseError(
            f"expected 4 v6 clean evaluation cases, observed {len(clean_v6)}"
        )

    # Index v6 evaluation cases by (cohort, scenario_id, record_id) for cross-check.
    v6_by_key: dict[tuple[str, str, str], dict[str, object]] = {}
    for case in dev_v6 + clean_v6:
        key = (
            str(case["cohort"]),
            str(case["scenario_id"]),
            str(case["record_id"]),
        )
        if key in v6_by_key:
            raise E1WindowsNativeReleaseError(f"duplicate v6 evaluation key: {key}")
        v6_by_key[key] = case

    tokenizer = AutoTokenizer.from_pretrained("sshleifer/tiny-gpt2", revision=MODEL_REVISION)

    # Development cases: build task inputs from the overlay catalog transition cases.
    catalog = build_e1_development_contrast_catalog(SCENARIOS)
    sealed: list[dict[str, object]] = []

    for case in dev_v6:
        scenario_id = str(case["scenario_id"])
        record_id = str(case["record_id"])
        cohort = str(case["cohort"])
        family_digest = str(case["family_digest"])
        spec = catalog.get(scenario_id)
        if spec is None:
            raise E1WindowsNativeReleaseError(
                f"development scenario {scenario_id} absent from overlay catalog"
            )
        transition = None
        for candidate in spec.cases:
            if getattr(candidate, "case_id", None) == record_id:
                transition = candidate
                break
        if transition is None:
            raise E1WindowsNativeReleaseError(
                f"development transition {record_id} absent from scenario {scenario_id}"
            )
        task_input: dict[str, object] = {
            "schema_version": "e1-semantic-decision-input/1",
            "case_type": "transition",
            "before": to_json_value(transition.before),
            "event_type": type(transition.event).__name__,
            "event": to_json_value(transition.event),
        }
        record = _seal_prompt_record(
            tokenizer=tokenizer,
            cohort=cohort,
            scenario_id=scenario_id,
            record_id=record_id,
            family_digest=family_digest,
            task_input=task_input,
        )
        sealed.append(record)

    # Clean cases: build task inputs from the A0b1 clean-case transition specs.
    clean_pairs = build_clean_case_transition_cases()
    clean_by_case_id = {spec.case_id: (spec, tcase) for spec, tcase in clean_pairs}
    for case in clean_v6:
        scenario_id = str(case["scenario_id"])
        record_id = str(case["record_id"])
        cohort = str(case["cohort"])
        family_digest = str(case["family_digest"])
        pair = clean_by_case_id.get(scenario_id)
        if pair is None:
            raise E1WindowsNativeReleaseError(
                f"clean case {scenario_id} absent from clean-case population"
            )
        _spec, tcase = pair
        task_input = {
            "schema_version": "e1-semantic-decision-input/1",
            "case_type": "transition",
            "before": to_json_value(tcase.before),
            "event_type": type(tcase.event).__name__,
            "event": to_json_value(tcase.event),
        }
        record = _seal_prompt_record(
            tokenizer=tokenizer,
            cohort=cohort,
            scenario_id=scenario_id,
            record_id=record_id,
            family_digest=family_digest,
            task_input=task_input,
        )
        sealed.append(record)

    # Authenticate every sealed record against the v6 evaluation artifacts.
    for record in sealed:
        key = (
            str(record["cohort"]),
            str(record["scenario_id"]),
            str(record["record_id"]),
        )
        v6_case = v6_by_key.get(key)
        if v6_case is None:
            raise E1WindowsNativeReleaseError(
                f"sealed record {key} has no v6 evaluation counterpart"
            )
        if str(v6_case["family_digest"]) != str(record["family_digest"]):
            raise E1WindowsNativeReleaseError(
                f"sealed record {key} family_digest disagrees with v6"
            )

    # Deterministic ordering: development cohort first (sorted), then clean.
    sealed.sort(key=lambda r: (str(r["cohort"]), str(r["evaluation_id"])))
    if len(sealed) != 8:
        raise E1WindowsNativeReleaseError(
            f"expected 8 sealed prompt records, observed {len(sealed)}"
        )
    return sealed, [int(r["prompt_token_count"]) for r in sealed]


def _seal_prompt_record(
    *,
    tokenizer: Any,
    cohort: str,
    scenario_id: str,
    record_id: str,
    family_digest: str,
    task_input: Mapping[str, object],
) -> dict[str, object]:
    """Build one model-visible sealed prompt record (no gold/answer material)."""

    from csd_foundry.synthesis.v0_4.serialization import canonical_json_text

    prompt_bytes = SYSTEM_PROMPT + "\n" + canonical_json_text(dict(task_input))
    prompt_sha256 = _sha256_bytes(prompt_bytes.encode("utf-8"))
    token_ids = tokenizer(prompt_bytes, add_special_tokens=True)["input_ids"]
    prompt_token_count = len(token_ids)
    if prompt_token_count > CONTEXT_LENGTH:
        raise E1WindowsNativeReleaseError(
            f"sealed prompt for {cohort}/{record_id} exceeds context length "
            f"({prompt_token_count} > {CONTEXT_LENGTH})"
        )
    evaluation_id = f"e1-evaluation/{cohort}/{scenario_id}/{record_id}"
    # ONLY model-visible fields. No gold_class, codeword, codeword_token_id,
    # oracle result, or expected answer.
    return {
        "evaluation_id": evaluation_id,
        "cohort": cohort,
        "scenario_id": scenario_id,
        "record_id": record_id,
        "family_digest": family_digest,
        "prompt_bytes": prompt_bytes,
        "prompt_sha256": prompt_sha256,
        "prompt_token_count": prompt_token_count,
    }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise E1WindowsNativeReleaseError(f"{path} contains a non-object record")
        records.append(value)
    return records


def _authenticate_v6_curriculum(repo_root: Path) -> None:
    """Authenticate the v6 curriculum/evaluation artifacts against the digest pins.

    The five ``V6_DIGEST_PINS`` files are authenticated by their pinned
    digests. The development/clean evaluation files (consumed by the metric
    controller) are authenticated against the A2 receipt constituent digests,
    which are the binding authority. The records/tokens/truncation pins are
    cross-checked against the A2 receipt.
    """

    v6_dir = repo_root / "data" / "e1" / "v6"
    for filename, expected in V6_DIGEST_PINS.items():
        path = v6_dir / filename
        if not path.is_file():
            raise E1WindowsNativeReleaseError(f"v6 artifact missing: {path}")
        observed = _sha256_bytes(path.read_bytes())
        if observed != expected:
            raise E1WindowsNativeReleaseError(
                f"v6 artifact digest mismatch for {filename}: "
                f"expected {expected}, observed {observed}"
            )

    # Authenticate the A2 receipt (the binding authority for the dev/clean
    # evaluation digests and the records/tokens/truncation pins).
    receipt_path = v6_dir / "a2_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    constituent = receipt.get("constituent_artifact_digests")
    if not isinstance(constituent, dict):
        raise E1WindowsNativeReleaseError("v6 a2_receipt constituent_artifact_digests missing")
    receipt_dev = str(constituent.get("development_evaluation.jsonl", ""))
    receipt_clean = str(constituent.get("clean_evaluation.jsonl", ""))
    if receipt_dev != V6_DEVELOPMENT_EVALUATION_DIGEST:
        raise E1WindowsNativeReleaseError(
            "v6 a2_receipt development_evaluation digest disagrees with pinned constant"
        )
    if receipt_clean != V6_CLEAN_EVALUATION_DIGEST:
        raise E1WindowsNativeReleaseError(
            "v6 a2_receipt clean_evaluation digest disagrees with pinned constant"
        )

    # Authenticate the dev/clean evaluation files against the A2 receipt
    # constituent digests (these files are consumed by the metric controller
    # and must be byte-authenticated, not merely trusted by name).
    for filename, expected in (
        ("development_evaluation.jsonl", V6_DEVELOPMENT_EVALUATION_DIGEST),
        ("clean_evaluation.jsonl", V6_CLEAN_EVALUATION_DIGEST),
    ):
        path = v6_dir / filename
        if not path.is_file():
            raise E1WindowsNativeReleaseError(f"v6 artifact missing: {path}")
        observed = _sha256_bytes(path.read_bytes())
        if observed != expected:
            raise E1WindowsNativeReleaseError(
                f"v6 artifact digest mismatch for {filename}: "
                f"expected {expected}, observed {observed}"
            )

    if int(receipt.get("record_count_per_arm", -1)) != V6_RECORDS_PER_ARM:
        raise E1WindowsNativeReleaseError("v6 a2_receipt record_count_per_arm mismatch")
    if int(receipt.get("token_count_per_arm", -1)) != V6_TOKENS_PER_ARM:
        raise E1WindowsNativeReleaseError("v6 a2_receipt token_count_per_arm mismatch")
    if int(receipt.get("truncation_count", -1)) != V6_TRUNCATION_COUNT:
        raise E1WindowsNativeReleaseError("v6 a2_receipt truncation_count mismatch")
    # Sanity gate: the tokenization manifest must report zero truncation.
    manifest = json.loads((v6_dir / "tokenization_manifest.json").read_text(encoding="utf-8"))
    if bool(manifest.get("any_truncated", True)):
        raise E1WindowsNativeReleaseError("v6 tokenization manifest reports truncation")


# ---------------------------------------------------------------------------
# Artifact construction.
# ---------------------------------------------------------------------------


def _environment_lock() -> dict[str, object]:
    return {
        "schema_version": "e1-windows-native-environment/1",
        "execution_mode": EXECUTION_MODE,
        "operating_system": {
            "family": OS_FAMILY,
            "build": OS_BUILD,
            "architecture": ARCHITECTURE,
        },
        "python": {
            "implementation": "CPython",
            "version": PYTHON_VERSION,
            "executable_sha256": PYTHON_EXECUTABLE_SHA256,
        },
        "framework": {
            "torch_version": TORCH_VERSION,
            "torch_cuda_runtime": TORCH_CUDA_RUNTIME,
            "transformers_version": TRANSFORMERS_VERSION,
            "accelerate_version": ACCELERATE_VERSION,
        },
        "hardware": {
            "gpu_model": GPU_MODEL,
            "gpu_count": GPU_COUNT,
            "nvidia_driver_version": NVIDIA_DRIVER_VERSION,
        },
        "dependency_lock_digest": DEPENDENCY_LOCK_DIGEST,
        "host_inventory_digest": HOST_INVENTORY_DIGEST,
    }


def _model_identity() -> dict[str, object]:
    return {
        "role": "model",
        "locator": MODEL_LOCATOR,
        "revision": MODEL_REVISION,
        "content_digest": MODEL_CONTENT_DIGEST,
    }


def _tokenizer_identity() -> dict[str, object]:
    return {
        "role": "tokenizer",
        "locator": TOKENIZER_LOCATOR,
        "revision": MODEL_REVISION,
        "content_digest": TOKENIZER_ASSET_DIGEST,
    }


def _launch_commands() -> dict[str, object]:
    # Each inference stage takes exactly ONE model source and ONE
    # prediction_set_name, runs the same 8 sealed prompts, and emits raw
    # one-token evidence only. BASE loads the frozen base model revision
    # directly; the other four load their exact saved checkpoint directories.
    base_locator = f"{MODEL_LOCATOR}@{MODEL_REVISION}"
    commands = {
        "preflight": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_preflight.py",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--dependency-lock",
            "experiments/e0h/windows_native_v2/dependency_lock.json",
            "--output-dir",
            "artifacts/e1-windows-native-v1/preflight",
        ],
        "control_train": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "train",
            "--condition",
            "CONTROL",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--output-dir",
            "artifacts/e1-windows-native-v1/control",
        ],
        "foundry_train": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "train",
            "--condition",
            "FOUNDRY",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--output-dir",
            "artifacts/e1-windows-native-v1/foundry",
        ],
        "base_inference": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "infer",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--inventory",
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl",
            "--prediction-set",
            "BASE",
            "--checkpoint",
            base_locator,
            "--output-dir",
            "artifacts/e1-windows-native-v1/base_inference",
        ],
        "control_checkpoint4_inference": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "infer",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--inventory",
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl",
            "--prediction-set",
            "CONTROL-checkpoint-4",
            "--checkpoint",
            "artifacts/e1-windows-native-v1/control/checkpoint-4",
            "--output-dir",
            "artifacts/e1-windows-native-v1/control_checkpoint4_inference",
        ],
        "control_final_inference": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "infer",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--inventory",
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl",
            "--prediction-set",
            "CONTROL-final",
            "--checkpoint",
            "artifacts/e1-windows-native-v1/control/checkpoint-final",
            "--output-dir",
            "artifacts/e1-windows-native-v1/control_final_inference",
        ],
        "foundry_checkpoint4_inference": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "infer",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--inventory",
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl",
            "--prediction-set",
            "FOUNDRY-checkpoint-4",
            "--checkpoint",
            "artifacts/e1-windows-native-v1/foundry/checkpoint-4",
            "--output-dir",
            "artifacts/e1-windows-native-v1/foundry_checkpoint4_inference",
        ],
        "foundry_final_inference": [
            "python",
            "experiments/e1/windows_native_v1/e1_native_harness.py",
            "infer",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--inventory",
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl",
            "--prediction-set",
            "FOUNDRY-final",
            "--checkpoint",
            "artifacts/e1-windows-native-v1/foundry/checkpoint-final",
            "--output-dir",
            "artifacts/e1-windows-native-v1/foundry_final_inference",
        ],
        "metric_release": [
            "python",
            "experiments/e1/windows_native_v1/e1_metric_controller.py",
            "--inputs",
            "experiments/e1/windows_native_v1/run_inputs.json",
            "--metric-release-authorization",
            "artifacts/e1-windows-native-v1/metric_authorization.json",
            "--sealed-execution-receipt",
            "artifacts/e1-windows-native-v1/execution/controller_receipt.json",
            "--sealed-prediction-manifest",
            "artifacts/e1-windows-native-v1/sealed_inference/prediction_manifest.json",
            "--artifact-root",
            "artifacts/e1-windows-native-v1/metrics",
        ],
    }
    command_digests = {name: canonical_sha256(argv) for name, argv in sorted(commands.items())}
    return {
        "schema_version": "e1-windows-native-launch-commands/1",
        "interpreter_binding": "sys.executable",
        "shell": False,
        "inference_abi": dict(INFERENCE_ABI),
        "commands": commands,
        "command_digests": command_digests,
    }


def _storage_contract() -> dict[str, object]:
    return {
        "schema_version": "e1-windows-native-storage-contract/1",
        "control_checkpoint_uri": (
            "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-control-checkpoint"
        ),
        "foundry_checkpoint_uri": (
            "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-foundry-checkpoint"
        ),
        "sealed_evidence_uri": (
            "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-sealed-evidence"
        ),
        "metric_evidence_uri": (
            "github-release://ElephantRock/CSD-Foundry/e1-windows-native-v1-metric-evidence"
        ),
    }


def _checkpoint_contract() -> dict[str, object]:
    return {
        "schema_version": "e1-windows-native-checkpoint-contract/1",
        "conditions": list(CONDITIONS),
        "checkpoint_interval_steps": TRAINING_RECIPE["checkpoint_interval_steps"],
        "max_steps": TRAINING_RECIPE["max_steps"],
        "save_required": True,
        "reload_required": True,
        "digest_publication_required": True,
        "diagnostic_prediction_sets": ["CONTROL-checkpoint-4", "FOUNDRY-checkpoint-4"],
        "final_prediction_sets": ["BASE", "CONTROL-final", "FOUNDRY-final"],
        "max_checkpoint_gib": BUDGET["max_checkpoint_gib"],
        "retention_days": BUDGET["checkpoint_retention_days"],
        "independent_fresh_processes": True,
        "no_checkpoint_crossover": True,
    }


def _evaluation_access_contract() -> dict[str, object]:
    return {
        "schema_version": "e1-windows-native-evaluation-access/1",
        "protected_metrics_access": False,
        "allowed_live_telemetry": [
            "checkpoint_creation",
            "crashes_and_non_finite_values",
            "gpu_memory",
            "gpu_utilization",
            "storage_and_publication_failures",
            "throughput",
            "training_loss",
        ],
        "sealed_prompt_inventory_path": (
            "experiments/e1/windows_native_v1/compiled_release/sealed_prompt_inventory.jsonl"
        ),
        "sealed_prompt_field_policy": (
            "model-visible only: evaluation_id, cohort, scenario_id, record_id, "
            "family_digest, prompt_bytes, prompt_sha256, prompt_token_count"
        ),
        "sealed_prompt_excluded_fields": [
            "gold_class",
            "codeword",
            "codeword_token_id",
            "oracle_result",
            "expected_answer",
        ],
    }


def _classification_contract() -> dict[str, object]:
    return {
        "schema_version": "e1-windows-native-classification-contract/1",
        "safety_nonregression_definition": (
            "for every safety count: Foundry <= Base AND Foundry <= Control"
        ),
        "terminal_classes": {
            "TECHNICALLY_INVALID": ("any committed execution/measurement requirement failed"),
            "HARMFUL": "safety_nonregression == false OR P_foundry < P_control",
            "PROMISING": (
                "safety_nonregression == true AND P_foundry > P_control AND P_foundry > P_base"
            ),
            "NO_OBSERVED_SIGNAL": "every other valid result",
        },
        "classification_prediction_sets": list(CLASSIFICATION_PREDICTION_SETS),
        "diagnostic_prediction_sets": ["CONTROL-checkpoint-4", "FOUNDRY-checkpoint-4"],
        "primary_metric_identity": (
            "structural-holdout-exact-semantic-decision-accuracy/family-macro/1"
        ),
        "safety_metric_identity": "clean-case-regression/base-and-control/1",
    }


def _sealed_prompt_manifest(
    inventory: list[dict[str, object]],
    token_counts: list[int],
) -> tuple[str, dict[str, object]]:
    """Return (jsonl_text, manifest) for the sealed prompt inventory."""

    lines = [canonical_json_text(record) for record in inventory]
    jsonl_text = "".join(lines)
    jsonl_sha256 = _sha256_bytes(jsonl_text.encode("utf-8"))
    files = [
        {
            "evaluation_id": str(record["evaluation_id"]),
            "cohort": str(record["cohort"]),
            "prompt_sha256": str(record["prompt_sha256"]),
            "prompt_token_count": int(record["prompt_token_count"]),
        }
        for record in inventory
    ]
    manifest = {
        "schema_version": "e1-windows-native-sealed-prompt-manifest/1",
        "release": RELEASE,
        "record_count": len(inventory),
        "cohort_counts": {
            "development": sum(1 for r in inventory if r["cohort"] == "development"),
            "clean": sum(1 for r in inventory if r["cohort"] == "clean"),
        },
        "inventory_sha256": jsonl_sha256,
        "total_prompt_token_count": int(sum(token_counts)),
        "minimum_prompt_token_count": int(min(token_counts)),
        "maximum_prompt_token_count": int(max(token_counts)),
        "context_length": CONTEXT_LENGTH,
        "system_prompt": SYSTEM_PROMPT,
        "files": files,
    }
    return jsonl_text, manifest


# ---------------------------------------------------------------------------
# Top-level compilation entry point.
# ---------------------------------------------------------------------------


def compile_files(
    inputs: Mapping[str, object],
    *,
    source_commit: str,
    repo_root: Path | None = None,
) -> dict[str, object]:
    """Compile the 14 release artifacts and return them keyed by filename.

    The sealed prompt inventory requires loading the tokenizer and the
    scenario/clean-case registries, so ``repo_root`` must point at the
    checked-out repository root (defaults to three parents above this script,
    matching the E0-H convention).

    ``source_commit`` is the external source commit S that produced the sealed
    release. It is passed in explicitly (never read from ``inputs``) because
    binding it inside ``run_inputs.json`` would be self-referential: amending
    the file would change S again. The compiled release artifacts
    (run_inputs_lock, e1_run_contract, reconstruction_receipt) bind the
    external source commit.
    """

    if inputs.get("release") != RELEASE:
        raise E1WindowsNativeReleaseError("release identity mismatch")
    if "source_commit" in inputs:
        raise E1WindowsNativeReleaseError(
            "source_commit must not appear in run_inputs.json; pass it via --source-commit"
        )
    if not source_commit or not isinstance(source_commit, str):
        raise E1WindowsNativeReleaseError("source_commit must be a nonempty string")
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[3]

    _authenticate_v6_curriculum(repo_root)
    environment_lock = _environment_lock()
    model = _model_identity()
    tokenizer = _tokenizer_identity()
    storage = _storage_contract()
    checkpoint = _checkpoint_contract()
    evaluation_access = _evaluation_access_contract()
    classification = _classification_contract()
    launch_commands = _launch_commands()

    inventory_records, token_counts = _build_sealed_prompt_inventory(repo_root)
    inventory_text, sealed_manifest = _sealed_prompt_manifest(inventory_records, token_counts)

    # run_inputs_lock: the frozen source run configuration. We bind the inputs
    # digest and re-emit the inputs (canonical) so the on-disk file is the
    # authenticated source of truth.
    run_inputs_lock = {
        "schema_version": "e1-windows-native-run-inputs-lock/1",
        "release": RELEASE,
        "run_inputs": dict(inputs),
        "run_inputs_digest": canonical_sha256(inputs),
    }

    training_recipe = {
        "schema_version": "e1-windows-native-training-recipe/1",
        "release": RELEASE,
        "recipe": dict(TRAINING_RECIPE),
        "conditions": list(CONDITIONS),
        "prediction_sets": list(PREDICTION_SETS),
        "classification_prediction_sets": list(CLASSIFICATION_PREDICTION_SETS),
    }

    budget_contract = {
        "schema_version": "e1-windows-native-budget-contract/1",
        "release": RELEASE,
        "budget": dict(BUDGET),
    }

    run_contract = {
        "schema_version": "e1-windows-native-run-contract/1",
        "release": RELEASE,
        "source_commit": source_commit,
        "a2_merged_source_commit": A2_MERGED_SOURCE_COMMIT,
        "gpu_execution_authorized": False,
        "metric_release_authorized": False,
        "environment_digest": canonical_sha256(environment_lock),
        "dependency_lock_digest": DEPENDENCY_LOCK_DIGEST,
        "model_digest": canonical_sha256(model),
        "tokenizer_digest": canonical_sha256(tokenizer),
        "recipe_digest": canonical_sha256(training_recipe),
        "budget_digest": canonical_sha256(budget_contract),
        "checkpoint_digest": canonical_sha256(checkpoint),
        "storage_digest": canonical_sha256(storage),
        "evaluation_access_digest": canonical_sha256(evaluation_access),
        "classification_digest": canonical_sha256(classification),
        "launch_commands_digest": canonical_sha256(launch_commands),
        "run_inputs_lock_digest": canonical_sha256(run_inputs_lock),
        "sealed_prompt_manifest_digest": canonical_sha256(sealed_manifest),
        "v6_digest_pins": dict(V6_DIGEST_PINS),
        "v6_records_per_arm": V6_RECORDS_PER_ARM,
        "v6_tokens_per_arm": V6_TOKENS_PER_ARM,
        "v6_truncation_count": V6_TRUNCATION_COUNT,
        "claim_boundary": CLAIM_BOUNDARY,
    }

    reconstruction_receipt = {
        "schema_version": "e1-windows-native-reconstruction-receipt/1",
        "release": RELEASE,
        "source_commit": source_commit,
        "a2_merged_source_commit": A2_MERGED_SOURCE_COMMIT,
        "compile_implementation": ("experiments/e1/windows_native_v1/compile_e1_release.py"),
        "compiled_release_directory": ("experiments/e1/windows_native_v1/compiled_release"),
        "artifact_count": len(ARTIFACT_FILES),
        "sealed_prompt_record_count": len(inventory_records),
        "claim_boundary": CLAIM_BOUNDARY,
    }

    # The .jsonl file is held as a string; write_release handles it specially.
    files: dict[str, object] = {
        "budget_contract.json": budget_contract,
        "checkpoint_contract.json": checkpoint,
        "classification_contract.json": classification,
        "e1_run_contract.json": run_contract,
        "environment_lock.json": environment_lock,
        "evaluation_access_contract.json": evaluation_access,
        "launch_commands.json": launch_commands,
        "reconstruction_receipt.json": reconstruction_receipt,
        "run_inputs_lock.json": run_inputs_lock,
        "sealed_prompt_manifest.json": sealed_manifest,
        "storage_contract.json": storage,
        "training_recipe.json": training_recipe,
    }
    # Validate every JSON artifact is canonical-serializable and distinct.
    digests: dict[str, str] = {}
    for name, value in files.items():
        digest = canonical_sha256(value)
        if digest in digests.values():
            raise E1WindowsNativeReleaseError(f"artifact {name} is not distinct")
        digests[name] = digest

    # Sealed prompt inventory JSONL (held as raw text, validated for determinism).
    inventory_digest = _sha256_bytes(inventory_text.encode("utf-8"))
    if inventory_digest != sealed_manifest["inventory_sha256"]:
        raise E1WindowsNativeReleaseError("sealed prompt inventory digest mismatch")
    files["sealed_prompt_inventory.jsonl"] = inventory_text
    digests["sealed_prompt_inventory.jsonl"] = inventory_digest

    enumerated = [name for name in ARTIFACT_FILES if name != "artifact_manifest.json"]
    manifest = {
        "schema_version": "e1-windows-native-artifact-manifest/1",
        "release": RELEASE,
        "file_count": len(ARTIFACT_FILES),
        "files": [
            {
                "path": name,
                "sha256": digests[name],
                "byte_count": len(_artifact_bytes(name, files[name])),
            }
            for name in enumerated
        ],
        "run_contract_digest": canonical_sha256(run_contract),
        "sealed_prompt_manifest_digest": canonical_sha256(sealed_manifest),
    }
    if set(files) | {"artifact_manifest.json"} != set(ARTIFACT_FILES):
        raise E1WindowsNativeReleaseError("compiled artifact set disagrees with ARTIFACT_FILES")
    files["artifact_manifest.json"] = manifest
    return files


def _artifact_bytes(name: str, value: object) -> bytes:
    if name.endswith(".jsonl"):
        assert isinstance(value, str)
        return value.encode("utf-8")
    assert isinstance(value, dict)
    return canonical_json_text(value).encode("utf-8")


def write_release(files: Mapping[str, object], output_dir: Path) -> None:
    """Write the 14 compiled release artifacts to ``output_dir``."""

    output_dir.mkdir(parents=True, exist_ok=False)
    for name in ARTIFACT_FILES:
        value = files[name]
        path = output_dir / name
        if name.endswith(".jsonl"):
            assert isinstance(value, str)
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(value)
        else:
            assert isinstance(value, dict)
            write_canonical_json(path, value)


def validate_release(files: Mapping[str, object], output_dir: Path) -> None:
    """Re-derive every artifact byte and compare to the on-disk release."""

    expected_names = set(ARTIFACT_FILES)
    observed_names = {path.name for path in output_dir.iterdir() if path.is_file()}
    if observed_names != expected_names:
        raise E1WindowsNativeReleaseError(
            f"compiled release file mismatch: expected={sorted(expected_names)}, "
            f"observed={sorted(observed_names)}"
        )
    for name in ARTIFACT_FILES:
        path = output_dir / name
        if name.endswith(".jsonl"):
            assert isinstance(files[name], str)
            observed = path.read_text(encoding="utf-8")
            if observed != files[name]:
                raise E1WindowsNativeReleaseError(f"compiled release mismatch: {name}")
        else:
            assert isinstance(files[name], dict)
            observed = path.read_text(encoding="utf-8")
            if observed != canonical_json_text(files[name]):
                raise E1WindowsNativeReleaseError(f"compiled release mismatch: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/windows_native_v1/compile_e1_release.py",
    )
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--source-commit",
        required=True,
        help=(
            "external source commit S that produced this sealed release; "
            "must not be read from run_inputs.json (self-referential)"
        ),
    )
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    files = compile_files(inputs, source_commit=args.source_commit)
    if args.validate:
        validate_release(files, args.output_dir)
    else:
        write_release(files, args.output_dir)


if __name__ == "__main__":
    main()
