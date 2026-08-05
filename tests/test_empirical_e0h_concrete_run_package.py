from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from csd_foundry.empirical.e0h import (
    compile_e0h_run_release,
    load_e0h_run_release_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments" / "e0h" / "v1"
COMPILED = PACKAGE / "compiled_release"
PREFLIGHT_RECEIPTS = PACKAGE / "preflight_receipts"
WORKFLOW = ROOT / ".github" / "workflows" / "e0h-preflight.yml"


def _inputs():
    return load_e0h_run_release_inputs((PACKAGE / "run_inputs.json").read_text(encoding="utf-8"))


def _harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location("e0h_harness", PACKAGE / "harness.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_concrete_e0h_inputs_compile_to_self_describing_release() -> None:
    inputs = _inputs()
    bundle = compile_e0h_run_release(inputs)

    assert bundle.release == "e0h-harness-v1"
    assert bundle.source_commit == "6bfd2f653c12055de99ae4b39556c78937d96239"
    assert len(bundle.files) == 10
    assert (
        bundle.file("run_inputs_lock.json").content
        == (COMPILED / "run_inputs_lock.json").read_bytes()
    )
    assert bundle.file("run_inputs_lock.json").content != (PACKAGE / "run_inputs.json").read_bytes()
    assert b'"gpu_execution_authorized":false' in bundle.file("e0h_run_contract.json").content


def test_materialized_release_is_exact_reconstruction() -> None:
    bundle = compile_e0h_run_release(_inputs())
    expected = {item.path: item.content for item in bundle.files}
    observed = {path.name: path.read_bytes() for path in COMPILED.iterdir() if path.is_file()}
    assert observed == expected


def test_smoke_fixture_matches_frozen_digest() -> None:
    fixture = PACKAGE / "smoke_fixture.jsonl"
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        == "5ebd75980df43dd5d2a062e1190baed5e5d1604cb268230a440e4dce29048f8e"
    )


def test_preflight_and_container_are_immutably_bound() -> None:
    inputs = json.loads((PACKAGE / "run_inputs.json").read_text(encoding="utf-8"))
    dockerfile = (PACKAGE / "container" / "Dockerfile").read_text(encoding="utf-8")
    requirements = (PACKAGE / "container" / "requirements.lock").read_text(encoding="utf-8")
    preflight = (PACKAGE / "preflight.py").read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert inputs["environment"]["container_image"] in dockerfile
    assert "--no-deps" in dockerfile
    assert "transformers==4.44.2" in requirements
    assert "accelerate==0.34.2" in requirements
    assert inputs["model"]["revision"] in preflight
    assert '"model.safetensors"' in preflight
    assert '"vocab.json"' in preflight
    assert "forward_pass_complete" in preflight
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow
    assert (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
        in workflow
    )
    assert "actions/checkout@v4" not in workflow
    assert "actions/upload-artifact@v4" not in workflow


def test_committed_preflight_receipts_bind_the_frozen_inputs() -> None:
    inputs = json.loads((PACKAGE / "run_inputs.json").read_text(encoding="utf-8"))
    assets = json.loads(
        (PREFLIGHT_RECEIPTS / "external_asset_receipt.json").read_text(encoding="utf-8")
    )
    environment = json.loads(
        (PREFLIGHT_RECEIPTS / "environment_receipt.json").read_text(encoding="utf-8")
    )
    tokenization = json.loads(
        (PREFLIGHT_RECEIPTS / "tokenization_receipt.json").read_text(encoding="utf-8")
    )
    device = json.loads(
        (PREFLIGHT_RECEIPTS / "minimal_device_preflight.json").read_text(encoding="utf-8")
    )

    assert assets["resolved_revision"] == inputs["model"]["revision"]
    assert assets["model_weight_digest"] == inputs["model"]["content_digest"]
    assert assets["tokenizer_aggregate_digest"] == inputs["tokenizer"]["content_digest"]
    assert environment["expected"] == inputs["environment"]
    assert tokenization["sft_records_loaded"] == inputs["dataset"]["sft_records"]
    assert tokenization["truncation_count"] == 0
    assert device["forward_pass_complete"] is True


def test_harness_rejects_mutable_inputs_and_context_truncation(tmp_path: Path) -> None:
    harness = _harness()
    inputs = json.loads((PACKAGE / "run_inputs.json").read_text(encoding="utf-8"))
    inputs["model"]["revision"] = "0" * 40
    substituted = tmp_path / "substituted-inputs.json"
    substituted.write_text(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(ValueError, match="model locator or revision"):
        harness._load_inputs(substituted)

    class OversizeTokenizer:
        def __call__(self, text: str, *, add_special_tokens: bool) -> dict[str, list[int]]:
            assert add_special_tokens is True
            return {"input_ids": list(range(int(text)))}

    with pytest.raises(RuntimeError, match="truncation is forbidden"):
        harness._require_context_fit(OversizeTokenizer(), ["513"], 512)


def test_harness_receipts_fail_closed_on_clobber(tmp_path: Path) -> None:
    harness = _harness()
    receipt = tmp_path / "receipt.json"
    harness._write_json(receipt, {"status": "first"})
    with pytest.raises(FileExistsError):
        harness._write_json(receipt, {"status": "replacement"})


def test_harness_consumes_the_frozen_training_recipe() -> None:
    harness = (PACKAGE / "harness.py").read_text(encoding="utf-8")
    assert 'optim=str(recipe["optimizer"])' in harness
    assert 'lr_scheduler_type=str(recipe["scheduler"])' in harness
    assert "truncation=False" in harness
    assert "_require_cuda_envelope(torch, inputs)" in harness
    assert 'path.open("x"' in harness


def test_harness_commands_remain_outside_protected_metric_surface() -> None:
    inputs = _inputs()
    commands = (
        inputs.tokenization_command,
        inputs.training_command,
        inputs.reload_command,
        inputs.inference_command,
        inputs.smoke_evaluation_command,
    )
    prohibited = (
        "accuracy",
        "holdout",
        "mutation",
        "subgroup",
        "primary_metric",
        "safety_metric",
        "forbidden_inference_rate",
    )
    for command in commands:
        lowered = command.lower()
        assert not any(term in lowered for term in prohibited)
