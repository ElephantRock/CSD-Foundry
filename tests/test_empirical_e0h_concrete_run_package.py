from __future__ import annotations

import hashlib
from pathlib import Path

from csd_foundry.empirical.e0h import (
    compile_e0h_run_release,
    load_e0h_run_release_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments" / "e0h" / "v1"


def test_concrete_e0h_inputs_compile_to_self_describing_release() -> None:
    inputs_path = PACKAGE / "run_inputs.json"
    inputs = load_e0h_run_release_inputs(inputs_path.read_text(encoding="utf-8"))
    bundle = compile_e0h_run_release(inputs)

    assert bundle.release == "e0h-harness-v1"
    assert bundle.source_commit == "6bfd2f653c12055de99ae4b39556c78937d96239"
    assert len(bundle.files) == 10
    assert bundle.file("run_inputs_lock.json").content == inputs_path.read_bytes()
    assert b'"gpu_execution_authorized":false' in bundle.file("e0h_run_contract.json").content


def test_smoke_fixture_matches_frozen_digest() -> None:
    fixture = PACKAGE / "smoke_fixture.jsonl"
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        == "5ebd75980df43dd5d2a062e1190baed5e5d1604cb268230a440e4dce29048f8e"
    )


def test_harness_commands_remain_outside_protected_metric_surface() -> None:
    inputs = load_e0h_run_release_inputs((PACKAGE / "run_inputs.json").read_text(encoding="utf-8"))
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
