"""Reload the final E0-H checkpoint in a clean process and execute a finite forward pass."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any, cast

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_empty_output_directory,
    read_json_object,
    read_jsonl,
    verify_static_inputs,
    write_json_no_clobber,
)
from csd_foundry.empirical.e0h.harness.preflight import run_preflight
from csd_foundry.empirical.e0h.harness.train import (
    _checkpoint_digest,
    _checkpoint_receipts,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def _final_checkpoint(paths: RunPaths) -> tuple[Path, dict[str, object]]:
    health = read_json_object(paths.work / "training" / "training_health.json")
    raw_checkpoints = health.get("checkpoints")
    if not isinstance(raw_checkpoints, list) or not raw_checkpoints:
        raise E0HRunReleaseError("training health does not declare checkpoints")
    final = raw_checkpoints[-1]
    if not isinstance(final, dict):
        raise E0HRunReleaseError("final checkpoint receipt must be an object")
    receipt = cast(dict[str, object], final)
    directory = receipt.get("directory")
    digest = receipt.get("digest")
    if not isinstance(directory, str) or Path(directory).name != directory:
        raise E0HRunReleaseError("final checkpoint directory is invalid")
    if not isinstance(digest, str):
        raise E0HRunReleaseError("final checkpoint digest is invalid")
    checkpoint = paths.work / "training" / directory
    observed_digest = _checkpoint_digest(_checkpoint_receipts(checkpoint))
    if observed_digest != digest:
        raise E0HRunReleaseError("final checkpoint digest does not match training receipt")
    return checkpoint, receipt


def _prompt_ids(tokenizer: Any, messages: object) -> list[int]:
    if not isinstance(messages, list):
        raise E0HRunReleaseError("smoke fixture messages must be a list")
    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
    )
    if not isinstance(prompt, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in prompt
    ):
        raise E0HRunReleaseError("smoke fixture prompt did not tokenize to integer IDs")
    return cast(list[int], prompt)


def reload_checkpoint(paths: RunPaths) -> dict[str, object]:
    """Load the final checkpoint and prove one finite smoke forward pass."""

    verify_static_inputs(paths, require_snapshot=True)
    run_preflight(paths, mode="gpu", require_snapshot=True)
    checkpoint, checkpoint_receipt = _final_checkpoint(paths)
    fixtures = read_jsonl(paths.smoke_fixture)
    if not fixtures:
        raise E0HRunReleaseError("smoke fixture is empty")

    torch = importlib.import_module("torch")
    transformers = importlib.import_module("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(paths.model_snapshot),
        local_files_only=True,
        trust_remote_code=False,
        use_fast=True,
    )
    model = transformers.AutoModelForCausalLM.from_pretrained(
        str(checkpoint),
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=torch.bfloat16,
    )
    model.to("cuda")
    model.eval()
    input_ids = _prompt_ids(tokenizer, fixtures[0].get("messages"))
    with torch.no_grad():
        outputs = model(input_ids=torch.tensor([input_ids], dtype=torch.long, device="cuda"))
    finite = bool(torch.isfinite(outputs.logits).all().item())
    if not finite:
        raise E0HRunReleaseError("reloaded checkpoint produced non-finite logits")

    output_dir = paths.work / "reload"
    assert_empty_output_directory(output_dir)
    receipt = {
        "schema_version": "e0h-reload-receipt/1",
        "checkpoint_directory": checkpoint.name,
        "checkpoint_digest": checkpoint_receipt["digest"],
        "optimizer_step": checkpoint_receipt["step"],
        "prompt_tokens": len(input_ids),
        "finite_logits": finite,
        "clean_process_required": True,
        "protected_metrics_computed": False,
    }
    write_json_no_clobber(output_dir / "reload_receipt.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e0h.harness.reload")
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(reload_checkpoint(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
