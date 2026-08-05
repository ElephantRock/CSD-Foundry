"""Run the bounded deterministic E0-H training smoke exercise."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import random
import time
from pathlib import Path
from typing import Any, cast

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_empty_output_directory,
    read_jsonl,
    sha256_file,
    verify_static_inputs,
    write_json_no_clobber,
)
from csd_foundry.empirical.e0h.harness.preflight import run_preflight
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def _integer_list(value: object, *, field: str) -> list[int]:
    if not isinstance(value, list):
        raise E0HRunReleaseError(f"{field} must be a list")
    if any(isinstance(item, bool) or not isinstance(item, int) for item in value):
        raise E0HRunReleaseError(f"{field} must contain only integers")
    return cast(list[int], value)


def _load_tokenized(paths: RunPaths, expected_digest: str) -> tuple[dict[str, object], ...]:
    data_path = paths.work / "tokenized" / "tokenized_train.jsonl"
    receipt_path = paths.work / "tokenized" / "tokenization_receipt.json"
    if sha256_file(data_path) != expected_digest:
        raise E0HRunReleaseError("tokenized artifact digest does not match the declared receipt")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise E0HRunReleaseError("tokenization receipt is missing")
    records = read_jsonl(data_path)
    if len(records) != 168:
        raise E0HRunReleaseError(
            f"tokenized record count mismatch; expected=168, observed={len(records)}"
        )
    return records


def _checkpoint_receipts(directory: Path) -> tuple[dict[str, object], ...]:
    if directory.is_symlink() or not directory.is_dir():
        raise E0HRunReleaseError(f"checkpoint directory is invalid: {directory}")
    receipts: list[dict[str, object]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise E0HRunReleaseError(f"checkpoint member is not a regular file: {path}")
        receipts.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    if not receipts:
        raise E0HRunReleaseError("checkpoint directory is empty")
    return tuple(receipts)


def _checkpoint_digest(receipts: tuple[dict[str, object], ...]) -> str:
    payload = json.dumps(
        list(receipts),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _save_checkpoint(
    *,
    torch: Any,
    model: Any,
    optimizer: Any,
    scheduler: Any,
    directory: Path,
    step: int,
    seed: int,
) -> dict[str, object]:
    if directory.exists() or directory.is_symlink():
        raise E0HRunReleaseError(f"refusing to overwrite checkpoint: {directory}")
    directory.mkdir(parents=True)
    model.save_pretrained(
        directory,
        safe_serialization=True,
        max_shard_size="1GB",
    )
    torch.save(optimizer.state_dict(), directory / "optimizer.pt")
    torch.save(scheduler.state_dict(), directory / "scheduler.pt")
    state = {
        "schema_version": "e0h-training-state/1",
        "optimizer_step": step,
        "seed": seed,
    }
    (directory / "training_state.json").write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    receipts = _checkpoint_receipts(directory)
    return {
        "step": step,
        "directory": directory.name,
        "digest": _checkpoint_digest(receipts),
        "files": list(receipts),
    }


def _learning_rate_factor(step: int, *, warmup_steps: int, max_steps: int) -> float:
    if step < warmup_steps:
        return float(step + 1) / float(max(warmup_steps, 1))
    remaining = max_steps - step
    decay_span = max(max_steps - warmup_steps, 1)
    return max(float(remaining) / float(decay_span), 0.0)


def run_training(paths: RunPaths) -> dict[str, object]:
    """Execute exactly the frozen number of optimizer steps and publish health receipts."""

    inputs = verify_static_inputs(paths, require_snapshot=True)
    run_preflight(paths, mode="gpu", require_snapshot=True)
    token_receipt_path = paths.work / "tokenized" / "tokenization_receipt.json"
    token_receipt = json.loads(token_receipt_path.read_text(encoding="utf-8"))
    if not isinstance(token_receipt, dict):
        raise E0HRunReleaseError("tokenization receipt must be an object")
    token_digest = token_receipt.get("tokenized_artifact_digest")
    if not isinstance(token_digest, str):
        raise E0HRunReleaseError("tokenization receipt lacks an artifact digest")
    records = _load_tokenized(paths, token_digest)

    torch = importlib.import_module("torch")
    transformers = importlib.import_module("transformers")
    seed = inputs.recipe.seed
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False

    model = transformers.AutoModelForCausalLM.from_pretrained(
        str(paths.model_snapshot),
        local_files_only=True,
        trust_remote_code=False,
        torch_dtype=torch.bfloat16,
    )
    model.to("cuda")
    model.train()
    model.config.use_cache = False

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=float(inputs.recipe.learning_rate),
        weight_decay=0.0,
    )
    scheduler = torch.optim.lr_scheduler.LambdaLR(
        optimizer,
        lambda step: _learning_rate_factor(
            int(step),
            warmup_steps=inputs.recipe.warmup_steps,
            max_steps=inputs.recipe.max_steps,
        ),
    )

    output_dir = paths.work / "training"
    assert_empty_output_directory(output_dir)
    losses: list[str] = []
    checkpoints: list[dict[str, object]] = []
    started = time.monotonic()
    optimizer.zero_grad(set_to_none=True)
    record_index = 0
    for optimizer_step in range(1, inputs.recipe.max_steps + 1):
        accumulated_loss = 0.0
        for _ in range(inputs.recipe.gradient_accumulation_steps):
            record = records[record_index % len(records)]
            record_index += 1
            input_ids = _integer_list(record.get("input_ids"), field="input_ids")
            attention_mask = _integer_list(
                record.get("attention_mask"),
                field="attention_mask",
            )
            labels = _integer_list(record.get("labels"), field="labels")
            batch = {
                "input_ids": torch.tensor([input_ids], dtype=torch.long, device="cuda"),
                "attention_mask": torch.tensor(
                    [attention_mask],
                    dtype=torch.long,
                    device="cuda",
                ),
                "labels": torch.tensor([labels], dtype=torch.long, device="cuda"),
            }
            outputs = model(**batch)
            loss = outputs.loss
            if loss is None or not bool(torch.isfinite(loss).item()):
                raise E0HRunReleaseError(
                    f"non-finite training loss at optimizer step {optimizer_step}"
                )
            scaled = loss / inputs.recipe.gradient_accumulation_steps
            scaled.backward()
            accumulated_loss += float(loss.detach().cpu().item())
        torch.nn.utils.clip_grad_norm_(
            model.parameters(),
            float(inputs.recipe.max_grad_norm),
        )
        optimizer.step()
        scheduler.step()
        optimizer.zero_grad(set_to_none=True)
        mean_loss = accumulated_loss / inputs.recipe.gradient_accumulation_steps
        if not math.isfinite(mean_loss):
            raise E0HRunReleaseError("non-finite accumulated training loss")
        losses.append(format(mean_loss, ".12g"))

        if optimizer_step % inputs.recipe.checkpoint_interval_steps == 0:
            checkpoint_dir = output_dir / f"checkpoint-{optimizer_step:04d}"
            checkpoints.append(
                _save_checkpoint(
                    torch=torch,
                    model=model,
                    optimizer=optimizer,
                    scheduler=scheduler,
                    directory=checkpoint_dir,
                    step=optimizer_step,
                    seed=seed,
                )
            )

    elapsed_seconds = time.monotonic() - started
    if not checkpoints or checkpoints[-1]["step"] != inputs.recipe.max_steps:
        raise E0HRunReleaseError("final checkpoint was not created")
    receipt = {
        "schema_version": "e0h-training-health/1",
        "optimizer_steps": inputs.recipe.max_steps,
        "micro_steps": inputs.recipe.max_steps
        * inputs.recipe.gradient_accumulation_steps,
        "record_visits": record_index,
        "losses": losses,
        "non_finite_values": 0,
        "checkpoint_creation": True,
        "checkpoints": checkpoints,
        "gpu_memory_peak_bytes": int(torch.cuda.max_memory_allocated()),
        "elapsed_seconds": format(elapsed_seconds, ".6f"),
        "throughput_records_per_second": format(
            record_index / elapsed_seconds,
            ".6f",
        ),
        "protected_metrics_computed": False,
    }
    write_json_no_clobber(output_dir / "training_health.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m csd_foundry.empirical.e0h.harness.train"
    )
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(run_training(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
