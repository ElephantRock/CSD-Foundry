#!/usr/bin/env python3
"""Bounded E0-H training-harness entry points.

This module exposes infrastructure-only operations. It intentionally does not
compute protected E1 capability or safety metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import time
from pathlib import Path
from typing import Any

MODEL_ID = "sshleifer/tiny-gpt2"
MODEL_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_canonical(value) + "\n", encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_inputs(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("run inputs must be an object")
    return value


def _load_stack() -> tuple[Any, Any, Any, Any]:
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments
    except ImportError as exc:
        raise RuntimeError(
            "E0-H requires torch and transformers from the frozen container environment"
        ) from exc
    return torch, AutoModelForCausalLM, AutoTokenizer, (Trainer, TrainingArguments)


def _tokenizer() -> Any:
    _, _, auto_tokenizer, _ = _load_stack()
    tokenizer = auto_tokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def _training_texts(dataset_path: Path) -> list[str]:
    rows: list[str] = []
    with dataset_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            record = json.loads(line)
            if record.get("split") != "train":
                continue
            messages = record.get("messages")
            if not isinstance(messages, list):
                raise ValueError(f"line {line_number}: messages must be a list")
            rows.append("\n".join(str(item["content"]) for item in messages))
    if not rows:
        raise ValueError("no training rows selected")
    return rows


def command_tokenize(args: argparse.Namespace) -> None:
    inputs = _load_inputs(args.inputs)
    tokenizer = _tokenizer()
    texts = _training_texts(Path(inputs["dataset"]["sft_path"]))
    lengths = [len(tokenizer(text, add_special_tokens=True)["input_ids"]) for text in texts]
    context = int(inputs["recipe"]["context_length"])
    receipt = {
        "schema_version": "e0h-tokenization-receipt/1",
        "dataset_records": len(texts),
        "token_count": sum(lengths),
        "minimum_sequence_tokens": min(lengths),
        "maximum_sequence_tokens": max(lengths),
        "mean_sequence_tokens_floor": sum(lengths) // len(lengths),
        "over_context_records": sum(length > context for length in lengths),
        "context_length": context,
        "model_revision": MODEL_REVISION,
    }
    _write_json(args.output, receipt)


def command_train(args: argparse.Namespace) -> None:
    torch, auto_model, _, trainer_types = _load_stack()
    trainer_class, training_arguments_class = trainer_types
    inputs = _load_inputs(args.inputs)
    recipe = inputs["recipe"]
    seed = int(recipe["seed"])
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    tokenizer = _tokenizer()
    texts = _training_texts(Path(inputs["dataset"]["sft_path"]))
    context = int(recipe["context_length"])
    encoded = tokenizer(texts, truncation=True, max_length=context, padding="max_length")

    class Dataset(torch.utils.data.Dataset):
        def __len__(self) -> int:
            return len(encoded["input_ids"])

        def __getitem__(self, index: int) -> dict[str, Any]:
            ids = torch.tensor(encoded["input_ids"][index], dtype=torch.long)
            mask = torch.tensor(encoded["attention_mask"][index], dtype=torch.long)
            labels = ids.clone()
            labels[mask == 0] = -100
            return {"input_ids": ids, "attention_mask": mask, "labels": labels}

    model = auto_model.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        use_safetensors=True,
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    training_args = training_arguments_class(
        output_dir=str(output_dir),
        seed=seed,
        data_seed=seed,
        max_steps=int(recipe["max_steps"]),
        per_device_train_batch_size=int(recipe["micro_batch_size"]),
        gradient_accumulation_steps=int(recipe["gradient_accumulation_steps"]),
        learning_rate=float(recipe["learning_rate"]),
        warmup_steps=int(recipe["warmup_steps"]),
        max_grad_norm=float(recipe["max_grad_norm"]),
        save_steps=int(recipe["checkpoint_interval_steps"]),
        save_total_limit=2,
        logging_steps=1,
        report_to=[],
        fp16=recipe["precision"] == "fp16",
        bf16=recipe["precision"] == "bf16",
        dataloader_num_workers=0,
        full_determinism=True,
    )
    started = time.monotonic()
    trainer = trainer_class(model=model, args=training_args, train_dataset=Dataset())
    result = trainer.train()
    final_dir = output_dir / "checkpoint-final"
    trainer.save_model(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))
    elapsed = time.monotonic() - started
    _write_json(
        output_dir / "training_health.json",
        {
            "schema_version": "e0h-training-health/1",
            "elapsed_seconds_ceil": math.ceil(elapsed),
            "global_steps": int(result.global_step),
            "training_loss": float(result.training_loss),
            "cuda_available": bool(torch.cuda.is_available()),
            "checkpoint_created": final_dir.is_dir(),
        },
    )


def command_reload(args: argparse.Namespace) -> None:
    torch, auto_model, auto_tokenizer, _ = _load_stack()
    model = auto_model.from_pretrained(args.checkpoint, local_files_only=True)
    tokenizer = auto_tokenizer.from_pretrained(args.checkpoint, local_files_only=True)
    parameter_count = sum(parameter.numel() for parameter in model.parameters())
    _write_json(
        Path(args.checkpoint) / "reload_receipt.json",
        {
            "schema_version": "e0h-reload-receipt/1",
            "parameter_count": parameter_count,
            "vocabulary_size": len(tokenizer),
            "device": "cuda" if torch.cuda.is_available() else "cpu",
        },
    )


def command_infer(args: argparse.Namespace) -> None:
    torch, auto_model, auto_tokenizer, _ = _load_stack()
    tokenizer = auto_tokenizer.from_pretrained(args.checkpoint, local_files_only=True)
    model = auto_model.from_pretrained(args.checkpoint, local_files_only=True)
    model.eval()
    rows: list[str] = []
    with args.fixture.open("r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            tokens = tokenizer(item["prompt"], return_tensors="pt")
            with torch.no_grad():
                output = model.generate(
                    **tokens,
                    do_sample=False,
                    max_new_tokens=8,
                    pad_token_id=tokenizer.eos_token_id,
                )
            generated = tokenizer.decode(
                output[0][tokens["input_ids"].shape[1] :], skip_special_tokens=True
            )
            rows.append(
                _canonical(
                    {
                        "id": item["id"],
                        "generated_text": generated.strip(),
                    }
                )
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")


def command_smoke(args: argparse.Namespace) -> None:
    expected = {}
    with args.fixture.open("r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            expected[item["id"]] = item["expected_exact"]
    observed = {}
    with args.inference.open("r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            observed[item["id"]] = item["generated_text"]
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    _write_json(
        args.output,
        {
            "schema_version": "e0h-smoke-receipt/1",
            "fixture_sha256": _sha256(args.fixture),
            "inference_sha256": _sha256(args.inference),
            "record_count": len(observed),
            "missing_ids": missing,
            "extra_ids": extra,
            "execution_complete": not missing and not extra,
            "exact_text_matches": sum(
                observed.get(key) == value for key, value in expected.items()
            ),
            "claim_boundary": (
                "Infrastructure smoke execution only; no protected capability conclusion."
            ),
        },
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)

    tokenize = subparsers.add_parser("tokenize")
    tokenize.add_argument("--inputs", type=Path, required=True)
    tokenize.add_argument("--output", type=Path, required=True)
    tokenize.set_defaults(handler=command_tokenize)

    train = subparsers.add_parser("train")
    train.add_argument("--inputs", type=Path, required=True)
    train.add_argument("--output-dir", type=Path, required=True)
    train.set_defaults(handler=command_train)

    reload_parser = subparsers.add_parser("reload")
    reload_parser.add_argument("--checkpoint", type=Path, required=True)
    reload_parser.set_defaults(handler=command_reload)

    infer = subparsers.add_parser("infer")
    infer.add_argument("--checkpoint", type=Path, required=True)
    infer.add_argument("--fixture", type=Path, required=True)
    infer.add_argument("--output", type=Path, required=True)
    infer.set_defaults(handler=command_infer)

    smoke = subparsers.add_parser("smoke")
    smoke.add_argument("--fixture", type=Path, required=True)
    smoke.add_argument("--inference", type=Path, required=True)
    smoke.add_argument("--output", type=Path, required=True)
    smoke.set_defaults(handler=command_smoke)
    return root


def main() -> None:
    args = parser().parse_args()
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    args.handler(args)


if __name__ == "__main__":
    main()
