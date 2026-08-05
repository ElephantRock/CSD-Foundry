#!/usr/bin/env python3
"""Verify the frozen E0-H assets, environment, tokenization, and CPU forward path."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
from pathlib import Path
from typing import Any

MODEL_ID = "sshleifer/tiny-gpt2"
MODEL_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
MODEL_FILES = ("config.json", "model.safetensors")
TOKENIZER_FILES = (
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer_config.json",
    "vocab.json",
)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_digest(value: object) -> str:
    return hashlib.sha256((_canonical(value) + "\n").encode("utf-8")).hexdigest()


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
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("run inputs must be an object")
    if _canonical(value) + "\n" != text:
        raise ValueError("run inputs must use canonical UTF-8 LF JSON bytes")
    return value


def _load_stack() -> tuple[Any, Any, Any]:
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "E0-H preparation requires torch and transformers from the frozen environment"
        ) from exc
    return torch, AutoModelForCausalLM, AutoTokenizer


def _dataset_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"line {line_number}: record must be an object")
            rows.append(item)
    return rows


def _training_records(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    selected: list[dict[str, Any]] = []
    texts: list[str] = []
    for line_number, item in enumerate(_dataset_rows(path), 1):
        if item.get("split") != "train":
            continue
        messages = item.get("messages")
        if not isinstance(messages, list):
            raise ValueError(f"line {line_number}: messages must be a list")
        selected.append(item)
        texts.append("\n".join(str(message["content"]) for message in messages))
    if not selected:
        raise ValueError("no training records selected")
    return selected, texts


def _asset_receipt(path: Path, name: str) -> dict[str, object]:
    return {"path": name, "sha256": _sha256(path), "byte_count": path.stat().st_size}


def verify_assets(inputs: dict[str, Any], cache_dir: Path) -> dict[str, object]:
    try:
        from huggingface_hub import HfApi, snapshot_download
    except ImportError as exc:
        raise RuntimeError("asset verification requires huggingface_hub") from exc

    info = HfApi().model_info(MODEL_ID, revision=MODEL_REVISION, files_metadata=True)
    if info.sha != MODEL_REVISION:
        raise RuntimeError(f"resolved revision mismatch: {info.sha}")
    snapshot = Path(
        snapshot_download(
            MODEL_ID,
            revision=MODEL_REVISION,
            allow_patterns=[*MODEL_FILES, *TOKENIZER_FILES],
            cache_dir=cache_dir,
        )
    )
    model_assets = [_asset_receipt(snapshot / name, name) for name in MODEL_FILES]
    tokenizer_assets = [_asset_receipt(snapshot / name, name) for name in TOKENIZER_FILES]
    model_weight_digest = next(
        str(item["sha256"]) for item in model_assets if item["path"] == "model.safetensors"
    )
    tokenizer_digest = _canonical_digest(tokenizer_assets)
    expected_model = str(inputs["model"]["content_digest"])
    expected_tokenizer = str(inputs["tokenizer"]["content_digest"])
    if model_weight_digest != expected_model:
        raise RuntimeError(
            f"model content digest mismatch: {model_weight_digest} != {expected_model}"
        )
    if tokenizer_digest != expected_tokenizer:
        raise RuntimeError(
            f"tokenizer content digest mismatch: {tokenizer_digest} != {expected_tokenizer}"
        )
    return {
        "schema_version": "e0h-external-asset-receipt/1",
        "repository": MODEL_ID,
        "requested_revision": MODEL_REVISION,
        "resolved_revision": info.sha,
        "model_assets": model_assets,
        "model_weight_digest": model_weight_digest,
        "tokenizer_assets": tokenizer_assets,
        "tokenizer_aggregate_digest": tokenizer_digest,
        "container_image": inputs["environment"]["container_image"],
        "container_platform": "linux/amd64",
    }


def verify_environment(inputs: dict[str, Any]) -> dict[str, object]:
    torch, _, _ = _load_stack()
    expected = inputs["environment"]
    observed = {
        "python_version": platform.python_version(),
        "cuda_version": os.environ.get("CUDA_VERSION") or str(torch.version.cuda),
        "torch_version": str(torch.__version__).split("+")[0],
        "transformers_version": importlib.metadata.version("transformers"),
        "accelerate_version": importlib.metadata.version("accelerate"),
        "safetensors_version": importlib.metadata.version("safetensors"),
        "tokenizers_version": importlib.metadata.version("tokenizers"),
        "huggingface_hub_version": importlib.metadata.version("huggingface-hub"),
        "machine": platform.machine(),
        "cuda_available": bool(torch.cuda.is_available()),
    }
    for field in (
        "python_version",
        "cuda_version",
        "torch_version",
        "transformers_version",
        "accelerate_version",
    ):
        if observed[field] != expected[field]:
            raise RuntimeError(
                f"environment mismatch for {field}: {observed[field]} != {expected[field]}"
            )
    if observed["machine"] not in {"AMD64", "x86_64"}:
        raise RuntimeError(f"unsupported machine architecture: {observed['machine']}")
    return {
        "schema_version": "e0h-environment-receipt/1",
        "container_image": expected["container_image"],
        "expected": expected,
        "observed": observed,
    }


def tokenize(inputs: dict[str, Any]) -> dict[str, object]:
    _, _, auto_tokenizer = _load_stack()
    tokenizer = auto_tokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    dataset_path = Path(inputs["dataset"]["sft_path"])
    all_records = _dataset_rows(dataset_path)
    selected, texts = _training_records(dataset_path)
    lengths = [len(tokenizer(text, add_special_tokens=True)["input_ids"]) for text in texts]
    context = int(inputs["recipe"]["context_length"])
    inventory = [
        {
            "id": str(record["id"]),
            "sequence_tokens": length,
            "truncated": length > context,
        }
        for record, length in zip(selected, lengths, strict=True)
    ]
    return {
        "schema_version": "e0h-tokenization-receipt/1",
        "sft_records_loaded": len(all_records),
        "training_records_selected": len(texts),
        "token_count": sum(lengths),
        "minimum_sequence_tokens": min(lengths),
        "maximum_sequence_tokens": max(lengths),
        "mean_sequence_tokens_floor": sum(lengths) // len(lengths),
        "over_context_records": sum(length > context for length in lengths),
        "truncation_count": sum(length > context for length in lengths),
        "context_length": context,
        "model_revision": MODEL_REVISION,
        "inventory_digest": _canonical_digest(inventory),
    }


def preflight(inputs: dict[str, Any]) -> dict[str, object]:
    torch, auto_model, auto_tokenizer = _load_stack()
    dataset_path = Path(inputs["dataset"]["sft_path"])
    if _sha256(dataset_path) != inputs["dataset"]["sft_digest"]:
        raise RuntimeError("SFT dataset digest mismatch")
    selected, texts = _training_records(dataset_path)
    tokenizer = auto_tokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    context = int(inputs["recipe"]["context_length"])
    encoded = tokenizer(
        texts[0],
        add_special_tokens=True,
        truncation=True,
        max_length=context,
        return_tensors="pt",
    )
    model = auto_model.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        use_safetensors=True,
    )
    model.eval()
    labels = encoded["input_ids"].clone()
    with torch.no_grad():
        output = model(**encoded, labels=labels)
    loss = float(output.loss)
    if not math.isfinite(loss):
        raise RuntimeError("preflight forward loss is non-finite")
    return {
        "schema_version": "e0h-minimal-device-preflight/1",
        "device": "cpu",
        "selected_training_records": len(selected),
        "first_record_id": str(selected[0]["id"]),
        "input_shape": list(encoded["input_ids"].shape),
        "attention_mask_shape": list(encoded["attention_mask"].shape),
        "parameter_count": sum(parameter.numel() for parameter in model.parameters()),
        "vocabulary_size": len(tokenizer),
        "forward_loss": loss,
        "forward_pass_complete": True,
        "model_revision": MODEL_REVISION,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    inputs = _load_inputs(args.inputs)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(
        args.output_dir / "external_asset_receipt.json",
        verify_assets(inputs, args.cache_dir),
    )
    _write_json(args.output_dir / "environment_receipt.json", verify_environment(inputs))
    _write_json(args.output_dir / "tokenization_receipt.json", tokenize(inputs))
    _write_json(args.output_dir / "minimal_device_preflight.json", preflight(inputs))


if __name__ == "__main__":
    main()
