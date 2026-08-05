"""Deterministically tokenize the immutable E0-H training split."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
from typing import Any, cast

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_empty_output_directory,
    read_jsonl,
    sha256_file,
    verify_static_inputs,
    write_json_no_clobber,
    write_jsonl_no_clobber,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def _messages(record: dict[str, object]) -> list[dict[str, str]]:
    raw = record.get("messages")
    if not isinstance(raw, list) or len(raw) < 3:
        raise E0HRunReleaseError("SFT record messages must contain system, user, and assistant")
    messages: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"content", "role"}:
            raise E0HRunReleaseError("SFT message fields do not match schema")
        role = item["role"]
        content = item["content"]
        if not isinstance(role, str) or not isinstance(content, str):
            raise E0HRunReleaseError("SFT message role and content must be strings")
        messages.append({"role": role, "content": content})
    if messages[-1]["role"] != "assistant":
        raise E0HRunReleaseError("SFT record must end with an assistant target")
    return messages


def _token_ids(tokenizer: Any, text: str) -> list[int]:
    encoded = tokenizer(text, add_special_tokens=False, return_attention_mask=False)
    if not isinstance(encoded, dict) or not isinstance(encoded.get("input_ids"), list):
        raise E0HRunReleaseError("tokenizer returned an invalid input_ids payload")
    ids = encoded["input_ids"]
    if any(isinstance(item, bool) or not isinstance(item, int) for item in ids):
        raise E0HRunReleaseError("tokenizer returned non-integer token IDs")
    return cast(list[int], ids)


def tokenize_training_split(paths: RunPaths) -> dict[str, object]:
    """Create a canonical masked-label token artifact for the 168 training records."""

    inputs = verify_static_inputs(paths, require_snapshot=True)
    transformers = importlib.import_module("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(
        str(paths.model_snapshot),
        local_files_only=True,
        trust_remote_code=False,
        use_fast=True,
    )
    if tokenizer.eos_token is None:
        raise E0HRunReleaseError("tokenizer must declare an EOS token")

    source_path = paths.repository_root / inputs.dataset.sft_path
    source = read_jsonl(source_path)
    output_records: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for record in source:
        if record.get("split") != "train":
            continue
        record_id = record.get("id")
        if not isinstance(record_id, str) or not record_id:
            raise E0HRunReleaseError("SFT record id must be a nonempty string")
        if record_id in seen_ids:
            raise E0HRunReleaseError(f"duplicate SFT record id: {record_id}")
        seen_ids.add(record_id)
        messages = _messages(record)
        prompt_messages = messages[:-1]
        prompt_text = tokenizer.apply_chat_template(
            prompt_messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        if not isinstance(prompt_text, str):
            raise E0HRunReleaseError("chat template did not return prompt text")
        full_text = prompt_text + messages[-1]["content"] + tokenizer.eos_token
        prompt_ids = _token_ids(tokenizer, prompt_text)
        input_ids = _token_ids(tokenizer, full_text)
        if input_ids[: len(prompt_ids)] != prompt_ids:
            raise E0HRunReleaseError(f"assistant target is not prompt-prefix stable: {record_id}")
        target_count = len(input_ids) - len(prompt_ids)
        if target_count <= 0:
            raise E0HRunReleaseError(f"assistant target has no tokens: {record_id}")
        if len(input_ids) > inputs.recipe.context_length:
            raise E0HRunReleaseError(
                f"record exceeds context length without truncation: {record_id}"
            )
        labels = [-100] * len(prompt_ids) + input_ids[len(prompt_ids) :]
        output_records.append(
            {
                "schema_version": "e0h-tokenized-example/1",
                "id": record_id,
                "input_ids": input_ids,
                "attention_mask": [1] * len(input_ids),
                "labels": labels,
                "prompt_tokens": len(prompt_ids),
                "target_tokens": target_count,
                "total_tokens": len(input_ids),
            }
        )

    output_records.sort(key=lambda item: cast(str, item["id"]))
    if len(output_records) != 168:
        raise E0HRunReleaseError(
            f"training split count mismatch; expected=168, observed={len(output_records)}"
        )

    output_dir = paths.work / "tokenized"
    assert_empty_output_directory(output_dir)
    data_path = output_dir / "tokenized_train.jsonl"
    write_jsonl_no_clobber(data_path, output_records)
    total_tokens = sum(cast(int, item["total_tokens"]) for item in output_records)
    receipt = {
        "schema_version": "e0h-tokenization-receipt/1",
        "source_digest": inputs.dataset.sft_digest,
        "tokenizer_digest": inputs.tokenizer.content_digest,
        "tokenizer_revision": inputs.tokenizer.revision,
        "record_count": len(output_records),
        "minimum_tokens": min(cast(int, item["total_tokens"]) for item in output_records),
        "maximum_tokens": max(cast(int, item["total_tokens"]) for item in output_records),
        "total_tokens": total_tokens,
        "truncated_records": 0,
        "tokenized_artifact": "tokenized_train.jsonl",
        "tokenized_artifact_digest": sha256_file(data_path),
    }
    write_json_no_clobber(output_dir / "tokenization_receipt.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m csd_foundry.empirical.e0h.harness.tokenize"
    )
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(tokenize_training_split(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
