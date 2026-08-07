#!/usr/bin/env python3
"""E1 curriculum adapter over the reviewed E0-H native harness.

The E1 training curriculum (v6) is already in the E0-H-compatible text format:
each training record's ``prompt_messages`` join as ``(system, user)`` and the
training sequence is ``(system, user, codeword)`` joined by newlines. This
adapter reuses the reviewed E0-H harness training/inference loop but sources
its training texts and inference prompts from the v6 curriculum and the
compiled sealed prompt inventory rather than the E0-H seed SFT dataset.

Two conditions are trained, in independent fresh processes:
* CONTROL — base model trained on data/e1/v6/control_train.jsonl (8 steps).
* FOUNDRY — base model trained on data/e1/v6/foundry_train.jsonl (8 steps).

BASE is NEVER trained: it is the untouched frozen base model. The five
prediction sets (BASE, CONTROL-checkpoint-4, CONTROL-final,
FOUNDRY-checkpoint-4, FOUNDRY-final) are each produced by a separate
inference invocation that loads exactly ONE model source (the frozen base
revision for BASE, or a saved checkpoint directory otherwise) and runs the
same 8 sealed prompts under the frozen unforgiving ABI.

The harness does NOT compute protected metrics; it produces only checkpoints,
training-health receipts, and raw single-token prediction evidence (the
generated token id and its exact decoded suffix). Parsing belongs exclusively
to the metric-release controller through the authenticated A0b2 strict parser.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import time
from pathlib import Path
from typing import Any

MODEL_ID = "sshleifer/tiny-gpt2"
MODEL_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
MODEL_LOCATOR = f"hf://{MODEL_ID}"
TOKENIZER_LOCATOR = f"hf://{MODEL_ID}#tokenizer-assets"
RELEASE = "e1-windows-native-v1"
CONTEXT_LENGTH = 512
CONDITIONS = ("BASE", "CONTROL", "FOUNDRY")

# The five prediction-set identities. Each maps to exactly one model source:
# BASE -> the frozen base model revision; the other four -> saved checkpoint
# directories (the intermediate checkpoint-4 and the final checkpoint-final).
PREDICTION_SETS = (
    "BASE",
    "CONTROL-checkpoint-4",
    "CONTROL-final",
    "FOUNDRY-checkpoint-4",
    "FOUNDRY-final",
)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _write_json(path: Path, value: object) -> None:
    _write_text(path, _canonical(value) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_canonical_inputs(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("run inputs must be an object")
    if _canonical(value) + "\n" != text:
        raise ValueError("run inputs must use canonical UTF-8 LF JSON bytes")
    if value.get("release") != RELEASE:
        raise ValueError("run input release does not match the E1 native harness")
    return value


def _load_stack() -> tuple[Any, Any, Any, Any]:
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments
    except ImportError as exc:
        raise RuntimeError(
            "E1 requires torch and transformers from the frozen Windows-native environment"
        ) from exc
    return torch, AutoModelForCausalLM, AutoTokenizer, (Trainer, TrainingArguments)


def _tokenizer() -> Any:
    _, _, auto_tokenizer, _ = _load_stack()
    tokenizer = auto_tokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def _curriculum_training_texts(path: Path) -> tuple[list[str], list[str]]:
    """Load v6 curriculum training texts.

    Each v6 record carries ``prompt_messages`` (system, user) and a
    ``codeword``; the E0-H training text is ``"\\n".join((system, user,
    codeword))``. Returns ``(texts, record_ids)`` in file order.
    """

    texts: list[str] = []
    record_ids: list[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"line {line_number}: record must be an object")
            messages = record.get("prompt_messages")
            codeword = record.get("codeword")
            if not isinstance(messages, list) or len(messages) != 2:
                raise ValueError(f"line {line_number}: prompt_messages must be a 2-element list")
            if not isinstance(codeword, str) or not codeword:
                raise ValueError(f"line {line_number}: codeword must be a nonempty string")
            system = str(messages[0].get("content", ""))
            user = str(messages[1].get("content", ""))
            texts.append("\n".join((system, user, codeword)))
            record_ids.append(str(record.get("record_id", f"line-{line_number}")))
    if not texts:
        raise ValueError(f"no training rows selected from {path}")
    return texts, record_ids


def _verified_curriculum_texts(inputs: dict[str, Any], condition: str) -> list[str]:
    """Load and digest-verify the curriculum arm for the given condition."""

    curriculum = inputs.get("curriculum")
    if not isinstance(curriculum, dict):
        raise ValueError("curriculum input must be an object")
    if condition == "BASE":
        raise ValueError("BASE condition is not trained")
    if condition == "CONTROL":
        path_key, digest_key = "control_train_path", "control_train_digest"
    elif condition == "FOUNDRY":
        path_key, digest_key = "foundry_train_path", "foundry_train_digest"
    else:
        raise ValueError(f"unknown training condition: {condition}")
    repo_root = (
        Path(inputs["source_commit_anchor"]) if "source_commit_anchor" in inputs else Path.cwd()
    )
    path = Path(str(curriculum[path_key]))
    if not path.is_absolute():
        path = (repo_root / path).resolve() if (repo_root / path).exists() else path.resolve()
    expected = str(curriculum[digest_key])
    observed = _sha256(path)
    if observed != expected:
        raise RuntimeError(f"curriculum digest mismatch for {condition}: {observed} != {expected}")
    texts, _ids = _curriculum_training_texts(path)
    return texts


def _require_context_fit(tokenizer: Any, texts: list[str], context: int) -> None:
    lengths = [len(tokenizer(text, add_special_tokens=True)["input_ids"]) for text in texts]
    over_context = [length for length in lengths if length > context]
    if over_context:
        raise RuntimeError(
            f"{len(over_context)} training records exceed context length {context}; "
            "truncation is forbidden"
        )


def command_train(args: argparse.Namespace) -> None:
    if args.condition == "BASE":
        raise ValueError("BASE condition is not trained; it is the untouched reference checkpoint")
    torch, auto_model, _, trainer_types = _load_stack()
    trainer_class, training_arguments_class = trainer_types
    inputs = _load_canonical_inputs(args.inputs)
    recipe = inputs["recipe"]
    seed = int(recipe["seed"])
    random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

    tokenizer = _tokenizer()
    texts = _verified_curriculum_texts(inputs, args.condition)
    context = int(recipe["context_length"])
    _require_context_fit(tokenizer, texts, context)
    encoded = tokenizer(texts, truncation=False, max_length=context, padding="max_length")

    class Dataset(torch.utils.data.Dataset):
        def __len__(self) -> int:
            return len(encoded["input_ids"])

        def __getitem__(self, index: int) -> dict[str, Any]:
            ids = torch.tensor(encoded["input_ids"][index], dtype=torch.long)
            mask = torch.tensor(encoded["attention_mask"][index], dtype=torch.long)
            labels = ids.clone()
            labels[mask == 0] = -100
            return {"input_ids": ids, "attention_mask": mask, "labels": labels}

    model = auto_model.from_pretrained(MODEL_ID, revision=MODEL_REVISION, use_safetensors=True)
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
        optim=str(recipe["optimizer"]),
        lr_scheduler_type=str(recipe["scheduler"]),
        save_steps=int(recipe["checkpoint_interval_steps"]),
        save_strategy="steps",
        save_total_limit=2,
        save_safetensors=True,
        logging_steps=1,
        logging_strategy="steps",
        report_to=[],
        fp16=recipe["precision"] == "fp16",
        bf16=recipe["precision"] == "bf16",
        dataloader_num_workers=0,
        full_determinism=bool(recipe.get("deterministic_dataloader", True)),
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
            "schema_version": "e1-windows-native-training-health/1",
            "release": RELEASE,
            "condition": args.condition,
            "elapsed_seconds_ceil": math.ceil(elapsed),
            "global_steps": int(result.global_step),
            "training_loss": float(result.training_loss),
            "cuda_available": bool(torch.cuda.is_available()),
            "gpu_count": int(torch.cuda.device_count()),
            "gpu_name": str(torch.cuda.get_device_name(0)),
            "checkpoint_created": final_dir.is_dir(),
        },
    )


def _is_base_locator(checkpoint: str) -> bool:
    """Return True when ``checkpoint`` names the frozen base model (no dir)."""

    return checkpoint.startswith("hf://") or "@" in checkpoint


def _load_model_source(
    *,
    auto_model: Any,
    auto_tokenizer: Any,
    checkpoint: str,
) -> tuple[Any, Any, str]:
    """Load a single model source and return (model, tokenizer, identity).

    A ``hf://...@<revision>`` (or bare ``hf://...``) locator loads the frozen
    base model directly; any other value is treated as a saved checkpoint
    directory and loaded ``local_files_only=True``. The returned identity is
    the canonical model source string for the prediction record.
    """

    if _is_base_locator(checkpoint):
        # A bare hf://locator pins the frozen revision explicitly.
        model = auto_model.from_pretrained(MODEL_ID, revision=MODEL_REVISION, use_safetensors=True)
        tokenizer = auto_tokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
        identity = f"{MODEL_LOCATOR}@{MODEL_REVISION}"
    else:
        path = Path(checkpoint)
        if not path.is_dir():
            raise RuntimeError(f"checkpoint directory missing: {checkpoint}")
        model = auto_model.from_pretrained(path, local_files_only=True, use_safetensors=True)
        tokenizer = auto_tokenizer.from_pretrained(path, local_files_only=True)
        identity = str(path.as_posix())
    model.eval()
    return model, tokenizer, identity


def _run_inference(
    *,
    prediction_set_name: str,
    checkpoint: str,
    inventory_records: list[dict[str, Any]],
    abi: dict[str, Any],
    torch: Any,
    auto_model: Any,
    auto_tokenizer: Any,
) -> tuple[list[dict[str, object]], str]:
    """Run one prediction set over the 8 sealed prompts.

    Returns ``(predictions, model_identity)`` where each prediction carries
    ONLY the frozen unforgiving ABI evidence: ``generated_token_id`` (the raw
    int from ``output[0][-1].item()``), ``exact_decoded_suffix`` (the raw
    ``tokenizer.decode([token_id])`` with no strip/case-fold/repair),
    ``prompt_sha256``, and ``checkpoint_or_model_identity``. The prediction
    set name and the sealed-record identity fields are joined for the metric
    controller. No semantic class is parsed here: parsing belongs exclusively
    to the metric-release controller through the authenticated A0b2 strict
    parser.
    """

    model, tokenizer, model_identity = _load_model_source(
        auto_model=auto_model, auto_tokenizer=auto_tokenizer, checkpoint=checkpoint
    )
    predictions: list[dict[str, object]] = []
    do_sample = bool(abi.get("do_sample", False))
    num_beams = int(abi.get("num_beams", 1))
    max_new_tokens = int(abi.get("max_new_tokens", 1))
    if max_new_tokens != 1:
        raise RuntimeError(
            f"frozen inference ABI requires max_new_tokens=1, observed {max_new_tokens}"
        )
    for record in inventory_records:
        prompt_bytes = str(record["prompt_bytes"])
        prompt_sha256 = str(record["prompt_sha256"])
        tokens = tokenizer(prompt_bytes, return_tensors="pt")
        with torch.no_grad():
            output = model.generate(
                **tokens,
                do_sample=do_sample,
                num_beams=num_beams,
                max_new_tokens=max_new_tokens,
                pad_token_id=tokenizer.eos_token_id,
            )
        # Raw generated token id from the final position of the output
        # sequence. No stripping, no case-fold, no repair: the decoded suffix
        # is recorded exactly as the tokenizer renders the single token.
        generated_token_id = int(output[0][-1].item())
        exact_decoded_suffix = str(tokenizer.decode([generated_token_id]))
        predictions.append(
            {
                "prediction_set_name": prediction_set_name,
                "evaluation_id": str(record["evaluation_id"]),
                "cohort": str(record["cohort"]),
                "scenario_id": str(record["scenario_id"]),
                "record_id": str(record["record_id"]),
                "family_digest": str(record["family_digest"]),
                "prompt_sha256": prompt_sha256,
                "generated_token_id": generated_token_id,
                "exact_decoded_suffix": exact_decoded_suffix,
                "checkpoint_or_model_identity": model_identity,
            }
        )
    return predictions, model_identity


def command_infer(args: argparse.Namespace) -> None:
    """Run sealed single-token inference for ONE prediction set.

    Exactly one model source (``--checkpoint``) and one prediction set
    (``--prediction-set``) are loaded. The model source is either a saved
    checkpoint directory or, for BASE, the frozen base model locator
    ``hf://sshleifer/tiny-gpt2@<revision>``. The frozen unforgiving ABI
    (do_sample=False, num_beams=1, max_new_tokens=1) is enforced and the raw
    generated token id plus its exact decoded suffix are recorded per sealed
    prompt. No semantic class is parsed here.
    """

    torch, auto_model, auto_tokenizer, _ = _load_stack()
    inputs = _load_canonical_inputs(args.inputs)
    abi = inputs.get("inference_abi")
    if not isinstance(abi, dict):
        raise ValueError("run inputs inference_abi must be an object")
    prediction_set_name = str(args.prediction_set)
    if prediction_set_name not in PREDICTION_SETS:
        raise ValueError(
            f"prediction set must be one of {PREDICTION_SETS}, observed {prediction_set_name!r}"
        )
    checkpoint = str(args.checkpoint)

    inventory_records: list[dict[str, Any]] = []
    for line in args.inventory.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("sealed prompt inventory record must be an object")
        inventory_records.append(record)
    if not inventory_records:
        raise ValueError("sealed prompt inventory is empty")

    predictions, model_identity = _run_inference(
        prediction_set_name=prediction_set_name,
        checkpoint=checkpoint,
        inventory_records=inventory_records,
        abi=abi,
        torch=torch,
        auto_model=auto_model,
        auto_tokenizer=auto_tokenizer,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "e1-windows-native-sealed-prediction-manifest/1",
        "release": RELEASE,
        "prediction_set_name": prediction_set_name,
        "prediction_count": len(predictions),
        "inference_abi": dict(abi),
        "checkpoint_or_model_identity": model_identity,
        "predictions": predictions,
    }
    _write_json(output_dir / "prediction_manifest.json", manifest)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)

    train = subparsers.add_parser("train")
    train.add_argument("--condition", required=True, choices=["CONTROL", "FOUNDRY"])
    train.add_argument("--inputs", type=Path, required=True)
    train.add_argument("--output-dir", type=Path, required=True)
    train.set_defaults(handler=command_train)

    infer = subparsers.add_parser("infer")
    infer.add_argument("--inputs", type=Path, required=True)
    infer.add_argument("--inventory", type=Path, required=True)
    infer.add_argument(
        "--prediction-set",
        required=True,
        choices=list(PREDICTION_SETS),
        help="prediction set identity (one model source per invocation)",
    )
    infer.add_argument(
        "--checkpoint",
        required=True,
        help=(
            "model source: a saved checkpoint directory, or "
            "hf://sshleifer/tiny-gpt2@<revision> for the frozen base model"
        ),
    )
    infer.add_argument("--output-dir", type=Path, required=True)
    infer.set_defaults(handler=command_infer)
    return root


def main() -> None:
    import os

    args = parser().parse_args()
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    args.handler(args)


if __name__ == "__main__":
    main()
