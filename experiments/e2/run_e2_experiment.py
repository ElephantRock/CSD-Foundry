#!/usr/bin/env python3
"""E2 Foundry-vs-control experiment runner.

Three arms, each in an independent fresh process:

* BASE     - untouched gpt2@607a30d, greedy one-token inference on 30 cases.
* CONTROL  - gpt2 trained on data/e1/v6/control_train.jsonl (19 records, 128
             steps, response-token-only loss), then greedy one-token inference.
* FOUNDRY  - gpt2 trained on data/e1/v6/foundry_train.jsonl (19 records, 128
             steps, response-token-only loss), then greedy one-token inference.

After all three arms produce sealed raw predictions, the metric-release phase
parses every prediction with the strict A-E parser (exact codeword match, no
strip/repair), scores the primary family-macro accuracy over the 20 primary
families and the 5 frozen safety counts over the 10 clean cases, applies the
classification truth table, and prints the full results.

Run with::

    python experiments/e2/run_e2_experiment.py
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from csd_foundry.synthesis.v0_4.serialization import canonical_json_text

# ---------------------------------------------------------------------------
# Frozen identities.
# ---------------------------------------------------------------------------

MODEL_ID = "gpt2"
MODEL_REVISION = "607a30d783dfa663caf39e06633721c8d4cfcd7e"
CONTEXT_LENGTH = 512
SEED = 1729
STEPS = 128
LEARNING_RATE = 5e-5
MICRO_BATCH = 1
GRAD_ACCUM = 4
WARMUP_STEPS = 1
MAX_GRAD_NORM = 1.0
OPTIMIZER = "adamw_torch"
SCHEDULER = "linear"
FP16 = True
FULL_DETERMINISM = True
GPU_MINUTE_CEILING = 15

CONTROL_TRAIN = "data/e1/v6/control_train.jsonl"
FOUNDRY_TRAIN = "data/e1/v6/foundry_train.jsonl"
PRIMARY_EVAL = "experiments/e2/protected_primary.jsonl"
CLEAN_EVAL = "experiments/e2/protected_clean.jsonl"
MANIFEST = "experiments/e2/protected_manifest.json"

CODEBOOK = {
    "NEITHER": "A",
    "REMOVES_ONLY": "B",
    "SURVIVES_ONLY": "C",
    "BOTH": "D",
    "NOT_APPLICABLE": "E",
}
CODEWORD_TO_CLASS = {v: k for k, v in CODEBOOK.items()}
TOKEN_ID_BY_CODEWORD = {"A": 32, "B": 33, "C": 34, "D": 35, "E": 36}

ARMS = ("BASE", "CONTROL", "FOUNDRY")


# ---------------------------------------------------------------------------
# IO helpers.
# ---------------------------------------------------------------------------


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _load_canonical_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _e1_record_count(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


# ---------------------------------------------------------------------------
# Phase 1: preflight.
# ---------------------------------------------------------------------------


def _preflight(repo_root: Path) -> dict[str, Any]:
    """Load all inputs and verify the frozen invariants before any GPU work."""

    print("[phase 1] preflight", flush=True)

    control_path = repo_root / CONTROL_TRAIN
    foundry_path = repo_root / FOUNDRY_TRAIN
    primary_path = repo_root / PRIMARY_EVAL
    clean_path = repo_root / CLEAN_EVAL
    manifest_path = repo_root / MANIFEST

    for path in (control_path, foundry_path, primary_path, clean_path, manifest_path):
        if not path.is_file():
            raise FileNotFoundError(f"preflight: missing required file {path}")

    control_rows = _load_jsonl(control_path)
    foundry_rows = _load_jsonl(foundry_path)
    primary_records = _load_jsonl(primary_path)
    clean_records = _load_jsonl(clean_path)
    manifest = _load_canonical_json(manifest_path)

    # Training arms must each carry 19 records.
    if len(control_rows) != 19:
        raise ValueError(f"control train has {len(control_rows)} records, expected 19")
    if len(foundry_rows) != 19:
        raise ValueError(f"foundry train has {len(foundry_rows)} records, expected 19")

    # Evaluation record counts.
    if len(primary_records) != 20:
        raise ValueError(f"primary eval has {len(primary_records)} records, expected 20")
    if len(clean_records) != 10:
        raise ValueError(f"clean eval has {len(clean_records)} records, expected 10")

    # Prompt identity across arms: each control/foundry pair must share prompt_bytes.
    for c, f in zip(control_rows, foundry_rows, strict=True):
        if c.get("prompt_bytes") != f.get("prompt_bytes"):
            raise ValueError(
                f"prompt identity violated at control/{c.get('record_id')} vs "
                f"foundry/{f.get('record_id')}"
            )

    # All targets are exactly one token.
    all_eval = primary_records + clean_records
    for record in all_eval:
        if record.get("codeword_token_id") not in (32, 33, 34, 35, 36):
            raise ValueError(f"{record['record_id']}: codeword token id out of range")
        if record.get("codeword") not in CODEWORD_TO_CLASS:
            raise ValueError(f"{record['record_id']}: codeword not in A-E")

    # Retokenize under gpt2@607a30d and verify identity + zero truncation.
    transformers = importlib.import_module("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    for record in all_eval:
        prompt_ids = tokenizer(record["prompt_bytes"], add_special_tokens=True)["input_ids"]
        if len(prompt_ids) > CONTEXT_LENGTH:
            raise ValueError(f"{record['record_id']}: prompt truncates at context {CONTEXT_LENGTH}")
        cw_ids = tokenizer.encode(record["codeword"], add_special_tokens=False)
        if len(cw_ids) != 1 or cw_ids[0] != record["codeword_token_id"]:
            raise ValueError(f"{record['record_id']}: codeword not single-token under gpt2")

    # Disjointness: E2 task_input_digests must not appear in any E1 train row.
    e1_digests: set[str] = set()
    for row in control_rows + foundry_rows:
        if "task_input_digest" in row:
            e1_digests.add(str(row["task_input_digest"]))
    for record in all_eval:
        if record["task_input_digest"] in e1_digests:
            raise ValueError(f"{record['record_id']}: E2 record collides with E1 training prompt")

    print(
        "[phase 1] ok: 19/19 train arms, 30 eval records, "
        "prompts identical across arms, zero truncation",
        flush=True,
    )
    return {
        "control_rows": control_rows,
        "foundry_rows": foundry_rows,
        "primary_records": primary_records,
        "clean_records": clean_records,
        "manifest": manifest,
    }


# ---------------------------------------------------------------------------
# Training + inference subprocess.
# ---------------------------------------------------------------------------


_TRAIN_SCRIPT = """\
import hashlib
import importlib
import json
import math
import random
import sys
from pathlib import Path


def main(arm, train_path, cases_path, out_path, model_id, revision):
    transformers = importlib.import_module("transformers")
    torch = importlib.import_module("torch")
    AutoModelForCausalLM = transformers.AutoModelForCausalLM
    AutoTokenizer = transformers.AutoTokenizer
    Trainer = transformers.Trainer
    TrainingArguments = transformers.TrainingArguments

    SEED = 1729
    STEPS = 128
    LR = 5e-5
    MICRO = 1
    ACCUM = 4
    WARMUP = 1
    MAX_GRAD = 1.0
    CONTEXT = 512

    random.seed(SEED)
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)

    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision)
    tokenizer.pad_token = tokenizer.eos_token

    # Load training rows and build response-only sequences (skipped for BASE).
    train_rows = []
    if train_path:
        with open(train_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                train_rows.append(json.loads(line))

    sequences = []  # list of (input_ids, prompt_len)
    for row in train_rows:
        system_content = row["prompt_messages"][0]["content"]
        user_content = row["prompt_messages"][1]["content"]
        codeword = row["codeword"]
        # Training text mirrors E1 v6: system + user + codeword joined by newlines.
        prompt_text = system_content + "\\n" + user_content + "\\n"
        prompt_ids = tokenizer(prompt_text, add_special_tokens=True)["input_ids"]
        cw_ids = tokenizer.encode(codeword, add_special_tokens=False)
        if len(cw_ids) != 1:
            raise RuntimeError(f"codeword {codeword!r} is not single-token: {cw_ids}")
        full_ids = prompt_ids + cw_ids
        if len(full_ids) > CONTEXT:
            raise RuntimeError(f"training row truncates: {len(full_ids)} > {CONTEXT}")
        sequences.append((full_ids, len(prompt_ids)))

    # Load inference cases.
    cases = []
    with open(cases_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            cases.append(json.loads(line))

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # --- BASE arm: no training. ---
    model = AutoModelForCausalLM.from_pretrained(model_id, revision=revision, use_safetensors=True)
    model.to(device)
    model.eval()

    if arm != "BASE":
        # Build response-only dataset: mask ALL tokens except the final codeword token to -100.
        class Dataset(torch.utils.data.Dataset):
            def __len__(self):
                return len(sequences)

            def __getitem__(self, idx):
                full_ids, prompt_len = sequences[idx]
                ids = torch.tensor(full_ids, dtype=torch.long)
                labels = ids.clone()
                # Mask every position except the final (codeword) token.
                labels[:-1] = -100
                attention = torch.ones(len(ids), dtype=torch.long)
                return {"input_ids": ids, "attention_mask": attention, "labels": labels}

        # Reload the untouched base for this arm's training.
        del model
        torch.cuda.empty_cache()
        model = AutoModelForCausalLM.from_pretrained(
            model_id, revision=revision, use_safetensors=True
        )
        model.to(device)

        output_dir = Path(out_path).parent / f"checkpoint-{arm.lower()}"
        output_dir.mkdir(parents=True, exist_ok=True)
        args = TrainingArguments(
            output_dir=str(output_dir),
            seed=SEED,
            data_seed=SEED,
            max_steps=STEPS,
            per_device_train_batch_size=MICRO,
            gradient_accumulation_steps=ACCUM,
            learning_rate=LR,
            warmup_steps=WARMUP,
            max_grad_norm=MAX_GRAD,
            optim="adamw_torch",
            lr_scheduler_type="linear",
            save_strategy="no",
            save_safetensors=True,
            logging_steps=16,
            logging_strategy="steps",
            report_to=[],
            fp16=True,
            dataloader_num_workers=0,
            full_determinism=True,
        )
        trainer = Trainer(model=model, args=args, train_dataset=Dataset())
        trainer.train()
        model.eval()

    # --- Inference: greedy one-token on every case. ---
    predictions = []
    for case in cases:
        prompt_text = case["prompt_bytes"]
        inputs = tokenizer(prompt_text, return_tensors="pt", add_special_tokens=True)
        input_ids = inputs["input_ids"].to(device)
        attention_mask = inputs["attention_mask"].to(device)
        with torch.no_grad():
            outputs = model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                do_sample=False,
                num_beams=1,
                max_new_tokens=1,
                pad_token_id=tokenizer.eos_token_id,
            )
        new_id = int(outputs[0][-1].item())
        decoded_suffix = tokenizer.decode([new_id])
        predictions.append({
            "record_id": case["record_id"],
            "family_id": case["family_id"],
            "case_id": case["case_id"],
            "generated_token_id": new_id,
            "decoded_suffix": decoded_suffix,
        })

    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump({"arm": arm, "predictions": predictions}, handle)
    print(f"[{arm}] wrote {len(predictions)} predictions to {out_path}", flush=True)


if __name__ == "__main__":
    arm = sys.argv[1]
    train_path = sys.argv[2]
    cases_path = sys.argv[3]
    out_path = sys.argv[4]
    model_id = sys.argv[5]
    revision = sys.argv[6]
    main(arm, train_path, cases_path, out_path, model_id, revision)
"""


def _run_arm(
    arm: str, repo_root: Path, cases_records: list[dict[str, Any]], work_dir: Path
) -> Path:
    """Run one arm (BASE/CONTROL/FOUNDRY) in an independent fresh process."""

    train_path = (
        ""
        if arm == "BASE"
        else str(repo_root / (CONTROL_TRAIN if arm == "CONTROL" else FOUNDRY_TRAIN))
    )
    cases_path = work_dir / f"cases-{arm.lower()}.jsonl"
    with cases_path.open("w", encoding="utf-8") as handle:
        for record in cases_records:
            handle.write(json.dumps(record))
            handle.write("\n")

    script_path = work_dir / "_arm_worker.py"
    script_path.write_text(_TRAIN_SCRIPT, encoding="utf-8")

    out_path = work_dir / f"predictions-{arm.lower()}.json"
    cmd = [
        sys.executable,
        str(script_path),
        arm,
        train_path,
        str(cases_path),
        str(out_path),
        MODEL_ID,
        MODEL_REVISION,
    ]
    print(
        f"[phase {'2' if arm == 'BASE' else '3' if arm == 'CONTROL' else '4'}] "
        f"running arm {arm} in a fresh process",
        flush=True,
    )
    started = time.monotonic()
    completed = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True)
    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(f"arm {arm} failed with exit code {completed.returncode}")
    if not out_path.is_file():
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(f"arm {arm} produced no predictions file")
    print(f"[arm {arm}] elapsed {elapsed:.1f}s", flush=True)
    if completed.stderr.strip():
        # Surface warnings (non-fatal) but keep going.
        for line in completed.stderr.strip().splitlines()[-5:]:
            print(f"  [{arm} stderr] {line}", flush=True)
    return out_path


# ---------------------------------------------------------------------------
# Phase 5: metric release.
# ---------------------------------------------------------------------------


def _strict_parse(decoded_suffix: str) -> str | None:
    """Strict A-E parser: accepts ONLY the exact codeword, no strip/repair."""

    return CODEWORD_TO_CLASS.get(decoded_suffix)


def _score_primary(
    primary_records: list[dict[str, Any]], predictions_by_record: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Family-macro accuracy over the 20 primary families (one record per family)."""

    # Group by gold_class for the confusion matrix; family-macro here is per-family
    # (each family == one record), so family accuracy == exact correctness per record.
    family_results: list[dict[str, Any]] = []
    correct = 0
    for record in primary_records:
        rid = record["record_id"]
        gold = record["gold_class"]
        pred = predictions_by_record.get(rid, {})
        decoded = pred.get("decoded_suffix", "")
        parsed = _strict_parse(decoded)
        is_correct = parsed == gold
        if is_correct:
            correct += 1
        family_results.append(
            {
                "record_id": rid,
                "family_id": record["family_id"],
                "gold_class": gold,
                "decoded_suffix": decoded,
                "parsed_class": parsed,
                "is_correct": is_correct,
            }
        )
    total = len(primary_records)
    # Family-macro accuracy: each family is a single record, so macro == micro == correct/total.
    return {
        "metric_identity": "e2-primary-family-macro-accuracy/1",
        "family_count": total,
        "correct_count": correct,
        "family_macro_accuracy": correct / total,
        "per_family": family_results,
    }


def _score_safety(
    clean_records: list[dict[str, Any]], predictions_by_record: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Five frozen counts over the 10 clean cases."""

    clean_exact_error_count = 0
    spurious_basis_removal_count = 0
    valid_basis_rejection_count = 0
    clean_not_applicable_count = 0
    clean_malformed_count = 0
    per_case: list[dict[str, Any]] = []

    removal_classes = {"REMOVES_ONLY", "BOTH"}
    survival_classes = {"SURVIVES_ONLY", "BOTH"}
    basis_classes = {"NEITHER", "REMOVES_ONLY", "SURVIVES_ONLY", "BOTH"}

    for record in clean_records:
        rid = record["record_id"]
        gold = record["gold_class"]
        pred = predictions_by_record.get(rid, {})
        decoded = pred.get("decoded_suffix", "")
        parsed = _strict_parse(decoded)

        exact_error = parsed != gold
        if exact_error:
            clean_exact_error_count += 1
        if parsed is None:
            clean_malformed_count += 1
        elif parsed == "NOT_APPLICABLE":
            clean_not_applicable_count += 1
        elif parsed in basis_classes and gold in basis_classes:
            if gold not in removal_classes and parsed in removal_classes:
                spurious_basis_removal_count += 1
            if gold in survival_classes and parsed not in survival_classes:
                valid_basis_rejection_count += 1
        per_case.append(
            {
                "record_id": rid,
                "gold_class": gold,
                "decoded_suffix": decoded,
                "parsed_class": parsed,
                "exact_error": exact_error,
            }
        )

    return {
        "metric_identity": "e2-clean-case-regression/1",
        "clean_case_count": len(clean_records),
        "clean_exact_error_count": clean_exact_error_count,
        "spurious_basis_removal_count": spurious_basis_removal_count,
        "valid_basis_rejection_count": valid_basis_rejection_count,
        "clean_not_applicable_count": clean_not_applicable_count,
        "clean_malformed_count": clean_malformed_count,
        "per_case": per_case,
    }


def _confusion_matrix(
    primary_records: list[dict[str, Any]],
    predictions_by_record: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    classes = ["NEITHER", "REMOVES_ONLY", "SURVIVES_ONLY", "BOTH", "NOT_APPLICABLE", "MALFORMED"]
    matrix = {g: {p: 0 for p in classes} for g in classes}
    for record in primary_records:
        gold = record["gold_class"]
        decoded = predictions_by_record.get(record["record_id"], {}).get("decoded_suffix", "")
        parsed = _strict_parse(decoded)
        pred = parsed if parsed is not None else "MALFORMED"
        matrix[gold][pred] += 1
    return {"classes": classes, "matrix": matrix}


def _classify(
    primary: dict[str, Any], safety: dict[str, Any], arms: Mapping[str, dict[str, Any]]
) -> str:
    """Apply the frozen classification truth table."""

    # Execution/measurement failure anywhere -> TECHNICALLY_INVALID.
    for arm in ARMS:
        if arms[arm].get("status") != "ok":
            return "TECHNICALLY_INVALID"

    safety_passes = safety["clean_exact_error_count"] == 0
    p_foundry = arms["FOUNDRY"]["primary"]["family_macro_accuracy"]
    p_control = arms["CONTROL"]["primary"]["family_macro_accuracy"]
    p_base = arms["BASE"]["primary"]["family_macro_accuracy"]

    if not safety_passes or p_foundry < p_control:
        return "HARMFUL"
    if safety_passes and p_foundry > p_control and p_foundry > p_base:
        return "PROMISING"
    return "NO_OBSERVED_SIGNAL"


def _metric_release(
    primary_records: list[dict[str, Any]],
    clean_records: list[dict[str, Any]],
    prediction_files: Mapping[str, Path],
) -> dict[str, Any]:
    """Parse all predictions, score both metrics, classify, return full results."""

    print("[phase 5] metric release", flush=True)
    arm_results: dict[str, dict[str, Any]] = {}
    for arm in ARMS:
        payload = json.loads(prediction_files[arm].read_text(encoding="utf-8"))
        preds = {p["record_id"]: p for p in payload["predictions"]}
        primary = _score_primary(primary_records, preds)
        safety = _score_safety(clean_records, preds)
        confusion = _confusion_matrix(primary_records, preds)
        arm_results[arm] = {
            "status": "ok",
            "primary": primary,
            "safety": safety,
            "confusion_matrix": confusion,
        }

    classification = _classify(
        arm_results["FOUNDRY"]["primary"],
        arm_results["FOUNDRY"]["safety"],
        arm_results,
    )
    return {"arms": arm_results, "classification": classification}


# ---------------------------------------------------------------------------
# Phase 6: report.
# ---------------------------------------------------------------------------


def _print_report(results: dict[str, Any]) -> None:
    print("", flush=True)
    print("=" * 72, flush=True)
    print("E2 FOUNDRY-VS-CONTROL EXPERIMENT RESULTS", flush=True)
    print("=" * 72, flush=True)
    for arm in ARMS:
        arm_data = results["arms"][arm]
        primary = arm_data["primary"]
        safety = arm_data["safety"]
        print(f"\n--- {arm} ---", flush=True)
        acc = primary["family_macro_accuracy"]
        print(
            f"  primary family-macro accuracy: "
            f"{primary['correct_count']}/{primary['family_count']} = {acc:.4f}",
            flush=True,
        )
        print(
            f"  safety: exact_errors={safety['clean_exact_error_count']} "
            f"spurious_removals={safety['spurious_basis_removal_count']} "
            f"valid_rejections={safety['valid_basis_rejection_count']} "
            f"not_applicable={safety['clean_not_applicable_count']} "
            f"malformed={safety['clean_malformed_count']}",
            flush=True,
        )
        # Confusion matrix for primary set.
        cm = arm_data["confusion_matrix"]
        gold_classes = [c for c in cm["classes"] if c != "MALFORMED"]
        print("  confusion matrix (rows=gold, cols=pred):", flush=True)
        header = "    " + " ".join(f"{c[:4]:>5}" for c in cm["classes"])
        print(header, flush=True)
        for gold in gold_classes:
            row = " ".join(f"{cm['matrix'][gold][p]:>5}" for p in cm["classes"])
            print(f"  {gold[:4]:>2} {row}", flush=True)

    print("", flush=True)
    print(f"TERMINAL CLASSIFICATION: {results['classification']}", flush=True)
    print("=" * 72, flush=True)


# ---------------------------------------------------------------------------
# Contract.
# ---------------------------------------------------------------------------


def _build_contract(repo_root: Path, preflight_data: dict[str, Any]) -> dict[str, Any]:
    """Build the frozen experiment contract binding every input identity."""

    manifest = preflight_data["manifest"]
    control_path = repo_root / CONTROL_TRAIN
    foundry_path = repo_root / FOUNDRY_TRAIN
    contract = {
        "schema_version": "e2-experiment-contract/1",
        "release": "e2-foundry-vs-control/1",
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "context_length": CONTEXT_LENGTH,
        "training_recipe": {
            "seed": SEED,
            "steps": STEPS,
            "learning_rate": LEARNING_RATE,
            "micro_batch_size": MICRO_BATCH,
            "gradient_accumulation_steps": GRAD_ACCUM,
            "effective_batch_size": MICRO_BATCH * GRAD_ACCUM,
            "warmup_steps": WARMUP_STEPS,
            "max_grad_norm": MAX_GRAD_NORM,
            "optimizer": OPTIMIZER,
            "scheduler": SCHEDULER,
            "fp16": FP16,
            "full_determinism": FULL_DETERMINISM,
            "loss": "response-token-only (all prompt tokens masked to -100)",
        },
        "inference": {
            "do_sample": False,
            "num_beams": 1,
            "max_new_tokens": 1,
        },
        "control_train_path": CONTROL_TRAIN,
        "control_train_sha256": _sha256_file(control_path),
        "control_train_record_count": _e1_record_count(control_path),
        "foundry_train_path": FOUNDRY_TRAIN,
        "foundry_train_sha256": _sha256_file(foundry_path),
        "foundry_train_record_count": _e1_record_count(foundry_path),
        "primary_evaluation_path": PRIMARY_EVAL,
        "primary_evaluation_sha256": manifest["primary_artifact_sha256"],
        "primary_record_count": manifest["primary_record_count"],
        "clean_evaluation_path": CLEAN_EVAL,
        "clean_evaluation_sha256": manifest["clean_artifact_sha256"],
        "clean_record_count": manifest["clean_record_count"],
        "protected_manifest_path": MANIFEST,
        "codebook": CODEBOOK,
        "token_id_codebook": TOKEN_ID_BY_CODEWORD,
        "malformed_definition": (
            "Output is malformed if decoded suffix is not exactly A/B/C/D/E (no strip, no repair)."
        ),
        "primary_metric": {
            "identity": "e2-primary-family-macro-accuracy/1",
            "aggregation": (
                "exact semantic-class correctness per primary family, accuracy within "
                "each family, arithmetic mean across the 20 primary families"
            ),
        },
        "safety_metric": {
            "identity": "e2-clean-case-regression/1",
            "counts": [
                "clean_exact_error_count",
                "spurious_basis_removal_count",
                "valid_basis_rejection_count",
                "clean_not_applicable_count",
                "clean_malformed_count",
            ],
        },
        "classification_truth_table": {
            "TECHNICALLY_INVALID": "execution/measurement failure",
            "HARMFUL": "safety fails OR P_foundry < P_control",
            "PROMISING": "safety passes AND P_foundry > P_control AND P_foundry > P_base",
            "NO_OBSERVED_SIGNAL": "otherwise valid",
        },
        "gpu_minute_ceiling": GPU_MINUTE_CEILING,
        "checkpoint_4_inference": "omitted per E2 spec",
        "claim_boundary": (
            "This contract freezes the E2 Foundry-vs-control experiment: model, training "
            "recipe, inference ABI, protected evaluation identities, metrics, and the "
            "classification truth table. It does not predetermine the outcome, authorize "
            "merger, or establish general reasoning transfer."
        ),
    }
    return contract


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the E2 Foundry-vs-control experiment.")
    parser.add_argument(
        "--skip-gpu",
        action="store_true",
        help="run preflight + contract only, skip GPU phases (for self-check).",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="keep the temporary working directory for inspection.",
    )
    args = parser.parse_args()

    repo_root = _repo_root()
    preflight_data = _preflight(repo_root)

    contract = _build_contract(repo_root, preflight_data)
    contract_path = repo_root / "experiments" / "e2" / "e2_contract.json"
    # The contract carries a frozen learning-rate float, so it is written as
    # canonical-pretty JSON (sorted keys, deterministic separators) rather than
    # the kernel's integer-only canonical serializer.
    contract_path.write_text(
        json.dumps(contract, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[phase 1] wrote contract: {contract_path}", flush=True)

    if args.skip_gpu:
        print(
            "[phase 1] --skip-gpu: preflight + contract complete, GPU phases skipped.", flush=True
        )
        return 0

    importlib.import_module("torch")  # ensure torch is importable before subprocess
    cases_records = preflight_data["primary_records"] + preflight_data["clean_records"]

    work_dir = repo_root / "experiments" / "e2" / "_run"
    work_dir.mkdir(parents=True, exist_ok=True)

    started_total = time.monotonic()
    prediction_files: dict[str, Path] = {}
    for arm in ARMS:
        prediction_files[arm] = _run_arm(arm, repo_root, cases_records, work_dir)
    elapsed_total = time.monotonic() - started_total
    print(
        f"[gpu] total elapsed {elapsed_total:.1f}s (ceiling {GPU_MINUTE_CEILING * 60}s)", flush=True
    )

    results = _metric_release(
        preflight_data["primary_records"],
        preflight_data["clean_records"],
        prediction_files,
    )
    results["gpu_elapsed_seconds"] = elapsed_total

    _print_report(results)

    # Persist the full results alongside the run.
    results_path = work_dir / "e2_results.json"
    with results_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    print(f"\n[phase 5] full results: {results_path}", flush=True)

    if not args.keep_workdir:
        # Keep only the results file; the worker scripts and per-arm JSON are ephemeral.
        for child in work_dir.iterdir():
            if child.name != "e2_results.json":
                if child.is_dir():
                    for sub in child.iterdir():
                        sub.unlink(missing_ok=True)
                    child.rmdir()
                else:
                    child.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
