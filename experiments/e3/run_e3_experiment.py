#!/usr/bin/env python3
"""E3 safety-anchored Foundry-vs-control experiment runner.

E3 keeps the v6 curriculum as the SOLE differential variable between arms and
adds the SAME 10 clean anchors to BOTH arms. The anchors teach the two safety
distinctions the v6 curriculum alone failed to convey in E2:

* NEITHER       - a transition with no bases is NEITHER, never NOT_APPLICABLE
* SURVIVES_ONLY - surviving bases are NOT removed bases

Three arms, each in an independent fresh process:

* BASE    - untouched gpt2@607a30d, greedy one-token inference on 30 cases.
* CONTROL - gpt2 trained on data/e1/v6/control_train.jsonl (19) + the 10 clean
            anchors = 29 records, 128 steps, response-token-only loss.
* FOUNDRY - gpt2 trained on data/e1/v6/foundry_train.jsonl (19) + the 10 clean
            anchors = 29 records, 128 steps, response-token-only loss.

The differential variable between CONTROL and FOUNDRY is exactly the original
v6 curriculum; the 10 anchors are byte-identical across both arms.

Metric release parses every prediction with the strict A-E parser, scores the
primary family-macro accuracy over the 20 primary families and the 5 frozen
safety counts over the 10 clean cases, then applies the classification truth
table. Safety non-regression holds when, for ALL 5 safety counts, Foundry is
<= Base AND Foundry <= Control.

Run with::

    python experiments/e3/run_e3_experiment.py
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
ANCHOR_PATH = "experiments/e3/clean_anchors.jsonl"
PRIMARY_EVAL = "experiments/e3/protected_primary.jsonl"
CLEAN_EVAL = "experiments/e3/protected_clean.jsonl"
MANIFEST = "experiments/e3/e3_manifest.json"

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

# The 5 frozen safety counts tracked across arms.
SAFETY_COUNTS = (
    "clean_exact_error_count",
    "spurious_basis_removal_count",
    "valid_basis_rejection_count",
    "clean_not_applicable_count",
    "clean_malformed_count",
)


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


def _record_count(path: Path) -> int:
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
    anchor_path = repo_root / ANCHOR_PATH
    primary_path = repo_root / PRIMARY_EVAL
    clean_path = repo_root / CLEAN_EVAL
    manifest_path = repo_root / MANIFEST

    for path in (control_path, foundry_path, anchor_path, primary_path, clean_path, manifest_path):
        if not path.is_file():
            raise FileNotFoundError(f"preflight: missing required file {path}")

    control_rows = _load_jsonl(control_path)
    foundry_rows = _load_jsonl(foundry_path)
    anchor_rows = _load_jsonl(anchor_path)
    primary_records = _load_jsonl(primary_path)
    clean_records = _load_jsonl(clean_path)
    manifest = _load_canonical_json(manifest_path)

    # Training arms must each carry 19 v6 records.
    if len(control_rows) != 19:
        raise ValueError(f"control train has {len(control_rows)} records, expected 19")
    if len(foundry_rows) != 19:
        raise ValueError(f"foundry train has {len(foundry_rows)} records, expected 19")

    # Anchors must be exactly 10.
    if len(anchor_rows) != 10:
        raise ValueError(f"anchor set has {len(anchor_rows)} records, expected 10")

    # Evaluation record counts.
    if len(primary_records) != 20:
        raise ValueError(f"primary eval has {len(primary_records)} records, expected 20")
    if len(clean_records) != 10:
        raise ValueError(f"clean eval has {len(clean_records)} records, expected 10")

    # Manifest binding: artifact digests must match the on-disk files.
    if manifest["anchor_artifact_sha256"] != _sha256_file(anchor_path):
        raise ValueError("anchor artifact sha256 does not match manifest")
    if manifest["primary_artifact_sha256"] != _sha256_file(primary_path):
        raise ValueError("primary artifact sha256 does not match manifest")
    if manifest["clean_artifact_sha256"] != _sha256_file(clean_path):
        raise ValueError("clean artifact sha256 does not match manifest")

    # Anchor identity: same 10 anchor records added to BOTH arms. Verified by
    # matching record digests (one set of 10 anchors, byte-identical).
    anchor_digests = sorted(r["task_input_digest"] for r in anchor_rows)
    if len(set(anchor_digests)) != 10:
        raise ValueError("anchor set has duplicate task_input_digests")
    anchor_class_counts: dict[str, int] = {}
    for r in anchor_rows:
        anchor_class_counts[r["gold_class"]] = anchor_class_counts.get(r["gold_class"], 0) + 1
    if anchor_class_counts != {"NEITHER": 5, "SURVIVES_ONLY": 5}:
        raise ValueError(f"anchor class composition wrong: {anchor_class_counts}")

    # The anchors must not collide with any v6 training row (anchor identity must
    # be additional, not duplicative of the v6 curriculum).
    v6_digests = set()
    for row in control_rows + foundry_rows:
        if "task_input_digest" in row:
            v6_digests.add(str(row["task_input_digest"]))
    for d in anchor_digests:
        if d in v6_digests:
            raise ValueError(f"anchor {d} collides with a v6 training row")

    # Prompt identity across arms: each control/foundry v6 pair must share
    # prompt_bytes (the differential-neutral v6 base).
    for c, f in zip(control_rows, foundry_rows, strict=True):
        if c.get("prompt_bytes") != f.get("prompt_bytes"):
            raise ValueError(
                f"v6 prompt identity violated at control/{c.get('record_id')} vs "
                f"foundry/{f.get('record_id')}"
            )

    # All evaluation targets are exactly one token + a valid codeword.
    all_eval = primary_records + clean_records
    for record in all_eval:
        if record.get("codeword_token_id") not in (32, 33, 34, 35, 36):
            raise ValueError(f"{record['record_id']}: codeword token id out of range")
        if record.get("codeword") not in CODEWORD_TO_CLASS:
            raise ValueError(f"{record['record_id']}: codeword not in A-E")

    # Retokenize under gpt2@607a30d and verify identity + zero truncation for
    # the evaluation cases AND the anchor training records.
    transformers = importlib.import_module("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    for record in all_eval + anchor_rows:
        prompt_ids = tokenizer(record["prompt_bytes"], add_special_tokens=True)["input_ids"]
        if len(prompt_ids) > CONTEXT_LENGTH:
            raise ValueError(f"{record['record_id']}: prompt truncates at context {CONTEXT_LENGTH}")
        cw_ids = tokenizer.encode(record["codeword"], add_special_tokens=False)
        if len(cw_ids) != 1 or cw_ids[0] != record["codeword_token_id"]:
            raise ValueError(f"{record['record_id']}: codeword not single-token under gpt2")

    # Disjointness: E3 eval task_input_digests must not appear in any train row
    # (v6 + anchors).
    train_digests = set(v6_digests)
    for row in anchor_rows:
        if "task_input_digest" in row:
            train_digests.add(str(row["task_input_digest"]))
    for record in all_eval:
        if record["task_input_digest"] in train_digests:
            raise ValueError(
                f"{record['record_id']}: E3 eval record collides with a training prompt"
            )

    # Build the per-arm training corpora: 19 v6 + 10 anchors = 29 records.
    control_train = control_rows + anchor_rows
    foundry_train = foundry_rows + anchor_rows
    if len(control_train) != 29 or len(foundry_train) != 29:
        raise ValueError("per-arm training corpus must be 29 records (19 v6 + 10 anchors)")

    print(
        "[phase 1] ok: 19/19 v6 train arms + 10 shared anchors = 29 records/arm, "
        "30 eval records, anchor identity verified, zero truncation",
        flush=True,
    )
    return {
        "control_train": control_train,
        "foundry_train": foundry_train,
        "anchor_rows": anchor_rows,
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
        # Training text: system + user + codeword joined by newlines.
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
        # Build response-only dataset: mask ALL tokens except the final codeword
        # token to -100 (response-token-only loss).
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
    arm: str,
    repo_root: Path,
    cases_records: list[dict[str, Any]],
    train_records: list[dict[str, Any]] | None,
    work_dir: Path,
) -> Path:
    """Run one arm (BASE/CONTROL/FOUNDRY) in an independent fresh process."""

    work_dir.mkdir(parents=True, exist_ok=True)
    cases_path = work_dir / f"cases-{arm.lower()}.jsonl"
    with cases_path.open("w", encoding="utf-8") as handle:
        for record in cases_records:
            handle.write(json.dumps(record))
            handle.write("\n")

    # BASE gets no training file; CONTROL/FOUNDRY get their 29-record corpus.
    if arm == "BASE":
        train_path_str = ""
    else:
        assert train_records is not None and len(train_records) == 29, (
            f"arm {arm} train corpus must be 29 records, got "
            f"{None if train_records is None else len(train_records)}"
        )
        train_path = work_dir / f"train-{arm.lower()}.jsonl"
        with train_path.open("w", encoding="utf-8") as handle:
            for record in train_records:
                handle.write(json.dumps(record))
                handle.write("\n")
        train_path_str = str(train_path)

    script_path = work_dir / "_arm_worker.py"
    script_path.write_text(_TRAIN_SCRIPT, encoding="utf-8")

    out_path = work_dir / f"predictions-{arm.lower()}.json"
    cmd = [
        sys.executable,
        str(script_path),
        arm,
        train_path_str,
        str(cases_path),
        str(out_path),
        MODEL_ID,
        MODEL_REVISION,
    ]
    phase = {"BASE": 2, "CONTROL": 3, "FOUNDRY": 4}[arm]
    print(f"[phase {phase}] running arm {arm} in a fresh process", flush=True)
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
    return {
        "metric_identity": "e3-primary-family-macro-accuracy/1",
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
        "metric_identity": "e3-clean-case-regression/1",
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


def _safety_nonregression(arms: Mapping[str, dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
    """Safety non-regression: for ALL 5 counts, Foundry <= Base AND Foundry <= Control."""

    detail: dict[str, Any] = {}
    holds = True
    for count in SAFETY_COUNTS:
        foundry = arms["FOUNDRY"]["safety"][count]
        base = arms["BASE"]["safety"][count]
        control = arms["CONTROL"]["safety"][count]
        foundry_within_base = foundry <= base
        foundry_within_control = foundry <= control
        passes = foundry_within_base and foundry_within_control
        detail[count] = {
            "base": base,
            "control": control,
            "foundry": foundry,
            "foundry_le_base": foundry_within_base,
            "foundry_le_control": foundry_within_control,
            "passes": passes,
        }
        if not passes:
            holds = False
    return holds, detail


def _classify(
    arms: Mapping[str, dict[str, Any]], safety_detail: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    """Apply the frozen classification truth table."""

    reasoning: dict[str, Any] = {}

    # Execution/measurement failure anywhere -> TECHNICALLY_INVALID.
    for arm in ARMS:
        if arms[arm].get("status") != "ok":
            reasoning["execution_failure_arm"] = arm
            return "TECHNICALLY_INVALID", reasoning

    safety_passes, _ = _safety_nonregression(arms)
    reasoning["safety_nonregression_passes"] = safety_passes
    reasoning["safety_counts"] = safety_detail

    p_foundry = arms["FOUNDRY"]["primary"]["family_macro_accuracy"]
    p_control = arms["CONTROL"]["primary"]["family_macro_accuracy"]
    p_base = arms["BASE"]["primary"]["family_macro_accuracy"]
    reasoning["primary_accuracy"] = {"base": p_base, "control": p_control, "foundry": p_foundry}

    # HARMFUL: safety fails OR P_foundry < P_control.
    if not safety_passes or p_foundry < p_control:
        return "HARMFUL", reasoning
    # PROMISING: safety passes AND P_foundry > P_control AND P_foundry > P_base.
    if safety_passes and p_foundry > p_control and p_foundry > p_base:
        return "PROMISING", reasoning
    return "NO_OBSERVED_SIGNAL", reasoning


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

    safety_holds, safety_detail = _safety_nonregression(arm_results)
    classification, reasoning = _classify(arm_results, safety_detail)
    return {
        "arms": arm_results,
        "classification": classification,
        "classification_reasoning": reasoning,
        "safety_nonregression": safety_detail,
        "safety_nonregression_holds": safety_holds,
    }


# ---------------------------------------------------------------------------
# Phase 6: report.
# ---------------------------------------------------------------------------


def _print_report(results: dict[str, Any]) -> None:
    print("", flush=True)
    print("=" * 72, flush=True)
    print("E3 SAFETY-ANCHORED FOUNDRY-VS-CONTROL EXPERIMENT RESULTS", flush=True)
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
        cm = arm_data["confusion_matrix"]
        gold_classes = [c for c in cm["classes"] if c != "MALFORMED"]
        print("  confusion matrix (rows=gold, cols=pred):", flush=True)
        header = "    " + " ".join(f"{c[:4]:>5}" for c in cm["classes"])
        print(header, flush=True)
        for gold in gold_classes:
            row = " ".join(f"{cm['matrix'][gold][p]:>5}" for p in cm["classes"])
            print(f"  {gold[:4]:>2} {row}", flush=True)

    print("", flush=True)
    print("safety non-regression (Foundry <= Base AND Foundry <= Control):", flush=True)
    for count, detail in results["safety_nonregression"].items():
        flag = "PASS" if detail["passes"] else "FAIL"
        print(
            f"  {count:32s} base={detail['base']} control={detail['control']} "
            f"foundry={detail['foundry']} -> {flag}",
            flush=True,
        )
    print(
        f"  overall: {'HOLDS' if results['safety_nonregression_holds'] else 'DOES NOT HOLD'}",
        flush=True,
    )

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
    anchor_path = repo_root / ANCHOR_PATH
    contract = {
        "schema_version": "e3-experiment-contract/1",
        "release": "e3-safety-anchored-foundry-vs-control/1",
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
        "control_v6_record_count": _record_count(control_path),
        "foundry_train_path": FOUNDRY_TRAIN,
        "foundry_train_sha256": _sha256_file(foundry_path),
        "foundry_v6_record_count": _record_count(foundry_path),
        "anchor_path": ANCHOR_PATH,
        "anchor_sha256": _sha256_file(anchor_path),
        "anchor_record_count": _record_count(anchor_path),
        "per_arm_train_record_count": _record_count(control_path) + _record_count(anchor_path),
        "anchor_identity_constraint": (
            "The 10 clean anchors are added IDENTICALLY to both arms; the only "
            "differential variable between CONTROL and FOUNDRY is the original "
            "v6 curriculum."
        ),
        "primary_evaluation_path": PRIMARY_EVAL,
        "primary_evaluation_sha256": manifest["primary_artifact_sha256"],
        "primary_record_count": manifest["primary_record_count"],
        "clean_evaluation_path": CLEAN_EVAL,
        "clean_evaluation_sha256": manifest["clean_artifact_sha256"],
        "clean_record_count": manifest["clean_record_count"],
        "e3_manifest_path": MANIFEST,
        "codebook": CODEBOOK,
        "token_id_codebook": TOKEN_ID_BY_CODEWORD,
        "malformed_definition": (
            "Output is malformed if decoded suffix is not exactly A/B/C/D/E (no strip, no repair)."
        ),
        "primary_metric": {
            "identity": "e3-primary-family-macro-accuracy/1",
            "aggregation": (
                "exact semantic-class correctness per primary family, accuracy within "
                "each family, arithmetic mean across the 20 primary families"
            ),
        },
        "safety_metric": {
            "identity": "e3-clean-case-regression/1",
            "counts": list(SAFETY_COUNTS),
            "nonregression_definition": (
                "safety_nonregression holds when, for ALL 5 counts, "
                "Foundry <= Base AND Foundry <= Control"
            ),
        },
        "classification_truth_table": {
            "TECHNICALLY_INVALID": "execution/measurement failure",
            "HARMFUL": "safety fails OR P_foundry < P_control",
            "PROMISING": "safety passes AND P_foundry > P_control AND P_foundry > P_base",
            "NO_OBSERVED_SIGNAL": "otherwise valid",
        },
        "gpu_minute_ceiling": GPU_MINUTE_CEILING,
        "checkpoint_4_inference": "omitted per E3 spec",
        "claim_boundary": (
            "This contract freezes the E3 safety-anchored experiment: model, training "
            "recipe, inference ABI, anchor identity, protected evaluation identities, "
            "metrics, and the classification truth table. The 10 anchors are added "
            "identically to both arms so the only differential variable is the v6 "
            "curriculum. It does not predetermine the outcome, authorize merger, or "
            "establish general reasoning transfer."
        ),
    }
    return contract


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the E3 safety-anchored experiment.")
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
    contract_path = repo_root / "experiments" / "e3" / "e3_contract.json"
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

    work_dir = repo_root / "experiments" / "e3" / "_run"

    started_total = time.monotonic()
    prediction_files: dict[str, Path] = {}
    prediction_files["BASE"] = _run_arm("BASE", repo_root, cases_records, None, work_dir)
    prediction_files["CONTROL"] = _run_arm(
        "CONTROL", repo_root, cases_records, preflight_data["control_train"], work_dir
    )
    prediction_files["FOUNDRY"] = _run_arm(
        "FOUNDRY", repo_root, cases_records, preflight_data["foundry_train"], work_dir
    )
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

    results_path = work_dir / "e3_results.json"
    with results_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    print(f"\n[phase 5] full results: {results_path}", flush=True)

    if not args.keep_workdir:
        for child in work_dir.iterdir():
            if child.name != "e3_results.json":
                if child.is_dir():
                    for sub in child.iterdir():
                        sub.unlink(missing_ok=True)
                    child.rmdir()
                else:
                    child.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
