import importlib
import json
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
        with open(train_path, encoding="utf-8") as handle:
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
        prompt_text = system_content + "\n" + user_content + "\n"
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
    with open(cases_path, encoding="utf-8") as handle:
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
        predictions.append(
            {
                "record_id": case["record_id"],
                "family_id": case["family_id"],
                "case_id": case["case_id"],
                "generated_token_id": new_id,
                "decoded_suffix": decoded_suffix,
            }
        )

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
