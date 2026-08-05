"""Generate deterministic non-metric smoke outputs from the final E0-H checkpoint."""

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
from csd_foundry.empirical.e0h.harness.preflight import run_preflight
from csd_foundry.empirical.e0h.harness.reload import _final_checkpoint, _prompt_ids
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def _fixture_id(fixture: dict[str, object]) -> str:
    value = fixture.get("id")
    if not isinstance(value, str) or not value:
        raise E0HRunReleaseError("smoke fixture id must be a nonempty string")
    return value


def _max_new_tokens(fixture: dict[str, object]) -> int:
    value = fixture.get("max_new_tokens")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 64:
        raise E0HRunReleaseError("smoke max_new_tokens must be an integer from 1 through 64")
    return value


def _generate_once(
    *,
    torch: Any,
    model: Any,
    tokenizer: Any,
    prompt_ids: list[int],
    max_new_tokens: int,
    seed: int,
) -> tuple[list[int], str]:
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    tensor = torch.tensor([prompt_ids], dtype=torch.long, device="cuda")
    with torch.no_grad():
        generated = model.generate(
            input_ids=tensor,
            do_sample=False,
            num_beams=1,
            max_new_tokens=max_new_tokens,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    raw = generated[0].detach().cpu().tolist()
    if not isinstance(raw, list):
        raise E0HRunReleaseError("generation did not return a token list")
    token_ids = cast(list[int], raw[len(prompt_ids) :])
    if not token_ids:
        raise E0HRunReleaseError("generation returned no continuation tokens")
    return token_ids, str(tokenizer.decode(token_ids, skip_special_tokens=True))


def run_inference(paths: RunPaths) -> dict[str, object]:
    """Generate each fixture twice with greedy decoding and preserve both byte receipts."""

    inputs = verify_static_inputs(paths, require_snapshot=True)
    run_preflight(paths, mode="gpu", require_snapshot=True)
    checkpoint, checkpoint_receipt = _final_checkpoint(paths)
    fixtures = read_jsonl(paths.smoke_fixture)

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

    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for fixture in fixtures:
        fixture_id = _fixture_id(fixture)
        if fixture_id in seen:
            raise E0HRunReleaseError(f"duplicate smoke fixture id: {fixture_id}")
        seen.add(fixture_id)
        prompt_ids = _prompt_ids(tokenizer, fixture.get("messages"))
        max_new_tokens = _max_new_tokens(fixture)
        first_ids, first_text = _generate_once(
            torch=torch,
            model=model,
            tokenizer=tokenizer,
            prompt_ids=prompt_ids,
            max_new_tokens=max_new_tokens,
            seed=inputs.recipe.seed,
        )
        second_ids, second_text = _generate_once(
            torch=torch,
            model=model,
            tokenizer=tokenizer,
            prompt_ids=prompt_ids,
            max_new_tokens=max_new_tokens,
            seed=inputs.recipe.seed,
        )
        records.append(
            {
                "schema_version": "e0h-smoke-inference/1",
                "id": fixture_id,
                "prompt_tokens": len(prompt_ids),
                "first_token_ids": first_ids,
                "second_token_ids": second_ids,
                "first_text": first_text,
                "second_text": second_text,
            }
        )

    records.sort(key=lambda item: cast(str, item["id"]))
    output_dir = paths.work / "inference"
    assert_empty_output_directory(output_dir)
    output_path = output_dir / "inference_outputs.jsonl"
    write_jsonl_no_clobber(output_path, records)
    receipt = {
        "schema_version": "e0h-inference-receipt/1",
        "checkpoint_digest": checkpoint_receipt["digest"],
        "fixture_digest": inputs.evaluation.smoke_fixture_digest,
        "record_count": len(records),
        "output_digest": sha256_file(output_path),
        "decoding": "greedy",
        "repetitions_per_fixture": 2,
        "protected_metrics_computed": False,
    }
    write_json_no_clobber(output_dir / "inference_receipt.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m csd_foundry.empirical.e0h.harness.infer"
    )
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(run_inference(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
