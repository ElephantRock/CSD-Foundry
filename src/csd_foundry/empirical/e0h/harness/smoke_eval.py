"""Evaluate only deterministic infrastructure properties of E0-H smoke inference."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_empty_output_directory,
    read_json_object,
    read_jsonl,
    sha256_file,
    verify_static_inputs,
    write_json_no_clobber,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def evaluate_smoke_outputs(paths: RunPaths) -> dict[str, object]:
    """Check coverage, nonempty output, and exact repeated greedy decoding only."""

    inputs = verify_static_inputs(paths, require_snapshot=False)
    fixture_records = read_jsonl(paths.smoke_fixture)
    output_path = paths.work / "inference" / "inference_outputs.jsonl"
    output_records = read_jsonl(output_path)
    inference_receipt = read_json_object(paths.work / "inference" / "inference_receipt.json")
    if inference_receipt.get("output_digest") != sha256_file(output_path):
        raise E0HRunReleaseError("inference output digest mismatch")
    if inference_receipt.get("fixture_digest") != inputs.evaluation.smoke_fixture_digest:
        raise E0HRunReleaseError("inference receipt does not bind the smoke fixture")

    fixture_ids = [record.get("id") for record in fixture_records]
    output_ids = [record.get("id") for record in output_records]
    if fixture_ids != output_ids:
        raise E0HRunReleaseError(
            f"smoke fixture coverage mismatch; expected={fixture_ids}, observed={output_ids}"
        )

    for record in output_records:
        first_ids = record.get("first_token_ids")
        second_ids = record.get("second_token_ids")
        first_text = record.get("first_text")
        second_text = record.get("second_text")
        if not isinstance(first_ids, list) or not first_ids:
            raise E0HRunReleaseError("smoke output must contain first-run token IDs")
        if first_ids != second_ids:
            raise E0HRunReleaseError(f"repeated greedy token IDs diverged for {record.get('id')}")
        if not isinstance(first_text, str) or not isinstance(second_text, str):
            raise E0HRunReleaseError("smoke output text fields must be strings")
        if first_text != second_text:
            raise E0HRunReleaseError(f"repeated greedy text diverged for {record.get('id')}")

    output_dir = paths.work / "smoke"
    assert_empty_output_directory(output_dir)
    receipt = {
        "schema_version": "e0h-smoke-evaluation-receipt/1",
        "fixture_digest": inputs.evaluation.smoke_fixture_digest,
        "inference_output_digest": inference_receipt["output_digest"],
        "record_count": len(output_records),
        "coverage_complete": True,
        "outputs_nonempty": True,
        "repeated_greedy_outputs_identical": True,
        "protected_metrics_computed": False,
        "semantic_correctness_assessed": False,
    }
    write_json_no_clobber(output_dir / "smoke_evaluation_receipt.json", receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e0h.harness.smoke_eval")
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(evaluate_smoke_outputs(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
