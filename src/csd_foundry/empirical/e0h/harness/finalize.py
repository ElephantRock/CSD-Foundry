"""Finalize one E0-H execution as HARNESS_PASSED or HARNESS_FAILED."""

from __future__ import annotations

import argparse
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_empty_output_directory,
    read_json_object,
    sha256_file,
    verify_static_inputs,
    write_json_no_clobber,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")


def _gpu_minutes(value: str, *, maximum: int) -> str:
    if _DECIMAL.fullmatch(value) is None:
        raise E0HRunReleaseError("actual GPU minutes must be a canonical nonnegative decimal")
    try:
        observed = Decimal(value)
    except InvalidOperation as exc:
        raise E0HRunReleaseError("actual GPU minutes are invalid") from exc
    if observed > Decimal(maximum):
        raise E0HRunReleaseError(
            f"actual GPU minutes exceed E0-H budget; maximum={maximum}, observed={value}"
        )
    return value


def _evidence(paths: RunPaths) -> tuple[dict[str, object], ...]:
    relative_paths = (
        "tokenized/tokenization_receipt.json",
        "training/training_health.json",
        "reload/reload_receipt.json",
        "inference/inference_receipt.json",
        "smoke/smoke_evaluation_receipt.json",
    )
    evidence: list[dict[str, object]] = []
    for relative in relative_paths:
        path = paths.work / relative
        payload = read_json_object(path)
        if payload.get("protected_metrics_computed") is not False:
            raise E0HRunReleaseError(f"evidence does not deny protected metrics: {relative}")
        evidence.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
            }
        )
    return tuple(evidence)


def finalize_execution(
    paths: RunPaths,
    *,
    classification: str,
    actual_gpu_minutes: str,
    failure_reason: str | None,
) -> dict[str, object]:
    """Seal bounded execution evidence without introducing a model-quality conclusion."""

    inputs = verify_static_inputs(paths, require_snapshot=False)
    minutes = _gpu_minutes(actual_gpu_minutes, maximum=inputs.budget.e0h_gpu_minutes)
    if classification not in {"HARNESS_PASSED", "HARNESS_FAILED"}:
        raise E0HRunReleaseError("classification must be HARNESS_PASSED or HARNESS_FAILED")

    evidence: tuple[dict[str, object], ...] = ()
    if classification == "HARNESS_PASSED":
        if failure_reason is not None:
            raise E0HRunReleaseError("HARNESS_PASSED cannot include a failure reason")
        evidence = _evidence(paths)
        reload_receipt = read_json_object(paths.work / "reload" / "reload_receipt.json")
        smoke_receipt = read_json_object(paths.work / "smoke" / "smoke_evaluation_receipt.json")
        if reload_receipt.get("finite_logits") is not True:
            raise E0HRunReleaseError("reload evidence does not establish finite logits")
        if smoke_receipt.get("repeated_greedy_outputs_identical") is not True:
            raise E0HRunReleaseError("smoke evidence does not establish deterministic output")
    else:
        if failure_reason is None or not failure_reason.strip():
            raise E0HRunReleaseError("HARNESS_FAILED requires a nonempty failure reason")
        if len(failure_reason) > 500:
            raise E0HRunReleaseError("failure reason exceeds 500 characters")

    remaining = Decimal(inputs.budget.aggregate_gpu_minutes) - Decimal(minutes)
    result = {
        "schema_version": "e0h-execution-result/1",
        "classification": classification,
        "failure_reason": failure_reason,
        "source_commit": inputs.source_commit,
        "actual_gpu_minutes": minutes,
        "aggregate_gpu_minutes": inputs.budget.aggregate_gpu_minutes,
        "remaining_aggregate_gpu_minutes": format(remaining, "f"),
        "checkpoint_uri": inputs.storage.checkpoint_uri,
        "evidence_uri": inputs.storage.evidence_uri,
        "evidence": list(evidence),
        "protected_metrics_computed": False,
        "reasoning_improvement_claim_authorized": False,
        "e0h_harness_qualified": classification == "HARNESS_PASSED",
        "e1_execution_authorized": False,
    }
    output_dir = paths.work / "final"
    assert_empty_output_directory(output_dir)
    write_json_no_clobber(output_dir / "e0h_result.json", result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e0h.harness.finalize")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument(
        "--classification",
        choices=("HARNESS_PASSED", "HARNESS_FAILED"),
        required=True,
    )
    parser.add_argument("--actual-gpu-minutes", required=True)
    parser.add_argument("--failure-reason")
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    result = finalize_execution(
        paths,
        classification=args.classification,
        actual_gpu_minutes=args.actual_gpu_minutes,
        failure_reason=args.failure_reason,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
