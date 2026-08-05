"""Validate the concrete E0-H run package before any bounded execution."""

from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from csd_foundry.empirical.e0h import compile_e0h_run_release, validate_e0h_run_release
from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    assert_python_version,
    read_jsonl,
    verify_static_inputs,
)
from csd_foundry.empirical.e0h.harness.package_lock import verify_installed_python_lock
from csd_foundry.empirical.e0h.harness.package_manifest import (
    verify_execution_package_manifest,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError

_EXPECTED_TRAIN_RECORDS = 168


def run_preflight(paths: RunPaths, *, mode: str, require_snapshot: bool) -> dict[str, object]:
    """Validate immutable inputs, release reconstruction, runtime, and device boundary."""

    inputs = verify_static_inputs(paths, require_snapshot=require_snapshot)
    package_manifest = verify_execution_package_manifest(paths, inputs)
    assert_python_version(inputs.environment.python_version)
    runtime_versions = verify_installed_python_lock(paths, inputs)

    bundle = compile_e0h_run_release(inputs)
    release_report = validate_e0h_run_release(paths.compiled_release, inputs)
    if not release_report.success:
        raise E0HRunReleaseError(
            f"compiled E0-H release failed validation: {release_report.errors}"
        )

    training_records = [
        record
        for record in read_jsonl(paths.repository_root / inputs.dataset.sft_path)
        if record.get("split") == "train"
    ]
    if len(training_records) != _EXPECTED_TRAIN_RECORDS:
        raise E0HRunReleaseError(
            f"training record count mismatch; expected={_EXPECTED_TRAIN_RECORDS}, "
            f"observed={len(training_records)}"
        )

    device: dict[str, object] = {"mode": mode}
    if mode == "gpu":
        torch = importlib.import_module("torch")
        if not torch.cuda.is_available():
            raise E0HRunReleaseError("GPU preflight requires CUDA availability")
        count = int(torch.cuda.device_count())
        if count != inputs.environment.gpu_count:
            raise E0HRunReleaseError(
                f"GPU count mismatch; expected={inputs.environment.gpu_count}, observed={count}"
            )
        names = [str(torch.cuda.get_device_name(index)) for index in range(count)]
        if any("L4" not in name for name in names):
            raise E0HRunReleaseError(f"GPU model mismatch; expected NVIDIA L4, observed={names}")
        if not bool(torch.cuda.is_bf16_supported()):
            raise E0HRunReleaseError("configured GPU does not support bf16")
        device["names"] = names
        device["cuda_runtime"] = str(torch.version.cuda)
    elif mode != "cpu":
        raise E0HRunReleaseError("preflight mode must be cpu or gpu")

    return {
        "schema_version": "e0h-preflight-receipt/1",
        "release": inputs.release,
        "source_commit": inputs.source_commit,
        "run_contract_digest": bundle.run_contract_digest,
        "execution_package_file_count": package_manifest["file_count"],
        "training_record_count": len(training_records),
        "protected_metrics_access": inputs.evaluation.protected_metrics_access,
        "runtime_versions": runtime_versions,
        "device": device,
        "gpu_execution_authorized": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m csd_foundry.empirical.e0h.harness.preflight")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--mode", choices=("cpu", "gpu"), required=True)
    parser.add_argument("--require-snapshot", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    receipt = run_preflight(
        paths,
        mode=args.mode,
        require_snapshot=bool(args.require_snapshot),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
