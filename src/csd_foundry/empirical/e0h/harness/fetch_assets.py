"""Fetch and verify the exact immutable model snapshot for E0-H."""

from __future__ import annotations

import argparse
import json
import shutil
import urllib.request
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e0h.harness.common import (
    RunPaths,
    load_inputs,
    sha256_file,
    verify_snapshot_manifest,
)
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError


def fetch_snapshot(paths: RunPaths) -> dict[str, object]:
    """Download the declared snapshot into a new no-clobber directory."""

    inputs = load_inputs(paths)
    manifest = verify_snapshot_manifest(paths, inputs)
    raw_files = manifest["files"]
    if not isinstance(raw_files, list):
        raise E0HRunReleaseError("snapshot manifest files must be a list")
    if paths.model_snapshot.exists() or paths.model_snapshot.is_symlink():
        raise E0HRunReleaseError(
            f"refusing to reuse model snapshot directory: {paths.model_snapshot}"
        )

    temporary = paths.model_snapshot.with_name(".model.download")
    if temporary.exists() or temporary.is_symlink():
        raise E0HRunReleaseError(f"temporary model directory already exists: {temporary}")
    temporary.mkdir(parents=True)
    try:
        for raw in raw_files:
            if not isinstance(raw, dict):
                raise E0HRunReleaseError("snapshot file receipt must be an object")
            receipt = cast(dict[str, object], raw)
            name = receipt["path"]
            expected_digest = receipt["sha256"]
            expected_size = receipt["size_bytes"]
            if not isinstance(name, str) or Path(name).name != name:
                raise E0HRunReleaseError(f"invalid snapshot filename: {name!r}")
            if not isinstance(expected_digest, str):
                raise E0HRunReleaseError(f"invalid snapshot digest for {name}")
            if isinstance(expected_size, bool) or not isinstance(expected_size, int):
                raise E0HRunReleaseError(f"invalid snapshot size for {name}")
            repository = manifest["repository"]
            revision = manifest["revision"]
            if not isinstance(repository, str) or not isinstance(revision, str):
                raise E0HRunReleaseError("invalid snapshot repository or revision")
            url = (
                f"https://huggingface.co/{repository}/resolve/{revision}/{name}"
                "?download=true"
            )
            target = temporary / name
            with urllib.request.urlopen(url, timeout=300) as response, target.open("wb") as handle:
                shutil.copyfileobj(response, handle, length=1024 * 1024)
            if target.stat().st_size != expected_size:
                raise E0HRunReleaseError(f"downloaded snapshot size mismatch: {name}")
            if sha256_file(target) != expected_digest:
                raise E0HRunReleaseError(f"downloaded snapshot digest mismatch: {name}")
        temporary.rename(paths.model_snapshot)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    receipt_payload = {
        "schema_version": "e0h-model-fetch-receipt/1",
        "snapshot_digest": manifest["snapshot_digest"],
        "tokenizer_snapshot_digest": manifest["tokenizer_snapshot_digest"],
        "model_digest": inputs.model.content_digest,
        "file_count": len(raw_files),
        "snapshot_directory": str(paths.model_snapshot),
    }
    receipt_path = paths.run_root / "assets" / "model_fetch_receipt.json"
    receipt_path.write_text(
        json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return receipt_payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m csd_foundry.empirical.e0h.harness.fetch_assets"
    )
    parser.add_argument("--run-root", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    paths = RunPaths.resolve(args.run_root)
    print(json.dumps(fetch_snapshot(paths), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
