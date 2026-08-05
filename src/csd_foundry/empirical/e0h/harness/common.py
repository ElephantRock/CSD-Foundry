"""Shared deterministic utilities for the concrete E0-H harness."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, cast

from csd_foundry.empirical.e0h import E0HRunReleaseInputs, load_e0h_run_release_inputs
from csd_foundry.empirical.e0h.run_release import E0HRunReleaseError
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

_MODEL_FILES = {
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
}
_TOKENIZER_FILES = {
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
}


@dataclass(frozen=True, slots=True)
class RunPaths:
    """Resolved filesystem locations for one concrete E0-H run package."""

    run_root: Path

    @classmethod
    def resolve(cls, value: str | Path) -> RunPaths:
        path = Path(value).resolve()
        if not path.is_dir() or path.is_symlink():
            raise E0HRunReleaseError(f"run root must be a real directory: {path}")
        return cls(path)

    @property
    def repository_root(self) -> Path:
        return self.run_root.parents[2]

    @property
    def run_inputs(self) -> Path:
        return self.run_root / "run_inputs.json"

    @property
    def snapshot_manifest(self) -> Path:
        return self.run_root / "model_snapshot_manifest.json"

    @property
    def smoke_fixture(self) -> Path:
        return self.run_root / "smoke_fixture.jsonl"

    @property
    def model_snapshot(self) -> Path:
        return self.run_root / "assets" / "model"

    @property
    def compiled_release(self) -> Path:
        return self.run_root / "compiled_release"

    @property
    def work(self) -> Path:
        return self.run_root / "work"


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    _require_regular_file(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise E0HRunReleaseError(f"expected a regular file: {path}")


def read_json_object(path: Path) -> dict[str, object]:
    _require_regular_file(path)
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise E0HRunReleaseError(f"invalid JSON object at {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise E0HRunReleaseError(f"expected a JSON object at {path}")
    return cast(dict[str, object], parsed)


def read_jsonl(path: Path) -> tuple[dict[str, object], ...]:
    _require_regular_file(path)
    content = path.read_bytes()
    if not content or not content.endswith(b"\n"):
        raise E0HRunReleaseError(f"JSONL must be nonempty and LF-terminated: {path}")
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        try:
            parsed = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise E0HRunReleaseError(
                f"invalid JSONL record at {path}:{line_number}: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise E0HRunReleaseError(f"JSONL record is not an object at {path}:{line_number}")
        record = cast(dict[str, object], parsed)
        if canonical_json_bytes(record).rstrip(b"\n") != line:
            raise E0HRunReleaseError(f"noncanonical JSONL record at {path}:{line_number}")
        records.append(record)
    return tuple(records)


def write_json_no_clobber(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise E0HRunReleaseError(f"refusing to overwrite output: {path}")
    path.write_bytes(canonical_json_bytes(payload))


def write_jsonl_no_clobber(path: Path, records: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise E0HRunReleaseError(f"refusing to overwrite output: {path}")
    content = b"".join(canonical_json_bytes(record) for record in records)
    if not content:
        raise E0HRunReleaseError("refusing to write an empty JSONL artifact")
    path.write_bytes(content)


def load_inputs(paths: RunPaths) -> E0HRunReleaseInputs:
    _require_regular_file(paths.run_inputs)
    return load_e0h_run_release_inputs(paths.run_inputs.read_text(encoding="utf-8"))


def _manifest_files(manifest: dict[str, object]) -> tuple[dict[str, object], ...]:
    raw_files = manifest.get("files")
    if not isinstance(raw_files, list):
        raise E0HRunReleaseError("snapshot manifest files must be a list")
    files: list[dict[str, object]] = []
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise E0HRunReleaseError("snapshot manifest file receipt must be an object")
        receipt = cast(dict[str, object], raw)
        if set(receipt) != {"path", "sha256", "size_bytes"}:
            raise E0HRunReleaseError("snapshot manifest file receipt fields do not match schema")
        if not isinstance(receipt["path"], str):
            raise E0HRunReleaseError("snapshot file path must be a string")
        if not isinstance(receipt["sha256"], str):
            raise E0HRunReleaseError("snapshot file digest must be a string")
        if isinstance(receipt["size_bytes"], bool) or not isinstance(receipt["size_bytes"], int):
            raise E0HRunReleaseError("snapshot file size must be an integer")
        files.append(receipt)
    return tuple(files)


def verify_snapshot_manifest(paths: RunPaths, inputs: E0HRunReleaseInputs) -> dict[str, object]:
    manifest = read_json_object(paths.snapshot_manifest)
    expected_fields = {
        "files",
        "repository",
        "revision",
        "schema_version",
        "snapshot_digest",
        "tokenizer_snapshot_digest",
    }
    if set(manifest) != expected_fields:
        raise E0HRunReleaseError("snapshot manifest fields do not match schema")
    if manifest["schema_version"] != "e0h-hf-snapshot/1":
        raise E0HRunReleaseError("unexpected snapshot manifest schema")
    if manifest["repository"] != "HuggingFaceTB/SmolLM2-135M-Instruct":
        raise E0HRunReleaseError("unexpected model repository")
    if (
        manifest["revision"] != inputs.model.revision
        or inputs.model.revision != inputs.tokenizer.revision
    ):
        raise E0HRunReleaseError("snapshot revision does not match model and tokenizer inputs")

    receipts = _manifest_files(manifest)
    observed_paths = {cast(str, receipt["path"]) for receipt in receipts}
    if observed_paths != _MODEL_FILES:
        raise E0HRunReleaseError(
            f"snapshot file set mismatch; expected={sorted(_MODEL_FILES)}, "
            f"observed={sorted(observed_paths)}"
        )

    full_payload = {
        "schema_version": manifest["schema_version"],
        "repository": manifest["repository"],
        "revision": manifest["revision"],
        "files": list(receipts),
    }
    full_digest = sha256_bytes(
        json.dumps(full_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if manifest["snapshot_digest"] != full_digest:
        raise E0HRunReleaseError("snapshot manifest digest mismatch")

    tokenizer_receipts = [
        receipt for receipt in receipts if cast(str, receipt["path"]) in _TOKENIZER_FILES
    ]
    tokenizer_payload = {
        "schema_version": "e0h-hf-tokenizer-snapshot/1",
        "repository": manifest["repository"],
        "revision": manifest["revision"],
        "files": tokenizer_receipts,
    }
    tokenizer_digest = sha256_bytes(
        json.dumps(tokenizer_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if manifest["tokenizer_snapshot_digest"] != tokenizer_digest:
        raise E0HRunReleaseError("tokenizer snapshot digest mismatch")
    if inputs.tokenizer.content_digest != tokenizer_digest:
        raise E0HRunReleaseError("run inputs do not bind the tokenizer snapshot digest")

    model_receipt = next(receipt for receipt in receipts if receipt["path"] == "model.safetensors")
    if inputs.model.content_digest != model_receipt["sha256"]:
        raise E0HRunReleaseError("run inputs do not bind the model weight digest")
    return manifest


def verify_snapshot_files(paths: RunPaths, manifest: dict[str, object]) -> None:
    if paths.model_snapshot.is_symlink() or not paths.model_snapshot.is_dir():
        raise E0HRunReleaseError(f"model snapshot directory is unavailable: {paths.model_snapshot}")
    receipts = _manifest_files(manifest)
    expected = {cast(str, receipt["path"]) for receipt in receipts}
    observed = {item.name for item in paths.model_snapshot.iterdir()}
    if observed != expected:
        raise E0HRunReleaseError(
            f"model snapshot file set mismatch; expected={sorted(expected)}, "
            f"observed={sorted(observed)}"
        )
    for receipt in receipts:
        name = cast(str, receipt["path"])
        expected_digest = cast(str, receipt["sha256"])
        expected_size = cast(int, receipt["size_bytes"])
        path = paths.model_snapshot / name
        _require_regular_file(path)
        if path.stat().st_size != expected_size:
            raise E0HRunReleaseError(f"snapshot file size mismatch: {name}")
        if sha256_file(path) != expected_digest:
            raise E0HRunReleaseError(f"snapshot file digest mismatch: {name}")


def verify_static_inputs(paths: RunPaths, *, require_snapshot: bool) -> E0HRunReleaseInputs:
    inputs = load_inputs(paths)
    manifest = verify_snapshot_manifest(paths, inputs)
    repo = paths.repository_root
    dataset_paths = {
        repo / inputs.dataset.manifest_path: inputs.dataset.manifest_digest,
        repo / inputs.dataset.sft_path: inputs.dataset.sft_digest,
        repo / inputs.dataset.preference_path: inputs.dataset.preference_digest,
        paths.smoke_fixture: inputs.evaluation.smoke_fixture_digest,
    }
    for path, expected_digest in dataset_paths.items():
        if sha256_file(path) != expected_digest:
            raise E0HRunReleaseError(f"static input digest mismatch: {path}")
    if require_snapshot:
        verify_snapshot_files(paths, manifest)
    return inputs


def assert_python_version(expected: str) -> None:
    observed = ".".join(str(part) for part in sys.version_info[:3])
    if observed != expected:
        raise E0HRunReleaseError(
            f"Python version mismatch; expected={expected}, observed={observed}"
        )


def assert_empty_output_directory(path: Path) -> None:
    if path.is_symlink():
        raise E0HRunReleaseError(f"output directory cannot be a symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise E0HRunReleaseError(f"output path is not a directory: {path}")
        if any(path.iterdir()):
            raise E0HRunReleaseError(f"output directory is not empty: {path}")
    else:
        path.mkdir(parents=True)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise E0HRunReleaseError(f"refusing to overwrite output: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(content)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
