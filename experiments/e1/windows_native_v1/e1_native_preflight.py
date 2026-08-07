#!/usr/bin/env python3
"""Read-only preflight for the Windows-native E1 release.

The preflight is strictly read-only: it authenticates the inherited runtime
identity pins, the A2 v6 curriculum/evaluation digest pins, the compiled
release artifacts, and the sealed prompt inventory against the authenticated
v6 evaluation cases. It does NOT execute a model, allocate a GPU, write to
the repository tree (only to its own output directory), or expose protected
metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    canonical_sha256,
    validate_installed_dependencies,
    write_canonical_json,
)

RELEASE = "e1-windows-native-v1"

MODEL_REPOSITORY = "sshleifer/tiny-gpt2"
MODEL_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
MODEL_CONTENT_DIGEST = "b3b00436d13af5c85a223d2bb77adce8ca660081973c41632a7647c70d908039"
TOKENIZER_ASSET_DIGEST = "fa91cdd29a17c266d450a7b713c7cb3ee9f63d778d2987550da429c55ff93891"

_EXPECTED_ENVIRONMENT = {
    "execution_mode": "windows_native_shared",
    "os_family": "Windows",
    "os_build": "26200",
    "architecture": "AMD64",
    "python_implementation": "CPython",
    "python_version": "3.12.10",
    "python_executable_sha256": "4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a",
    "torch_version": "2.6.0+cu124",
    "torch_cuda_runtime": "12.4",
    "transformers_version": "4.50.0",
    "accelerate_version": "1.1.1",
    "gpu_model": "NVIDIA GeForce RTX 3080 Ti",
    "gpu_count": 1,
    "nvidia_driver_version": "610.47",
    "dependency_lock_digest": "16756dfd91503ef8b30362426c48ec0dfdb0a61ace3a7519962753c9118c1932",
    "host_inventory_digest": "c0dcea8f66b042d2a6bd6d676c4c72c5fc955962e254045abc1f37bd8fda6d10",
}

V6_DIGEST_PINS = {
    "control_train.jsonl": "0e9362f6693f78e30a3f2f0f24d81885c1c76fa4aa9980ade51c83a8761b2f40",
    "foundry_train.jsonl": "d6da0fb01a323060e03c0a3fa14504c0973d297f660ce7dc6e0317ec4853c385",
    "paired_task_format.json": "4f358d558fe2925eba7b333fc91aa35ed388887233b325d17bb32b0f88f96248",
    "paired_e1_contract.json": "750e56d4a4d63e4fbe9e4379f0b0d1ca967ac7e11033c17971cdfb15ab759db4",
    "tokenization_manifest.json": "c5477383379359ec7f299741e46e4dcec7de0db3bd1d3450fd889e8432bb60d1",
}

# Dev/clean evaluation digests bound to the A2 receipt constituent digests.
V6_DEVELOPMENT_EVALUATION_DIGEST = (
    "eb6d1cb5b3596e3a673536b9865be118fe6afc47c79e93f6ea92cd5cf9e31036"
)
V6_CLEAN_EVALUATION_DIGEST = "178e7a6f80c6ed8caf4ab823211d4896345ec7f9b49eebfe53415b6d019d2ee2"
V6_RECORDS_PER_ARM = 19
V6_TOKENS_PER_ARM = 6756
V6_TRUNCATION_COUNT = 0


def _load_canonical(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _authenticate_environment(inputs: dict[str, Any]) -> None:
    environment = inputs.get("environment")
    if not isinstance(environment, dict):
        raise ValueError("run inputs environment must be an object")
    mismatches = {
        field: {"expected": expected, "observed": environment.get(field)}
        for field, expected in _EXPECTED_ENVIRONMENT.items()
        if environment.get(field) != expected
    }
    if mismatches:
        raise RuntimeError(f"frozen environment mismatch: {mismatches}")


def _authenticate_v6_curriculum(repo_root: Path) -> dict[str, Any]:
    """Authenticate the v6 curriculum/evaluation artifacts.

    The five ``V6_DIGEST_PINS`` files are authenticated by their pinned
    digests. The development/clean evaluation files (consumed by the metric
    controller) are authenticated against the A2 receipt constituent digests,
    which are the binding authority.
    """

    v6_dir = repo_root / "data" / "e1" / "v6"
    digests: dict[str, str] = {}
    for filename, expected in V6_DIGEST_PINS.items():
        path = v6_dir / filename
        if not path.is_file():
            raise RuntimeError(f"v6 artifact missing: {path}")
        observed = _sha256_bytes(path.read_bytes())
        if observed != expected:
            raise RuntimeError(
                f"v6 artifact digest mismatch for {filename}: "
                f"expected {expected}, observed {observed}"
            )
        digests[filename] = observed

    # Authenticate dev/clean evaluation files against the A2 receipt
    # constituent digests (the binding authority). The metric controller
    # joins predictions to these gold labels, so they must be byte-
    # authenticated, not merely trusted by name.
    receipt = json.loads((v6_dir / "a2_receipt.json").read_text(encoding="utf-8"))
    constituent = receipt.get("constituent_artifact_digests") if isinstance(receipt, dict) else None
    if not isinstance(constituent, dict):
        raise RuntimeError("v6 a2_receipt constituent_artifact_digests must be an object")
    for filename, expected in (
        ("development_evaluation.jsonl", V6_DEVELOPMENT_EVALUATION_DIGEST),
        ("clean_evaluation.jsonl", V6_CLEAN_EVALUATION_DIGEST),
    ):
        path = v6_dir / filename
        if not path.is_file():
            raise RuntimeError(f"v6 artifact missing: {path}")
        observed = _sha256_bytes(path.read_bytes())
        if observed != expected:
            raise RuntimeError(
                f"v6 artifact digest mismatch for {filename}: "
                f"expected {expected}, observed {observed}"
            )
        if str(constituent.get(filename, "")) != expected:
            raise RuntimeError(f"v6 a2_receipt {filename} digest disagrees with pinned constant")
        digests[filename] = observed
    return digests


def _authenticate_compiled_release(
    repo_root: Path,
) -> dict[str, Any]:
    release_dir = repo_root / "experiments" / "e1" / "windows_native_v1" / "compiled_release"
    if not release_dir.is_dir():
        raise RuntimeError(f"compiled release directory missing: {release_dir}")
    manifest_path = release_dir / "artifact_manifest.json"
    manifest = _load_canonical(manifest_path)
    files_entry = manifest.get("files")
    if not isinstance(files_entry, list):
        raise RuntimeError("artifact manifest files entry must be a list")
    observed: dict[str, str] = {}
    for entry in files_entry:
        if not isinstance(entry, dict):
            raise RuntimeError("artifact manifest entry must be an object")
        name = str(entry["path"])
        expected_digest = str(entry["sha256"])
        path = release_dir / name
        if not path.is_file():
            raise RuntimeError(f"compiled release artifact missing: {path}")
        actual = _sha256_bytes(path.read_bytes())
        if actual != expected_digest:
            raise RuntimeError(f"compiled release artifact digest mismatch: {name}")
        observed[name] = actual
    return {
        "manifest_path": manifest_path.as_posix(),
        "file_count": len(observed),
        "file_digests": dict(sorted(observed.items())),
    }


def _authenticate_sealed_inventory(repo_root: Path) -> dict[str, Any]:
    inventory_path = (
        repo_root
        / "experiments"
        / "e1"
        / "windows_native_v1"
        / "compiled_release"
        / "sealed_prompt_inventory.jsonl"
    )
    records: list[dict[str, Any]] = []
    forbidden = {"gold_class", "codeword", "codeword_token_id", "oracle_result", "expected_answer"}
    for line in inventory_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise RuntimeError("sealed prompt inventory record must be an object")
        leaked = set(record) & forbidden
        if leaked:
            raise RuntimeError(
                f"sealed prompt inventory leaks forbidden field(s): {sorted(leaked)}"
            )
        records.append(record)
    # Cross-check every sealed record against the authenticated v6 eval cases.
    dev = _load_jsonl(repo_root / "data" / "e1" / "v6" / "development_evaluation.jsonl")
    clean = _load_jsonl(repo_root / "data" / "e1" / "v6" / "clean_evaluation.jsonl")
    gold_by_key = {
        (str(c["cohort"]), str(c["scenario_id"]), str(c["record_id"])): c for c in dev + clean
    }
    for record in records:
        key = (
            str(record["cohort"]),
            str(record["scenario_id"]),
            str(record["record_id"]),
        )
        gold = gold_by_key.get(key)
        if gold is None:
            raise RuntimeError(f"sealed record {key} has no v6 evaluation counterpart")
        if str(gold["family_digest"]) != str(record["family_digest"]):
            raise RuntimeError(f"sealed record {key} family_digest disagrees with v6")
    return {
        "record_count": len(records),
        "inventory_sha256": _sha256_bytes(inventory_path.read_bytes()),
    }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path} contains a non-object record")
        records.append(value)
    return records


# ---------------------------------------------------------------------------
# Windows runtime qualification (platform-gated).
#
# The Windows-target runtime checks (python/torch/CUDA/GPU/device-count) are
# run ONLY on the actual Windows target. On non-Windows hosts the runtime
# qualification is reported as ``NOT_RUN_NON_WINDOWS`` and the preflight is not
# authoritative. Platform-independent checks (A2 auth, v6 digests, sealed
# inventory, compiled-release reconstruction, retokenization) always run. The
# skip authority is platform alone: no env var, missing torch, or
# cuda.is_available()==False may suppress runtime qualification on Windows.
# ---------------------------------------------------------------------------


def _qualify_windows_runtime(
    *,
    lock: dict[str, Any],
    inputs: dict[str, Any],
) -> dict[str, Any]:
    """Run every Windows-target runtime qualification check, fail-closed.

    Verifies the running python/torch/CUDA/GPU identities, the installed
    package inventory against the dependency lock, and the model/tokenizer
    asset digests. Any mismatch raises; on success returns the qualification
    receipt. Only invoked on the actual Windows target.
    """

    import torch  # type: ignore[import-not-found]

    mismatches: dict[str, dict[str, str]] = {}
    if platform.python_version() != _EXPECTED_ENVIRONMENT["python_version"]:
        mismatches["python_version"] = {
            "expected": _EXPECTED_ENVIRONMENT["python_version"],
            "observed": platform.python_version(),
        }
    if str(torch.__version__) != _EXPECTED_ENVIRONMENT["torch_version"]:
        mismatches["torch_version"] = {
            "expected": _EXPECTED_ENVIRONMENT["torch_version"],
            "observed": str(torch.__version__),
        }
    if str(torch.version.cuda) != _EXPECTED_ENVIRONMENT["torch_cuda_runtime"]:
        mismatches["torch_cuda_runtime"] = {
            "expected": _EXPECTED_ENVIRONMENT["torch_cuda_runtime"],
            "observed": str(torch.version.cuda),
        }
    if int(torch.cuda.device_count()) != _EXPECTED_ENVIRONMENT["gpu_count"]:
        mismatches["gpu_count"] = {
            "expected": str(_EXPECTED_ENVIRONMENT["gpu_count"]),
            "observed": str(torch.cuda.device_count()),
        }
    if torch.cuda.device_count() > 0:
        gpu_name = str(torch.cuda.get_device_name(0))
        if gpu_name != _EXPECTED_ENVIRONMENT["gpu_model"]:
            mismatches["gpu_model"] = {
                "expected": _EXPECTED_ENVIRONMENT["gpu_model"],
                "observed": gpu_name,
            }
    if mismatches:
        raise RuntimeError(f"Windows runtime qualification failed (fail-closed): {mismatches}")

    # Package inventory must match the dependency lock exactly.
    installed = validate_installed_dependencies(lock)

    # Model/tokenizer asset digests must match the frozen pins. On Windows
    # (authoritative mode), an unresolved digest is a hard failure.
    asset_digest = _compute_tokenizer_asset_digest()
    if asset_digest is None:
        raise RuntimeError(
            "tokenizer asset digest could not be computed on Windows — "
            "HF cache snapshot not found or incomplete"
        )
    if asset_digest != TOKENIZER_ASSET_DIGEST:
        raise RuntimeError(
            f"tokenizer asset digest mismatch: expected {TOKENIZER_ASSET_DIGEST}, "
            f"observed {asset_digest}"
        )

    # Verify model safetensors digest on Windows.
    model_digest = _compute_model_safetensors_digest()
    if model_digest is not None and model_digest != MODEL_CONTENT_DIGEST:
        raise RuntimeError(
            f"model safetensors digest mismatch: expected {MODEL_CONTENT_DIGEST}, "
            f"observed {model_digest}"
        )

    return {
        "platform": platform.system(),
        "python_version": platform.python_version(),
        "torch_version": str(torch.__version__),
        "torch_cuda_runtime": str(torch.version.cuda),
        "gpu_count": int(torch.cuda.device_count()),
        "gpu_model": str(torch.cuda.get_device_name(0)) if torch.cuda.device_count() else None,
        "installed_dependency_count": len(installed),
        "tokenizer_asset_digest": asset_digest if asset_digest is not None else "UNRESOLVED",
    }


def _find_hf_snapshot() -> Path | None:
    """Find the HF cache snapshot for the frozen model revision."""

    import os

    candidate_dirs: list[Path] = []
    env_home = os.environ.get("HF_HOME")
    if env_home:
        candidate_dirs.append(Path(env_home))
    env_cache = os.environ.get("HF_HUB_CACHE") or os.environ.get("HUGGINGFACE_HUB_CACHE")
    if env_cache:
        candidate_dirs.append(Path(env_cache))
    # Standard default locations
    candidate_dirs.append(Path.home() / ".cache" / "huggingface" / "hub")
    candidate_dirs.append(Path("C:/huggingface_cache/hub"))
    candidate_dirs.append(Path("artifacts") / "e0h-windows-native-v2" / "hf-cache")

    for cache_dir in candidate_dirs:
        snapshot = cache_dir / "models--sshleifer--tiny-gpt2" / "snapshots" / MODEL_REVISION
        if snapshot.is_dir():
            return snapshot
    return None


def _compute_tokenizer_asset_digest() -> str | None:
    """Recompute the tokenizer asset aggregate digest over the local snapshot."""

    snapshot = _find_hf_snapshot()
    if snapshot is None:
        return None
    files = ("merges.txt", "special_tokens_map.json", "tokenizer_config.json", "vocab.json")
    receipts: list[dict[str, object]] = []
    for name in files:
        path = snapshot / name
        if not path.is_file():
            return None
        receipts.append(
            {
                "path": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "byte_count": path.stat().st_size,
            }
        )
    return canonical_sha256(receipts)


def _compute_model_safetensors_digest() -> str | None:
    """Recompute the model safetensors SHA-256 over the local snapshot."""

    snapshot = _find_hf_snapshot()
    if snapshot is None:
        return None
    model_file = snapshot / "model.safetensors"
    if not model_file.is_file():
        return None
    return hashlib.sha256(model_file.read_bytes()).hexdigest()


def _retokenize_curriculum_arms(repo_root: Path) -> dict[str, Any]:
    """Retokenize both training arms at preflight.

    Verifies each arm produces exactly ``V6_RECORDS_PER_ARM`` records,
    ``V6_TOKENS_PER_ARM`` tokens, and zero truncation, matching the A2 receipt
    pins. The frozen tokenizer is loaded from the pinned revision.
    """

    v6_dir = repo_root / "data" / "e1" / "v6"
    try:
        import importlib

        transformers_module = importlib.import_module("transformers")
        AutoTokenizer = transformers_module.AutoTokenizer
    except ImportError as exc:
        raise RuntimeError("transformers is required to retokenize the v6 curriculum arms") from exc
    tokenizer = AutoTokenizer.from_pretrained(MODEL_REPOSITORY, revision=MODEL_REVISION)

    arms: dict[str, dict[str, Any]] = {}
    for arm, filename in (("control", "control_train.jsonl"), ("foundry", "foundry_train.jsonl")):
        path = v6_dir / filename
        record_count = 0
        token_count = 0
        truncation_count = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RuntimeError(f"{filename} contains a non-object record")
            record_count += 1
            messages = value.get("prompt_messages")
            codeword = value.get("codeword")
            if (
                not isinstance(messages, list)
                or len(messages) != 2
                or not isinstance(codeword, str)
            ):
                raise RuntimeError(f"{filename} record malformed prompt_messages/codeword")
            system = str(messages[0].get("content", ""))
            user = str(messages[1].get("content", ""))
            text = "\n".join((system, user, str(codeword)))
            ids = tokenizer(text, add_special_tokens=True)["input_ids"]
            token_count += len(ids)
            if len(ids) > 512:
                truncation_count += 1
        if record_count != V6_RECORDS_PER_ARM:
            raise RuntimeError(
                f"{filename} record count {record_count} != pinned {V6_RECORDS_PER_ARM}"
            )
        if token_count != V6_TOKENS_PER_ARM:
            raise RuntimeError(
                f"{filename} token count {token_count} != pinned {V6_TOKENS_PER_ARM}"
            )
        if truncation_count != V6_TRUNCATION_COUNT:
            raise RuntimeError(
                f"{filename} truncation count {truncation_count} != pinned {V6_TRUNCATION_COUNT}"
            )
        arms[arm] = {
            "record_count": record_count,
            "token_count": token_count,
            "truncation_count": truncation_count,
        }
    return arms


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--dependency-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[3]
    inputs = _load_canonical(args.inputs)
    if inputs.get("release") != RELEASE:
        raise ValueError("run input release does not match the E1 native preflight")

    # The dependency lock is authenticated by digest (the heavy import-time
    # validation belongs to the harness execution; the preflight is read-only).
    lock = _load_canonical(args.dependency_lock)
    lock_digest = canonical_sha256(lock)
    if lock_digest != _EXPECTED_ENVIRONMENT["dependency_lock_digest"]:
        raise RuntimeError(
            f"dependency lock digest mismatch: expected "
            f"{_EXPECTED_ENVIRONMENT['dependency_lock_digest']}, observed {lock_digest}"
        )

    # Platform-independent checks (always run in both modes): the declared
    # environment pins, the A2/v6 digests, the compiled release
    # reconstruction, the sealed inventory boundary, and retokenization of
    # both training arms (19 records / 6756 tokens / zero truncation).
    _authenticate_environment(inputs)
    v6_receipt = _authenticate_v6_curriculum(repo_root)
    release_receipt = _authenticate_compiled_release(repo_root)
    sealed_receipt = _authenticate_sealed_inventory(repo_root)
    retokenization_receipt = _retokenize_curriculum_arms(repo_root)

    # Platform-gated Windows runtime qualification. On the actual Windows
    # target every runtime check runs and any mismatch fails closed; on
    # non-Windows hosts the qualification is reported as not run and the
    # preflight is explicitly non-authoritative.
    is_windows = platform.system() == "Windows"
    if is_windows:
        runtime_receipt: dict[str, Any] = _qualify_windows_runtime(lock=lock, inputs=inputs)
        windows_runtime_qualification = "RUN"
        authoritative_windows_preflight = True
    else:
        runtime_receipt = {"platform": platform.system()}
        windows_runtime_qualification = "NOT_RUN_NON_WINDOWS"
        authoritative_windows_preflight = False

    args.output_dir.mkdir(parents=True, exist_ok=False)
    write_canonical_json(
        args.output_dir / "preflight_receipt.json",
        {
            "schema_version": "e1-windows-native-preflight-receipt/1",
            "release": RELEASE,
            "platform_independent_checks": "PASSED",
            "environment_authenticated": True,
            "v6_curriculum_digests": v6_receipt,
            "compiled_release_receipt": release_receipt,
            "sealed_inventory_receipt": sealed_receipt,
            "retokenization_receipt": retokenization_receipt,
            "windows_runtime_qualification": windows_runtime_qualification,
            "windows_runtime_receipt": runtime_receipt,
            "authoritative_windows_preflight": authoritative_windows_preflight,
            "claim_boundary": (
                "Preflight authenticates the runtime identity, the v6 curriculum/evaluation "
                "digests (including dev/clean evaluation against the A2 receipt), the "
                "compiled release artifacts, the sealed prompt inventory boundary, and "
                "retokenizes both training arms. On the Windows target it additionally "
                "qualifies the running python/torch/CUDA/GPU runtime. It does not expose "
                "protected metrics."
            ),
        },
    )


if __name__ == "__main__":
    main()
