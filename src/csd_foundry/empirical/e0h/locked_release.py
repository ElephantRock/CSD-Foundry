"""Self-describing E0-H run-release compilation over the validated base contract."""

from __future__ import annotations

from typing import cast

from csd_foundry.empirical.e0h.run_release import (
    E0HRunReleaseBundle,
    E0HRunReleaseInputs,
)
from csd_foundry.empirical.e0h.run_release import (
    compile_e0h_run_release as _compile_base_release,
)
from csd_foundry.empirical.e1.foundry_artifact_compiler import ArtifactFile
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
    load_json_text,
)

_INPUT_LOCK_PATH = "run_inputs_lock.json"
_MANIFEST_PATH = "artifact_manifest.json"
_RECEIPT_PATH = "reconstruction_receipt.json"
_CONTRACT_PATH = "e0h_run_contract.json"


def _object(content: bytes, *, field: str) -> dict[str, object]:
    parsed = load_json_text(content.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{field} is not an object")
    return cast(dict[str, object], parsed)


def _artifact(path: str, role: str, payload: dict[str, object]) -> ArtifactFile:
    return ArtifactFile(path, role, canonical_json_bytes(payload))


def compile_e0h_run_release(inputs: E0HRunReleaseInputs) -> E0HRunReleaseBundle:
    """Compile a self-describing release containing the exact canonical input lock."""

    base = _compile_base_release(inputs)
    input_lock = _artifact(_INPUT_LOCK_PATH, "run_inputs_lock", inputs.to_dict())

    contract_payload = _object(base.file(_CONTRACT_PATH).content, field="run contract")
    contract_payload["run_inputs_lock_digest"] = input_lock.sha256
    run_contract_digest = canonical_sha256(contract_payload)
    contract_file = _artifact(_CONTRACT_PATH, "e0h_run_contract", contract_payload)

    primary_files = tuple(
        sorted(
            (
                *(
                    item
                    for item in base.files
                    if item.path not in {_CONTRACT_PATH, _MANIFEST_PATH, _RECEIPT_PATH}
                ),
                contract_file,
                input_lock,
            ),
            key=lambda item: item.path,
        )
    )

    manifest_payload = _object(base.file(_MANIFEST_PATH).content, field="artifact manifest")
    manifest_payload["run_contract_digest"] = run_contract_digest
    manifest_payload["files"] = [item.receipt() for item in primary_files]
    manifest_payload["file_count"] = len(primary_files)
    manifest_file = _artifact(_MANIFEST_PATH, "artifact_manifest", manifest_payload)

    receipt_payload = _object(base.file(_RECEIPT_PATH).content, field="reconstruction receipt")
    receipt_payload["run_contract_digest"] = run_contract_digest
    receipt_payload["artifact_manifest_digest"] = manifest_file.sha256
    receipt_file = _artifact(_RECEIPT_PATH, "reconstruction_receipt", receipt_payload)

    files = tuple(sorted((*primary_files, manifest_file, receipt_file), key=lambda item: item.path))
    return E0HRunReleaseBundle(
        release=base.release,
        source_commit=base.source_commit,
        run_contract_digest=run_contract_digest,
        files=files,
    )
