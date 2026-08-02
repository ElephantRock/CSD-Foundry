"""Locate and load frozen v0.5 resources in editable and wheel installations."""

from __future__ import annotations

import json
import sysconfig
from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any, cast

from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError


def resource_root() -> Path:
    """Return the repository root or installed shared-data root."""

    repository = Path(__file__).resolve().parents[4]
    if (repository / "specs/v0.5/contract_catalog_v1.json").is_file():
        return repository
    installed = Path(sysconfig.get_path("data")) / "share" / "csd-foundry"
    if (installed / "specs/v0.5/contract_catalog_v1.json").is_file():
        return installed
    raise GovernanceContractError("V0_5_RESOURCES_UNAVAILABLE")


@cache
def _load_json_cached(relative_path: str) -> dict[str, Any]:
    if type(relative_path) is not str or not relative_path:
        raise GovernanceContractError("RESOURCE_PATH_INVALID")
    path = resource_root() / relative_path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceContractError("RESOURCE_LOAD_FAILED", relative_path) from exc
    if type(value) is not dict:
        raise GovernanceContractError("RESOURCE_ROOT_NOT_OBJECT", relative_path)
    return value


def load_json(relative_path: str) -> dict[str, Any]:
    return deepcopy(_load_json_cached(relative_path))


def contract_catalog() -> dict[str, Any]:
    return load_json("specs/v0.5/contract_catalog_v1.json")


def canonicalization_policy() -> dict[str, Any]:
    return load_json("specs/v0.5/canonicalization_policy_v1.json")


def projection_phase_policy() -> dict[str, Any]:
    return load_json("specs/v0.5/projection_phase_order_v1.json")


def charter_invariants() -> dict[str, Any]:
    return load_json("specs/v0.5/charter_invariants_v1.json")


def rejection_code_registry() -> dict[str, Any]:
    return load_json("specs/v0.5/rejection_code_registry_v1.json")


def api_contracts() -> dict[str, Any]:
    return load_json("specs/v0.5/api_contracts_v1.json")


def contract_vectors() -> dict[str, Any]:
    return load_json("data/canary/v0.5/contract-v1/contract_vectors.json")


def admission_vectors() -> dict[str, Any]:
    return load_json("data/canary/v0.5/admission-v1/admission_vectors.json")


def temporal_vectors() -> dict[str, Any]:
    return load_json("data/canary/v0.5/temporal-v1/temporal_vectors.json")


def evidence_vectors() -> dict[str, Any]:
    """Assemble the committed evidence vector catalog from its manifest and canaries."""

    base = "data/canary/v0.5/evidence-v1"
    manifest = load_json(f"{base}/manifest.json")
    if manifest.get("schema_version") != "evidence-conformance-manifest/0.5":
        raise GovernanceContractError("EVIDENCE_VECTOR_MANIFEST_SCHEMA_INVALID")
    accepted_files = _manifest_files(manifest, "accepted_files")
    rejected_files = _manifest_files(manifest, "rejected_files")
    return {
        "schema_version": manifest.get("vector_schema_version"),
        "vector_version": manifest.get("vector_version"),
        "authority_policy": deepcopy(manifest.get("authority_policy")),
        "challenge_policy": deepcopy(manifest.get("challenge_policy")),
        "accepted_vectors": [load_json(f"{base}/{name}") for name in accepted_files],
        "rejected_vectors": [load_json(f"{base}/{name}") for name in rejected_files],
        "claim_boundary": manifest.get("claim_boundary"),
        "catalog_digest": manifest.get("catalog_digest"),
    }


def _manifest_files(manifest: dict[str, Any], field: str) -> tuple[str, ...]:
    value = manifest.get(field)
    if type(value) is not list or any(type(item) is not str for item in value):
        raise GovernanceContractError("EVIDENCE_VECTOR_MANIFEST_FILES_INVALID", field)
    names = tuple(cast(list[str], value))
    if not names or len(set(names)) != len(names):
        raise GovernanceContractError("EVIDENCE_VECTOR_MANIFEST_FILES_INVALID", field)
    for name in names:
        if not name.endswith(".json") or "/" in name or "\\" in name or name in {".", ".."}:
            raise GovernanceContractError("EVIDENCE_VECTOR_MANIFEST_FILE_INVALID", name)
    return names
