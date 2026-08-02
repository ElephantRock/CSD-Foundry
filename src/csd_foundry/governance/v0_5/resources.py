"""Locate and load frozen v0.5 resources in editable and wheel installations."""

from __future__ import annotations

import json
import sysconfig
from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any

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
