from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from csd_foundry.governance.v0_5 import (
    CONTRACT_TYPES,
    GovernanceContractError,
    canonical_bytes,
    parse_contract,
    validate_governance_contracts,
)
from csd_foundry.governance.v0_5.contracts import FrozenObject, RawEvent, contract_schema
from csd_foundry.governance.v0_5.resources import contract_vectors
from csd_foundry.governance.v0_5.validation import generated_contract_fixture

_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_report_matches_frozen_standalone_report() -> None:
    expected = json.loads((_ROOT / "reports/contract_freeze_v0.5.json").read_text(encoding="utf-8"))
    report = validate_governance_contracts("v0.5")
    assert report.success
    assert report.to_dict() == expected


def test_all_typed_contracts_reproduce_frozen_digests() -> None:
    expected = contract_vectors()["contract_fixture_digests"]
    assert set(CONTRACT_TYPES) == set(expected)
    for name, contract_type in CONTRACT_TYPES.items():
        contract = generated_contract_fixture(name)
        assert type(contract) is contract_type
        assert contract.digest == expected[name]
        assert parse_contract(name, contract.to_json_value()) == contract


def test_canonicalization_vectors_are_exact() -> None:
    for vector in contract_vectors()["canonicalization_vectors"]:
        assert canonical_bytes(vector["value"], vector["schema"]) == base64.b64decode(
            vector["expected_canonical_utf8_base64"]
        )


def test_contract_values_are_immutable() -> None:
    contract = generated_contract_fixture("raw-event")
    with pytest.raises(FrozenInstanceError):
        contract.value = contract.value  # type: ignore[misc]


def test_direct_typed_construction_is_still_validated() -> None:
    with pytest.raises(GovernanceContractError) as rejected:
        RawEvent(FrozenObject((("schema_version", "raw-event/1"),)))
    assert rejected.value.code == "SCHEMA_REJECTED"


def test_schema_results_are_isolated_from_callers() -> None:
    mutated = contract_schema("raw-event")
    mutated["additionalProperties"] = True
    assert contract_schema("raw-event")["additionalProperties"] is False


def test_composite_collection_members_compare_only_by_canonical_bytes() -> None:
    item_schema = {
        "type": "object",
        "properties": {"a": {"type": "integer"}},
        "additionalProperties": False,
    }
    with pytest.raises(GovernanceContractError) as duplicate:
        canonical_bytes(
            [{"a": 1}, {"a": 1}],
            {
                "type": "array",
                "x-csd-collection-kind": "SET",
                "items": item_schema,
            },
        )
    assert duplicate.value.code == "DUPLICATE_SET_MEMBER"
    assert canonical_bytes(
        [{"a": 1}, {"a": 1}],
        {
            "type": "array",
            "x-csd-collection-kind": "MULTISET",
            "items": item_schema,
        },
    ) == b'[{"a":1},{"a":1}]\n'


def test_duplicate_set_and_float_fail_with_stable_codes() -> None:
    with pytest.raises(GovernanceContractError) as duplicate:
        canonical_bytes(
            ["a", "a"],
            {
                "type": "array",
                "x-csd-collection-kind": "SET",
                "items": {"type": "string"},
            },
        )
    assert duplicate.value.code == "DUPLICATE_SET_MEMBER"

    with pytest.raises(GovernanceContractError) as floating:
        canonical_bytes(
            {"schema_version": "x/1", "x": 1.5},
            {
                "type": "object",
                "properties": {
                    "schema_version": {"type": "string"},
                    "x": {"type": "number"},
                },
            },
        )
    assert floating.value.code == "FLOAT_PROHIBITED"
