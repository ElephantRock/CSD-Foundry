"""Tests for the repository-side E1 experiment selection contract."""

from dataclasses import replace

import pytest

from csd_foundry.empirical.e1 import (
    E1Split,
    FamilySplitError,
    compile_e1_experiment_contract,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_SOURCE_COMMIT = "94fb719c89a1adbc97a5c1e188c1c038e7253dab"
_RELEASE = "e1-candidate/1"


def _compile(scenarios: object = None):  # type: ignore[no-untyped-def]
    selected = SCENARIOS.values() if scenarios is None else scenarios
    return compile_e1_experiment_contract(
        selected,
        release=_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def test_current_catalog_compiles_expected_candidate_partition() -> None:
    contract = _compile()
    assignments = contract.split_manifest.assignments
    scenario_counts = {
        split: sum(
            len(item.scenario_ids) for item in assignments if item.split is split
        )
        for split in E1Split
    }

    assert contract.eligible_scenario_count == 18
    assert contract.excluded_blind_scenario_count == 3
    assert scenario_counts == {E1Split.TRAIN: 14, E1Split.DEVELOPMENT: 4}
    assert all("test" not in item.source_splits for item in assignments)
    assert contract.to_dict()["source_split_policy"] == {
        "train": "train",
        "validation": "development",
        "test": "excluded_blind",
    }


def test_contract_is_independent_of_input_order() -> None:
    scenarios = tuple(SCENARIOS.values())

    assert _compile(scenarios) == _compile(reversed(scenarios))


def test_blind_semantic_content_is_not_derived_into_e1_contract() -> None:
    scenarios = list(SCENARIOS.values())
    blind_index = next(index for index, item in enumerate(scenarios) if item.split == "test")
    blind = scenarios[blind_index]
    scenarios[blind_index] = replace(
        blind,
        rule_ids=frozenset(),
        family="changed-blind-family",
        source_section="changed blind content",
    )

    assert _compile(scenarios).contract_digest == _compile().contract_digest


def test_symbolic_family_may_not_cross_source_train_validation_boundary() -> None:
    base = SCENARIOS["M-01"]
    crossing = replace(
        base,
        scenario_id="M-01-VALIDATION-CLONE",
        split="validation",
    )

    with pytest.raises(FamilySplitError, match="cross source train/validation"):
        _compile((*SCENARIOS.values(), crossing))


def test_contract_rejects_unknown_split_and_missing_blind_partition() -> None:
    scenarios = tuple(SCENARIOS.values())
    first = scenarios[0]
    unknown = (replace(first, split="unknown"), *scenarios[1:])

    with pytest.raises(FamilySplitError, match="unsupported E1 source splits"):
        _compile(unknown)

    without_blind = tuple(item for item in scenarios if item.split != "test")
    with pytest.raises(FamilySplitError, match="excluded blind source split"):
        _compile(without_blind)


def test_contract_digest_binds_policy_manifest_counts_and_claim_boundary() -> None:
    payload = _compile().to_dict()
    digest = payload.pop("contract_digest")

    assert canonical_sha256(payload) == digest

    changed = dict(payload)
    changed["excluded_blind_scenario_count"] = 0
    assert canonical_sha256(changed) != digest

    changed = dict(payload)
    changed["claim_boundary"] = "E1 proves general reasoning transfer."
    assert canonical_sha256(changed) != digest
