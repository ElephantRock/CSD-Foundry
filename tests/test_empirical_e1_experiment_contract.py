"""Tests for the repository-side E1 experiment selection contract."""

from collections.abc import Iterable
from dataclasses import replace

import pytest

from csd_foundry.empirical.e1 import (
    E1ExperimentContract,
    E1Split,
    FamilySplitError,
    compile_e1_experiment_contract,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import ScenarioSpec
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_SOURCE_COMMIT = "94fb719c89a1adbc97a5c1e188c1c038e7253dab"
_RELEASE = "e1-candidate/1"


def _compile(scenarios: Iterable[ScenarioSpec] | None = None) -> E1ExperimentContract:
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
        split: sum(len(item.scenario_ids) for item in assignments if item.split is split)
        for split in E1Split
    }

    assert contract.eligible_scenario_count == 18
    assert contract.excluded_source_test_scenario_ids == ("H-01", "L-01", "M-15")
    assert contract.excluded_source_test_scenario_count == 3
    assert scenario_counts == {E1Split.TRAIN: 14, E1Split.DEVELOPMENT: 4}
    assert all("test" not in item.source_splits for item in assignments)
    assert contract.to_dict()["source_split_policy"] == {
        "train": "train",
        "validation": "development",
        "test": "excluded_source_test",
    }
    assert "outside the working repository" in str(contract.to_dict()["claim_boundary"])


def test_contract_is_independent_of_input_order() -> None:
    scenarios = tuple(SCENARIOS.values())

    assert _compile(scenarios) == _compile(reversed(scenarios))


def test_excluded_source_test_semantics_are_not_derived_into_e1_contract() -> None:
    scenarios = list(SCENARIOS.values())
    excluded_index = next(index for index, item in enumerate(scenarios) if item.split == "test")
    excluded = scenarios[excluded_index]
    scenarios[excluded_index] = replace(
        excluded,
        rule_ids=frozenset(),
        family="changed-source-test-family",
        source_section="changed source test content",
    )

    assert _compile(scenarios).contract_digest == _compile().contract_digest


def test_excluded_source_test_identity_change_changes_contract_digest() -> None:
    scenarios = list(SCENARIOS.values())
    excluded_index = next(index for index, item in enumerate(scenarios) if item.split == "test")
    scenarios[excluded_index] = replace(
        scenarios[excluded_index],
        scenario_id="RENAMED-SOURCE-TEST",
    )

    assert _compile(scenarios).contract_digest != _compile().contract_digest


def test_symbolic_family_may_not_cross_source_train_validation_boundary() -> None:
    base = SCENARIOS["M-01"]
    crossing = replace(
        base,
        scenario_id="M-01-VALIDATION-CLONE",
        split="validation",
    )

    with pytest.raises(FamilySplitError, match="cross source train/validation"):
        _compile((*SCENARIOS.values(), crossing))


def test_contract_rejects_unknown_split_and_missing_source_test_partition() -> None:
    scenarios = tuple(SCENARIOS.values())
    first = scenarios[0]
    unknown = (replace(first, split="unknown"), *scenarios[1:])

    with pytest.raises(FamilySplitError, match="unsupported E1 source splits"):
        _compile(unknown)

    without_source_test = tuple(item for item in scenarios if item.split != "test")
    with pytest.raises(FamilySplitError, match="excluded source test partition"):
        _compile(without_source_test)


def test_contract_constructor_rejects_forged_source_split_mapping() -> None:
    contract = _compile()
    assignments = list(contract.split_manifest.assignments)
    development_index = next(
        index for index, item in enumerate(assignments) if item.split is E1Split.DEVELOPMENT
    )
    assignments[development_index] = replace(
        assignments[development_index],
        source_splits=("train",),
    )
    forged_manifest = replace(
        contract.split_manifest,
        assignments=tuple(assignments),
    )

    with pytest.raises(FamilySplitError, match="contradicts the source split policy"):
        replace(contract, split_manifest=forged_manifest)


def test_contract_constructor_rejects_noncanonical_excluded_ids() -> None:
    contract = _compile()

    with pytest.raises(FamilySplitError, match="must be unique"):
        replace(
            contract,
            excluded_source_test_scenario_ids=("H-01", "H-01"),
        )

    with pytest.raises(FamilySplitError, match="must be sorted"):
        replace(
            contract,
            excluded_source_test_scenario_ids=("M-15", "H-01", "L-01"),
        )


def test_contract_digest_binds_policy_manifest_counts_ids_and_claim_boundary() -> None:
    payload = _compile().to_dict()
    digest = payload.pop("contract_digest")

    assert canonical_sha256(payload) == digest

    changed = dict(payload)
    changed["excluded_source_test_scenario_count"] = 0
    assert canonical_sha256(changed) != digest

    changed = dict(payload)
    changed["excluded_source_test_scenario_ids"] = ["OTHER"]
    assert canonical_sha256(changed) != digest

    changed = dict(payload)
    changed["claim_boundary"] = "E1 proves general reasoning transfer."
    assert canonical_sha256(changed) != digest
