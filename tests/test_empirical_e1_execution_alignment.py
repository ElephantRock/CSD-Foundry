"""Execution-alignment regressions for E1 symbolic family identities."""

from dataclasses import replace

import pytest

from csd_foundry.empirical.e1 import FamilySplitError, derive_scenario_family_identity
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import TransitionCase


def test_consistent_sequence_control_renaming_is_identity_invariant() -> None:
    scenario = SCENARIOS["M-11"]
    control_labels: dict[str, str] = {}
    renamed_cases = []

    for case in scenario.cases:
        assert isinstance(case, TransitionCase)
        original_control = case.before.control_id
        if original_control not in control_labels:
            control_labels[original_control] = f"RENAMED-CONTROL-{len(control_labels)}"
        renamed_cases.append(
            replace(
                case,
                before=replace(
                    case.before,
                    control_id=control_labels[original_control],
                ),
            )
        )

    renamed = replace(scenario, cases=tuple(renamed_cases))

    assert (
        derive_scenario_family_identity(scenario).family_digest
        == derive_scenario_family_identity(renamed).family_digest
    )


def test_broken_cross_step_control_identity_changes_family_digest() -> None:
    scenario = SCENARIOS["M-11"]
    changed_cases = list(scenario.cases)
    second_case = changed_cases[1]
    assert isinstance(second_case, TransitionCase)

    changed_cases[1] = replace(
        second_case,
        before=replace(second_case.before, control_id="CTRL-M11-DIVERGED"),
    )
    changed = replace(scenario, cases=tuple(changed_cases))

    assert (
        derive_scenario_family_identity(scenario).family_digest
        != derive_scenario_family_identity(changed).family_digest
    )


def test_sequence_step_grammar_matches_runner_hyphen_rule() -> None:
    scenario = SCENARIOS["M-11"]
    changed_cases = list(scenario.cases)
    second_case = changed_cases[1]
    assert isinstance(second_case, TransitionCase)
    assert "2-" in second_case.case_id

    changed_cases[1] = replace(
        second_case,
        case_id=second_case.case_id.replace("2-", "2_", 1),
    )
    changed = replace(scenario, cases=tuple(changed_cases))

    with pytest.raises(FamilySplitError, match="has no numeric step"):
        derive_scenario_family_identity(changed)
