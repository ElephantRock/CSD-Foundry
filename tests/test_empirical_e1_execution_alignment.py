"""Execution-alignment regressions for E1 symbolic family identities."""

from dataclasses import replace

import pytest

from csd_foundry.empirical.e1 import FamilySplitError, derive_scenario_family_identity
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import TransitionCase


def test_runner_rejected_transition_scenario_fails_closed() -> None:
    scenario = SCENARIOS["M-01"]
    case = scenario.cases[0]
    assert isinstance(case, TransitionCase)

    changed = replace(
        scenario,
        cases=(replace(case, expected_invalidated_evidence=frozenset()),),
    )

    with pytest.raises(FamilySplitError, match="scenario is not executable"):
        derive_scenario_family_identity(changed)


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


def test_broken_cross_step_control_identity_fails_closed() -> None:
    scenario = SCENARIOS["M-11"]
    changed_cases = list(scenario.cases)
    second_case = changed_cases[1]
    assert isinstance(second_case, TransitionCase)

    changed_cases[1] = replace(
        second_case,
        before=replace(second_case.before, control_id="CTRL-M11-DIVERGED"),
    )
    changed = replace(scenario, cases=tuple(changed_cases))

    with pytest.raises(
        FamilySplitError,
        match="declared before state does not equal the preceding oracle post-state",
    ):
        derive_scenario_family_identity(changed)


def test_order_sensitive_sequence_state_must_remain_executable() -> None:
    scenario = SCENARIOS["M-11"]
    changed_cases = list(scenario.cases)
    fourth_case = changed_cases[3]
    assert isinstance(fourth_case, TransitionCase)
    assert len(fourth_case.before.evidence) > 1
    assert len(fourth_case.before.bases) > 1

    changed_cases[3] = replace(
        fourth_case,
        before=replace(
            fourth_case.before,
            evidence=tuple(reversed(fourth_case.before.evidence)),
            bases=tuple(reversed(fourth_case.before.bases)),
        ),
    )
    changed = replace(scenario, cases=tuple(changed_cases))

    with pytest.raises(
        FamilySplitError,
        match="declared before state does not equal the preceding oracle post-state",
    ):
        derive_scenario_family_identity(changed)


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
