import json
from dataclasses import replace
from pathlib import Path

from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.runner import run_scenario, validate_release
from csd_foundry.scenarios.spec import TransitionCase
from csd_foundry.scenarios.v0_1.manifest import SCENARIO_METADATA
from csd_foundry.synthesis.scenario_mutations import evaluate_release


def test_v0_1_registry_is_manifest_complete_and_executable() -> None:
    result = validate_release(SCENARIOS, "v0.1")

    assert result.success, result.to_dict()
    assert result.manifest_scenarios == 21
    assert result.registry_scenarios == 21
    assert result.accepted_scenarios == 21
    assert result.oracle_backed_cases == 20
    assert result.observation_cases == 7
    assert result.rejected_transition_cases == 1
    assert result.failed_cases == 0


def test_packaged_manifest_matches_immutable_release_manifest() -> None:
    path = Path(__file__).resolve().parents[1] / "data/seed/v0.1/csd_reasoning_manifest_v0.1.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    release_entries = {
        entry["scenario_id"]: {
            "split": entry["split"],
            "family": entry["family"],
            "source_section": entry["source_section"],
            "rules": frozenset(entry["rules"]),
        }
        for entry in raw["scenarios"]
    }
    packaged_entries = {
        entry.scenario_id: {
            "split": entry.split,
            "family": entry.family,
            "source_section": entry.source_section,
            "rules": entry.rules,
        }
        for entry in SCENARIO_METADATA
    }
    assert packaged_entries == release_entries


def test_v0_1_scenarios_are_deterministic_across_repeated_runs() -> None:
    first = validate_release(SCENARIOS, "v0.1")
    second = validate_release(SCENARIOS, "v0.1")
    assert first == second


def test_sequence_runner_rejects_a_hand_authored_intermediate_divergence() -> None:
    spec = SCENARIOS["M-11"]
    changed_cases = []
    target_id = "M-11/order-a/2-reassess"
    for case in spec.cases:
        if isinstance(case, TransitionCase) and case.case_id == target_id:
            changed_cases.append(
                replace(case, before=replace(case.before, control_id="CTRL-M11-DIVERGED"))
            )
        else:
            changed_cases.append(case)

    result = run_scenario(replace(spec, cases=tuple(changed_cases)))
    target = next(case for case in result.cases if case.case_id == target_id)
    assert not target.accepted
    assert any("preceding oracle post-state" in detail for detail in target.details)


def test_registry_mutations_are_all_killed() -> None:
    report = evaluate_release("v0.1")

    assert report.success, report.to_dict()
    assert report.total == 10
    assert report.killed == 10
    assert report.escaped == 0
    assert report.invalid_canonical == 0
    assert report.covered_invariants
