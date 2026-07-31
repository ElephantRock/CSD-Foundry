from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.runner import validate_release
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


def test_v0_1_scenarios_are_deterministic_across_repeated_runs() -> None:
    first = validate_release(SCENARIOS, "v0.1")
    second = validate_release(SCENARIOS, "v0.1")
    assert first == second


def test_registry_mutations_are_all_killed() -> None:
    report = evaluate_release("v0.1")

    assert report.success, report.to_dict()
    assert report.total == 10
    assert report.killed == 10
    assert report.escaped == 0
    assert report.invalid_canonical == 0
    assert report.covered_invariants
