"""Execution, comparison, and release-level coverage reporting for scenarios."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from csd_foundry.kernel.invariants import (
    validate_event_transition,
    validate_state,
    validate_transition,
)
from csd_foundry.kernel.oracle import CsdOracle, OracleRejected
from csd_foundry.kernel.transitions import TransitionError
from csd_foundry.scenarios.spec import (
    ExecutableCase,
    ObservationCase,
    RejectedTransitionCase,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)


@dataclass(frozen=True, slots=True)
class CaseResult:
    scenario_id: str
    case_id: str
    case_type: str
    accepted: bool
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario_id: str
    accepted: bool
    cases: tuple[CaseResult, ...]


@dataclass(frozen=True, slots=True)
class ReleaseResult:
    release: str
    manifest_scenarios: int
    registry_scenarios: int
    accepted_scenarios: int
    oracle_backed_cases: int
    observation_cases: int
    rejected_transition_cases: int
    failed_cases: int
    metadata_errors: tuple[str, ...]
    scenarios: tuple[ScenarioResult, ...]

    @property
    def success(self) -> bool:
        return not self.metadata_errors and self.failed_cases == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "manifest_scenarios": self.manifest_scenarios,
            "registry_scenarios": self.registry_scenarios,
            "accepted_scenarios": self.accepted_scenarios,
            "oracle_backed_cases": self.oracle_backed_cases,
            "observation_cases": self.observation_cases,
            "rejected_transition_cases": self.rejected_transition_cases,
            "failed_cases": self.failed_cases,
            "metadata_errors": list(self.metadata_errors),
            "scenarios": [
                {
                    "scenario_id": scenario.scenario_id,
                    "accepted": scenario.accepted,
                    "cases": [
                        {
                            "case_id": case.case_id,
                            "case_type": case.case_type,
                            "accepted": case.accepted,
                            "details": list(case.details),
                        }
                        for case in scenario.cases
                    ],
                }
                for scenario in self.scenarios
            ],
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def manifest_path(release: str) -> Path:
    if release != "v0.1":
        raise ValueError(f"unsupported scenario release: {release}")
    return _project_root() / "data/seed/v0.1/csd_reasoning_manifest_v0.1.json"


def _load_manifest(release: str) -> tuple[dict[str, object], ...]:
    raw = cast(dict[str, object], json.loads(manifest_path(release).read_text(encoding="utf-8")))
    scenarios = cast(list[dict[str, object]], raw["scenarios"])
    return tuple(scenarios)


def _expectation_errors(state: object, expected: StateExpectation) -> tuple[str, ...]:
    from csd_foundry.kernel.models import ControlState

    if not isinstance(state, ControlState):
        return ("internal runner error: expectation target is not ControlState",)

    errors: list[str] = []
    if expected.obligation is not None and state.obligation is not expected.obligation:
        errors.append(
            f"obligation={state.obligation.value}; expected {expected.obligation.value}"
        )
    if expected.source_state is not None and state.source_state is not expected.source_state:
        errors.append(
            f"source_state={state.source_state.value}; expected {expected.source_state.value}"
        )
    if expected.assurance is not None and state.assurance is not expected.assurance:
        errors.append(f"assurance={state.assurance.value}; expected {expected.assurance.value}")

    evidence = state.evidence_by_id()
    for evidence_id, status in expected.evidence_statuses:
        item = evidence.get(evidence_id)
        if item is None:
            errors.append(f"missing evidence {evidence_id}")
        elif item.status is not status:
            errors.append(
                f"evidence {evidence_id} status={item.status.value}; expected {status.value}"
            )
    for evidence_id, outcome in expected.evidence_outcomes:
        item = evidence.get(evidence_id)
        if item is None:
            errors.append(f"missing evidence {evidence_id}")
        elif item.outcome != outcome:
            errors.append(f"evidence {evidence_id} outcome={item.outcome!r}; expected {outcome!r}")

    bases = state.bases_by_id()
    for basis_id, claim in expected.basis_claims:
        basis = bases.get(basis_id)
        if basis is None:
            errors.append(f"missing basis {basis_id}")
        elif basis.claim != claim:
            errors.append(f"basis {basis_id} claim={basis.claim}; expected {claim}")

    if (
        expected.current_source_basis_ids is not None
        and state.current_source_basis_ids != expected.current_source_basis_ids
    ):
        errors.append(
            "current_source_basis_ids="
            f"{sorted(state.current_source_basis_ids)}; expected "
            f"{sorted(expected.current_source_basis_ids)}"
        )
    if (
        expected.current_verdict_basis_ids is not None
        and state.current_verdict_basis_ids != expected.current_verdict_basis_ids
    ):
        errors.append(
            "current_verdict_basis_ids="
            f"{sorted(state.current_verdict_basis_ids)}; expected "
            f"{sorted(expected.current_verdict_basis_ids)}"
        )
    if expected.history_length is not None and len(state.history) != expected.history_length:
        errors.append(f"history_length={len(state.history)}; expected {expected.history_length}")
    if expected.history_event_types is not None:
        observed = tuple(item.event_type for item in state.history)
        if observed != expected.history_event_types:
            errors.append(f"history_event_types={observed!r}; expected {expected.history_event_types!r}")
    return tuple(errors)


def _run_transition(scenario_id: str, case: TransitionCase) -> CaseResult:
    errors: list[str] = []
    oracle = CsdOracle()
    try:
        first = oracle.apply(case.before, case.event)
        second = oracle.apply(case.before, case.event)
    except (OracleRejected, TransitionError, TypeError, ValueError) as exc:
        return CaseResult(
            scenario_id,
            case.case_id,
            "transition",
            False,
            (f"oracle rejected canonical transition: {exc}",),
        )

    if first != second:
        errors.append("transition is not deterministic")
    errors.extend(_expectation_errors(first.after, case.expected))

    if case.expected_invalidated_evidence is not None:
        observed_invalidated = frozenset(first.trace.invalidated_evidence)
        if observed_invalidated != case.expected_invalidated_evidence:
            errors.append(
                f"invalidated_evidence={sorted(observed_invalidated)}; expected "
                f"{sorted(case.expected_invalidated_evidence)}"
            )
    if case.expected_surviving_bases is not None:
        observed_surviving = frozenset(first.trace.surviving_bases)
        if observed_surviving != case.expected_surviving_bases:
            errors.append(
                f"surviving_bases={sorted(observed_surviving)}; expected "
                f"{sorted(case.expected_surviving_bases)}"
            )
    observed_rules = frozenset(first.trace.rules_fired)
    missing_rules = case.required_trace_rules - observed_rules
    if missing_rules:
        errors.append(f"trace is missing required rules: {sorted(missing_rules)}")

    return CaseResult(scenario_id, case.case_id, "transition", not errors, tuple(errors))


def _run_observation(scenario_id: str, case: ObservationCase) -> CaseResult:
    errors = [
        f"{violation.invariant_id}: {violation.message}" for violation in validate_state(case.state)
    ]
    errors.extend(_expectation_errors(case.state, case.expected))
    return CaseResult(scenario_id, case.case_id, "observation", not errors, tuple(errors))


def _run_rejected(scenario_id: str, case: RejectedTransitionCase) -> CaseResult:
    violations = list(validate_transition(case.before, case.proposed_after))
    if case.event is not None:
        violations.extend(validate_event_transition(case.before, case.event, case.proposed_after))
    observed = frozenset(item.invariant_id for item in violations)
    errors: list[str] = []
    if not observed:
        errors.append("proposed invalid transition was accepted")
    missing = case.expected_invariants - observed
    if missing:
        errors.append(
            f"missing expected invariant detections {sorted(missing)}; observed {sorted(observed)}"
        )
    return CaseResult(
        scenario_id,
        case.case_id,
        "rejected_transition",
        not errors,
        tuple(errors),
    )


def run_case(scenario_id: str, case: ExecutableCase) -> CaseResult:
    if isinstance(case, TransitionCase):
        return _run_transition(scenario_id, case)
    if isinstance(case, ObservationCase):
        return _run_observation(scenario_id, case)
    if isinstance(case, RejectedTransitionCase):
        return _run_rejected(scenario_id, case)
    raise TypeError(f"unsupported scenario case: {type(case).__name__}")


def run_scenario(spec: ScenarioSpec) -> ScenarioResult:
    cases = tuple(run_case(spec.scenario_id, case) for case in spec.cases)
    return ScenarioResult(spec.scenario_id, all(case.accepted for case in cases), cases)


def _metadata_errors(
    registry: Mapping[str, ScenarioSpec], manifest: tuple[dict[str, object], ...]
) -> tuple[str, ...]:
    errors: list[str] = []
    manifest_by_id = {str(entry["scenario_id"]): entry for entry in manifest}
    registry_ids = set(registry)
    manifest_ids = set(manifest_by_id)
    missing = manifest_ids - registry_ids
    extra = registry_ids - manifest_ids
    if missing:
        errors.append(f"registry is missing manifest scenarios: {sorted(missing)}")
    if extra:
        errors.append(f"registry has non-manifest scenarios: {sorted(extra)}")

    for scenario_id in sorted(registry_ids & manifest_ids):
        spec = registry[scenario_id]
        entry = manifest_by_id[scenario_id]
        if spec.scenario_id != scenario_id:
            errors.append(f"registry key {scenario_id} disagrees with spec ID {spec.scenario_id}")
        if spec.split != str(entry["split"]):
            errors.append(f"{scenario_id}: split mismatch")
        if spec.family != str(entry["family"]):
            errors.append(f"{scenario_id}: family mismatch")
        if spec.source_section != str(entry["source_section"]):
            errors.append(f"{scenario_id}: source-section mismatch")
        manifest_rules = frozenset(str(rule) for rule in cast(list[object], entry["rules"]))
        if spec.rule_ids != manifest_rules:
            errors.append(
                f"{scenario_id}: rule mismatch; registry={sorted(spec.rule_ids)}, "
                f"manifest={sorted(manifest_rules)}"
            )
        if not spec.cases:
            errors.append(f"{scenario_id}: no executable cases")
    return tuple(errors)


def validate_release(
    registry: Mapping[str, ScenarioSpec], release: str = "v0.1"
) -> ReleaseResult:
    manifest = _load_manifest(release)
    metadata_errors = _metadata_errors(registry, manifest)
    scenarios = tuple(run_scenario(registry[key]) for key in sorted(registry))
    case_results = tuple(case for scenario in scenarios for case in scenario.cases)
    oracle_backed = sum(case.case_type == "transition" for case in case_results)
    observations = sum(case.case_type == "observation" for case in case_results)
    rejected = sum(case.case_type == "rejected_transition" for case in case_results)
    failed = sum(not case.accepted for case in case_results)
    return ReleaseResult(
        release=release,
        manifest_scenarios=len(manifest),
        registry_scenarios=len(registry),
        accepted_scenarios=sum(scenario.accepted for scenario in scenarios),
        oracle_backed_cases=oracle_backed,
        observation_cases=observations,
        rejected_transition_cases=rejected,
        failed_cases=failed,
        metadata_errors=metadata_errors,
        scenarios=scenarios,
    )
