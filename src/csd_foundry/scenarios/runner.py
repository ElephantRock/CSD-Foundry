"""Execution, comparison, and release-level coverage reporting for scenarios."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from csd_foundry.kernel.invariants import (
    validate_event_transition,
    validate_state,
    validate_transition,
)
from csd_foundry.kernel.models import ControlState
from csd_foundry.kernel.oracle import CsdOracle, OracleRejected
from csd_foundry.kernel.transitions import TransitionError
from csd_foundry.scenarios.spec import (
    ExecutableCase,
    ObservationCase,
    RejectedTransitionCase,
    ScenarioMode,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)
from csd_foundry.scenarios.v0_1.manifest import ManifestScenario, SCENARIO_METADATA


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


def _load_manifest(release: str) -> tuple[ManifestScenario, ...]:
    if release != "v0.1":
        raise ValueError(f"unsupported scenario release: {release}")
    return SCENARIO_METADATA


def _expectation_errors(
    state: ControlState,
    expected: StateExpectation,
) -> tuple[str, ...]:
    errors: list[str] = []
    if expected.obligation is not None and state.obligation is not expected.obligation:
        errors.append(f"obligation={state.obligation.value}; expected {expected.obligation.value}")
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
            errors.append(
                f"history_event_types={observed!r}; expected {expected.history_event_types!r}"
            )
    return tuple(errors)


def _execute_transition(
    scenario_id: str,
    case: TransitionCase,
    before: ControlState | None = None,
) -> tuple[CaseResult, ControlState | None]:
    effective_before = case.before if before is None else before
    errors: list[str] = []
    oracle = CsdOracle()
    try:
        first = oracle.apply(effective_before, case.event)
        second = oracle.apply(effective_before, case.event)
    except (OracleRejected, TransitionError, TypeError, ValueError) as exc:
        return (
            CaseResult(
                scenario_id,
                case.case_id,
                "transition",
                False,
                (f"oracle rejected canonical transition: {exc}",),
            ),
            None,
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

    result = CaseResult(
        scenario_id,
        case.case_id,
        "transition",
        not errors,
        tuple(errors),
    )
    return result, first.after


def _run_transition(scenario_id: str, case: TransitionCase) -> CaseResult:
    result, _ = _execute_transition(scenario_id, case)
    return result


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


def _sequence_coordinates(case_id: str) -> tuple[str, int]:
    parts = case_id.split("/")
    if len(parts) < 3:
        raise ValueError(f"sequence case {case_id!r} must use '<scenario>/<branch>/<step>-<name>'")
    step_text = parts[-1].split("-", maxsplit=1)[0]
    try:
        step = int(step_text)
    except ValueError as exc:
        raise ValueError(f"sequence case {case_id!r} has no numeric step") from exc
    return "/".join(parts[:-1]), step


def _run_sequence(spec: ScenarioSpec) -> tuple[CaseResult, ...]:
    groups: dict[str, list[tuple[int, TransitionCase]]] = {}
    errors: list[CaseResult] = []

    for case in spec.cases:
        if not isinstance(case, TransitionCase):
            errors.append(
                CaseResult(
                    spec.scenario_id,
                    case.case_id,
                    type(case).__name__,
                    False,
                    ("sequence scenarios may contain only transition cases",),
                )
            )
            continue
        try:
            group_id, step = _sequence_coordinates(case.case_id)
        except ValueError as exc:
            errors.append(
                CaseResult(
                    spec.scenario_id,
                    case.case_id,
                    "transition",
                    False,
                    (str(exc),),
                )
            )
            continue
        groups.setdefault(group_id, []).append((step, case))

    results: list[CaseResult] = list(errors)
    for group_id, members in groups.items():
        ordered = sorted(members, key=lambda member: member[0])
        previous_after: ControlState | None = None
        for expected_step, (step, case) in enumerate(ordered, start=1):
            link_errors: list[str] = []
            if step != expected_step:
                link_errors.append(
                    f"sequence {group_id} uses step {step}; expected contiguous step {expected_step}"
                )

            if expected_step == 1:
                effective_before = case.before
            elif previous_after is None:
                results.append(
                    CaseResult(
                        spec.scenario_id,
                        case.case_id,
                        "transition",
                        False,
                        ("preceding sequence step did not produce a post-state",),
                    )
                )
                continue
            else:
                effective_before = previous_after
                if previous_after != case.before:
                    link_errors.append(
                        "declared before state does not equal the preceding oracle post-state"
                    )

            case_result, previous_after = _execute_transition(
                spec.scenario_id,
                case,
                effective_before,
            )
            if link_errors:
                case_result = replace(
                    case_result,
                    accepted=False,
                    details=(*link_errors, *case_result.details),
                )
            results.append(case_result)
    return tuple(results)


def run_scenario(spec: ScenarioSpec) -> ScenarioResult:
    if spec.mode is ScenarioMode.SEQUENCE:
        cases = _run_sequence(spec)
    else:
        cases = tuple(run_case(spec.scenario_id, case) for case in spec.cases)
    return ScenarioResult(spec.scenario_id, all(case.accepted for case in cases), cases)


def _metadata_errors(
    registry: Mapping[str, ScenarioSpec],
    manifest: tuple[ManifestScenario, ...],
) -> tuple[str, ...]:
    errors: list[str] = []
    manifest_by_id = {entry.scenario_id: entry for entry in manifest}
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
        if spec.split != entry.split:
            errors.append(f"{scenario_id}: split mismatch")
        if spec.family != entry.family:
            errors.append(f"{scenario_id}: family mismatch")
        if spec.source_section != entry.source_section:
            errors.append(f"{scenario_id}: source-section mismatch")
        if spec.rule_ids != entry.rules:
            errors.append(
                f"{scenario_id}: rule mismatch; registry={sorted(spec.rule_ids)}, "
                f"manifest={sorted(entry.rules)}"
            )
        if not spec.cases:
            errors.append(f"{scenario_id}: no executable cases")
        case_ids = [case.case_id for case in spec.cases]
        if len(case_ids) != len(set(case_ids)):
            errors.append(f"{scenario_id}: duplicate case identity")
    return tuple(errors)


def validate_release(
    registry: Mapping[str, ScenarioSpec],
    release: str = "v0.1",
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
