"""Invariant-targeted mutation probes over the executable scenario registry."""

from __future__ import annotations

from dataclasses import dataclass, replace

from csd_foundry.kernel.events import CsdEvent
from csd_foundry.kernel.invariants import validate_event_transition, validate_transition
from csd_foundry.kernel.models import Assurance, ControlState, EvidenceStatus, SourceState
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.scenarios.runner import run_case
from csd_foundry.scenarios.spec import TransitionCase


@dataclass(frozen=True, slots=True)
class MutationProbe:
    mutation_id: str
    scenario_id: str
    before: ControlState
    proposed_after: ControlState
    expected_invariants: frozenset[str]
    event: CsdEvent | None = None


@dataclass(frozen=True, slots=True)
class MutationResult:
    mutation_id: str
    scenario_id: str
    killed: bool
    expected_invariants: tuple[str, ...]
    observed_invariants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MutationReport:
    release: str
    total: int
    killed: int
    escaped: int
    invalid_canonical: int
    covered_invariants: tuple[str, ...]
    results: tuple[MutationResult, ...]

    @property
    def success(self) -> bool:
        return self.total > 0 and self.escaped == 0 and self.invalid_canonical == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "total": self.total,
            "killed": self.killed,
            "escaped": self.escaped,
            "invalid_canonical": self.invalid_canonical,
            "kill_rate": self.killed / self.total if self.total else 0.0,
            "covered_invariants": list(self.covered_invariants),
            "results": [
                {
                    "mutation_id": result.mutation_id,
                    "scenario_id": result.scenario_id,
                    "killed": result.killed,
                    "expected_invariants": list(result.expected_invariants),
                    "observed_invariants": list(result.observed_invariants),
                }
                for result in self.results
            ],
        }


def _case(registry: dict[str, object], scenario_id: str, case_id: str) -> TransitionCase:
    from csd_foundry.scenarios.spec import ScenarioSpec

    raw_spec = registry[scenario_id]
    if not isinstance(raw_spec, ScenarioSpec):
        raise TypeError(f"{scenario_id} is not a ScenarioSpec")
    for case in raw_spec.cases:
        if isinstance(case, TransitionCase) and case.case_id == case_id:
            return case
    raise KeyError(f"missing transition case {scenario_id}/{case_id}")


def _canonical_after(case: TransitionCase) -> ControlState:
    return CsdOracle().apply(case.before, case.event).after


def _replace_evidence_status(
    state: ControlState, evidence_id: str, status: EvidenceStatus
) -> ControlState:
    evidence = tuple(
        replace(item, status=status) if item.evidence_id == evidence_id else item
        for item in state.evidence
    )
    return replace(state, evidence=evidence)


def build_probes() -> tuple[MutationProbe, ...]:
    from csd_foundry.scenarios.registry import SCENARIOS

    registry: dict[str, object] = dict(SCENARIOS)

    m01 = _case(registry, "M-01", "M-01/dependency-change")
    m01_after = _canonical_after(m01)
    m01_evidence_id = m01.before.evidence[0].evidence_id

    m10 = _case(registry, "M-10", "M-10/control-b")
    m10_after = _canonical_after(m10)

    m11 = _case(registry, "M-11", "M-11/order-b/1-reassess")
    m11_after = _canonical_after(m11)

    g02 = _case(registry, "G-02", "G-02/reassess-verdict")
    g02_after = _canonical_after(g02)
    g02_old_id = g02.before.evidence[0].evidence_id

    h01 = _case(registry, "H-01", "H-01/corrected-reassessment")
    h01_after = _canonical_after(h01)
    h01_current_basis_id = next(iter(h01_after.current_source_basis_ids))
    h01_bases = tuple(
        replace(basis, claim=SourceState.WIRED_INERT.value)
        if basis.basis_id == h01_current_basis_id
        else basis
        for basis in h01_after.bases
    )

    g04 = _case(registry, "G-04", "G-04/retire")
    g04_after = _canonical_after(g04)
    g04_without_retirement_evidence = replace(g04_after, evidence=g04.before.evidence)

    m07 = _case(registry, "M-07", "M-07/dependency-change")
    m07_after = _canonical_after(m07)

    m13 = _case(registry, "M-13", "M-13/historical-dependency-change")
    m13_after = _canonical_after(m13)

    return (
        MutationProbe(
            "mut-m01-retain-invalid-basis",
            "M-01",
            m01.before,
            replace(
                m01_after,
                current_source_basis_ids=m01.before.current_source_basis_ids,
            ),
            frozenset({"INV-13"}),
            m01.event,
        ),
        MutationProbe(
            "mut-m01-promote-after-revocation",
            "M-01",
            m01.before,
            replace(m01_after, source_state=SourceState.CONNECTED),
            frozenset({"INV-05", "INV-15"}),
            m01.event,
        ),
        MutationProbe(
            "mut-m01-ignore-dependency-impact",
            "M-01",
            m01.before,
            _replace_evidence_status(m01_after, m01_evidence_id, EvidenceStatus.CURRENT),
            frozenset({"INV-11"}),
            m01.event,
        ),
        MutationProbe(
            "mut-m10-drop-independent-fail-basis",
            "M-10",
            m10.before,
            replace(
                m10_after,
                assurance=Assurance.STALE,
                current_verdict_basis_ids=frozenset(),
            ),
            frozenset({"INV-16"}),
            m10.event,
        ),
        MutationProbe(
            "mut-m11-overwrite-history",
            "M-11",
            m11.before,
            replace(m11_after, history=m11_after.history[-1:]),
            frozenset({"INV-19"}),
            m11.event,
        ),
        MutationProbe(
            "mut-g02-reactivate-old-evidence",
            "G-02",
            g02.before,
            _replace_evidence_status(g02_after, g02_old_id, EvidenceStatus.CURRENT),
            frozenset({"INV-18"}),
            g02.event,
        ),
        MutationProbe(
            "mut-h01-contradict-source-basis-claim",
            "H-01",
            h01.before,
            replace(h01_after, bases=h01_bases),
            frozenset({"INV-05", "G-INV-11"}),
            h01.event,
        ),
        MutationProbe(
            "mut-g04-retire-without-evidence",
            "G-04",
            g04.before,
            g04_without_retirement_evidence,
            frozenset({"G-INV-13"}),
            g04.event,
        ),
        MutationProbe(
            "mut-m07-replace-pass-with-fail",
            "M-07",
            m07.before,
            replace(m07_after, assurance=Assurance.FAIL),
            frozenset({"INV-07", "INV-15"}),
            m07.event,
        ),
        MutationProbe(
            "mut-m13-assess-retired-obligation",
            "M-13",
            m13.before,
            replace(m13_after, assurance=Assurance.STALE),
            frozenset({"INV-04"}),
            m13.event,
        ),
    )


def evaluate_probe(probe: MutationProbe) -> MutationResult:
    violations = list(validate_transition(probe.before, probe.proposed_after))
    if probe.event is not None:
        violations.extend(
            validate_event_transition(probe.before, probe.event, probe.proposed_after)
        )
    observed = frozenset(item.invariant_id for item in violations)
    killed = bool(probe.expected_invariants & observed)
    return MutationResult(
        mutation_id=probe.mutation_id,
        scenario_id=probe.scenario_id,
        killed=killed,
        expected_invariants=tuple(sorted(probe.expected_invariants)),
        observed_invariants=tuple(sorted(observed)),
    )


def evaluate_release(release: str = "v0.1") -> MutationReport:
    if release != "v0.1":
        raise ValueError(f"unsupported mutation release: {release}")

    from csd_foundry.scenarios.registry import SCENARIOS

    invalid_canonical = 0
    for spec in SCENARIOS.values():
        for case in spec.cases:
            if isinstance(case, TransitionCase) and not run_case(spec.scenario_id, case).accepted:
                invalid_canonical += 1

    probes = build_probes()
    results = tuple(evaluate_probe(probe) for probe in probes)
    covered = tuple(
        sorted({invariant for result in results for invariant in result.observed_invariants})
    )
    killed = sum(result.killed for result in results)
    return MutationReport(
        release=release,
        total=len(results),
        killed=killed,
        escaped=len(results) - killed,
        invalid_canonical=invalid_canonical,
        covered_invariants=covered,
        results=results,
    )
