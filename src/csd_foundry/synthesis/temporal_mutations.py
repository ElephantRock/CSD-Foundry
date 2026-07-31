"""Invariant-targeted mutation probes for temporal kernel release v0.3."""

from __future__ import annotations

from dataclasses import dataclass, replace

from csd_foundry.kernel.events import (
    AdvanceClock,
    CsdEvent,
    ProfileChange,
    Reassess,
    RecordHeartbeat,
    RequestReassessment,
)
from csd_foundry.kernel.invariants import validate_event_transition, validate_transition
from csd_foundry.kernel.models import (
    Assurance,
    ControlState,
    EvidenceStatus,
    HeartbeatState,
)
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.kernel.temporal import is_temporal_event
from csd_foundry.kernel.temporal_invariants import (
    validate_temporal_event,
    validate_temporal_transition,
)
from csd_foundry.temporal.v0_3 import base_state, validate_release


@dataclass(frozen=True, slots=True)
class TemporalMutationProbe:
    mutation_id: str
    before: ControlState
    event: CsdEvent
    proposed_after: ControlState
    expected_invariants: frozenset[str]


@dataclass(frozen=True, slots=True)
class TemporalMutationResult:
    mutation_id: str
    killed: bool
    expected_invariants: tuple[str, ...]
    observed_invariants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TemporalMutationReport:
    release: str
    total: int
    killed: int
    escaped: int
    invalid_canonical: int
    covered_invariants: tuple[str, ...]
    results: tuple[TemporalMutationResult, ...]

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
                    "mutation_id": item.mutation_id,
                    "killed": item.killed,
                    "expected_invariants": list(item.expected_invariants),
                    "observed_invariants": list(item.observed_invariants),
                }
                for item in self.results
            ],
        }


def _replace_evidence_status(
    state: ControlState, evidence_id: str, status: EvidenceStatus
) -> ControlState:
    return replace(
        state,
        evidence=tuple(
            replace(item, status=status) if item.evidence_id == evidence_id else item
            for item in state.evidence
        ),
    )


def build_probes() -> tuple[TemporalMutationProbe, ...]:
    oracle = CsdOracle()

    expiry_before = base_state(source_expires_at=5)
    expiry_event = AdvanceClock(5)
    expiry_after = oracle.apply(expiry_before, expiry_event).after

    early_event = AdvanceClock(4)
    early_after = oracle.apply(expiry_before, early_event).after

    forward_before = base_state(logical_time=5)
    forward_event = AdvanceClock(6)
    forward_after = oracle.apply(forward_before, forward_event).after

    resurrection_before = expiry_after
    resurrection_event = AdvanceClock(6)
    resurrection_after = oracle.apply(resurrection_before, resurrection_event).after

    profile_before = base_state(profile_id="PROFILE-A", profile_version=1)
    profile_event = ProfileChange("PROFILE-A", 2)
    profile_after = oracle.apply(profile_before, profile_event).after
    unauthorized_profile_event = replace(profile_event, authority="I2")

    stale = replace(
        base_state(),
        assurance=Assurance.STALE,
        current_verdict_basis_ids=frozenset(),
    )
    request_event = RequestReassessment("REQ-MUT", "mutation control", due_at=8)
    request_after = oracle.apply(stale, request_event).after
    unauthorized_request_event = replace(request_event, authority="I2")

    heartbeat_event = RecordHeartbeat(at_time=0, interval=5)
    heartbeat_after = oracle.apply(stale, heartbeat_event).after
    unauthorized_heartbeat_event = replace(heartbeat_event, authority="I2")

    missed_before = base_state(heartbeat=HeartbeatState(interval=5, last_recorded_at=0, due_at=5))
    missed_event = AdvanceClock(5)
    missed_after = oracle.apply(missed_before, missed_event).after

    requested = oracle.apply(
        base_state(),
        RequestReassessment("REQ-CLOSE", "close control", due_at=8),
    ).after
    close_event = Reassess((), (), close_request_ids=("REQ-CLOSE",))
    close_after = oracle.apply(requested, close_event).after
    unknown_close_event = Reassess((), (), close_request_ids=("REQ-UNKNOWN",))
    already_closed_event = Reassess((), (), close_request_ids=("REQ-CLOSE",))

    clock_request_event = AdvanceClock(1)
    clock_request_after = oracle.apply(requested, clock_request_event).after
    rewritten_request = replace(requested.reassessment_requests[0], due_at=9)

    return (
        TemporalMutationProbe(
            "mut-temporal-suppress-expiry",
            expiry_before,
            expiry_event,
            _replace_evidence_status(expiry_after, "EV-SOURCE", EvidenceStatus.CURRENT),
            frozenset({"T-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-temporal-expire-early",
            expiry_before,
            early_event,
            _replace_evidence_status(early_after, "EV-SOURCE", EvidenceStatus.EXPIRED),
            frozenset({"T-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-temporal-backward-time",
            forward_before,
            forward_event,
            replace(forward_after, logical_time=4),
            frozenset({"T-INV-01"}),
        ),
        TemporalMutationProbe(
            "mut-temporal-resurrect-expired",
            resurrection_before,
            resurrection_event,
            replace(
                _replace_evidence_status(
                    resurrection_after,
                    "EV-SOURCE",
                    EvidenceStatus.CURRENT,
                ),
                source_state=expiry_before.source_state,
                current_source_basis_ids=expiry_before.current_source_basis_ids,
            ),
            frozenset({"INV-18", "T-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-profile-invalidate-unbound-evidence",
            profile_before,
            profile_event,
            _replace_evidence_status(
                profile_after,
                "EV-VERDICT",
                EvidenceStatus.INVALIDATED,
            ),
            frozenset({"P-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-profile-retain-incompatible-basis",
            profile_before,
            profile_event,
            replace(
                profile_after,
                source_state=profile_before.source_state,
                current_source_basis_ids=profile_before.current_source_basis_ids,
            ),
            frozenset({"P-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-profile-unauthorized-authority",
            profile_before,
            unauthorized_profile_event,
            profile_after,
            frozenset({"P-INV-01"}),
        ),
        TemporalMutationProbe(
            "mut-request-unauthorized-authority",
            stale,
            unauthorized_request_event,
            request_after,
            frozenset({"R-INV-01"}),
        ),
        TemporalMutationProbe(
            "mut-heartbeat-unauthorized-authority",
            stale,
            unauthorized_heartbeat_event,
            heartbeat_after,
            frozenset({"H-INV-01"}),
        ),
        TemporalMutationProbe(
            "mut-request-promote-verdict",
            stale,
            request_event,
            replace(
                request_after,
                assurance=Assurance.PASS,
                current_verdict_basis_ids=frozenset({"BASIS-VERDICT"}),
            ),
            frozenset({"R-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-heartbeat-promote-verdict",
            stale,
            heartbeat_event,
            replace(
                heartbeat_after,
                assurance=Assurance.PASS,
                current_verdict_basis_ids=frozenset({"BASIS-VERDICT"}),
            ),
            frozenset({"H-INV-02"}),
        ),
        TemporalMutationProbe(
            "mut-heartbeat-ignore-missed-deadline",
            missed_before,
            missed_event,
            replace(
                missed_after,
                assurance=Assurance.PASS,
                current_verdict_basis_ids=frozenset({"BASIS-VERDICT"}),
            ),
            frozenset({"T-INV-06"}),
        ),
        TemporalMutationProbe(
            "mut-reassessment-omit-request-closure",
            requested,
            close_event,
            replace(close_after, reassessment_requests=requested.reassessment_requests),
            frozenset({"R-INV-03"}),
        ),
        TemporalMutationProbe(
            "mut-reassessment-close-unknown-request",
            requested,
            unknown_close_event,
            requested,
            frozenset({"R-INV-03"}),
        ),
        TemporalMutationProbe(
            "mut-reassessment-close-already-closed-request",
            close_after,
            already_closed_event,
            close_after,
            frozenset({"R-INV-03"}),
        ),
        TemporalMutationProbe(
            "mut-request-rewrite-due-time",
            requested,
            clock_request_event,
            replace(clock_request_after, reassessment_requests=(rewritten_request,)),
            frozenset({"R-INV-03"}),
        ),
    )


def evaluate_probe(probe: TemporalMutationProbe) -> TemporalMutationResult:
    violations = [
        *validate_transition(probe.before, probe.proposed_after),
        *validate_temporal_transition(probe.before, probe.proposed_after),
    ]
    if not is_temporal_event(probe.event):
        violations.extend(
            validate_event_transition(probe.before, probe.event, probe.proposed_after)
        )
    violations.extend(validate_temporal_event(probe.before, probe.event, probe.proposed_after))
    observed = frozenset(item.invariant_id for item in violations)
    return TemporalMutationResult(
        mutation_id=probe.mutation_id,
        killed=bool(observed & probe.expected_invariants),
        expected_invariants=tuple(sorted(probe.expected_invariants)),
        observed_invariants=tuple(sorted(observed)),
    )


def evaluate_release(release: str = "v0.3") -> TemporalMutationReport:
    if release != "v0.3":
        raise ValueError(f"unsupported temporal mutation release: {release}")
    canonical = validate_release(release)
    probes = build_probes()
    results = tuple(evaluate_probe(probe) for probe in probes)
    killed = sum(item.killed for item in results)
    covered = tuple(
        sorted({invariant for item in results for invariant in item.observed_invariants})
    )
    return TemporalMutationReport(
        release=release,
        total=len(results),
        killed=killed,
        escaped=len(results) - killed,
        invalid_canonical=canonical.failed,
        covered_invariants=covered,
        results=results,
    )
