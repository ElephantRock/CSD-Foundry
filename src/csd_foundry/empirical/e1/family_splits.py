"""Canonical symbolic-family identities and leakage-safe E1 split manifests."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.kernel.events import (
    AdvanceClock,
    CsdEvent,
    DependencyChange,
    ProfileChange,
    Reassess,
    RecordHeartbeat,
    RequestReassessment,
    RetireControl,
)
from csd_foundry.kernel.models import Basis, ControlState, Evidence
from csd_foundry.scenarios.spec import (
    ObservationCase,
    RejectedTransitionCase,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


class FamilySplitError(ValueError):
    """Raised when a symbolic family or E1 split manifest is invalid."""


class E1Split(StrEnum):
    """Permitted E1 development splits."""

    TRAIN = "train"
    DEVELOPMENT = "development"


_FAMILY_SCHEMA_VERSION = "e1-symbolic-family/1"
_MANIFEST_SCHEMA_VERSION = "e1-family-split-manifest/1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _require_text(value: str, field_name: str) -> None:
    if not value.strip():
        raise FamilySplitError(f"{field_name} must be nonempty")


def _evidence_shape(item: Evidence, logical_time: int) -> dict[str, object]:
    return {
        "dimension": item.dimension,
        "status": item.status.value,
        "dependency_count": len(item.dependencies),
        "outcome": item.outcome,
        "issued_offset": item.issued_at - logical_time,
        "expiry_offset": None if item.expires_at is None else item.expires_at - logical_time,
        "profile_scoped": item.profile_id is not None,
        "profile_version": item.profile_version,
    }


def _evidence_shape_map(state: ControlState) -> dict[str, dict[str, object]]:
    return {item.evidence_id: _evidence_shape(item, state.logical_time) for item in state.evidence}


def _basis_shape(
    item: Basis,
    evidence_shapes: dict[str, dict[str, object]],
) -> dict[str, object]:
    member_shapes: list[dict[str, object]] = []
    for evidence_id in item.member_evidence_ids:
        try:
            member_shapes.append(evidence_shapes[evidence_id])
        except KeyError as exc:
            raise FamilySplitError(
                f"basis {item.basis_id} references unknown evidence {evidence_id}"
            ) from exc
    member_shapes.sort(key=canonical_sha256)
    return {
        "kind": item.kind.value,
        "claim": item.claim,
        "approved": item.approved,
        "member_evidence": member_shapes,
    }


def _basis_shape_map(
    state: ControlState,
    evidence_shapes: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    return {item.basis_id: _basis_shape(item, evidence_shapes) for item in state.bases}


def _referenced_shapes(
    identifiers: Iterable[str],
    shapes: dict[str, dict[str, object]],
    field_name: str,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for identifier in identifiers:
        try:
            result.append(shapes[identifier])
        except KeyError as exc:
            raise FamilySplitError(
                f"{field_name} references unknown identity {identifier}"
            ) from exc
    result.sort(key=canonical_sha256)
    return result


def _state_shape(state: ControlState) -> dict[str, object]:
    evidence_shapes = _evidence_shape_map(state)
    basis_shapes = _basis_shape_map(state, evidence_shapes)

    dependency_incidence: Counter[str] = Counter()
    for item in state.evidence:
        dependency_incidence.update(item.dependencies)

    evidence_values = list(evidence_shapes.values())
    evidence_values.sort(key=canonical_sha256)
    basis_values = list(basis_shapes.values())
    basis_values.sort(key=canonical_sha256)

    request_shapes = [
        {
            "status": request.status.value,
            "requested_offset": request.requested_at - state.logical_time,
            "due_offset": request.due_at - state.logical_time,
            "closed_offset": (
                None if request.closed_at is None else request.closed_at - state.logical_time
            ),
            "reason_present": bool(request.reason.strip()),
        }
        for request in state.reassessment_requests
    ]
    request_shapes.sort(key=canonical_sha256)

    history_shapes = [
        {
            "event_type": item.event_type,
            "detail_keys": sorted(name for name, _ in item.details),
        }
        for item in state.history
    ]

    heartbeat_shape: dict[str, object] | None = None
    if state.heartbeat is not None:
        heartbeat_shape = {
            "interval": state.heartbeat.interval,
            "last_recorded_offset": state.heartbeat.last_recorded_at - state.logical_time,
            "due_offset": state.heartbeat.due_at - state.logical_time,
        }

    return {
        "obligation": state.obligation.value,
        "source_state": state.source_state.value,
        "assurance": state.assurance.value,
        "evidence": evidence_values,
        "dependency_incidence": sorted(dependency_incidence.values()),
        "bases": basis_values,
        "current_source_bases": _referenced_shapes(
            state.current_source_basis_ids,
            basis_shapes,
            "current_source_basis_ids",
        ),
        "current_verdict_bases": _referenced_shapes(
            state.current_verdict_basis_ids,
            basis_shapes,
            "current_verdict_basis_ids",
        ),
        "history": history_shapes,
        "required_profile_present": state.required_profile_id is not None,
        "required_profile_version": state.required_profile_version,
        "reassessment_requests": request_shapes,
        "heartbeat": heartbeat_shape,
    }


def _event_shape(event: CsdEvent, before: ControlState | None) -> dict[str, object]:
    if isinstance(event, DependencyChange):
        affected_evidence = 0
        if before is not None:
            affected_evidence = sum(
                event.dependency_id in item.dependencies for item in before.evidence
            )
        return {
            "event_type": type(event).__name__,
            "apparent_direction": event.apparent_direction,
            "affected_evidence_count": affected_evidence,
        }

    if isinstance(event, Reassess):
        logical_time = 0 if before is None else before.logical_time
        existing_evidence = {} if before is None else _evidence_shape_map(before)
        new_evidence_shapes = {
            item.evidence_id: _evidence_shape(item, logical_time) for item in event.new_evidence
        }
        all_evidence = {**existing_evidence, **new_evidence_shapes}
        basis_shapes = [_basis_shape(item, all_evidence) for item in event.new_bases]
        new_evidence = list(new_evidence_shapes.values())
        new_evidence.sort(key=canonical_sha256)
        basis_shapes.sort(key=canonical_sha256)
        return {
            "event_type": type(event).__name__,
            "new_evidence": new_evidence,
            "new_bases": basis_shapes,
            "source_state": None if event.source_state is None else event.source_state.value,
            "assurance": None if event.assurance is None else event.assurance.value,
            "authority": event.authority,
            "close_request_count": len(event.close_request_ids),
        }

    if isinstance(event, RetireControl):
        logical_time = 0 if before is None else before.logical_time
        return {
            "event_type": type(event).__name__,
            "retirement_evidence": _evidence_shape(event.retirement_evidence, logical_time),
            "authority": event.authority,
        }

    if isinstance(event, AdvanceClock):
        logical_time = 0 if before is None else before.logical_time
        return {
            "event_type": type(event).__name__,
            "target_offset": event.target_time - logical_time,
        }

    if isinstance(event, ProfileChange):
        logical_time = 0 if before is None else before.logical_time
        return {
            "event_type": type(event).__name__,
            "profile_version": event.profile_version,
            "authority": event.authority,
            "request_present": event.request_id is not None,
            "request_due_offset": (
                None if event.request_due_at is None else event.request_due_at - logical_time
            ),
        }

    if isinstance(event, RequestReassessment):
        logical_time = 0 if before is None else before.logical_time
        return {
            "event_type": type(event).__name__,
            "reason_present": bool(event.reason.strip()),
            "due_offset": event.due_at - logical_time,
            "authority": event.authority,
        }

    if isinstance(event, RecordHeartbeat):
        logical_time = 0 if before is None else before.logical_time
        return {
            "event_type": type(event).__name__,
            "at_offset": event.at_time - logical_time,
            "interval": event.interval,
            "authority": event.authority,
        }

    raise FamilySplitError(f"unsupported CSD event type: {type(event).__qualname__}")


def _expectation_shape(
    expected: StateExpectation,
    evidence_shapes: dict[str, dict[str, object]],
    basis_shapes: dict[str, dict[str, object]],
) -> dict[str, object]:
    evidence_statuses = [
        {
            "evidence": _referenced_shapes((evidence_id,), evidence_shapes, "evidence_statuses")[0],
            "status": status.value,
        }
        for evidence_id, status in expected.evidence_statuses
    ]
    evidence_statuses.sort(key=canonical_sha256)

    evidence_outcomes = [
        {
            "evidence": _referenced_shapes((evidence_id,), evidence_shapes, "evidence_outcomes")[0],
            "outcome": outcome,
        }
        for evidence_id, outcome in expected.evidence_outcomes
    ]
    evidence_outcomes.sort(key=canonical_sha256)

    basis_claims = [
        {
            "basis": _referenced_shapes((basis_id,), basis_shapes, "basis_claims")[0],
            "claim": claim,
        }
        for basis_id, claim in expected.basis_claims
    ]
    basis_claims.sort(key=canonical_sha256)

    source_bases: list[dict[str, object]] | None = None
    if expected.current_source_basis_ids is not None:
        source_bases = _referenced_shapes(
            expected.current_source_basis_ids,
            basis_shapes,
            "expected current_source_basis_ids",
        )

    verdict_bases: list[dict[str, object]] | None = None
    if expected.current_verdict_basis_ids is not None:
        verdict_bases = _referenced_shapes(
            expected.current_verdict_basis_ids,
            basis_shapes,
            "expected current_verdict_basis_ids",
        )

    return {
        "obligation": None if expected.obligation is None else expected.obligation.value,
        "source_state": None if expected.source_state is None else expected.source_state.value,
        "assurance": None if expected.assurance is None else expected.assurance.value,
        "evidence_statuses": evidence_statuses,
        "evidence_outcomes": evidence_outcomes,
        "basis_claims": basis_claims,
        "current_source_bases": source_bases,
        "current_verdict_bases": verdict_bases,
        "history_length": expected.history_length,
        "history_event_types": expected.history_event_types,
    }


def _transition_reference_shapes(
    case: TransitionCase,
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    evidence_shapes = _evidence_shape_map(case.before)
    basis_shapes = _basis_shape_map(case.before, evidence_shapes)

    if isinstance(case.event, Reassess):
        logical_time = case.before.logical_time
        for evidence_item in case.event.new_evidence:
            evidence_shapes[evidence_item.evidence_id] = _evidence_shape(
                evidence_item,
                logical_time,
            )
        for basis_item in case.event.new_bases:
            basis_shapes[basis_item.basis_id] = _basis_shape(
                basis_item,
                evidence_shapes,
            )
    elif isinstance(case.event, RetireControl):
        retirement_evidence = case.event.retirement_evidence
        evidence_shapes[retirement_evidence.evidence_id] = _evidence_shape(
            retirement_evidence,
            case.before.logical_time,
        )

    return evidence_shapes, basis_shapes


def _transition_shape(case: TransitionCase) -> dict[str, object]:
    before_evidence = _evidence_shape_map(case.before)
    reference_evidence, reference_bases = _transition_reference_shapes(case)
    invalidated: list[dict[str, object]] | None = None
    if case.expected_invalidated_evidence is not None:
        invalidated = _referenced_shapes(
            case.expected_invalidated_evidence,
            before_evidence,
            "expected_invalidated_evidence",
        )
    surviving: list[dict[str, object]] | None = None
    if case.expected_surviving_bases is not None:
        surviving = _referenced_shapes(
            case.expected_surviving_bases,
            reference_bases,
            "expected_surviving_bases",
        )
    return {
        "case_kind": "transition",
        "before": _state_shape(case.before),
        "event": _event_shape(case.event, case.before),
        "expected": _expectation_shape(
            case.expected,
            reference_evidence,
            reference_bases,
        ),
        "expected_invalidated_evidence": invalidated,
        "expected_surviving_bases": surviving,
        "required_trace_rules": sorted(case.required_trace_rules),
    }


def _case_shape(
    case: TransitionCase | ObservationCase | RejectedTransitionCase,
) -> dict[str, object]:
    if isinstance(case, TransitionCase):
        return _transition_shape(case)
    if isinstance(case, ObservationCase):
        evidence_shapes = _evidence_shape_map(case.state)
        basis_shapes = _basis_shape_map(case.state, evidence_shapes)
        return {
            "case_kind": "observation",
            "state": _state_shape(case.state),
            "expected": _expectation_shape(
                case.expected,
                evidence_shapes,
                basis_shapes,
            ),
        }
    if isinstance(case, RejectedTransitionCase):
        return {
            "case_kind": "rejected_transition",
            "before": _state_shape(case.before),
            "proposed_after": _state_shape(case.proposed_after),
            "event": None if case.event is None else _event_shape(case.event, case.before),
            "expected_invariants": sorted(case.expected_invariants),
        }
    raise FamilySplitError(f"unsupported scenario case type: {type(case).__qualname__}")


def _family_material(spec: ScenarioSpec) -> dict[str, object]:
    case_shapes = [_case_shape(case) for case in spec.cases]
    case_shapes.sort(key=canonical_sha256)
    return {
        "schema_version": _FAMILY_SCHEMA_VERSION,
        "mode": spec.mode.value,
        "rule_ids": sorted(spec.rule_ids),
        "cases": case_shapes,
    }


@dataclass(frozen=True, slots=True)
class ScenarioFamilyIdentity:
    """Surface-invariant symbolic family identity for one executable scenario."""

    scenario_id: str
    declared_family: str
    source_split: str
    family_digest: str
    case_count: int

    def __post_init__(self) -> None:
        _require_text(self.scenario_id, "scenario_id")
        _require_text(self.declared_family, "declared_family")
        _require_text(self.source_split, "source_split")
        if _HEX_DIGEST.fullmatch(self.family_digest) is None:
            raise FamilySplitError("family_digest must be a lowercase SHA-256 digest")
        if self.case_count <= 0:
            raise FamilySplitError("case_count must be positive")

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "declared_family": self.declared_family,
            "source_split": self.source_split,
            "family_digest": self.family_digest,
            "case_count": self.case_count,
        }


def derive_scenario_family_identity(spec: ScenarioSpec) -> ScenarioFamilyIdentity:
    """Derive an identity that excludes prose, source metadata, and concrete object IDs."""

    if not spec.cases:
        raise FamilySplitError(f"scenario {spec.scenario_id} has no executable cases")
    return ScenarioFamilyIdentity(
        scenario_id=spec.scenario_id,
        declared_family=spec.family,
        source_split=spec.split,
        family_digest=canonical_sha256(_family_material(spec)),
        case_count=len(spec.cases),
    )


@dataclass(frozen=True, slots=True)
class FamilySplitAssignment:
    """One whole-family assignment to an E1 split."""

    family_digest: str
    split: E1Split
    scenario_ids: tuple[str, ...]
    declared_families: tuple[str, ...]
    source_splits: tuple[str, ...]

    def __post_init__(self) -> None:
        if _HEX_DIGEST.fullmatch(self.family_digest) is None:
            raise FamilySplitError("assignment family_digest must be a SHA-256 digest")
        if not self.scenario_ids:
            raise FamilySplitError("family assignment must contain scenarios")
        if self.scenario_ids != tuple(sorted(set(self.scenario_ids))):
            raise FamilySplitError("scenario_ids must be unique and canonically sorted")
        if self.declared_families != tuple(sorted(set(self.declared_families))):
            raise FamilySplitError("declared_families must be unique and canonically sorted")
        if self.source_splits != tuple(sorted(set(self.source_splits))):
            raise FamilySplitError("source_splits must be unique and canonically sorted")

    def to_dict(self) -> dict[str, object]:
        return {
            "family_digest": self.family_digest,
            "split": self.split.value,
            "scenario_ids": list(self.scenario_ids),
            "declared_families": list(self.declared_families),
            "source_splits": list(self.source_splits),
        }


@dataclass(frozen=True, slots=True)
class FamilySplitManifest:
    """Canonical E1 manifest that makes family overlap mechanically impossible."""

    release: str
    source_commit: str
    assignments: tuple[FamilySplitAssignment, ...]
    schema_version: str = _MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text(self.release, "release")
        if self.schema_version != _MANIFEST_SCHEMA_VERSION:
            raise FamilySplitError("unsupported family split manifest schema")
        if _GIT_COMMIT.fullmatch(self.source_commit) is None:
            raise FamilySplitError("source_commit must be a lowercase Git commit digest")
        if not self.assignments:
            raise FamilySplitError("family split manifest must contain assignments")
        if self.assignments != tuple(sorted(self.assignments, key=lambda item: item.family_digest)):
            raise FamilySplitError("assignments must be canonically sorted by family digest")

        family_digests = tuple(item.family_digest for item in self.assignments)
        if len(family_digests) != len(set(family_digests)):
            raise FamilySplitError("a symbolic family cannot appear in multiple assignments")

        scenario_ids = [
            scenario_id
            for assignment in self.assignments
            for scenario_id in assignment.scenario_ids
        ]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise FamilySplitError("a scenario cannot appear in multiple family assignments")

        if {item.split for item in self.assignments} != set(E1Split):
            raise FamilySplitError("manifest requires nonempty train and development splits")

    @property
    def manifest_digest(self) -> str:
        return canonical_sha256(
            {
                "schema_version": self.schema_version,
                "release": self.release,
                "source_commit": self.source_commit,
                "assignments": [item.to_dict() for item in self.assignments],
            }
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "assignments": [item.to_dict() for item in self.assignments],
            "manifest_digest": self.manifest_digest,
            "family_overlap": False,
            "claim_boundary": (
                "This manifest proves family-level train/development isolation for the "
                "listed executable scenarios. It does not establish distributional "
                "completeness, statistical power, learning value, or final-holdout integrity."
            ),
        }


def compile_family_split_manifest(
    scenarios: Iterable[ScenarioSpec],
    *,
    development_family_digests: frozenset[str],
    release: str,
    source_commit: str,
) -> FamilySplitManifest:
    """Compile explicit whole-family E1 assignments from executable scenarios."""

    ordered_scenarios = tuple(sorted(scenarios, key=lambda item: item.scenario_id))
    if not ordered_scenarios:
        raise FamilySplitError("cannot compile a split manifest without scenarios")

    scenario_ids = tuple(item.scenario_id for item in ordered_scenarios)
    if len(scenario_ids) != len(set(scenario_ids)):
        raise FamilySplitError("scenario identifiers must be unique")

    identities = tuple(derive_scenario_family_identity(item) for item in ordered_scenarios)
    grouped: dict[str, list[ScenarioFamilyIdentity]] = {}
    for identity in identities:
        grouped.setdefault(identity.family_digest, []).append(identity)

    known_families = frozenset(grouped)
    unknown_development = development_family_digests - known_families
    if unknown_development:
        raise FamilySplitError(
            "development families are not present in the scenario catalog: "
            f"{sorted(unknown_development)}"
        )
    if not development_family_digests:
        raise FamilySplitError("at least one development family is required")
    if development_family_digests == known_families:
        raise FamilySplitError("at least one training family is required")

    assignments: list[FamilySplitAssignment] = []
    for family_digest, members in grouped.items():
        split = (
            E1Split.DEVELOPMENT if family_digest in development_family_digests else E1Split.TRAIN
        )
        assignments.append(
            FamilySplitAssignment(
                family_digest=family_digest,
                split=split,
                scenario_ids=tuple(sorted(item.scenario_id for item in members)),
                declared_families=tuple(sorted({item.declared_family for item in members})),
                source_splits=tuple(sorted({item.source_split for item in members})),
            )
        )

    return FamilySplitManifest(
        release=release,
        source_commit=source_commit,
        assignments=tuple(sorted(assignments, key=lambda item: item.family_digest)),
    )
