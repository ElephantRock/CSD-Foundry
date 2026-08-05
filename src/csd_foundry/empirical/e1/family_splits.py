"""Canonical symbolic-family identities and leakage-safe E1 split manifests."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import permutations, product
from math import factorial

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
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256


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
_MAX_CANONICAL_LABELINGS = 250_000


def _require_text(value: str, field_name: str) -> None:
    if not value.strip():
        raise FamilySplitError(f"{field_name} must be nonempty")


@dataclass(frozen=True, slots=True)
class _NamespaceIds:
    evidence: tuple[str, ...]
    bases: tuple[str, ...]
    dependencies: tuple[str, ...]
    requests: tuple[str, ...]
    profiles: tuple[str, ...]

    @property
    def labeling_count(self) -> int:
        result = 1
        for identifiers in (
            self.evidence,
            self.bases,
            self.dependencies,
            self.requests,
            self.profiles,
        ):
            result *= factorial(len(identifiers))
        return result


@dataclass(frozen=True, slots=True)
class _IdMap:
    evidence: Mapping[str, str]
    bases: Mapping[str, str]
    dependencies: Mapping[str, str]
    requests: Mapping[str, str]
    profiles: Mapping[str, str]


def _add_state_ids(
    state: ControlState,
    *,
    evidence: set[str],
    bases: set[str],
    dependencies: set[str],
    requests: set[str],
    profiles: set[str],
) -> None:
    for evidence_item in state.evidence:
        evidence.add(evidence_item.evidence_id)
        dependencies.update(evidence_item.dependencies)
        if evidence_item.profile_id is not None:
            profiles.add(evidence_item.profile_id)
    for basis_item in state.bases:
        bases.add(basis_item.basis_id)
        evidence.update(basis_item.member_evidence_ids)
    bases.update(state.current_source_basis_ids)
    bases.update(state.current_verdict_basis_ids)
    if state.required_profile_id is not None:
        profiles.add(state.required_profile_id)
    for request in state.reassessment_requests:
        requests.add(request.request_id)


def _add_event_ids(
    event: CsdEvent,
    *,
    evidence: set[str],
    bases: set[str],
    dependencies: set[str],
    requests: set[str],
    profiles: set[str],
) -> None:
    if isinstance(event, DependencyChange):
        dependencies.add(event.dependency_id)
    elif isinstance(event, Reassess):
        for evidence_item in event.new_evidence:
            evidence.add(evidence_item.evidence_id)
            dependencies.update(evidence_item.dependencies)
            if evidence_item.profile_id is not None:
                profiles.add(evidence_item.profile_id)
        for basis_item in event.new_bases:
            bases.add(basis_item.basis_id)
            evidence.update(basis_item.member_evidence_ids)
        requests.update(event.close_request_ids)
    elif isinstance(event, RetireControl):
        item = event.retirement_evidence
        evidence.add(item.evidence_id)
        dependencies.update(item.dependencies)
        if item.profile_id is not None:
            profiles.add(item.profile_id)
    elif isinstance(event, ProfileChange):
        profiles.add(event.profile_id)
        if event.request_id is not None:
            requests.add(event.request_id)
    elif isinstance(event, RequestReassessment):
        requests.add(event.request_id)
    elif isinstance(event, (AdvanceClock, RecordHeartbeat)):
        return
    else:
        raise FamilySplitError(f"unsupported CSD event type: {type(event).__qualname__}")


def _add_expectation_ids(
    expected: StateExpectation,
    *,
    evidence: set[str],
    bases: set[str],
) -> None:
    evidence.update(evidence_id for evidence_id, _ in expected.evidence_statuses)
    evidence.update(evidence_id for evidence_id, _ in expected.evidence_outcomes)
    bases.update(basis_id for basis_id, _ in expected.basis_claims)
    if expected.current_source_basis_ids is not None:
        bases.update(expected.current_source_basis_ids)
    if expected.current_verdict_basis_ids is not None:
        bases.update(expected.current_verdict_basis_ids)


def _collect_case_ids(
    case: TransitionCase | ObservationCase | RejectedTransitionCase,
) -> _NamespaceIds:
    evidence: set[str] = set()
    bases: set[str] = set()
    dependencies: set[str] = set()
    requests: set[str] = set()
    profiles: set[str] = set()

    if isinstance(case, TransitionCase):
        _add_state_ids(
            case.before,
            evidence=evidence,
            bases=bases,
            dependencies=dependencies,
            requests=requests,
            profiles=profiles,
        )
        _add_event_ids(
            case.event,
            evidence=evidence,
            bases=bases,
            dependencies=dependencies,
            requests=requests,
            profiles=profiles,
        )
        _add_expectation_ids(case.expected, evidence=evidence, bases=bases)
        if case.expected_invalidated_evidence is not None:
            evidence.update(case.expected_invalidated_evidence)
        if case.expected_surviving_bases is not None:
            bases.update(case.expected_surviving_bases)
    elif isinstance(case, ObservationCase):
        _add_state_ids(
            case.state,
            evidence=evidence,
            bases=bases,
            dependencies=dependencies,
            requests=requests,
            profiles=profiles,
        )
        _add_expectation_ids(case.expected, evidence=evidence, bases=bases)
    elif isinstance(case, RejectedTransitionCase):
        _add_state_ids(
            case.before,
            evidence=evidence,
            bases=bases,
            dependencies=dependencies,
            requests=requests,
            profiles=profiles,
        )
        _add_state_ids(
            case.proposed_after,
            evidence=evidence,
            bases=bases,
            dependencies=dependencies,
            requests=requests,
            profiles=profiles,
        )
        if case.event is not None:
            _add_event_ids(
                case.event,
                evidence=evidence,
                bases=bases,
                dependencies=dependencies,
                requests=requests,
                profiles=profiles,
            )
    else:
        raise FamilySplitError(f"unsupported scenario case type: {type(case).__qualname__}")

    return _NamespaceIds(
        evidence=tuple(sorted(evidence)),
        bases=tuple(sorted(bases)),
        dependencies=tuple(sorted(dependencies)),
        requests=tuple(sorted(requests)),
        profiles=tuple(sorted(profiles)),
    )


def _label_map(order: tuple[str, ...], prefix: str) -> dict[str, str]:
    return {identifier: f"{prefix}{index}" for index, identifier in enumerate(order)}


def _candidate_maps(namespaces: _NamespaceIds) -> Iterable[_IdMap]:
    if namespaces.labeling_count > _MAX_CANONICAL_LABELINGS:
        raise FamilySplitError(
            "symbolic family canonicalization exceeds the bounded labeling budget: "
            f"{namespaces.labeling_count} > {_MAX_CANONICAL_LABELINGS}"
        )

    for evidence_order, basis_order, dependency_order, request_order, profile_order in product(
        permutations(namespaces.evidence),
        permutations(namespaces.bases),
        permutations(namespaces.dependencies),
        permutations(namespaces.requests),
        permutations(namespaces.profiles),
    ):
        yield _IdMap(
            evidence=_label_map(evidence_order, "E"),
            bases=_label_map(basis_order, "B"),
            dependencies=_label_map(dependency_order, "D"),
            requests=_label_map(request_order, "R"),
            profiles=_label_map(profile_order, "P"),
        )


def _mapped(mapping: Mapping[str, str], identifier: str, field_name: str) -> str:
    try:
        return mapping[identifier]
    except KeyError as exc:
        raise FamilySplitError(f"{field_name} references unknown identity {identifier}") from exc


def _render_evidence(item: Evidence, logical_time: int, ids: _IdMap) -> dict[str, object]:
    return {
        "evidence_id": _mapped(ids.evidence, item.evidence_id, "evidence"),
        "dimension": item.dimension,
        "status": item.status.value,
        "dependencies": sorted(
            _mapped(ids.dependencies, dependency_id, "evidence dependency")
            for dependency_id in item.dependencies
        ),
        "outcome": item.outcome,
        "issued_offset": item.issued_at - logical_time,
        "expiry_offset": None if item.expires_at is None else item.expires_at - logical_time,
        "profile_id": (
            None
            if item.profile_id is None
            else _mapped(ids.profiles, item.profile_id, "evidence profile")
        ),
        "profile_version": item.profile_version,
    }


def _render_basis(item: Basis, ids: _IdMap) -> dict[str, object]:
    return {
        "basis_id": _mapped(ids.bases, item.basis_id, "basis"),
        "kind": item.kind.value,
        "claim": item.claim,
        "member_evidence_ids": sorted(
            _mapped(ids.evidence, evidence_id, "basis member evidence")
            for evidence_id in item.member_evidence_ids
        ),
        "approved": item.approved,
    }


def _render_state(state: ControlState, ids: _IdMap) -> dict[str, object]:
    evidence = [_render_evidence(item, state.logical_time, ids) for item in state.evidence]
    evidence.sort(key=lambda item: str(item["evidence_id"]))
    bases = [_render_basis(item, ids) for item in state.bases]
    bases.sort(key=lambda item: str(item["basis_id"]))
    requests = [
        {
            "request_id": _mapped(ids.requests, request.request_id, "reassessment request"),
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
    requests.sort(key=lambda item: str(item["request_id"]))

    heartbeat: dict[str, object] | None = None
    if state.heartbeat is not None:
        heartbeat = {
            "interval": state.heartbeat.interval,
            "last_recorded_offset": state.heartbeat.last_recorded_at - state.logical_time,
            "due_offset": state.heartbeat.due_at - state.logical_time,
        }

    return {
        "obligation": state.obligation.value,
        "source_state": state.source_state.value,
        "assurance": state.assurance.value,
        "evidence": evidence,
        "bases": bases,
        "current_source_basis_ids": sorted(
            _mapped(ids.bases, basis_id, "current source basis")
            for basis_id in state.current_source_basis_ids
        ),
        "current_verdict_basis_ids": sorted(
            _mapped(ids.bases, basis_id, "current verdict basis")
            for basis_id in state.current_verdict_basis_ids
        ),
        "history": [
            {
                "event_type": item.event_type,
                "detail_keys": sorted(name for name, _ in item.details),
            }
            for item in state.history
        ],
        "required_profile_id": (
            None
            if state.required_profile_id is None
            else _mapped(ids.profiles, state.required_profile_id, "required profile")
        ),
        "required_profile_version": state.required_profile_version,
        "reassessment_requests": requests,
        "heartbeat": heartbeat,
    }


def _render_event(event: CsdEvent, before: ControlState | None, ids: _IdMap) -> dict[str, object]:
    logical_time = 0 if before is None else before.logical_time

    if isinstance(event, DependencyChange):
        return {
            "event_type": type(event).__name__,
            "dependency_id": _mapped(ids.dependencies, event.dependency_id, "dependency event"),
            "apparent_direction": event.apparent_direction,
        }
    if isinstance(event, Reassess):
        evidence = [_render_evidence(item, logical_time, ids) for item in event.new_evidence]
        evidence.sort(key=lambda item: str(item["evidence_id"]))
        bases = [_render_basis(item, ids) for item in event.new_bases]
        bases.sort(key=lambda item: str(item["basis_id"]))
        return {
            "event_type": type(event).__name__,
            "new_evidence": evidence,
            "new_bases": bases,
            "source_state": None if event.source_state is None else event.source_state.value,
            "assurance": None if event.assurance is None else event.assurance.value,
            "authority": event.authority,
            "close_request_ids": sorted(
                _mapped(ids.requests, request_id, "closed reassessment request")
                for request_id in event.close_request_ids
            ),
        }
    if isinstance(event, RetireControl):
        return {
            "event_type": type(event).__name__,
            "retirement_evidence": _render_evidence(
                event.retirement_evidence,
                logical_time,
                ids,
            ),
            "authority": event.authority,
        }
    if isinstance(event, AdvanceClock):
        return {
            "event_type": type(event).__name__,
            "target_offset": event.target_time - logical_time,
        }
    if isinstance(event, ProfileChange):
        return {
            "event_type": type(event).__name__,
            "profile_id": _mapped(ids.profiles, event.profile_id, "profile change"),
            "profile_version": event.profile_version,
            "authority": event.authority,
            "request_id": (
                None
                if event.request_id is None
                else _mapped(ids.requests, event.request_id, "profile change request")
            ),
            "request_due_offset": (
                None if event.request_due_at is None else event.request_due_at - logical_time
            ),
        }
    if isinstance(event, RequestReassessment):
        return {
            "event_type": type(event).__name__,
            "request_id": _mapped(ids.requests, event.request_id, "requested reassessment"),
            "reason_present": bool(event.reason.strip()),
            "due_offset": event.due_at - logical_time,
            "authority": event.authority,
        }
    if isinstance(event, RecordHeartbeat):
        return {
            "event_type": type(event).__name__,
            "at_offset": event.at_time - logical_time,
            "interval": event.interval,
            "authority": event.authority,
        }
    raise FamilySplitError(f"unsupported CSD event type: {type(event).__qualname__}")


def _render_expectation(expected: StateExpectation, ids: _IdMap) -> dict[str, object]:
    evidence_statuses = [
        {
            "evidence_id": _mapped(ids.evidence, evidence_id, "expected evidence status"),
            "status": status.value,
        }
        for evidence_id, status in expected.evidence_statuses
    ]
    evidence_statuses.sort(key=lambda item: str(item["evidence_id"]))
    evidence_outcomes = [
        {
            "evidence_id": _mapped(ids.evidence, evidence_id, "expected evidence outcome"),
            "outcome": outcome,
        }
        for evidence_id, outcome in expected.evidence_outcomes
    ]
    evidence_outcomes.sort(key=lambda item: str(item["evidence_id"]))
    basis_claims = [
        {
            "basis_id": _mapped(ids.bases, basis_id, "expected basis claim"),
            "claim": claim,
        }
        for basis_id, claim in expected.basis_claims
    ]
    basis_claims.sort(key=lambda item: str(item["basis_id"]))

    return {
        "obligation": None if expected.obligation is None else expected.obligation.value,
        "source_state": None if expected.source_state is None else expected.source_state.value,
        "assurance": None if expected.assurance is None else expected.assurance.value,
        "evidence_statuses": evidence_statuses,
        "evidence_outcomes": evidence_outcomes,
        "basis_claims": basis_claims,
        "current_source_basis_ids": (
            None
            if expected.current_source_basis_ids is None
            else sorted(
                _mapped(ids.bases, basis_id, "expected current source basis")
                for basis_id in expected.current_source_basis_ids
            )
        ),
        "current_verdict_basis_ids": (
            None
            if expected.current_verdict_basis_ids is None
            else sorted(
                _mapped(ids.bases, basis_id, "expected current verdict basis")
                for basis_id in expected.current_verdict_basis_ids
            )
        ),
        "history_length": expected.history_length,
        "history_event_types": expected.history_event_types,
    }


def _render_case(
    case: TransitionCase | ObservationCase | RejectedTransitionCase,
    ids: _IdMap,
) -> dict[str, object]:
    if isinstance(case, TransitionCase):
        return {
            "case_kind": "transition",
            "before": _render_state(case.before, ids),
            "event": _render_event(case.event, case.before, ids),
            "expected": _render_expectation(case.expected, ids),
            "expected_invalidated_evidence": (
                None
                if case.expected_invalidated_evidence is None
                else sorted(
                    _mapped(ids.evidence, evidence_id, "expected invalidated evidence")
                    for evidence_id in case.expected_invalidated_evidence
                )
            ),
            "expected_surviving_bases": (
                None
                if case.expected_surviving_bases is None
                else sorted(
                    _mapped(ids.bases, basis_id, "expected surviving basis")
                    for basis_id in case.expected_surviving_bases
                )
            ),
            "required_trace_rules": sorted(case.required_trace_rules),
        }
    if isinstance(case, ObservationCase):
        return {
            "case_kind": "observation",
            "state": _render_state(case.state, ids),
            "expected": _render_expectation(case.expected, ids),
        }
    if isinstance(case, RejectedTransitionCase):
        return {
            "case_kind": "rejected_transition",
            "before": _render_state(case.before, ids),
            "proposed_after": _render_state(case.proposed_after, ids),
            "event": None if case.event is None else _render_event(case.event, case.before, ids),
            "expected_invariants": sorted(case.expected_invariants),
        }
    raise FamilySplitError(f"unsupported scenario case type: {type(case).__qualname__}")


def _canonical_case_shape(
    case: TransitionCase | ObservationCase | RejectedTransitionCase,
) -> dict[str, object]:
    namespaces = _collect_case_ids(case)
    best_shape: dict[str, object] | None = None
    best_bytes: bytes | None = None
    for ids in _candidate_maps(namespaces):
        candidate = _render_case(case, ids)
        candidate_bytes = canonical_json_bytes(candidate)
        if best_bytes is None or candidate_bytes < best_bytes:
            best_shape = candidate
            best_bytes = candidate_bytes
    if best_shape is None:
        raise FamilySplitError("symbolic family canonicalization produced no candidates")
    return best_shape


def _family_material(spec: ScenarioSpec) -> dict[str, object]:
    case_shapes = [_canonical_case_shape(case) for case in spec.cases]
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
