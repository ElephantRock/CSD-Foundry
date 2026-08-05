"""Execution-aligned E1 family identities and split compilation."""

from __future__ import annotations

from collections.abc import Iterable

from csd_foundry.empirical.e1 import scenario_splits as _base
from csd_foundry.scenarios.spec import (
    ObservationCase,
    RejectedTransitionCase,
    ScenarioMode,
    ScenarioSpec,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

E1Split = _base.E1Split
FamilySplitAssignment = _base.FamilySplitAssignment
FamilySplitError = _base.FamilySplitError
FamilySplitManifest = _base.FamilySplitManifest
ScenarioFamilyIdentity = _base.ScenarioFamilyIdentity

_EXECUTION_TOPOLOGY_SCHEMA = "e1-execution-topology/1"


def _canonical_control_topology(spec: ScenarioSpec) -> list[dict[str, object]]:
    """Preserve control-identity equality while ignoring concrete control names."""

    labels: dict[str, str] = {}

    def label(control_id: str) -> str:
        if control_id not in labels:
            labels[control_id] = f"C{len(labels)}"
        return labels[control_id]

    cases: list[dict[str, object]] = []
    for position, case in enumerate(spec.cases):
        if isinstance(case, TransitionCase):
            cases.append(
                {
                    "position": position,
                    "case_kind": "transition",
                    "before_control": label(case.before.control_id),
                }
            )
        elif isinstance(case, ObservationCase):
            cases.append(
                {
                    "position": position,
                    "case_kind": "observation",
                    "state_control": label(case.state.control_id),
                }
            )
        elif isinstance(case, RejectedTransitionCase):
            cases.append(
                {
                    "position": position,
                    "case_kind": "rejected_transition",
                    "before_control": label(case.before.control_id),
                    "proposed_after_control": label(case.proposed_after.control_id),
                }
            )
        else:
            raise FamilySplitError(
                f"unsupported scenario case type: {type(case).__qualname__}"
            )
    return cases


def _sequence_execution_coordinates(spec: ScenarioSpec) -> list[dict[str, object]] | None:
    """Validate and canonicalize the exact sequence grammar used by the runner."""

    if spec.mode is not ScenarioMode.SEQUENCE:
        return None

    group_labels: dict[str, str] = {}
    coordinates: list[dict[str, object]] = []
    for position, case in enumerate(spec.cases):
        if not isinstance(case, TransitionCase):
            raise FamilySplitError("sequence scenarios may contain only transition cases")

        parts = case.case_id.split("/")
        if len(parts) < 3:
            raise FamilySplitError(
                f"sequence case {case.case_id!r} must use "
                "'<scenario>/<branch>/<step>-<name>'"
            )
        step_text = parts[-1].split("-", maxsplit=1)[0]
        try:
            step = int(step_text)
        except ValueError as exc:
            raise FamilySplitError(
                f"sequence case {case.case_id!r} has no numeric step"
            ) from exc

        group_id = "/".join(parts[:-1])
        if group_id not in group_labels:
            group_labels[group_id] = f"G{len(group_labels)}"
        coordinates.append(
            {
                "position": position,
                "group": group_labels[group_id],
                "step": step,
            }
        )
    return coordinates


def derive_scenario_family_identity(spec: ScenarioSpec) -> ScenarioFamilyIdentity:
    """Derive a family identity aligned with actual scenario execution semantics."""

    base_identity = _base.derive_scenario_family_identity(spec)
    family_digest = canonical_sha256(
        {
            "schema_version": _EXECUTION_TOPOLOGY_SCHEMA,
            "base_family_digest": base_identity.family_digest,
            "control_topology": _canonical_control_topology(spec),
            "sequence_execution_coordinates": _sequence_execution_coordinates(spec),
        }
    )
    return ScenarioFamilyIdentity(
        scenario_id=base_identity.scenario_id,
        declared_family=base_identity.declared_family,
        source_split=base_identity.source_split,
        family_digest=family_digest,
        case_count=base_identity.case_count,
    )


def compile_family_split_manifest(
    scenarios: Iterable[ScenarioSpec],
    *,
    development_family_digests: frozenset[str],
    release: str,
    source_commit: str,
) -> FamilySplitManifest:
    """Compile whole-family assignments using execution-aligned identities."""

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
            E1Split.DEVELOPMENT
            if family_digest in development_family_digests
            else E1Split.TRAIN
        )
        assignments.append(
            FamilySplitAssignment(
                family_digest=family_digest,
                split=split,
                scenario_ids=tuple(sorted(item.scenario_id for item in members)),
                declared_families=tuple(
                    sorted({item.declared_family for item in members})
                ),
                source_splits=tuple(sorted({item.source_split for item in members})),
            )
        )

    return FamilySplitManifest(
        release=release,
        source_commit=source_commit,
        assignments=tuple(sorted(assignments, key=lambda item: item.family_digest)),
    )
