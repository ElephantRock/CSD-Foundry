"""E1 primary projection selection and clean-case population module.

This module selects ``basis_disposition`` as the E1 primary semantic projection,
compiles four straightforward valid transition ``clean cases`` across four
symbolic families, and emits a population-support receipt that binds the clean
population to the immutable A0c successor label-space audit.

The module implements five blocking correctness properties that the pre-reset
version lacked:

1. **Independent verification.** The structured clean-case policy predicate IS
   the independent verifier. It independently derives the expected post-state
   from the before-state and event *without* calling ``apply_event`` or
   ``CsdOracle``. The oracle output is the thing being verified. The second
   ``apply_event`` call is renamed ``deterministic_replay`` (it proves
   determinism, not independent verification).

2. **Pinned A0c predecessor authority.** The predecessor audit SHA-256, source
   commit, schema, release, selection digest, and bundle manifest SHA-256 are
   pinned as module constants and fail-closed on mismatch, so a coherently
   substituted audit cannot pass.

3. **Complete event-symbol extraction.** ``_extract_symbols`` covers every
   event-introduced identifier across all ``CsdEvent`` variants, so a clean-case
   identifier colliding with any existing event-introduced identifier is caught.

4. **Externally bound source_commit in tests.** The orchestration records the
   source commit and tests re-derive the expected value from git state rather
   than reading it back from the receipt.

5. **Real adversarial mutation tests.** ~12 fail-closed canaries exercise the
   hardening gates end-to-end.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

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
from csd_foundry.kernel.models import (
    Assurance,
    AuditEvent,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    SourceState,
)
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.kernel.transitions import apply_event
from csd_foundry.scenarios.spec import (
    ObservationCase,
    RejectedTransitionCase,
    ScenarioCase,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
)


class E1ProjectionCleanCaseError(ValueError):
    """Raised when the projection/clean-case population cannot be compiled."""


# ---------------------------------------------------------------------------
# Schema and release identifiers
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "e1-primary-projection-contract/1"
_RELEASE = "e1-primary-projection/1"
_CLEAN_CASE_POLICY_SCHEMA = "e1-clean-case-policy/1"
_CLEAN_CASE_RECORD_SCHEMA = "e1-clean-case-semantic-record/1"
_CLEAN_CASE_MANIFEST_SCHEMA = "e1-clean-case-manifest/1"
_CLEAN_CASE_EVIDENCE_SCHEMA = "e1-clean-case-evidence/1"
_POPULATION_RECEIPT_SCHEMA = "e1-population-support-receipt/1"

_PRIMARY_PROJECTION_NAME = "basis_disposition"
_VERIFIER_IMPLEMENTATION_IDENTITY = "structured_policy_predicate_v1"

# Clean-case disposition classes: the declared projection outcome for each
# clean case. NEITHER means no basis is removed and no basis survives (the
# before-state has no bases); SURVIVES_ONLY means no basis is removed and at
# least one basis survives (the before-state basis is on a stable dependency
# disjoint from the event).
_DISPOSITION_NEITHER = "NEITHER"
_DISPOSITION_SURVIVES_ONLY = "SURVIVES_ONLY"


# ---------------------------------------------------------------------------
# Fix 2: pinned A0c predecessor authority constants.
#
# These values are NOT read from the audit being authenticated. The compiler
# reads the audit payload, compares every relevant field to these constants,
# and fails closed on any mismatch. This prevents a coherently-substituted
# audit (one whose internal digests are self-consistent but different) from
# passing.
# ---------------------------------------------------------------------------

_EXPECTED_PREDECESSOR_AUDIT_SHA256 = (
    "c5321213a1e89b92561ced7687573481ebe653ff33127c1d9077dd625d32eb09"
)
_EXPECTED_PREDECESSOR_SOURCE_COMMIT = "cfac62da30d501f4744f88d31fee5d3096d1cfb6"
_EXPECTED_PREDECESSOR_AUDIT_SCHEMA = "e1-label-space-audit/1"
_EXPECTED_PREDECESSOR_AUDIT_RELEASE = "e1-label-space-audit/2"
_EXPECTED_PREDECESSOR_SELECTION_DIGEST = (
    "4a9ac4e8a0de98247b8f50b838ad7e67ba151b6e6c8167b2a8840e865b883f49"
)
_EXPECTED_PREDECESSOR_BUNDLE_MANIFEST_SHA256 = (
    "08c15c2fc4387fdd4d9454c192642502b461845dddcde2842f75c302ac694d14"
)

_CLAIM_BOUNDARY = (
    "This module selects basis_disposition as the E1 primary semantic projection and compiles "
    "four straightforward valid transition clean cases across four symbolic families. The "
    "structured policy predicate independently derives the expected post-state without invoking "
    "the kernel transition reducer, so it serves as the independent verifier of the oracle "
    "output; the second apply_event call proves determinism only. The predecessor A0c audit "
    "identity is pinned to constants, so a coherently-substituted audit cannot authenticate "
    "the clean population. This module does not select a tokenizer, execute a model, fix a "
    "training recipe, allocate a GPU, or establish learning value or general transfer."
)


# ---------------------------------------------------------------------------
# Fix 3: complete event-symbol extraction.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScenarioSymbols:
    """Typed inventory of every identifier introduced by a scenario case.

    The inventory combines before-state identifiers (control, evidence with
    their dependencies, and basis identifiers) and every event-introduced
    identifier across all ``CsdEvent`` variants. The isolation check uses this
    to catch a clean-case identifier colliding with any existing event-introduced
    identifier.
    """

    control_ids: frozenset[str]
    evidence_ids: frozenset[str]
    evidence_dependencies: frozenset[str]
    basis_ids: frozenset[str]
    request_ids: frozenset[str]
    profile_ids: frozenset[str]
    event_introduced_evidence_ids: frozenset[str]
    event_introduced_basis_ids: frozenset[str]
    event_introduced_dependency_ids: frozenset[str]
    event_introduced_request_ids: frozenset[str]
    event_introduced_profile_ids: frozenset[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "control_ids": sorted(self.control_ids),
            "evidence_ids": sorted(self.evidence_ids),
            "evidence_dependencies": sorted(self.evidence_dependencies),
            "basis_ids": sorted(self.basis_ids),
            "request_ids": sorted(self.request_ids),
            "profile_ids": sorted(self.profile_ids),
            "event_introduced_evidence_ids": sorted(self.event_introduced_evidence_ids),
            "event_introduced_basis_ids": sorted(self.event_introduced_basis_ids),
            "event_introduced_dependency_ids": sorted(self.event_introduced_dependency_ids),
            "event_introduced_request_ids": sorted(self.event_introduced_request_ids),
            "event_introduced_profile_ids": sorted(self.event_introduced_profile_ids),
        }


def _extract_state_symbols(state: ControlState) -> dict[str, set[str]]:
    """Extract all identifiers present in a before/observation state."""

    control_ids: set[str] = {state.control_id}
    evidence_ids: set[str] = set()
    evidence_dependencies: set[str] = set()
    basis_ids: set[str] = set()
    request_ids: set[str] = set()
    profile_ids: set[str] = set()
    for evidence_item in state.evidence:
        evidence_ids.add(evidence_item.evidence_id)
        evidence_dependencies.update(evidence_item.dependencies)
        if evidence_item.profile_id is not None:
            profile_ids.add(evidence_item.profile_id)
    for basis_item in state.bases:
        basis_ids.add(basis_item.basis_id)
        evidence_ids.update(basis_item.member_evidence_ids)
    basis_ids.update(state.current_source_basis_ids)
    basis_ids.update(state.current_verdict_basis_ids)
    if state.required_profile_id is not None:
        profile_ids.add(state.required_profile_id)
    for request in state.reassessment_requests:
        request_ids.add(request.request_id)
    return {
        "control_ids": control_ids,
        "evidence_ids": evidence_ids,
        "evidence_dependencies": evidence_dependencies,
        "basis_ids": basis_ids,
        "request_ids": request_ids,
        "profile_ids": profile_ids,
    }


def _extract_event_symbols(event: CsdEvent) -> dict[str, set[str]]:
    """Extract every identifier introduced by an event across all CsdEvent variants."""

    evidence_ids: set[str] = set()
    basis_ids: set[str] = set()
    dependency_ids: set[str] = set()
    request_ids: set[str] = set()
    profile_ids: set[str] = set()

    if isinstance(event, DependencyChange):
        dependency_ids.add(event.dependency_id)
    elif isinstance(event, Reassess):
        for evidence_item in event.new_evidence:
            evidence_ids.add(evidence_item.evidence_id)
            dependency_ids.update(evidence_item.dependencies)
            if evidence_item.profile_id is not None:
                profile_ids.add(evidence_item.profile_id)
        for basis_item in event.new_bases:
            basis_ids.add(basis_item.basis_id)
            evidence_ids.update(basis_item.member_evidence_ids)
        request_ids.update(event.close_request_ids)
    elif isinstance(event, RetireControl):
        retirement_evidence = event.retirement_evidence
        evidence_ids.add(retirement_evidence.evidence_id)
        dependency_ids.update(retirement_evidence.dependencies)
        if retirement_evidence.profile_id is not None:
            profile_ids.add(retirement_evidence.profile_id)
    elif isinstance(event, ProfileChange):
        profile_ids.add(event.profile_id)
        if event.request_id is not None:
            request_ids.add(event.request_id)
    elif isinstance(event, RequestReassessment):
        request_ids.add(event.request_id)
    elif isinstance(event, (AdvanceClock, RecordHeartbeat)):
        pass
    else:
        raise E1ProjectionCleanCaseError(f"unsupported CSD event type: {type(event).__qualname__}")

    return {
        "evidence_ids": evidence_ids,
        "basis_ids": basis_ids,
        "dependency_ids": dependency_ids,
        "request_ids": request_ids,
        "profile_ids": profile_ids,
    }


def _extract_symbols(case: ScenarioCase) -> ScenarioSymbols:
    """Build the typed identifier inventory for a scenario case.

    For observation cases, identifiers are read from ``case.state``. For
    rejected-transition cases, identifiers are read from ``case.before`` (and
    the event, if any). For transition cases, identifiers come from
    ``case.before`` and ``case.event``.
    """

    if isinstance(case, ObservationCase):
        state_symbols = _extract_state_symbols(case.state)
        event_symbols: dict[str, set[str]] = {
            "evidence_ids": set(),
            "basis_ids": set(),
            "dependency_ids": set(),
            "request_ids": set(),
            "profile_ids": set(),
        }
    elif isinstance(case, RejectedTransitionCase):
        state_symbols = _extract_state_symbols(case.before)
        if case.event is None:
            event_symbols = {
                "evidence_ids": set(),
                "basis_ids": set(),
                "dependency_ids": set(),
                "request_ids": set(),
                "profile_ids": set(),
            }
        else:
            event_symbols = _extract_event_symbols(case.event)
    elif isinstance(case, TransitionCase):
        state_symbols = _extract_state_symbols(case.before)
        event_symbols = _extract_event_symbols(case.event)
    else:
        raise E1ProjectionCleanCaseError(
            f"unsupported scenario case type: {type(case).__qualname__}"
        )

    return ScenarioSymbols(
        control_ids=frozenset(state_symbols["control_ids"]),
        evidence_ids=frozenset(state_symbols["evidence_ids"]),
        evidence_dependencies=frozenset(state_symbols["evidence_dependencies"]),
        basis_ids=frozenset(state_symbols["basis_ids"]),
        request_ids=frozenset(state_symbols["request_ids"]),
        profile_ids=frozenset(state_symbols["profile_ids"]),
        event_introduced_evidence_ids=frozenset(event_symbols["evidence_ids"]),
        event_introduced_basis_ids=frozenset(event_symbols["basis_ids"]),
        event_introduced_dependency_ids=frozenset(event_symbols["dependency_ids"]),
        event_introduced_request_ids=frozenset(event_symbols["request_ids"]),
        event_introduced_profile_ids=frozenset(event_symbols["profile_ids"]),
    )


def _merge_symbols(symbols: tuple[ScenarioSymbols, ...]) -> dict[str, frozenset[str]]:
    """Union identifier inventories across many cases for isolation comparison."""

    def _union(key: str) -> frozenset[str]:
        return frozenset().union(*(getattr(item, key) for item in symbols))

    return {
        "control_ids": _union("control_ids"),
        "evidence_ids": _union("evidence_ids"),
        "evidence_dependencies": _union("evidence_dependencies"),
        "basis_ids": _union("basis_ids"),
        "request_ids": _union("request_ids"),
        "profile_ids": _union("profile_ids"),
        "event_introduced_evidence_ids": _union("event_introduced_evidence_ids"),
        "event_introduced_basis_ids": _union("event_introduced_basis_ids"),
        "event_introduced_dependency_ids": _union("event_introduced_dependency_ids"),
        "event_introduced_request_ids": _union("event_introduced_request_ids"),
        "event_introduced_profile_ids": _union("event_introduced_profile_ids"),
    }


# Namespace keys shared between the clean population and the existing
# (development-contrast) population symbols. The clean-vs-existing gate
# intersects every clean namespace against the matching existing namespace, so
# the two dictionaries must use the same key vocabulary.
_POPULATION_NAMESPACE_KEYS: tuple[str, ...] = (
    "control_ids",
    "evidence_ids",
    "evidence_dependencies",
    "basis_ids",
    "request_ids",
    "profile_ids",
    "event_introduced_evidence_ids",
    "event_introduced_basis_ids",
    "event_introduced_dependency_ids",
    "event_introduced_request_ids",
    "event_introduced_profile_ids",
)


def _extract_scenario_population_symbols(
    specs: tuple[ScenarioSpec, ...],
) -> dict[str, frozenset[str]]:
    """Extract every identifier in a population of ``ScenarioSpec`` objects.

    The returned dictionary uses the same namespace keys as
    :func:`_merge_symbols`, so a clean population can be intersected against it
    namespace-by-namespace. In addition to the per-case state and event-introduced
    symbols (collected via :func:`_extract_symbols` and :func:`_merge_symbols`),
    the inventory captures population-level identifiers that are not derivable
    from a single case:

    - ``scenario_ids``: each spec's ``scenario_id``;
    - ``case_ids``: every ``case.case_id`` across every spec;
    - ``declared_families``: each spec's declared ``family``;
    - ``family_digests``: the canonical family digest of each spec.

    Population-level namespaces are returned alongside the merged case symbols
    so callers that compare a subset of namespaces (the clean-vs-existing gate
    compares the eleven ``_POPULATION_NAMESPACE_KEYS`` namespaces) do not need a
    second pass.
    """

    from csd_foundry.empirical.e1.scenario_splits import derive_scenario_family_identity

    case_symbols: list[ScenarioSymbols] = []
    scenario_ids: set[str] = set()
    case_ids: set[str] = set()
    declared_families: set[str] = set()
    family_digests: set[str] = set()

    for spec in specs:
        scenario_ids.add(spec.scenario_id)
        declared_families.add(spec.family)
        family_digests.add(derive_scenario_family_identity(spec).family_digest)
        for case in spec.cases:
            case_ids.add(case.case_id)
            case_symbols.append(_extract_symbols(case))

    merged = _merge_symbols(tuple(case_symbols))
    merged["scenario_ids"] = frozenset(scenario_ids)
    merged["case_ids"] = frozenset(case_ids)
    merged["declared_families"] = frozenset(declared_families)
    merged["family_digests"] = frozenset(family_digests)
    return merged


# ---------------------------------------------------------------------------
# Clean-case scenario construction.
# ---------------------------------------------------------------------------


def _e(
    evidence_id: str,
    dimension: str,
    *,
    dependencies: tuple[str, ...] = (),
    status: EvidenceStatus = EvidenceStatus.CURRENT,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        dimension=dimension,
        status=status,
        dependencies=frozenset(dependencies),
    )


def _b(basis_id: str, kind: BasisKind, claim: str, *members: str) -> Basis:
    return Basis(basis_id, kind, claim, frozenset(members))


@dataclass(frozen=True, slots=True)
class CleanCaseSpec:
    """One straightforward valid transition clean case.

    Each clean case has evidence with a stable dependency (distinct from the
    event dependency) and an irrelevant ``DependencyChange`` event. The
    declared class is NEITHER (no bases) or SURVIVES_ONLY (basis unaffected).
    """

    case_id: str
    family: str
    dimension: str
    stable_dependency: str
    event_dependency: str
    declared_class: str
    has_source_basis: bool
    assurance: Assurance
    source_state: SourceState

    def event(self) -> DependencyChange:
        return DependencyChange(self.event_dependency, "apparentlyUnfavourable")

    def before(self) -> ControlState:
        evidence = _e(
            f"EV-{self.case_id}-STABLE",
            self.dimension,
            dependencies=(self.stable_dependency,),
        )
        if not self.has_source_basis:
            return ControlState(
                control_id=f"CTRL-{self.case_id}",
                source_state=self.source_state,
                assurance=self.assurance,
                evidence=(evidence,),
            )
        source_basis = _b(
            f"BASIS-{self.case_id}-SOURCE",
            BasisKind.SOURCE,
            self.source_state.value,
            evidence.evidence_id,
        )
        return ControlState(
            control_id=f"CTRL-{self.case_id}",
            source_state=self.source_state,
            assurance=self.assurance,
            evidence=(evidence,),
            bases=(source_basis,),
            current_source_basis_ids=frozenset({source_basis.basis_id}),
        )

    def before_with_verdict_basis(self, claim: str) -> ControlState:
        """Build a before-state carrying a verdict basis on the stable evidence."""

        evidence = _e(
            f"EV-{self.case_id}-STABLE",
            self.dimension,
            dependencies=(self.stable_dependency,),
        )
        verdict_basis = _b(
            f"BASIS-{self.case_id}-VERDICT",
            BasisKind.VERDICT,
            claim,
            evidence.evidence_id,
        )
        return ControlState(
            control_id=f"CTRL-{self.case_id}",
            source_state=self.source_state,
            assurance=self.assurance,
            evidence=(evidence,),
            bases=(verdict_basis,),
            current_verdict_basis_ids=frozenset({verdict_basis.basis_id}),
        )

    def transition_case(self, before: ControlState) -> TransitionCase:
        return TransitionCase(
            case_id=f"{self.case_id}/irrelevant-dependency-change",
            before=before,
            event=self.event(),
            expected=StateExpectation(
                source_state=self.source_state,
                assurance=self.assurance,
                evidence_statuses=((f"EV-{self.case_id}-STABLE", EvidenceStatus.CURRENT),),
                current_source_basis_ids=(
                    frozenset({f"BASIS-{self.case_id}-SOURCE"})
                    if self.has_source_basis
                    else frozenset()
                ),
                current_verdict_basis_ids=(
                    frozenset({f"BASIS-{self.case_id}-VERDICT"})
                    if self.declared_class == _DISPOSITION_SURVIVES_ONLY
                    and not self.has_source_basis
                    else frozenset()
                ),
                history_length=1,
            ),
            expected_invalidated_evidence=frozenset(),
            expected_surviving_bases=(
                frozenset({f"BASIS-{self.case_id}-SOURCE"})
                if self.has_source_basis
                else (
                    frozenset({f"BASIS-{self.case_id}-VERDICT"})
                    if self.declared_class == _DISPOSITION_SURVIVES_ONLY
                    else frozenset()
                )
            ),
            required_trace_rules=frozenset({"INV-11", "INV-14", "INV-16", "SYM-01"}),
        )


_CLEAN_CASE_SPECS: tuple[CleanCaseSpec, ...] = (
    # E1-CLEAN-01: dimension="D", no bases, UNKNOWN source -> NEITHER
    CleanCaseSpec(
        case_id="E1-CLEAN-01",
        family="clean_case_no_basis_d",
        dimension="D",
        stable_dependency="DEP-CLEAN-01-STABLE",
        event_dependency="DEP-CLEAN-01-IRRELEVANT",
        declared_class=_DISPOSITION_NEITHER,
        has_source_basis=False,
        assurance=Assurance.UNVERIFIED,
        source_state=SourceState.UNKNOWN,
    ),
    # E1-CLEAN-02: dimension="V", no bases, UNKNOWN source -> NEITHER (distinct from 01)
    CleanCaseSpec(
        case_id="E1-CLEAN-02",
        family="clean_case_no_basis_v",
        dimension="V",
        stable_dependency="DEP-CLEAN-02-STABLE",
        event_dependency="DEP-CLEAN-02-IRRELEVANT",
        declared_class=_DISPOSITION_NEITHER,
        has_source_basis=False,
        assurance=Assurance.UNVERIFIED,
        source_state=SourceState.UNKNOWN,
    ),
    # E1-CLEAN-03: dimension="A", source basis on stable dep, CONNECTED -> SURVIVES_ONLY
    CleanCaseSpec(
        case_id="E1-CLEAN-03",
        family="clean_case_source_survives_a",
        dimension="A",
        stable_dependency="DEP-CLEAN-03-STABLE",
        event_dependency="DEP-CLEAN-03-IRRELEVANT",
        declared_class=_DISPOSITION_SURVIVES_ONLY,
        has_source_basis=True,
        assurance=Assurance.UNVERIFIED,
        source_state=SourceState.CONNECTED,
    ),
    # E1-CLEAN-04: dimension="V", verdict basis on stable dep, UNKNOWN, PASS -> SURVIVES_ONLY
    CleanCaseSpec(
        case_id="E1-CLEAN-04",
        family="clean_case_verdict_survives_v",
        dimension="V",
        stable_dependency="DEP-CLEAN-04-STABLE",
        event_dependency="DEP-CLEAN-04-IRRELEVANT",
        declared_class=_DISPOSITION_SURVIVES_ONLY,
        has_source_basis=False,
        assurance=Assurance.PASS,
        source_state=SourceState.UNKNOWN,
    ),
)


def build_clean_case_transition_cases() -> tuple[tuple[CleanCaseSpec, TransitionCase], ...]:
    """Build the four clean-case transition cases.

    Returns a tuple of (spec, transition_case) pairs. The before-state for
    E1-CLEAN-04 carries a verdict basis (PASS) instead of a source basis, since
    its declared class is SURVIVES_ONLY via a surviving verdict.
    """

    built: list[tuple[CleanCaseSpec, TransitionCase]] = []
    for spec in _CLEAN_CASE_SPECS:
        if spec.case_id == "E1-CLEAN-04":
            before = spec.before_with_verdict_basis(Assurance.PASS.value)
        else:
            before = spec.before()
        built.append((spec, spec.transition_case(before)))
    return tuple(built)


# ---------------------------------------------------------------------------
# Fix 1: independent verification via the structured policy predicate.
#
# The predicate independently derives the expected post-state from the
# before-state and event without calling apply_event or CsdOracle. It then
# reports the ten policy fields. The oracle output is the thing being verified.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CleanCasePolicyReceipt:
    """Structured policy predicate receipt (10 fields).

    Each boolean is independently derived from the before-state and event, then
    compared against the oracle post-state. ``policy_passes`` is the conjunction
    of the other nine checks.
    """

    accepted_dependency_change: bool
    dependency_disjoint: bool
    no_evidence_change: bool
    no_basis_removal: bool
    no_source_change: bool
    no_assurance_change: bool
    no_obligation_change: bool
    semantic_state_unchanged: bool
    history_exactly_appended: bool
    policy_passes: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted_dependency_change": self.accepted_dependency_change,
            "dependency_disjoint": self.dependency_disjoint,
            "no_evidence_change": self.no_evidence_change,
            "no_basis_removal": self.no_basis_removal,
            "no_source_change": self.no_source_change,
            "no_assurance_change": self.no_assurance_change,
            "no_obligation_change": self.no_obligation_change,
            "semantic_state_unchanged": self.semantic_state_unchanged,
            "history_exactly_appended": self.history_exactly_appended,
            "policy_passes": self.policy_passes,
        }


def evaluate_clean_case_policy(
    before: ControlState,
    event: DependencyChange,
    after: ControlState,
) -> CleanCasePolicyReceipt:
    """Independently derive the expected post-state and compare to ``after``.

    This predicate does NOT call ``apply_event`` or ``CsdOracle``. It derives
    each expected field directly from ``before`` and ``event``:

    - the event must be an accepted ``DependencyChange``;
    - the event dependency must be disjoint from every evidence dependency
      (nothing is affected, so evidence is preserved exactly);
    - evidence tuples must match exactly (identity, status, dependencies);
    - basis sets must match exactly (no removal, no rewrite);
    - source_state, assurance, and obligation must be unchanged;
    - semantic-state fields (current source/verdict basis ids) must be unchanged;
    - history must be exactly the before history plus one DependencyChange audit
      event.
    """

    accepted = isinstance(event, DependencyChange)

    event_dep = event.dependency_id
    all_evidence_deps: set[str] = set()
    for evidence_item in before.evidence:
        all_evidence_deps.update(evidence_item.dependencies)
    dependency_disjoint = event_dep not in all_evidence_deps

    # Evidence: identity and full content must match (status preserved because
    # nothing is affected by the disjoint dependency).
    before_evidence_by_id = before.evidence_by_id()
    after_evidence_by_id = after.evidence_by_id()
    no_evidence_change = before_evidence_by_id == after_evidence_by_id and tuple(
        before.evidence
    ) == tuple(after.evidence)

    # Bases: the append-only basis ledger must be unchanged (identity and
    # content), AND no current basis may be removed from the current source or
    # verdict sets. A DependencyChange that invalidates supporting evidence
    # removes the basis from the current set even though the Basis object itself
    # is retained in the append-only ledger.
    no_basis_removal = (
        before.bases_by_id() == after.bases_by_id()
        and tuple(before.bases) == tuple(after.bases)
        and before.current_source_basis_ids == after.current_source_basis_ids
        and before.current_verdict_basis_ids == after.current_verdict_basis_ids
    )

    no_source_change = before.source_state == after.source_state
    no_assurance_change = before.assurance == after.assurance
    no_obligation_change = before.obligation == after.obligation

    # Semantic state: every non-history ControlState field must be unchanged.
    # Comparing only the basis-id sets would miss a mutation that rewrites the
    # basis ledger, flips the logical clock, or alters the required profile /
    # reassessment requests / heartbeat while preserving the current sets. The
    # full 13-field comparison (history excluded; the append is checked below)
    # closes that gap. This is intentionally broader than no_basis_removal so a
    # semantic-only mutation that leaves bases untouched is still caught.
    expected_audit = AuditEvent.create(
        "DependencyChange",
        dependency_id=event.dependency_id,
        apparent_direction=event.apparent_direction or "unspecified",
    )
    semantic_state_unchanged = all(
        getattr(before, fn) == getattr(after, fn)
        for fn in (
            "control_id",
            "obligation",
            "source_state",
            "assurance",
            "evidence",
            "bases",
            "current_source_basis_ids",
            "current_verdict_basis_ids",
            "logical_time",
            "required_profile_id",
            "required_profile_version",
            "reassessment_requests",
            "heartbeat",
        )
    )

    # History: exactly one new DependencyChange audit event appended.
    history_exactly_appended = (
        len(after.history) == len(before.history) + 1
        and tuple(after.history)[: len(before.history)] == tuple(before.history)
        and after.history[len(before.history)] == expected_audit
    )

    policy_passes = (
        accepted
        and dependency_disjoint
        and no_evidence_change
        and no_basis_removal
        and no_source_change
        and no_assurance_change
        and no_obligation_change
        and semantic_state_unchanged
        and history_exactly_appended
    )

    return CleanCasePolicyReceipt(
        accepted_dependency_change=accepted,
        dependency_disjoint=dependency_disjoint,
        no_evidence_change=no_evidence_change,
        no_basis_removal=no_basis_removal,
        no_source_change=no_source_change,
        no_assurance_change=no_assurance_change,
        no_obligation_change=no_obligation_change,
        semantic_state_unchanged=semantic_state_unchanged,
        history_exactly_appended=history_exactly_appended,
        policy_passes=policy_passes,
    )


# ---------------------------------------------------------------------------
# Clean-case semantic record compilation (Fix 1 receipts).
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CleanCaseSemanticRecord:
    """One compiled clean-case semantic record with the four receipt digests."""

    schema_version: str
    record_id: str
    case_id: str
    declared_family: str
    declared_class: str
    event_type: str
    before_state_digest: str
    event_digest: str
    after_state_digest: str
    trace_digest: str
    oracle_receipt_digest: str
    deterministic_replay_digest: str
    independent_verification_receipt_digest: str
    verifier_implementation_identity: str
    policy_receipt: CleanCasePolicyReceipt
    expected_invalidated_evidence: tuple[str, ...]
    expected_surviving_bases: tuple[str, ...]
    observed_trace_rules: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "case_id": self.case_id,
            "declared_family": self.declared_family,
            "declared_class": self.declared_class,
            "event_type": self.event_type,
            "before_state_digest": self.before_state_digest,
            "event_digest": self.event_digest,
            "after_state_digest": self.after_state_digest,
            "trace_digest": self.trace_digest,
            "oracle_receipt_digest": self.oracle_receipt_digest,
            "deterministic_replay_digest": self.deterministic_replay_digest,
            "independent_verification_receipt_digest": (
                self.independent_verification_receipt_digest
            ),
            "verifier_implementation_identity": self.verifier_implementation_identity,
            "policy_receipt": self.policy_receipt.to_dict(),
            "expected_invalidated_evidence": list(self.expected_invalidated_evidence),
            "expected_surviving_bases": list(self.expected_surviving_bases),
            "observed_trace_rules": list(self.observed_trace_rules),
        }


def compile_clean_case_record(
    spec: CleanCaseSpec,
    case: TransitionCase,
) -> CleanCaseSemanticRecord:
    """Compile one clean-case semantic record with independent verification.

    The oracle output is the thing being verified. The deterministic replay
    (second ``apply_event`` call) proves determinism only. The independent
    verification receipt covers the structured policy predicate result.
    """

    if not isinstance(case.event, DependencyChange):
        raise E1ProjectionCleanCaseError(
            f"{case.case_id}: clean-case event must be a DependencyChange"
        )

    oracle = CsdOracle()
    oracle_result = oracle.apply(case.before, case.event)
    oracle_after = oracle_result.after
    oracle_trace = oracle_result.trace

    # Deterministic replay: a second apply_event call. Proves determinism only;
    # NOT independent verification (same reducer).
    replay_after, replay_trace = apply_event(case.before, case.event)
    if (replay_after, replay_trace) != (oracle_after, oracle_trace):
        raise E1ProjectionCleanCaseError(
            f"{case.case_id}: deterministic replay disagrees with oracle"
        )

    # Independent verification: the structured policy predicate derives the
    # expected post-state from before + event without calling apply_event.
    policy = evaluate_clean_case_policy(case.before, case.event, oracle_after)

    before_digest = canonical_sha256(case.before)
    event_digest = canonical_sha256(case.event)
    after_digest = canonical_sha256(oracle_after)
    trace_digest = canonical_sha256(oracle_trace)

    oracle_receipt_digest = canonical_sha256(
        {
            "case_id": case.case_id,
            "before_state_digest": before_digest,
            "event_digest": event_digest,
            "after_state_digest": after_digest,
            "trace_digest": trace_digest,
        }
    )
    deterministic_replay_digest = canonical_sha256(
        {
            "case_id": case.case_id,
            "replay_after_digest": canonical_sha256(replay_after),
            "replay_trace_digest": canonical_sha256(replay_trace),
            "matches_oracle": True,
        }
    )
    independent_verification_receipt_digest = canonical_sha256(
        {
            "case_id": case.case_id,
            "verifier_implementation_identity": _VERIFIER_IMPLEMENTATION_IDENTITY,
            "policy_receipt": policy.to_dict(),
            "oracle_after_digest": after_digest,
            "matches_policy": policy.policy_passes,
        }
    )

    # All four digests must be mutually distinct.
    digests = {
        oracle_receipt_digest,
        deterministic_replay_digest,
        independent_verification_receipt_digest,
    }
    if len(digests) != 3:
        raise E1ProjectionCleanCaseError(
            f"{case.case_id}: receipt digests must be mutually distinct"
        )

    return CleanCaseSemanticRecord(
        schema_version=_CLEAN_CASE_RECORD_SCHEMA,
        record_id=f"e1-clean-case/{spec.case_id}/{case.case_id}",
        case_id=case.case_id,
        declared_family=spec.family,
        declared_class=spec.declared_class,
        event_type=type(case.event).__name__,
        before_state_digest=before_digest,
        event_digest=event_digest,
        after_state_digest=after_digest,
        trace_digest=trace_digest,
        oracle_receipt_digest=oracle_receipt_digest,
        deterministic_replay_digest=deterministic_replay_digest,
        independent_verification_receipt_digest=independent_verification_receipt_digest,
        verifier_implementation_identity=_VERIFIER_IMPLEMENTATION_IDENTITY,
        policy_receipt=policy,
        expected_invalidated_evidence=tuple(
            sorted(case.expected_invalidated_evidence or frozenset())
        ),
        expected_surviving_bases=tuple(sorted(case.expected_surviving_bases or frozenset())),
        observed_trace_rules=tuple(sorted(oracle_trace.rules_fired)),
    )


# ---------------------------------------------------------------------------
# Projection contract, manifest, evidence, and population receipt.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PrimaryProjectionContract:
    """Contract binding the selected primary projection to its authority."""

    schema_version: str
    release: str
    source_commit: str
    primary_projection_name: str
    primary_projection_description: str
    predecessor_audit_sha256: str
    predecessor_source_commit: str
    predecessor_audit_schema: str
    predecessor_audit_release: str
    predecessor_selection_contract_digest: str
    predecessor_bundle_manifest_sha256: str
    compiler_implementation_sha256: str
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "primary_projection_name": self.primary_projection_name,
            "primary_projection_description": self.primary_projection_description,
            "predecessor_audit_sha256": self.predecessor_audit_sha256,
            "predecessor_source_commit": self.predecessor_source_commit,
            "predecessor_audit_schema": self.predecessor_audit_schema,
            "predecessor_audit_release": self.predecessor_audit_release,
            "predecessor_selection_contract_digest": (self.predecessor_selection_contract_digest),
            "predecessor_bundle_manifest_sha256": self.predecessor_bundle_manifest_sha256,
            "compiler_implementation_sha256": self.compiler_implementation_sha256,
            "claim_boundary": self.claim_boundary,
        }


@dataclass(frozen=True, slots=True)
class CleanCasePolicy:
    """Frozen clean-case policy: supported iff every clean case passes the predicate."""

    schema_version: str
    release: str
    source_commit: str
    verifier_implementation_identity: str
    clean_case_count: int
    clean_case_policy_status: str
    clean_case_class_distribution: dict[str, int]
    clean_case_policy_receipt_digests: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "verifier_implementation_identity": self.verifier_implementation_identity,
            "clean_case_count": self.clean_case_count,
            "clean_case_policy_status": self.clean_case_policy_status,
            "clean_case_class_distribution": dict(
                sorted(self.clean_case_class_distribution.items())
            ),
            "clean_case_policy_receipt_digests": list(self.clean_case_policy_receipt_digests),
        }


@dataclass(frozen=True, slots=True)
class CleanCaseManifest:
    """Manifest binding clean-case records to the isolation inventory."""

    schema_version: str
    release: str
    source_commit: str
    clean_case_count: int
    clean_case_record_digests: tuple[str, ...]
    isolation_inventory: dict[str, frozenset[str]]
    isolation_collisions: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "clean_case_count": self.clean_case_count,
            "clean_case_record_digests": list(self.clean_case_record_digests),
            "isolation_inventory": {
                key: sorted(value) for key, value in self.isolation_inventory.items()
            },
            "isolation_collisions": list(self.isolation_collisions),
        }


@dataclass(frozen=True, slots=True)
class CleanCaseEvidence:
    """Evidence file binding the four clean-case records to their receipts."""

    schema_version: str
    release: str
    source_commit: str
    verifier_implementation_identity: str
    clean_case_records: tuple[CleanCaseSemanticRecord, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "verifier_implementation_identity": self.verifier_implementation_identity,
            "clean_case_count": len(self.clean_case_records),
            "clean_case_records": [item.to_dict() for item in self.clean_case_records],
        }


@dataclass(frozen=True, slots=True)
class PopulationSupportReceipt:
    """Receipt binding the clean population to the predecessor audit."""

    schema_version: str
    release: str
    source_commit: str
    primary_projection_name: str
    primary_projection_contract_digest: str
    clean_case_policy_digest: str
    clean_case_records_digest: str
    clean_case_manifest_digest: str
    clean_case_evidence_digest: str
    constituent_artifact_digests: dict[str, str]
    predecessor_audit_sha256: str
    predecessor_selection_contract_digest: str
    predecessor_bundle_manifest_sha256: str
    verifier_implementation_identity: str
    compiler_implementation_sha256: str
    carried_blockers: tuple[str, ...]
    full_e1_population_support: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "primary_projection_name": self.primary_projection_name,
            "primary_projection_contract_digest": self.primary_projection_contract_digest,
            "clean_case_policy_digest": self.clean_case_policy_digest,
            "clean_case_records_digest": self.clean_case_records_digest,
            "clean_case_manifest_digest": self.clean_case_manifest_digest,
            "clean_case_evidence_digest": self.clean_case_evidence_digest,
            "constituent_artifact_digests": dict(sorted(self.constituent_artifact_digests.items())),
            "predecessor_audit_sha256": self.predecessor_audit_sha256,
            "predecessor_selection_contract_digest": (self.predecessor_selection_contract_digest),
            "predecessor_bundle_manifest_sha256": self.predecessor_bundle_manifest_sha256,
            "verifier_implementation_identity": self.verifier_implementation_identity,
            "compiler_implementation_sha256": self.compiler_implementation_sha256,
            "carried_blockers": list(self.carried_blockers),
            "full_e1_population_support": self.full_e1_population_support,
        }


# ---------------------------------------------------------------------------
# Fix 2: predecessor audit authentication.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthenticatedPredecessorAudit:
    """Predecessor A0c audit after pinned-constant authentication."""

    audit_sha256: str
    payload: dict[str, Any]
    source_commit: str
    selection_contract_digest: str
    bundle_manifest_sha256: str
    experiment_blockers: tuple[str, ...]
    primary_population_supported: bool


def authenticate_predecessor_audit(audit_bytes: bytes) -> AuthenticatedPredecessorAudit:
    """Authenticate the predecessor A0c audit against pinned constants.

    The audit SHA-256 is computed over the raw bytes and compared to the pinned
    constant. The payload fields are then compared to the pinned constants. This
    fail-closed gate prevents a coherently-substituted audit (one whose internal
    digests are self-consistent but different) from authenticating the clean
    population.
    """

    import json

    audit_sha256 = hashlib.sha256(audit_bytes).hexdigest()
    if audit_sha256 != _EXPECTED_PREDECESSOR_AUDIT_SHA256:
        raise E1ProjectionCleanCaseError(
            f"predecessor audit SHA-256 mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_AUDIT_SHA256}, observed {audit_sha256}"
        )

    payload: dict[str, Any] = json.loads(audit_bytes.decode("utf-8"))

    schema_version = str(payload.get("schema_version"))
    if schema_version != _EXPECTED_PREDECESSOR_AUDIT_SCHEMA:
        raise E1ProjectionCleanCaseError(
            f"predecessor audit schema_version mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_AUDIT_SCHEMA}, observed {schema_version}"
        )
    release = str(payload.get("release"))
    if release != _EXPECTED_PREDECESSOR_AUDIT_RELEASE:
        raise E1ProjectionCleanCaseError(
            f"predecessor audit release mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_AUDIT_RELEASE}, observed {release}"
        )
    source_commit = str(payload.get("source_commit"))
    if source_commit != _EXPECTED_PREDECESSOR_SOURCE_COMMIT:
        raise E1ProjectionCleanCaseError(
            f"predecessor source_commit mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_SOURCE_COMMIT}, observed {source_commit}"
        )
    selection_digest = str(payload.get("selection_contract_digest"))
    if selection_digest != _EXPECTED_PREDECESSOR_SELECTION_DIGEST:
        raise E1ProjectionCleanCaseError(
            f"predecessor selection_contract_digest mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_SELECTION_DIGEST}, observed {selection_digest}"
        )
    bundle_manifest = str(payload.get("foundry_bundle_manifest_sha256"))
    if bundle_manifest != _EXPECTED_PREDECESSOR_BUNDLE_MANIFEST_SHA256:
        raise E1ProjectionCleanCaseError(
            f"predecessor bundle_manifest_sha256 mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_BUNDLE_MANIFEST_SHA256}, observed {bundle_manifest}"
        )

    raw_blockers = payload.get("experiment_blockers", [])
    if not isinstance(raw_blockers, list):
        raise E1ProjectionCleanCaseError("predecessor audit experiment_blockers must be a list")
    blockers = tuple(str(item) for item in raw_blockers)
    primary_supported = bool(payload.get("primary_population_supported"))

    return AuthenticatedPredecessorAudit(
        audit_sha256=audit_sha256,
        payload=payload,
        source_commit=source_commit,
        selection_contract_digest=selection_digest,
        bundle_manifest_sha256=bundle_manifest,
        experiment_blockers=blockers,
        primary_population_supported=primary_supported,
    )


# ---------------------------------------------------------------------------
# Isolation inventory and collision detection (Fix 3).
# ---------------------------------------------------------------------------


def compute_isolation_inventory(
    records: tuple[CleanCaseSemanticRecord, ...],
    clean_cases: tuple[TransitionCase, ...],
    *,
    existing_symbols: dict[str, frozenset[str]] | None = None,
) -> tuple[dict[str, frozenset[str]], tuple[str, ...]]:
    """Compute the clean-case isolation inventory and detect collisions.

    The isolation inventory unions all clean-case identifiers. Three collision
    classes are detected:

    1. A clean-case before-state identifier that also appears as an
       event-introduced identifier (across all clean cases).
    2. A pairwise intra-clean duplicate: an identifier appearing in more than one
       clean case (the union would silently collapse it, so the per-case symbols
       are inspected before unioning).
    3. A clean identifier that collides with an identifier in the existing
       (development-contrast) population, when ``existing_symbols`` is supplied.
    """

    symbols = tuple(_extract_symbols(case) for case in clean_cases)
    merged = _merge_symbols(symbols)

    # Detect collisions: a clean-case identifier that also appears as an
    # event-introduced identifier, or a duplicate within the clean population.
    collisions: list[str] = []

    # Before-state identifiers colliding with event-introduced identifiers.
    evidence_collision = merged["evidence_ids"] & merged["event_introduced_evidence_ids"]
    for item in sorted(evidence_collision):
        collisions.append(f"evidence_id_collision:{item}")
    basis_collision = merged["basis_ids"] & merged["event_introduced_basis_ids"]
    for item in sorted(basis_collision):
        collisions.append(f"basis_id_collision:{item}")
    dependency_collision = (
        merged["evidence_dependencies"] & merged["event_introduced_dependency_ids"]
    )
    for item in sorted(dependency_collision):
        collisions.append(f"dependency_collision:{item}")
    request_collision = merged["request_ids"] & merged["event_introduced_request_ids"]
    for item in sorted(request_collision):
        collisions.append(f"request_id_collision:{item}")
    profile_collision = merged["profile_ids"] & merged["event_introduced_profile_ids"]
    for item in sorted(profile_collision):
        collisions.append(f"profile_id_collision:{item}")

    # Pairwise intra-clean disjointness: an identifier appearing in more than one
    # clean case is a duplicate the union would silently hide. The per-case
    # symbols are ``ScenarioSymbols`` frozen dataclasses, so attribute access
    # (getattr) is used rather than dict subscript.
    seen_by_ns: dict[str, dict[str, int]] = {key: {} for key in _POPULATION_NAMESPACE_KEYS}
    for syms in symbols:
        for ns_key in _POPULATION_NAMESPACE_KEYS:
            for item in getattr(syms, ns_key, frozenset()):
                seen_by_ns[ns_key][item] = seen_by_ns[ns_key].get(item, 0) + 1
    for ns_key in _POPULATION_NAMESPACE_KEYS:
        for item, count in sorted(seen_by_ns[ns_key].items()):
            if count > 1:
                collisions.append(f"intra_clean_{ns_key}_duplicate:{item}")

    # Clean-vs-existing isolation: compare unified identity domains, not
    # individual storage namespaces. A clean before-state evidence ID must not
    # collide with an existing event-introduced evidence ID even though they
    # live in different per-case namespaces. Each identity domain is unified
    # by unioning state-origin and event-introduced namespaces.
    if existing_symbols is not None:
        # Build unified identity domains for the clean population.
        clean_unified = {
            "evidence": merged.get("evidence_ids", frozenset())
            | merged.get("event_introduced_evidence_ids", frozenset()),
            "basis": merged.get("basis_ids", frozenset())
            | merged.get("event_introduced_basis_ids", frozenset()),
            "dependency": merged.get("evidence_dependencies", frozenset())
            | merged.get("event_introduced_dependency_ids", frozenset()),
            "request": merged.get("request_ids", frozenset())
            | merged.get("event_introduced_request_ids", frozenset()),
            "profile": merged.get("profile_ids", frozenset())
            | merged.get("event_introduced_profile_ids", frozenset()),
            "control": merged.get("control_ids", frozenset()),
            "scenario": merged.get("scenario_ids", frozenset()),
            "case": merged.get("case_ids", frozenset()),
            "family": merged.get("declared_families", frozenset()),
            "family_digest": merged.get("family_digests", frozenset()),
        }

        # Build unified identity domains for the existing population.
        existing_unified = {
            "evidence": existing_symbols.get("evidence_ids", frozenset())
            | existing_symbols.get("event_introduced_evidence_ids", frozenset()),
            "basis": existing_symbols.get("basis_ids", frozenset())
            | existing_symbols.get("event_introduced_basis_ids", frozenset()),
            "dependency": existing_symbols.get("evidence_dependencies", frozenset())
            | existing_symbols.get("event_introduced_dependency_ids", frozenset()),
            "request": existing_symbols.get("request_ids", frozenset())
            | existing_symbols.get("event_introduced_request_ids", frozenset()),
            "profile": existing_symbols.get("profile_ids", frozenset())
            | existing_symbols.get("event_introduced_profile_ids", frozenset()),
            "control": existing_symbols.get("control_ids", frozenset()),
            "scenario": existing_symbols.get("scenario_ids", frozenset()),
            "case": existing_symbols.get("case_ids", frozenset()),
            "family": existing_symbols.get("declared_families", frozenset()),
            "family_digest": existing_symbols.get("family_digests", frozenset()),
        }

        for domain in sorted(set(clean_unified) & set(existing_unified)):
            for item in sorted(clean_unified[domain] & existing_unified[domain]):
                collisions.append(f"clean_vs_existing:{domain}:{item}")

    return merged, tuple(collisions)


# ---------------------------------------------------------------------------
# Top-level compilation: the 6 output artifacts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProjectionCleanCasePopulation:
    """Compiled projection + clean-case population artifacts."""

    projection_contract: PrimaryProjectionContract
    clean_case_policy: CleanCasePolicy
    clean_case_records: tuple[CleanCaseSemanticRecord, ...]
    clean_case_manifest: CleanCaseManifest
    clean_case_evidence: CleanCaseEvidence
    population_support_receipt: PopulationSupportReceipt

    def artifacts(self) -> dict[str, bytes]:
        """Return the six canonical artifacts keyed by output filename."""

        records_jsonl = b"".join(
            canonical_json_bytes(item.to_dict()) for item in self.clean_case_records
        )
        return {
            "primary_projection_contract.json": canonical_json_bytes(
                self.projection_contract.to_dict()
            ),
            "clean_case_policy.json": canonical_json_bytes(self.clean_case_policy.to_dict()),
            "clean_case_semantic_records.jsonl": records_jsonl,
            "clean_case_manifest.json": canonical_json_bytes(self.clean_case_manifest.to_dict()),
            "clean_case_evidence.json": canonical_json_bytes(self.clean_case_evidence.to_dict()),
            "population_support_receipt.json": canonical_json_bytes(
                self.population_support_receipt.to_dict()
            ),
        }


def compile_projection_clean_case_population(
    *,
    source_commit: str,
    predecessor_audit_bytes: bytes,
    compiler_implementation_sha256: str,
) -> ProjectionCleanCasePopulation:
    """Compile the projection contract, clean-case population, and receipt.

    Parameters
    ----------
    source_commit:
        The git commit SHA that produced these artifacts (commit S in the spec).
    predecessor_audit_bytes:
        Raw bytes of the A0c predecessor audit (``data/e1/v2/label_space_audit.json``).
    compiler_implementation_sha256:
        SHA-256 of this module's source bytes. Passed in by the orchestration so
        the same value is bound into every artifact.
    """

    # Fix 2: authenticate the predecessor audit against pinned constants.
    predecessor = authenticate_predecessor_audit(predecessor_audit_bytes)

    # Build and compile the four clean cases.
    clean_pairs = build_clean_case_transition_cases()
    clean_cases = tuple(pair[1] for pair in clean_pairs)
    records = tuple(compile_clean_case_record(spec, case) for spec, case in clean_pairs)
    if len(records) != 4:
        raise E1ProjectionCleanCaseError(
            f"expected exactly 4 clean-case records, observed {len(records)}"
        )

    # Fix 1: every clean case must pass the independent policy predicate.
    all_pass = all(record.policy_receipt.policy_passes for record in records)
    if not all_pass:
        failed = [record.case_id for record in records if not record.policy_receipt.policy_passes]
        raise E1ProjectionCleanCaseError(f"clean-case policy predicate failed for: {failed}")

    # Declared-class distribution: 2 NEITHER + 2 SURVIVES_ONLY.
    class_distribution: dict[str, int] = {}
    for spec, _ in clean_pairs:
        class_distribution[spec.declared_class] = class_distribution.get(spec.declared_class, 0) + 1
    if (
        class_distribution.get(_DISPOSITION_NEITHER, 0) != 2
        or class_distribution.get(_DISPOSITION_SURVIVES_ONLY, 0) != 2
    ):
        raise E1ProjectionCleanCaseError(
            f"expected 2 NEITHER + 2 SURVIVES_ONLY, observed {class_distribution}"
        )

    # Fix 3: isolation inventory and collision detection. The clean population is
    # checked for intra-clean duplicates and against the existing
    # development-contrast population so a clean-case identifier cannot reuse an
    # identifier already bound in the predecessor label space.
    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )
    from csd_foundry.scenarios.registry import SCENARIOS

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    overlay_specs = tuple(overlay_catalog.values())
    existing_symbols = _extract_scenario_population_symbols(overlay_specs)

    isolation_inventory, collisions = compute_isolation_inventory(
        records,
        clean_cases,
        existing_symbols=existing_symbols,
    )
    if collisions:
        raise E1ProjectionCleanCaseError(
            f"clean-case symbolic namespace collisions detected: {list(collisions)}"
        )

    # Projection contract.
    projection_contract = PrimaryProjectionContract(
        schema_version=_SCHEMA_VERSION,
        release=_RELEASE,
        source_commit=source_commit,
        primary_projection_name=_PRIMARY_PROJECTION_NAME,
        primary_projection_description=(
            "Composite basis disposition over (any_basis_removed, any_basis_survives); "
            "the primary semantic projection selected from the A0c candidate inventory."
        ),
        predecessor_audit_sha256=predecessor.audit_sha256,
        predecessor_source_commit=predecessor.source_commit,
        predecessor_audit_schema=_EXPECTED_PREDECESSOR_AUDIT_SCHEMA,
        predecessor_audit_release=_EXPECTED_PREDECESSOR_AUDIT_RELEASE,
        predecessor_selection_contract_digest=predecessor.selection_contract_digest,
        predecessor_bundle_manifest_sha256=predecessor.bundle_manifest_sha256,
        compiler_implementation_sha256=compiler_implementation_sha256,
        claim_boundary=_CLAIM_BOUNDARY,
    )

    # Clean-case policy.
    policy_receipt_digests = tuple(
        record.independent_verification_receipt_digest for record in records
    )
    clean_case_policy = CleanCasePolicy(
        schema_version=_CLEAN_CASE_POLICY_SCHEMA,
        release=_RELEASE,
        source_commit=source_commit,
        verifier_implementation_identity=_VERIFIER_IMPLEMENTATION_IDENTITY,
        clean_case_count=len(records),
        clean_case_policy_status="supported" if all_pass else "unsupported",
        clean_case_class_distribution=class_distribution,
        clean_case_policy_receipt_digests=policy_receipt_digests,
    )

    # Clean-case manifest.
    record_digests = tuple(canonical_sha256(record.to_dict()) for record in records)
    clean_case_manifest = CleanCaseManifest(
        schema_version=_CLEAN_CASE_MANIFEST_SCHEMA,
        release=_RELEASE,
        source_commit=source_commit,
        clean_case_count=len(records),
        clean_case_record_digests=record_digests,
        isolation_inventory=isolation_inventory,
        isolation_collisions=collisions,
    )

    # Clean-case evidence.
    clean_case_evidence = CleanCaseEvidence(
        schema_version=_CLEAN_CASE_EVIDENCE_SCHEMA,
        release=_RELEASE,
        source_commit=source_commit,
        verifier_implementation_identity=_VERIFIER_IMPLEMENTATION_IDENTITY,
        clean_case_records=records,
    )

    # Constituent artifact digests (all 5 non-receipt artifacts).
    records_jsonl = b"".join(canonical_json_bytes(item.to_dict()) for item in records)
    constituent_artifact_digests = {
        "primary_projection_contract.json": hashlib.sha256(
            canonical_json_bytes(projection_contract.to_dict())
        ).hexdigest(),
        "clean_case_policy.json": hashlib.sha256(
            canonical_json_bytes(clean_case_policy.to_dict())
        ).hexdigest(),
        "clean_case_semantic_records.jsonl": hashlib.sha256(records_jsonl).hexdigest(),
        "clean_case_manifest.json": hashlib.sha256(
            canonical_json_bytes(clean_case_manifest.to_dict())
        ).hexdigest(),
        "clean_case_evidence.json": hashlib.sha256(
            canonical_json_bytes(clean_case_evidence.to_dict())
        ).hexdigest(),
    }

    # Population-support receipt binds all 5 constituent digests + predecessor
    # authority + verifier identity + compiler identity + carried blockers +
    # full support derivation.
    primary_supported = predecessor.primary_population_supported
    clean_case_policy_supported = clean_case_policy.clean_case_policy_status == "supported"
    full_support = bool(primary_supported and clean_case_policy_supported)

    projection_contract_digest = hashlib.sha256(
        canonical_json_bytes(projection_contract.to_dict())
    ).hexdigest()
    policy_digest = hashlib.sha256(canonical_json_bytes(clean_case_policy.to_dict())).hexdigest()
    records_digest = hashlib.sha256(records_jsonl).hexdigest()
    manifest_digest = hashlib.sha256(
        canonical_json_bytes(clean_case_manifest.to_dict())
    ).hexdigest()
    evidence_digest = hashlib.sha256(
        canonical_json_bytes(clean_case_evidence.to_dict())
    ).hexdigest()

    population_support_receipt = PopulationSupportReceipt(
        schema_version=_POPULATION_RECEIPT_SCHEMA,
        release=_RELEASE,
        source_commit=source_commit,
        primary_projection_name=_PRIMARY_PROJECTION_NAME,
        primary_projection_contract_digest=projection_contract_digest,
        clean_case_policy_digest=policy_digest,
        clean_case_records_digest=records_digest,
        clean_case_manifest_digest=manifest_digest,
        clean_case_evidence_digest=evidence_digest,
        constituent_artifact_digests=constituent_artifact_digests,
        predecessor_audit_sha256=predecessor.audit_sha256,
        predecessor_selection_contract_digest=predecessor.selection_contract_digest,
        predecessor_bundle_manifest_sha256=predecessor.bundle_manifest_sha256,
        verifier_implementation_identity=_VERIFIER_IMPLEMENTATION_IDENTITY,
        compiler_implementation_sha256=compiler_implementation_sha256,
        carried_blockers=predecessor.experiment_blockers,
        full_e1_population_support=full_support,
    )

    return ProjectionCleanCasePopulation(
        projection_contract=projection_contract,
        clean_case_policy=clean_case_policy,
        clean_case_records=records,
        clean_case_manifest=clean_case_manifest,
        clean_case_evidence=clean_case_evidence,
        population_support_receipt=population_support_receipt,
    )


SCHEMA_VERSION = _SCHEMA_VERSION
RELEASE = _RELEASE
CLAIM_BOUNDARY = _CLAIM_BOUNDARY
PRIMARY_PROJECTION_NAME = _PRIMARY_PROJECTION_NAME
VERIFIER_IMPLEMENTATION_IDENTITY = _VERIFIER_IMPLEMENTATION_IDENTITY


__all__ = [
    "CLAIM_BOUNDARY",
    "PRIMARY_PROJECTION_NAME",
    "RELEASE",
    "SCHEMA_VERSION",
    "VERIFIER_IMPLEMENTATION_IDENTITY",
    "AuthenticatedPredecessorAudit",
    "CleanCaseEvidence",
    "CleanCaseManifest",
    "CleanCasePolicy",
    "CleanCasePolicyReceipt",
    "CleanCaseSemanticRecord",
    "CleanCaseSpec",
    "E1ProjectionCleanCaseError",
    "PopulationSupportReceipt",
    "PrimaryProjectionContract",
    "ProjectionCleanCasePopulation",
    "ScenarioSymbols",
    "authenticate_predecessor_audit",
    "build_clean_case_transition_cases",
    "compile_clean_case_record",
    "compile_projection_clean_case_population",
    "compute_isolation_inventory",
    "evaluate_clean_case_policy",
    "_CLEAN_CASE_SPECS",
    "_DISPOSITION_NEITHER",
    "_DISPOSITION_SURVIVES_ONLY",
    "_EXPECTED_PREDECESSOR_AUDIT_RELEASE",
    "_EXPECTED_PREDECESSOR_AUDIT_SCHEMA",
    "_EXPECTED_PREDECESSOR_AUDIT_SHA256",
    "_EXPECTED_PREDECESSOR_BUNDLE_MANIFEST_SHA256",
    "_EXPECTED_PREDECESSOR_SELECTION_DIGEST",
    "_EXPECTED_PREDECESSOR_SOURCE_COMMIT",
    "_extract_event_symbols",
    "_extract_scenario_population_symbols",
    "_extract_state_symbols",
    "_extract_symbols",
    "_merge_symbols",
]
