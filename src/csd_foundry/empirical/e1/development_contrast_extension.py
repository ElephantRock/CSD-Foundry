"""E1-only development-contrast scenario overlay.

This module produces a versioned E1-only scenario catalog that extends the
frozen v0.1 registry with two executable transition contrasts in the
development split:

* M-12 gains an ``AdvanceClock`` transition that expires scoped evidence while
  an independent same-verdict basis survives.
* M-14 gains a ``ProfileChange`` transition that advances the required profile
  version, decouples the prior verdict basis, and makes the established
  verdict stale.

The base :data:`SCENARIOS` registry is never mutated. The overlay copies it,
replaces only M-12 and M-14 with frozen successor specifications that retain
every original case byte-identically and append one transition case each, and
returns a fresh immutable catalog. The successor family digests necessarily
differ from the PR #73/#74 predecessor identities because scenario-family
identity includes mode, cases, and executable structure.

The temporal appliers ``apply_advance_clock`` and ``apply_profile_change``
already implement scoped expiry, surviving-basis recomputation, profile
advance, and assurance preservation/decay. No kernel expansion is required.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from csd_foundry.kernel.events import AdvanceClock, ProfileChange
from csd_foundry.kernel.models import (
    Assurance,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
)
from csd_foundry.scenarios.spec import (
    ObservationCase,
    ScenarioMode,
    ScenarioSpec,
    StateExpectation,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_EXTENSION_SCHEMA_VERSION = "e1-development-contrast-extension/1"
_RELEASE = "e1-development-contrast-extension/1"

_M12_TRANSITION_CASE_ID = "M-12/e1-advance-clock-with-survivor"
_M14_TRANSITION_CASE_ID = "M-14/e1-profile-strengthening"

_M12_TRACE_RULES = frozenset({"T-INV-01", "T-INV-02", "T-INV-03", "T-INV-06"})
_M14_TRACE_RULES = frozenset({"P-INV-01", "P-INV-02", "P-INV-03"})

_CLAIM_BOUNDARY = (
    "This overlay extends the E1 development split with two executable transition "
    "contrasts (M-12 AdvanceClock, M-14 ProfileChange) while preserving every "
    "original v0.1 case byte-identically and leaving the base registry unchanged. "
    "Successor family digests necessarily differ from the PR #73/#74 predecessor "
    "identities. This overlay does not select a response projection, define "
    "metrics, construct a control arm, load a tokenizer, execute a model, or "
    "establish learning value."
)


class E1DevelopmentContrastError(ValueError):
    """Raised when the development-contrast overlay cannot be compiled."""


# ---------------------------------------------------------------------------
# M-12 AdvanceClock transition contrast
# ---------------------------------------------------------------------------


def _m12_transition_before() -> ControlState:
    """Fresh before-state for the M-12 AdvanceClock contrast.

    The existing M-12 observation state cannot host this transition: its
    evidence is already EXPIRED with no ``expires_at``. This before-state
    constructs two current verdict bases — one on scoped evidence that will
    expire at logical time 1, one on no-expiry evidence that survives — so
    that ``apply_advance_clock`` exercises evidence expiry, basis removal,
    independent basis survival, and unchanged assurance.
    """

    evidence_a = Evidence(
        evidence_id="EV-M12-E1-SCOPED",
        dimension="D",
        status=EvidenceStatus.CURRENT,
        issued_at=0,
        expires_at=1,
    )
    evidence_b = Evidence(
        evidence_id="EV-M12-E1-LIVE",
        dimension="D",
        status=EvidenceStatus.CURRENT,
        issued_at=0,
        expires_at=None,
    )
    basis_a = Basis(
        basis_id="BASIS-M12-E1-SCOPED",
        kind=BasisKind.VERDICT,
        claim="pass",
        member_evidence_ids=frozenset({evidence_a.evidence_id}),
        approved=True,
    )
    basis_b = Basis(
        basis_id="BASIS-M12-E1-LIVE",
        kind=BasisKind.VERDICT,
        claim="pass",
        member_evidence_ids=frozenset({evidence_b.evidence_id}),
        approved=True,
    )
    return ControlState(
        control_id="CTRL-M12-E1",
        assurance=Assurance.PASS,
        evidence=(evidence_a, evidence_b),
        bases=(basis_a, basis_b),
        current_verdict_basis_ids=frozenset({basis_a.basis_id, basis_b.basis_id}),
        logical_time=0,
    )


def _m12_transition_case() -> TransitionCase:
    before = _m12_transition_before()
    evidence_a_id = "EV-M12-E1-SCOPED"
    basis_b_id = "BASIS-M12-E1-LIVE"
    return TransitionCase(
        case_id=_M12_TRANSITION_CASE_ID,
        before=before,
        event=AdvanceClock(target_time=1),
        expected=StateExpectation(
            assurance=Assurance.PASS,
            evidence_statuses=(
                (evidence_a_id, EvidenceStatus.EXPIRED),
                ("EV-M12-E1-LIVE", EvidenceStatus.CURRENT),
            ),
            current_verdict_basis_ids=frozenset({basis_b_id}),
            history_event_types=("AdvanceClock",),
        ),
        expected_invalidated_evidence=frozenset({evidence_a_id}),
        expected_surviving_bases=frozenset({basis_b_id}),
        required_trace_rules=_M12_TRACE_RULES,
    )


# ---------------------------------------------------------------------------
# M-14 ProfileChange transition contrast
# ---------------------------------------------------------------------------


_PROFILE_ID = "PROFILE-M14"


def _m14_transition_before() -> ControlState:
    """Fresh before-state for the M-14 ProfileChange contrast.

    The existing M-14 observation state uses no real profile fields. This
    before-state introduces a required profile (PROFILE-M14 v1) with one
    current verdict basis on profile-aligned evidence, so that
    ``apply_profile_change`` to v2 advances the required version, decouples
    the prior basis, and makes the established verdict stale.
    """

    evidence_a = Evidence(
        evidence_id="EV-M14-E1-A",
        dimension="A",
        status=EvidenceStatus.CURRENT,
        issued_at=0,
        expires_at=None,
        profile_id=_PROFILE_ID,
        profile_version=1,
    )
    basis_a = Basis(
        basis_id="BASIS-M14-E1-PASS-A",
        kind=BasisKind.VERDICT,
        claim="pass",
        member_evidence_ids=frozenset({evidence_a.evidence_id}),
        approved=True,
    )
    return ControlState(
        control_id="CTRL-M14-E1",
        assurance=Assurance.PASS,
        evidence=(evidence_a,),
        bases=(basis_a,),
        current_verdict_basis_ids=frozenset({basis_a.basis_id}),
        required_profile_id=_PROFILE_ID,
        required_profile_version=1,
        logical_time=0,
    )


def _m14_transition_case() -> TransitionCase:
    return TransitionCase(
        case_id=_M14_TRANSITION_CASE_ID,
        before=_m14_transition_before(),
        event=ProfileChange(
            profile_id=_PROFILE_ID,
            profile_version=2,
            authority="I3",
        ),
        expected=StateExpectation(
            assurance=Assurance.STALE,
            evidence_statuses=(("EV-M14-E1-A", EvidenceStatus.CURRENT),),
            basis_claims=(("BASIS-M14-E1-PASS-A", "pass"),),
            current_verdict_basis_ids=frozenset(),
            history_event_types=("ProfileChange",),
        ),
        expected_invalidated_evidence=frozenset(),
        expected_surviving_bases=frozenset(),
        required_trace_rules=_M14_TRACE_RULES,
    )


# ---------------------------------------------------------------------------
# Overlay construction
# ---------------------------------------------------------------------------


def _successor_m12(base: ScenarioSpec) -> ScenarioSpec:
    """Return M-12 with its original observation case plus the AdvanceClock case."""

    if base.scenario_id != "M-12":
        raise E1DevelopmentContrastError("successor M-12 requires the base M-12 spec")
    original_case = base.cases[0]
    if not isinstance(original_case, ObservationCase):
        raise E1DevelopmentContrastError("base M-12 must retain its observation case")
    new_case = _m12_transition_case()
    case_ids = {original_case.case_id, new_case.case_id}
    if len(case_ids) != 2:
        raise E1DevelopmentContrastError("M-12 transition case id must be unique")
    return replace(
        base,
        mode=ScenarioMode.TRANSITION,
        cases=(original_case, new_case),
    )


def _successor_m14(base: ScenarioSpec) -> ScenarioSpec:
    """Return M-14 with its original observation case plus the ProfileChange case."""

    if base.scenario_id != "M-14":
        raise E1DevelopmentContrastError("successor M-14 requires the base M-14 spec")
    original_case = base.cases[0]
    if not isinstance(original_case, ObservationCase):
        raise E1DevelopmentContrastError("base M-14 must retain its observation case")
    new_case = _m14_transition_case()
    case_ids = {original_case.case_id, new_case.case_id}
    if len(case_ids) != 2:
        raise E1DevelopmentContrastError("M-14 transition case id must be unique")
    return replace(
        base,
        mode=ScenarioMode.TRANSITION,
        cases=(original_case, new_case),
    )


def build_e1_development_contrast_catalog(
    base_registry: Mapping[str, ScenarioSpec],
) -> dict[str, ScenarioSpec]:
    """Return a frozen E1 overlay catalog with M-12 and M-14 transition contrasts.

    The base registry is copied; only M-12 and M-14 are replaced with successor
    specifications that retain every original case byte-identically and append
    one transition case each. ``SCENARIOS`` is never mutated.
    """

    catalog: dict[str, ScenarioSpec] = dict(base_registry)
    base_m12 = catalog.get("M-12")
    base_m14 = catalog.get("M-14")
    if base_m12 is None or base_m14 is None:
        raise E1DevelopmentContrastError("base registry must contain M-12 and M-14")
    catalog["M-12"] = _successor_m12(base_m12)
    catalog["M-14"] = _successor_m14(base_m14)
    return catalog


def development_contrast_overlay_catalog_digest(catalog: Mapping[str, ScenarioSpec]) -> str:
    """Content-bound canonical digest of the catalog identity.

    The digest is bound to each scenario's executable identity (family digest,
    declared family, source split, case count) rather than just scenario IDs,
    so the base and overlay catalogs — which share scenario IDs but differ in
    M-12/M-14 executable structure — receive distinct digests.
    """

    from csd_foundry.empirical.e1.scenario_splits import derive_scenario_family_identity

    identities = [
        {
            "scenario_id": scenario_id,
            "family_digest": derive_scenario_family_identity(spec).family_digest,
            "declared_family": spec.family,
            "source_split": spec.split,
            "case_count": len(spec.cases),
        }
        for scenario_id, spec in sorted(catalog.items())
    ]
    return canonical_sha256(
        {
            "schema_version": "e1-development-contrast-catalog/1",
            "scenarios": identities,
        }
    )


@dataclass(frozen=True, slots=True)
class E1DevelopmentContrastExtension:
    """Governed receipt binding the development-contrast overlay to its successor artifacts."""

    schema_version: str
    release: str
    base_source_commit: str
    extension_implementation_sha256: str
    predecessor_audit_sha256: str
    predecessor_selection_contract_digest: str
    base_catalog_digest: str
    overlay_catalog_digest: str
    modified_scenario_ids: tuple[str, ...]
    unchanged_training_scenario_ids: tuple[str, ...]
    unchanged_test_scenario_ids: tuple[str, ...]
    base_family_digest_by_scenario: dict[str, str]
    successor_family_digest_by_scenario: dict[str, str]
    changed_family_digest_mapping: dict[str, dict[str, str]]
    successor_selection_contract: dict[str, object]
    successor_selection_contract_digest: str
    successor_foundry_bundle_manifest_sha256: str
    successor_foundry_file_receipts: tuple[dict[str, object], ...]
    transition_receipts: tuple[dict[str, object], ...]
    successor_audit_sha256: str
    extension_outcome: str
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "base_source_commit": self.base_source_commit,
            "extension_implementation_sha256": self.extension_implementation_sha256,
            "predecessor_audit_sha256": self.predecessor_audit_sha256,
            "predecessor_selection_contract_digest": (self.predecessor_selection_contract_digest),
            "base_catalog_digest": self.base_catalog_digest,
            "overlay_catalog_digest": self.overlay_catalog_digest,
            "modified_scenario_ids": list(self.modified_scenario_ids),
            "unchanged_training_scenario_ids": list(self.unchanged_training_scenario_ids),
            "unchanged_test_scenario_ids": list(self.unchanged_test_scenario_ids),
            "base_family_digest_by_scenario": dict(
                sorted(self.base_family_digest_by_scenario.items())
            ),
            "successor_family_digest_by_scenario": dict(
                sorted(self.successor_family_digest_by_scenario.items())
            ),
            "changed_family_digest_mapping": dict(
                sorted(self.changed_family_digest_mapping.items())
            ),
            "successor_selection_contract": self.successor_selection_contract,
            "successor_selection_contract_digest": (self.successor_selection_contract_digest),
            "successor_foundry_bundle_manifest_sha256": (
                self.successor_foundry_bundle_manifest_sha256
            ),
            "successor_foundry_file_receipts": [
                dict(item) for item in self.successor_foundry_file_receipts
            ],
            "transition_receipts": [dict(item) for item in self.transition_receipts],
            "successor_audit_sha256": self.successor_audit_sha256,
            "extension_outcome": self.extension_outcome,
            "claim_boundary": self.claim_boundary,
        }


SCHEMAS_VERSION = _EXTENSION_SCHEMA_VERSION
RELEASE = _RELEASE
CLAIM_BOUNDARY = _CLAIM_BOUNDARY


__all__ = [
    "CLAIM_BOUNDARY",
    "E1DevelopmentContrastError",
    "E1DevelopmentContrastExtension",
    "RELEASE",
    "SCHEMAS_VERSION",
    "build_e1_development_contrast_catalog",
    "development_contrast_overlay_catalog_digest",
]
