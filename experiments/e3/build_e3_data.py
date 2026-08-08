#!/usr/bin/env python3
"""Construct the E3 safety-anchored dataset.

Three disjoint cohorts, every label derived from CsdOracle execution over an
explicit ``(before-state, event)`` pair, then mapped through the frozen codebook
(NEITHER->A, REMOVES_ONLY->B, SURVIVES_ONLY->C, BOTH->D, NOT_APPLICABLE->E).

Cohorts
-------

1. ``clean_anchors.jsonl`` (10 records) -- the shared clean anchor curriculum,
   added IDENTICALLY to BOTH training arms. The anchors are designed to teach
   the two safety-relevant distinctions that the v6 curriculum alone failed to
   convey in E2:

   * 5 x NEITHER (``E3-ANC-N01..N05``): ``DependencyChange`` on an irrelevant
     dependency where the before-state has current evidence but NO bases at all,
     so no basis is removed and none survives. A transition with no bases is
     NEITHER, never NOT_APPLICABLE (NOT_APPLICABLE is reserved for observations).
   * 5 x SURVIVES_ONLY (``E3-ANC-S01..S05``): the before-state carries 2 bases
     on evidence whose dependencies do NOT intersect the event dependency, so
     the bases survive. Each anchor is structurally distinct (different basis
     kinds, evidence counts, and dependency configurations -- not ID-renamed
     copies).

2. ``protected_primary.jsonl`` (20 records) -- 4 structurally distinct families
   per class (NEITHER, REMOVES_ONLY, SURVIVES_ONLY, BOTH, NOT_APPLICABLE). The
   4 BOTH families have genuine mixed survival/removal (partial intersection).

3. ``protected_clean.jsonl`` (10 records) -- 5 NEITHER + 5 SURVIVES_ONLY clean
   safety cases.

Disjointness is enforced against: E1 v6 train/dev, E2 evaluation records, LF
calibration (CAL-* namespace), and the E3 anchors themselves. No record overlaps
between primary and clean.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from csd_foundry.kernel.events import DependencyChange
from csd_foundry.kernel.models import (
    Assurance,
    Basis,
    BasisKind,
    ControlState,
    Evidence,
    EvidenceStatus,
    ObligationStatus,
    SourceState,
)
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    to_json_value,
)

# ---------------------------------------------------------------------------
# Frozen identities.
# ---------------------------------------------------------------------------

SYSTEM_CONTENT = "Return the frozen response codeword and nothing else."
SCHEMA_VERSION = "e1-semantic-decision-input/1"
CONTEXT_LENGTH = 512

MODEL_ID = "gpt2"
MODEL_REVISION = "607a30d783dfa663caf39e06633721c8d4cfcd7e"

# Frozen codebook (verified single-token A-E over gpt2@607a30d).
CODEWORD_BY_CLASS: dict[str, str] = {
    "NEITHER": "A",
    "REMOVES_ONLY": "B",
    "SURVIVES_ONLY": "C",
    "BOTH": "D",
    "NOT_APPLICABLE": "E",
}
TOKEN_ID_BY_CODEWORD: dict[str, int] = {"A": 32, "B": 33, "C": 34, "D": 35, "E": 36}

# Sources E3 must stay disjoint from.
DISJOINT_SOURCES = (
    "data/e1/v6/control_train.jsonl",
    "data/e1/v6/foundry_train.jsonl",
    "data/e1/v6/development_evaluation.jsonl",
    "data/e1/v6/clean_evaluation.jsonl",
    "experiments/e2/protected_primary.jsonl",
    "experiments/e2/protected_clean.jsonl",
)


# ---------------------------------------------------------------------------
# Spec primitives.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FamilySpec:
    """A structurally described record."""

    family_id: str
    record_id: str
    declared_family: str
    assertion: str
    control_id: str
    before: ControlState
    event: Any  # DependencyChange for transitions; None for observation


def _ev(
    eid: str,
    deps: tuple[str, ...] = (),
    status: EvidenceStatus = EvidenceStatus.CURRENT,
    dimension: str = "D",
    outcome: str | None = None,
) -> Evidence:
    return Evidence(
        evidence_id=eid,
        dimension=dimension,
        dependencies=frozenset(deps),
        status=status,
        outcome=outcome,
    )


def _src_basis(bid: str, members: tuple[str, ...], claim: str = "connected") -> Basis:
    return Basis(
        basis_id=bid,
        kind=BasisKind.SOURCE,
        claim=claim,
        member_evidence_ids=frozenset(members),
    )


def _vrd_basis(bid: str, members: tuple[str, ...], claim: str = "pass") -> Basis:
    return Basis(
        basis_id=bid,
        kind=BasisKind.VERDICT,
        claim=claim,
        member_evidence_ids=frozenset(members),
    )


def _state(
    control_id: str,
    evidence: tuple[Evidence, ...],
    bases: tuple[Basis, ...],
    src_ids: frozenset[str],
    vrd_ids: frozenset[str],
    source: SourceState = SourceState.UNKNOWN,
    assurance: Assurance = Assurance.UNVERIFIED,
) -> ControlState:
    return ControlState(
        control_id=control_id,
        obligation=ObligationStatus.CURRENT,
        source_state=source,
        assurance=assurance,
        evidence=evidence,
        bases=bases,
        current_source_basis_ids=src_ids,
        current_verdict_basis_ids=vrd_ids,
    )


# ---------------------------------------------------------------------------
# Cohort 1: clean anchors (10 records, 5 NEITHER + 5 SURVIVES_ONLY).
#
# Anchors are SHARED across both training arms. They teach the two
# safety-relevant distinctions:
#   NEITHER        -> a transition with no bases is NEITHER, never NOT_APPLICABLE
#   SURVIVES_ONLY  -> surviving bases are NOT removed bases
# ---------------------------------------------------------------------------


def _anchor_specs() -> list[FamilySpec]:
    specs: list[FamilySpec] = []

    # === 5 x NEITHER anchors (E3-ANC-N01..N05) ===
    # Each: before-state has 1-2 current evidence items but ZERO bases. Event is a
    # DependencyChange on a dependency that does NOT intersect any evidence dep.
    # Oracle confirms: no basis removed, no basis survives -> NEITHER (codeword A).
    # Structurally diverse: different evidence counts and dependency configs.

    # N01: single evidence, single dep, change on a different dep
    specs.append(
        FamilySpec(
            family_id="E3-ANC-N01",
            record_id="E3-ANC-N01/anchor-neither-single-evidence",
            declared_family="anchor_neither_single_evidence",
            assertion="A dependency change with no basis to remove removes nothing.",
            control_id="E3-ANC-N1",
            before=_state(
                "E3-ANC-N1",
                (_ev("EV-AN1", deps=("depAnchorData",)),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depAnchorUnrelated1"),
        )
    )

    # N02: two evidence items with disjoint deps, change on a third dep
    specs.append(
        FamilySpec(
            family_id="E3-ANC-N02",
            record_id="E3-ANC-N02/anchor-neither-dual-evidence",
            declared_family="anchor_neither_dual_evidence",
            assertion="Two current evidence items without any basis keep a change neutral.",
            control_id="E3-ANC-N2",
            before=_state(
                "E3-ANC-N2",
                (
                    _ev("EV-AN2A", deps=("depAnchorAlpha",)),
                    _ev("EV-AN2B", deps=("depAnchorBeta",)),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depAnchorGamma"),
        )
    )

    # N03: single evidence carrying an apparent_direction, change on an absent dep
    specs.append(
        FamilySpec(
            family_id="E3-ANC-N03",
            record_id="E3-ANC-N03/anchor-neither-direction-annotated",
            declared_family="anchor_neither_direction_annotated",
            assertion="An apparent dependency direction with no basis removes nothing.",
            control_id="E3-ANC-N3",
            before=_state(
                "E3-ANC-N3",
                (_ev("EV-AN3", deps=("depAnchorWire",)),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depAnchorOther", apparent_direction="down"),
        )
    )

    # N04: multi-dep evidence (3 deps), change on a dep absent from the member set
    specs.append(
        FamilySpec(
            family_id="E3-ANC-N04",
            record_id="E3-ANC-N04/anchor-neither-multidep-miss",
            declared_family="anchor_neither_multidep_miss",
            assertion="A multi-dependency evidence with no basis survives an unrelated change.",
            control_id="E3-ANC-N4",
            before=_state(
                "E3-ANC-N4",
                (_ev("EV-AN4", deps=("depAnchorA", "depAnchorB", "depAnchorC")),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depAnchorZ"),
        )
    )

    # N05: evidence with an outcome, change on an irrelevant dep (still no bases)
    specs.append(
        FamilySpec(
            family_id="E3-ANC-N05",
            record_id="E3-ANC-N05/anchor-neither-outcome-evidence",
            declared_family="anchor_neither_outcome_evidence",
            assertion=(
                "A substantive outcome with no basis disposition is still neutral "
                "on an unrelated change."
            ),
            control_id="E3-ANC-N5",
            before=_state(
                "E3-ANC-N5",
                (
                    _ev(
                        "EV-AN5",
                        deps=("depAnchorProbe",),
                        outcome="demonstratesSuccess",
                    ),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depAnchorDisjoint"),
        )
    )

    # === 5 x SURVIVES_ONLY anchors (E3-ANC-S01..S05) ===
    # Each: before-state has 2 bases on evidence whose dependencies do NOT
    # intersect the event dependency. Oracle confirms: some basis survives,
    # none removed -> SURVIVES_ONLY (codeword C). Structurally diverse: different
    # basis kinds (source/verdict), evidence counts, dependency configurations.

    # S01: 2 verdict bases on two distinct deps; change on a third, unrelated dep
    specs.append(
        FamilySpec(
            family_id="E3-ANC-S01",
            record_id="E3-ANC-S01/anchor-survives-two-verdict",
            declared_family="anchor_survives_two_verdict",
            assertion="Two verdict bases on unrelated deps both survive an irrelevant change.",
            control_id="E3-ANC-S1",
            before=_state(
                "E3-ANC-S1",
                (
                    _ev("EV-AS1A", deps=("depAnchorV1",)),
                    _ev("EV-AS1B", deps=("depAnchorV2",)),
                ),
                (
                    _vrd_basis("BAS-AS1A", ("EV-AS1A",)),
                    _vrd_basis("BAS-AS1B", ("EV-AS1B",)),
                ),
                frozenset(),
                frozenset({"BAS-AS1A", "BAS-AS1B"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depAnchorUnrelatedS1"),
        )
    )

    # S02: 2 source bases (connected) on distinct deps; change on an absent dep
    specs.append(
        FamilySpec(
            family_id="E3-ANC-S02",
            record_id="E3-ANC-S02/anchor-survives-two-source",
            declared_family="anchor_survives_two_source",
            assertion="Two source bases on unrelated deps both survive an irrelevant change.",
            control_id="E3-ANC-S2",
            before=_state(
                "E3-ANC-S2",
                (
                    _ev("EV-AS2A", deps=("depAnchorSrc1",)),
                    _ev("EV-AS2B", deps=("depAnchorSrc2",)),
                ),
                (
                    _src_basis("BAS-AS2A", ("EV-AS2A",)),
                    _src_basis("BAS-AS2B", ("EV-AS2B",)),
                ),
                frozenset({"BAS-AS2A", "BAS-AS2B"}),
                frozenset(),
                source=SourceState.CONNECTED,
                assurance=Assurance.UNVERIFIED,
            ),
            event=DependencyChange(dependency_id="depAnchorUnrelatedS2"),
        )
    )

    # S03: 1 source + 1 verdict base on distinct unrelated deps; change on a third
    specs.append(
        FamilySpec(
            family_id="E3-ANC-S03",
            record_id="E3-ANC-S03/anchor-survives-source-and-verdict",
            declared_family="anchor_survives_source_and_verdict",
            assertion="A source and a verdict base on unrelated deps both survive.",
            control_id="E3-ANC-S3",
            before=_state(
                "E3-ANC-S3",
                (
                    _ev("EV-AS3SRC", deps=("depAnchorS3src",)),
                    _ev("EV-AS3VRD", deps=("depAnchorS3vrd",)),
                ),
                (
                    _src_basis("BAS-AS3S", ("EV-AS3SRC",)),
                    _vrd_basis("BAS-AS3V", ("EV-AS3VRD",)),
                ),
                frozenset({"BAS-AS3S"}),
                frozenset({"BAS-AS3V"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depAnchorS3unrelated"),
        )
    )

    # S04: 2 verdict bases, one spanning two evidence (multi-member), one single;
    #      change on a dep absent from every member
    specs.append(
        FamilySpec(
            family_id="E3-ANC-S04",
            record_id="E3-ANC-S04/anchor-survives-spanning-and-single",
            declared_family="anchor_survives_spanning_and_single",
            assertion="A spanning verdict basis and a single verdict basis both survive.",
            control_id="E3-ANC-S4",
            before=_state(
                "E3-ANC-S4",
                (
                    _ev("EV-AS4A", deps=("depAnchorSpanA",)),
                    _ev("EV-AS4B", deps=("depAnchorSpanB",)),
                    _ev("EV-AS4C", deps=("depAnchorSingC",)),
                ),
                (
                    _vrd_basis("BAS-AS4SPAN", ("EV-AS4A", "EV-AS4B"), claim="fail"),
                    _vrd_basis("BAS-AS4SING", ("EV-AS4C",), claim="fail"),
                ),
                frozenset(),
                frozenset({"BAS-AS4SPAN", "BAS-AS4SING"}),
                assurance=Assurance.FAIL,
            ),
            event=DependencyChange(dependency_id="depAnchorS4absent"),
        )
    )

    # S05: 1 verdict base + 1 source base, both on the SAME evidence item, on a
    #      dep that is NOT that evidence's dep; change on yet another dep. Both
    #      survive (co-supported but on an unrelated dep).
    specs.append(
        FamilySpec(
            family_id="E3-ANC-S05",
            record_id="E3-ANC-S05/anchor-survives-cosupported-unrelated",
            declared_family="anchor_survives_cosupported_unrelated",
            assertion="Co-supported bases on one evidence survive an unrelated change.",
            control_id="E3-ANC-S5",
            before=_state(
                "E3-ANC-S5",
                (_ev("EV-AS5", deps=("depAnchorS5data",)),),
                (
                    _src_basis("BAS-AS5S", ("EV-AS5",)),
                    _vrd_basis("BAS-AS5V", ("EV-AS5",)),
                ),
                frozenset({"BAS-AS5S"}),
                frozenset({"BAS-AS5V"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depAnchorS5other"),
        )
    )

    assert len(specs) == 10, f"expected 10 anchor specs, got {len(specs)}"
    return specs


# ---------------------------------------------------------------------------
# Cohort 2: protected primary (20 records, 4 families per class).
# ---------------------------------------------------------------------------


def _primary_specs() -> list[FamilySpec]:
    """20 structurally distinct primary families, 4 per semantic class."""

    specs: list[FamilySpec] = []

    # === NEITHER (4): DependencyChange on irrelevant dep, NO bases at all ===

    # NEITHER-1: single evidence, no bases, change on a disjoint dep
    specs.append(
        FamilySpec(
            family_id="E3-PRI-001",
            record_id="E3-PRI-001/neither-single-no-basis",
            declared_family="neither_single_no_basis",
            assertion="A dependency change touching no basis removes nothing.",
            control_id="E3-P1N",
            before=_state(
                "E3-P1N",
                (_ev("EV-P1N", deps=("depP1data",)),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depP1disjoint"),
        )
    )

    # NEITHER-2: two evidence with disjoint deps, no bases, change on a third
    specs.append(
        FamilySpec(
            family_id="E3-PRI-002",
            record_id="E3-PRI-002/neither-dual-no-basis",
            declared_family="neither_dual_no_basis",
            assertion="Distinct-evidence no-basis states stay neutral under unrelated changes.",
            control_id="E3-P2N",
            before=_state(
                "E3-P2N",
                (
                    _ev("EV-P2NA", deps=("depP2alpha",)),
                    _ev("EV-P2NB", deps=("depP2beta",)),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depP2gamma", apparent_direction="up"),
        )
    )

    # NEITHER-3: multi-dep evidence (3 deps), no bases, change on an absent dep
    specs.append(
        FamilySpec(
            family_id="E3-PRI-003",
            record_id="E3-PRI-003/neither-multidep-no-basis",
            declared_family="neither_multidep_no_basis",
            assertion="A multi-dependency evidence with no basis is neutral on a disjoint change.",
            control_id="E3-P3N",
            before=_state(
                "E3-P3N",
                (_ev("EV-P3N", deps=("depP3a", "depP3b", "depP3c")),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depP3z"),
        )
    )

    # NEITHER-4: evidence with a substantive outcome, no bases, change on an
    #             irrelevant dep
    specs.append(
        FamilySpec(
            family_id="E3-PRI-004",
            record_id="E3-PRI-004/neither-outcome-no-basis",
            declared_family="neither_outcome_no_basis",
            assertion="A substantive outcome without a basis disposition stays neutral.",
            control_id="E3-P4N",
            before=_state(
                "E3-P4N",
                (
                    _ev(
                        "EV-P4N",
                        deps=("depP4probe",),
                        outcome="demonstratesFailure",
                    ),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depP4other"),
        )
    )

    # === REMOVES_ONLY (4): DependencyChange invalidates ALL basis support ===

    # REMOVES-1: single verdict basis, single-dep evidence, change kills it
    specs.append(
        FamilySpec(
            family_id="E3-PRI-005",
            record_id="E3-PRI-005/removes-single-verdict",
            declared_family="removes_only_single_verdict",
            assertion="A dependency change can retire the only basis supporting a verdict.",
            control_id="E3-P1R",
            before=_state(
                "E3-P1R",
                (_ev("EV-P1R", deps=("depP1sensor",)),),
                (_vrd_basis("BAS-P1RV", ("EV-P1R",)),),
                frozenset(),
                frozenset({"BAS-P1RV"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP1sensor"),
        )
    )

    # REMOVES-2: single source basis (connected), change kills its evidence
    specs.append(
        FamilySpec(
            family_id="E3-PRI-006",
            record_id="E3-PRI-006/removes-single-source",
            declared_family="removes_only_single_source",
            assertion="A source basis falls when its sole supporting dependency changes.",
            control_id="E3-P2R",
            before=_state(
                "E3-P2R",
                (_ev("EV-P2R", deps=("depP2feed",)),),
                (_src_basis("BAS-P2RS", ("EV-P2R",)),),
                frozenset({"BAS-P2RS"}),
                frozenset(),
                source=SourceState.CONNECTED,
                assurance=Assurance.UNVERIFIED,
            ),
            event=DependencyChange(dependency_id="depP2feed"),
        )
    )

    # REMOVES-3: source + verdict bases BOTH on the SAME evidence; one dep change
    #            kills both
    specs.append(
        FamilySpec(
            family_id="E3-PRI-007",
            record_id="E3-PRI-007/removes-joint-source-verdict",
            declared_family="removes_only_joint_source_verdict",
            assertion="Co-supported source and verdict bases fall together on one dep change.",
            control_id="E3-P3R",
            before=_state(
                "E3-P3R",
                (_ev("EV-P3R", deps=("depP3shared",)),),
                (
                    _src_basis("BAS-P3RS", ("EV-P3R",)),
                    _vrd_basis("BAS-P3RV", ("EV-P3R",)),
                ),
                frozenset({"BAS-P3RS"}),
                frozenset({"BAS-P3RV"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP3shared"),
        )
    )

    # REMOVES-4: verdict basis spanning two evidence on the SAME dep; change kills
    specs.append(
        FamilySpec(
            family_id="E3-PRI-008",
            record_id="E3-PRI-008/removes-spanning-verdict",
            declared_family="removes_only_spanning_verdict",
            assertion="A spanning verdict basis falls when its shared dep changes.",
            control_id="E3-P4R",
            before=_state(
                "E3-P4R",
                (
                    _ev("EV-P4RA", deps=("depP4probe",)),
                    _ev("EV-P4RB", deps=("depP4probe",)),
                ),
                (_vrd_basis("BAS-P4RV", ("EV-P4RA", "EV-P4RB"), claim="fail"),),
                frozenset(),
                frozenset({"BAS-P4RV"}),
                assurance=Assurance.FAIL,
            ),
            event=DependencyChange(dependency_id="depP4probe"),
        )
    )

    # === SURVIVES_ONLY (4): irrelevant dep change, bases unaffected ===

    # SURVIVES-1: single verdict basis on depB, change on depX
    specs.append(
        FamilySpec(
            family_id="E3-PRI-009",
            record_id="E3-PRI-009/survives-single-verdict",
            declared_family="survives_only_single_verdict",
            assertion="An unrelated dependency change leaves a verdict basis intact.",
            control_id="E3-P1S",
            before=_state(
                "E3-P1S",
                (_ev("EV-P1S", deps=("depP1link",)),),
                (_vrd_basis("BAS-P1SV", ("EV-P1S",)),),
                frozenset(),
                frozenset({"BAS-P1SV"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP1unrelated"),
        )
    )

    # SURVIVES-2: single source basis (connected), change on an unrelated dep
    specs.append(
        FamilySpec(
            family_id="E3-PRI-010",
            record_id="E3-PRI-010/survives-single-source",
            declared_family="survives_only_single_source",
            assertion="A source basis survives when an unrelated dependency changes.",
            control_id="E3-P2S",
            before=_state(
                "E3-P2S",
                (_ev("EV-P2S", deps=("depP2feed",)),),
                (_src_basis("BAS-P2SS", ("EV-P2S",)),),
                frozenset({"BAS-P2SS"}),
                frozenset(),
                source=SourceState.CONNECTED,
                assurance=Assurance.UNVERIFIED,
            ),
            event=DependencyChange(dependency_id="depP2other"),
        )
    )

    # SURVIVES-3: source + verdict on DISTINCT deps, change on a third dep
    specs.append(
        FamilySpec(
            family_id="E3-PRI-011",
            record_id="E3-PRI-011/survives-source-and-verdict",
            declared_family="survives_only_source_and_verdict",
            assertion="Distinct bases on distinct deps survive an unrelated change.",
            control_id="E3-P3S",
            before=_state(
                "E3-P3S",
                (
                    _ev("EV-P3SSRC", deps=("depP3src",)),
                    _ev("EV-P3SVRD", deps=("depP3vrd",)),
                ),
                (
                    _src_basis("BAS-P3SS", ("EV-P3SSRC",)),
                    _vrd_basis("BAS-P3SV", ("EV-P3SVRD",)),
                ),
                frozenset({"BAS-P3SS"}),
                frozenset({"BAS-P3SV"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP3unrelated"),
        )
    )

    # SURVIVES-4: multi-member verdict basis, change on a dep absent from members
    specs.append(
        FamilySpec(
            family_id="E3-PRI-012",
            record_id="E3-PRI-012/survives-multimember-verdict",
            declared_family="survives_only_multimember_verdict",
            assertion="A multi-member basis survives when none of its members' deps change.",
            control_id="E3-P4S",
            before=_state(
                "E3-P4S",
                (
                    _ev("EV-P4SA", deps=("depP4a",)),
                    _ev("EV-P4SB", deps=("depP4b",)),
                ),
                (_vrd_basis("BAS-P4SV", ("EV-P4SA", "EV-P4SB"), claim="partial"),),
                frozenset(),
                frozenset({"BAS-P4SV"}),
                assurance=Assurance.PARTIAL,
            ),
            event=DependencyChange(dependency_id="depP4c"),
        )
    )

    # === BOTH (4): genuine mixed survival/removal (partial intersection) ===

    # BOTH-1: two verdict bases on distinct deps; change kills one, keeps one
    specs.append(
        FamilySpec(
            family_id="E3-PRI-013",
            record_id="E3-PRI-013/both-two-verdict-bases",
            declared_family="both_partial_two_verdict_bases",
            assertion="A dependency change can retire one verdict basis while another survives.",
            control_id="E3-P1B",
            before=_state(
                "E3-P1B",
                (
                    _ev("EV-P1BHIT", deps=("depP1hit",)),
                    _ev("EV-P1BKEP", deps=("depP1keep",)),
                ),
                (
                    _vrd_basis("BAS-P1BHIT", ("EV-P1BHIT",)),
                    _vrd_basis("BAS-P1BKEP", ("EV-P1BKEP",)),
                ),
                frozenset(),
                frozenset({"BAS-P1BHIT", "BAS-P1BKEP"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP1hit"),
        )
    )

    # BOTH-2: source basis removed, verdict basis survives (cross-kind partial)
    specs.append(
        FamilySpec(
            family_id="E3-PRI-014",
            record_id="E3-PRI-014/both-source-removed-verdict-survives",
            declared_family="both_partial_source_removed_verdict_survives",
            assertion="A change can drop the source basis while the verdict basis survives.",
            control_id="E3-P2B",
            before=_state(
                "E3-P2B",
                (
                    _ev("EV-P2BSRC", deps=("depP2src",)),
                    _ev("EV-P2BVRD", deps=("depP2vrd",)),
                ),
                (
                    _src_basis("BAS-P2BS", ("EV-P2BSRC",)),
                    _vrd_basis("BAS-P2BV", ("EV-P2BVRD",)),
                ),
                frozenset({"BAS-P2BS"}),
                frozenset({"BAS-P2BV"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP2src"),
        )
    )

    # BOTH-3: three bases (1 source + 2 verdict); change removes the source,
    #         both verdicts survive (on distinct deps)
    specs.append(
        FamilySpec(
            family_id="E3-PRI-015",
            record_id="E3-PRI-015/both-three-basis-mix",
            declared_family="both_partial_three_basis_mix",
            assertion="Among three bases a change can remove one and leave two standing.",
            control_id="E3-P3B",
            before=_state(
                "E3-P3B",
                (
                    _ev("EV-P3BHIT", deps=("depP3hit",)),
                    _ev("EV-P3BV1", deps=("depP3v1",)),
                    _ev("EV-P3BV2", deps=("depP3v2",)),
                ),
                (
                    _src_basis("BAS-P3BHIT", ("EV-P3BHIT",)),
                    _vrd_basis("BAS-P3BV1", ("EV-P3BV1",)),
                    _vrd_basis("BAS-P3BV2", ("EV-P3BV2",)),
                ),
                frozenset({"BAS-P3BHIT"}),
                frozenset({"BAS-P3BV1", "BAS-P3BV2"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP3hit"),
        )
    )

    # BOTH-4: one spanning verdict basis (one member hit -> removed) plus one
    #         independent verdict basis that survives (basis-internal partial)
    specs.append(
        FamilySpec(
            family_id="E3-PRI-016",
            record_id="E3-PRI-016/both-spanning-and-independent",
            declared_family="both_partial_spanning_and_independent",
            assertion="A spanning basis falls when one member is hit; another survives.",
            control_id="E3-P4B",
            before=_state(
                "E3-P4B",
                (
                    _ev("EV-P4BSPANHIT", deps=("depP4hit",)),
                    _ev("EV-P4BSPANKEP", deps=("depP4keep",)),
                    _ev("EV-P4BIND", deps=("depP4ind",)),
                ),
                (
                    _vrd_basis("BAS-P4BSPAN", ("EV-P4BSPANHIT", "EV-P4BSPANKEP")),
                    _vrd_basis("BAS-P4BIND", ("EV-P4BIND",)),
                ),
                frozenset(),
                frozenset({"BAS-P4BSPAN", "BAS-P4BIND"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depP4hit"),
        )
    )

    # === NOT_APPLICABLE (4): ObservationCase (valid state, no basis disposition) ===

    # NA-1: minimal observation (single current evidence, no verdict)
    specs.append(
        FamilySpec(
            family_id="E3-PRI-017",
            record_id="E3-PRI-017/na-observation-minimal",
            declared_family="na_observation_minimal",
            assertion="An observation with no basis disposition is NOT_APPLICABLE.",
            control_id="E3-P1NA",
            before=_state(
                "E3-P1NA",
                (_ev("EV-P1NA", deps=("depP1d",), outcome="demonstratesFailure"),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=None,
        )
    )

    # NA-2: observation with multiple evidence
    specs.append(
        FamilySpec(
            family_id="E3-PRI-018",
            record_id="E3-PRI-018/na-observation-multi-evidence",
            declared_family="na_observation_multi_evidence",
            assertion="A multi-evidence observation still carries no basis disposition.",
            control_id="E3-P2NA",
            before=_state(
                "E3-P2NA",
                (
                    _ev("EV-P2NAA", deps=("depP2a",), outcome="demonstratesSuccess"),
                    _ev("EV-P2NAB", deps=("depP2b",), outcome="demonstratesFailure"),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=None,
        )
    )

    # NA-3: observation with expired + current evidence mix
    specs.append(
        FamilySpec(
            family_id="E3-PRI-019",
            record_id="E3-PRI-019/na-observation-expired-mix",
            declared_family="na_observation_expired_mix",
            assertion="An observation may carry non-current evidence without a disposition.",
            control_id="E3-P3NA",
            before=_state(
                "E3-P3NA",
                (
                    _ev("EV-P3NAEXP", deps=("depP3old",), status=EvidenceStatus.EXPIRED),
                    _ev("EV-P3NACUR", deps=("depP3new",), outcome="demonstratesSuccess"),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=None,
        )
    )

    # NA-4: observation of an unverified assurance with a stale prior evidence
    specs.append(
        FamilySpec(
            family_id="E3-PRI-020",
            record_id="E3-PRI-020/na-observation-stale-prior",
            declared_family="na_observation_stale_prior",
            assertion="An unverified observation with a stale prior is still NOT_APPLICABLE.",
            control_id="E3-P4NA",
            before=_state(
                "E3-P4NA",
                (
                    _ev("EV-P4NAOLD", deps=("depP4old",), status=EvidenceStatus.INVALIDATED),
                    _ev("EV-P4NANEW", deps=("depP4new",), outcome="demonstratesFailure"),
                ),
                (),
                frozenset(),
                frozenset(),
            ),
            event=None,
        )
    )

    assert len(specs) == 20, f"expected 20 primary specs, got {len(specs)}"
    return specs


# ---------------------------------------------------------------------------
# Cohort 3: clean safety (10 records, 5 NEITHER + 5 SURVIVES_ONLY).
# ---------------------------------------------------------------------------


def _clean_specs() -> list[FamilySpec]:
    """10 clean safety cases: 5 SURVIVES_ONLY + 5 NEITHER, distinct from anchors."""

    specs: list[FamilySpec] = []

    # Clean 1-5: SURVIVES_ONLY (irrelevant change, surviving basis present)
    for i in range(1, 6):
        dep_keep = f"depPclnK{i}"
        dep_change = f"depPclnU{i}"
        specs.append(
            FamilySpec(
                family_id=f"E3-CLN-{i:03d}",
                record_id=f"E3-CLN-{i:03d}/clean-survives",
                declared_family=f"clean_survives_only_{i}",
                assertion="An irrelevant dependency change leaves an established basis intact.",
                control_id=f"E3-CLN-S{i}",
                before=_state(
                    f"E3-CLN-S{i}",
                    (_ev(f"EV-PCLN-S{i}", deps=(dep_keep,)),),
                    (_vrd_basis(f"BAS-PCLN-S{i}", (f"EV-PCLN-S{i}",)),),
                    frozenset(),
                    frozenset({f"BAS-PCLN-S{i}"}),
                    assurance=Assurance.PASS,
                ),
                event=DependencyChange(dependency_id=dep_change),
            )
        )

    # Clean 6-10: NEITHER (irrelevant change, no bases at all)
    for i in range(6, 11):
        dep_change = f"depPclnU{i}"
        specs.append(
            FamilySpec(
                family_id=f"E3-CLN-{i:03d}",
                record_id=f"E3-CLN-{i:03d}/clean-neither",
                declared_family=f"clean_neither_{i}",
                assertion="An irrelevant change with no bases removes or preserves nothing.",
                control_id=f"E3-CLN-N{i}",
                before=_state(
                    f"E3-CLN-N{i}",
                    (_ev(f"EV-PCLN-N{i}", deps=(f"depPclnD{i}",)),),
                    (),
                    frozenset(),
                    frozenset(),
                ),
                event=DependencyChange(dependency_id=dep_change),
            )
        )

    assert len(specs) == 10, f"expected 10 clean specs, got {len(specs)}"
    return specs


# ---------------------------------------------------------------------------
# Record compilation.
# ---------------------------------------------------------------------------


def _user_content(spec: FamilySpec) -> str:
    """Build the user-content JSON for a spec (mirrors e1-semantic-decision-input/1)."""

    if spec.event is None:
        # Observation case: single 'state' object.
        payload: dict[str, Any] = {
            "assertion": spec.assertion,
            "case_type": "observation",
            "schema_version": SCHEMA_VERSION,
            "state": to_json_value(spec.before),
        }
    else:
        # Transition case: before + event.
        payload = {
            "assertion": spec.assertion,
            "case_type": "transition",
            "schema_version": SCHEMA_VERSION,
            "event_type": type(spec.event).__name__,
            "before": to_json_value(spec.before),
            "event": to_json_value(spec.event),
        }
    return canonical_json_text(payload).rstrip("\n")


def _prompt_bytes(user_content: str) -> str:
    return "\n".join((SYSTEM_CONTENT, user_content, ""))


def _derive_class(spec: FamilySpec) -> str:
    """Derive the semantic class for a spec via the oracle (or NOT_APPLICABLE)."""

    if spec.event is None:
        return "NOT_APPLICABLE"
    oracle = CsdOracle().apply(spec.before, spec.event)
    any_removed = len(oracle.trace.removed_bases) > 0
    any_survives = len(oracle.trace.surviving_bases) > 0
    if any_removed and any_survives:
        return "BOTH"
    if any_removed:
        return "REMOVES_ONLY"
    if any_survives:
        return "SURVIVES_ONLY"
    return "NEITHER"


def _task_input_digest(user_content: str) -> str:
    """sha256 over user_content + newline, matching the E1 task_input_digest."""

    return hashlib.sha256((user_content + "\n").encode("utf-8")).hexdigest()


def _compile_record(spec: FamilySpec, cohort: str) -> dict[str, Any]:
    user_content = _user_content(spec)
    gold_class = _derive_class(spec)
    codeword = CODEWORD_BY_CLASS[gold_class]
    prompt_bytes = _prompt_bytes(user_content)
    record = {
        "schema_version": "e3-codeword-case/1",
        "cohort": cohort,
        "case_id": f"e3/{cohort}/{spec.family_id}/{spec.record_id.split('/', 1)[1]}",
        "record_id": spec.record_id,
        "family_id": spec.family_id,
        "declared_family": spec.declared_family,
        "case_kind": "observation" if spec.event is None else "transition",
        "assertion": spec.assertion,
        "gold_class": gold_class,
        "semantic_class": gold_class,
        "codeword": codeword,
        "codeword_token_id": TOKEN_ID_BY_CODEWORD[codeword],
        "system_content": SYSTEM_CONTENT,
        "user_content": user_content,
        "prompt_bytes": prompt_bytes,
        "task_input_digest": _task_input_digest(user_content),
        "prompt_messages": [
            {"content": SYSTEM_CONTENT, "role": "system"},
            {"content": user_content, "role": "user"},
        ],
    }
    return record


def _load_disjoint_digests(repo_root: Path) -> set[str]:
    """Collect every task_input_digest (or sha256 of user content) from disjoint sources."""

    digests: set[str] = set()
    for rel in DISJOINT_SOURCES:
        path = repo_root / rel
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                if "task_input_digest" in record:
                    digests.add(str(record["task_input_digest"]))
                elif "prompt_messages" in record:
                    user = record["prompt_messages"][-1]["content"]
                    digests.add(_task_input_digest(user))
                elif "case_id" in record:
                    digests.add(f"case_id:{record['case_id']}")
    return digests


def _retokenize_and_verify(records: list[dict[str, Any]]) -> None:
    """Verify single-token targets and zero truncation under gpt2@607a30d."""

    import importlib

    transformers = importlib.import_module("transformers")
    tokenizer = transformers.AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token

    for record in records:
        prompt_ids = tokenizer(record["prompt_bytes"], add_special_tokens=True)["input_ids"]
        if len(prompt_ids) > CONTEXT_LENGTH:
            raise ValueError(
                f"{record['record_id']}: prompt truncates at context {CONTEXT_LENGTH} "
                f"({len(prompt_ids)} tokens)"
            )
        cw_ids = tokenizer.encode(record["codeword"], add_special_tokens=False)
        if len(cw_ids) != 1 or cw_ids[0] != record["codeword_token_id"]:
            raise ValueError(
                f"{record['record_id']}: codeword {record['codeword']} is not single-token "
                f"({cw_ids})"
            )
        record["prompt_token_count"] = len(prompt_ids)


def _oracle_reverify(records: list[dict[str, Any]], specs: list[FamilySpec]) -> None:
    """Re-verify every gold class by re-executing the oracle from the spec."""

    for record, spec in zip(records, specs, strict=True):
        gold = _derive_class(spec)
        if gold != record["gold_class"]:
            raise ValueError(
                f"{record['record_id']}: oracle re-verification mismatch "
                f"({gold} != {record['gold_class']})"
            )


def build(repo_root: Path) -> dict[str, Any]:
    """Build the E3 dataset and write the four artifacts."""

    out_dir = repo_root / "experiments" / "e3"
    out_dir.mkdir(parents=True, exist_ok=True)

    anchor_specs = _anchor_specs()
    primary_specs = _primary_specs()
    clean_specs = _clean_specs()

    # Enforce the intended class composition BEFORE compilation so a mislabeled
    # spec fails loudly here rather than in the runner.
    anchor_classes = [(_derive_class(s), s.family_id) for s in anchor_specs]
    anchor_n = [fid for cls, fid in anchor_classes if cls == "NEITHER"]
    anchor_s = [fid for cls, fid in anchor_classes if cls == "SURVIVES_ONLY"]
    if len(anchor_n) != 5 or len(anchor_s) != 5:
        raise ValueError(
            f"anchor class composition wrong: NEITHER={anchor_n}, SURVIVES_ONLY={anchor_s}"
        )
    if len({c for c, _ in anchor_classes}) != 2:
        raise ValueError(f"anchors must be only NEITHER/SURVIVES_ONLY: {anchor_classes}")

    primary_counts: dict[str, int] = {}
    for spec in primary_specs:
        cls = _derive_class(spec)
        primary_counts[cls] = primary_counts.get(cls, 0) + 1
    expected_primary = {
        "NEITHER": 4,
        "REMOVES_ONLY": 4,
        "SURVIVES_ONLY": 4,
        "BOTH": 4,
        "NOT_APPLICABLE": 4,
    }
    if primary_counts != expected_primary:
        raise ValueError(f"primary class counts mismatch: {primary_counts} != {expected_primary}")

    clean_counts: dict[str, int] = {}
    for spec in clean_specs:
        cls = _derive_class(spec)
        clean_counts[cls] = clean_counts.get(cls, 0) + 1
    if clean_counts != {"NEITHER": 5, "SURVIVES_ONLY": 5}:
        raise ValueError(f"clean class counts mismatch: {clean_counts}")

    anchor_records = [_compile_record(spec, "anchor") for spec in anchor_specs]
    primary_records = [_compile_record(spec, "primary") for spec in primary_specs]
    clean_records = [_compile_record(spec, "clean") for spec in clean_specs]

    all_records = anchor_records + primary_records + clean_records

    # Disjointness: no E3 record may collide with any E1/E2 train/dev digest.
    disjoint_digests = _load_disjoint_digests(repo_root)
    for record in all_records:
        if record["task_input_digest"] in disjoint_digests:
            raise ValueError(f"{record['record_id']}: collides with an E1/E2 task_input_digest")
        if record["record_id"].startswith("CAL-") or record["family_id"].startswith("CAL-"):
            raise ValueError(f"{record['record_id']}: collides with LF calibration namespace")

    # Internal disjointness: no two E3 records share a digest (unique prompts).
    internal_digests = [r["task_input_digest"] for r in all_records]
    if len(set(internal_digests)) != len(internal_digests):
        seen: dict[str, str] = {}
        for r in all_records:
            d = r["task_input_digest"]
            if d in seen:
                raise ValueError(f"internal digest collision: {r['record_id']} == {seen[d]} ({d})")
            seen[d] = r["record_id"]

    # Re-verify oracle labels and retokenize.
    _oracle_reverify(all_records, anchor_specs + primary_specs + clean_specs)
    _retokenize_and_verify(all_records)

    # Write the three JSONL files.
    anchor_path = out_dir / "clean_anchors.jsonl"
    primary_path = out_dir / "protected_primary.jsonl"
    clean_path = out_dir / "protected_clean.jsonl"
    with anchor_path.open("w", encoding="utf-8") as handle:
        for record in anchor_records:
            handle.write(canonical_json_text(record))
    with primary_path.open("w", encoding="utf-8") as handle:
        for record in primary_records:
            handle.write(canonical_json_text(record))
    with clean_path.open("w", encoding="utf-8") as handle:
        for record in clean_records:
            handle.write(canonical_json_text(record))

    anchor_digest = hashlib.sha256(anchor_path.read_bytes()).hexdigest()
    primary_digest = hashlib.sha256(primary_path.read_bytes()).hexdigest()
    clean_digest = hashlib.sha256(clean_path.read_bytes()).hexdigest()
    anchor_constituents = [
        hashlib.sha256(canonical_json_bytes(r)).hexdigest() for r in anchor_records
    ]
    primary_constituents = [
        hashlib.sha256(canonical_json_bytes(r)).hexdigest() for r in primary_records
    ]
    clean_constituents = [
        hashlib.sha256(canonical_json_bytes(r)).hexdigest() for r in clean_records
    ]
    if len(set(primary_constituents + clean_constituents)) != 30:
        raise ValueError("protected (primary+clean) record digests are not mutually distinct")
    if len(set(anchor_constituents + primary_constituents + clean_constituents)) != 40:
        raise ValueError("E3 record digests are not mutually distinct")

    manifest = {
        "schema_version": "e3-manifest/1",
        "release": "e3-safety-anchored/1",
        "anchor_record_count": len(anchor_records),
        "primary_record_count": len(primary_records),
        "clean_record_count": len(clean_records),
        "total_record_count": len(all_records),
        "anchor_class_counts": {"NEITHER": 5, "SURVIVES_ONLY": 5},
        "primary_class_counts": primary_counts,
        "clean_class_counts": dict(sorted(clean_counts.items())),
        "anchor_artifact_sha256": anchor_digest,
        "primary_artifact_sha256": primary_digest,
        "clean_artifact_sha256": clean_digest,
        "anchor_record_digests": anchor_constituents,
        "primary_record_digests": primary_constituents,
        "clean_record_digests": clean_constituents,
        "anchor_record_ids": [r["record_id"] for r in anchor_records],
        "primary_record_ids": [r["record_id"] for r in primary_records],
        "clean_record_ids": [r["record_id"] for r in clean_records],
        "task_input_digests": [r["task_input_digest"] for r in all_records],
        "anchor_identity_constraint": (
            "The 10 clean anchors are added IDENTICALLY to both training arms; "
            "their prompt_bytes are the sole differential-neutral seed."
        ),
        "codeword_codebook": CODEWORD_BY_CLASS,
        "token_id_codebook": TOKEN_ID_BY_CODEWORD,
        "oracle_verification": {
            "label_authority": "executable_semantics",
            "oracle": "csd_foundry.kernel.oracle.CsdOracle",
            "all_labels_reverified": True,
        },
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "context_length": CONTEXT_LENGTH,
        "disjoint_from_e1_train_dev": True,
        "disjoint_from_e2_evaluation": True,
        "disjoint_from_lf_calibration": True,
        "claim_boundary": (
            "This manifest binds the 40 E3 records (10 shared clean anchors + 20 "
            "primary + 10 clean safety), their class counts, digests, and oracle-"
            "derived labels. Labels are produced by CsdOracle execution (or "
            "NOT_APPLICABLE for observations). It does not fix a training recipe, "
            "authorize GPU execution, or establish learning value."
        ),
    }
    manifest_path = out_dir / "e3_manifest.json"
    manifest_path.write_text(canonical_json_text(manifest), encoding="utf-8")

    return {
        "anchor_records": anchor_records,
        "primary_records": primary_records,
        "clean_records": clean_records,
        "manifest": manifest,
        "paths": {
            "anchor": str(anchor_path),
            "primary": str(primary_path),
            "clean": str(clean_path),
            "manifest": str(manifest_path),
        },
    }


def main() -> None:
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    result = build(repo_root)
    print(f"anchor:   {result['paths']['anchor']}")
    print(f"primary:  {result['paths']['primary']}")
    print(f"clean:    {result['paths']['clean']}")
    print(f"manifest: {result['paths']['manifest']}")
    manifest = result["manifest"]
    print(
        f"records: {manifest['total_record_count']} "
        f"({manifest['anchor_record_count']} anchor + "
        f"{manifest['primary_record_count']} primary + "
        f"{manifest['clean_record_count']} clean)"
    )
    print(f"anchor class counts: {manifest['anchor_class_counts']}")
    print(f"primary class counts: {manifest['primary_class_counts']}")
    print(f"clean class counts:   {manifest['clean_class_counts']}")
    print("E3 dataset built successfully.", file=sys.stderr)


if __name__ == "__main__":
    main()
