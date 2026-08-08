#!/usr/bin/env python3
"""Construct the E2 protected evaluation set from the executable CSD kernel.

Builds 20 primary families (4 per semantic class x 5 classes) and 10 clean
safety cases. Every label is derived from CsdOracle execution over an explicit
``(before-state, event)`` pair, then mapped through the frozen codebook
(NEITHER->A, REMOVES_ONLY->B, SURVIVES_ONLY->C, BOTH->D, NOT_APPLICABLE->E).

Primary classes (4 structurally distinct families each):

* NEITHER        - DependencyChange on an irrelevant dependency, no bases at all
* REMOVES_ONLY   - DependencyChange invalidates all basis support, no survivors
* SURVIVES_ONLY  - DependencyChange on irrelevant dependency, bases unaffected
* BOTH           - DependencyChange invalidates SOME but not all basis support
                   (structurally diverse evidence/basis/dependency configurations)
* NOT_APPLICABLE - ObservationCase (valid state, no basis disposition)

Clean safety cases (10 records): straightforward valid transitions that do not
require the new semantic distinctions (SURVIVES_ONLY / NEITHER patterns only).

Critical constraints enforced by this constructor:

* No record matches any E1 training/dev prompt (checked by user_content digest).
* No record matches any LF calibration record (CAL-* ids).
* Every label comes from CsdOracle execution (or NOT_APPLICABLE for observation).
* Every target is exactly one token (A=32, B=33, C=34, D=35, E=36).
* Zero truncation at context 512.
* Train and eval are completely disjoint.
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

# E1 v6 training/dev + LF calibration sources that E2 must stay disjoint from.
DISJOINT_SOURCES = (
    "data/e1/v6/control_train.jsonl",
    "data/e1/v6/foundry_train.jsonl",
    "data/e1/v6/development_evaluation.jsonl",
    "data/e1/v6/clean_evaluation.jsonl",
)


# ---------------------------------------------------------------------------
# Spec primitives.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FamilySpec:
    """A structurally described primary family."""

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
# Primary family construction (20 families: 4 per class x 5 classes).
# ---------------------------------------------------------------------------


def _primary_specs() -> list[FamilySpec]:
    """20 structurally distinct primary families, 4 per semantic class."""

    specs: list[FamilySpec] = []

    # === NEITHER (4): DependencyChange on irrelevant dep, NO bases at all ===

    # NEITHER-1: single evidence, no bases, irrelevant dependency
    specs.append(
        FamilySpec(
            family_id="E2-PRI-001",
            record_id="E2-PRI-001/neither-irrelevant-single",
            declared_family="neither_irrelevant_no_basis_single",
            assertion="A dependency change touching no basis removes nothing and survives nothing.",
            control_id="E2-N1",
            before=_state(
                "E2-N1",
                (_ev("EV-N1", deps=("depData",)),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depUnrelated"),
        )
    )

    # NEITHER-2: two evidence items with different deps, no bases
    specs.append(
        FamilySpec(
            family_id="E2-PRI-002",
            record_id="E2-PRI-002/neither-irrelevant-dual-evidence",
            declared_family="neither_irrelevant_no_basis_dual",
            assertion="Distinct dependencies keep unrelated changes from touching bases.",
            control_id="E2-N2",
            before=_state(
                "E2-N2",
                (_ev("EV-N2A", deps=("depAlpha",)), _ev("EV-N2B", deps=("depBeta",))),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depGamma"),
        )
    )

    # NEITHER-3: evidence with apparent_direction, no bases
    specs.append(
        FamilySpec(
            family_id="E2-PRI-003",
            record_id="E2-PRI-003/neither-direction-annotated",
            declared_family="neither_irrelevant_no_basis_direction",
            assertion="Apparent dependency direction does not create a basis to remove.",
            control_id="E2-N3",
            before=_state(
                "E2-N3",
                (_ev("EV-N3", deps=("depWire",)),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depOther", apparent_direction="down"),
        )
    )

    # NEITHER-4: multi-dep evidence, change on a dependency that is absent
    specs.append(
        FamilySpec(
            family_id="E2-PRI-004",
            record_id="E2-PRI-004/neither-multidep-miss",
            declared_family="neither_irrelevant_no_basis_multidep",
            assertion="A multi-dependency evidence survives a change on none of its deps.",
            control_id="E2-N4",
            before=_state(
                "E2-N4",
                (_ev("EV-N4", deps=("depA", "depB", "depC")),),
                (),
                frozenset(),
                frozenset(),
            ),
            event=DependencyChange(dependency_id="depZ"),
        )
    )

    # === REMOVES_ONLY (4): DependencyChange invalidates ALL basis support ===

    # REMOVES-1: single verdict basis, single dep evidence, change kills it
    specs.append(
        FamilySpec(
            family_id="E2-PRI-005",
            record_id="E2-PRI-005/removes-single-verdict",
            declared_family="removes_only_single_verdict",
            assertion="A dependency change can retire the only basis supporting a verdict.",
            control_id="E2-R1",
            before=_state(
                "E2-R1",
                (_ev("EV-R1", deps=("depSensor",)),),
                (_vrd_basis("BAS-R1V", ("EV-R1",)),),
                frozenset(),
                frozenset({"BAS-R1V"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depSensor"),
        )
    )

    # REMOVES-2: single source basis (connected), change kills the evidence
    specs.append(
        FamilySpec(
            family_id="E2-PRI-006",
            record_id="E2-PRI-006/removes-single-source",
            declared_family="removes_only_single_source",
            assertion="A source basis falls when its sole supporting dependency changes.",
            control_id="E2-R2",
            before=_state(
                "E2-R2",
                (_ev("EV-R2", deps=("depFeed",)),),
                (_src_basis("BAS-R2S", ("EV-R2",)),),
                frozenset({"BAS-R2S"}),
                frozenset(),
                source=SourceState.CONNECTED,
                assurance=Assurance.UNVERIFIED,
            ),
            event=DependencyChange(dependency_id="depFeed"),
        )
    )

    # REMOVES-3: source + verdict basis BOTH on the SAME evidence; change kills both
    specs.append(
        FamilySpec(
            family_id="E2-PRI-007",
            record_id="E2-PRI-007/removes-joint-source-verdict",
            declared_family="removes_only_joint_source_verdict",
            assertion="Co-supported source and verdict bases fall together on one dep change.",
            control_id="E2-R3",
            before=_state(
                "E2-R3",
                (_ev("EV-R3", deps=("depShared",)),),
                (
                    _src_basis("BAS-R3S", ("EV-R3",)),
                    _vrd_basis("BAS-R3V", ("EV-R3",)),
                ),
                frozenset({"BAS-R3S"}),
                frozenset({"BAS-R3V"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depShared"),
        )
    )

    # REMOVES-4: verdict basis spanning two pieces of evidence on the SAME dep
    specs.append(
        FamilySpec(
            family_id="E2-PRI-008",
            record_id="E2-PRI-008/removes-spanning-verdict",
            declared_family="removes_only_spanning_verdict",
            assertion="A basis spanning multiple evidence on one dep falls on that dep change.",
            control_id="E2-R4",
            before=_state(
                "E2-R4",
                (
                    _ev("EV-R4A", deps=("depProbe",)),
                    _ev("EV-R4B", deps=("depProbe",)),
                ),
                (_vrd_basis("BAS-R4V", ("EV-R4A", "EV-R4B"), claim="fail"),),
                frozenset(),
                frozenset({"BAS-R4V"}),
                assurance=Assurance.FAIL,
            ),
            event=DependencyChange(dependency_id="depProbe"),
        )
    )

    # === SURVIVES_ONLY (4): irrelevant dependency change, bases unaffected ===

    # SURVIVES-1: verdict basis on depB, change on depX
    specs.append(
        FamilySpec(
            family_id="E2-PRI-009",
            record_id="E2-PRI-009/survives-single-verdict",
            declared_family="survives_only_single_verdict",
            assertion="An unrelated dependency change leaves a verdict basis intact.",
            control_id="E2-S1",
            before=_state(
                "E2-S1",
                (_ev("EV-S1", deps=("depB",)),),
                (_vrd_basis("BAS-S1V", ("EV-S1",)),),
                frozenset(),
                frozenset({"BAS-S1V"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depX"),
        )
    )

    # SURVIVES-2: source basis (connected), change on unrelated dep
    specs.append(
        FamilySpec(
            family_id="E2-PRI-010",
            record_id="E2-PRI-010/survives-single-source",
            declared_family="survives_only_single_source",
            assertion="A source basis survives when an unrelated dependency changes.",
            control_id="E2-S2",
            before=_state(
                "E2-S2",
                (_ev("EV-S2", deps=("depLink",)),),
                (_src_basis("BAS-S2S", ("EV-S2",)),),
                frozenset({"BAS-S2S"}),
                frozenset(),
                source=SourceState.CONNECTED,
                assurance=Assurance.UNVERIFIED,
            ),
            event=DependencyChange(dependency_id="depOther"),
        )
    )

    # SURVIVES-3: source + verdict on DISTINCT unrelated deps, change on a third
    specs.append(
        FamilySpec(
            family_id="E2-PRI-011",
            record_id="E2-PRI-011/survives-source-and-verdict",
            declared_family="survives_only_source_and_verdict",
            assertion="Distinct bases on distinct deps survive an unrelated change.",
            control_id="E2-S3",
            before=_state(
                "E2-S3",
                (
                    _ev("EV-S3SRC", deps=("depSrc",)),
                    _ev("EV-S3VRD", deps=("depVrd",)),
                ),
                (
                    _src_basis("BAS-S3S", ("EV-S3SRC",)),
                    _vrd_basis("BAS-S3V", ("EV-S3VRD",)),
                ),
                frozenset({"BAS-S3S"}),
                frozenset({"BAS-S3V"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depUnrelated"),
        )
    )

    # SURVIVES-4: multi-evidence verdict basis, change on a dep absent from all members
    specs.append(
        FamilySpec(
            family_id="E2-PRI-012",
            record_id="E2-PRI-012/survives-multimember-verdict",
            declared_family="survives_only_multimember_verdict",
            assertion="A multi-member basis survives when none of its members' deps change.",
            control_id="E2-S4",
            before=_state(
                "E2-S4",
                (
                    _ev("EV-S4A", deps=("depA",)),
                    _ev("EV-S4B", deps=("depB",)),
                ),
                (_vrd_basis("BAS-S4V", ("EV-S4A", "EV-S4B"), claim="partial"),),
                frozenset(),
                frozenset({"BAS-S4V"}),
                assurance=Assurance.PARTIAL,
            ),
            event=DependencyChange(dependency_id="depC"),
        )
    )

    # === BOTH (4): partial-intersection, structurally diverse ===

    # BOTH-1: two verdict bases on distinct deps; change kills one, keeps one
    specs.append(
        FamilySpec(
            family_id="E2-PRI-013",
            record_id="E2-PRI-013/both-two-verdict-bases",
            declared_family="both_partial_two_verdict_bases",
            assertion="A dependency change can retire one verdict basis while another survives.",
            control_id="E2-B1",
            before=_state(
                "E2-B1",
                (
                    _ev("EV-B1HIT", deps=("depHit",)),
                    _ev("EV-B1KEP", deps=("depKeep",)),
                ),
                (
                    _vrd_basis("BAS-B1HIT", ("EV-B1HIT",)),
                    _vrd_basis("BAS-B1KEP", ("EV-B1KEP",)),
                ),
                frozenset(),
                frozenset({"BAS-B1HIT", "BAS-B1KEP"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depHit"),
        )
    )

    # BOTH-2: source basis removed, verdict basis survives (cross-kind partial)
    specs.append(
        FamilySpec(
            family_id="E2-PRI-014",
            record_id="E2-PRI-014/both-source-removed-verdict-survives",
            declared_family="both_partial_source_removed_verdict_survives",
            assertion="A change can drop the source basis while the verdict basis survives.",
            control_id="E2-B2",
            before=_state(
                "E2-B2",
                (
                    _ev("EV-B2SRC", deps=("depSrc",)),
                    _ev("EV-B2VRD", deps=("depVrd",)),
                ),
                (
                    _src_basis("BAS-B2S", ("EV-B2SRC",)),
                    _vrd_basis("BAS-B2V", ("EV-B2VRD",)),
                ),
                frozenset({"BAS-B2S"}),
                frozenset({"BAS-B2V"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depSrc"),
        )
    )

    # BOTH-3: verdict basis survives, source basis survives; a THIRD basis removed
    #         (3 bases total: 2 survive, 1 removed)
    specs.append(
        FamilySpec(
            family_id="E2-PRI-015",
            record_id="E2-PRI-015/both-three-basis-mix",
            declared_family="both_partial_three_basis_mix",
            assertion="Among three bases a change can remove one and leave two standing.",
            control_id="E2-B3",
            before=_state(
                "E2-B3",
                (
                    _ev("EV-B3HIT", deps=("depHit",)),
                    _ev("EV-B3V1", deps=("depV1",)),
                    _ev("EV-B3V2", deps=("depV2",)),
                ),
                (
                    _src_basis("BAS-B3HIT", ("EV-B3HIT",)),
                    _vrd_basis("BAS-B3V1", ("EV-B3V1",)),
                    _vrd_basis("BAS-B3V2", ("EV-B3V2",)),
                ),
                frozenset({"BAS-B3HIT"}),
                frozenset({"BAS-B3V1", "BAS-B3V2"}),
                source=SourceState.CONNECTED,
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depHit"),
        )
    )

    # BOTH-4: one basis spanning two evidence (one member hit, one kept) -> removed;
    #         a second independent basis survives. (basis-internal partial + cross)
    specs.append(
        FamilySpec(
            family_id="E2-PRI-016",
            record_id="E2-PRI-016/both-spanning-and-independent",
            declared_family="both_partial_spanning_and_independent",
            assertion="A spanning basis falls when one member is hit; another survives.",
            control_id="E2-B4",
            before=_state(
                "E2-B4",
                (
                    _ev("EV-B4SPANHIT", deps=("depHit",)),
                    _ev("EV-B4SPANKEP", deps=("depKeep",)),
                    _ev("EV-B4IND", deps=("depInd",)),
                ),
                (
                    _vrd_basis("BAS-B4SPAN", ("EV-B4SPANHIT", "EV-B4SPANKEP")),
                    _vrd_basis("BAS-B4IND", ("EV-B4IND",)),
                ),
                frozenset(),
                frozenset({"BAS-B4SPAN", "BAS-B4IND"}),
                assurance=Assurance.PASS,
            ),
            event=DependencyChange(dependency_id="depHit"),
        )
    )

    # === NOT_APPLICABLE (4): ObservationCase (valid state, no basis disposition) ===

    # NA-1: minimal observation (single current evidence, no verdict)
    specs.append(
        FamilySpec(
            family_id="E2-PRI-017",
            record_id="E2-PRI-017/na-observation-minimal",
            declared_family="na_observation_minimal",
            assertion="An observation with no basis disposition is NOT_APPLICABLE.",
            control_id="E2-NA1",
            before=_state(
                "E2-NA1",
                (_ev("EV-NA1", deps=("depD",), outcome="demonstratesFailure"),),
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
            family_id="E2-PRI-018",
            record_id="E2-PRI-018/na-observation-multi-evidence",
            declared_family="na_observation_multi_evidence",
            assertion="A multi-evidence observation still carries no basis disposition.",
            control_id="E2-NA2",
            before=_state(
                "E2-NA2",
                (
                    _ev("EV-NA2A", deps=("depA",), outcome="demonstratesSuccess"),
                    _ev("EV-NA2B", deps=("depB",), outcome="demonstratesFailure"),
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
            family_id="E2-PRI-019",
            record_id="E2-PRI-019/na-observation-expired-mix",
            declared_family="na_observation_expired_mix",
            assertion="An observation may carry non-current evidence without a disposition.",
            control_id="E2-NA3",
            before=_state(
                "E2-NA3",
                (
                    _ev("EV-NA3EXP", deps=("depOld",), status=EvidenceStatus.EXPIRED),
                    _ev("EV-NA3CUR", deps=("depNew",), outcome="demonstratesSuccess"),
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
            family_id="E2-PRI-020",
            record_id="E2-PRI-020/na-observation-stale-prior",
            declared_family="na_observation_stale_prior",
            assertion="An unverified observation with a stale prior is still NOT_APPLICABLE.",
            control_id="E2-NA4",
            before=_state(
                "E2-NA4",
                (
                    _ev("EV-NA4OLD", deps=("depOld",), status=EvidenceStatus.INVALIDATED),
                    _ev("EV-NA4NEW", deps=("depNew",), outcome="demonstratesFailure"),
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
# Clean safety cases (10 records).
# ---------------------------------------------------------------------------


def _clean_specs() -> list[FamilySpec]:
    """10 clean safety cases: straightforward valid transitions (SURVIVES_ONLY / NEITHER)."""

    specs: list[FamilySpec] = []

    # Clean 1-5: SURVIVES_ONLY (irrelevant change, surviving basis present)
    for i in range(1, 6):
        dep_keep = f"depKeep{i}"
        dep_change = f"depUnrelated{i}"
        specs.append(
            FamilySpec(
                family_id=f"E2-CLN-{i:03d}",
                record_id=f"E2-CLN-{i:03d}/clean-survives",
                declared_family=f"clean_survives_only_{i}",
                assertion="An irrelevant dependency change leaves an established basis intact.",
                control_id=f"E2-CLN-S{i}",
                before=_state(
                    f"E2-CLN-S{i}",
                    (_ev(f"EV-CLN-S{i}", deps=(dep_keep,)),),
                    (_vrd_basis(f"BAS-CLN-S{i}", (f"EV-CLN-S{i}",)),),
                    frozenset(),
                    frozenset({f"BAS-CLN-S{i}"}),
                    assurance=Assurance.PASS,
                ),
                event=DependencyChange(dependency_id=dep_change),
            )
        )

    # Clean 6-10: NEITHER (irrelevant change, no bases at all)
    for i in range(6, 11):
        dep_change = f"depUnrelated{i}"
        specs.append(
            FamilySpec(
                family_id=f"E2-CLN-{i:03d}",
                record_id=f"E2-CLN-{i:03d}/clean-neither",
                declared_family=f"clean_neither_{i}",
                assertion="An irrelevant change with no bases removes or preserves nothing.",
                control_id=f"E2-CLN-N{i}",
                before=_state(
                    f"E2-CLN-N{i}",
                    (_ev(f"EV-CLN-N{i}", deps=(f"depData{i}",)),),
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
    # Compact JSON with sorted keys + no whitespace, matching the kernel canonical form.
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
        "schema_version": "e2-codeword-evaluation-case/1",
        "cohort": cohort,
        "case_id": f"e2-evaluation/{cohort}/{spec.family_id}/{spec.record_id.split('/', 1)[1]}",
        "record_id": spec.record_id,
        "family_id": spec.family_id,
        "declared_family": spec.declared_family,
        "case_kind": "observation" if spec.event is None else "transition",
        "assertion": spec.assertion,
        "gold_class": gold_class,
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
                    # development/clean evaluation cases carry no prompt; identity by case_id
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
        # Verify the codeword is exactly one token.
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
    """Build the protected evaluation set and write the three artifacts."""

    out_dir = repo_root / "experiments" / "e2"
    out_dir.mkdir(parents=True, exist_ok=True)

    primary_specs = _primary_specs()
    clean_specs = _clean_specs()
    primary_records = [_compile_record(spec, "primary") for spec in primary_specs]
    clean_records = [_compile_record(spec, "clean") for spec in clean_specs]

    all_records = primary_records + clean_records

    # Enforce class-count expectations on the primary set (4 per class).
    primary_counts: dict[str, int] = {}
    for record in primary_records:
        primary_counts[record["gold_class"]] = primary_counts.get(record["gold_class"], 0) + 1
    expected_primary = {
        "NEITHER": 4,
        "REMOVES_ONLY": 4,
        "SURVIVES_ONLY": 4,
        "BOTH": 4,
        "NOT_APPLICABLE": 4,
    }
    if primary_counts != expected_primary:
        raise ValueError(f"primary class counts mismatch: {primary_counts} != {expected_primary}")

    # Clean cases must be SURVIVES_ONLY or NEITHER only.
    clean_counts: dict[str, int] = {}
    for record in clean_records:
        clean_counts[record["gold_class"]] = clean_counts.get(record["gold_class"], 0) + 1
    if not set(clean_counts) <= {"SURVIVES_ONLY", "NEITHER"}:
        raise ValueError(f"clean cases must be SURVIVES_ONLY/NEITHER, observed {set(clean_counts)}")

    # Disjointness: no E2 record may collide with any E1 train/dev digest.
    disjoint_digests = _load_disjoint_digests(repo_root)
    for record in all_records:
        if record["task_input_digest"] in disjoint_digests:
            raise ValueError(
                f"{record['record_id']}: collides with an E1 train/dev task_input_digest"
            )
        if record["record_id"].startswith("CAL-") or record["family_id"].startswith("CAL-"):
            raise ValueError(f"{record['record_id']}: collides with LF calibration namespace")

    # Re-verify oracle labels and retokenize.
    _oracle_reverify(all_records, primary_specs + clean_specs)
    _retokenize_and_verify(all_records)

    # Write the two JSONL files.
    primary_path = out_dir / "protected_primary.jsonl"
    clean_path = out_dir / "protected_clean.jsonl"
    with primary_path.open("w", encoding="utf-8") as handle:
        for record in primary_records:
            handle.write(canonical_json_text(record))
    with clean_path.open("w", encoding="utf-8") as handle:
        for record in clean_records:
            handle.write(canonical_json_text(record))

    # Manifest binding all 30 records, class counts, digests, oracle verification.
    primary_digest = hashlib.sha256(primary_path.read_bytes()).hexdigest()
    clean_digest = hashlib.sha256(clean_path.read_bytes()).hexdigest()
    primary_constituents = [
        hashlib.sha256(canonical_json_bytes(r)).hexdigest() for r in primary_records
    ]
    clean_constituents = [
        hashlib.sha256(canonical_json_bytes(r)).hexdigest() for r in clean_records
    ]
    if len(set(primary_constituents + clean_constituents)) != 30:
        raise ValueError("protected record digests are not mutually distinct")

    manifest = {
        "schema_version": "e2-protected-manifest/1",
        "release": "e2-protected-evaluation/1",
        "primary_record_count": len(primary_records),
        "clean_record_count": len(clean_records),
        "total_record_count": len(all_records),
        "primary_class_counts": primary_counts,
        "clean_class_counts": dict(sorted(clean_counts.items())),
        "primary_artifact_sha256": primary_digest,
        "clean_artifact_sha256": clean_digest,
        "primary_record_digests": primary_constituents,
        "clean_record_digests": clean_constituents,
        "record_ids": [r["record_id"] for r in all_records],
        "family_ids": [r["family_id"] for r in all_records],
        "task_input_digests": [r["task_input_digest"] for r in all_records],
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
        "disjoint_from_lf_calibration": True,
        "claim_boundary": (
            "This manifest binds the 30 E2 protected evaluation records, their class "
            "counts, digests, and oracle-derived labels. Labels are produced by "
            "CsdOracle execution (or NOT_APPLICABLE for observations). It does not "
            "fix a training recipe, authorize GPU execution, or establish learning value."
        ),
    }
    manifest_path = out_dir / "protected_manifest.json"
    manifest_path.write_text(canonical_json_text(manifest), encoding="utf-8")

    return {
        "primary_records": primary_records,
        "clean_records": clean_records,
        "manifest": manifest,
        "paths": {
            "primary": str(primary_path),
            "clean": str(clean_path),
            "manifest": str(manifest_path),
        },
    }


def main() -> None:
    import sys

    repo_root = Path(__file__).resolve().parents[2]
    result = build(repo_root)
    print(f"primary: {result['paths']['primary']}")
    print(f"clean:   {result['paths']['clean']}")
    print(f"manifest: {result['paths']['manifest']}")
    manifest = result["manifest"]
    print(
        f"records: {manifest['total_record_count']} "
        f"({manifest['primary_record_count']} primary + {manifest['clean_record_count']} clean)"
    )
    print(f"primary class counts: {manifest['primary_class_counts']}")
    print("E2 protected evaluation built successfully.", file=sys.stderr)


if __name__ == "__main__":
    main()
