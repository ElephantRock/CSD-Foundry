"""Tests for E1 symbolic-family identities and leakage-safe split manifests."""

from dataclasses import replace

import pytest

from csd_foundry.empirical.e1 import (
    E1Split,
    FamilySplitError,
    compile_family_split_manifest,
    derive_scenario_family_identity,
)
from csd_foundry.kernel.events import DependencyChange
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import ObservationCase, TransitionCase


_SOURCE_COMMIT = "b87d42e4103f0c8b07c58f8e8f04dfda5cf5d111"


def _scenario_values() -> tuple[object, ...]:
    return tuple(SCENARIOS.values())


def test_all_seed_scenarios_have_canonical_family_identities() -> None:
    identities = [
        derive_scenario_family_identity(scenario) for scenario in SCENARIOS.values()
    ]

    assert len(identities) == 21
    assert all(len(identity.family_digest) == 64 for identity in identities)
    assert all(identity.case_count > 0 for identity in identities)


def test_family_identity_ignores_surface_metadata_and_observation_wording() -> None:
    scenario = SCENARIOS["M-03"]
    case = scenario.cases[0]
    assert isinstance(case, ObservationCase)

    variant_case = replace(
        case,
        case_id="PARAPHRASE/post-expiry",
        assertion="Completely different wording for the same executable obligation.",
    )
    variant = replace(
        scenario,
        scenario_id="PARAPHRASE-03",
        split="validation",
        family="renamed_family_label",
        source_section="Different prose source",
        cases=(variant_case,),
        forbidden_inferences=("Different wording",),
        assumptions=("Different wording",),
    )

    assert (
        derive_scenario_family_identity(scenario).family_digest
        == derive_scenario_family_identity(variant).family_digest
    )


def test_family_identity_ignores_consistent_concrete_identity_renaming() -> None:
    scenario = SCENARIOS["M-01"]
    case = scenario.cases[0]
    assert isinstance(case, TransitionCase)
    assert isinstance(case.event, DependencyChange)

    evidence = case.before.evidence[0]
    basis = case.before.bases[0]
    renamed_evidence = replace(
        evidence,
        evidence_id="RENAMED-EVIDENCE",
        dependencies=frozenset({"RENAMED-DEPENDENCY"}),
    )
    renamed_basis = replace(
        basis,
        basis_id="RENAMED-BASIS",
        member_evidence_ids=frozenset({renamed_evidence.evidence_id}),
    )
    renamed_before = replace(
        case.before,
        control_id="RENAMED-CONTROL",
        evidence=(renamed_evidence,),
        bases=(renamed_basis,),
        current_source_basis_ids=frozenset({renamed_basis.basis_id}),
    )
    renamed_expected = replace(
        case.expected,
        evidence_statuses=((renamed_evidence.evidence_id, case.expected.evidence_statuses[0][1]),),
    )
    renamed_case = replace(
        case,
        case_id="RENAMED/case",
        before=renamed_before,
        event=replace(case.event, dependency_id="RENAMED-DEPENDENCY"),
        expected=renamed_expected,
        expected_invalidated_evidence=frozenset({renamed_evidence.evidence_id}),
    )
    renamed_scenario = replace(
        scenario,
        scenario_id="RENAMED-M-01",
        cases=(renamed_case,),
    )

    assert (
        derive_scenario_family_identity(scenario).family_digest
        == derive_scenario_family_identity(renamed_scenario).family_digest
    )


def test_family_identity_changes_when_executable_rules_change() -> None:
    scenario = SCENARIOS["M-01"]
    changed_rules = frozenset(sorted(scenario.rule_ids)[1:])
    changed = replace(scenario, rule_ids=changed_rules)

    assert (
        derive_scenario_family_identity(scenario).family_digest
        != derive_scenario_family_identity(changed).family_digest
    )


def test_manifest_assigns_an_entire_symbolic_family_to_one_split() -> None:
    base = SCENARIOS["M-03"]
    case = base.cases[0]
    assert isinstance(case, ObservationCase)
    paraphrase = replace(
        base,
        scenario_id="M-03-PARAPHRASE",
        family="different_declared_label",
        source_section="Different surface source",
        cases=(replace(case, case_id="M-03-PARAPHRASE/case", assertion="Paraphrase"),),
    )
    base_digest = derive_scenario_family_identity(base).family_digest
    other = next(
        scenario
        for scenario in SCENARIOS.values()
        if derive_scenario_family_identity(scenario).family_digest != base_digest
    )

    manifest = compile_family_split_manifest(
        (base, paraphrase, other),
        development_family_digests=frozenset({base_digest}),
        release="e1-dev",
        source_commit=_SOURCE_COMMIT,
    )

    development = next(
        assignment for assignment in manifest.assignments if assignment.split is E1Split.DEVELOPMENT
    )
    assert development.scenario_ids == ("M-03", "M-03-PARAPHRASE")
    assert manifest.to_dict()["family_overlap"] is False


def test_manifest_is_independent_of_scenario_input_order() -> None:
    scenarios = tuple(SCENARIOS.values())
    family_digests = sorted(
        {derive_scenario_family_identity(scenario).family_digest for scenario in scenarios}
    )
    development = frozenset({family_digests[0]})

    forward = compile_family_split_manifest(
        scenarios,
        development_family_digests=development,
        release="e1-dev",
        source_commit=_SOURCE_COMMIT,
    )
    reverse = compile_family_split_manifest(
        reversed(scenarios),
        development_family_digests=development,
        release="e1-dev",
        source_commit=_SOURCE_COMMIT,
    )

    assert forward == reverse
    assert forward.manifest_digest == reverse.manifest_digest


def test_manifest_rejects_invalid_family_selection_and_duplicate_scenarios() -> None:
    scenarios = tuple(SCENARIOS.values())
    known = frozenset(
        {derive_scenario_family_identity(scenario).family_digest for scenario in scenarios}
    )

    with pytest.raises(FamilySplitError, match="at least one development family"):
        compile_family_split_manifest(
            scenarios,
            development_family_digests=frozenset(),
            release="e1-dev",
            source_commit=_SOURCE_COMMIT,
        )

    with pytest.raises(FamilySplitError, match="not present"):
        compile_family_split_manifest(
            scenarios,
            development_family_digests=frozenset({"0" * 64}),
            release="e1-dev",
            source_commit=_SOURCE_COMMIT,
        )

    with pytest.raises(FamilySplitError, match="at least one training family"):
        compile_family_split_manifest(
            scenarios,
            development_family_digests=known,
            release="e1-dev",
            source_commit=_SOURCE_COMMIT,
        )

    with pytest.raises(FamilySplitError, match="scenario identifiers must be unique"):
        compile_family_split_manifest(
            (*scenarios, scenarios[0]),
            development_family_digests=frozenset({next(iter(known))}),
            release="e1-dev",
            source_commit=_SOURCE_COMMIT,
        )
