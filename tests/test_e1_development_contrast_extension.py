"""Tests for the E1 development-contrast extension overlay integrity."""

from __future__ import annotations

from pathlib import Path

import pytest

from csd_foundry.empirical.e1.development_contrast_extension import (
    build_e1_development_contrast_catalog,
    development_contrast_overlay_catalog_digest,
)
from csd_foundry.empirical.e1.scenario_splits import derive_scenario_family_identity
from csd_foundry.kernel.events import AdvanceClock, ProfileChange
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.runner import run_scenario
from csd_foundry.scenarios.spec import ObservationCase, ScenarioMode, TransitionCase

_PREDECESSOR_BASE_COMMIT = "2cf5875f3a78bb5aa14578bc1bf1f33c18b7a199"


@pytest.fixture(scope="module")
def overlay():
    return build_e1_development_contrast_catalog(SCENARIOS)


# ---------------------------------------------------------------------------
# Overlay integrity
# ---------------------------------------------------------------------------


def test_base_scenarios_registry_is_unchanged(overlay):
    # The base SCENARIOS dict must keep exactly 21 entries and the original modes.
    assert len(SCENARIOS) == 21
    assert SCENARIOS["M-12"].mode is ScenarioMode.OBSERVATION
    assert SCENARIOS["M-14"].mode is ScenarioMode.OBSERVATION


def test_only_m12_and_m14_differ(overlay):
    for scenario_id, base_spec in SCENARIOS.items():
        overlay_spec = overlay[scenario_id]
        if scenario_id in ("M-12", "M-14"):
            assert overlay_spec is not base_spec
            assert overlay_spec.cases != base_spec.cases
        else:
            assert overlay_spec is base_spec, f"{scenario_id} must be the same object"


def test_original_cases_retained_byte_identical_and_ordered(overlay):
    for scenario_id in ("M-12", "M-14"):
        base_cases = SCENARIOS[scenario_id].cases
        overlay_cases = overlay[scenario_id].cases
        # The original observation case is the first case, preserved exactly.
        assert isinstance(overlay_cases[0], ObservationCase)
        assert overlay_cases[0] == base_cases[0]


def test_new_transition_case_ids_are_unique(overlay):
    for scenario_id in ("M-12", "M-14"):
        cases = overlay[scenario_id].cases
        ids = {c.case_id for c in cases}
        assert len(ids) == len(cases)


def test_no_training_or_test_scenario_modified(overlay):
    for scenario_id in SCENARIOS:
        if SCENARIOS[scenario_id].split in ("train", "test"):
            assert overlay[scenario_id] is SCENARIOS[scenario_id]


def test_no_source_split_change(overlay):
    for scenario_id in SCENARIOS:
        assert overlay[scenario_id].split == SCENARIOS[scenario_id].split


def test_successor_modes_are_transition(overlay):
    assert overlay["M-12"].mode is ScenarioMode.TRANSITION
    assert overlay["M-14"].mode is ScenarioMode.TRANSITION


# ---------------------------------------------------------------------------
# Semantic execution
# ---------------------------------------------------------------------------


def test_m12_transition_passes_canonical_runner(overlay):
    result = run_scenario(overlay["M-12"])
    assert result.accepted


def test_m14_transition_passes_canonical_runner(overlay):
    result = run_scenario(overlay["M-14"])
    assert result.accepted


def test_m12_transition_is_deterministic(overlay):
    case = next(c for c in overlay["M-12"].cases if isinstance(c, TransitionCase))
    assert isinstance(case.event, AdvanceClock)
    from csd_foundry.kernel.oracle import CsdOracle

    oracle = CsdOracle()
    first = oracle.apply(case.before, case.event)
    second = oracle.apply(case.before, case.event)
    assert first == second


def test_m14_transition_is_deterministic(overlay):
    case = next(c for c in overlay["M-14"].cases if isinstance(c, TransitionCase))
    assert isinstance(case.event, ProfileChange)
    from csd_foundry.kernel.oracle import CsdOracle

    oracle = CsdOracle()
    first = oracle.apply(case.before, case.event)
    second = oracle.apply(case.before, case.event)
    assert first == second


def test_direct_apply_event_replay_matches_oracle(overlay):
    from csd_foundry.kernel.oracle import CsdOracle
    from csd_foundry.kernel.transitions import apply_event

    oracle = CsdOracle()
    for scenario_id in ("M-12", "M-14"):
        case = next(c for c in overlay[scenario_id].cases if isinstance(c, TransitionCase))
        result = oracle.apply(case.before, case.event)
        replay_after, replay_trace = apply_event(case.before, case.event)
        assert (replay_after, replay_trace) == (result.after, result.trace)


def test_m12_required_trace_rules_present(overlay):
    case = next(c for c in overlay["M-12"].cases if isinstance(c, TransitionCase))
    from csd_foundry.kernel.oracle import CsdOracle

    result = CsdOracle().apply(case.before, case.event)
    assert case.required_trace_rules <= frozenset(result.trace.rules_fired)


def test_m14_required_trace_rules_present(overlay):
    case = next(c for c in overlay["M-14"].cases if isinstance(c, TransitionCase))
    from csd_foundry.kernel.oracle import CsdOracle

    result = CsdOracle().apply(case.before, case.event)
    assert case.required_trace_rules <= frozenset(result.trace.rules_fired)


def test_m14_profile_version_post_state(overlay):
    case = next(c for c in overlay["M-14"].cases if isinstance(c, TransitionCase))
    from csd_foundry.kernel.oracle import CsdOracle

    result = CsdOracle().apply(case.before, case.event)
    assert result.after.required_profile_id == "PROFILE-M14"
    assert result.after.required_profile_version == 2


# ---------------------------------------------------------------------------
# Split integrity
# ---------------------------------------------------------------------------


def test_four_development_scenarios(overlay):
    dev = [s for s in overlay.values() if s.split == "validation"]
    assert len(dev) == 4


def test_every_development_family_has_a_transition(overlay):
    dev_specs = [s for s in overlay.values() if s.split == "validation"]
    for spec in dev_specs:
        has_transition = any(isinstance(c, TransitionCase) for c in spec.cases)
        assert has_transition, f"development scenario {spec.scenario_id} has no transition"


def test_no_training_development_family_overlap(overlay):
    train_ids = {
        derive_scenario_family_identity(s).family_digest
        for s in overlay.values()
        if s.split == "train"
    }
    dev_ids = {
        derive_scenario_family_identity(s).family_digest
        for s in overlay.values()
        if s.split == "validation"
    }
    assert train_ids.isdisjoint(dev_ids)


def test_training_family_digests_unchanged(overlay):
    for scenario_id, base_spec in SCENARIOS.items():
        if base_spec.split != "train":
            continue
        base_digest = derive_scenario_family_identity(base_spec).family_digest
        overlay_digest = derive_scenario_family_identity(overlay[scenario_id]).family_digest
        assert base_digest == overlay_digest, f"{scenario_id} family digest changed"


def test_excluded_test_ids_unchanged(overlay):
    test_ids = {s.scenario_id for s in overlay.values() if s.split == "test"}
    assert test_ids == {"H-01", "L-01", "M-15"}


def test_m12_m14_have_new_successor_family_digests(overlay):
    for scenario_id in ("M-12", "M-14"):
        base_digest = derive_scenario_family_identity(SCENARIOS[scenario_id]).family_digest
        overlay_digest = derive_scenario_family_identity(overlay[scenario_id]).family_digest
        assert base_digest != overlay_digest, (
            f"{scenario_id} successor family digest must differ from predecessor"
        )


# ---------------------------------------------------------------------------
# Audit integrity (recomputed from candidate records, no hard-coded winners)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def successor_audit_dict():
    import json

    return json.loads(Path("data/e1/v2/label_space_audit.json").read_text(encoding="utf-8"))


def test_audit_status_fields_are_internally_consistent(successor_audit_dict):
    candidates = successor_audit_dict["candidate_projections"]
    expected_sem = any(cp["semantic_candidate"] for cp in candidates)
    expected_primary = any(cp["primary_population_eligible"] for cp in candidates)
    assert successor_audit_dict["semantic_projection_candidate_present"] == expected_sem
    assert successor_audit_dict["primary_population_supported"] == expected_primary


def test_at_least_one_primary_population_eligible_projection(successor_audit_dict):
    eligible = [
        cp
        for cp in successor_audit_dict["candidate_projections"]
        if cp["primary_population_eligible"]
    ]
    assert eligible


def test_full_e1_population_support_is_null_while_clean_case_unfrozen(successor_audit_dict):
    assert successor_audit_dict["clean_case_policy_status"] == "unfrozen"
    assert successor_audit_dict["full_e1_population_support"] is None


def test_no_invalid_transition_contrast_blocker_remains(successor_audit_dict):
    # Not repaired by A0c; H-01 still excluded.
    assert "no_invalid_transition_contrast" in successor_audit_dict["experiment_blockers"]


def test_right_answer_wrong_basis_unassessable_remains(successor_audit_dict):
    assert "right_answer_wrong_basis_unassessable" in successor_audit_dict["experiment_blockers"]


def test_eligible_projection_covers_four_development_families(successor_audit_dict):
    eligible = [
        cp
        for cp in successor_audit_dict["candidate_projections"]
        if cp["primary_population_eligible"]
    ]
    for cp in eligible:
        assert cp["covered_development_family_count"] == 4


def test_successor_development_record_count_is_six(successor_audit_dict):
    assert successor_audit_dict["population"]["development_record_count"] == 6


# ---------------------------------------------------------------------------
# Historical immutability
# ---------------------------------------------------------------------------


def test_predecessor_audit_artifact_byte_identical():
    predecessor = Path("data/e1/v1/label_space_audit.json").read_bytes()
    # Recompile the predecessor audit from the base registry and compare.
    import sys

    sys.path.insert(0, str(Path("src")))
    from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
    from csd_foundry.empirical.e1.foundry_artifact_compiler import (
        compile_e1_foundry_artifacts,
    )
    from csd_foundry.empirical.e1.label_space_audit import audit_e1_label_space

    selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release="e1-candidate/1",
        source_commit=_PREDECESSOR_BASE_COMMIT,
    )
    bundle = compile_e1_foundry_artifacts(
        SCENARIOS,
        selection,
        release="e1-foundry-artifacts/1",
        selection_release="e1-candidate/1",
        source_commit=_PREDECESSOR_BASE_COMMIT,
    )
    audit = audit_e1_label_space(
        bundle,
        selection,
        release="e1-label-space-audit/1",
        source_commit=_PREDECESSOR_BASE_COMMIT,
    )
    from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

    assert canonical_json_bytes(audit.to_dict()) == predecessor


def test_no_released_schema_or_historical_digest_replaced():
    # The v0.1 registry and manifest must still validate.
    from csd_foundry.scenarios.v0_1.manifest import SCENARIO_METADATA

    metadata_ids = {entry.scenario_id for entry in SCENARIO_METADATA}
    assert len(SCENARIO_METADATA) == 21
    for scenario_id in SCENARIOS:
        assert scenario_id in metadata_ids


# ---------------------------------------------------------------------------
# Catalog digest: content-bound, sensitive, mapping-order invariant (repair #1)
# ---------------------------------------------------------------------------


def test_base_and_overlay_catalog_digests_differ(overlay):
    base_digest = development_contrast_overlay_catalog_digest(SCENARIOS)
    overlay_digest = development_contrast_overlay_catalog_digest(overlay)
    assert base_digest != overlay_digest


def test_catalog_digest_invariant_under_mapping_order_permutation(overlay):
    # Building the catalog dict in a different insertion order must not change
    # the digest (the digest sorts by scenario_id internally).
    import random

    keys = list(overlay.keys())
    shuffled = dict(overlay)
    random.shuffle(keys)
    reordered = {k: overlay[k] for k in keys}
    assert development_contrast_overlay_catalog_digest(
        shuffled
    ) == development_contrast_overlay_catalog_digest(reordered)


def test_catalog_digest_sensitive_to_case_count_change(overlay):
    from dataclasses import replace

    from csd_foundry.scenarios.spec import ScenarioMode

    # Remove the appended transition case from M-12 — the digest must change.
    m12 = overlay["M-12"]
    trimmed = replace(m12, cases=m12.cases[:1], mode=ScenarioMode.OBSERVATION)
    perturbed = dict(overlay)
    perturbed["M-12"] = trimmed
    assert development_contrast_overlay_catalog_digest(
        overlay
    ) != development_contrast_overlay_catalog_digest(perturbed)


def test_catalog_digest_sensitive_to_mode_change(overlay):
    from dataclasses import replace

    from csd_foundry.scenarios.spec import ScenarioMode

    # Change M-14 mode without changing cases — the digest must change because
    # family identity includes mode.
    m14 = overlay["M-14"]
    mode_changed = replace(m14, mode=ScenarioMode.OBSERVATION)
    perturbed = dict(overlay)
    perturbed["M-14"] = mode_changed
    assert development_contrast_overlay_catalog_digest(
        overlay
    ) != development_contrast_overlay_catalog_digest(perturbed)


def test_catalog_digest_sensitive_to_event_change(overlay):
    # Change the M-12 AdvanceClock target_time — the family digest changes
    # because the executable structure changes, so the catalog digest changes.
    from dataclasses import replace

    from csd_foundry.kernel.events import AdvanceClock

    m12 = overlay["M-12"]
    cases = list(m12.cases)
    transition_idx = next(i for i, c in enumerate(cases) if isinstance(c, TransitionCase))
    original = cases[transition_idx]
    cases[transition_idx] = replace(original, event=AdvanceClock(target_time=999))
    perturbed_m12 = replace(m12, cases=tuple(cases))
    perturbed = dict(overlay)
    perturbed["M-12"] = perturbed_m12
    assert development_contrast_overlay_catalog_digest(
        overlay
    ) != development_contrast_overlay_catalog_digest(perturbed)
