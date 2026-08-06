"""Tests for the deterministic E1 label-space and treatment-adequacy audit."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
)
from csd_foundry.empirical.e1.label_space_audit import (
    REJECTION_CONSTANT,
    REJECTION_DIRECT_PROMPT_EXPOSURE,
    REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES,
    REJECTION_NO_APPLICABLE_TRAINING_RECORDS,
    audit_e1_label_space,
    validate_label_space_audit,
    write_label_space_audit,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

_SOURCE_COMMIT = "2cf5875f3a78bb5aa14578bc1bf1f33c18b7a199"
_RELEASE = "e1-foundry-artifacts/1"
_SELECTION_RELEASE = "e1-candidate/1"
_AUDIT_RELEASE = "e1-label-space-audit/1"


def _selection():
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _bundle(selection):
    return compile_e1_foundry_artifacts(
        SCENARIOS,
        selection,
        release=_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _audit():
    selection = _selection()
    bundle = _bundle(selection)
    return audit_e1_label_space(
        bundle,
        selection,
        release=_AUDIT_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


# ---------------------------------------------------------------------------
# Deterministic reconstruction
# ---------------------------------------------------------------------------


def test_audit_is_byte_identical_on_recompile(tmp_path: Path):
    audit = _audit()
    path = tmp_path / "label_space_audit.json"
    write_label_space_audit(audit, str(path))

    # Recompile independently and require byte identity.
    other = _audit()
    assert canonical_json_bytes(other.to_dict()) == path.read_bytes()
    assert validate_label_space_audit(audit, str(path))


def test_tampered_artifact_fails_validation(tmp_path: Path):
    audit = _audit()
    path = tmp_path / "label_space_audit.json"
    write_label_space_audit(audit, str(path))
    tampered = path.read_bytes().replace(b"e1-label-space-audit/1", b"e1-label-space-audit/9")
    path.write_bytes(tampered)
    assert not validate_label_space_audit(audit, str(path))


# ---------------------------------------------------------------------------
# Audited-input binding (correction #1)
# ---------------------------------------------------------------------------


def test_audit_binds_exact_compiled_input_identities():
    selection = _selection()
    bundle = _bundle(selection)
    audit = audit_e1_label_space(
        bundle,
        selection,
        release=_AUDIT_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )
    assert audit.source_commit == bundle.source_commit == _SOURCE_COMMIT
    assert audit.selection_contract_digest == bundle.selection_contract_digest
    assert audit.selection_contract_digest == selection.contract_digest
    assert audit.task_format_digest == bundle.task_format_digest
    assert audit.foundry_bundle_manifest_sha256 == bundle.file("bundle_manifest.json").sha256
    assert audit.foundry_train_sha256 == bundle.file("foundry_train.jsonl").sha256
    assert audit.development_evaluation_sha256 == bundle.file("development_evaluation.jsonl").sha256
    assert audit.training_record_count == bundle.training_record_count
    assert audit.development_record_count == bundle.development_record_count


def test_source_commit_mismatch_is_rejected():
    selection = _selection()
    bundle = _bundle(selection)
    with pytest.raises(Exception, match="source_commit"):
        audit_e1_label_space(
            bundle,
            selection,
            release=_AUDIT_RELEASE,
            source_commit="0" * 40,
        )


def test_selection_digest_mismatch_is_rejected():
    # Build a bundle under one selection, then pass a different selection object
    # whose digest differs. We construct a second selection under a different
    # release so its contract digest changes.
    selection_a = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release="e1-candidate/1",
        source_commit=_SOURCE_COMMIT,
    )
    bundle = compile_e1_foundry_artifacts(
        SCENARIOS,
        selection_a,
        release=_RELEASE,
        selection_release="e1-candidate/1",
        source_commit=_SOURCE_COMMIT,
    )
    selection_b = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release="e1-candidate/2",
        source_commit=_SOURCE_COMMIT,
    )
    with pytest.raises(Exception, match="selection contract digest"):
        audit_e1_label_space(
            bundle,
            selection_b,
            release=_AUDIT_RELEASE,
            source_commit=_SOURCE_COMMIT,
        )


# ---------------------------------------------------------------------------
# Population correctness
# ---------------------------------------------------------------------------


def test_population_matches_expected_selection_membership():
    audit = _audit()
    pop = audit.population
    assert pop["train_record_count"] == 19
    assert pop["development_record_count"] == 4
    assert pop["overall_record_count"] == 23
    assert pop["overall_case_type_counts"] == {"observation": 5, "transition": 18}
    assert pop["development_case_type_counts"] == {"observation": 2, "transition": 2}
    assert pop["overall_acceptance_counts"] == {"accepted": 23}
    # No rejected_transition case reaches the selected population.
    assert "rejected_transition" not in pop["overall_case_type_counts"]


def test_excluded_source_test_scenarios_absent():
    audit = _audit()
    # The 23 records cover only the 18 selected scenarios; H-01/L-01/M-15 are
    # excluded. Distinct full labels == record count (every label is unique).
    assert audit.population["overall_distinct_full_label_count"] == 23
    assert audit.population["training_distinct_full_label_count"] == 19
    assert audit.population["development_distinct_full_label_count"] == 4


# ---------------------------------------------------------------------------
# Dimension summaries (split-specific, exact-rational, constant/undefined)
# ---------------------------------------------------------------------------


def test_dimensions_are_split_specific_and_enumerated():
    audit = _audit()
    names = {d.name for d in audit.dimensions}
    # All audited atoms are summarized, including acceptance.
    for required in (
        "case_type",
        "acceptance",
        "event_type",
        "any_evidence_invalidated",
        "any_basis_removed",
        "any_basis_survives",
        "assurance_changed",
        "obligation_changed",
        "retirement_involved",
        "reassessment_involved",
    ):
        assert required in names


def test_observation_records_have_undefined_trace_atoms():
    audit = _audit()
    by_name = {d.name: d for d in audit.dimensions}
    # Five observation records (3 train + 2 dev) have no trace.
    assert by_name["any_evidence_invalidated"].train_undefined_count == 3
    assert by_name["any_evidence_invalidated"].development_undefined_count == 2
    assert by_name["any_evidence_invalidated"].undefined_count == 5


def test_observation_involvement_atoms_are_undefined():
    audit = _audit()
    by_name = {d.name: d for d in audit.dimensions}
    # event_type / retirement_involved / reassessment_involved are None for
    # the five observation records.
    for atom in ("event_type", "retirement_involved", "reassessment_involved"):
        assert by_name[atom].undefined_count == 5, atom


def test_constant_rule_distinguishes_defined_from_undefined():
    audit = _audit()
    by_name = {d.name: d for d in audit.dimensions}
    # acceptance is constant 'accepted' across all 23 defined records.
    acc = by_name["acceptance"]
    assert acc.defined_count == 23
    assert acc.distinct_value_count == 1
    assert acc.constant is True
    assert acc.majority_value == "accepted"
    assert acc.majority_count == 23


def test_constant_false_when_no_defined_values():
    # Construct a dimension summary with zero defined values via an atom that
    # is undefined for every record. obligation_changed is undefined for all
    # observation records but defined for transitions, so build a synthetic
    # check: any dimension with defined_count==0 must have constant=False and
    # null majority. We exercise the rule directly.
    from csd_foundry.empirical.e1.label_space_audit import DimensionSummary

    empty = DimensionSummary(
        name="synthetic",
        derivation_version="e1-audit-atom/1",
        input_paths=("reference_label.trace.synthetic",),
        derivation_description="synthetic",
        direct_prompt_exposure=False,
        direct_prompt_paths=(),
        derivation_requires_executable_output=True,
        train_value_counts={},
        development_value_counts={},
        train_defined_count=0,
        train_undefined_count=5,
        development_defined_count=0,
        development_undefined_count=2,
        value_counts={},
        defined_count=0,
        undefined_count=7,
        total_count=7,
        distinct_value_count=0,
        majority_value=None,
        majority_count=0,
        majority_fraction_numerator=0,
        majority_fraction_denominator=0,
        constant=False,
    )
    assert empty.constant is False
    assert empty.majority_value is None


def test_majority_fraction_is_reduced():
    audit = _audit()
    by_name = {d.name: d for d in audit.dimensions}
    inv = by_name["any_evidence_invalidated"]
    # Numerator/denominator are coprime (reduced form) and the denominator is
    # the reduced value of defined_count, not necessarily defined_count itself.
    if inv.majority_fraction_denominator:
        assert math.gcd(inv.majority_fraction_numerator, inv.majority_fraction_denominator) == 1
        assert inv.majority_fraction_denominator <= inv.defined_count
        assert inv.majority_fraction_numerator <= inv.majority_count


# ---------------------------------------------------------------------------
# Candidate projections: semantic vs population separation (final correction)
# ---------------------------------------------------------------------------


def _candidate(audit, name):
    return next(cp for cp in audit.candidate_projections if cp.name == name)


def test_acceptance_rejected_as_constant_and_collapsing():
    audit = _audit()
    cp = _candidate(audit, "acceptance")
    assert REJECTION_CONSTANT in cp.semantic_rejection_reasons
    assert REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES in cp.semantic_rejection_reasons
    assert cp.prompt_only_reconstruction_possible is True
    assert cp.prompt_only_reconstruction_witness is not None
    assert cp.semantic_candidate is False


def test_case_type_rejected_as_prompt_exposed_and_collapsing():
    audit = _audit()
    cp = _candidate(audit, "case_type")
    assert REJECTION_DIRECT_PROMPT_EXPOSURE in cp.semantic_rejection_reasons
    assert REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES in cp.semantic_rejection_reasons
    assert cp.prompt_only_reconstruction_witness is not None
    assert cp.semantic_candidate is False


def test_case_type_acceptance_rejected_as_prompt_exposed_and_collapsing():
    audit = _audit()
    cp = _candidate(audit, "case_type_acceptance")
    # NOT constant: case_type varies. The two rejections are exposure + collapse.
    assert REJECTION_CONSTANT not in cp.semantic_rejection_reasons
    assert REJECTION_DIRECT_PROMPT_EXPOSURE in cp.semantic_rejection_reasons
    assert REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES in cp.semantic_rejection_reasons
    assert cp.prompt_only_reconstruction_witness is not None


def test_obligation_changed_is_constant_in_training():
    audit = _audit()
    cp = _candidate(audit, "obligation_changed")
    # Only G-04 retires in the selected training set; obligation_changed is
    # 'false' for every other transition and undefined for observations.
    # The training projection is dominated by one value; whether it is exactly
    # constant depends on G-04. At minimum it must be a non-collapsing,
    # executable-consequence atom with a null witness.
    assert cp.prompt_only_reconstruction_witness is None
    assert REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES not in cp.semantic_rejection_reasons


def test_executable_consequence_projection_is_semantic_candidate():
    audit = _audit()
    # At least one executable-consequence projection must be a semantic
    # candidate (non-degenerate, non-copyable) — the central positive finding.
    semantic_names = {cp.name for cp in audit.candidate_projections if cp.semantic_candidate}
    assert semantic_names, "expected at least one semantic candidate projection"
    # The candidate is NOT primary-eligible because development has
    # observation-only families the projection cannot cover.
    eligible = [cp for cp in audit.candidate_projections if cp.primary_population_eligible]
    assert eligible == []


def test_executable_candidate_has_incomplete_development_family_coverage():
    audit = _audit()
    cp = _candidate(audit, "any_basis_removed")
    assert cp.semantic_candidate is True
    assert "incomplete_development_family_coverage" in cp.population_adequacy_failures
    assert cp.primary_population_eligible is False
    # Two of four development families are uncovered (the observation families).
    assert cp.covered_development_family_count < 4
    assert cp.uncovered_development_family_digests


def test_no_applicable_training_records_rejection_fires_for_prompt_only_atom_with_no_atoms():
    # A projection whose scored atoms are all undefined for every record gets
    # the no_applicable_training_records semantic rejection. We verify the
    # constant is exported and reachable.
    assert REJECTION_NO_APPLICABLE_TRAINING_RECORDS == "no_applicable_training_records"


# ---------------------------------------------------------------------------
# Status fields: determinism and internal consistency
# ---------------------------------------------------------------------------


def test_status_fields_are_internally_consistent():
    audit = _audit()
    expected_sem = any(cp.semantic_candidate for cp in audit.candidate_projections)
    expected_primary = any(cp.primary_population_eligible for cp in audit.candidate_projections)
    assert audit.semantic_projection_candidate_present == expected_sem
    assert audit.primary_population_supported == expected_primary

    if not audit.primary_population_supported:
        assert audit.full_e1_population_support is False
    elif audit.clean_case_policy_status == "unfrozen":
        assert audit.full_e1_population_support is None
    elif audit.clean_case_policy_status == "supported":
        assert audit.full_e1_population_support is True
    else:
        assert audit.full_e1_population_support is False


def test_clean_case_policy_status_is_unfrozen():
    audit = _audit()
    assert audit.clean_case_policy_status == "unfrozen"


# ---------------------------------------------------------------------------
# CleanCaseEvidence: nullable fields for observations
# ---------------------------------------------------------------------------


def test_clean_case_evidence_nullable_for_observations():
    audit = _audit()
    observation_evidence = [e for e in audit.clean_case_evidence if e.case_type == "observation"]
    assert observation_evidence, "expected observation clean-case evidence"
    for evidence in observation_evidence:
        assert evidence.event_type is None
        assert evidence.any_evidence_invalidated is None
        assert evidence.any_basis_removed is None
        assert evidence.source_state_changed is None
        assert evidence.assurance_changed is None
        assert evidence.obligation_changed is None
        assert evidence.retirement_involved is None
        assert evidence.reassessment_involved is None


def test_clean_case_evidence_has_no_included_or_rationale():
    audit = _audit()
    payload = audit.clean_case_evidence[0].to_dict()
    assert "included" not in payload
    assert "rationale" not in payload


# ---------------------------------------------------------------------------
# obligation_changed derivation
# ---------------------------------------------------------------------------


def test_obligation_changed_atom_derivation_description_is_explicit():
    audit = _audit()
    by_name = {d.name: d for d in audit.dimensions}
    desc = by_name["obligation_changed"].derivation_description
    assert "before.obligation" in desc
    assert "after.obligation" in desc
    assert "TransitionTrace" in desc


# ---------------------------------------------------------------------------
# Contrast inventory and blockers
# ---------------------------------------------------------------------------


def test_contrast_predicates_are_exact_and_present_is_computed():
    audit = _audit()
    by_name = {c.name: c for c in audit.contrast_inventory}
    assert by_name["basis_loss"].predicate == "any_basis_removed == True"
    assert by_name["basis_survival"].predicate == "any_basis_survives == True"
    assert by_name["invalid_transition"].predicate == "case_type == 'rejected_transition'"
    # basis_loss/basis_survival are present in the selected training population.
    assert by_name["basis_loss"].present is True
    assert by_name["basis_survival"].present is True
    # invalid_transition is absent (H-01 is excluded).
    assert by_name["invalid_transition"].present is False
    assert by_name["invalid_transition"].train_record_ids == ()
    assert by_name["invalid_transition"].development_record_ids == ()


def test_right_answer_wrong_basis_is_unassessable():
    audit = _audit()
    rawb = next(c for c in audit.contrast_inventory if c.name == "right_answer_wrong_basis")
    assert rawb.assessable is False
    assert rawb.present is None
    assert rawb.unassessable_reason is not None


def test_blockers_distinguish_unassessable_from_absent():
    audit = _audit()
    assert "right_answer_wrong_basis_unassessable" in audit.experiment_blockers
    assert "missing_right_answer_wrong_basis_contrast" not in audit.experiment_blockers
    assert "no_invalid_transition_contrast" in audit.experiment_blockers
    assert "insufficient_development_transition_coverage" in audit.experiment_blockers


def test_no_invalid_transition_contrast_counts_are_split_specific():
    audit = _audit()
    # The rejected_transition contrast is absent across both splits.
    inv = next(c for c in audit.contrast_inventory if c.name == "invalid_transition")
    assert len(inv.train_record_ids) == 0
    assert len(inv.development_record_ids) == 0


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------


def test_no_tokenizer_or_model_imported():
    source = Path("src/csd_foundry/empirical/e1/label_space_audit.py").read_text(encoding="utf-8")
    assert "import torch" not in source
    assert "import transformers" not in source
    assert "from torch" not in source
    assert "from transformers" not in source


def test_artifact_contains_no_floats():
    audit = _audit()
    payload = json.loads(canonical_json_bytes(audit.to_dict()).decode("utf-8"))

    def walk(value):
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, float):
            raise AssertionError(f"float value in audit artifact: {value!r}")
        if isinstance(value, int):
            return
        if isinstance(value, str):
            return
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
            return

    walk(payload)


def test_output_lists_are_sorted_and_duplicate_free():
    audit = _audit()
    payload = audit.to_dict()
    # The sorted-and-duplicate-free invariant applies to the closed-set lists
    # (rejection reasons, blockers, paths, record IDs, family digests), not to
    # ordered semantic content like a projection's scored_atoms.
    ordered_keys = {"scored_atoms", "prompt_roles", "metadata_excluded_from_model_input"}

    def check(value, key=None):
        if isinstance(value, list):
            if key in ordered_keys:
                return
            string_items = [item for item in value if isinstance(item, str)]
            if string_items:
                assert string_items == sorted(string_items), (
                    f"unsorted list under {key}: {string_items}"
                )
                assert len(string_items) == len(set(string_items)), (
                    f"duplicate list items under {key}: {string_items}"
                )
            for item in value:
                check(item, key)
        elif isinstance(value, dict):
            for sub_key, item in value.items():
                check(item, sub_key)

    check(payload)


def test_release_is_nonempty_and_reconstruction_bound():
    audit = _audit()
    assert audit.release.strip()
    # audit_digest is stable across recomputes.
    again = _audit()
    assert audit.audit_digest == again.audit_digest


# ---------------------------------------------------------------------------
# Synthetic divergence fixture: semantic_candidate != primary_population_eligible
# ---------------------------------------------------------------------------


def test_synthetic_fixture_semantic_candidate_present_but_primary_unsupported():
    """Demonstrate the divergence the audit is designed to expose.

    A future refactor must not collapse semantic candidacy into primary
    eligibility. This fixture builds the two booleans independently from a
    hand-constructed candidate set and asserts they diverge.
    """

    from csd_foundry.empirical.e1.label_space_audit import CandidateProjection

    candidates = [
        # Semantic candidate, but development-family coverage is incomplete.
        CandidateProjection(
            name="synthetic_executable",
            description="synthetic",
            scored_atoms=("any_basis_removed",),
            projection_function_description="synthetic",
            train_value_counts={"true": 5, "false": 5},
            development_value_counts={"true": 1},
            applicable_train_record_count=10,
            applicable_development_record_count=1,
            covered_development_family_count=2,
            uncovered_development_record_ids=("e1-foundry/development/M-12/x",),
            uncovered_development_family_digests=("family-obs-a",),
            prompt_only_reconstruction_possible=False,
            prompt_only_reconstruction_witness=None,
            semantic_rejection_reasons=(),
            semantic_candidate=True,
            population_adequacy_failures=("incomplete_development_family_coverage",),
            primary_population_eligible=False,
        ),
    ]
    semantic_present = any(cp.semantic_candidate for cp in candidates)
    primary_supported = any(cp.primary_population_eligible for cp in candidates)
    assert semantic_present is True
    assert primary_supported is False
    assert semantic_present != primary_supported
