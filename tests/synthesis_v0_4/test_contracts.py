from __future__ import annotations

from pathlib import Path

import pytest

from csd_foundry.kernel.invariant_registry import EXECUTABLE_INVARIANT_IDS
from csd_foundry.kernel.invariants import Violation
from csd_foundry.synthesis.v0_4 import validation as synthesis_validation
from csd_foundry.synthesis.v0_4.contracts import (
    CompletenessEvidenceKind,
    CompletenessWitnessMap,
    ContractValidationError,
    CoverageTarget,
    EscapeClassification,
    EscapeSeverity,
    GenerationAttempt,
    MutationRiskBudget,
    MutationRiskPolicy,
    PerformancePolicy,
    RejectionCause,
    SearchBudget,
    SemanticEffect,
    TargetDisposition,
)
from csd_foundry.synthesis.v0_4.serialization import (
    CanonicalSerializationError,
    canonical_json_bytes,
    load_json_text,
)
from csd_foundry.synthesis.v0_4.specs import SCHEMA_DOCUMENT_NAMES, SPEC_DOCUMENTS
from csd_foundry.synthesis.v0_4.validation import load_targets, validate_release

ROOT = Path(__file__).resolve().parents[2]
SPEC_ROOT = ROOT / "specs" / "v0.4"


def _completeness(target_id: str) -> CompletenessWitnessMap:
    return CompletenessWitnessMap(
        target_id=target_id,
        evidence_kind=CompletenessEvidenceKind.FULLY_BOUNDED,
        bounded_projection_id="micro-test",
        omitted_dimensions=(),
        justification="Complete within the test domain.",
        alternative_witness_id=None,
    )


def _budget() -> SearchBudget:
    return SearchBudget(1, 1, 1, 1)


def test_v04_contract_release_is_valid_but_release_scale_is_blocked() -> None:
    report = validate_release("v0.4")

    assert report.success
    assert report.target_count == 5
    assert report.required_targets == 4
    assert report.exploratory_targets == 1
    assert report.machine_proven_infeasible_targets == 0
    assert report.unresolved_targets == 0
    assert report.release_scale_blocked
    assert report.schema_document_count == 8
    assert report.policy_count == 6
    assert len(report.canonical_digest) == 64


def test_every_rejection_cause_has_exactly_one_owner() -> None:
    owners = {cause: cause.owner for cause in RejectionCause}

    assert set(owners) == set(RejectionCause)
    assert owners[RejectionCause.SAMPLER_PRECONDITION_FAILURE].value == "event_sampler"
    assert owners[RejectionCause.MUTATION_ESCAPE].value == "mutation_engine"


def test_rejected_attempt_requires_one_typed_cause() -> None:
    with pytest.raises(ContractValidationError):
        GenerationAttempt(
            attempt_id="attempt-1",
            release="v0.4",
            seed_path="target/a/sample/1/attempt/0",
            target_id="a",
            plan_id=None,
            accepted=False,
            rejection_cause=None,
            diagnostic_codes=(),
            trajectory_digest=None,
        )

    attempt = GenerationAttempt(
        attempt_id="attempt-2",
        release="v0.4",
        seed_path="target/a/sample/1/attempt/1",
        target_id="a",
        plan_id="plan-a",
        accepted=False,
        rejection_cause=RejectionCause.SAMPLER_PRECONDITION_FAILURE,
        diagnostic_codes=("EVENT_NOT_ELIGIBLE",),
        trajectory_digest=None,
    )
    assert attempt.rejection_cause is RejectionCause.SAMPLER_PRECONDITION_FAILURE


def test_machine_proven_infeasible_cannot_be_asserted_without_a_witness() -> None:
    with pytest.raises(ContractValidationError):
        CoverageTarget(
            target_id="impossible",
            disposition=TargetDisposition.MACHINE_PROVEN_INFEASIBLE,
            topology_pattern="contradictory",
            event_pattern=("AdvanceClock",),
            temporal_pattern="before-and-after",
            request_pattern="none",
            profile_pattern="stable",
            required_invariants=frozenset({"T-INV-01"}),
            required_consequences=frozenset({"contradiction"}),
            minimum_count=0,
            rarity_weight=1,
            holdout_tags=frozenset(),
            search_budget=_budget(),
            completeness=_completeness("impossible"),
            infeasibility_witness=None,
        )


def test_required_target_needs_positive_quota_and_budget() -> None:
    with pytest.raises(ContractValidationError):
        CoverageTarget(
            target_id="required",
            disposition=TargetDisposition.REQUIRED,
            topology_pattern="single",
            event_pattern=("AdvanceClock",),
            temporal_pattern="boundary",
            request_pattern="none",
            profile_pattern="stable",
            required_invariants=frozenset({"T-INV-01"}),
            required_consequences=frozenset({"time-advances"}),
            minimum_count=0,
            rarity_weight=1,
            holdout_tags=frozenset(),
            search_budget=SearchBudget(0, 0, 0, 0),
            completeness=_completeness("required"),
        )


def test_escape_severity_cannot_understate_semantic_effects() -> None:
    with pytest.raises(ContractValidationError):
        EscapeClassification(
            escape_id="escape-1",
            mutation_id="mut-verdict",
            invariant_family="INV-VERDICT",
            severity=EscapeSeverity.MODERATE,
            semantic_effects=frozenset({SemanticEffect.FABRICATE_VERDICT}),
            reproducible=True,
            genuinely_invalid=True,
            resolution=None,
            reviewer_ids=(),
        )

    critical = EscapeClassification(
        escape_id="escape-2",
        mutation_id="mut-verdict",
        invariant_family="INV-VERDICT",
        severity=EscapeSeverity.CRITICAL,
        semantic_effects=frozenset({SemanticEffect.FABRICATE_VERDICT}),
        reproducible=True,
        genuinely_invalid=True,
        resolution="verifier corrected",
        reviewer_ids=("reviewer-1",),
    )
    assert critical.severity is EscapeSeverity.CRITICAL


def test_canonical_json_is_order_stable_and_rejects_floats() -> None:
    left = {"b": [3, 2, 1], "a": {"z": 2, "y": 1}}
    right = {"a": {"y": 1, "z": 2}, "b": [3, 2, 1]}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(frozenset({"b", "a"})) == b'["a","b"]\n'
    with pytest.raises(CanonicalSerializationError):
        canonical_json_bytes({"weight": 0.5})
    with pytest.raises(CanonicalSerializationError):
        load_json_text('{"weight": 0.5}')


def test_repository_specs_equal_packaged_specs() -> None:
    for name, packaged in SPEC_DOCUMENTS.items():
        repository_value = load_json_text((SPEC_ROOT / name).read_text(encoding="utf-8"))
        assert repository_value == packaged


def test_schema_documents_are_declared_draft_2020_12() -> None:
    for name in SCHEMA_DOCUMENT_NAMES:
        schema = load_json_text((SPEC_ROOT / name).read_text(encoding="utf-8"))
        assert isinstance(schema, dict)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"


def test_all_shipped_targets_have_completeness_evidence_and_budgets() -> None:
    for target in load_targets():
        assert target.search_budget.is_positive
        assert target.completeness.target_id == target.target_id
        if target.disposition is TargetDisposition.REQUIRED:
            assert target.minimum_count > 0


def test_frozen_performance_policy_requires_calibration_evidence() -> None:
    with pytest.raises(ContractValidationError):
        PerformancePolicy(
            release="v0.4",
            policy_status="frozen",
            reference_environment=(),
            benchmark_corpus_digest=None,
            thresholds=(),
        )


def test_frozen_mutation_policy_requires_samples_and_confidence_bounds() -> None:
    budgets = tuple(
        MutationRiskBudget(
            severity=severity,
            maximum_unresolved_deterministic=0,
            maximum_unresolved_stochastic=0,
            upper_confidence_bound_decimal=None,
            minimum_invalid_mutants=0,
        )
        for severity in EscapeSeverity
    )
    with pytest.raises(ContractValidationError):
        MutationRiskPolicy(
            release="v0.4",
            confidence_level_decimal="0.95",
            policy_status="frozen",
            budgets=budgets,
        )


@pytest.mark.parametrize("value", ["1.5", "1.01", "2", "-0.1"])
def test_probability_contracts_reject_values_outside_zero_to_one(value: str) -> None:
    with pytest.raises(ContractValidationError):
        MutationRiskBudget(
            severity=EscapeSeverity.HIGH,
            maximum_unresolved_deterministic=0,
            maximum_unresolved_stochastic=0,
            upper_confidence_bound_decimal=value,
            minimum_invalid_mutants=1,
        )


def test_coverage_schema_requires_machine_infeasibility_witness() -> None:
    schema = load_json_text(
        (SPEC_ROOT / "coverage_targets.schema.json").read_text(encoding="utf-8")
    )
    assert isinstance(schema, dict)
    witness = schema["$defs"]
    assert isinstance(witness, dict)
    witness_schema = witness["infeasibilityWitness"]
    assert isinstance(witness_schema, dict)
    assert set(witness_schema["required"]) == {
        "target_id",
        "grammar_version",
        "constraint_ids",
        "proof_method",
        "unsat_core",
        "verifier_version",
        "witness_digest",
    }
    target_schema = schema["properties"]
    assert isinstance(target_schema, dict)
    target_items = target_schema["targets"]
    assert isinstance(target_items, dict)
    assert "allOf" in target_items["items"]


def test_required_invariants_must_be_executable() -> None:
    with pytest.raises(ContractValidationError):
        CoverageTarget(
            target_id="unknown-invariant",
            disposition=TargetDisposition.REQUIRED,
            topology_pattern="single",
            event_pattern=("AdvanceClock",),
            temporal_pattern="boundary",
            request_pattern="none",
            profile_pattern="stable",
            required_invariants=frozenset({"T-INV-99"}),
            required_consequences=frozenset({"time-advances"}),
            minimum_count=1,
            rarity_weight=1,
            holdout_tags=frozenset(),
            search_budget=_budget(),
            completeness=_completeness("unknown-invariant"),
        )
    with pytest.raises(ValueError):
        Violation("T-INV-99", "not executable")
    assert all(target.required_invariants <= EXECUTABLE_INVARIANT_IDS for target in load_targets())


@pytest.mark.parametrize(
    ("kind", "bounded_id", "alternative_id"),
    [
        (CompletenessEvidenceKind.FULLY_BOUNDED, "", None),
        (CompletenessEvidenceKind.PROJECTED_BOUNDED, "", "alternative"),
        (CompletenessEvidenceKind.ALTERNATIVE_ASSURANCE, None, ""),
    ],
)
def test_completeness_witness_identifiers_must_be_nonempty(
    kind: CompletenessEvidenceKind,
    bounded_id: str | None,
    alternative_id: str | None,
) -> None:
    omitted = () if kind is CompletenessEvidenceKind.FULLY_BOUNDED else ("scale",)
    with pytest.raises(ContractValidationError):
        CompletenessWitnessMap(
            target_id="target",
            evidence_kind=kind,
            bounded_projection_id=bounded_id,
            omitted_dimensions=omitted,
            justification="test witness",
            alternative_witness_id=alternative_id,
        )


def test_packaged_loader_rejects_schema_version_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mismatched = dict(synthesis_validation.COVERAGE_TARGETS_SPEC)
    mismatched["schema_version"] = "0.4.1"
    monkeypatch.setattr(
        synthesis_validation,
        "COVERAGE_TARGETS_SPEC",
        mismatched,
    )
    with pytest.raises(ContractValidationError):
        synthesis_validation.load_targets()
