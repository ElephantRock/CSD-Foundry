"""Validation and release evidence for the v0.4 synthesis contract layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from csd_foundry.synthesis.v0_4.contracts import (
    CompletenessEvidenceKind,
    CompletenessWitnessMap,
    ContractValidationError,
    CoverageTarget,
    DeterministicArithmeticPolicy,
    EscapeSeverity,
    HoldoutRule,
    InfeasibilityProofMethod,
    InfeasibilityWitness,
    MutationRiskBudget,
    MutationRiskPolicy,
    RejectionCause,
    ReleasePolicy,
    SearchBudget,
    SemanticEffect,
    TargetDisposition,
    minimum_severity,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256
from csd_foundry.synthesis.v0_4.specs import (
    COVERAGE_TARGETS_SPEC,
    DETERMINISTIC_ARITHMETIC_POLICY_SPEC,
    HOLDOUTS_SPEC,
    MUTATION_RISK_POLICY_SPEC,
    RELEASE_POLICY_SPEC,
    SCHEMA_DOCUMENT_NAMES,
    SPEC_DOCUMENTS,
)


@dataclass(frozen=True, slots=True)
class SynthesisContractReport:
    release: str
    target_count: int
    required_targets: int
    exploratory_targets: int
    machine_proven_infeasible_targets: int
    unresolved_targets: int
    holdout_rule_count: int
    policy_count: int
    schema_document_count: int
    rejection_cause_count: int
    rejection_owner_count: int
    semantic_effect_count: int
    canonical_digest: str
    release_scale_blocked: bool
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "release": self.release,
            "status": "valid" if self.success else "invalid",
            "target_count": self.target_count,
            "required_targets": self.required_targets,
            "exploratory_targets": self.exploratory_targets,
            "machine_proven_infeasible_targets": self.machine_proven_infeasible_targets,
            "unresolved_targets": self.unresolved_targets,
            "holdout_rule_count": self.holdout_rule_count,
            "policy_count": self.policy_count,
            "schema_document_count": self.schema_document_count,
            "rejection_cause_count": self.rejection_cause_count,
            "rejection_owner_count": self.rejection_owner_count,
            "semantic_effect_count": self.semantic_effect_count,
            "canonical_digest": self.canonical_digest,
            "release_scale_blocked": self.release_scale_blocked,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report validates v0.4 synthesis contracts and deterministic policies. "
                "It does not establish planner completeness, construction validity, structural "
                "canonicalization, mutation residual risk, performance, or release-scale output."
            ),
        }


def _mapping(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ContractValidationError(f"{field_name} must be an object with string keys")
    return cast(dict[str, object], value)


def _sequence(value: object, field_name: str) -> list[object]:
    if not isinstance(value, list):
        raise ContractValidationError(f"{field_name} must be an array")
    return cast(list[object], value)


def _string(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ContractValidationError(f"{key} must be a string")
    return value


def _optional_string(data: dict[str, object], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ContractValidationError(f"{key} must be a string or null")
    return value


def _integer(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContractValidationError(f"{key} must be an integer")
    return value


def _boolean(data: dict[str, object], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ContractValidationError(f"{key} must be a boolean")
    return value


def _strings(data: dict[str, object], key: str) -> tuple[str, ...]:
    values = _sequence(data.get(key), key)
    if not all(isinstance(item, str) for item in values):
        raise ContractValidationError(f"{key} must contain only strings")
    return tuple(cast(list[str], values))


def _search_budget(data: dict[str, object]) -> SearchBudget:
    return SearchBudget(
        maximum_plan_attempts=_integer(data, "maximum_plan_attempts"),
        maximum_construction_attempts_per_plan=_integer(
            data, "maximum_construction_attempts_per_plan"
        ),
        maximum_oracle_attempts=_integer(data, "maximum_oracle_attempts"),
        maximum_elapsed_milliseconds=_integer(data, "maximum_elapsed_milliseconds"),
    )


def _infeasibility_witness(value: object) -> InfeasibilityWitness | None:
    if value is None:
        return None
    data = _mapping(value, "infeasibility_witness")
    return InfeasibilityWitness(
        target_id=_string(data, "target_id"),
        grammar_version=_string(data, "grammar_version"),
        constraint_ids=_strings(data, "constraint_ids"),
        proof_method=InfeasibilityProofMethod(_string(data, "proof_method")),
        unsat_core=_strings(data, "unsat_core"),
        verifier_version=_string(data, "verifier_version"),
        witness_digest=_string(data, "witness_digest"),
    )


def _completeness(target_id: str, value: object) -> CompletenessWitnessMap:
    data = _mapping(value, "completeness")
    return CompletenessWitnessMap(
        target_id=target_id,
        evidence_kind=CompletenessEvidenceKind(_string(data, "evidence_kind")),
        bounded_projection_id=_optional_string(data, "bounded_projection_id"),
        omitted_dimensions=_strings(data, "omitted_dimensions"),
        justification=_string(data, "justification"),
        alternative_witness_id=_optional_string(data, "alternative_witness_id"),
    )


def load_targets() -> tuple[CoverageTarget, ...]:
    document = _mapping(COVERAGE_TARGETS_SPEC, "coverage target document")
    if _string(document, "release") != "v0.4":
        raise ContractValidationError("coverage target release must be v0.4")
    targets: list[CoverageTarget] = []
    for value in _sequence(document.get("targets"), "targets"):
        data = _mapping(value, "target")
        target_id = _string(data, "target_id")
        targets.append(
            CoverageTarget(
                target_id=target_id,
                disposition=TargetDisposition(_string(data, "disposition")),
                topology_pattern=_string(data, "topology_pattern"),
                event_pattern=_strings(data, "event_pattern"),
                temporal_pattern=_string(data, "temporal_pattern"),
                request_pattern=_string(data, "request_pattern"),
                profile_pattern=_string(data, "profile_pattern"),
                required_invariants=frozenset(_strings(data, "required_invariants")),
                required_consequences=frozenset(_strings(data, "required_consequences")),
                minimum_count=_integer(data, "minimum_count"),
                rarity_weight=_integer(data, "rarity_weight"),
                holdout_tags=frozenset(_strings(data, "holdout_tags")),
                search_budget=_search_budget(_mapping(data.get("search_budget"), "search_budget")),
                completeness=_completeness(target_id, data.get("completeness")),
                infeasibility_witness=_infeasibility_witness(data.get("infeasibility_witness")),
            )
        )
    return tuple(targets)


def load_holdouts() -> tuple[HoldoutRule, ...]:
    document = _mapping(HOLDOUTS_SPEC, "holdout document")
    rules: list[HoldoutRule] = []
    for value in _sequence(document.get("rules"), "rules"):
        data = _mapping(value, "holdout rule")
        rules.append(
            HoldoutRule(
                holdout_id=_string(data, "holdout_id"),
                split=_string(data, "split"),
                topology_patterns=_strings(data, "topology_patterns"),
                trace_patterns=_strings(data, "trace_patterns"),
                temporal_patterns=_strings(data, "temporal_patterns"),
                invariant_patterns=_strings(data, "invariant_patterns"),
                priority=_integer(data, "priority"),
            )
        )
    return tuple(rules)


def load_release_policy() -> ReleasePolicy:
    data = _mapping(RELEASE_POLICY_SPEC, "release policy")
    return ReleasePolicy(
        release=_string(data, "release"),
        target_trajectory_count=_integer(data, "target_trajectory_count"),
        pilot_trajectory_count=_integer(data, "pilot_trajectory_count"),
        maximum_trajectory_steps=_integer(data, "maximum_trajectory_steps"),
        root_seed=_string(data, "root_seed"),
        rng_algorithm=_string(data, "rng_algorithm"),
        rng_version=_string(data, "rng_version"),
        choice_path_schema_version=_string(data, "choice_path_schema_version"),
        split_hash_salt=_string(data, "split_hash_salt"),
        performance_policy_status=_string(data, "performance_policy_status"),
        stochastic_risk_policy_status=_string(data, "stochastic_risk_policy_status"),
    )


def load_mutation_risk_policy() -> MutationRiskPolicy:
    data = _mapping(MUTATION_RISK_POLICY_SPEC, "mutation risk policy")
    budgets: list[MutationRiskBudget] = []
    for value in _sequence(data.get("budgets"), "budgets"):
        budget = _mapping(value, "mutation risk budget")
        budgets.append(
            MutationRiskBudget(
                severity=EscapeSeverity(_string(budget, "severity")),
                maximum_unresolved_deterministic=_integer(
                    budget, "maximum_unresolved_deterministic"
                ),
                maximum_unresolved_stochastic=_integer(budget, "maximum_unresolved_stochastic"),
                upper_confidence_bound_decimal=_optional_string(
                    budget, "upper_confidence_bound_decimal"
                ),
                minimum_invalid_mutants=_integer(budget, "minimum_invalid_mutants"),
            )
        )
    return MutationRiskPolicy(
        release=_string(data, "release"),
        confidence_level_decimal=_string(data, "confidence_level_decimal"),
        policy_status=_string(data, "policy_status"),
        budgets=tuple(budgets),
    )


def load_deterministic_arithmetic_policy() -> DeterministicArithmeticPolicy:
    data = _mapping(DETERMINISTIC_ARITHMETIC_POLICY_SPEC, "deterministic arithmetic policy")
    return DeterministicArithmeticPolicy(
        semantic_floating_point_permitted=_boolean(data, "semantic_floating_point_permitted"),
        statistical_decimal_precision=_integer(data, "statistical_decimal_precision"),
        rounding_mode=_string(data, "rounding_mode"),
        canonical_encoding=_string(data, "canonical_encoding"),
        canonical_json_numbers=_string(data, "canonical_json_numbers"),
        ordering=_string(data, "ordering"),
    )


def _reverse_mappings(value: object) -> object:
    if isinstance(value, dict):
        return {key: _reverse_mappings(item) for key, item in reversed(tuple(value.items()))}
    if isinstance(value, list):
        return [_reverse_mappings(item) for item in value]
    return value


def validate_release(release: str = "v0.4") -> SynthesisContractReport:
    errors: list[str] = []
    targets: tuple[CoverageTarget, ...] = ()
    holdouts: tuple[HoldoutRule, ...] = ()
    release_policy: ReleasePolicy | None = None
    risk_policy: MutationRiskPolicy | None = None

    if release != "v0.4":
        errors.append(f"unsupported synthesis contract release: {release}")
    else:
        try:
            targets = load_targets()
            holdouts = load_holdouts()
            release_policy = load_release_policy()
            risk_policy = load_mutation_risk_policy()
            load_deterministic_arithmetic_policy()
        except (ContractValidationError, ValueError) as exc:
            errors.append(str(exc))

    target_ids = tuple(item.target_id for item in targets)
    if len(target_ids) != len(set(target_ids)):
        errors.append("coverage target identities are not unique")
    holdout_ids = tuple(item.holdout_id for item in holdouts)
    if len(holdout_ids) != len(set(holdout_ids)):
        errors.append("holdout identities are not unique")

    for cause in RejectionCause:
        try:
            _ = cause.owner
        except KeyError:
            errors.append(f"rejection cause lacks an owner: {cause.value}")
    for effect in SemanticEffect:
        try:
            minimum_severity(frozenset({effect}))
        except ContractValidationError as exc:
            errors.append(str(exc))

    for name, document in SPEC_DOCUMENTS.items():
        if canonical_json_bytes(document) != canonical_json_bytes(_reverse_mappings(document)):
            errors.append(f"canonical serialization depends on mapping insertion order: {name}")

    if release_policy is not None and release_policy.release != release:
        errors.append("release policy identifier does not match the requested release")
    if risk_policy is not None and risk_policy.release != release:
        errors.append("mutation risk policy identifier does not match the requested release")

    required = sum(item.disposition is TargetDisposition.REQUIRED for item in targets)
    exploratory = sum(item.disposition is TargetDisposition.EXPLORATORY for item in targets)
    infeasible = sum(
        item.disposition is TargetDisposition.MACHINE_PROVEN_INFEASIBLE for item in targets
    )
    unresolved = sum(item.disposition is TargetDisposition.UNRESOLVED for item in targets)
    release_scale_blocked = bool(
        release_policy is None
        or risk_policy is None
        or release_policy.performance_policy_status != "frozen"
        or release_policy.stochastic_risk_policy_status != "frozen"
        or risk_policy.policy_status != "frozen"
    )

    return SynthesisContractReport(
        release=release,
        target_count=len(targets),
        required_targets=required,
        exploratory_targets=exploratory,
        machine_proven_infeasible_targets=infeasible,
        unresolved_targets=unresolved,
        holdout_rule_count=len(holdouts),
        policy_count=3,
        schema_document_count=len(SCHEMA_DOCUMENT_NAMES),
        rejection_cause_count=len(RejectionCause),
        rejection_owner_count=len({cause.owner for cause in RejectionCause}),
        semantic_effect_count=len(SemanticEffect),
        canonical_digest=canonical_sha256(SPEC_DOCUMENTS),
        release_scale_blocked=release_scale_blocked,
        errors=tuple(errors),
    )
