"""Typed contracts for deterministic constraint-valid synthesis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ContractValidationError(ValueError):
    """Raised when a v0.4 contract violates its declared schema."""


class TargetDisposition(StrEnum):
    REQUIRED = "required"
    EXPLORATORY = "exploratory"
    MACHINE_PROVEN_INFEASIBLE = "machine_proven_infeasible"
    UNRESOLVED = "unresolved"


class RejectionOwner(StrEnum):
    TARGET_CATALOG = "target_catalog"
    PLANNER = "planner"
    STATE_CONSTRUCTOR = "state_constructor"
    EVENT_SAMPLER = "event_sampler"
    KERNEL = "kernel"
    INDEPENDENT_VERIFIER = "independent_verifier"
    REPLAY_ENGINE = "replay_engine"
    CANONICALIZER = "canonicalizer"
    HOLDOUT_ALLOCATOR = "holdout_allocator"
    MUTATION_ENGINE = "mutation_engine"
    DUPLICATE_MONITOR = "duplicate_monitor"
    RELEASE_COMPILER = "release_compiler"


class RejectionCause(StrEnum):
    TARGET_CONTRACT_UNSAT = "TARGET_CONTRACT_UNSAT"
    TARGET_SEARCH_BUDGET_EXHAUSTED = "TARGET_SEARCH_BUDGET_EXHAUSTED"
    PLAN_CONSTRUCTION_FAILURE = "PLAN_CONSTRUCTION_FAILURE"
    STATE_CONSTRUCTION_FAILURE = "STATE_CONSTRUCTION_FAILURE"
    SAMPLER_PRECONDITION_FAILURE = "SAMPLER_PRECONDITION_FAILURE"
    KERNEL_EXECUTION_FAILURE = "KERNEL_EXECUTION_FAILURE"
    INDEPENDENT_VERIFIER_FAILURE = "INDEPENDENT_VERIFIER_FAILURE"
    REPLAY_DIVERGENCE = "REPLAY_DIVERGENCE"
    CANONICALIZATION_FAILURE = "CANONICALIZATION_FAILURE"
    CANONICALIZATION_DIVERGENCE = "CANONICALIZATION_DIVERGENCE"
    HOLDOUT_CONFLICT = "HOLDOUT_CONFLICT"
    MUTATION_NOOP = "MUTATION_NOOP"
    MUTATION_NOT_INVALID = "MUTATION_NOT_INVALID"
    MUTATION_AMBIGUOUS = "MUTATION_AMBIGUOUS"
    MUTATION_ESCAPE = "MUTATION_ESCAPE"
    DUPLICATE_ANOMALY = "DUPLICATE_ANOMALY"
    ARTIFACT_SERIALIZATION_FAILURE = "ARTIFACT_SERIALIZATION_FAILURE"

    @property
    def owner(self) -> RejectionOwner:
        return _REJECTION_OWNERS[self]


_REJECTION_OWNERS: dict[RejectionCause, RejectionOwner] = {
    RejectionCause.TARGET_CONTRACT_UNSAT: RejectionOwner.TARGET_CATALOG,
    RejectionCause.TARGET_SEARCH_BUDGET_EXHAUSTED: RejectionOwner.PLANNER,
    RejectionCause.PLAN_CONSTRUCTION_FAILURE: RejectionOwner.PLANNER,
    RejectionCause.STATE_CONSTRUCTION_FAILURE: RejectionOwner.STATE_CONSTRUCTOR,
    RejectionCause.SAMPLER_PRECONDITION_FAILURE: RejectionOwner.EVENT_SAMPLER,
    RejectionCause.KERNEL_EXECUTION_FAILURE: RejectionOwner.KERNEL,
    RejectionCause.INDEPENDENT_VERIFIER_FAILURE: RejectionOwner.INDEPENDENT_VERIFIER,
    RejectionCause.REPLAY_DIVERGENCE: RejectionOwner.REPLAY_ENGINE,
    RejectionCause.CANONICALIZATION_FAILURE: RejectionOwner.CANONICALIZER,
    RejectionCause.CANONICALIZATION_DIVERGENCE: RejectionOwner.CANONICALIZER,
    RejectionCause.HOLDOUT_CONFLICT: RejectionOwner.HOLDOUT_ALLOCATOR,
    RejectionCause.MUTATION_NOOP: RejectionOwner.MUTATION_ENGINE,
    RejectionCause.MUTATION_NOT_INVALID: RejectionOwner.MUTATION_ENGINE,
    RejectionCause.MUTATION_AMBIGUOUS: RejectionOwner.MUTATION_ENGINE,
    RejectionCause.MUTATION_ESCAPE: RejectionOwner.MUTATION_ENGINE,
    RejectionCause.DUPLICATE_ANOMALY: RejectionOwner.DUPLICATE_MONITOR,
    RejectionCause.ARTIFACT_SERIALIZATION_FAILURE: RejectionOwner.RELEASE_COMPILER,
}


class InfeasibilityProofMethod(StrEnum):
    EXHAUSTIVE_ENUMERATION = "exhaustive_enumeration"
    TYPED_CONTRADICTION = "typed_contradiction"
    CHECKED_UNSAT_CORE = "checked_unsat_core"
    VERIFIED_PATTERN_REDUCTION = "verified_pattern_reduction"


class CompletenessEvidenceKind(StrEnum):
    FULLY_BOUNDED = "fully_bounded"
    PROJECTED_BOUNDED = "projected_bounded"
    ALTERNATIVE_ASSURANCE = "alternative_assurance"


class EscapeSeverity(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class SemanticEffect(StrEnum):
    FABRICATE_SOURCE_STATE = "fabricate_source_state"
    FABRICATE_VERDICT = "fabricate_verdict"
    RETAIN_UNSUPPORTED_VERDICT = "retain_unsupported_verdict"
    REACTIVATE_EVIDENCE = "reactivate_evidence"
    BYPASS_RETIREMENT = "bypass_retirement"
    UNAUTHORIZED_GOVERNANCE = "unauthorized_governance"
    REWRITE_SUBSTANTIVE_HISTORY = "rewrite_substantive_history"
    CROSS_TRUST_BOUNDARY = "cross_trust_boundary"
    SUPPRESS_EXPIRY = "suppress_expiry"
    PREMATURE_EXPIRY = "premature_expiry"
    RETAIN_INCOMPATIBLE_BASIS = "retain_incompatible_basis"
    CLOSE_WRONG_REQUEST = "close_wrong_request"
    ALTER_PROFILE_CONSEQUENCE = "alter_profile_consequence"
    VIOLATE_CAUSAL_ORDER = "violate_causal_order"
    OMIT_SUBSTANTIVE_AUDIT = "omit_substantive_audit"
    CROSS_STEP_INCONSISTENCY = "cross_step_inconsistency"
    INCORRECT_NONSUBSTANTIVE_AUDIT = "incorrect_nonsubstantive_audit"
    INCORRECT_REQUEST_METADATA = "incorrect_request_metadata"
    NONCANONICAL_ORDER = "noncanonical_order"
    TRACE_INCONSISTENCY = "trace_inconsistency"
    REPORTING_ERROR = "reporting_error"
    COUNTER_ERROR = "counter_error"
    EXPLANATION_ERROR = "explanation_error"
    PERFORMANCE_METADATA_ERROR = "performance_metadata_error"


_SEVERITY_RANK: dict[EscapeSeverity, int] = {
    EscapeSeverity.LOW: 0,
    EscapeSeverity.MODERATE: 1,
    EscapeSeverity.HIGH: 2,
    EscapeSeverity.CRITICAL: 3,
}

_EFFECT_SEVERITY: dict[SemanticEffect, EscapeSeverity] = {
    SemanticEffect.FABRICATE_SOURCE_STATE: EscapeSeverity.CRITICAL,
    SemanticEffect.FABRICATE_VERDICT: EscapeSeverity.CRITICAL,
    SemanticEffect.RETAIN_UNSUPPORTED_VERDICT: EscapeSeverity.CRITICAL,
    SemanticEffect.REACTIVATE_EVIDENCE: EscapeSeverity.CRITICAL,
    SemanticEffect.BYPASS_RETIREMENT: EscapeSeverity.CRITICAL,
    SemanticEffect.UNAUTHORIZED_GOVERNANCE: EscapeSeverity.CRITICAL,
    SemanticEffect.REWRITE_SUBSTANTIVE_HISTORY: EscapeSeverity.CRITICAL,
    SemanticEffect.CROSS_TRUST_BOUNDARY: EscapeSeverity.CRITICAL,
    SemanticEffect.SUPPRESS_EXPIRY: EscapeSeverity.HIGH,
    SemanticEffect.PREMATURE_EXPIRY: EscapeSeverity.HIGH,
    SemanticEffect.RETAIN_INCOMPATIBLE_BASIS: EscapeSeverity.HIGH,
    SemanticEffect.CLOSE_WRONG_REQUEST: EscapeSeverity.HIGH,
    SemanticEffect.ALTER_PROFILE_CONSEQUENCE: EscapeSeverity.HIGH,
    SemanticEffect.VIOLATE_CAUSAL_ORDER: EscapeSeverity.HIGH,
    SemanticEffect.OMIT_SUBSTANTIVE_AUDIT: EscapeSeverity.HIGH,
    SemanticEffect.CROSS_STEP_INCONSISTENCY: EscapeSeverity.HIGH,
    SemanticEffect.INCORRECT_NONSUBSTANTIVE_AUDIT: EscapeSeverity.MODERATE,
    SemanticEffect.INCORRECT_REQUEST_METADATA: EscapeSeverity.MODERATE,
    SemanticEffect.NONCANONICAL_ORDER: EscapeSeverity.MODERATE,
    SemanticEffect.TRACE_INCONSISTENCY: EscapeSeverity.MODERATE,
    SemanticEffect.REPORTING_ERROR: EscapeSeverity.LOW,
    SemanticEffect.COUNTER_ERROR: EscapeSeverity.LOW,
    SemanticEffect.EXPLANATION_ERROR: EscapeSeverity.LOW,
    SemanticEffect.PERFORMANCE_METADATA_ERROR: EscapeSeverity.LOW,
}


_DECIMAL_PATTERN = re.compile(r"^(0|1)(?:\.\d+)?$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_text(value: str, field_name: str) -> None:
    if not value.strip():
        raise ContractValidationError(f"{field_name} must be nonempty")


def _require_unique(values: tuple[str, ...], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ContractValidationError(f"{field_name} must not contain duplicates")
    for value in values:
        _require_text(value, field_name)


def minimum_severity(effects: frozenset[SemanticEffect]) -> EscapeSeverity:
    if not effects:
        raise ContractValidationError("escape classification requires semantic effects")
    return max((_EFFECT_SEVERITY[item] for item in effects), key=_SEVERITY_RANK.__getitem__)


@dataclass(frozen=True, slots=True)
class SearchBudget:
    maximum_plan_attempts: int
    maximum_construction_attempts_per_plan: int
    maximum_oracle_attempts: int
    maximum_elapsed_milliseconds: int

    def __post_init__(self) -> None:
        for field_name, value in (
            ("maximum_plan_attempts", self.maximum_plan_attempts),
            (
                "maximum_construction_attempts_per_plan",
                self.maximum_construction_attempts_per_plan,
            ),
            ("maximum_oracle_attempts", self.maximum_oracle_attempts),
            ("maximum_elapsed_milliseconds", self.maximum_elapsed_milliseconds),
        ):
            if value < 0:
                raise ContractValidationError(f"{field_name} must be nonnegative")

    @property
    def is_positive(self) -> bool:
        return all(
            value > 0
            for value in (
                self.maximum_plan_attempts,
                self.maximum_construction_attempts_per_plan,
                self.maximum_oracle_attempts,
                self.maximum_elapsed_milliseconds,
            )
        )


@dataclass(frozen=True, slots=True)
class InfeasibilityWitness:
    target_id: str
    grammar_version: str
    constraint_ids: tuple[str, ...]
    proof_method: InfeasibilityProofMethod
    unsat_core: tuple[str, ...]
    verifier_version: str
    witness_digest: str

    def __post_init__(self) -> None:
        _require_text(self.target_id, "target_id")
        _require_text(self.grammar_version, "grammar_version")
        _require_unique(self.constraint_ids, "constraint_ids")
        _require_unique(self.unsat_core, "unsat_core")
        _require_text(self.verifier_version, "verifier_version")
        if not self.constraint_ids or not self.unsat_core:
            raise ContractValidationError(
                "infeasibility witness requires constraints and an unsat core"
            )
        if _SHA256_PATTERN.fullmatch(self.witness_digest) is None:
            raise ContractValidationError("witness_digest must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class CompletenessWitnessMap:
    target_id: str
    evidence_kind: CompletenessEvidenceKind
    bounded_projection_id: str | None
    omitted_dimensions: tuple[str, ...]
    justification: str
    alternative_witness_id: str | None

    def __post_init__(self) -> None:
        _require_text(self.target_id, "target_id")
        _require_unique(self.omitted_dimensions, "omitted_dimensions")
        _require_text(self.justification, "justification")
        if self.evidence_kind is CompletenessEvidenceKind.FULLY_BOUNDED:
            if self.bounded_projection_id is None or self.omitted_dimensions:
                raise ContractValidationError(
                    "fully bounded evidence requires a projection and no omitted dimensions"
                )
            if self.alternative_witness_id is not None:
                raise ContractValidationError(
                    "fully bounded evidence cannot use an alternative witness"
                )
        elif self.evidence_kind is CompletenessEvidenceKind.PROJECTED_BOUNDED:
            if self.bounded_projection_id is None or not self.omitted_dimensions:
                raise ContractValidationError(
                    "projected bounded evidence requires a projection and omitted dimensions"
                )
        elif self.alternative_witness_id is None:
            raise ContractValidationError(
                "alternative assurance requires an alternative witness identity"
            )


@dataclass(frozen=True, slots=True)
class CoverageTarget:
    target_id: str
    disposition: TargetDisposition
    topology_pattern: str
    event_pattern: tuple[str, ...]
    temporal_pattern: str
    request_pattern: str
    profile_pattern: str
    required_invariants: frozenset[str]
    required_consequences: frozenset[str]
    minimum_count: int
    rarity_weight: int
    holdout_tags: frozenset[str]
    search_budget: SearchBudget
    completeness: CompletenessWitnessMap
    infeasibility_witness: InfeasibilityWitness | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("target_id", self.target_id),
            ("topology_pattern", self.topology_pattern),
            ("temporal_pattern", self.temporal_pattern),
            ("request_pattern", self.request_pattern),
            ("profile_pattern", self.profile_pattern),
        ):
            _require_text(value, field_name)
        for event_type in self.event_pattern:
            _require_text(event_type, "event_pattern")
        if not self.event_pattern:
            raise ContractValidationError("event_pattern must be nonempty")
        if not self.required_invariants:
            raise ContractValidationError("required_invariants must be nonempty")
        if not self.required_consequences:
            raise ContractValidationError("required_consequences must be nonempty")
        if self.minimum_count < 0:
            raise ContractValidationError("minimum_count must be nonnegative")
        if self.rarity_weight <= 0:
            raise ContractValidationError("rarity_weight must be positive")
        if self.completeness.target_id != self.target_id:
            raise ContractValidationError("completeness witness must reference the target")

        if self.disposition is TargetDisposition.REQUIRED:
            if self.minimum_count <= 0 or not self.search_budget.is_positive:
                raise ContractValidationError(
                    "required targets need a positive quota and positive search budget"
                )
            if self.infeasibility_witness is not None:
                raise ContractValidationError(
                    "required targets cannot carry infeasibility witnesses"
                )
        elif self.disposition is TargetDisposition.MACHINE_PROVEN_INFEASIBLE:
            if self.minimum_count != 0 or self.infeasibility_witness is None:
                raise ContractValidationError(
                    "machine-proven infeasible targets need zero quota and a witness"
                )
            if self.infeasibility_witness.target_id != self.target_id:
                raise ContractValidationError("infeasibility witness must reference the target")
        else:
            if self.infeasibility_witness is not None:
                raise ContractValidationError(
                    "only machine-proven infeasible targets may carry infeasibility witnesses"
                )
            if self.disposition is TargetDisposition.UNRESOLVED and self.minimum_count != 0:
                raise ContractValidationError("unresolved targets must have zero quota")


@dataclass(frozen=True, slots=True)
class TrajectoryPlan:
    plan_id: str
    target_id: str
    event_skeleton: tuple[str, ...]
    support_graph_pattern: str
    relative_time_relations: tuple[str, ...]
    required_preconditions: tuple[str, ...]
    expected_state_deltas: tuple[str, ...]
    expected_invariant_sequence: tuple[frozenset[str], ...]

    def __post_init__(self) -> None:
        _require_text(self.plan_id, "plan_id")
        _require_text(self.target_id, "target_id")
        for event_type in self.event_skeleton:
            _require_text(event_type, "event_skeleton")
        _require_text(self.support_graph_pattern, "support_graph_pattern")
        if not self.event_skeleton:
            raise ContractValidationError("event_skeleton must be nonempty")
        if len(self.expected_invariant_sequence) != len(self.event_skeleton):
            raise ContractValidationError(
                "expected invariant sequence must align with the event skeleton"
            )


@dataclass(frozen=True, slots=True)
class ConstraintProof:
    target_id: str
    constraint_ids: tuple[str, ...]
    witnesses: tuple[tuple[str, str], ...]
    identity_allocations: tuple[tuple[str, str], ...]
    temporal_assignments: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        _require_text(self.target_id, "target_id")
        _require_unique(self.constraint_ids, "constraint_ids")
        if not self.constraint_ids:
            raise ContractValidationError("constraint proof must name at least one constraint")


@dataclass(frozen=True, slots=True)
class EligibilityProof:
    event_type: str
    precondition_ids: tuple[str, ...]
    witness_ids: tuple[str, ...]
    boundary_relations: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.event_type, "event_type")
        _require_unique(self.precondition_ids, "precondition_ids")
        _require_unique(self.witness_ids, "witness_ids")
        if not self.precondition_ids:
            raise ContractValidationError("eligibility proof must name event preconditions")


@dataclass(frozen=True, slots=True)
class GenerationAttempt:
    attempt_id: str
    release: str
    seed_path: str
    target_id: str
    plan_id: str | None
    accepted: bool
    rejection_cause: RejectionCause | None
    diagnostic_codes: tuple[str, ...]
    trajectory_digest: str | None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("attempt_id", self.attempt_id),
            ("release", self.release),
            ("seed_path", self.seed_path),
            ("target_id", self.target_id),
        ):
            _require_text(value, field_name)
        _require_unique(self.diagnostic_codes, "diagnostic_codes")
        if self.accepted:
            if self.rejection_cause is not None or self.trajectory_digest is None:
                raise ContractValidationError(
                    "accepted attempts require a trajectory digest and no rejection cause"
                )
            if _SHA256_PATTERN.fullmatch(self.trajectory_digest) is None:
                raise ContractValidationError("trajectory_digest must be a lowercase SHA-256")
        elif self.rejection_cause is None or self.trajectory_digest is not None:
            raise ContractValidationError(
                "rejected attempts require exactly one rejection cause and no trajectory digest"
            )


@dataclass(frozen=True, slots=True)
class EscapeClassification:
    escape_id: str
    mutation_id: str
    invariant_family: str
    severity: EscapeSeverity
    semantic_effects: frozenset[SemanticEffect]
    reproducible: bool
    genuinely_invalid: bool
    resolution: str | None
    reviewer_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.escape_id, "escape_id")
        _require_text(self.mutation_id, "mutation_id")
        _require_text(self.invariant_family, "invariant_family")
        _require_unique(self.reviewer_ids, "reviewer_ids")
        required = minimum_severity(self.semantic_effects)
        if _SEVERITY_RANK[self.severity] < _SEVERITY_RANK[required]:
            raise ContractValidationError(
                f"severity {self.severity.value} understates semantic effects requiring "
                f"{required.value}"
            )
        if self.resolution is not None:
            _require_text(self.resolution, "resolution")


@dataclass(frozen=True, slots=True)
class HoldoutRule:
    holdout_id: str
    split: str
    topology_patterns: tuple[str, ...]
    trace_patterns: tuple[str, ...]
    temporal_patterns: tuple[str, ...]
    invariant_patterns: tuple[str, ...]
    priority: int

    def __post_init__(self) -> None:
        _require_text(self.holdout_id, "holdout_id")
        if self.split not in {"train", "validation", "test"}:
            raise ContractValidationError("holdout split must be train, validation, or test")
        if self.priority < 0:
            raise ContractValidationError("holdout priority must be nonnegative")
        if not any(
            (
                self.topology_patterns,
                self.trace_patterns,
                self.temporal_patterns,
                self.invariant_patterns,
            )
        ):
            raise ContractValidationError("holdout rule must contain at least one pattern")


@dataclass(frozen=True, slots=True)
class DeterministicArithmeticPolicy:
    semantic_floating_point_permitted: bool
    statistical_decimal_precision: int
    rounding_mode: str
    canonical_encoding: str
    canonical_json_numbers: str
    ordering: str

    def __post_init__(self) -> None:
        if self.semantic_floating_point_permitted:
            raise ContractValidationError("semantic floating-point decisions are prohibited")
        if self.statistical_decimal_precision <= 0:
            raise ContractValidationError("decimal precision must be positive")
        if self.rounding_mode != "ROUND_HALF_EVEN":
            raise ContractValidationError("rounding mode must be ROUND_HALF_EVEN")
        if self.canonical_encoding.lower() != "utf-8":
            raise ContractValidationError("canonical encoding must be UTF-8")
        if self.canonical_json_numbers != "integers-only":
            raise ContractValidationError("canonical semantic JSON must use integers only")
        if self.ordering != "unsigned-byte-lexicographic":
            raise ContractValidationError("canonical ordering policy is unsupported")


@dataclass(frozen=True, slots=True)
class ReleasePolicy:
    release: str
    target_trajectory_count: int
    pilot_trajectory_count: int
    maximum_trajectory_steps: int
    root_seed: str
    rng_algorithm: str
    rng_version: str
    choice_path_schema_version: str
    split_hash_salt: str
    performance_policy_status: str
    stochastic_risk_policy_status: str

    def __post_init__(self) -> None:
        for field_name, value in (
            ("release", self.release),
            ("root_seed", self.root_seed),
            ("rng_algorithm", self.rng_algorithm),
            ("rng_version", self.rng_version),
            ("choice_path_schema_version", self.choice_path_schema_version),
            ("split_hash_salt", self.split_hash_salt),
        ):
            _require_text(value, field_name)
        if self.target_trajectory_count <= 0 or self.pilot_trajectory_count <= 0:
            raise ContractValidationError("release and pilot trajectory counts must be positive")
        if self.pilot_trajectory_count >= self.target_trajectory_count:
            raise ContractValidationError("pilot count must be smaller than release count")
        if self.maximum_trajectory_steps <= 0:
            raise ContractValidationError("maximum trajectory steps must be positive")
        if self.performance_policy_status not in {"unfrozen", "frozen"}:
            raise ContractValidationError("performance policy status must be frozen or unfrozen")
        if self.stochastic_risk_policy_status not in {"unfrozen", "frozen"}:
            raise ContractValidationError("risk policy status must be frozen or unfrozen")


@dataclass(frozen=True, slots=True)
class MutationRiskBudget:
    severity: EscapeSeverity
    maximum_unresolved_deterministic: int
    maximum_unresolved_stochastic: int
    upper_confidence_bound_decimal: str | None
    minimum_invalid_mutants: int

    def __post_init__(self) -> None:
        if self.maximum_unresolved_deterministic < 0:
            raise ContractValidationError("deterministic escape budget must be nonnegative")
        if self.maximum_unresolved_stochastic < 0:
            raise ContractValidationError("stochastic escape budget must be nonnegative")
        if self.minimum_invalid_mutants < 0:
            raise ContractValidationError("minimum invalid mutants must be nonnegative")
        if (
            self.upper_confidence_bound_decimal is not None
            and _DECIMAL_PATTERN.fullmatch(self.upper_confidence_bound_decimal) is None
        ):
            raise ContractValidationError(
                "confidence bound must be an exact decimal string between zero and one"
            )


@dataclass(frozen=True, slots=True)
class MutationRiskPolicy:
    release: str
    confidence_level_decimal: str
    policy_status: str
    budgets: tuple[MutationRiskBudget, ...]

    def __post_init__(self) -> None:
        _require_text(self.release, "release")
        if _DECIMAL_PATTERN.fullmatch(self.confidence_level_decimal) is None:
            raise ContractValidationError("confidence level must be an exact decimal string")
        if self.policy_status not in {"unfrozen", "frozen"}:
            raise ContractValidationError("mutation risk policy status must be frozen or unfrozen")
        severities = tuple(item.severity for item in self.budgets)
        if len(severities) != len(set(severities)):
            raise ContractValidationError("mutation risk policy has duplicate severity budgets")
        if set(severities) != set(EscapeSeverity):
            raise ContractValidationError("mutation risk policy must cover every severity")
