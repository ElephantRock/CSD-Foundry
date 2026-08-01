"""Immutable v0.4 synthesis policy documents packaged with the wheel."""

from __future__ import annotations

SCHEMA_DOCUMENT_NAMES = (
    "coverage_targets.schema.json",
    "holdouts.schema.json",
    "release_policy.schema.json",
    "mutation_risk_policy.schema.json",
    "deterministic_arithmetic_policy.schema.json",
)

COVERAGE_TARGETS_SPEC: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "targets": [
        {
            "target_id": "v04-source-expiry-last-basis",
            "disposition": "required",
            "topology_pattern": "single-source-basis",
            "event_pattern": ["AdvanceClock"],
            "temporal_pattern": "source-expiry-equals-target-time",
            "request_pattern": "none",
            "profile_pattern": "stable",
            "required_invariants": ["T-INV-02", "T-INV-03", "T-INV-04"],
            "required_consequences": ["source-becomes-unknown", "basis-removed"],
            "minimum_count": 200,
            "rarity_weight": 5,
            "holdout_tags": ["expiry", "last-basis"],
            "search_budget": {
                "maximum_plan_attempts": 8,
                "maximum_construction_attempts_per_plan": 8,
                "maximum_oracle_attempts": 8,
                "maximum_elapsed_milliseconds": 2000,
            },
            "completeness": {
                "evidence_kind": "fully_bounded",
                "bounded_projection_id": "micro-v0.4-e3-b2",
                "omitted_dimensions": [],
                "justification": "The complete target fits the bounded evidence and basis domain.",
                "alternative_witness_id": None,
            },
            "infeasibility_witness": None,
        },
        {
            "target_id": "v04-profile-strengthening-request",
            "disposition": "required",
            "topology_pattern": "profile-bound-source-and-verdict-bases",
            "event_pattern": ["ProfileChange"],
            "temporal_pattern": "request-due-after-profile-change",
            "request_pattern": "created-pending",
            "profile_pattern": "monotonic-strengthening",
            "required_invariants": ["P-INV-01", "P-INV-02", "P-INV-03", "P-INV-04"],
            "required_consequences": [
                "historical-support-preserved",
                "incompatible-current-basis-removed",
                "request-pending",
            ],
            "minimum_count": 250,
            "rarity_weight": 7,
            "holdout_tags": ["profile", "request"],
            "search_budget": {
                "maximum_plan_attempts": 12,
                "maximum_construction_attempts_per_plan": 8,
                "maximum_oracle_attempts": 8,
                "maximum_elapsed_milliseconds": 3000,
            },
            "completeness": {
                "evidence_kind": "projected_bounded",
                "bounded_projection_id": "micro-v0.4-profile-e3-b2-r1",
                "omitted_dimensions": ["large-support-multiplicity"],
                "justification": (
                    "The profile and request joint is preserved in a bounded projection."
                ),
                "alternative_witness_id": "constructive-profile-family-v0.4",
            },
            "infeasibility_witness": None,
        },
        {
            "target_id": "v04-heartbeat-expiry-joint",
            "disposition": "required",
            "topology_pattern": "two-independent-source-bases-one-expiring",
            "event_pattern": ["AdvanceClock"],
            "temporal_pattern": "expiry-equals-heartbeat-deadline",
            "request_pattern": "none",
            "profile_pattern": "stable",
            "required_invariants": ["T-INV-02", "T-INV-03", "T-INV-06"],
            "required_consequences": ["source-survives", "assurance-stales"],
            "minimum_count": 300,
            "rarity_weight": 11,
            "holdout_tags": ["joint-boundary", "heartbeat", "expiry"],
            "search_budget": {
                "maximum_plan_attempts": 16,
                "maximum_construction_attempts_per_plan": 12,
                "maximum_oracle_attempts": 12,
                "maximum_elapsed_milliseconds": 4000,
            },
            "completeness": {
                "evidence_kind": "projected_bounded",
                "bounded_projection_id": "micro-v0.4-heartbeat-expiry-e3-b2",
                "omitted_dimensions": ["additional-dormant-bases"],
                "justification": (
                    "The rare temporal joint is preserved while incidental bases are omitted."
                ),
                "alternative_witness_id": "constructive-heartbeat-expiry-family-v0.4",
            },
            "infeasibility_witness": None,
        },
        {
            "target_id": "v04-request-lifecycle",
            "disposition": "required",
            "topology_pattern": "stable-support-with-governance-request",
            "event_pattern": ["RequestReassessment", "Reassess"],
            "temporal_pattern": "closure-at-current-logical-time",
            "request_pattern": "created-then-explicitly-closed",
            "profile_pattern": "stable",
            "required_invariants": ["R-INV-01", "R-INV-03", "R-INV-04"],
            "required_consequences": ["substantive-state-preserved", "request-closed"],
            "minimum_count": 250,
            "rarity_weight": 7,
            "holdout_tags": ["request-lifecycle"],
            "search_budget": {
                "maximum_plan_attempts": 12,
                "maximum_construction_attempts_per_plan": 10,
                "maximum_oracle_attempts": 10,
                "maximum_elapsed_milliseconds": 3000,
            },
            "completeness": {
                "evidence_kind": "fully_bounded",
                "bounded_projection_id": "micro-v0.4-request-e2-b2-r1",
                "omitted_dimensions": [],
                "justification": "The complete request lifecycle fits the bounded request domain.",
                "alternative_witness_id": None,
            },
            "infeasibility_witness": None,
        },
        {
            "target_id": "v04-independent-event-convergence",
            "disposition": "exploratory",
            "topology_pattern": "independent-profile-and-heartbeat-subsystems",
            "event_pattern": ["ProfileChange", "RecordHeartbeat"],
            "temporal_pattern": "same-logical-time-independent-events",
            "request_pattern": "optional-profile-request",
            "profile_pattern": "monotonic-strengthening",
            "required_invariants": ["P-INV-02", "H-INV-02"],
            "required_consequences": ["substantive-convergence"],
            "minimum_count": 50,
            "rarity_weight": 13,
            "holdout_tags": ["composition", "convergence"],
            "search_budget": {
                "maximum_plan_attempts": 24,
                "maximum_construction_attempts_per_plan": 16,
                "maximum_oracle_attempts": 16,
                "maximum_elapsed_milliseconds": 6000,
            },
            "completeness": {
                "evidence_kind": "alternative_assurance",
                "bounded_projection_id": None,
                "omitted_dimensions": ["full-commutativity-class"],
                "justification": (
                    "A constructive witness family and metamorphic event-order check are required."
                ),
                "alternative_witness_id": "convergence-metamorphic-family-v0.4",
            },
            "infeasibility_witness": None,
        },
    ],
}

HOLDOUTS_SPEC: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "rules": [
        {
            "holdout_id": "test-heartbeat-expiry-joint",
            "split": "test",
            "topology_patterns": ["two-independent-source-bases-one-expiring"],
            "trace_patterns": ["AdvanceClock"],
            "temporal_patterns": ["expiry-equals-heartbeat-deadline"],
            "invariant_patterns": ["T-INV-02", "T-INV-06"],
            "priority": 100,
        },
        {
            "holdout_id": "validation-profile-request",
            "split": "validation",
            "topology_patterns": ["profile-bound-source-and-verdict-bases"],
            "trace_patterns": ["ProfileChange"],
            "temporal_patterns": ["request-due-after-profile-change"],
            "invariant_patterns": ["P-INV-02", "P-INV-03"],
            "priority": 50,
        },
    ],
}

RELEASE_POLICY_SPEC: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "target_trajectory_count": 100000,
    "pilot_trajectory_count": 10000,
    "maximum_trajectory_steps": 8,
    "root_seed": "csd-foundry-v0.4-release-seed",
    "rng_algorithm": "sha256-integer-choice-path",
    "rng_version": "0.4.0",
    "choice_path_schema_version": "0.4.0",
    "split_hash_salt": "csd-foundry-v0.4-structural-family-split",
    "performance_policy_status": "unfrozen",
    "stochastic_risk_policy_status": "unfrozen",
    "release_blocked_until_policies_frozen": True,
}

MUTATION_RISK_POLICY_SPEC: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "confidence_level_decimal": "0.95",
    "policy_status": "unfrozen",
    "budgets": [
        {
            "severity": "critical",
            "maximum_unresolved_deterministic": 0,
            "maximum_unresolved_stochastic": 0,
            "upper_confidence_bound_decimal": None,
            "minimum_invalid_mutants": 0,
        },
        {
            "severity": "high",
            "maximum_unresolved_deterministic": 0,
            "maximum_unresolved_stochastic": 0,
            "upper_confidence_bound_decimal": None,
            "minimum_invalid_mutants": 0,
        },
        {
            "severity": "moderate",
            "maximum_unresolved_deterministic": 0,
            "maximum_unresolved_stochastic": 0,
            "upper_confidence_bound_decimal": None,
            "minimum_invalid_mutants": 0,
        },
        {
            "severity": "low",
            "maximum_unresolved_deterministic": 0,
            "maximum_unresolved_stochastic": 0,
            "upper_confidence_bound_decimal": None,
            "minimum_invalid_mutants": 0,
        },
    ],
}

DETERMINISTIC_ARITHMETIC_POLICY_SPEC: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "semantic_floating_point_permitted": False,
    "statistical_decimal_precision": 50,
    "rounding_mode": "ROUND_HALF_EVEN",
    "canonical_encoding": "utf-8",
    "canonical_json_numbers": "integers-only",
    "ordering": "unsigned-byte-lexicographic",
}

SPEC_DOCUMENTS: dict[str, dict[str, object]] = {
    "coverage_targets.json": COVERAGE_TARGETS_SPEC,
    "holdouts.json": HOLDOUTS_SPEC,
    "release_policy.json": RELEASE_POLICY_SPEC,
    "mutation_risk_policy.json": MUTATION_RISK_POLICY_SPEC,
    "deterministic_arithmetic_policy.json": DETERMINISTIC_ARITHMETIC_POLICY_SPEC,
}
