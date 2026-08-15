"""Public facade for the P3.7 Phase-3 integrated qualification layer.

Thin re-export of the internal Phase-3 qualification module (plus the
independent validator and mutation campaign entry points) to preserve the
clean dependency graph. The qualification layer builds the deterministic
canary corpus through the real D5 integration layer, serializes every
committed artifact, and validates it with the independent Phase-3 validator
and mutation campaign.
"""

from csd_foundry.governance.v0_5._phase3_qualification import (
    Phase3CanaryScenario,
    Phase3QualificationReport,
    build_phase3_canary_corpus,
    build_phase3_scenario,
    commit_phase3_generation,
    phase3_adapters,
    phase3_context,
    run_phase3_qualification,
    serialize_phase3_corpus,
)
from csd_foundry.governance.v0_5.phase3_mutations import (
    Phase3MutationError,
    Phase3MutationReport,
    Phase3MutationResult,
    build_phase3_mutation_manifest,
    evaluate_phase3_mutations,
    phase3_corpus_digest,
)
from csd_foundry.governance.v0_5.phase3_validation import (
    Phase3GenerationSummary,
    Phase3ValidationError,
    Phase3ValidationReport,
    compute_generation_digest,
    validate_phase3_generations,
)

__all__ = [
    "Phase3CanaryScenario",
    "Phase3GenerationSummary",
    "Phase3MutationError",
    "Phase3MutationReport",
    "Phase3MutationResult",
    "Phase3QualificationReport",
    "Phase3ValidationError",
    "Phase3ValidationReport",
    "build_phase3_canary_corpus",
    "build_phase3_mutation_manifest",
    "build_phase3_scenario",
    "commit_phase3_generation",
    "compute_generation_digest",
    "evaluate_phase3_mutations",
    "phase3_adapters",
    "phase3_context",
    "phase3_corpus_digest",
    "run_phase3_qualification",
    "serialize_phase3_corpus",
    "validate_phase3_generations",
]
