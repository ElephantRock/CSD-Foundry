"""Public facade for the frozen assumption use-time admissibility evaluator (D3.2-B)."""

from csd_foundry.governance.v0_5._assumption_use_admissibility import (
    AssumptionUseAdmissibilityDecision,
    AssumptionUseEvaluation,
    EvidenceEvaluation,
    UseAdmissibilityError,
    UseTimeTraversedAssumption,
    evaluate_assumption_use_admissibility,
)

__all__ = [
    "AssumptionUseAdmissibilityDecision",
    "AssumptionUseEvaluation",
    "EvidenceEvaluation",
    "UseAdmissibilityError",
    "UseTimeTraversedAssumption",
    "evaluate_assumption_use_admissibility",
]
