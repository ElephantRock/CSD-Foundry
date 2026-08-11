"""Public facade for the P3.4 governed alternative-model layer.

Thin re-export of the internal governed alternative-model module:
authority + structural-difference + FULL_REPLAY + comparison + use-time gate.
"""

from csd_foundry.governance.v0_5._governed_alternative_model import (
    AlternativeModelReplayExecutor,
    ComparisonReceipt,
    GovernedAlternativeModelAdmitResult,
    GovernedAlternativeModelAuthorization,
    GovernedAlternativeModelError,
    ReplayReceipt,
    StructuralDifferenceReceipt,
    UseAuthorityDecision,
    append_governed_alternative_model_admit,
    compare_alternative_model_replays,
    compute_structural_difference_digest,
    detect_structural_difference,
    evaluate_alternative_model_use_authority,
    run_full_replay_comparison,
)

__all__ = [
    "AlternativeModelReplayExecutor",
    "ComparisonReceipt",
    "GovernedAlternativeModelAdmitResult",
    "GovernedAlternativeModelAuthorization",
    "GovernedAlternativeModelError",
    "ReplayReceipt",
    "StructuralDifferenceReceipt",
    "UseAuthorityDecision",
    "append_governed_alternative_model_admit",
    "compare_alternative_model_replays",
    "compute_structural_difference_digest",
    "detect_structural_difference",
    "evaluate_alternative_model_use_authority",
    "run_full_replay_comparison",
]
