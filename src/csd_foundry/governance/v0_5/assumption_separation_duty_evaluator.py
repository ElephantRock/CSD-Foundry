"""Public facade for the frozen separation-of-duty authority evaluator (I1-B / D3.2-A2).

Thin re-export of the internal evaluator module. Dedicated facade to preserve
the clean dependency graph:

    assumption_separation_duty_evaluator (this facade)
        ↓ _assumption_separation_duty_evaluator
        ↓ assumption_policy_resolution
        ↓ assumption_governance_contracts

Re-exporting through ``assumption_governance_contracts`` would introduce an
import cycle because ``assumption_policy_resolution`` already imports from that
facade.
"""

from csd_foundry.governance.v0_5._assumption_separation_duty_evaluator import (
    SeparationOfDutyDecision,
    SeparationOfDutyRuleEvaluation,
    evaluate_separation_of_duty,
)

__all__ = [
    "SeparationOfDutyDecision",
    "SeparationOfDutyRuleEvaluation",
    "evaluate_separation_of_duty",
]
