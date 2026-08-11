"""Public facade for staged assumption projection and impact receipts (P3.2).

Thin re-export of the internal projection module to preserve the clean
dependency graph. Mirrors :mod:`csd_foundry.governance.v0_5.evidence_projection`
for the assumption lifecycle.
"""

from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionExpiryAuthority,
    AssumptionExpiryPlan,
    AssumptionExpiryPlanner,
    AssumptionImpactReceipt,
    AssumptionImpactResolver,
    AssumptionIntentResolver,
    AssumptionProjectionError,
    AssumptionProjectionPlan,
    EmptyAssumptionImpactResolver,
    EmptyAssumptionIntentResolver,
    StagedAssumptionProjectionAdapter,
)

__all__ = [
    "AssumptionExpiryAuthority",
    "AssumptionExpiryPlan",
    "AssumptionExpiryPlanner",
    "AssumptionImpactReceipt",
    "AssumptionImpactResolver",
    "AssumptionIntentResolver",
    "AssumptionProjectionError",
    "AssumptionProjectionPlan",
    "EmptyAssumptionImpactResolver",
    "EmptyAssumptionIntentResolver",
    "StagedAssumptionProjectionAdapter",
]
