"""Public facade for staged alternative-model projection and impact receipts (P3.5).

Thin re-export of the internal projection module to preserve the clean
dependency graph. Mirrors :mod:`csd_foundry.governance.v0_5.assumption_projection`
for the alternative-model lifecycle.
"""

from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelExpiryAuthority,
    AlternativeModelExpiryAuthorization,
    AlternativeModelExpiryPlan,
    AlternativeModelExpiryPlanner,
    AlternativeModelImpactReceipt,
    AlternativeModelImpactResolver,
    AlternativeModelIntentResolver,
    AlternativeModelProjectionError,
    AlternativeModelProjectionPlan,
    EmptyAlternativeModelImpactResolver,
    EmptyAlternativeModelIntentResolver,
    StagedAlternativeModelProjectionAdapter,
)

__all__ = [
    "AlternativeModelExpiryAuthority",
    "AlternativeModelExpiryAuthorization",
    "AlternativeModelExpiryPlan",
    "AlternativeModelExpiryPlanner",
    "AlternativeModelImpactReceipt",
    "AlternativeModelImpactResolver",
    "AlternativeModelIntentResolver",
    "AlternativeModelProjectionError",
    "AlternativeModelProjectionPlan",
    "EmptyAlternativeModelImpactResolver",
    "EmptyAlternativeModelIntentResolver",
    "StagedAlternativeModelProjectionAdapter",
]
