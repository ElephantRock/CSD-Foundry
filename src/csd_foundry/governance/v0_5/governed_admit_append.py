"""Public facade for the frozen governed ADMIT append (D3.2-A3.2).

Thin re-export of the internal governed append module.
"""

from csd_foundry.governance.v0_5._governed_admit_append import (
    GovernedAdmitAuthorization,
    GovernedAdmitError,
    GovernedAdmitResult,
    append_governed_admit_assumption,
)

__all__ = [
    "GovernedAdmitAuthorization",
    "GovernedAdmitError",
    "GovernedAdmitResult",
    "append_governed_admit_assumption",
]
