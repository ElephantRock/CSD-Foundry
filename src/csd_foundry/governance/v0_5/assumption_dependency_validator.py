"""Public facade for the frozen admission-time dependency validator (I1-C / D3.2-A3.1).

Thin re-export of the internal validator module. Dedicated facade to preserve
the clean dependency graph.
"""

from csd_foundry.governance.v0_5._assumption_dependency_validator import (
    DependencyValidationReceipt,
    TraversedDependency,
    validate_assumption_dependencies,
)

__all__ = [
    "DependencyValidationReceipt",
    "TraversedDependency",
    "validate_assumption_dependencies",
]
