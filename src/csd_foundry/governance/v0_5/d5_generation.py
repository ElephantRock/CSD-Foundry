"""Public facade for the D5 atomic multi-registry integration layer (P3.6).

Thin re-export of the internal D5 generation module to preserve the clean
dependency graph. The D5 layer connects the three mature staged projection
adapters (evidence P3.1, assumption P3.2, alternative-model P3.5) into one
atomic generation publication.
"""

from csd_foundry.governance.v0_5._d5_generation import (
    D5GenerationConflictError,
    D5GenerationError,
    D5GenerationManifest,
    D5GenerationStore,
    DispositionAdapterFactory,
    DispositionProjector,
    GenerationRegistryView,
    QuarantineAdapterFactory,
    QuarantineProjector,
    ReferenceDispositionAdapter,
    ReferenceQuarantineAdapter,
    ReferenceQuarantineProjection,
)

__all__ = [
    "D5GenerationConflictError",
    "D5GenerationError",
    "D5GenerationManifest",
    "D5GenerationStore",
    "DispositionAdapterFactory",
    "DispositionProjector",
    "GenerationRegistryView",
    "QuarantineAdapterFactory",
    "QuarantineProjector",
    "ReferenceDispositionAdapter",
    "ReferenceQuarantineAdapter",
    "ReferenceQuarantineProjection",
]
