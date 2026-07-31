"""Governed CSD events accepted by the executable kernel."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.kernel.models import Assurance, Basis, Evidence, SourceState


@dataclass(frozen=True, slots=True)
class DependencyChange:
    dependency_id: str
    apparent_direction: str | None = None


@dataclass(frozen=True, slots=True)
class Reassess:
    new_evidence: tuple[Evidence, ...]
    new_bases: tuple[Basis, ...]
    source_state: SourceState | None = None
    assurance: Assurance | None = None
    authority: str = "I3"


@dataclass(frozen=True, slots=True)
class RetireControl:
    retirement_evidence: Evidence
    authority: str = "I3"


CsdEvent = DependencyChange | Reassess | RetireControl
