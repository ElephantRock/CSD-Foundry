"""Immutable domain model for the executable CSD kernel."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class EvidenceStatus(StrEnum):
    CURRENT = "currentEvidence"
    INVALIDATED = "invalidated"
    EXPIRED = "expired"


class ObligationStatus(StrEnum):
    CURRENT = "current"
    PLANNED = "planned"
    RETIRED = "retired"


class SourceState(StrEnum):
    CONNECTED = "connected"
    WIRED_INERT = "wiredInert"
    UNKNOWN = "sourceUnknown"


class Assurance(StrEnum):
    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"
    UNVERIFIED = "unverified"
    STALE = "stale"
    NA = "assuranceNA"


class BasisKind(StrEnum):
    SOURCE = "source"
    DEPLOYMENT = "deployment"
    VERDICT = "verdict"


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    dimension: str
    status: EvidenceStatus = EvidenceStatus.CURRENT
    dependencies: frozenset[str] = frozenset()
    outcome: str | None = None

    def invalidate(self) -> Evidence:
        if self.status is not EvidenceStatus.CURRENT:
            return self
        return replace(self, status=EvidenceStatus.INVALIDATED)


@dataclass(frozen=True, slots=True)
class Basis:
    basis_id: str
    kind: BasisKind
    claim: str
    member_evidence_ids: frozenset[str]
    approved: bool = True


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str
    details: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, event_type: str, **details: str) -> AuditEvent:
        return cls(event_type=event_type, details=tuple(sorted(details.items())))


@dataclass(frozen=True, slots=True)
class ControlState:
    control_id: str
    obligation: ObligationStatus = ObligationStatus.CURRENT
    source_state: SourceState = SourceState.UNKNOWN
    assurance: Assurance = Assurance.UNVERIFIED
    evidence: tuple[Evidence, ...] = ()
    bases: tuple[Basis, ...] = ()
    current_source_basis_ids: frozenset[str] = frozenset()
    current_verdict_basis_ids: frozenset[str] = frozenset()
    history: tuple[AuditEvent, ...] = ()

    def evidence_by_id(self) -> dict[str, Evidence]:
        return {item.evidence_id: item for item in self.evidence}

    def bases_by_id(self) -> dict[str, Basis]:
        return {basis.basis_id: basis for basis in self.bases}

    def append_history(self, event: AuditEvent) -> ControlState:
        return replace(self, history=(*self.history, event))

    def replace_evidence(self, items: tuple[Evidence, ...]) -> ControlState:
        return replace(self, evidence=items)
