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
    close_request_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RetireControl:
    retirement_evidence: Evidence
    authority: str = "I3"


@dataclass(frozen=True, slots=True)
class AdvanceClock:
    target_time: int


@dataclass(frozen=True, slots=True)
class ProfileChange:
    profile_id: str
    profile_version: int
    authority: str = "I3"
    request_id: str | None = None
    request_due_at: int | None = None


@dataclass(frozen=True, slots=True)
class RequestReassessment:
    request_id: str
    reason: str
    due_at: int
    authority: str = "I3"


@dataclass(frozen=True, slots=True)
class RecordHeartbeat:
    at_time: int
    interval: int | None = None
    authority: str = "I3"


CsdEvent = (
    DependencyChange
    | Reassess
    | RetireControl
    | AdvanceClock
    | ProfileChange
    | RequestReassessment
    | RecordHeartbeat
)
