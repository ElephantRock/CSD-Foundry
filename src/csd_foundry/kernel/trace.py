"""Canonical public transition trace."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TransitionTrace:
    event_type: str
    invalidated_evidence: tuple[str, ...] = ()
    preserved_evidence: tuple[str, ...] = ()
    removed_bases: tuple[str, ...] = ()
    surviving_bases: tuple[str, ...] = ()
    previous_source_state: str | None = None
    resulting_source_state: str | None = None
    previous_assurance: str | None = None
    resulting_assurance: str | None = None
    forbidden_inferences: tuple[str, ...] = ()
    rules_fired: tuple[str, ...] = ()
    next_governed_step: str | None = None
