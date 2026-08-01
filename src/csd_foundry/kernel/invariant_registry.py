"""Stable identifiers emitted by the independent CSD verifier layers."""

from __future__ import annotations

CORE_INVARIANT_IDS = frozenset(
    {
        "G-INV-06",
        "G-INV-10",
        "G-INV-11",
        "G-INV-13",
        "INV-04",
        "INV-05",
        "INV-07",
        "INV-11",
        "INV-13",
        "INV-14",
        "INV-15",
        "INV-16",
        "INV-18",
        "INV-19",
    }
)

TEMPORAL_INVARIANT_IDS = frozenset(
    {
        "T-INV-01",
        "T-INV-02",
        "T-INV-03",
        "T-INV-04",
        "T-INV-06",
        "P-INV-01",
        "P-INV-02",
        "P-INV-03",
        "P-INV-04",
        "R-INV-01",
        "R-INV-02",
        "R-INV-03",
        "R-INV-04",
        "H-INV-01",
        "H-INV-02",
        "H-INV-03",
    }
)

EXECUTABLE_INVARIANT_IDS = CORE_INVARIANT_IDS | TEMPORAL_INVARIANT_IDS
