"""Immutable catalog metadata for v0.4 replay canaries."""

from __future__ import annotations

REPLAY_VECTOR_CATALOG: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "vector_ids": [
        "accepted-attempt-zero",
        "rejected-prefix-then-accepted",
        "complete-exhaustion",
        "call-order-independence",
        "typed-weighted-domain",
        "forced-redraw",
        "identity-commitment",
    ],
}

FROZEN_REPLAY_VECTOR_CATALOG_DIGEST = (
    "4ff25bab69ab6ca5fe93ad657c2544505e71d8601bea13956b8566eb772e28d1"
)

# Filled only from independently reviewed executable canaries. Once committed, values are
# immutable under replay-policy version 1; behavior changes require replay-v2 evidence.
EXPECTED_REPLAY_DIGESTS: dict[str, str] = {}
