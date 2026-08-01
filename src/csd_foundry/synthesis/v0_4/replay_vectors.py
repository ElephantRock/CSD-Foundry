"""Immutable catalog metadata for v0.4 replay canaries."""

from __future__ import annotations

REPLAY_VECTOR_VERSION = 1
REPLAY_VECTOR_IDS: tuple[str, ...] = (
    "accepted-attempt-zero",
    "rejected-prefix-then-accepted",
    "complete-exhaustion",
    "call-order-independence",
    "typed-weighted-domain",
    "forced-redraw",
    "identity-commitment",
)
REPLAY_VECTOR_COUNT = len(REPLAY_VECTOR_IDS)

REPLAY_VECTOR_CATALOG: dict[str, object] = {
    "release": "v0.4",
    "schema_version": "0.4.0",
    "vector_ids": list(REPLAY_VECTOR_IDS),
}

FROZEN_REPLAY_VECTOR_CATALOG_DIGEST = (
    "4ff25bab69ab6ca5fe93ad657c2544505e71d8601bea13956b8566eb772e28d1"
)

EXPECTED_REPLAY_DIGESTS: dict[str, str] = {
    "accepted-attempt-zero": "bcf07635ed4ea2db541483c68b7bdeee2c121053e6be6a561591589b0b679fd2",
    "call-order-independence": "03894c316e4ae26b230c508dc02af74eda91acd861b4f581089ae2909385fda6",
    "complete-exhaustion": "1ee27d1c3b344728e8f5c60f1fb227a895092976b5c418e895ad0af523801d60",
    "forced-redraw": "dab2d22b3724a19187a4e11e95bb61bb9f9ad1fb6a563d720e7f4c4b14c5545d",
    "identity-commitment": "6ed7b5294afc02081fa130a89ad22c4851cbd40ee8b24fb4ff600e6b953896f6",
    "rejected-prefix-then-accepted": (
        "e7a164f95689c82a57715bdf6c80db69d5d224bc8539bda57fc123d69f9d152e"
    ),
    "typed-weighted-domain": "bea5b2f02d0c49d4f93a687bff943130c8effeb7fdcecf559a31924b57840e3f",
}
