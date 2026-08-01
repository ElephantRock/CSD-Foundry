from __future__ import annotations

from csd_foundry.synthesis.v0_4.choice_vectors import KNOWN_ANSWER_VECTORS
from csd_foundry.synthesis.v0_4.determinism_validation import validate_determinism


def test_version_one_vector_catalog_digest_is_immutable() -> None:
    vector = KNOWN_ANSWER_VECTORS[0]
    original_vector_id = vector["vector_id"]
    try:
        vector["vector_id"] = "edited-version-one-vector"
        report = validate_determinism("v0.4")
        assert not report.success
        assert any("frozen replay oracle" in error for error in report.errors)
    finally:
        vector["vector_id"] = original_vector_id
