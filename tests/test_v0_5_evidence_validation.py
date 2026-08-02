from __future__ import annotations

from copy import deepcopy

from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.evidence_validation import validate_evidence_registry
from csd_foundry.governance.v0_5.resources import evidence_vectors


def test_committed_evidence_vectors_validate_independently() -> None:
    report = validate_evidence_registry()

    assert report.success
    assert report.accepted_vector_count == 5
    assert report.rejected_vector_count == 8
    assert len(report.accepted_registry_roots) == 5
    assert len(report.accepted_receipt_digests) == 5
    assert len(report.rejected_failure_codes) == 8
    assert report.vector_catalog_digest == (
        "sha256:32a7b0e3d3ba7ebd50f88b4c0c939fdd23f4a2394592d4e049bf717bb65701b4"
    )


def test_evidence_vector_loader_returns_defensive_copies() -> None:
    first = evidence_vectors()
    second = evidence_vectors()

    first["accepted_vectors"][0]["vector_id"] = "mutated"
    assert second["accepted_vectors"][0]["vector_id"] == "EV-A01-REGISTER-VERIFY"


def test_validator_detects_expected_root_tampering_even_with_recommitted_catalog() -> None:
    vectors = deepcopy(evidence_vectors())
    vectors["accepted_vectors"][0]["expected_registry_root"] = "sha256:" + "0" * 64
    vectors["catalog_digest"] = catalog_digest(vectors, b"EVIDENCE_VECTOR_CATALOG\0")

    report = validate_evidence_registry(vectors=vectors)

    assert not report.success
    assert any("EVIDENCE_EXPECTED_ROOT_MISMATCH" in error for error in report.errors)


def test_validator_rejects_unsupported_release() -> None:
    report = validate_evidence_registry("v0.6")

    assert not report.success
    assert "evidence registry validation supports only v0.5" in report.errors
