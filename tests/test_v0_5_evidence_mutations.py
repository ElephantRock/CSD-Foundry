from __future__ import annotations

from csd_foundry.governance.v0_5.evidence_mutations import evaluate_evidence_mutations
from csd_foundry.governance.v0_5.resources import evidence_mutation_manifest


def test_evidence_mutation_campaign_kills_every_declared_mutation() -> None:
    report = evaluate_evidence_mutations()

    assert report.success
    assert len(report.results) == 17
    assert report.killed_count == 17
    assert report.survived_count == 0
    assert report.equivalent_count == 0
    assert report.invalid_mutation_count == 0
    assert report.unexplained_escape_count == 0
    assert report.mutation_catalog_digest == (
        "sha256:e2fde18a05ef22069db68fcf74291f9f8380139d369489479410b5a8fcbf70da"
    )
    assert all(item.observed_classification == "KILLED" for item in report.results)
    assert all(item.observed_detector == item.expected_detector for item in report.results)


def test_evidence_mutation_report_is_byte_stable() -> None:
    first = evaluate_evidence_mutations()
    second = evaluate_evidence_mutations()

    assert first.to_dict() == second.to_dict()
    assert first.report_digest == second.report_digest
    assert first.report_digest.startswith("sha256:")
    assert len(first.report_digest) == 71


def test_evidence_mutation_manifest_tampering_fails_closed() -> None:
    manifest = evidence_mutation_manifest()
    mutations = manifest["mutations"]
    assert isinstance(mutations, list)
    first = mutations[0]
    assert isinstance(first, dict)
    first["expected_detector"] = "EVIDENCE_ADMISSIBLE"

    report = evaluate_evidence_mutations(manifest=manifest)

    assert not report.success
    assert any("EVIDENCE_MUTATION_CATALOG_DIGEST_MISMATCH" in item for item in report.errors)


def test_evidence_mutation_resources_are_defensive_copies() -> None:
    first = evidence_mutation_manifest()
    mutations = first["mutations"]
    assert isinstance(mutations, list)
    mutations.clear()

    second = evidence_mutation_manifest()
    second_mutations = second["mutations"]
    assert isinstance(second_mutations, list)
    assert len(second_mutations) == 17
