from __future__ import annotations

from csd_foundry.governance.v0_5.assumption_mutations import evaluate_assumption_mutations
from csd_foundry.governance.v0_5.resources import assumption_mutation_manifest


def test_assumption_mutation_campaign_kills_every_declared_mutation() -> None:
    report = evaluate_assumption_mutations()

    assert report.success
    assert len(report.results) == 22
    assert report.killed_count == 22
    assert report.survived_count == 0
    assert report.equivalent_count == 0
    assert report.invalid_mutation_count == 0
    assert report.unexplained_escape_count == 0
    assert report.mutation_catalog_digest == (
        "sha256:00cbd34aa340efb5c4ed3c61ab89dd062e772353dc59995d35621ab011029dcb"
    )
    assert all(item.observed_classification == "KILLED" for item in report.results)
    assert all(item.observed_detector == item.expected_detector for item in report.results)


def test_assumption_mutation_report_is_byte_stable() -> None:
    first = evaluate_assumption_mutations()
    second = evaluate_assumption_mutations()

    assert first.to_dict() == second.to_dict()
    assert first.report_digest == second.report_digest
    assert first.report_digest.startswith("sha256:")
    assert len(first.report_digest) == 71


def test_assumption_mutation_manifest_tampering_fails_closed() -> None:
    manifest = assumption_mutation_manifest()
    mutations = manifest["mutations"]
    assert isinstance(mutations, list)
    first = mutations[0]
    assert isinstance(first, dict)
    first["expected_detector"] = "ASSUMPTION_USE_ALLOWED"

    report = evaluate_assumption_mutations(manifest=manifest)

    assert not report.success
    assert any("ASSUMPTION_MUTATION_CATALOG_DIGEST_MISMATCH" in item for item in report.errors)


def test_assumption_mutation_resources_are_defensive_copies() -> None:
    first = assumption_mutation_manifest()
    mutations = first["mutations"]
    assert isinstance(mutations, list)
    mutations.clear()

    second = assumption_mutation_manifest()
    second_mutations = second["mutations"]
    assert isinstance(second_mutations, list)
    assert len(second_mutations) == 22
