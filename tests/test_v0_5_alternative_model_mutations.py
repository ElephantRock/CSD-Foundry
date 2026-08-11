from __future__ import annotations

from csd_foundry.governance.v0_5.alternative_model_mutations import (
    evaluate_alternative_mutations,
)
from csd_foundry.governance.v0_5.resources import alternative_model_mutation_manifest


def test_alternative_model_mutation_campaign_kills_every_declared_mutation() -> None:
    report = evaluate_alternative_mutations()

    assert report.success
    assert len(report.results) == 38
    assert report.killed_count == 38
    assert report.survived_count == 0
    assert report.equivalent_count == 0
    assert report.invalid_mutation_count == 0
    assert report.unexplained_escape_count == 0
    assert report.mutation_catalog_digest == (
        "sha256:6e336fa681911fb521a4a5e5d5ead335a3c7f3ffbd64e5c5e48f3ebf6dcfc92c"
    )
    assert all(item.observed_classification == "KILLED" for item in report.results)
    assert all(item.observed_detector == item.expected_detector for item in report.results)


def test_alternative_model_mutation_report_is_byte_stable() -> None:
    first = evaluate_alternative_mutations()
    second = evaluate_alternative_mutations()

    assert first.to_dict() == second.to_dict()
    assert first.report_digest == second.report_digest
    assert first.report_digest.startswith("sha256:")
    assert len(first.report_digest) == 71


def test_alternative_model_mutation_manifest_tampering_fails_closed() -> None:
    manifest = alternative_model_mutation_manifest()
    mutations = manifest["mutations"]
    assert isinstance(mutations, list)
    first = mutations[0]
    assert isinstance(first, dict)
    first["expected_detector"] = "USE_ALLOWED"

    report = evaluate_alternative_mutations(manifest=manifest)

    assert not report.success
    assert any(
        "ALTERNATIVE_MODEL_MUTATION_CATALOG_DIGEST_MISMATCH" in item for item in report.errors
    )


def test_alternative_model_mutation_resources_are_defensive_copies() -> None:
    first = alternative_model_mutation_manifest()
    mutations = first["mutations"]
    assert isinstance(mutations, list)
    mutations.clear()

    second = alternative_model_mutation_manifest()
    second_mutations = second["mutations"]
    assert isinstance(second_mutations, list)
    assert len(second_mutations) == 38
