"""Tests for deterministic E1 executable-semantics artifact compilation."""

from pathlib import Path

import pytest

from csd_foundry.empirical.e1 import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    E1ArtifactError,
    compile_e1_foundry_artifacts,
    e1_task_format_digest,
    load_artifact_records,
    validate_e1_foundry_artifacts,
    write_e1_foundry_artifacts,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import load_json_text

_SOURCE_COMMIT = "2eb623a2cc2e1984af198a15be600d019bb91416"
_SELECTION_RELEASE = "e1-candidate/1"
_ARTIFACT_RELEASE = "e1-foundry-artifacts/1"


def _selection():
    return compile_e1_experiment_contract(
        SCENARIOS.values(),
        release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def _bundle():
    return compile_e1_foundry_artifacts(
        SCENARIOS,
        _selection(),
        release=_ARTIFACT_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )


def test_compiler_materializes_exact_selected_training_and_development_membership() -> None:
    bundle = _bundle()

    assert len(bundle.training_scenario_ids) == 14
    assert len(bundle.development_scenario_ids) == 4
    assert bundle.development_family_count == 4
    assert set(bundle.training_scenario_ids).isdisjoint(bundle.development_scenario_ids)
    assert {"H-01", "L-01", "M-15"}.isdisjoint(
        {*bundle.training_scenario_ids, *bundle.development_scenario_ids}
    )
    assert "M-03" in bundle.training_scenario_ids

    expected_training_records = sum(
        len(SCENARIOS[scenario_id].cases) for scenario_id in bundle.training_scenario_ids
    )
    expected_development_records = sum(
        len(SCENARIOS[scenario_id].cases) for scenario_id in bundle.development_scenario_ids
    )
    assert bundle.training_record_count == expected_training_records
    assert bundle.development_record_count == expected_development_records


def test_compiler_is_byte_identical_and_role_digests_are_distinct() -> None:
    first = _bundle()
    second = _bundle()

    assert first == second
    assert first.task_format_digest == e1_task_format_digest()
    assert tuple((item.path, item.content) for item in first.files) == tuple(
        (item.path, item.content) for item in second.files
    )

    role_paths = (
        "foundry_train.jsonl",
        "foundry_curriculum_manifest.json",
        "development_evaluation.jsonl",
        "development_evaluation_manifest.json",
        "executable_oracle_evidence.json",
        "independent_verification_evidence.json",
    )
    role_digests = tuple(first.file(path).sha256 for path in role_paths)
    assert len(role_digests) == len(set(role_digests))


def test_task_records_bind_executable_and_independent_receipts() -> None:
    bundle = _bundle()
    records = load_artifact_records(bundle.file("foundry_train.jsonl").content)

    assert records
    assert tuple(str(record["record_id"]) for record in records) == tuple(
        sorted(str(record["record_id"]) for record in records)
    )
    assert all(record["label_authority"] == "executable_semantics" for record in records)
    assert all(record["task_format_digest"] == bundle.task_format_digest for record in records)
    assert all(
        record["executable_oracle_receipt_digest"]
        != record["independent_verification_receipt_digest"]
        for record in records
    )

    m03 = next(record for record in records if record["scenario_id"] == "M-03")
    reference = m03["reference_label"]
    assert isinstance(reference, dict)
    assert reference["case_type"] == "observation"
    assert reference["acceptance"] == "accepted"


def test_evidence_receipts_cover_every_compiled_case() -> None:
    bundle = _bundle()
    total_records = bundle.training_record_count + bundle.development_record_count
    oracle = load_json_text(
        bundle.file("executable_oracle_evidence.json").content.decode("utf-8")
    )
    verification = load_json_text(
        bundle.file("independent_verification_evidence.json").content.decode("utf-8")
    )

    assert isinstance(oracle, dict)
    assert isinstance(verification, dict)
    assert oracle["case_count"] == total_records
    assert verification["case_count"] == total_records
    assert len(oracle["cases"]) == total_records
    assert len(verification["cases"]) == total_records


def test_written_bundle_reconstructs_exactly_and_tampering_fails(tmp_path: Path) -> None:
    bundle = _bundle()
    output = tmp_path / "foundry"
    write_e1_foundry_artifacts(bundle, output)

    valid = validate_e1_foundry_artifacts(
        output,
        SCENARIOS,
        _selection(),
        release=_ARTIFACT_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )
    assert valid.success
    assert not valid.errors

    training_path = output / "foundry_train.jsonl"
    training_path.write_bytes(training_path.read_bytes() + b" ")
    invalid = validate_e1_foundry_artifacts(
        output,
        SCENARIOS,
        _selection(),
        release=_ARTIFACT_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=_SOURCE_COMMIT,
    )
    assert not invalid.success
    assert any("foundry_train.jsonl" in error for error in invalid.errors)


def test_writer_rejects_nonempty_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "foundry"
    output.mkdir()
    (output / "stale.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(E1ArtifactError, match="not empty"):
        write_e1_foundry_artifacts(_bundle(), output)
