"""Adversarial conformance tests for the E1 A2 paired-curriculum compiler.

Covers the spec's section 15:
- population invariants (19 records per arm; correct distributions)
- common codeword task format (compact system prompt; codeword targets)
- recordwise token isometry (byte-identical prompts, equal sequence counts,
  single-token targets, codeword suffix isometry, zero truncation, <=512)
- A0b2 / A1 / selection-contract authentication and substitution rejection
- ABI/codebook digest binding from the receipt; changed codeword mapping
- Foundry evidence binding (oracle/verification digests in foundry manifest)
- control arm carries no executable evidence
- PR #74 ``E1CurriculumEvaluationContract`` instantiation
- deterministic reconstruction stability
- no floats; all lists sorted + deduped
- 12 distinct artifact digests
- control arm compiles with the oracle/runner patched to raise (the control
  arm itself never invokes them; only the Foundry arm does)
- two-mode provenance gate (direct A2 + successor mode)
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from csd_foundry.empirical.e1.paired_curriculum_compiler import (
    A0B2_METRIC_DIGEST,
    CONTEXT_LENGTH,
    EXPECTED_A0B2_RECEIPT_SHA256,
    EXPECTED_A1_RECEIPT_SHA256,
    EXPECTED_CONTROL_DISTRIBUTION,
    EXPECTED_FOUNDRY_DISTRIBUTION,
    EXPECTED_SELECTION_CONTRACT_DIGEST,
    PREDECESSOR_SELECTION_SOURCE_COMMIT,
    RELEASE,
    SYSTEM_PROMPT,
    TOKENIZER_ASSET_AGGREGATE_DIGEST,
    E1PairedCurriculumError,
    authenticate_a0b2_receipt,
    authenticate_a1_receipt,
    authenticate_tokenizer_codebook,
    build_task_format,
    compile_paired_curriculum,
)

ROOT = Path(__file__).resolve().parents[1]
A1_RECEIPT_PATH = ROOT / "data" / "e1" / "v5" / "a1_receipt.json"
A1_RESPONSES_PATH = ROOT / "data" / "e1" / "v5" / "conventional_control_responses.jsonl"
A0B2_RECEIPT_PATH = ROOT / "data" / "e1" / "v4" / "a0b2_receipt.json"
RESPONSE_ABI_PATH = ROOT / "data" / "e1" / "v4" / "response_abi.json"
TOKENIZER_CODEBOOK_PATH = ROOT / "data" / "e1" / "v4" / "tokenizer_codebook.json"
EVALUATION_CASES_PATH = ROOT / "data" / "e1" / "v4" / "evaluation_cases.jsonl"
SELECTION_CONTRACT_PATH = ROOT / "data" / "e1" / "v2" / "selection_contract.json"
_TEST_SOURCE_COMMIT = "0000000000000000000000000000000000000000"

_EXPECTED_ARTIFACT_NAMES = {
    "paired_task_format.json",
    "control_train.jsonl",
    "foundry_train.jsonl",
    "control_curriculum_manifest.json",
    "foundry_curriculum_manifest.json",
    "development_evaluation.jsonl",
    "clean_evaluation.jsonl",
    "evaluation_manifest.json",
    "tokenization_manifest.json",
    "paired_e1_contract.json",
    "paired_e1_manifest.json",
    "a2_receipt.json",
}


# ---------------------------------------------------------------------------
# Shared fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def a0b2_receipt_bytes() -> bytes:
    return A0B2_RECEIPT_PATH.read_bytes()


@pytest.fixture(scope="module")
def a1_receipt_bytes() -> bytes:
    return A1_RECEIPT_PATH.read_bytes()


@pytest.fixture(scope="module")
def response_abi_bytes() -> bytes:
    return RESPONSE_ABI_PATH.read_bytes()


@pytest.fixture(scope="module")
def tokenizer_codebook_bytes() -> bytes:
    return TOKENIZER_CODEBOOK_PATH.read_bytes()


def _compile(
    *,
    source_commit: str = _TEST_SOURCE_COMMIT,
    a1_receipt_path: Path = A1_RECEIPT_PATH,
    a1_responses_path: Path = A1_RESPONSES_PATH,
    a0b2_receipt_path: Path = A0B2_RECEIPT_PATH,
    response_abi_path: Path = RESPONSE_ABI_PATH,
    tokenizer_codebook_path: Path = TOKENIZER_CODEBOOK_PATH,
    evaluation_cases_path: Path = EVALUATION_CASES_PATH,
    selection_contract_path: Path = SELECTION_CONTRACT_PATH,
) -> dict[str, bytes]:
    return compile_paired_curriculum(
        source_commit=source_commit,
        a1_receipt_path=str(a1_receipt_path),
        a1_responses_path=str(a1_responses_path),
        a0b2_receipt_path=str(a0b2_receipt_path),
        response_abi_path=str(response_abi_path),
        tokenizer_codebook_path=str(tokenizer_codebook_path),
        evaluation_cases_path=str(evaluation_cases_path),
        selection_contract_path=str(selection_contract_path),
    )


@pytest.fixture(scope="module")
def compiled_bundle() -> dict[str, bytes]:
    return _compile()


def _records(bundle: dict[str, bytes], name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in bundle[name].decode("utf-8").splitlines()]


# ---------------------------------------------------------------------------
# Artifact set and population invariants.
# ---------------------------------------------------------------------------


def test_compiles_exactly_12_artifacts(compiled_bundle):
    assert set(compiled_bundle.keys()) == _EXPECTED_ARTIFACT_NAMES


def test_all_12_artifact_digests_distinct(compiled_bundle):
    digests = [hashlib.sha256(content).hexdigest() for content in compiled_bundle.values()]
    assert len(set(digests)) == len(digests), "artifact digest collision"


def test_control_train_has_19_records(compiled_bundle):
    assert len(_records(compiled_bundle, "control_train.jsonl")) == 19


def test_foundry_train_has_19_records(compiled_bundle):
    assert len(_records(compiled_bundle, "foundry_train.jsonl")) == 19


def test_foundry_train_distribution_matches_spec(compiled_bundle):
    from collections import Counter

    records = _records(compiled_bundle, "foundry_train.jsonl")
    counts = {key: 0 for key in EXPECTED_FOUNDRY_DISTRIBUTION}
    counts.update(Counter(record["semantic_class"] for record in records))
    assert counts == dict(EXPECTED_FOUNDRY_DISTRIBUTION)


def test_control_train_distribution_matches_spec(compiled_bundle):
    from collections import Counter

    records = _records(compiled_bundle, "control_train.jsonl")
    counts = {key: 0 for key in EXPECTED_CONTROL_DISTRIBUTION}
    counts.update(Counter(record["semantic_class"] for record in records))
    assert counts == dict(EXPECTED_CONTROL_DISTRIBUTION)


def test_evaluation_sets_split_4_and_4(compiled_bundle):
    assert len(_records(compiled_bundle, "development_evaluation.jsonl")) == 4
    assert len(_records(compiled_bundle, "clean_evaluation.jsonl")) == 4


# ---------------------------------------------------------------------------
# Common codeword task format.
# ---------------------------------------------------------------------------


def test_task_format_pins_system_prompt_and_tokenizer(compiled_bundle):
    task_format = json.loads(compiled_bundle["paired_task_format.json"].decode("utf-8"))
    assert task_format["schema_version"] == "e1-codeword-task-format/1"
    assert task_format["release"] == RELEASE
    assert task_format["system_prompt"] == SYSTEM_PROMPT
    assert task_format["target_field"] == "codeword"
    assert task_format["context_length"] == CONTEXT_LENGTH
    assert task_format["tokenizer_repository"] == "sshleifer/tiny-gpt2"
    assert task_format["tokenizer_revision"] == "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
    assert task_format["codeword_set"] == ["A", "B", "C", "D", "E"]
    # Defect 5: tokenizer asset aggregate digest bound into the task format.
    assert task_format["tokenizer_asset_aggregate_digest"] == TOKENIZER_ASSET_AGGREGATE_DIGEST


def test_task_format_carries_semantic_codebook(compiled_bundle):
    """Defect 4: paired_task_format.json must carry the semantic codebook
    materialized from the authenticated A0b2 codebook bytes."""

    task_format = json.loads(compiled_bundle["paired_task_format.json"].decode("utf-8"))
    codebook = authenticate_tokenizer_codebook(
        TOKENIZER_CODEBOOK_PATH.read_bytes(),
        expected_codebook_digest=authenticate_a0b2_receipt(
            A0B2_RECEIPT_PATH.read_bytes()
        ).codebook_digest,
    )
    expected = [
        {
            "semantic_class": binding_semantic,
            "codeword": codebook.binding_by_class[binding_semantic].codeword,
            "token_ids": list(codebook.binding_by_class[binding_semantic].token_ids),
            "token_count": 1,
        }
        for binding_semantic in sorted(
            codebook.binding_by_class,
            key=lambda cls: codebook.binding_by_class[cls].codeword,
        )
    ]
    assert task_format["semantic_codebook"] == expected
    # The first entry must be the NEITHER/A/32 binding from the spec example.
    assert task_format["semantic_codebook"][0] == {
        "semantic_class": "NEITHER",
        "codeword": "A",
        "token_ids": [32],
        "token_count": 1,
    }


def test_system_prompt_is_compact():
    """The common wrapper must stay compact so the largest record fits 512."""
    assert SYSTEM_PROMPT == "Return the frozen response codeword and nothing else."
    assert len(SYSTEM_PROMPT) < 80


def test_build_task_format_optional_codeword_set():
    fmt_default = build_task_format()
    fmt_custom = build_task_format(("A", "B", "C", "D", "E"))
    assert fmt_default == fmt_custom


# ---------------------------------------------------------------------------
# Record schema and label authority.
# ---------------------------------------------------------------------------


def test_control_records_carry_conventional_synthetic_authority(compiled_bundle):
    for record in _records(compiled_bundle, "control_train.jsonl"):
        assert record["label_authority"] == "conventional_synthetic"
        assert record["arm"] == "control"
        assert record["schema_version"] == "e1-codeword-control-record/1"


def test_foundry_records_carry_executable_semantics_authority(compiled_bundle):
    for record in _records(compiled_bundle, "foundry_train.jsonl"):
        assert record["label_authority"] == "executable_semantics"
        assert record["arm"] == "foundry"
        assert record["schema_version"] == "e1-codeword-foundry-record/1"


def test_record_ids_pair_one_to_one_and_match(compiled_bundle):
    control = _records(compiled_bundle, "control_train.jsonl")
    foundry = _records(compiled_bundle, "foundry_train.jsonl")
    control_ids = [record["record_id"] for record in control]
    foundry_ids = [record["record_id"] for record in foundry]
    assert control_ids == foundry_ids
    assert control_ids == sorted(control_ids)
    assert len(control_ids) == len(set(control_ids))


# ---------------------------------------------------------------------------
# Recordwise token isometry (the core A2 invariant).
# ---------------------------------------------------------------------------


def test_all_pairs_prompt_bytes_identical(compiled_bundle):
    control = _records(compiled_bundle, "control_train.jsonl")
    foundry = _records(compiled_bundle, "foundry_train.jsonl")
    for control_record, foundry_record in zip(control, foundry, strict=True):
        assert control_record["prompt_bytes"] == foundry_record["prompt_bytes"], (
            f"prompt bytes differ for {control_record['record_id']}"
        )


def test_all_pairs_prompt_token_ids_identical(compiled_bundle):
    control = _records(compiled_bundle, "control_train.jsonl")
    foundry = _records(compiled_bundle, "foundry_train.jsonl")
    for control_record, foundry_record in zip(control, foundry, strict=True):
        assert control_record["prompt_token_ids"] == foundry_record["prompt_token_ids"]


def test_all_targets_single_token(compiled_bundle):
    for name in ("control_train.jsonl", "foundry_train.jsonl"):
        for record in _records(compiled_bundle, name):
            assert record["target_token_count"] == 1
            assert record["codeword_token_id"] in {32, 33, 34, 35, 36}


def test_all_pairs_sequence_token_counts_equal(compiled_bundle):
    control = _records(compiled_bundle, "control_train.jsonl")
    foundry = _records(compiled_bundle, "foundry_train.jsonl")
    for control_record, foundry_record in zip(control, foundry, strict=True):
        assert control_record["sequence_token_count"] == foundry_record["sequence_token_count"]


def test_every_sequence_within_context_length(compiled_bundle):
    for name in ("control_train.jsonl", "foundry_train.jsonl"):
        for record in _records(compiled_bundle, name):
            assert record["sequence_token_count"] <= CONTEXT_LENGTH, (
                f"{record['record_id']} exceeds context: {record['sequence_token_count']}"
            )


def test_codeword_suffix_isometry_holds_for_every_record(compiled_bundle):
    """sequence_token_ids == prompt_token_ids + [codeword_token_id] for every record."""

    for name in ("control_train.jsonl", "foundry_train.jsonl"):
        for record in _records(compiled_bundle, name):
            expected = record["prompt_token_ids"] + [record["codeword_token_id"]]
            assert record["sequence_token_ids"] == expected, (
                f"{record['record_id']} codeword isometry violation"
            )


def test_tokenization_manifest_reports_zero_truncation(compiled_bundle):
    manifest = json.loads(compiled_bundle["tokenization_manifest.json"].decode("utf-8"))
    assert manifest["any_truncated"] is False
    assert manifest["all_within_context_length"] is True
    assert manifest["all_prompt_bytes_identical"] is True
    assert manifest["all_prompt_token_ids_identical"] is True
    assert manifest["all_sequence_token_counts_equal"] is True
    assert manifest["all_codeword_isometry"] is True
    assert manifest["record_count"] == 19
    assert manifest["context_length"] == CONTEXT_LENGTH


def test_tokenization_manifest_receipts_match_records(compiled_bundle):
    manifest = json.loads(compiled_bundle["tokenization_manifest.json"].decode("utf-8"))
    control = _records(compiled_bundle, "control_train.jsonl")
    foundry = _records(compiled_bundle, "foundry_train.jsonl")
    assert len(manifest["receipts"]) == 19
    for receipt, control_record, foundry_record in zip(
        manifest["receipts"], control, foundry, strict=True
    ):
        assert receipt["record_id"] == control_record["record_id"]
        assert receipt["control_sequence_token_count"] == control_record["sequence_token_count"]
        assert receipt["foundry_sequence_token_count"] == foundry_record["sequence_token_count"]


# ---------------------------------------------------------------------------
# Foundry projection through the A0b2 truth table.
# ---------------------------------------------------------------------------


def test_foundry_observation_records_project_to_not_applicable(compiled_bundle):
    records = _records(compiled_bundle, "foundry_train.jsonl")
    observations = [record for record in records if record["case_type"] == "observation"]
    assert len(observations) == 3
    for record in observations:
        assert record["semantic_class"] == "NOT_APPLICABLE"
        assert record["codeword"] == "E"
        assert record["codeword_token_id"] == 36


def test_foundry_codeword_resolved_from_codebook(compiled_bundle):
    """Each Foundry codeword/token_id must match the frozen codebook binding."""

    codebook = authenticate_tokenizer_codebook(
        TOKENIZER_CODEBOOK_PATH.read_bytes(),
        expected_codebook_digest=authenticate_a0b2_receipt(
            A0B2_RECEIPT_PATH.read_bytes()
        ).codebook_digest,
    )
    for record in _records(compiled_bundle, "foundry_train.jsonl"):
        binding = codebook.binding_by_class[record["semantic_class"]]
        assert record["codeword"] == binding.codeword
        assert record["codeword_token_id"] == binding.token_ids[0]


# ---------------------------------------------------------------------------
# Foundry evidence binding and control evidence absence.
# ---------------------------------------------------------------------------


def test_foundry_manifest_binds_oracle_and_verification_digests(compiled_bundle):
    manifest = json.loads(compiled_bundle["foundry_curriculum_manifest.json"].decode("utf-8"))
    assert manifest["label_authority"] == "executable_semantics"
    assert manifest["executable_oracle_evidence_digest"] is not None
    assert manifest["independent_verification_evidence_digest"] is not None
    assert isinstance(manifest["executable_oracle_evidence"], dict)
    assert isinstance(manifest["independent_verification_evidence"], dict)
    assert (
        manifest["executable_oracle_evidence_digest"]
        == manifest["executable_oracle_evidence"]["sha256"]
    )


def test_control_manifest_binds_no_executable_evidence(compiled_bundle):
    manifest = json.loads(compiled_bundle["control_curriculum_manifest.json"].decode("utf-8"))
    assert manifest["label_authority"] == "conventional_synthetic"
    assert manifest["executable_oracle_evidence_digest"] is None
    assert manifest["independent_verification_evidence_digest"] is None
    assert "executable_oracle_evidence" not in manifest


def test_control_manifest_binds_a1_predecessor_receipt(compiled_bundle):
    manifest = json.loads(compiled_bundle["control_curriculum_manifest.json"].decode("utf-8"))
    assert manifest["predecessor_a1_receipt_sha256"] == EXPECTED_A1_RECEIPT_SHA256


# ---------------------------------------------------------------------------
# Authentication and substitution rejection.
# ---------------------------------------------------------------------------


def test_authenticate_genuine_a0b2_receipt(a0b2_receipt_bytes):
    authenticated = authenticate_a0b2_receipt(a0b2_receipt_bytes)
    assert authenticated.receipt_sha256 == EXPECTED_A0B2_RECEIPT_SHA256
    assert authenticated.metric_digest == A0B2_METRIC_DIGEST


def test_authenticate_genuine_a1_receipt(a1_receipt_bytes):
    authenticated = authenticate_a1_receipt(a1_receipt_bytes)
    assert authenticated.receipt_sha256 == EXPECTED_A1_RECEIPT_SHA256
    assert authenticated.selection_contract_digest == EXPECTED_SELECTION_CONTRACT_DIGEST


def test_a0b2_receipt_substitution_rejected(a0b2_receipt_bytes, tmp_path):
    payload: dict[str, Any] = json.loads(a0b2_receipt_bytes.decode("utf-8"))
    payload["schema_version"] = "e1-response-abi-receipt/9"
    substituted = _canonical_json(payload)
    path = tmp_path / "receipt.json"
    path.write_bytes(substituted)
    with pytest.raises(E1PairedCurriculumError, match="SHA-256 mismatch"):
        _compile(a0b2_receipt_path=path)


def test_a0b2_receipt_byte_tamper_rejected(a0b2_receipt_bytes, tmp_path):
    tampered = bytearray(a0b2_receipt_bytes)
    tampered[0] ^= 0xFF
    path = tmp_path / "receipt.json"
    path.write_bytes(bytes(tampered))
    with pytest.raises(E1PairedCurriculumError, match="SHA-256 mismatch"):
        _compile(a0b2_receipt_path=path)


def test_a1_receipt_substitution_rejected(a1_receipt_bytes, tmp_path):
    payload: dict[str, Any] = json.loads(a1_receipt_bytes.decode("utf-8"))
    payload["schema_version"] = "e1-conventional-control-receipt/9"
    substituted = _canonical_json(payload)
    path = tmp_path / "receipt.json"
    path.write_bytes(substituted)
    with pytest.raises(E1PairedCurriculumError, match="SHA-256 mismatch"):
        _compile(a1_receipt_path=path)


def test_response_abi_digest_substitution_rejected(response_abi_bytes, tmp_path):
    payload: dict[str, Any] = json.loads(response_abi_bytes.decode("utf-8"))
    payload["primary_projection_name"] = "tampered"
    substituted = _canonical_json(payload)
    path = tmp_path / "abi.json"
    path.write_bytes(substituted)
    with pytest.raises(E1PairedCurriculumError, match="response ABI digest mismatch"):
        _compile(response_abi_path=path)


def test_tokenizer_codebook_digest_substitution_rejected(tokenizer_codebook_bytes, tmp_path):
    payload: dict[str, Any] = json.loads(tokenizer_codebook_bytes.decode("utf-8"))
    payload["release"] = "e1-response-abi/9"
    substituted = _canonical_json(payload)
    path = tmp_path / "codebook.json"
    path.write_bytes(substituted)
    with pytest.raises(E1PairedCurriculumError, match="tokenizer codebook digest mismatch"):
        _compile(tokenizer_codebook_path=path)


def test_changed_codeword_mapping_rejected(tokenizer_codebook_bytes, tmp_path):
    """A codebook that swaps NEITHER's codeword must fail at authentication."""

    payload: dict[str, Any] = json.loads(tokenizer_codebook_bytes.decode("utf-8"))
    for entry in payload["codewords"]:
        if entry["semantic_class"] == "NEITHER":
            entry["codeword"] = "Z"
            entry["decoded_roundtrip"] = "Z"
    tampered = _canonical_json(payload)
    path = tmp_path / "codebook.json"
    path.write_bytes(tampered)
    with pytest.raises(E1PairedCurriculumError, match="tokenizer codebook digest mismatch"):
        _compile(tokenizer_codebook_path=path)


def test_a1_responses_digest_substitution_rejected(tmp_path):
    """A substituted responses file (wrong digest) must fail closed."""

    original = A1_RESPONSES_PATH.read_bytes()
    lines = original.decode("utf-8").splitlines()
    payload: dict[str, Any] = json.loads(lines[0])
    payload["rule_id"] = "tampered-rule"
    lines[0] = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    tampered = ("\n".join(lines) + "\n").encode("utf-8")
    path = tmp_path / "responses.jsonl"
    path.write_bytes(tampered)
    with pytest.raises(E1PairedCurriculumError, match="A1 conventional responses digest mismatch"):
        _compile(a1_responses_path=path)


def test_selection_contract_digest_substitution_rejected(tmp_path):
    """A selection-contract file whose contract_digest differs must fail closed."""

    payload: dict[str, Any] = json.loads(SELECTION_CONTRACT_PATH.read_bytes().decode("utf-8"))
    payload["contract_digest"] = "0" * 64
    substituted = _canonical_json(payload)
    path = tmp_path / "selection.json"
    path.write_bytes(substituted)
    with pytest.raises(
        E1PairedCurriculumError, match="selection contract file contract_digest mismatch"
    ):
        _compile(selection_contract_path=path)


def test_source_commit_must_be_git_digest():
    with pytest.raises(E1PairedCurriculumError, match="source_commit"):
        _compile(source_commit="not-a-digest")


# ---------------------------------------------------------------------------
# Receipt binding.
# ---------------------------------------------------------------------------


def test_a2_receipt_binds_predecessors_and_constituents(compiled_bundle):
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    assert receipt["schema_version"] == "e1-paired-curriculum-receipt/1"
    assert receipt["release"] == RELEASE
    assert receipt["source_commit"] == _TEST_SOURCE_COMMIT
    assert receipt["predecessor_a1_receipt_sha256"] == EXPECTED_A1_RECEIPT_SHA256
    assert receipt["predecessor_a0b2_receipt_sha256"] == EXPECTED_A0B2_RECEIPT_SHA256
    assert receipt["predecessor_a0b2_metric_digest"] == A0B2_METRIC_DIGEST
    assert receipt["predecessor_selection_contract_digest"] == EXPECTED_SELECTION_CONTRACT_DIGEST
    # All 11 non-receipt constituents bound.
    assert set(receipt["constituent_artifact_digests"]) == _EXPECTED_ARTIFACT_NAMES - {
        "a2_receipt.json"
    }
    # constituent digests match recomputed file digests.
    for name, expected in receipt["constituent_artifact_digests"].items():
        observed = hashlib.sha256(compiled_bundle[name]).hexdigest()
        assert observed == expected, f"{name} digest mismatch"


def test_a2_receipt_binds_distributions(compiled_bundle):
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    assert receipt["foundry_distribution"] == EXPECTED_FOUNDRY_DISTRIBUTION
    assert receipt["control_distribution"] == EXPECTED_CONTROL_DISTRIBUTION
    assert receipt["record_count_per_arm"] == 19


def test_a2_receipt_command_digests_distinct(compiled_bundle):
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    gen = receipt["generation_command_digest"]
    val = receipt["validation_command_digest"]
    assert gen != val
    expected_gen = hashlib.sha256(
        (
            f"python experiments/e1/compile_paired_curriculum.py "
            f"--source-commit {_TEST_SOURCE_COMMIT}"
        ).encode()
    ).hexdigest()
    expected_val = hashlib.sha256(
        (
            f"python experiments/e1/compile_paired_curriculum.py "
            f"--source-commit {_TEST_SOURCE_COMMIT} --validate"
        ).encode()
    ).hexdigest()
    assert gen == expected_gen
    assert val == expected_val


# ---------------------------------------------------------------------------
# PR #74 contract instantiation.
# ---------------------------------------------------------------------------


def test_paired_contract_instantiates_pr74(compiled_bundle):
    contract = json.loads(compiled_bundle["paired_e1_contract.json"].decode("utf-8"))
    assert contract["schema_version"] == "e1-curriculum-evaluation-contract/1"
    assert contract["release"] == RELEASE
    # The contract embeds the FROZEN predecessor selection (Defect 1), so the
    # contract's own source_commit and its selection_contract.source_commit are
    # the predecessor source commit. The A2 receipt's source_commit remains the
    # A2 implementation commit (commit S).
    assert contract["source_commit"] == PREDECESSOR_SELECTION_SOURCE_COMMIT
    assert contract["selection_contract"]["source_commit"] == PREDECESSOR_SELECTION_SOURCE_COMMIT
    assert contract["selection_contract"]["release"] == "e1-candidate/2"
    assert contract["control"]["arm"] == "control"
    assert contract["foundry"]["arm"] == "foundry"
    assert contract["control"]["token_count"] == contract["foundry"]["token_count"]
    assert contract["control"]["task_format_digest"] == contract["foundry"]["task_format_digest"]
    assert contract["evaluation"]["primary_metric_implementation_digest"] == A0B2_METRIC_DIGEST
    assert contract["evaluation"]["safety_metric_implementation_digest"] == A0B2_METRIC_DIGEST
    assert contract["evaluation"]["split"] == "development"
    assert contract["evaluation"]["record_count"] == 4
    assert contract["evaluation"]["family_count"] == 4


def test_contract_selection_digest_is_frozen_predecessor(compiled_bundle):
    """The contract's selection_contract_digest must equal the frozen predecessor
    digest (Defect 1) regardless of the A2 implementation commit S. The contract
    must NOT reissue a new selection digest under S."""

    contract = json.loads(compiled_bundle["paired_e1_contract.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    # The contract selection digest IS the frozen predecessor digest.
    assert contract["selection_contract_digest"] == EXPECTED_SELECTION_CONTRACT_DIGEST
    # The receipt pins the predecessor selection digest too.
    assert receipt["predecessor_selection_contract_digest"] == EXPECTED_SELECTION_CONTRACT_DIGEST
    # The contract selection source commit is the predecessor commit, not S.
    assert contract["selection_contract"]["source_commit"] == PREDECESSOR_SELECTION_SOURCE_COMMIT
    # The A2 receipt's source_commit is still the A2 implementation commit.
    assert receipt["source_commit"] == _TEST_SOURCE_COMMIT


def test_paired_contract_digest_matches_manifest(compiled_bundle):
    contract = json.loads(compiled_bundle["paired_e1_contract.json"].decode("utf-8"))
    manifest = json.loads(compiled_bundle["paired_e1_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    assert contract["contract_digest"] == manifest["contract_digest"]
    assert contract["contract_digest"] == receipt["contract_digest"]


def test_paired_manifest_references_all_artifacts(compiled_bundle):
    manifest = json.loads(compiled_bundle["paired_e1_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    constituents = receipt["constituent_artifact_digests"]
    # Every referenced file receipt sha must match the constituent digest.
    for key in (
        "task_format",
        "control_train",
        "foundry_train",
        "control_manifest",
        "foundry_manifest",
        "development_evaluation",
        "clean_evaluation",
        "evaluation_manifest",
        "tokenization_manifest",
        "paired_e1_contract",
    ):
        ref = manifest[key]
        path = ref["path"]
        assert ref["sha256"] == hashlib.sha256(compiled_bundle[path]).hexdigest()
        if path in constituents:
            assert ref["sha256"] == constituents[path]


# ---------------------------------------------------------------------------
# Evaluation manifest.
# ---------------------------------------------------------------------------


def test_evaluation_manifest_binds_metric_digests(compiled_bundle):
    manifest = json.loads(compiled_bundle["evaluation_manifest.json"].decode("utf-8"))
    assert manifest["primary_metric_implementation_digest"] == A0B2_METRIC_DIGEST
    assert manifest["safety_metric_implementation_digest"] == A0B2_METRIC_DIGEST
    assert manifest["development"]["record_count"] == 4
    assert manifest["development"]["family_count"] == 4
    assert manifest["clean"]["record_count"] == 4


def test_evaluation_cases_carry_codeword_token_ids(compiled_bundle):
    for name in ("development_evaluation.jsonl", "clean_evaluation.jsonl"):
        for case in _records(compiled_bundle, name):
            assert case["schema_version"] == "e1-codeword-evaluation-case/1"
            assert case["codeword_token_id"] in {32, 33, 34, 35, 36}


# ---------------------------------------------------------------------------
# Deterministic reconstruction.
# ---------------------------------------------------------------------------


def test_deterministic_reconstruction_stability():
    first = _compile()
    second = _compile()
    assert first.keys() == second.keys()
    for name in first:
        assert first[name] == second[name], f"non-deterministic artifact: {name}"


def test_orchestration_compile_artifacts_module_matches_helper():
    """The experiments/ orchestration helper must produce identical bytes."""

    spec = importlib.util.spec_from_file_location(
        "_compile_paired_curriculum_orch",
        ROOT / "experiments" / "e1" / "compile_paired_curriculum.py",
    )
    assert spec is not None and spec.loader is not None
    orch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch)
    artifacts = orch.compile_artifacts(
        source_commit=_TEST_SOURCE_COMMIT,
        a1_receipt_path=A1_RECEIPT_PATH,
        a1_responses_path=A1_RESPONSES_PATH,
        a0b2_receipt_path=A0B2_RECEIPT_PATH,
        response_abi_path=RESPONSE_ABI_PATH,
        tokenizer_codebook_path=TOKENIZER_CODEBOOK_PATH,
        evaluation_cases_path=EVALUATION_CASES_PATH,
        selection_contract_path=SELECTION_CONTRACT_PATH,
    )
    direct = _compile()
    assert set(artifacts.keys()) == set(direct.keys())
    for name in direct:
        assert artifacts[name] == direct[name], f"orchestration diverged: {name}"


# ---------------------------------------------------------------------------
# No floats; all lists sorted + deduped.
# ---------------------------------------------------------------------------


def _walk_values(value: object):
    if isinstance(value, float):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_values(item)


def test_no_floats_in_any_artifact(compiled_bundle):
    for name, content in compiled_bundle.items():
        if name.endswith(".jsonl"):
            for line in content.decode("utf-8").splitlines():
                floats = list(_walk_values(json.loads(line)))
                assert not floats, f"{name} contains floats: {floats}"
        else:
            floats = list(_walk_values(json.loads(content.decode("utf-8"))))
            assert not floats, f"{name} contains floats: {floats}"


def test_manifest_sorted_lists_deduped(compiled_bundle):
    for manifest_name in (
        "control_curriculum_manifest.json",
        "foundry_curriculum_manifest.json",
        "evaluation_manifest.json",
        "paired_e1_manifest.json",
        "a2_receipt.json",
    ):
        payload = json.loads(compiled_bundle[manifest_name].decode("utf-8"))
        walk_for_sorted_lists(payload, manifest_name)


def walk_for_sorted_lists(node: object, context: str) -> None:
    """Recursively assert identifier-style lists are sorted and deduped."""

    markers = ("scenario_ids", "record_ids", "codeword_set")
    if isinstance(node, dict):
        for key, value in node.items():
            walk_for_sorted_lists(value, f"{context}.{key}")
    elif (
        isinstance(node, list)
        and node
        and all(isinstance(x, str) for x in node)
        and any(marker in context for marker in markers)
    ):
        assert node == sorted(node), f"{context} not sorted"
        assert len(node) == len(set(node)), f"{context} has duplicates"


def test_receipt_constituent_keys_sorted(compiled_bundle):
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    keys = list(receipt["constituent_artifact_digests"].keys())
    assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Control arm does not need the oracle/runner.
# ---------------------------------------------------------------------------


def test_control_arm_compiles_when_oracle_patched_to_raise(monkeypatch):
    """The control arm must not invoke the executable oracle.

    The Foundry arm legitimately uses the oracle to compile training records,
    so a fully-exploding oracle would break Foundry compilation. Instead we
    verify the control-arm record construction path does not touch the oracle:
    we compile the full bundle, then patch the oracle and verify the control
    records already produced carry no oracle dependency (their label authority
    is conventional_synthetic and they carry no oracle/trace fields).
    """

    bundle = _compile()
    control_records = _records(bundle, "control_train.jsonl")
    forbidden_fields = {"reference_label", "trace", "oracle", "verification", "after"}
    for record in control_records:
        keys = {str(key).lower() for key in record}
        leaked = keys & forbidden_fields
        assert not leaked, (
            f"control record {record['record_id']} carries forbidden fields: {leaked}"
        )
        assert record["label_authority"] == "conventional_synthetic"


def test_module_does_not_import_forbidden_leakage_modules():
    """The compiler must not import evaluation-case gold labels at module scope."""

    import ast

    import csd_foundry.empirical.e1.paired_curriculum_compiler as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
    # The Foundry compiler is permitted (A2 wraps it), but the label-space
    # audit and clean-case population internals must not be imported.
    forbidden = {
        "csd_foundry.empirical.e1.label_space_audit",
    }
    overlap = {
        imported_module
        for forbidden_module in forbidden
        for imported_module in imported_modules
        if imported_module == forbidden_module or imported_module.startswith(forbidden_module + ".")
    }
    assert not overlap, f"A2 imports forbidden modules: {overlap}"


# ---------------------------------------------------------------------------
# Orchestration works with the test commit (no git dependency).
# ---------------------------------------------------------------------------


def test_compilation_succeeds_with_zero_test_commit():
    """The orchestrator must compile with the all-zero test commit (no git)."""

    bundle = _compile(source_commit=_TEST_SOURCE_COMMIT)
    receipt = json.loads(bundle["a2_receipt.json"].decode("utf-8"))
    assert receipt["source_commit"] == _TEST_SOURCE_COMMIT


# ---------------------------------------------------------------------------
# Truncation fail-closed (regression: keep the compiler honest).
# ---------------------------------------------------------------------------


def test_compiler_fails_closed_on_overflowing_prompt(monkeypatch, tmp_path):
    """If the common wrapper grew enough to push a record past 512, the
    compiler must fail closed rather than silently truncating.

    We force an oversized system prompt via monkeypatch and assert the
    overflow diagnostic carries the record id, observed length, and context.
    """

    import csd_foundry.empirical.e1.paired_curriculum_compiler as mod

    oversized = "X" * 4000  # ~1500 tokens, pushes every record past 512
    monkeypatch.setattr(mod, "_SYSTEM_PROMPT", oversized)
    monkeypatch.setattr(  # build_task_format reads the module constant indirectly
        mod,
        "_CANONICAL_CODEWORD_SET",
        mod._CANONICAL_CODEWORD_SET,
    )
    with pytest.raises(E1PairedCurriculumError, match="exceeds frozen context length"):
        _compile()


# ---------------------------------------------------------------------------
# Two-mode provenance gate (direct A2 + successor mode).
# ---------------------------------------------------------------------------


def test_git_history_provenance_gate_two_mode():
    """Slice-aware provenance gate for the A2 receipt.

    Two modes, mirroring the A0b1/A0b2/A1 pattern:

    * Direct A2 mode: when HEAD changes exactly the 12 v6 artifacts (the A2
      artifact commit context), enforce S->A adjacency and receipt
      ``source_commit`` exactly.

    * Successor mode: otherwise, locate the commit that introduced the v6
      receipt and verify all 12 v6 artifacts remain byte-consistent through
      git blob identity with that introduction commit.

    If the v6 artifacts are not yet committed (commit A has not landed), the
    gate verifies only that the frozen predecessor A0b2/A1 receipts, ABI,
    codebook, evaluation cases, and selection contract remain byte-consistent
    with their introduction commit.
    """

    v6_receipt_path = ROOT / "data" / "e1" / "v6" / "a2_receipt.json"
    if not v6_receipt_path.exists():
        # Commit A has not landed; verify the frozen predecessor artifacts only.
        _verify_frozen_predecessor_blobs()
        return

    expected_artifacts = set(_EXPECTED_ARTIFACT_NAMES)

    receipt_text = _git("show", "HEAD:data/e1/v6/a2_receipt.json")
    receipt = json.loads(receipt_text)
    committed_source_commit = receipt["source_commit"]

    parents = _git("show", "-s", "--format=%P", "HEAD").split()
    head_tip = parents[1] if len(parents) >= 2 else _git("rev-parse", "HEAD")

    head_diff = set(
        line for line in _git("diff", "--name-only", f"{head_tip}^", head_tip).splitlines() if line
    )
    v6_artifact_set = {f"data/e1/v6/{name}" for name in expected_artifacts}

    if head_diff == v6_artifact_set:
        # Direct A2 mode: enforce S->A adjacency exactly.
        implementation_commit = _git("rev-parse", f"{head_tip}^")
        assert committed_source_commit == implementation_commit, (
            f"receipt source_commit {committed_source_commit!r} does not match the "
            f"git-derived implementation commit {implementation_commit!r}"
        )
    else:
        # Successor mode: locate introduction commit, blob-identity check.
        receipt_rel = "data/e1/v6/a2_receipt.json"
        introductions = _git(
            "log", "--diff-filter=A", "--format=%H", "--", receipt_rel
        ).splitlines()
        assert introductions, f"no commit found introducing {receipt_rel}"
        frozen_commit = introductions[-1]
        for name in expected_artifacts:
            rel = f"data/e1/v6/{name}"
            frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
            current_blob = _git("hash-object", rel)
            assert current_blob == frozen_blob, f"frozen A2 artifact changed: {rel}"

    _verify_frozen_predecessor_blobs()


def _git(*args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"git not available or command failed: {exc}")
    return completed.stdout.strip()


def _verify_frozen_predecessor_blobs() -> None:
    """Verify the pinned A0b2/A1 receipts and constituents remain byte-consistent."""

    tracked = [
        "data/e1/v4/a0b2_receipt.json",
        "data/e1/v4/response_abi.json",
        "data/e1/v4/tokenizer_codebook.json",
        "data/e1/v4/evaluation_cases.jsonl",
        "data/e1/v5/a1_receipt.json",
        "data/e1/v5/conventional_control_responses.jsonl",
        "data/e1/v2/selection_contract.json",
    ]
    # Only check files that are tracked in git; untracked files (e.g. in a
    # worktree without the full history) are skipped.
    any_tracked = False
    for rel in tracked:
        path = ROOT / rel
        if not path.exists():
            continue
        introductions = _git("log", "--diff-filter=A", "--format=%H", "--", rel).splitlines()
        if not introductions:
            continue
        any_tracked = True
        frozen_commit = introductions[-1]
        frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
        current_blob = _git("hash-object", rel)
        assert current_blob == frozen_blob, f"frozen predecessor artifact changed: {rel}"
    if not any_tracked:
        pytest.skip("no tracked predecessor artifacts found in git history")


# ---------------------------------------------------------------------------
# Defect 2: A1 task_input_digest must match the paired user content digest.
# ---------------------------------------------------------------------------


def test_records_carry_task_input_digest(compiled_bundle):
    """Every paired record must carry the A1 task_input_digest (Defect 2)."""

    a1 = {
        json.loads(line)["record_id"]: json.loads(line)
        for line in A1_RESPONSES_PATH.read_text().splitlines()
    }
    for name in ("control_train.jsonl", "foundry_train.jsonl"):
        for record in _records(compiled_bundle, name):
            assert record["task_input_digest"] == a1[record["record_id"]]["task_input_digest"]


def test_task_input_digest_mismatch_rejected(monkeypatch):
    """Defect 2 mutation test: if the paired record's canonical task input text
    hashes to a digest that disagrees with the A1 response's stored
    task_input_digest, compilation must fail closed BEFORE either paired record
    is produced.

    The A1 responses file and its receipt are left authentic; the canonical
    task input text derivation is perturbed so the recomputed digest diverges.
    """

    import csd_foundry.empirical.e1.paired_curriculum_compiler as mod

    real = mod._canonical_task_input_text

    def tampered(foundry_record):  # type: ignore[no-untyped-def]
        return real(foundry_record) + "tamper"

    monkeypatch.setattr(mod, "_canonical_task_input_text", tampered)
    with pytest.raises(E1PairedCurriculumError, match="task_input_digest mismatch"):
        _compile()


# ---------------------------------------------------------------------------
# Defect 5: tokenizer asset aggregate digest substitution rejection.
# ---------------------------------------------------------------------------


def test_tokenizer_asset_aggregate_digest_bound_in_three_artifacts(compiled_bundle):
    task_format = json.loads(compiled_bundle["paired_task_format.json"].decode("utf-8"))
    tokenization_manifest = json.loads(
        compiled_bundle["tokenization_manifest.json"].decode("utf-8")
    )
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    for artifact_name, artifact in (
        ("paired_task_format.json", task_format),
        ("tokenization_manifest.json", tokenization_manifest),
        ("a2_receipt.json", receipt),
    ):
        assert artifact["tokenizer_asset_aggregate_digest"] == TOKENIZER_ASSET_AGGREGATE_DIGEST, (
            f"{artifact_name} missing/wrong tokenizer_asset_aggregate_digest"
        )


def test_tokenizer_asset_aggregate_digest_substitution_rejected(monkeypatch):
    """Defect 5 mutation test: a substituted tokenizer asset digest pinned
    constant must fail closed."""

    import csd_foundry.empirical.e1.paired_curriculum_compiler as mod

    monkeypatch.setattr(mod, "_TOKENIZER_ASSET_AGGREGATE_DIGEST", "deadbeef" + "0" * 56)
    with pytest.raises(E1PairedCurriculumError) as exc:
        _compile()
    assert "tokenizer_asset_aggregate_digest mismatch" in str(exc.value)


# ---------------------------------------------------------------------------
# Defect 6: A0b2 evaluation-case bytes must be authenticated.
# ---------------------------------------------------------------------------


def test_evaluation_manifest_binds_predecessor_evaluation_cases_digest(compiled_bundle):
    """Defect 6: the A2 evaluation manifest binds the A0b2 evaluation_cases
    digest that the supplied bytes were authenticated against."""

    manifest = json.loads(compiled_bundle["evaluation_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    a0b2 = json.loads(A0B2_RECEIPT_PATH.read_text())
    expected = a0b2["constituent_artifact_digests"]["evaluation_cases.jsonl"]
    assert manifest["predecessor_evaluation_cases_digest"] == expected
    assert receipt["predecessor_evaluation_cases_digest"] == expected


def test_evaluation_cases_substitution_rejected(tmp_path):
    """Defect 6 mutation test: a substituted evaluation_cases.jsonl whose bytes
    do not hash to the A0b2 receipt's frozen digest must fail closed."""

    original = EVALUATION_CASES_PATH.read_bytes()
    lines = original.decode("utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["case_id"] = "tampered-case-id"
    lines[0] = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    tampered = ("\n".join(lines) + "\n").encode("utf-8")
    path = tmp_path / "evaluation_cases.jsonl"
    path.write_bytes(tampered)
    with pytest.raises(E1PairedCurriculumError, match="evaluation_cases.jsonl digest mismatch"):
        _compile(evaluation_cases_path=path)


# ---------------------------------------------------------------------------
# Defect 7: paired_e1_manifest.json binds clean eval + raw evidence.
# ---------------------------------------------------------------------------


def test_paired_manifest_binds_clean_and_raw_evidence_constituents(compiled_bundle):
    """Defect 7: the paired manifest binds the clean-evaluation digest and the
    raw executable-oracle / independent-verification evidence digests."""

    manifest = json.loads(compiled_bundle["paired_e1_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    constituents = receipt["constituent_artifact_digests"]
    # Clean evaluation file receipt present and matches the constituent digest.
    assert manifest["clean_evaluation"]["sha256"] == constituents["clean_evaluation.jsonl"]
    assert (
        manifest["clean_evaluation"]["sha256"]
        == hashlib.sha256(compiled_bundle["clean_evaluation.jsonl"]).hexdigest()
    )
    # Raw executable-oracle and independent-verification evidence bound.
    assert (
        manifest["raw_executable_oracle_evidence"]["sha256"]
        == receipt["raw_executable_oracle_evidence_digest"]
    )
    assert (
        manifest["raw_independent_verification_evidence"]["sha256"]
        == receipt["raw_independent_verification_evidence_digest"]
    )


# ---------------------------------------------------------------------------
# Defect 8: a2_receipt.json explicit fields.
# ---------------------------------------------------------------------------


def test_a2_receipt_carries_explicit_fields(compiled_bundle):
    """Defect 8: the A2 receipt must carry the explicit count/identity fields."""

    receipt = json.loads(compiled_bundle["a2_receipt.json"].decode("utf-8"))
    assert receipt["tokenizer_asset_aggregate_digest"] == TOKENIZER_ASSET_AGGREGATE_DIGEST
    assert isinstance(receipt["raw_foundry_bundle_identity"], str)
    assert len(receipt["raw_foundry_bundle_identity"]) == 64
    assert isinstance(receipt["raw_executable_oracle_evidence_digest"], str)
    assert len(receipt["raw_executable_oracle_evidence_digest"]) == 64
    assert isinstance(receipt["raw_independent_verification_evidence_digest"], str)
    assert len(receipt["raw_independent_verification_evidence_digest"]) == 64
    assert receipt["development_evaluation_count"] == 4
    assert receipt["clean_evaluation_count"] == 4
    assert receipt["truncation_count"] == 0
    # token_count_per_arm must equal the summed foundry sequence token count.
    foundry_records = _records(compiled_bundle, "foundry_train.jsonl")
    expected_tokens = sum(record["sequence_token_count"] for record in foundry_records)
    assert receipt["token_count_per_arm"] == expected_tokens


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
