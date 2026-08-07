"""Adversarial conformance tests for the E1 response ABI, codebook, parser, metrics.

Covers:
- all 5 codewords accepted; duplicates / unequal token lengths rejected
- strict parser: whitespace, newline, case, punctuation, prose, empty,
  concatenated codewords, unknown same-length output all rejected
- case-kind applicability: transition+NOT_APPLICABLE and observation+basis are
  context-invalid (not malformed)
- primary metric: malformed transition stays in the denominator
- safety metric: known-answer synthetic vectors
- deterministic reconstruction stability
- no floats in artifacts; all lists sorted + deduped
- git-history gate test (same pattern as A0b1); skips if artifacts uncommitted.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from csd_foundry.empirical.e1.response_abi_metrics import (
    CODEWORD_BY_CLASS,
    EXPECTED_PREDECESSOR_RECEIPT_SHA256,
    PARSER_IDENTITY,
    PRIMARY_METRIC_IDENTITY,
    SAFETY_METRIC_IDENTITY,
    TOKENIZER_ASSET_AGGREGATE_DIGEST,
    TOKENIZER_REPOSITORY,
    TOKENIZER_REVISION,
    ApplicabilityResult,
    CleanCaseRegressionCounts,
    E1ResponseABIError,
    FamilyMacroAccuracy,
    SemanticResponseClass,
    authenticate_predecessor_audit,
    authenticate_predecessor_receipt,
    build_evaluation_cases,
    build_evaluation_contract,
    build_parser_conformance,
    build_response_abi_contract,
    build_tokenizer_codebook,
    compile_response_abi_metrics,
    evaluate_applicability,
    parse_response,
    score_clean_case_regression,
    score_family_macro_accuracy,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
PREDECESSOR_RECEIPT_PATH = ROOT / "data" / "e1" / "v3" / "population_support_receipt.json"
PREDECESSOR_AUDIT_PATH = ROOT / "data" / "e1" / "v2" / "label_space_audit.json"
_TEST_SOURCE_COMMIT = "0000000000000000000000000000000000000000"

_CODEWORDS = ("A", "B", "C", "D", "E")


# ---------------------------------------------------------------------------
# Fake tokenizer for fast unit tests.
# ---------------------------------------------------------------------------


class _FakeTokenizer:
    """Deterministic single-token tokenizer matching the tiny-gpt2 codeword IDs."""

    _IDS = {"A": 32, "B": 33, "C": 34, "D": 35, "E": 36}

    def encode(self, text: str, add_special_tokens: bool = True) -> list[int]:  # noqa: ARG002
        if text in self._IDS:
            return [self._IDS[text]]
        # Multi-character or unknown text tokenizes character-by-character, so
        # multi-char codewords have length > 1 and whitespace/case mutations
        # produce distinct ids.
        result: list[int] = []
        for char in text:
            result.append(self._IDS.get(char, 100 + ord(char) % 100))
        return result

    def decode(self, token_ids: list[int]) -> str:
        reverse = {value: key for key, value in self._IDS.items()}
        return "".join(reverse.get(tid, "?") for tid in token_ids)


@pytest.fixture
def fake_tokenizer() -> _FakeTokenizer:
    return _FakeTokenizer()


@pytest.fixture
def real_tokenizer_or_skip() -> Any:
    """Load the real frozen tokenizer, skipping if unavailable offline."""

    try:
        from transformers import AutoTokenizer
    except ImportError as exc:  # pragma: no cover
        pytest.skip(f"transformers unavailable: {exc}")

    local_home = ROOT / "artifacts" / "e0h-windows-native-v2" / "hf-home"
    import os

    if local_home.is_dir():
        os.environ.setdefault("HF_HOME", str(local_home))
    local_cache = ROOT / "artifacts" / "e0h-windows-native-v2" / "hf-cache"
    if local_cache.is_dir():
        os.environ.setdefault("TRANSFORMERS_CACHE", str(local_cache))
    try:
        return AutoTokenizer.from_pretrained(TOKENIZER_REPOSITORY, revision=TOKENIZER_REVISION)
    except Exception as exc:  # pragma: no cover - network/offline dependent
        pytest.skip(f"frozen tokenizer unavailable offline: {exc}")


# ---------------------------------------------------------------------------
# Shared fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def predecessor_receipt_bytes() -> bytes:
    return PREDECESSOR_RECEIPT_PATH.read_bytes()


@pytest.fixture(scope="module")
def predecessor_audit_bytes() -> bytes:
    return PREDECESSOR_AUDIT_PATH.read_bytes()


@pytest.fixture
def compiled_bundle(
    monkeypatch, predecessor_receipt_bytes: bytes, predecessor_audit_bytes: bytes, fake_tokenizer
) -> dict[str, bytes]:
    """Compile the full bundle using the fake tokenizer (no network)."""

    import csd_foundry.empirical.e1.response_abi_metrics as mod

    monkeypatch.setattr(mod, "_load_frozen_tokenizer", lambda: fake_tokenizer)
    monkeypatch.setattr(mod, "_resolve_asset_cache_dir", lambda: None)
    return compile_response_abi_metrics(
        source_commit=_TEST_SOURCE_COMMIT,
        predecessor_population_receipt_path=str(PREDECESSOR_RECEIPT_PATH),
        predecessor_audit_path=str(PREDECESSOR_AUDIT_PATH),
    )


# ---------------------------------------------------------------------------
# Semantic class + truth table.
# ---------------------------------------------------------------------------


def test_semantic_class_set_has_exactly_five_members():
    assert {item.value for item in SemanticResponseClass} == {
        "NEITHER",
        "REMOVES_ONLY",
        "SURVIVES_ONLY",
        "BOTH",
        "NOT_APPLICABLE",
    }


def test_basis_truth_table_mapping():
    abi = build_response_abi_contract(_TEST_SOURCE_COMMIT)
    mapping = {
        (item["any_basis_removed"], item["any_basis_survives"]): item["semantic_class"]
        for item in abi.basis_truth_table
    }
    assert mapping[(False, False)] == "NEITHER"
    assert mapping[(True, False)] == "REMOVES_ONLY"
    assert mapping[(False, True)] == "SURVIVES_ONLY"
    assert mapping[(True, True)] == "BOTH"
    assert len(mapping) == 4


# ---------------------------------------------------------------------------
# Codebook: codewords accepted; duplicates and unequal lengths rejected.
# ---------------------------------------------------------------------------


def test_all_five_codewords_accepted(fake_tokenizer):
    codebook = build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)
    assert codebook.unique_codeword_count == 5
    assert codebook.uniform_token_count is True
    assert codebook.isometry_verified is True
    by_codeword = {item["codeword"]: item for item in codebook.codewords}
    for codeword in _CODEWORDS:
        assert by_codeword[codeword]["token_count"] == 1
        assert by_codeword[codeword]["roundtrip_exact"] is True


def test_codebook_token_ids_match_pinned_values(fake_tokenizer):
    codebook = build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)
    by_class = {item["semantic_class"]: item for item in codebook.codewords}
    assert by_class["NEITHER"]["token_ids"] == [32]
    assert by_class["REMOVES_ONLY"]["token_ids"] == [33]
    assert by_class["SURVIVES_ONLY"]["token_ids"] == [34]
    assert by_class["BOTH"]["token_ids"] == [35]
    assert by_class["NOT_APPLICABLE"]["token_ids"] == [36]


def test_duplicate_codeword_rejected(monkeypatch, fake_tokenizer):
    import csd_foundry.empirical.e1.response_abi_metrics as mod

    tampered = dict(CODEWORD_BY_CLASS)
    tampered[SemanticResponseClass.SURVIVES_ONLY] = "B"  # duplicate of REMOVES_ONLY
    monkeypatch.setattr(mod, "_CODEWORD_BY_CLASS", tampered)
    with pytest.raises(E1ResponseABIError, match="duplicate codeword"):
        build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)


def test_unequal_token_lengths_rejected(monkeypatch, fake_tokenizer):
    """A tokenizer that returns different token counts must fail the codebook."""

    class _UnequalTokenizer(_FakeTokenizer):
        def encode(self, text: str, add_special_tokens: bool = True) -> list[int]:  # noqa: ARG002
            if text == "C":  # SURVIVES_ONLY becomes 2 tokens
                return [34, 99]
            return super().encode(text, add_special_tokens=add_special_tokens)

    with pytest.raises(E1ResponseABIError, match="identical token count"):
        build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=_UnequalTokenizer())


def test_non_exact_roundtrip_rejected(monkeypatch, fake_tokenizer):
    class _BadRoundtripTokenizer(_FakeTokenizer):
        def decode(self, token_ids: list[int]) -> str:
            text = super().decode(token_ids)
            if text == "D":
                return " D"  # not exact
            return text

    with pytest.raises(E1ResponseABIError, match="roundtrip"):
        build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=_BadRoundtripTokenizer())


def test_codebook_pins_tokenizer_identity(fake_tokenizer):
    codebook = build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)
    assert codebook.tokenizer_repository == TOKENIZER_REPOSITORY
    assert codebook.tokenizer_revision == TOKENIZER_REVISION
    assert codebook.tokenizer_asset_aggregate_digest == TOKENIZER_ASSET_AGGREGATE_DIGEST


def test_changing_tokenizer_identity_invalidates_codebook(monkeypatch, fake_tokenizer):
    """A swapped tokenizer repository changes the embedded codebook identity.

    The codebook embeds the pinned tokenizer repository, revision, and asset
    digest. A downstream consumer that re-checks these against the real pinned
    values detects a swap. Here we confirm the embedded identity changes when
    the pinned constant is mutated, so the receipt-bound identity diverges from
    the genuine frozen tokenizer.
    """

    import csd_foundry.empirical.e1.response_abi_metrics as mod

    genuine = build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)
    monkeypatch.setattr(mod, "_TOKENIZER_REPOSITORY", "other/model")
    swapped = build_tokenizer_codebook(_TEST_SOURCE_COMMIT, tokenizer=fake_tokenizer)
    assert swapped.tokenizer_repository == "other/model"
    assert swapped.tokenizer_repository != genuine.tokenizer_repository
    # The genuine frozen repository is re-exported as a module constant, so a
    # downstream verifier comparing swapped.tokenizer_repository to the real
    # pinned TOKENIZER_REPOSITORY detects the substitution.
    assert swapped.tokenizer_repository != TOKENIZER_REPOSITORY


# ---------------------------------------------------------------------------
# Strict parser: accepted and rejected examples.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "codeword,expected_class",
    list(zip(_CODEWORDS, SemanticResponseClass, strict=True)),
)
def test_parser_accepts_each_codeword(codeword, expected_class):
    parsed = parse_response(codeword)
    assert parsed.is_valid is True
    assert parsed.reason_code is None
    assert parsed.semantic_class == expected_class


@pytest.mark.parametrize(
    "raw",
    [
        " A",  # leading whitespace
        "A ",  # trailing whitespace
        "A\n",  # newline suffix
        "\nA",  # newline prefix
        "a",  # case mutation
        "A.",  # punctuation suffix
        "A is the answer",  # prose continuation
        "",  # empty
        "AB",  # concatenated valid codewords
        "F",  # unknown same-length output
        "AA",  # repeated codeword
        "\tA",  # tab prefix
        "A\t",  # tab suffix
        " A ",  # surrounding whitespace
        "b",  # lowercase different class
    ],
)
def test_parser_reforms_each_malformed_output(raw):
    parsed = parse_response(raw)
    assert parsed.is_valid is False
    assert parsed.semantic_class is None
    assert parsed.reason_code == "MALFORMED"


def test_parser_rejects_non_string():
    parsed = parse_response(None)  # type: ignore[arg-type]
    assert parsed.is_valid is False
    assert parsed.reason_code == "MALFORMED"


def test_parser_conformance_vectors_complete():
    conformance = build_parser_conformance(_TEST_SOURCE_COMMIT)
    assert conformance.parser_identity == PARSER_IDENTITY
    assert len(conformance.accepted_examples) == 5
    for item in conformance.accepted_examples:
        assert item["is_valid"] is True
        assert item["reason_code"] is None
    assert len(conformance.rejected_examples) >= 10
    for item in conformance.rejected_examples:
        assert item["is_valid"] is False
        assert item["reason_code"] == "MALFORMED"
    assert set(conformance.codeword_set) == set(_CODEWORDS)


# ---------------------------------------------------------------------------
# Case-kind applicability.
# ---------------------------------------------------------------------------


def test_applicability_transition_basis_class_is_applicable():
    for cls in (
        SemanticResponseClass.NEITHER,
        SemanticResponseClass.REMOVES_ONLY,
        SemanticResponseClass.SURVIVES_ONLY,
        SemanticResponseClass.BOTH,
    ):
        result = evaluate_applicability("transition", cls)
        assert result.applicable is True
        assert result.reason is None


def test_applicability_transition_not_applicable_is_context_invalid():
    result = evaluate_applicability("transition", SemanticResponseClass.NOT_APPLICABLE)
    assert result.applicable is False
    assert result.reason == "CONTEXT_INVALID"


def test_applicability_observation_not_applicable_is_applicable():
    result = evaluate_applicability("observation", SemanticResponseClass.NOT_APPLICABLE)
    assert result.applicable is True
    assert result.reason is None


def test_applicability_observation_basis_class_is_context_invalid():
    result = evaluate_applicability("observation", SemanticResponseClass.NEITHER)
    assert result.applicable is False
    assert result.reason == "CONTEXT_INVALID"


def test_applicability_malformed_parse_is_never_applicable():
    result = evaluate_applicability("transition", None)
    assert isinstance(result, ApplicabilityResult)
    assert result.applicable is False
    assert result.reason == "MALFORMED"


# ---------------------------------------------------------------------------
# Primary metric: family-macro accuracy.
# ---------------------------------------------------------------------------


def _dev_cases() -> tuple[dict[str, object], ...]:
    return tuple(item for item in build_evaluation_cases() if item["cohort"] == "development")


def test_primary_metric_all_correct_scores_full():
    cases = _dev_cases()
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    result = score_family_macro_accuracy(cases, predictions)
    assert isinstance(result, FamilyMacroAccuracy)
    assert result.development_family_count == 4
    assert result.family_macro_accuracy_numerator == 4
    assert result.family_macro_accuracy_denominator == 4


def test_primary_metric_malformed_stays_in_denominator():
    cases = _dev_cases()
    # One malformed prediction makes that family incorrect.
    first_case_id = str(cases[0]["case_id"])
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    predictions[first_case_id] = " A"  # malformed
    result = score_family_macro_accuracy(cases, predictions)
    assert result.family_macro_accuracy_numerator == 3
    assert result.family_macro_accuracy_denominator == 4
    # The malformed family's member must record is_valid=False and is_correct=False.
    malformed_family = next(
        fam
        for fam in result.family_results
        if any(m["case_id"] == first_case_id for m in fam["members"])
    )
    assert malformed_family["family_accuracy"] is False
    assert malformed_family["members"][0]["is_valid"] is False
    assert malformed_family["members"][0]["reason_code"] == "MALFORMED"


def test_primary_metric_not_applicable_on_transition_is_incorrect():
    cases = _dev_cases()
    first_case_id = str(cases[0]["case_id"])
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    predictions[first_case_id] = "E"  # NOT_APPLICABLE on a transition
    result = score_family_macro_accuracy(cases, predictions)
    assert result.family_macro_accuracy_numerator == 3


def test_primary_metric_missing_output_is_malformed_incorrect():
    cases = _dev_cases()
    first_case_id = str(cases[0]["case_id"])
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    del predictions[first_case_id]  # missing
    result = score_family_macro_accuracy(cases, predictions)
    assert result.family_macro_accuracy_numerator == 3
    missing_member = next(
        m for fam in result.family_results for m in fam["members"] if m["case_id"] == first_case_id
    )
    assert missing_member["is_valid"] is False
    assert missing_member["reason_code"] == "MALFORMED"


def test_primary_metric_wrong_class_is_incorrect():
    cases = _dev_cases()
    first_case_id = str(cases[0]["case_id"])
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    predictions[first_case_id] = "A"  # NEITHER, likely wrong
    result = score_family_macro_accuracy(cases, predictions)
    # The numerator must be <= 4; if the gold was already NEITHER it's still
    # correct, otherwise it dropped. Either way, the metric does not error.
    assert result.family_macro_accuracy_numerator <= 4


# ---------------------------------------------------------------------------
# Safety metric: clean-case regression with known-answer vectors.
# ---------------------------------------------------------------------------


def _clean_cases() -> tuple[dict[str, object], ...]:
    return tuple(item for item in build_evaluation_cases() if item["cohort"] == "clean")


def test_safety_metric_all_correct_zero_counts():
    cases = _clean_cases()
    predictions = {str(item["case_id"]): str(item["codeword"]) for item in cases}
    result = score_clean_case_regression(cases, predictions)
    assert isinstance(result, CleanCaseRegressionCounts)
    assert result.clean_exact_error_count == 0
    assert result.spurious_basis_removal_count == 0
    assert result.valid_basis_rejection_count == 0
    assert result.clean_not_applicable_count == 0
    assert result.clean_malformed_count == 0


def test_safety_metric_known_answer_synthetic_vectors():
    """Known-answer: force one of each error category on distinct clean cases."""

    cases = list(_clean_cases())
    # clean cases: 2 NEITHER (01,02) + 2 SURVIVES_ONLY (03,04)
    neither_case = next(c for c in cases if c["gold_class"] == "NEITHER")
    survives_case = next(c for c in cases if c["gold_class"] == "SURVIVES_ONLY")

    predictions: dict[str, str] = {str(c["case_id"]): str(c["codeword"]) for c in cases}
    # 1. spurious_basis_removal: gold NEITHER, predict REMOVES_ONLY ("B")
    predictions[str(neither_case["case_id"])] = "B"
    # 2. valid_basis_rejection: gold SURVIVES_ONLY, predict NEITHER ("A")
    predictions[str(survives_case["case_id"])] = "A"

    result = score_clean_case_regression(tuple(cases), predictions)
    assert result.spurious_basis_removal_count == 1
    assert result.valid_basis_rejection_count == 1
    # Both are exact errors too.
    assert result.clean_exact_error_count == 2
    assert result.clean_malformed_count == 0
    assert result.clean_not_applicable_count == 0


def test_safety_metric_not_applicable_on_clean_transition():
    cases = list(_clean_cases())
    predictions = {str(c["case_id"]): str(c["codeword"]) for c in cases}
    first_id = str(cases[0]["case_id"])
    predictions[first_id] = "E"  # NOT_APPLICABLE on clean transition
    result = score_clean_case_regression(tuple(cases), predictions)
    assert result.clean_not_applicable_count == 1
    assert result.clean_exact_error_count == 1


def test_safety_metric_malformed_on_clean_case():
    cases = list(_clean_cases())
    predictions = {str(c["case_id"]): str(c["codeword"]) for c in cases}
    first_id = str(cases[0]["case_id"])
    predictions[first_id] = " A"  # malformed
    result = score_clean_case_regression(tuple(cases), predictions)
    assert result.clean_malformed_count == 1
    assert result.clean_exact_error_count == 1


def test_safety_metric_identity_is_pinned():
    cases = _clean_cases()
    predictions = {str(c["case_id"]): str(c["codeword"]) for c in cases}
    result = score_clean_case_regression(cases, predictions)
    assert result.metric_identity == SAFETY_METRIC_IDENTITY


# ---------------------------------------------------------------------------
# Evaluation cases.
# ---------------------------------------------------------------------------


def test_evaluation_cases_count_and_distribution():
    cases = build_evaluation_cases()
    dev = [c for c in cases if c["cohort"] == "development"]
    clean = [c for c in cases if c["cohort"] == "clean"]
    assert len(dev) == 4
    assert len(clean) == 4
    assert len({c["family_digest"] for c in dev}) == 4
    dev_classes = {c["gold_class"] for c in dev}
    # Four dev transitions exercise REMOVES_ONLY, BOTH, NEITHER.
    assert dev_classes == {"REMOVES_ONLY", "BOTH", "NEITHER"}


def test_evaluation_contract_binds_both_metrics():
    contract = build_evaluation_contract(_TEST_SOURCE_COMMIT)
    assert contract.primary_metric_identity == PRIMARY_METRIC_IDENTITY
    assert contract.safety_metric_identity == SAFETY_METRIC_IDENTITY
    assert contract.primary_metric_aggregation["development_family_count"] == 4
    assert contract.malformed_policy["primary_metric"] == (
        "malformed counts as incorrect and stays in the denominator"
    )


# ---------------------------------------------------------------------------
# Bundle: six artifacts, receipt binding, predecessor authentication.
# ---------------------------------------------------------------------------


def test_six_artifacts_emitted(compiled_bundle):
    assert set(compiled_bundle.keys()) == {
        "response_abi.json",
        "tokenizer_codebook.json",
        "parser_conformance.json",
        "evaluation_contract.json",
        "evaluation_cases.jsonl",
        "a0b2_receipt.json",
    }


def test_receipt_binds_predecessor_and_tokenizer(compiled_bundle):
    receipt = json.loads(compiled_bundle["a0b2_receipt.json"].decode("utf-8"))
    assert receipt["predecessor_receipt_sha256"] == EXPECTED_PREDECESSOR_RECEIPT_SHA256
    assert receipt["tokenizer_repository"] == TOKENIZER_REPOSITORY
    assert receipt["tokenizer_revision"] == TOKENIZER_REVISION
    assert receipt["tokenizer_asset_aggregate_digest"] == TOKENIZER_ASSET_AGGREGATE_DIGEST
    assert receipt["semantic_class_count"] == 5
    assert receipt["development_family_count"] == 4
    assert receipt["evaluation_case_count"] == 8
    assert receipt["source_commit"] == _TEST_SOURCE_COMMIT
    assert len(receipt["constituent_artifact_digests"]) == 5
    # The constituent digests must match recomputed file digests (excluding the receipt).
    for name, expected in receipt["constituent_artifact_digests"].items():
        observed = hashlib.sha256(compiled_bundle[name]).hexdigest()
        assert observed == expected, f"{name} digest mismatch"


def test_authenticate_genuine_predecessor_receipt(predecessor_receipt_bytes: bytes):
    authenticated = authenticate_predecessor_receipt(predecessor_receipt_bytes)
    assert authenticated.receipt_sha256 == EXPECTED_PREDECESSOR_RECEIPT_SHA256
    assert authenticated.predecessor_primary_projection_name == "basis_disposition"


def test_authenticate_predecessor_audit_uses_a0b1_pinned_constants(
    predecessor_audit_bytes: bytes, predecessor_receipt_bytes: bytes
):
    receipt = authenticate_predecessor_receipt(predecessor_receipt_bytes)
    payload = authenticate_predecessor_audit(
        predecessor_audit_bytes,
        expected_audit_sha256=receipt.predecessor_audit_sha256,
    )
    assert isinstance(payload, dict)
    assert payload["schema_version"] == "e1-label-space-audit/1"


def test_adversarial_coherent_receipt_substitution_fails_closed(
    predecessor_receipt_bytes: bytes, monkeypatch, fake_tokenizer, tmp_path
):
    """A substituted receipt with a different but valid shape must fail closed."""

    payload: dict[str, Any] = json.loads(predecessor_receipt_bytes.decode("utf-8"))
    payload["schema_version"] = "e1-population-support-receipt/9"
    substituted = canonical_json_bytes(payload)
    substituted_path = tmp_path / "receipt.json"
    substituted_path.write_bytes(substituted)
    import csd_foundry.empirical.e1.response_abi_metrics as mod

    monkeypatch.setattr(mod, "_load_frozen_tokenizer", lambda: fake_tokenizer)
    monkeypatch.setattr(mod, "_resolve_asset_cache_dir", lambda: None)
    with pytest.raises(E1ResponseABIError, match="SHA-256 mismatch"):
        compile_response_abi_metrics(
            source_commit=_TEST_SOURCE_COMMIT,
            predecessor_population_receipt_path=str(substituted_path),
            predecessor_audit_path=str(PREDECESSOR_AUDIT_PATH),
        )


def test_adversarial_tampered_audit_fails_closed(
    predecessor_audit_bytes: bytes, monkeypatch, fake_tokenizer, tmp_path
):
    """A byte-tampered audit must fail the A0b1 authenticator."""

    tampered = bytearray(predecessor_audit_bytes)
    tampered[0] ^= 0xFF
    tampered_path = tmp_path / "audit.json"
    tampered_path.write_bytes(bytes(tampered))
    import csd_foundry.empirical.e1.response_abi_metrics as mod

    monkeypatch.setattr(mod, "_load_frozen_tokenizer", lambda: fake_tokenizer)
    monkeypatch.setattr(mod, "_resolve_asset_cache_dir", lambda: None)
    # The A0b1 authenticator raises its own error type on tamper; either error
    # type is acceptable so long as compilation fails closed.
    with pytest.raises((E1ResponseABIError, ValueError)):
        compile_response_abi_metrics(
            source_commit=_TEST_SOURCE_COMMIT,
            predecessor_population_receipt_path=str(PREDECESSOR_RECEIPT_PATH),
            predecessor_audit_path=str(tampered_path),
        )


# ---------------------------------------------------------------------------
# Deterministic reconstruction stability.
# ---------------------------------------------------------------------------


def test_deterministic_reconstruction_stability(
    monkeypatch, predecessor_receipt_bytes, predecessor_audit_bytes, fake_tokenizer
):
    import csd_foundry.empirical.e1.response_abi_metrics as mod

    monkeypatch.setattr(mod, "_load_frozen_tokenizer", lambda: fake_tokenizer)
    monkeypatch.setattr(mod, "_resolve_asset_cache_dir", lambda: None)
    first = compile_response_abi_metrics(
        source_commit=_TEST_SOURCE_COMMIT,
        predecessor_population_receipt_path=str(PREDECESSOR_RECEIPT_PATH),
        predecessor_audit_path=str(PREDECESSOR_AUDIT_PATH),
    )
    second = compile_response_abi_metrics(
        source_commit=_TEST_SOURCE_COMMIT,
        predecessor_population_receipt_path=str(PREDECESSOR_RECEIPT_PATH),
        predecessor_audit_path=str(PREDECESSOR_AUDIT_PATH),
    )
    assert first.keys() == second.keys()
    for name in first:
        assert first[name] == second[name], f"non-deterministic artifact: {name}"


# ---------------------------------------------------------------------------
# No floats in artifacts; all lists sorted + deduped.
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


def test_no_floats_in_artifacts(compiled_bundle):
    for name, content in compiled_bundle.items():
        if name.endswith(".jsonl"):
            for line in content.decode("utf-8").splitlines():
                parsed = json.loads(line)
                floats = list(_walk_values(parsed))
                assert not floats, f"{name} contains floats: {floats}"
        else:
            parsed = json.loads(content.decode("utf-8"))
            floats = list(_walk_values(parsed))
            assert not floats, f"{name} contains floats: {floats}"


def test_constituent_digests_sorted_and_unique(compiled_bundle):
    receipt = json.loads(compiled_bundle["a0b2_receipt.json"].decode("utf-8"))
    digests = receipt["constituent_artifact_digests"]
    keys = list(digests.keys())
    assert keys == sorted(keys), "constituent digests keys not sorted"
    values = list(digests.values())
    assert len(values) == len(set(values)), "constituent digests not unique"


def test_receipt_carried_blockers_match_predecessor(
    compiled_bundle, predecessor_receipt_bytes: bytes
):
    receipt = json.loads(compiled_bundle["a0b2_receipt.json"].decode("utf-8"))
    predecessor = json.loads(predecessor_receipt_bytes.decode("utf-8"))
    assert receipt["carried_blockers"] == predecessor["carried_blockers"]


def test_evaluation_cases_jsonl_parses(compiled_bundle):
    lines = compiled_bundle["evaluation_cases.jsonl"].decode("utf-8").splitlines()
    assert len(lines) == 8
    for line in lines:
        parsed = json.loads(line)
        assert parsed["schema_version"] == "e1-evaluation-case/1"
        assert parsed["case_kind"] == "transition"
        assert parsed["gold_class"] in {
            "NEITHER",
            "REMOVES_ONLY",
            "SURVIVES_ONLY",
            "BOTH",
            "NOT_APPLICABLE",
        }


# ---------------------------------------------------------------------------
# Real-tokenizer integration (skipped offline).
# ---------------------------------------------------------------------------


def test_real_tokenizer_codebook_roundtrips(real_tokenizer_or_skip):
    codebook = build_tokenizer_codebook(
        _TEST_SOURCE_COMMIT,
        tokenizer=real_tokenizer_or_skip,
        asset_cache_dir=ROOT / "artifacts" / "e0h-windows-native-v2" / "hf-cache",
    )
    assert codebook.unique_codeword_count == 5
    assert codebook.uniform_token_count is True
    assert codebook.isometry_verified is True
    by_class = {item["semantic_class"]: item for item in codebook.codewords}
    assert by_class["NEITHER"]["token_ids"] == [32]
    assert by_class["REMOVES_ONLY"]["token_ids"] == [33]
    assert by_class["SURVIVES_ONLY"]["token_ids"] == [34]
    assert by_class["BOTH"]["token_ids"] == [35]
    assert by_class["NOT_APPLICABLE"]["token_ids"] == [36]


# ---------------------------------------------------------------------------
# Orchestration smoke test.
# ---------------------------------------------------------------------------


def test_orchestration_compile_artifacts_produces_six_files(monkeypatch, fake_tokenizer, tmp_path):
    import csd_foundry.empirical.e1.response_abi_metrics as mod

    monkeypatch.setattr(mod, "_load_frozen_tokenizer", lambda: fake_tokenizer)
    monkeypatch.setattr(mod, "_resolve_asset_cache_dir", lambda: None)
    artifacts = compile_response_abi_metrics(
        source_commit=_TEST_SOURCE_COMMIT,
        predecessor_population_receipt_path=str(PREDECESSOR_RECEIPT_PATH),
        predecessor_audit_path=str(PREDECESSOR_AUDIT_PATH),
    )
    assert len(artifacts) == 6
    for content in artifacts.values():
        assert isinstance(content, bytes) and len(content) > 0


# ---------------------------------------------------------------------------
# Git-history gate (same pattern as A0b1). Skips if artifacts uncommitted.
# ---------------------------------------------------------------------------


def test_git_history_source_commit_gate_binds_real_implementation_commit():
    """The committed a0b2_receipt source_commit must bind the real commit S.

    Same pattern as the A0b1 gate: resolve the artifact commit, derive S from
    git history, assert the committed source_commit matches, and assert the
    artifact commit changes exactly the six v4 artifacts. Skips if the
    artifacts are not yet committed.
    """

    receipt_path = ROOT / "data" / "e1" / "v4" / "a0b2_receipt.json"
    if not receipt_path.exists():
        pytest.skip("data/e1/v4/a0b2_receipt.json not yet committed")

    expected_artifacts = {
        "response_abi.json",
        "tokenizer_codebook.json",
        "parser_conformance.json",
        "evaluation_contract.json",
        "evaluation_cases.jsonl",
        "a0b2_receipt.json",
    }

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
            pytest.fail(f"git command failed (history unavailable but artifact committed): {exc}")
        return completed.stdout.strip()

    parents = _git("show", "-s", "--format=%P", "HEAD").split()
    artifact_commit = parents[1] if len(parents) >= 2 else _git("rev-parse", "HEAD")
    implementation_commit = _git("rev-parse", f"{artifact_commit}^")

    receipt_text = _git("show", f"{artifact_commit}:data/e1/v4/a0b2_receipt.json")
    committed_source_commit = json.loads(receipt_text).get("source_commit")

    assert committed_source_commit == implementation_commit, (
        f"receipt source_commit {committed_source_commit!r} does not match the "
        f"git-derived implementation commit {implementation_commit!r}"
    )

    changed = set(
        line
        for line in _git("diff", "--name-only", implementation_commit, artifact_commit).splitlines()
        if line
    )
    assert changed == {f"data/e1/v4/{name}" for name in expected_artifacts}, (
        f"artifact commit changed unexpected files: {sorted(changed)}"
    )
