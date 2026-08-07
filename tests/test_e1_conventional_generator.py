"""Adversarial conformance tests for the E1 A1 conventional-control compiler.

Covers:
- population invariants (19 records, 14 scenarios, 3/5/11 distribution)
- the three frozen rules (observation->E/36, Reassess->A/32, DependencyChange->B/33)
- rules carry no codeword; codewords are resolved from the codebook
- unknown transition event fails closed
- development record injection rejected
- reordered inputs produce byte-identical output
- A0b2 receipt / ABI / codebook substitution rejected
- changed A/B/E mapping rejected
- generator succeeds with the oracle and runner patched to raise (no Foundry
  dependency: A1 extracts TRAIN task inputs directly from ScenarioSpec cases)
- no development IDs in output
- deterministic reconstruction stability
- no floats in artifacts; all lists sorted + deduped
- manifest binds selection contract digest + case_kind/event_type/rule_id counts
- receipt binds selection contract digest + generation/validation command
  digests + all three non-receipt constituents
- two-mode provenance gate (direct A1 mode + successor mode, same pattern as
  A0b1/A0b2)
- ``label_authority == "conventional_synthetic"`` in every record
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from csd_foundry.empirical.e1.conventional_generator import (
    ALLOWED_FEATURES,
    EXPECTED_A0B2_RECEIPT_SHA256,
    EXPECTED_DISTRIBUTION,
    EXPECTED_OBSERVATION_COUNT,
    EXPECTED_RECORD_COUNT,
    EXPECTED_SCENARIO_COUNT,
    EXPECTED_TRANSITION_COUNT,
    FAIL_CLOSED_REASON,
    PREDECESSOR_SOURCE_COMMIT,
    RELEASE,
    RULES,
    E1ConventionalGeneratorError,
    ExtractedTrainingView,
    authenticate_a0b2_receipt,
    authenticate_response_abi,
    authenticate_tokenizer_codebook,
    build_rule_catalog,
    compute_compiler_implementation_sha256,
    label_conventional_control,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
A0B2_RECEIPT_PATH = ROOT / "data" / "e1" / "v4" / "a0b2_receipt.json"
RESPONSE_ABI_PATH = ROOT / "data" / "e1" / "v4" / "response_abi.json"
TOKENIZER_CODEBOOK_PATH = ROOT / "data" / "e1" / "v4" / "tokenizer_codebook.json"
_TEST_SOURCE_COMMIT = "0000000000000000000000000000000000000000"

# Development scenario IDs (excluded from training; must never appear in output).
_DEVELOPMENT_SCENARIO_IDS = {"G-04", "M-12", "M-13", "M-14"}


# ---------------------------------------------------------------------------
# Shared fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def a0b2_receipt_bytes() -> bytes:
    return A0B2_RECEIPT_PATH.read_bytes()


@pytest.fixture(scope="module")
def response_abi_bytes() -> bytes:
    return RESPONSE_ABI_PATH.read_bytes()


@pytest.fixture(scope="module")
def tokenizer_codebook_bytes() -> bytes:
    return TOKENIZER_CODEBOOK_PATH.read_bytes()


@pytest.fixture
def compiled_bundle() -> dict[str, bytes]:
    return _compile()


def _compile(
    *,
    source_commit: str = _TEST_SOURCE_COMMIT,
    a0b2_receipt_path: Path = A0B2_RECEIPT_PATH,
    response_abi_path: Path = RESPONSE_ABI_PATH,
    tokenizer_codebook_path: Path = TOKENIZER_CODEBOOK_PATH,
) -> dict[str, bytes]:
    from csd_foundry.empirical.e1.conventional_generator import (
        compile_conventional_generator,
    )

    return compile_conventional_generator(
        source_commit=source_commit,
        a0b2_receipt_path=str(a0b2_receipt_path),
        response_abi_path=str(response_abi_path),
        tokenizer_codebook_path=str(tokenizer_codebook_path),
    )


def _responses(bundle: dict[str, bytes]) -> list[dict[str, Any]]:
    lines = bundle["conventional_control_responses.jsonl"].decode("utf-8").splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Population invariants.
# ---------------------------------------------------------------------------


def test_all_19_records_compiled_exactly_once(compiled_bundle):
    responses = _responses(compiled_bundle)
    assert len(responses) == EXPECTED_RECORD_COUNT
    record_ids = [response["record_id"] for response in responses]
    assert len(record_ids) == len(set(record_ids)), "duplicate record IDs"


def test_exactly_14_scenario_ids(compiled_bundle):
    responses = _responses(compiled_bundle)
    scenario_ids = {response["scenario_id"] for response in responses}
    assert len(scenario_ids) == EXPECTED_SCENARIO_COUNT


def test_exact_rule_distribution(compiled_bundle):
    responses = _responses(compiled_bundle)
    counts = {"NOT_APPLICABLE": 0, "NEITHER": 0, "REMOVES_ONLY": 0, "SURVIVES_ONLY": 0, "BOTH": 0}
    for response in responses:
        counts[response["semantic_class"]] += 1
    assert counts == EXPECTED_DISTRIBUTION


def test_observation_maps_to_e_token_36(compiled_bundle):
    responses = _responses(compiled_bundle)
    observations = [r for r in responses if r["case_kind"] == "observation"]
    assert len(observations) == 3
    for response in observations:
        assert response["semantic_class"] == "NOT_APPLICABLE"
        assert response["codeword"] == "E"
        assert response["token_ids"] == [36]
        assert response["token_count"] == 1
        assert response["rule_id"] == "CTRL-OBSERVATION-NA/1"
        assert response["event_type"] == ""


def test_reassess_maps_to_a_token_32(compiled_bundle):
    responses = _responses(compiled_bundle)
    reassess = [r for r in responses if r["event_type"] == "Reassess"]
    assert len(reassess) == 5
    for response in reassess:
        assert response["semantic_class"] == "NEITHER"
        assert response["codeword"] == "A"
        assert response["token_ids"] == [32]
        assert response["token_count"] == 1
        assert response["rule_id"] == "CTRL-REASSESS-NEITHER/1"
        assert response["case_kind"] == "transition"


def test_dependency_change_maps_to_b_token_33(compiled_bundle):
    responses = _responses(compiled_bundle)
    dependency = [r for r in responses if r["event_type"] == "DependencyChange"]
    assert len(dependency) == 11
    for response in dependency:
        assert response["semantic_class"] == "REMOVES_ONLY"
        assert response["codeword"] == "B"
        assert response["token_ids"] == [33]
        assert response["token_count"] == 1
        assert response["rule_id"] == "CTRL-DEPENDENCYCHANGE-REMOVES/1"
        assert response["case_kind"] == "transition"


# ---------------------------------------------------------------------------
# Record schema invariants.
# ---------------------------------------------------------------------------


_EXPECTED_SCHEMA_KEYS = {
    "schema_version",
    "response_id",
    "scenario_id",
    "record_id",
    "split",
    "case_kind",
    "event_type",
    "task_input_digest",
    "control_view_digest",
    "label_authority",
    "rule_id",
    "semantic_class",
    "codeword",
    "token_ids",
    "token_count",
}


def test_every_record_has_exact_schema(compiled_bundle):
    responses = _responses(compiled_bundle)
    for response in responses:
        assert set(response.keys()) == _EXPECTED_SCHEMA_KEYS
        assert response["schema_version"] == "e1-conventional-control-response/1"
        assert response["split"] == "train"
        assert response["label_authority"] == "conventional_synthetic"
        assert response["token_count"] == 1
        assert isinstance(response["token_ids"], list) and len(response["token_ids"]) == 1


def test_response_id_derived_from_record_id(compiled_bundle):
    responses = _responses(compiled_bundle)
    for response in responses:
        assert response["response_id"] == f"e1-control/{response['record_id']}"


def test_records_sorted_by_record_id(compiled_bundle):
    responses = _responses(compiled_bundle)
    record_ids = [response["record_id"] for response in responses]
    assert record_ids == sorted(record_ids)


def test_control_view_digest_is_canonical_sha_of_case_kind_event_type(compiled_bundle):
    """control_view_digest = SHA-256 of canonical JSON {case_kind, event_type}."""

    responses = _responses(compiled_bundle)
    for response in responses:
        event_type = response["event_type"]
        expected = hashlib.sha256(
            json.dumps(
                {"case_kind": response["case_kind"], "event_type": event_type or None},
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        ).hexdigest()
        assert response["control_view_digest"] == expected


def test_task_input_digest_matches_scenario_case_canonical_text(compiled_bundle):
    """task_input_digest equals SHA-256 of the canonical task input text built
    directly from the TRAIN ScenarioSpec cases (no Foundry compiler involved).

    A1 must not depend on the Foundry compiler, so this test reconstructs the
    same canonical user-message content the Foundry compiler would emit using
    ONLY ``case.before``/``case.event`` (transition) and
    ``case.state``/``case.assertion`` (observation), and verifies A1's
    ``task_input_digest`` matches.
    """

    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )
    from csd_foundry.empirical.e1.execution_splits import E1Split
    from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
    from csd_foundry.scenarios.registry import SCENARIOS
    from csd_foundry.scenarios.spec import ObservationCase, TransitionCase
    from csd_foundry.synthesis.v0_4.serialization import (
        canonical_json_text,
        to_json_value,
    )

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/2",
        source_commit=PREDECESSOR_SOURCE_COMMIT,
    )
    training_ids: set[str] = set()
    for assignment in selection.split_manifest.assignments:
        if assignment.split is E1Split.TRAIN:
            training_ids.update(assignment.scenario_ids)

    user_content_by_record_id: dict[str, str] = {}
    for scenario_id in training_ids:
        spec = overlay_catalog[scenario_id]
        for case in spec.cases:
            if isinstance(case, TransitionCase):
                task_input = {
                    "schema_version": "e1-semantic-decision-input/1",
                    "case_type": "transition",
                    "before": to_json_value(case.before),
                    "event_type": type(case.event).__name__,
                    "event": to_json_value(case.event),
                }
            elif isinstance(case, ObservationCase):
                task_input = {
                    "schema_version": "e1-semantic-decision-input/1",
                    "case_type": "observation",
                    "state": to_json_value(case.state),
                    "assertion": case.assertion,
                }
            else:
                pytest.fail(f"unexpected case type: {type(case).__name__}")
            record_id = f"e1-foundry/train/{spec.scenario_id}/{case.case_id}"
            user_content_by_record_id[record_id] = canonical_json_text(task_input)

    responses = _responses(compiled_bundle)
    for response in responses:
        user_content = user_content_by_record_id[response["record_id"]]
        expected = hashlib.sha256(user_content.encode("utf-8")).hexdigest()
        assert response["task_input_digest"] == expected


# ---------------------------------------------------------------------------
# Fail-closed behavior.
# ---------------------------------------------------------------------------


def test_unknown_transition_event_fails_closed():
    """A transition with an unrecognized event_type fails closed."""

    view = ExtractedTrainingView(
        record_id="e1-foundry/train/X/X/case",
        scenario_id="X",
        split="train",
        case_kind="transition",
        event_type="AdvanceClock",
        task_input_digest="0" * 64,
    )
    with pytest.raises(E1ConventionalGeneratorError, match=FAIL_CLOSED_REASON):
        label_conventional_control(view)


def test_transition_missing_event_type_fails_closed():
    view = ExtractedTrainingView(
        record_id="e1-foundry/train/X/X/case",
        scenario_id="X",
        split="train",
        case_kind="transition",
        event_type=None,
        task_input_digest="0" * 64,
    )
    with pytest.raises(E1ConventionalGeneratorError, match=FAIL_CLOSED_REASON):
        label_conventional_control(view)


def test_observation_with_event_type_fails_closed():
    view = ExtractedTrainingView(
        record_id="e1-foundry/train/X/X/case",
        scenario_id="X",
        split="train",
        case_kind="observation",
        event_type="Reassess",
        task_input_digest="0" * 64,
    )
    with pytest.raises(E1ConventionalGeneratorError, match="event_type"):
        label_conventional_control(view)


def test_unsupported_case_kind_fails_closed():
    view = ExtractedTrainingView(
        record_id="e1-foundry/train/X/X/case",
        scenario_id="X",
        split="train",
        case_kind="rejected_transition",
        event_type=None,
        task_input_digest="0" * 64,
    )
    with pytest.raises(E1ConventionalGeneratorError, match=FAIL_CLOSED_REASON):
        label_conventional_control(view)


def test_development_record_injection_rejected(monkeypatch):
    """If a non-TRAIN case were injected into the extracted population, the
    per-record labeling fails closed because the case_kind is unsupported.

    The new direct-extraction path always pins the split segment to
    ``E1Split.TRAIN.value`` in every record_id, so a development-segment
    record_id cannot arise from the real extractor. We instead simulate a
    tampered extractor by patching ``_build_training_records`` to return a
    single record with an unsupported ``case_kind`` (the kind a development
    ``RejectedTransitionCase`` would produce) and assert the labeler fails
    closed rather than emitting a response.
    """

    from csd_foundry.empirical.e1 import conventional_generator as mod

    def _fake_training_records() -> tuple[object, ...]:
        return (
            mod._ExtractedRecord(
                record_id="e1-foundry/development/G-04/G-04/dev-case",
                scenario_id="G-04",
                family_digest="0" * 64,
                case_kind="rejected_transition",
                event_type=None,
                task_input={"case_type": "rejected_transition"},
                task_input_text="{}\n",
            ),
        )

    monkeypatch.setattr(mod, "_build_training_records", _fake_training_records)
    with pytest.raises(E1ConventionalGeneratorError, match=FAIL_CLOSED_REASON):
        _compile()


def test_development_scenario_id_never_in_extracted_training_records():
    """The real extractor never emits a development scenario_id.

    This complements the output-level ``test_no_development_record_ids_in_output``
    by asserting the property at the extraction layer: the TRAIN membership is
    read from the selection contract's split manifest and contains none of the
    frozen development scenario IDs.
    """

    from csd_foundry.empirical.e1 import conventional_generator as mod

    records = mod._build_training_records()
    scenario_ids = {record.scenario_id for record in records}
    assert scenario_ids.isdisjoint(_DEVELOPMENT_SCENARIO_IDS)
    for record in records:
        assert record.record_id.startswith("e1-foundry/train/")


def test_development_scenario_id_never_in_output(compiled_bundle):
    responses = _responses(compiled_bundle)
    scenario_ids = {response["scenario_id"] for response in responses}
    assert scenario_ids.isdisjoint(_DEVELOPMENT_SCENARIO_IDS)


def test_no_development_record_ids_in_output(compiled_bundle):
    responses = _responses(compiled_bundle)
    for response in responses:
        assert "/development/" not in response["record_id"]
        assert response["record_id"].startswith("e1-foundry/train/")


# ---------------------------------------------------------------------------
# Authentication and substitution rejection.
# ---------------------------------------------------------------------------


def test_authenticate_genuine_a0b2_receipt(a0b2_receipt_bytes):
    authenticated = authenticate_a0b2_receipt(a0b2_receipt_bytes)
    assert authenticated.receipt_sha256 == EXPECTED_A0B2_RECEIPT_SHA256


def test_a0b2_receipt_substitution_rejected(a0b2_receipt_bytes, tmp_path):
    """A substituted receipt with a different but valid shape must fail closed."""

    payload: dict[str, Any] = json.loads(a0b2_receipt_bytes.decode("utf-8"))
    payload["schema_version"] = "e1-response-abi-receipt/9"
    substituted = canonical_json_bytes(payload)
    substituted_path = tmp_path / "receipt.json"
    substituted_path.write_bytes(substituted)
    with pytest.raises(E1ConventionalGeneratorError, match="SHA-256 mismatch"):
        _compile(a0b2_receipt_path=substituted_path)


def test_a0b2_receipt_byte_tamper_rejected(a0b2_receipt_bytes, tmp_path):
    tampered = bytearray(a0b2_receipt_bytes)
    tampered[0] ^= 0xFF
    tampered_path = tmp_path / "receipt.json"
    tampered_path.write_bytes(bytes(tampered))
    with pytest.raises(E1ConventionalGeneratorError, match="SHA-256 mismatch"):
        _compile(a0b2_receipt_path=tampered_path)


def test_response_abi_digest_substitution_rejected(response_abi_bytes, tmp_path):
    """A swapped ABI file (different digest than pinned) must fail closed."""

    payload: dict[str, Any] = json.loads(response_abi_bytes.decode("utf-8"))
    payload["primary_projection_name"] = "tampered"
    substituted = canonical_json_bytes(payload)
    substituted_path = tmp_path / "abi.json"
    substituted_path.write_bytes(substituted)
    with pytest.raises(E1ConventionalGeneratorError, match="response ABI digest mismatch"):
        _compile(response_abi_path=substituted_path)


def test_tokenizer_codebook_digest_substitution_rejected(tokenizer_codebook_bytes, tmp_path):
    """A swapped codebook file (different digest than pinned) must fail closed."""

    payload: dict[str, Any] = json.loads(tokenizer_codebook_bytes.decode("utf-8"))
    payload["release"] = "e1-response-abi/9"
    substituted = canonical_json_bytes(payload)
    substituted_path = tmp_path / "codebook.json"
    substituted_path.write_bytes(substituted)
    with pytest.raises(E1ConventionalGeneratorError, match="tokenizer codebook digest mismatch"):
        _compile(tokenizer_codebook_path=substituted_path)


def test_changed_codeword_mapping_rejected(
    monkeypatch, response_abi_bytes, tokenizer_codebook_bytes, tmp_path
):
    """A codebook that swaps the A/B/E mapping must fail closed.

    A1 resolves codewords/token_ids from the authenticated codebook at
    response-record construction time, so a changed mapping must invalidate
    the output. The codebook digest is pinned from the A0b2 receipt, so any
    tampered binding (here NEITHER's codeword swapped to "Z") is caught at
    authentication time before any record is labeled.
    """

    # Build a tampered codebook payload that swaps NEITHER's codeword.
    payload: dict[str, Any] = json.loads(tokenizer_codebook_bytes.decode("utf-8"))
    for entry in payload["codewords"]:
        if entry["semantic_class"] == "NEITHER":
            entry["codeword"] = "Z"
            entry["decoded_roundtrip"] = "Z"
    tampered = canonical_json_bytes(payload)
    tampered_path = tmp_path / "codebook.json"
    tampered_path.write_bytes(tampered)
    with pytest.raises(E1ConventionalGeneratorError, match="tokenizer codebook digest mismatch"):
        _compile(tokenizer_codebook_path=tampered_path)


def test_rule_catalog_materializes_codewords_from_codebook():
    """Rules carry no codeword; the catalog resolves codewords/token_ids from
    the authenticated codebook by semantic class.

    Defect 2: rules map only visible_condition -> semantic_class. The codeword
    is materialized from the codebook so a changed A/B/E mapping (caught by the
    codebook digest check) invalidates the catalog rather than being stored on
    the rule.
    """

    authenticated_receipt = authenticate_a0b2_receipt(A0B2_RECEIPT_PATH.read_bytes())
    abi = authenticate_response_abi(
        RESPONSE_ABI_PATH.read_bytes(),
        expected_abi_digest=authenticated_receipt.abi_digest,
    )
    codebook = authenticate_tokenizer_codebook(
        TOKENIZER_CODEBOOK_PATH.read_bytes(),
        expected_codebook_digest=authenticated_receipt.codebook_digest,
    )

    # The frozen rules must NOT carry a codeword attribute.
    for rule in RULES:
        assert not hasattr(rule, "codeword"), f"{rule.rule_id} must not carry a codeword (defect 2)"

    catalog = build_rule_catalog(abi=abi, codebook=codebook)
    for rule_payload, rule in zip(catalog["rules"], RULES, strict=True):
        entry = codebook.binding_by_class[rule.semantic_class]
        assert rule_payload["rule_id"] == rule.rule_id
        assert rule_payload["semantic_class"] == rule.semantic_class
        assert rule_payload["visible_condition"] == rule.visible_condition
        # Codeword and token_ids are materialized from the codebook.
        assert rule_payload["codeword"] == entry.codeword
        assert rule_payload["token_ids"] == list(entry.token_ids)


def test_rule_catalog_rejects_missing_semantic_class_in_codebook(monkeypatch):
    """A rule whose semantic class is absent from the codebook fails closed."""

    authenticated_receipt = authenticate_a0b2_receipt(A0B2_RECEIPT_PATH.read_bytes())
    abi = authenticate_response_abi(
        RESPONSE_ABI_PATH.read_bytes(),
        expected_abi_digest=authenticated_receipt.abi_digest,
    )
    codebook = authenticate_tokenizer_codebook(
        TOKENIZER_CODEBOOK_PATH.read_bytes(),
        expected_codebook_digest=authenticated_receipt.codebook_digest,
    )
    from csd_foundry.empirical.e1.conventional_generator import AuthenticatedCodebook

    # Drop NOT_APPLICABLE from the codebook so the observation rule cannot
    # resolve a codeword.
    pruned_binding = {
        key: value for key, value in codebook.binding_by_class.items() if key != "NOT_APPLICABLE"
    }
    pruned_codebook = AuthenticatedCodebook(
        codebook_digest=codebook.codebook_digest,
        payload=codebook.payload,
        binding_by_class=pruned_binding,
    )
    with pytest.raises(E1ConventionalGeneratorError, match="absent from authenticated codebook"):
        build_rule_catalog(abi=abi, codebook=pruned_codebook)


def test_rule_catalog_rejects_missing_semantic_class_in_abi(monkeypatch):
    """A rule whose semantic class is absent from the authenticated ABI fails."""

    authenticated_receipt = authenticate_a0b2_receipt(A0B2_RECEIPT_PATH.read_bytes())
    abi = authenticate_response_abi(
        RESPONSE_ABI_PATH.read_bytes(),
        expected_abi_digest=authenticated_receipt.abi_digest,
    )
    codebook = authenticate_tokenizer_codebook(
        TOKENIZER_CODEBOOK_PATH.read_bytes(),
        expected_codebook_digest=authenticated_receipt.codebook_digest,
    )
    from csd_foundry.empirical.e1.conventional_generator import AuthenticatedABI

    tampered_abi = AuthenticatedABI(
        abi_digest=abi.abi_digest,
        payload=abi.payload,
        semantic_classes=frozenset({"NEITHER", "REMOVES_ONLY", "SURVIVES_ONLY", "BOTH"}),
    )
    with pytest.raises(E1ConventionalGeneratorError, match="absent from authenticated ABI"):
        build_rule_catalog(abi=tampered_abi, codebook=codebook)


def test_source_commit_must_be_git_digest():
    with pytest.raises(E1ConventionalGeneratorError, match="source_commit"):
        _compile(source_commit="not-a-digest")


# ---------------------------------------------------------------------------
# No runner / oracle dependency.
# ---------------------------------------------------------------------------


def test_generator_succeeds_without_executable_runner_oracle(compiled_bundle):
    """The control arm must compile without importing the kernel runner or oracle.

    We verify by checking that the conventional_generator module does not
    directly import the runner/oracle at module load time, and that it does not
    import the foundry artifact compiler. The compiled bundle must still be
    valid. (The docstring legitimately NAMES these symbols to describe the
    information boundary, so we check import statements, not raw substrings.)
    """

    import ast

    import csd_foundry.empirical.e1.conventional_generator as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_modules.add(node.module)
    forbidden = {
        "csd_foundry.scenarios.runner",
        "csd_foundry.kernel.oracle",
        "csd_foundry.kernel.transitions",
        "csd_foundry.empirical.e1.foundry_artifact_compiler",
    }
    overlap = {
        mod
        for forbidden_module in forbidden
        for mod in imported_modules
        if mod == forbidden_module or mod.startswith(forbidden_module + ".")
    }
    assert not overlap, f"A1 imports forbidden runner/oracle/foundry modules: {overlap}"
    # The compiled bundle has the expected four artifacts.
    assert set(compiled_bundle.keys()) == {
        "conventional_rule_catalog.json",
        "conventional_control_responses.jsonl",
        "conventional_control_manifest.json",
        "a1_receipt.json",
    }


def test_generator_succeeds_when_oracle_is_patched_to_raise(monkeypatch):
    """A1 must compile successfully even if CsdOracle raises on every call.

    Defect 1 (principal blocker): A1 must NOT execute any Foundry/oracle
    machinery. We monkeypatch ``CsdOracle`` to raise on instantiation and prove
    A1 still compiles the full bundle. If A1 transitively executed the oracle,
    this test would fail.
    """

    from csd_foundry.kernel import oracle as oracle_module

    class _ExplodingOracle:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("A1 must not instantiate CsdOracle")

        def apply(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("A1 must not invoke CsdOracle.apply")

    monkeypatch.setattr(oracle_module, "CsdOracle", _ExplodingOracle)
    bundle = _compile()
    assert set(bundle.keys()) == {
        "conventional_rule_catalog.json",
        "conventional_control_responses.jsonl",
        "conventional_control_manifest.json",
        "a1_receipt.json",
    }
    responses = _responses(bundle)
    assert len(responses) == EXPECTED_RECORD_COUNT


def test_generator_succeeds_when_runner_is_patched_to_raise(monkeypatch):
    """A1 must compile successfully even if run_scenario raises on every call.

    Defect 1 (principal blocker): A1 must NOT execute the canonical runner. We
    monkeypatch ``run_scenario`` to raise and prove A1 still compiles the full
    bundle. If A1 transitively executed the runner, this test would fail.
    """

    from csd_foundry.scenarios import runner as runner_module

    def _exploding_run_scenario(*args: object, **kwargs: object) -> None:
        raise AssertionError("A1 must not invoke run_scenario")

    monkeypatch.setattr(runner_module, "run_scenario", _exploding_run_scenario)
    bundle = _compile()
    assert set(bundle.keys()) == {
        "conventional_rule_catalog.json",
        "conventional_control_responses.jsonl",
        "conventional_control_manifest.json",
        "a1_receipt.json",
    }
    responses = _responses(bundle)
    assert len(responses) == EXPECTED_RECORD_COUNT


# ---------------------------------------------------------------------------
# Deterministic reconstruction stability.
# ---------------------------------------------------------------------------


def test_deterministic_reconstruction_stability():
    first = _compile()
    second = _compile()
    assert first.keys() == second.keys()
    for name in first:
        assert first[name] == second[name], f"non-deterministic artifact: {name}"


def test_reordered_inputs_produce_byte_identical_output(tmp_path):
    """Reordering the input files on disk must not change the output, because the
    generator consumes them by path and the population is internally sorted."""

    # Copy the three input files to a temp dir in a different "order" (the
    # generator reads by path, so ordering is irrelevant). The point of this
    # test is that the output is independent of filesystem or call-order noise.
    receipt = (tmp_path / "r.json").write_bytes(A0B2_RECEIPT_PATH.read_bytes())
    abi = (tmp_path / "a.json").write_bytes(RESPONSE_ABI_PATH.read_bytes())
    cb = (tmp_path / "c.json").write_bytes(TOKENIZER_CODEBOOK_PATH.read_bytes())
    assert receipt and abi and cb  # files exist
    first = _compile()
    second = _compile(
        a0b2_receipt_path=tmp_path / "r.json",
        response_abi_path=tmp_path / "a.json",
        tokenizer_codebook_path=tmp_path / "c.json",
    )
    assert first.keys() == second.keys()
    for name in first:
        assert first[name] == second[name], f"input reordering changed output: {name}"


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
                floats = list(_walk_values(json.loads(line)))
                assert not floats, f"{name} contains floats: {floats}"
        else:
            floats = list(_walk_values(json.loads(content.decode("utf-8"))))
            assert not floats, f"{name} contains floats: {floats}"


def test_all_sorted_lists_deduped(compiled_bundle):
    """Every list-valued field in manifest/receipt must be sorted and deduped."""

    manifest = json.loads(compiled_bundle["conventional_control_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a1_receipt.json"].decode("utf-8"))

    def _check_list(value: list[Any], context: str) -> None:
        assert value == sorted(value), f"{context} not sorted"
        assert len(value) == len(set(value)), f"{context} has duplicates"

    _check_list(manifest["scenario_ids"], "manifest.scenario_ids")
    _check_list(manifest["record_ids"], "manifest.record_ids")
    _check_list(list(receipt["constituent_artifact_digests"].keys()), "receipt.constituent keys")

    # scenario_ids in the responses must also be sorted (manifest copies them).
    responses = _responses(compiled_bundle)
    record_ids = [r["record_id"] for r in responses]
    assert record_ids == sorted(record_ids), "responses not sorted by record_id"
    assert len(record_ids) == len(set(record_ids)), "responses have duplicate record_ids"


# ---------------------------------------------------------------------------
# Rule catalog and receipt binding.
# ---------------------------------------------------------------------------


def test_rule_catalog_pins_three_rules_and_allowed_features(compiled_bundle):
    catalog = json.loads(compiled_bundle["conventional_rule_catalog.json"].decode("utf-8"))
    assert catalog["schema_version"] == "e1-conventional-rule-catalog/1"
    assert catalog["release"] == RELEASE
    assert catalog["label_authority"] == "conventional_synthetic"
    assert catalog["allowed_features"] == list(ALLOWED_FEATURES)
    assert len(catalog["rules"]) == 3
    rule_ids = [rule["rule_id"] for rule in catalog["rules"]]
    assert rule_ids == [rule.rule_id for rule in RULES]
    assert catalog["fail_closed"]["reason_code"] == FAIL_CLOSED_REASON
    abi_bytes = RESPONSE_ABI_PATH.read_bytes()
    assert catalog["abi_identity"]["sha256"] == hashlib.sha256(abi_bytes).hexdigest()
    cb_bytes = TOKENIZER_CODEBOOK_PATH.read_bytes()
    assert catalog["codebook_identity"]["sha256"] == hashlib.sha256(cb_bytes).hexdigest()

    # Defect 2: rules carry no stored codeword; the catalog materializes
    # codeword/token_ids from the codebook by semantic class.
    codebook = authenticate_tokenizer_codebook(
        cb_bytes,
        expected_codebook_digest=authenticate_a0b2_receipt(
            A0B2_RECEIPT_PATH.read_bytes()
        ).codebook_digest,
    )
    for rule_payload, rule in zip(catalog["rules"], RULES, strict=True):
        assert rule_payload["visible_condition"] == rule.visible_condition
        assert rule_payload["semantic_class"] == rule.semantic_class
        entry = codebook.binding_by_class[rule.semantic_class]
        assert rule_payload["codeword"] == entry.codeword
        assert rule_payload["token_ids"] == list(entry.token_ids)


def test_receipt_binds_source_commit_and_predecessor(compiled_bundle):
    receipt = json.loads(compiled_bundle["a1_receipt.json"].decode("utf-8"))
    assert receipt["schema_version"] == "e1-conventional-control-receipt/1"
    assert receipt["release"] == RELEASE
    assert receipt["source_commit"] == _TEST_SOURCE_COMMIT
    assert receipt["a0b2_receipt_sha256"] == EXPECTED_A0B2_RECEIPT_SHA256
    assert receipt["predecessor_source_commit"] == PREDECESSOR_SOURCE_COMMIT
    assert receipt["record_count"] == EXPECTED_RECORD_COUNT
    assert receipt["scenario_count"] == EXPECTED_SCENARIO_COUNT
    assert receipt["label_authority"] == "conventional_synthetic"

    # Defect 3: receipt must bind all THREE non-receipt constituents.
    assert set(receipt["constituent_artifact_digests"]) == {
        "conventional_rule_catalog.json",
        "conventional_control_responses.jsonl",
        "conventional_control_manifest.json",
    }
    # constituent digests must match recomputed file digests.
    for name, expected in receipt["constituent_artifact_digests"].items():
        observed = hashlib.sha256(compiled_bundle[name]).hexdigest()
        assert observed == expected, f"{name} digest mismatch"

    # rule_catalog_digest alias must match the catalog constituent digest.
    assert (
        receipt["rule_catalog_digest"]
        == receipt["constituent_artifact_digests"]["conventional_rule_catalog.json"]
    )
    # responses_digest and manifest_digest aliases must match too.
    assert (
        receipt["responses_digest"]
        == receipt["constituent_artifact_digests"]["conventional_control_responses.jsonl"]
    )
    assert (
        receipt["manifest_digest"]
        == receipt["constituent_artifact_digests"]["conventional_control_manifest.json"]
    )

    # Defect 3: selection contract digest + generation/validation command digests.
    selection_digest = receipt["selection_contract_digest"]
    assert isinstance(selection_digest, str) and len(selection_digest) == 64
    # The manifest must carry the same selection contract digest.
    manifest = json.loads(compiled_bundle["conventional_control_manifest.json"].decode("utf-8"))
    assert manifest["selection_contract_digest"] == selection_digest
    # The selection contract digest must equal the experiment contract digest.
    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )
    from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
    from csd_foundry.scenarios.registry import SCENARIOS

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/2",
        source_commit=PREDECESSOR_SOURCE_COMMIT,
    )
    assert selection_digest == selection.contract_digest

    generation_digest = receipt["generation_command_digest"]
    validation_digest = receipt["validation_command_digest"]
    assert isinstance(generation_digest, str) and len(generation_digest) == 64
    assert isinstance(validation_digest, str) and len(validation_digest) == 64
    # The command digests must be deterministic SHA-256 hashes of the canonical
    # command strings.
    expected_generation = hashlib.sha256(
        (
            f"python experiments/e1/compile_conventional_generator.py "
            f"--source-commit {_TEST_SOURCE_COMMIT}"
        ).encode()
    ).hexdigest()
    expected_validation = hashlib.sha256(
        (
            f"python experiments/e1/compile_conventional_generator.py "
            f"--source-commit {_TEST_SOURCE_COMMIT} --validate"
        ).encode()
    ).hexdigest()
    assert generation_digest == expected_generation
    assert validation_digest == expected_validation
    assert generation_digest != validation_digest

    # compiler implementation SHA-256 must be a 64-char digest.
    impl = receipt["compiler_implementation_sha256"]
    assert isinstance(impl, str) and len(impl) == 64


def test_manifest_binds_counts_and_predecessor(compiled_bundle):
    manifest = json.loads(compiled_bundle["conventional_control_manifest.json"].decode("utf-8"))
    assert manifest["schema_version"] == "e1-conventional-control-manifest/1"
    assert manifest["release"] == RELEASE
    assert manifest["source_commit"] == _TEST_SOURCE_COMMIT
    assert manifest["label_authority"] == "conventional_synthetic"
    assert manifest["scenario_count"] == EXPECTED_SCENARIO_COUNT
    assert manifest["record_count"] == EXPECTED_RECORD_COUNT
    assert manifest["distribution"] == EXPECTED_DISTRIBUTION
    assert manifest["predecessor_source_commit"] == PREDECESSOR_SOURCE_COMMIT
    assert manifest["predecessor_a0b2_receipt_sha256"] == EXPECTED_A0B2_RECEIPT_SHA256

    # Defect 3: selection contract digest.
    selection_digest = manifest["selection_contract_digest"]
    assert isinstance(selection_digest, str) and len(selection_digest) == 64

    # Defect 3: case_kind / event_type / rule_id count tallies.
    responses = _responses(compiled_bundle)
    assert manifest["case_kind_counts"] == {
        "observation": EXPECTED_OBSERVATION_COUNT,
        "transition": EXPECTED_TRANSITION_COUNT,
    }
    assert manifest["event_type_counts"] == {
        "DependencyChange": 11,
        "Reassess": 5,
        "observation": EXPECTED_OBSERVATION_COUNT,
    }
    assert manifest["rule_id_counts"] == {
        "CTRL-DEPENDENCYCHANGE-REMOVES/1": 11,
        "CTRL-OBSERVATION-NA/1": EXPECTED_OBSERVATION_COUNT,
        "CTRL-REASSESS-NEITHER/1": 5,
    }
    # The count tallies must be internally consistent with the responses.
    case_kind_counts: dict[str, int] = {}
    event_type_counts: dict[str, int] = {}
    rule_id_counts: dict[str, int] = {}
    for response in responses:
        case_kind_counts[response["case_kind"]] = case_kind_counts.get(response["case_kind"], 0) + 1
        event_key = response["event_type"] if response["event_type"] else "observation"
        event_type_counts[event_key] = event_type_counts.get(event_key, 0) + 1
        rule_id_counts[response["rule_id"]] = rule_id_counts.get(response["rule_id"], 0) + 1
    assert manifest["case_kind_counts"] == dict(sorted(case_kind_counts.items()))
    assert manifest["event_type_counts"] == dict(sorted(event_type_counts.items()))
    assert manifest["rule_id_counts"] == dict(sorted(rule_id_counts.items()))

    # manifest scenario_ids must match the responses' scenario set.
    response_scenarios = sorted({r["scenario_id"] for r in responses})
    assert manifest["scenario_ids"] == response_scenarios
    response_record_ids = [r["record_id"] for r in responses]
    assert manifest["record_ids"] == response_record_ids


def test_compiler_implementation_sha256_is_stable():
    first = compute_compiler_implementation_sha256()
    second = compute_compiler_implementation_sha256()
    assert first == second
    assert len(first) == 64


# ---------------------------------------------------------------------------
# Label authority invariant.
# ---------------------------------------------------------------------------


def test_label_authority_conventional_synthetic_in_all_records(compiled_bundle):
    responses = _responses(compiled_bundle)
    for response in responses:
        assert response["label_authority"] == "conventional_synthetic"


def test_manifest_and_receipt_label_authority_conventional_synthetic(compiled_bundle):
    manifest = json.loads(compiled_bundle["conventional_control_manifest.json"].decode("utf-8"))
    receipt = json.loads(compiled_bundle["a1_receipt.json"].decode("utf-8"))
    catalog = json.loads(compiled_bundle["conventional_rule_catalog.json"].decode("utf-8"))
    assert manifest["label_authority"] == "conventional_synthetic"
    assert receipt["label_authority"] == "conventional_synthetic"
    assert catalog["label_authority"] == "conventional_synthetic"


# ---------------------------------------------------------------------------
# Information boundary: no leakage fields.
# ---------------------------------------------------------------------------


_LEAKAGE_FIELDS = {
    "reference_label",
    "trace",
    "oracle",
    "verification",
    "after",
    "before",
    "event",
    "gold_class",
    "metric",
    "rationale",
    "explanation",
}


def test_no_leakage_fields_in_responses(compiled_bundle):
    responses = _responses(compiled_bundle)
    for response in responses:
        keys = {str(k).lower() for k in response}
        assert not (keys & _LEAKAGE_FIELDS), (
            f"response {response['record_id']} carries leakage fields: {keys & _LEAKAGE_FIELDS}"
        )


# ---------------------------------------------------------------------------
# Orchestration smoke test.
# ---------------------------------------------------------------------------


def test_orchestration_compile_artifacts_module_matches_helper():
    """The experiments/ orchestration helper must produce identical bytes."""

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_compile_conventional_generator_orch",
        ROOT / "experiments" / "e1" / "compile_conventional_generator.py",
    )
    assert spec is not None and spec.loader is not None
    orch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch)
    artifacts = orch.compile_artifacts(
        source_commit=_TEST_SOURCE_COMMIT,
        a0b2_receipt_path=A0B2_RECEIPT_PATH,
        response_abi_path=RESPONSE_ABI_PATH,
        tokenizer_codebook_path=TOKENIZER_CODEBOOK_PATH,
    )
    direct = _compile()
    assert set(artifacts.keys()) == set(direct.keys())
    for name in direct:
        assert artifacts[name] == direct[name], f"orchestration diverged: {name}"


# ---------------------------------------------------------------------------
# Two-mode provenance gate (same pattern as A0b1/A0b2).
# ---------------------------------------------------------------------------


def test_git_history_provenance_gate_two_mode():
    """Slice-aware provenance gate for the A1 receipt (defect 4).

    Two modes, mirroring the A0b1/A0b2 pattern:

    * Direct A1 mode: when HEAD changes exactly the four v5 artifacts (the A1
      artifact commit context), enforce S→A adjacency and receipt
      ``source_commit`` exactly.

    * Successor mode: otherwise, locate the commit that introduced the v5
      receipt and verify all four v5 artifacts remain byte-consistent through
      Git blob identity with that introduction commit.

    If the v5 artifacts are not yet committed (commit A has not landed), the
    gate verifies only that the frozen predecessor A0b2 receipt/ABI/codebook
    remain byte-consistent with their introduction commit.
    """

    v5_receipt_path = ROOT / "data" / "e1" / "v5" / "a1_receipt.json"
    if not v5_receipt_path.exists():
        # Commit A has not landed; verify the frozen predecessor artifacts only.
        _verify_frozen_predecessor_blobs()
        return

    expected_artifacts = {
        "conventional_rule_catalog.json",
        "conventional_control_responses.jsonl",
        "conventional_control_manifest.json",
        "a1_receipt.json",
    }

    # Read the committed receipt source_commit.
    receipt_text = _git("show", "HEAD:data/e1/v5/a1_receipt.json")
    receipt = json.loads(receipt_text)
    committed_source_commit = receipt["source_commit"]

    # Check if HEAD changes exactly the A1 v5 artifacts.
    parents = _git("show", "-s", "--format=%P", "HEAD").split()
    head_tip = parents[1] if len(parents) >= 2 else _git("rev-parse", "HEAD")

    head_diff = set(
        line for line in _git("diff", "--name-only", f"{head_tip}^", head_tip).splitlines() if line
    )
    v5_artifact_set = {f"data/e1/v5/{name}" for name in expected_artifacts}

    if head_diff == v5_artifact_set:
        # Direct A1 mode: enforce S→A adjacency exactly.
        implementation_commit = _git("rev-parse", f"{head_tip}^")
        assert committed_source_commit == implementation_commit, (
            f"receipt source_commit {committed_source_commit!r} does not match the "
            f"git-derived implementation commit {implementation_commit!r}"
        )
    else:
        # Successor mode: locate introduction commit, blob-identity check.
        receipt_rel = "data/e1/v5/a1_receipt.json"
        introductions = _git(
            "log", "--diff-filter=A", "--format=%H", "--", receipt_rel
        ).splitlines()
        assert introductions, f"no commit found introducing {receipt_rel}"
        frozen_commit = introductions[-1]
        for name in expected_artifacts:
            rel = f"data/e1/v5/{name}"
            frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
            current_blob = _git("hash-object", rel)
            assert current_blob == frozen_blob, f"frozen A1 artifact changed: {rel}"

    # In both modes, the frozen predecessor artifacts must also remain
    # byte-consistent with their introduction commit.
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
        pytest.fail(f"git command failed: {exc}")
    return completed.stdout.strip()


def _verify_frozen_predecessor_blobs() -> None:
    """Verify the pinned A0b2 receipt, ABI, and codebook remain byte-consistent."""

    receipt_rel = "data/e1/v4/a0b2_receipt.json"
    introductions = _git("log", "--diff-filter=A", "--format=%H", "--", receipt_rel).splitlines()
    assert introductions, f"no commit found introducing {receipt_rel}"
    frozen_commit = introductions[-1]
    for rel in (
        "data/e1/v4/a0b2_receipt.json",
        "data/e1/v4/response_abi.json",
        "data/e1/v4/tokenizer_codebook.json",
    ):
        frozen_blob = _git("rev-parse", f"{frozen_commit}:{rel}")
        current_blob = _git("hash-object", rel)
        assert current_blob == frozen_blob, f"frozen predecessor artifact changed: {rel}"
