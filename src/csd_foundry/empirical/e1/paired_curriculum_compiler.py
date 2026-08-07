"""E1 A2 paired-curriculum compiler.

This module (the A2 slice) is the final repository-side curriculum /
evaluation materialization. It compiles two training curricula (Foundry +
control) into a common codeword task format, tokenizes both with the frozen
``sshleifer/tiny-gpt2`` tokenizer, validates recordwise token isometry,
packages the development + clean evaluation sets, and instantiates the
PR #74 paired ``E1CurriculumEvaluationContract``.

Compilation flow (all deterministic, no model execution, no GPU):

1. Run the existing Foundry compiler to obtain raw training records (each
   carrying its oracle receipt, trace, and verification digest).
2. Project each Foundry record through the A0b2 ABI basis-disposition truth
   table to obtain ``semantic_class -> codeword``.
3. Load the A1 conventional responses (19 records carrying
   ``semantic_class`` / ``codeword``).
4. Build the common codeword task format (system prompt + user prompt +
   codeword target) for both arms.
5. Tokenize both arms with the frozen tokenizer and verify recordwise token
   isometry.
6. Package the development + clean evaluation cases.
7. Instantiate ``E1CurriculumEvaluationContract`` and emit 12 artifacts.

Five blocking correctness properties:

1. **Pinned predecessor receipts.** The A1 receipt SHA-256, the A0b2 receipt
   SHA-256, and the selection-contract digest are pinned as module constants
   and fail-closed on mismatch, so a coherently-substituted predecessor
   cannot authenticate the paired curriculum.

2. **ABI/codebook digest binding from the receipt.** The response ABI and
   tokenizer codebook constituent digests are read from the authenticated
   A0b2 receipt and re-verified against the supplied file bytes, so a swapped
   ABI or codebook cannot slip through.

3. **Recordwise token isometry.** For every one of the 19 pairs the control
   and Foundry prompt bytes are byte-identical, prompt token-ids are equal,
   the target is exactly one token, the sequence token counts match, the
   codeword tokenizes as a clean single-token suffix, no sequence is
   truncated, and every sequence fits in the 512-token context.

4. **Compilation invariants.** The Foundry TRAIN distribution
   (NA:3/NEITHER:1/REMOVES_ONLY:6/SURVIVES_ONLY:5/BOTH:4) and control TRAIN
   distribution (NA:3/NEITHER:5/REMOVES_ONLY:11) are compilation
   invariants; any mismatch fails closed.

5. **Foundry evidence binding.** The Foundry curriculum manifest binds the
   raw oracle and verification evidence digests read from the Foundry
   bundle, while the control manifest binds no executable evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e1.curriculum_evaluation_contract import (
    E1CurriculumArm,
    E1CurriculumArtifact,
    E1CurriculumEvaluationContract,
    E1EvaluationArtifact,
    E1LabelAuthority,
    compile_e1_curriculum_evaluation_contract,
)
from csd_foundry.empirical.e1.execution_splits import E1Split
from csd_foundry.empirical.e1.experiment_contract import E1ExperimentContract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    E1FoundryArtifactBundle,
    compile_e1_foundry_artifacts,
    load_artifact_records,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
    load_json_text,
)


class E1PairedCurriculumError(ValueError):
    """Raised when the paired curriculum cannot be compiled or reconstructed."""


# ---------------------------------------------------------------------------
# Schema and release identifiers.
# ---------------------------------------------------------------------------

_TASK_FORMAT_SCHEMA_VERSION = "e1-codeword-task-format/1"
_CONTROL_RECORD_SCHEMA = "e1-codeword-control-record/1"
_FOUNDRY_RECORD_SCHEMA = "e1-codeword-foundry-record/1"
_EVAL_CASE_SCHEMA = "e1-codeword-evaluation-case/1"
_CONTROL_MANIFEST_SCHEMA = "e1-codeword-control-manifest/1"
_FOUNDRY_MANIFEST_SCHEMA = "e1-codeword-foundry-manifest/1"
_EVAL_MANIFEST_SCHEMA = "e1-codeword-evaluation-manifest/1"
_TOKENIZATION_MANIFEST_SCHEMA = "e1-codeword-tokenization-manifest/1"
_PAIRED_MANIFEST_SCHEMA = "e1-paired-curriculum-manifest/1"
_A2_RECEIPT_SCHEMA = "e1-paired-curriculum-receipt/1"
_RELEASE = "e1-paired-curriculum/1"

# Predecessor source commits (read back from the authenticated receipts).
_PREDECESSOR_SELECTION_SOURCE_COMMIT = "cfac62da30d501f4744f88d31fee5d3096d1cfb6"

# ---------------------------------------------------------------------------
# Pinned predecessor identities (computed over the committed file bytes).
# ---------------------------------------------------------------------------

# A1 receipt SHA-256 over data/e1/v5/a1_receipt.json.
_EXPECTED_A1_RECEIPT_SHA256 = "84e4004a9df7d7a8fa1098fb8c703ea2037acbf3eecd6b922a8286a473469b24"

# A0b2 receipt SHA-256 over data/e1/v4/a0b2_receipt.json.
_EXPECTED_A0B2_RECEIPT_SHA256 = "6a033dbcfdae129e0013b1de50b452d38963492cec3a7c693254761f16c40c8a"

# Selection contract digest (e1-candidate/2 experiment-contract contract_digest).
# This is the FROZEN predecessor selection identity, compiled at the predecessor
# source commit. The paired ``E1CurriculumEvaluationContract`` embeds a selection
# reconstructed at the predecessor commit so its ``selection_contract_digest``
# equals this frozen constant (Defect 1: the frozen selection contract must not
# be reissued under A2's commit S).
_EXPECTED_SELECTION_CONTRACT_DIGEST = (
    "4a9ac4e8a0de98247b8f50b838ad7e67ba151b6e6c8167b2a8840e865b883f49"
)

# A0b2 metric digest (used for both primary and safety metric implementation).
_A0B2_METRIC_DIGEST = "0558a949afbbfcc55c46c24fb48fe5c8c5ecb26242a5f73a9b33838194d07f3d"

# Frozen tokenizer asset aggregate digest (mirrors the A0b2 codebook/receipt).
# Bound into ``paired_task_format.json``, ``tokenization_manifest.json``, and
# ``a2_receipt.json`` so a swapped tokenizer asset set cannot slip through.
_TOKENIZER_ASSET_AGGREGATE_DIGEST = (
    "fa91cdd29a17c266d450a7b713c7cb3ee9f63d778d2987550da429c55ff93891"
)

# Frozen tokenizer identity (mirrors the A0b2 codebook).
_TOKENIZER_REPOSITORY = "sshleifer/tiny-gpt2"
_TOKENIZER_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
_CONTEXT_LENGTH = 512

# Compilation population invariants (TRAIN split, 19 records).
_EXPECTED_RECORD_COUNT = 19
_EXPECTED_FOUNDRY_DISTRIBUTION = {
    "NOT_APPLICABLE": 3,
    "NEITHER": 1,
    "REMOVES_ONLY": 6,
    "SURVIVES_ONLY": 5,
    "BOTH": 4,
}
_EXPECTED_CONTROL_DISTRIBUTION = {
    "NOT_APPLICABLE": 3,
    "NEITHER": 5,
    "REMOVES_ONLY": 11,
    "SURVIVES_ONLY": 0,
    "BOTH": 0,
}

_GIT_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

# The common codeword task format system prompt. Identical for both arms.
#
# This is the minimal common A2 wrapper: it instructs the model to return the
# frozen codeword and nothing else. The verbose class-name enumeration from the
# A0b2 response ABI is deliberately NOT inlined here, because the largest
# Foundry training record (M-04/M-04/dependency-change) tokenizes to 490 tokens
# of canonical task input alone; inlining the class names pushes the sequence
# past the frozen 512-token execution envelope. The five codewords and their
# semantic-class bindings remain frozen in the A0b2 tokenizer codebook and the
# ``paired_task_format.json`` artifact, so the wrapper stays minimal while the
# task contract stays fully specified. The compiler fails closed if any record
# would still be truncated.
_SYSTEM_PROMPT = "Return the frozen response codeword and nothing else."

_CLAIM_BOUNDARY = (
    "This compiler materializes the final repository-side paired E1 curriculum "
    "and evaluation artifacts. It compiles the Foundry and control arms into a "
    "common codeword task format, tokenizes both with the frozen "
    "sshleifer/tiny-gpt2 tokenizer, validates recordwise token isometry, "
    "packages the development and clean evaluation sets, and instantiates the "
    "PR #74 paired curriculum/evaluation contract. It does not execute a model, "
    "fix a training recipe, allocate a GPU, expose protected metrics, or "
    "establish learning value or general transfer."
)

_GENERATION_COMMAND_TEMPLATE = (
    "python experiments/e1/compile_paired_curriculum.py --source-commit {source_commit}"
)
_VALIDATION_COMMAND_TEMPLATE = (
    "python experiments/e1/compile_paired_curriculum.py --source-commit {source_commit} --validate"
)


# ---------------------------------------------------------------------------
# Tokenizer loading.
# ---------------------------------------------------------------------------


def _load_frozen_tokenizer() -> Any:
    """Load the pinned tokenizer via ``transformers.AutoTokenizer``.

    Uses a dynamic import so that ``mypy src`` does not require transformers
    to be installed in the type-checking environment.
    """

    try:
        import importlib

        transformers_module = importlib.import_module("transformers")
        tokenizer_cls = transformers_module.AutoTokenizer
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise E1PairedCurriculumError(
            "transformers is required to tokenize the paired curriculum"
        ) from exc

    return tokenizer_cls.from_pretrained(_TOKENIZER_REPOSITORY, revision=_TOKENIZER_REVISION)


# ---------------------------------------------------------------------------
# Authentication: A0b2 receipt, A1 receipt, ABI, codebook.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthenticatedA0b2Receipt:
    """Authenticated A0b2 response-ABI receipt plus constituent digests."""

    receipt_sha256: str
    payload: dict[str, Any]
    abi_digest: str
    codebook_digest: str
    metric_digest: str
    source_commit: str


def authenticate_a0b2_receipt(receipt_bytes: bytes) -> AuthenticatedA0b2Receipt:
    """Authenticate the A0b2 response-ABI receipt (pinned SHA-256).

    The response ABI and tokenizer codebook constituent digests and the metric
    digest are read from the authenticated payload (they were pinned one hop
    earlier in the A0b2 module) so a coherently-substituted receipt cannot
    pass.
    """

    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha256 != _EXPECTED_A0B2_RECEIPT_SHA256:
        raise E1PairedCurriculumError(
            "A0b2 receipt SHA-256 mismatch: expected "
            f"{_EXPECTED_A0B2_RECEIPT_SHA256}, observed {receipt_sha256}"
        )

    payload: dict[str, Any] = json.loads(receipt_bytes.decode("utf-8"))
    if str(payload.get("schema_version")) != "e1-response-abi-receipt/1":
        raise E1PairedCurriculumError("A0b2 receipt schema_version is unsupported")

    constituents = payload.get("constituent_artifact_digests")
    if not isinstance(constituents, dict):
        raise E1PairedCurriculumError("A0b2 receipt constituent_artifact_digests must be an object")
    abi_digest = constituents.get("response_abi.json")
    codebook_digest = constituents.get("tokenizer_codebook.json")
    if not isinstance(abi_digest, str) or not isinstance(codebook_digest, str):
        raise E1PairedCurriculumError(
            "A0b2 receipt must carry response_abi.json and tokenizer_codebook.json digests"
        )
    metric_digest = payload.get("metric_digest")
    if not isinstance(metric_digest, str):
        raise E1PairedCurriculumError("A0b2 receipt must carry a metric_digest")

    source_commit = str(payload.get("source_commit"))
    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1PairedCurriculumError("A0b2 receipt source_commit must be a lowercase Git digest")

    return AuthenticatedA0b2Receipt(
        receipt_sha256=receipt_sha256,
        payload=payload,
        abi_digest=abi_digest,
        codebook_digest=codebook_digest,
        metric_digest=metric_digest,
        source_commit=source_commit,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedA1Receipt:
    """Authenticated A1 conventional-control receipt."""

    receipt_sha256: str
    payload: dict[str, Any]
    responses_digest: str
    source_commit: str
    selection_contract_digest: str


def authenticate_a1_receipt(receipt_bytes: bytes) -> AuthenticatedA1Receipt:
    """Authenticate the A1 conventional-control receipt (pinned SHA-256)."""

    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha256 != _EXPECTED_A1_RECEIPT_SHA256:
        raise E1PairedCurriculumError(
            "A1 receipt SHA-256 mismatch: expected "
            f"{_EXPECTED_A1_RECEIPT_SHA256}, observed {receipt_sha256}"
        )

    payload: dict[str, Any] = json.loads(receipt_bytes.decode("utf-8"))
    if str(payload.get("schema_version")) != "e1-conventional-control-receipt/1":
        raise E1PairedCurriculumError("A1 receipt schema_version is unsupported")

    constituents = payload.get("constituent_artifact_digests")
    if not isinstance(constituents, dict):
        raise E1PairedCurriculumError("A1 receipt constituent_artifact_digests must be an object")
    responses_digest = constituents.get("conventional_control_responses.jsonl")
    if not isinstance(responses_digest, str):
        raise E1PairedCurriculumError(
            "A1 receipt must carry conventional_control_responses.jsonl digest"
        )
    source_commit = str(payload.get("source_commit"))
    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1PairedCurriculumError("A1 receipt source_commit must be a lowercase Git digest")
    selection_digest = str(payload.get("selection_contract_digest"))
    if _SHA256_HEX.fullmatch(selection_digest) is None:
        raise E1PairedCurriculumError(
            "A1 receipt selection_contract_digest must be a SHA-256 digest"
        )
    return AuthenticatedA1Receipt(
        receipt_sha256=receipt_sha256,
        payload=payload,
        responses_digest=responses_digest,
        source_commit=source_commit,
        selection_contract_digest=selection_digest,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedABI:
    """Authenticated frozen response ABI plus the basis-disposition truth table."""

    abi_digest: str
    payload: dict[str, Any]
    semantic_classes: frozenset[str]
    truth_table: dict[tuple[bool, bool], str]


def _load_truth_table(rows: object) -> dict[tuple[bool, bool], str]:
    """Build the (removed, survives) -> semantic_class truth table from ABI rows."""

    if not isinstance(rows, list) or not rows:
        raise E1PairedCurriculumError("response ABI basis_truth_table must be a nonempty list")
    table: dict[tuple[bool, bool], str] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise E1PairedCurriculumError(
                f"response ABI basis_truth_table[{index}] must be an object"
            )
        removed = row.get("any_basis_removed")
        survives = row.get("any_basis_survives")
        semantic_class = row.get("semantic_class")
        if not isinstance(removed, bool) or not isinstance(survives, bool):
            raise E1PairedCurriculumError(
                f"response ABI basis_truth_table[{index}] booleans missing"
            )
        if not isinstance(semantic_class, str):
            raise E1PairedCurriculumError(
                f"response ABI basis_truth_table[{index}] semantic_class missing"
            )
        key = (removed, survives)
        if key in table:
            raise E1PairedCurriculumError(
                f"response ABI basis_truth_table[{index}] duplicates a (removed, survives) pair"
            )
        table[key] = semantic_class
    return table


def authenticate_response_abi(abi_bytes: bytes, *, expected_abi_digest: str) -> AuthenticatedABI:
    """Authenticate the frozen response ABI against the receipt-pinned digest."""

    abi_digest = hashlib.sha256(abi_bytes).hexdigest()
    if abi_digest != expected_abi_digest:
        raise E1PairedCurriculumError(
            f"response ABI digest mismatch: expected {expected_abi_digest}, observed {abi_digest}"
        )
    payload: dict[str, Any] = json.loads(abi_bytes.decode("utf-8"))
    if str(payload.get("schema_version")) != "e1-response-abi/1":
        raise E1PairedCurriculumError("response ABI schema_version is unsupported")
    semantic_classes = payload.get("semantic_classes")
    if not isinstance(semantic_classes, list):
        raise E1PairedCurriculumError("response ABI semantic_classes must be a list")
    classes = frozenset(str(item) for item in semantic_classes)
    truth_table = _load_truth_table(payload.get("basis_truth_table"))
    return AuthenticatedABI(
        abi_digest=abi_digest,
        payload=payload,
        semantic_classes=classes,
        truth_table=truth_table,
    )


@dataclass(frozen=True, slots=True)
class CodebookBinding:
    """One authenticated codeword binding (semantic_class -> codeword/tokens)."""

    codeword: str
    token_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AuthenticatedCodebook:
    """Authenticated frozen tokenizer codebook plus codeword bindings."""

    codebook_digest: str
    payload: dict[str, Any]
    binding_by_class: dict[str, CodebookBinding]


def authenticate_tokenizer_codebook(
    codebook_bytes: bytes, *, expected_codebook_digest: str
) -> AuthenticatedCodebook:
    """Authenticate the frozen tokenizer codebook against the receipt-pinned digest.

    The codeword and token-id bindings are READ from the codebook rather than
    independently mapped, so a changed A/B/C/D/E mapping is caught.
    """

    codebook_digest = hashlib.sha256(codebook_bytes).hexdigest()
    if codebook_digest != expected_codebook_digest:
        raise E1PairedCurriculumError(
            "tokenizer codebook digest mismatch: expected "
            f"{expected_codebook_digest}, observed {codebook_digest}"
        )
    payload: dict[str, Any] = json.loads(codebook_bytes.decode("utf-8"))
    if str(payload.get("schema_version")) != "e1-tokenizer-codebook/1":
        raise E1PairedCurriculumError("tokenizer codebook schema_version is unsupported")
    codewords = payload.get("codewords")
    if not isinstance(codewords, list):
        raise E1PairedCurriculumError("tokenizer codebook codewords must be a list")
    binding_by_class: dict[str, CodebookBinding] = {}
    for entry in codewords:
        if not isinstance(entry, dict):
            raise E1PairedCurriculumError("tokenizer codebook codeword entry must be an object")
        semantic_class = entry.get("semantic_class")
        codeword = entry.get("codeword")
        token_ids = entry.get("token_ids")
        token_count = entry.get("token_count")
        if not isinstance(semantic_class, str) or not isinstance(codeword, str):
            raise E1PairedCurriculumError(
                "tokenizer codebook codeword entry missing semantic_class/codeword"
            )
        if not isinstance(token_ids, list) or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in token_ids
        ):
            raise E1PairedCurriculumError(
                f"tokenizer codebook codeword {codeword!r} token_ids must be ints"
            )
        if not isinstance(token_count, int) or isinstance(token_count, bool):
            raise E1PairedCurriculumError(
                f"tokenizer codebook codeword {codeword!r} token_count must be an int"
            )
        if token_count != 1 or len(token_ids) != 1:
            raise E1PairedCurriculumError(
                f"tokenizer codebook codeword {codeword!r} must be single-token"
            )
        binding_by_class[semantic_class] = CodebookBinding(
            codeword=codeword,
            token_ids=tuple(token_ids),
        )
    return AuthenticatedCodebook(
        codebook_digest=codebook_digest,
        payload=payload,
        binding_by_class=binding_by_class,
    )


# ---------------------------------------------------------------------------
# Selection contract reconstruction.
# ---------------------------------------------------------------------------


def _reconstruct_selection_contract(source_commit: str) -> E1ExperimentContract:
    """Re-derive the selection contract from the overlay catalog at a commit.

    The overlay catalog and selection contract are built deterministically
    from the v0.1 registry and the M-12/M-14 development contrasts; this
    re-derivation does not execute semantics. The ``source_commit`` pins
    which commit the selection is materialized under (and therefore which
    digest it carries).
    """

    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )
    from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    return compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/2",
        source_commit=source_commit,
    )


def _reconstruct_frozen_selection_contract() -> E1ExperimentContract:
    """Reconstruct the FROZEN predecessor selection contract.

    The paired ``E1CurriculumEvaluationContract`` requires
    ``source_commit == selection.source_commit``. To preserve the frozen
    selection identity (Defect 1), the contract's embedded selection is
    reconstructed at the PREDECESSOR source commit, NOT A2's commit S. The
    resulting ``contract_digest`` equals the pinned
    ``_EXPECTED_SELECTION_CONTRACT_DIGEST``.

    The A2 receipt's own ``source_commit`` still equals S (the A2
    implementation commit); only the paired contract's selection identity is
    frozen to the predecessor.
    """

    selection = _reconstruct_selection_contract(_PREDECESSOR_SELECTION_SOURCE_COMMIT)
    if selection.contract_digest != _EXPECTED_SELECTION_CONTRACT_DIGEST:
        raise E1PairedCurriculumError(
            "frozen selection contract digest mismatch: expected "
            f"{_EXPECTED_SELECTION_CONTRACT_DIGEST}, observed {selection.contract_digest}"
        )
    return selection


def _authenticate_selection_contract_file(
    selection_contract_path: str, *, expected_digest: str
) -> dict[str, Any]:
    """Authenticate the on-disk predecessor selection contract file.

    The file carries the predecessor selection contract (compiled at the
    predecessor source commit) whose ``contract_digest`` must equal the
    pinned constant. Returns the parsed payload so callers can read its
    predecessor source commit.
    """

    content = Path(selection_contract_path).read_bytes()
    payload: dict[str, Any] = json.loads(content.decode("utf-8"))
    file_digest = payload.get("contract_digest")
    if not isinstance(file_digest, str) or file_digest != expected_digest:
        raise E1PairedCurriculumError(
            "selection contract file contract_digest mismatch: expected "
            f"{expected_digest}, observed {file_digest}"
        )
    file_source_commit = payload.get("source_commit")
    if (
        not isinstance(file_source_commit, str)
        or file_source_commit != _PREDECESSOR_SELECTION_SOURCE_COMMIT
    ):
        raise E1PairedCurriculumError(
            "selection contract file source_commit mismatch: expected "
            f"{_PREDECESSOR_SELECTION_SOURCE_COMMIT}, observed {file_source_commit}"
        )
    return payload


# ---------------------------------------------------------------------------
# Foundry compilation and A0b2 projection.
# ---------------------------------------------------------------------------


def _compile_foundry_bundle(
    selection: E1ExperimentContract, *, source_commit: str
) -> E1FoundryArtifactBundle:
    """Compile the Foundry training records at the supplied source commit.

    The Foundry compiler executes the oracle/runner/invariant verification to
    produce the raw training records. A2 binds the resulting oracle and
    verification evidence digests into the Foundry curriculum manifest.
    """

    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    return compile_e1_foundry_artifacts(
        overlay_catalog,
        selection,
        release="e1-foundry-artifacts/1",
        selection_release=selection.release,
        source_commit=source_commit,
    )


def _project_foundry_semantic_class(
    record: Mapping[str, object], truth_table: dict[tuple[bool, bool], str]
) -> str:
    """Project one Foundry record through the A0b2 truth table.

    Observations map to ``NOT_APPLICABLE`` (basis disposition is undefined).
    Transitions map through the (any_basis_removed, any_basis_survives) pair
    read from the executable trace bound into the Foundry reference label.
    """

    record_id = str(record.get("record_id", ""))
    case_type = record.get("case_type")
    if case_type == "observation":
        return "NOT_APPLICABLE"
    if case_type != "transition":
        raise E1PairedCurriculumError(f"{record_id}: unsupported Foundry case_type {case_type!r}")
    reference_label = record.get("reference_label")
    if not isinstance(reference_label, dict):
        raise E1PairedCurriculumError(f"{record_id}: reference_label missing")
    trace = reference_label.get("trace")
    if not isinstance(trace, dict):
        raise E1PairedCurriculumError(f"{record_id}: trace missing")
    removed_bases = trace.get("removed_bases")
    surviving_bases = trace.get("surviving_bases")
    if not isinstance(removed_bases, list) or not isinstance(surviving_bases, list):
        raise E1PairedCurriculumError(f"{record_id}: trace basis lists missing")
    key = (len(removed_bases) > 0, len(surviving_bases) > 0)
    if key not in truth_table:
        raise E1PairedCurriculumError(f"{record_id}: truth table has no entry for {key}")
    return truth_table[key]


# ---------------------------------------------------------------------------
# A1 conventional response loading.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConventionalResponse:
    """One A1 conventional response projected onto the common task format."""

    record_id: str
    scenario_id: str
    case_kind: str
    event_type: str
    semantic_class: str
    codeword: str
    token_ids: tuple[int, ...]
    task_input_digest: str


def _load_conventional_responses(
    responses_bytes: bytes,
    *,
    codebook: AuthenticatedCodebook,
    abi: AuthenticatedABI,
    expected_responses_digest: str,
) -> tuple[ConventionalResponse, ...]:
    """Load and authenticate the 19 A1 conventional responses.

    The codeword and token_ids are RE-RESOLVED from the authenticated codebook
    by each response's ``semantic_class`` and cross-checked against the value
    stored on the response, so a changed A/B/E mapping that slips past the
    codebook digest is still caught. Each response's ``task_input_digest`` is
    retained so the paired compiler can require it to equal the SHA-256 of the
    paired record's canonical task input text (Defect 2).
    """

    observed_digest = hashlib.sha256(responses_bytes).hexdigest()
    if observed_digest != expected_responses_digest:
        raise E1PairedCurriculumError(
            "A1 conventional responses digest mismatch: expected "
            f"{expected_responses_digest}, observed {observed_digest}"
        )

    responses: list[ConventionalResponse] = []
    for line_number, line in enumerate(responses_bytes.decode("utf-8").splitlines(), start=1):
        parsed = load_json_text(line)
        if not isinstance(parsed, dict):
            raise E1PairedCurriculumError(f"A1 response line {line_number} is not an object")
        record_id = parsed.get("record_id")
        scenario_id = parsed.get("scenario_id")
        case_kind = parsed.get("case_kind")
        event_type = parsed.get("event_type")
        semantic_class = parsed.get("semantic_class")
        stored_codeword = parsed.get("codeword")
        stored_token_ids = parsed.get("token_ids")
        task_input_digest = parsed.get("task_input_digest")
        if not (
            isinstance(record_id, str)
            and isinstance(scenario_id, str)
            and isinstance(case_kind, str)
            and isinstance(semantic_class, str)
        ):
            raise E1PairedCurriculumError(
                f"A1 response line {line_number} missing required string fields"
            )
        if (
            not isinstance(task_input_digest, str)
            or _SHA256_HEX.fullmatch(task_input_digest) is None
        ):
            raise E1PairedCurriculumError(
                f"A1 response line {line_number}: task_input_digest must be a SHA-256 digest"
            )
        if semantic_class not in abi.semantic_classes:
            raise E1PairedCurriculumError(
                f"A1 response line {line_number}: semantic_class {semantic_class!r} "
                "absent from authenticated ABI"
            )
        if semantic_class not in codebook.binding_by_class:
            raise E1PairedCurriculumError(
                f"A1 response line {line_number}: semantic_class {semantic_class!r} "
                "absent from authenticated codebook"
            )
        binding = codebook.binding_by_class[semantic_class]
        if stored_codeword != binding.codeword:
            raise E1PairedCurriculumError(
                f"A1 response line {line_number}: codeword {stored_codeword!r} "
                f"disagrees with codebook {binding.codeword!r}"
            )
        if not isinstance(stored_token_ids, list) or tuple(stored_token_ids) != binding.token_ids:
            raise E1PairedCurriculumError(
                f"A1 response line {line_number}: token_ids disagree with codebook"
            )
        event_type_text = event_type if isinstance(event_type, str) and event_type else ""
        responses.append(
            ConventionalResponse(
                record_id=record_id,
                scenario_id=scenario_id,
                case_kind=case_kind,
                event_type=event_type_text,
                semantic_class=semantic_class,
                codeword=binding.codeword,
                token_ids=binding.token_ids,
                task_input_digest=task_input_digest,
            )
        )
    result = tuple(sorted(responses, key=lambda item: item.record_id))
    if len({item.record_id for item in result}) != len(result):
        raise E1PairedCurriculumError("A1 responses contain duplicate record IDs")
    return result


# ---------------------------------------------------------------------------
# Common codeword task format.
# ---------------------------------------------------------------------------


def build_task_format(codeword_set: tuple[str, ...] | None = None) -> dict[str, object]:
    """Build the common codeword task format definition.

    Parameters
    ----------
    codeword_set:
        Optional sorted tuple of the frozen codeword strings. When omitted the
        canonical five-codeword set (``["A", "B", "C", "D", "E"]``) is used.
    """

    return {
        "schema_version": _TASK_FORMAT_SCHEMA_VERSION,
        "release": _RELEASE,
        "system_prompt": _SYSTEM_PROMPT,
        "prompt_roles": ["system", "user"],
        "target_field": "codeword",
        "target_encoding": "single_token_codeword",
        "user_encoding": "canonical_json_text",
        "context_length": _CONTEXT_LENGTH,
        "tokenizer_repository": _TOKENIZER_REPOSITORY,
        "tokenizer_revision": _TOKENIZER_REVISION,
        "tokenizer_asset_aggregate_digest": _TOKENIZER_ASSET_AGGREGATE_DIGEST,
        "codeword_set": list(codeword_set)
        if codeword_set is not None
        else ["A", "B", "C", "D", "E"],
        "claim_boundary": _CLAIM_BOUNDARY,
    }


def build_task_format_digest(codeword_set: tuple[str, ...] | None = None) -> str:
    return canonical_sha256(build_task_format(codeword_set))


def _build_semantic_codebook(codebook: AuthenticatedCodebook) -> list[dict[str, object]]:
    """Materialize the semantic codebook from authenticated A0b2 codebook bytes.

    Each entry binds one ``semantic_class`` to its frozen codeword and the
    single tokenizer token id, in the codebook's canonical (codeword-sorted)
    order so a swapped mapping cannot slip through.
    """

    entries = sorted(
        codebook.payload.get("codewords", []), key=lambda entry: str(entry["codeword"])
    )
    semantic_codebook: list[dict[str, object]] = []
    for entry in entries:
        semantic_codebook.append(
            {
                "semantic_class": str(entry["semantic_class"]),
                "codeword": str(entry["codeword"]),
                "token_ids": list(
                    codebook.binding_by_class[str(entry["semantic_class"])].token_ids
                ),
                "token_count": len(
                    codebook.binding_by_class[str(entry["semantic_class"])].token_ids
                ),
            }
        )
    return semantic_codebook


# The canonical five-codeword set bound by the frozen tokenizer codebook.
_CANONICAL_CODEWORD_SET: tuple[str, ...] = ("A", "B", "C", "D", "E")


# ---------------------------------------------------------------------------
# Common record construction.
# ---------------------------------------------------------------------------


def _prompt_messages(user_content: str) -> tuple[dict[str, str], ...]:
    """Build the (system, user) prompt-message pair for one record.

    ``user_content`` is the serialization form (canonical JSON text without its
    trailing newline) so the E0-H serializer produces clean ``\\n`` boundaries.
    """

    return (
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    )


def _canonical_task_input_text(foundry_record: Mapping[str, object]) -> str:
    """Extract the canonical task input text from a Foundry record.

    The Foundry compiler stores the user-message content as
    ``canonical_json_text(task_input)``, which carries a single trailing
    ``\\n`` (the canonical-JSON terminator). A1 computes its
    ``task_input_digest`` as the SHA-256 of this exact text, so the digest
    check (Defect 2) must run over this WITH-newline form.
    """

    prompt_messages = foundry_record.get("prompt_messages")
    if not isinstance(prompt_messages, list) or len(prompt_messages) != 2:
        raise E1PairedCurriculumError(
            f"{foundry_record.get('record_id')}: prompt_messages must be a 2-element list"
        )
    user_message = prompt_messages[1]
    if not isinstance(user_message, dict) or user_message.get("role") != "user":
        raise E1PairedCurriculumError("Foundry user message missing or wrong role")
    content = user_message.get("content")
    if not isinstance(content, str) or not content:
        raise E1PairedCurriculumError("Foundry user message content must be nonempty")
    return content


def _serialization_user_content(canonical_task_input_text: str) -> str:
    """Strip the canonical-JSON trailing newline for the E0-H serializer.

    The frozen E0-H serializer joins ``(system, user, codeword)`` with ``\\n``;
    because the canonical task input text already terminates with ``\\n``, the
    trailing newline is removed here so the join produces exactly one ``\\n``
    separator before the codeword (preserving codeword suffix isometry).
    """

    if not canonical_task_input_text.endswith("\n"):
        raise E1PairedCurriculumError("canonical task input text must terminate with a newline")
    return canonical_task_input_text.removesuffix("\n")


def _task_input_digest(canonical_task_input_text: str) -> str:
    """SHA-256 of the canonical task input text (matches A1's semantics)."""

    return hashlib.sha256(canonical_task_input_text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PairedRecord:
    """One tokenized codeword task record (control or Foundry)."""

    arm: str
    record_id: str
    scenario_id: str
    family_digest: str
    case_id: str
    case_type: str
    split: str
    label_authority: str
    semantic_class: str
    codeword: str
    codeword_token_id: int
    task_input_digest: str
    prompt_messages: tuple[dict[str, str], ...]
    prompt_bytes: str
    prompt_token_ids: tuple[int, ...]
    sequence_token_ids: tuple[int, ...]
    prompt_token_count: int
    target_token_count: int
    sequence_token_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _CONTROL_RECORD_SCHEMA
            if self.arm == E1CurriculumArm.CONTROL.value
            else _FOUNDRY_RECORD_SCHEMA,
            "arm": self.arm,
            "record_id": self.record_id,
            "scenario_id": self.scenario_id,
            "family_digest": self.family_digest,
            "case_id": self.case_id,
            "case_type": self.case_type,
            "split": self.split,
            "label_authority": self.label_authority,
            "semantic_class": self.semantic_class,
            "codeword": self.codeword,
            "codeword_token_id": self.codeword_token_id,
            "task_input_digest": self.task_input_digest,
            "prompt_messages": [dict(item) for item in self.prompt_messages],
            "prompt_bytes": self.prompt_bytes,
            "prompt_token_ids": list(self.prompt_token_ids),
            "sequence_token_ids": list(self.sequence_token_ids),
            "prompt_token_count": self.prompt_token_count,
            "target_token_count": self.target_token_count,
            "sequence_token_count": self.sequence_token_count,
        }


def _tokenize_record(
    *,
    tokenizer: Any,
    record_id: str,
    user_content: str,
    codeword: str,
    codeword_token_id: int,
) -> tuple[str, tuple[int, ...], tuple[int, ...]]:
    """Tokenize one record's prompt and full training sequence (E0-H pattern).

    The frozen E0-H serializer joins ``(system_content, user_content,
    codeword)`` with ``\\n``:

    .. code-block:: python

        target_prefix = system_content + "\\n" + user_content + "\\n"
        training_text = "\\n".join((system_content, user_content, codeword))

    ``user_content`` is the serialization form (canonical JSON text without its
    trailing newline) so the join yields exactly one ``\\n`` before the
    codeword. ``prompt_text`` carries the trailing separator (``target_prefix``)
    so codeword suffix isometry holds:

    .. code-block:: python

        tokenize(target_prefix + codeword) == tokenize(target_prefix)
            + [frozen_codeword_token_id]

    Tokenization is performed WITHOUT truncation. If the resulting sequence
    exceeds the frozen 512-token context, the compiler fails closed with a
    diagnostic carrying the record id, observed length, and overflow.
    """

    target_prefix = _SYSTEM_PROMPT + "\n" + user_content + "\n"
    training_text = "\n".join((_SYSTEM_PROMPT, user_content, codeword))
    if training_text != target_prefix + codeword:
        raise E1PairedCurriculumError(f"{record_id}: E0-H serializer invariant violated")
    prompt_encoding = tokenizer(target_prefix, add_special_tokens=True)
    prompt_token_ids = tuple(int(value) for value in prompt_encoding["input_ids"])
    sequence_encoding = tokenizer(training_text, add_special_tokens=True)
    sequence_token_ids = tuple(int(value) for value in sequence_encoding["input_ids"])
    if len(sequence_token_ids) > _CONTEXT_LENGTH:
        raise E1PairedCurriculumError(
            f"{record_id}: sequence exceeds frozen context length "
            f"(observed_sequence_tokens={len(sequence_token_ids)}, "
            f"context_length={_CONTEXT_LENGTH}, "
            f"overflow_tokens={len(sequence_token_ids) - _CONTEXT_LENGTH}, "
            f"tokenizer_revision={_TOKENIZER_REVISION})"
        )
    return target_prefix, prompt_token_ids, sequence_token_ids


def _build_foundry_record(
    foundry_record: Mapping[str, object],
    *,
    semantic_class: str,
    codeword: str,
    codeword_token_id: int,
    task_input_digest: str,
    tokenizer: Any,
) -> PairedRecord:
    """Build one Foundry codeword task record."""

    canonical_text = _canonical_task_input_text(foundry_record)
    user_content = _serialization_user_content(canonical_text)
    prompt_text, prompt_ids, sequence_ids = _tokenize_record(
        tokenizer=tokenizer,
        record_id=str(foundry_record["record_id"]),
        user_content=user_content,
        codeword=codeword,
        codeword_token_id=codeword_token_id,
    )
    return PairedRecord(
        arm=E1CurriculumArm.FOUNDRY.value,
        record_id=str(foundry_record["record_id"]),
        scenario_id=str(foundry_record["scenario_id"]),
        family_digest=str(foundry_record["family_digest"]),
        case_id=str(foundry_record["case_id"]),
        case_type=str(foundry_record["case_type"]),
        split=str(foundry_record["split"]),
        label_authority="executable_semantics",
        semantic_class=semantic_class,
        codeword=codeword,
        codeword_token_id=codeword_token_id,
        task_input_digest=task_input_digest,
        prompt_messages=_prompt_messages(user_content),
        prompt_bytes=prompt_text,
        prompt_token_ids=prompt_ids,
        sequence_token_ids=sequence_ids,
        prompt_token_count=len(prompt_ids),
        target_token_count=1,
        sequence_token_count=len(sequence_ids),
    )


def _build_control_record(
    foundry_record: Mapping[str, object],
    response: ConventionalResponse,
    *,
    task_input_digest: str,
    tokenizer: Any,
) -> PairedRecord:
    """Build one control codeword task record.

    The control arm reuses the EXACT Foundry prompt (byte-identical user
    content) and accepts the A1 conventional codeword as its target. The A1
    ``task_input_digest`` is required to equal the SHA-256 of the paired
    record's canonical task input text before either record is produced
    (Defect 2).
    """

    canonical_text = _canonical_task_input_text(foundry_record)
    user_content = _serialization_user_content(canonical_text)
    prompt_text, prompt_ids, sequence_ids = _tokenize_record(
        tokenizer=tokenizer,
        record_id=str(foundry_record["record_id"]),
        user_content=user_content,
        codeword=response.codeword,
        codeword_token_id=response.token_ids[0],
    )
    return PairedRecord(
        arm=E1CurriculumArm.CONTROL.value,
        record_id=str(foundry_record["record_id"]),
        scenario_id=str(foundry_record["scenario_id"]),
        family_digest=str(foundry_record["family_digest"]),
        case_id=str(foundry_record["case_id"]),
        case_type=str(foundry_record["case_type"]),
        split=str(foundry_record["split"]),
        label_authority="conventional_synthetic",
        semantic_class=response.semantic_class,
        codeword=response.codeword,
        codeword_token_id=response.token_ids[0],
        task_input_digest=task_input_digest,
        prompt_messages=_prompt_messages(user_content),
        prompt_bytes=prompt_text,
        prompt_token_ids=prompt_ids,
        sequence_token_ids=sequence_ids,
        prompt_token_count=len(prompt_ids),
        target_token_count=1,
        sequence_token_count=len(sequence_ids),
    )


# ---------------------------------------------------------------------------
# Token isometry validation.
# ---------------------------------------------------------------------------


def _validate_pair_isometry(
    control: PairedRecord, foundry: PairedRecord, *, tokenizer: Any
) -> None:
    """Validate every recordwise token-isometry requirement for one pair."""

    pair_id = control.record_id
    if control.record_id != foundry.record_id:
        raise E1PairedCurriculumError("control and Foundry records are misaligned")
    if control.prompt_bytes != foundry.prompt_bytes:
        raise E1PairedCurriculumError(f"{pair_id}: prompt bytes differ between arms")
    if control.prompt_token_ids != foundry.prompt_token_ids:
        raise E1PairedCurriculumError(f"{pair_id}: prompt token ids differ between arms")
    if control.target_token_count != 1:
        raise E1PairedCurriculumError(f"{pair_id}: control target is not single-token")
    if foundry.target_token_count != 1:
        raise E1PairedCurriculumError(f"{pair_id}: foundry target is not single-token")
    if control.sequence_token_count != foundry.sequence_token_count:
        raise E1PairedCurriculumError(
            f"{pair_id}: sequence token counts differ ({control.sequence_token_count} "
            f"vs {foundry.sequence_token_count})"
        )
    # Codeword suffix isometry: tokenize(prompt_text + codeword) must equal
    # prompt_token_ids + [frozen_codeword_token_id] for both arms.
    for record in (control, foundry):
        combined_ids = tokenizer(record.prompt_bytes + record.codeword, add_special_tokens=True)[
            "input_ids"
        ]
        combined = tuple(int(value) for value in combined_ids)
        expected = record.prompt_token_ids + (record.codeword_token_id,)
        if combined != expected:
            raise E1PairedCurriculumError(f"{pair_id}: {record.arm} codeword isometry violation")
    # Context-length gate: every sequence must fit in the frozen 512-token
    # envelope with zero truncation. (``_tokenize_record`` already fails closed
    # on overflow at construction time; this is the paired-record-level guard.)
    if control.sequence_token_count > _CONTEXT_LENGTH:
        raise E1PairedCurriculumError(
            f"{pair_id}: control sequence exceeds context length "
            f"({control.sequence_token_count} > {_CONTEXT_LENGTH})"
        )
    if foundry.sequence_token_count > _CONTEXT_LENGTH:
        raise E1PairedCurriculumError(
            f"{pair_id}: foundry sequence exceeds context length "
            f"({foundry.sequence_token_count} > {_CONTEXT_LENGTH})"
        )


# ---------------------------------------------------------------------------
# Evaluation cases.
# ---------------------------------------------------------------------------


def _load_evaluation_cases(
    cases_bytes: bytes,
    *,
    codebook: AuthenticatedCodebook,
) -> tuple[dict[str, object], ...]:
    """Load the 8 evaluation cases and re-resolve codewords from the codebook."""

    cases: list[dict[str, object]] = []
    for line_number, line in enumerate(cases_bytes.decode("utf-8").splitlines(), start=1):
        parsed: dict[str, Any] = json.loads(line)
        case: dict[str, object] = dict(parsed)
        semantic_class = case.get("gold_class")
        stored_codeword = case.get("codeword")
        if not isinstance(semantic_class, str):
            raise E1PairedCurriculumError(f"evaluation case line {line_number} missing gold_class")
        if semantic_class not in codebook.binding_by_class:
            raise E1PairedCurriculumError(
                f"evaluation case line {line_number}: gold_class absent from codebook"
            )
        binding = codebook.binding_by_class[semantic_class]
        if stored_codeword != binding.codeword:
            raise E1PairedCurriculumError(
                f"evaluation case line {line_number}: codeword disagrees with codebook"
            )
        case["schema_version"] = _EVAL_CASE_SCHEMA
        case["codeword_token_id"] = binding.token_ids[0]
        cases.append(case)
    return tuple(cases)


def _split_evaluation_cases(
    cases: tuple[dict[str, object], ...],
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    """Split the 8 evaluation cases into 4 development + 4 clean records."""

    development = tuple(
        sorted(
            (case for case in cases if case.get("cohort") == "development"),
            key=lambda item: str(item["case_id"]),
        )
    )
    clean = tuple(
        sorted(
            (case for case in cases if case.get("cohort") == "clean"),
            key=lambda item: str(item["case_id"]),
        )
    )
    if len(development) != 4:
        raise E1PairedCurriculumError(
            f"expected 4 development evaluation cases, observed {len(development)}"
        )
    if len(clean) != 4:
        raise E1PairedCurriculumError(f"expected 4 clean evaluation cases, observed {len(clean)}")
    return development, clean


# ---------------------------------------------------------------------------
# Serialization helpers.
# ---------------------------------------------------------------------------


def _jsonl(records: tuple[dict[str, object], ...]) -> bytes:
    return b"".join(canonical_json_bytes(record) for record in records)


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _command_digest(template: str, source_commit: str) -> str:
    return hashlib.sha256(template.format(source_commit=source_commit).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Distribution validation.
# ---------------------------------------------------------------------------


def _validate_distribution(
    records: tuple[PairedRecord, ...],
    expected: Mapping[str, int],
    *,
    arm: str,
) -> None:
    counts: dict[str, int] = {key: 0 for key in expected}
    for record in records:
        counts[record.semantic_class] = counts.get(record.semantic_class, 0) + 1
    if counts != dict(expected):
        raise E1PairedCurriculumError(
            f"{arm} distribution mismatch: expected {dict(expected)}, observed {counts}"
        )


# ---------------------------------------------------------------------------
# Tokenization receipt.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenizationReceipt:
    """Per-record tokenization receipt binding one control/Foundry pair."""

    record_id: str
    control_prompt_bytes_digest: str
    foundry_prompt_bytes_digest: str
    control_prompt_token_ids: tuple[int, ...]
    foundry_prompt_token_ids: tuple[int, ...]
    control_sequence_token_count: int
    foundry_sequence_token_count: int
    control_target_token_count: int
    foundry_target_token_count: int
    prompt_bytes_identical: bool
    prompt_token_ids_identical: bool
    sequence_token_counts_equal: bool
    codeword_isometry_control: bool
    codeword_isometry_foundry: bool
    truncated: bool
    within_context_length: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "control_prompt_bytes_digest": self.control_prompt_bytes_digest,
            "foundry_prompt_bytes_digest": self.foundry_prompt_bytes_digest,
            "control_prompt_token_ids": list(self.control_prompt_token_ids),
            "foundry_prompt_token_ids": list(self.foundry_prompt_token_ids),
            "control_sequence_token_count": self.control_sequence_token_count,
            "foundry_sequence_token_count": self.foundry_sequence_token_count,
            "control_target_token_count": self.control_target_token_count,
            "foundry_target_token_count": self.foundry_target_token_count,
            "prompt_bytes_identical": self.prompt_bytes_identical,
            "prompt_token_ids_identical": self.prompt_token_ids_identical,
            "sequence_token_counts_equal": self.sequence_token_counts_equal,
            "codeword_isometry_control": self.codeword_isometry_control,
            "codeword_isometry_foundry": self.codeword_isometry_foundry,
            "truncated": self.truncated,
            "within_context_length": self.within_context_length,
        }


def _build_tokenization_receipt(
    control: PairedRecord, foundry: PairedRecord, *, tokenizer: Any
) -> TokenizationReceipt:
    """Build one tokenization receipt after validating the pair isometry."""

    _validate_pair_isometry(control, foundry, tokenizer=tokenizer)
    return TokenizationReceipt(
        record_id=control.record_id,
        control_prompt_bytes_digest=_digest(control.prompt_bytes.encode("utf-8")),
        foundry_prompt_bytes_digest=_digest(foundry.prompt_bytes.encode("utf-8")),
        control_prompt_token_ids=control.prompt_token_ids,
        foundry_prompt_token_ids=foundry.prompt_token_ids,
        control_sequence_token_count=control.sequence_token_count,
        foundry_sequence_token_count=foundry.sequence_token_count,
        control_target_token_count=control.target_token_count,
        foundry_target_token_count=foundry.target_token_count,
        prompt_bytes_identical=control.prompt_bytes == foundry.prompt_bytes,
        prompt_token_ids_identical=control.prompt_token_ids == foundry.prompt_token_ids,
        sequence_token_counts_equal=(control.sequence_token_count == foundry.sequence_token_count),
        codeword_isometry_control=True,
        codeword_isometry_foundry=True,
        truncated=False,
        within_context_length=control.sequence_token_count <= _CONTEXT_LENGTH,
    )


# ---------------------------------------------------------------------------
# Compilation entry point.
# ---------------------------------------------------------------------------


def compile_paired_curriculum(
    *,
    source_commit: str,
    a1_receipt_path: str,
    a1_responses_path: str,
    a0b2_receipt_path: str,
    response_abi_path: str,
    tokenizer_codebook_path: str,
    evaluation_cases_path: str,
    selection_contract_path: str,
) -> dict[str, bytes]:
    """Compile the 12 paired-curriculum artifacts keyed by output filename.

    Parameters
    ----------
    source_commit:
        The git commit SHA that produces these artifacts (commit S in the spec).
    a1_receipt_path:
        Path to the A1 conventional-control receipt
        (``data/e1/v5/a1_receipt.json``).
    a1_responses_path:
        Path to the 19 A1 conventional responses
        (``data/e1/v5/conventional_control_responses.jsonl``).
    a0b2_receipt_path:
        Path to the A0b2 response-ABI receipt
        (``data/e1/v4/a0b2_receipt.json``).
    response_abi_path:
        Path to the frozen response ABI (``data/e1/v4/response_abi.json``).
    tokenizer_codebook_path:
        Path to the frozen tokenizer codebook
        (``data/e1/v4/tokenizer_codebook.json``).
    evaluation_cases_path:
        Path to the 8 evaluation cases
        (``data/e1/v4/evaluation_cases.jsonl``).
    selection_contract_path:
        Path to the predecessor selection contract
        (``data/e1/v2/selection_contract.json``).
    """

    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1PairedCurriculumError("source_commit must be a lowercase Git digest")

    # 1. Authenticate the predecessor receipts and constituents.
    a0b2_receipt = authenticate_a0b2_receipt(Path(a0b2_receipt_path).read_bytes())
    a1_receipt = authenticate_a1_receipt(Path(a1_receipt_path).read_bytes())
    abi = authenticate_response_abi(
        Path(response_abi_path).read_bytes(), expected_abi_digest=a0b2_receipt.abi_digest
    )
    codebook = authenticate_tokenizer_codebook(
        Path(tokenizer_codebook_path).read_bytes(),
        expected_codebook_digest=a0b2_receipt.codebook_digest,
    )
    if a0b2_receipt.metric_digest != _A0B2_METRIC_DIGEST:
        raise E1PairedCurriculumError(
            "A0b2 metric_digest mismatch: expected "
            f"{_A0B2_METRIC_DIGEST}, observed {a0b2_receipt.metric_digest}"
        )
    if a1_receipt.selection_contract_digest != _EXPECTED_SELECTION_CONTRACT_DIGEST:
        raise E1PairedCurriculumError(
            "A1 receipt selection_contract_digest mismatch: expected "
            f"{_EXPECTED_SELECTION_CONTRACT_DIGEST}, observed "
            f"{a1_receipt.selection_contract_digest}"
        )
    _authenticate_selection_contract_file(
        selection_contract_path, expected_digest=_EXPECTED_SELECTION_CONTRACT_DIGEST
    )

    # 2. Reconstruct the selection contracts.
    # The Foundry bundle is compiled against the A2-time selection (compiled at
    # the A2 ``source_commit``) because the Foundry compiler requires
    # ``selection.source_commit == source_commit``. The paired
    # ``E1CurriculumEvaluationContract`` embeds the FROZEN predecessor selection
    # (compiled at the predecessor commit) so its ``selection_contract_digest``
    # preserves the frozen identity (Defect 1).
    selection = _reconstruct_selection_contract(source_commit)
    frozen_selection = _reconstruct_frozen_selection_contract()

    # 3. Compile the Foundry bundle (executes oracle/runner/verification).
    foundry_bundle = _compile_foundry_bundle(selection, source_commit=source_commit)

    # 4. Load and project the Foundry training records.
    foundry_train_records = load_artifact_records(
        foundry_bundle.file("foundry_train.jsonl").content
    )
    if len(foundry_train_records) != _EXPECTED_RECORD_COUNT:
        raise E1PairedCurriculumError(
            f"expected {_EXPECTED_RECORD_COUNT} Foundry training records, "
            f"observed {len(foundry_train_records)}"
        )
    foundry_train_records = tuple(
        sorted(foundry_train_records, key=lambda item: str(item["record_id"]))
    )

    # 5. Load the A1 conventional responses.
    conventional_responses = _load_conventional_responses(
        Path(a1_responses_path).read_bytes(),
        codebook=codebook,
        abi=abi,
        expected_responses_digest=a1_receipt.responses_digest,
    )
    if len(conventional_responses) != _EXPECTED_RECORD_COUNT:
        raise E1PairedCurriculumError(
            f"expected {_EXPECTED_RECORD_COUNT} A1 responses, "
            f"observed {len(conventional_responses)}"
        )
    response_by_record_id = {item.record_id: item for item in conventional_responses}

    # 6. Load and split the evaluation cases. The supplied bytes are
    #    authenticated against the A0b2 receipt's ``evaluation_cases.jsonl``
    #    constituent digest BEFORE any case is interpreted (Defect 6).
    evaluation_cases_bytes = Path(evaluation_cases_path).read_bytes()
    evaluation_cases_digest = hashlib.sha256(evaluation_cases_bytes).hexdigest()
    expected_evaluation_cases_digest = a0b2_receipt.payload.get(
        "constituent_artifact_digests", {}
    ).get("evaluation_cases.jsonl")
    if not isinstance(expected_evaluation_cases_digest, str):
        raise E1PairedCurriculumError(
            "A0b2 receipt must carry an evaluation_cases.jsonl constituent digest"
        )
    if evaluation_cases_digest != expected_evaluation_cases_digest:
        raise E1PairedCurriculumError(
            "evaluation_cases.jsonl digest mismatch: expected "
            f"{expected_evaluation_cases_digest}, observed {evaluation_cases_digest}"
        )
    evaluation_cases = _load_evaluation_cases(evaluation_cases_bytes, codebook=codebook)
    development_cases, clean_cases = _split_evaluation_cases(evaluation_cases)

    # 7. Build the common task format (codeword set from authenticated codebook)
    #    and materialize the semantic codebook directly from the authenticated
    #    A0b2 codebook bytes (Defect 4).
    codeword_set = tuple(
        sorted({binding.codeword for binding in codebook.binding_by_class.values()})
    )
    if codeword_set != _CANONICAL_CODEWORD_SET:
        raise E1PairedCurriculumError(
            f"codebook codeword set {codeword_set} is not the canonical {_CANONICAL_CODEWORD_SET}"
        )
    if (
        codebook.payload.get("tokenizer_asset_aggregate_digest")
        != _TOKENIZER_ASSET_AGGREGATE_DIGEST
    ):
        raise E1PairedCurriculumError(
            "tokenizer codebook tokenizer_asset_aggregate_digest mismatch: expected "
            f"{_TOKENIZER_ASSET_AGGREGATE_DIGEST}, observed "
            f"{codebook.payload.get('tokenizer_asset_aggregate_digest')}"
        )
    task_format = build_task_format(codeword_set)
    task_format["semantic_codebook"] = _build_semantic_codebook(codebook)
    task_format_digest = canonical_sha256(task_format)

    # 8. Load the frozen tokenizer.
    tokenizer = _load_frozen_tokenizer()

    # 9. Build the paired records (Foundry projected through the truth table,
    #    control reusing the exact prompt + A1 codeword). For each record the
    #    A1 ``task_input_digest`` is required to equal the SHA-256 of the paired
    #    record's canonical task input text BEFORE either record is produced
    #    (Defect 2).
    foundry_records: list[PairedRecord] = []
    control_records: list[PairedRecord] = []
    for foundry_record in foundry_train_records:
        record_id = str(foundry_record["record_id"])
        if record_id not in response_by_record_id:
            raise E1PairedCurriculumError(f"{record_id}: no matching A1 conventional response")
        response = response_by_record_id[record_id]
        canonical_task_input_text = _canonical_task_input_text(foundry_record)
        observed_digest = _task_input_digest(canonical_task_input_text)
        if observed_digest != response.task_input_digest:
            raise E1PairedCurriculumError(
                f"{record_id}: A1 task_input_digest mismatch (expected "
                f"{response.task_input_digest}, observed {observed_digest})"
            )
        semantic_class = _project_foundry_semantic_class(foundry_record, abi.truth_table)
        if semantic_class not in codebook.binding_by_class:
            raise E1PairedCurriculumError(
                f"{record_id}: projected semantic_class {semantic_class!r} absent from codebook"
            )
        binding = codebook.binding_by_class[semantic_class]
        foundry_records.append(
            _build_foundry_record(
                foundry_record,
                semantic_class=semantic_class,
                codeword=binding.codeword,
                codeword_token_id=binding.token_ids[0],
                task_input_digest=observed_digest,
                tokenizer=tokenizer,
            )
        )
        control_records.append(
            _build_control_record(
                foundry_record,
                response,
                task_input_digest=observed_digest,
                tokenizer=tokenizer,
            )
        )

    foundry_tuple = tuple(foundry_records)
    control_tuple = tuple(control_records)

    # 10. Validate the TRAIN distribution invariants.
    _validate_distribution(foundry_tuple, _EXPECTED_FOUNDRY_DISTRIBUTION, arm="foundry")
    _validate_distribution(control_tuple, _EXPECTED_CONTROL_DISTRIBUTION, arm="control")

    # 11. Validate recordwise token isometry and build tokenization receipts.
    tokenization_receipts: list[TokenizationReceipt] = []
    for control, foundry in zip(control_tuple, foundry_tuple, strict=True):
        tokenization_receipts.append(
            _build_tokenization_receipt(control, foundry, tokenizer=tokenizer)
        )

    # 12. Build the artifact payloads.
    artifacts = _build_artifacts(
        source_commit=source_commit,
        selection=selection,
        frozen_selection=frozen_selection,
        foundry_bundle=foundry_bundle,
        control_records=control_tuple,
        foundry_records=foundry_tuple,
        development_cases=development_cases,
        clean_cases=clean_cases,
        task_format=task_format,
        task_format_digest=task_format_digest,
        tokenization_receipts=tuple(tokenization_receipts),
        a0b2_receipt=a0b2_receipt,
        a1_receipt=a1_receipt,
        abi=abi,
        codebook=codebook,
        evaluation_cases_digest=evaluation_cases_digest,
    )

    # 13. Distinctness checks across all 12 artifact digests.
    artifact_digests = {name: _digest(content) for name, content in artifacts.items()}
    if len(set(artifact_digests.values())) != len(artifact_digests):
        duplicates = sorted(
            {
                name
                for name, digest in artifact_digests.items()
                if list(artifact_digests.values()).count(digest) > 1
            }
        )
        raise E1PairedCurriculumError(
            f"the 12 paired-curriculum artifact digests must be mutually distinct; "
            f"collisions: {duplicates}"
        )

    return artifacts


# ---------------------------------------------------------------------------
# Artifact assembly.
# ---------------------------------------------------------------------------


def _build_artifacts(
    *,
    source_commit: str,
    selection: E1ExperimentContract,
    frozen_selection: E1ExperimentContract,
    foundry_bundle: E1FoundryArtifactBundle,
    control_records: tuple[PairedRecord, ...],
    foundry_records: tuple[PairedRecord, ...],
    development_cases: tuple[dict[str, object], ...],
    clean_cases: tuple[dict[str, object], ...],
    task_format: dict[str, object],
    task_format_digest: str,
    tokenization_receipts: tuple[TokenizationReceipt, ...],
    a0b2_receipt: AuthenticatedA0b2Receipt,
    a1_receipt: AuthenticatedA1Receipt,
    abi: AuthenticatedABI,
    codebook: AuthenticatedCodebook,
    evaluation_cases_digest: str,
) -> dict[str, bytes]:
    """Assemble the 12 paired-curriculum artifacts."""

    # The paired ``E1CurriculumEvaluationContract`` and the paired-curriculum
    # manifests bind the FROZEN predecessor selection digest (Defect 1). The
    # A2-time ``selection`` drives only the Foundry bundle compilation.
    frozen_selection_digest = frozen_selection.contract_digest

    # ---- 1. paired_task_format.json --------------------------------------
    task_format_bytes = canonical_json_bytes(task_format)

    # ---- 2/3. control_train.jsonl + foundry_train.jsonl -------------------
    control_train_bytes = _jsonl(tuple(record.to_dict() for record in control_records))
    foundry_train_bytes = _jsonl(tuple(record.to_dict() for record in foundry_records))

    # ---- 4/5. control/foundry curriculum manifests ------------------------
    training_scenario_ids = tuple(sorted({record.scenario_id for record in foundry_records}))
    oracle_evidence_digest = foundry_bundle.file("executable_oracle_evidence.json").sha256
    verification_evidence_digest = foundry_bundle.file(
        "independent_verification_evidence.json"
    ).sha256

    control_manifest = {
        "schema_version": _CONTROL_MANIFEST_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "arm": E1CurriculumArm.CONTROL.value,
        "label_authority": "conventional_synthetic",
        "selection_contract_digest": frozen_selection_digest,
        "task_format_digest": task_format_digest,
        "scenario_ids": list(training_scenario_ids),
        "scenario_count": len(training_scenario_ids),
        "record_ids": [record.record_id for record in control_records],
        "record_count": len(control_records),
        "distribution": dict(sorted(_EXPECTED_CONTROL_DISTRIBUTION.items())),
        "artifact": _file_receipt("control_train.jsonl", control_train_bytes, len(control_records)),
        "task_format": _file_receipt("paired_task_format.json", task_format_bytes),
        "tokenizer_repository": _TOKENIZER_REPOSITORY,
        "tokenizer_revision": _TOKENIZER_REVISION,
        "tokenizer_asset_aggregate_digest": _TOKENIZER_ASSET_AGGREGATE_DIGEST,
        "context_length": _CONTEXT_LENGTH,
        "token_count": sum(record.sequence_token_count for record in control_records),
        "executable_oracle_evidence_digest": None,
        "independent_verification_evidence_digest": None,
        "predecessor_a1_receipt_sha256": a1_receipt.receipt_sha256,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    foundry_manifest = {
        "schema_version": _FOUNDRY_MANIFEST_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "arm": E1CurriculumArm.FOUNDRY.value,
        "label_authority": "executable_semantics",
        "selection_contract_digest": frozen_selection_digest,
        "task_format_digest": task_format_digest,
        "scenario_ids": list(training_scenario_ids),
        "scenario_count": len(training_scenario_ids),
        "record_ids": [record.record_id for record in foundry_records],
        "record_count": len(foundry_records),
        "distribution": dict(sorted(_EXPECTED_FOUNDRY_DISTRIBUTION.items())),
        "artifact": _file_receipt("foundry_train.jsonl", foundry_train_bytes, len(foundry_records)),
        "task_format": _file_receipt("paired_task_format.json", task_format_bytes),
        "tokenizer_repository": _TOKENIZER_REPOSITORY,
        "tokenizer_revision": _TOKENIZER_REVISION,
        "tokenizer_asset_aggregate_digest": _TOKENIZER_ASSET_AGGREGATE_DIGEST,
        "context_length": _CONTEXT_LENGTH,
        "token_count": sum(record.sequence_token_count for record in foundry_records),
        "executable_oracle_evidence_digest": oracle_evidence_digest,
        "independent_verification_evidence_digest": verification_evidence_digest,
        "executable_oracle_evidence": foundry_bundle.file(
            "executable_oracle_evidence.json"
        ).receipt(),
        "independent_verification_evidence": foundry_bundle.file(
            "independent_verification_evidence.json"
        ).receipt(),
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    control_manifest_bytes = canonical_json_bytes(control_manifest)
    foundry_manifest_bytes = canonical_json_bytes(foundry_manifest)

    # ---- 6/7. development_evaluation.jsonl + clean_evaluation.jsonl -------
    development_bytes = _jsonl(development_cases)
    clean_bytes = _jsonl(clean_cases)

    # ---- 8. evaluation_manifest.json --------------------------------------
    development_scenario_ids = tuple(
        sorted({str(case["scenario_id"]) for case in development_cases})
    )
    development_family_count = len({str(case["family_digest"]) for case in development_cases})
    evaluation_manifest = {
        "schema_version": _EVAL_MANIFEST_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "selection_contract_digest": frozen_selection_digest,
        "task_format_digest": task_format_digest,
        "predecessor_evaluation_cases_digest": evaluation_cases_digest,
        "development": {
            "scenario_ids": list(development_scenario_ids),
            "scenario_count": len(development_scenario_ids),
            "family_count": development_family_count,
            "record_count": len(development_cases),
            "artifact": _file_receipt(
                "development_evaluation.jsonl", development_bytes, len(development_cases)
            ),
        },
        "clean": {
            "record_count": len(clean_cases),
            "artifact": _file_receipt("clean_evaluation.jsonl", clean_bytes, len(clean_cases)),
        },
        "primary_metric_implementation_digest": _A0B2_METRIC_DIGEST,
        "safety_metric_implementation_digest": _A0B2_METRIC_DIGEST,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    evaluation_manifest_bytes = canonical_json_bytes(evaluation_manifest)

    # ---- 9. tokenization_manifest.json ------------------------------------
    tokenization_manifest = {
        "schema_version": _TOKENIZATION_MANIFEST_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "tokenizer_repository": _TOKENIZER_REPOSITORY,
        "tokenizer_revision": _TOKENIZER_REVISION,
        "tokenizer_asset_aggregate_digest": _TOKENIZER_ASSET_AGGREGATE_DIGEST,
        "context_length": _CONTEXT_LENGTH,
        "record_count": len(tokenization_receipts),
        "control_artifact_digest": _digest(control_train_bytes),
        "foundry_artifact_digest": _digest(foundry_train_bytes),
        "token_count_control": sum(
            receipt.control_sequence_token_count for receipt in tokenization_receipts
        ),
        "token_count_foundry": sum(
            receipt.foundry_sequence_token_count for receipt in tokenization_receipts
        ),
        "all_prompt_bytes_identical": all(
            receipt.prompt_bytes_identical for receipt in tokenization_receipts
        ),
        "all_prompt_token_ids_identical": all(
            receipt.prompt_token_ids_identical for receipt in tokenization_receipts
        ),
        "all_sequence_token_counts_equal": all(
            receipt.sequence_token_counts_equal for receipt in tokenization_receipts
        ),
        "all_codeword_isometry": all(
            receipt.codeword_isometry_control and receipt.codeword_isometry_foundry
            for receipt in tokenization_receipts
        ),
        "any_truncated": any(receipt.truncated for receipt in tokenization_receipts),
        "all_within_context_length": all(
            receipt.within_context_length for receipt in tokenization_receipts
        ),
        "receipts": [receipt.to_dict() for receipt in tokenization_receipts],
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    tokenization_manifest_bytes = canonical_json_bytes(tokenization_manifest)

    # ---- 10/11. paired_e1_contract.json + paired_e1_manifest.json ---------
    contract, contract_bytes, paired_manifest = _build_contract_and_manifest(
        source_commit=source_commit,
        selection=frozen_selection,
        control_records=control_records,
        foundry_records=foundry_records,
        development_cases=development_cases,
        clean_cases=clean_cases,
        development_scenario_ids=development_scenario_ids,
        development_family_count=development_family_count,
        foundry_bundle=foundry_bundle,
        control_train_bytes=control_train_bytes,
        foundry_train_bytes=foundry_train_bytes,
        control_manifest_bytes=control_manifest_bytes,
        foundry_manifest_bytes=foundry_manifest_bytes,
        development_bytes=development_bytes,
        clean_bytes=clean_bytes,
        evaluation_manifest_bytes=evaluation_manifest_bytes,
        tokenization_manifest_bytes=tokenization_manifest_bytes,
        task_format_bytes=task_format_bytes,
        task_format_digest=task_format_digest,
    )
    paired_manifest_bytes = canonical_json_bytes(paired_manifest)

    # ---- 12. a2_receipt.json ----------------------------------------------
    receipt = _build_a2_receipt(
        source_commit=source_commit,
        selection=frozen_selection,
        foundry_bundle=foundry_bundle,
        a0b2_receipt=a0b2_receipt,
        a1_receipt=a1_receipt,
        abi=abi,
        codebook=codebook,
        task_format_bytes=task_format_bytes,
        control_train_bytes=control_train_bytes,
        foundry_train_bytes=foundry_train_bytes,
        control_manifest_bytes=control_manifest_bytes,
        foundry_manifest_bytes=foundry_manifest_bytes,
        development_bytes=development_bytes,
        clean_bytes=clean_bytes,
        evaluation_manifest_bytes=evaluation_manifest_bytes,
        tokenization_manifest_bytes=tokenization_manifest_bytes,
        contract_bytes=contract_bytes,
        paired_manifest_bytes=paired_manifest_bytes,
        contract_digest=contract.contract_digest,
        development_evaluation_count=len(development_cases),
        clean_evaluation_count=len(clean_cases),
        token_count_per_arm=sum(record.sequence_token_count for record in foundry_records),
    )
    receipt_bytes = canonical_json_bytes(receipt)

    return {
        "paired_task_format.json": task_format_bytes,
        "control_train.jsonl": control_train_bytes,
        "foundry_train.jsonl": foundry_train_bytes,
        "control_curriculum_manifest.json": control_manifest_bytes,
        "foundry_curriculum_manifest.json": foundry_manifest_bytes,
        "development_evaluation.jsonl": development_bytes,
        "clean_evaluation.jsonl": clean_bytes,
        "evaluation_manifest.json": evaluation_manifest_bytes,
        "tokenization_manifest.json": tokenization_manifest_bytes,
        "paired_e1_contract.json": contract_bytes,
        "paired_e1_manifest.json": paired_manifest_bytes,
        "a2_receipt.json": receipt_bytes,
    }


def _file_receipt(path: str, content: bytes, record_count: int | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "path": path,
        "sha256": _digest(content),
        "byte_count": len(content),
    }
    if record_count is not None:
        result["record_count"] = record_count
    return result


def _build_contract_and_manifest(
    *,
    source_commit: str,
    selection: E1ExperimentContract,
    control_records: tuple[PairedRecord, ...],
    foundry_records: tuple[PairedRecord, ...],
    development_cases: tuple[dict[str, object], ...],
    clean_cases: tuple[dict[str, object], ...],
    development_scenario_ids: tuple[str, ...],
    development_family_count: int,
    foundry_bundle: E1FoundryArtifactBundle,
    control_train_bytes: bytes,
    foundry_train_bytes: bytes,
    control_manifest_bytes: bytes,
    foundry_manifest_bytes: bytes,
    development_bytes: bytes,
    clean_bytes: bytes,
    evaluation_manifest_bytes: bytes,
    tokenization_manifest_bytes: bytes,
    task_format_bytes: bytes,
    task_format_digest: str,
) -> tuple[E1CurriculumEvaluationContract, bytes, dict[str, object]]:
    """Instantiate the PR #74 contract and the paired manifest.

    The contract bytes are computed here (not by the caller) so the paired
    manifest can carry the real contract file receipt. The contract embeds the
    FROZEN predecessor ``selection`` (Defect 1), so the contract's own
    ``source_commit`` is the predecessor source commit (the contract requires
    ``source_commit == selection.source_commit``).
    """

    control_token_count = sum(record.sequence_token_count for record in control_records)
    foundry_token_count = sum(record.sequence_token_count for record in foundry_records)
    control_artifact = E1CurriculumArtifact(
        arm=E1CurriculumArm.CONTROL,
        label_authority=E1LabelAuthority.CONVENTIONAL_SYNTHETIC,
        artifact_digest=_digest(control_train_bytes),
        manifest_digest=_digest(control_manifest_bytes),
        generation_command_digest=_command_digest(_GENERATION_COMMAND_TEMPLATE, source_commit),
        validation_command_digest=_command_digest(_VALIDATION_COMMAND_TEMPLATE, source_commit),
        task_format_digest=task_format_digest,
        scenario_ids=tuple(sorted({record.scenario_id for record in control_records})),
        record_count=len(control_records),
        token_count=control_token_count,
    )
    foundry_artifact = E1CurriculumArtifact(
        arm=E1CurriculumArm.FOUNDRY,
        label_authority=E1LabelAuthority.EXECUTABLE_SEMANTICS,
        artifact_digest=_digest(foundry_train_bytes),
        manifest_digest=_digest(foundry_manifest_bytes),
        generation_command_digest=foundry_bundle.generation_command_digest,
        validation_command_digest=foundry_bundle.validation_command_digest,
        task_format_digest=task_format_digest,
        scenario_ids=tuple(sorted({record.scenario_id for record in foundry_records})),
        record_count=len(foundry_records),
        token_count=foundry_token_count,
        executable_oracle_evidence_digest=foundry_bundle.file(
            "executable_oracle_evidence.json"
        ).sha256,
        independent_verification_evidence_digest=foundry_bundle.file(
            "independent_verification_evidence.json"
        ).sha256,
    )
    evaluation = E1EvaluationArtifact(
        split=E1Split.DEVELOPMENT,
        artifact_digest=_digest(development_bytes),
        manifest_digest=_digest(evaluation_manifest_bytes),
        generation_command_digest=foundry_bundle.generation_command_digest,
        validation_command_digest=foundry_bundle.validation_command_digest,
        scenario_ids=development_scenario_ids,
        record_count=len(development_cases),
        family_count=development_family_count,
        primary_metric_implementation_digest=_A0B2_METRIC_DIGEST,
        safety_metric_implementation_digest=_A0B2_METRIC_DIGEST,
    )
    tokenizer_revision_digest = canonical_sha256(
        {
            "tokenizer_repository": _TOKENIZER_REPOSITORY,
            "tokenizer_revision": _TOKENIZER_REVISION,
        }
    )
    # The contract embeds the FROZEN predecessor selection, so its source_commit
    # is the predecessor source commit (the contract invariant requires
    # ``source_commit == selection.source_commit``).
    contract = compile_e1_curriculum_evaluation_contract(
        selection,
        release=_RELEASE,
        source_commit=selection.source_commit,
        tokenizer_revision_digest=tokenizer_revision_digest,
        control=control_artifact,
        foundry=foundry_artifact,
        evaluation=evaluation,
    )
    contract_bytes = canonical_json_bytes(contract.to_dict())
    paired_manifest: dict[str, object] = {
        "schema_version": _PAIRED_MANIFEST_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "selection_contract_digest": selection.contract_digest,
        "contract_digest": contract.contract_digest,
        "task_format": _file_receipt("paired_task_format.json", task_format_bytes),
        "task_format_digest": task_format_digest,
        "control_train": _file_receipt(
            "control_train.jsonl", control_train_bytes, len(control_records)
        ),
        "foundry_train": _file_receipt(
            "foundry_train.jsonl", foundry_train_bytes, len(foundry_records)
        ),
        "control_manifest": _file_receipt(
            "control_curriculum_manifest.json", control_manifest_bytes
        ),
        "foundry_manifest": _file_receipt(
            "foundry_curriculum_manifest.json", foundry_manifest_bytes
        ),
        "development_evaluation": _file_receipt(
            "development_evaluation.jsonl", development_bytes, len(development_cases)
        ),
        "clean_evaluation": _file_receipt("clean_evaluation.jsonl", clean_bytes, len(clean_cases)),
        "evaluation_manifest": _file_receipt("evaluation_manifest.json", evaluation_manifest_bytes),
        "tokenization_manifest": _file_receipt(
            "tokenization_manifest.json", tokenization_manifest_bytes
        ),
        "paired_e1_contract": _file_receipt("paired_e1_contract.json", contract_bytes),
        "raw_executable_oracle_evidence": foundry_bundle.file(
            "executable_oracle_evidence.json"
        ).receipt(),
        "raw_independent_verification_evidence": foundry_bundle.file(
            "independent_verification_evidence.json"
        ).receipt(),
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    return contract, contract_bytes, paired_manifest


def _build_a2_receipt(
    *,
    source_commit: str,
    selection: E1ExperimentContract,
    foundry_bundle: E1FoundryArtifactBundle,
    a0b2_receipt: AuthenticatedA0b2Receipt,
    a1_receipt: AuthenticatedA1Receipt,
    abi: AuthenticatedABI,
    codebook: AuthenticatedCodebook,
    task_format_bytes: bytes,
    control_train_bytes: bytes,
    foundry_train_bytes: bytes,
    control_manifest_bytes: bytes,
    foundry_manifest_bytes: bytes,
    development_bytes: bytes,
    clean_bytes: bytes,
    evaluation_manifest_bytes: bytes,
    tokenization_manifest_bytes: bytes,
    contract_bytes: bytes,
    paired_manifest_bytes: bytes,
    contract_digest: str,
    development_evaluation_count: int,
    clean_evaluation_count: int,
    token_count_per_arm: int,
) -> dict[str, object]:
    """Build the A2 receipt binding all 12 artifacts and predecessor identities."""

    constituent_digests = {
        "paired_task_format.json": _digest(task_format_bytes),
        "control_train.jsonl": _digest(control_train_bytes),
        "foundry_train.jsonl": _digest(foundry_train_bytes),
        "control_curriculum_manifest.json": _digest(control_manifest_bytes),
        "foundry_curriculum_manifest.json": _digest(foundry_manifest_bytes),
        "development_evaluation.jsonl": _digest(development_bytes),
        "clean_evaluation.jsonl": _digest(clean_bytes),
        "evaluation_manifest.json": _digest(evaluation_manifest_bytes),
        "tokenization_manifest.json": _digest(tokenization_manifest_bytes),
        "paired_e1_contract.json": _digest(contract_bytes),
        "paired_e1_manifest.json": _digest(paired_manifest_bytes),
    }
    generation_command_digest = _command_digest(_GENERATION_COMMAND_TEMPLATE, source_commit)
    validation_command_digest = _command_digest(_VALIDATION_COMMAND_TEMPLATE, source_commit)
    raw_executable_oracle_evidence_digest = foundry_bundle.file(
        "executable_oracle_evidence.json"
    ).sha256
    raw_independent_verification_evidence_digest = foundry_bundle.file(
        "independent_verification_evidence.json"
    ).sha256
    raw_foundry_bundle_identity = foundry_bundle.file("bundle_manifest.json").sha256
    return {
        "schema_version": _A2_RECEIPT_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "selection_contract_digest": selection.contract_digest,
        "contract_digest": contract_digest,
        "constituent_artifact_digests": dict(sorted(constituent_digests.items())),
        "predecessor_a1_receipt_sha256": a1_receipt.receipt_sha256,
        "predecessor_a1_source_commit": a1_receipt.source_commit,
        "predecessor_a0b2_receipt_sha256": a0b2_receipt.receipt_sha256,
        "predecessor_a0b2_source_commit": a0b2_receipt.source_commit,
        "predecessor_a0b2_metric_digest": a0b2_receipt.metric_digest,
        "predecessor_response_abi_digest": abi.abi_digest,
        "predecessor_tokenizer_codebook_digest": codebook.codebook_digest,
        "predecessor_selection_contract_digest": _EXPECTED_SELECTION_CONTRACT_DIGEST,
        "predecessor_evaluation_cases_digest": a0b2_receipt.payload.get(
            "constituent_artifact_digests", {}
        ).get("evaluation_cases.jsonl"),
        "generation_command_digest": generation_command_digest,
        "validation_command_digest": validation_command_digest,
        "tokenizer_repository": _TOKENIZER_REPOSITORY,
        "tokenizer_revision": _TOKENIZER_REVISION,
        "tokenizer_asset_aggregate_digest": _TOKENIZER_ASSET_AGGREGATE_DIGEST,
        "raw_foundry_bundle_identity": raw_foundry_bundle_identity,
        "raw_executable_oracle_evidence_digest": raw_executable_oracle_evidence_digest,
        "raw_independent_verification_evidence_digest": (
            raw_independent_verification_evidence_digest
        ),
        "context_length": _CONTEXT_LENGTH,
        "record_count_per_arm": _EXPECTED_RECORD_COUNT,
        "development_evaluation_count": development_evaluation_count,
        "clean_evaluation_count": clean_evaluation_count,
        "token_count_per_arm": token_count_per_arm,
        "truncation_count": 0,
        "foundry_distribution": dict(sorted(_EXPECTED_FOUNDRY_DISTRIBUTION.items())),
        "control_distribution": dict(sorted(_EXPECTED_CONTROL_DISTRIBUTION.items())),
        "claim_boundary": _CLAIM_BOUNDARY,
    }


# ---------------------------------------------------------------------------
# Public re-exports.
# ---------------------------------------------------------------------------

RELEASE = _RELEASE
CLAIM_BOUNDARY = _CLAIM_BOUNDARY
SYSTEM_PROMPT = _SYSTEM_PROMPT
EXPECTED_A1_RECEIPT_SHA256 = _EXPECTED_A1_RECEIPT_SHA256
EXPECTED_A0B2_RECEIPT_SHA256 = _EXPECTED_A0B2_RECEIPT_SHA256
EXPECTED_SELECTION_CONTRACT_DIGEST = _EXPECTED_SELECTION_CONTRACT_DIGEST
A0B2_METRIC_DIGEST = _A0B2_METRIC_DIGEST
EXPECTED_FOUNDRY_DISTRIBUTION = _EXPECTED_FOUNDRY_DISTRIBUTION
EXPECTED_CONTROL_DISTRIBUTION = _EXPECTED_CONTROL_DISTRIBUTION
TOKENIZER_REPOSITORY = _TOKENIZER_REPOSITORY
TOKENIZER_REVISION = _TOKENIZER_REVISION
TOKENIZER_ASSET_AGGREGATE_DIGEST = _TOKENIZER_ASSET_AGGREGATE_DIGEST
CONTEXT_LENGTH = _CONTEXT_LENGTH
PREDECESSOR_SELECTION_SOURCE_COMMIT = _PREDECESSOR_SELECTION_SOURCE_COMMIT

__all__ = [
    "A0B2_METRIC_DIGEST",
    "CLAIM_BOUNDARY",
    "CONTEXT_LENGTH",
    "ConventionalResponse",
    "EXPECTED_A0B2_RECEIPT_SHA256",
    "EXPECTED_A1_RECEIPT_SHA256",
    "EXPECTED_CONTROL_DISTRIBUTION",
    "EXPECTED_FOUNDRY_DISTRIBUTION",
    "EXPECTED_SELECTION_CONTRACT_DIGEST",
    "E1PairedCurriculumError",
    "PairedRecord",
    "PREDECESSOR_SELECTION_SOURCE_COMMIT",
    "RELEASE",
    "SYSTEM_PROMPT",
    "TOKENIZER_ASSET_AGGREGATE_DIGEST",
    "TOKENIZER_REPOSITORY",
    "TOKENIZER_REVISION",
    "TokenizationReceipt",
    "authenticate_a0b2_receipt",
    "authenticate_a1_receipt",
    "authenticate_response_abi",
    "authenticate_tokenizer_codebook",
    "build_task_format",
    "build_task_format_digest",
    "compile_paired_curriculum",
]
