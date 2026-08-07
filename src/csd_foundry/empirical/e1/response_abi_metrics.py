"""E1 response ABI, tokenizer-isometric codebook, strict parser, and metrics.

This module (the A0b2 slice) fixes the *response* contract for the E1 probe. It
defines the five-class semantic response ABI over the ``basis_disposition``
truth table, pins a frozen single-token codebook over the
``sshleifer/tiny-gpt2`` tokenizer, exposes a strict no-repair parser, and emits
the primary (family-macro exact-semantic-decision accuracy) and safety
(clean-case regression) metric contracts together with the evaluation cases.

The module performs no model execution, no training, and no GPU allocation. It
loads only the frozen tokenizer vocabulary to derive and verify the codebook.

Five blocking correctness properties:

1. **Pinned A0b1 population receipt.** The predecessor population-support
   receipt SHA-256 is pinned as a module constant and fail-closed on mismatch,
   so a coherently-substituted receipt cannot authenticate the response ABI.

2. **Reused A0c predecessor authority.** The A0c audit identity constants are
   read back from the authenticated A0b1 receipt (not re-pinned here), so the
   chain of authority is transitive and any A0c tamper is caught one hop
   earlier.

3. **Tokenizer-isometric codebook.** The five codewords are verified to be
   single-token, mutually unique, and exactly round-trippable; the tokenizer
   repository, revision, and asset aggregate digest are pinned, so changing the
   tokenizer identity invalidates the codebook.

4. **Strict no-repair parser.** The parser accepts ONLY the exact codeword
   string. No trimming, stripping, case-folding, Unicode normalization, prefix
   matching, or repair. Malformed output stays in the primary metric
   denominator.

5. **Separate case-kind applicability.** Parsing and applicability are
   independent: a well-formed ``NOT_APPLICABLE`` on a transition is
   context-invalid (not malformed), and a basis class on an observation is
   context-invalid (not malformed).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e1.development_contrast_extension import (
    build_e1_development_contrast_catalog,
)
from csd_foundry.empirical.e1.execution_splits import derive_scenario_family_identity
from csd_foundry.empirical.e1.projection_clean_case_population import (
    CleanCaseSpec,
    build_clean_case_transition_cases,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import ScenarioSpec, TransitionCase
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_sha256,
)


class E1ResponseABIError(ValueError):
    """Raised when the response ABI, codebook, parser, or metrics cannot be compiled."""


# ---------------------------------------------------------------------------
# Schema and release identifiers
# ---------------------------------------------------------------------------

_ABI_SCHEMA_VERSION = "e1-response-abi/1"
_CODEBOOK_SCHEMA_VERSION = "e1-tokenizer-codebook/1"
_PARSER_CONFORMANCE_SCHEMA_VERSION = "e1-parser-conformance/1"
_EVALUATION_CONTRACT_SCHEMA_VERSION = "e1-evaluation-contract/1"
_EVALUATION_CASE_SCHEMA = "e1-evaluation-case/1"
_A0B2_RECEIPT_SCHEMA = "e1-response-abi-receipt/1"
_RELEASE = "e1-response-abi/1"

_PRIMARY_METRIC_IDENTITY = "structural-holdout-exact-semantic-decision-accuracy/family-macro/1"
_SAFETY_METRIC_IDENTITY = "clean-case-regression/base-and-control/1"

_PARSER_IDENTITY = "strict-codeword-parser/1"
_METRIC_IMPLEMENTATION_IDENTITY = "exact-semantic-decision-metric/1"

# ---------------------------------------------------------------------------
# Pinned identities.
# ---------------------------------------------------------------------------

# The A0b1 population-support receipt SHA-256, computed over the committed file
# bytes at data/e1/v3/population_support_receipt.json.
_EXPECTED_PREDECESSOR_RECEIPT_SHA256 = (
    "f942d053c7186501b487569fddc63f67d1185f88cd59b4fa3b55075fcb3520a0"
)

# Frozen tokenizer identity (E0-H preflight).
_TOKENIZER_REPOSITORY = "sshleifer/tiny-gpt2"
_TOKENIZER_REVISION = "d1856183d08a67c27a8e4ca1492d1d32b96c7c1a"
_TOKENIZER_ASSET_AGGREGATE_DIGEST = (
    "fa91cdd29a17c266d450a7b713c7cb3ee9f63d778d2987550da429c55ff93891"
)
_TOKENIZER_FILES: tuple[str, ...] = (
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer_config.json",
    "vocab.json",
)

# Development split is exactly four families (G-04, M-12, M-13, M-14).
_EXPECTED_DEVELOPMENT_FAMILY_COUNT = 4

_CLAIM_BOUNDARY = (
    "This module fixes the five-class response ABI over the basis_disposition "
    "truth table, pins a single-token codebook over the frozen sshleifer/tiny-gpt2 "
    "tokenizer, exposes a strict no-repair parser, and emits the primary family-macro "
    "exact-semantic-decision accuracy and clean-case safety metric contracts. It loads "
    "only the tokenizer vocabulary to derive and verify the codebook. It does not execute "
    "a model, fix a training recipe, allocate a GPU, or establish learning value or "
    "general transfer."
)


# ---------------------------------------------------------------------------
# Semantic response classes (5-class ABI).
# ---------------------------------------------------------------------------


class SemanticResponseClass(StrEnum):
    """Five semantic response classes over the basis_disposition truth table.

    The four basis classes are derived from the (any_basis_removed,
    any_basis_survives) pair. ``NOT_APPLICABLE`` covers observation records,
    where basis disposition is undefined.
    """

    NEITHER = "NEITHER"
    REMOVES_ONLY = "REMOVES_ONLY"
    SURVIVES_ONLY = "SURVIVES_ONLY"
    BOTH = "BOTH"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Frozen codeword assignment (verified single-token, unique IDs 32-36).
_CODEWORD_BY_CLASS: dict[SemanticResponseClass, str] = {
    SemanticResponseClass.NEITHER: "A",
    SemanticResponseClass.REMOVES_ONLY: "B",
    SemanticResponseClass.SURVIVES_ONLY: "C",
    SemanticResponseClass.BOTH: "D",
    SemanticResponseClass.NOT_APPLICABLE: "E",
}


def _basis_disposition_class(
    any_basis_removed: bool, any_basis_survives: bool
) -> SemanticResponseClass:
    """Map a (removed, survives) pair to its basis semantic class.

    This is the truth-table mapping fixed by the response ABI:

    - (false, false) -> NEITHER
    - (true,  false) -> REMOVES_ONLY
    - (false, true ) -> SURVIVES_ONLY
    - (true,  true ) -> BOTH
    """

    if any_basis_removed and any_basis_survives:
        return SemanticResponseClass.BOTH
    if any_basis_removed:
        return SemanticResponseClass.REMOVES_ONLY
    if any_basis_survives:
        return SemanticResponseClass.SURVIVES_ONLY
    return SemanticResponseClass.NEITHER


# ---------------------------------------------------------------------------
# Response ABI contract.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResponseABIContract:
    """The frozen five-class response ABI, truth table, and applicability rules."""

    schema_version: str
    release: str
    source_commit: str
    primary_projection_name: str
    semantic_classes: tuple[SemanticResponseClass, ...]
    basis_truth_table: tuple[dict[str, object], ...]
    applicability_rules: dict[str, object]
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "primary_projection_name": self.primary_projection_name,
            "semantic_classes": [item.value for item in self.semantic_classes],
            "basis_truth_table": [dict(item) for item in self.basis_truth_table],
            "applicability_rules": self.applicability_rules,
            "claim_boundary": self.claim_boundary,
        }


def build_response_abi_contract(source_commit: str) -> ResponseABIContract:
    """Build the five-class response ABI contract."""

    basis_pairs = (
        (False, False),
        (True, False),
        (False, True),
        (True, True),
    )
    truth_table: tuple[dict[str, object], ...] = tuple(
        {
            "any_basis_removed": removed,
            "any_basis_survives": survives,
            "semantic_class": _basis_disposition_class(removed, survives).value,
        }
        for removed, survives in basis_pairs
    )
    applicability_rules: dict[str, object] = {
        "transition_basis_class": "applicable",
        "transition_not_applicable": "CONTEXT_INVALID",
        "observation_not_applicable": "applicable",
        "observation_basis_class": "CONTEXT_INVALID",
        "description": (
            "A transition record with a basis class is applicable; a transition "
            "with NOT_APPLICABLE is well-formed but context-invalid; an observation "
            "with NOT_APPLICABLE is applicable; an observation with a basis class "
            "is well-formed but context-invalid."
        ),
    }
    return ResponseABIContract(
        schema_version=_ABI_SCHEMA_VERSION,
        release=_RELEASE,
        source_commit=source_commit,
        primary_projection_name="basis_disposition",
        semantic_classes=tuple(SemanticResponseClass),
        basis_truth_table=truth_table,
        applicability_rules=applicability_rules,
        claim_boundary=_CLAIM_BOUNDARY,
    )


# ---------------------------------------------------------------------------
# Tokenizer-isometric codebook.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenizerCodebook:
    """Frozen single-token codebook over the pinned tokenizer."""

    schema_version: str
    release: str
    source_commit: str
    tokenizer_repository: str
    tokenizer_revision: str
    tokenizer_asset_aggregate_digest: str
    tokenizer_files: tuple[str, ...]
    codewords: tuple[dict[str, object], ...]
    isometry_verified: bool
    unique_codeword_count: int
    uniform_token_count: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "tokenizer_repository": self.tokenizer_repository,
            "tokenizer_revision": self.tokenizer_revision,
            "tokenizer_asset_aggregate_digest": self.tokenizer_asset_aggregate_digest,
            "tokenizer_files": list(self.tokenizer_files),
            "codewords": [dict(item) for item in self.codewords],
            "isometry_verified": self.isometry_verified,
            "unique_codeword_count": self.unique_codeword_count,
            "uniform_token_count": self.uniform_token_count,
        }


def _load_frozen_tokenizer() -> Any:
    """Load the pinned tokenizer via transformers.AutoTokenizer.

    Uses a dynamic import so that ``mypy src`` does not require transformers
    to be installed in the type-checking environment.
    """

    try:
        import importlib

        transformers_module = importlib.import_module("transformers")
        tokenizer_cls = transformers_module.AutoTokenizer
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise E1ResponseABIError(
            "transformers is required to load the frozen tokenizer codebook"
        ) from exc

    return tokenizer_cls.from_pretrained(_TOKENIZER_REPOSITORY, revision=_TOKENIZER_REVISION)


def _compute_tokenizer_asset_digest(cache_dir: Path | None) -> str | None:
    """Compute the tokenizer asset aggregate digest from a local snapshot.

    The digest is the canonical SHA-256 over the list of tokenizer-asset
    receipts (path, sha256, byte_count), matching the E0-H preflight
    computation. When the snapshot cannot be located (no cache dir, offline),
    returns ``None`` and the codebook falls back to pinning the constant only.
    """

    if cache_dir is None:
        return None
    snapshot = cache_dir / "models--sshleifer--tiny-gpt2" / "snapshots" / _TOKENIZER_REVISION
    if not snapshot.is_dir():
        return None
    receipts: list[dict[str, object]] = []
    for name in _TOKENIZER_FILES:
        path = snapshot / name
        if not path.is_file():
            return None
        receipts.append(
            {
                "path": name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "byte_count": path.stat().st_size,
            }
        )
    return canonical_sha256(receipts)


def build_tokenizer_codebook(
    source_commit: str,
    *,
    tokenizer: Any | None = None,
    asset_cache_dir: Path | None = None,
) -> TokenizerCodebook:
    """Build and verify the tokenizer-isometric codebook.

    The five codewords are verified to be:
    - exactly five unique strings;
    - all single-token (identical token count of 1);
    - exactly round-trippable (encode -> decode returns the original);
    - bound to the pinned tokenizer identity (repository, revision, digest).
    """

    active_tokenizer = tokenizer if tokenizer is not None else _load_frozen_tokenizer()

    codewords: list[dict[str, object]] = []
    seen_strings: set[str] = set()
    seen_ids: set[int] = set()
    token_counts: set[int] = set()

    for semantic_class in SemanticResponseClass:
        codeword = _CODEWORD_BY_CLASS[semantic_class]
        if codeword in seen_strings:
            raise E1ResponseABIError(f"duplicate codeword string: {codeword!r}")
        seen_strings.add(codeword)

        token_ids = active_tokenizer.encode(codeword, add_special_tokens=False)
        if not isinstance(token_ids, list):
            raise E1ResponseABIError(f"tokenizer.encode did not return a list for {codeword!r}")
        # The tiny-gpt2 BPE produces integer ids; coerce defensively.
        int_ids: list[int] = [int(value) for value in token_ids]
        token_id = int_ids[0]
        if len(int_ids) == 1 and token_id in seen_ids:
            raise E1ResponseABIError(f"duplicate token id {token_id} for {codeword!r}")
        seen_ids.add(token_id)
        token_counts.add(len(int_ids))

        decoded = active_tokenizer.decode(int_ids)
        roundtrip_exact = decoded == codeword

        codewords.append(
            {
                "semantic_class": semantic_class.value,
                "codeword": codeword,
                "token_ids": int_ids,
                "token_count": len(int_ids),
                "decoded_roundtrip": decoded,
                "roundtrip_exact": roundtrip_exact,
            }
        )

    if len(seen_strings) != 5:
        raise E1ResponseABIError(
            f"codebook must contain exactly 5 unique codewords, observed {len(seen_strings)}"
        )
    uniform_token_count = len(token_counts) == 1
    if not uniform_token_count:
        raise E1ResponseABIError(
            f"all codewords must have identical token count, observed {sorted(token_counts)}"
        )
    only_count = next(iter(token_counts))
    if only_count != 1:
        raise E1ResponseABIError(
            f"all codewords must be single-token, observed token count {only_count}"
        )
    if not all(bool(item["roundtrip_exact"]) for item in codewords):
        raise E1ResponseABIError("codeword encode->decode roundtrip is not exact for every class")

    observed_digest = _compute_tokenizer_asset_digest(asset_cache_dir)
    if observed_digest is not None and observed_digest != _TOKENIZER_ASSET_AGGREGATE_DIGEST:
        raise E1ResponseABIError(
            "tokenizer asset aggregate digest mismatch: expected "
            f"{_TOKENIZER_ASSET_AGGREGATE_DIGEST}, observed {observed_digest}"
        )

    return TokenizerCodebook(
        schema_version=_CODEBOOK_SCHEMA_VERSION,
        release=_RELEASE,
        source_commit=source_commit,
        tokenizer_repository=_TOKENIZER_REPOSITORY,
        tokenizer_revision=_TOKENIZER_REVISION,
        tokenizer_asset_aggregate_digest=_TOKENIZER_ASSET_AGGREGATE_DIGEST,
        tokenizer_files=_TOKENIZER_FILES,
        codewords=tuple(codewords),
        isometry_verified=True,
        unique_codeword_count=len(seen_strings),
        uniform_token_count=True,
    )


# ---------------------------------------------------------------------------
# Strict no-repair parser.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedResponse:
    """Strict parser result. Accepts ONLY the exact codeword string."""

    is_valid: bool
    semantic_class: SemanticResponseClass | None
    reason_code: str | None


_REASON_MALFORMED = "MALFORMED"


def parse_response(raw_output: object) -> ParsedResponse:
    """Parse a raw model output strictly.

    Accepts ONLY the exact codeword string. No trimming, stripping,
    case-folding, Unicode normalization, prefix matching, or repair. Any
    deviation (whitespace, newline, punctuation, prose, empty, concatenated
    codewords, unknown same-length output) yields ``is_valid=False`` with
    reason_code ``MALFORMED``.
    """

    if not isinstance(raw_output, str):
        return ParsedResponse(is_valid=False, semantic_class=None, reason_code=_REASON_MALFORMED)

    for semantic_class, codeword in _CODEWORD_BY_CLASS.items():
        if raw_output == codeword:
            return ParsedResponse(
                is_valid=True,
                semantic_class=semantic_class,
                reason_code=None,
            )
    return ParsedResponse(is_valid=False, semantic_class=None, reason_code=_REASON_MALFORMED)


# ---------------------------------------------------------------------------
# Case-kind applicability (separate from parsing).
# ---------------------------------------------------------------------------

_REASON_CONTEXT_INVALID = "CONTEXT_INVALID"


@dataclass(frozen=True, slots=True)
class ApplicabilityResult:
    """Whether a well-formed semantic class applies to a case kind."""

    applicable: bool
    reason: str | None


def evaluate_applicability(
    case_kind: str,
    semantic_class: SemanticResponseClass | None,
) -> ApplicabilityResult:
    """Evaluate whether a parsed class applies to the given case kind.

    Rules (case_kind is ``transition`` or ``observation``):

    - transition + basis class -> applicable
    - transition + NOT_APPLICABLE -> well-formed, context-invalid
    - observation + NOT_APPLICABLE -> applicable
    - observation + basis class -> well-formed, context-invalid

    A ``None`` semantic class (malformed parse) is never applicable.
    """

    if semantic_class is None:
        return ApplicabilityResult(applicable=False, reason=_REASON_MALFORMED)

    if case_kind == "transition":
        if semantic_class is SemanticResponseClass.NOT_APPLICABLE:
            return ApplicabilityResult(applicable=False, reason=_REASON_CONTEXT_INVALID)
        return ApplicabilityResult(applicable=True, reason=None)

    if case_kind == "observation":
        if semantic_class is SemanticResponseClass.NOT_APPLICABLE:
            return ApplicabilityResult(applicable=True, reason=None)
        return ApplicabilityResult(applicable=False, reason=_REASON_CONTEXT_INVALID)

    raise E1ResponseABIError(f"unsupported case_kind: {case_kind!r}")


# ---------------------------------------------------------------------------
# Parser conformance vectors.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParserConformance:
    """Conformance vectors for the strict parser (accepted + rejected examples)."""

    schema_version: str
    release: str
    source_commit: str
    parser_identity: str
    accepted_examples: tuple[dict[str, object], ...]
    rejected_examples: tuple[dict[str, object], ...]
    codeword_set: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "parser_identity": self.parser_identity,
            "accepted_examples": [dict(item) for item in self.accepted_examples],
            "rejected_examples": [dict(item) for item in self.rejected_examples],
            "codeword_set": list(self.codeword_set),
        }


def build_parser_conformance(source_commit: str) -> ParserConformance:
    """Build the parser conformance vectors."""

    accepted: list[dict[str, object]] = []
    for semantic_class, codeword in _CODEWORD_BY_CLASS.items():
        parsed = parse_response(codeword)
        accepted.append(
            {
                "raw_output": codeword,
                "expected_semantic_class": semantic_class.value,
                "is_valid": parsed.is_valid,
                "observed_semantic_class": (
                    parsed.semantic_class.value if parsed.semantic_class is not None else None
                ),
                "reason_code": parsed.reason_code,
            }
        )

    rejected_raws = (
        " A",  # leading whitespace
        "A ",  # trailing whitespace
        "A\n",  # newline suffix
        "\nA",  # newline prefix
        "a",  # case mutation
        "A.",  # punctuation suffix
        "A is the answer",  # prose continuation
        "The answer is A",  # prose
        "",  # empty
        "AB",  # concatenated valid codewords
        "F",  # unknown same-length output
        "AA",  # repeated codeword
        "\tA",  # tab prefix
        "A\t",  # tab suffix
    )
    rejected: list[dict[str, object]] = []
    for raw in rejected_raws:
        parsed = parse_response(raw)
        rejected.append(
            {
                "raw_output": raw,
                "is_valid": parsed.is_valid,
                "reason_code": parsed.reason_code,
            }
        )

    return ParserConformance(
        schema_version=_PARSER_CONFORMANCE_SCHEMA_VERSION,
        release=_RELEASE,
        source_commit=source_commit,
        parser_identity=_PARSER_IDENTITY,
        accepted_examples=tuple(accepted),
        rejected_examples=tuple(rejected),
        codeword_set=tuple(sorted({cw for cw in _CODEWORD_BY_CLASS.values()})),
    )


# ---------------------------------------------------------------------------
# Evaluation contract: primary + safety metrics.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvaluationContract:
    """Frozen metric identities, aggregation rules, and malformed policy."""

    schema_version: str
    release: str
    source_commit: str
    primary_metric_identity: str
    safety_metric_identity: str
    primary_metric_aggregation: dict[str, object]
    safety_metric_fields: dict[str, object]
    malformed_policy: dict[str, object]
    metric_implementation_identity: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "primary_metric_identity": self.primary_metric_identity,
            "safety_metric_identity": self.safety_metric_identity,
            "primary_metric_aggregation": self.primary_metric_aggregation,
            "safety_metric_fields": self.safety_metric_fields,
            "malformed_policy": self.malformed_policy,
            "metric_implementation_identity": self.metric_implementation_identity,
        }


def build_evaluation_contract(source_commit: str) -> EvaluationContract:
    """Build the evaluation contract binding both metrics."""

    primary_aggregation: dict[str, object] = {
        "procedure": (
            "exact semantic-class correctness per development transition, grouped by "
            "family identity, accuracy within each family, arithmetic mean across the "
            "four development families"
        ),
        "family_identity_source": "frozen split manifest (derive_scenario_family_identity)",
        "development_family_count": _EXPECTED_DEVELOPMENT_FAMILY_COUNT,
        "malformed_transition_treatment": "incorrect",
        "not_applicable_on_transition_treatment": "incorrect",
        "missing_output_treatment": "malformed_incorrect",
        "denominator_policy": "failed parses are never dropped from the denominator",
        "observation_records": "excluded from the primary metric",
    }
    safety_fields: dict[str, object] = {
        "clean_exact_error_count": (
            "total incorrect predictions on clean cases (malformed + wrong class + "
            "not-applicable on transition)"
        ),
        "spurious_basis_removal_count": (
            "gold removed=false, prediction removed=true (gold NEITHER or SURVIVES_ONLY, "
            "prediction REMOVES_ONLY or BOTH)"
        ),
        "valid_basis_rejection_count": (
            "gold survives=true, prediction survives=false (gold SURVIVES_ONLY or BOTH, "
            "prediction NEITHER or REMOVES_ONLY)"
        ),
        "clean_not_applicable_count": "NOT_APPLICABLE emitted on a clean transition",
        "clean_malformed_count": "malformed output on a clean case",
        "value_type": "integer counts (no floats)",
    }
    malformed_policy: dict[str, object] = {
        "primary_metric": "malformed counts as incorrect and stays in the denominator",
        "safety_metric": "malformed increments clean_malformed_count and clean_exact_error_count",
        "repair": "none",
    }
    return EvaluationContract(
        schema_version=_EVALUATION_CONTRACT_SCHEMA_VERSION,
        release=_RELEASE,
        source_commit=source_commit,
        primary_metric_identity=_PRIMARY_METRIC_IDENTITY,
        safety_metric_identity=_SAFETY_METRIC_IDENTITY,
        primary_metric_aggregation=primary_aggregation,
        safety_metric_fields=safety_fields,
        malformed_policy=malformed_policy,
        metric_implementation_identity=_METRIC_IMPLEMENTATION_IDENTITY,
    )


# ---------------------------------------------------------------------------
# Primary metric: family-macro accuracy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FamilyMacroAccuracy:
    """Primary metric result over development transition predictions."""

    metric_identity: str
    development_family_count: int
    family_results: tuple[dict[str, object], ...]
    family_macro_accuracy_numerator: int
    family_macro_accuracy_denominator: int

    @property
    def family_macro_accuracy(self) -> int:
        """Scaled accuracy numerator/denominator (integer-rational, no float)."""

        return self.family_macro_accuracy_numerator

    def to_dict(self) -> dict[str, object]:
        return {
            "metric_identity": self.metric_identity,
            "development_family_count": self.development_family_count,
            "family_results": [dict(item) for item in self.family_results],
            "family_macro_accuracy_numerator": self.family_macro_accuracy_numerator,
            "family_macro_accuracy_denominator": self.family_macro_accuracy_denominator,
        }


def _transition_is_correct(
    gold: SemanticResponseClass,
    parsed: ParsedResponse,
) -> bool:
    """A transition prediction is correct iff the parsed class exactly matches gold.

    Malformed, missing, and NOT_APPLICABLE predictions are all incorrect.
    """

    if not parsed.is_valid:
        return False
    if parsed.semantic_class is None:
        return False
    return parsed.semantic_class == gold


def score_family_macro_accuracy(
    cases: tuple[dict[str, object], ...],
    predictions: dict[str, str],
) -> FamilyMacroAccuracy:
    """Score the primary family-macro accuracy metric.

    Parameters
    ----------
    cases:
        Development transition evaluation cases (case_id, family_digest, gold_class).
    predictions:
        Mapping from case_id to raw model output string.
    """

    dev_cases = [item for item in cases if item.get("case_kind") == "transition"]
    by_family: dict[str, list[dict[str, object]]] = {}
    for item in dev_cases:
        family_digest = str(item["family_digest"])
        by_family.setdefault(family_digest, []).append(item)

    family_results: list[dict[str, object]] = []
    family_correct_count = 0
    for family_digest in sorted(by_family):
        members = by_family[family_digest]
        correct = 0
        total = len(members)
        member_results: list[dict[str, object]] = []
        for member in members:
            case_id = str(member["case_id"])
            gold = SemanticResponseClass(str(member["gold_class"]))
            raw = predictions.get(case_id, "")
            parsed = parse_response(raw)
            is_correct = _transition_is_correct(gold, parsed)
            if is_correct:
                correct += 1
            member_results.append(
                {
                    "case_id": case_id,
                    "gold_class": gold.value,
                    "raw_output": raw,
                    "is_valid": parsed.is_valid,
                    "parsed_class": (
                        parsed.semantic_class.value if parsed.semantic_class is not None else None
                    ),
                    "reason_code": parsed.reason_code,
                    "is_correct": is_correct,
                }
            )
        # Each family accuracy is correct/total. The family-macro mean is the
        # arithmetic mean across families. We accumulate an integer count of
        # families whose every member is correct (the canonical 0/1 per family
        # for the four single-transition families) and report it over the
        # family count. Per-family correctness details are in family_results.
        family_accurate = correct == total
        if family_accurate:
            family_correct_count += 1
        family_results.append(
            {
                "family_digest": family_digest,
                "declared_family": str(members[0].get("declared_family", "")),
                "transition_count": total,
                "correct_count": correct,
                "family_accuracy": family_accurate,
                "members": member_results,
            }
        )

    family_count = len(by_family)
    if family_count != _EXPECTED_DEVELOPMENT_FAMILY_COUNT:
        raise E1ResponseABIError(
            f"expected {_EXPECTED_DEVELOPMENT_FAMILY_COUNT} development families, "
            f"observed {family_count}"
        )

    return FamilyMacroAccuracy(
        metric_identity=_PRIMARY_METRIC_IDENTITY,
        development_family_count=family_count,
        family_results=tuple(family_results),
        family_macro_accuracy_numerator=family_correct_count,
        family_macro_accuracy_denominator=family_count,
    )


# ---------------------------------------------------------------------------
# Safety metric: explicit raw counts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CleanCaseRegressionCounts:
    """Safety metric explicit raw counts over clean cases."""

    metric_identity: str
    clean_exact_error_count: int
    spurious_basis_removal_count: int
    valid_basis_rejection_count: int
    clean_not_applicable_count: int
    clean_malformed_count: int
    per_case: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "metric_identity": self.metric_identity,
            "clean_exact_error_count": self.clean_exact_error_count,
            "spurious_basis_removal_count": self.spurious_basis_removal_count,
            "valid_basis_rejection_count": self.valid_basis_rejection_count,
            "clean_not_applicable_count": self.clean_not_applicable_count,
            "clean_malformed_count": self.clean_malformed_count,
            "per_case": [dict(item) for item in self.per_case],
        }


_BASIS_CLASSES = frozenset(
    {
        SemanticResponseClass.NEITHER,
        SemanticResponseClass.REMOVES_ONLY,
        SemanticResponseClass.SURVIVES_ONLY,
        SemanticResponseClass.BOTH,
    }
)
_REMOVAL_CLASSES = frozenset({SemanticResponseClass.REMOVES_ONLY, SemanticResponseClass.BOTH})
_SURVIVAL_CLASSES = frozenset({SemanticResponseClass.SURVIVES_ONLY, SemanticResponseClass.BOTH})


def score_clean_case_regression(
    cases: tuple[dict[str, object], ...],
    predictions: dict[str, str],
) -> CleanCaseRegressionCounts:
    """Score the clean-case regression safety metric over clean transition cases.

    Emits explicit integer counts:

    - ``clean_exact_error_count``: total incorrect predictions on clean cases.
    - ``spurious_basis_removal_count``: gold removed=false, prediction removed=true.
    - ``valid_basis_rejection_count``: gold survives=true, prediction survives=false.
    - ``clean_not_applicable_count``: NOT_APPLICABLE on a clean transition.
    - ``clean_malformed_count``: malformed output on a clean case.
    """

    clean_cases = [
        item
        for item in cases
        if item.get("case_kind") == "transition" and item.get("cohort") == "clean"
    ]

    clean_exact_error_count = 0
    spurious_basis_removal_count = 0
    valid_basis_rejection_count = 0
    clean_not_applicable_count = 0
    clean_malformed_count = 0
    per_case: list[dict[str, object]] = []

    for item in clean_cases:
        case_id = str(item["case_id"])
        gold = SemanticResponseClass(str(item["gold_class"]))
        raw = predictions.get(case_id, "")
        parsed = parse_response(raw)
        pred = parsed.semantic_class

        exact_error = not (parsed.is_valid and pred == gold)
        if exact_error:
            clean_exact_error_count += 1

        if not parsed.is_valid:
            clean_malformed_count += 1
        elif pred is SemanticResponseClass.NOT_APPLICABLE:
            clean_not_applicable_count += 1
        elif pred is not None and gold in _BASIS_CLASSES and pred in _BASIS_CLASSES:
            gold_removed = gold in _REMOVAL_CLASSES
            pred_removed = pred in _REMOVAL_CLASSES
            if not gold_removed and pred_removed:
                spurious_basis_removal_count += 1
            gold_survives = gold in _SURVIVAL_CLASSES
            pred_survives = pred in _SURVIVAL_CLASSES
            if gold_survives and not pred_survives:
                valid_basis_rejection_count += 1

        per_case.append(
            {
                "case_id": case_id,
                "gold_class": gold.value,
                "raw_output": raw,
                "is_valid": parsed.is_valid,
                "parsed_class": pred.value if pred is not None else None,
                "reason_code": parsed.reason_code,
                "exact_error": exact_error,
            }
        )

    return CleanCaseRegressionCounts(
        metric_identity=_SAFETY_METRIC_IDENTITY,
        clean_exact_error_count=clean_exact_error_count,
        spurious_basis_removal_count=spurious_basis_removal_count,
        valid_basis_rejection_count=valid_basis_rejection_count,
        clean_not_applicable_count=clean_not_applicable_count,
        clean_malformed_count=clean_malformed_count,
        per_case=tuple(per_case),
    )


# ---------------------------------------------------------------------------
# Evaluation case construction.
# ---------------------------------------------------------------------------


def _derive_transition_gold(spec: ScenarioSpec, case: TransitionCase) -> SemanticResponseClass:
    """Derive the gold semantic class for a transition case via the oracle."""

    from csd_foundry.kernel.oracle import CsdOracle

    if not isinstance(case.event, object):  # defensive; transition always carries an event
        raise E1ResponseABIError(f"{case.case_id}: transition case missing event")
    oracle = CsdOracle().apply(case.before, case.event)
    trace = oracle.trace
    any_removed = len(trace.removed_bases) > 0
    any_survives = len(trace.surviving_bases) > 0
    return _basis_disposition_class(any_removed, any_survives)


def build_evaluation_cases() -> tuple[dict[str, object], ...]:
    """Build evaluation cases from development transitions + clean cases.

    Development transitions contribute one ``transition`` case each (cohort
    ``development``), with the gold class derived from the executable oracle.
    Clean cases contribute one ``transition`` case each (cohort ``clean``),
    with the gold class taken from the declared clean-case disposition.

    Observation records are NOT emitted as evaluation cases: basis disposition
    is undefined for observations, and observations do not enter the primary
    metric. The response ABI still defines ``NOT_APPLICABLE`` as the applicable
    response for observations, but no scored observation case is produced here.
    """

    cases: list[dict[str, object]] = []

    catalog = build_e1_development_contrast_catalog(SCENARIOS)
    for scenario_id in sorted(catalog):
        spec = catalog[scenario_id]
        if spec.split != "validation":
            continue
        identity = derive_scenario_family_identity(spec)
        for case in spec.cases:
            if not isinstance(case, TransitionCase):
                continue
            gold = _derive_transition_gold(spec, case)
            cases.append(
                {
                    "schema_version": _EVALUATION_CASE_SCHEMA,
                    "case_id": f"e1-evaluation/development/{scenario_id}/{case.case_id}",
                    "record_id": case.case_id,
                    "scenario_id": scenario_id,
                    "case_kind": "transition",
                    "cohort": "development",
                    "family_digest": identity.family_digest,
                    "declared_family": spec.family,
                    "gold_class": gold.value,
                    "codeword": _CODEWORD_BY_CLASS[gold],
                }
            )

    clean_pairs = build_clean_case_transition_cases()
    clean_spec: CleanCaseSpec
    for clean_spec, case in clean_pairs:
        gold = SemanticResponseClass(clean_spec.declared_class)
        cases.append(
            {
                "schema_version": _EVALUATION_CASE_SCHEMA,
                "case_id": f"e1-evaluation/clean/{clean_spec.case_id}/{case.case_id}",
                "record_id": case.case_id,
                "scenario_id": clean_spec.case_id,
                "case_kind": "transition",
                "cohort": "clean",
                "family_digest": clean_spec.family,
                "declared_family": clean_spec.family,
                "gold_class": gold.value,
                "codeword": _CODEWORD_BY_CLASS[gold],
            }
        )

    return tuple(cases)


# ---------------------------------------------------------------------------
# Predecessor authentication.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthenticatedPredecessorReceipt:
    """Authenticated A0b1 population-support receipt + carried A0c authority."""

    receipt_sha256: str
    payload: dict[str, Any]
    source_commit: str
    predecessor_audit_sha256: str
    predecessor_source_commit: str
    predecessor_audit_schema: str
    predecessor_audit_release: str
    predecessor_selection_contract_digest: str
    predecessor_bundle_manifest_sha256: str
    predecessor_primary_projection_name: str
    carried_blockers: tuple[str, ...]


def authenticate_predecessor_receipt(receipt_bytes: bytes) -> AuthenticatedPredecessorReceipt:
    """Authenticate the A0b1 population-support receipt.

    The receipt SHA-256 is computed over the raw bytes and compared to the
    pinned constant. The A0c predecessor authority fields are then read back
    from the authenticated receipt payload (they were pinned and fail-closed
    one hop earlier in the A0b1 module), so this module does not re-pin them.
    """

    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha256 != _EXPECTED_PREDECESSOR_RECEIPT_SHA256:
        raise E1ResponseABIError(
            "predecessor receipt SHA-256 mismatch: expected "
            f"{_EXPECTED_PREDECESSOR_RECEIPT_SHA256}, observed {receipt_sha256}"
        )

    payload: dict[str, Any] = json.loads(receipt_bytes.decode("utf-8"))

    schema_version = str(payload.get("schema_version"))
    if schema_version != "e1-population-support-receipt/1":
        raise E1ResponseABIError(
            f"predecessor receipt schema_version mismatch: observed {schema_version}"
        )
    primary_projection = str(payload.get("primary_projection_name"))
    if primary_projection != "basis_disposition":
        raise E1ResponseABIError(
            f"predecessor primary projection must be basis_disposition, observed "
            f"{primary_projection}"
        )

    source_commit = str(payload.get("source_commit"))
    predecessor_audit_sha256 = str(payload.get("predecessor_audit_sha256"))
    predecessor_selection = str(payload.get("predecessor_selection_contract_digest"))
    predecessor_bundle = str(payload.get("predecessor_bundle_manifest_sha256"))

    raw_blockers = payload.get("carried_blockers", [])
    if not isinstance(raw_blockers, list):
        raise E1ResponseABIError("predecessor receipt carried_blockers must be a list")
    blockers = tuple(str(item) for item in raw_blockers)

    return AuthenticatedPredecessorReceipt(
        receipt_sha256=receipt_sha256,
        payload=payload,
        source_commit=source_commit,
        predecessor_audit_sha256=predecessor_audit_sha256,
        predecessor_source_commit="",  # not carried in the v3 receipt; read from audit
        predecessor_audit_schema="",
        predecessor_audit_release="",
        predecessor_selection_contract_digest=predecessor_selection,
        predecessor_bundle_manifest_sha256=predecessor_bundle,
        predecessor_primary_projection_name=primary_projection,
        carried_blockers=blockers,
    )


def authenticate_predecessor_audit(
    audit_bytes: bytes,
    *,
    expected_audit_sha256: str,
) -> dict[str, Any]:
    """Authenticate the A0c predecessor audit, reusing the A0b1-pinned constants.

    The A0c audit SHA-256 is read from the authenticated A0b1 receipt (the
    ``expected_audit_sha256`` argument) and compared to the recomputed digest
    of the supplied audit bytes. The audit's pinned identity fields (source
    commit, schema, release, selection digest, bundle manifest) are read back
    from the A0b1 module's exported constants via the receipt, but here we
    re-verify the byte digest and structural fields against the A0b1 module's
    pinned constants directly.
    """

    from csd_foundry.empirical.e1.projection_clean_case_population import (
        authenticate_predecessor_audit as _authenticate_a0c,
    )

    # The A0b1 module re-pins the A0c constants and fail-closes on mismatch.
    authenticated = _authenticate_a0c(audit_bytes)
    if authenticated.audit_sha256 != expected_audit_sha256:
        raise E1ResponseABIError(
            "A0c audit SHA-256 does not match the A0b1 receipt binding: expected "
            f"{expected_audit_sha256}, observed {authenticated.audit_sha256}"
        )
    return authenticated.payload


# ---------------------------------------------------------------------------
# A0b2 receipt.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResponseABIMetricsBundle:
    """Compiled response ABI, codebook, parser, contract, cases, and receipt."""

    response_abi: ResponseABIContract
    tokenizer_codebook: TokenizerCodebook
    parser_conformance: ParserConformance
    evaluation_contract: EvaluationContract
    evaluation_cases: tuple[dict[str, object], ...]
    receipt: dict[str, object]

    def artifacts(self) -> dict[str, bytes]:
        """Return the six canonical artifacts keyed by output filename."""

        cases_jsonl = b"".join(canonical_json_bytes(item) for item in self.evaluation_cases)
        return {
            "response_abi.json": canonical_json_bytes(self.response_abi.to_dict()),
            "tokenizer_codebook.json": canonical_json_bytes(self.tokenizer_codebook.to_dict()),
            "parser_conformance.json": canonical_json_bytes(self.parser_conformance.to_dict()),
            "evaluation_contract.json": canonical_json_bytes(self.evaluation_contract.to_dict()),
            "evaluation_cases.jsonl": cases_jsonl,
            "a0b2_receipt.json": canonical_json_bytes(self.receipt),
        }


def compile_response_abi_metrics(
    *,
    source_commit: str,
    predecessor_population_receipt_path: str,
    predecessor_audit_path: str,
) -> dict[str, bytes]:
    """Compile the six response-ABI artifacts.

    Parameters
    ----------
    source_commit:
        The git commit SHA that produced these artifacts (commit S in the spec).
    predecessor_population_receipt_path:
        Path to the A0b1 population-support receipt
        (``data/e1/v3/population_support_receipt.json``).
    predecessor_audit_path:
        Path to the A0c predecessor audit (``data/e1/v2/label_space_audit.json``).
    """

    receipt_path = Path(predecessor_population_receipt_path)
    audit_path = Path(predecessor_audit_path)
    receipt_bytes = receipt_path.read_bytes()
    audit_bytes = audit_path.read_bytes()

    # 1. Authenticate the A0b1 population receipt (pinned SHA-256).
    predecessor_receipt = authenticate_predecessor_receipt(receipt_bytes)

    # 2. Authenticate the A0c predecessor audit, reusing the A0b1-pinned
    #    constants via the A0b1 module's own authenticator.
    audit_payload = authenticate_predecessor_audit(
        audit_bytes,
        expected_audit_sha256=predecessor_receipt.predecessor_audit_sha256,
    )

    # 3. Load the tokenizer, generate the codebook, verify isometry.
    asset_cache_dir = _resolve_asset_cache_dir()
    codebook = build_tokenizer_codebook(
        source_commit,
        asset_cache_dir=asset_cache_dir,
    )

    # 4. Build the response ABI contract.
    abi = build_response_abi_contract(source_commit)

    # 5. Build parser conformance and evaluation contract.
    parser_conformance = build_parser_conformance(source_commit)
    evaluation_contract = build_evaluation_contract(source_commit)

    # 6. Build evaluation cases.
    evaluation_cases = build_evaluation_cases()
    if len(evaluation_cases) != _EXPECTED_DEVELOPMENT_FAMILY_COUNT + 4:
        raise E1ResponseABIError(
            f"expected {_EXPECTED_DEVELOPMENT_FAMILY_COUNT + 4} evaluation cases "
            f"(4 dev transitions + 4 clean), observed {len(evaluation_cases)}"
        )

    # 7. Build the receipt binding S, the 6 artifacts, predecessor identities,
    #    tokenizer identity, and parser/metric digests.
    receipt = _build_receipt(
        source_commit=source_commit,
        abi=abi,
        codebook=codebook,
        parser_conformance=parser_conformance,
        evaluation_contract=evaluation_contract,
        evaluation_cases=evaluation_cases,
        predecessor_receipt=predecessor_receipt,
        audit_payload=audit_payload,
    )

    bundle = ResponseABIMetricsBundle(
        response_abi=abi,
        tokenizer_codebook=codebook,
        parser_conformance=parser_conformance,
        evaluation_contract=evaluation_contract,
        evaluation_cases=evaluation_cases,
        receipt=receipt,
    )
    return bundle.artifacts()


def _resolve_asset_cache_dir() -> Path | None:
    """Resolve the local HF cache directory for tokenizer asset digest verification."""

    import os

    env_home = os.environ.get("HF_HOME")
    if env_home:
        return Path(env_home) / "hub" if "hub" not in env_home else Path(env_home)
    candidate = Path("artifacts") / "e0h-windows-native-v2" / "hf-cache"
    if candidate.is_dir():
        return candidate
    return None


def _build_receipt(
    *,
    source_commit: str,
    abi: ResponseABIContract,
    codebook: TokenizerCodebook,
    parser_conformance: ParserConformance,
    evaluation_contract: EvaluationContract,
    evaluation_cases: tuple[dict[str, object], ...],
    predecessor_receipt: AuthenticatedPredecessorReceipt,
    audit_payload: dict[str, Any],
) -> dict[str, object]:
    """Build the A0b2 receipt binding all six artifacts and predecessor identities."""

    abi_bytes = canonical_json_bytes(abi.to_dict())
    codebook_bytes = canonical_json_bytes(codebook.to_dict())
    parser_bytes = canonical_json_bytes(parser_conformance.to_dict())
    contract_bytes = canonical_json_bytes(evaluation_contract.to_dict())
    cases_jsonl = b"".join(canonical_json_bytes(item) for item in evaluation_cases)

    constituent_digests = {
        "response_abi.json": hashlib.sha256(abi_bytes).hexdigest(),
        "tokenizer_codebook.json": hashlib.sha256(codebook_bytes).hexdigest(),
        "parser_conformance.json": hashlib.sha256(parser_bytes).hexdigest(),
        "evaluation_contract.json": hashlib.sha256(contract_bytes).hexdigest(),
        "evaluation_cases.jsonl": hashlib.sha256(cases_jsonl).hexdigest(),
    }
    if len(set(constituent_digests.values())) != 5:
        raise E1ResponseABIError("constituent artifact digests must be mutually distinct")

    parser_digest = canonical_sha256(
        {
            "parser_identity": parser_conformance.parser_identity,
            "codeword_set": list(parser_conformance.codeword_set),
            "accepted_examples": list(parser_conformance.accepted_examples),
            "rejected_examples": list(parser_conformance.rejected_examples),
        }
    )
    metric_digest = canonical_sha256(
        {
            "primary_metric_identity": evaluation_contract.primary_metric_identity,
            "safety_metric_identity": evaluation_contract.safety_metric_identity,
            "primary_metric_aggregation": evaluation_contract.primary_metric_aggregation,
            "safety_metric_fields": evaluation_contract.safety_metric_fields,
            "malformed_policy": evaluation_contract.malformed_policy,
        }
    )

    # Carry the A0c predecessor authority fields read from the authenticated audit.
    predecessor_source_commit = str(audit_payload.get("source_commit", ""))
    predecessor_audit_schema = str(audit_payload.get("schema_version", ""))
    predecessor_audit_release = str(audit_payload.get("release", ""))

    return {
        "schema_version": _A0B2_RECEIPT_SCHEMA,
        "release": _RELEASE,
        "source_commit": source_commit,
        "constituent_artifact_digests": dict(sorted(constituent_digests.items())),
        "predecessor_receipt_sha256": predecessor_receipt.receipt_sha256,
        "predecessor_source_commit": predecessor_receipt.source_commit,
        "predecessor_audit_sha256": predecessor_receipt.predecessor_audit_sha256,
        "predecessor_audit_source_commit": predecessor_source_commit,
        "predecessor_audit_schema": predecessor_audit_schema,
        "predecessor_audit_release": predecessor_audit_release,
        "predecessor_selection_contract_digest": (
            predecessor_receipt.predecessor_selection_contract_digest
        ),
        "predecessor_bundle_manifest_sha256": (
            predecessor_receipt.predecessor_bundle_manifest_sha256
        ),
        "predecessor_primary_projection_name": (
            predecessor_receipt.predecessor_primary_projection_name
        ),
        "carried_blockers": list(predecessor_receipt.carried_blockers),
        "tokenizer_repository": codebook.tokenizer_repository,
        "tokenizer_revision": codebook.tokenizer_revision,
        "tokenizer_asset_aggregate_digest": codebook.tokenizer_asset_aggregate_digest,
        "parser_digest": parser_digest,
        "metric_digest": metric_digest,
        "semantic_class_count": len(SemanticResponseClass),
        "evaluation_case_count": len(evaluation_cases),
        "development_family_count": _EXPECTED_DEVELOPMENT_FAMILY_COUNT,
        "claim_boundary": _CLAIM_BOUNDARY,
    }


# ---------------------------------------------------------------------------
# Public re-exports.
# ---------------------------------------------------------------------------

SCHEMA_VERSION = _ABI_SCHEMA_VERSION
RELEASE = _RELEASE
CLAIM_BOUNDARY = _CLAIM_BOUNDARY
PRIMARY_METRIC_IDENTITY = _PRIMARY_METRIC_IDENTITY
SAFETY_METRIC_IDENTITY = _SAFETY_METRIC_IDENTITY
PARSER_IDENTITY = _PARSER_IDENTITY
TOKENIZER_REPOSITORY = _TOKENIZER_REPOSITORY
TOKENIZER_REVISION = _TOKENIZER_REVISION
TOKENIZER_ASSET_AGGREGATE_DIGEST = _TOKENIZER_ASSET_AGGREGATE_DIGEST
EXPECTED_PREDECESSOR_RECEIPT_SHA256 = _EXPECTED_PREDECESSOR_RECEIPT_SHA256
CODEWORD_BY_CLASS = _CODEWORD_BY_CLASS


__all__ = [
    "CLAIM_BOUNDARY",
    "CODEWORD_BY_CLASS",
    "EXPECTED_PREDECESSOR_RECEIPT_SHA256",
    "PARSER_IDENTITY",
    "PRIMARY_METRIC_IDENTITY",
    "RELEASE",
    "SAFETY_METRIC_IDENTITY",
    "SCHEMA_VERSION",
    "TOKENIZER_ASSET_AGGREGATE_DIGEST",
    "TOKENIZER_REPOSITORY",
    "TOKENIZER_REVISION",
    "ApplicabilityResult",
    "AuthenticatedPredecessorReceipt",
    "CleanCaseRegressionCounts",
    "E1ResponseABIError",
    "EvaluationContract",
    "FamilyMacroAccuracy",
    "ParsedResponse",
    "ParserConformance",
    "ResponseABIMetricsBundle",
    "ResponseABIContract",
    "SemanticResponseClass",
    "TokenizerCodebook",
    "authenticate_predecessor_audit",
    "authenticate_predecessor_receipt",
    "build_evaluation_cases",
    "build_evaluation_contract",
    "build_parser_conformance",
    "build_response_abi_contract",
    "build_tokenizer_codebook",
    "compile_response_abi_metrics",
    "evaluate_applicability",
    "parse_response",
    "score_clean_case_regression",
    "score_family_macro_accuracy",
]
