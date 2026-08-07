"""E1 A1 conventional-control response compiler.

This module (the A1 slice) compiles a deterministic, prompt-visible event
heuristic that produces a conventional-synthetic control arm over the frozen
E1 training population. It is the counterpart to the executable-semantics
arm: where the Foundry arm labels each transition through the executable
oracle and invariant verification, this arm labels the same prompt inventory
through three frozen event rules that inspect ONLY ``case_kind`` and
``event_type``.

Three frozen rules (priority order):

* ``CTRL-OBSERVATION-NA/1`` — ``case_kind == observation`` -> ``NOT_APPLICABLE`` / ``E``
* ``CTRL-REASSESS-NEITHER/1`` — transition + ``event_type == Reassess`` -> ``NEITHER`` / ``A``
* ``CTRL-DEPENDENCYCHANGE-REMOVES/1`` — transition + ``event_type == DependencyChange``
  -> ``REMOVES_ONLY`` / ``B``

Anything else fails closed with ``UNSUPPORTED_CONVENTIONAL_CONTROL_EVENT``.

Hard information boundary. The generator may consume:

* The frozen selection contract / canonical TRAINING membership (via the A0c
  overlay catalog and the experiment selection contract). It does NOT consume
  the foundry artifact compiler and does NOT execute the oracle, runner, or
  invariant verification.
* Canonical model-visible task inputs reconstructed from the TRAIN
  ``ScenarioSpec`` cases (using ONLY ``case.before``/``case.event`` for
  transitions and ``case.state``/``case.assertion`` for observations).
* ``data/e1/v4/a0b2_receipt.json``, ``data/e1/v4/response_abi.json``,
  ``data/e1/v4/tokenizer_codebook.json``.

It must NOT consume/import/derive from canonical runner execution, traces,
oracle outputs, verification outputs, ``data/e1/v2/label_space_audit.json``,
``data/e1/v3/clean_case_*``, ``data/e1/v4/evaluation_cases.jsonl``, or
development gold labels and metric results. In particular it must NOT import
``compile_e1_foundry_artifacts`` or ``load_artifact_records``, because those
transitively execute ``CsdOracle``, ``apply_event``, ``run_scenario``, and
invariant verification.

Five blocking correctness properties:

1. **Pinned A0b2 receipt SHA-256.** The predecessor response-ABI receipt
   SHA-256 is pinned as a module constant and fail-closed on mismatch, so a
   coherently-substituted receipt cannot authenticate the control arm.

2. **ABI and codebook digest pinning from the receipt.** The response ABI and
   tokenizer codebook constituent digests are read from the authenticated
   receipt and re-verified against the supplied file bytes, so a swapped ABI
   or codebook cannot slip through.

3. **Codeword/token IDs read from the frozen codebook.** The codeword and
   token identifiers are READ from the authenticated codebook at
   response-record construction time, not stored on the rules. A changed
   A/B/E mapping invalidates the output.

4. **Training population invariants.** The expected scenario count (14),
   record count (19 = 3 observations + 16 transitions), and rule distribution
   (NOT_APPLICABLE:3, NEITHER:5, REMOVES_ONLY:11) are compilation
   invariants; any mismatch fails closed.

5. **No leakage.** The compiler reads ONLY ``case_kind``, ``event_type``, the
   prompt provenance fields, and the user-message content (the canonical task
   input text). It does not read ``reference_label``, ``trace``, oracle, or
   verification fields, and emits no rationales, traces, oracle references,
   evaluation fields, or generated prose.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e1.development_contrast_extension import (
    build_e1_development_contrast_catalog,
)
from csd_foundry.empirical.e1.execution_splits import (
    E1Split,
    derive_scenario_family_identity,
)
from csd_foundry.empirical.e1.experiment_contract import (
    E1ExperimentContract,
    compile_e1_experiment_contract,
)
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.spec import (
    ObservationCase,
    ScenarioSpec,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    to_json_value,
)


class E1ConventionalGeneratorError(ValueError):
    """Raised when the conventional-control response compiler fails closed."""


# ---------------------------------------------------------------------------
# Schema and release identifiers.
# ---------------------------------------------------------------------------

_RESPONSE_SCHEMA_VERSION = "e1-conventional-control-response/1"
_RULE_CATALOG_SCHEMA_VERSION = "e1-conventional-rule-catalog/1"
_MANIFEST_SCHEMA_VERSION = "e1-conventional-control-manifest/1"
_RECEIPT_SCHEMA_VERSION = "e1-conventional-control-receipt/1"
_RELEASE = "e1-conventional-control-generator/1"

# Predecessor source commit (from the A0c audit). The selection contract and
# the TRAIN ScenarioSpec population are re-derived at this commit so the
# control arm covers the exact frozen training population.
_PREDECESSOR_SOURCE_COMMIT = "cfac62da30d501f4744f88d31fee5d3096d1cfb6"

# Compilation population invariants.
_EXPECTED_SCENARIO_COUNT = 14
_EXPECTED_RECORD_COUNT = 19
_EXPECTED_OBSERVATION_COUNT = 3
_EXPECTED_TRANSITION_COUNT = 16
_EXPECTED_DISTRIBUTION = {
    "NOT_APPLICABLE": 3,
    "NEITHER": 5,
    "REMOVES_ONLY": 11,
    "SURVIVES_ONLY": 0,
    "BOTH": 0,
}
_TOTAL_DISTRIBUTION = sum(_EXPECTED_DISTRIBUTION.values())

# ---------------------------------------------------------------------------
# Pinned predecessor identities.
# ---------------------------------------------------------------------------

# The A0b2 response-ABI receipt SHA-256, computed over the committed file
# bytes at data/e1/v4/a0b2_receipt.json. Fail-closed on mismatch.
_EXPECTED_A0B2_RECEIPT_SHA256 = "6a033dbcfdae129e0013b1de50b452d38963492cec3a7c693254761f16c40c8a"

_FAIL_CLOSED_REASON = "UNSUPPORTED_CONVENTIONAL_CONTROL_EVENT"

_CLAIM_BOUNDARY = (
    "This compiler emits a deterministic, prompt-visible event heuristic that "
    "labels the frozen E1 training population with three rules over case_kind "
    "and event_type. It consumes only the frozen selection contract, the "
    "canonical model-visible task inputs reconstructed from the TRAIN "
    "ScenarioSpec cases, and the authenticated A0b2 response ABI, tokenizer "
    "codebook, and receipt. It does not execute a model, load a runner or "
    "oracle, read reference labels, traces, verification outputs, evaluation "
    "cases, or development gold labels, allocate a GPU, or establish learning "
    "value or general transfer."
)

# Allowed prompt-visible features. The labeler inspects ONLY these.
_ALLOWED_FEATURES = ("case_kind", "event_type")

_GIT_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")

# Canonical command strings whose SHA-256 digests are bound into the receipt.
# The generation/validation commands mirror the experiments/ orchestration
# helper interface and use the A1 predecessor source commit.
_GENERATION_COMMAND_TEMPLATE = (
    "python experiments/e1/compile_conventional_generator.py --source-commit {source_commit}"
)
_VALIDATION_COMMAND_TEMPLATE = (
    "python experiments/e1/compile_conventional_generator.py "
    "--source-commit {source_commit} --validate"
)


# ---------------------------------------------------------------------------
# Frozen rule table.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConventionalRule:
    """One frozen conventional-control rule.

    Rules map a prompt-visible condition to a semantic class ONLY. The
    codeword and token identifiers are NOT stored on the rule; they are
    resolved from the authenticated codebook at response-record construction
    time so a changed A/B/E mapping invalidates the output.
    """

    rule_id: str
    visible_condition: str
    semantic_class: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "visible_condition": self.visible_condition,
            "semantic_class": self.semantic_class,
        }


# Three frozen rules in evaluation (priority) order. The visible_condition is
# a prompt-visible predicate over the allowed features. Order matters:
# observation is checked first because observations carry no event_type.
_OBSERVATION_RULE = ConventionalRule(
    rule_id="CTRL-OBSERVATION-NA/1",
    visible_condition="case_kind == observation",
    semantic_class="NOT_APPLICABLE",
)
_REASSESS_RULE = ConventionalRule(
    rule_id="CTRL-REASSESS-NEITHER/1",
    visible_condition="transition and event_type == Reassess",
    semantic_class="NEITHER",
)
_DEPENDENCY_RULE = ConventionalRule(
    rule_id="CTRL-DEPENDENCYCHANGE-REMOVES/1",
    visible_condition="transition and event_type == DependencyChange",
    semantic_class="REMOVES_ONLY",
)
_RULES: tuple[ConventionalRule, ...] = (
    _OBSERVATION_RULE,
    _REASSESS_RULE,
    _DEPENDENCY_RULE,
)


# ---------------------------------------------------------------------------
# Response record.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConventionalControlResponseRecord:
    """One conventional-control response over a single training record."""

    schema_version: str
    response_id: str
    scenario_id: str
    record_id: str
    split: str
    case_kind: str
    event_type: str
    task_input_digest: str
    control_view_digest: str
    label_authority: str
    rule_id: str
    semantic_class: str
    codeword: str
    token_ids: tuple[int, ...]
    token_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "response_id": self.response_id,
            "scenario_id": self.scenario_id,
            "record_id": self.record_id,
            "split": self.split,
            "case_kind": self.case_kind,
            "event_type": self.event_type,
            "task_input_digest": self.task_input_digest,
            "control_view_digest": self.control_view_digest,
            "label_authority": self.label_authority,
            "rule_id": self.rule_id,
            "semantic_class": self.semantic_class,
            "codeword": self.codeword,
            "token_ids": list(self.token_ids),
            "token_count": self.token_count,
        }


# ---------------------------------------------------------------------------
# Authentication.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthenticatedA0b2Receipt:
    """Authenticated A0b2 response-ABI receipt plus constituent digests."""

    receipt_sha256: str
    payload: dict[str, Any]
    abi_digest: str
    codebook_digest: str
    source_commit: str


def authenticate_a0b2_receipt(receipt_bytes: bytes) -> AuthenticatedA0b2Receipt:
    """Authenticate the A0b2 response-ABI receipt.

    The receipt SHA-256 is computed over the raw bytes and compared to the
    pinned constant. The ABI and codebook constituent digests are then read
    from the authenticated payload (they were pinned one hop earlier in the
    A0b2 module).
    """

    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha256 != _EXPECTED_A0B2_RECEIPT_SHA256:
        raise E1ConventionalGeneratorError(
            "A0b2 receipt SHA-256 mismatch: expected "
            f"{_EXPECTED_A0B2_RECEIPT_SHA256}, observed {receipt_sha256}"
        )

    payload: dict[str, Any] = json.loads(receipt_bytes.decode("utf-8"))
    schema_version = str(payload.get("schema_version"))
    if schema_version != "e1-response-abi-receipt/1":
        raise E1ConventionalGeneratorError(
            f"A0b2 receipt schema_version mismatch: observed {schema_version}"
        )

    constituents = payload.get("constituent_artifact_digests")
    if not isinstance(constituents, dict):
        raise E1ConventionalGeneratorError(
            "A0b2 receipt constituent_artifact_digests must be an object"
        )
    abi_digest = constituents.get("response_abi.json")
    codebook_digest = constituents.get("tokenizer_codebook.json")
    if not isinstance(abi_digest, str) or not isinstance(codebook_digest, str):
        raise E1ConventionalGeneratorError(
            "A0b2 receipt must carry response_abi.json and tokenizer_codebook.json digests"
        )

    source_commit = str(payload.get("source_commit"))
    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1ConventionalGeneratorError(
            "A0b2 receipt source_commit must be a lowercase Git digest"
        )

    return AuthenticatedA0b2Receipt(
        receipt_sha256=receipt_sha256,
        payload=payload,
        abi_digest=abi_digest,
        codebook_digest=codebook_digest,
        source_commit=source_commit,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedABI:
    """Authenticated frozen response ABI plus the semantic-class set."""

    abi_digest: str
    payload: dict[str, Any]
    semantic_classes: frozenset[str]


def authenticate_response_abi(abi_bytes: bytes, *, expected_abi_digest: str) -> AuthenticatedABI:
    """Authenticate the frozen response ABI against the pinned digest."""

    abi_digest = hashlib.sha256(abi_bytes).hexdigest()
    if abi_digest != expected_abi_digest:
        raise E1ConventionalGeneratorError(
            f"response ABI digest mismatch: expected {expected_abi_digest}, observed {abi_digest}"
        )
    payload: dict[str, Any] = json.loads(abi_bytes.decode("utf-8"))
    schema_version = str(payload.get("schema_version"))
    if schema_version != "e1-response-abi/1":
        raise E1ConventionalGeneratorError(
            f"response ABI schema_version mismatch: observed {schema_version}"
        )
    semantic_classes = payload.get("semantic_classes")
    if not isinstance(semantic_classes, list):
        raise E1ConventionalGeneratorError("response ABI semantic_classes must be a list")
    classes = frozenset(str(item) for item in semantic_classes)
    return AuthenticatedABI(
        abi_digest=abi_digest,
        payload=payload,
        semantic_classes=classes,
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedCodebookEntry:
    """One authenticated codeword binding (semantic_class -> codeword/tokens)."""

    codeword: str
    token_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class AuthenticatedCodebook:
    """Authenticated frozen tokenizer codebook plus codeword bindings."""

    codebook_digest: str
    payload: dict[str, Any]
    # codeword by semantic class -> entry
    binding_by_class: dict[str, AuthenticatedCodebookEntry]


def authenticate_tokenizer_codebook(
    codebook_bytes: bytes, *, expected_codebook_digest: str
) -> AuthenticatedCodebook:
    """Authenticate the frozen tokenizer codebook against the pinned digest.

    The codeword and token-id bindings are READ from the codebook, not
    independently mapped, so a changed A/B/E mapping is caught.
    """

    codebook_digest = hashlib.sha256(codebook_bytes).hexdigest()
    if codebook_digest != expected_codebook_digest:
        raise E1ConventionalGeneratorError(
            "tokenizer codebook digest mismatch: expected "
            f"{expected_codebook_digest}, observed {codebook_digest}"
        )
    payload: dict[str, Any] = json.loads(codebook_bytes.decode("utf-8"))
    schema_version = str(payload.get("schema_version"))
    if schema_version != "e1-tokenizer-codebook/1":
        raise E1ConventionalGeneratorError(
            f"tokenizer codebook schema_version mismatch: observed {schema_version}"
        )
    codewords = payload.get("codewords")
    if not isinstance(codewords, list):
        raise E1ConventionalGeneratorError("tokenizer codebook codewords must be a list")
    binding_by_class: dict[str, AuthenticatedCodebookEntry] = {}
    for entry in codewords:
        if not isinstance(entry, dict):
            raise E1ConventionalGeneratorError(
                "tokenizer codebook codeword entry must be an object"
            )
        semantic_class = entry.get("semantic_class")
        codeword = entry.get("codeword")
        token_ids = entry.get("token_ids")
        token_count = entry.get("token_count")
        if not isinstance(semantic_class, str) or not isinstance(codeword, str):
            raise E1ConventionalGeneratorError(
                "tokenizer codebook codeword entry missing semantic_class/codeword"
            )
        if not isinstance(token_ids, list) or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in token_ids
        ):
            raise E1ConventionalGeneratorError(
                f"tokenizer codebook codeword {codeword!r} token_ids must be ints"
            )
        if not isinstance(token_count, int) or isinstance(token_count, bool):
            raise E1ConventionalGeneratorError(
                f"tokenizer codebook codeword {codeword!r} token_count must be an int"
            )
        if token_count != 1 or len(token_ids) != 1:
            raise E1ConventionalGeneratorError(
                f"tokenizer codebook codeword {codeword!r} must be single-token"
            )
        binding_by_class[semantic_class] = AuthenticatedCodebookEntry(
            codeword=codeword,
            token_ids=tuple(token_ids),
        )
    return AuthenticatedCodebook(
        codebook_digest=codebook_digest,
        payload=payload,
        binding_by_class=binding_by_class,
    )


# ---------------------------------------------------------------------------
# Training population: direct extraction from ScenarioSpec cases.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExtractedTrainingView:
    """Prompt-visible features plus provenance for one training record."""

    record_id: str
    scenario_id: str
    split: str
    case_kind: str
    event_type: str | None
    task_input_digest: str


@dataclass(frozen=True, slots=True)
class _ExtractedRecord:
    """One extracted training record with its canonical task input text."""

    record_id: str
    scenario_id: str
    family_digest: str
    case_kind: str
    event_type: str | None
    task_input: dict[str, object]
    task_input_text: str


def _task_input_for_case(spec: ScenarioSpec, case: object) -> dict[str, object]:
    """Build the canonical model-visible task input for one ScenarioSpec case.

    Only the prompt-visible fields are read. For a transition the task input
    uses ``case.before`` and ``case.event`` (the same material the Foundry
    compiler emits as the user-message content). For an observation it uses
    ``case.state`` and ``case.assertion``. No oracle/runner/verification
    machinery is invoked.
    """

    if isinstance(case, TransitionCase):
        return {
            "schema_version": "e1-semantic-decision-input/1",
            "case_type": "transition",
            "before": to_json_value(case.before),
            "event_type": type(case.event).__name__,
            "event": to_json_value(case.event),
        }
    if isinstance(case, ObservationCase):
        return {
            "schema_version": "e1-semantic-decision-input/1",
            "case_type": "observation",
            "state": to_json_value(case.state),
            "assertion": case.assertion,
        }
    raise E1ConventionalGeneratorError(
        f"unsupported training case type for {spec.scenario_id}: {type(case).__name__}"
    )


def _extract_training_records(
    registry: Mapping[str, ScenarioSpec],
    selection: E1ExperimentContract,
) -> tuple[_ExtractedRecord, ...]:
    """Extract the canonical TRAIN task inputs directly from ScenarioSpec cases.

    The TRAIN scenario IDs are read from the selection contract's split
    manifest (the union of all train-assignment scenario IDs). For each TRAIN
    ScenarioSpec, each ``case`` in ``spec.cases`` becomes one training record
    whose ``record_id`` matches the Foundry compiler's format
    ``e1-foundry/train/{scenario_id}/{case_id}``. Records are returned sorted
    by ``record_id``.
    """

    training_ids: set[str] = set()
    for assignment in selection.split_manifest.assignments:
        if assignment.split is E1Split.TRAIN:
            training_ids.update(assignment.scenario_ids)
    if len(training_ids) != _EXPECTED_SCENARIO_COUNT:
        raise E1ConventionalGeneratorError(
            f"expected {_EXPECTED_SCENARIO_COUNT} training scenarios, observed {len(training_ids)}"
        )

    records: list[_ExtractedRecord] = []
    missing = tuple(sorted(training_ids - set(registry)))
    if missing:
        raise E1ConventionalGeneratorError(f"training scenarios missing from registry: {missing}")
    for scenario_id in training_ids:
        spec = registry[scenario_id]
        family_digest = derive_scenario_family_identity(spec).family_digest
        for case in spec.cases:
            task_input = _task_input_for_case(spec, case)
            case_id = case.case_id
            record_id = f"e1-foundry/{E1Split.TRAIN.value}/{spec.scenario_id}/{case_id}"
            case_kind = str(task_input["case_type"])
            raw_event_type = task_input.get("event_type")
            if raw_event_type is None:
                event_type: str | None = None
            elif isinstance(raw_event_type, str):
                event_type = raw_event_type
            else:
                raise E1ConventionalGeneratorError(
                    f"training record {record_id}: event_type must be a string or null"
                )
            task_input_text = canonical_json_text(task_input)
            records.append(
                _ExtractedRecord(
                    record_id=record_id,
                    scenario_id=spec.scenario_id,
                    family_digest=family_digest,
                    case_kind=case_kind,
                    event_type=event_type,
                    task_input=task_input,
                    task_input_text=task_input_text,
                )
            )

    records.sort(key=lambda item: item.record_id)
    record_ids = [record.record_id for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise E1ConventionalGeneratorError("training record identifiers must be unique")
    return tuple(records)


def _extract_training_view(record: _ExtractedRecord) -> ExtractedTrainingView:
    """Project the prompt-visible view plus the task-input digest.

    Reads ONLY: record_id, scenario_id, split, case_kind, event_type, and the
    canonical task input text. Does NOT read reference_label, trace, oracle,
    or verification fields.
    """

    task_input_digest = hashlib.sha256(record.task_input_text.encode("utf-8")).hexdigest()
    return ExtractedTrainingView(
        record_id=record.record_id,
        scenario_id=record.scenario_id,
        split=E1Split.TRAIN.value,
        case_kind=record.case_kind,
        event_type=record.event_type,
        task_input_digest=task_input_digest,
    )


# ---------------------------------------------------------------------------
# Three-rule labeler.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConventionalLabel:
    """The deterministic label produced by the three-rule heuristic."""

    rule_id: str
    semantic_class: str


def label_conventional_control(view: ExtractedTrainingView) -> ConventionalLabel:
    """Apply the three frozen rules in priority order.

    Observations (no event_type) match CTRL-OBSERVATION-NA/1. Transitions are
    dispatched on event_type; only Reassess and DependencyChange are
    recognized. Anything else fails closed.
    """

    if view.case_kind == "observation":
        if view.event_type is not None:
            raise E1ConventionalGeneratorError(
                f"{view.record_id}: observation must not carry an event_type"
            )
        return ConventionalLabel(
            rule_id=_OBSERVATION_RULE.rule_id,
            semantic_class=_OBSERVATION_RULE.semantic_class,
        )
    if view.case_kind == "transition":
        if view.event_type is None:
            raise E1ConventionalGeneratorError(
                f"{view.record_id}: transition must carry an event_type ({_FAIL_CLOSED_REASON})"
            )
        if view.event_type == "Reassess":
            return ConventionalLabel(
                rule_id=_REASSESS_RULE.rule_id,
                semantic_class=_REASSESS_RULE.semantic_class,
            )
        if view.event_type == "DependencyChange":
            return ConventionalLabel(
                rule_id=_DEPENDENCY_RULE.rule_id,
                semantic_class=_DEPENDENCY_RULE.semantic_class,
            )
        raise E1ConventionalGeneratorError(
            f"{view.record_id}: unsupported transition event_type "
            f"{view.event_type!r} ({_FAIL_CLOSED_REASON})"
        )
    raise E1ConventionalGeneratorError(
        f"{view.record_id}: unsupported case_kind {view.case_kind!r} ({_FAIL_CLOSED_REASON})"
    )


# ---------------------------------------------------------------------------
# Rule catalog, response records, manifest, receipt.
# ---------------------------------------------------------------------------


def build_rule_catalog(
    *,
    abi: AuthenticatedABI,
    codebook: AuthenticatedCodebook,
) -> dict[str, object]:
    """Build the frozen rule catalog payload.

    The catalog materializes each rule's codeword/token_ids from the
    authenticated codebook (resolved by the rule's semantic class), so the
    emitted codewords track the frozen codebook rather than being stored on
    the rules. A tampered codebook (changed A/B/E mapping) is caught by the
    digest check earlier in the pipeline.
    """

    rules_payload: list[dict[str, object]] = []
    for rule in _RULES:
        if rule.semantic_class not in abi.semantic_classes:
            raise E1ConventionalGeneratorError(
                f"rule {rule.rule_id} semantic class {rule.semantic_class} "
                "absent from authenticated ABI"
            )
        if rule.semantic_class not in codebook.binding_by_class:
            raise E1ConventionalGeneratorError(
                f"rule {rule.rule_id} semantic class {rule.semantic_class} "
                "absent from authenticated codebook"
            )
        entry = codebook.binding_by_class[rule.semantic_class]
        rules_payload.append(
            {
                "rule_id": rule.rule_id,
                "visible_condition": rule.visible_condition,
                "semantic_class": rule.semantic_class,
                "codeword": entry.codeword,
                "token_ids": list(entry.token_ids),
            }
        )

    return {
        "schema_version": _RULE_CATALOG_SCHEMA_VERSION,
        "release": _RELEASE,
        "label_authority": "conventional_synthetic",
        "allowed_features": list(_ALLOWED_FEATURES),
        "rules": rules_payload,
        "precedence": (
            "Rules are evaluated in declared order: observation first (it "
            "carries no event_type), then Reassess, then DependencyChange. The "
            "first matching rule wins; everything else fails closed."
        ),
        "fail_closed": {
            "reason_code": _FAIL_CLOSED_REASON,
            "description": (
                "Any case_kind/event_type pair not matching a frozen rule fails "
                "closed and produces no response record."
            ),
        },
        "abi_identity": {
            "schema_version": abi.payload.get("schema_version"),
            "release": abi.payload.get("release"),
            "sha256": abi.abi_digest,
            "semantic_classes": sorted(abi.semantic_classes),
        },
        "codebook_identity": {
            "schema_version": codebook.payload.get("schema_version"),
            "release": codebook.payload.get("release"),
            "sha256": codebook.codebook_digest,
            "tokenizer_repository": codebook.payload.get("tokenizer_repository"),
            "tokenizer_revision": codebook.payload.get("tokenizer_revision"),
        },
        "claim_boundary": _CLAIM_BOUNDARY,
    }


def _build_response_record(
    view: ExtractedTrainingView,
    label: ConventionalLabel,
    codebook: AuthenticatedCodebook,
) -> ConventionalControlResponseRecord:
    """Build one conventional-control response record.

    The codeword and token_ids are resolved from the authenticated codebook
    by the label's semantic class. They are NOT stored on the rule.
    """

    entry = codebook.binding_by_class[label.semantic_class]
    codeword = entry.codeword
    token_ids = entry.token_ids
    control_view_digest = canonical_sha256(
        {"case_kind": view.case_kind, "event_type": view.event_type}
    )
    return ConventionalControlResponseRecord(
        schema_version=_RESPONSE_SCHEMA_VERSION,
        response_id=f"e1-control/{view.record_id}",
        scenario_id=view.scenario_id,
        record_id=view.record_id,
        split=view.split,
        case_kind=view.case_kind,
        event_type=view.event_type if view.event_type is not None else "",
        task_input_digest=view.task_input_digest,
        control_view_digest=control_view_digest,
        label_authority="conventional_synthetic",
        rule_id=label.rule_id,
        semantic_class=label.semantic_class,
        codeword=codeword,
        token_ids=token_ids,
        token_count=len(token_ids),
    )


def _jsonl(records: tuple[ConventionalControlResponseRecord, ...]) -> bytes:
    return b"".join(canonical_json_bytes(record.to_dict()) for record in records)


def _command_digest(template: str, source_commit: str) -> str:
    command = template.format(source_commit=source_commit)
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def _build_receipt(
    *,
    source_commit: str,
    a0b2_receipt: AuthenticatedA0b2Receipt,
    abi: AuthenticatedABI,
    codebook: AuthenticatedCodebook,
    selection_contract_digest: str,
    rule_catalog: dict[str, object],
    responses: tuple[ConventionalControlResponseRecord, ...],
    manifest: dict[str, object],
    implementation_sha256: str,
) -> dict[str, object]:
    """Build the A1 receipt binding all three non-receipt artifacts.

    The receipt binds the rule catalog, the responses, and the manifest (the
    three non-receipt constituents) plus the selection contract digest and the
    generation/validation command digests.
    """

    rule_catalog_digest = canonical_sha256(rule_catalog)
    responses_digest = hashlib.sha256(_jsonl(responses)).hexdigest()
    manifest_digest = canonical_sha256(manifest)
    constituent_digests = {
        "conventional_rule_catalog.json": rule_catalog_digest,
        "conventional_control_responses.jsonl": responses_digest,
        "conventional_control_manifest.json": manifest_digest,
    }
    if len(set(constituent_digests.values())) != 3:
        raise E1ConventionalGeneratorError(
            "rule catalog, responses, and manifest digests must be mutually distinct"
        )
    generation_command_digest = _command_digest(_GENERATION_COMMAND_TEMPLATE, source_commit)
    validation_command_digest = _command_digest(_VALIDATION_COMMAND_TEMPLATE, source_commit)
    return {
        "schema_version": _RECEIPT_SCHEMA_VERSION,
        "release": _RELEASE,
        "source_commit": source_commit,
        "selection_contract_digest": selection_contract_digest,
        "constituent_artifact_digests": dict(sorted(constituent_digests.items())),
        "a0b2_receipt_sha256": a0b2_receipt.receipt_sha256,
        "response_abi_digest": abi.abi_digest,
        "tokenizer_codebook_digest": codebook.codebook_digest,
        "rule_catalog_digest": rule_catalog_digest,
        "responses_digest": responses_digest,
        "manifest_digest": manifest_digest,
        "generation_command_digest": generation_command_digest,
        "validation_command_digest": validation_command_digest,
        "compiler_implementation_sha256": implementation_sha256,
        "predecessor_source_commit": _PREDECESSOR_SOURCE_COMMIT,
        "predecessor_a0b2_source_commit": a0b2_receipt.source_commit,
        "record_count": len(responses),
        "scenario_count": len({response.scenario_id for response in responses}),
        "label_authority": "conventional_synthetic",
        "claim_boundary": _CLAIM_BOUNDARY,
    }


def compute_compiler_implementation_sha256() -> str:
    """Compute the SHA-256 of this module's source bytes.

    The implementation identity is bound into the receipt so that a changed
    compiler (different rules, different feature extraction) produces a
    different receipt even if the population is unchanged.
    """

    module_path = Path(__file__).resolve()
    return hashlib.sha256(module_path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Compilation entry point.
# ---------------------------------------------------------------------------


def _build_training_records() -> tuple[_ExtractedRecord, ...]:
    """Re-derive the frozen TRAIN population directly from ScenarioSpec cases.

    The overlay catalog and selection contract are built (these do not execute
    semantics). The TRAIN task inputs are then extracted from the
    ``ScenarioSpec.cases`` tuples WITHOUT importing or invoking the foundry
    artifact compiler, oracle, runner, or invariant verification.
    """

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/2",
        source_commit=_PREDECESSOR_SOURCE_COMMIT,
    )
    _validate_selection(selection)
    records = _extract_training_records(overlay_catalog, selection)
    _validate_population(records)
    return records


def _validate_selection(selection: E1ExperimentContract) -> None:
    """Fail-closed if the selected training membership is not the frozen one.

    The split manifest assigns one family at a time, so the training membership
    is the union of all train-assignment scenario IDs. The union must be exactly
    the frozen 14 training scenarios with no overlap against the development or
    excluded source-test partitions.
    """

    training_ids: set[str] = set()
    for assignment in selection.split_manifest.assignments:
        if assignment.split.value == "train":
            training_ids.update(assignment.scenario_ids)
    if len(training_ids) != _EXPECTED_SCENARIO_COUNT:
        raise E1ConventionalGeneratorError(
            f"expected {_EXPECTED_SCENARIO_COUNT} training scenarios, observed {len(training_ids)}"
        )


def _validate_population(records: tuple[_ExtractedRecord, ...]) -> None:
    """Fail-closed if the training population does not match the invariants."""

    if len(records) != _EXPECTED_RECORD_COUNT:
        raise E1ConventionalGeneratorError(
            f"expected {_EXPECTED_RECORD_COUNT} training records, observed {len(records)}"
        )
    observation_count = sum(1 for record in records if record.case_kind == "observation")
    transition_count = sum(1 for record in records if record.case_kind == "transition")
    if observation_count != _EXPECTED_OBSERVATION_COUNT:
        raise E1ConventionalGeneratorError(
            f"expected {_EXPECTED_OBSERVATION_COUNT} observations, observed {observation_count}"
        )
    if transition_count != _EXPECTED_TRANSITION_COUNT:
        raise E1ConventionalGeneratorError(
            f"expected {_EXPECTED_TRANSITION_COUNT} transitions, observed {transition_count}"
        )


def _validate_distribution(
    responses: tuple[ConventionalControlResponseRecord, ...],
) -> None:
    """Fail-closed if the response distribution does not match the invariants."""

    counts: dict[str, int] = {key: 0 for key in _EXPECTED_DISTRIBUTION}
    for response in responses:
        counts[response.semantic_class] = counts.get(response.semantic_class, 0) + 1
    if counts != _EXPECTED_DISTRIBUTION:
        raise E1ConventionalGeneratorError(
            f"response distribution mismatch: expected {_EXPECTED_DISTRIBUTION}, observed {counts}"
        )
    if len(responses) != _TOTAL_DISTRIBUTION:
        raise E1ConventionalGeneratorError(
            f"expected {_TOTAL_DISTRIBUTION} responses, observed {len(responses)}"
        )


def _count_by_key(
    responses: tuple[ConventionalControlResponseRecord, ...],
    key: str,
) -> dict[str, int]:
    """Tally counts of a response field, sorted by key for determinism."""

    counts: dict[str, int] = {}
    for response in responses:
        value = getattr(response, key)
        text = (value if value else "observation") if key == "event_type" else value
        counts[text] = counts.get(text, 0) + 1
    return dict(sorted(counts.items()))


def compile_conventional_generator(
    *,
    source_commit: str,
    a0b2_receipt_path: str,
    response_abi_path: str,
    tokenizer_codebook_path: str,
) -> dict[str, bytes]:
    """Compile the four conventional-control artifacts.

    Parameters
    ----------
    source_commit:
        The git commit SHA that produced these artifacts (commit S in the spec).
    a0b2_receipt_path:
        Path to the A0b2 response-ABI receipt (``data/e1/v4/a0b2_receipt.json``).
    response_abi_path:
        Path to the frozen response ABI (``data/e1/v4/response_abi.json``).
    tokenizer_codebook_path:
        Path to the frozen tokenizer codebook
        (``data/e1/v4/tokenizer_codebook.json``).
    """

    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1ConventionalGeneratorError("source_commit must be a lowercase Git digest")

    receipt_bytes = Path(a0b2_receipt_path).read_bytes()
    abi_bytes = Path(response_abi_path).read_bytes()
    codebook_bytes = Path(tokenizer_codebook_path).read_bytes()

    # 1. Authenticate the A0b2 receipt (pinned SHA-256).
    a0b2_receipt = authenticate_a0b2_receipt(receipt_bytes)

    # 2. Authenticate the ABI and codebook against the receipt-pinned digests.
    abi = authenticate_response_abi(abi_bytes, expected_abi_digest=a0b2_receipt.abi_digest)
    codebook = authenticate_tokenizer_codebook(
        codebook_bytes, expected_codebook_digest=a0b2_receipt.codebook_digest
    )

    # 3. Re-derive the frozen TRAIN population directly from ScenarioSpec cases.
    records = _build_training_records()

    # 4. Extract the prompt-visible view and label each record.
    responses: list[ConventionalControlResponseRecord] = []
    for record in records:
        view = _extract_training_view(record)
        label = label_conventional_control(view)
        responses.append(_build_response_record(view, label, codebook))

    responses_tuple = tuple(sorted(responses, key=lambda item: item.record_id))
    record_ids = [response.record_id for response in responses_tuple]
    if len(record_ids) != len(set(record_ids)):
        raise E1ConventionalGeneratorError("response record identifiers must be unique")

    # 5. Validate the distribution invariants.
    _validate_distribution(responses_tuple)

    # 6. Build the four artifacts in dependency order:
    #    rule catalog -> responses -> manifest -> receipt.
    rule_catalog = build_rule_catalog(abi=abi, codebook=codebook)
    rule_catalog_bytes = canonical_json_bytes(rule_catalog)
    responses_bytes = _jsonl(responses_tuple)

    # Re-derive the selection contract so its digest can be bound into the
    # manifest and receipt. This re-derivation is deterministic and does not
    # execute semantics.
    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/2",
        source_commit=_PREDECESSOR_SOURCE_COMMIT,
    )
    selection_contract_digest = selection.contract_digest

    scenario_ids = tuple(sorted({response.scenario_id for response in responses_tuple}))
    record_ids_tuple = tuple(record_ids)
    manifest = {
        "schema_version": _MANIFEST_SCHEMA_VERSION,
        "release": _RELEASE,
        "source_commit": source_commit,
        "label_authority": "conventional_synthetic",
        "selection_contract_digest": selection_contract_digest,
        "scenario_ids": list(scenario_ids),
        "scenario_count": len(scenario_ids),
        "record_ids": list(record_ids_tuple),
        "record_count": len(record_ids_tuple),
        "distribution": dict(sorted(_EXPECTED_DISTRIBUTION.items())),
        "case_kind_counts": _count_by_key(responses_tuple, "case_kind"),
        "event_type_counts": _count_by_key(responses_tuple, "event_type"),
        "rule_id_counts": _count_by_key(responses_tuple, "rule_id"),
        "constituent_artifact_digests": {
            "conventional_rule_catalog.json": hashlib.sha256(rule_catalog_bytes).hexdigest(),
            "conventional_control_responses.jsonl": (hashlib.sha256(responses_bytes).hexdigest()),
        },
        "predecessor_source_commit": _PREDECESSOR_SOURCE_COMMIT,
        "predecessor_a0b2_receipt_sha256": a0b2_receipt.receipt_sha256,
        "predecessor_a0b2_source_commit": a0b2_receipt.source_commit,
        "predecessor_response_abi_digest": abi.abi_digest,
        "predecessor_tokenizer_codebook_digest": codebook.codebook_digest,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    manifest_bytes = canonical_json_bytes(manifest)

    implementation_sha256 = compute_compiler_implementation_sha256()
    receipt = _build_receipt(
        source_commit=source_commit,
        a0b2_receipt=a0b2_receipt,
        abi=abi,
        codebook=codebook,
        selection_contract_digest=selection_contract_digest,
        rule_catalog=rule_catalog,
        responses=responses_tuple,
        manifest=manifest,
        implementation_sha256=implementation_sha256,
    )
    receipt_bytes = canonical_json_bytes(receipt)

    # Distinctness checks: every artifact digest must be mutually distinct.
    artifact_digests = {
        "conventional_rule_catalog.json": hashlib.sha256(rule_catalog_bytes).hexdigest(),
        "conventional_control_responses.jsonl": hashlib.sha256(responses_bytes).hexdigest(),
        "conventional_control_manifest.json": hashlib.sha256(manifest_bytes).hexdigest(),
        "a1_receipt.json": hashlib.sha256(receipt_bytes).hexdigest(),
    }
    if len(set(artifact_digests.values())) != 4:
        raise E1ConventionalGeneratorError(
            "the four conventional-control artifact digests must be mutually distinct"
        )

    return {
        "conventional_rule_catalog.json": rule_catalog_bytes,
        "conventional_control_responses.jsonl": responses_bytes,
        "conventional_control_manifest.json": manifest_bytes,
        "a1_receipt.json": receipt_bytes,
    }


# ---------------------------------------------------------------------------
# Public re-exports.
# ---------------------------------------------------------------------------

SCHEMA_VERSION = _RESPONSE_SCHEMA_VERSION
RELEASE = _RELEASE
CLAIM_BOUNDARY = _CLAIM_BOUNDARY
EXPECTED_A0B2_RECEIPT_SHA256 = _EXPECTED_A0B2_RECEIPT_SHA256
PREDECESSOR_SOURCE_COMMIT = _PREDECESSOR_SOURCE_COMMIT
EXPECTED_SCENARIO_COUNT = _EXPECTED_SCENARIO_COUNT
EXPECTED_RECORD_COUNT = _EXPECTED_RECORD_COUNT
EXPECTED_OBSERVATION_COUNT = _EXPECTED_OBSERVATION_COUNT
EXPECTED_TRANSITION_COUNT = _EXPECTED_TRANSITION_COUNT
EXPECTED_DISTRIBUTION = _EXPECTED_DISTRIBUTION
ALLOWED_FEATURES = _ALLOWED_FEATURES
RULES = _RULES
FAIL_CLOSED_REASON = _FAIL_CLOSED_REASON


__all__ = [
    "ALLOWED_FEATURES",
    "CLAIM_BOUNDARY",
    "ConventionalControlResponseRecord",
    "ConventionalLabel",
    "ConventionalRule",
    "EXPECTED_A0B2_RECEIPT_SHA256",
    "EXPECTED_DISTRIBUTION",
    "EXPECTED_OBSERVATION_COUNT",
    "EXPECTED_RECORD_COUNT",
    "EXPECTED_SCENARIO_COUNT",
    "EXPECTED_TRANSITION_COUNT",
    "E1ConventionalGeneratorError",
    "FAIL_CLOSED_REASON",
    "PREDECESSOR_SOURCE_COMMIT",
    "RELEASE",
    "RULES",
    "SCHEMA_VERSION",
    "AuthenticatedA0b2Receipt",
    "AuthenticatedABI",
    "AuthenticatedCodebook",
    "AuthenticatedCodebookEntry",
    "ExtractedTrainingView",
    "authenticate_a0b2_receipt",
    "authenticate_response_abi",
    "authenticate_tokenizer_codebook",
    "build_rule_catalog",
    "compile_conventional_generator",
    "compute_compiler_implementation_sha256",
    "label_conventional_control",
]
