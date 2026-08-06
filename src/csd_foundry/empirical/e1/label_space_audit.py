"""Deterministic E1 label-space and treatment-adequacy audit.

This module is a pure repository-side semantic audit. It consumes an already
compiled :class:`E1FoundryArtifactBundle`, enumerates atomic executable-
consequence dimensions per record, evaluates candidate response projections
against mechanical non-degeneracy and population-adequacy rules, and emits a
canonical audit artifact.

It performs no tokenizer loading, no metric scoring, no control generation,
no GPU activity, and no clean-case policy decision. A negative result
(no viable projection, or a viable projection that the current development
population cannot evaluate) is a valid, useful outcome.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from csd_foundry.empirical.e1.execution_splits import E1Split
from csd_foundry.empirical.e1.experiment_contract import E1ExperimentContract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    E1FoundryArtifactBundle,
    load_artifact_records,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    load_json_text,
)

_SCHEMA_VERSION = "e1-label-space-audit/1"
_ATOM_DERIVATION_VERSION = "e1-audit-atom/1"
_UNDEFINED = "__undefined__"
_CLAIM_BOUNDARY = (
    "This audit mechanically inventories the compiled E1 label space, enumerates "
    "atomic executable-consequence dimensions, and evaluates candidate response "
    "projections against non-degeneracy and population-adequacy rules. It performs "
    "no tokenizer loading, no metric scoring, no control generation, and no "
    "clean-case policy decision. It does not establish that any projection is "
    "pedagogically effective or that the current corpus can support the E1 contract."
)

# Atomic dimensions whose value is directly present in the canonical task input
# shown to the model. These are mechanically copy-solvable from the prompt.
_DIRECT_PROMPT_ATOMS: frozenset[str] = frozenset({"case_type", "event_type"})

# Atomic dimensions whose value is derived from the executable oracle output
# (label / trace / after-state) rather than from public prompt bytes.
_EXECUTABLE_ATOMS: frozenset[str] = frozenset(
    {
        "acceptance",
        "any_evidence_invalidated",
        "invalidated_evidence_count",
        "any_basis_removed",
        "removed_basis_count",
        "any_basis_survives",
        "surviving_basis_count",
        "source_state_changed",
        "resulting_source_state",
        "assurance_changed",
        "resulting_assurance",
        "obligation_changed",
        "resulting_obligation",
        "retirement_involved",
        "reassessment_involved",
    }
)

# All atoms audited per record. Order is the canonical emission order.
_ALL_ATOMS: tuple[str, ...] = (
    "case_type",
    "acceptance",
    "event_type",
    "any_evidence_invalidated",
    "invalidated_evidence_count",
    "any_basis_removed",
    "removed_basis_count",
    "any_basis_survives",
    "surviving_basis_count",
    "source_state_changed",
    "resulting_source_state",
    "assurance_changed",
    "resulting_assurance",
    "obligation_changed",
    "resulting_obligation",
    "retirement_involved",
    "reassessment_involved",
)

# Semantic (non-degeneracy) rejection reasons.
REJECTION_CONSTANT = "constant"
REJECTION_NO_APPLICABLE_TRAINING_RECORDS = "no_applicable_training_records"
REJECTION_DIRECT_PROMPT_EXPOSURE = "direct_prompt_exposure"
REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES = "model_visible_treatment_collapses"

# Population-adequacy failures (separate from semantic rejection).
POP_FAIL_SINGLE_DEVELOPMENT_OUTCOME_CLASS = "single_development_outcome_class"
POP_FAIL_INCOMPLETE_DEVELOPMENT_FAMILY_COVERAGE = "incomplete_development_family_coverage"

# Corpus-level experiment blockers.
BLOCKER_NO_INVALID_TRANSITION_CONTRAST = "no_invalid_transition_contrast"
BLOCKER_INSUFFICIENT_DEVELOPMENT_TRANSITION_COVERAGE = (
    "insufficient_development_transition_coverage"
)
BLOCKER_RIGHT_ANSWER_WRONG_BASIS_UNASSESSABLE = "right_answer_wrong_basis_unassessable"
BLOCKER_MISSING_RIGHT_ANSWER_WRONG_BASIS_CONTRAST = "missing_right_answer_wrong_basis_contrast"


@dataclass(frozen=True, slots=True)
class ConsequenceAtom:
    """One atomic consequence value derived for one record."""

    name: str
    derivation_version: str
    input_paths: tuple[str, ...]
    derivation_description: str
    derived_value: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "derivation_version": self.derivation_version,
            "input_paths": list(self.input_paths),
            "derivation_description": self.derivation_description,
            "derived_value": self.derived_value,
        }


@dataclass(frozen=True, slots=True)
class DimensionSummary:
    """Exact-rational distribution of one atom across the audited records."""

    name: str
    derivation_version: str
    input_paths: tuple[str, ...]
    derivation_description: str
    direct_prompt_exposure: bool
    direct_prompt_paths: tuple[str, ...]
    derivation_requires_executable_output: bool
    train_value_counts: dict[str, int]
    development_value_counts: dict[str, int]
    train_defined_count: int
    train_undefined_count: int
    development_defined_count: int
    development_undefined_count: int
    value_counts: dict[str, int]
    defined_count: int
    undefined_count: int
    total_count: int
    distinct_value_count: int
    majority_value: str | None
    majority_count: int
    majority_fraction_numerator: int
    majority_fraction_denominator: int
    constant: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "derivation_version": self.derivation_version,
            "input_paths": list(self.input_paths),
            "derivation_description": self.derivation_description,
            "direct_prompt_exposure": self.direct_prompt_exposure,
            "direct_prompt_paths": list(self.direct_prompt_paths),
            "derivation_requires_executable_output": (self.derivation_requires_executable_output),
            "train_value_counts": dict(sorted(self.train_value_counts.items())),
            "development_value_counts": dict(sorted(self.development_value_counts.items())),
            "train_defined_count": self.train_defined_count,
            "train_undefined_count": self.train_undefined_count,
            "development_defined_count": self.development_defined_count,
            "development_undefined_count": self.development_undefined_count,
            "value_counts": dict(sorted(self.value_counts.items())),
            "defined_count": self.defined_count,
            "undefined_count": self.undefined_count,
            "total_count": self.total_count,
            "distinct_value_count": self.distinct_value_count,
            "majority_value": self.majority_value,
            "majority_count": self.majority_count,
            "majority_fraction_numerator": self.majority_fraction_numerator,
            "majority_fraction_denominator": self.majority_fraction_denominator,
            "constant": self.constant,
        }


@dataclass(frozen=True, slots=True)
class CandidateProjection:
    """One audited response projection with semantic and population verdicts."""

    name: str
    description: str
    scored_atoms: tuple[str, ...]
    projection_function_description: str
    train_value_counts: dict[str, int]
    development_value_counts: dict[str, int]
    applicable_train_record_count: int
    applicable_development_record_count: int
    covered_development_family_count: int
    uncovered_development_record_ids: tuple[str, ...]
    uncovered_development_family_digests: tuple[str, ...]
    prompt_only_reconstruction_possible: bool
    prompt_only_reconstruction_witness: str | None
    semantic_rejection_reasons: tuple[str, ...]
    semantic_candidate: bool
    population_adequacy_failures: tuple[str, ...]
    primary_population_eligible: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "scored_atoms": list(self.scored_atoms),
            "projection_function_description": self.projection_function_description,
            "train_value_counts": dict(sorted(self.train_value_counts.items())),
            "development_value_counts": dict(sorted(self.development_value_counts.items())),
            "applicable_train_record_count": self.applicable_train_record_count,
            "applicable_development_record_count": self.applicable_development_record_count,
            "covered_development_family_count": self.covered_development_family_count,
            "uncovered_development_record_ids": list(self.uncovered_development_record_ids),
            "uncovered_development_family_digests": list(self.uncovered_development_family_digests),
            "prompt_only_reconstruction_possible": self.prompt_only_reconstruction_possible,
            "prompt_only_reconstruction_witness": self.prompt_only_reconstruction_witness,
            "semantic_rejection_reasons": list(self.semantic_rejection_reasons),
            "semantic_candidate": self.semantic_candidate,
            "population_adequacy_failures": list(self.population_adequacy_failures),
            "primary_population_eligible": self.primary_population_eligible,
        }


@dataclass(frozen=True, slots=True)
class CleanCaseEvidence:
    """Exact per-record features for a future clean-case policy (A0b)."""

    record_id: str
    family_digest: str
    case_type: str
    event_type: str | None
    any_evidence_invalidated: bool | None
    any_basis_removed: bool | None
    source_state_changed: bool | None
    assurance_changed: bool | None
    obligation_changed: bool | None
    retirement_involved: bool | None
    reassessment_involved: bool | None

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "family_digest": self.family_digest,
            "case_type": self.case_type,
            "event_type": self.event_type,
            "any_evidence_invalidated": self.any_evidence_invalidated,
            "any_basis_removed": self.any_basis_removed,
            "source_state_changed": self.source_state_changed,
            "assurance_changed": self.assurance_changed,
            "obligation_changed": self.obligation_changed,
            "retirement_involved": self.retirement_involved,
            "reassessment_involved": self.reassessment_involved,
        }


@dataclass(frozen=True, slots=True)
class ContrastFinding:
    """One mechanically-defined contrast over the audited records."""

    name: str
    predicate: str
    assessable: bool
    present: bool | None
    unassessable_reason: str | None
    train_record_ids: tuple[str, ...]
    development_record_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "predicate": self.predicate,
            "assessable": self.assessable,
            "present": self.present,
            "unassessable_reason": self.unassessable_reason,
            "train_record_ids": list(self.train_record_ids),
            "development_record_ids": list(self.development_record_ids),
        }


@dataclass(frozen=True, slots=True)
class LabelSpaceAudit:
    """The complete deterministic audit of one compiled Foundry bundle."""

    schema_version: str
    release: str
    source_commit: str
    selection_contract_digest: str
    foundry_bundle_manifest_sha256: str
    foundry_train_sha256: str
    development_evaluation_sha256: str
    task_format_digest: str
    training_record_count: int
    development_record_count: int
    population: dict[str, object]
    dimensions: tuple[DimensionSummary, ...]
    candidate_projections: tuple[CandidateProjection, ...]
    clean_case_evidence: tuple[CleanCaseEvidence, ...]
    contrast_inventory: tuple[ContrastFinding, ...]
    experiment_blockers: tuple[str, ...]
    clean_case_policy_status: str
    semantic_projection_candidate_present: bool
    primary_population_supported: bool
    full_e1_population_support: bool | None
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "release": self.release,
            "source_commit": self.source_commit,
            "selection_contract_digest": self.selection_contract_digest,
            "foundry_bundle_manifest_sha256": self.foundry_bundle_manifest_sha256,
            "foundry_train_sha256": self.foundry_train_sha256,
            "development_evaluation_sha256": self.development_evaluation_sha256,
            "task_format_digest": self.task_format_digest,
            "training_record_count": self.training_record_count,
            "development_record_count": self.development_record_count,
            "population": self.population,
            "dimensions": [item.to_dict() for item in self.dimensions],
            "candidate_projections": [item.to_dict() for item in self.candidate_projections],
            "clean_case_evidence": [item.to_dict() for item in self.clean_case_evidence],
            "contrast_inventory": [item.to_dict() for item in self.contrast_inventory],
            "experiment_blockers": list(self.experiment_blockers),
            "clean_case_policy_status": self.clean_case_policy_status,
            "semantic_projection_candidate_present": (self.semantic_projection_candidate_present),
            "primary_population_supported": self.primary_population_supported,
            "full_e1_population_support": self.full_e1_population_support,
            "claim_boundary": self.claim_boundary,
        }

    @property
    def audit_digest(self) -> str:
        return canonical_sha256(self.to_dict())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sorted_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _counter_to_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items()))


def _reduce_fraction(numerator: int, denominator: int) -> tuple[int, int]:
    if denominator <= 0:
        return 0, 0
    from math import gcd

    divisor = gcd(numerator, denominator)
    if divisor == 0:
        return 0, denominator
    return numerator // divisor, denominator // divisor


@dataclass(frozen=True, slots=True)
class _CompiledRecord:
    """Internal per-record projection of the audited fields."""

    record_id: str
    scenario_id: str
    family_digest: str
    split: str
    case_type: str
    task_input: dict[str, object]
    reference_label: dict[str, object]
    atoms: dict[str, str | None]


def _trace_dict(reference_label: dict[str, object]) -> dict[str, object] | None:
    raw = reference_label.get("trace")
    if isinstance(raw, dict):
        return raw
    return None


def _coerce_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _atom_input_paths(name: str) -> tuple[str, ...]:
    if name in _DIRECT_PROMPT_ATOMS:
        return (f"prompt_messages[1].content.{name}",)
    if name == "acceptance":
        return ("reference_label.acceptance",)
    if name == "obligation_changed":
        return (
            "prompt_messages[1].content.before.obligation",
            "reference_label.after.obligation",
        )
    if name == "resulting_obligation":
        return ("reference_label.after.obligation",)
    return (f"reference_label.trace.{name}",)


def _atom_description(name: str) -> str:
    descriptions = {
        "acceptance": "reference_label.acceptance; constant 'accepted' across the selected "
        "population (rejected_transition is excluded)",
        "case_type": "case_type copied from task_input.case_type (directly prompt-exposed)",
        "event_type": "event_type copied from task_input.event_type for transition records "
        "(directly prompt-exposed); None for observation records",
        "any_evidence_invalidated": "len(trace.invalidated_evidence) > 0",
        "invalidated_evidence_count": "len(trace.invalidated_evidence)",
        "any_basis_removed": "len(trace.removed_bases) > 0",
        "removed_basis_count": "len(trace.removed_bases)",
        "any_basis_survives": "len(trace.surviving_bases) > 0",
        "surviving_basis_count": "len(trace.surviving_bases)",
        "source_state_changed": "trace.previous_source_state != trace.resulting_source_state",
        "resulting_source_state": "trace.resulting_source_state",
        "assurance_changed": "trace.previous_assurance != trace.resulting_assurance",
        "resulting_assurance": "trace.resulting_assurance",
        "obligation_changed": "derived from task_input.before.obligation vs "
        "reference_label.after.obligation; not present in TransitionTrace",
        "resulting_obligation": "reference_label.after.obligation",
        "retirement_involved": "(event_type == 'RetireControl') or (obligation_changed is True) "
        "for transition records; None for observation records",
        "reassessment_involved": "event_type == 'Reassess' for transition records; "
        "None for observation records",
    }
    return descriptions[name]


def _derive_atoms(record: dict[str, object]) -> dict[str, str | None]:
    """Derive every atomic consequence value for one compiled record."""

    task_input_raw = record.get("task_input")
    reference_label = record.get("reference_label")
    case_type_raw = record.get("case_type")
    case_type = _coerce_str(case_type_raw)
    if not isinstance(task_input_raw, dict) or not isinstance(reference_label, dict):
        raise LabelSpaceAuditError("record missing task_input or reference_label")

    atoms: dict[str, str | None] = {}
    atoms["case_type"] = case_type
    # acceptance is a reference-label field (constant 'accepted' across the
    # selected population). Populated for every record so acceptance-based
    # projections can evaluate applicability.
    atoms["acceptance"] = _coerce_str(reference_label.get("acceptance"))

    is_transition = case_type == "transition"

    # event_type and the two involvement atoms use an explicit transition-only
    # branch so we never evaluate string equality against None.
    if is_transition:
        event_type = _coerce_str(task_input_raw.get("event_type"))
        atoms["event_type"] = event_type
    else:
        atoms["event_type"] = None

    trace = _trace_dict(reference_label)
    if is_transition and trace is not None:
        invalidated = trace.get("invalidated_evidence")
        removed = trace.get("removed_bases")
        surviving = trace.get("surviving_bases")
        prev_source = trace.get("previous_source_state")
        result_source = trace.get("resulting_source_state")
        prev_assurance = trace.get("previous_assurance")
        result_assurance = trace.get("resulting_assurance")

        invalidated_count = len(invalidated) if isinstance(invalidated, list) else None
        removed_count = len(removed) if isinstance(removed, list) else None
        surviving_count = len(surviving) if isinstance(surviving, list) else None

        atoms["any_evidence_invalidated"] = (
            "true" if invalidated_count and invalidated_count > 0 else "false"
        )
        atoms["invalidated_evidence_count"] = (
            str(invalidated_count) if invalidated_count is not None else None
        )
        atoms["any_basis_removed"] = "true" if removed_count and removed_count > 0 else "false"
        atoms["removed_basis_count"] = str(removed_count) if removed_count is not None else None
        atoms["any_basis_survives"] = "true" if surviving_count and surviving_count > 0 else "false"
        atoms["surviving_basis_count"] = (
            str(surviving_count) if surviving_count is not None else None
        )
        atoms["source_state_changed"] = "true" if prev_source != result_source else "false"
        atoms["resulting_source_state"] = _coerce_str(result_source)
        atoms["assurance_changed"] = "true" if prev_assurance != result_assurance else "false"
        atoms["resulting_assurance"] = _coerce_str(result_assurance)
    else:
        for name in (
            "any_evidence_invalidated",
            "invalidated_evidence_count",
            "any_basis_removed",
            "removed_basis_count",
            "any_basis_survives",
            "surviving_basis_count",
            "source_state_changed",
            "resulting_source_state",
            "assurance_changed",
            "resulting_assurance",
        ):
            atoms[name] = None

    # obligation_changed and resulting_obligation are derived from
    # before/after ControlState projections (obligation is NOT in the trace).
    if is_transition:
        before_raw = task_input_raw.get("before")
        after_raw = reference_label.get("after")
        if isinstance(before_raw, dict) and isinstance(after_raw, dict):
            before_obligation = before_raw.get("obligation")
            after_obligation = after_raw.get("obligation")
            obligation_changed = before_obligation != after_obligation
            atoms["obligation_changed"] = "true" if obligation_changed else "false"
            atoms["resulting_obligation"] = _coerce_str(after_obligation)
        else:
            atoms["obligation_changed"] = None
            atoms["resulting_obligation"] = None
    else:
        atoms["obligation_changed"] = None
        atoms["resulting_obligation"] = None

    # retirement_involved / reassessment_involved: explicit transition-only branch.
    if is_transition:
        event_type_value = atoms["event_type"]
        obligation_changed_value = atoms["obligation_changed"]
        retirement = event_type_value == "RetireControl" or obligation_changed_value == "true"
        atoms["retirement_involved"] = "true" if retirement else "false"
        atoms["reassessment_involved"] = "true" if event_type_value == "Reassess" else "false"
    else:
        atoms["retirement_involved"] = None
        atoms["reassessment_involved"] = None

    return atoms


def _decode_task_input(record: dict[str, object]) -> dict[str, object]:
    """Recover the canonical task_input dict from the prompt user message."""

    messages = record.get("prompt_messages")
    if not isinstance(messages, list) or len(messages) < 2:
        raise LabelSpaceAuditError("record missing prompt_messages")
    user_message = messages[1]
    if not isinstance(user_message, dict):
        raise LabelSpaceAuditError("user prompt message must be an object")
    content = user_message.get("content")
    if not isinstance(content, str):
        raise LabelSpaceAuditError("user prompt content must be a string")
    decoded: dict[str, object] = load_json_text(content)  # type: ignore[assignment]
    if not isinstance(decoded, dict):
        raise LabelSpaceAuditError("user prompt content must decode to an object")
    return decoded


class LabelSpaceAuditError(ValueError):
    """Raised when the E1 label-space audit cannot be completed deterministically."""


def _compile_record(record: dict[str, object]) -> _CompiledRecord:
    record_id = record.get("record_id")
    scenario_id = record.get("scenario_id")
    family_digest = record.get("family_digest")
    split = record.get("split")
    case_type = record.get("case_type")
    reference_label = record.get("reference_label")
    if not isinstance(record_id, str):
        raise LabelSpaceAuditError("record_id must be a string")
    if not isinstance(scenario_id, str):
        raise LabelSpaceAuditError("scenario_id must be a string")
    if not isinstance(family_digest, str):
        raise LabelSpaceAuditError("family_digest must be a string")
    if not isinstance(split, str):
        raise LabelSpaceAuditError("split must be a string")
    if not isinstance(case_type, str):
        raise LabelSpaceAuditError("case_type must be a string")
    if not isinstance(reference_label, dict):
        raise LabelSpaceAuditError("reference_label must be an object")

    task_input = _decode_task_input(record)
    # Attach the decoded task_input so atom derivation can read it; keep the
    # original record dict shape intact for label-digest accounting.
    augmented = dict(record)
    augmented["task_input"] = task_input
    atoms = _derive_atoms(augmented)
    return _CompiledRecord(
        record_id=record_id,
        scenario_id=scenario_id,
        family_digest=family_digest,
        split=split,
        case_type=case_type,
        task_input=task_input,
        reference_label=reference_label,
        atoms=atoms,
    )


def _value_to_atom_string(value: str | None) -> str | None:
    return value


def _summarize_dimension(
    name: str,
    records: tuple[_CompiledRecord, ...],
) -> DimensionSummary:
    train_values: list[str | None] = []
    dev_values: list[str | None] = []
    for rec in records:
        value = rec.atoms.get(name)
        if rec.split == E1Split.TRAIN.value:
            train_values.append(value)
        elif rec.split == E1Split.DEVELOPMENT.value:
            dev_values.append(value)

    train_defined = [v for v in train_values if v is not None]
    dev_defined = [v for v in dev_values if v is not None]
    train_counter = Counter(train_defined)
    dev_counter = Counter(dev_defined)
    combined_counter = Counter(train_defined) + Counter(dev_defined)

    train_defined_count = len(train_defined)
    train_undefined_count = len(train_values) - train_defined_count
    dev_defined_count = len(dev_defined)
    dev_undefined_count = len(dev_values) - dev_defined_count
    defined_count = len(train_defined) + len(dev_defined)
    undefined_count = train_undefined_count + dev_undefined_count
    total_count = len(records)
    distinct_value_count = len(combined_counter)

    if combined_counter:
        majority_value, majority_count = sorted(
            combined_counter.items(), key=lambda kv: (-kv[1], kv[0])
        )[0]
        num, den = _reduce_fraction(majority_count, defined_count)
    else:
        majority_value = None
        majority_count = 0
        num, den = 0, 0

    constant = defined_count > 0 and distinct_value_count == 1
    direct_prompt = name in _DIRECT_PROMPT_ATOMS
    requires_executable = name in _EXECUTABLE_ATOMS

    return DimensionSummary(
        name=name,
        derivation_version=_ATOM_DERIVATION_VERSION,
        input_paths=_atom_input_paths(name),
        derivation_description=_atom_description(name),
        direct_prompt_exposure=direct_prompt,
        direct_prompt_paths=_atom_input_paths(name) if direct_prompt else (),
        derivation_requires_executable_output=requires_executable,
        train_value_counts=_counter_to_dict(train_counter),
        development_value_counts=_counter_to_dict(dev_counter),
        train_defined_count=train_defined_count,
        train_undefined_count=train_undefined_count,
        development_defined_count=dev_defined_count,
        development_undefined_count=dev_undefined_count,
        value_counts=_counter_to_dict(combined_counter),
        defined_count=defined_count,
        undefined_count=undefined_count,
        total_count=total_count,
        distinct_value_count=distinct_value_count,
        majority_value=majority_value,
        majority_count=majority_count,
        majority_fraction_numerator=num,
        majority_fraction_denominator=den,
        constant=constant,
    )


# ---------------------------------------------------------------------------
# Candidate projection machinery
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ProjectionSpec:
    """Declarative description of one candidate projection."""

    name: str
    description: str
    scored_atoms: tuple[str, ...]
    projection_function_description: str
    prompt_only_reconstruction_possible: bool
    prompt_only_reconstruction_witness: str | None


def _projection_value(rec: _CompiledRecord, spec: _ProjectionSpec) -> str | None:
    """Return the canonical projection value for one record, or None if undefined."""

    parts: list[str] = []
    for atom_name in spec.scored_atoms:
        value = rec.atoms.get(atom_name)
        if value is None:
            return None
        parts.append(f"{atom_name}={value}")
    if not parts:
        return None
    return "|".join(parts)


def _projection_applicability_filter(spec: _ProjectionSpec, rec: _CompiledRecord) -> bool:
    """A record is applicable to a projection iff all scored atoms are defined."""

    return all(rec.atoms.get(name) is not None for name in spec.scored_atoms)


_PROJECTION_SPECS: tuple[_ProjectionSpec, ...] = (
    _ProjectionSpec(
        name="acceptance",
        description="Reference label acceptance field.",
        scored_atoms=("acceptance",),
        projection_function_description="acceptance := constant 'accepted' (all selected "
        "records carry acceptance='accepted'; rejected_transition is excluded)",
        prompt_only_reconstruction_possible=True,
        prompt_only_reconstruction_witness='acceptance := constant "accepted"',
    ),
    _ProjectionSpec(
        name="case_type",
        description="Reference label case_type field.",
        scored_atoms=("case_type",),
        projection_function_description="case_type := task_input.case_type",
        prompt_only_reconstruction_possible=True,
        prompt_only_reconstruction_witness="case_type := task_input.case_type",
    ),
    _ProjectionSpec(
        name="case_type_acceptance",
        description="Composite (case_type, acceptance).",
        scored_atoms=("case_type", "acceptance"),
        projection_function_description="case_type := task_input.case_type; "
        'acceptance := constant "accepted"',
        prompt_only_reconstruction_possible=True,
        prompt_only_reconstruction_witness="case_type := task_input.case_type; "
        'acceptance := constant "accepted"',
    ),
    _ProjectionSpec(
        name="any_evidence_invalidated",
        description="Whether any evidence was invalidated by the transition.",
        scored_atoms=("any_evidence_invalidated",),
        projection_function_description="any_evidence_invalidated := "
        "len(trace.invalidated_evidence) > 0",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
    _ProjectionSpec(
        name="any_basis_removed",
        description="Whether any basis was removed by the transition.",
        scored_atoms=("any_basis_removed",),
        projection_function_description="any_basis_removed := len(trace.removed_bases) > 0",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
    _ProjectionSpec(
        name="basis_disposition",
        description="Composite basis disposition over removal and survival.",
        scored_atoms=("any_basis_removed", "any_basis_survives"),
        projection_function_description="basis_disposition := "
        "(any_basis_removed, any_basis_survives) composite",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
    _ProjectionSpec(
        name="assurance_changed",
        description="Whether assurance transitioned.",
        scored_atoms=("assurance_changed",),
        projection_function_description="assurance_changed := "
        "trace.previous_assurance != trace.resulting_assurance",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
    _ProjectionSpec(
        name="state_change",
        description="Composite state-change over source, assurance, obligation.",
        scored_atoms=(
            "source_state_changed",
            "assurance_changed",
            "obligation_changed",
        ),
        projection_function_description="state_change := (source_state_changed or "
        "assurance_changed or obligation_changed) composite",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
    _ProjectionSpec(
        name="obligation_changed",
        description="Whether obligation transitioned (derived from before/after).",
        scored_atoms=("obligation_changed",),
        projection_function_description="obligation_changed := "
        "before.obligation != after.obligation",
        prompt_only_reconstruction_possible=False,
        prompt_only_reconstruction_witness=None,
    ),
)


def _evaluate_projection(
    spec: _ProjectionSpec,
    records: tuple[_CompiledRecord, ...],
    development_family_digests: frozenset[str],
    total_development_family_count: int,
) -> CandidateProjection:
    train_records = [r for r in records if r.split == E1Split.TRAIN.value]
    dev_records = [r for r in records if r.split == E1Split.DEVELOPMENT.value]
    applicable_train = [r for r in train_records if _projection_applicability_filter(spec, r)]
    applicable_dev = [r for r in dev_records if _projection_applicability_filter(spec, r)]

    train_values = [v for v in (_projection_value(r, spec) for r in applicable_train) if v]
    dev_values = [v for v in (_projection_value(r, spec) for r in applicable_dev) if v]
    train_counter = Counter(train_values)
    dev_counter = Counter(dev_values)

    train_value_counts = _counter_to_dict(train_counter)
    dev_value_counts = _counter_to_dict(dev_counter)

    applicable_train_count = len(applicable_train)
    applicable_dev_count = len(applicable_dev)

    covered_families: set[str] = set()
    uncovered_dev_record_ids: list[str] = []
    uncovered_family_digests: set[str] = set()
    for r in dev_records:
        if _projection_applicability_filter(spec, r):
            covered_families.add(r.family_digest)
        else:
            uncovered_dev_record_ids.append(r.record_id)
            uncovered_family_digests.add(r.family_digest)
    # Development families that contain at least one applicable record cover it.
    # Families with zero applicable records are uncovered.
    all_dev_families = set(development_family_digests)
    uncovered_families_total = sorted(all_dev_families - covered_families)
    covered_count = total_development_family_count - len(uncovered_families_total)

    # ---- semantic rejection reasons (training-split non-degeneracy) ----
    semantic_rejection_buf: list[str] = []
    if applicable_train_count == 0:
        semantic_rejection_buf.append(REJECTION_NO_APPLICABLE_TRAINING_RECORDS)
    elif len(train_value_counts) == 1:
        semantic_rejection_buf.append(REJECTION_CONSTANT)
    if spec.scored_atoms and any(name in _DIRECT_PROMPT_ATOMS for name in spec.scored_atoms):
        semantic_rejection_buf.append(REJECTION_DIRECT_PROMPT_EXPOSURE)
    if spec.prompt_only_reconstruction_possible:
        semantic_rejection_buf.append(REJECTION_MODEL_VISIBLE_TREATMENT_COLLAPSES)
    semantic_rejections = _sorted_unique(semantic_rejection_buf)
    semantic_candidate = not semantic_rejections

    # ---- population-adequacy failures (separate from semantic) ----
    pop_failure_buf: list[str] = []
    dev_defined = len(dev_values)
    dev_distinct = len(dev_value_counts)
    if dev_defined > 0 and dev_distinct == 1:
        pop_failure_buf.append(POP_FAIL_SINGLE_DEVELOPMENT_OUTCOME_CLASS)
    if covered_count < total_development_family_count:
        pop_failure_buf.append(POP_FAIL_INCOMPLETE_DEVELOPMENT_FAMILY_COVERAGE)
    pop_failures = _sorted_unique(pop_failure_buf)
    primary_eligible = semantic_candidate and not pop_failures

    return CandidateProjection(
        name=spec.name,
        description=spec.description,
        scored_atoms=spec.scored_atoms,
        projection_function_description=spec.projection_function_description,
        train_value_counts=train_value_counts,
        development_value_counts=dev_value_counts,
        applicable_train_record_count=applicable_train_count,
        applicable_development_record_count=applicable_dev_count,
        covered_development_family_count=covered_count,
        uncovered_development_record_ids=tuple(sorted(uncovered_dev_record_ids)),
        uncovered_development_family_digests=tuple(uncovered_families_total),
        prompt_only_reconstruction_possible=spec.prompt_only_reconstruction_possible,
        prompt_only_reconstruction_witness=spec.prompt_only_reconstruction_witness,
        semantic_rejection_reasons=tuple(semantic_rejections),
        semantic_candidate=semantic_candidate,
        population_adequacy_failures=tuple(pop_failures),
        primary_population_eligible=primary_eligible,
    )


# ---------------------------------------------------------------------------
# Contrasts and blockers
# ---------------------------------------------------------------------------


def _records_matching(
    records: tuple[_CompiledRecord, ...],
    predicate_name: str,
) -> tuple[list[str], list[str]]:
    train_ids: list[str] = []
    dev_ids: list[str] = []

    def matches(rec: _CompiledRecord) -> bool:
        if predicate_name == "basis_loss":
            return rec.atoms.get("any_basis_removed") == "true"
        if predicate_name == "basis_survival":
            return rec.atoms.get("any_basis_survives") == "true"
        if predicate_name == "state_change":
            return (
                rec.atoms.get("source_state_changed") == "true"
                or rec.atoms.get("assurance_changed") == "true"
                or rec.atoms.get("obligation_changed") == "true"
            )
        if predicate_name == "invalid_transition":
            return rec.case_type == "rejected_transition"
        return False

    for rec in records:
        if matches(rec):
            if rec.split == E1Split.TRAIN.value:
                train_ids.append(rec.record_id)
            elif rec.split == E1Split.DEVELOPMENT.value:
                dev_ids.append(rec.record_id)
    return train_ids, dev_ids


_CONTRAST_PREDICATES: tuple[tuple[str, str], ...] = (
    ("basis_loss", "any_basis_removed == True"),
    ("basis_survival", "any_basis_survives == True"),
    (
        "state_change",
        "source_state_changed or assurance_changed or obligation_changed",
    ),
    ("invalid_transition", "case_type == 'rejected_transition'"),
)


def _build_contrasts(
    records: tuple[_CompiledRecord, ...],
) -> tuple[ContrastFinding, ...]:
    findings: list[ContrastFinding] = []
    for name, predicate in _CONTRAST_PREDICATES:
        train_ids, dev_ids = _records_matching(records, name)
        present = bool(train_ids or dev_ids)
        findings.append(
            ContrastFinding(
                name=name,
                predicate=predicate,
                assessable=True,
                present=present,
                unassessable_reason=None,
                train_record_ids=tuple(sorted(train_ids)),
                development_record_ids=tuple(sorted(dev_ids)),
            )
        )
    # right-answer/wrong-basis is not mechanically identifiable from the
    # canonical record bytes; it remains unassessable in this audit.
    findings.append(
        ContrastFinding(
            name="right_answer_wrong_basis",
            predicate="not mechanically expressible from audited record bytes",
            assessable=False,
            present=None,
            unassessable_reason=(
                "selected canonical records contain no frozen right-answer/wrong-basis annotation"
            ),
            train_record_ids=(),
            development_record_ids=(),
        )
    )
    return tuple(findings)


def _derive_blockers(
    contrasts: tuple[ContrastFinding, ...],
    records: tuple[_CompiledRecord, ...],
    development_family_digests: frozenset[str],
) -> tuple[str, ...]:
    blockers: set[str] = set()

    rejected_total = sum(1 for r in records if r.case_type == "rejected_transition")
    if rejected_total == 0:
        blockers.add(BLOCKER_NO_INVALID_TRANSITION_CONTRAST)

    # Family-level development transition coverage.
    dev_families_with_transition: set[str] = set()
    for r in records:
        if r.split == E1Split.DEVELOPMENT.value and r.case_type == "transition":
            dev_families_with_transition.add(r.family_digest)
    total_dev_families = len(development_family_digests)
    if len(dev_families_with_transition) < total_dev_families:
        blockers.add(BLOCKER_INSUFFICIENT_DEVELOPMENT_TRANSITION_COVERAGE)

    # right-answer/wrong-basis: distinguish unassessable from absent.
    rawb = next((c for c in contrasts if c.name == "right_answer_wrong_basis"), None)
    if rawb is not None:
        if not rawb.assessable:
            blockers.add(BLOCKER_RIGHT_ANSWER_WRONG_BASIS_UNASSESSABLE)
        elif rawb.present is False:
            blockers.add(BLOCKER_MISSING_RIGHT_ANSWER_WRONG_BASIS_CONTRAST)

    return tuple(sorted(blockers))


def _population_inventory(records: tuple[_CompiledRecord, ...]) -> dict[str, object]:
    train_records = [r for r in records if r.split == E1Split.TRAIN.value]
    dev_records = [r for r in records if r.split == E1Split.DEVELOPMENT.value]
    all_records = list(records)

    def case_type_counts(subset: list[_CompiledRecord]) -> dict[str, int]:
        return _counter_to_dict(Counter(r.case_type for r in subset))

    def acceptance_counts(subset: list[_CompiledRecord]) -> dict[str, int]:
        return _counter_to_dict(
            Counter(
                str(r.reference_label.get("acceptance"))
                if isinstance(r.reference_label.get("acceptance"), str)
                else _UNDEFINED
                for r in subset
            )
        )

    def distinct_label_count(subset: list[_CompiledRecord]) -> int:
        digests: set[str] = set()
        for rec in subset:
            digests.add(canonical_sha256(rec.reference_label))
        return len(digests)

    return {
        "train_record_count": len(train_records),
        "development_record_count": len(dev_records),
        "overall_record_count": len(all_records),
        "train_case_type_counts": case_type_counts(train_records),
        "development_case_type_counts": case_type_counts(dev_records),
        "overall_case_type_counts": case_type_counts(all_records),
        "train_acceptance_counts": acceptance_counts(train_records),
        "development_acceptance_counts": acceptance_counts(dev_records),
        "overall_acceptance_counts": acceptance_counts(all_records),
        "training_distinct_full_label_count": distinct_label_count(train_records),
        "development_distinct_full_label_count": distinct_label_count(dev_records),
        "overall_distinct_full_label_count": distinct_label_count(all_records),
    }


def _bool_atom(atoms: dict[str, str | None], name: str) -> bool | None:
    value = atoms.get(name)
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _clean_case_evidence_for(records: tuple[_CompiledRecord, ...]) -> tuple[CleanCaseEvidence, ...]:
    items: list[CleanCaseEvidence] = []
    for rec in records:
        items.append(
            CleanCaseEvidence(
                record_id=rec.record_id,
                family_digest=rec.family_digest,
                case_type=rec.case_type,
                event_type=rec.atoms.get("event_type"),
                any_evidence_invalidated=_bool_atom(rec.atoms, "any_evidence_invalidated"),
                any_basis_removed=_bool_atom(rec.atoms, "any_basis_removed"),
                source_state_changed=_bool_atom(rec.atoms, "source_state_changed"),
                assurance_changed=_bool_atom(rec.atoms, "assurance_changed"),
                obligation_changed=_bool_atom(rec.atoms, "obligation_changed"),
                retirement_involved=_bool_atom(rec.atoms, "retirement_involved"),
                reassessment_involved=_bool_atom(rec.atoms, "reassessment_involved"),
            )
        )
    return tuple(items)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def audit_e1_label_space(
    foundry: E1FoundryArtifactBundle,
    selection: E1ExperimentContract,
    *,
    release: str,
    source_commit: str,
) -> LabelSpaceAudit:
    """Audit one compiled Foundry bundle for non-degenerate executable signal."""

    if not release.strip():
        raise LabelSpaceAuditError("release must be nonempty")
    if source_commit != foundry.source_commit:
        raise LabelSpaceAuditError("source_commit must equal the foundry bundle source commit")
    if selection.contract_digest != foundry.selection_contract_digest:
        raise LabelSpaceAuditError(
            "selection contract digest must match the foundry bundle binding"
        )

    foundry_train = foundry.file("foundry_train.jsonl")
    development_evaluation = foundry.file("development_evaluation.jsonl")
    bundle_manifest = foundry.file("bundle_manifest.json")

    train_records_raw = load_artifact_records(foundry_train.content)
    dev_records_raw = load_artifact_records(development_evaluation.content)
    all_records_raw: tuple[dict[str, object], ...] = train_records_raw + dev_records_raw
    records = tuple(_compile_record(r) for r in all_records_raw)

    if len(train_records_raw) != foundry.training_record_count:
        raise LabelSpaceAuditError("training record count mismatch with bundle binding")
    if len(dev_records_raw) != foundry.development_record_count:
        raise LabelSpaceAuditError("development record count mismatch with bundle binding")

    development_family_digests: frozenset[str] = frozenset(
        assignment.family_digest
        for assignment in selection.split_manifest.assignments
        if assignment.split is E1Split.DEVELOPMENT
    )
    total_development_family_count = foundry.development_family_count

    dimensions = tuple(_summarize_dimension(name, records) for name in _ALL_ATOMS)

    candidate_projections = tuple(
        _evaluate_projection(
            spec,
            records,
            development_family_digests,
            total_development_family_count,
        )
        for spec in _PROJECTION_SPECS
    )

    contrasts = _build_contrasts(records)
    blockers = _derive_blockers(contrasts, records, development_family_digests)
    population = _population_inventory(records)
    clean_case_evidence = _clean_case_evidence_for(records)

    semantic_candidate_present = any(cp.semantic_candidate for cp in candidate_projections)
    primary_supported = any(cp.primary_population_eligible for cp in candidate_projections)

    # Deterministic full_e1_population_support derivation.
    clean_case_policy_status = "unfrozen"
    if not primary_supported:
        full_support: bool | None = False
    elif clean_case_policy_status == "unfrozen":
        full_support = None
    elif clean_case_policy_status == "supported":
        full_support = True
    else:
        full_support = False

    all_dimensions = dimensions

    return LabelSpaceAudit(
        schema_version=_SCHEMA_VERSION,
        release=release,
        source_commit=source_commit,
        selection_contract_digest=foundry.selection_contract_digest,
        foundry_bundle_manifest_sha256=bundle_manifest.sha256,
        foundry_train_sha256=foundry_train.sha256,
        development_evaluation_sha256=development_evaluation.sha256,
        task_format_digest=foundry.task_format_digest,
        training_record_count=foundry.training_record_count,
        development_record_count=foundry.development_record_count,
        population=population,
        dimensions=all_dimensions,
        candidate_projections=candidate_projections,
        clean_case_evidence=clean_case_evidence,
        contrast_inventory=contrasts,
        experiment_blockers=blockers,
        clean_case_policy_status=clean_case_policy_status,
        semantic_projection_candidate_present=semantic_candidate_present,
        primary_population_supported=primary_supported,
        full_e1_population_support=full_support,
        claim_boundary=_CLAIM_BOUNDARY,
    )


def write_label_space_audit(audit: LabelSpaceAudit, path: str) -> None:
    """Write the canonical audit artifact bytes."""

    text = canonical_json_text(audit.to_dict())
    with open(path, "w", encoding="utf-8", newline="\n") as handle:  # noqa: PTH123
        handle.write(text)


def validate_label_space_audit(audit: LabelSpaceAudit, path: str) -> bool:
    """Return True iff the on-disk artifact is byte-identical to the audit."""

    expected = canonical_json_bytes(audit.to_dict())
    with open(path, "rb") as handle:  # noqa: PTH123
        observed = handle.read()
    return observed == expected


# Silence unused-import linters for re-exported helpers kept for API symmetry.
_ = (field, canonical_json_text)
