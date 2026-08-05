"""Compile deterministic executable-semantics artifacts for the bounded E1 probe."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from csd_foundry.empirical.e1.execution_splits import E1Split
from csd_foundry.empirical.e1.experiment_contract import E1ExperimentContract
from csd_foundry.kernel.events import CsdEvent
from csd_foundry.kernel.invariants import (
    Violation,
    validate_event_transition,
    validate_state,
    validate_transition,
)
from csd_foundry.kernel.models import ControlState
from csd_foundry.kernel.oracle import CsdOracle, OracleRejected
from csd_foundry.kernel.temporal import is_temporal_event
from csd_foundry.kernel.temporal_invariants import (
    validate_temporal_event,
    validate_temporal_state,
    validate_temporal_transition,
)
from csd_foundry.kernel.transitions import TransitionError, apply_event
from csd_foundry.scenarios.runner import run_scenario
from csd_foundry.scenarios.spec import (
    ObservationCase,
    RejectedTransitionCase,
    ScenarioMode,
    ScenarioSpec,
    TransitionCase,
)
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
    load_json_text,
    to_json_value,
)

_GIT_DIGEST = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DEFAULT_OUTPUT = "artifacts/e1/foundry-v1"
_SYSTEM = (
    "Apply the supplied CSD semantics and return only the canonical JSON decision label. "
    "Do not infer a replacement state or verdict not established by the executable semantics."
)
_CLAIM_BOUNDARY = (
    "This bundle establishes deterministic compilation, canonical-runner admission, "
    "executable labels, and separate replay-and-invariant verification. It does not select "
    "a tokenizer, establish control-arm token parity, authorize GPU execution, or establish "
    "pedagogical effectiveness or general reasoning transfer."
)
_FILES = {
    "train": "foundry_train.jsonl",
    "development": "development_evaluation.jsonl",
    "runner": "runner_execution_evidence.json",
    "oracle": "executable_oracle_evidence.json",
    "verification": "independent_verification_evidence.json",
    "train_manifest": "foundry_curriculum_manifest.json",
    "development_manifest": "development_evaluation_manifest.json",
    "bundle_manifest": "bundle_manifest.json",
}


class E1ArtifactError(ValueError):
    """Raised when an E1 artifact cannot be compiled or reconstructed exactly."""


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    path: str
    role: str
    content: bytes
    record_count: int | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def receipt(self) -> dict[str, object]:
        result: dict[str, object] = {
            "path": self.path,
            "role": self.role,
            "sha256": self.sha256,
            "byte_count": len(self.content),
        }
        if self.record_count is not None:
            result["record_count"] = self.record_count
        return result


@dataclass(frozen=True, slots=True)
class E1FoundryArtifactBundle:
    release: str
    source_commit: str
    selection_contract_digest: str
    training_scenario_ids: tuple[str, ...]
    development_scenario_ids: tuple[str, ...]
    development_family_count: int
    training_record_count: int
    development_record_count: int
    task_format_digest: str
    generation_command_digest: str
    validation_command_digest: str
    files: tuple[ArtifactFile, ...]

    def file(self, path: str) -> ArtifactFile:
        for item in self.files:
            if item.path == path:
                return item
        raise KeyError(path)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "e1-foundry-artifact-bundle/1",
            "release": self.release,
            "source_commit": self.source_commit,
            "selection_contract_digest": self.selection_contract_digest,
            "training_scenario_ids": list(self.training_scenario_ids),
            "development_scenario_ids": list(self.development_scenario_ids),
            "development_family_count": self.development_family_count,
            "training_record_count": self.training_record_count,
            "development_record_count": self.development_record_count,
            "task_format_digest": self.task_format_digest,
            "generation_command_digest": self.generation_command_digest,
            "validation_command_digest": self.validation_command_digest,
            "files": [item.receipt() for item in self.files],
            "claim_boundary": _CLAIM_BOUNDARY,
        }


@dataclass(frozen=True, slots=True)
class E1ArtifactValidationReport:
    success: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"status": "valid" if self.success else "invalid", "errors": list(self.errors)}


def e1_task_format() -> dict[str, object]:
    return {
        "schema_version": "e1-semantic-decision-task-format/1",
        "prompt_field": "prompt_messages",
        "target_field": "target",
        "prompt_roles": ["system", "user"],
        "system_prompt": _SYSTEM,
        "user_encoding": "canonical_json_text",
        "target_encoding": "canonical_json_text",
        "metadata_excluded_from_model_input": [
            "case_id",
            "case_type",
            "declared_family",
            "executable_oracle_receipt_digest",
            "family_digest",
            "independent_verification_receipt_digest",
            "label_authority",
            "record_id",
            "reference_label",
            "scenario_id",
            "source_section",
            "split",
            "task_format_digest",
        ],
    }


def e1_task_format_digest() -> str:
    return canonical_sha256(e1_task_format())


def _jsonl(records: tuple[dict[str, object], ...]) -> bytes:
    return b"".join(canonical_json_bytes(item) for item in records)


def _violations(items: tuple[Violation, ...]) -> list[dict[str, str]]:
    return [
        {"invariant_id": item.invariant_id, "message": item.message}
        for item in sorted(items, key=lambda value: (value.invariant_id, value.message))
    ]


def _transition_violations(
    before: ControlState,
    event: CsdEvent,
    after: ControlState,
) -> tuple[Violation, ...]:
    event_violations: tuple[Violation, ...] = ()
    if not is_temporal_event(event):
        event_violations = validate_event_transition(before, event, after)
    return (
        *validate_transition(before, after),
        *validate_temporal_transition(before, after),
        *event_violations,
        *validate_temporal_event(before, event, after),
    )


def _transition_case(
    spec: ScenarioSpec,
    case: TransitionCase,
    before: ControlState,
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
    ControlState,
]:
    initial = (*validate_state(before), *validate_temporal_state(before))
    if initial:
        raise E1ArtifactError(f"{case.case_id}: invalid pre-state: {_violations(initial)}")
    try:
        oracle = CsdOracle().apply(before, case.event)
    except (OracleRejected, TransitionError, TypeError, ValueError) as exc:
        raise E1ArtifactError(f"{case.case_id}: oracle rejected canonical case: {exc}") from exc
    replay_after, replay_trace = apply_event(before, case.event)
    replay_violations = _transition_violations(before, case.event, replay_after)
    if replay_violations:
        raise E1ArtifactError(
            f"{case.case_id}: replay violated invariants: {_violations(replay_violations)}"
        )
    if (replay_after, replay_trace) != (oracle.after, oracle.trace):
        raise E1ArtifactError(f"{case.case_id}: replay disagrees with oracle")
    task_input: dict[str, object] = {
        "schema_version": "e1-semantic-decision-input/1",
        "case_type": "transition",
        "before": to_json_value(before),
        "event_type": type(case.event).__name__,
        "event": to_json_value(case.event),
    }
    label: dict[str, object] = {
        "schema_version": "e1-semantic-decision-label/1",
        "case_type": "transition",
        "acceptance": "accepted",
        "after": to_json_value(oracle.after),
        "trace": to_json_value(oracle.trace),
    }
    oracle_receipt: dict[str, object] = {
        "schema_version": "e1-executable-oracle-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "transition",
        "input_digest": canonical_sha256(task_input),
        "before_digest": canonical_sha256(before),
        "event_digest": canonical_sha256(
            {"event_type": type(case.event).__name__, "event": case.event}
        ),
        "after_digest": canonical_sha256(oracle.after),
        "trace_digest": canonical_sha256(oracle.trace),
        "label_digest": canonical_sha256(label),
    }
    verification_receipt: dict[str, object] = {
        "schema_version": "e1-independent-verification-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "transition",
        "replay_after_digest": canonical_sha256(replay_after),
        "replay_trace_digest": canonical_sha256(replay_trace),
        "violations": _violations(replay_violations),
        "matches_oracle": True,
        "label_digest": canonical_sha256(label),
    }
    return task_input, label, oracle_receipt, verification_receipt, oracle.after


def _observation_case(
    spec: ScenarioSpec,
    case: ObservationCase,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    violations = (*validate_state(case.state), *validate_temporal_state(case.state))
    if violations:
        raise E1ArtifactError(f"{case.case_id}: invalid observation: {_violations(violations)}")
    task_input: dict[str, object] = {
        "schema_version": "e1-semantic-decision-input/1",
        "case_type": "observation",
        "state": to_json_value(case.state),
        "assertion": case.assertion,
    }
    label: dict[str, object] = {
        "schema_version": "e1-semantic-decision-label/1",
        "case_type": "observation",
        "acceptance": "accepted",
        "assertion_status": "holds",
        "state": to_json_value(case.state),
    }
    oracle: dict[str, object] = {
        "schema_version": "e1-executable-oracle-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "observation",
        "execution_mode": "state_invariant_evaluation",
        "input_digest": canonical_sha256(task_input),
        "state_digest": canonical_sha256(case.state),
        "label_digest": canonical_sha256(label),
    }
    verification: dict[str, object] = {
        "schema_version": "e1-independent-verification-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "observation",
        "violations": _violations(violations),
        "matches_oracle": True,
        "label_digest": canonical_sha256(label),
    }
    return task_input, label, oracle, verification


def _rejected_case(
    spec: ScenarioSpec,
    case: RejectedTransitionCase,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    observed = list(validate_transition(case.before, case.proposed_after))
    if case.event is not None:
        observed.extend(validate_event_transition(case.before, case.event, case.proposed_after))
    violations = tuple(observed)
    invariant_ids = tuple(sorted({item.invariant_id for item in violations}))
    missing = case.expected_invariants - frozenset(invariant_ids)
    if not invariant_ids or missing:
        raise E1ArtifactError(
            f"{case.case_id}: rejection evidence incomplete; missing={sorted(missing)}"
        )
    task_input: dict[str, object] = {
        "schema_version": "e1-semantic-decision-input/1",
        "case_type": "rejected_transition",
        "before": to_json_value(case.before),
        "event_type": None if case.event is None else type(case.event).__name__,
        "event": None if case.event is None else to_json_value(case.event),
        "proposed_after": to_json_value(case.proposed_after),
    }
    label: dict[str, object] = {
        "schema_version": "e1-semantic-decision-label/1",
        "case_type": "rejected_transition",
        "acceptance": "rejected",
        "invariant_ids": list(invariant_ids),
    }
    oracle: dict[str, object] = {
        "schema_version": "e1-executable-oracle-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "rejected_transition",
        "execution_mode": "invariant_rejection",
        "input_digest": canonical_sha256(task_input),
        "label_digest": canonical_sha256(label),
    }
    verification: dict[str, object] = {
        "schema_version": "e1-independent-verification-case/1",
        "scenario_id": spec.scenario_id,
        "case_id": case.case_id,
        "case_type": "rejected_transition",
        "violations": _violations(violations),
        "expected_invariant_ids": sorted(case.expected_invariants),
        "matches_oracle": True,
        "label_digest": canonical_sha256(label),
    }
    return task_input, label, oracle, verification


def _record(
    spec: ScenarioSpec,
    split: E1Split,
    family_digest: str,
    case_id: str,
    task_input: dict[str, object],
    label: dict[str, object],
    oracle: dict[str, object],
    verification: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "e1-semantic-decision-record/1",
        "record_id": f"e1-foundry/{split.value}/{spec.scenario_id}/{case_id}",
        "split": split.value,
        "scenario_id": spec.scenario_id,
        "family_digest": family_digest,
        "declared_family": spec.family,
        "source_section": spec.source_section,
        "case_id": case_id,
        "case_type": task_input["case_type"],
        "label_authority": "executable_semantics",
        "task_format_digest": e1_task_format_digest(),
        "prompt_messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": canonical_json_text(task_input)},
        ],
        "target": canonical_json_text(label),
        "reference_label": label,
        "executable_oracle_receipt_digest": canonical_sha256(oracle),
        "independent_verification_receipt_digest": canonical_sha256(verification),
    }


def _sequence_coordinates(case_id: str) -> tuple[str, int]:
    parts = case_id.split("/")
    if len(parts) < 3:
        raise E1ArtifactError(f"invalid sequence case identity: {case_id}")
    try:
        step = int(parts[-1].split("-", maxsplit=1)[0])
    except ValueError as exc:
        raise E1ArtifactError(f"sequence case has no numeric step: {case_id}") from exc
    return "/".join(parts[:-1]), step


def _compile_scenario(
    spec: ScenarioSpec,
    split: E1Split,
    family_digest: str,
) -> tuple[
    tuple[dict[str, object], ...],
    tuple[dict[str, object], ...],
    tuple[dict[str, object], ...],
]:
    records: list[dict[str, object]] = []
    oracle_receipts: list[dict[str, object]] = []
    verification_receipts: list[dict[str, object]] = []

    def append(
        case_id: str,
        task_input: dict[str, object],
        label: dict[str, object],
        oracle: dict[str, object],
        verification: dict[str, object],
    ) -> None:
        records.append(
            _record(
                spec,
                split,
                family_digest,
                case_id,
                task_input,
                label,
                oracle,
                verification,
            )
        )
        oracle_receipts.append(oracle)
        verification_receipts.append(verification)

    if spec.mode is ScenarioMode.SEQUENCE:
        groups: dict[str, list[tuple[int, TransitionCase]]] = {}
        for case in spec.cases:
            if not isinstance(case, TransitionCase):
                raise E1ArtifactError("sequence scenarios may contain only transitions")
            group, step = _sequence_coordinates(case.case_id)
            groups.setdefault(group, []).append((step, case))
        for group in sorted(groups):
            previous: ControlState | None = None
            for expected_step, (step, case) in enumerate(
                sorted(groups[group], key=lambda item: item[0]), start=1
            ):
                if step != expected_step:
                    raise E1ArtifactError(f"noncontiguous sequence {group}: {step}")
                before = case.before if previous is None else previous
                if previous is not None and case.before != previous:
                    raise E1ArtifactError(f"sequence state-link mismatch: {case.case_id}")
                task_input, label, oracle, verification, previous = _transition_case(
                    spec, case, before
                )
                append(case.case_id, task_input, label, oracle, verification)
    else:
        for case in spec.cases:
            if isinstance(case, TransitionCase):
                task_input, label, oracle, verification, _ = _transition_case(
                    spec, case, case.before
                )
            elif isinstance(case, ObservationCase):
                task_input, label, oracle, verification = _observation_case(spec, case)
            elif isinstance(case, RejectedTransitionCase):
                task_input, label, oracle, verification = _rejected_case(spec, case)
            else:
                raise E1ArtifactError(f"unsupported case type: {type(case).__name__}")
            append(case.case_id, task_input, label, oracle, verification)
    return tuple(records), tuple(oracle_receipts), tuple(verification_receipts)


def _command(
    action: str,
    release: str,
    selection_release: str,
    source_commit: str,
) -> dict[str, object]:
    return {
        "argv": [
            "python",
            "-m",
            "csd_foundry.empirical.e1.foundry_artifact_cli",
            action,
            "--release",
            release,
            "--selection-release",
            selection_release,
            "--source-commit",
            source_commit,
            "--output-dir",
            _DEFAULT_OUTPUT,
        ]
    }


def compile_e1_foundry_artifacts(
    registry: Mapping[str, ScenarioSpec],
    selection: E1ExperimentContract,
    *,
    release: str,
    selection_release: str,
    source_commit: str,
) -> E1FoundryArtifactBundle:
    """Compile Foundry curriculum, development labels, receipts, and manifests."""

    if not release.strip() or not selection_release.strip():
        raise E1ArtifactError("release identifiers must be nonempty")
    if _GIT_DIGEST.fullmatch(source_commit) is None:
        raise E1ArtifactError("source_commit must be a lowercase Git digest")
    if selection.release != selection_release or selection.source_commit != source_commit:
        raise E1ArtifactError("selection identity does not match artifact compilation")

    membership: dict[str, tuple[E1Split, str]] = {}
    for assignment in selection.split_manifest.assignments:
        for scenario_id in assignment.scenario_ids:
            if scenario_id in membership:
                raise E1ArtifactError(f"duplicate selected scenario: {scenario_id}")
            membership[scenario_id] = (assignment.split, assignment.family_digest)
    registry_ids = set(registry)
    selected_ids = set(membership)
    missing = tuple(sorted(selected_ids - registry_ids))
    if missing:
        raise E1ArtifactError(f"selected scenarios missing from registry: {missing}")
    excluded_ids = set(selection.excluded_source_test_scenario_ids)
    extras = tuple(sorted(registry_ids - selected_ids - excluded_ids))
    if extras:
        raise E1ArtifactError(f"registry contains scenarios outside the E1 selection: {extras}")

    training: list[dict[str, object]] = []
    development: list[dict[str, object]] = []
    runner_evidence: list[dict[str, object]] = []
    oracle_evidence: list[dict[str, object]] = []
    verification_evidence: list[dict[str, object]] = []
    for scenario_id in sorted(membership):
        split, family_digest = membership[scenario_id]
        spec = registry[scenario_id]
        runner = run_scenario(spec)
        runner_payload = {
            "scenario_id": scenario_id,
            "accepted": runner.accepted,
            "cases": [
                {
                    "case_id": case.case_id,
                    "case_type": case.case_type,
                    "accepted": case.accepted,
                    "details": list(case.details),
                }
                for case in runner.cases
            ],
        }
        runner_evidence.append(runner_payload)
        if not runner.accepted:
            raise E1ArtifactError(f"canonical runner rejected selected scenario: {scenario_id}")
        records, oracle, verification = _compile_scenario(spec, split, family_digest)
        (training if split is E1Split.TRAIN else development).extend(records)
        oracle_evidence.extend(oracle)
        verification_evidence.extend(verification)

    training_records = tuple(sorted(training, key=lambda item: str(item["record_id"])))
    development_records = tuple(sorted(development, key=lambda item: str(item["record_id"])))
    oracle_cases = tuple(
        sorted(oracle_evidence, key=lambda item: (str(item["scenario_id"]), str(item["case_id"])))
    )
    verification_cases = tuple(
        sorted(
            verification_evidence,
            key=lambda item: (str(item["scenario_id"]), str(item["case_id"])),
        )
    )
    record_ids = [str(item["record_id"]) for item in (*training_records, *development_records)]
    if len(record_ids) != len(set(record_ids)):
        raise E1ArtifactError("compiled record identifiers are not unique")

    training_ids = tuple(
        sorted(key for key, value in membership.items() if value[0] is E1Split.TRAIN)
    )
    development_ids = tuple(
        sorted(key for key, value in membership.items() if value[0] is E1Split.DEVELOPMENT)
    )
    development_family_count = sum(
        item.split is E1Split.DEVELOPMENT for item in selection.split_manifest.assignments
    )
    generation_command = _command("compile", release, selection_release, source_commit)
    validation_command = _command("validate", release, selection_release, source_commit)
    generation_digest = canonical_sha256(generation_command)
    validation_digest = canonical_sha256(validation_command)

    train_file = ArtifactFile(
        _FILES["train"],
        "foundry_training_curriculum",
        _jsonl(training_records),
        len(training_records),
    )
    development_file = ArtifactFile(
        _FILES["development"],
        "development_evaluation",
        _jsonl(development_records),
        len(development_records),
    )
    runner_file = ArtifactFile(
        _FILES["runner"],
        "canonical_runner_evidence",
        canonical_json_bytes(
            {
                "schema_version": "e1-canonical-runner-evidence/1",
                "release": release,
                "source_commit": source_commit,
                "selection_contract_digest": selection.contract_digest,
                "scenario_count": len(runner_evidence),
                "scenarios": runner_evidence,
            }
        ),
    )
    oracle_file = ArtifactFile(
        _FILES["oracle"],
        "executable_oracle_evidence",
        canonical_json_bytes(
            {
                "schema_version": "e1-executable-oracle-evidence/1",
                "release": release,
                "source_commit": source_commit,
                "selection_contract_digest": selection.contract_digest,
                "case_count": len(oracle_cases),
                "cases": list(oracle_cases),
            }
        ),
    )
    verification_file = ArtifactFile(
        _FILES["verification"],
        "independent_verification_evidence",
        canonical_json_bytes(
            {
                "schema_version": "e1-independent-verification-evidence/1",
                "release": release,
                "source_commit": source_commit,
                "selection_contract_digest": selection.contract_digest,
                "case_count": len(verification_cases),
                "cases": list(verification_cases),
            }
        ),
    )

    common_manifest = {
        "release": release,
        "source_commit": source_commit,
        "selection_release": selection_release,
        "selection_contract_digest": selection.contract_digest,
        "task_format": e1_task_format(),
        "task_format_digest": e1_task_format_digest(),
        "generation_command": generation_command,
        "generation_command_digest": generation_digest,
        "validation_command": validation_command,
        "validation_command_digest": validation_digest,
        "canonical_runner_evidence": runner_file.receipt(),
        "executable_oracle_evidence": oracle_file.receipt(),
        "independent_verification_evidence": verification_file.receipt(),
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    train_manifest = ArtifactFile(
        _FILES["train_manifest"],
        "foundry_curriculum_manifest",
        canonical_json_bytes(
            {
                "schema_version": "e1-foundry-curriculum-manifest/1",
                **common_manifest,
                "selection_contract": selection.to_dict(),
                "split": E1Split.TRAIN.value,
                "label_authority": "executable_semantics",
                "scenario_ids": list(training_ids),
                "scenario_count": len(training_ids),
                "record_count": len(training_records),
                "artifact": train_file.receipt(),
                "tokenizer_revision_status": "unbound_pending_common_tokenizer_selection",
                "token_count_status": "unbound_pending_token_budget_equalization",
            }
        ),
    )
    development_manifest = ArtifactFile(
        _FILES["development_manifest"],
        "development_evaluation_manifest",
        canonical_json_bytes(
            {
                "schema_version": "e1-development-evaluation-manifest/1",
                **common_manifest,
                "split": E1Split.DEVELOPMENT.value,
                "scenario_ids": list(development_ids),
                "scenario_count": len(development_ids),
                "family_count": development_family_count,
                "record_count": len(development_records),
                "artifact": development_file.receipt(),
                "metric_execution_status": ("not_executed_protected_until_checkpoints_complete"),
            }
        ),
    )
    role_digests = {
        train_file.sha256,
        development_file.sha256,
        train_manifest.sha256,
        development_manifest.sha256,
        oracle_file.sha256,
        verification_file.sha256,
    }
    if len(role_digests) != 6:
        raise E1ArtifactError("artifact, manifest, oracle, and verification digests must differ")

    pre_manifest = tuple(
        sorted(
            (
                train_file,
                development_file,
                runner_file,
                oracle_file,
                verification_file,
                train_manifest,
                development_manifest,
            ),
            key=lambda item: item.path,
        )
    )
    bundle_manifest = ArtifactFile(
        _FILES["bundle_manifest"],
        "bundle_manifest",
        canonical_json_bytes(
            {
                "schema_version": "e1-foundry-bundle-manifest/1",
                "release": release,
                "source_commit": source_commit,
                "selection_release": selection_release,
                "selection_contract_digest": selection.contract_digest,
                "training_scenario_ids": list(training_ids),
                "development_scenario_ids": list(development_ids),
                "development_family_count": development_family_count,
                "training_record_count": len(training_records),
                "development_record_count": len(development_records),
                "task_format_digest": e1_task_format_digest(),
                "generation_command_digest": generation_digest,
                "validation_command_digest": validation_digest,
                "files": [item.receipt() for item in pre_manifest],
                "claim_boundary": _CLAIM_BOUNDARY,
            }
        ),
    )
    files = tuple(sorted((*pre_manifest, bundle_manifest), key=lambda item: item.path))
    return E1FoundryArtifactBundle(
        release=release,
        source_commit=source_commit,
        selection_contract_digest=selection.contract_digest,
        training_scenario_ids=training_ids,
        development_scenario_ids=development_ids,
        development_family_count=development_family_count,
        training_record_count=len(training_records),
        development_record_count=len(development_records),
        task_format_digest=e1_task_format_digest(),
        generation_command_digest=generation_digest,
        validation_command_digest=validation_digest,
        files=files,
    )


def write_e1_foundry_artifacts(bundle: E1FoundryArtifactBundle, directory: Path) -> None:
    if directory.exists() and any(directory.iterdir()):
        raise E1ArtifactError(f"output directory is not empty: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    for item in bundle.files:
        (directory / item.path).write_bytes(item.content)


def validate_e1_foundry_artifacts(
    directory: Path,
    registry: Mapping[str, ScenarioSpec],
    selection: E1ExperimentContract,
    *,
    release: str,
    selection_release: str,
    source_commit: str,
) -> E1ArtifactValidationReport:
    expected = compile_e1_foundry_artifacts(
        registry,
        selection,
        release=release,
        selection_release=selection_release,
        source_commit=source_commit,
    )
    if not directory.is_dir():
        return E1ArtifactValidationReport(False, (f"missing directory: {directory}",))
    errors: list[str] = []
    expected_paths = {item.path for item in expected.files}
    actual_paths = {item.name for item in directory.iterdir()}
    if expected_paths != actual_paths:
        errors.append(
            f"file-set mismatch; missing={sorted(expected_paths - actual_paths)}, "
            f"extra={sorted(actual_paths - expected_paths)}"
        )
    for item in expected.files:
        path = directory / item.path
        if path.is_symlink() or not path.is_file():
            errors.append(f"{item.path}: expected a regular non-symlink file")
            continue
        observed_bytes = path.read_bytes()
        if observed_bytes != item.content:
            observed = hashlib.sha256(observed_bytes).hexdigest()
            errors.append(f"{item.path}: expected {item.sha256}, observed {observed}")
    return E1ArtifactValidationReport(not errors, tuple(errors))


def load_artifact_records(content: bytes) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(content.decode("utf-8").splitlines(), start=1):
        parsed = load_json_text(line)
        if not isinstance(parsed, dict):
            raise E1ArtifactError(f"record line {line_number} is not an object")
        records.append(cast(dict[str, object], parsed))
    return tuple(records)
