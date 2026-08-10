"""Frozen assumption use-time admissibility evaluator (D3.2-B).

Deterministically decide whether a specific admitted assumption may support a
specific decision by replaying its complete authoritative history, recomputing
current challenge/materiality state, recursively validating assumption and
evidence dependencies, and binding the result to exact registry roots and
logical time — without mutating any registry.

D3.2-B trusts the authoritative registry history and receipt digests already
committed there; it does not independently establish the authority validity of
every post-ADMIT lifecycle event.

The evaluator is authoritative **relative to its supplied validated registry
snapshots and decision binding** — not external truth, global completeness, or
real-world validity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionEvaluationWork,
    AssumptionGovernanceContractError,
    DecisionAssumptionBinding,
    _domain_digest,
    _json_bytes,
    _require_digest,
    _require_self_digest,
    _require_token,
    canonical_cycle_witness,
)
from csd_foundry.governance.v0_5.assumption import (
    AssumptionRegistryError,
    project_assumption_history,
)
from csd_foundry.governance.v0_5.evidence_governance import (
    EvidenceAdmissibilityEvaluator,
    EvidenceAdmissibilityReceipt,
    EvidenceGovernanceError,
    EvidenceUseRequest,
)
from csd_foundry.governance.v0_5.registry import RegistryStore

_DECISION_SCHEMA_VERSION = "assumption-use-admissibility-decision/1"
_DECISION_DOMAIN = "ASSUMPTION_USE_ADMISSIBILITY_DECISION"

_ACTIVE_STANDINGS = frozenset({"ADMITTED", "CONFIRMED"})
_TERMINAL_STANDINGS = frozenset({"REJECTED", "EXPIRED", "SUPERSEDED"})

# Exact traversal-code vocabulary.
_TRAVERSAL_CODES = frozenset(
    {
        "ASSUMPTION_USE_NODE_PRESENT",
        "ASSUMPTION_USE_MISSING",
        "ASSUMPTION_USE_DEPENDENCY_MISSING",
        "ASSUMPTION_USE_HISTORY_INVALID",
        "ASSUMPTION_USE_TERMINAL",
        "ASSUMPTION_USE_NOT_ADMITTED",
        "ASSUMPTION_USE_CHALLENGED",
        "ASSUMPTION_USE_NOT_YET_VALID",
        "ASSUMPTION_USE_EXPIRED",
    }
)


def _ordered_tuple(items: tuple[str, ...]) -> tuple[str, ...]:
    """Return items in their original order (for already-canonical tuples)."""
    return items


@dataclass(frozen=True, slots=True)
class UseTimeTraversedAssumption:
    """One visited assumption node with its authoritative projected state.

    Carries enough information for the parent receipt to mechanically:
    - Replay DFS closure from dependency tuples
    - Check exact temporal denial from recorded clock and validity interval
    - Rebuild and verify each D2 evidence request from the owner's state
    - Recompute work counters
    """

    assumption_id: str
    validation_code: str
    current_event_digest: str | None
    current_entity_sequence: int | None
    history_event_count: int
    proposition_id: str | None
    scope_ids: tuple[str, ...]
    materiality: str | None
    standing: str | None
    active_challenge_ids: tuple[str, ...]
    valid_from_sequence: int | None
    expires_at_sequence: int | None
    assumption_dependency_ids: tuple[str, ...]
    evidence_dependency_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    maximum_reuse_class: str | None

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "USE_TRAVERSED_ID_INVALID")
        if type(self.validation_code) is not str:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_CODE_INVALID")
        if self.validation_code not in _TRAVERSAL_CODES:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_CODE_INVALID")
        if type(self.history_event_count) is not int or isinstance(self.history_event_count, bool):
            raise AssumptionGovernanceContractError("USE_TRAVERSED_HISTORY_COUNT_INVALID")
        if self.history_event_count < 0:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_HISTORY_COUNT_INVALID")
        if type(self.scope_ids) is not tuple:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_SCOPE_IDS_INVALID")
        if type(self.active_challenge_ids) is not tuple:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_CHALLENGES_INVALID")
        if type(self.assumption_dependency_ids) is not tuple:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_ASSUMPTION_DEPS_INVALID")
        if type(self.evidence_dependency_ids) is not tuple:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_EVIDENCE_DEPS_INVALID")
        if type(self.limitations) is not tuple:
            raise AssumptionGovernanceContractError("USE_TRAVERSED_LIMITATIONS_INVALID")

        is_present = self.validation_code == "ASSUMPTION_USE_NODE_PRESENT"
        if is_present:
            if self.current_event_digest is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_PRESENT_DIGEST_MISSING")
            _require_digest(self.current_event_digest, "USE_TRAVERSED_DIGEST_INVALID")
            if self.current_entity_sequence is None or self.current_entity_sequence < 1:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_SEQUENCE_INVALID")
            if self.proposition_id is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_PROP_MISSING")
            if self.materiality is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_MATERIALITY_MISSING")
            if self.standing is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_STANDING_MISSING")
            if self.valid_from_sequence is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_VALID_FROM_MISSING")
            if self.maximum_reuse_class is None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_REUSE_MISSING")
        else:
            if self.current_event_digest is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_DIGEST")
            if self.current_entity_sequence is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_SEQUENCE")
            if self.proposition_id is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_PROP")
            if self.materiality is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_MATERIALITY")
            if self.standing is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_STANDING")
            if self.valid_from_sequence is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_VALID_FROM")
            if self.maximum_reuse_class is not None:
                raise AssumptionGovernanceContractError("USE_TRAVERSED_NONPRESENT_REUSE")
            # expires_at_sequence can be None for both present and non-present

    def to_json_value(self) -> dict[str, object]:
        return {
            "assumption_id": self.assumption_id,
            "validation_code": self.validation_code,
            "current_event_digest": self.current_event_digest,
            "current_entity_sequence": self.current_entity_sequence,
            "history_event_count": self.history_event_count,
            "proposition_id": self.proposition_id,
            "scope_ids": list(self.scope_ids),
            "materiality": self.materiality,
            "standing": self.standing,
            "active_challenge_ids": list(self.active_challenge_ids),
            "valid_from_sequence": self.valid_from_sequence,
            "expires_at_sequence": self.expires_at_sequence,
            "assumption_dependency_ids": list(self.assumption_dependency_ids),
            "evidence_dependency_ids": list(self.evidence_dependency_ids),
            "limitations": list(self.limitations),
            "maximum_reuse_class": self.maximum_reuse_class,
        }


@dataclass(frozen=True, slots=True)
class EvidenceEvaluation:
    """One D2 evidence admissibility evaluation bound to its owning assumption."""

    owner_assumption_id: str
    request: EvidenceUseRequest
    receipt: EvidenceAdmissibilityReceipt

    def __post_init__(self) -> None:
        _require_token(self.owner_assumption_id, "USE_EVIDENCE_EVAL_OWNER_INVALID")
        if type(self.request) is not EvidenceUseRequest:
            raise AssumptionGovernanceContractError("USE_EVIDENCE_EVAL_REQUEST_TYPE_INVALID")
        if type(self.receipt) is not EvidenceAdmissibilityReceipt:
            raise AssumptionGovernanceContractError("USE_EVIDENCE_EVAL_RECEIPT_TYPE_INVALID")
        if self.receipt.request_digest != self.request.request_digest:
            raise AssumptionGovernanceContractError("USE_EVIDENCE_EVAL_REQUEST_MISMATCH")
        if self.receipt.evidence_id != self.request.evidence_id:
            raise AssumptionGovernanceContractError("USE_EVIDENCE_EVAL_EVIDENCE_ID_MISMATCH")

    def to_json_value(self) -> dict[str, object]:
        return {
            "owner_assumption_id": self.owner_assumption_id,
            "request": self.request.to_json_value(),
            "receipt": self.receipt.to_json_value(),
        }


@dataclass(frozen=True, slots=True)
class AssumptionUseEvaluation:
    """Per-assumption use-time evaluation result."""

    assumption_id: str
    validation_code: str
    result: str
    self_state: UseTimeTraversedAssumption
    traversed_dependencies: tuple[UseTimeTraversedAssumption, ...]
    cycle_witness: tuple[str, ...]
    evidence_evaluations: tuple[EvidenceEvaluation, ...]

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "USE_EVAL_ID_INVALID")
        if type(self.validation_code) is not str:
            raise AssumptionGovernanceContractError("USE_EVAL_CODE_INVALID")
        if type(self.result) is not str or self.result not in ("ALLOW", "DENY"):
            raise AssumptionGovernanceContractError("USE_EVAL_RESULT_INVALID")
        if type(self.self_state) is not UseTimeTraversedAssumption:
            raise AssumptionGovernanceContractError("USE_EVAL_SELF_STATE_TYPE_INVALID")
        if type(self.traversed_dependencies) is not tuple:
            raise AssumptionGovernanceContractError("USE_EVAL_TRAVERSED_INVALID")
        if type(self.cycle_witness) is not tuple:
            raise AssumptionGovernanceContractError("USE_EVAL_CYCLE_WITNESS_INVALID")
        if type(self.evidence_evaluations) is not tuple:
            raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_INVALID")

        # self_state must describe this assumption.
        if self.self_state.assumption_id != self.assumption_id:
            raise AssumptionGovernanceContractError("USE_EVAL_SELF_STATE_ID_MISMATCH")

        # Result/code consistency.
        if self.result == "ALLOW":
            if self.validation_code != "ASSUMPTION_USE_ALLOWED":
                raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_CODE_MISMATCH")
            if self.cycle_witness != ():
                raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_CYCLE_PRESENT")
            if self.self_state.validation_code != "ASSUMPTION_USE_NODE_PRESENT":
                raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_SELF_NOT_PRESENT")
            for td in self.traversed_dependencies:
                if td.validation_code != "ASSUMPTION_USE_NODE_PRESENT":
                    raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_HAS_FAILURE")
        else:
            if self.validation_code == "ASSUMPTION_USE_ALLOWED":
                raise AssumptionGovernanceContractError("USE_EVAL_DENY_ALLOW_CODE")

        # Traversed dependency types.
        for td in self.traversed_dependencies:
            if type(td) is not UseTimeTraversedAssumption:
                raise AssumptionGovernanceContractError("USE_EVAL_TRAVERSED_TYPE_INVALID")

        # Evidence evaluation types.
        for ee in self.evidence_evaluations:
            if type(ee) is not EvidenceEvaluation:
                raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_TYPE_INVALID")

    def to_json_value(self) -> dict[str, object]:
        return {
            "assumption_id": self.assumption_id,
            "validation_code": self.validation_code,
            "result": self.result,
            "self_state": self.self_state.to_json_value(),
            "traversed_dependencies": [td.to_json_value() for td in self.traversed_dependencies],
            "cycle_witness": list(self.cycle_witness),
            "evidence_evaluations": [ee.to_json_value() for ee in self.evidence_evaluations],
        }


@dataclass(frozen=True, slots=True)
class AssumptionUseAdmissibilityDecision:
    """Top-level self-digesting use-time admissibility decision."""

    binding: DecisionAssumptionBinding
    evaluated_assumptions: tuple[AssumptionUseEvaluation, ...]
    evaluation_work: AssumptionEvaluationWork
    admissible: bool
    decision_digest: str

    def __post_init__(self) -> None:
        if type(self.binding) is not DecisionAssumptionBinding:
            raise AssumptionGovernanceContractError("USE_DECISION_BINDING_TYPE_INVALID")
        if type(self.evaluated_assumptions) is not tuple:
            raise AssumptionGovernanceContractError("USE_DECISION_EVALUATED_INVALID")
        if type(self.evaluation_work) is not AssumptionEvaluationWork:
            raise AssumptionGovernanceContractError("USE_DECISION_WORK_TYPE_INVALID")
        if type(self.admissible) is not bool:
            raise AssumptionGovernanceContractError("USE_DECISION_ADMISSIBLE_NOT_BOOL")

        for ev in self.evaluated_assumptions:
            if type(ev) is not AssumptionUseEvaluation:
                raise AssumptionGovernanceContractError("USE_DECISION_EVAL_TYPE_INVALID")

        # Evaluated assumption IDs must equal binding.required_assumption_ids.
        eval_ids = tuple(ev.assumption_id for ev in self.evaluated_assumptions)
        if eval_ids != self.binding.required_assumption_ids:
            raise AssumptionGovernanceContractError("USE_DECISION_IDS_MISMATCH")

        # admissible == all ALLOW.
        expected_admissible = all(ev.result == "ALLOW" for ev in self.evaluated_assumptions)
        if self.admissible != expected_admissible:
            raise AssumptionGovernanceContractError("USE_DECISION_ADMISSIBLE_MISMATCH")

        # Recompute work counters from children.
        self._validate_work_counters()

        # Self-digest.
        _require_self_digest(
            _DECISION_DOMAIN,
            self._unsigned_value(),
            self.decision_digest,
            "USE_DECISION_DIGEST_MISMATCH",
        )

    def _validate_work_counters(self) -> None:
        """Recompute work counters from child evaluations."""
        # Collect all unique nodes across all evaluations.
        all_nodes: dict[str, UseTimeTraversedAssumption] = {}
        total_events = 0
        total_challenge_records = 0
        total_evidence_refs = 0
        total_dep_edges = 0

        for ev in self.evaluated_assumptions:
            # Root node.
            root = ev.self_state
            if root.assumption_id not in all_nodes:
                all_nodes[root.assumption_id] = root
                total_events += root.history_event_count
                total_challenge_records += len(root.active_challenge_ids)
            # Traversed dependencies.
            for td in ev.traversed_dependencies:
                if td.assumption_id not in all_nodes:
                    all_nodes[td.assumption_id] = td
                    total_events += td.history_event_count
                    total_challenge_records += len(td.active_challenge_ids)
                # Count edges (dependency IDs that were examined).
                total_dep_edges += len(td.assumption_dependency_ids)
            # Also count root's edges.
            total_dep_edges += len(root.assumption_dependency_ids)
            # Evidence references.
            total_evidence_refs += len(ev.evidence_evaluations)

        expected_histories = len(all_nodes)
        expected_unique_nodes = len(all_nodes)

        w = self.evaluation_work
        if w.assumption_histories_reconstructed != expected_histories:
            raise AssumptionGovernanceContractError("USE_WORK_HISTORIES_MISMATCH")
        if w.assumption_events_replayed != total_events:
            raise AssumptionGovernanceContractError("USE_WORK_EVENTS_MISMATCH")
        if w.authority_decisions_evaluated != 0:
            raise AssumptionGovernanceContractError("USE_WORK_AUTHORITY_NONZERO")
        if w.unique_assumption_nodes_evaluated != expected_unique_nodes:
            raise AssumptionGovernanceContractError("USE_WORK_UNIQUE_NODES_MISMATCH")
        if w.assumption_dependency_edges_examined != total_dep_edges:
            raise AssumptionGovernanceContractError("USE_WORK_EDGES_MISMATCH")
        if w.evidence_dependency_references_evaluated != total_evidence_refs:
            raise AssumptionGovernanceContractError("USE_WORK_EVIDENCE_REFS_MISMATCH")
        if w.active_challenges_evaluated != total_challenge_records:
            raise AssumptionGovernanceContractError("USE_WORK_CHALLENGES_MISMATCH")
        if w.separation_duty_rules_evaluated != 0:
            raise AssumptionGovernanceContractError("USE_WORK_SOD_NONZERO")

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _DECISION_SCHEMA_VERSION,
            "admissible": self.admissible,
            "binding": self.binding.to_json_value(),
            "evaluated_assumptions": [ev.to_json_value() for ev in self.evaluated_assumptions],
            "evaluation_work": self.evaluation_work.to_json_value(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "decision_digest": self.decision_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


class UseAdmissibilityError(Exception):
    """Stable error for use-time admissibility evaluation failures."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


def evaluate_assumption_use_admissibility(
    *,
    store: RegistryStore,
    binding: DecisionAssumptionBinding,
    evidence_evaluator: EvidenceAdmissibilityEvaluator,
) -> AssumptionUseAdmissibilityDecision:
    """Evaluate use-time admissibility for all assumptions bound to a decision.

    Read-only. No registry mutation. Every outcome leaves heads/roots unchanged.

    Raises:
        UseAdmissibilityError: on root/store mismatch, root drift, or store identity.
    """
    # --- Root rebind: start roots must equal binding roots ---
    assumption_root_start = store.snapshot("ASSUMPTION").root_digest
    evidence_root_start = store.snapshot("EVIDENCE_UNIT").root_digest
    if assumption_root_start != binding.assumption_registry_root:
        raise UseAdmissibilityError("USE_ROOT_ASSUMPTION_MISMATCH")
    if evidence_root_start != binding.evidence_registry_root:
        raise UseAdmissibilityError("USE_ROOT_EVIDENCE_MISMATCH")
    if evidence_evaluator.store is not store:
        raise UseAdmissibilityError("USE_EVALUATOR_STORE_MISMATCH")

    # --- Evaluate each required assumption ---
    evaluations: list[AssumptionUseEvaluation] = []
    for assumption_id in binding.required_assumption_ids:
        ev = _evaluate_one_assumption(
            store=store,
            binding=binding,
            evidence_evaluator=evidence_evaluator,
            assumption_id=assumption_id,
            is_top_level=True,
        )
        evaluations.append(ev)

    # --- Root stability: end roots must equal start roots ---
    assumption_root_end = store.snapshot("ASSUMPTION").root_digest
    evidence_root_end = store.snapshot("EVIDENCE_UNIT").root_digest
    if assumption_root_end != assumption_root_start:
        raise UseAdmissibilityError("USE_ROOT_ASSUMPTION_DRIFTED")
    if evidence_root_end != evidence_root_start:
        raise UseAdmissibilityError("USE_ROOT_EVIDENCE_DRIFTED")

    # --- Build work counters ---
    all_nodes: dict[str, UseTimeTraversedAssumption] = {}
    total_events = 0
    total_challenge_records = 0
    total_evidence_refs = 0
    total_dep_edges = 0

    for ev in evaluations:
        root = ev.self_state
        if root.assumption_id not in all_nodes:
            all_nodes[root.assumption_id] = root
            total_events += root.history_event_count
            total_challenge_records += len(root.active_challenge_ids)
        for td in ev.traversed_dependencies:
            if td.assumption_id not in all_nodes:
                all_nodes[td.assumption_id] = td
                total_events += td.history_event_count
                total_challenge_records += len(td.active_challenge_ids)
            total_dep_edges += len(td.assumption_dependency_ids)
        total_dep_edges += len(root.assumption_dependency_ids)
        total_evidence_refs += len(ev.evidence_evaluations)

    evaluation_work = AssumptionEvaluationWork.build(
        assumption_histories_reconstructed=len(all_nodes),
        assumption_events_replayed=total_events,
        authority_decisions_evaluated=0,
        unique_assumption_nodes_evaluated=len(all_nodes),
        assumption_dependency_edges_examined=total_dep_edges,
        evidence_dependency_references_evaluated=total_evidence_refs,
        active_challenges_evaluated=total_challenge_records,
        separation_duty_rules_evaluated=0,
    )

    admissible = all(ev.result == "ALLOW" for ev in evaluations)

    unsigned = {
        "schema_version": _DECISION_SCHEMA_VERSION,
        "admissible": admissible,
        "binding": binding.to_json_value(),
        "decision_digest": "",  # placeholder
        "evaluated_assumptions": [ev.to_json_value() for ev in evaluations],
        "evaluation_work": evaluation_work.to_json_value(),
    }
    # Remove decision_digest for digest computation, then add it back.
    unsigned_for_digest = {k: v for k, v in unsigned.items() if k != "decision_digest"}
    decision_digest = _domain_digest(_DECISION_DOMAIN, unsigned_for_digest)

    return AssumptionUseAdmissibilityDecision(
        binding=binding,
        evaluated_assumptions=tuple(evaluations),
        evaluation_work=evaluation_work,
        admissible=admissible,
        decision_digest=decision_digest,
    )


def _evaluate_one_assumption(
    *,
    store: RegistryStore,
    binding: DecisionAssumptionBinding,
    evidence_evaluator: EvidenceAdmissibilityEvaluator,
    assumption_id: str,
    is_top_level: bool,
) -> AssumptionUseEvaluation:
    """Evaluate one assumption for use-time admissibility."""
    # --- SELF_HISTORY: reconstruct + project ---
    history = store.reconstruct_entity("ASSUMPTION", assumption_id)
    if not history:
        code = "ASSUMPTION_USE_MISSING" if is_top_level else "ASSUMPTION_USE_DEPENDENCY_MISSING"
        return _build_denial_evaluation(
            assumption_id,
            code,
            _empty_traversed(assumption_id, code, len(history)),
        )

    try:
        projected = project_assumption_history(history)
    except AssumptionRegistryError:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_HISTORY_INVALID",
            _empty_traversed(assumption_id, "ASSUMPTION_USE_HISTORY_INVALID", len(history)),
        )
    if projected is None:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_HISTORY_INVALID",
            _empty_traversed(assumption_id, "ASSUMPTION_USE_HISTORY_INVALID", len(history)),
        )

    self_state = _projected_to_traversed(projected, len(history))

    # --- Standing gate ---
    if projected.standing in _TERMINAL_STANDINGS:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_TERMINAL",
            self_state,
        )
    if projected.standing not in _ACTIVE_STANDINGS:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_NOT_ADMITTED",
            self_state,
        )

    # --- ACTIVE_CHALLENGES ---
    if projected.active_challenges:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_CHALLENGED",
            self_state,
        )

    # --- Temporal validity ---
    clock = binding.logical_clock_sequence
    if clock < projected.valid_from_sequence:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_NOT_YET_VALID",
            self_state,
        )
    if projected.expires_at_sequence is not None and clock >= projected.expires_at_sequence:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_EXPIRED",
            self_state,
        )

    # --- ASSUMPTION_DEPENDENCIES: DFS ---
    traversed: list[UseTimeTraversedAssumption] = []
    cycle_witness: tuple[str, ...] = ()
    dfs_failed = False
    dfs_code = ""

    dfs_stack: list[str] = [assumption_id]
    dfs_stack_index: dict[str, int] = {assumption_id: 0}
    dfs_visited: set[str] = set()

    def _dfs(node: str) -> None:
        nonlocal cycle_witness, dfs_failed, dfs_code

        if dfs_failed:
            return

        if node in dfs_stack_index:
            i = dfs_stack_index[node]
            raw_cycle = tuple(dfs_stack[i:] + [node])
            cycle_witness = canonical_cycle_witness(raw_cycle)
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_DEPENDENCY_CYCLE"
            return

        if node in dfs_visited:
            return

        dep_history = store.reconstruct_entity("ASSUMPTION", node)
        if not dep_history:
            traversed.append(_empty_traversed(node, "ASSUMPTION_USE_DEPENDENCY_MISSING", 0))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_DEPENDENCY_MISSING"
            return

        try:
            dep_projected = project_assumption_history(dep_history)
        except AssumptionRegistryError:
            traversed.append(
                _empty_traversed(node, "ASSUMPTION_USE_HISTORY_INVALID", len(dep_history))
            )
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_HISTORY_INVALID"
            return
        if dep_projected is None:
            traversed.append(
                _empty_traversed(node, "ASSUMPTION_USE_HISTORY_INVALID", len(dep_history))
            )
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_HISTORY_INVALID"
            return

        dep_state = _projected_to_traversed(dep_projected, len(dep_history))

        # Standing gate for dependency.
        if dep_projected.standing in _TERMINAL_STANDINGS:
            traversed.append(_replace_traversed_code(dep_state, "ASSUMPTION_USE_TERMINAL"))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_TERMINAL"
            return
        if dep_projected.standing not in _ACTIVE_STANDINGS:
            traversed.append(_replace_traversed_code(dep_state, "ASSUMPTION_USE_NOT_ADMITTED"))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_NOT_ADMITTED"
            return

        # Challenge gate for dependency.
        if dep_projected.active_challenges:
            traversed.append(_replace_traversed_code(dep_state, "ASSUMPTION_USE_CHALLENGED"))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_CHALLENGED"
            return

        # Temporal gate for dependency.
        if clock < dep_projected.valid_from_sequence:
            traversed.append(_replace_traversed_code(dep_state, "ASSUMPTION_USE_NOT_YET_VALID"))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_NOT_YET_VALID"
            return
        if (
            dep_projected.expires_at_sequence is not None
            and clock >= dep_projected.expires_at_sequence
        ):
            traversed.append(_replace_traversed_code(dep_state, "ASSUMPTION_USE_EXPIRED"))
            dfs_failed = True
            dfs_code = "ASSUMPTION_USE_EXPIRED"
            return

        traversed.append(dep_state)
        dfs_stack_index[node] = len(dfs_stack)
        dfs_stack.append(node)
        for child in dep_projected.assumption_dependency_ids:
            _dfs(child)
            if dfs_failed:
                break
        if not dfs_failed:
            dfs_stack.pop()
            del dfs_stack_index[node]
            dfs_visited.add(node)

    for dep in projected.assumption_dependency_ids:
        if dfs_failed:
            break
        _dfs(dep)

    if dfs_failed:
        return AssumptionUseEvaluation(
            assumption_id=assumption_id,
            validation_code=dfs_code,
            result="DENY",
            self_state=self_state,
            traversed_dependencies=tuple(traversed),
            cycle_witness=cycle_witness,
            evidence_evaluations=(),
        )

    # --- EVIDENCE_DEPENDENCIES: D2 evaluation ---
    evidence_evals: list[EvidenceEvaluation] = []
    evidence_failed = False
    evidence_code = ""

    # Collect all nodes that need evidence evaluation: self + all traversed deps.
    all_evaluated_nodes = [self_state] + list(traversed)
    for node_state in all_evaluated_nodes:
        if node_state.validation_code != "ASSUMPTION_USE_NODE_PRESENT":
            continue
        for evidence_id in node_state.evidence_dependency_ids:
            request = EvidenceUseRequest.build(
                decision_id=binding.decision_id,
                evidence_id=evidence_id,
                proposition_id=cast(str, node_state.proposition_id),
                scope_ids=node_state.scope_ids,
                required_reuse_class=cast(str, node_state.maximum_reuse_class),
                clock_sequence=binding.logical_clock_sequence,
                accepted_limitation_codes=node_state.limitations,
            )
            try:
                receipt = evidence_evaluator.evaluate(request)
            except EvidenceGovernanceError as exc:
                evidence_failed = True
                evidence_code = str(exc)
                break
            evidence_evals.append(
                EvidenceEvaluation(
                    owner_assumption_id=node_state.assumption_id,
                    request=request,
                    receipt=receipt,
                )
            )
            if not receipt.allowed:
                evidence_failed = True
                evidence_code = receipt.code
                break
        if evidence_failed:
            break

    if evidence_failed:
        return AssumptionUseEvaluation(
            assumption_id=assumption_id,
            validation_code=evidence_code,
            result="DENY",
            self_state=self_state,
            traversed_dependencies=tuple(traversed),
            cycle_witness=(),
            evidence_evaluations=tuple(evidence_evals),
        )

    # --- ALLOW ---
    return AssumptionUseEvaluation(
        assumption_id=assumption_id,
        validation_code="ASSUMPTION_USE_ALLOWED",
        result="ALLOW",
        self_state=self_state,
        traversed_dependencies=tuple(traversed),
        cycle_witness=(),
        evidence_evaluations=tuple(evidence_evals),
    )


def _projected_to_traversed(projected: Any, history_count: int) -> UseTimeTraversedAssumption:
    """Convert a projected Assumption to a UseTimeTraversedAssumption."""
    return UseTimeTraversedAssumption(
        assumption_id=projected.assumption_id,
        validation_code="ASSUMPTION_USE_NODE_PRESENT",
        current_event_digest=projected.current_event_digest,
        current_entity_sequence=projected.current_entity_sequence,
        history_event_count=history_count,
        proposition_id=projected.proposition_id,
        scope_ids=projected.scope_ids,
        materiality=projected.materiality,
        standing=projected.standing,
        active_challenge_ids=projected.active_challenge_ids,
        valid_from_sequence=projected.valid_from_sequence,
        expires_at_sequence=projected.expires_at_sequence,
        assumption_dependency_ids=projected.assumption_dependency_ids,
        evidence_dependency_ids=projected.evidence_dependency_ids,
        limitations=projected.limitations,
        maximum_reuse_class=projected.maximum_reuse_class,
    )


def _empty_traversed(
    assumption_id: str, code: str, history_count: int
) -> UseTimeTraversedAssumption:
    """Build a non-PRESENT traversed node."""
    return UseTimeTraversedAssumption(
        assumption_id=assumption_id,
        validation_code=code,
        current_event_digest=None,
        current_entity_sequence=None,
        history_event_count=history_count,
        proposition_id=None,
        scope_ids=(),
        materiality=None,
        standing=None,
        active_challenge_ids=(),
        valid_from_sequence=None,
        expires_at_sequence=None,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=(),
        maximum_reuse_class=None,
    )


def _replace_traversed_code(
    state: UseTimeTraversedAssumption, code: str
) -> UseTimeTraversedAssumption:
    """Create a non-PRESENT version of a node that failed a gate after reconstruction.

    All fields that __post_init__ requires to be None for non-PRESENT codes are
    nulled out; only identity/audit metadata (history count, scopes, limitations)
    is retained.
    """
    return UseTimeTraversedAssumption(
        assumption_id=state.assumption_id,
        validation_code=code,
        current_event_digest=None,
        current_entity_sequence=None,
        history_event_count=state.history_event_count,
        proposition_id=None,
        scope_ids=state.scope_ids,
        materiality=None,
        standing=None,
        active_challenge_ids=state.active_challenge_ids,
        valid_from_sequence=None,
        expires_at_sequence=None,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=state.limitations,
        maximum_reuse_class=None,
    )


def _build_denial_evaluation(
    assumption_id: str,
    code: str,
    self_state: UseTimeTraversedAssumption,
) -> AssumptionUseEvaluation:
    return AssumptionUseEvaluation(
        assumption_id=assumption_id,
        validation_code=code,
        result="DENY",
        self_state=self_state,
        traversed_dependencies=(),
        cycle_witness=(),
        evidence_evaluations=(),
    )
