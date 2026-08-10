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

# Codes that terminate DFS as soon as they are encountered: the node was either
# unreconstructable or failed a gate, so its own outgoing edges were never
# traversed. NODE_PRESENT means the node passed all gates and its edges WERE
# traversed (pushed, recursed, popped, marked visited).
_DFS_TERMINAL_CODES = frozenset(
    {
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


def _replay_dfs_closure(
    self_state: UseTimeTraversedAssumption,
    traversed: tuple[UseTimeTraversedAssumption, ...],
    cycle_witness: tuple[str, ...],
    result: str,
) -> int:
    """Mechanically replay the DFS closure from the traversal records.

    Reconstructs the depth-first traversal that produced ``traversed`` starting
    from ``self_state.assumption_dependency_ids``, consuming records in order.
    Returns the exact number of assumption-dependency edges that were actually
    followed (i.e. traversed across) before the DFS terminated. Raises on any
    inconsistency between the records and the mechanical replay.

    The replay mirrors the producer's DFS exactly:
      * records are consumed strictly left-to-right, depth-first;
      * a NODE_PRESENT record is pushed, its children recursed in declared
        order, then it is popped and marked visited;
      * any other (terminal) record stops the DFS immediately;
      * a node encountered while still on the active stack is a cycle.

    The number of edges followed is the number of ``_dfs(child)`` invocations
    the producer made before termination - i.e. one per edge that was actually
    examined. For a PRESENT node whose sub-DFS was fully completed, that equals
    ``len(assumption_dependency_ids)``. For fail-fast termination inside a
    child, the parent's later edges are never followed and are therefore not
    counted, which is exactly what the producer did.
    """
    records: list[UseTimeTraversedAssumption] = list(traversed)
    record_idx = 0
    replay_terminated = False
    detected_cycle_witness: tuple[str, ...] = ()

    # A node may appear at most once in a well-formed traversal (DFS
    # first-discovery), so any duplicate id is an immediate structural error.
    seen_ids: set[str] = set()
    for rec in records:
        if rec.assumption_id in seen_ids:
            raise AssumptionGovernanceContractError("USE_EVAL_TRAVERSED_DUPLICATE_NODE")
        seen_ids.add(rec.assumption_id)

    visited: set[str] = set()
    # The root is always on the active DFS stack (the producer seeds its stack
    # with the root id), so a back-edge to the root is a cycle. The root itself
    # is never consumed as a record.
    stack: list[str] = [self_state.assumption_id]
    edges_followed = 0

    def _consume(node_id: str) -> UseTimeTraversedAssumption:
        nonlocal record_idx
        if record_idx >= len(records):
            raise AssumptionGovernanceContractError("USE_EVAL_TRAVERSAL_RECORD_MISSING")
        rec = records[record_idx]
        record_idx += 1
        if rec.assumption_id != node_id:
            raise AssumptionGovernanceContractError("USE_EVAL_TRAVERSAL_ORDER_MISMATCH")
        return rec

    def _dfs(node_id: str) -> None:
        nonlocal replay_terminated, edges_followed, detected_cycle_witness

        if replay_terminated:
            return

        # Cycle: node is already on the active DFS stack.
        if node_id in stack:
            raw_cycle = tuple(stack[stack.index(node_id) :] + [node_id])
            detected_cycle_witness = canonical_cycle_witness(raw_cycle)
            replay_terminated = True
            return

        if node_id in visited:
            return

        # Count this edge as followed only when we actually advance across it to
        # examine the child (i.e. _dfs was invoked for a child that is not on
        # the stack and not yet fully visited). The root's own entry into _dfs is
        # not an edge (the root is never a child), so edges_followed is only
        # incremented by the recursive child calls below.
        rec = _consume(node_id)

        if rec.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
            stack.append(node_id)
            for child_id in rec.assumption_dependency_ids:
                if replay_terminated:
                    break
                edges_followed += 1
                _dfs(child_id)
            if not replay_terminated:
                stack.pop()
                visited.add(node_id)
        else:
            # Terminal record: DFS stops here.
            replay_terminated = True

    # Drive the DFS from the root's declared assumption-dependency edges. The
    # root itself is never consumed as a record (it is self_state); only its
    # outgoing edges are followed.
    for root_child_id in self_state.assumption_dependency_ids:
        if replay_terminated:
            break
        edges_followed += 1
        _dfs(root_child_id)

    # cycle_witness must match exactly what the replay detected.
    if detected_cycle_witness != cycle_witness:
        raise AssumptionGovernanceContractError("USE_EVAL_CYCLE_WITNESS_MISMATCH")

    if result == "ALLOW":
        # ALLOW: the DFS must have completed without terminating early, all
        # records consumed, and no cycle detected.
        if replay_terminated:
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_TRAVERSAL_TERMINATED")
        if record_idx != len(records):
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_RECORDS_NOT_CONSUMED")
        if cycle_witness != ():
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_CYCLE_PRESENT")
    else:  # DENY
        # DENY: exactly a prefix of records is consumed, up to and including the
        # terminal record (or zero records if the DFS never reached any dep, e.g.
        # a self-gate failure with no traversed records).
        if not replay_terminated and len(records) > 0:
            raise AssumptionGovernanceContractError("USE_EVAL_DENY_TRAVERSAL_NOT_TERMINATED")
        # Records after the consumed prefix would mean the producer kept
        # traversing past a terminal node, which is impossible.
        if record_idx != len(records) and replay_terminated:
            # The terminal record may be the last consumed one; any remaining
            # records beyond it are illegal.
            raise AssumptionGovernanceContractError("USE_EVAL_DENY_TRAVERSAL_HAS_LEFTOVER_RECORDS")

    return edges_followed


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

        # Non-PRESENT codes split into two groups:
        #   * "structurally unavailable" (MISSING / DEPENDENCY_MISSING / HISTORY_INVALID):
        #     the node could not be reconstructed, so ALL projected fields must be absent.
        #   * "gate-failed but projected" (TERMINAL / NOT_ADMITTED / CHALLENGED /
        #     NOT_YET_VALID / EXPIRED): the node WAS reconstructed (it passed
        #     SELF_HISTORY) and then failed a later gate. The full projected state is
        #     RETAINED so the receipt proves WHY it failed, but its own dependency
        #     edges were NOT traversed (assumption_dependency_ids and
        #     evidence_dependency_ids are empty).
        _STRUCTURALLY_UNAVAILABLE = frozenset(
            {
                "ASSUMPTION_USE_MISSING",
                "ASSUMPTION_USE_DEPENDENCY_MISSING",
                "ASSUMPTION_USE_HISTORY_INVALID",
            }
        )
        _GATE_FAILED_PROJECTED = frozenset(
            {
                "ASSUMPTION_USE_TERMINAL",
                "ASSUMPTION_USE_NOT_ADMITTED",
                "ASSUMPTION_USE_CHALLENGED",
                "ASSUMPTION_USE_NOT_YET_VALID",
                "ASSUMPTION_USE_EXPIRED",
            }
        )

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
        elif self.validation_code in _STRUCTURALLY_UNAVAILABLE:
            # Could not be reconstructed: every projected field must be absent.
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
        elif self.validation_code in _GATE_FAILED_PROJECTED:
            # Reconstructed then failed a gate: full projected state is RETAINED.
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
            # Own dependency edges were NOT traversed when the gate failed.
            if self.assumption_dependency_ids != ():
                raise AssumptionGovernanceContractError(
                    "USE_TRAVERSED_GATE_FAILED_HAS_ASSUMPTION_DEPS"
                )
            if self.evidence_dependency_ids != ():
                raise AssumptionGovernanceContractError(
                    "USE_TRAVERSED_GATE_FAILED_HAS_EVIDENCE_DEPS"
                )
        # expires_at_sequence can be None for present, gate-failed, and unavailable.

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

        # Mechanical DFS-closure replay. Only the DFS-over-dependencies phase
        # produces traversed records; a self-gate failure (root failed a gate
        # before any dependency was examined) yields self_state with a non-PRESENT
        # code and no traversed records, so there is nothing to replay.
        if self.self_state.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
            _replay_dfs_closure(
                self.self_state,
                self.traversed_dependencies,
                self.cycle_witness,
                self.result,
            )
        else:
            # Root did not pass SELF_HISTORY (or failed a self-gate): no DFS ran,
            # so there must be no traversed records and no cycle witness.
            if self.traversed_dependencies != ():
                raise AssumptionGovernanceContractError("USE_EVAL_SELF_FAILED_HAS_TRAVERSED")
            if self.cycle_witness != ():
                raise AssumptionGovernanceContractError("USE_EVAL_SELF_FAILED_HAS_CYCLE")

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

        # D2 child/request substitution prevention: every evidence evaluation's
        # request must be mechanically rebuildable from its owner assumption's
        # projected state (proposition/scope/reuse-class/limitations) plus this
        # decision's binding (decision_id + logical_clock_sequence). This blocks
        # transplanting a valid (request, receipt) pair from one owner onto an
        # incompatible owner: the rebuilt request_digest would not match.
        self._validate_evidence_request_binding()

        # Recompute work counters from children.
        self._validate_work_counters()

        # Self-digest.
        _require_self_digest(
            _DECISION_DOMAIN,
            self._unsigned_value(),
            self.decision_digest,
            "USE_DECISION_DIGEST_MISMATCH",
        )

    def _validate_evidence_request_binding(self) -> None:
        """Rebuild each evidence request from its owner's projected state + binding.

        For every EvidenceEvaluation, locate the owning assumption node in the
        evaluation's self_state + traversed_dependencies, rebuild the expected
        EvidenceUseRequest from that node's proposition_id / scope_ids /
        maximum_reuse_class / limitations plus the binding's decision_id and
        logical_clock_sequence and the request's evidence_id, and require the
        rebuilt request_digest to match. This prevents semantic substitution of
        a valid (request, receipt) pair onto an incompatible owner.
        """
        for ev in self.evaluated_assumptions:
            # Index this evaluation's traversable nodes by id.
            nodes: dict[str, UseTimeTraversedAssumption] = {
                ev.self_state.assumption_id: ev.self_state
            }
            for td in ev.traversed_dependencies:
                nodes[td.assumption_id] = td

            for ee in ev.evidence_evaluations:
                owner = nodes.get(ee.owner_assumption_id)
                if owner is None:
                    raise AssumptionGovernanceContractError("USE_DECISION_EVIDENCE_OWNER_NOT_FOUND")
                # Only a NODE_PRESENT owner carries the projected state needed to
                # rebuild the request. A gate-failed owner would not have been
                # subject to evidence evaluation in the producer, so an evidence
                # evaluation bound to a non-PRESENT owner is itself illegal.
                if owner.validation_code != "ASSUMPTION_USE_NODE_PRESENT":
                    raise AssumptionGovernanceContractError(
                        "USE_DECISION_EVIDENCE_OWNER_NOT_PRESENT"
                    )
                rebuilt = EvidenceUseRequest.build(
                    decision_id=self.binding.decision_id,
                    evidence_id=ee.request.evidence_id,
                    proposition_id=cast(str, owner.proposition_id),
                    scope_ids=owner.scope_ids,
                    required_reuse_class=cast(str, owner.maximum_reuse_class),
                    clock_sequence=self.binding.logical_clock_sequence,
                    accepted_limitation_codes=owner.limitations,
                )
                if rebuilt.request_digest != ee.request.request_digest:
                    raise AssumptionGovernanceContractError(
                        "USE_DECISION_EVIDENCE_REQUEST_DIGEST_MISMATCH"
                    )

    def _validate_work_counters(self) -> None:
        """Recompute work counters from child evaluations.

        Edge count is receipt-derived: it equals the number of dependency edges
        the DFS actually followed before terminating, recomputed by replaying
        each evaluation's traversal closure. Fail-fast terminations therefore
        count only the edges examined up to and including the terminal edge, not
        every declared dep of every node.
        """
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
            # Edge count: replay the DFS closure to count edges actually followed.
            # A self-gate failure (root not NODE_PRESENT) ran no DFS -> 0 edges.
            if root.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
                total_dep_edges += _replay_dfs_closure(
                    root, ev.traversed_dependencies, ev.cycle_witness, ev.result
                )
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
        # Edge count matches the receipt-derivable replay: count only the edges
        # the DFS actually followed before termination.
        if root.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
            total_dep_edges += _replay_dfs_closure(
                root, ev.traversed_dependencies, ev.cycle_witness, ev.result
            )
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
            _replace_traversed_code(self_state, "ASSUMPTION_USE_TERMINAL"),
        )
    if projected.standing not in _ACTIVE_STANDINGS:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_NOT_ADMITTED",
            _replace_traversed_code(self_state, "ASSUMPTION_USE_NOT_ADMITTED"),
        )

    # --- ACTIVE_CHALLENGES ---
    if projected.active_challenges:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_CHALLENGED",
            _replace_traversed_code(self_state, "ASSUMPTION_USE_CHALLENGED"),
        )

    # --- Temporal validity ---
    clock = binding.logical_clock_sequence
    if clock < projected.valid_from_sequence:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_NOT_YET_VALID",
            _replace_traversed_code(self_state, "ASSUMPTION_USE_NOT_YET_VALID"),
        )
    if projected.expires_at_sequence is not None and clock >= projected.expires_at_sequence:
        return _build_denial_evaluation(
            assumption_id,
            "ASSUMPTION_USE_EXPIRED",
            _replace_traversed_code(self_state, "ASSUMPTION_USE_EXPIRED"),
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
    """Create a gate-failed version of a node that passed SELF_HISTORY.

    The node WAS reconstructed (it carries a valid event digest / sequence /
    proposition / scope / materiality / standing / validity interval), then
    failed a later gate (TERMINAL / NOT_ADMITTED / CHALLENGED / NOT_YET_VALID /
    EXPIRED). The full projected state is RETAINED so the receipt proves WHY the
    node failed (e.g. standing == EXPIRED, or active_challenge_ids non-empty);
    only its OWN assumption/evidence dependency edges are dropped, because those
    edges were never traversed (the DFS terminated at this node).
    """
    return UseTimeTraversedAssumption(
        assumption_id=state.assumption_id,
        validation_code=code,
        current_event_digest=state.current_event_digest,
        current_entity_sequence=state.current_entity_sequence,
        history_event_count=state.history_event_count,
        proposition_id=state.proposition_id,
        scope_ids=state.scope_ids,
        materiality=state.materiality,
        standing=state.standing,
        active_challenge_ids=state.active_challenge_ids,
        valid_from_sequence=state.valid_from_sequence,
        expires_at_sequence=state.expires_at_sequence,
        assumption_dependency_ids=(),
        evidence_dependency_ids=(),
        limitations=state.limitations,
        maximum_reuse_class=state.maximum_reuse_class,
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
