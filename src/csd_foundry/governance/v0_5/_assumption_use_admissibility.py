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


# Validation codes that, when they appear on an AssumptionUseEvaluation, mean
# the DFS terminated at an assumption-dependency failure (cycle, missing dep,
# history-invalid dep, or a gate failure inside a dependency). The terminal
# traversed record carries the matching gate code; ASSUMPTION_USE_DEPENDENCY_CYCLE
# is produced only when a cycle is detected.
_DFS_FAILURE_EVAL_CODES = frozenset(
    {
        "ASSUMPTION_USE_DEPENDENCY_CYCLE",
        "ASSUMPTION_USE_DEPENDENCY_MISSING",
        "ASSUMPTION_USE_HISTORY_INVALID",
        "ASSUMPTION_USE_TERMINAL",
        "ASSUMPTION_USE_NOT_ADMITTED",
        "ASSUMPTION_USE_CHALLENGED",
        "ASSUMPTION_USE_NOT_YET_VALID",
        "ASSUMPTION_USE_EXPIRED",
    }
)

# Validation codes that, when they appear on an AssumptionUseEvaluation, mean
# the root (self_state) failed a self-gate BEFORE any dependency edge was
# examined: the producer never started the DFS, so there are no traversed
# records, no cycle witness, and no evidence evaluations. The evaluation's
# validation_code equals self_state.validation_code for these codes.
# (DEPENDENCY_MISSING here is the top-level variant: a top-level required
# assumption that was never proposed.)
_SELF_GATE_FAILURE_EVAL_CODES = frozenset(
    {
        "ASSUMPTION_USE_MISSING",
        "ASSUMPTION_USE_HISTORY_INVALID",
        "ASSUMPTION_USE_TERMINAL",
        "ASSUMPTION_USE_NOT_ADMITTED",
        "ASSUMPTION_USE_CHALLENGED",
        "ASSUMPTION_USE_NOT_YET_VALID",
        "ASSUMPTION_USE_EXPIRED",
    }
)


# Codes whose value is determined by reconstruction availability rather than
# by gate precedence: they cannot be re-derived from projected state (the
# projected state is absent for these nodes) and are passed through unchanged.
_STRUCTURAL_NODE_CODES = frozenset(
    {
        "ASSUMPTION_USE_MISSING",
        "ASSUMPTION_USE_DEPENDENCY_MISSING",
        "ASSUMPTION_USE_HISTORY_INVALID",
    }
)


def _derive_node_code(node: UseTimeTraversedAssumption, clock: int) -> str:
    """Compute the exact expected validation_code for a node from its recorded
    projected state, by evaluating the gates in frozen precedence order.

    This is the inverse of the producer's gate cascade: TERMINAL > NOT_ADMITTED
    > CHALLENGED > NOT_YET_VALID > EXPIRED > NODE_PRESENT. A node whose recorded
    standing is terminal AND which carries active challenges must derive
    TERMINAL (terminal standing wins over the challenge gate).

    Structural codes (MISSING / DEPENDENCY_MISSING / HISTORY_INVALID) carry no
    projected state and are returned unchanged; they cannot be re-derived.
    """
    if node.validation_code in _STRUCTURAL_NODE_CODES:
        return node.validation_code  # structural; can't re-derive
    if node.standing in _TERMINAL_STANDINGS:
        return "ASSUMPTION_USE_TERMINAL"
    if node.standing not in _ACTIVE_STANDINGS:
        return "ASSUMPTION_USE_NOT_ADMITTED"
    if len(node.active_challenge_ids) > 0:
        return "ASSUMPTION_USE_CHALLENGED"
    if clock < cast(int, node.valid_from_sequence):
        return "ASSUMPTION_USE_NOT_YET_VALID"
    if node.expires_at_sequence is not None and clock >= node.expires_at_sequence:
        return "ASSUMPTION_USE_EXPIRED"
    return "ASSUMPTION_USE_NODE_PRESENT"


def _validate_node_code_against_state(node: UseTimeTraversedAssumption, clock: int) -> None:
    """Validate a node's validation_code against its recorded projected state.

    Derives the exact expected code via frozen gate precedence
    (:func:`_derive_node_code`) and requires the recorded code to equal it.
    This enforces precedence: a REJECTED assumption with active challenges must
    be TERMINAL, not CHALLENGED.

    Raises AssumptionGovernanceContractError on any mismatch. This is a
    receipt-level integrity check: it proves the recorded code is the code the
    producer would have produced from the recorded state.
    """
    expected = _derive_node_code(node, clock)
    if node.validation_code == expected:
        return

    # Map the specific mismatch to a stable, human-readable error code for the
    # common cases; fall back to a generic code otherwise.
    if expected == "ASSUMPTION_USE_TERMINAL":
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_TERMINAL_MISMATCH")
    if expected == "ASSUMPTION_USE_NOT_ADMITTED":
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_NOT_ADMITTED_MISMATCH")
    if expected == "ASSUMPTION_USE_CHALLENGED":
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_CHALLENGED_MISMATCH")
    if expected == "ASSUMPTION_USE_NOT_YET_VALID":
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_NOT_YET_VALID_MISMATCH")
    if expected == "ASSUMPTION_USE_EXPIRED":
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_EXPIRED_MISMATCH")
    if expected == "ASSUMPTION_USE_NODE_PRESENT":
        # The recorded code is a gate-failure code, but the projected state
        # passes every gate.
        if node.validation_code == "ASSUMPTION_USE_TERMINAL":
            raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_TERMINAL_MISMATCH")
        if node.validation_code == "ASSUMPTION_USE_NOT_ADMITTED":
            raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_NOT_ADMITTED_MISMATCH")
        if node.validation_code == "ASSUMPTION_USE_CHALLENGED":
            raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_CHALLENGED_MISMATCH")
        if node.validation_code == "ASSUMPTION_USE_NOT_YET_VALID":
            raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_NOT_YET_VALID_MISMATCH")
        if node.validation_code == "ASSUMPTION_USE_EXPIRED":
            raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_EXPIRED_MISMATCH")
        raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_PRESENT_MISMATCH")
    raise AssumptionGovernanceContractError("USE_NODE_CODE_STATE_MISMATCH")


def _replay_dfs_closure(
    self_state: UseTimeTraversedAssumption,
    traversed: tuple[UseTimeTraversedAssumption, ...],
    cycle_witness: tuple[str, ...],
    validation_code: str,
) -> tuple[int, str | None]:
    """Mechanically replay the DFS closure from the traversal records.

    Reconstructs the depth-first traversal that produced ``traversed`` starting
    from ``self_state.assumption_dependency_ids``, consuming records in order.
    Returns ``(edges_followed, terminal_code)`` where ``edges_followed`` is the
    exact number of assumption-dependency edges that were actually followed
    (i.e. traversed across) before the DFS terminated, and ``terminal_code`` is
    the ``validation_code`` of the record at which the DFS terminated (or
    ``"ASSUMPTION_USE_DEPENDENCY_CYCLE"`` for a cycle), or ``None`` if the DFS
    completed without terminating. Raises on any inconsistency between the
    records and the mechanical replay.

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

    The DFS disposition is derived from ``validation_code`` (the
    AssumptionUseEvaluation's own code), NOT from the overall ALLOW/DENY
    result: an evidence-phase DENY (a code beginning with ``EVIDENCE_``) occurs
    AFTER the DFS completed successfully, so the replay must treat it the same
    as a successful ALLOW traversal.
    """
    records: list[UseTimeTraversedAssumption] = list(traversed)
    record_idx = 0
    replay_terminated = False
    detected_cycle_witness: tuple[str, ...] = ()

    # The validation_code of the terminal record (the inherited denial code the
    # producer propagated up to the evaluation), or ASSUMPTION_USE_DEPENDENCY_CYCLE
    # for cycles, or None if the DFS completed. Captured at termination time so
    # callers can bind the evaluation's validation_code to it.
    terminal_code: str | None = None

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
        nonlocal replay_terminated, edges_followed, detected_cycle_witness, terminal_code

        if replay_terminated:
            return

        # Cycle: node is already on the active DFS stack.
        if node_id in stack:
            raw_cycle = tuple(stack[stack.index(node_id) :] + [node_id])
            detected_cycle_witness = canonical_cycle_witness(raw_cycle)
            replay_terminated = True
            terminal_code = "ASSUMPTION_USE_DEPENDENCY_CYCLE"
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
            # Terminal record: DFS stops here. Capture the terminal node's code
            # as the inherited denial propagated up to the evaluation.
            replay_terminated = True
            terminal_code = rec.validation_code

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

    # Derive the DFS disposition from the evaluation's validation_code rather
    # than from the overall ALLOW/DENY result. An evidence-phase DENY (a D2 code
    # starting with "EVIDENCE_") happens AFTER the DFS completed successfully,
    # so it must be treated as a completed traversal (just like ALLOW), not as a
    # traversal that failed to terminate.
    dfs_terminated = validation_code in _DFS_FAILURE_EVAL_CODES
    if dfs_terminated:
        # DFS terminated at an assumption-dependency failure: exactly a prefix of
        # records is consumed, up to and including the terminal record (or zero
        # records if the DFS never reached any dep, e.g. the producer detected a
        # cycle directly on a root child before consuming any record).
        if not replay_terminated and len(records) > 0:
            raise AssumptionGovernanceContractError("USE_EVAL_DENY_TRAVERSAL_NOT_TERMINATED")
        # Records after the consumed prefix would mean the producer kept
        # traversing past a terminal node, which is impossible.
        if record_idx != len(records) and replay_terminated:
            # The terminal record may be the last consumed one; any remaining
            # records beyond it are illegal.
            raise AssumptionGovernanceContractError("USE_EVAL_DENY_TRAVERSAL_HAS_LEFTOVER_RECORDS")
    else:
        # ALLOW, ALLOWABLE-with-self-gate-DENY, or a D2 evidence-phase DENY:
        # the DFS completed without terminating early, all records were consumed,
        # and no cycle was detected.
        if replay_terminated:
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_TRAVERSAL_TERMINATED")
        if record_idx != len(records):
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_RECORDS_NOT_CONSUMED")
        if cycle_witness != ():
            raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_CYCLE_PRESENT")

    return edges_followed, terminal_code


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
        #     RETAINED so the receipt proves WHY it failed, INCLUDING its own
        #     assumption_dependency_ids and evidence_dependency_ids. These IDs are
        #     part of the authoritative projected state and must be retained; the
        #     DFS replay still terminates at this node (it never follows these
        #     edges), because the replay stops immediately on any non-PRESENT
        #     record.
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
            # Reconstructed then failed a gate: full projected state is RETAINED,
            # including the node's own assumption_dependency_ids and
            # evidence_dependency_ids. These are part of the authoritative
            # projected state; the DFS replay terminates at any non-PRESENT
            # record, so the retained IDs do NOT cause the replay to traverse
            # them.
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
        # Rebuild the D2 receipt from its own canonical fields and require the
        # rebuilt receipt to equal the supplied one. This validates BOTH the
        # canonical content (allowed / code / digests / dependencies /
        # advisories) AND the receipt_digest, without modifying D2's public
        # contract: any field-level tamper that leaves the receipt_digest stale
        # (or that mutates the digest alone) is rejected here.
        rebuilt_receipt = EvidenceAdmissibilityReceipt.build(
            allowed=self.receipt.allowed,
            code=self.receipt.code,
            request=self.request,
            evidence_event_digest=self.receipt.evidence_event_digest,
            authority_policy_digest=self.receipt.authority_policy_digest,
            challenge_policy_digest=self.receipt.challenge_policy_digest,
            dependency_event_digests=self.receipt.dependency_event_digests,
            advisory_codes=self.receipt.advisory_codes,
        )
        if rebuilt_receipt != self.receipt:
            raise AssumptionGovernanceContractError("USE_EVIDENCE_EVAL_RECEIPT_REBUILD_MISMATCH")

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

        # Top-level self_state must use MISSING, not DEPENDENCY_MISSING.
        # DEPENDENCY_MISSING is reserved for traversed dependency records.
        if self.self_state.validation_code == "ASSUMPTION_USE_DEPENDENCY_MISSING":
            raise AssumptionGovernanceContractError("USE_EVAL_TOPLEVEL_DEPENDENCY_MISSING")

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
            _edges, terminal_code = _replay_dfs_closure(
                self.self_state,
                self.traversed_dependencies,
                self.cycle_witness,
                self.validation_code,
            )
            # Fix #3: bind the DFS terminal outcome to the evaluation's own
            # inherited denial code. If the DFS terminated at a dependency
            # failure, the evaluation's validation_code MUST equal the terminal
            # node's validation_code (the inherited denial). If the DFS
            # completed, the evaluation's code must be ALLOW or an evidence D2
            # code (the evidence phase runs only after a completed DFS).
            if terminal_code is not None:
                if self.validation_code != terminal_code:
                    raise AssumptionGovernanceContractError("USE_EVAL_DFS_TERMINAL_CODE_MISMATCH")
            else:
                # DFS completed: the evaluation's code must be ALLOW or an
                # evidence-phase D2 code (a code beginning with "EVIDENCE_").
                dfs_completed_ok = (
                    self.validation_code == "ASSUMPTION_USE_ALLOWED"
                    or self.validation_code.startswith("EVIDENCE_")
                )
                if not dfs_completed_ok:
                    raise AssumptionGovernanceContractError(
                        "USE_EVAL_DFS_COMPLETED_NON_ALLOW_NON_EVIDENCE_CODE"
                    )
        else:
            # Root did not pass SELF_HISTORY (or failed a self-gate): no DFS ran,
            # so there must be no traversed records and no cycle witness.
            if self.traversed_dependencies != ():
                raise AssumptionGovernanceContractError("USE_EVAL_SELF_FAILED_HAS_TRAVERSED")
            if self.cycle_witness != ():
                raise AssumptionGovernanceContractError("USE_EVAL_SELF_FAILED_HAS_CYCLE")
            # Fix #3: when self failed a gate (no DFS ran), the evaluation's
            # validation_code must be the self-gate code carried on self_state.
            if self.validation_code != self.self_state.validation_code:
                raise AssumptionGovernanceContractError("USE_EVAL_SELF_GATE_CODE_MISMATCH")

    def _validate_evidence_closure(self, clock: int) -> None:
        """Mechanically replay evidence dependency coverage/order/fail-fast.

        Builds the expected evidence reference sequence from self_state +
        traversed_dependencies (the nodes the DFS actually reached in
        first-discovery order, self first), enumerating each NODE_PRESENT
        node's ``evidence_dependency_ids`` in canonical order. Each produces an
        expected ``(owner_assumption_id, evidence_id)`` pair.

        Then compares against the actual ``evidence_evaluations``:

        * If ``validation_code`` is a self-gate failure or a DFS failure:
          ``evidence_evaluations`` must be empty ().
        * If ``validation_code`` is ALLOW: ``evidence_evaluations`` must exactly
          equal the complete expected sequence; every ``receipt.allowed`` must
          be True; every owner / evidence_id must match.
        * If ``validation_code`` is an evidence D2 code: ``evidence_evaluations``
          must be the exact prefix of the expected sequence through the first
          denying receipt; the last ``receipt.allowed`` must be False; the last
          ``receipt.code`` must equal ``validation_code``; no evaluations may
          follow the denial.

        Requires ``clock`` (the binding's logical clock) from the parent
        decision; this method is invoked from
        ``AssumptionUseAdmissibilityDecision.__post_init__``.
        """
        # Build the expected evidence reference sequence in the producer's order:
        # self first, then traversed_dependencies in DFS first-discovery order.
        # Only NODE_PRESENT nodes carry evidence_dependency_ids that the
        # evidence phase evaluates; gate-failed nodes terminate the DFS and
        # never reach the evidence phase.
        expected_pairs: list[tuple[str, str]] = []
        node_sequence: list[UseTimeTraversedAssumption] = []
        if self.self_state.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
            node_sequence.append(self.self_state)
            for td in self.traversed_dependencies:
                if td.validation_code == "ASSUMPTION_USE_NODE_PRESENT":
                    node_sequence.append(td)
        for node in node_sequence:
            for evidence_id in node.evidence_dependency_ids:
                expected_pairs.append((node.assumption_id, evidence_id))
        expected = tuple(expected_pairs)

        actual = tuple(
            (ee.owner_assumption_id, ee.receipt.evidence_id) for ee in self.evidence_evaluations
        )

        code = self.validation_code

        if code in _SELF_GATE_FAILURE_EVAL_CODES or code in _DFS_FAILURE_EVAL_CODES:
            # Self-gate or DFS failure: the evidence phase never ran.
            if self.evidence_evaluations != ():
                raise AssumptionGovernanceContractError("USE_EVAL_FAILURE_HAS_EVIDENCE_EVALUATIONS")
            return

        if code == "ASSUMPTION_USE_ALLOWED":
            # ALLOW: every declared evidence dependency must have been evaluated,
            # in the exact expected order, and every receipt must be allowed.
            if actual != expected:
                raise AssumptionGovernanceContractError("USE_EVAL_ALLOW_EVIDENCE_SEQUENCE_MISMATCH")
            for ee in self.evidence_evaluations:
                if not ee.receipt.allowed:
                    raise AssumptionGovernanceContractError(
                        "USE_EVAL_ALLOW_EVIDENCE_RECEIPT_DENIED"
                    )
            return

        if code.startswith("EVIDENCE_"):
            # Evidence D2 DENY: evaluations must be the exact prefix of the
            # expected sequence through (and including) the first denying
            # receipt. The last receipt must be denied; its code must equal the
            # evaluation's validation_code; nothing may follow the denial.
            if len(self.evidence_evaluations) == 0:
                raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_DENY_NO_EVALUATIONS")
            last_ee = self.evidence_evaluations[-1]
            if last_ee.receipt.allowed:
                raise AssumptionGovernanceContractError(
                    "USE_EVAL_EVIDENCE_DENY_LAST_RECEIPT_ALLOWED"
                )
            if last_ee.receipt.code != code:
                raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_DENY_CODE_MISMATCH")
            # The prefix must match the expected sequence exactly (coverage +
            # ordering). The prefix length equals the number of evaluations
            # actually performed (all allowed, then the final denial).
            prefix_len = len(self.evidence_evaluations)
            if prefix_len > len(expected):
                raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_DENY_PREFIX_TOO_LONG")
            if actual != expected[:prefix_len]:
                raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_DENY_SEQUENCE_MISMATCH")
            # Every receipt before the last (denying) one must be allowed.
            for ee in self.evidence_evaluations[:-1]:
                if not ee.receipt.allowed:
                    raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_DENY_EARLY_DENIAL")
            return

        # Any other code here is structurally impossible (the __post_init__
        # DFS-binding check above should have caught it), but defend in depth.
        raise AssumptionGovernanceContractError("USE_EVAL_EVIDENCE_CLOSURE_UNKNOWN_CODE")

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

        # Validate each traversed node's validation_code against its recorded
        # projected state and the binding's logical clock. This catches a
        # node whose code disagrees with its own recorded standing / challenge
        # set / temporal interval (e.g. ASSUMPTION_USE_TERMINAL with a
        # standing of ADMITTED), and enforces the exact frozen gate precedence
        # (a REJECTED node with active challenges must be TERMINAL, not CHALLENGED).
        clock = self.binding.logical_clock_sequence
        for ev in self.evaluated_assumptions:
            _validate_node_code_against_state(ev.self_state, clock)
            for td in ev.traversed_dependencies:
                _validate_node_code_against_state(td, clock)

        # Fix #1: mechanically replay evidence dependency coverage/order/
        # fail-fast for each evaluation. Requires the binding's clock to
        # re-derive each node's gate state. The clock is needed because the
        # evaluation itself is clock-agnostic (it has no binding).
        for ev in self.evaluated_assumptions:
            ev._validate_evidence_closure(clock)

        # Recompute work counters from children.
        self._validate_work_counters()

        # Decision-wide repeated-node state consistency: for every occurrence
        # of an assumption ID across all self_state and traversed_dependencies,
        # require authoritative state fields to equal the first occurrence.
        self._validate_node_consistency()

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
                edges_followed, _terminal_code = _replay_dfs_closure(
                    root, ev.traversed_dependencies, ev.cycle_witness, ev.validation_code
                )
                total_dep_edges += edges_followed
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

    def _validate_node_consistency(self) -> None:
        """Require that repeated assumption IDs carry identical authoritative state.

        Across all self_state and traversed_dependencies in every evaluation,
        the first occurrence of each assumption ID establishes the canonical
        authoritative state. Later occurrences must match on all authoritative
        fields (current_event_digest, entity_sequence, history_event_count,
        proposition_id, scope_ids, materiality, standing, challenges, temporal,
        dependency/evidence IDs, limitations, reuse class).

        validation_code is NOT compared because MISSING vs DEPENDENCY_MISSING
        depends on role (top-level vs dependency), not on the assumption itself.
        """
        canonical: dict[str, UseTimeTraversedAssumption] = {}
        for ev in self.evaluated_assumptions:
            for node in (ev.self_state, *ev.traversed_dependencies):
                existing = canonical.get(node.assumption_id)
                if existing is None:
                    canonical[node.assumption_id] = node
                    continue
                # Compare authoritative state fields (exclude validation_code).
                for field_name in (
                    "current_event_digest",
                    "current_entity_sequence",
                    "history_event_count",
                    "proposition_id",
                    "scope_ids",
                    "materiality",
                    "standing",
                    "active_challenge_ids",
                    "valid_from_sequence",
                    "expires_at_sequence",
                    "assumption_dependency_ids",
                    "evidence_dependency_ids",
                    "limitations",
                    "maximum_reuse_class",
                ):
                    if getattr(node, field_name) != getattr(existing, field_name):
                        raise AssumptionGovernanceContractError(
                            "USE_DECISION_NODE_CONSISTENCY_MISMATCH",
                            detail=f"{node.assumption_id}.{field_name}",
                        )

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
            edges_followed, _terminal_code = _replay_dfs_closure(
                root, ev.traversed_dependencies, ev.cycle_witness, ev.validation_code
            )
            total_dep_edges += edges_followed
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
    node failed (e.g. standing == EXPIRED, or active_challenge_ids non-empty),
    INCLUDING its own assumption_dependency_ids and evidence_dependency_ids,
    which are part of the authoritative projected state. The DFS replay
    terminates immediately on any non-PRESENT record, so the retained edges are
    NOT traversed.
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
        assumption_dependency_ids=state.assumption_dependency_ids,
        evidence_dependency_ids=state.evidence_dependency_ids,
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
