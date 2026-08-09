"""Frozen admission-time dependency validator for assumption governance (I1-C / D3.2-A3.1).

Deterministically validate the immutable dependencies of a candidate assumption at
admission time (pre-ADMIT), against exact supplied registry snapshots, before any
assumption-registry append or root advancement.

The validator is authoritative **relative to its supplied validated registry
snapshots**. It mechanically rebinds the candidate history to the store's
authoritative reconstruction via canonical-byte equality, captures start/end
snapshot roots to detect concurrent mutation, and never writes or advances any
registry root.

Semantic boundaries (frozen):

* **Phase order**: candidate/self history → assumption dependency graph →
  evidence dependencies. An assumption missing/cycle/history failure produces
  zero evidence eligibility evaluations. The ``ACTIVE_CHALLENGES`` phase is
  deliberately unevaluated in A3.1.
* **Dependency authority**: dependencies come from the reconstructed immutable
  ``PROPOSE`` state, never caller tuples.
* **Candidate identity**: the candidate history must be canonical-byte identical
  to the store's authoritative reconstruction for the same ``assumption_id``.
* **Exact pre-ADMIT state**: the authoritative assumption must be ``PROPOSED``,
  at entity sequence 1; the candidate ADMIT is sequence 2 at a logical time
  strictly after the PROPOSE clock.
* **Assumption graph**: every reachable referenced assumption must exist and
  reconstruct canonically. Direct or indirect directed cycles are rejected with
  a canonical directed witness.
* **Evidence dependencies**: evaluated through the existing
  ``evaluate_evidence_admission_eligibility`` A0 gate, in canonical
  ``evidence_id`` order, fail-fast on the first ineligible dependency.
* **Snapshot stability**: start and end roots must match. Instability raises an
  exception, not a receipt.
* **No writes, no root advancement, no retry.**

No public v0.5 schema, catalog, or vector changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionGovernanceContractError,
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
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    EvidenceAdmissionEligibilityDecision,
    evaluate_evidence_admission_eligibility,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import RegistryStore, RegistryStoreError

_DEPENDENCY_VALIDATION_SCHEMA_VERSION = "assumption-dependency-validation/1"
_DEPENDENCY_VALIDATION_DOMAIN = "ASSUMPTION_DEPENDENCY_VALIDATION"

# Closed traversal-code vocabulary.
_TRAVERSAL_CODES = frozenset(
    {"DEPENDENCY_PRESENT", "ASSUMPTION_DEPENDENCY_MISSING", "ASSUMPTION_DEPENDENCY_HISTORY_INVALID"}
)

# Closed top-level validation-code vocabulary.
# PASS + all assumption-phase denial codes + all A0 evidence denial codes.
_ASSUMPTION_DENY_CODES = frozenset(
    {
        "ASSUMPTION_DEPENDENCY_MISSING",
        "ASSUMPTION_DEPENDENCY_HISTORY_INVALID",
        "ASSUMPTION_DEPENDENCY_CYCLE",
    }
)
_PASS_CODE = "DEPENDENCY_VALIDATION_PASSED"


def _require_canonical_dependency_ids(value: object, code: str) -> tuple[str, ...]:
    """Require a canonical dependency-ID tuple: exact tuple type, exact string
    members, valid tokens, sorted ascending, no duplicates."""
    if type(value) is not tuple:
        raise AssumptionGovernanceContractError(code)
    for item in value:
        if type(item) is not str:
            raise AssumptionGovernanceContractError(code)
        _require_token(item, code)
    if tuple(sorted(value)) != value:
        raise AssumptionGovernanceContractError(code)
    if len(set(value)) != len(value):
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


@dataclass(frozen=True, slots=True)
class TraversedDependency:
    """One traversed assumption dependency node with its outcome.

    For ``DEPENDENCY_PRESENT``: ``current_entity_sequence`` and
    ``current_event_digest`` come from the projected state;
    ``direct_dependency_ids`` is the canonical tuple from the projection.

    For ``ASSUMPTION_DEPENDENCY_MISSING``: both sequence and digest are ``None``
    and ``direct_dependency_ids`` is ``()``.

    For ``ASSUMPTION_DEPENDENCY_HISTORY_INVALID``: sequence and digest come from
    the independently obtained entity head (the head exists, but the history
    cannot be validly reconstructed/projected); ``direct_dependency_ids`` is ``()``.
    """

    assumption_id: str
    validation_code: str
    current_entity_sequence: int | None
    current_event_digest: str | None
    direct_dependency_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_token(self.assumption_id, "TRAVERSED_DEPENDENCY_ID_INVALID")
        if type(self.validation_code) is not str:
            raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_CODE_INVALID")
        if self.validation_code not in _TRAVERSAL_CODES:
            raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_CODE_INVALID")
        if self.validation_code == "DEPENDENCY_PRESENT":
            if self.current_entity_sequence is None or self.current_event_digest is None:
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_PRESENT_INCOMPLETE")
            if type(self.current_entity_sequence) is not int or isinstance(
                self.current_entity_sequence, bool
            ):
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_SEQUENCE_INVALID")
            if self.current_entity_sequence < 1:
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_SEQUENCE_INVALID")
            _require_digest(self.current_event_digest, "TRAVERSED_DEPENDENCY_DIGEST_INVALID")
            _require_canonical_dependency_ids(
                self.direct_dependency_ids, "TRAVERSED_DEPENDENCY_DEPS_INVALID"
            )
            # A valid Assumption projection already prohibits self-dependency.
            if self.assumption_id in self.direct_dependency_ids:
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_SELF_REFERENCE")
        elif self.validation_code == "ASSUMPTION_DEPENDENCY_MISSING":
            if self.current_entity_sequence is not None or self.current_event_digest is not None:
                raise AssumptionGovernanceContractError(
                    "TRAVERSED_DEPENDENCY_MISSING_FIELDS_PRESENT"
                )
            if self.direct_dependency_ids != ():
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_MISSING_DEPS_PRESENT")
        else:  # HISTORY_INVALID
            if self.current_entity_sequence is None or self.current_event_digest is None:
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_HISTORY_INCOMPLETE")
            if type(self.current_entity_sequence) is not int or isinstance(
                self.current_entity_sequence, bool
            ):
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_SEQUENCE_INVALID")
            if self.current_entity_sequence < 1:
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_SEQUENCE_INVALID")
            _require_digest(self.current_event_digest, "TRAVERSED_DEPENDENCY_DIGEST_INVALID")
            if self.direct_dependency_ids != ():
                raise AssumptionGovernanceContractError("TRAVERSED_DEPENDENCY_HISTORY_DEPS_PRESENT")

    def to_json_value(self) -> dict[str, object]:
        return {
            "assumption_id": self.assumption_id,
            "validation_code": self.validation_code,
            "current_entity_sequence": self.current_entity_sequence,
            "current_event_digest": self.current_event_digest,
            "direct_dependency_ids": list(self.direct_dependency_ids),
        }


@dataclass(frozen=True, slots=True)
class DependencyValidationReceipt:
    """Self-digesting admission-time dependency validation receipt.

    Mechanically validates its own traversal evidence by replaying the DFS in
    ``__post_init__``, ensuring every reachable dependency was traversed (for
    PASS/evidence-DENY) or that the traversal is the exact deterministic prefix
    through the first failure (for assumption-DENY).
    """

    # Candidate identity + exact predecessor binding
    assumption_id: str
    candidate_predecessor_event_digest: str
    candidate_entity_sequence: int
    event_sequence: int
    # Supplied snapshot roots
    assumption_registry_root: str
    evidence_registry_root: str
    # Immutable direct dependency sets
    assumption_dependency_ids: tuple[str, ...]
    evidence_dependency_ids: tuple[str, ...]
    # Phase 1: assumption DFS (first-discovery preorder)
    traversed_dependencies: tuple[TraversedDependency, ...]
    # Cycle evidence
    cycle_witness: tuple[str, ...]
    # Phase 2: evidence eligibility (canonical evidence_id order)
    evidence_eligibility_decisions: tuple[EvidenceAdmissionEligibilityDecision, ...]
    # Result
    validation_code: str
    validation_result: str
    receipt_digest: str

    def __post_init__(self) -> None:
        # --- Scalar validation ---
        _require_token(self.assumption_id, "DEPENDENCY_RECEIPT_ASSUMPTION_ID_INVALID")
        _require_digest(
            self.candidate_predecessor_event_digest,
            "DEPENDENCY_RECEIPT_PREDECESSOR_DIGEST_INVALID",
        )
        if (
            type(self.candidate_entity_sequence) is not int
            or isinstance(self.candidate_entity_sequence, bool)
            or self.candidate_entity_sequence != 2
        ):
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_CANDIDATE_SEQUENCE_INVALID")
        if (
            type(self.event_sequence) is not int
            or isinstance(self.event_sequence, bool)
            or self.event_sequence < 1
        ):
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_EVENT_SEQUENCE_INVALID")
        _require_digest(self.assumption_registry_root, "DEPENDENCY_RECEIPT_ASSUMPTION_ROOT_INVALID")
        _require_digest(self.evidence_registry_root, "DEPENDENCY_RECEIPT_EVIDENCE_ROOT_INVALID")
        _require_canonical_dependency_ids(
            self.assumption_dependency_ids, "DEPENDENCY_RECEIPT_ASSUMPTION_DEPS_INVALID"
        )
        _require_canonical_dependency_ids(
            self.evidence_dependency_ids, "DEPENDENCY_RECEIPT_EVIDENCE_DEPS_INVALID"
        )
        if type(self.traversed_dependencies) is not tuple:
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_TRAVERSED_INVALID")
        if type(self.cycle_witness) is not tuple:
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_CYCLE_WITNESS_INVALID")
        if type(self.evidence_eligibility_decisions) is not tuple:
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_EVIDENCE_DECISIONS_INVALID")
        for ev in self.evidence_eligibility_decisions:
            if type(ev) is not EvidenceAdmissionEligibilityDecision:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_DECISION_TYPE_INVALID"
                )
        if self.validation_result not in ("PASS", "DENY"):
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_RESULT_INVALID")

        # --- DFS closure replay (mechanical traversal validation) ---
        self._validate_traversal_closure()

        # --- Phase/result consistency ---
        self._validate_phase_result_consistency()

        # --- A0 decision binding ---
        self._validate_evidence_decisions()

        # --- Self-digest ---
        _require_self_digest(
            _DEPENDENCY_VALIDATION_DOMAIN,
            self._unsigned_value(),
            self.receipt_digest,
            "DEPENDENCY_RECEIPT_DIGEST_MISMATCH",
        )

    def _validate_traversal_closure(self) -> None:
        """Replay the DFS over the receipt's own dependency graph.

        Once replay encounters a terminal outcome (MISSING, HISTORY_INVALID, or
        cycle), the entire replay terminates — matching the runtime fail-fast
        semantics. No sibling dependencies are replayed after a terminal outcome.
        """
        records = list(self.traversed_dependencies)
        record_idx = 0
        replay_terminated = False

        def _replay_dfs(
            node: str, stack: list[str], stack_index: dict[str, int], visited: set[str]
        ) -> None:
            nonlocal record_idx, replay_terminated

            if replay_terminated:
                return

            # Check active stack before consuming a record.
            if node in stack_index:
                # Cycle: derive witness from the stack.
                i = stack_index[node]
                raw_cycle = tuple(stack[i:] + [node])
                witness = canonical_cycle_witness(raw_cycle)
                if self.cycle_witness != witness:
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_CYCLE_WITNESS_MISMATCH"
                    )
                if self.validation_code != "ASSUMPTION_DEPENDENCY_CYCLE":
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_CYCLE_CODE_MISMATCH"
                    )
                replay_terminated = True
                return

            if node in visited:
                return

            # Consume the next traversal record.
            if record_idx >= len(records):
                raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_TRAVERSAL_INCOMPLETE")
            record = records[record_idx]
            record_idx += 1
            if record.assumption_id != node:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_TRAVERSAL_ORDER_MISMATCH"
                )
            if record.validation_code == "DEPENDENCY_PRESENT":
                # Recurse through its direct deps.
                stack_index[node] = len(stack)
                stack.append(node)
                for child in record.direct_dependency_ids:
                    _replay_dfs(child, stack, stack_index, visited)
                    if replay_terminated:
                        break
                if not replay_terminated:
                    stack.pop()
                    del stack_index[node]
                    visited.add(node)
            else:
                # MISSING or HISTORY_INVALID: terminal — stop the entire replay.
                replay_terminated = True
                return

        # Seed DFS from candidate's direct deps.
        stack: list[str] = [self.assumption_id]
        stack_index: dict[str, int] = {self.assumption_id: 0}
        visited: set[str] = set()
        for dep in self.assumption_dependency_ids:
            if replay_terminated:
                break
            _replay_dfs(dep, stack, stack_index, visited)

        # Consumption exactness: all cases require exact prefix consumed.
        if record_idx != len(records):
            raise AssumptionGovernanceContractError(
                "DEPENDENCY_RECEIPT_TRAVERSAL_HAS_EXTRA_RECORDS"
            )

    def _validate_phase_result_consistency(self) -> None:
        is_pass = self.validation_result == "PASS"
        is_cycle = self.validation_code == "ASSUMPTION_DEPENDENCY_CYCLE"
        is_assumption_deny = self.validation_code in _ASSUMPTION_DENY_CODES
        is_evidence_deny = self.validation_result == "DENY" and not is_assumption_deny

        if is_pass:
            if self.validation_code != _PASS_CODE:
                raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_PASS_CODE_MISMATCH")
            if self.cycle_witness != ():
                raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_PASS_CYCLE_PRESENT")
            # Every traversed dep must be PRESENT.
            for td in self.traversed_dependencies:
                if td.validation_code != "DEPENDENCY_PRESENT":
                    raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_PASS_HAS_FAILURE")
        elif is_assumption_deny:
            # Assumption-phase denial: no evidence decisions.
            if self.evidence_eligibility_decisions != ():
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_ASSUMPTION_DENY_HAS_EVIDENCE"
                )
            # Cycle-specific witness check.
            if is_cycle:
                if self.cycle_witness == ():
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_CYCLE_WITNESS_EMPTY"
                    )
            else:
                if self.cycle_witness != ():
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_NONCYCLE_WITNESS_PRESENT"
                    )
        elif is_evidence_deny:
            # Evidence-phase denial: assumption graph complete.
            if self.cycle_witness != ():
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_DENY_CYCLE_PRESENT"
                )
            for td in self.traversed_dependencies:
                if td.validation_code != "DEPENDENCY_PRESENT":
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_EVIDENCE_DENY_HAS_FAILURE"
                    )
            # Validation code must match one of the A0 denial codes or be an evidence code.
            # We check this loosely here: the evidence-decision binding below enforces specifics.
        else:
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_RESULT_CODE_INCONSISTENT")

    def _validate_evidence_decisions(self) -> None:
        """Validate A0 decision bindings and canonical ordering.

        For PASS: decisions must exactly equal evidence_dependency_ids (same IDs,
        same order, all eligible). For evidence-DENY: decisions must be the exact
        canonical prefix of evidence_dependency_ids through the first ineligible.
        """
        decision_ids = tuple(dec.evidence_id for dec in self.evidence_eligibility_decisions)

        if self.validation_result == "PASS":
            # Exact prefix equality: decisions == direct deps.
            if decision_ids != self.evidence_dependency_ids:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_PREFIX_MISMATCH"
                )
            for dec in self.evidence_eligibility_decisions:
                if not dec.eligible:
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_PASS_HAS_INELIGIBLE_EVIDENCE"
                    )
        elif (
            self.validation_result == "DENY" and self.validation_code not in _ASSUMPTION_DENY_CODES
        ):
            # Evidence-phase denial: decisions are canonical prefix through first ineligible.
            if self.evidence_eligibility_decisions == ():
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_DENY_NO_DECISIONS"
                )
            # Exact prefix: decision_ids == evidence_dependency_ids[:len(decision_ids)].
            expected_prefix = self.evidence_dependency_ids[: len(decision_ids)]
            if decision_ids != expected_prefix:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_PREFIX_MISMATCH"
                )
            # All preceding must be eligible; final must be ineligible.
            for dec in self.evidence_eligibility_decisions[:-1]:
                if not dec.eligible:
                    raise AssumptionGovernanceContractError(
                        "DEPENDENCY_RECEIPT_EVIDENCE_DENY_NOT_FAILFAST"
                    )
            final = self.evidence_eligibility_decisions[-1]
            if final.eligible:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_DENY_FINAL_ELIGIBLE"
                )
            if self.validation_code != final.code:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_DENY_CODE_MISMATCH"
                )

        # Every decision must bind correctly.
        evidence_id_set = set(self.evidence_dependency_ids)
        for dec in self.evidence_eligibility_decisions:
            if dec.evidence_id not in evidence_id_set:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_ID_NOT_DIRECT_DEP"
                )
            if dec.evaluated_at_sequence != self.event_sequence:
                raise AssumptionGovernanceContractError(
                    "DEPENDENCY_RECEIPT_EVIDENCE_SEQUENCE_MISMATCH"
                )
            if dec.evidence_registry_root != self.evidence_registry_root:
                raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_EVIDENCE_ROOT_MISMATCH")

        # Canonical evidence_id order.
        dec_ids = [dec.evidence_id for dec in self.evidence_eligibility_decisions]
        if dec_ids != sorted(dec_ids):
            raise AssumptionGovernanceContractError("DEPENDENCY_RECEIPT_EVIDENCE_NOT_CANONICAL")

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _DEPENDENCY_VALIDATION_SCHEMA_VERSION,
            "assumption_dependency_ids": list(self.assumption_dependency_ids),
            "assumption_id": self.assumption_id,
            "assumption_registry_root": self.assumption_registry_root,
            "candidate_entity_sequence": self.candidate_entity_sequence,
            "candidate_predecessor_event_digest": self.candidate_predecessor_event_digest,
            "cycle_witness": list(self.cycle_witness),
            "evidence_dependency_ids": list(self.evidence_dependency_ids),
            "evidence_eligibility_decisions": [
                dec.to_json_value() for dec in self.evidence_eligibility_decisions
            ],
            "evidence_registry_root": self.evidence_registry_root,
            "event_sequence": self.event_sequence,
            "traversed_dependencies": [td.to_json_value() for td in self.traversed_dependencies],
            "validation_code": self.validation_code,
            "validation_result": self.validation_result,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "receipt_digest": self.receipt_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def validate_assumption_dependencies(
    *,
    store: RegistryStore,
    candidate_history: tuple[RegistryEvent, ...],
    event_sequence: int,
) -> DependencyValidationReceipt:
    """Validate the immutable dependencies of a candidate assumption at admission time.

    Requires the authoritative PROPOSE state, traverses all reachable assumption
    dependencies (existence + reconstructability + acyclicity), evaluates direct
    evidence dependencies through the A0 gate, and returns a self-digesting
    receipt. Snapshot instability raises an exception, not a receipt.

    Raises:
        AssumptionGovernanceContractError: on detached history, invalid pre-ADMIT
            state, or snapshot instability.
        AssumptionRegistryError: if the candidate or dependency history has a
            chain defect (re-raised from the lifecycle layer).
    """
    # --- STEP 0: Capture start roots ---
    assumption_root_start = store.snapshot("ASSUMPTION").root_digest
    evidence_root_start = store.snapshot("EVIDENCE_UNIT").root_digest

    # --- STEP 1: Canonical-byte candidate rebinding ---
    if type(candidate_history) is not tuple:
        raise AssumptionGovernanceContractError("DEPENDENCY_VALIDATION_HISTORY_NOT_TUPLE")
    for event in candidate_history:
        if type(event) is not RegistryEvent:
            raise AssumptionGovernanceContractError(
                "DEPENDENCY_VALIDATION_HISTORY_EVENT_TYPE_INVALID"
            )

    projected = project_assumption_history(candidate_history)
    if projected is None:
        raise AssumptionGovernanceContractError("DEPENDENCY_VALIDATION_HISTORY_EMPTY")

    assumption_id = projected.assumption_id
    authoritative_history = store.reconstruct_entity("ASSUMPTION", assumption_id)

    if len(candidate_history) != len(authoritative_history):
        raise AssumptionGovernanceContractError("DEPENDENCY_VALIDATION_HISTORY_LENGTH_MISMATCH")
    for supplied, authoritative in zip(candidate_history, authoritative_history, strict=True):
        if type(supplied) is not RegistryEvent:
            raise AssumptionGovernanceContractError(
                "DEPENDENCY_VALIDATION_HISTORY_EVENT_TYPE_INVALID"
            )
        if supplied.canonical_bytes != authoritative.canonical_bytes:
            raise AssumptionGovernanceContractError(
                "DEPENDENCY_VALIDATION_HISTORY_CANONICAL_BYTES_MISMATCH"
            )

    # Re-project the AUTHORITATIVE history.
    propose_state = project_assumption_history(authoritative_history)
    if propose_state is None:
        raise AssumptionGovernanceContractError("DEPENDENCY_VALIDATION_AUTHORITATIVE_HISTORY_EMPTY")

    # --- STEP 2: Exact pre-ADMIT state + advancing logical time ---
    if propose_state.standing != "PROPOSED":
        raise AssumptionGovernanceContractError(
            "DEPENDENCY_VALIDATION_NOT_PROPOSED",
            detail=f"standing={propose_state.standing}",
        )
    if propose_state.current_entity_sequence != 1:
        raise AssumptionGovernanceContractError(
            "DEPENDENCY_VALIDATION_NOT_GENESIS",
            detail=f"sequence={propose_state.current_entity_sequence}",
        )
    if event_sequence <= propose_state.last_clock_sequence:
        raise AssumptionGovernanceContractError(
            "DEPENDENCY_VALIDATION_CLOCK_NOT_ADVANCING",
            detail=(
                f"event_sequence={event_sequence}"
                f" <= propose_clock={propose_state.last_clock_sequence}"
            ),
        )

    candidate_predecessor_event_digest = propose_state.current_event_digest
    assumption_dependency_ids = propose_state.assumption_dependency_ids
    evidence_dependency_ids = propose_state.evidence_dependency_ids

    # --- STEP 3: Assumption dependency DFS ---
    traversed: list[TraversedDependency] = []
    dfs_cycle_witness: tuple[str, ...] = ()
    dfs_denied = False
    dfs_code = ""

    def _finalize(
        code: str,
        result: str,
        traversed_deps: tuple[TraversedDependency, ...],
        cycle_witness_val: tuple[str, ...],
        evidence_decs: tuple[EvidenceAdmissionEligibilityDecision, ...],
    ) -> DependencyValidationReceipt:
        # --- STEP 5: Verify root stability before any receipt return ---
        assumption_root_end = store.snapshot("ASSUMPTION").root_digest
        evidence_root_end = store.snapshot("EVIDENCE_UNIT").root_digest
        if assumption_root_end != assumption_root_start:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_DEPENDENCY_ASSUMPTION_SNAPSHOT_CHANGED"
            )
        if evidence_root_end != evidence_root_start:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_DEPENDENCY_EVIDENCE_SNAPSHOT_CHANGED"
            )
        unsigned = {
            "schema_version": _DEPENDENCY_VALIDATION_SCHEMA_VERSION,
            "assumption_dependency_ids": list(assumption_dependency_ids),
            "assumption_id": assumption_id,
            "assumption_registry_root": assumption_root_start,
            "candidate_entity_sequence": 2,
            "candidate_predecessor_event_digest": candidate_predecessor_event_digest,
            "cycle_witness": list(cycle_witness_val),
            "evidence_dependency_ids": list(evidence_dependency_ids),
            "evidence_eligibility_decisions": [dec.to_json_value() for dec in evidence_decs],
            "evidence_registry_root": evidence_root_start,
            "event_sequence": event_sequence,
            "traversed_dependencies": [td.to_json_value() for td in traversed_deps],
            "validation_code": code,
            "validation_result": result,
        }
        receipt_digest = _domain_digest(_DEPENDENCY_VALIDATION_DOMAIN, unsigned)
        return DependencyValidationReceipt(
            assumption_id=assumption_id,
            candidate_predecessor_event_digest=candidate_predecessor_event_digest,
            candidate_entity_sequence=2,
            event_sequence=event_sequence,
            assumption_registry_root=assumption_root_start,
            evidence_registry_root=evidence_root_start,
            assumption_dependency_ids=assumption_dependency_ids,
            evidence_dependency_ids=evidence_dependency_ids,
            traversed_dependencies=traversed_deps,
            cycle_witness=cycle_witness_val,
            evidence_eligibility_decisions=evidence_decs,
            validation_code=code,
            validation_result=result,
            receipt_digest=receipt_digest,
        )

    # DFS implementation with ordered active stack.
    dfs_stack: list[str] = [assumption_id]
    dfs_stack_index: dict[str, int] = {assumption_id: 0}
    dfs_visited: set[str] = set()

    def _dfs(node: str) -> None:
        nonlocal dfs_cycle_witness, dfs_denied, dfs_code

        if dfs_denied:
            return

        # Check active stack before reconstruction.
        if node in dfs_stack_index:
            i = dfs_stack_index[node]
            raw_cycle = tuple(dfs_stack[i:] + [node])
            dfs_cycle_witness = canonical_cycle_witness(raw_cycle)
            dfs_denied = True
            dfs_code = "ASSUMPTION_DEPENDENCY_CYCLE"
            return

        if node in dfs_visited:
            return

        # Obtain head independently (correction #4).
        head = store.entity_head("ASSUMPTION", node)
        if head is None:
            traversed.append(
                TraversedDependency(
                    assumption_id=node,
                    validation_code="ASSUMPTION_DEPENDENCY_MISSING",
                    current_entity_sequence=None,
                    current_event_digest=None,
                    direct_dependency_ids=(),
                )
            )
            dfs_denied = True
            dfs_code = "ASSUMPTION_DEPENDENCY_MISSING"
            return

        # Reconstruct and project.
        try:
            dep_history = store.reconstruct_entity("ASSUMPTION", node)
            dep_state = project_assumption_history(dep_history)
        except (RegistryStoreError, AssumptionRegistryError):
            traversed.append(
                TraversedDependency(
                    assumption_id=node,
                    validation_code="ASSUMPTION_DEPENDENCY_HISTORY_INVALID",
                    current_entity_sequence=head.entity_sequence,
                    current_event_digest=head.event_digest,
                    direct_dependency_ids=(),
                )
            )
            dfs_denied = True
            dfs_code = "ASSUMPTION_DEPENDENCY_HISTORY_INVALID"
            return

        if dep_state is None:
            traversed.append(
                TraversedDependency(
                    assumption_id=node,
                    validation_code="ASSUMPTION_DEPENDENCY_HISTORY_INVALID",
                    current_entity_sequence=head.entity_sequence,
                    current_event_digest=head.event_digest,
                    direct_dependency_ids=(),
                )
            )
            dfs_denied = True
            dfs_code = "ASSUMPTION_DEPENDENCY_HISTORY_INVALID"
            return

        # Consistency: projected head must match authoritative head.
        if (
            dep_state.current_entity_sequence != head.entity_sequence
            or dep_state.current_event_digest != head.event_digest
        ):
            traversed.append(
                TraversedDependency(
                    assumption_id=node,
                    validation_code="ASSUMPTION_DEPENDENCY_HISTORY_INVALID",
                    current_entity_sequence=head.entity_sequence,
                    current_event_digest=head.event_digest,
                    direct_dependency_ids=(),
                )
            )
            dfs_denied = True
            dfs_code = "ASSUMPTION_DEPENDENCY_HISTORY_INVALID"
            return

        traversed.append(
            TraversedDependency(
                assumption_id=node,
                validation_code="DEPENDENCY_PRESENT",
                current_entity_sequence=dep_state.current_entity_sequence,
                current_event_digest=dep_state.current_event_digest,
                direct_dependency_ids=dep_state.assumption_dependency_ids,
            )
        )

        # Push and recurse.
        dfs_stack_index[node] = len(dfs_stack)
        dfs_stack.append(node)
        for child in dep_state.assumption_dependency_ids:
            _dfs(child)
            if dfs_denied:
                break
        dfs_stack.pop()
        del dfs_stack_index[node]
        dfs_visited.add(node)

    for dep in assumption_dependency_ids:
        if dfs_denied:
            break
        _dfs(dep)

    if dfs_denied:
        return _finalize(
            code=dfs_code,
            result="DENY",
            traversed_deps=tuple(traversed),
            cycle_witness_val=dfs_cycle_witness,
            evidence_decs=(),
        )

    # --- STEP 4: Evidence dependency eligibility ---
    evidence_decisions: list[EvidenceAdmissionEligibilityDecision] = []
    evidence_denied = False
    evidence_code = ""

    for evidence_id in evidence_dependency_ids:
        decision = evaluate_evidence_admission_eligibility(
            store=store,
            evidence_id=evidence_id,
            evaluated_at_sequence=event_sequence,
        )
        if decision.evidence_registry_root != evidence_root_start:
            raise AssumptionGovernanceContractError(
                "ASSUMPTION_DEPENDENCY_EVIDENCE_SNAPSHOT_CHANGED"
            )
        if decision.evaluated_at_sequence != event_sequence:
            raise AssumptionGovernanceContractError(
                "DEPENDENCY_VALIDATION_EVIDENCE_SEQUENCE_UNEXPECTED"
            )
        evidence_decisions.append(decision)
        if not decision.eligible:
            evidence_denied = True
            evidence_code = decision.code
            break

    if evidence_denied:
        return _finalize(
            code=evidence_code,
            result="DENY",
            traversed_deps=tuple(traversed),
            cycle_witness_val=(),
            evidence_decs=tuple(evidence_decisions),
        )

    # --- PASS ---
    return _finalize(
        code=_PASS_CODE,
        result="PASS",
        traversed_deps=tuple(traversed),
        cycle_witness_val=(),
        evidence_decs=tuple(evidence_decisions),
    )
