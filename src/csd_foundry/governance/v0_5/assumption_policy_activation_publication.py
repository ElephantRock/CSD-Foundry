"""V0.5-D3.2-A1.3-A publication contracts and in-memory execution.

Implements the publication half of the A1 activation order against the
non-circular V3 signing envelope. Provides:

* ``ExpectedPolicyLedgerStateV3`` — exact observed ledger/3 state;
* ``classify_exact_idempotence_v3`` — V3 exact idempotence;
* ``compare_and_append_policy_entry_v3`` — pure V3 compare-and-append;
* ``InMemoryAssumptionPolicyPublisher`` — thread-safe atomic publisher;
* ``AssumptionPolicyActivationServiceV3`` — V3 service protocol;
* ``ReferenceAssumptionPolicyActivationService`` — composes the V3 preparer
  with the V3 publisher.

A1.3-A provides process-local in-memory atomicity only. A1.3-B will provide
filesystem persistence, interprocess locking, atomic replace, restart
reconstruction, and corruption detection. A1.3-C will provide historical
resolution and grant selection.

Publication precedence:

    1. exact idempotence
    2. expected root/head comparison
    3. predecessor-policy and predecessor-commit validation
    4. effective-sequence monotonicity
    5. append
    6. resulting ledger/3 root
    7. activation result

No failed attempt may claim a resulting root.

Claim boundary:

    thread-safe atomic publication within one Python process

    not:
    interprocess synchronization
    durability
    filesystem atomicity
    restart reconstruction
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Protocol, runtime_checkable

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    require_digest,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
    validate_successor_position_v3,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionPolicyActivationResult,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
)
from csd_foundry.governance.v0_5.assumption_policy_activation import (
    ReferenceAssumptionPolicyActivationPreparer,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
    AssumptionPolicyPublicationConflict,
    PreparedPolicyActivation,
)
from csd_foundry.governance.v0_5.contracts import SignatureSet

# --- 1. V3 expected ledger state -------------------------------------------


@dataclass(frozen=True, slots=True)
class ExpectedPolicyLedgerStateV3:
    """Exact observed ledger/3 state; ``None`` head is valid only for empty."""

    ledger_root_digest: str
    head_entry_digest: str | None

    def __post_init__(self) -> None:
        require_digest(
            self.ledger_root_digest,
            "ASSUMPTION_POLICY_EXPECTED_LEDGER_ROOT_V3_INVALID",
        )
        if self.head_entry_digest is None:
            if self.ledger_root_digest != AssumptionPolicyLedgerV3.build(()).ledger_root_digest:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_POLICY_BLIND_EMPTY_EXPECTATION_V3_FORBIDDEN"
                )
            return
        require_digest(
            self.head_entry_digest,
            "ASSUMPTION_POLICY_EXPECTED_LEDGER_HEAD_V3_INVALID",
        )

    @classmethod
    def empty(cls) -> ExpectedPolicyLedgerStateV3:
        ledger = AssumptionPolicyLedgerV3.build(())
        return cls(ledger_root_digest=ledger.ledger_root_digest, head_entry_digest=None)

    @classmethod
    def from_ledger(cls, ledger: AssumptionPolicyLedgerV3) -> ExpectedPolicyLedgerStateV3:
        head = ledger.entries[-1].ledger_entry_digest if ledger.entries else None
        return cls(ledger_root_digest=ledger.ledger_root_digest, head_entry_digest=head)

    @classmethod
    def observed(
        cls,
        *,
        ledger_root_digest: str,
        head_entry_digest: str,
    ) -> ExpectedPolicyLedgerStateV3:
        return cls(
            ledger_root_digest=ledger_root_digest,
            head_entry_digest=head_entry_digest,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "schema_version": "assumption-policy-ledger-state-expectation-v3/1",
            "head_entry_digest": self.head_entry_digest,
            "ledger_root_digest": self.ledger_root_digest,
        }


# --- 2. V3 exact idempotence -----------------------------------------------


def classify_exact_idempotence_v3(
    existing: AssumptionPolicyLedgerEntryV3,
    candidate: AssumptionPolicyLedgerEntryV3,
) -> str:
    """Classify whether ``candidate`` is an exact retry of ``existing``."""

    digest_equal = existing.ledger_entry_digest == candidate.ledger_entry_digest
    bytes_equal = existing.canonical_bytes == candidate.canonical_bytes
    if digest_equal and bytes_equal:
        return "IDEMPOTENT_APPEND"
    same_commit = (
        existing.policy_commit.commit_receipt_digest
        == candidate.policy_commit.commit_receipt_digest
    )
    if same_commit:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_ENTRY_V3_DIVERGENCE")
    return "DISTINCT_ENTRY"


# --- 3. V3 compare-and-append ----------------------------------------------


def compare_and_append_policy_entry_v3(
    *,
    ledger: AssumptionPolicyLedgerV3,
    expected_state: ExpectedPolicyLedgerStateV3,
    candidate: AssumptionPolicyLedgerEntryV3,
) -> tuple[AssumptionPolicyLedgerV3, AssumptionPolicyActivationResult]:
    """Pure reference V3 compare-and-append with deterministic conflict semantics.

    Precedence:
      1. exact idempotence
      2. expected root/head comparison
      3. predecessor-policy and predecessor-commit validation
      4. effective-sequence monotonicity
      5. append
      6. resulting ledger/3 root
      7. activation result
    """

    # 1. Exact idempotence: if this candidate is already in the ledger, return
    #    IDEMPOTENT_APPEND without mutating the ledger.
    for existing in ledger.entries:
        try:
            classification = classify_exact_idempotence_v3(existing, candidate)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyPublicationConflict(
                exc.code,
                exc.detail,
            ) from exc
        if classification == "IDEMPOTENT_APPEND":
            result = AssumptionPolicyActivationResult.build(
                append_result="IDEMPOTENT_APPEND",
                policy_commit_receipt_digest=candidate.policy_commit.commit_receipt_digest,
                ledger_entry_digest=candidate.ledger_entry_digest,
                predecessor_ledger_root=ledger.ledger_root_digest,
                resulting_ledger_root=ledger.ledger_root_digest,
            )
            return ledger, result

    # 2. Expected root/head comparison.
    actual_state = ExpectedPolicyLedgerStateV3.from_ledger(ledger)
    if expected_state != actual_state:
        expected_empty = (
            expected_state.head_entry_digest is None
            and expected_state.ledger_root_digest
            == AssumptionPolicyLedgerV3.build(()).ledger_root_digest
        )
        candidate_is_genesis = (
            candidate.signing_payload.predecessor_policy_digest is None
            and candidate.signing_payload.predecessor_commit_receipt_digest is None
        )
        if expected_empty and candidate_is_genesis:
            raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH")
        if ledger.entries:
            current_head = ledger.entries[-1]
            candidate_predecessor_policy = candidate.signing_payload.predecessor_policy_digest
            candidate_predecessor_commit = (
                candidate.signing_payload.predecessor_commit_receipt_digest
            )
            if (
                candidate_predecessor_policy != current_head.policy.policy_digest
                or candidate_predecessor_commit != current_head.policy_commit.commit_receipt_digest
            ):
                raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_CHAIN_V3_FORK")
        raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH")

    # 3+4. Predecessor validation + monotonic sequence.
    if ledger.entries:
        try:
            validate_successor_position_v3(ledger.entries[-1], candidate)
        except AssumptionPolicyActivationContractError as exc:
            raise AssumptionPolicyPublicationConflict(exc.code, exc.detail) from exc
    elif (
        candidate.signing_payload.predecessor_policy_digest is not None
        or candidate.signing_payload.predecessor_commit_receipt_digest is not None
    ):
        raise AssumptionPolicyPublicationConflict("ASSUMPTION_POLICY_LEDGER_GENESIS_INVALID")

    # 5+6. Append and compute resulting root.
    updated = AssumptionPolicyLedgerV3.build((*ledger.entries, candidate))

    # 7. Activation result.
    result = AssumptionPolicyActivationResult.build(
        append_result="COMMITTED",
        policy_commit_receipt_digest=candidate.policy_commit.commit_receipt_digest,
        ledger_entry_digest=candidate.ledger_entry_digest,
        predecessor_ledger_root=ledger.ledger_root_digest,
        resulting_ledger_root=updated.ledger_root_digest,
    )
    return updated, result


# --- 4. V3 service protocol ------------------------------------------------


@runtime_checkable
class AssumptionPolicyActivationServiceV3(Protocol):
    """V3 success-only prepare/publish API for the executable A1 implementation."""

    def prepare(
        self,
        *,
        policy: AssumptionAuthorityPolicy,
        signing_payload: AssumptionPolicySigningPayload,
        commit: AssumptionAuthorityPolicyCommitV3,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
        signature_set: SignatureSet,
    ) -> PreparedPolicyActivation: ...

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerStateV3,
    ) -> AssumptionPolicyActivationResult: ...


class AssumptionPolicyPublisher(Protocol):
    """V3 atomic publication boundary."""

    def read_state(self) -> ExpectedPolicyLedgerStateV3: ...

    def read_ledger(self) -> AssumptionPolicyLedgerV3: ...

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerStateV3,
    ) -> AssumptionPolicyActivationResult: ...


# --- 5. In-memory atomic publisher -----------------------------------------


class InMemoryAssumptionPolicyPublisher:
    """Thread-safe atomic publisher holding a single ``AssumptionPolicyLedgerV3``.

    A reentrant lock protects the complete mutable state. The entire
    compare-and-append transition — actual-state read, idempotence
    classification, expected-state comparison, successor validation,
    updated-ledger construction, activation-result construction, and state
    assignment — occurs under the lock.

    Claim boundary: thread-safe atomic publication within one Python process.
    Does not provide interprocess synchronization, durability, filesystem
    atomicity, or restart reconstruction.
    """

    def __init__(
        self,
        initial_ledger: AssumptionPolicyLedgerV3 | None = None,
    ) -> None:
        self._lock = RLock()
        if initial_ledger is not None:
            if type(initial_ledger) is not AssumptionPolicyLedgerV3:
                raise AssumptionPolicyPublicationConflict(
                    "ASSUMPTION_POLICY_LEDGER_VERSION_NOT_ACTIVATABLE"
                )
            self._ledger = initial_ledger
        else:
            self._ledger = AssumptionPolicyLedgerV3.build(())

    def read_state(self) -> ExpectedPolicyLedgerStateV3:
        with self._lock:
            return ExpectedPolicyLedgerStateV3.from_ledger(self._ledger)

    def read_ledger(self) -> AssumptionPolicyLedgerV3:
        with self._lock:
            return self._ledger

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerStateV3,
    ) -> AssumptionPolicyActivationResult:
        entry = prepared.ledger_entry

        if type(entry) is not AssumptionPolicyLedgerEntryV3:
            raise AssumptionPolicyPublicationConflict(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"
            )

        with self._lock:
            updated, result = compare_and_append_policy_entry_v3(
                ledger=self._ledger,
                expected_state=expected_state,
                candidate=entry,
            )

            if result.append_result == "COMMITTED":
                self._ledger = updated

            return result


# --- 6. Complete service composition ---------------------------------------


@dataclass(frozen=True, slots=True)
class ReferenceAssumptionPolicyActivationService(
    AssumptionPolicyActivationServiceV3,
):
    """Composes the V3 preparer with a V3 publisher.

    Implements the full ``prepare`` + ``publish`` activation path. The
    preparer validates and constructs the entry; the publisher atomically
    appends it to the ledger.
    """

    preparer: ReferenceAssumptionPolicyActivationPreparer
    publisher: AssumptionPolicyPublisher

    def prepare(
        self,
        *,
        policy: AssumptionAuthorityPolicy,
        signing_payload: AssumptionPolicySigningPayload,
        commit: AssumptionAuthorityPolicyCommitV3,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
        signature_set: SignatureSet,
    ) -> PreparedPolicyActivation:
        return self.preparer.prepare(
            policy=policy,
            signing_payload=signing_payload,
            commit=commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_policy=challenge_policy,
            signature_set=signature_set,
        )

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerStateV3,
    ) -> AssumptionPolicyActivationResult:
        return self.publisher.publish(
            prepared=prepared,
            expected_state=expected_state,
        )
