"""Atomic v0.5 temporal claim, projection, completion, and visibility protocol."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, cast

from csd_foundry.governance.v0_5.admission import require_validated_event
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    ClockCompletionReceipt,
    ClockProjectionFailure,
    ContractObject,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.resources import projection_phase_policy


class TemporalProtocolError(RuntimeError):
    """Base class for temporal serialization and visibility failures."""


class TemporalClaimRejected(TemporalProtocolError):
    """Raised when a successor claim loses the compare-and-append race."""


class TemporalProjectionError(TemporalProtocolError):
    """Raised by a projection adapter to fail the current tick closed."""

    def __init__(self, phase: str, code: str, detail_digest: str | None = None) -> None:
        super().__init__(f"{phase}: {code}")
        self.phase = phase
        self.code = code
        self.detail_digest = detail_digest


@dataclass(frozen=True, slots=True)
class TemporalHead:
    clock_sequence: int
    completion_digest: str | None

    def __post_init__(self) -> None:
        if type(self.clock_sequence) is not int or self.clock_sequence < 0:
            raise TemporalProtocolError("clock sequence must be a nonnegative integer")
        if self.clock_sequence == 0 and self.completion_digest is not None:
            raise TemporalProtocolError("genesis head cannot cite a completion")
        if self.clock_sequence > 0 and self.completion_digest is None:
            raise TemporalProtocolError("non-genesis head must cite a completion")


@dataclass(frozen=True, slots=True)
class ClaimInstallResult:
    claim: ClockClaim
    acquired: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ProjectionArtifacts:
    evidence_unit_root_digest: str
    assumption_root_digest: str
    alternative_model_root_digest: str
    disposition_receipt_digest: str
    quarantine_epoch: int
    quarantine_marker_digests: tuple[str, ...]
    observed_phase_order: tuple[str, ...]
    release_compilation_invocations: int = 0


@dataclass(frozen=True, slots=True)
class TemporalAttemptOutcome:
    claim: ClockClaim
    semantic_receipt: SemanticProjectionReceipt | None
    completion: ClockCompletionReceipt | None
    failure: ClockProjectionFailure | None

    def __post_init__(self) -> None:
        terminal_count = int(self.completion is not None) + int(self.failure is not None)
        if terminal_count != 1:
            raise TemporalProtocolError("attempt outcome must contain exactly one terminal receipt")


class TemporalStore(Protocol):
    def read_head(self) -> TemporalHead: ...

    def claim_successor(self, expected_head: TemporalHead, claim: ClockClaim) -> ClaimInstallResult: ...

    def put_contract(self, contract: ContractObject) -> None: ...

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None: ...

    def record_attempt_artifact(
        self,
        attempt_id: str,
        artifact_name: str,
        contract: ContractObject,
    ) -> None: ...

    def record_failure(self, claim: ClockClaim, failure: ClockProjectionFailure) -> None: ...

    def prepare_completion(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None: ...

    def publish_completion(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead: ...

    def current_snapshot(self) -> ClockCompletionReceipt | None: ...

    def reconstruct_chain(self) -> tuple[ClockCompletionReceipt, ...]: ...


class SemanticProjector(Protocol):
    def project(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
    ) -> SemanticProjectionReceipt: ...


class OrderedProjectionAdapter(Protocol):
    def project_remaining(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
    ) -> ProjectionArtifacts: ...


class TemporalProjectionCoordinator:
    """Coordinates one complete tick without exposing partial attempts."""

    def __init__(
        self,
        *,
        store: TemporalStore,
        semantic_projector: SemanticProjector,
        projection_adapter: OrderedProjectionAdapter,
        claim_policy_digest: str,
        completion_policy_digest: str,
    ) -> None:
        self._store = store
        self._semantic_projector = semantic_projector
        self._projection_adapter = projection_adapter
        self._claim_policy_digest = claim_policy_digest
        self._completion_policy_digest = completion_policy_digest
        self._ordered_phases = _load_projection_order()

    def build_claim(
        self,
        validated_event: ValidatedEvent,
        *,
        attempt_id: str,
        claimant_id: str,
        observed_head: TemporalHead | None = None,
    ) -> tuple[TemporalHead, ClockClaim]:
        require_validated_event(validated_event)
        head = observed_head or self._store.read_head()
        claim = cast(
            ClockClaim,
            ClockClaim.build(
                {
                    "schema_version": "clock-claim/1",
                    "attempt_id": attempt_id,
                    "previous_committed_sequence": head.clock_sequence,
                    "previous_completion_digest": head.completion_digest,
                    "proposed_sequence": head.clock_sequence + 1,
                    "validated_event_digest": validated_event.digest,
                    "claimant_id": claimant_id,
                    "claim_policy_digest": self._claim_policy_digest,
                }
            ),
        )
        return head, claim

    def claim(
        self,
        validated_event: ValidatedEvent,
        *,
        attempt_id: str,
        claimant_id: str,
        observed_head: TemporalHead | None = None,
    ) -> tuple[TemporalHead, ClaimInstallResult]:
        head, claim = self.build_claim(
            validated_event,
            attempt_id=attempt_id,
            claimant_id=claimant_id,
            observed_head=observed_head,
        )
        result = self._store.claim_successor(head, claim)
        return head, result

    def execute(
        self,
        validated_event: ValidatedEvent,
        *,
        attempt_id: str,
        claimant_id: str,
    ) -> TemporalAttemptOutcome:
        head, result = self.claim(
            validated_event,
            attempt_id=attempt_id,
            claimant_id=claimant_id,
        )
        if not result.acquired:
            raise TemporalClaimRejected(result.reason)
        return self.complete_claim(head, result.claim, validated_event)

    def complete_claim(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
    ) -> TemporalAttemptOutcome:
        require_validated_event(validated_event)
        _verify_claim_event(claim, validated_event)
        semantic_receipt: SemanticProjectionReceipt | None = None
        try:
            semantic_receipt = self._semantic_projector.project(
                claim=claim,
                validated_event=validated_event,
            )
            _verify_semantic_receipt(claim, validated_event, semantic_receipt)
            self._store.put_contract(semantic_receipt)
            self._store.record_attempt_artifact(
                _claim_attempt_id(claim),
                "semantic",
                semantic_receipt,
            )
            artifacts = self._projection_adapter.project_remaining(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
            )
            self._verify_projection_artifacts(artifacts)
            completion = self._build_completion(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                artifacts=artifacts,
            )
            self._store.prepare_completion(claim, completion)
            self._store.publish_completion(expected_head, claim, completion)
            return TemporalAttemptOutcome(
                claim=claim,
                semantic_receipt=semantic_receipt,
                completion=completion,
                failure=None,
            )
        except TemporalProjectionError as exc:
            failure = self._build_failure(claim, exc)
            self._store.record_failure(claim, failure)
            return TemporalAttemptOutcome(
                claim=claim,
                semantic_receipt=semantic_receipt,
                completion=None,
                failure=failure,
            )
        except Exception as exc:
            detail = _text_digest(type(exc).__qualname__ + ":" + str(exc))
            failure = self._build_failure(
                claim,
                TemporalProjectionError("SEMANTIC", "UNHANDLED_PROJECTION_FAILURE", detail),
            )
            self._store.record_failure(claim, failure)
            return TemporalAttemptOutcome(
                claim=claim,
                semantic_receipt=semantic_receipt,
                completion=None,
                failure=failure,
            )

    def _verify_projection_artifacts(self, artifacts: ProjectionArtifacts) -> None:
        expected = self._ordered_phases[1:]
        if artifacts.observed_phase_order != expected:
            raise TemporalProjectionError(
                "QUARANTINE_COMMIT",
                "PROJECTION_ORDER_MISMATCH",
                _text_digest("|".join(artifacts.observed_phase_order)),
            )
        if artifacts.release_compilation_invocations != 0:
            raise TemporalProjectionError(
                "QUARANTINE_COMMIT",
                "RELEASE_COMPILATION_IN_TICK",
            )
        for value in (
            artifacts.evidence_unit_root_digest,
            artifacts.assumption_root_digest,
            artifacts.alternative_model_root_digest,
            artifacts.disposition_receipt_digest,
            *artifacts.quarantine_marker_digests,
        ):
            _require_digest(value)
        if type(artifacts.quarantine_epoch) is not int or artifacts.quarantine_epoch < 0:
            raise TemporalProjectionError("QUARANTINE_COMMIT", "QUARANTINE_EPOCH_INVALID")

    def _build_completion(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        artifacts: ProjectionArtifacts,
    ) -> ClockCompletionReceipt:
        claim_value = claim.to_json_value()
        return cast(
            ClockCompletionReceipt,
            ClockCompletionReceipt.build(
                {
                    "schema_version": "clock-completion-receipt/1",
                    "clock_sequence": claim_value["proposed_sequence"],
                    "previous_completion_digest": claim_value["previous_completion_digest"],
                    "clock_claim_digest": claim.digest,
                    "validated_event_digest": validated_event.digest,
                    "semantic_projection_receipt_digest": semantic_receipt.digest,
                    "registry_root_digests": {
                        "evidence_unit": artifacts.evidence_unit_root_digest,
                        "assumption": artifacts.assumption_root_digest,
                        "alternative_model": artifacts.alternative_model_root_digest,
                    },
                    "disposition_receipt_digest": artifacts.disposition_receipt_digest,
                    "quarantine_epoch": artifacts.quarantine_epoch,
                    "quarantine_marker_digests": list(artifacts.quarantine_marker_digests),
                    "completion_policy_digest": self._completion_policy_digest,
                }
            ),
        )

    def _build_failure(
        self,
        claim: ClockClaim,
        error: TemporalProjectionError,
    ) -> ClockProjectionFailure:
        claim_value = claim.to_json_value()
        phase = error.phase if error.phase in self._ordered_phases else "SEMANTIC"
        return cast(
            ClockProjectionFailure,
            ClockProjectionFailure.build(
                {
                    "schema_version": "clock-projection-failure/1",
                    "attempt_id": claim_value["attempt_id"],
                    "previous_committed_sequence": claim_value["previous_committed_sequence"],
                    "previous_completion_digest": claim_value["previous_completion_digest"],
                    "proposed_sequence": claim_value["proposed_sequence"],
                    "clock_claim_digest": claim.digest,
                    "validated_event_digest": claim_value["validated_event_digest"],
                    "failure_phase": phase,
                    "failure_code": error.code,
                    "failure_detail_digest": error.detail_digest,
                    "recorded_against_tick": claim_value["previous_committed_sequence"],
                }
            ),
        )


def _load_projection_order() -> tuple[str, ...]:
    policy = projection_phase_policy()
    phases = policy.get("ordered_phases")
    if type(phases) is not list or not all(type(item) is str for item in phases):
        raise GovernanceContractError("PROJECTION_PHASE_POLICY_INVALID")
    order = tuple(cast(list[str], phases))
    expected = (
        "SEMANTIC",
        "EVIDENCE_REGISTRY",
        "ASSUMPTION_REGISTRY",
        "ALTERNATIVE_MODEL_REGISTRY",
        "DISPOSITION",
        "QUARANTINE_COMMIT",
    )
    if order != expected or policy.get("release_compilation_phase") is not None:
        raise GovernanceContractError("PROJECTION_PHASE_POLICY_INVALID")
    return order


def _verify_claim_event(claim: ClockClaim, validated_event: ValidatedEvent) -> None:
    value = claim.to_json_value()
    if value["validated_event_digest"] != validated_event.digest:
        raise TemporalProjectionError("SEMANTIC", "VALIDATED_EVENT_MISMATCH")


def _verify_semantic_receipt(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    receipt: SemanticProjectionReceipt,
) -> None:
    value = receipt.to_json_value()
    claim_value = claim.to_json_value()
    if value["clock_claim_digest"] != claim.digest:
        raise TemporalProjectionError("SEMANTIC", "SEMANTIC_CLAIM_MISMATCH")
    if value["validated_event_digest"] != validated_event.digest:
        raise TemporalProjectionError("SEMANTIC", "SEMANTIC_EVENT_MISMATCH")
    if value["projection_sequence"] != claim_value["proposed_sequence"]:
        raise TemporalProjectionError("SEMANTIC", "SEMANTIC_SEQUENCE_MISMATCH")


def _claim_attempt_id(claim: ClockClaim) -> str:
    value = claim.to_json_value().get("attempt_id")
    if type(value) is not str:
        raise TemporalProtocolError("clock claim attempt id is invalid")
    return value


def _require_digest(value: object) -> None:
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        raise TemporalProjectionError("QUARANTINE_COMMIT", "PROJECTION_DIGEST_INVALID")


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
