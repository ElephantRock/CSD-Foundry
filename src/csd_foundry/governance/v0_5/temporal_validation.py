"""Reference adapters and independent validation campaign for v0.5 temporal completion."""

from __future__ import annotations

import hashlib
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from multiprocessing import get_context
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from csd_foundry.governance.v0_5.admission_validation import (
    build_reference_admission_fixture,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    ClockCompletionReceipt,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.temporal import (
    ProjectionArtifacts,
    TemporalHead,
    TemporalProjectionCoordinator,
    TemporalProjectionError,
)
from csd_foundry.governance.v0_5.temporal_store import (
    FilesystemTemporalStore,
    InMemoryTemporalStore,
)

_ORDER = (
    "SEMANTIC",
    "EVIDENCE_REGISTRY",
    "ASSUMPTION_REGISTRY",
    "ALTERNATIVE_MODEL_REGISTRY",
    "DISPOSITION",
    "QUARANTINE_COMMIT",
)
_CLAIM_POLICY_DIGEST = "sha256:" + hashlib.sha256(b"claim-policy-v0.5").hexdigest()
_COMPLETION_POLICY_DIGEST = "sha256:" + hashlib.sha256(b"completion-policy-v0.5").hexdigest()
_SEMANTIC_POLICY_DIGEST = "sha256:" + hashlib.sha256(b"semantic-policy-v0.5").hexdigest()


class ReferenceSemanticProjector:
    """Deterministic semantic receipt adapter with an injectable fail-closed phase."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    def project(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
    ) -> SemanticProjectionReceipt:
        if self.fail:
            raise TemporalProjectionError("SEMANTIC", "REFERENCE_SEMANTIC_FAILURE")
        sequence = cast(int, claim.to_json_value()["proposed_sequence"])
        return cast(
            SemanticProjectionReceipt,
            SemanticProjectionReceipt.build(
                {
                    "schema_version": "semantic-projection-receipt/1",
                    "clock_claim_digest": claim.digest,
                    "validated_event_digest": validated_event.digest,
                    "projection_sequence": sequence,
                    "pre_state_digest": _digest(f"pre-state:{sequence - 1}"),
                    "post_state_digest": _digest(f"post-state:{sequence}"),
                    "semantic_trace_digest": _digest(
                        f"trace:{claim.digest}:{validated_event.digest}"
                    ),
                    "semantic_policy_digest": _SEMANTIC_POLICY_DIGEST,
                    "projection_result": "COMPLETED",
                }
            ),
        )


class ReferenceOrderedProjectionAdapter:
    """Typed placeholder commitments for v0.5-D/E phases, without assurance claims."""

    def __init__(
        self,
        *,
        fail_phase: str | None = None,
        release_compilation_invocations: int = 0,
    ) -> None:
        self.fail_phase = fail_phase
        self.release_compilation_invocations = release_compilation_invocations

    def project_remaining(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
    ) -> ProjectionArtifacts:
        observed: list[str] = []
        for phase in _ORDER[1:]:
            observed.append(phase)
            if self.fail_phase == phase:
                raise TemporalProjectionError(phase, f"REFERENCE_{phase}_FAILURE")
        basis = f"{claim.digest}:{validated_event.digest}:{semantic_receipt.digest}"
        return ProjectionArtifacts(
            evidence_unit_root_digest=_digest("evidence:" + basis),
            assumption_root_digest=_digest("assumption:" + basis),
            alternative_model_root_digest=_digest("alternative-model:" + basis),
            disposition_receipt_digest=_digest("disposition:" + basis),
            quarantine_epoch=cast(int, claim.to_json_value()["proposed_sequence"]),
            quarantine_marker_digests=(_digest("quarantine:" + basis),),
            observed_phase_order=tuple(observed),
            release_compilation_invocations=self.release_compilation_invocations,
        )


@dataclass(frozen=True, slots=True)
class AtomicTemporalValidationReport:
    successful_claim_digest: str
    semantic_receipt_digest: str
    completion_receipt_digest: str
    concurrent_claimants: int
    concurrent_winners: int
    concurrent_losers: int
    failed_phase_receipt_digests: tuple[tuple[str, str], ...]
    failure_sequences_unchanged: bool
    retry_reused_sequence: bool
    stale_head_rejected: bool
    partial_visibility_blocked: bool
    prepared_completion_recovered: bool
    incomplete_claim_failed_on_recovery: bool
    restart_deterministic: bool
    chain_length: int
    release_compilation_invocations: int
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "atomic-temporal-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
            "successful_claim_digest": self.successful_claim_digest,
            "semantic_receipt_digest": self.semantic_receipt_digest,
            "completion_receipt_digest": self.completion_receipt_digest,
            "concurrent_claimants": self.concurrent_claimants,
            "concurrent_winners": self.concurrent_winners,
            "concurrent_losers": self.concurrent_losers,
            "failed_phase_receipt_digests": {
                phase: digest for phase, digest in self.failed_phase_receipt_digests
            },
            "failure_sequences_unchanged": self.failure_sequences_unchanged,
            "retry_reused_sequence": self.retry_reused_sequence,
            "stale_head_rejected": self.stale_head_rejected,
            "partial_visibility_blocked": self.partial_visibility_blocked,
            "prepared_completion_recovered": self.prepared_completion_recovered,
            "incomplete_claim_failed_on_recovery": self.incomplete_claim_failed_on_recovery,
            "restart_deterministic": self.restart_deterministic,
            "chain_length": self.chain_length,
            "release_compilation_invocations": self.release_compilation_invocations,
            "errors": list(self.errors),
            "claim_boundary": (
                "Establishes deterministic single-host temporal serialization and "
                "atomic visibility "
                "for the POSIX reference store and supplied projection artifacts. It does not "
                "establish distributed consensus, substantive registry or disposition correctness, "
                "external truth, or production safety."
            ),
        }


def build_reference_validated_event() -> ValidatedEvent:
    fixture = build_reference_admission_fixture()
    outcome = fixture.engine.admit(
        fixture.raw_event,
        fixture.single_signatures,
        fixture.single_policy,
        validated_at_tick=41,
    )
    if outcome.accepted is None:
        raise RuntimeError("reference admission fixture did not produce a ValidatedEvent")
    return outcome.accepted


def build_reference_coordinator(
    store: InMemoryTemporalStore | FilesystemTemporalStore,
    *,
    fail_phase: str | None = None,
    release_compilation_invocations: int = 0,
) -> TemporalProjectionCoordinator:
    return TemporalProjectionCoordinator(
        store=store,
        semantic_projector=ReferenceSemanticProjector(fail=fail_phase == "SEMANTIC"),
        projection_adapter=ReferenceOrderedProjectionAdapter(
            fail_phase=fail_phase,
            release_compilation_invocations=release_compilation_invocations,
        ),
        claim_policy_digest=_CLAIM_POLICY_DIGEST,
        completion_policy_digest=_COMPLETION_POLICY_DIGEST,
    )


def validate_atomic_temporal(release: str = "v0.5") -> AtomicTemporalValidationReport:
    errors: list[str] = []
    event = build_reference_validated_event()

    success_store = InMemoryTemporalStore()
    success_coordinator = build_reference_coordinator(success_store)
    first = success_coordinator.execute(
        event,
        attempt_id="attempt-success-1",
        claimant_id="validator",
    )
    if first.completion is None or first.semantic_receipt is None:
        raise RuntimeError("reference success attempt did not complete")
    second = success_coordinator.execute(
        event,
        attempt_id="attempt-success-2",
        claimant_id="validator",
    )
    if second.completion is None:
        raise RuntimeError("second reference success attempt did not complete")
    chain = success_store.reconstruct_chain()
    if tuple(item.to_json_value()["clock_sequence"] for item in chain) != (1, 2):
        errors.append("completion chain is not contiguous")

    failed_phase_receipts: list[tuple[str, str]] = []
    failure_sequences_unchanged = True
    retry_reused_sequence = True
    partial_visibility_blocked = True
    for phase in _ORDER:
        store = InMemoryTemporalStore()
        coordinator = build_reference_coordinator(store, fail_phase=phase)
        outcome = coordinator.execute(
            event,
            attempt_id=f"attempt-fail-{phase.lower()}",
            claimant_id="validator",
        )
        if outcome.failure is None:
            errors.append(f"{phase}: failed attempt did not emit ClockProjectionFailure")
            continue
        failed_phase_receipts.append((phase, outcome.failure.digest))
        if store.read_head() != TemporalHead(0, None):
            failure_sequences_unchanged = False
            errors.append(f"{phase}: failure advanced the committed head")
        if store.current_snapshot() is not None:
            partial_visibility_blocked = False
            errors.append(f"{phase}: partial attempt became visible")
        retry = build_reference_coordinator(store).execute(
            event,
            attempt_id=f"attempt-retry-{phase.lower()}",
            claimant_id="validator",
        )
        if retry.completion is None or retry.completion.to_json_value()["clock_sequence"] != 1:
            retry_reused_sequence = False
            errors.append(f"{phase}: retry did not reuse the failed proposed sequence")

    concurrency = _validate_process_concurrency(event, errors)
    recovery = _validate_recovery(event, errors)
    stale_head_rejected = _validate_stale_head(event, errors)

    if release != "v0.5":
        errors.append("atomic temporal validation supports only v0.5")

    return AtomicTemporalValidationReport(
        successful_claim_digest=first.claim.digest,
        semantic_receipt_digest=first.semantic_receipt.digest,
        completion_receipt_digest=first.completion.digest,
        concurrent_claimants=concurrency[0],
        concurrent_winners=concurrency[1],
        concurrent_losers=concurrency[2],
        failed_phase_receipt_digests=tuple(failed_phase_receipts),
        failure_sequences_unchanged=failure_sequences_unchanged,
        retry_reused_sequence=retry_reused_sequence,
        stale_head_rejected=stale_head_rejected,
        partial_visibility_blocked=partial_visibility_blocked,
        prepared_completion_recovered=recovery[0],
        incomplete_claim_failed_on_recovery=recovery[1],
        restart_deterministic=recovery[2],
        chain_length=len(chain),
        release_compilation_invocations=0,
        errors=tuple(errors),
    )


def _validate_process_concurrency(
    event: ValidatedEvent,
    errors: list[str],
) -> tuple[int, int, int]:
    claimant_count = 12
    with TemporaryDirectory() as directory:
        root = Path(directory)
        store = FilesystemTemporalStore(root)
        head = store.read_head()
        coordinator = build_reference_coordinator(store)
        claims = [
            coordinator.build_claim(
                event,
                attempt_id=f"process-claim-{index:02d}",
                claimant_id=f"process-{index:02d}",
                observed_head=head,
            )[1]
            for index in range(claimant_count)
        ]
        with ProcessPoolExecutor(
            max_workers=claimant_count,
            mp_context=get_context("spawn"),
        ) as executor:
            results = list(
                executor.map(
                    _claim_worker,
                    [str(root)] * claimant_count,
                    [claim.to_json_value() for claim in claims],
                )
            )
        winners = [item for item in results if item[0]]
        losers = [item for item in results if not item[0]]
        if len(winners) != 1:
            errors.append(f"concurrency campaign produced {len(winners)} winners")
        if len(losers) != claimant_count - 1:
            errors.append("concurrency campaign did not reject every losing claimant")
        if winners:
            winner = next(claim for claim in claims if claim.digest == winners[0][2])
            completed = coordinator.complete_claim(head, winner, event)
            if completed.completion is None or store.read_head().clock_sequence != 1:
                errors.append(
                    "winning process claim did not produce exactly one committed successor"
                )
        return claimant_count, len(winners), len(losers)


def _claim_worker(root: str, claim_value: dict[str, Any]) -> tuple[bool, str, str]:
    store = FilesystemTemporalStore(Path(root))
    claim = cast(ClockClaim, ClockClaim.from_json(claim_value))
    value = claim.to_json_value()
    head = TemporalHead(
        cast(int, value["previous_committed_sequence"]),
        cast(str | None, value["previous_completion_digest"]),
    )
    result = store.claim_successor(head, claim)
    return result.acquired, result.reason, claim.digest


def _validate_recovery(
    event: ValidatedEvent,
    errors: list[str],
) -> tuple[bool, bool, bool]:
    incomplete_failed = False
    prepared_recovered = False
    restart_deterministic = False

    with TemporaryDirectory() as directory:
        root = Path(directory)
        store = FilesystemTemporalStore(root)
        coordinator = build_reference_coordinator(store)
        head, result = coordinator.claim(
            event,
            attempt_id="crash-after-claim",
            claimant_id="validator",
        )
        if not result.acquired or store.current_snapshot() is not None:
            errors.append("claim-only crash fixture was not isolated from visibility")
        reopened = FilesystemTemporalStore(root)
        incomplete_failed = reopened.recover() == "INCOMPLETE_ATTEMPT_FAILED"
        if not incomplete_failed or reopened.read_head() != head:
            errors.append("incomplete claim recovery did not fail closed")

        retry = build_reference_coordinator(reopened).execute(
            event,
            attempt_id="crash-after-claim-retry",
            claimant_id="validator",
        )
        if retry.completion is None:
            errors.append("recovery did not permit a same-sequence retry")

    with TemporaryDirectory() as directory:
        root = Path(directory)
        store = FilesystemTemporalStore(root)
        coordinator = build_reference_coordinator(store)
        head, result = coordinator.claim(
            event,
            attempt_id="crash-after-prepare",
            claimant_id="validator",
        )
        if not result.acquired:
            errors.append("prepared-completion fixture could not acquire its claim")
            return prepared_recovered, incomplete_failed, restart_deterministic
        semantic = ReferenceSemanticProjector().project(
            claim=result.claim,
            validated_event=event,
        )
        artifacts = ReferenceOrderedProjectionAdapter().project_remaining(
            claim=result.claim,
            validated_event=event,
            semantic_receipt=semantic,
        )
        completion = _build_reference_completion(result.claim, event, semantic, artifacts)
        store.put_contract(semantic)
        store.record_attempt_artifact("crash-after-prepare", "semantic", semantic)
        store.record_projection_artifacts(result.claim, semantic, artifacts)
        store.prepare_completion(result.claim, completion)
        if store.current_snapshot() is not None:
            errors.append("prepared completion became visible before head publication")

        reopened = FilesystemTemporalStore(root)
        prepared_recovered = reopened.recover() == "PREPARED_COMPLETION_PUBLISHED"
        snapshot = reopened.current_snapshot()
        if not prepared_recovered or snapshot is None or snapshot.digest != completion.digest:
            errors.append("prepared completion was not published deterministically on recovery")
        second_reopen = FilesystemTemporalStore(root)
        chain_a = tuple(item.canonical_bytes for item in reopened.reconstruct_chain())
        chain_b = tuple(item.canonical_bytes for item in second_reopen.reconstruct_chain())
        restart_deterministic = (
            reopened.read_head() == second_reopen.read_head() and chain_a == chain_b
        )
        if not restart_deterministic:
            errors.append("restart changed committed temporal identity")

    return prepared_recovered, incomplete_failed, restart_deterministic


def _validate_stale_head(event: ValidatedEvent, errors: list[str]) -> bool:
    store = InMemoryTemporalStore()
    coordinator = build_reference_coordinator(store)
    genesis = store.read_head()
    first = coordinator.execute(
        event,
        attempt_id="stale-head-success",
        claimant_id="validator",
    )
    if first.completion is None:
        errors.append("stale-head fixture could not establish sequence one")
        return False
    _, stale_claim = coordinator.build_claim(
        event,
        attempt_id="stale-head-loser",
        claimant_id="validator",
        observed_head=genesis,
    )
    result = store.claim_successor(genesis, stale_claim)
    rejected = not result.acquired and result.reason == "STALE_EXPECTED_HEAD"
    if not rejected:
        errors.append("stale expected-head claim was not rejected")
    return rejected


def _build_reference_completion(
    claim: ClockClaim,
    event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
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
                "validated_event_digest": event.digest,
                "semantic_projection_receipt_digest": semantic.digest,
                "registry_root_digests": {
                    "evidence_unit": artifacts.evidence_unit_root_digest,
                    "assumption": artifacts.assumption_root_digest,
                    "alternative_model": artifacts.alternative_model_root_digest,
                },
                "disposition_receipt_digest": artifacts.disposition_receipt_digest,
                "quarantine_epoch": artifacts.quarantine_epoch,
                "quarantine_marker_digests": list(artifacts.quarantine_marker_digests),
                "completion_policy_digest": _COMPLETION_POLICY_DIGEST,
            }
        ),
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
