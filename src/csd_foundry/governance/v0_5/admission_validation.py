"""Independent fixtures and validation report for v0.5 event admission."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from csd_foundry.governance.v0_5.admission import (
    AdmissionOutcome,
    CommittedValidationContext,
    EventAdmissionEngine,
    EventAdmissionStore,
    SignatureRecord,
    reconstruct_accepted,
    require_validated_event,
)
from csd_foundry.governance.v0_5.admission_store import (
    FilesystemEventAdmissionStore,
    InMemoryEventAdmissionStore,
)
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    EventValidationFailure,
    RawEvent,
    SignatureSet,
    ValidatedEvent,
    ValidationPolicy,
)


@dataclass(frozen=True, slots=True)
class SignerAuthority:
    signer_id: str
    key_id: str
    authority_scopes: tuple[str, ...]
    algorithms: tuple[str, ...]
    valid_from_tick: int
    valid_through_tick: int | None


class ReferenceCommittedContextResolver:
    def __init__(self, contexts: tuple[CommittedValidationContext, ...]) -> None:
        self._contexts = {context.tick: context for context in contexts}

    def latest_committed_tick(self) -> int | None:
        committed = [tick for tick, context in self._contexts.items() if context.committed]
        return max(committed) if committed else None

    def resolve(self, tick: int) -> CommittedValidationContext | None:
        return self._contexts.get(tick)


class ReferenceValidationPolicyRegistry:
    def __init__(self, policies: tuple[ValidationPolicy, ...]) -> None:
        self._policies = {policy.digest: policy for policy in policies}

    def resolve(self, policy_digest: str) -> ValidationPolicy | None:
        return self._policies.get(policy_digest)

    def is_allowed(
        self,
        policy: ValidationPolicy,
        *,
        context: CommittedValidationContext,
    ) -> bool:
        return context.committed and self._policies.get(policy.digest) == policy


class ReferenceSignerAuthorityResolver:
    def __init__(self, authorities: tuple[SignerAuthority, ...]) -> None:
        self._authorities = {
            (authority.signer_id, authority.key_id): authority for authority in authorities
        }

    def is_authorized(
        self,
        signature: SignatureRecord,
        *,
        policy: ValidationPolicy,
        context: CommittedValidationContext,
    ) -> bool:
        authority = self._authorities.get((signature.signer_id, signature.key_id))
        if authority is None:
            return False
        policy_value = policy.to_json_value()
        if cast(str, policy_value["authority_policy_digest"]) != _digest("authority-policy-v1"):
            return False
        if context.tick < authority.valid_from_tick:
            return False
        if authority.valid_through_tick is not None and context.tick > authority.valid_through_tick:
            return False
        return (
            signature.authority_scope in authority.authority_scopes
            and signature.algorithm in authority.algorithms
        )


class DeterministicTestSignatureVerifier:
    """Deterministic test double; it makes no production cryptographic claim."""

    def verify(self, signature: SignatureRecord, *, raw_event_digest: str) -> bool:
        if not raw_event_digest.startswith("sha256:"):
            return False
        expected = deterministic_test_signature(
            key_id=signature.key_id,
            algorithm=signature.algorithm,
            signed_digest=signature.signed_digest,
        )
        return hmac.compare_digest(signature.signature_base64, expected)


@dataclass(frozen=True, slots=True)
class ReferenceAdmissionFixture:
    engine: EventAdmissionEngine
    store: EventAdmissionStore
    context_resolver: ReferenceCommittedContextResolver
    signature_verifier: DeterministicTestSignatureVerifier
    authority_resolver: ReferenceSignerAuthorityResolver
    policy_registry: ReferenceValidationPolicyRegistry
    raw_event: RawEvent
    single_policy: ValidationPolicy
    threshold_policy: ValidationPolicy
    single_signatures: SignatureSet
    threshold_signatures: SignatureSet


@dataclass(frozen=True, slots=True)
class AdmissionValidationReport:
    accepted_receipt_digests: tuple[str, ...]
    failure_receipt_digests: tuple[tuple[str, str], ...]
    failure_code_sets: tuple[tuple[str, tuple[str, ...]], ...]
    reconstructed_acceptance_count: int
    restart_deterministic: bool
    reducer_boundary_enforced: bool
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted_receipt_digests": list(self.accepted_receipt_digests),
            "accepted_receipts": len(self.accepted_receipt_digests),
            "claim_boundary": (
                "This report establishes deterministic event admission relative to pinned "
                "validation policies, committed contexts, signer-authority resolution, and a "
                "deterministic signature-verifier test double. It does not establish production "
                "key validity, signer truthfulness, external truth, CSD semantic validity, or "
                "production safety."
            ),
            "errors": list(self.errors),
            "failure_code_sets": {
                case_id: list(codes) for case_id, codes in self.failure_code_sets
            },
            "failure_receipt_digests": {
                case_id: digest for case_id, digest in self.failure_receipt_digests
            },
            "reconstructed_acceptance_count": self.reconstructed_acceptance_count,
            "reducer_boundary_enforced": self.reducer_boundary_enforced,
            "rejected_receipts": len(self.failure_receipt_digests),
            "restart_deterministic": self.restart_deterministic,
            "schema_version": "event-admission-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
        }


def build_reference_admission_fixture(
    store: EventAdmissionStore | None = None,
) -> ReferenceAdmissionFixture:
    active_store: EventAdmissionStore = store or InMemoryEventAdmissionStore()
    contexts = (
        CommittedValidationContext.build(
            tick=40,
            state_root_digest=_digest("state-root-40"),
            authority_root_digest=_digest("authority-root-40"),
        ),
        CommittedValidationContext.build(
            tick=41,
            state_root_digest=_digest("state-root-41"),
            authority_root_digest=_digest("authority-root-41"),
        ),
        CommittedValidationContext.build(
            tick=42,
            state_root_digest=_digest("state-root-42"),
            authority_root_digest=_digest("authority-root-42"),
            committed=False,
        ),
    )
    context_resolver = ReferenceCommittedContextResolver(contexts)

    single_policy = _build_policy(policy_id="admission-single", policy_version=1, threshold=1)
    threshold_policy = _build_policy(policy_id="admission-threshold", policy_version=2, threshold=2)
    policy_registry = ReferenceValidationPolicyRegistry((single_policy, threshold_policy))

    authority_resolver = ReferenceSignerAuthorityResolver(
        (
            SignerAuthority(
                signer_id="alice",
                key_id="key-alice-1",
                authority_scopes=("csd.events",),
                algorithms=("ed25519", "ecdsa-p256-sha256"),
                valid_from_tick=0,
                valid_through_tick=None,
            ),
            SignerAuthority(
                signer_id="alice",
                key_id="key-alice-2",
                authority_scopes=("csd.events",),
                algorithms=("ed25519",),
                valid_from_tick=0,
                valid_through_tick=None,
            ),
            SignerAuthority(
                signer_id="bob",
                key_id="key-bob-1",
                authority_scopes=("csd.events",),
                algorithms=("ed25519",),
                valid_from_tick=0,
                valid_through_tick=None,
            ),
        )
    )
    signature_verifier = DeterministicTestSignatureVerifier()

    raw_event = cast(
        RawEvent,
        RawEvent.build(
            {
                "schema_version": "raw-event/1",
                "event_id": "evt-advance-clock-001",
                "event_type": "AdvanceClock",
                "payload_schema_version": "advance-clock/1",
                "payload": {"delta_ticks": 1},
                "submitted_against_tick": 41,
            }
        ),
    )
    single_signatures = build_signature_set(
        raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=raw_event.digest,
                authority_scope="csd.events",
            ),
        ),
    )
    threshold_signatures = build_signature_set(
        raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=raw_event.digest,
                authority_scope="csd.events",
            ),
            make_signature(
                signer_id="bob",
                key_id="key-bob-1",
                algorithm="ed25519",
                signed_digest=raw_event.digest,
                authority_scope="csd.events",
            ),
        ),
    )

    engine = EventAdmissionEngine(
        context_resolver=context_resolver,
        signature_verifier=signature_verifier,
        authority_resolver=authority_resolver,
        policy_registry=policy_registry,
        store=active_store,
    )
    return ReferenceAdmissionFixture(
        engine=engine,
        store=active_store,
        context_resolver=context_resolver,
        signature_verifier=signature_verifier,
        authority_resolver=authority_resolver,
        policy_registry=policy_registry,
        raw_event=raw_event,
        single_policy=single_policy,
        threshold_policy=threshold_policy,
        single_signatures=single_signatures,
        threshold_signatures=threshold_signatures,
    )


def make_signature(
    *,
    signer_id: str,
    key_id: str,
    algorithm: str,
    signed_digest: str,
    authority_scope: str,
    signature_base64: str | None = None,
) -> dict[str, str]:
    return {
        "signer_id": signer_id,
        "key_id": key_id,
        "algorithm": algorithm,
        "signed_digest": signed_digest,
        "signature_base64": signature_base64
        or deterministic_test_signature(
            key_id=key_id,
            algorithm=algorithm,
            signed_digest=signed_digest,
        ),
        "authority_scope": authority_scope,
    }


def build_signature_set(
    raw_event_digest: str,
    signatures: tuple[dict[str, str], ...],
) -> SignatureSet:
    del raw_event_digest
    return cast(
        SignatureSet,
        SignatureSet.build(
            {
                "schema_version": "signature-set/1",
                "signatures": list(signatures),
            }
        ),
    )


def deterministic_test_signature(*, key_id: str, algorithm: str, signed_digest: str) -> str:
    payload = f"{key_id}\0{algorithm}\0{signed_digest}".encode("utf-8")
    digest = hashlib.sha256(b"CSD_TEST_SIGNATURE\0" + payload).digest()
    return base64.b64encode(digest).decode("ascii")


def validate_event_admission(release: str = "v0.5") -> AdmissionValidationReport:
    errors: list[str] = []
    fixture = build_reference_admission_fixture()
    accepted_outcomes = (
        fixture.engine.admit(
            fixture.raw_event,
            fixture.single_signatures,
            fixture.single_policy,
            validated_at_tick=41,
        ),
        fixture.engine.admit(
            fixture.raw_event,
            fixture.threshold_signatures,
            fixture.threshold_policy,
            validated_at_tick=41,
        ),
    )
    accepted_receipts: list[ValidatedEvent] = []
    reconstructed = 0
    for outcome in accepted_outcomes:
        if outcome.accepted is None or outcome.failure is not None:
            errors.append("accepted fixture did not produce exactly one ValidatedEvent")
            continue
        accepted_receipts.append(outcome.accepted)
        bundle = reconstruct_accepted(outcome.accepted, fixture.store)
        if (
            bundle.raw_event != fixture.raw_event
            or bundle.context.tick != 41
            or bundle.receipt != outcome.accepted
        ):
            errors.append("accepted receipt reconstruction changed pinned evidence")
        else:
            reconstructed += 1

    failure_cases = _reference_failure_cases(fixture)
    expected_codes = _expected_failure_codes()
    failure_receipts: list[tuple[str, EventValidationFailure]] = []
    for case_id, outcome in failure_cases:
        if outcome.failure is None or outcome.accepted is not None:
            errors.append(f"{case_id}: rejection did not produce exactly one failure receipt")
            continue
        observed = tuple(sorted(cast(list[str], outcome.failure.to_json_value()["failure_codes"])))
        if observed != expected_codes[case_id]:
            errors.append(f"{case_id}: expected {expected_codes[case_id]}, observed {observed}")
        failure_receipts.append((case_id, outcome.failure))

    reducer_boundary_enforced = True
    boundary_values: tuple[object, ...] = (
        fixture.raw_event,
        failure_receipts[0][1] if failure_receipts else fixture.raw_event,
    )
    for value in boundary_values:
        try:
            require_validated_event(value)
        except GovernanceContractError as exc:
            if exc.code != "VALIDATION_RESULT_NOT_ACCEPTED":
                errors.append("reducer boundary returned an unstable rejection code")
                reducer_boundary_enforced = False
        else:
            errors.append("reducer boundary accepted a non-ValidatedEvent")
            reducer_boundary_enforced = False

    restart_deterministic = _validate_restart_determinism(errors)
    if release != "v0.5":
        errors.append("event admission validation supports only v0.5")

    return AdmissionValidationReport(
        accepted_receipt_digests=tuple(receipt.digest for receipt in accepted_receipts),
        failure_receipt_digests=tuple(
            (case_id, receipt.digest) for case_id, receipt in failure_receipts
        ),
        failure_code_sets=tuple(sorted(expected_codes.items())),
        reconstructed_acceptance_count=reconstructed,
        restart_deterministic=restart_deterministic,
        reducer_boundary_enforced=reducer_boundary_enforced,
        errors=tuple(errors),
    )


def _reference_failure_cases(
    fixture: ReferenceAdmissionFixture,
) -> tuple[tuple[str, AdmissionOutcome], ...]:
    raw_schema = fixture.raw_event.to_json_value()
    raw_schema["unexpected"] = True

    raw_digest = fixture.raw_event.to_json_value()
    raw_digest["raw_event_digest"] = _digest("wrong-raw-event")

    wrong_signed_digest = _digest("wrong-signed-digest")
    signature_digest_mismatch = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=wrong_signed_digest,
                authority_scope="csd.events",
            ),
        ),
    )
    algorithm_not_allowed = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ecdsa-p256-sha256",
                signed_digest=fixture.raw_event.digest,
                authority_scope="csd.events",
            ),
        ),
    )
    invalid_signature = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=fixture.raw_event.digest,
                authority_scope="csd.events",
                signature_base64="ZmFrZQ==",
            ),
        ),
    )
    wrong_scope = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=fixture.raw_event.digest,
                authority_scope="other.scope",
            ),
        ),
    )
    duplicate_signer = build_signature_set(
        fixture.raw_event.digest,
        (
            make_signature(
                signer_id="alice",
                key_id="key-alice-1",
                algorithm="ed25519",
                signed_digest=fixture.raw_event.digest,
                authority_scope="csd.events",
            ),
            make_signature(
                signer_id="alice",
                key_id="key-alice-2",
                algorithm="ed25519",
                signed_digest=fixture.raw_event.digest,
                authority_scope="csd.events",
            ),
        ),
    )
    unknown_policy = _build_policy(policy_id="unregistered-policy", policy_version=99, threshold=1)

    return (
        (
            "raw-schema-rejected",
            fixture.engine.admit(
                raw_schema,
                fixture.single_signatures,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "raw-digest-mismatch",
            fixture.engine.admit(
                raw_digest,
                fixture.single_signatures,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "signature-digest-mismatch",
            fixture.engine.admit(
                fixture.raw_event,
                signature_digest_mismatch,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "signature-algorithm-not-allowed",
            fixture.engine.admit(
                fixture.raw_event,
                algorithm_not_allowed,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "signature-invalid",
            fixture.engine.admit(
                fixture.raw_event,
                invalid_signature,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "signature-threshold-not-met",
            fixture.engine.admit(
                fixture.raw_event,
                fixture.single_signatures,
                fixture.threshold_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "authority-scope-rejected",
            fixture.engine.admit(
                fixture.raw_event,
                wrong_scope,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "duplicate-signer-rejected",
            fixture.engine.admit(
                fixture.raw_event,
                duplicate_signer,
                fixture.single_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "validation-policy-not-allowed",
            fixture.engine.admit(
                fixture.raw_event,
                fixture.single_signatures,
                unknown_policy,
                validated_at_tick=41,
            ),
        ),
        (
            "validation-context-unavailable",
            fixture.engine.admit(
                fixture.raw_event,
                fixture.single_signatures,
                fixture.single_policy,
                validated_at_tick=99,
            ),
        ),
        (
            "validation-context-not-committed",
            fixture.engine.admit(
                fixture.raw_event,
                fixture.single_signatures,
                fixture.single_policy,
                validated_at_tick=42,
            ),
        ),
        (
            "validation-context-stale",
            fixture.engine.admit(
                fixture.raw_event,
                fixture.single_signatures,
                fixture.single_policy,
                validated_at_tick=40,
            ),
        ),
    )


def _expected_failure_codes() -> dict[str, tuple[str, ...]]:
    return {
        "authority-scope-rejected": (
            "AUTHORITY_SCOPE_REJECTED",
            "SIGNATURE_THRESHOLD_NOT_MET",
        ),
        "duplicate-signer-rejected": ("SIGNATURE_INVALID",),
        "raw-digest-mismatch": ("RAW_DIGEST_MISMATCH",),
        "raw-schema-rejected": ("RAW_SCHEMA_REJECTED",),
        "signature-algorithm-not-allowed": (
            "SIGNATURE_ALGORITHM_NOT_ALLOWED",
            "SIGNATURE_THRESHOLD_NOT_MET",
        ),
        "signature-digest-mismatch": (
            "SIGNATURE_DIGEST_MISMATCH",
            "SIGNATURE_THRESHOLD_NOT_MET",
        ),
        "signature-invalid": (
            "SIGNATURE_INVALID",
            "SIGNATURE_THRESHOLD_NOT_MET",
        ),
        "signature-threshold-not-met": ("SIGNATURE_THRESHOLD_NOT_MET",),
        "validation-context-not-committed": ("VALIDATION_CONTEXT_NOT_COMMITTED",),
        "validation-context-stale": ("VALIDATION_CONTEXT_NOT_COMMITTED",),
        "validation-context-unavailable": ("VALIDATION_CONTEXT_UNAVAILABLE",),
        "validation-policy-not-allowed": ("VALIDATION_POLICY_NOT_ALLOWED",),
    }


def _validate_restart_determinism(errors: list[str]) -> bool:
    with TemporaryDirectory(prefix="csd-admission-") as temporary:
        root = Path(temporary)
        first_store = FilesystemEventAdmissionStore(root)
        first_fixture = build_reference_admission_fixture(first_store)
        first = first_fixture.engine.admit(
            first_fixture.raw_event,
            first_fixture.threshold_signatures,
            first_fixture.threshold_policy,
            validated_at_tick=41,
        )
        if first.accepted is None:
            errors.append("filesystem admission fixture was rejected")
            return False

        second_store = FilesystemEventAdmissionStore(root)
        second_fixture = build_reference_admission_fixture(second_store)
        second = second_fixture.engine.admit(
            second_fixture.raw_event,
            second_fixture.threshold_signatures,
            second_fixture.threshold_policy,
            validated_at_tick=41,
        )
        if second.accepted is None:
            errors.append("restart admission fixture was rejected")
            return False
        if first.accepted.canonical_bytes != second.accepted.canonical_bytes:
            errors.append("admission receipt changed across process restart")
            return False
        bundle = reconstruct_accepted(second.accepted, second_store)
        if bundle.context.tick != 41:
            errors.append("restart reconstruction resolved the wrong context")
            return False
        return True


def _build_policy(*, policy_id: str, policy_version: int, threshold: int) -> ValidationPolicy:
    return cast(
        ValidationPolicy,
        ValidationPolicy.build(
            {
                "schema_version": "validation-policy/1",
                "policy_id": policy_id,
                "policy_version": policy_version,
                "canonicalization_policy_digest": _digest("canonicalization-policy-v1"),
                "authority_policy_digest": _digest("authority-policy-v1"),
                "accepted_raw_event_schemas": ["advance-clock/1"],
                "allowed_signature_algorithms": ["ed25519"],
                "minimum_signature_count": threshold,
            }
        ),
    )


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()
