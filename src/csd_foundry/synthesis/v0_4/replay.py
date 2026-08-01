"""Independent replay of deterministic choice and identity evidence."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.choice_ledger import ChoiceLedger
from csd_foundry.synthesis.v0_4.choice_records import (
    BooleanRatioChoiceRecord,
    BoundedIntegerChoiceRecord,
    ChoiceRecord,
    WeightedChoiceRecord,
    choice_record_bytes,
    record_from_boolean_result,
    record_from_bounded_result,
    record_from_weighted_result,
)
from csd_foundry.synthesis.v0_4.deterministic_choices import (
    bounded_integer,
    choose_ratio,
    weighted_choice,
)
from csd_foundry.synthesis.v0_4.generation_namespace import GenerationNamespace
from csd_foundry.synthesis.v0_4.identities import IdentityRecord, derive_identity
from csd_foundry.synthesis.v0_4.choice_paths import RootSeed
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256


class ReplayMismatchError(ValueError):
    """Raised when deterministic evidence cannot be reproduced exactly."""


@dataclass(frozen=True, slots=True)
class ReplayVerification:
    choice_record_count: int
    choice_ledger_digest: str
    identity_record_count: int
    identity_ledger_digest: str

    def __post_init__(self) -> None:
        if type(self) is not ReplayVerification:
            raise ReplayMismatchError("replay verification must use the exact contract class")
        if type(self.choice_record_count) is not int or self.choice_record_count < 0:
            raise ReplayMismatchError("choice_record_count must be nonnegative")
        if type(self.identity_record_count) is not int or self.identity_record_count < 0:
            raise ReplayMismatchError("identity_record_count must be nonnegative")
        for value in (self.choice_ledger_digest, self.identity_ledger_digest):
            if type(value) is not str or len(value) != 64:
                raise ReplayMismatchError("replay digests must be lowercase SHA-256 values")


def _replayed_record(
    seed: RootSeed,
    namespace: GenerationNamespace,
    record: ChoiceRecord,
) -> ChoiceRecord:
    if type(seed) is not RootSeed:
        raise ReplayMismatchError("replay seed must use the exact RootSeed class")
    if type(namespace) is not GenerationNamespace:
        raise ReplayMismatchError(
            "replay namespace must use the exact GenerationNamespace class"
        )
    if record.seed_commitment != seed.commitment:
        raise ReplayMismatchError("choice record seed commitment does not match")
    if record.generation_namespace_digest != namespace.digest:
        raise ReplayMismatchError("choice record generation namespace does not match")

    if type(record) is BoundedIntegerChoiceRecord:
        result = bounded_integer(seed, record.path, record.upper_exclusive)
        return record_from_bounded_result(
            path=record.path,
            generation_namespace_digest=namespace.digest,
            seed_commitment=seed.commitment,
            upper_exclusive=record.upper_exclusive,
            result=result,
        )
    if type(record) is WeightedChoiceRecord:
        result = weighted_choice(
            seed,
            record.path,
            record.values.to_json_value(),
            record.weights,
        )
        return record_from_weighted_result(
            path=record.path,
            generation_namespace_digest=namespace.digest,
            seed_commitment=seed.commitment,
            values=record.values,
            weights=record.weights,
            result=result,
        )
    if type(record) is BooleanRatioChoiceRecord:
        result = choose_ratio(
            seed,
            record.path,
            record.numerator,
            record.denominator,
        )
        return record_from_boolean_result(
            path=record.path,
            generation_namespace_digest=namespace.digest,
            seed_commitment=seed.commitment,
            numerator=record.numerator,
            denominator=record.denominator,
            result=result,
        )
    raise ReplayMismatchError("unsupported or non-exact choice record type")


def replay_choice_record(
    seed: RootSeed,
    namespace: GenerationNamespace,
    record: ChoiceRecord,
) -> None:
    replayed = _replayed_record(seed, namespace, record)
    if choice_record_bytes(replayed) != choice_record_bytes(record):
        raise ReplayMismatchError("choice record replay diverged")


def replay_choice_ledger(
    seed: RootSeed,
    namespace: GenerationNamespace,
    ledger: ChoiceLedger,
) -> str:
    if type(ledger) is not ChoiceLedger:
        raise ReplayMismatchError("choice ledger must use the exact contract class")
    if ledger.seed_commitment != seed.commitment:
        raise ReplayMismatchError("choice ledger seed commitment does not match")
    if ledger.generation_namespace_digest != namespace.digest:
        raise ReplayMismatchError("choice ledger generation namespace does not match")
    for record in ledger.records:
        replay_choice_record(seed, namespace, record)
    reconstructed = ChoiceLedger(
        seed_commitment=ledger.seed_commitment,
        generation_namespace_digest=ledger.generation_namespace_digest,
        attempt_key=ledger.attempt_key,
        producer_contract_id=ledger.producer_contract_id,
        allowed_namespace_prefix=ledger.allowed_namespace_prefix,
        records=ledger.records,
        schema_version=ledger.schema_version,
    )
    if reconstructed.canonical_bytes != ledger.canonical_bytes:
        raise ReplayMismatchError("choice ledger canonical reconstruction diverged")
    return ledger.canonical_digest


def replay_identity_records(
    seed: RootSeed,
    namespace: GenerationNamespace,
    records: tuple[IdentityRecord, ...],
    expected_digest: str,
) -> str:
    if type(records) is not tuple:
        raise ReplayMismatchError("identity records must be an immutable tuple")
    if not all(type(record) is IdentityRecord for record in records):
        raise ReplayMismatchError("identity records must use exact IdentityRecord values")
    if type(expected_digest) is not str or len(expected_digest) != 64:
        raise ReplayMismatchError("expected identity digest must be lowercase SHA-256")

    ordered = tuple(
        sorted(
            records,
            key=lambda record: canonical_json_bytes(record.request.to_json_value()),
        )
    )
    seen_requests: set[bytes] = set()
    seen_full: set[str] = set()
    seen_display: set[str] = set()
    for record in ordered:
        request_bytes = canonical_json_bytes(record.request.to_json_value())
        if request_bytes in seen_requests:
            raise ReplayMismatchError("identity replay contains a duplicate semantic role")
        seen_requests.add(request_bytes)
        replayed = derive_identity(seed, namespace, record.request)
        if replayed != record.identity:
            raise ReplayMismatchError("identity record replay diverged")
        if record.identity.full_digest in seen_full:
            raise ReplayMismatchError("identity replay contains a full-digest collision")
        if record.identity.display_id in seen_display:
            raise ReplayMismatchError("identity replay contains a display collision")
        seen_full.add(record.identity.full_digest)
        seen_display.add(record.identity.display_id)

    digest = canonical_sha256([record.to_json_value() for record in ordered])
    if digest != expected_digest:
        raise ReplayMismatchError("identity ledger digest diverged")
    return digest


def replay_bundle_commitment(
    *,
    choice_ledger: ChoiceLedger,
    identity_records: tuple[IdentityRecord, ...],
    identity_ledger_digest: str,
) -> str:
    """Commit independently replayable ledger evidence without retaining it in completions."""

    return canonical_sha256(
        {
            "choice_ledger": choice_ledger.to_json_value(),
            "identity_ledger_digest": identity_ledger_digest,
            "identity_records": [record.to_json_value() for record in identity_records],
        }
    )
