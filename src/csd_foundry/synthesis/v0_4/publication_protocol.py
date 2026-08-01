"""Topology-independent completion envelopes and append-only publication evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from csd_foundry.synthesis.v0_4.attempts import AttemptAccepted, AttemptRejected
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, SampleKey
from csd_foundry.synthesis.v0_4.execution_protocol import (
    ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION,
    INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION,
    OPERATIONAL_PUBLICATION_SCHEMA_VERSION,
    ExecutionInventory,
    SampleExecutionSpec,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes, canonical_sha256

_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_UINT32_MAX = (1 << 32) - 1


class PublicationProtocolError(ValueError):
    """Raised when publication evidence violates the v0.4 contract."""


class CompletionStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class PublicationObjectKind(StrEnum):
    ATTEMPT_COMPLETION_ENVELOPE = "attempt-completion-envelope"
    INVENTORY_COMPLETION_REFERENCE = "inventory-completion-reference"
    SHARD_INDEX = "shard-index"
    SHARD_MANIFEST = "shard-manifest"


class PublicationDisposition(StrEnum):
    PUBLISHED = "published"
    EXISTING_IDENTICAL = "existing-identical"


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise PublicationProtocolError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise PublicationProtocolError(f"{field_name} must be a lowercase ASCII token")
    return value


def _sample_key_value(sample_key: SampleKey) -> dict[str, object]:
    if type(sample_key) is not SampleKey:
        raise PublicationProtocolError("sample_key must use the exact SampleKey class")
    return {
        "release": sample_key.release,
        "sample_index": sample_key.sample_index,
        "target_id": sample_key.target_id,
    }


def _attempt_key_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey:
        raise PublicationProtocolError("attempt_key must use the exact AttemptKey class")
    return {
        **_sample_key_value(attempt_key.sample_key),
        "attempt_index": attempt_key.attempt_index,
    }


@dataclass(frozen=True, slots=True, init=False)
class AttemptCompletionEnvelope:
    """Topology-independent semantic completion commitment."""

    attempt_key: AttemptKey
    generation_namespace_digest: str
    attempt_input_commitment_digest: str
    completion_status: CompletionStatus
    completion_digest: str
    search_branch_digest: str
    choice_ledger_digest: str
    identity_ledger_digest: str
    schema_version: str = ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttemptCompletionEnvelope:
            raise PublicationProtocolError("completion envelopes must use the exact class")
        _attempt_key_value(self.attempt_key)
        for field_name, value in (
            ("generation_namespace_digest", self.generation_namespace_digest),
            ("attempt_input_commitment_digest", self.attempt_input_commitment_digest),
            ("completion_digest", self.completion_digest),
            ("search_branch_digest", self.search_branch_digest),
            ("choice_ledger_digest", self.choice_ledger_digest),
            ("identity_ledger_digest", self.identity_ledger_digest),
        ):
            _require_digest(value, field_name)
        if type(self.completion_status) is not CompletionStatus:
            raise PublicationProtocolError("completion_status must use the exact enum")
        if self.schema_version != ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION:
            raise PublicationProtocolError(
                "completion envelope schema version does not match the v0.4 registry"
            )

    @classmethod
    def from_completion(
        cls,
        completion: AttemptAccepted | AttemptRejected,
    ) -> AttemptCompletionEnvelope:
        if cls is not AttemptCompletionEnvelope:
            raise PublicationProtocolError("completion construction requires the exact class")
        if type(completion) is AttemptAccepted:
            status = CompletionStatus.ACCEPTED
        elif type(completion) is AttemptRejected:
            status = CompletionStatus.REJECTED
        else:
            raise PublicationProtocolError(
                "semantic completion must be an exact AttemptAccepted or AttemptRejected"
            )
        envelope = object.__new__(AttemptCompletionEnvelope)
        object.__setattr__(envelope, "attempt_key", completion.attempt_key)
        object.__setattr__(
            envelope,
            "generation_namespace_digest",
            completion.generation_namespace_digest,
        )
        object.__setattr__(
            envelope,
            "attempt_input_commitment_digest",
            completion.attempt_input_commitment_digest,
        )
        object.__setattr__(envelope, "completion_status", status)
        object.__setattr__(envelope, "completion_digest", completion.completion_digest)
        object.__setattr__(envelope, "search_branch_digest", completion.search_branch_digest)
        object.__setattr__(envelope, "choice_ledger_digest", completion.choice_ledger_digest)
        object.__setattr__(envelope, "identity_ledger_digest", completion.identity_ledger_digest)
        object.__setattr__(
            envelope,
            "schema_version",
            ATTEMPT_COMPLETION_ENVELOPE_SCHEMA_VERSION,
        )
        envelope.__post_init__()
        return envelope

    def validate_completion(self, completion: AttemptAccepted | AttemptRejected) -> None:
        expected = AttemptCompletionEnvelope.from_completion(completion)
        if self != expected:
            raise PublicationProtocolError(
                "completion envelope does not match the supplied semantic completion"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_input_commitment_digest": self.attempt_input_commitment_digest,
            "attempt_key": _attempt_key_value(self.attempt_key),
            "choice_ledger_digest": self.choice_ledger_digest,
            "completion_digest": self.completion_digest,
            "completion_status": self.completion_status.value,
            "generation_namespace_digest": self.generation_namespace_digest,
            "identity_ledger_digest": self.identity_ledger_digest,
            "schema_version": self.schema_version,
            "search_branch_digest": self.search_branch_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True, init=False)
class InventoryCompletionReference:
    """Inventory-authorized reference to one topology-independent completion envelope."""

    inventory_digest: str
    global_ordinal: int
    sample_key: SampleKey
    attempt_key: AttemptKey
    sample_execution_spec_digest: str
    completion_envelope_digest: str
    schema_version: str = INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not InventoryCompletionReference:
            raise PublicationProtocolError("inventory references must use the exact class")
        _require_digest(self.inventory_digest, "inventory_digest")
        if type(self.global_ordinal) is not int or not 0 <= self.global_ordinal <= _UINT32_MAX:
            raise PublicationProtocolError("global_ordinal must be an exact uint32")
        _sample_key_value(self.sample_key)
        _attempt_key_value(self.attempt_key)
        if self.attempt_key.sample_key != self.sample_key:
            raise PublicationProtocolError("attempt_key and sample_key must identify one sample")
        _require_digest(self.sample_execution_spec_digest, "sample_execution_spec_digest")
        _require_digest(self.completion_envelope_digest, "completion_envelope_digest")
        if self.schema_version != INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION:
            raise PublicationProtocolError(
                "inventory reference schema version does not match the v0.4 registry"
            )

    @classmethod
    def from_inventory(
        cls,
        inventory: ExecutionInventory,
        envelope: AttemptCompletionEnvelope,
    ) -> InventoryCompletionReference:
        if cls is not InventoryCompletionReference:
            raise PublicationProtocolError("inventory reference construction requires exact class")
        if type(inventory) is not ExecutionInventory:
            raise PublicationProtocolError("inventory reference requires an exact inventory")
        if type(envelope) is not AttemptCompletionEnvelope:
            raise PublicationProtocolError("inventory reference requires an exact envelope")
        if envelope.generation_namespace_digest != inventory.generation_namespace_digest:
            raise PublicationProtocolError(
                "completion namespace does not match the execution inventory"
            )
        matching = tuple(
            spec for spec in inventory.samples if spec.sample_key == envelope.attempt_key.sample_key
        )
        if len(matching) != 1:
            raise PublicationProtocolError("completion sample is absent from the inventory")
        spec = matching[0]
        if not spec.attempt_range.contains(envelope.attempt_key.attempt_index):
            raise PublicationProtocolError(
                "completion attempt is outside the inventory attempt range"
            )
        reference = object.__new__(InventoryCompletionReference)
        object.__setattr__(reference, "inventory_digest", inventory.digest)
        object.__setattr__(reference, "global_ordinal", spec.global_ordinal)
        object.__setattr__(reference, "sample_key", spec.sample_key)
        object.__setattr__(reference, "attempt_key", envelope.attempt_key)
        object.__setattr__(reference, "sample_execution_spec_digest", spec.digest)
        object.__setattr__(reference, "completion_envelope_digest", envelope.digest)
        object.__setattr__(
            reference,
            "schema_version",
            INVENTORY_COMPLETION_REFERENCE_SCHEMA_VERSION,
        )
        reference.__post_init__()
        return reference

    def validate_against(
        self,
        inventory: ExecutionInventory,
        envelope: AttemptCompletionEnvelope,
    ) -> None:
        expected = InventoryCompletionReference.from_inventory(inventory, envelope)
        if self != expected:
            raise PublicationProtocolError(
                "inventory completion reference does not match its authority"
            )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "completion_envelope_digest": self.completion_envelope_digest,
            "global_ordinal": self.global_ordinal,
            "inventory_digest": self.inventory_digest,
            "sample_execution_spec_digest": self.sample_execution_spec_digest,
            "sample_key": _sample_key_value(self.sample_key),
            "schema_version": self.schema_version,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


@dataclass(frozen=True, slots=True)
class OperationalPublicationReceipt:
    """Append-only operational receipt that never enters semantic completion identity."""

    execution_run_id: str
    inventory_digest: str
    attempt_key: AttemptKey
    publication_ordinal: int
    object_kind: PublicationObjectKind
    object_digest: str
    disposition: PublicationDisposition
    previous_publication_receipt_digest: str | None
    schema_version: str = OPERATIONAL_PUBLICATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not OperationalPublicationReceipt:
            raise PublicationProtocolError("publication receipts must use the exact class")
        _require_token(self.execution_run_id, "execution_run_id")
        _require_digest(self.inventory_digest, "inventory_digest")
        _attempt_key_value(self.attempt_key)
        if (
            type(self.publication_ordinal) is not int
            or not 0 <= self.publication_ordinal <= _UINT32_MAX
        ):
            raise PublicationProtocolError("publication_ordinal must be an exact uint32")
        if type(self.object_kind) is not PublicationObjectKind:
            raise PublicationProtocolError("object_kind must use the exact enum")
        _require_digest(self.object_digest, "object_digest")
        if type(self.disposition) is not PublicationDisposition:
            raise PublicationProtocolError("disposition must use the exact enum")
        if self.publication_ordinal == 0:
            if self.previous_publication_receipt_digest is not None:
                raise PublicationProtocolError(
                    "initial publication receipt cannot reference a predecessor"
                )
        else:
            _require_digest(
                self.previous_publication_receipt_digest,
                "previous_publication_receipt_digest",
            )
        if self.schema_version != OPERATIONAL_PUBLICATION_SCHEMA_VERSION:
            raise PublicationProtocolError(
                "publication receipt schema version does not match the v0.4 registry"
            )

    @classmethod
    def append(
        cls,
        *,
        previous: OperationalPublicationReceipt | None,
        execution_run_id: str,
        inventory_digest: str,
        attempt_key: AttemptKey,
        object_kind: PublicationObjectKind,
        object_digest: str,
        disposition: PublicationDisposition,
    ) -> OperationalPublicationReceipt:
        if cls is not OperationalPublicationReceipt:
            raise PublicationProtocolError("publication receipt construction requires exact class")
        if previous is not None and type(previous) is not OperationalPublicationReceipt:
            raise PublicationProtocolError("previous receipt must use the exact class")
        ordinal = 0 if previous is None else previous.publication_ordinal + 1
        if previous is not None:
            if previous.execution_run_id != execution_run_id:
                raise PublicationProtocolError("publication receipt chain spans execution runs")
            if previous.inventory_digest != inventory_digest:
                raise PublicationProtocolError("publication receipt chain spans inventories")
            if previous.attempt_key != attempt_key:
                raise PublicationProtocolError("publication receipt chain spans attempts")
        return cls(
            execution_run_id=execution_run_id,
            inventory_digest=inventory_digest,
            attempt_key=attempt_key,
            publication_ordinal=ordinal,
            object_kind=object_kind,
            object_digest=object_digest,
            disposition=disposition,
            previous_publication_receipt_digest=(None if previous is None else previous.digest),
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "disposition": self.disposition.value,
            "execution_run_id": self.execution_run_id,
            "inventory_digest": self.inventory_digest,
            "object_digest": self.object_digest,
            "object_kind": self.object_kind.value,
            "previous_publication_receipt_digest": (self.previous_publication_receipt_digest),
            "publication_ordinal": self.publication_ordinal,
            "schema_version": self.schema_version,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_json_value())

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_json_value())


def validate_publication_receipt_chain(
    receipts: tuple[OperationalPublicationReceipt, ...],
) -> tuple[OperationalPublicationReceipt, ...]:
    if type(receipts) is not tuple or not receipts:
        raise PublicationProtocolError("publication receipt chain requires an immutable tuple")
    if not all(type(receipt) is OperationalPublicationReceipt for receipt in receipts):
        raise PublicationProtocolError("publication receipt chain contains a derived value")
    first = receipts[0]
    for index, receipt in enumerate(receipts):
        if receipt.execution_run_id != first.execution_run_id:
            raise PublicationProtocolError("publication receipt chain spans execution runs")
        if receipt.inventory_digest != first.inventory_digest:
            raise PublicationProtocolError("publication receipt chain spans inventories")
        if receipt.attempt_key != first.attempt_key:
            raise PublicationProtocolError("publication receipt chain spans attempts")
        if receipt.publication_ordinal != index:
            raise PublicationProtocolError(
                "publication receipt ordinals must be contiguous from zero"
            )
        expected_previous = None if index == 0 else receipts[index - 1].digest
        if receipt.previous_publication_receipt_digest != expected_previous:
            raise PublicationProtocolError("publication receipt previous-digest chain is broken")
    return receipts


def reference_spec(
    inventory: ExecutionInventory,
    reference: InventoryCompletionReference,
) -> SampleExecutionSpec:
    """Resolve and verify the unique inventory spec committed by a reference."""

    if type(inventory) is not ExecutionInventory:
        raise PublicationProtocolError("reference resolution requires an exact inventory")
    if type(reference) is not InventoryCompletionReference:
        raise PublicationProtocolError("reference resolution requires an exact reference")
    if reference.inventory_digest != inventory.digest:
        raise PublicationProtocolError("reference belongs to a different inventory")
    matching = tuple(
        spec
        for spec in inventory.samples
        if spec.global_ordinal == reference.global_ordinal
        and spec.sample_key == reference.sample_key
    )
    if len(matching) != 1:
        raise PublicationProtocolError("reference does not resolve one inventory spec")
    spec = matching[0]
    if spec.digest != reference.sample_execution_spec_digest:
        raise PublicationProtocolError("reference sample-spec digest does not match")
    if not spec.attempt_range.contains(reference.attempt_key.attempt_index):
        raise PublicationProtocolError("reference attempt is outside the declared range")
    return spec
