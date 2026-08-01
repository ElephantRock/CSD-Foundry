"""Versioned replay-policy, attempt-input, branch, and budget contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.canonical_values import CanonicalObject
from csd_foundry.synthesis.v0_4.choice_paths import AttemptKey, ChoiceValidationError
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

REPLAY_POLICY_ID = "csd-replay-contract"
REPLAY_POLICY_VERSION = 1
SEMANTIC_EXECUTION_MODE = "lowest-valid-attempt"
ATTEMPT_INPUT_SCHEMA_VERSION = "csd-attempt-input/0.4"
SEARCH_BRANCH_SCHEMA_VERSION = "csd-search-branch/0.4"

_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class ReplayContractError(ValueError):
    """Raised when replay evidence violates its versioned contract."""


class ChoiceBudgetExceeded(RuntimeError):
    """Raised when one attempt exceeds its deterministic choice budget."""

    def __init__(
        self,
        *,
        choice_count: int,
        maximum_choices: int,
        canonical_bytes: int,
        maximum_canonical_bytes: int,
    ) -> None:
        self.choice_count = choice_count
        self.maximum_choices = maximum_choices
        self.canonical_bytes = canonical_bytes
        self.maximum_canonical_bytes = maximum_canonical_bytes
        super().__init__(
            "choice budget exceeded: "
            f"count={choice_count}/{maximum_choices}, "
            f"canonical_bytes={canonical_bytes}/{maximum_canonical_bytes}"
        )


def _require_digest(value: object, field_name: str) -> str:
    if type(value) is not str or _HEX_256_PATTERN.fullmatch(value) is None:
        raise ReplayContractError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
        raise ReplayContractError(
            f"{field_name} must match [a-z0-9][a-z0-9._-]*"
        )
    return value


def _require_positive_integer(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReplayContractError(f"{field_name} must be a positive exact integer")
    return value


def _attempt_key_value(attempt_key: AttemptKey) -> dict[str, object]:
    if type(attempt_key) is not AttemptKey:
        raise ReplayContractError("attempt_key must use the exact AttemptKey class")
    sample = attempt_key.sample_key
    return {
        "attempt_index": attempt_key.attempt_index,
        "release": sample.release,
        "sample_index": sample.sample_index,
        "target_id": sample.target_id,
    }


@dataclass(frozen=True, slots=True)
class ChoiceBudget:
    maximum_choices_per_attempt: int
    maximum_canonical_ledger_bytes: int

    def __post_init__(self) -> None:
        if type(self) is not ChoiceBudget:
            raise ReplayContractError("choice budgets must use the exact contract class")
        _require_positive_integer(
            self.maximum_choices_per_attempt,
            "maximum_choices_per_attempt",
        )
        _require_positive_integer(
            self.maximum_canonical_ledger_bytes,
            "maximum_canonical_ledger_bytes",
        )


@dataclass(frozen=True, slots=True)
class AttemptInputCommitment:
    attempt_key: AttemptKey
    generation_namespace_digest: str
    producer_contract_id: str
    producer_contract_version: int
    producer_contract_digest: str
    payload: CanonicalObject
    schema_version: str = ATTEMPT_INPUT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttemptInputCommitment:
            raise ReplayContractError(
                "attempt input commitments must use the exact contract class"
            )
        _attempt_key_value(self.attempt_key)
        _require_digest(
            self.generation_namespace_digest,
            "generation_namespace_digest",
        )
        _require_token(self.producer_contract_id, "producer_contract_id")
        _require_positive_integer(
            self.producer_contract_version,
            "producer_contract_version",
        )
        _require_digest(self.producer_contract_digest, "producer_contract_digest")
        if type(self.payload) is not CanonicalObject:
            raise ReplayContractError("attempt input payload must be an exact CanonicalObject")
        if self.schema_version != ATTEMPT_INPUT_SCHEMA_VERSION:
            raise ReplayContractError(
                f"attempt input schema must be {ATTEMPT_INPUT_SCHEMA_VERSION}"
            )

    @property
    def payload_digest(self) -> str:
        return canonical_sha256(self.payload.to_json_value())

    def commitment_value(self) -> dict[str, object]:
        return {
            "attempt_key": _attempt_key_value(self.attempt_key),
            "generation_namespace_digest": self.generation_namespace_digest,
            "payload_digest": self.payload_digest,
            "producer_contract_digest": self.producer_contract_digest,
            "producer_contract_id": self.producer_contract_id,
            "producer_contract_version": self.producer_contract_version,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.commitment_value())

    def to_json_value(self) -> dict[str, object]:
        return {
            **self.commitment_value(),
            "commitment_digest": self.digest,
            "payload": self.payload.to_json_value(),
        }


@dataclass(frozen=True, slots=True)
class SearchBranchCommitment:
    attempt_key: AttemptKey
    generation_namespace_digest: str
    attempt_input_commitment_digest: str
    choice_ledger_digest: str
    branch_facts: CanonicalObject
    schema_version: str = SEARCH_BRANCH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not SearchBranchCommitment:
            raise ReplayContractError(
                "search branch commitments must use the exact contract class"
            )
        _attempt_key_value(self.attempt_key)
        _require_digest(
            self.generation_namespace_digest,
            "generation_namespace_digest",
        )
        _require_digest(
            self.attempt_input_commitment_digest,
            "attempt_input_commitment_digest",
        )
        _require_digest(self.choice_ledger_digest, "choice_ledger_digest")
        if type(self.branch_facts) is not CanonicalObject:
            raise ReplayContractError("branch_facts must be an exact CanonicalObject")
        if self.schema_version != SEARCH_BRANCH_SCHEMA_VERSION:
            raise ReplayContractError(
                f"search branch schema must be {SEARCH_BRANCH_SCHEMA_VERSION}"
            )

    def commitment_value(self) -> dict[str, object]:
        return {
            "attempt_input_commitment_digest": self.attempt_input_commitment_digest,
            "attempt_key": _attempt_key_value(self.attempt_key),
            "branch_facts": self.branch_facts.to_json_value(),
            "choice_ledger_digest": self.choice_ledger_digest,
            "generation_namespace_digest": self.generation_namespace_digest,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return canonical_sha256(self.commitment_value())

    def to_json_value(self) -> dict[str, object]:
        return {**self.commitment_value(), "search_branch_digest": self.digest}


def replay_policy_document() -> dict[str, object]:
    """Return the exact replay-policy v1 document committed by existing identities."""

    return {
        "policy_id": REPLAY_POLICY_ID,
        "policy_version": REPLAY_POLICY_VERSION,
        "semantic_execution_mode": SEMANTIC_EXECUTION_MODE,
    }
