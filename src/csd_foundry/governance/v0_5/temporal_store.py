"""In-memory and POSIX filesystem stores for atomic v0.5 temporal completion."""

from __future__ import annotations

import fcntl
import json
import os
import re
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, cast

from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    CONTRACT_TYPES,
    ClockClaim,
    ClockCompletionReceipt,
    ClockProjectionFailure,
    ContractObject,
    parse_contract,
)
from csd_foundry.governance.v0_5.temporal import (
    ClaimInstallResult,
    TemporalHead,
    TemporalProtocolError,
)

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ATTEMPT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


class TemporalStoreError(TemporalProtocolError):
    """Base class for temporal store failures."""


class TemporalStoreConflictError(TemporalStoreError):
    """Raised when an immutable or compare-and-append identity conflicts."""


class InMemoryTemporalStore:
    """Deterministic reference store with the same transitions as the filesystem store."""

    def __init__(self) -> None:
        self._head = TemporalHead(0, None)
        self._active: ClockClaim | None = None
        self._contracts: dict[tuple[str, str], bytes] = {}
        self._attempts: dict[tuple[str, str], bytes] = {}

    def read_head(self) -> TemporalHead:
        return self._head

    def claim_successor(self, expected_head: TemporalHead, claim: ClockClaim) -> ClaimInstallResult:
        self.put_contract(claim)
        _verify_claim_against_head(expected_head, claim)
        if self._head != expected_head:
            return ClaimInstallResult(claim, False, "STALE_EXPECTED_HEAD")
        if self._active is not None:
            if self._active.canonical_bytes == claim.canonical_bytes:
                return ClaimInstallResult(claim, True, "IDEMPOTENT_ACTIVE_CLAIM")
            return ClaimInstallResult(claim, False, "ACTIVE_SUCCESSOR_EXISTS")
        self._active = claim
        self.record_attempt_artifact(_attempt_id(claim), "claim", claim)
        return ClaimInstallResult(claim, True, "CLAIM_ACQUIRED")

    def put_contract(self, contract: ContractObject) -> None:
        key = (contract.CONTRACT_NAME, contract.digest)
        existing = self._contracts.get(key)
        if existing is not None and existing != contract.canonical_bytes:
            raise TemporalStoreConflictError("contract identity already contains different bytes")
        self._contracts[key] = contract.canonical_bytes

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        payload = self._contracts.get((contract_name, digest))
        return None if payload is None else _parse_contract_payload(contract_name, payload)

    def record_attempt_artifact(
        self,
        attempt_id: str,
        artifact_name: str,
        contract: ContractObject,
    ) -> None:
        _validate_attempt_component(attempt_id)
        _validate_attempt_component(artifact_name)
        self.put_contract(contract)
        key = (attempt_id, artifact_name)
        existing = self._attempts.get(key)
        if existing is not None and existing != contract.canonical_bytes:
            raise TemporalStoreConflictError("attempt artifact already contains different bytes")
        self._attempts[key] = contract.canonical_bytes

    def record_failure(self, claim: ClockClaim, failure: ClockProjectionFailure) -> None:
        _verify_failure_matches_claim(claim, failure)
        self.record_attempt_artifact(_attempt_id(claim), "failure", failure)
        if self._active is None or self._active.digest != claim.digest:
            raise TemporalStoreConflictError("failure does not own the active claim")
        self._active = None

    def prepare_completion(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
        _verify_completion_matches_claim(claim, completion)
        self.record_attempt_artifact(_attempt_id(claim), "completion", completion)

    def publish_completion(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        _verify_completion_matches_claim(claim, completion)
        if self._head.clock_sequence == _completion_sequence(completion):
            if self._head.completion_digest != completion.digest:
                raise TemporalStoreConflictError("clock sequence already committed with different bytes")
            return self._head
        if self._head != expected_head:
            raise TemporalStoreConflictError("committed head changed before completion publication")
        if self._active is None or self._active.digest != claim.digest:
            raise TemporalStoreConflictError("completion does not own the active claim")
        self.prepare_completion(claim, completion)
        self._head = TemporalHead(_completion_sequence(completion), completion.digest)
        self._active = None
        return self._head

    def current_snapshot(self) -> ClockCompletionReceipt | None:
        if self._head.completion_digest is None:
            return None
        contract = self.get_contract("clock-completion-receipt", self._head.completion_digest)
        if type(contract) is not ClockCompletionReceipt:
            raise TemporalStoreConflictError("committed head completion is unavailable")
        return contract

    def reconstruct_chain(self) -> tuple[ClockCompletionReceipt, ...]:
        return _reconstruct_chain(self)

    def recover(self) -> str:
        if self._active is None:
            return "NO_ACTIVE_CLAIM"
        attempt_id = _attempt_id(self._active)
        prepared = self._attempts.get((attempt_id, "completion"))
        if prepared is not None:
            completion = _parse_contract_payload("clock-completion-receipt", prepared)
            if type(completion) is not ClockCompletionReceipt:
                raise TemporalStoreConflictError("prepared completion has wrong type")
            expected = TemporalHead(
                _claim_previous_sequence(self._active),
                _claim_previous_completion(self._active),
            )
            self.publish_completion(expected, self._active, completion)
            return "PREPARED_COMPLETION_PUBLISHED"
        failure = _recovery_failure(self._active)
        self.record_failure(self._active, failure)
        return "INCOMPLETE_ATTEMPT_FAILED"


class FilesystemTemporalStore:
    """POSIX reference store using a process-shared lock and durable head pointer."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TemporalStoreError("temporal root must be a pathlib Path")
        self.root = root
        self.objects_root = root / "objects"
        self.attempts_root = root / "attempts"
        self.state_root = root / "state"
        self.temporary_root = root / ".tmp"
        self.lock_path = self.state_root / "temporal.lock"
        self.head_path = self.state_root / "head.json"
        self.active_path = self.state_root / "active-claim.json"
        for directory in (
            self.root,
            self.objects_root,
            self.attempts_root,
            self.state_root,
            self.temporary_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)
        _fsync_directory(self.state_root)
        with self._exclusive_lock():
            if not self.head_path.exists():
                self._replace_pointer(self.head_path, _head_bytes(TemporalHead(0, None)))

    def read_head(self) -> TemporalHead:
        with self._exclusive_lock():
            return self._read_head_unlocked()

    def claim_successor(self, expected_head: TemporalHead, claim: ClockClaim) -> ClaimInstallResult:
        self.put_contract(claim)
        _verify_claim_against_head(expected_head, claim)
        self.record_attempt_artifact(_attempt_id(claim), "claim", claim)
        with self._exclusive_lock():
            current = self._read_head_unlocked()
            if current != expected_head:
                return ClaimInstallResult(claim, False, "STALE_EXPECTED_HEAD")
            active = self._read_active_unlocked()
            if active is not None:
                if active.digest == claim.digest:
                    return ClaimInstallResult(claim, True, "IDEMPOTENT_ACTIVE_CLAIM")
                return ClaimInstallResult(claim, False, "ACTIVE_SUCCESSOR_EXISTS")
            self._replace_pointer(self.active_path, _active_bytes(claim))
            return ClaimInstallResult(claim, True, "CLAIM_ACQUIRED")

    def put_contract(self, contract: ContractObject) -> None:
        path = self._contract_path(contract.CONTRACT_NAME, contract.digest)
        self._atomic_install(path, contract.canonical_bytes)

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        path = self._contract_path(contract_name, digest)
        if not path.is_file():
            return None
        contract = _parse_contract_payload(contract_name, path.read_bytes())
        if contract.digest != digest:
            raise TemporalStoreConflictError("stored contract does not match its identity path")
        return contract

    def record_attempt_artifact(
        self,
        attempt_id: str,
        artifact_name: str,
        contract: ContractObject,
    ) -> None:
        _validate_attempt_component(attempt_id)
        _validate_attempt_component(artifact_name)
        self.put_contract(contract)
        path = self.attempts_root / attempt_id / f"{artifact_name}.json"
        self._atomic_install(path, contract.canonical_bytes)

    def record_failure(self, claim: ClockClaim, failure: ClockProjectionFailure) -> None:
        _verify_failure_matches_claim(claim, failure)
        self.record_attempt_artifact(_attempt_id(claim), "failure", failure)
        with self._exclusive_lock():
            active = self._read_active_unlocked()
            if active is None or active.digest != claim.digest:
                raise TemporalStoreConflictError("failure does not own the active claim")
            self.active_path.unlink(missing_ok=True)
            _fsync_directory(self.state_root)

    def prepare_completion(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
        _verify_completion_matches_claim(claim, completion)
        self.record_attempt_artifact(_attempt_id(claim), "completion", completion)

    def publish_completion(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        _verify_completion_matches_claim(claim, completion)
        self.prepare_completion(claim, completion)
        with self._exclusive_lock():
            return self._publish_completion_unlocked(expected_head, claim, completion)

    def current_snapshot(self) -> ClockCompletionReceipt | None:
        with self._exclusive_lock():
            head = self._read_head_unlocked()
        if head.completion_digest is None:
            return None
        contract = self.get_contract("clock-completion-receipt", head.completion_digest)
        if type(contract) is not ClockCompletionReceipt:
            raise TemporalStoreConflictError("committed head completion is unavailable")
        return contract

    def reconstruct_chain(self) -> tuple[ClockCompletionReceipt, ...]:
        return _reconstruct_chain(self)

    def recover(self) -> str:
        removed = 0
        for path in sorted(self.temporary_root.glob("*.tmp")):
            path.unlink(missing_ok=True)
            removed += 1
        if removed:
            _fsync_directory(self.temporary_root)
        with self._exclusive_lock():
            active = self._read_active_unlocked()
            if active is None:
                return "NO_ACTIVE_CLAIM"
            attempt_id = _attempt_id(active)
            completion_path = self.attempts_root / attempt_id / "completion.json"
            if completion_path.is_file():
                completion = _parse_contract_payload(
                    "clock-completion-receipt",
                    completion_path.read_bytes(),
                )
                if type(completion) is not ClockCompletionReceipt:
                    raise TemporalStoreConflictError("prepared completion has wrong type")
                expected = TemporalHead(
                    _claim_previous_sequence(active),
                    _claim_previous_completion(active),
                )
                self._publish_completion_unlocked(expected, active, completion)
                return "PREPARED_COMPLETION_PUBLISHED"
            failure = _recovery_failure(active)
            self.record_attempt_artifact(attempt_id, "failure", failure)
            self.active_path.unlink(missing_ok=True)
            _fsync_directory(self.state_root)
            return "INCOMPLETE_ATTEMPT_FAILED"

    def _publish_completion_unlocked(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        current = self._read_head_unlocked()
        sequence = _completion_sequence(completion)
        if current.clock_sequence == sequence:
            if current.completion_digest != completion.digest:
                raise TemporalStoreConflictError("clock sequence already committed with different bytes")
            self.active_path.unlink(missing_ok=True)
            _fsync_directory(self.state_root)
            return current
        if current != expected_head:
            raise TemporalStoreConflictError("committed head changed before completion publication")
        active = self._read_active_unlocked()
        if active is None or active.digest != claim.digest:
            raise TemporalStoreConflictError("completion does not own the active claim")
        new_head = TemporalHead(sequence, completion.digest)
        self._replace_pointer(self.head_path, _head_bytes(new_head))
        self.active_path.unlink(missing_ok=True)
        _fsync_directory(self.state_root)
        return new_head

    def _read_head_unlocked(self) -> TemporalHead:
        try:
            payload = self.head_path.read_bytes()
        except OSError as exc:
            raise TemporalStoreConflictError("committed head is unavailable") from exc
        return _parse_head(payload)

    def _read_active_unlocked(self) -> ClockClaim | None:
        if not self.active_path.is_file():
            return None
        try:
            value = json.loads(self.active_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TemporalStoreConflictError("active claim pointer is invalid") from exc
        if type(value) is not dict or set(value) != {
            "schema_version",
            "clock_claim_digest",
        }:
            raise TemporalStoreConflictError("active claim pointer has invalid fields")
        digest = value.get("clock_claim_digest")
        contract = self.get_contract("clock-claim", cast(str, digest))
        if type(contract) is not ClockClaim:
            raise TemporalStoreConflictError("active claim object is unavailable")
        return contract

    def _contract_path(self, contract_name: str, digest: str) -> Path:
        if contract_name not in CONTRACT_TYPES:
            raise TemporalStoreError("unknown v0.5 contract name")
        hex_digest = _digest_hex(digest)
        return self.objects_root / contract_name / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _atomic_install(self, final_path: Path, payload: bytes) -> None:
        if type(payload) is not bytes:
            raise TemporalStoreError("temporal payload must use the exact bytes type")
        final_path.parent.mkdir(parents=True, exist_ok=True)
        _fsync_directory(final_path.parent)
        if final_path.exists():
            if final_path.read_bytes() != payload:
                raise TemporalStoreConflictError("immutable path already contains different bytes")
            return
        temporary_path = self.temporary_root / f"{uuid.uuid4().hex}.tmp"
        with temporary_path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, final_path)
        except FileExistsError:
            if final_path.read_bytes() != payload:
                raise TemporalStoreConflictError(
                    "concurrent immutable install contains different bytes"
                ) from None
        _fsync_directory(final_path.parent)
        temporary_path.unlink(missing_ok=True)
        _fsync_directory(self.temporary_root)

    def _replace_pointer(self, final_path: Path, payload: bytes) -> None:
        temporary_path = self.temporary_root / f"{uuid.uuid4().hex}.tmp"
        with temporary_path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, final_path)
        _fsync_directory(final_path.parent)
        _fsync_directory(self.temporary_root)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self.lock_path.open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _reconstruct_chain(
    store: InMemoryTemporalStore | FilesystemTemporalStore,
) -> tuple[ClockCompletionReceipt, ...]:
    head = store.read_head()
    if head.completion_digest is None:
        return ()
    descending: list[ClockCompletionReceipt] = []
    digest: str | None = head.completion_digest
    expected_sequence = head.clock_sequence
    while digest is not None:
        contract = store.get_contract("clock-completion-receipt", digest)
        if type(contract) is not ClockCompletionReceipt:
            raise TemporalStoreConflictError("completion chain object is unavailable")
        value = contract.to_json_value()
        if value["clock_sequence"] != expected_sequence:
            raise TemporalStoreConflictError("completion chain sequence is discontinuous")
        descending.append(contract)
        digest = cast(str | None, value["previous_completion_digest"])
        expected_sequence -= 1
    if expected_sequence != 0:
        raise TemporalStoreConflictError("completion chain does not terminate at genesis")
    return tuple(reversed(descending))


def _verify_claim_against_head(head: TemporalHead, claim: ClockClaim) -> None:
    value = claim.to_json_value()
    if value["previous_committed_sequence"] != head.clock_sequence:
        raise TemporalStoreConflictError("claim predecessor sequence does not match expected head")
    if value["previous_completion_digest"] != head.completion_digest:
        raise TemporalStoreConflictError("claim predecessor digest does not match expected head")
    if value["proposed_sequence"] != head.clock_sequence + 1:
        raise TemporalStoreConflictError("claim is not the immediate successor")


def _verify_failure_matches_claim(claim: ClockClaim, failure: ClockProjectionFailure) -> None:
    claim_value = claim.to_json_value()
    value = failure.to_json_value()
    pairs = (
        ("attempt_id", "attempt_id"),
        ("previous_committed_sequence", "previous_committed_sequence"),
        ("previous_completion_digest", "previous_completion_digest"),
        ("proposed_sequence", "proposed_sequence"),
        ("validated_event_digest", "validated_event_digest"),
    )
    if any(value[left] != claim_value[right] for left, right in pairs):
        raise TemporalStoreConflictError("failure receipt does not match its claim")
    if value["clock_claim_digest"] != claim.digest:
        raise TemporalStoreConflictError("failure receipt cites a different claim")


def _verify_completion_matches_claim(claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
    claim_value = claim.to_json_value()
    value = completion.to_json_value()
    if value["clock_claim_digest"] != claim.digest:
        raise TemporalStoreConflictError("completion cites a different claim")
    if value["validated_event_digest"] != claim_value["validated_event_digest"]:
        raise TemporalStoreConflictError("completion cites a different validated event")
    if value["clock_sequence"] != claim_value["proposed_sequence"]:
        raise TemporalStoreConflictError("completion sequence does not match its claim")
    if value["previous_completion_digest"] != claim_value["previous_completion_digest"]:
        raise TemporalStoreConflictError("completion predecessor does not match its claim")


def _recovery_failure(claim: ClockClaim) -> ClockProjectionFailure:
    value = claim.to_json_value()
    return cast(
        ClockProjectionFailure,
        ClockProjectionFailure.build(
            {
                "schema_version": "clock-projection-failure/1",
                "attempt_id": value["attempt_id"],
                "previous_committed_sequence": value["previous_committed_sequence"],
                "previous_completion_digest": value["previous_completion_digest"],
                "proposed_sequence": value["proposed_sequence"],
                "clock_claim_digest": claim.digest,
                "validated_event_digest": value["validated_event_digest"],
                "failure_phase": "SEMANTIC",
                "failure_code": "RECOVERY_INCOMPLETE_ATTEMPT",
                "failure_detail_digest": None,
                "recorded_against_tick": value["previous_committed_sequence"],
            }
        ),
    )


def _parse_contract_payload(contract_name: str, payload: bytes) -> ContractObject:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TemporalStoreConflictError("stored contract bytes are not canonical JSON") from exc
    if type(value) is not dict:
        raise TemporalStoreConflictError("stored contract root is not an object")
    try:
        contract = parse_contract(contract_name, cast(dict[str, Any], value))
    except GovernanceContractError as exc:
        raise TemporalStoreConflictError("stored contract fails frozen validation") from exc
    if contract.canonical_bytes != payload:
        raise TemporalStoreConflictError("stored contract bytes are not canonical")
    return contract


def _head_bytes(head: TemporalHead) -> bytes:
    value = {
        "schema_version": "temporal-head/1",
        "clock_sequence": head.clock_sequence,
        "completion_digest": head.completion_digest,
    }
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")


def _parse_head(payload: bytes) -> TemporalHead:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TemporalStoreConflictError("committed head bytes are invalid") from exc
    if type(value) is not dict or set(value) != {
        "schema_version",
        "clock_sequence",
        "completion_digest",
    }:
        raise TemporalStoreConflictError("committed head fields are invalid")
    if value.get("schema_version") != "temporal-head/1":
        raise TemporalStoreConflictError("committed head schema version is invalid")
    head = TemporalHead(
        cast(int, value["clock_sequence"]),
        cast(str | None, value["completion_digest"]),
    )
    if _head_bytes(head) != payload:
        raise TemporalStoreConflictError("committed head bytes are not canonical")
    return head


def _active_bytes(claim: ClockClaim) -> bytes:
    value = {
        "schema_version": "active-clock-claim/1",
        "clock_claim_digest": claim.digest,
    }
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")


def _attempt_id(claim: ClockClaim) -> str:
    value = claim.to_json_value().get("attempt_id")
    if type(value) is not str:
        raise TemporalStoreConflictError("claim attempt id is invalid")
    return value


def _claim_previous_sequence(claim: ClockClaim) -> int:
    value = claim.to_json_value().get("previous_committed_sequence")
    if type(value) is not int:
        raise TemporalStoreConflictError("claim predecessor sequence is invalid")
    return value


def _claim_previous_completion(claim: ClockClaim) -> str | None:
    value = claim.to_json_value().get("previous_completion_digest")
    if value is not None and type(value) is not str:
        raise TemporalStoreConflictError("claim predecessor digest is invalid")
    return cast(str | None, value)


def _completion_sequence(completion: ClockCompletionReceipt) -> int:
    value = completion.to_json_value().get("clock_sequence")
    if type(value) is not int:
        raise TemporalStoreConflictError("completion sequence is invalid")
    return value


def _validate_attempt_component(value: object) -> None:
    if type(value) is not str or _ATTEMPT_PATTERN.fullmatch(value) is None:
        raise TemporalStoreError("attempt path component is invalid")


def _digest_hex(value: object) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise TemporalStoreError("identity must be a canonical sha256 digest")
    return value.removeprefix("sha256:")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
