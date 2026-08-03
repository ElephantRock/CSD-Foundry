"""POSIX compare-and-append storage for v0.5 atomic temporal completion."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from csd_foundry._platform import advisory_lock, fsync_directory
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import (
    CONTRACT_TYPES,
    ClockClaim,
    ClockCompletionReceipt,
    ClockProjectionFailure,
    ContractObject,
    SemanticProjectionReceipt,
    parse_contract,
)
from csd_foundry.governance.v0_5.temporal import (
    ClaimInstallResult,
    ProjectionArtifacts,
    TemporalHead,
    TemporalProtocolError,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_PHASES = [
    "EVIDENCE_REGISTRY",
    "ASSUMPTION_REGISTRY",
    "ALTERNATIVE_MODEL_REGISTRY",
    "DISPOSITION",
    "QUARANTINE_COMMIT",
]


class TemporalStoreError(TemporalProtocolError):
    """Base class for temporal persistence failures."""


class TemporalStoreConflictError(TemporalStoreError):
    """Raised when immutable bytes or a compare-and-append precondition conflict."""


class InMemoryTemporalStore:
    """Ephemeral reference store backed by the same filesystem protocol."""

    def __init__(self) -> None:
        self._temporary = TemporaryDirectory()
        self._store = FilesystemTemporalStore(Path(self._temporary.name))

    def read_head(self) -> TemporalHead:
        return self._store.read_head()

    def claim_successor(self, expected_head: TemporalHead, claim: ClockClaim) -> ClaimInstallResult:
        return self._store.claim_successor(expected_head, claim)

    def put_contract(self, contract: ContractObject) -> None:
        self._store.put_contract(contract)

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        return self._store.get_contract(contract_name, digest)

    def record_attempt_artifact(
        self, attempt_id: str, artifact_name: str, contract: ContractObject
    ) -> None:
        self._store.record_attempt_artifact(attempt_id, artifact_name, contract)

    def record_projection_artifacts(
        self,
        claim: ClockClaim,
        semantic_receipt: SemanticProjectionReceipt,
        artifacts: ProjectionArtifacts,
    ) -> None:
        self._store.record_projection_artifacts(claim, semantic_receipt, artifacts)

    def record_failure(self, claim: ClockClaim, failure: ClockProjectionFailure) -> None:
        self._store.record_failure(claim, failure)

    def prepare_completion(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
        self._store.prepare_completion(claim, completion)

    def publish_completion(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        return self._store.publish_completion(expected_head, claim, completion)

    def current_snapshot(self) -> ClockCompletionReceipt | None:
        return self._store.current_snapshot()

    def reconstruct_chain(self) -> tuple[ClockCompletionReceipt, ...]:
        return self._store.reconstruct_chain()

    def recover(self) -> str:
        return self._store.recover()


class FilesystemTemporalStore:
    """Single-host POSIX store with process-shared locking and durable visibility."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TemporalStoreError("temporal root must be a pathlib Path")
        self.root = root
        self.objects = root / "objects"
        self.attempts = root / "attempts"
        self.state = root / "state"
        self.temporary = root / ".tmp"
        self.lock_path = self.state / "temporal.lock"
        self.head_path = self.state / "head.json"
        self.active_path = self.state / "active-claim.json"
        for directory in (root, self.objects, self.attempts, self.state, self.temporary):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)
        with self._lock():
            if not self.head_path.exists():
                self._replace(self.head_path, _head_bytes(TemporalHead(0, None)))

    def read_head(self) -> TemporalHead:
        with self._lock():
            return self._read_head()

    def claim_successor(self, expected_head: TemporalHead, claim: ClockClaim) -> ClaimInstallResult:
        _verify_claim(expected_head, claim)
        self.record_attempt_artifact(_attempt_id(claim), "claim", claim)
        with self._lock():
            if self._read_head() != expected_head:
                return ClaimInstallResult(claim, False, "STALE_EXPECTED_HEAD")
            active = self._read_active()
            if active is not None:
                if active.digest == claim.digest:
                    return ClaimInstallResult(claim, True, "IDEMPOTENT_ACTIVE_CLAIM")
                return ClaimInstallResult(claim, False, "ACTIVE_SUCCESSOR_EXISTS")
            self._replace(self.active_path, _active_bytes(claim))
            return ClaimInstallResult(claim, True, "CLAIM_ACQUIRED")

    def put_contract(self, contract: ContractObject) -> None:
        self._install(
            self._object_path(contract.CONTRACT_NAME, contract.digest), contract.canonical_bytes
        )

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        path = self._object_path(contract_name, digest)
        if not path.is_file():
            return None
        contract = _parse_contract(contract_name, path.read_bytes())
        if contract.digest != digest:
            raise TemporalStoreConflictError("stored contract identity path is invalid")
        return contract

    def record_attempt_artifact(
        self, attempt_id: str, artifact_name: str, contract: ContractObject
    ) -> None:
        _require_token(attempt_id)
        _require_token(artifact_name)
        self.put_contract(contract)
        self._install(
            self._attempt_directory(attempt_id) / f"{artifact_name}.json",
            contract.canonical_bytes,
        )

    def record_projection_artifacts(
        self,
        claim: ClockClaim,
        semantic_receipt: SemanticProjectionReceipt,
        artifacts: ProjectionArtifacts,
    ) -> None:
        self._install(
            self._attempt_directory(_attempt_id(claim)) / "projection-bundle.json",
            _projection_bundle_bytes(claim, semantic_receipt, artifacts),
        )

    def record_failure(self, claim: ClockClaim, failure: ClockProjectionFailure) -> None:
        _verify_failure(claim, failure)
        self.record_attempt_artifact(_attempt_id(claim), "failure", failure)
        with self._lock():
            active = self._read_active()
            if active is None or active.digest != claim.digest:
                raise TemporalStoreConflictError("failure does not own the active claim")
            self._clear_active()

    def prepare_completion(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
        _verify_completion(claim, completion)
        attempt_id = _attempt_id(claim)
        attempt = self._attempt_directory(attempt_id)
        bundle_path = attempt / "projection-bundle.json"
        semantic_path = attempt / "semantic.json"
        if not bundle_path.is_file() or not semantic_path.is_file():
            raise TemporalStoreConflictError("completion dependencies are incomplete")
        _verify_projection_bundle(bundle_path.read_bytes(), claim, completion)
        semantic_digest = cast(
            str, completion.to_json_value()["semantic_projection_receipt_digest"]
        )
        semantic = self.get_contract("semantic-projection-receipt", semantic_digest)
        if semantic is None or semantic_path.read_bytes() != semantic.canonical_bytes:
            raise TemporalStoreConflictError("completion semantic receipt is unavailable")
        self.record_attempt_artifact(attempt_id, "completion", completion)

    def publish_completion(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        self.prepare_completion(claim, completion)
        with self._lock():
            return self._publish(expected_head, claim, completion)

    def current_snapshot(self) -> ClockCompletionReceipt | None:
        head = self.read_head()
        if head.completion_digest is None:
            return None
        result = self.get_contract("clock-completion-receipt", head.completion_digest)
        if type(result) is not ClockCompletionReceipt:
            raise TemporalStoreConflictError("committed completion is unavailable")
        return result

    def reconstruct_chain(self) -> tuple[ClockCompletionReceipt, ...]:
        head = self.read_head()
        result: list[ClockCompletionReceipt] = []
        digest = head.completion_digest
        expected = head.clock_sequence
        while digest is not None:
            item = self.get_contract("clock-completion-receipt", digest)
            if type(item) is not ClockCompletionReceipt:
                raise TemporalStoreConflictError("completion chain object is unavailable")
            value = item.to_json_value()
            if value["clock_sequence"] != expected:
                raise TemporalStoreConflictError("completion chain is discontinuous")
            result.append(item)
            digest = cast(str | None, value["previous_completion_digest"])
            expected -= 1
        if expected != 0:
            raise TemporalStoreConflictError("completion chain does not terminate at genesis")
        return tuple(reversed(result))

    def recover(self) -> str:
        for path in self.temporary.glob("*.tmp"):
            path.unlink(missing_ok=True)
        with self._lock():
            active = self._read_active()
            if active is None:
                return "NO_ACTIVE_CLAIM"
            completion_path = self._attempt_directory(_attempt_id(active)) / "completion.json"
            if completion_path.is_file():
                completion = _parse_contract(
                    "clock-completion-receipt", completion_path.read_bytes()
                )
                if type(completion) is not ClockCompletionReceipt:
                    raise TemporalStoreConflictError("prepared completion has wrong type")
                self._verify_prepared(active, completion)
                expected = TemporalHead(
                    cast(int, active.to_json_value()["previous_committed_sequence"]),
                    cast(str | None, active.to_json_value()["previous_completion_digest"]),
                )
                self._publish(expected, active, completion)
                return "PREPARED_COMPLETION_PUBLISHED"
            failure = _recovery_failure(active)
            self.record_attempt_artifact(_attempt_id(active), "failure", failure)
            self._clear_active()
            return "INCOMPLETE_ATTEMPT_FAILED"

    def _verify_prepared(self, claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
        _verify_completion(claim, completion)
        attempt = self._attempt_directory(_attempt_id(claim))
        _verify_projection_bundle(
            (attempt / "projection-bundle.json").read_bytes(), claim, completion
        )
        semantic_digest = cast(
            str, completion.to_json_value()["semantic_projection_receipt_digest"]
        )
        semantic = self.get_contract("semantic-projection-receipt", semantic_digest)
        if semantic is None or (attempt / "semantic.json").read_bytes() != semantic.canonical_bytes:
            raise TemporalStoreConflictError("prepared semantic receipt is unavailable")

    def _publish(
        self,
        expected_head: TemporalHead,
        claim: ClockClaim,
        completion: ClockCompletionReceipt,
    ) -> TemporalHead:
        current = self._read_head()
        sequence = cast(int, completion.to_json_value()["clock_sequence"])
        if current.clock_sequence == sequence:
            if current.completion_digest != completion.digest:
                raise TemporalStoreConflictError(
                    "clock sequence already committed with different bytes"
                )
            self._clear_active()
            return current
        if current != expected_head:
            raise TemporalStoreConflictError("committed head changed before publication")
        active = self._read_active()
        if active is None or active.digest != claim.digest:
            raise TemporalStoreConflictError("completion does not own the active claim")
        new_head = TemporalHead(sequence, completion.digest)
        self._replace(self.head_path, _head_bytes(new_head))
        self._clear_active()
        return new_head

    def _read_head(self) -> TemporalHead:
        return _parse_head(self.head_path.read_bytes())

    def _read_active(self) -> ClockClaim | None:
        if not self.active_path.is_file():
            return None
        value = _json_object(self.active_path.read_bytes(), "active claim")
        digest = value.get("clock_claim_digest")
        result = self.get_contract("clock-claim", cast(str, digest))
        if type(result) is not ClockClaim:
            raise TemporalStoreConflictError("active claim object is unavailable")
        return result

    def _clear_active(self) -> None:
        self.active_path.unlink(missing_ok=True)
        _fsync_directory(self.state)

    def _object_path(self, contract_name: str, digest: str) -> Path:
        if contract_name not in CONTRACT_TYPES:
            raise TemporalStoreError("unknown contract name")
        hex_digest = _digest_hex(digest)
        return self.objects / contract_name / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _attempt_directory(self, attempt_id: str) -> Path:
        _require_token(attempt_id)
        encoded = hashlib.sha256(
            b"TEMPORAL_ATTEMPT_PATH\0" + attempt_id.encode("utf-8")
        ).hexdigest()
        return self.attempts / encoded[:2] / encoded[2:]

    def _install(self, final_path: Path, payload: bytes) -> None:
        final_path.parent.mkdir(parents=True, exist_ok=True)
        if final_path.exists():
            if final_path.read_bytes() != payload:
                raise TemporalStoreConflictError("immutable path contains different bytes")
            return
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        try:
            os.link(temporary, final_path)
        except FileExistsError:
            if final_path.read_bytes() != payload:
                raise TemporalStoreConflictError(
                    "concurrent immutable install conflicted"
                ) from None
        temporary.unlink(missing_ok=True)
        _fsync_directory(final_path.parent)

    def _replace(self, final_path: Path, payload: bytes) -> None:
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        os.replace(temporary, final_path)
        _fsync_directory(final_path.parent)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with advisory_lock(self.lock_path):
            yield


def _projection_bundle_bytes(
    claim: ClockClaim,
    semantic: SemanticProjectionReceipt,
    artifacts: ProjectionArtifacts,
) -> bytes:
    value: dict[str, Any] = {
        "schema_version": "temporal-projection-bundle/1",
        "clock_claim_digest": claim.digest,
        "semantic_projection_receipt_digest": semantic.digest,
        "registry_root_digests": {
            "evidence_unit": artifacts.evidence_unit_root_digest,
            "assumption": artifacts.assumption_root_digest,
            "alternative_model": artifacts.alternative_model_root_digest,
        },
        "disposition_receipt_digest": artifacts.disposition_receipt_digest,
        "quarantine_epoch": artifacts.quarantine_epoch,
        "quarantine_marker_digests": sorted(artifacts.quarantine_marker_digests),
        "observed_phase_order": list(artifacts.observed_phase_order),
        "release_compilation_invocations": artifacts.release_compilation_invocations,
    }
    unsigned = _json_bytes(value)
    value["projection_bundle_digest"] = (
        "sha256:" + hashlib.sha256(b"TEMPORAL_PROJECTION_BUNDLE\0" + unsigned).hexdigest()
    )
    return _json_bytes(value)


def _verify_projection_bundle(
    payload: bytes, claim: ClockClaim, completion: ClockCompletionReceipt
) -> None:
    value = _json_object(payload, "projection bundle")
    digest = value.pop("projection_bundle_digest", None)
    expected = (
        "sha256:" + hashlib.sha256(b"TEMPORAL_PROJECTION_BUNDLE\0" + _json_bytes(value)).hexdigest()
    )
    if digest != expected:
        raise TemporalStoreConflictError("projection bundle digest is invalid")
    rebuilt = dict(value)
    rebuilt["projection_bundle_digest"] = digest
    if _json_bytes(rebuilt) != payload:
        raise TemporalStoreConflictError("projection bundle bytes are not canonical")
    completed = completion.to_json_value()
    checks = {
        "clock_claim_digest": claim.digest,
        "semantic_projection_receipt_digest": completed["semantic_projection_receipt_digest"],
        "registry_root_digests": completed["registry_root_digests"],
        "disposition_receipt_digest": completed["disposition_receipt_digest"],
        "quarantine_epoch": completed["quarantine_epoch"],
        "quarantine_marker_digests": sorted(completed["quarantine_marker_digests"]),
        "observed_phase_order": _PHASES,
        "release_compilation_invocations": 0,
    }
    if any(value.get(key) != expected_value for key, expected_value in checks.items()):
        raise TemporalStoreConflictError("projection bundle does not match completion")


def _verify_claim(head: TemporalHead, claim: ClockClaim) -> None:
    value = claim.to_json_value()
    if (
        value["previous_committed_sequence"] != head.clock_sequence
        or value["previous_completion_digest"] != head.completion_digest
        or value["proposed_sequence"] != head.clock_sequence + 1
    ):
        raise TemporalStoreConflictError("claim does not match its expected predecessor")


def _verify_failure(claim: ClockClaim, failure: ClockProjectionFailure) -> None:
    claim_value = claim.to_json_value()
    value = failure.to_json_value()
    for field in (
        "attempt_id",
        "previous_committed_sequence",
        "previous_completion_digest",
        "proposed_sequence",
        "validated_event_digest",
    ):
        if value[field] != claim_value[field]:
            raise TemporalStoreConflictError("failure receipt does not match its claim")
    if value["clock_claim_digest"] != claim.digest:
        raise TemporalStoreConflictError("failure receipt cites a different claim")


def _verify_completion(claim: ClockClaim, completion: ClockCompletionReceipt) -> None:
    claim_value = claim.to_json_value()
    value = completion.to_json_value()
    if (
        value["clock_claim_digest"] != claim.digest
        or value["validated_event_digest"] != claim_value["validated_event_digest"]
        or value["clock_sequence"] != claim_value["proposed_sequence"]
        or value["previous_completion_digest"] != claim_value["previous_completion_digest"]
    ):
        raise TemporalStoreConflictError("completion does not match its claim")


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


def _parse_contract(name: str, payload: bytes) -> ContractObject:
    value = _json_object(payload, "stored contract")
    try:
        result = parse_contract(name, value)
    except GovernanceContractError as exc:
        raise TemporalStoreConflictError("stored contract fails validation") from exc
    if result.canonical_bytes != payload:
        raise TemporalStoreConflictError("stored contract bytes are not canonical")
    return result


def _head_bytes(head: TemporalHead) -> bytes:
    return _json_bytes(
        {
            "schema_version": "temporal-head/1",
            "clock_sequence": head.clock_sequence,
            "completion_digest": head.completion_digest,
        }
    )


def _parse_head(payload: bytes) -> TemporalHead:
    value = _json_object(payload, "temporal head")
    if value.get("schema_version") != "temporal-head/1":
        raise TemporalStoreConflictError("temporal head schema is invalid")
    result = TemporalHead(
        cast(int, value.get("clock_sequence")),
        cast(str | None, value.get("completion_digest")),
    )
    if _head_bytes(result) != payload:
        raise TemporalStoreConflictError("temporal head bytes are not canonical")
    return result


def _active_bytes(claim: ClockClaim) -> bytes:
    return _json_bytes(
        {
            "schema_version": "active-clock-claim/1",
            "clock_claim_digest": claim.digest,
        }
    )


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TemporalStoreConflictError(f"{label} bytes are invalid") from exc
    if type(value) is not dict:
        raise TemporalStoreConflictError(f"{label} root is not an object")
    return cast(dict[str, Any], value)


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")


def _attempt_id(claim: ClockClaim) -> str:
    value = claim.to_json_value().get("attempt_id")
    _require_token(value)
    return cast(str, value)


def _require_token(value: object) -> None:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        raise TemporalStoreError("attempt path token is invalid")


def _digest_hex(value: object) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise TemporalStoreError("identity must be a canonical sha256 digest")
    return value.removeprefix("sha256:")


def _write_fsync(path: Path, payload: bytes, *, exclusive: bool) -> None:
    mode = "xb" if exclusive else "wb"
    with path.open(mode) as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)
