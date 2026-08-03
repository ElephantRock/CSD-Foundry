"""Deterministic append-only registry substrate for v0.5 governed registries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol, cast

from csd_foundry._platform import advisory_lock, fsync_directory
from csd_foundry.governance.v0_5.contracts import RegistryEvent

_REGISTRY_PHASE = {
    "EVIDENCE_UNIT": "EVIDENCE_REGISTRY",
    "ASSUMPTION": "ASSUMPTION_REGISTRY",
    "ALTERNATIVE_MODEL": "ALTERNATIVE_MODEL_REGISTRY",
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RegistryStoreError(RuntimeError):
    """Base class for deterministic registry failures."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


class RegistryStoreConflictError(RegistryStoreError):
    """Raised when append-only identity or predecessor constraints conflict."""


@dataclass(frozen=True, slots=True)
class RegistryEntityHead:
    registry_type: str
    entity_id: str
    entity_sequence: int
    event_digest: str

    def __post_init__(self) -> None:
        _require_registry_type(self.registry_type)
        if type(self.entity_id) is not str or not self.entity_id:
            raise RegistryStoreError("REGISTRY_ENTITY_ID_INVALID")
        if type(self.entity_sequence) is not int or self.entity_sequence < 1:
            raise RegistryStoreError("REGISTRY_ENTITY_SEQUENCE_INVALID")
        _require_digest(self.event_digest)


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    registry_type: str
    heads: tuple[RegistryEntityHead, ...]
    root_digest: str

    def __post_init__(self) -> None:
        _require_registry_type(self.registry_type)
        if type(self.heads) is not tuple:
            raise RegistryStoreError("REGISTRY_SNAPSHOT_HEADS_INVALID")
        expected_order = tuple(sorted(self.heads, key=lambda item: item.entity_id))
        if self.heads != expected_order:
            raise RegistryStoreError("REGISTRY_SNAPSHOT_ORDER_INVALID")
        if len({item.entity_id for item in self.heads}) != len(self.heads):
            raise RegistryStoreError("REGISTRY_SNAPSHOT_DUPLICATE_ENTITY")
        if any(item.registry_type != self.registry_type for item in self.heads):
            raise RegistryStoreError("REGISTRY_SNAPSHOT_TYPE_MISMATCH")
        if self.root_digest != _snapshot_root(self.registry_type, self.heads):
            raise RegistryStoreError("REGISTRY_SNAPSHOT_ROOT_MISMATCH")


@dataclass(frozen=True, slots=True)
class RegistryAppendResult:
    event: RegistryEvent
    head: RegistryEntityHead
    applied: bool
    reason: str


class RegistryStore(Protocol):
    def append(self, event: RegistryEvent) -> RegistryAppendResult: ...

    def get_event(self, digest: str) -> RegistryEvent | None: ...

    def entity_head(self, registry_type: str, entity_id: str) -> RegistryEntityHead | None: ...

    def snapshot(self, registry_type: str) -> RegistrySnapshot: ...

    def reconstruct_entity(
        self, registry_type: str, entity_id: str
    ) -> tuple[RegistryEvent, ...]: ...

    def reconstruct_snapshot(self, registry_type: str) -> tuple[tuple[RegistryEvent, ...], ...]: ...


class InMemoryRegistryStore:
    """Ephemeral reference store backed by the filesystem protocol."""

    def __init__(self) -> None:
        self._temporary = TemporaryDirectory()
        self._store = FilesystemRegistryStore(Path(self._temporary.name))

    def append(self, event: RegistryEvent) -> RegistryAppendResult:
        return self._store.append(event)

    def get_event(self, digest: str) -> RegistryEvent | None:
        return self._store.get_event(digest)

    def entity_head(self, registry_type: str, entity_id: str) -> RegistryEntityHead | None:
        return self._store.entity_head(registry_type, entity_id)

    def snapshot(self, registry_type: str) -> RegistrySnapshot:
        return self._store.snapshot(registry_type)

    def reconstruct_entity(self, registry_type: str, entity_id: str) -> tuple[RegistryEvent, ...]:
        return self._store.reconstruct_entity(registry_type, entity_id)

    def reconstruct_snapshot(self, registry_type: str) -> tuple[tuple[RegistryEvent, ...], ...]:
        return self._store.reconstruct_snapshot(registry_type)


class FilesystemRegistryStore:
    """Single-host POSIX store with process-shared compare-and-append heads."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise RegistryStoreError("REGISTRY_ROOT_NOT_PATH")
        self.root = root
        self.objects = root / "objects" / "registry-event"
        self.heads = root / "heads"
        self.temporary = root / ".tmp"
        self.lock_path = root / "registry.lock"
        for directory in (root, self.objects, self.heads, self.temporary):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)

    def append(self, event: RegistryEvent) -> RegistryAppendResult:
        _verify_event(event)
        value = event.to_json_value()
        registry_type = cast(str, value["registry_type"])
        entity_id = cast(str, value["entity_id"])
        sequence = cast(int, value["entity_sequence"])
        previous = cast(str | None, value["previous_entity_event_digest"])
        self._install(self._object_path(event.digest), event.canonical_bytes)
        with self._lock():
            current = self._read_head(registry_type, entity_id)
            if current is not None and current.event_digest == event.digest:
                if current.entity_sequence != sequence:
                    raise RegistryStoreConflictError("REGISTRY_IDEMPOTENT_SEQUENCE_MISMATCH")
                return RegistryAppendResult(event, current, False, "IDEMPOTENT_APPEND")
            expected_sequence = 1 if current is None else current.entity_sequence + 1
            expected_previous = None if current is None else current.event_digest
            if sequence != expected_sequence:
                raise RegistryStoreConflictError(
                    "REGISTRY_SEQUENCE_CONFLICT",
                    f"expected {expected_sequence}, observed {sequence}",
                )
            if previous != expected_previous:
                raise RegistryStoreConflictError("REGISTRY_PREDECESSOR_CONFLICT")
            head = RegistryEntityHead(registry_type, entity_id, sequence, event.digest)
            self._replace(self._head_path(registry_type, entity_id), _head_bytes(head))
            return RegistryAppendResult(event, head, True, "APPENDED")

    def get_event(self, digest: str) -> RegistryEvent | None:
        path = self._object_path(digest)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryStoreConflictError("REGISTRY_EVENT_BYTES_INVALID") from exc
        if type(value) is not dict:
            raise RegistryStoreConflictError("REGISTRY_EVENT_NOT_OBJECT")
        try:
            event = cast(RegistryEvent, RegistryEvent.from_json(value))
        except Exception as exc:
            raise RegistryStoreConflictError("REGISTRY_EVENT_CONTRACT_INVALID") from exc
        if event.digest != digest or event.canonical_bytes != path.read_bytes():
            raise RegistryStoreConflictError("REGISTRY_EVENT_IDENTITY_MISMATCH")
        return event

    def entity_head(self, registry_type: str, entity_id: str) -> RegistryEntityHead | None:
        _require_registry_type(registry_type)
        _require_entity_id(entity_id)
        with self._lock():
            return self._read_head(registry_type, entity_id)

    def snapshot(self, registry_type: str) -> RegistrySnapshot:
        _require_registry_type(registry_type)
        with self._lock():
            directory = self.heads / registry_type.lower()
            found: dict[str, RegistryEntityHead] = {}
            if directory.is_dir():
                for path in sorted(directory.glob("*.json")):
                    head = _parse_head(path.read_bytes())
                    if head.registry_type != registry_type:
                        raise RegistryStoreConflictError("REGISTRY_HEAD_TYPE_MISMATCH")
                    expected_path = self._head_path(head.registry_type, head.entity_id)
                    if path != expected_path:
                        raise RegistryStoreConflictError("REGISTRY_HEAD_PATH_MISMATCH")
                    existing = found.get(head.entity_id)
                    if existing is not None and existing != head:
                        raise RegistryStoreConflictError("REGISTRY_HEAD_DUPLICATE_ENTITY")
                    found[head.entity_id] = head
            heads = tuple(sorted(found.values(), key=lambda item: item.entity_id))
            for head in heads:
                event = self.get_event(head.event_digest)
                if event is None:
                    raise RegistryStoreConflictError("REGISTRY_HEAD_EVENT_MISSING")
                _verify_head_event(head, event)
            return RegistrySnapshot(registry_type, heads, _snapshot_root(registry_type, heads))

    def reconstruct_entity(self, registry_type: str, entity_id: str) -> tuple[RegistryEvent, ...]:
        head = self.entity_head(registry_type, entity_id)
        if head is None:
            return ()
        result: list[RegistryEvent] = []
        digest: str | None = head.event_digest
        expected_sequence = head.entity_sequence
        seen: set[str] = set()
        while digest is not None:
            if digest in seen:
                raise RegistryStoreConflictError("REGISTRY_EVENT_CYCLE")
            seen.add(digest)
            event = self.get_event(digest)
            if event is None:
                raise RegistryStoreConflictError("REGISTRY_CHAIN_EVENT_MISSING")
            value = event.to_json_value()
            if value["registry_type"] != registry_type or value["entity_id"] != entity_id:
                raise RegistryStoreConflictError("REGISTRY_CHAIN_ENTITY_MISMATCH")
            if value["entity_sequence"] != expected_sequence:
                raise RegistryStoreConflictError("REGISTRY_CHAIN_SEQUENCE_MISMATCH")
            result.append(event)
            digest = cast(str | None, value["previous_entity_event_digest"])
            expected_sequence -= 1
        if expected_sequence != 0:
            raise RegistryStoreConflictError("REGISTRY_CHAIN_NOT_GENESIS_LINKED")
        return tuple(reversed(result))

    def reconstruct_snapshot(self, registry_type: str) -> tuple[tuple[RegistryEvent, ...], ...]:
        snapshot = self.snapshot(registry_type)
        return tuple(
            self.reconstruct_entity(registry_type, head.entity_id) for head in snapshot.heads
        )

    def _read_head(self, registry_type: str, entity_id: str) -> RegistryEntityHead | None:
        path = self._head_path(registry_type, entity_id)
        if not path.is_file():
            return None
        head = _parse_head(path.read_bytes())
        if head.registry_type != registry_type or head.entity_id != entity_id:
            raise RegistryStoreConflictError("REGISTRY_HEAD_IDENTITY_MISMATCH")
        return head

    def _object_path(self, digest: str) -> Path:
        hex_digest = _digest_hex(digest)
        return self.objects / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _head_path(self, registry_type: str, entity_id: str) -> Path:
        _require_registry_type(registry_type)
        _require_entity_id(entity_id)
        encoded = hashlib.sha256(
            b"REGISTRY_ENTITY_PATH\0"
            + registry_type.encode("utf-8")
            + b"\0"
            + entity_id.encode("utf-8")
        ).hexdigest()
        return self.heads / registry_type.lower() / f"{encoded}.json"

    def _install(self, final_path: Path, payload: bytes) -> None:
        final_path.parent.mkdir(parents=True, exist_ok=True)
        if final_path.exists():
            if final_path.read_bytes() != payload:
                raise RegistryStoreConflictError("REGISTRY_IMMUTABLE_PATH_CONFLICT")
            return
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        try:
            os.link(temporary, final_path)
        except FileExistsError:
            if final_path.read_bytes() != payload:
                raise RegistryStoreConflictError("REGISTRY_CONCURRENT_INSTALL_CONFLICT") from None
        temporary.unlink(missing_ok=True)
        _fsync_directory(final_path.parent)

    def _replace(self, final_path: Path, payload: bytes) -> None:
        final_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        os.replace(temporary, final_path)
        _fsync_directory(final_path.parent)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with advisory_lock(self.lock_path):
            yield


def build_registry_event(
    *,
    registry_type: str,
    entity_id: str,
    entity_sequence: int,
    previous_entity_event_digest: str | None,
    clock_sequence: int,
    source_receipt_digest: str,
    payload_schema_version: str,
    payload: dict[str, object],
) -> RegistryEvent:
    """Build one frozen `registry-event/1` envelope with the required phase."""

    _require_registry_type(registry_type)
    if type(payload) is not dict:
        raise RegistryStoreError("REGISTRY_PAYLOAD_NOT_OBJECT")
    return cast(
        RegistryEvent,
        RegistryEvent.build(
            {
                "schema_version": "registry-event/1",
                "registry_type": registry_type,
                "entity_id": entity_id,
                "entity_sequence": entity_sequence,
                "previous_entity_event_digest": previous_entity_event_digest,
                "clock_sequence": clock_sequence,
                "projection_phase": _REGISTRY_PHASE[registry_type],
                "source_receipt_digest": source_receipt_digest,
                "payload_schema_version": payload_schema_version,
                "payload": payload,
            }
        ),
    )


def _verify_event(event: RegistryEvent) -> None:
    if type(event) is not RegistryEvent:
        raise RegistryStoreError("REGISTRY_EVENT_TYPE_INVALID")
    value = event.to_json_value()
    registry_type = cast(str, value["registry_type"])
    _require_registry_type(registry_type)
    if value["projection_phase"] != _REGISTRY_PHASE[registry_type]:
        raise RegistryStoreError("REGISTRY_PROJECTION_PHASE_MISMATCH")
    _require_entity_id(value["entity_id"])


def _verify_head_event(head: RegistryEntityHead, event: RegistryEvent) -> None:
    value = event.to_json_value()
    if (
        value["registry_type"] != head.registry_type
        or value["entity_id"] != head.entity_id
        or value["entity_sequence"] != head.entity_sequence
        or event.digest != head.event_digest
    ):
        raise RegistryStoreConflictError("REGISTRY_HEAD_EVENT_MISMATCH")


def _snapshot_root(registry_type: str, heads: tuple[RegistryEntityHead, ...]) -> str:
    value = {
        "schema_version": "registry-snapshot/1",
        "registry_type": registry_type,
        "heads": [
            {
                "entity_id": item.entity_id,
                "entity_sequence": item.entity_sequence,
                "event_digest": item.event_digest,
            }
            for item in heads
        ],
    }
    return "sha256:" + hashlib.sha256(b"REGISTRY_SNAPSHOT\0" + _json_bytes(value)).hexdigest()


def _head_bytes(head: RegistryEntityHead) -> bytes:
    value = {
        "schema_version": "registry-head/1",
        "registry_type": head.registry_type,
        "entity_id": head.entity_id,
        "entity_sequence": head.entity_sequence,
        "event_digest": head.event_digest,
    }
    unsigned = _json_bytes(value)
    value["head_digest"] = "sha256:" + hashlib.sha256(b"REGISTRY_HEAD\0" + unsigned).hexdigest()
    return _json_bytes(value)


def _parse_head(payload: bytes) -> RegistryEntityHead:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RegistryStoreConflictError("REGISTRY_HEAD_BYTES_INVALID") from exc
    if type(value) is not dict or set(value) != {
        "schema_version",
        "registry_type",
        "entity_id",
        "entity_sequence",
        "event_digest",
        "head_digest",
    }:
        raise RegistryStoreConflictError("REGISTRY_HEAD_SHAPE_INVALID")
    if value["schema_version"] != "registry-head/1":
        raise RegistryStoreConflictError("REGISTRY_HEAD_VERSION_INVALID")
    expected = dict(value)
    actual_digest = expected.pop("head_digest")
    calculated = "sha256:" + hashlib.sha256(b"REGISTRY_HEAD\0" + _json_bytes(expected)).hexdigest()
    if actual_digest != calculated or payload != _json_bytes(value):
        raise RegistryStoreConflictError("REGISTRY_HEAD_DIGEST_INVALID")
    try:
        return RegistryEntityHead(
            cast(str, value["registry_type"]),
            cast(str, value["entity_id"]),
            cast(int, value["entity_sequence"]),
            cast(str, value["event_digest"]),
        )
    except RegistryStoreError as exc:
        raise RegistryStoreConflictError(exc.code, exc.detail) from exc


def _require_registry_type(value: object) -> None:
    if type(value) is not str or value not in _REGISTRY_PHASE:
        raise RegistryStoreError("REGISTRY_TYPE_INVALID")


def _require_entity_id(value: object) -> None:
    if type(value) is not str or not value:
        raise RegistryStoreError("REGISTRY_ENTITY_ID_INVALID")


def _require_digest(value: object) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RegistryStoreError("REGISTRY_DIGEST_INVALID")


def _digest_hex(value: str) -> str:
    _require_digest(value)
    return value.removeprefix("sha256:")


def _json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RegistryStoreError("REGISTRY_INTERNAL_JSON_INVALID") from exc


def _write_fsync(path: Path, payload: bytes, *, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)
