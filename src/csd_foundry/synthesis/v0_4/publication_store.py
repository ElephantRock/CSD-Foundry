"""Atomic content-addressed no-clobber publication storage."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from csd_foundry.synthesis.v0_4.publication_protocol import PublicationDisposition
from csd_foundry.synthesis.v0_4.serialization import canonical_json_bytes

_HEX_256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PublicationStoreError(RuntimeError):
    """Base class for publication storage failures."""


class PublicationConflictError(PublicationStoreError):
    """Raised when an existing digest path contains different bytes."""


class PublicationCorruptionError(PublicationStoreError):
    """Raised when authoritative bytes do not match their digest path."""


class InjectedPublicationCrash(PublicationStoreError):
    """Test-only crash injected at a durable publication boundary."""


FaultInjector = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class PublicationResult:
    digest: str
    relative_path: str
    disposition: PublicationDisposition


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    temporary_objects_removed: int
    authoritative_objects_verified: int


class ContentAddressedPublicationStore:
    """Filesystem store using durable staging and atomic no-clobber installation."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise PublicationStoreError("publication root must be a pathlib Path")
        self.root = root
        self.objects_root = root / "objects"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.temporary_root)

    @staticmethod
    def _require_digest(digest: object) -> str:
        if type(digest) is not str or _HEX_256_PATTERN.fullmatch(digest) is None:
            raise PublicationStoreError("object digest must be a lowercase SHA-256 digest")
        return digest

    def object_path(self, digest: str) -> Path:
        normalized = self._require_digest(digest)
        return self.objects_root / normalized[:2] / normalized[2:]

    def relative_object_path(self, digest: str) -> str:
        return self.object_path(digest).relative_to(self.root).as_posix()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @classmethod
    def _ensure_directory(cls, path: Path) -> None:
        """Create a directory and durably persist its entry in the parent."""

        missing: list[Path] = []
        cursor = path
        while not cursor.exists():
            missing.append(cursor)
            cursor = cursor.parent
        for directory in reversed(missing):
            directory.mkdir()
            cls._fsync_directory(directory)
            cls._fsync_directory(directory.parent)
        if not path.is_dir():
            raise PublicationStoreError("publication path exists but is not a directory")

    @staticmethod
    def _invoke(fault_injector: FaultInjector | None, stage: str) -> None:
        if fault_injector is not None:
            fault_injector(stage)

    def _classify_existing(
        self, final_path: Path, payload: bytes, digest: str
    ) -> PublicationResult:
        existing = final_path.read_bytes()
        existing_digest = hashlib.sha256(existing).hexdigest()
        if existing_digest != digest:
            raise PublicationCorruptionError(
                "authoritative object bytes do not match their digest path"
            )
        if existing != payload:
            raise PublicationConflictError("existing digest path contains different bytes")
        return PublicationResult(
            digest=digest,
            relative_path=final_path.relative_to(self.root).as_posix(),
            disposition=PublicationDisposition.EXISTING_IDENTICAL,
        )

    def _durable_existing(
        self, final_path: Path, payload: bytes, digest: str
    ) -> PublicationResult:
        result = self._classify_existing(final_path, payload, digest)
        self._fsync_directory(final_path.parent)
        return result

    def publish_bytes(
        self,
        payload: bytes,
        *,
        expected_digest: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        if type(payload) is not bytes:
            raise PublicationStoreError("publication payload must use the exact bytes type")
        digest = hashlib.sha256(payload).hexdigest()
        if expected_digest is not None:
            self._require_digest(expected_digest)
            if digest != expected_digest:
                raise PublicationCorruptionError(
                    "publication payload does not match the expected digest"
                )
        final_path = self.object_path(digest)
        self._ensure_directory(final_path.parent)
        if final_path.exists():
            return self._durable_existing(final_path, payload, digest)

        temporary_path = self.temporary_root / f"{digest}.{uuid.uuid4().hex}.tmp"
        with temporary_path.open("xb") as handle:
            self._invoke(fault_injector, "temporary-created")
            handle.write(payload)
            handle.flush()
            self._invoke(fault_injector, "content-written")
            os.fsync(handle.fileno())
            self._invoke(fault_injector, "file-synced")

        try:
            os.link(temporary_path, final_path)
        except FileExistsError:
            result = self._durable_existing(final_path, payload, digest)
            temporary_path.unlink(missing_ok=True)
            self._fsync_directory(self.temporary_root)
            return result

        self._fsync_directory(final_path.parent)
        self._invoke(fault_injector, "object-installed")
        temporary_path.unlink(missing_ok=True)
        self._fsync_directory(self.temporary_root)
        return PublicationResult(
            digest=digest,
            relative_path=final_path.relative_to(self.root).as_posix(),
            disposition=PublicationDisposition.PUBLISHED,
        )

    def publish_canonical(
        self,
        value: object,
        *,
        expected_digest: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        return self.publish_bytes(
            canonical_json_bytes(value),
            expected_digest=expected_digest,
            fault_injector=fault_injector,
        )

    def read_verified(self, digest: str) -> bytes:
        path = self.object_path(digest)
        if not path.is_file():
            raise PublicationStoreError("content-addressed object does not exist")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise PublicationCorruptionError(
                "authoritative object bytes do not match their digest path"
            )
        return payload

    def recover(self) -> RecoveryReport:
        removed = 0
        verified = 0
        for temporary_path in sorted(self.temporary_root.glob("*.tmp")):
            declared_digest = temporary_path.name.split(".", 1)[0]
            if _HEX_256_PATTERN.fullmatch(declared_digest) is not None:
                final_path = self.object_path(declared_digest)
                if final_path.exists():
                    self.read_verified(declared_digest)
                    self._fsync_directory(final_path.parent)
                    verified += 1
            temporary_path.unlink(missing_ok=True)
            removed += 1
        if removed:
            self._fsync_directory(self.temporary_root)
        return RecoveryReport(
            temporary_objects_removed=removed,
            authoritative_objects_verified=verified,
        )
