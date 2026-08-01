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
_TOKEN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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
        self.claims_root = root / "claims"
        self.references_root = root / "references"
        self.temporary_root = root / ".tmp"
        self._ensure_directory(self.root)
        self._ensure_directory(self.objects_root)
        self._ensure_directory(self.claims_root)
        self._ensure_directory(self.references_root)
        self._ensure_directory(self.temporary_root)

    @staticmethod
    def _require_digest(digest: object) -> str:
        if type(digest) is not str or _HEX_256_PATTERN.fullmatch(digest) is None:
            raise PublicationStoreError("object digest must be a lowercase SHA-256 digest")
        return digest

    @staticmethod
    def _require_token(value: object, field_name: str) -> str:
        if type(value) is not str or _TOKEN_PATTERN.fullmatch(value) is None:
            raise PublicationStoreError(f"{field_name} must be a lowercase ASCII token")
        return value

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
            try:
                directory.mkdir()
            except FileExistsError:
                if not directory.is_dir():
                    raise PublicationStoreError(
                        "publication path was concurrently created as a non-directory"
                    ) from None
            cls._fsync_directory(directory)
            cls._fsync_directory(directory.parent)
        if not path.is_dir():
            raise PublicationStoreError("publication path exists but is not a directory")
        cls._fsync_directory(path)
        cls._fsync_directory(path.parent)

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

    def _durable_existing(self, final_path: Path, payload: bytes, digest: str) -> PublicationResult:
        result = self._classify_existing(final_path, payload, digest)
        self._fsync_directory(final_path.parent)
        return result

    def publication_claim_path(self, object_kind: str, digest: str) -> Path:
        kind = self._require_token(object_kind, "object_kind")
        object_digest = self._require_digest(digest)
        return self.claims_root / kind / object_digest[:2] / object_digest[2:]

    @classmethod
    def _publication_claim_bytes(cls, owner_digest: str) -> bytes:
        return (cls._require_digest(owner_digest) + "\n").encode("ascii")

    def _read_publication_claim_owner(self, path: Path) -> str:
        payload = path.read_bytes()
        if len(payload) != 65 or payload[-1:] != b"\n":
            raise PublicationCorruptionError(
                "publication claim does not contain one canonical owner digest"
            )
        try:
            owner = payload[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise PublicationCorruptionError("publication claim owner is not ASCII") from exc
        self._require_digest(owner)
        self._fsync_directory(path.parent)
        return owner

    def claim_publication(
        self,
        *,
        object_kind: str,
        digest: str,
        owner_digest: str,
        fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> bool:
        claim_path = self.publication_claim_path(object_kind, digest)
        claim_payload = self._publication_claim_bytes(owner_digest)
        self._ensure_directory(claim_path.parent)
        if claim_path.exists():
            return self._read_publication_claim_owner(claim_path) == owner_digest

        temporary_path = self.temporary_root / (f"claim.{digest}.{uuid.uuid4().hex}.tmp")
        with temporary_path.open("xb") as handle:
            handle.write(claim_payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, claim_path)
        except FileExistsError:
            owned = self._read_publication_claim_owner(claim_path) == owner_digest
            temporary_path.unlink(missing_ok=True)
            self._fsync_directory(self.temporary_root)
            return owned

        self._fsync_directory(claim_path.parent)
        if fault_stage is not None:
            self._invoke(fault_injector, fault_stage)
        temporary_path.unlink(missing_ok=True)
        self._fsync_directory(self.temporary_root)
        return True

    def claim_and_publish_bytes(
        self,
        payload: bytes,
        *,
        expected_digest: str,
        object_kind: str,
        owner_digest: str,
        claim_fault_stage: str | None = None,
        object_fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        if type(payload) is not bytes:
            raise PublicationStoreError("publication payload must use the exact bytes type")
        digest = hashlib.sha256(payload).hexdigest()
        self._require_digest(expected_digest)
        if digest != expected_digest:
            raise PublicationCorruptionError(
                "publication payload does not match the expected digest"
            )
        claim_path = self.publication_claim_path(object_kind, digest)
        object_path = self.object_path(digest)

        if object_path.exists() and not claim_path.exists():
            result = self.publish_bytes(payload, expected_digest=digest)
            if object_fault_stage is not None:
                self._invoke(fault_injector, object_fault_stage)
            return result

        owned = self.claim_publication(
            object_kind=object_kind,
            digest=digest,
            owner_digest=owner_digest,
            fault_stage=claim_fault_stage,
            fault_injector=fault_injector,
        )
        if not owned and not object_path.exists():
            raise PublicationStoreError(
                "publication object is claimed by another execution run but not installed"
            )
        result = self.publish_bytes(payload, expected_digest=digest)
        if object_fault_stage is not None:
            self._invoke(fault_injector, object_fault_stage)
        return PublicationResult(
            digest=result.digest,
            relative_path=result.relative_path,
            disposition=(
                PublicationDisposition.PUBLISHED
                if owned
                else PublicationDisposition.EXISTING_IDENTICAL
            ),
        )

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

    def reference_path(
        self,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
    ) -> Path:
        if category not in {"indexes", "manifests", "seals"}:
            raise PublicationStoreError("unknown publication reference category")
        inventory = self._require_digest(inventory_digest)
        object_digest = self._require_digest(digest)
        if type(shard_index) is not int or not 0 <= shard_index <= (1 << 32) - 1:
            raise PublicationStoreError("shard_index must be an exact uint32")
        return self.references_root / category / inventory / str(shard_index) / object_digest

    def install_digest_reference(
        self,
        *,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
        fault_stage: str | None = None,
        fault_injector: FaultInjector | None = None,
    ) -> PublicationResult:
        source = self.object_path(digest)
        payload = self.read_verified(digest)
        final_path = self.reference_path(
            category,
            inventory_digest,
            shard_index,
            digest,
        )
        self._ensure_directory(final_path.parent)
        if final_path.exists():
            return self._durable_existing(final_path, payload, digest)
        try:
            os.link(source, final_path)
        except FileExistsError:
            return self._durable_existing(final_path, payload, digest)
        self._fsync_directory(final_path.parent)
        if fault_stage is not None:
            self._invoke(fault_injector, fault_stage)
        return PublicationResult(
            digest=digest,
            relative_path=final_path.relative_to(self.root).as_posix(),
            disposition=PublicationDisposition.PUBLISHED,
        )

    def reference_exists_verified(
        self,
        *,
        category: str,
        inventory_digest: str,
        shard_index: int,
        digest: str,
    ) -> bool:
        path = self.reference_path(category, inventory_digest, shard_index, digest)
        if not path.is_file():
            return False
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise PublicationCorruptionError(
                "publication reference bytes do not match the referenced digest"
            )
        self._fsync_directory(path.parent)
        return True

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
