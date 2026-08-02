"""Append-only in-memory and filesystem storage for v0.5 admission evidence."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, cast

from csd_foundry.governance.v0_5.admission import CommittedValidationContext
from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import CONTRACT_TYPES, ContractObject, parse_contract

_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class AdmissionStoreError(RuntimeError):
    """Base class for admission evidence storage failures."""


class AdmissionStoreConflictError(AdmissionStoreError):
    """Raised when an immutable identity already contains different bytes."""


class InMemoryEventAdmissionStore:
    """Deterministic append-only store used by reference validation and unit tests."""

    def __init__(self) -> None:
        self._contracts: dict[tuple[str, str], bytes] = {}
        self._contexts: dict[int, bytes] = {}

    def put_contract(self, contract: ContractObject) -> None:
        key = (contract.CONTRACT_NAME, contract.digest)
        payload = contract.canonical_bytes
        existing = self._contracts.get(key)
        if existing is not None and existing != payload:
            raise AdmissionStoreConflictError("contract identity already contains different bytes")
        self._contracts[key] = payload

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        payload = self._contracts.get((contract_name, digest))
        if payload is None:
            return None
        return _parse_contract_payload(contract_name, payload)

    def put_context(self, context: CommittedValidationContext) -> None:
        existing = self._contexts.get(context.tick)
        if existing is not None and existing != context.canonical_bytes:
            raise AdmissionStoreConflictError("validation tick already has a different context")
        self._contexts[context.tick] = context.canonical_bytes

    def get_context(self, tick: int) -> CommittedValidationContext | None:
        payload = self._contexts.get(tick)
        if payload is None:
            return None
        return _parse_context_payload(payload)


class FilesystemEventAdmissionStore:
    """Filesystem store with atomic no-clobber installation and restart reconstruction."""

    def __init__(self, root: Path) -> None:
        if type(root) is not Path:
            raise AdmissionStoreError("admission root must be an exact pathlib Path")
        self.root = root
        self.objects_root = root / "objects"
        self.contexts_root = root / "contexts"
        self.temporary_root = root / ".tmp"
        for directory in (self.root, self.objects_root, self.contexts_root, self.temporary_root):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)

    def put_contract(self, contract: ContractObject) -> None:
        path = self._contract_path(contract.CONTRACT_NAME, contract.digest)
        self._atomic_install(path, contract.canonical_bytes)

    def get_contract(self, contract_name: str, digest: str) -> ContractObject | None:
        path = self._contract_path(contract_name, digest)
        if not path.is_file():
            return None
        payload = path.read_bytes()
        contract = _parse_contract_payload(contract_name, payload)
        if contract.digest != digest:
            raise AdmissionStoreConflictError("stored contract does not match its identity path")
        return contract

    def put_context(self, context: CommittedValidationContext) -> None:
        self._atomic_install(self._context_path(context.tick), context.canonical_bytes)

    def get_context(self, tick: int) -> CommittedValidationContext | None:
        path = self._context_path(tick)
        if not path.is_file():
            return None
        context = _parse_context_payload(path.read_bytes())
        if context.tick != tick:
            raise AdmissionStoreConflictError("stored context does not match its tick path")
        return context

    def recover(self) -> int:
        removed = 0
        for path in sorted(self.temporary_root.glob("*.tmp")):
            path.unlink(missing_ok=True)
            removed += 1
        if removed:
            _fsync_directory(self.temporary_root)
        return removed

    def _contract_path(self, contract_name: str, digest: str) -> Path:
        if contract_name not in CONTRACT_TYPES:
            raise AdmissionStoreError("unknown v0.5 contract name")
        hex_digest = _digest_hex(digest)
        return self.objects_root / contract_name / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _context_path(self, tick: int) -> Path:
        if type(tick) is not int or tick < 0:
            raise AdmissionStoreError("context tick must be an exact nonnegative integer")
        return self.contexts_root / f"{tick}.json"

    def _atomic_install(self, final_path: Path, payload: bytes) -> None:
        if type(payload) is not bytes:
            raise AdmissionStoreError("admission payload must use the exact bytes type")
        final_path.parent.mkdir(parents=True, exist_ok=True)
        _fsync_directory(final_path.parent)
        if final_path.exists():
            if final_path.read_bytes() != payload:
                raise AdmissionStoreConflictError("immutable path already contains different bytes")
            _fsync_directory(final_path.parent)
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
                raise AdmissionStoreConflictError(
                    "concurrent immutable install contains different bytes"
                ) from None
        _fsync_directory(final_path.parent)
        temporary_path.unlink(missing_ok=True)
        _fsync_directory(self.temporary_root)


def _parse_contract_payload(contract_name: str, payload: bytes) -> ContractObject:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionStoreConflictError("stored contract bytes are not canonical JSON") from exc
    if type(value) is not dict:
        raise AdmissionStoreConflictError("stored contract root is not an object")
    try:
        contract = parse_contract(contract_name, cast(dict[str, Any], value))
    except GovernanceContractError as exc:
        raise AdmissionStoreConflictError("stored contract fails frozen validation") from exc
    if contract.canonical_bytes != payload:
        raise AdmissionStoreConflictError("stored contract bytes are not canonical")
    return contract


def _parse_context_payload(payload: bytes) -> CommittedValidationContext:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdmissionStoreConflictError("stored context bytes are not canonical JSON") from exc
    if type(value) is not dict:
        raise AdmissionStoreConflictError("stored context root is not an object")
    try:
        context = CommittedValidationContext.from_json(cast(dict[str, Any], value))
    except GovernanceContractError as exc:
        raise AdmissionStoreConflictError("stored context fails validation") from exc
    if context.canonical_bytes != payload:
        raise AdmissionStoreConflictError("stored context bytes are not canonical")
    return context


def _digest_hex(value: object) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise AdmissionStoreError("identity must be a canonical sha256 digest")
    return value.removeprefix("sha256:")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
