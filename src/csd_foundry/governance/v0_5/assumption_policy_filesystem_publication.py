"""Durable filesystem publication for v0.5-D3.2-A1.3-B V3 policy activation.

Provides ``FilesystemAssumptionPolicyPublisher``: an interprocess-safe atomic
publisher that stores the authoritative ``AssumptionPolicyLedgerV3`` as a
single canonical JSON file and uses ``_platform.advisory_lock`` for exclusive
access.

The pure A1.3-A function ``compare_and_append_policy_entry_v3`` remains the
semantic oracle. The filesystem layer owns: locking, stored-byte validation,
atomic replacement, restart reconstruction, post-write verification, and
platform-specific durability boundaries.

Claim boundary:

    POSIX: exclusive interprocess lock, temporary-file fsync, atomic
    same-filesystem replace, directory fsync where supported.

    Windows: exclusive interprocess lock, temporary-file flush, atomic
    visibility through the supported replacement primitive, restart
    reconstruction.

    POSIX-equivalent sudden-power-loss directory-fsync durability is NOT
    claimed on Windows.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, cast

from csd_foundry._platform import advisory_lock, fsync_directory
from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    ACTIVATION_PROOF_V2_SCHEMA_VERSION,
    AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION,
    POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION,
    SIGNING_PAYLOAD_SCHEMA_VERSION,
    AssumptionAuthorityPolicyCommitV3,
    AssumptionPolicyActivationProofV2,
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
    AssumptionPolicySigningPayload,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_ledger import (
    AssumptionPolicyActivationResult,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
    AssumptionPolicyApprovalRule,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_hardening import (
    AssumptionPolicyPublicationConflict,
    PreparedPolicyActivation,
)
from csd_foundry.governance.v0_5.assumption_policy_activation_publication import (
    ExpectedPolicyLedgerStateV3,
    compare_and_append_policy_entry_v3,
)

_LEDGER_SCHEMA_VERSION = "assumption-policy-ledger/3"


class PolicyStoreError(RuntimeError):
    """Stable error for filesystem policy-store failures."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --- V3 parsers (reconstruct typed objects from canonical bytes) ------------


def _require_str(value: dict[str, Any], key: str, code: str) -> str:
    v = value.get(key)
    if type(v) is not str:
        raise PolicyStoreError(code, key)
    return v


def _require_optional_str(value: dict[str, Any], key: str, code: str) -> str | None:
    v = value.get(key)
    if v is None:
        return None
    if type(v) is not str:
        raise PolicyStoreError(code, key)
    return v


def _require_int(value: dict[str, Any], key: str, code: str) -> int:
    v = value.get(key)
    if type(v) is not int or v < 0:
        raise PolicyStoreError(code, key)
    return v


def parse_signing_payload(value: dict[str, Any]) -> AssumptionPolicySigningPayload:
    """Parse and self-validate a signing-payload/1 from canonical JSON."""

    if value.get("schema_version") != SIGNING_PAYLOAD_SCHEMA_VERSION:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED")
    try:
        return AssumptionPolicySigningPayload(
            policy_id=_require_str(value, "policy_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            policy_digest=_require_str(
                value, "policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            predecessor_policy_digest=_require_optional_str(
                value, "predecessor_policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            predecessor_commit_receipt_digest=_require_optional_str(
                value, "predecessor_commit_receipt_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            authority_root_digest=_require_str(
                value, "authority_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            grant_set_digest=_require_str(
                value, "grant_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            separation_duty_rule_set_digest=_require_str(
                value, "separation_duty_rule_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            exception_set_digest=_require_str(
                value, "exception_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            exception_count=_require_int(
                value, "exception_count", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            approval_class=_require_str(
                value, "approval_class", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            effective_from_sequence=_require_int(
                value, "effective_from_sequence", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            approval_policy_digest=_require_str(
                value, "approval_policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            signature_profile_digest=_require_str(
                value, "signature_profile_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            challenge_classification_policy_digest=_require_str(
                value,
                "challenge_classification_policy_digest",
                "ASSUMPTION_POLICY_STORED_FIELD_INVALID",
            ),
            signing_payload_digest=_require_str(
                value, "signing_payload_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_policy_commit_v3(value: dict[str, Any]) -> AssumptionAuthorityPolicyCommitV3:
    if value.get("schema_version") != AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED")
    try:
        return AssumptionAuthorityPolicyCommitV3(
            signing_payload_digest=_require_str(
                value, "signing_payload_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            signature_set_digest=_require_str(
                value, "signature_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            commit_receipt_digest=_require_str(
                value, "commit_receipt_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_activation_proof_v2(value: dict[str, Any]) -> AssumptionPolicyActivationProofV2:
    if value.get("schema_version") != ACTIVATION_PROOF_V2_SCHEMA_VERSION:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED")
    raw_signers = value.get("valid_signer_ids")
    if type(raw_signers) is not list:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_FIELD_INVALID", "valid_signer_ids")
    raw_rejected = value.get("rejected_signer_ids")
    if type(raw_rejected) is not list:
        raw_rejected = value.get("rejected_signer_codes", [])
        if type(raw_rejected) is not list:
            raise PolicyStoreError(
                "ASSUMPTION_POLICY_STORED_FIELD_INVALID", "rejected_signer_codes"
            )
    try:
        return AssumptionPolicyActivationProofV2(
            signing_payload_digest=_require_str(
                value, "signing_payload_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            policy_commit_receipt_digest=_require_str(
                value, "policy_commit_receipt_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            approval_policy_digest=_require_str(
                value, "approval_policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            approval_rule_digest=_require_str(
                value, "approval_rule_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            signature_profile_digest=_require_str(
                value, "signature_profile_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            challenge_classification_policy_digest=_require_str(
                value,
                "challenge_classification_policy_digest",
                "ASSUMPTION_POLICY_STORED_FIELD_INVALID",
            ),
            authority_root_digest=_require_str(
                value, "authority_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            signature_set_digest=_require_str(
                value, "signature_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            valid_signer_ids=tuple(cast(list[str], raw_signers)),
            rejected_signer_codes=tuple(cast(list[str], raw_rejected)),
            activation_proof_digest=_require_str(
                value, "activation_proof_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_ledger_entry_v3(value: dict[str, Any]) -> AssumptionPolicyLedgerEntryV3:
    if value.get("schema_version") != POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED")
    try:
        return AssumptionPolicyLedgerEntryV3(
            policy=_parse_authority_policy(cast(dict[str, Any], value["policy"])),
            signing_payload=parse_signing_payload(cast(dict[str, Any], value["signing_payload"])),
            policy_commit=parse_policy_commit_v3(cast(dict[str, Any], value["policy_commit"])),
            approval_policy=_parse_approval_policy(cast(dict[str, Any], value["approval_policy"])),
            signature_profile=_parse_signature_profile(
                cast(dict[str, Any], value["signature_profile"])
            ),
            challenge_classification_policy=_parse_challenge_policy(
                cast(dict[str, Any], value["challenge_classification_policy"])
            ),
            activation_proof=parse_activation_proof_v2(
                cast(dict[str, Any], value["activation_proof"])
            ),
            ledger_entry_digest=_require_str(
                value, "ledger_entry_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_ledger_v3(payload: bytes) -> AssumptionPolicyLedgerV3:
    """Parse, revalidate, and reconstruct a complete ``AssumptionPolicyLedgerV3``
    from canonical stored bytes."""

    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_INVALID") from exc
    if type(value) is not dict:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_INVALID")
    if value.get("schema_version") != _LEDGER_SCHEMA_VERSION:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED")
    raw_entries = value.get("entries")
    if type(raw_entries) is not list:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_FIELD_INVALID", "entries")
    entries = tuple(parse_ledger_entry_v3(cast(dict[str, Any], e)) for e in raw_entries)
    stored_root = _require_str(
        value, "ledger_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
    )
    try:
        ledger = AssumptionPolicyLedgerV3.build(entries)
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc
    # Verify the stored root matches the rebuilt root.
    if ledger.ledger_root_digest != stored_root:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_ROOT_MISMATCH")
    # Verify the stored bytes are canonical.
    if ledger.canonical_bytes != payload:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_NONCANONICAL")
    return ledger


# --- helpers for parsing embedded sub-objects ------------------------------


def _parse_authority_policy(value: dict[str, Any]) -> AssumptionAuthorityPolicy:
    """Parse an AssumptionAuthorityPolicy from its to_json_value dict."""

    from csd_foundry.governance.v0_5.assumption_governance_contracts import (
        AssumptionAuthorityGrant,
        AssumptionDutyException,
        AssumptionSeparationDutyRule,
    )

    def _parse_grant(g: dict[str, Any]) -> AssumptionAuthorityGrant:
        scopes_raw = g.get("scope_ids", [])
        scopes = tuple(cast(list[str], scopes_raw))
        mat_raw = g.get("assumption_materialities", [])
        chal_raw = g.get("challenge_materialities", [])
        return AssumptionAuthorityGrant(
            grant_id=_require_str(g, "grant_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            action=_require_str(g, "action", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            authority_id=_require_str(g, "authority_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            scope_ids=scopes,
            assumption_materialities=tuple(cast(list[str], mat_raw)),
            challenge_materialities=tuple(cast(list[str], chal_raw)),
            effective_from_sequence=_require_int(
                g, "effective_from_sequence", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            effective_until_sequence=(
                g["effective_until_sequence"]
                if g.get("effective_until_sequence") is not None
                else None
            ),
            grant_digest=_require_str(g, "grant_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
        )

    def _parse_rule(r: dict[str, Any]) -> AssumptionSeparationDutyRule:
        return AssumptionSeparationDutyRule(
            rule_id=_require_str(r, "rule_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            action=_require_str(r, "action", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            conflicting_roles=tuple(cast(list[str], r.get("conflicting_roles", []))),
            scope_ids=tuple(cast(list[str], r.get("scope_ids", []))),
            assumption_materialities=tuple(cast(list[str], r.get("assumption_materialities", []))),
            rule_digest=_require_str(r, "rule_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
        )

    def _parse_exception(e: dict[str, Any]) -> AssumptionDutyException:
        return AssumptionDutyException(
            exception_id=_require_str(e, "exception_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            rule_id=_require_str(e, "rule_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            action=_require_str(e, "action", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            authority_id=_require_str(e, "authority_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            conflicting_roles=tuple(cast(list[str], e.get("conflicting_roles", []))),
            scope_ids=tuple(cast(list[str], e.get("scope_ids", []))),
            assumption_ids=tuple(cast(list[str], e.get("assumption_ids", []))),
            assumption_materialities=tuple(cast(list[str], e.get("assumption_materialities", []))),
            reason_code=_require_str(e, "reason_code", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            effective_from_sequence=_require_int(
                e, "effective_from_sequence", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            effective_until_sequence=_require_int(
                e, "effective_until_sequence", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            exception_digest=_require_str(
                e, "exception_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )

    grants_raw = value.get("grants", [])
    rules_raw = value.get("separation_duty_rules", [])
    exceptions_raw = value.get("duty_exceptions", [])
    try:
        return AssumptionAuthorityPolicy(
            policy_id=_require_str(value, "policy_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            authority_root_digest=_require_str(
                value, "authority_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            grants=tuple(_parse_grant(g) for g in grants_raw),
            separation_duty_rules=tuple(_parse_rule(r) for r in rules_raw),
            duty_exceptions=tuple(_parse_exception(e) for e in exceptions_raw),
            grant_set_digest=_require_str(
                value, "grant_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            separation_duty_rule_set_digest=_require_str(
                value, "separation_duty_rule_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            exception_set_digest=_require_str(
                value, "exception_set_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            policy_digest=_require_str(
                value, "policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except Exception as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID") from exc


def _parse_approval_policy(value: dict[str, Any]) -> AssumptionPolicyApprovalPolicy:
    rules_raw = value.get("rules")
    if type(rules_raw) is not list:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_FIELD_INVALID", "rules")
    rules = tuple(
        AssumptionPolicyApprovalRule(
            approval_class=_require_str(
                r, "approval_class", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            eligible_signer_ids=tuple(cast(list[str], r.get("eligible_signer_ids", []))),
            required_signature_count=_require_int(
                r, "required_signature_count", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            required_signer_ids=tuple(cast(list[str], r.get("required_signer_ids", []))),
            rule_digest=_require_str(r, "rule_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
        )
        for r in rules_raw
    )
    try:
        return AssumptionPolicyApprovalPolicy(
            approval_policy_id=_require_str(
                value, "approval_policy_id", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            authority_root_digest=_require_str(
                value, "authority_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            rules=rules,
            approval_policy_digest=_require_str(
                value, "approval_policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except Exception as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID") from exc


def _parse_signature_profile(value: dict[str, Any]) -> AssumptionPolicySignatureProfile:
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        AssumptionPolicyAlgorithmProfile,
    )

    profiles_raw = value.get("algorithm_profiles")
    if type(profiles_raw) is not list:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_FIELD_INVALID", "algorithm_profiles")
    profiles = tuple(
        AssumptionPolicyAlgorithmProfile(
            algorithm=_require_str(p, "algorithm", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            verification_profile=_require_str(
                p, "verification_profile", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
        for p in profiles_raw
    )
    try:
        return AssumptionPolicySignatureProfile(
            signature_set_schema_version=_require_str(
                value, "signature_set_schema_version", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            signature_record_semantics_version=_require_str(
                value,
                "signature_record_semantics_version",
                "ASSUMPTION_POLICY_STORED_FIELD_INVALID",
            ),
            algorithm_profiles=profiles,
            required_authority_scope=_require_str(
                value, "required_authority_scope", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            key_authority_root_digest=_require_str(
                value, "key_authority_root_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            duplicate_signer_rule=_require_str(
                value, "duplicate_signer_rule", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            profile_digest=_require_str(
                value, "profile_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def _parse_challenge_policy(value: dict[str, Any]) -> AssumptionChallengeClassificationPolicy:
    from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
        AssumptionChallengeClassificationRule,
    )

    rules_raw = value.get("reason_rules")
    if type(rules_raw) is not list:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_FIELD_INVALID", "reason_rules")
    rules = tuple(
        AssumptionChallengeClassificationRule(
            reason_code=_require_str(r, "reason_code", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
            materiality=_require_str(r, "materiality", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"),
        )
        for r in rules_raw
    )
    try:
        return AssumptionChallengeClassificationPolicy(
            reason_rules=rules,
            unknown_reason_behavior=_require_str(
                value, "unknown_reason_behavior", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
            policy_digest=_require_str(
                value, "policy_digest", "ASSUMPTION_POLICY_STORED_FIELD_INVALID"
            ),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


# --- filesystem publisher --------------------------------------------------


class FilesystemAssumptionPolicyPublisher:
    """Interprocess-safe atomic filesystem publisher.

    Stores the authoritative ``AssumptionPolicyLedgerV3`` as a single canonical
    JSON file. Uses ``_platform.advisory_lock`` for exclusive interprocess
    access and ``os.replace`` for atomic file replacement.

    Atomic publication sequence (all under one lock):

      1. acquire exclusive publication lock
      2. read authoritative stored ledger bytes
      3. reconstruct and fully validate ledger/3
      4. derive exact current root and head
      5. run V3 exact idempotence (via the A1.3-A oracle)
      6. compare exact expected state
      7. validate predecessor pair and sequence
      8. construct updated ledger/3 bytes
      9. write temporary file
     10. flush and fsync the temporary file
     11. atomically replace the authoritative file
     12. perform supported directory durability operation
     13. reread authoritative bytes
     14. reconstruct and verify exact root/head/bytes
     15. return the activation result
     16. release the lock
    """

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_INVALID")
        self.root = root
        self.ledger_path = root / "ledger.json"
        self.lock_path = root / "publication.lock"
        self.temporary = root / ".tmp"
        for directory in (root, self.temporary):
            directory.mkdir(parents=True, exist_ok=True)
            fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)
        # Clean orphan temp files from a previous crash.
        for orphan in self.temporary.glob("*.tmp"):
            orphan.unlink(missing_ok=True)
        # Initialize empty ledger if missing.
        if not self.ledger_path.exists():
            empty = AssumptionPolicyLedgerV3.build(())
            self._write_atomic(empty.canonical_bytes)

    def _read_ledger_bytes(self) -> bytes:
        if not self.ledger_path.exists():
            raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_MISSING")
        return self.ledger_path.read_bytes()

    def _write_atomic(self, payload: bytes) -> None:
        temp = self.temporary / f"{uuid.uuid4().hex}.tmp"
        with open(temp, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.ledger_path)
        fsync_directory(self.root)

    def _reconstruct(self) -> AssumptionPolicyLedgerV3:
        payload = self._read_ledger_bytes()
        return parse_ledger_v3(payload)

    def read_state(self) -> ExpectedPolicyLedgerStateV3:
        with advisory_lock(self.lock_path):
            return ExpectedPolicyLedgerStateV3.from_ledger(self._reconstruct())

    def read_ledger(self) -> AssumptionPolicyLedgerV3:
        with advisory_lock(self.lock_path):
            return self._reconstruct()

    def publish(
        self,
        *,
        prepared: PreparedPolicyActivation,
        expected_state: ExpectedPolicyLedgerStateV3,
    ) -> AssumptionPolicyActivationResult:
        entry = prepared.ledger_entry
        if type(entry) is not AssumptionPolicyLedgerEntryV3:
            raise AssumptionPolicyPublicationConflict(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE"
            )
        with advisory_lock(self.lock_path):
            ledger = self._reconstruct()
            updated, result = compare_and_append_policy_entry_v3(
                ledger=ledger,
                expected_state=expected_state,
                candidate=entry,
            )
            if result.append_result == "COMMITTED":
                self._write_atomic(updated.canonical_bytes)
                # Post-write verification: reread and confirm.
                verified = self._reconstruct()
                if verified.ledger_root_digest != updated.ledger_root_digest:
                    raise PolicyStoreError("ASSUMPTION_POLICY_STORED_VERIFICATION_FAILED")
            return result
