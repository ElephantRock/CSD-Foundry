"""Durable filesystem publication for v0.5-D3.2-A1.3-B V3 policy activation.

Provides ``FilesystemAssumptionPolicyPublisher``: an interprocess-safe atomic
publisher that stores the authoritative ``AssumptionPolicyLedgerV3`` as a
single canonical JSON file and uses a *strict* composition of the
``_platform`` lock primitives for exclusive access.

The pure A1.3-A function ``compare_and_append_policy_entry_v3`` remains the
semantic oracle. The filesystem layer owns: locking, stored-byte validation,
atomic replacement, restart reconstruction, post-write verification, and
platform-specific durability boundaries.

Claim boundary
==============

This module claims, on every supported platform:

* exclusive interprocess publication via a *strict* lock composition: the lock
  file is opened with ``_platform.open_lock_file_strict`` (POSIX
  ``O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW``; Windows ``a+b`` plus an
  ``os.fstat`` regular-file check) so a symlink (or directory, or any other
  non-regular shape) at ``publication.lock`` is rejected before any lock is
  acquired. The publisher does NOT use the ordinary ``_platform.advisory_lock``
  used by the temporal, admission, and registry stores -- those remain
  permissive and are intentionally untouched;
* atomic visibility of the authoritative ledger through ``os.replace`` on the
  same filesystem as the destination;
* temporary-file fsync before the atomic replace so the replacement is durable
  up to the supported durability boundary;
* crash-safe temporary-file handling: every managed temp file is named
  ``.policy-ledger.<uuid>.tmp`` inside the store root, and any such orphan left
  by a previous crash is removed at store open. Orphan enumeration and every
  candidate inspection (``iterdir``, ``is_symlink``, ``is_dir``, ``unlink``)
  is normalized: no raw ``OSError`` from these calls may escape -- a failure
  surfaces ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`` with the offending
  name (or ``"<root>"``) as the detail;
* full restart reconstruction: every published ledger is re-parsed and fully
  revalidated (including every nested contract's schema version) on read;
* strengthened post-write verification that the bytes just written are the
  exact canonical bytes the publisher intended and that the resulting ledger's
  entries, root, and head match the oracle's updated ledger.

POSIX additionally claims:

* directory fsync of the store root after the atomic replace, providing
  sudden-power-loss durability of the rename.

Windows does NOT claim POSIX-equivalent sudden-power-loss directory-fsync
durability: directories cannot be opened as file descriptors and ``os.sync``
is unavailable. ``fsync_directory`` is a no-op on Windows.

Lock-path invariant
===================

``publication.lock`` must always be a regular file. A symlink at the lock path
is rejected, as is a directory or any other non-regular shape. The platform
opener (:func:`csd_foundry._platform.open_lock_file_strict`) refuses such a
path during acquisition:

* **POSIX:** ``os.open`` with ``O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW``.
  ``O_NOFOLLOW`` causes the kernel to reject a symlink at ``publication.lock``
  with ``ELOOP`` before any file is opened or followed; ``fstat`` on the
  descriptor then confirms a regular file.
* **Windows:** there is no ``O_NOFOLLOW`` equivalent. The opener performs
  cooperative acquisition-time validation:

  1. ``lstat`` the path;
  2. reject an observed symlink or non-regular shape;
  3. atomically create a missing regular file or open an existing path
     without truncation;
  4. ``fstat`` the opened descriptor and require a regular file;
  5. ``lstat`` the path again;
  6. require the descriptor and path to identify the same regular file;
  7. seed only after all checks succeed.

  The opener does not seed or lock through a symlink or replacement
  detected during acquisition. A noncooperating actor changing the
  directory entry after validation is outside the cooperative
  single-host claim.

Every such shape/open failure is normalized to
``ASSUMPTION_POLICY_STORE_LOCK_INVALID``. A descriptor that validated but whose
handle could not be created or seeded (``os.fdopen`` or the seed
``write``/``flush``/``fsync`` failed) is normalized to
``ASSUMPTION_POLICY_STORE_LOCK_FAILED`` -- the lock path is a valid regular
file, but a usable lock could not be established. ``LOCK_FAILED`` is also used
for the case where the lock path is a valid regular file but the advisory lock
itself could not be acquired. An ``OSError`` raised by the protected operation
inside the lock scope is never mislabeled as either lock code. No backend
exception message is carried into the public ``detail``.

Lifecycle
=========

The constructor performs no initialization: it records paths only. Two
explicit lifecycle entry points perform all managed, side-effecting work:

* ``create()`` -- initialize an empty authoritative ledger. Performed exactly
  once under the publication lock. A subsequent ``create()`` against an
  existing valid ledger raises ``ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED``.
  A ``create()`` against a corrupt or partial ledger raises the appropriate
  reconstruction error rather than silently re-initializing.
* ``open()`` -- open an existing store. Never initializes. A missing ledger
  raises ``ASSUMPTION_POLICY_STORED_BYTES_MISSING``.

Read and publish operations reconstruct the authoritative ledger from bytes on
every call (full revalidation, no in-memory cache), so an unmodified store can
be reopened from any process at any time.

Atomic publication sequence
===========================

All steps run under a single strict lock acquisition:

  1. acquire exclusive publication lock (strict opener)
  2. read authoritative stored ledger bytes
  3. reconstruct and fully validate ledger/3 (every nested contract revalidated)
  4. derive exact current root and head
  5. run V3 exact idempotence (via the A1.3-A oracle)
  6. compare exact expected state
  7. validate predecessor pair and sequence
  8. construct updated ledger/3 bytes
  9. ``_checkpoint("BEFORE_TEMP_CREATE")`` -- fault injection point
 10. write managed temporary file ``.policy-ledger.<uuid>.tmp``
 11. ``_checkpoint("AFTER_PARTIAL_TEMP_WRITE")`` -- fault injection point
 12. ``_checkpoint("AFTER_TEMP_FLUSH")`` -- fault injection point
 13. ``_checkpoint("BEFORE_REPLACE")`` -- fault injection point (pre-commit)
 14. ``os.replace`` atomically swaps the authoritative file
     [commit point: os.replace crosses here]
 15. ``_checkpoint("AFTER_REPLACE")`` -- fault injection point (post-commit)
 16. ``_checkpoint("BEFORE_DIRECTORY_FSYNC")`` -- fault injection point
 17. perform supported directory durability operation
 18. ``_checkpoint("BEFORE_POST_WRITE_READ")`` -- fault injection point
 19. reread authoritative bytes
 20. ``_checkpoint("DURING_POST_WRITE_READ")`` -- fault injection point
 21. reconstruct and verify exact bytes + entries + root + head + predecessor
 22. return the activation result
 23. release the lock

Named fault-injection checkpoints (all normalized)
===================================================

There are exactly eight deterministic checkpoints, split at the ``os.replace``
commit point. A fault raised at any of them is normalized to a stable public
code (never the raw exception type or message):

* pre-replace (old ledger byte-for-byte intact, fault is normalized, temp
  removed):

  - ``BEFORE_TEMP_CREATE``
  - ``AFTER_PARTIAL_TEMP_WRITE``
  - ``AFTER_TEMP_FLUSH``
  - ``BEFORE_REPLACE``

  The first three normalize to ``ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED``;
  ``BEFORE_REPLACE`` normalizes to
  ``ASSUMPTION_POLICY_STORE_REPLACE_FAILED``. If the owned-temp cleanup that
  follows any of these faults itself fails, the public code is
  ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`` (the cleanup failure
  dominates the original write/replace error because an un-removable orphan is
  the more actionable signal).

* post-replace (the publication may have landed, so any fault is normalized to
  ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`` and no rollback is
  attempted):

  - ``AFTER_REPLACE``
  - ``BEFORE_DIRECTORY_FSYNC``
  - ``BEFORE_POST_WRITE_READ``
  - ``DURING_POST_WRITE_READ``

Pre-commit failure (steps 1-13): the old ledger is intact, no result is
returned, no rollback is required. Post-commit failure (steps 14+): the
replacement may or may not have been durably installed; the publisher raises
``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`` and never attempts a
rollback (which could itself corrupt a successfully-installed ledger).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from csd_foundry._platform import (
    LockInitializationError,
    LockInvalidError,
    fsync_directory,
    lock_file,
    open_lock_file_strict,
    unlock_file,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION,
    SIGNATURE_PROFILE_SCHEMA_VERSION,
    AssumptionChallengeClassificationPolicy,
    AssumptionChallengeClassificationRule,
    AssumptionPolicyActivationContractError,
    AssumptionPolicyAlgorithmProfile,
    AssumptionPolicySignatureProfile,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    ACTIVATION_PROOF_V2_SCHEMA_VERSION,
    AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION,
    POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION,
    POLICY_LEDGER_V3_SCHEMA_VERSION,
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
    AUTHORITY_GRANT_SCHEMA_VERSION,
    AUTHORITY_POLICY_SCHEMA_VERSION,
    DUTY_EXCEPTION_SCHEMA_VERSION,
    SEPARATION_DUTY_RULE_SCHEMA_VERSION,
    AssumptionAuthorityGrant,
    AssumptionAuthorityPolicy,
    AssumptionDutyException,
    AssumptionSeparationDutyRule,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    APPROVAL_POLICY_SCHEMA_VERSION,
    APPROVAL_RULE_SCHEMA_VERSION,
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

# Stable field-set and schema-version constants for every closed object the
# publisher must parse from canonical stored bytes. These are kept here (rather
# than imported piecemeal) so that the JSON boundary validation is auditable in
# one place.

_LEDGER_SCHEMA_VERSION = POLICY_LEDGER_V3_SCHEMA_VERSION

_LEDGER_FIELDS = frozenset({"schema_version", "entries", "ledger_root_digest"})
_LEDGER_ENTRY_FIELDS = frozenset(
    {
        "schema_version",
        "policy",
        "signing_payload",
        "policy_commit",
        "approval_policy",
        "signature_profile",
        "challenge_classification_policy",
        "activation_proof",
        "ledger_entry_digest",
    }
)
_SIGNING_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "policy_digest",
        "predecessor_policy_digest",
        "predecessor_commit_receipt_digest",
        "authority_root_digest",
        "grant_set_digest",
        "separation_duty_rule_set_digest",
        "exception_set_digest",
        "exception_count",
        "approval_class",
        "effective_from_sequence",
        "approval_policy_digest",
        "signature_profile_digest",
        "challenge_classification_policy_digest",
        "signing_payload_digest",
    }
)
_POLICY_COMMIT_V3_FIELDS = frozenset(
    {
        "schema_version",
        "signing_payload_digest",
        "signature_set_digest",
        "commit_receipt_digest",
    }
)
_ACTIVATION_PROOF_V2_FIELDS = frozenset(
    {
        "schema_version",
        "signing_payload_digest",
        "policy_commit_receipt_digest",
        "approval_policy_digest",
        "approval_rule_digest",
        "signature_profile_digest",
        "challenge_classification_policy_digest",
        "authority_root_digest",
        "signature_set_digest",
        "valid_signer_ids",
        "rejected_signer_codes",
        "activation_proof_digest",
    }
)
_AUTHORITY_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "authority_root_digest",
        "grants",
        "separation_duty_rules",
        "duty_exceptions",
        "grant_set_digest",
        "separation_duty_rule_set_digest",
        "exception_set_digest",
        "policy_digest",
    }
)
_AUTHORITY_GRANT_FIELDS = frozenset(
    {
        "schema_version",
        "grant_id",
        "action",
        "authority_id",
        "scope_ids",
        "assumption_materialities",
        "challenge_materialities",
        "effective_from_sequence",
        "effective_until_sequence",
        "grant_digest",
    }
)
_SEPARATION_DUTY_RULE_FIELDS = frozenset(
    {
        "schema_version",
        "rule_id",
        "action",
        "conflicting_roles",
        "scope_ids",
        "assumption_materialities",
        "rule_digest",
    }
)
_DUTY_EXCEPTION_FIELDS = frozenset(
    {
        "schema_version",
        "exception_id",
        "rule_id",
        "action",
        "authority_id",
        "conflicting_roles",
        "scope_ids",
        "assumption_ids",
        "assumption_materialities",
        "reason_code",
        "effective_from_sequence",
        "effective_until_sequence",
        "exception_digest",
    }
)
_APPROVAL_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "approval_policy_id",
        "authority_root_digest",
        "rules",
        "approval_policy_digest",
    }
)
_APPROVAL_RULE_FIELDS = frozenset(
    {
        "schema_version",
        "approval_class",
        "eligible_signer_ids",
        "required_signature_count",
        "required_signer_ids",
        "rule_digest",
    }
)
_SIGNATURE_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "signature_set_schema_version",
        "signature_record_semantics_version",
        "algorithm_profiles",
        "required_authority_scope",
        "key_authority_root_digest",
        "duplicate_signer_rule",
        "profile_digest",
    }
)
_ALGORITHM_PROFILE_FIELDS = frozenset({"algorithm", "verification_profile"})
_CHALLENGE_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "reason_rules",
        "unknown_reason_behavior",
        "policy_digest",
    }
)
_CHALLENGE_RULE_FIELDS = frozenset({"reason_code", "materiality"})

# Managed temporary-file naming pattern. Every temp file the publisher writes
# matches the exact pattern ``.policy-ledger.<32-lowercase-hex>.tmp`` so that
# orphan cleanup at open() is both safe (only files the publisher could have
# created are touched) and complete. The middle segment is exactly 32 lowercase
# hex characters (``uuid.uuid4().hex``).
_TEMP_PREFIX = ".policy-ledger."
_TEMP_SUFFIX = ".tmp"
# Exact middle pattern: 32 lowercase hex characters. Orphan cleanup matches the
# whole name against this compiled pattern so that an unrelated file can never
# be mistaken for a managed temp.
_TEMP_NAME_PATTERN = re.compile(
    r"^" + re.escape(_TEMP_PREFIX) + r"[0-9a-f]{32}" + re.escape(_TEMP_SUFFIX) + r"$"
)

# Deterministic fault-injection checkpoints. Tests may install a callback via
# ``with_fault_injection`` that raises at a named checkpoint to verify pre- and
# post-commit failure behavior. The first four checkpoints are PRE-replace: a
# fault there leaves the old authoritative ledger intact. The last four are
# POST-replace: the replacement may or may not have landed, so any fault is
# reported as ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN``.
_CHECKPOINT_BEFORE_TEMP_CREATE = "BEFORE_TEMP_CREATE"
_CHECKPOINT_AFTER_PARTIAL_TEMP_WRITE = "AFTER_PARTIAL_TEMP_WRITE"
_CHECKPOINT_AFTER_TEMP_FLUSH = "AFTER_TEMP_FLUSH"
_CHECKPOINT_BEFORE_REPLACE = "BEFORE_REPLACE"
# --- commit point (os.replace) crosses here ---
_CHECKPOINT_AFTER_REPLACE = "AFTER_REPLACE"
_CHECKPOINT_BEFORE_DIRECTORY_FSYNC = "BEFORE_DIRECTORY_FSYNC"
_CHECKPOINT_BEFORE_POST_WRITE_READ = "BEFORE_POST_WRITE_READ"
_CHECKPOINT_DURING_POST_WRITE_READ = "DURING_POST_WRITE_READ"

# The set of all checkpoint names, grouped by commit side. ``_commit`` and
# ``create`` rely on the invariant that the first four names are pre-replace
# (old ledger intact on any fault) and the last four are post-replace (outcome
# uncertain on any fault). The assertion below preserves the split at import.
_PRE_REPLACE_CHECKPOINTS = frozenset(
    {
        _CHECKPOINT_BEFORE_TEMP_CREATE,
        _CHECKPOINT_AFTER_PARTIAL_TEMP_WRITE,
        _CHECKPOINT_AFTER_TEMP_FLUSH,
        _CHECKPOINT_BEFORE_REPLACE,
    }
)
_POST_REPLACE_CHECKPOINTS = frozenset(
    {
        _CHECKPOINT_AFTER_REPLACE,
        _CHECKPOINT_BEFORE_DIRECTORY_FSYNC,
        _CHECKPOINT_BEFORE_POST_WRITE_READ,
        _CHECKPOINT_DURING_POST_WRITE_READ,
    }
)
assert len(_PRE_REPLACE_CHECKPOINTS) == 4
assert len(_POST_REPLACE_CHECKPOINTS) == 4
assert _PRE_REPLACE_CHECKPOINTS.isdisjoint(_POST_REPLACE_CHECKPOINTS)


class PolicyStoreError(RuntimeError):
    """Stable, normalized error for filesystem policy-store failures.

    Every filesystem, locking, and parser failure is normalized to a stable
    ``code`` so callers can switch on outcomes without parsing messages. The
    set of codes a caller may observe from this module is:

    * ``ASSUMPTION_POLICY_STORE_ROOT_INVALID`` -- constructor root argument was
      not a ``pathlib.Path``.
    * ``ASSUMPTION_POLICY_STORE_ROOT_MISSING`` -- ``open()`` was called against
      a root directory that does not exist. Only ``create()`` may create the
      root; ``open()`` never does.
    * ``ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY`` -- root exists but is not
      a directory (or is an unusable path shape such as a symlink to a file).
    * ``ASSUMPTION_POLICY_STORE_ROOT_CREATE_FAILED`` -- the root directory or
      its parent could not be created or synced.
    * ``ASSUMPTION_POLICY_STORE_LOCK_INVALID`` -- the publication lock path is
      not a regular file (it is a symlink, a directory, or another non-regular
      shape). The strict lock opener refuses to open or follow such a path, so
      the publication lock can never be held against an attacker-controlled
      file. Raised during acquisition only; an ``OSError`` raised by a
      protected operation is never mislabeled as ``LOCK_INVALID``.
    * ``ASSUMPTION_POLICY_STORE_LOCK_FAILED`` -- the lock path is a valid
      regular file but the advisory lock itself could not be acquired (raised
      by the lock helper as ``OSError`` during acquisition only; an ``OSError``
      raised by a protected operation is never mislabeled as ``LOCK_FAILED``).
    * ``ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED`` -- ``create()`` was called
      against a store that already holds a valid authoritative ledger.
    * ``ASSUMPTION_POLICY_STORED_BYTES_MISSING`` -- the authoritative ledger
      file does not exist (``open()`` on an uninitialized store, or any read
      before ``create()``).
    * ``ASSUMPTION_POLICY_STORED_BYTES_INVALID`` -- the stored bytes are not
      valid UTF-8 JSON, or the top-level value is not a JSON object.
    * ``ASSUMPTION_POLICY_STORED_BYTES_NONCANONICAL`` -- the stored bytes are
      valid JSON but not the canonical byte sequence the contract would emit.
    * ``ASSUMPTION_POLICY_STORED_DUPLICATE_KEY`` -- the stored JSON contains a
      duplicate key at any depth (rejected by the closed parser).
    * ``ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED`` -- a stored object's
      ``schema_version`` is not the version this publisher activates.
    * ``ASSUMPTION_POLICY_STORED_FIELD_INVALID`` -- a stored object is missing
      a required field, has an extra/unknown field, or has a field of the
      wrong type.
    * ``ASSUMPTION_POLICY_STORED_CONTRACT_INVALID`` -- a stored object parsed
      structurally but failed frozen-contract self-validation.
    * ``ASSUMPTION_POLICY_STORED_ROOT_MISMATCH`` -- the stored ledger root
      digest does not match the rebuilt root.
    * ``ASSUMPTION_POLICY_STORED_VERIFICATION_FAILED`` -- post-write
      verification did not observe the exact ledger the publisher intended.
    * ``ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED`` -- a failure occurred
      before the atomic replace while writing or fsyncing the managed temp
      file. The old authoritative ledger is intact.
    * ``ASSUMPTION_POLICY_STORE_REPLACE_FAILED`` -- the atomic ``os.replace``
      itself failed. This is a pre-commit failure: the old authoritative
      ledger is intact (the temp file is removed).
    * ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`` -- a managed orphan
      temporary file (``.policy-ledger.<32-hex>.tmp``) could not be removed
      during the open/create/publish orphan sweep. The authoritative ledger is
      untouched; the operator must reconcile the unremovable orphan.
    * ``ASSUMPTION_POLICY_STORE_DURABILITY_FAILED`` -- at least one managed
      orphan was removed but the store-root directory fsync failed
      afterwards (POSIX only). The authoritative ledger is untouched.
    * ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`` -- a failure occurred
      after ``os.replace``; the publication may or may not have landed.

    No error code carries ``str(exc)`` or ``repr(exc)`` of an underlying
    backend exception as its ``detail``: the observable behavior depends only
    on the operation stage, the pre/post-commit status, and the stable storage
    code, never on backend diagnostic text.
    """

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ===========================================================================
# Hardened JSON parser boundary helpers
# ===========================================================================
#
# Every value entering the typed contract layer from canonical stored bytes
# passes through these helpers. They enforce, in order:
#
#   0. no duplicate keys at any depth (via ``object_pairs_hook`` at the
#      ``json.loads`` boundary);
#   1. the value is exactly a JSON object (``dict``);
#   2. the object's field set is exactly the closed schema's field set (no
#      missing fields, no unknown fields);
#   3. the object's ``schema_version`` is exactly the supported version;
#   4. each scalar field is the exact Python type the contract expects;
#   5. each list field is a list of the exact expected element type.
#
# Only after a value passes all six gates is it handed to the frozen contract
# constructor, which performs digest self-validation.


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """``json.loads`` ``object_pairs_hook`` that rejects duplicate keys.

    Applied at the JSON boundary so a stored object carrying a duplicate key at
    any depth (e.g. two ``schema_version`` fields, or a duplicate digest inside
    a nested grant) is rejected with the stable
    ``ASSUMPTION_POLICY_STORED_DUPLICATE_KEY`` code before any structural
    validation runs. The duplicate-key name is reported as ``detail`` so a test
    can assert which key collided, but no backend exception text is exposed.
    """

    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORED_DUPLICATE_KEY", key)
        seen[key] = value
    return seen


def _require_object(value: object, code: str, detail: str | None = None) -> dict[str, Any]:
    """Require ``value`` to be exactly a ``dict`` (a JSON object)."""

    if type(value) is not dict:
        raise PolicyStoreError(code, detail)
    return value


def _require_closed_object(
    value: dict[str, Any],
    expected_fields: frozenset[str],
    code: str,
) -> None:
    """Require ``value``'s key set to equal ``expected_fields`` exactly."""

    actual = set(value)
    unknown = actual - expected_fields
    if unknown:
        raise PolicyStoreError(code, sorted(unknown)[0])
    missing = expected_fields - actual
    if missing:
        raise PolicyStoreError(code, sorted(missing)[0])


def _require_schema_version(value: dict[str, Any], expected: str) -> None:
    """Require the ``schema_version`` field to equal ``expected`` exactly."""

    sv = value.get("schema_version")
    if type(sv) is not str or sv != expected:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED", expected)


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
    # ``bool`` is a subclass of ``int`` in Python; reject it explicitly so a
    # stored ``true`` cannot masquerade as ``1``.
    if type(v) is not int or isinstance(v, bool) or v < 0:
        raise PolicyStoreError(code, key)
    return v


def _require_optional_nonnegative_int(value: dict[str, Any], key: str, code: str) -> int | None:
    v = value.get(key)
    if v is None:
        return None
    if type(v) is not int or isinstance(v, bool) or v < 0:
        raise PolicyStoreError(code, key)
    return v


def _require_list(value: dict[str, Any], key: str, code: str) -> list[Any]:
    v = value.get(key)
    if type(v) is not list:
        raise PolicyStoreError(code, key)
    return v


def _require_list_of_objects(value: dict[str, Any], key: str, code: str) -> list[dict[str, Any]]:
    raw = _require_list(value, key, code)
    out: list[dict[str, Any]] = []
    for element in raw:
        if type(element) is not dict:
            raise PolicyStoreError(code, key)
        out.append(element)
    return out


def _require_list_of_strings(value: dict[str, Any], key: str, code: str) -> list[str]:
    raw = _require_list(value, key, code)
    out: list[str] = []
    for element in raw:
        if type(element) is not str:
            raise PolicyStoreError(code, key)
        out.append(element)
    return out


_FIELD_INVALID = "ASSUMPTION_POLICY_STORED_FIELD_INVALID"


# ===========================================================================
# V3 parsers (reconstruct typed objects from canonical bytes)
# ===========================================================================


def parse_signing_payload(value: dict[str, Any]) -> AssumptionPolicySigningPayload:
    """Parse and self-validate a signing-payload/1 from canonical JSON."""

    _require_closed_object(value, _SIGNING_PAYLOAD_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, SIGNING_PAYLOAD_SCHEMA_VERSION)
    policy_id = _require_str(value, "policy_id", _FIELD_INVALID)
    policy_digest = _require_str(value, "policy_digest", _FIELD_INVALID)
    predecessor_policy_digest = _require_optional_str(
        value, "predecessor_policy_digest", _FIELD_INVALID
    )
    predecessor_commit_receipt_digest = _require_optional_str(
        value, "predecessor_commit_receipt_digest", _FIELD_INVALID
    )
    authority_root_digest = _require_str(value, "authority_root_digest", _FIELD_INVALID)
    grant_set_digest = _require_str(value, "grant_set_digest", _FIELD_INVALID)
    separation_duty_rule_set_digest = _require_str(
        value, "separation_duty_rule_set_digest", _FIELD_INVALID
    )
    exception_set_digest = _require_str(value, "exception_set_digest", _FIELD_INVALID)
    exception_count = _require_int(value, "exception_count", _FIELD_INVALID)
    approval_class = _require_str(value, "approval_class", _FIELD_INVALID)
    effective_from_sequence = _require_int(value, "effective_from_sequence", _FIELD_INVALID)
    approval_policy_digest = _require_str(value, "approval_policy_digest", _FIELD_INVALID)
    signature_profile_digest = _require_str(value, "signature_profile_digest", _FIELD_INVALID)
    challenge_classification_policy_digest = _require_str(
        value, "challenge_classification_policy_digest", _FIELD_INVALID
    )
    signing_payload_digest = _require_str(value, "signing_payload_digest", _FIELD_INVALID)
    try:
        return AssumptionPolicySigningPayload(
            policy_id=policy_id,
            policy_digest=policy_digest,
            predecessor_policy_digest=predecessor_policy_digest,
            predecessor_commit_receipt_digest=predecessor_commit_receipt_digest,
            authority_root_digest=authority_root_digest,
            grant_set_digest=grant_set_digest,
            separation_duty_rule_set_digest=separation_duty_rule_set_digest,
            exception_set_digest=exception_set_digest,
            exception_count=exception_count,
            approval_class=approval_class,
            effective_from_sequence=effective_from_sequence,
            approval_policy_digest=approval_policy_digest,
            signature_profile_digest=signature_profile_digest,
            challenge_classification_policy_digest=challenge_classification_policy_digest,
            signing_payload_digest=signing_payload_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_policy_commit_v3(value: dict[str, Any]) -> AssumptionAuthorityPolicyCommitV3:
    """Parse and self-validate an authority-policy-commit/3 from canonical JSON."""

    _require_closed_object(value, _POLICY_COMMIT_V3_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION)
    signing_payload_digest = _require_str(value, "signing_payload_digest", _FIELD_INVALID)
    signature_set_digest = _require_str(value, "signature_set_digest", _FIELD_INVALID)
    commit_receipt_digest = _require_str(value, "commit_receipt_digest", _FIELD_INVALID)
    try:
        return AssumptionAuthorityPolicyCommitV3(
            signing_payload_digest=signing_payload_digest,
            signature_set_digest=signature_set_digest,
            commit_receipt_digest=commit_receipt_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_activation_proof_v2(value: dict[str, Any]) -> AssumptionPolicyActivationProofV2:
    """Parse and self-validate an activation-proof/2 from canonical JSON."""

    _require_closed_object(value, _ACTIVATION_PROOF_V2_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, ACTIVATION_PROOF_V2_SCHEMA_VERSION)
    proof_signing_payload_digest = _require_str(value, "signing_payload_digest", _FIELD_INVALID)
    policy_commit_receipt_digest = _require_str(
        value, "policy_commit_receipt_digest", _FIELD_INVALID
    )
    approval_policy_digest = _require_str(value, "approval_policy_digest", _FIELD_INVALID)
    approval_rule_digest = _require_str(value, "approval_rule_digest", _FIELD_INVALID)
    signature_profile_digest = _require_str(value, "signature_profile_digest", _FIELD_INVALID)
    challenge_classification_policy_digest = _require_str(
        value, "challenge_classification_policy_digest", _FIELD_INVALID
    )
    authority_root_digest = _require_str(value, "authority_root_digest", _FIELD_INVALID)
    signature_set_digest = _require_str(value, "signature_set_digest", _FIELD_INVALID)
    valid_signers = tuple(_require_list_of_strings(value, "valid_signer_ids", _FIELD_INVALID))
    rejected_codes = tuple(_require_list_of_strings(value, "rejected_signer_codes", _FIELD_INVALID))
    activation_proof_digest = _require_str(value, "activation_proof_digest", _FIELD_INVALID)
    try:
        return AssumptionPolicyActivationProofV2(
            signing_payload_digest=proof_signing_payload_digest,
            policy_commit_receipt_digest=policy_commit_receipt_digest,
            approval_policy_digest=approval_policy_digest,
            approval_rule_digest=approval_rule_digest,
            signature_profile_digest=signature_profile_digest,
            challenge_classification_policy_digest=challenge_classification_policy_digest,
            authority_root_digest=authority_root_digest,
            signature_set_digest=signature_set_digest,
            valid_signer_ids=valid_signers,
            rejected_signer_codes=rejected_codes,
            activation_proof_digest=activation_proof_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_ledger_entry_v3(value: dict[str, Any]) -> AssumptionPolicyLedgerEntryV3:
    """Parse and self-validate a policy-ledger-entry/3 from canonical JSON."""

    _require_closed_object(value, _LEDGER_ENTRY_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION)
    policy = _parse_authority_policy(_require_object(value.get("policy"), _FIELD_INVALID, "policy"))
    signing_payload = parse_signing_payload(
        _require_object(value.get("signing_payload"), _FIELD_INVALID, "signing_payload")
    )
    policy_commit = parse_policy_commit_v3(
        _require_object(value.get("policy_commit"), _FIELD_INVALID, "policy_commit")
    )
    approval_policy = _parse_approval_policy(
        _require_object(value.get("approval_policy"), _FIELD_INVALID, "approval_policy")
    )
    signature_profile = _parse_signature_profile(
        _require_object(value.get("signature_profile"), _FIELD_INVALID, "signature_profile")
    )
    challenge_policy = _parse_challenge_policy(
        _require_object(
            value.get("challenge_classification_policy"),
            _FIELD_INVALID,
            "challenge_classification_policy",
        )
    )
    activation_proof = parse_activation_proof_v2(
        _require_object(value.get("activation_proof"), _FIELD_INVALID, "activation_proof")
    )
    try:
        return AssumptionPolicyLedgerEntryV3(
            policy=policy,
            signing_payload=signing_payload,
            policy_commit=policy_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_classification_policy=challenge_policy,
            activation_proof=activation_proof,
            ledger_entry_digest=_require_str(value, "ledger_entry_digest", _FIELD_INVALID),
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def parse_ledger_v3(payload: bytes) -> AssumptionPolicyLedgerV3:
    """Parse, revalidate, and reconstruct a complete ``AssumptionPolicyLedgerV3``
    from canonical stored bytes.

    Every nested contract is re-parsed through its hardened parser, which
    enforces exact object type, exact closed field set, exact schema version,
    and exact scalar/list types before handing the value to the frozen
    contract constructor for digest self-validation. Duplicate keys at any
    depth are rejected at the ``json.loads`` boundary via
    ``object_pairs_hook=_reject_duplicate_pairs``.
    """

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_INVALID") from exc
    except PolicyStoreError:
        # A duplicate-key rejection raised inside the object_pairs_hook: it
        # already carries the stable DUPLICATE_KEY code, so re-raise unchanged.
        raise
    top = _require_object(value, "ASSUMPTION_POLICY_STORED_BYTES_INVALID")
    _require_closed_object(top, _LEDGER_FIELDS, _FIELD_INVALID)
    _require_schema_version(top, _LEDGER_SCHEMA_VERSION)
    raw_entries = _require_list_of_objects(top, "entries", _FIELD_INVALID)
    entries = tuple(parse_ledger_entry_v3(e) for e in raw_entries)
    stored_root = _require_str(top, "ledger_root_digest", _FIELD_INVALID)
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


# ---------------------------------------------------------------------------
# Helpers for parsing embedded sub-objects.
#
# Each helper validates its own closed field set and schema version, then
# delegates to the frozen contract constructor for digest self-validation.
# The frozen-contract errors are normalized to ``PolicyStoreError`` so the
# filesystem boundary never leaks contract-layer exception types.
# ---------------------------------------------------------------------------


def _parse_algorithm_profile(value: dict[str, Any]) -> AssumptionPolicyAlgorithmProfile:
    _require_closed_object(value, _ALGORITHM_PROFILE_FIELDS, _FIELD_INVALID)
    algorithm = _require_str(value, "algorithm", _FIELD_INVALID)
    verification_profile = _require_str(value, "verification_profile", _FIELD_INVALID)
    try:
        return AssumptionPolicyAlgorithmProfile(
            algorithm=algorithm,
            verification_profile=verification_profile,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def _parse_challenge_rule(value: dict[str, Any]) -> AssumptionChallengeClassificationRule:
    _require_closed_object(value, _CHALLENGE_RULE_FIELDS, _FIELD_INVALID)
    reason_code = _require_str(value, "reason_code", _FIELD_INVALID)
    materiality = _require_str(value, "materiality", _FIELD_INVALID)
    try:
        return AssumptionChallengeClassificationRule(
            reason_code=reason_code,
            materiality=materiality,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def _parse_grant(value: dict[str, Any]) -> AssumptionAuthorityGrant:
    _require_closed_object(value, _AUTHORITY_GRANT_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, AUTHORITY_GRANT_SCHEMA_VERSION)
    grant_id = _require_str(value, "grant_id", _FIELD_INVALID)
    action = _require_str(value, "action", _FIELD_INVALID)
    authority_id = _require_str(value, "authority_id", _FIELD_INVALID)
    scope_ids = tuple(_require_list_of_strings(value, "scope_ids", _FIELD_INVALID))
    assumption_mat = tuple(
        _require_list_of_strings(value, "assumption_materialities", _FIELD_INVALID)
    )
    challenge_mat = tuple(
        _require_list_of_strings(value, "challenge_materialities", _FIELD_INVALID)
    )
    effective_from = _require_int(value, "effective_from_sequence", _FIELD_INVALID)
    effective_until = _require_optional_nonnegative_int(
        value, "effective_until_sequence", _FIELD_INVALID
    )
    grant_digest = _require_str(value, "grant_digest", _FIELD_INVALID)
    try:
        return AssumptionAuthorityGrant(
            grant_id=grant_id,
            action=action,
            authority_id=authority_id,
            scope_ids=scope_ids,
            assumption_materialities=assumption_mat,
            challenge_materialities=challenge_mat,
            effective_from_sequence=effective_from,
            effective_until_sequence=effective_until,
            grant_digest=grant_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_separation_duty_rule(value: dict[str, Any]) -> AssumptionSeparationDutyRule:
    _require_closed_object(value, _SEPARATION_DUTY_RULE_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, SEPARATION_DUTY_RULE_SCHEMA_VERSION)
    rule_id = _require_str(value, "rule_id", _FIELD_INVALID)
    action = _require_str(value, "action", _FIELD_INVALID)
    conflicting_roles = tuple(_require_list_of_strings(value, "conflicting_roles", _FIELD_INVALID))
    scope_ids = tuple(_require_list_of_strings(value, "scope_ids", _FIELD_INVALID))
    materialities = tuple(
        _require_list_of_strings(value, "assumption_materialities", _FIELD_INVALID)
    )
    rule_digest = _require_str(value, "rule_digest", _FIELD_INVALID)
    try:
        return AssumptionSeparationDutyRule(
            rule_id=rule_id,
            action=action,
            conflicting_roles=conflicting_roles,
            scope_ids=scope_ids,
            assumption_materialities=materialities,
            rule_digest=rule_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_duty_exception(value: dict[str, Any]) -> AssumptionDutyException:
    _require_closed_object(value, _DUTY_EXCEPTION_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, DUTY_EXCEPTION_SCHEMA_VERSION)
    exception_id = _require_str(value, "exception_id", _FIELD_INVALID)
    rule_id = _require_str(value, "rule_id", _FIELD_INVALID)
    action = _require_str(value, "action", _FIELD_INVALID)
    authority_id = _require_str(value, "authority_id", _FIELD_INVALID)
    conflicting_roles = tuple(_require_list_of_strings(value, "conflicting_roles", _FIELD_INVALID))
    scope_ids = tuple(_require_list_of_strings(value, "scope_ids", _FIELD_INVALID))
    assumption_ids = tuple(_require_list_of_strings(value, "assumption_ids", _FIELD_INVALID))
    materialities = tuple(
        _require_list_of_strings(value, "assumption_materialities", _FIELD_INVALID)
    )
    reason_code = _require_str(value, "reason_code", _FIELD_INVALID)
    effective_from = _require_int(value, "effective_from_sequence", _FIELD_INVALID)
    effective_until = _require_int(value, "effective_until_sequence", _FIELD_INVALID)
    exception_digest = _require_str(value, "exception_digest", _FIELD_INVALID)
    try:
        return AssumptionDutyException(
            exception_id=exception_id,
            rule_id=rule_id,
            action=action,
            authority_id=authority_id,
            conflicting_roles=conflicting_roles,
            scope_ids=scope_ids,
            assumption_ids=assumption_ids,
            assumption_materialities=materialities,
            reason_code=reason_code,
            effective_from_sequence=effective_from,
            effective_until_sequence=effective_until,
            exception_digest=exception_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_authority_policy(value: dict[str, Any]) -> AssumptionAuthorityPolicy:
    """Parse an ``AssumptionAuthorityPolicy`` from its canonical JSON value."""

    _require_closed_object(value, _AUTHORITY_POLICY_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, AUTHORITY_POLICY_SCHEMA_VERSION)
    policy_id = _require_str(value, "policy_id", _FIELD_INVALID)
    authority_root_digest = _require_str(value, "authority_root_digest", _FIELD_INVALID)
    grants = tuple(
        _parse_grant(g) for g in _require_list_of_objects(value, "grants", _FIELD_INVALID)
    )
    rules = tuple(
        _parse_separation_duty_rule(r)
        for r in _require_list_of_objects(value, "separation_duty_rules", _FIELD_INVALID)
    )
    exceptions = tuple(
        _parse_duty_exception(e)
        for e in _require_list_of_objects(value, "duty_exceptions", _FIELD_INVALID)
    )
    grant_set_digest = _require_str(value, "grant_set_digest", _FIELD_INVALID)
    separation_duty_rule_set_digest = _require_str(
        value, "separation_duty_rule_set_digest", _FIELD_INVALID
    )
    exception_set_digest = _require_str(value, "exception_set_digest", _FIELD_INVALID)
    policy_digest = _require_str(value, "policy_digest", _FIELD_INVALID)
    try:
        return AssumptionAuthorityPolicy(
            policy_id=policy_id,
            authority_root_digest=authority_root_digest,
            grants=grants,
            separation_duty_rules=rules,
            duty_exceptions=exceptions,
            grant_set_digest=grant_set_digest,
            separation_duty_rule_set_digest=separation_duty_rule_set_digest,
            exception_set_digest=exception_set_digest,
            policy_digest=policy_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_approval_rule(value: dict[str, Any]) -> AssumptionPolicyApprovalRule:
    _require_closed_object(value, _APPROVAL_RULE_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, APPROVAL_RULE_SCHEMA_VERSION)
    approval_class = _require_str(value, "approval_class", _FIELD_INVALID)
    eligible = tuple(_require_list_of_strings(value, "eligible_signer_ids", _FIELD_INVALID))
    required_count = _require_int(value, "required_signature_count", _FIELD_INVALID)
    required = tuple(_require_list_of_strings(value, "required_signer_ids", _FIELD_INVALID))
    rule_digest = _require_str(value, "rule_digest", _FIELD_INVALID)
    try:
        return AssumptionPolicyApprovalRule(
            approval_class=approval_class,
            eligible_signer_ids=eligible,
            required_signature_count=required_count,
            required_signer_ids=required,
            rule_digest=rule_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_approval_policy(value: dict[str, Any]) -> AssumptionPolicyApprovalPolicy:
    _require_closed_object(value, _APPROVAL_POLICY_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, APPROVAL_POLICY_SCHEMA_VERSION)
    approval_policy_id = _require_str(value, "approval_policy_id", _FIELD_INVALID)
    authority_root_digest = _require_str(value, "authority_root_digest", _FIELD_INVALID)
    rules = tuple(
        _parse_approval_rule(r) for r in _require_list_of_objects(value, "rules", _FIELD_INVALID)
    )
    approval_policy_digest = _require_str(value, "approval_policy_digest", _FIELD_INVALID)
    try:
        return AssumptionPolicyApprovalPolicy(
            approval_policy_id=approval_policy_id,
            authority_root_digest=authority_root_digest,
            rules=rules,
            approval_policy_digest=approval_policy_digest,
        )
    except Exception as exc:
        code = getattr(exc, "code", None)
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", code) from exc


def _parse_signature_profile(value: dict[str, Any]) -> AssumptionPolicySignatureProfile:
    _require_closed_object(value, _SIGNATURE_PROFILE_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, SIGNATURE_PROFILE_SCHEMA_VERSION)
    signature_set_schema_version = _require_str(
        value, "signature_set_schema_version", _FIELD_INVALID
    )
    signature_record_semantics_version = _require_str(
        value, "signature_record_semantics_version", _FIELD_INVALID
    )
    profiles = tuple(
        _parse_algorithm_profile(p)
        for p in _require_list_of_objects(value, "algorithm_profiles", _FIELD_INVALID)
    )
    required_authority_scope = _require_str(value, "required_authority_scope", _FIELD_INVALID)
    key_authority_root_digest = _require_str(value, "key_authority_root_digest", _FIELD_INVALID)
    duplicate_signer_rule = _require_str(value, "duplicate_signer_rule", _FIELD_INVALID)
    profile_digest = _require_str(value, "profile_digest", _FIELD_INVALID)
    try:
        return AssumptionPolicySignatureProfile(
            signature_set_schema_version=signature_set_schema_version,
            signature_record_semantics_version=signature_record_semantics_version,
            algorithm_profiles=profiles,
            required_authority_scope=required_authority_scope,
            key_authority_root_digest=key_authority_root_digest,
            duplicate_signer_rule=duplicate_signer_rule,
            profile_digest=profile_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


def _parse_challenge_policy(value: dict[str, Any]) -> AssumptionChallengeClassificationPolicy:
    _require_closed_object(value, _CHALLENGE_POLICY_FIELDS, _FIELD_INVALID)
    _require_schema_version(value, CHALLENGE_CLASSIFICATION_POLICY_SCHEMA_VERSION)
    rules = tuple(
        _parse_challenge_rule(r)
        for r in _require_list_of_objects(value, "reason_rules", _FIELD_INVALID)
    )
    unknown_reason_behavior = _require_str(value, "unknown_reason_behavior", _FIELD_INVALID)
    policy_digest = _require_str(value, "policy_digest", _FIELD_INVALID)
    try:
        return AssumptionChallengeClassificationPolicy(
            reason_rules=rules,
            unknown_reason_behavior=unknown_reason_behavior,
            policy_digest=policy_digest,
        )
    except AssumptionPolicyActivationContractError as exc:
        raise PolicyStoreError("ASSUMPTION_POLICY_STORED_CONTRACT_INVALID", exc.code) from exc


# ===========================================================================
# Filesystem publisher
# ===========================================================================


class FilesystemAssumptionPolicyPublisher:
    """Interprocess-safe atomic filesystem publisher.

    Stores the authoritative ``AssumptionPolicyLedgerV3`` as a single canonical
    JSON file. Uses a *strict* composition of the ``_platform`` lock primitives
    (``open_lock_file_strict`` + ``lock_file``/``unlock_file``) for exclusive
    interprocess access -- not the ordinary ``_platform.advisory_lock`` used by
    the temporal, admission, and registry stores -- and ``os.replace`` for
    atomic file replacement. The strict opener rejects a symlink (or directory,
    or any other non-regular shape) at ``publication.lock`` before any lock is
    acquired.

    See the module docstring for the full claim boundary, lifecycle, and the
    atomic publication sequence.
    """

    def __init__(self, root: Path) -> None:
        """Record store paths only. Perform no initialization and no I/O.

        Use :meth:`create` to initialize an empty authoritative ledger or
        :meth:`open` to open an existing store. :meth:`read_state`,
        :meth:`read_ledger`, and :meth:`publish` reconstruct the ledger from
        bytes on every call, so they may be called after either lifecycle
        entry point (or directly, treating a missing ledger as a missing-store
        error).
        """

        if not isinstance(root, Path):
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_INVALID")
        self.root = root
        self.ledger_path = root / "ledger.json"
        self.lock_path = root / "publication.lock"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _validate_root(self) -> None:
        """Pre-lock validation that the root is usable.

        Runs before the publication lock is acquired so that a root that is a
        regular file (or otherwise unusable) surfaces the precise
        ``ROOT_NOT_DIRECTORY`` code rather than being masked as a lock
        acquisition failure (the lock helper would try to create the lock
        file's parent, which is the bad root). Does NOT require the root to
        exist: ``create()`` may create it.
        """

        if self.root.exists() and not self.root.is_dir():
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY")

    def _require_existing_root(self) -> None:
        """Require the root to exist and be a directory.

        Used by ``open()``, ``read_state()`` and ``read_ledger()`` so the read
        path never creates the root (only ``create()`` may). A missing root
        surfaces as ``ROOT_MISSING``; an existing non-directory surfaces as
        ``ROOT_NOT_DIRECTORY``.
        """

        if not self.root.exists():
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_MISSING")
        if not self.root.is_dir():
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY")

    def _ensure_root(self) -> None:
        """Create the store root directory if needed and sync it.

        Performed under the publication lock by ``create()`` only. The lock
        file is created by the strict lock opener (``open_lock_file_strict``)
        itself when it opens the lock path.
        """

        try:
            self.root.mkdir(parents=True, exist_ok=True)
            fsync_directory(self.root)
        except OSError as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ROOT_CREATE_FAILED") from exc

    def _cleanup_orphans(self) -> None:
        """Remove any managed temporary files left by a previous crash.

        Only regular files matching the *exact* managed pattern
        ``.policy-ledger.<32-lowercase-hex>.tmp`` are removed, so unrelated
        files in the store root are never touched. Directories and symlinks
        are never removed (and a symlink is never followed): anything matching
        the name pattern but not a regular file is left for the operator.

        Cleanup failures are NOT suppressed: a managed orphan that cannot be
        unlinked surfaces ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`` so the
        operator learns the store root is not in a clean state, and a directory
        fsync failure after at least one removal surfaces
        ``ASSUMPTION_POLICY_STORE_DURABILITY_FAILED``. Neither failure touches
        the authoritative ledger bytes, so the store state is unchanged on
        either failure and a subsequent read reconstructs the same ledger.

        Enumeration and inspection failures are normalized too: every
        filesystem operation involved in discovering and classifying a
        candidate (``iterdir``, ``lstat``/``is_symlink``/``is_dir``, and the
        managed ``unlink``) is wrapped so no raw ``OSError`` may escape. A
        failure to enumerate the store root or to inspect a candidate surfaces
        ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`` with the offending
        candidate name (or ``"<root>"`` for an enumeration failure) as the
        detail, so a caller can switch on the outcome without parsing the
        underlying backend message.
        """

        try:
            root_exists = self.root.exists()
            root_is_dir = self.root.is_dir() if root_exists else False
        except OSError as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED", "<root>") from exc
        if not root_exists or not root_is_dir:
            return
        removed_any = False
        try:
            candidates = list(self.root.iterdir())
        except OSError as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED", "<root>") from exc
        for candidate in candidates:
            name = candidate.name
            if not _TEMP_NAME_PATTERN.match(name):
                # Foreign file or non-matching name: leave untouched.
                continue
            # Never follow symlinks and never remove directories. A managed
            # temp is always a regular file; anything else matching the name
            # pattern is left untouched (and surfaces later as a publish
            # failure if it blocks the atomic replace). Each inspection call is
            # wrapped so a degraded filesystem cannot leak a raw OSError: an
            # inspection failure is a cleanup failure the operator must learn
            # about, and it is normalized to TEMP_CLEANUP_FAILED.
            try:
                is_symlink = candidate.is_symlink()
            except OSError as exc:
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED", name) from exc
            if is_symlink:
                continue
            try:
                is_dir = candidate.is_dir()
            except OSError as exc:
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED", name) from exc
            if is_dir:
                continue
            try:
                candidate.unlink()
            except OSError as exc:
                # A managed orphan that cannot be removed is a real store
                # condition the operator must learn about (the store root may
                # be read-only, or the filesystem may be degraded). The
                # authoritative ledger is untouched; raise the stable code so a
                # caller can switch on the outcome without parsing the message.
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED", name) from exc
            removed_any = True
        if removed_any:
            try:
                fsync_directory(self.root)
            except OSError as exc:
                # The removals landed but their directory entry deletions could
                # not be durably flushed. The authoritative ledger is
                # untouched; surface the durability boundary failure so the
                # operator can reconcile. (No-op on Windows, so this branch is
                # POSIX-only.)
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_DURABILITY_FAILED") from exc

    def create(self) -> None:
        """Initialize an empty authoritative ledger, exactly once.

        Performed under the publication lock. If a valid authoritative ledger
        already exists, raises ``ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED``
        rather than clobbering it. If a corrupt or partial ledger exists,
        surfaces the reconstruction error so the operator can decide rather
        than silently re-initializing.

        ``create()`` is the *only* lifecycle entry point that may create the
        store root directory. After writing the canonical empty ledger it
        rereads the authoritative bytes and verifies them exactly, so a
        post-replace failure here surfaces as
        ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN``.
        """

        self._validate_root()
        with self._locked():
            self._ensure_root()
            self._cleanup_orphans()
            if self.ledger_path.exists():
                # An authoritative file exists. If it reconstructs cleanly,
                # the store is already initialized and create() must refuse.
                # If it fails to reconstruct, surface that error.
                self._reconstruct()
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED")
            empty = AssumptionPolicyLedgerV3.build(())
            intended_bytes = empty.canonical_bytes
            temp = self._write_and_fsync_temp(intended_bytes)
            try:
                self._checkpoint(_CHECKPOINT_BEFORE_REPLACE)
                os.replace(temp, self.ledger_path)
            except Exception as exc:
                # Pre-commit failure normalization (mirrors _commit): the
                # canonical empty ledger did not land, the temp is owned by
                # this publisher, and the stable code is REPLACE_FAILED.
                self._cleanup_own_temp(temp)
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_REPLACE_FAILED") from exc
            # Commit point passed: the empty ledger may now be authoritative.
            # Any failure here is outcome-uncertain.
            try:
                self._checkpoint(_CHECKPOINT_AFTER_REPLACE)
                self._checkpoint(_CHECKPOINT_BEFORE_DIRECTORY_FSYNC)
                fsync_directory(self.root)
                stored_bytes = self._read_authoritative_after_commit()
                self._verify_create_post_write(intended_bytes, stored_bytes)
            except PolicyStoreError as exc:
                if exc.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN":
                    raise
                raise PolicyStoreError(
                    "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN", exc.code
                ) from exc
            except Exception as exc:
                raise PolicyStoreError("ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN") from exc

    def open(self) -> None:
        """Open an existing store. Never initializes.

        ``open()`` does not create the store root: a missing root raises
        ``ASSUMPTION_POLICY_STORE_ROOT_MISSING`` so a caller cannot accidentally
        create a fresh store through the read path. Only ``create()`` may
        create the root. Reconstructs the authoritative ledger under the
        publication lock to fail fast on corruption and to remove any orphan
        temp files. A missing authoritative ledger raises
        ``ASSUMPTION_POLICY_STORED_BYTES_MISSING``.
        """

        self._require_existing_root()
        with self._locked():
            self._cleanup_orphans()
            self._reconstruct()

    # ------------------------------------------------------------------
    # Locking context manager
    # ------------------------------------------------------------------

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Acquire the publication lock, normalizing acquisition failures.

        The lock file is opened with the *strict* opener
        (:func:`open_lock_file_strict`), which refuses a symlink (or directory,
        or any other non-regular shape) at ``publication.lock``: such a path
        can never be followed into an attacker-controlled file or directory.
        The strict opener raises three distinct ``OSError`` subclasses *during
        acquisition*, each normalized to a precise public code so a caller can
        switch on the exact recovery action:

        * :class:`LockInvalidError` -- the lock path is a symlink, a directory,
          or another non-regular shape, or it could not be opened at all.
          Normalized to ``ASSUMPTION_POLICY_STORE_LOCK_INVALID``.
        * :class:`LockInitializationError` -- a validated descriptor was
          acquired but the handle could not be created (``os.fdopen`` failed)
          or seeded (``write``/``flush``/``fsync`` failed). The lock path is a
          valid regular file but a usable lock could not be established, so it
          is normalized to ``ASSUMPTION_POLICY_STORE_LOCK_FAILED``.
        * any other ``OSError`` from the opener that is neither of the above is
          also normalized to ``ASSUMPTION_POLICY_STORE_LOCK_FAILED``.

        Once a valid regular lock file is open, acquiring the advisory lock
        itself may still fail (e.g. the kernel lock table is exhausted, or a
        lock held by a dead process cannot be reclaimed). That is normalized to
        ``ASSUMPTION_POLICY_STORE_LOCK_FAILED`` -- the lock path is valid, the
        acquisition simply could not complete.

        Any exception -- including an ``OSError`` -- raised by the protected
        operation inside the ``with`` body propagates unchanged: it must never
        be mislabeled as a lock failure, because the observable recovery action
        differs. The lock is released (best-effort) on exit even if the body
        raises.

        No backend exception message is carried into the public ``detail``:
        every acquisition-time normalization raises ``PolicyStoreError(code)``
        with ``detail=None`` so the observable behavior depends only on the
        acquisition stage, never on backend diagnostic text.

        This drives the lock primitives directly rather than using the
        ``advisory_lock_strict`` context manager, because that manager performs
        its open+lock during ``__enter__``: a caller cannot otherwise
        distinguish an acquisition-time ``OSError`` (lock invalid / lock
        failed) from a body-time ``OSError`` (operation failure). By performing
        the open+lock here, outside the body, the attribution is exact.
        """

        try:
            handle = open_lock_file_strict(self.lock_path)
        except LockInvalidError as exc:
            # Shape/open failure: the lock path is a symlink, a directory, or
            # otherwise not a usable regular file. The publication lock can
            # never be safely held against such a path. No backend message in
            # the detail (the chain is preserved via ``from exc`` for debugging,
            # but the public ``detail`` is None).
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_LOCK_INVALID") from exc
        except LockInitializationError as exc:
            # The lock path is a valid regular file, but a usable handle could
            # not be created or seeded. No backend message in the detail.
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_LOCK_FAILED") from exc
        except OSError as exc:
            # Any other opener-level OSError (not a LockInvalid /
            # LockInitialization subclass) is still an acquisition-time failure
            # against a lock path that is not usable as-is. No backend message
            # in the detail.
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_LOCK_FAILED") from exc
        try:
            try:
                lock_file(handle)
            except OSError as exc:
                # The lock path is a valid regular file, but the advisory lock
                # itself could not be acquired. No backend message in the
                # detail.
                raise PolicyStoreError("ASSUMPTION_POLICY_STORE_LOCK_FAILED") from exc
            yield
        finally:
            unlock_file(handle)
            handle.close()

    # ------------------------------------------------------------------
    # Fault injection
    # ------------------------------------------------------------------

    #: Class-level fault-injection hook. When set to a callable, it is invoked
    #: at each :meth:`_checkpoint` with the checkpoint name. A test installs a
    #: hook via :meth:`with_fault_injection` (context manager) so the hook is
    #: always cleared on exit. The hook is intentionally class-level so a fault
    #: injected from a child process is observable; production code never sets
    #: it.
    _fault_hook: Callable[[str], None] | None = None

    @classmethod
    def _checkpoint(cls, name: str) -> None:
        """Deterministic fault-injection checkpoint.

        Invoked at well-defined points in the publication sequence so tests
        can assert pre- and post-commit failure behavior without arbitrary
        monkey-patching of internal methods. A no-op in production (the hook
        is ``None``). The eight checkpoints, in commit order, are:

        ``BEFORE_TEMP_CREATE``, ``AFTER_PARTIAL_TEMP_WRITE``,
        ``AFTER_TEMP_FLUSH``, ``BEFORE_REPLACE`` (all pre-commit: old ledger
        intact), then ``AFTER_REPLACE``, ``BEFORE_DIRECTORY_FSYNC``,
        ``BEFORE_POST_WRITE_READ``, ``DURING_POST_WRITE_READ`` (all
        post-commit: outcome uncertain).
        """

        hook = cls._fault_hook
        if hook is not None:
            hook(name)

    class _FaultInjectionCtx:
        """Context manager installing a fault-injection hook for its scope."""

        def __init__(self, hook: Callable[[str], None]) -> None:
            self._hook = hook
            self._prev: Callable[[str], None] | None = None

        def __enter__(self) -> FilesystemAssumptionPolicyPublisher._FaultInjectionCtx:
            self._prev = FilesystemAssumptionPolicyPublisher._fault_hook
            FilesystemAssumptionPolicyPublisher._fault_hook = self._hook
            return self

        def __exit__(self, *exc: object) -> None:
            FilesystemAssumptionPolicyPublisher._fault_hook = self._prev

    @classmethod
    def with_fault_injection(
        cls, hook: Callable[[str], None]
    ) -> FilesystemAssumptionPolicyPublisher._FaultInjectionCtx:
        """Install ``hook`` as the fault-injection callback for a ``with`` block."""

        return cls._FaultInjectionCtx(hook)

    # ------------------------------------------------------------------
    # Atomic file I/O
    # ------------------------------------------------------------------

    def _read_ledger_bytes(self) -> bytes:
        if not self.ledger_path.exists():
            raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_MISSING")
        try:
            return self.ledger_path.read_bytes()
        except OSError as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORED_BYTES_INVALID") from exc

    def _read_authoritative_after_commit(self) -> bytes:
        """Reread the authoritative bytes after the commit point.

        This is the post-commit half of the publication sequence. It splits the
        read into two independently injectable checkpoints so a test can prove
        the OUTCOME_UNCERTAIN classification regardless of whether the failure
        occurs *before* the read (e.g. a fault-hook exception, or the
        authoritative file being made unreadable between the replace and the
        read) or *during* the read itself (e.g. an injected OSError from
        ``read_bytes``, or bytes that vanish mid-read).

        Any failure here is post-commit: ``os.replace`` already landed, so the
        publication may be authoritative. Every failure -- fault-hook
        exception, OSError from ``read_bytes``, or a vanished file -- is
        normalized to ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`` and
        no rollback is attempted.
        """

        self._checkpoint(_CHECKPOINT_BEFORE_POST_WRITE_READ)
        try:
            self._checkpoint(_CHECKPOINT_DURING_POST_WRITE_READ)
            return self.ledger_path.read_bytes()
        except Exception as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN") from exc

    def _new_temp_path(self) -> Path:
        """Return a fresh managed temp path (not yet created)."""

        return self.root / f"{_TEMP_PREFIX}{uuid.uuid4().hex}{_TEMP_SUFFIX}"

    def _cleanup_own_temp(self, temp: Path) -> None:
        """Unlink a temp file this publisher created, surfacing cleanup failure.

        Used on the pre-replace failure path only: if ``os.replace`` failed,
        the temp file is still owned by this publisher and the old
        authoritative ledger is intact, so removing the temp is always safe --
        and a failure to remove it is a real store condition the operator must
        learn about. Cleanup is therefore NOT best-effort: an ``OSError`` from
        the unlink surfaces ``ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED``.

        Because this is called from inside the pre-replace ``except`` handlers
        of ``_write_and_fsync_temp``, ``create``, and ``_commit``, a cleanup
        failure propagates in place of the original write/replace error: the
        caller observes ``TEMP_CLEANUP_FAILED`` rather than
        ``WRITE_FAILED`` / ``REPLACE_FAILED``. That is intentional -- a temp
        the publisher could not remove is a strictly more actionable signal
        than the write/replace error that preceded it (the operator must
        reconcile the orphan regardless), and the old authoritative ledger is
        byte-for-byte intact in every case.
        """

        try:
            temp.unlink(missing_ok=True)
        except OSError as exc:
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED") from exc

    def _write_and_fsync_temp(self, payload: bytes) -> Path:
        """Write ``payload`` to a managed temp file and fsync it; return path.

        This is the pre-commit half of the atomic write. It performs no
        ``os.replace``: the caller owns the commit decision. The temp file is
        named ``.policy-ledger.<32-hex>.tmp`` in the store root (same
        filesystem as the destination, so the subsequent ``os.replace`` is
        atomic). The payload write is split so the
        ``AFTER_PARTIAL_TEMP_WRITE`` checkpoint fires after a partial payload
        has been written (and ``AFTER_TEMP_FLUSH`` after the full fsync). Any
        failure here is a pre-commit failure: the old authoritative ledger is
        intact and ``PUBLICATION_WRITE_FAILED`` is raised.
        """

        temp = self._new_temp_path()
        try:
            self._checkpoint(_CHECKPOINT_BEFORE_TEMP_CREATE)
            # ``os.replace`` refuses to overwrite a directory or follow a
            # symlink at the destination, but we additionally refuse to create
            # our temp on top of an existing directory/symlink shape so the
            # pre-commit error is precise.
            if temp.exists() and (temp.is_dir() or temp.is_symlink()):
                raise PolicyStoreError("ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED")
            with open(temp, "wb") as handle:
                # Split the write so AFTER_PARTIAL_TEMP_WRITE fires after a
                # real partial payload is on disk (the first byte plus half of
                # the remainder), proving that a crash between the partial
                # write and the flush leaves only a partial temp -- which is
                # never visible as the authoritative ledger and is cleaned up
                # by the next open()'s orphan sweep.
                midpoint = max(1, len(payload) // 2)
                handle.write(payload[:midpoint])
                handle.flush()
                self._checkpoint(_CHECKPOINT_AFTER_PARTIAL_TEMP_WRITE)
                handle.write(payload[midpoint:])
                handle.flush()
                os.fsync(handle.fileno())
            self._checkpoint(_CHECKPOINT_AFTER_TEMP_FLUSH)
        except Exception as exc:
            # Any pre-replace failure -- an OSError from the underlying file
            # APIs, a fault-hook RuntimeError injected at one of the pre-replace
            # checkpoints, or the explicit WRITE_FAILED raised when the temp
            # path shape is a directory/symlink -- is normalized to the single
            # stable pre-commit code. The old authoritative ledger is intact in
            # every case (no os.replace has run), so the temp is cleaned up and
            # the caller can switch on the code without parsing the exception.
            self._cleanup_own_temp(temp)
            raise PolicyStoreError("ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED") from exc
        return temp

    def _reconstruct(self) -> AssumptionPolicyLedgerV3:
        payload = self._read_ledger_bytes()
        return parse_ledger_v3(payload)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def read_state(self) -> ExpectedPolicyLedgerStateV3:
        self._require_existing_root()
        with self._locked():
            return ExpectedPolicyLedgerStateV3.from_ledger(self._reconstruct())

    def read_ledger(self) -> AssumptionPolicyLedgerV3:
        self._require_existing_root()
        with self._locked():
            return self._reconstruct()

    # ------------------------------------------------------------------
    # Publish API
    # ------------------------------------------------------------------

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
        # publish() must NEVER create the store root, the publication lock, or
        # the authoritative ledger. Only create() may bring a store into
        # existence: a publish against a missing root is a missing-store error,
        # not an implicit initialization. ``_require_existing_root`` raises
        # ROOT_MISSING (root absent) or ROOT_NOT_DIRECTORY (root exists but is
        # not a usable directory) and performs no I/O of its own.
        self._require_existing_root()
        with self._locked():
            self._cleanup_orphans()
            ledger = self._reconstruct()
            updated, result = compare_and_append_policy_entry_v3(
                ledger=ledger,
                expected_state=expected_state,
                candidate=entry,
            )
            if result.append_result == "COMMITTED":
                self._commit(old_ledger=ledger, updated=updated, result=result)
            return result

    def _commit(
        self,
        *,
        old_ledger: AssumptionPolicyLedgerV3,
        updated: AssumptionPolicyLedgerV3,
        result: AssumptionPolicyActivationResult,
    ) -> None:
        """Write ``updated`` atomically and verify the write landed.

        The real commit point is ``os.replace``: before it, the old
        authoritative ledger is intact and any failure raises a normal
        pre-commit error (``PUBLICATION_WRITE_FAILED`` or
        ``STORE_REPLACE_FAILED``) and cleans up the temp. After it, the new
        ledger may be authoritative, so any failure (directory fsync,
        reread, verification mismatch, or a fault-hook exception) is
        normalized to ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`` and
        no rollback is attempted -- a rollback could destroy a successful
        publication.

        Post-write verification is bound to the oracle's
        ``AssumptionPolicyActivationResult``: the stored bytes, reconstructed
        ledger, root, head digest, predecessor root, and commit-receipt
        binding must all agree with the oracle's ``updated`` ledger and
        ``result``.
        """

        intended_bytes = updated.canonical_bytes
        # --- pre-replace: old authoritative ledger intact on any failure ---
        temp = self._write_and_fsync_temp(intended_bytes)
        try:
            self._checkpoint(_CHECKPOINT_BEFORE_REPLACE)
            os.replace(temp, self.ledger_path)
        except Exception as exc:
            # The os.replace itself, or a fault-hook exception raised at the
            # BEFORE_REPLACE checkpoint, is normalized to the single stable
            # pre-commit REPLACE_FAILED code. The temp is still owned by this
            # publisher (the replace did not land) so it is removed, and the
            # old authoritative ledger is byte-for-byte intact.
            self._cleanup_own_temp(temp)
            raise PolicyStoreError("ASSUMPTION_POLICY_STORE_REPLACE_FAILED") from exc
        # --- commit point crossed: os.replace returned ---
        # Everything from here on runs after os.replace: the publication may
        # have landed, so any failure (including a fault-hook exception or a
        # verification mismatch) is normalized to OUTCOME_UNCERTAIN. No
        # rollback is attempted: a rollback could destroy a successful
        # publication, and the caller must reconcile the uncertain outcome.
        try:
            self._checkpoint(_CHECKPOINT_AFTER_REPLACE)
            self._checkpoint(_CHECKPOINT_BEFORE_DIRECTORY_FSYNC)
            fsync_directory(self.root)
            stored_bytes = self._read_authoritative_after_commit()
            verified = parse_ledger_v3(stored_bytes)
            self._verify_post_write(
                old_ledger=old_ledger,
                updated=updated,
                intended_bytes=intended_bytes,
                verified=verified,
                result=result,
            )
        except PolicyStoreError as exc:
            # A verification failure that already carries the uncertain code
            # is re-raised unchanged; any other PolicyStoreError (e.g. a
            # reconstruction failure) is re-classified as uncertain.
            if exc.code == "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN":
                raise
            raise PolicyStoreError(
                "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN", exc.code
            ) from exc
        except Exception as exc:
            # A fault-hook RuntimeError or any other post-commit surprise. The
            # detail is the exception's stable code if it has one, else None:
            # never ``repr(exc)`` (which would leak backend diagnostics).
            detail = getattr(exc, "code", None)
            raise PolicyStoreError(
                "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN", detail
            ) from exc

    @staticmethod
    def _verify_post_write(
        *,
        old_ledger: AssumptionPolicyLedgerV3,
        updated: AssumptionPolicyLedgerV3,
        intended_bytes: bytes,
        verified: AssumptionPolicyLedgerV3,
        result: AssumptionPolicyActivationResult,
    ) -> None:
        """Strengthened post-write verification bound to the oracle result.

        Verifies ALL of:

        * the stored bytes equal ``updated.canonical_bytes``;
        * the reconstructed canonical bytes equal ``updated.canonical_bytes``;
        * the reconstructed entries equal ``updated.entries``;
        * the reconstructed root equals ``updated.ledger_root_digest`` and
          equals ``result.resulting_ledger_root``;
        * the reconstructed head digest equals ``result.ledger_entry_digest``;
        * ``result.predecessor_ledger_root`` equals
          ``old_ledger.ledger_root_digest``;
        * ``result.policy_commit_receipt_digest`` equals the updated head's
          commit receipt digest.

        Every check raises ``ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN``
        so that any divergence after ``os.replace`` surfaces as the uncertain
        outcome rather than a successful return. No check inspects exception
        text.
        """

        _uncertain = "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        _failed = "STORED_VERIFICATION_FAILED"
        if verified.canonical_bytes != intended_bytes:
            raise PolicyStoreError(_uncertain, _failed)
        if verified.canonical_bytes != updated.canonical_bytes:
            raise PolicyStoreError(_uncertain, _failed)
        if tuple(verified.entries) != tuple(updated.entries):
            raise PolicyStoreError(_uncertain, _failed)
        # Root binding: reconstructed == updated == oracle resulting root.
        if verified.ledger_root_digest != updated.ledger_root_digest:
            raise PolicyStoreError(_uncertain, _failed)
        if verified.ledger_root_digest != result.resulting_ledger_root:
            raise PolicyStoreError(_uncertain, _failed)
        if updated.ledger_root_digest != result.resulting_ledger_root:
            raise PolicyStoreError(_uncertain, _failed)
        # Head digest binding: reconstructed head == updated head == oracle
        # activation result's ledger_entry_digest.
        if updated.entries:
            head = updated.entries[-1]
            verified_head = verified.entries[-1]
            if verified_head.ledger_entry_digest != head.ledger_entry_digest:
                raise PolicyStoreError(_uncertain, _failed)
            if head.ledger_entry_digest != result.ledger_entry_digest:
                raise PolicyStoreError(_uncertain, _failed)
            # Predecessor root + commit receipt binding to the oracle result.
            if result.predecessor_ledger_root != old_ledger.ledger_root_digest:
                raise PolicyStoreError(_uncertain, _failed)
            if result.policy_commit_receipt_digest != head.policy_commit.commit_receipt_digest:
                raise PolicyStoreError(_uncertain, _failed)
            if (
                head.signing_payload.predecessor_commit_receipt_digest
                != verified_head.signing_payload.predecessor_commit_receipt_digest
            ):
                raise PolicyStoreError(_uncertain, _failed)
        else:
            # Empty ledger: the result must claim the empty ledger's root as
            # both predecessor and resulting root, and no head digest.
            if result.ledger_entry_digest != "":
                # An empty updated ledger has no head; the result must not
                # claim one. (The contract never produces an empty-ledger
                # COMMITTED result, so this is a defense-in-depth guard.)
                raise PolicyStoreError(_uncertain, _failed)

    @staticmethod
    def _verify_create_post_write(intended_bytes: bytes, stored_bytes: bytes) -> None:
        """Post-write verification for the canonical empty ledger written by
        ``create()``.

        The empty ledger is self-validating through ``parse_ledger_v3``, so
        the additional binding here is that the reread authoritative bytes are
        byte-for-byte the canonical empty ledger the publisher intended.
        """

        _uncertain = "ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN"
        _failed = "STORED_VERIFICATION_FAILED"
        if stored_bytes != intended_bytes:
            raise PolicyStoreError(_uncertain, _failed)
