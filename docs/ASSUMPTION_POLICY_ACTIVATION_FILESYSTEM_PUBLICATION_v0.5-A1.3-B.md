# Assumption Policy Activation Filesystem Publication v0.5-A1.3-B

**Status:** Implemented durable interprocess filesystem publication
**Date:** 2026-08-04
**Scope:** `FilesystemAssumptionPolicyPublisher` — durable, interprocess-safe,
atomic publication of the authoritative `AssumptionPolicyLedgerV3`

This module owns the filesystem half of A1 activation. The pure A1.3-A
function `compare_and_append_policy_entry_v3` remains the semantic oracle.
The filesystem layer owns: locking, stored-byte validation, atomic
replacement, restart reconstruction, post-write verification, and
platform-specific durability boundaries.

## 1. Authoritative ledger.json

The authoritative ledger is a single canonical JSON file at `root/ledger.json`.
Its bytes are exactly `AssumptionPolicyLedgerV3.canonical_bytes`: sorted keys,
`,`/`:` separators, UTF-8, trailing newline. Every read reconstructs and fully
revalidates the ledger from bytes (no in-memory cache), so an unmodified store
can be reopened from any process at any time.

## 2. publication.lock

Exclusive interprocess access is provided by a *strict* composition of the
`_platform` lock primitives on `root/publication.lock`. The publisher does NOT
use the ordinary `_platform.advisory_lock` used by the temporal, admission, and
registry stores — those remain permissive and are intentionally untouched.

The strict opener (`_platform.open_lock_file_strict`) opens the lock file and
guarantees it is a regular file before a handle is returned:

* **POSIX:** `os.open` with `O_RDWR | O_CREAT | O_APPEND | O_NOFOLLOW`.
  `O_NOFOLLOW` causes the kernel to reject a symlink at `publication.lock`
  with `ELOOP` before any file is opened or followed; `fstat` on the descriptor
  then confirms a regular file.
* **Windows:** there is no `O_NOFOLLOW` equivalent. The opener performs
  cooperative acquisition-time validation:

  1. `lstat` the path;
  2. reject an observed symlink or non-regular shape;
  3. atomically create a missing regular file or open an existing path
     without truncation; subsequent path-shape and identity checks must
     succeed before the descriptor is seeded or locked;
  4. `fstat` the opened descriptor and require a regular file. A symlink to
     a regular file may also produce a regular descriptor; the second `lstat`
     and descriptor/path identity comparison detect the observed symlink or
     replacement before seeding and locking;
  5. `lstat` the path again;
  6. require the descriptor and path to identify the same regular file;
  7. seed only after all checks succeed.

  The opener does not seed or lock through a symlink or replacement
  detected during acquisition. A noncooperating actor changing the
  directory entry after validation is outside the cooperative
  single-host claim.

POSIX uses `fcntl.flock`; Windows uses `msvcrt.locking` on byte 0. Both
provide process-wide exclusive advisory locking on the lock file, which is
sufficient for single-writer publication.

### Cooperative claim boundary

The strict opener's acquisition-time validation defends against cooperating
store operators: another publisher in the same single-host claim that attempts
to point `publication.lock` at a symlink, a directory, or a non-regular shape is
refused before any lock is acquired. A *noncooperating* actor replacing
directory entries after the opener's validation window closes is outside the
cooperative single-host claim, as is any cross-host or privilege-boundary
adversary. The claim is therefore precisely: among cooperating publishers on a
single host, the lock path is always a regular file when a handle is returned.

### Lock-path invariant

`publication.lock` must always be a regular file. A symlink (or directory, or
any other non-regular shape) at the lock path is rejected before any lock is
acquired — the publication lock can never be held against an attacker-controlled
file or followed into corruption. Every such shape/open failure is normalized
to `ASSUMPTION_POLICY_STORE_LOCK_INVALID`. A descriptor that validated but whose
handle could not be created or seeded (`os.fdopen` failed, or the seed
`write`/`flush`/`fsync` failed) is normalized to
`ASSUMPTION_POLICY_STORE_LOCK_FAILED` — the lock path is a valid regular file,
but a usable lock could not be established; the descriptor is closed in every
case (no leak). `ASSUMPTION_POLICY_STORE_LOCK_FAILED` is also reserved for the
case where the lock path is a valid regular file but the advisory lock itself
could not be acquired. An `OSError` raised by the protected operation inside
the lock scope is never mislabeled as either lock code. No backend exception
message is carried into the public `detail`.

The full lock scope covers the entire compare-and-append transition: actual
state read, oracle invocation, temp write, atomic replace, directory fsync,
post-write reread, and verification. Readers (`read_state`, `read_ledger`,
`open`) also hold the lock.

## 3. Managed temp naming

Every temp file the publisher writes is named
`.policy-ledger.<32-lowercase-hex>.tmp` in the store root (the same filesystem
as the destination, so the subsequent `os.replace` is atomic). The middle
segment is exactly `uuid.uuid4().hex` (32 lowercase hex characters). Orphan
cleanup matches the whole name against this exact compiled pattern, so an
unrelated file can never be mistaken for a managed temp.

## 4. create / open lifecycle

The constructor performs no initialization: it records paths only. Two
explicit lifecycle entry points perform all managed, side-effecting work:

* `create()` — initialize an empty authoritative ledger, exactly once, under
  the publication lock. `create()` is the *only* entry point that may create
  the store root directory. A subsequent `create()` against an existing valid
  ledger raises `ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED`. A `create()`
  against a corrupt or partial ledger surfaces the reconstruction error rather
  than silently re-initializing. After writing the canonical empty ledger it
  rereads the authoritative bytes and verifies them exactly, so a post-replace
  failure surfaces as `ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`.
* `open()` — open an existing store. Never initializes, and never creates the
  root: a missing root raises `ASSUMPTION_POLICY_STORE_ROOT_MISSING`. A missing
  authoritative ledger raises `ASSUMPTION_POLICY_STORED_BYTES_MISSING`.

`read_state()` and `read_ledger()` likewise require the root to pre-exist and
never create it.

## 5. Full lock scope

All steps of a publication run under a single lock acquisition:

```text
 1. acquire exclusive publication lock (strict opener)
 2. ensure root (create() only) + orphan cleanup
 3. read authoritative stored ledger bytes
 4. reconstruct and fully validate ledger/3 (every nested contract revalidated)
 5. run V3 exact idempotence (the A1.3-A oracle)
 6. compare expected state + predecessor/sequence validation
 7. construct updated ledger/3 canonical bytes
 8. checkpoint BEFORE_TEMP_CREATE        ← fault injection point
 9. write managed temp  (.policy-ledger.<32-hex>.tmp)
10. checkpoint AFTER_PARTIAL_TEMP_WRITE   ← fault injection point
11. checkpoint AFTER_TEMP_FLUSH           ← fault injection point
12. checkpoint BEFORE_REPLACE             ← fault injection point (pre-commit)
13. os.replace                            ← commit point
14. checkpoint AFTER_REPLACE              ← fault injection point (post-commit)
15. checkpoint BEFORE_DIRECTORY_FSYNC     ← fault injection point
16. fsync store directory (POSIX)
17. checkpoint BEFORE_POST_WRITE_READ     ← fault injection point
18. reread authoritative bytes
19. checkpoint DURING_POST_WRITE_READ     ← fault injection point
20. reconstruct + verify every binding
21. return the activation result
22. release lock
```

## 6. os.replace commit point

The real commit point is `os.replace(temp, ledger.json)`. The write sequence is
split around it:

```python
temp = self._write_and_fsync_temp(payload)  # pre-replace
try:
    os.replace(temp, self.ledger_path)  # commit point
except OSError as exc:
    self._cleanup_own_temp(temp)
    raise PolicyStoreError("ASSUMPTION_POLICY_STORE_REPLACE_FAILED") from exc
# commit point crossed — new ledger may be authoritative
try:
    fsync_directory(self.root)
    stored_bytes = self._read_ledger_bytes()
    verified = parse_ledger_v3(stored_bytes)
    self._verify_post_write(...)  # post-replace
except Exception:
    raise PolicyStoreError("ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN") from exc
```

Before `os.replace`: the old authoritative ledger is intact, the temp is
removed, and a normal pre-commit error is raised. After `os.replace`: the new
ledger may be authoritative, so any failure is normalized to
`ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN` and no rollback is attempted
(a rollback could destroy a successful publication).

## 7. Pre-commit errors

Pre-replace failures surface as one of:

* `ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED` — temp creation, partial write,
  full write, or fsync of the temp file failed. Old ledger intact; temp
  removed.
* `ASSUMPTION_POLICY_STORE_REPLACE_FAILED` — `os.replace` itself failed. Old
  ledger intact; temp removed.
* `ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED` — the owned-temp cleanup that
  follows a write/replace failure itself failed (the temp could not be
  unlinked). This code dominates the original write/replace error because an
  un-removable orphan is the more actionable signal; the old ledger is intact.

In every pre-commit case the caller receives no activation result, the old
authoritative ledger is byte-for-byte intact, and retrying the publication is
safe.

### Normalized fault table

Every filesystem, locking, enumeration, and parser failure is normalized to a
stable public code so callers can switch on outcomes without parsing messages.
No error code carries `str(exc)` or `repr(exc)` of an underlying backend
exception as its detail.

| Condition | Public code | Stage |
|---|---|---|
| constructor root not a `Path` | `ASSUMPTION_POLICY_STORE_ROOT_INVALID` | construction |
| `open()`/read against a missing root | `ASSUMPTION_POLICY_STORE_ROOT_MISSING` | pre-lock |
| root exists but is not a directory | `ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY` | pre-lock |
| root/parent create or sync failed | `ASSUMPTION_POLICY_STORE_ROOT_CREATE_FAILED` | create() |
| lock path is a symlink / directory / non-regular | `ASSUMPTION_POLICY_STORE_LOCK_INVALID` | lock acquisition |
| validated descriptor but handle init/seed failed (fdopen/seed write/flush/fsync) | `ASSUMPTION_POLICY_STORE_LOCK_FAILED` | lock acquisition |
| other opener-level `OSError` during acquisition | `ASSUMPTION_POLICY_STORE_LOCK_FAILED` | lock acquisition |
| lock path valid but advisory lock not acquired | `ASSUMPTION_POLICY_STORE_LOCK_FAILED` | lock acquisition |
| `create()` against an existing valid ledger | `ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED` | create() |
| authoritative ledger file missing | `ASSUMPTION_POLICY_STORED_BYTES_MISSING` | read |
| stored bytes not valid UTF-8 JSON / not an object | `ASSUMPTION_POLICY_STORED_BYTES_INVALID` | read |
| stored bytes valid JSON but not canonical | `ASSUMPTION_POLICY_STORED_BYTES_NONCANONICAL` | read |
| duplicate JSON key at any depth | `ASSUMPTION_POLICY_STORED_DUPLICATE_KEY` | read |
| unsupported `schema_version` | `ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED` | read |
| missing/extra/wrong-type field | `ASSUMPTION_POLICY_STORED_FIELD_INVALID` | read |
| frozen-contract self-validation failed | `ASSUMPTION_POLICY_STORED_CONTRACT_INVALID` | read |
| stored root digest != rebuilt root | `ASSUMPTION_POLICY_STORED_ROOT_MISMATCH` | read |
| post-write verification mismatch | `ASSUMPTION_POLICY_STORED_VERIFICATION_FAILED` | post-commit (→ uncertain) |
| temp write/fsync failure (pre-replace) | `ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED` | pre-commit |
| `os.replace` failure (pre-replace) | `ASSUMPTION_POLICY_STORE_REPLACE_FAILED` | pre-commit |
| owned-temp cleanup failure (pre-replace path) | `ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED` | pre-commit |
| orphan enumeration / inspection / unlink failure | `ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED` | orphan sweep |
| directory fsync after orphan removal (POSIX) | `ASSUMPTION_POLICY_STORE_DURABILITY_FAILED` | orphan sweep |
| any failure after `os.replace` | `ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN` | post-commit |

## 8. Post-commit uncertain outcomes

Post-replace failures (directory fsync, reread, reconstruction, verification
mismatch, or a fault-hook exception) are all normalized to
`ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN`. The publisher never attempts
a rollback. The caller must reconcile: reopen the store, reconstruct the
authoritative ledger, and retry the publication.

## 9. Exact retry reconciliation

A caller that received `OUTCOME_UNCERTAIN` reopens the store and reads the
current state:

* if the publication landed, the new head is visible and an exact retry yields
  `IDEMPOTENT_APPEND`;
* if the publication did not land, the old head is visible and the retry
  commits cleanly.

Either way, the store never holds a partial ledger: the only transitions are
"old complete ledger" and "new complete ledger", separated by the atomic
`os.replace`.

## 10. Restart reconstruction

Every published ledger is re-parsed and fully revalidated on read. Each nested
contract (signing payload, commit/3, activation proof/2, authority policy,
grants, separation-duty rules, duty exceptions, approval policy/rules,
signature profile, algorithm profiles, challenge policy/rules) is re-parsed
through its hardened parser, which enforces exact object type, exact closed
field set, exact schema version, and exact scalar/list types before handing
the value to the frozen contract constructor for digest self-validation. The
stored ledger root must match the rebuilt root, and the stored bytes must be
canonical.

## 11. Closed parsers

Every value entering the typed contract layer from stored bytes passes through
the hardened parser boundary, which enforces in order:

```text
0. no duplicate keys at any depth (object_pairs_hook)
1. the value is exactly a JSON object (dict)
2. the object's field set is exactly the closed schema's field set
3. the object's schema_version is exactly the supported version
4. each scalar field is the exact Python type the contract expects
5. each list field is a list of the exact expected element type
```

Only after a value passes all six gates is it handed to the frozen contract
constructor, which performs digest self-validation. Contract-layer exception
types are normalized to `PolicyStoreError` so the filesystem boundary never
leaks contract-layer exception types.

## 12. Duplicate-key handling

A stored JSON object carrying a duplicate key at any depth (two
`schema_version` fields, a duplicate `ledger_root_digest`, a duplicate digest
inside a nested grant, etc.) is rejected at the `json.loads` boundary via
`object_pairs_hook=_reject_duplicate_pairs` with the stable code
`ASSUMPTION_POLICY_STORED_DUPLICATE_KEY`. The duplicate key name is reported
as the error detail; no backend exception text is exposed.

## 13. Orphan cleanup

At `open()` (and at the start of every publish), the publisher removes any
managed temp files left by a previous crash. Only files matching the exact
pattern `.policy-ledger.<32-lowercase-hex>.tmp` are removed. Directories and
symlinks are never removed, and symlinks are never followed: a directory (even
one matching the name pattern) is skipped, and a symlink is left untouched. On
POSIX the store directory is fsynced after a successful deletion so the orphan
removal is durable.

### Normalized enumeration failures

Orphan enumeration and every candidate inspection are normalized: no raw
`OSError` from `iterdir()`, `is_symlink()`, `is_dir()`, or the managed
`unlink()` may escape `_cleanup_orphans`. A failure to enumerate the store
root surfaces `ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED` with detail
`"<root>"`; a failure to inspect or unlink a candidate surfaces the same code
with the offending candidate name as the detail. The authoritative ledger
bytes and the read state are unchanged in every case.

### Owned-temp cleanup behavior (pre-replace failure path)

`_cleanup_own_temp()` is NOT best-effort. On the pre-replace failure path (a
write or `os.replace` failure that leaves a temp file owned by this
publisher), a failure to unlink the temp surfaces
`ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED`. Because `_cleanup_own_temp` runs
inside the pre-replace `except` handlers of `_write_and_fsync_temp`, `create`,
and `_commit`, a cleanup failure propagates in place of the original
write/replace error: the caller observes `TEMP_CLEANUP_FAILED` rather than
`WRITE_FAILED` / `REPLACE_FAILED`. This is intentional — a temp the publisher
could not remove is a strictly more actionable signal than the write/replace
error that preceded it (the operator must reconcile the orphan regardless), and
the old authoritative ledger is byte-for-byte intact in every case.

## 14. Multiprocessing evidence

Real multiprocessing races (spawn context, barriers, queues) prove the claim.
Each spawn worker classifies its outcome into exactly one of four buckets so
the parent can assert the loser's *exception type* precisely, not just its
code:

* `("OK", worker_id, append_result, …)` — `publish()` returned a result;
* `("PUBLICATION_CONFLICT", worker_id, exc.code)` —
  `AssumptionPolicyPublicationConflict` (the expected "loser" outcome);
* `("STORE_ERROR", worker_id, exc.code)` — `PolicyStoreError` (a store-level
  failure that must never occur in a healthy race);
* `("UNEXPECTED", worker_id, type(exc).__name__)` — any other exception type
  (never silently swallowed by a broad conflict/store catch).

* **distinct genesis candidates:** exactly one `OK`/`COMMITTED` and exactly one
  `PUBLICATION_CONFLICT` with code `ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH`,
  with zero `STORE_ERROR` and zero `UNEXPECTED`. After both processes exit
  (exit code 0): one entry, head = winner digest, root = winner root, loser
  absent. A third publisher reopens and reconstructs the same root.
* **exact retry:** exactly two `OK` outcomes (one `COMMITTED`, one
  `IDEMPOTENT_APPEND`), one entry, the same digest and root, reopened root
  matches, with zero failures of every kind (no `PUBLICATION_CONFLICT`, no
  `STORE_ERROR`, no `UNEXPECTED`).
* **concurrent create:** exactly one `CREATED` and one
  `ALREADY_INITIALIZED`; the authoritative ledger is exactly one canonical
  empty ledger.
* **delayed lifecycle race:** process A creates + commits; process B does a
  delayed `create()` (refused with `ALREADY_INITIALIZED`, committed entry
  remains) or `open()` (reconstructs the populated ledger, never resets to
  empty).

No sleeps are used as synchronization.

## 15. Fault-injection evidence

Eight deterministic checkpoints, split at `os.replace`, prove the pre/post
failure behavior without arbitrary monkey-patching. Every checkpoint is
normalized to a stable public code — never the raw exception type or message:

```text
pre-replace (old ledger byte-for-byte intact, fault is normalized, temp removed):
  BEFORE_TEMP_CREATE         → ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED
  AFTER_PARTIAL_TEMP_WRITE   → ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED
  AFTER_TEMP_FLUSH           → ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED
  BEFORE_REPLACE             → ASSUMPTION_POLICY_STORE_REPLACE_FAILED
--- os.replace commit point ---
post-replace (outcome uncertain, publication may have landed):
  AFTER_REPLACE              → ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
  BEFORE_DIRECTORY_FSYNC     → ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
  BEFORE_POST_WRITE_READ     → ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
  DURING_POST_WRITE_READ     → ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
```

If the owned-temp cleanup that follows a pre-replace fault itself fails, the
public code is `ASSUMPTION_POLICY_STORE_TEMP_CLEANUP_FAILED` (the cleanup
failure dominates the original write/replace error because an un-removable
orphan is the more actionable signal).

For every checkpoint: a fault raises, the publication returns no result, a
fresh publisher reopens the store and reconstructs the old or new *complete*
ledger (never partial), and the retry yields `COMMITTED` (pre-replace) or
`IDEMPOTENT_APPEND` (post-replace). No managed temp is left behind on a
pre-replace fault. No backend exception diagnostic text is exposed in any
error detail.

## 16. POSIX durability

On POSIX, the temp file is fsynced before the atomic replace, and the store
directory is fsynced after the replace. This provides sudden-power-loss
durability of the rename up to the supported durability boundary.

## 17. Windows claim boundary

Windows does **not** claim POSIX-equivalent sudden-power-loss directory-fsync
durability: directories cannot be opened as file descriptors and `os.sync` is
unavailable. `fsync_directory` is a no-op on Windows. Atomicity and durability
rely on NTFS journaling plus the stores' use of `os.replace`. Interprocess
exclusion is provided by `msvcrt.locking` on the lock file.
