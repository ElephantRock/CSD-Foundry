# Assumption Policy Activation Filesystem Publication v0.5-A1.3-B

**Status:** Implemented durable interprocess filesystem publication
**Date:** 2026-08-03
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

Exclusive interprocess access is provided by `_platform` advisory locking on
`root/publication.lock`. The lock file is created by the lock helper itself on
first acquisition (opened `a+b`, seeded with one byte on Windows so the byte
range lock is well-defined). The publisher never creates the lock file
directly.

POSIX uses `fcntl.flock`; Windows uses `msvcrt.locking` on byte 0. Both
provide process-wide exclusive advisory locking on the lock file, which is
sufficient for single-writer publication.

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
1. acquire exclusive publication lock
2. ensure root (create() only) + orphan cleanup
3. read authoritative stored ledger bytes
4. reconstruct and fully validate ledger/3 (every nested contract revalidated)
5. run V3 exact idempotence (the A1.3-A oracle)
6. compare expected state + predecessor/sequence validation
7. construct updated ledger/3 canonical bytes
8. write managed temp  (.policy-ledger.<32-hex>.tmp)
9. fsync temp
10. os.replace  ← commit point
11. fsync store directory (POSIX)
12. reread authoritative bytes
13. reconstruct + verify every binding
14. release lock
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

In every pre-commit case the caller receives no activation result, the old
authoritative ledger is byte-for-byte intact, and retrying the publication is
safe.

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

## 14. Multiprocessing evidence

Real multiprocessing races (spawn context, barriers, queues) prove the claim:

* **distinct genesis candidates:** exactly one `COMMITTED` and one
  `PublicationConflict` with code `ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH`.
  After both processes exit (exit code 0): one entry, head = winner digest,
  root = winner root, loser absent. A third publisher reopens and reconstructs
  the same root.
* **exact retry:** one `COMMITTED` and one `IDEMPOTENT_APPEND`, one entry, the
  same digest and root, reopened root matches. Neither process observes a hard
  failure.
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
failure behavior without arbitrary monkey-patching:

```text
pre-replace (old ledger intact, fault propagates):
  BEFORE_TEMP_CREATE
  AFTER_PARTIAL_TEMP_WRITE
  AFTER_TEMP_FLUSH
  BEFORE_REPLACE
--- os.replace commit point ---
post-replace (outcome uncertain, publication may have landed):
  AFTER_REPLACE
  BEFORE_DIRECTORY_FSYNC
  BEFORE_POST_WRITE_READ
  DURING_POST_WRITE_READ
```

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
