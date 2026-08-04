# Assumption-Policy Activation Filesystem Publication v0.5-A1.3-B

**Status:** DRAFT IMPLEMENTATION CLAIM BOUNDARY  
**Version:** v0.5-A1.3-B  
**Date:** 2026-08-04  
**Issue:** #37  
**Implementation PR:** #53  
**Predecessor:** v0.5-A1.3-A pure V3 compare-and-append publication oracle  
**Implementation status:** Draft; this document does not authorize merge or claim gate completion

## 1. Purpose

This document defines the permitted claims, lifecycle, durable-file layout, lock boundary, commit point, failure semantics, restart behavior, error taxonomy, conformance evidence, and platform limits for V3 assumption-policy activation through a single-host filesystem publisher.

The filesystem publisher is an operational adapter around the existing pure semantic oracle:

```text
compare_and_append_policy_entry_v3
```

The semantic oracle remains authoritative for:

- exact expected-ledger-state comparison;
- exact retry and idempotent append;
- predecessor policy and commit binding;
- effective-sequence monotonicity;
- V3 ledger-entry eligibility;
- conflict and fork rejection;
- construction of the resulting canonical ledger and activation result.

The filesystem layer owns only:

- interprocess exclusion for cooperating publishers;
- authoritative stored-byte reconstruction and validation;
- explicit store creation and opening;
- managed temporary-file handling;
- same-filesystem atomic replacement;
- supported durability operations;
- post-replacement verification;
- restart reconstruction;
- storage-error normalization.

It may not reinterpret, weaken, or replace the semantic oracle.

## 2. Authoritative file layout

One publisher root contains:

```text
<root>/
├── ledger.json
├── publication.lock
└── .policy-ledger.<uuid-hex>.tmp
```

### 2.1 `ledger.json`

`ledger.json` is the sole authoritative assumption-policy ledger file.

It contains the exact canonical bytes of one `AssumptionPolicyLedgerV3` object. The file is not a cache, index, journal fragment, or best-effort snapshot.

A valid authoritative file must:

- decode as UTF-8;
- parse as one closed JSON object;
- use the supported ledger schema version;
- contain only supported closed nested contract objects;
- reconstruct every nested typed contract;
- pass every nested digest and contract invariant;
- reproduce the stored ledger root;
- equal the canonical bytes emitted by the rebuilt ledger.

### 2.2 `publication.lock`

`publication.lock` is the single interprocess exclusion object for all managed operations on the store.

All cooperating processes must use the same canonical root and lock path. A process that bypasses this lock is outside the claim boundary.

The lock file is not semantic state and is not included in ledger identity.

### 2.3 Managed temporary files

A temporary publication file must use the exact pattern:

```text
.policy-ledger.<uuid-hex>.tmp
```

It must be created inside the publisher root so the temporary file and `ledger.json` reside on the same filesystem for `os.replace`.

Cleanup may remove only regular managed files matching the exact pattern. It must not remove:

- unrelated `*.tmp` files;
- `.policy-ledger.tmp` without an identifier;
- directories;
- symbolic links followed as files;
- files outside the configured root.

## 3. Lifecycle contract

The constructor is side-effect free. It records paths only.

Store lifecycle is explicit.

### 3.1 `create()`

`create()` initializes one empty canonical V3 ledger.

Under the publication lock, it must:

1. establish the managed root needed for the lock and store;
2. clean only eligible orphaned managed temporary files;
3. determine whether `ledger.json` exists;
4. if it exists, reconstruct it fully;
5. reject a valid existing store with `ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED`;
6. surface corruption rather than replacing corrupt or partial authoritative bytes;
7. atomically publish the empty canonical ledger only when the store is uninitialized.

`create()` is not an idempotent reset operation. It may never silently replace a committed ledger with an empty ledger.

### 3.2 `open()`

`open()` opens and validates an existing store. It never initializes one.

Under the publication lock, it must:

1. establish the managed root needed for the lock path;
2. clean only eligible orphaned managed temporary files;
3. require `ledger.json`;
4. reconstruct and fully validate the complete stored object graph.

A missing authoritative ledger fails with:

```text
ASSUMPTION_POLICY_STORED_BYTES_MISSING
```

### 3.3 Read operations

`read_state()` and `read_ledger()` reconstruct the authoritative ledger from bytes under the publication lock on every call.

No in-memory cache is authoritative. Restart or a second process must derive the same root, head, entries, and state from `ledger.json` alone.

### 3.4 `publish()`

`publish()` requires an initialized, valid store and one prepared V3 activation.

It must reconstruct current authoritative state under the same lock before calling the pure compare-and-append oracle.

A V2 or otherwise unsupported ledger entry is rejected before filesystem publication.

## 4. Interprocess exclusion boundary

One publication-lock acquisition must cover every managed operation that can observe, decide, remove, replace, or verify store state.

The protected boundary includes:

```text
managed initialization decision
→ orphan cleanup
→ authoritative byte read
→ full reconstruction
→ current root/head derivation
→ exact idempotence and expected-state comparison
→ updated-ledger construction
→ temporary write and flush
→ temporary-file fsync
→ atomic replacement
→ directory durability operation
→ authoritative reread
→ exact post-write verification
```

No managed ledger-state decision or orphan cleanup may occur outside this exclusion boundary.

Only minimal path preparation required to make the lock path reachable may precede lock acquisition. Such preparation must not create, reset, interpret, or delete authoritative ledger state.

This is a cooperative single-host interprocess claim. It does not establish:

- distributed consensus;
- fencing against a noncooperating writer;
- multi-host lease safety;
- correctness on filesystems whose locking or rename semantics violate the documented platform assumptions.

## 5. Publication sequence

For a non-idempotent accepted append, the required sequence is:

```text
1. acquire publication lock
2. read authoritative ledger bytes
3. parse and fully validate ledger and all nested contracts
4. derive current root and head
5. invoke the pure V3 compare-and-append oracle
6. obtain updated canonical ledger bytes and activation result
7. create one managed temporary file in the root
8. write the complete canonical bytes
9. flush userspace buffers
10. fsync the temporary file where supported
11. atomically replace ledger.json with os.replace
12. perform the supported directory durability operation
13. reread ledger.json
14. reconstruct the complete stored graph
15. verify exact canonical bytes, entries, root, head, predecessor, and result bindings
16. return the activation result
17. release the lock
```

An `IDEMPOTENT_APPEND` does not rewrite the authoritative file.

## 6. Commit point

The filesystem publication commit point is:

```text
successful os.replace(temp, ledger.json)
```

Before this point, the old authoritative file remains the committed ledger.

After this point, the new file may be authoritative even if later durability or verification work fails.

The semantic activation result may be returned only after all required post-commit verification succeeds.

## 7. Failure semantics

### 7.1 Pre-commit failure

A failure before successful `os.replace` must:

- return no activation result;
- leave the old authoritative `ledger.json` byte-for-byte intact;
- avoid advancing the ledger root or head;
- perform best-effort cleanup of the current managed temporary file;
- remain recoverable by `open()`;
- use a stable pre-commit storage or semantic conflict code.

A pre-commit failure does not require rollback because no authoritative replacement occurred.

### 7.2 Post-commit failure

A failure after successful `os.replace` must:

- return no activation result;
- never attempt an automatic rollback;
- raise:

```text
ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
```

The new ledger may already be authoritative. Rolling back could destroy a valid committed publication or create a fork.

Recovery is:

```text
reopen and reconstruct authoritative bytes
→ compare root/head/entry with the attempted activation
→ exact retry using the reconstructed expected state
→ resolve as IDEMPOTENT_APPEND or a stable conflict
```

### 7.3 Failure-injection evidence

Before PR #53 is ready, deterministic tests must cover failures at least at:

- before temporary-file creation;
- after a partial temporary write;
- after temporary flush and fsync;
- immediately before `os.replace`;
- immediately after `os.replace` and before directory durability;
- before authoritative reread;
- during authoritative reread;
- during exact post-write verification.

For every checkpoint, restart must observe exactly the old complete ledger or the new complete ledger, never mixed or partially reconstructed state.

Two broad `pre-commit` and `post-commit` checkpoints alone do not establish every required boundary above.

## 8. Post-write verification

Successful publication requires exact verification under the same publication lock.

The verifier must establish:

- authoritative bytes equal the intended updated canonical bytes;
- the complete reconstructed entry sequence equals the oracle's updated ledger;
- reconstructed ledger root equals the result's resulting ledger root;
- reconstructed head entry digest equals the result's ledger entry digest;
- predecessor policy and commit bindings equal the accepted candidate;
- the result's expected predecessor root equals the pre-write authoritative root;
- the entry count and exact content match the updated ledger;
- no unexpected second writer modified the authoritative bytes before verification.

Checking only the rebuilt ledger root is insufficient.

Any post-commit mismatch is outcome-uncertain and must not return success.

## 9. Restart and corruption behavior

Every open, read, and publication operation reconstructs from canonical stored bytes.

The parser boundary is closed and type-safe:

- every stored object must be a JSON object of the exact expected field set;
- unknown and missing fields fail closed;
- every nested schema version is checked;
- lists must contain the exact permitted element type;
- booleans may not masquerade as integers;
- optional integer fields must be nonnegative when present;
- contract constructors revalidate digests and semantic invariants;
- parser failures escape only through stable `PolicyStoreError` or approved semantic conflict types.

Malformed stored data must not leak uncontrolled `KeyError`, `TypeError`, `AttributeError`, platform-specific parser messages, or partial typed objects.

## 10. Error taxonomy

### 10.1 Store lifecycle and path errors

```text
ASSUMPTION_POLICY_STORE_ROOT_INVALID
ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY
ASSUMPTION_POLICY_STORE_ROOT_CREATE_FAILED
ASSUMPTION_POLICY_STORE_LOCK_FAILED
ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED
ASSUMPTION_POLICY_STORED_BYTES_MISSING
```

### 10.2 Stored-byte and reconstruction errors

```text
ASSUMPTION_POLICY_STORED_BYTES_INVALID
ASSUMPTION_POLICY_STORED_BYTES_NONCANONICAL
ASSUMPTION_POLICY_STORED_SCHEMA_UNSUPPORTED
ASSUMPTION_POLICY_STORED_FIELD_INVALID
ASSUMPTION_POLICY_STORED_CONTRACT_INVALID
ASSUMPTION_POLICY_STORED_ROOT_MISMATCH
ASSUMPTION_POLICY_STORED_VERIFICATION_FAILED
```

### 10.3 Publication errors

```text
ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED
ASSUMPTION_POLICY_PUBLICATION_OUTCOME_UNCERTAIN
```

`ASSUMPTION_POLICY_PUBLICATION_WRITE_FAILED` is permitted only when the implementation can establish that the commit point was not crossed. Any failure whose timing relative to `os.replace` cannot be proven is outcome-uncertain.

### 10.4 Semantic conflicts

Semantic compare-and-append conflicts remain `AssumptionPolicyPublicationConflict` outcomes owned by the pure oracle. The filesystem adapter must not translate a deterministic semantic conflict into storage corruption or outcome uncertainty.

Error details may contain controlled context, but callers must branch on stable codes rather than operating-system messages.

## 11. Orphan temporary-file behavior

Orphan cleanup runs only under the publication lock.

It must:

- target only the exact managed naming pattern;
- avoid following symbolic links;
- avoid removing directories or foreign objects;
- tolerate a file already removed by another completed cleanup;
- surface material filesystem failures through stable codes rather than silently claiming a clean store;
- perform the required directory durability operation when cleanup changes directory entries and the platform claim requires it.

An active temporary file from another compliant publisher cannot be deleted because the other publisher holds the same interprocess lock.

## 12. Process-race evidence

Thread races are insufficient for the interprocess claim.

Conformance requires true separate-process tests using a spawn-compatible top-level worker, bounded joins, an interprocess synchronization primitive, and a multiprocessing queue or equivalent deterministic result channel.

Required races include:

### 12.1 Distinct genesis candidates

From one empty expected state:

```text
one COMMITTED
one ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH or exact oracle-owned conflict
one final authoritative entry
winner root and head present
loser entry absent
```

### 12.2 Exact retry

For two processes publishing the same candidate:

```text
one COMMITTED
one IDEMPOTENT_APPEND
one final authoritative entry
byte-identical final ledger
```

### 12.3 Concurrent store creation

For two processes invoking `create()` on one uninitialized root:

```text
one successful creation
one ASSUMPTION_POLICY_STORE_ALREADY_INITIALIZED
one canonical empty authoritative ledger
no clobber or duplicate initialization
```

### 12.4 Open during publication and restart

Opening or reconstructing during compliant publication must serialize on the same lock and observe one complete committed ledger. Restart after injected failure must reconstruct deterministically.

## 13. Platform claim boundary

### 13.1 Shared claims

On supported platforms, this implementation may claim only:

- cooperative interprocess exclusion through the repository's advisory-lock adapter;
- atomic name replacement through same-filesystem `os.replace`;
- full canonical restart reconstruction;
- stable error classification;
- exact idempotent retry and conflict behavior relative to the pure oracle.

### 13.2 POSIX

Where regular-file `fsync` and directory `fsync` succeed on the target filesystem, the implementation may claim:

- temporary-file content durability before replacement;
- persistence of the replacement directory entry across sudden power loss, subject to operating-system and filesystem guarantees.

This is not a distributed-filesystem or hardware-controller guarantee.

### 13.3 Windows

The implementation does not claim POSIX-equivalent directory-fsync durability on Windows.

It may claim atomic visibility under the documented `os.replace` behavior and successful file-level flush/fsync, but not sudden-power-loss persistence of the directory entry equivalent to the POSIX claim.

Spawn-based process tests are required so the concurrency evidence is not fork-only.

### 13.4 Unsupported environments

No claim is made for:

- network filesystems with undocumented or weaker lock/rename semantics;
- object stores mounted as filesystems;
- multiple hosts without a fencing or consensus protocol;
- noncooperating writers;
- external processes that edit `ledger.json` directly;
- storage media or drivers that acknowledge durability operations without honoring them.

## 14. Required conformance campaign

PR #53 may become ready only when all of the following pass on the review head:

- lifecycle create/open tests;
- constructor side-effect-free tests;
- canonical restart reconstruction;
- exact retry and semantic-conflict tests;
- closed parser mutation campaign for every nested object;
- bytes, root, head, predecessor, entry-count, and result-binding verification;
- granular pre-commit and post-commit failure injection;
- orphan cleanup and foreign-object tests under concurrency;
- true spawned-process distinct-writer, exact-retry, and concurrent-create races;
- stable filesystem and lock-failure normalization;
- corruption and missing-authoritative-byte tests;
- full historical v0.1-v0.5 gates;
- Linux CI;
- wheel build and installed-wheel validation.

The evidence record must identify the exact review commit and workflow run.

## 15. Explicit non-claims

Completion of A1.3-B does not establish:

- historical `resolve_at` behavior;
- active-policy selection;
- exact grant selection;
- assumption-registry lifecycle reduction;
- disposition or quarantine behavior;
- release or promotion compilation;
- distributed consensus;
- multi-host correctness;
- production key management;
- external truth of policy contents;
- production safety.

It establishes only that one V3 policy ledger can be published and reconstructed through the declared single-host filesystem boundary without silent clobber, partial authoritative state, or semantic-oracle reinterpretation.

## 16. Merge boundary

This document is a contract for the implementation and evidence required by PR #53. Its presence does not prove that the branch conforms.

PR #53 must remain draft until:

- the implementation matches every normative requirement above;
- the test campaign covers every required boundary;
- the complete CI and installed-wheel gates pass;
- blocking review findings are resolved against the exact head commit;
- a reviewer explicitly marks the PR ready.

A1.3-C must not begin on the PR #53 branch.
