# CSD Foundry v0.4 Publication Protocol

## Scope

Publication protocol version 1 adds durable append-only publication beneath the frozen v0.4
execution protocol. It persists semantic attempt completion without allowing worker topology,
execution-run identity, retry history, timestamps, storage location, or crash timing to alter
semantic commitment bytes.

The protocol establishes the three-record separation, durable content-addressed no-clobber
publication, canonical shard-index snapshots, factory-verified manifests, and append-only seal
references. Streaming reconciliation and canonical corpus merge remain outside this slice.

## Commitment separation

### AttemptCompletionEnvelope

`AttemptCompletionEnvelope` is topology-independent semantic content. It commits:

- the exact `AttemptKey`;
- the generation-namespace digest;
- the authoritative `attempt_input_commitment_digest`;
- accepted or rejected completion status;
- the existing completion, search-branch, choice-ledger, and identity-ledger digests.

It deliberately excludes inventory digest, execution-run ID, worker ID, retry count,
timestamps, shard indexes, publication disposition, and filesystem path.

### InventoryCompletionReference

`InventoryCompletionReference` binds one completion envelope to immutable execution authority.
Construction requires the exact `ExecutionInventory` and verifies:

- generation namespace equality;
- unique sample membership;
- global ordinal and sample-spec digest;
- attempt-range authorization;
- exact schema-version compatibility.

The reference does not change the semantic envelope.

### OperationalPublicationReceipt

`OperationalPublicationReceipt` records append-only operational publication history. Receipts
form a contiguous previous-digest chain within one execution run, inventory, and attempt.
Operational receipt bytes never enter completion-envelope identity. Before installing a
semantic object, the coordinator atomically installs an immutable per-kind, per-object
publication claim. The claim owner commits the execution run, inventory, attempt, object kind,
object digest, receipt ordinal, and predecessor receipt. Same-run workers therefore converge on
one `published` receipt choice even when they race; a different run observes
`existing-identical`. Because the claim is durable before object installation, recovery across
the object-to-receipt gap reproduces the uninterrupted receipt chain. A different run may
finish installing verified bytes under an abandoned claim while retaining an
`existing-identical` disposition, so a lost owner cannot permanently wedge publication.
Reused receipt objects are routed through the durable-existing path before success is returned.

## No-clobber object publication

Objects are addressed by lowercase SHA-256 digest:

```text
objects/<first-two-hex>/<remaining-sixty-two-hex>
```

Publication uses a same-filesystem temporary object, complete write, flush, file
synchronization, and an atomic hard-link installation. The hard link fails rather than
overwriting an existing authoritative path.

Existing identical bytes are classified as `existing-identical`. An existing object whose
bytes do not match its digest path fails closed as corruption. Partial temporary objects never
become authoritative.

## Crash recovery boundary

The implementation exposes deterministic fault points after temporary creation, content write,
file synchronization, and authoritative object installation.

Recovery removes non-authoritative temporary debris. When installation completed before a
crash, recovery verifies the authoritative object before removing the surviving temporary
link. Recovery never manufactures semantic completion or inventory authority.

## Frozen evidence

Publication evidence version 1 pins:

- accepted completion-envelope commitment;
- rejected completion-envelope commitment;
- inventory completion-reference commitment;
- publication receipt-chain commitment;
- no-clobber object-layout commitment.

Any change to vector IDs or expected values requires a new evidence version.

## Deliberate boundary

This protocol does not yet establish shard indexes, manifests, seals, global
lowest-valid-attempt resolution, bounded k-way merge, conflict escalation across shards,
semantic corpus publication, run-evidence publication, planner completeness, oracle-valid
trajectories, infeasibility, or release-scale readiness.

## Canonical shard indexes

A `ShardIndex` is an immutable content-addressed snapshot. Entries are sorted by global
ordinal, attempt index, completion-envelope digest, completion-reference digest, and final
publication-receipt digest. Construction collapses exact duplicates and fails closed when two
different completions occupy one inventory-attempt position.

Index snapshots do not commit construction order or predecessor snapshots. Old snapshots
remain addressable in the append-only store, while the final snapshot remains invariant to
worker count and completion order.

## Manifest sealing

`SealedShardManifest` has no public constructor. Its factory requires the exact execution
inventory, canonical shard index, complete published-completion set, and publication store.
Before issuing the manifest it verifies:

- shard-policy-v1 assignment for every index entry;
- the durable content-addressed index object and append-only index reference;
- every completion envelope, inventory reference, and receipt-chain object;
- exact inventory, namespace, and required-schema commitments;
- complete entry-aligned digest lists and aggregate object-set commitment.

The manifest's construction is the logical seal. Publication then installs append-only hard
links for the index, manifest, and seal under inventory-and-shard namespaces. A seal is
therefore a durable reference to verified manifest bytes, not a mutable status flag.

## Staged crash recovery

Completion receipts, inventory references, shard indexes, manifests, and seals are individually
content addressed and installed with no-clobber semantics. Re-executing after interruption
classifies already installed bytes as identical and finishes the remaining stages. Tests inject
failures after each durable stage and require convergence to the same semantic envelope and a
verified seal.
