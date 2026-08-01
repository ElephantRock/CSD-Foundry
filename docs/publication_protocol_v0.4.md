# CSD Foundry v0.4 Publication Protocol

## Scope

Publication protocol version 1 adds durable append-only publication beneath the frozen v0.4
execution protocol. It persists semantic attempt completion without allowing worker topology,
execution-run identity, retry history, timestamps, storage location, or crash timing to alter
semantic commitment bytes.

This first implementation slice establishes the three-record separation and the minimal
content-addressed no-clobber object store. Shard indexes, manifests, seals, streaming
reconciliation, and canonical corpus merge remain outside this slice.

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
Operational receipt bytes never enter completion-envelope identity.

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
