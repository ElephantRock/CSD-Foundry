# CSD Foundry v0.4 Execution Protocol

## Scope

Execution protocol version 1 freezes the immutable authority and operational evidence layer
required before durable shard publication and streaming reconciliation. It defines canonical
sample ordering, global ordinals, logical shard assignment, bounded operational retries,
terminal operational exhaustion evidence, and append-only inventory supersession.

It does not establish filesystem publication, shard manifests, streaming corpus merge,
planner completeness, state construction, oracle-valid trajectories, infeasibility, or
release-scale output.

## Compatibility boundary

The generation namespace already commits to shard policy version 1:

```json
{
  "policy_id": "csd-shard-contract",
  "policy_version": 1,
  "semantic_assignment": "global-ordinal-modulo-shard-count"
}
```

Version 1 therefore orders samples by canonical sample-key bytes, assigns contiguous global
ordinals, and computes the logical shard as `global_ordinal % shard_count`. Hash-based sample
routing would require shard policy version 2 and new generation-namespace, identity, and
replay evidence.

## Canonical sample-key bytes

Sample-key encoding is independently versioned as `csd-sample-key-canonical-json` version 1.
The encoded value contains exactly `release`, `sample_index`, and `target_id`, serialized by
the repository canonical JSON encoder with sorted keys, compact UTF-8, integer-only numbers,
and one terminal newline.

These bytes govern inventory ordering and global ordinal assignment. They are deliberately
separate from choice and identity algorithm versions.

## Execution inventory

An `ExecutionInventory` is immutable, content-addressed authority. It commits the generation
namespace, root-seed commitment, sample-key encoding policy, shard policy, shard count,
operational retry policy, validation policy, required schema registry, and ordered sample
specifications.

The sample tuple must be nonempty, uniquely keyed, canonically ordered, and indexed by
contiguous global ordinals starting at zero. Any target, attempt-range, policy, version, or
membership change produces a different inventory digest.

Repeated operational runs of identical inventory content use separate execution-run IDs.
Run IDs never enter deterministic choices, entity identities, semantic attempt commitments,
or inventory digests.

## Operational retry evidence

`OperationalRetryPolicy.maximum_operational_retries` is an exact unsigned byte. The packaged
v0.4 reference policy permits two retries, meaning three total executions including the
initial execution.

Every failed execution emits an immutable `OperationalFailureReceipt`. Receipts are bound to
one run, inventory, and attempt, use contiguous execution ordinals, and form a previous-digest
hash chain.

After every permitted execution fails, the system emits an `OperationalExhaustionRecord`
committing the complete failure-receipt chain. Operational exhaustion terminates rescheduling
for that attempt but remains nonsemantic: it is not `AttemptRejected`, `ExhaustionEvidence`,
or an infeasibility witness. A later reconciler must classify the attempt as semantically
missing and release sealing must remain blocked.

## Schema registry

One inventory pins one exact schema version for every execution, publication, reconciliation,
and manifest artifact. Mixed, unknown, or newer compatible-looking versions are rejected.
Implicit migration and field dropping are prohibited.

## Inventory supersession

Inventories and their evidence are never modified or deleted in place. A replacement
inventory is linked through a new append-only `InventorySupersessionRecord`. The previous
inventory and all partial evidence remain addressable under their original digests.

## Frozen evidence

Execution-protocol canary version 1 contains seven independently pinned vectors covering:

- canonical sample-key encoding;
- global-ordinal shard assignment;
- required schema versions;
- the retry policy;
- execution inventory commitment;
- terminal operational exhaustion commitment;
- append-only inventory supersession.

Any change to the vector catalog or expected digests requires a new evidence version.
