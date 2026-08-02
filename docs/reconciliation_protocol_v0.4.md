# CSD Foundry v0.4 Streaming Reconciliation Protocol

## Scope

This protocol completes PR 2C-C by reconciling factory-sealed shard publications into a canonical semantic corpus and a separate operational run-evidence corpus.

The reconciler consumes the immutable `ExecutionInventory`, every logical `PublishedShard`, verified content-addressed objects, and caller-supplied reconstruction and independent replay functions. It never trusts shard summaries as semantic truth.

## Streaming merge

Canonical `ShardIndexEntry` streams are merged with one cursor per shard and a bounded heap. The implementation buffers only the attempt prefix for the current sample plus logarithmic Merkle peaks. Whole-corpus in-memory materialization is prohibited.

Entries are ordered by global sample ordinal and attempt index. Exact duplicates collapse. Different evidence at one inventory-attempt position raises `ReconciliationConflictError` and prevents final sealing.

## Global resolution

For each inventory sample, the reconciler:

1. reconstructs the exact `PublishedCompletion`;
2. validates its `InventoryCompletionReference` against the inventory;
3. independently executes `FULL_REPLAY`;
4. persists a `ReplayAttestation`;
5. resolves the contiguous attempt prefix with the frozen replay protocol.

The first accepted attempt is selected only after every preceding rejection is verified. Complete exhaustion remains run evidence and does not enter the semantic corpus. Incomplete prefixes fail closed.

## Commitment separation

### Semantic corpus

`SemanticCorpusRecord` contains only topology-independent semantic content: sample identity, selected attempt, rejected semantic prefix, replay-attestation commitments, and the accepted canonical result. It excludes inventory digest, shard count, source manifests, execution-run IDs, receipts, paths, and timestamps.

### Run evidence

`RunEvidenceRecord` preserves inventory authority, source manifests, completion envelopes, semantic completions, replay attestations, resolution status, and resolution digest. Run-evidence manifests are expected to differ across shard topologies.

## Streaming Merkle publication

Every semantic and run-evidence record is individually content addressed. A streaming Merkle forest accumulates roots using logarithmic memory. Merkle nodes and roots are also content addressed.

The final sequence is:

```text
semantic records + run-evidence records
→ semantic and run Merkle roots
→ semantic-corpus manifest
→ run-evidence manifest
→ canonical merge seal
→ append-only seal reference
```

The merge seal is installed only after both manifests are durably published. Re-execution converges through existing no-clobber publication semantics.

## Frozen evidence

Evidence version 1 pins:

- topology-independent semantic manifest;
- semantic Merkle root;
- topology-specific run-manifest aggregate;
- topology-specific seal aggregate;
- full-replay summary;
- measured streaming buffer bound for 1, 2, and 7 shard fixtures.

The CLI gate is:

```text
csd-foundry synthesize reconciliation --release v0.4
```

## Claim boundary

This protocol establishes bounded cross-shard reconciliation, exact duplicate handling, conflict rejection, global lowest-valid-attempt resolution, complete independent replay, topology-independent semantic commitments, separate run evidence, and final sealing relative to the existing v0.4 contracts.

It does not establish planner completeness, state/event construction, oracle-valid trajectories, infeasibility, structural canonicalization, performance SLO compliance, or release-scale readiness.
