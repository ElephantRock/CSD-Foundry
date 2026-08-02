# Atomic Temporal Claim and Completion v0.5

## Status

This document describes the executable v0.5-C temporal protocol implemented under Issue #33. The frozen schemas, projection order, canonicalization rules, and `TEMP-SAFE-01` remain governed by `docs/CONTRACT_FREEZE_v0.5.md`.

## Purpose

The protocol serializes one accepted `ValidatedEvent` from a committed temporal head into either one complete committed successor or one audit-only projection failure.

```text
committed head H
→ atomically claim successor H+1
→ semantic projection
→ ordered projection commitments
→ quarantine commitment
→ completion receipt
→ atomically publish committed head H+1
```

Partial attempts, failed projections, and merely persisted completion objects are not current state. A snapshot becomes visible only when the committed-head pointer cites its `ClockCompletionReceipt`.

## Identity model

The protocol preserves three distinct identities:

- `attempt_id`: one execution attempt;
- `proposed_sequence`: the candidate immediate successor sequence;
- `clock_sequence`: the sequence visible only after successful completion publication.

A failed or recovered-incomplete attempt does not consume its proposed sequence. A new attempt with a new `attempt_id` may retry the same successor sequence.

## Authority boundary

Only an accepted `ValidatedEvent` may enter the coordinator. `RawEvent` and `EventValidationFailure` are rejected before a claim can be constructed.

Temporal authority comes from the compare-and-append committed-head transition. It does not come from:

- wall-clock time;
- directory enumeration;
- object publication order;
- maximum observed sequence;
- the existence of projection artifacts;
- the existence of a prepared completion receipt.

## Compare-and-append claim protocol

The reference POSIX store performs the following operation while holding a process-shared exclusive lock:

1. Read the current committed head `(H, previous_completion_digest)`.
2. Verify the caller's expected head matches exactly.
3. Verify the `ClockClaim` proposes `H+1` and cites the exact predecessor.
4. Verify no different active successor claim exists.
5. Install one active claim pointer.

Concurrent losing claims are retained as immutable attempt evidence but do not become active successors.

The validation campaign launches twelve independent processes against the same genesis head. Exactly one acquires the claim; eleven lose without advancing the clock.

## Frozen projection order

The coordinator executes the frozen order:

```text
SEMANTIC
→ EVIDENCE_REGISTRY
→ ASSUMPTION_REGISTRY
→ ALTERNATIVE_MODEL_REGISTRY
→ DISPOSITION
→ QUARANTINE_COMMIT
```

The semantic phase emits a `SemanticProjectionReceipt` before any dependent phase may complete.

In v0.5-C, the registry, disposition, and quarantine phases are deterministic typed reference adapters. They establish orchestration and commitment plumbing only. Substantive registry semantics are reserved for v0.5-D, and substantive disposition and quarantine eligibility are reserved for v0.5-E.

Release compilation is not a projection phase. Any attempt to invoke release compilation during an ordinary tick fails closed.

## Durable projection bundle

Before a completion may be prepared, the store persists a domain-separated internal projection bundle containing:

- the exact `ClockClaim` digest;
- the exact semantic receipt digest;
- evidence-unit, assumption, and alternative-model root digests;
- the disposition receipt digest;
- quarantine epoch and marker digests;
- the observed phase order;
- a zero release-compilation invocation count.

The bundle uses schema version `temporal-projection-bundle/1` and a `TEMPORAL_PROJECTION_BUNDLE\0` digest domain. Recovery and ordinary publication both verify that the bundle reconstructs every commitment embedded in the `ClockCompletionReceipt`.

## Two-stage completion protocol

Successful completion is deliberately separated into preparation and visibility:

```text
persist semantic receipt and projection bundle
→ construct ClockCompletionReceipt
→ persist prepared completion
→ compare-and-advance committed head
→ expose current snapshot
```

A crash after completion preparation but before head publication leaves the old head visible. Recovery revalidates the claim, semantic receipt, projection bundle, and completion before idempotently publishing the new head.

A conflicting completion cannot rebind a sequence that is already committed.

## Failure protocol

A failure in any mandatory phase emits one `ClockProjectionFailure` citing:

- the attempt and predecessor;
- the proposed sequence;
- the exact claim and validated event;
- the failure phase and stable failure code;
- the committed tick against which the failure was recorded.

The active claim is retired only after the failure receipt is durable. The committed head remains unchanged, and the current-snapshot API exposes no partial artifacts.

## Recovery protocol

The reference store distinguishes three restart states:

- no active claim: no recovery action;
- active claim without a prepared completion: emit a deterministic recovery failure and release the sequence for retry;
- active claim with a prepared completion: verify all committed dependencies and publish the completion idempotently.

Temporary installation debris is removed before recovery. Existing immutable objects remain content-addressed and no-clobber.

Recovery never advances the head merely because a higher sequence or completion-shaped file exists.

## Visibility and historical reconstruction

`current_snapshot()` resolves only the completion cited by the durable committed head.

`reconstruct_chain()` follows `previous_completion_digest` links back to genesis and rejects missing, discontinuous, or noncanonical completion objects.

Operational visibility and historical reconstruction therefore share the same immutable completion chain while keeping incomplete attempts outside current state.

## Determinism evidence

Frozen known-answer evidence is stored at:

- `data/canary/v0.5/temporal-v1/temporal_vectors.json`
- `reports/atomic_temporal_v0.5.json`

The committed campaign covers:

- twelve-process claim contention;
- stale expected-head rejection;
- rejection of non-validated event inputs;
- failure in every mandatory projection phase;
- no sequence advance or partial visibility after failure;
- same-sequence retry with a new attempt identity;
- conflicting-completion rejection;
- incomplete-attempt recovery;
- prepared-completion recovery;
- completion-chain reconstruction;
- receipt-field mutation rejection;
- byte-identical restart behavior;
- absence of release compilation from ordinary ticks.

## CI gate

Run:

```bash
csd-foundry-temporal-v0-5 --release v0.5
```

The command runs in editable and externally installed-wheel environments. All historical v0.1-v0.4 gates, the v0.5 contract gate, and the v0.5 admission gate must remain green.

## Claim boundary

This slice establishes deterministic single-host temporal serialization and atomic visibility for the POSIX reference store and supplied projection artifacts.

It does not establish:

- distributed consensus;
- multi-host lease safety;
- substantive evidence, assumption, or alternative-model registry correctness;
- substantive disposition or quarantine correctness;
- external truth;
- production safety;
- release or promotion compilation;
- replay pruning or performance-policy thresholds.
