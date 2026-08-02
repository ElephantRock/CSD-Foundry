# CSD Foundry v0.5 Foundational Contract Freeze

**Status:** FROZEN FOR IMPLEMENTATION  
**Catalog version:** 1  
**Evidence version:** 1  
**Date:** 2026-08-02

## 1. Purpose and scope

This specification freezes the identity, authority, ordering, replay, quarantine, and release boundaries required before implementation of the v0.5 governed-execution vertical slice. It is normative together with the machine-readable policies, schemas, vectors, validator, and report under `specs/v0.5`, `schemas/v0.5`, `data/canary/v0.5`, `scripts`, and `reports`.

It deliberately does not freeze performance thresholds, retry budgets, replay-pruning rules, cache policy, model-count limits, latency SLOs, stochastic mutation budgets, or release-scale quotas. Those remain measurement-dependent.

Existing v0.1, v0.3, and v0.4 artifacts remain immutable. The v0.5 canonicalization policy applies only to v0.5 contracts.

## 2. Charter invariants

### `TEMP-SAFE-01` — Atomic temporal progress

Temporal progress requires an atomic no-clobber completion protocol.

- At most one successor claim may complete for a committed temporal head.
- A failed projection attempt does not advance the committed sequence.
- Every committed sequence has exactly one complete projection bundle.
- Every failed claimed attempt produces `ClockProjectionFailure`.
- A new sequence is not externally complete until all mandatory projections and quarantine effects commit.

### `RAP-SAFE-01` — Conservative shadow replay

Every primary/shadow graph difference requires full replay until irrelevance is mechanically certified.

Added, removed, relabeled, rescoped, temporal, authority, and evidence-admission differences all trigger full replay. Cut-set pruning is prohibited until a versioned relevance-certificate contract, independent validator, counterexample vectors, and measured policy exist.

### `REL-ARCH-01` — Event-triggered release compilation

Release compilation runs only in response to an explicit post-snapshot request. It is not a mandatory clock phase. Promotion uses evidence current at the promotion-request snapshot and creates a new immutable release identity and manifest.

### `VAL-SAFE-01` — Validation/reduction separation

Reducers consume only committed `ValidatedEvent` receipts. Raw and rejected events cannot enter reducers. Schema, signature, authority, and validation-policy interpretation occurs before reduction, and historical acceptance remains bound to the original policy digest and committed context tick.

### `RAP-INV-01/02` — Semantic/disposition separation

Disposition may govern operational use, escalation, quarantine, and release eligibility but may not establish or replace a substantive CSD verdict. Reality Assurance may expose ignorance, evidence absence, expiry, challenge, disagreement, sensitivity, or required action but may not assert external truth or world-model completeness.

## 3. Canonicalization

The normative policy is `specs/v0.5/canonicalization_policy_v1.json`.

- UTF-8 encoding; no Unicode normalization.
- `schema_version` is serialized first when present.
- Remaining object keys are ordered by ascending UTF-8 key bytes.
- Exact integers only; booleans are not integers; floats are prohibited.
- Unknown fields are rejected unless explicitly permitted by the schema.
- Every array is declared `SET`, `MULTISET`, or `ORDERED_SEQUENCE`.
- `SET` members are sorted by canonical bytes and duplicate canonical members are rejected.
- `MULTISET` members are sorted while preserving multiplicity.
- `ORDERED_SEQUENCE` preserves supplied order exactly.
- Event histories, causal chains, operation traces, and repair trajectories are never sorted unless their schema explicitly says otherwise.
- Canonical JSON uses compact separators and one trailing LF.

Each digest-bearing contract has exactly one catalog-declared domain prefix. Its digest is SHA-256 over `domain_prefix || canonical_bytes(contract_without_its_digest_field)` and is encoded as `sha256:<lowercase-hex>`.

## 4. Event admission

The validation boundary is:

```text
RawEvent
  → schema / canonical digest / signature / authority / policy validation
  ├─ ValidatedEvent
  └─ EventValidationFailure
```

The frozen accepted receipt contains the raw-event digest, validation-policy digest, signature-set digest, `validation_result=ACCEPTED`, the latest committed context tick used for validation, and the receipt digest. `validated_at_tick` is never a proposed future tick or a wall-clock timestamp.

Rejected events use `EventValidationFailure`; reducers cannot consume failure receipts. Reducers verify receipt integrity and reconstructability but do not reinterpret signatures.

## 5. Temporal completion and projection order

The temporal protocol is:

```text
committed head H
  → atomic successor claim for H+1
  → SEMANTIC
  → EVIDENCE_REGISTRY
  → ASSUMPTION_REGISTRY
  → ALTERNATIVE_MODEL_REGISTRY
  → DISPOSITION
  → QUARANTINE_COMMIT
  → ClockCompletionReceipt
  → committed head H+1
```

The phase names are strings whose order is fixed by `specs/v0.5/projection_phase_order_v1.json`; numeric phase values have no authority.

Disposition may begin only after a committed `SemanticProjectionReceipt` and must cite the exact receipt consumed. Any mandatory-phase failure fails the tick closed, records `ClockProjectionFailure`, and leaves the committed head unchanged. A retry may reuse the proposed sequence with a new attempt identity.

Release compilation is intentionally absent from this phase list.

## 6. Event-sourced registries

Evidence-unit, assumption, and alternative-model registries are pure reductions over append-only validated events. The common `RegistryEvent` envelope freezes registry type, entity identity and sequence, predecessor digest, clock sequence, projection phase, source receipt, payload schema, payload, and event digest.

Entity sequences are contiguous and predecessor-linked. Entity-affine sharding is required. Every worker using the same validated event set and phase policy must reconstruct the same state and root. Historical state remains reconstructable from immutable events and roots.

Specific registry state machines and root layouts require separately versioned contracts before implementation claims completion.

## 7. Disposition

`DispositionReceipt` consumes the committed semantic receipt, decision class, clock sequence, and exact registry roots. It may return:

- `DOCUMENT_AND_PROCEED`;
- `FLAG_AND_PROCEED`;
- `ESCALATE_AND_HOLD`;
- `BLOCK`;
- `EXCLUDE_FROM_RELEASE`.

Evidence-conflict precedence applies only after admission, temporal validity, scope compatibility, proposition compatibility, and lineage/independence checks. The precedence policy is `runtime_observation > incident_report > architecture_review > expert_assertion`. Ties remain `CONTESTED` and use the more conservative class-specific disposition.

The ordered registry fold is deterministic and order-sensitive. Conflict aggregation over the current eligible evidence set is pure, commutative, associative, and identity-aware.

## 8. Quarantine and historical reconstruction

An `InvalidationEvent` identifies the governed cause and affected-asset index. The Temporal Service advances a quarantine epoch and commits a `QuarantineMarker`; it orders visibility but does not decide substantive invalidation.

`may_use_asset` is the current operational API. It fails closed when the consumer epoch is stale, the asset is quarantined, eligibility context is unavailable, or a digest cannot be verified.

`reconstruct_asset_at_epoch` is the historical audit API. Historical eligibility never authorizes current operational use.

Invalidation has two stages:

1. immediate synchronous logical quarantine;
2. asynchronous exact impact materialization and replay.

## 9. Release and promotion

`ReleaseRequest` and `PromotionRequest` pin a completed clock sequence, quarantine epoch, semantic root, disposition root, and evidence/assumption/alternative-model roots.

The external release compiler verifies snapshot completeness, current eligibility, reuse-class limits, required assurance, policy versions, and absence of quarantine. A promotion may not replay only the original fast-path admission; it must use evidence current at `requested_at_tick`.

Every promotion creates a new release identity and `ReleaseManifest`. Existing releases are never edited in place. If quarantine advances or an input becomes ineligible before publication, compilation fails closed.

## 10. Conformance evidence

Commit-blocking evidence is under `data/canary/v0.5/contract-v1/contract_vectors.json`. It contains canonicalization vectors, one deterministically generated accepted-fixture digest per frozen contract, and invalid schema/semantic/canonicalization vectors.

Run:

```bash
python scripts/validate_contract_freeze_v0_5.py
pytest -q tests/test_contract_freeze_v0_5.py
```

The validator checks policy and catalog digests, JSON Schemas, explicit collection kinds, contract versions, canonical bytes, domain-separated digests, selected cross-field semantics, projection ordering, and release-phase exclusion.

## 11. Change discipline

Published contract bytes are immutable. Changing a schema meaning, field semantics, domain prefix, phase order, rejection-code meaning, vector expectation, or API side-effect boundary requires a new schema, policy, catalog, registry, or evidence version plus explicit migration review.

## 12. Items not frozen

The following remain `UNMEASURED` until pilot evidence supports policy:

- exact assumption enumeration limits;
- cut-set and replay-pruning thresholds;
- cache capacity and eviction;
- D0–D3 latency budgets;
- maximum admitted shadow models;
- operational retry counts;
- throughput targets;
- mutation-risk budgets;
- final target quotas and release volume;
- production key-management topology.

## 13. Claim boundary

Passing the v0.5 contract validator establishes schema, canonical-byte, digest-domain, selected cross-field, and frozen-policy consistency. It does not establish implementation correctness under all hardware failures, cryptographic key validity, real-world dependency completeness, external truth, planner completeness, model learning, production safety, or release-scale readiness.
