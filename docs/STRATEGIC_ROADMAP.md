# CSD Foundry Strategic Roadmap

**Status:** Proposed program roadmap  
**Version:** 1.0  
**Date:** 2026-08-02

## 1. Strategic objective

Build CSD Foundry into a verifier-backed cognition-data manufacturing system that can execute governed semantics, synthesize deterministic trajectories, challenge declared models without claiming external truth, quarantine invalidated assets, compile governed releases, and produce multiple training and evaluation products from one verified episode.

The repository already has an executable CSD kernel, temporal semantics, independent invariant checks, deterministic choice and identity substrates, attempt replay, immutable execution inventories, and append-only no-clobber publication. The missing strategic layer is the governed execution boundary: validated-event admission, atomic temporal completion, Reality Assurance registries, disposition, quarantine, shadow replay, and post-snapshot release.

## 2. Program sequence

```text
Phase 0  Freeze foundational v0.5 contracts
Phase 1  Complete v0.4 streaming reconciliation and canonical merge
Phase 2  Implement validated-event admission and atomic temporal completion
Phase 3  Implement evidence, assumption, and alternative-model registries
Phase 4  Implement the separate disposition oracle
Phase 5  Prove the committed M-03 / M-15 vertical slice
Phase 6  Implement quarantine and event-triggered release/promotion
Phase 7  Build performance harness and constraint-valid synthesis
Phase 8  Add structural canonicalization, holdouts, and mutation assurance
Phase 9  Build Verified Cognition Episode and data compilers
Phase 10 Run the empirical model-training pilot
Phase 11 Freeze scale policies and compile the governed corpus
Phase 12 Deploy runtime governance and failure harvesting
```

## 3. Phase gates

### Gate A — Deterministic substrate complete

Proceed to governed execution only after shard-independent reconciliation, full replay, and canonical publication produce byte-identical semantic output across approved worker/shard topologies and crash/retry schedules.

### Gate B — Governance vertical slice complete

Proceed to synthesis scaling only after:

- `ValidatedEvent` is the sole reducer input;
- concurrent successor claims have exactly one winner;
- semantic failure leaves the clock head unchanged;
- disposition cites a committed semantic receipt and cannot rewrite semantic state;
- every graph difference triggers full shadow replay;
- invalidation produces immediate quarantine;
- ordinary clock ticks never invoke release compilation;
- promotion uses current evidence and creates a new manifest.

### Gate C — Synthesis pilot ready

Proceed to training only after joint coverage planning, constraint-valid state/event construction, complete oracle rollout, structural canonicalization, split isolation, and severity-aware mutation gates pass.

### Gate D — Scale authorized

Proceed to release-scale generation only after the model pilot demonstrates structural-holdout improvement, reduced forbidden inference, controlled abstention, acceptable verified-episode economics, and zero unresolved critical mutation escapes.

### Gate E — Runtime deployment authorized

Deploy runtime governance only after deterministic receipts, escalation ownership, quarantine, historical reconstruction, and incident replay pass production-like fault testing.

## 4. Phase 0 — Contract freeze

Freeze identity, authority, canonicalization, event admission, temporal ordering, projection receipts, registry events, disposition, quarantine, release, promotion, rejection codes, and APIs. Preserve all existing v0.1–v0.4 bytes. Do not freeze empirical thresholds or optimizations.

Exit: all schemas, policies, accepted vectors, rejected vectors, and the external validator pass in CI.

## 5. Phase 1 — Complete v0.4 deterministic substrate

Finish bounded streaming merge, global lowest-valid-attempt resolution, full independently attested replay, conflict escalation, canonical corpus ordering, separate semantic/run-evidence manifests, atomic final publication, and 1/2/7-shard invariance.

Exit: the same authorized inventory and semantic attempts produce one byte-identical semantic corpus manifest regardless of topology, order, retries, or restart schedule.

## 6. Phases 2–6 — Governed execution vertical slice

Implement:

1. raw-event validation into accepted or failure receipts;
2. atomic compare-and-append temporal claims;
3. semantic projection receipts;
4. event-sourced evidence-unit, assumption, and alternative-model registries;
5. a structurally separate disposition oracle;
6. full replay for every primary/shadow graph difference;
7. synchronous quarantine with asynchronous impact materialization;
8. event-triggered release and promotion compilation.

Use M-03 to prove expiry and atomic basis recomputation inside the committed temporal pipeline. Use M-15 to prove the hidden-dependency boundary: internal validity can survive while admitted shadow models diverge, and RAP changes disposition without asserting which model is true.

Exit: the complete M-03/M-15 pipeline is deterministic, fail-closed, historically reconstructable, and externally validated.

## 7. Phase 7 — Performance and constraint-valid synthesis

Measure before freezing policy. Benchmark assumption counts, exact cut sets, full replay, registry reductions, temporal commits, disposition by class, quarantine indexes, release compilation, and verified-episode cost.

Build a joint coverage planner across rule composition, state topology, basis topology, dependency structure, event depth, temporal/governance composition, authority path, decision class, assumption fragility, and mutation family.

Every accepted trajectory requires a target, constraint proof, eligibility proof, deterministic identities, validated events, complete semantic/disposition replay, and typed rejection evidence for failed attempts.

## 8. Phase 8 — Structural assurance

Canonicalize state, basis, dependency, event, assumption, and disposition structures before split assignment. Hold out topology, rule composition, event depth, basis-survival form, hidden-dependency pattern, and governance path.

Run deterministic and stochastic mutation campaigns across semantic decisions, evidence impact, basis recomputation, history, authority, evidence admission, graph structure, disposition, quarantine, and promotion. Search exhaustion remains unresolved and never becomes infeasibility without a machine-checkable witness.

## 9. Phase 9 — Verified Cognition Episode

Make the Verified Cognition Episode the canonical product. It contains initial state, validated events, semantic receipts, operation traces, final state, registry roots, shadow replays, dispositions, quarantine context, release eligibility, and provenance.

Compile each episode into:

- SFT;
- preference pairs;
- process supervision;
- verifier-positive and verifier-negative records;
- critique and repair trajectories;
- verifiable-reward episodes;
- benchmark records.

Every rendered artifact must trace to one immutable episode digest.

## 10. Phase 10 — Empirical model pilot

Compare a base model, SFT, SFT plus preference optimization, SFT plus verifier, and verifiable-reward training when stable.

Primary metrics:

- forbidden-inference rate;
- evidence-impact accuracy;
- basis-survival accuracy;
- restoration-integrity rate;
- assumption-boundary accuracy;
- repair success;
- verifier discrimination;
- abstention/over-conservatism;
- in-distribution versus structural-holdout gap;
- cost per accepted episode.

Do not authorize scale from training loss alone.

## 11. Phases 11–12 — Governed scale and runtime loop

After pilot evidence, freeze SLOs, retry budgets, exact-enumeration limits, cache/replay policy, mutation-risk thresholds, quotas, and release volume. Produce a reproducible governed corpus with separate semantic and operational manifests and current asset eligibility.

At runtime:

```text
model proposal
  → structured parse
  → semantic verification
  → evidence / assumption / model resolution
  → disposition
  → permit / flag / escalate / block
```

Runtime failures feed back into assumption/dependency challenges, replay, quarantine, mutations, curriculum, retraining, and reevaluation.

## 12. Workstreams

| Workstream | Responsibility |
|---|---|
| Semantic Kernel | CSD states, events, transitions, traces, invariants |
| Deterministic Substrate | choices, identities, replay, execution, sharding, storage, publication |
| Reality Assurance | evidence units, assumptions, alternative models, disposition, quarantine, promotion |
| Synthesis and Data | coverage, constructors, episodes, canonicalization, holdouts, mutations, compilers |
| Learning and Evaluation | training, verifiers, benchmarks, structural evaluation, runtime gate |

No workstream may silently absorb another workstream’s authority.

## 13. Immediate repository sequence

1. Merge the v0.5 foundational contract freeze.
2. Complete v0.4 PR 2C-C streaming reconciliation and canonical merge.
3. Implement validation receipts.
4. Implement atomic temporal claim/completion.
5. Implement registry reducers and roots.
6. Implement the disposition oracle.
7. Execute M-03/M-15 through the committed pipeline.
8. Implement quarantine and post-snapshot release/promotion.
9. Benchmark and freeze pilot policies.
10. Resume planner, constructor, rollout, structural assurance, and data compilation.
11. Run the empirical model pilot before authorizing release-scale generation.

## 14. Explicit deferrals

Do not implement replay pruning without a mechanically verified relevance certificate; approximate cut sets without measurements; release compilation on every tick; mutable assumption content inside `ControlState`; D2/D3 gating from `UNVERIFIED` evidence/models; search-exhaustion-as-infeasibility; or raw row expansion without executable semantic coverage.

## 15. Strategic position

Milestone A is to prove governed execution. Milestone B is to scale verified cognition-episode manufacturing. This ordering protects deterministic replay, semantic/disposition separation, auditable uncertainty, tiered economics, and append-only correction.
