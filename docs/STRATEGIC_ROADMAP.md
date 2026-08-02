# CSD Foundry Strategic Roadmap

**Status:** Proposed program roadmap  
**Version:** 1.1  
**Date:** 2026-08-02  
**Governing architecture:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.0.md`

## 1. Strategic objective

Build CSD Foundry in two successive stages:

1. complete CSD as a verifier-backed cognition-data manufacturing and runtime-governance domain; and
2. extract the reusable platform boundaries required for multi-domain, oracle-federated, and governed open-ended reasoning.

The immediate objective remains to execute governed CSD semantics, synthesize deterministic trajectories, challenge declared models without claiming external truth, quarantine invalidated assets, compile governed releases, and produce multiple training and evaluation products from one verified episode.

The longer-term platform objective is:

> A proof-carrying cognition manufacturing and governance platform that combines bounded executable semantics, external specialist oracles, empirical evidence, adjudicated processes, and governed exploration while preserving an exact claim boundary for every material result.

The platform charter is normative for strategic direction and constitutional boundaries. This roadmap remains normative for sequencing and release gates. Exact syntax, schemas, algorithms, model choices, and deployment topology remain versioned implementation decisions.

## 2. Current position

The repository has completed:

- executable CSD semantics and independent invariant checks;
- manifest-complete coverage of the 21 seed scenarios;
- deterministic temporal and governance semantics;
- deterministic choice, identity, replay, execution inventory, publication, reconciliation, and sealing;
- v0.5 foundational governance contracts and conformance vectors;
- v0.5-A canonicalization and typed contract objects;
- v0.5-B `ValidatedEvent` admission and failure receipts;
- v0.5-C atomic temporal claim, ordered projections, failure-no-advance, crash recovery, and committed-head visibility.

The current implementation frontier is v0.5-D: substantive evidence-unit, assumption, and alternative-model registries.

The repository has not yet completed:

- substantive governed registries;
- a substantive disposition oracle;
- synchronous quarantine eligibility;
- the committed M-03/M-15 vertical slice;
- event-triggered release and promotion;
- complete trajectory planning and construction;
- structural canonicalization and holdouts;
- the Verified Cognition Episode and data compilers;
- an empirical model-training pilot;
- a domain-neutral microkernel/domain-pack split;
- CognitionDL or the Domain Entry Compiler;
- the Reasoning ABI and oracle federation;
- governed open-ended exploration.

## 3. Program sequence

```text
Completed
Phase 0   Freeze foundational v0.5 contracts
Phase 1   Complete v0.4 streaming reconciliation and canonical merge
Phase 2A  Implement v0.5 canonicalization and typed contracts
Phase 2B  Implement validated-event admission
Phase 2C  Implement atomic temporal claim and completion

Current CSD milestone
Phase 3   Implement evidence, assumption, and alternative-model registries
Phase 4   Implement the separate disposition oracle and quarantine
Phase 5   Prove the committed M-03 / M-15 vertical slice
Phase 6   Implement event-triggered release and promotion
Phase 7   Build performance harness and constraint-valid synthesis
Phase 8   Add structural canonicalization, holdouts, and mutation assurance
Phase 9   Build Verified Cognition Episode and data compilers
Phase 10  Run the empirical model-training pilot
Phase 11  Freeze scale policies and compile the governed corpus
Phase 12  Deploy runtime governance and failure harvesting

Platform extraction and breadth
Phase 13  Extract the domain-neutral microkernel and make CSD the first domain pack
Phase 14  Implement CognitionDL and the minimal Domain Entry Compiler
Phase 15  Implement the Reasoning ABI, assurance classes, and cross-domain composition
Phase 16  Prove a second domain and one cross-domain governed decision
Phase 17  Implement the governed exploration plane and Open Reasoning Episode
Phase 18  Connect domain-gap harvesting to progressive formalization
```

Phases 13–18 must not interrupt completion of the governed CSD vertical slice. New v0.5 work should avoid unnecessary CSD-specific coupling where the domain-neutral boundary is already clear, but premature refactoring is prohibited.

## 4. Program gates

### Gate A — Deterministic substrate complete

**Status: passed.**

Shard-independent reconciliation, full replay, and canonical publication produce byte-identical semantic output across approved 1/2/7 shard topologies and bounded crash/retry schedules.

### Gate B1 — Admission and temporal authority complete

**Status: passed for the single-host reference implementation.**

- `ValidatedEvent` is the sole temporal coordinator input;
- concurrent successor claims have exactly one winner;
- failed projection leaves the committed head unchanged;
- prepared completion is not visible until committed-head publication;
- recovery is idempotent;
- release compilation is excluded from ordinary clock ticks.

This does not establish production key management, distributed consensus, or multi-host lease safety.

### Gate B2 — Governance vertical slice complete

Proceed to synthesis scaling only after:

- substantive registry reducers and roots are implemented;
- disposition cites a committed semantic receipt and cannot rewrite semantic state;
- every material graph difference triggers full shadow replay;
- invalidation produces immediate quarantine;
- historical reconstruction remains available;
- M-03 and M-15 pass end to end;
- promotion uses current evidence and creates a new manifest.

### Gate C — Synthesis pilot ready

Proceed to training only after joint coverage planning, constraint-valid state/event construction, complete oracle rollout, structural canonicalization, split isolation, and severity-aware mutation gates pass.

### Gate D — Scale authorized

Proceed to release-scale generation only after the model pilot demonstrates:

- structural-holdout improvement;
- reduced forbidden inference;
- controlled abstention;
- acceptable verified-episode economics;
- reproducible results;
- zero unresolved critical mutation escapes.

### Gate E — Runtime deployment authorized

Deploy runtime governance only after deterministic receipts, escalation ownership, quarantine, historical reconstruction, and incident replay pass production-like fault testing.

### Gate F — Multi-domain platform architecture proven

Proceed to broad domain expansion only after:

- CSD operates as a versioned domain pack over a domain-neutral microkernel;
- a second domain is compiled through the domain-definition toolchain;
- at least one external oracle is integrated through the Reasoning ABI;
- one cross-domain decision is composed under assurance policy;
- domain-pack constitutional violations fail closed.

### Gate G — Governed exploration proven

Proceed to open-ended curriculum scaling only after:

- hypotheses remain distinct from verified claims;
- epistemic type and assurance class are independently checked;
- structurally distinct hypotheses are distinguished from paraphrases;
- a selected question or test updates the hypothesis graph;
- unsupported epistemic promotion is mechanically rejected;
- outcome and search-quality evaluation are defined.

## 5. Completed foundation

### Phase 0 — Foundational v0.5 contract freeze

Frozen:

- identity and authority boundaries;
- canonicalization;
- event admission;
- temporal ordering;
- projection receipts;
- registry events;
- disposition;
- quarantine;
- release and promotion;
- rejection codes;
- APIs and conformance vectors.

Existing v0.1-v0.4 bytes remain immutable. Empirical thresholds and optimizations remain unfrozen.

### Phase 1 — v0.4 deterministic execution substrate

Completed:

- bounded streaming merge;
- global lowest-valid-attempt resolution;
- independent `FULL_REPLAY`;
- conflict escalation;
- separate semantic and run-evidence manifests;
- no-clobber final publication;
- 1/2/7-shard invariance.

### Phases 2A–2C — Governed admission and temporal completion

Completed:

- executable v0.5 canonicalization;
- immutable typed contracts;
- accepted and rejected event-admission receipts;
- committed-context and policy pinning;
- compare-and-append temporal claims;
- mandatory projection ordering;
- failure receipts without sequence advancement;
- prepared-completion recovery;
- current visibility only through committed-head state.

Registry, disposition, and quarantine artifacts in v0.5-C are typed orchestration commitments only. Their substantive behavior remains ahead.

## 6. Phases 3–6 — Complete governed CSD execution

### Phase 3 — Governed registries

Implement event-sourced registries for:

- evidence units;
- assumptions;
- alternative models.

Each registry must be deterministic, append-only, digest-rooted, reconstructable, and versioned. It must preserve provenance, authority, temporal validity, challenge state, and historical lifecycle.

Evidence admission must represent scope, lineage, correlation, independence, expiry, and separation status. Assumptions must be falsifiable, expirable, and linked to decision impact. Alternative models must carry material difference, scope, challenge basis, and admission status.

### Phase 4 — Disposition and quarantine

Implement a structurally separate `DispositionOracle` that may:

- document and proceed;
- flag and proceed;
- request evidence;
- escalate and hold;
- block;
- exclude from release.

It may not establish or replace a substantive CSD verdict.

Implement synchronous quarantine epochs and `may_use_asset()` so known-questionable assets become immediately ineligible while exact impact materialization and replay continue asynchronously.

### Phase 5 — M-03/M-15 vertical slice

Use M-03 to prove:

```text
validated clock event
→ atomic successor claim
→ evidence expiry
→ basis recomputation
→ semantic projection
→ registry updates
→ disposition
→ quarantine
→ committed completion
```

Use M-15 to prove:

```text
primary graph
+ materially different shadow graph
→ full replay of both
→ invariant or divergent classification
→ disposition change without external-truth assertion
```

### Phase 6 — Event-triggered release and promotion

Release compilation runs only after explicit requests against completed snapshots.

Promotion must:

- use evidence current at the request snapshot;
- rerun required assurance checks;
- reject quarantined assets;
- enforce maximum reuse class externally;
- create a new immutable release identity and manifest;
- preserve earlier releases unchanged.

## 7. Phase 7 — Performance and constraint-valid synthesis

Measure before freezing policy. Benchmark:

- assumption counts;
- full primary/shadow replay;
- registry reduction;
- temporal commit latency;
- disposition by class;
- quarantine indexes;
- release compilation;
- verified-episode cost.

Build a joint coverage planner across:

- rule composition;
- state topology;
- basis topology;
- dependency structure;
- alternative-basis count;
- event depth;
- temporal and governance composition;
- authority path;
- decision class;
- assumption fragility;
- mutation family.

Every accepted trajectory requires a target, constraint proof, eligibility proof, deterministic identities, validated events, complete semantic/disposition replay, and typed rejection evidence for failed attempts.

## 8. Phase 8 — Structural assurance

Canonicalize state, basis, dependency, event, assumption, and disposition structures before split assignment.

Hold out:

- topology;
- rule composition;
- event depth;
- basis-survival form;
- hidden-dependency pattern;
- temporal/governance path;
- assumption and disposition family.

Run deterministic and stochastic mutation campaigns across semantic decisions, evidence impact, basis recomputation, history, authority, admission, graphs, disposition, quarantine, promotion, and release eligibility.

Search exhaustion remains unresolved and never becomes infeasibility without a machine-checkable witness.

## 9. Phase 9 — Verified Cognition Episode and compilers

Make the Verified Cognition Episode the canonical CSD product. It contains:

- initial state;
- validated events;
- semantic receipts;
- operation traces;
- final state;
- registry roots;
- shadow replays;
- disposition receipts;
- quarantine context;
- release eligibility;
- provenance.

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

Compare:

1. base model;
2. SFT;
3. SFT plus preference optimization;
4. SFT plus trained verifier;
5. verifiable-reward training when stable.

Primary metrics:

- forbidden-inference rate;
- evidence-impact accuracy;
- basis-survival accuracy;
- restoration integrity;
- assumption-boundary accuracy;
- repair success;
- verifier discrimination;
- abstention and over-conservatism;
- in-distribution versus structural-holdout gap;
- cost per accepted episode.

Do not authorize scale from training loss alone.

## 11. Phases 11–12 — Governed scale and runtime loop

After pilot evidence, freeze:

- performance SLOs;
- retry budgets;
- exact-enumeration limits;
- cache and replay policy;
- mutation-risk thresholds;
- quotas;
- release volume.

At runtime:

```text
model proposal
  → structured parse
  → semantic verification
  → evidence / assumption / model resolution
  → disposition
  → permit / flag / request evidence / escalate / block
```

Runtime failures feed assumption and dependency challenges, replay, quarantine, mutations, curriculum, retraining, and reevaluation.

## 12. Phases 13–16 — Extract the multi-domain platform

### Phase 13 — Microkernel and CSD domain pack

Separate:

```text
domain-neutral governance microkernel
        +
CSD domain pack
```

The microkernel owns immutable identity, evidence lifecycle, support expressions, dependencies, temporal admissibility, authority, assumptions, alternative models, disposition, quarantine, release eligibility, and provenance.

The CSD pack owns CSD states, events, invariants, policies, constructors, mutations, renderers, benchmarks, and claim boundaries.

### Phase 14 — CognitionDL and Domain Entry Compiler

Implement a minimal declarative domain-definition toolchain with:

- typed domain primitives;
- transition and invariant declarations;
- authority and temporal policies;
- unsupported-scope declarations;
- oracle declarations;
- static analysis;
- generated conformance vectors;
- generated basic mutation families;
- typed renderer interfaces;
- versioned domain-pack manifests.

LLMs may propose candidate doctrine from source materials, but independent approval is required before release.

### Phase 15 — Reasoning ABI and assurance composition

Implement:

- oracle receipt schema;
- oracle identity and version pinning;
- environment and witness commitments;
- assurance classes;
- oracle revocation;
- assurance propagation;
- cross-domain composition receipts.

Exact tools, deterministic models, empirical systems, adjudicated processes, and heuristic models must retain distinct permitted claims.

### Phase 16 — Second domain and composition proof

Recommended first domains:

1. software release management;
2. ML evaluation and data governance.

Prove one composed model-release decision using receipts from both domains plus promotion authority and disposition.

## 13. Phases 17–18 — Governed open-ended reasoning

### Phase 17 — Exploration plane

Implement a separate exploration plane that can produce:

- problem interpretations;
- plural hypotheses;
- candidate representations;
- analogies;
- plans;
- questions;
- experiments;
- candidate oracles;
- candidate doctrine gaps.

Its canonical object is an Open Reasoning Episode or governed exploration graph. Every material node carries epistemic status, assumptions, evidence, provenance, and a discriminating test or explicit limitation where applicable.

Exploration never becomes verification by model agreement alone.

### Phase 18 — Formalization flywheel

Connect unsupported runtime requests to structured domain-gap records:

```text
unsupported request
→ hypotheses and candidate concepts
→ repeated gap pattern
→ candidate ontology or rule
→ counterexample-guided review
→ shadow execution
→ approved formal island
→ new domain-pack version
→ verified curriculum
```

Domain breadth grows from observed demand and reusable structure rather than speculative ontology expansion.

## 14. Workstreams

| Workstream | Responsibility |
|---|---|
| Semantic Kernel | Current CSD states, events, transitions, traces, invariants |
| Deterministic Substrate | Choice, identity, replay, execution, sharding, storage, publication |
| Reality Assurance | Evidence, assumptions, alternative models, disposition, quarantine, promotion |
| Synthesis and Data | Coverage, constructors, episodes, canonicalization, holdouts, mutations, compilers |
| Learning and Evaluation | Training, verifiers, benchmarks, structural evaluation, runtime gate |
| Platform Compiler | Microkernel extraction, CognitionDL, domain packs, static analysis |
| Oracle Federation | Reasoning ABI, adapters, witness validation, assurance composition |
| Governed Exploration | Hypothesis graphs, search control, epistemic typing, delayed outcomes |

No workstream may silently absorb another workstream's authority.

## 15. Immediate repository sequence

1. Implement evidence-unit, assumption, and alternative-model registry reducers and roots.
2. Implement the separate disposition oracle and synchronous quarantine.
3. Execute M-03 and M-15 through the committed pipeline.
4. Implement event-triggered release and promotion.
5. Benchmark the governed vertical slice and freeze pilot policies only from measurements.
6. Resume planner, constructor, rollout, structural assurance, and episode compilation.
7. Run the empirical model pilot before authorizing release-scale generation.
8. After the governed CSD vertical slice, extract the domain-neutral microkernel and make CSD the first domain pack.
9. Implement the minimal domain compiler and Reasoning ABI.
10. Prove one second domain and one cross-domain composition.
11. Implement a minimal governed exploration vertical slice.

## 16. Explicit deferrals

Do not implement prematurely:

- replay pruning without a mechanically verified relevance certificate;
- approximate cut sets without measurements;
- release compilation on every tick;
- mutable assumption contents inside semantic state;
- high-assurance gating from unverified evidence or models;
- search exhaustion as infeasibility;
- raw row expansion without executable semantic or exploratory coverage;
- a universal ontology;
- LLM judging presented as exact verification;
- broad multi-domain expansion before the microkernel, pack, ABI, and assurance contracts are proven;
- open-ended curriculum scaling before epistemic-promotion failures are mechanically detectable.

## 17. Strategic position

The program has three successive milestones:

> **Milestone A — Complete governed CSD execution.**

> **Milestone B — Scale verified cognition-episode manufacturing and prove learning value.**

> **Milestone C — Extract the multi-domain, oracle-federated, governed-exploration platform.**

This ordering protects deterministic replay, semantic/disposition separation, auditable uncertainty, append-only correction, and exact claim boundaries while preserving a credible path to broad reasoning coverage.
