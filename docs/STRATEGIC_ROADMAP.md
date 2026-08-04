# CSD Foundry Strategic Roadmap

**Status:** Active program roadmap  
**Version:** 1.2  
**Date:** 2026-08-04  
**Approved:** 2026-08-04  
**Approval PR:** #62  
**Approval commit:** `7cd16463eee6bcc4f815aaee81f9eef6b8d0d760`  
**Governing architecture:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md`  
**Distributional doctrine:** `docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md`

## 1. Strategic objective

Build CSD Foundry in two successive stages:

1. complete CSD as a verifier-backed, structurally assured, distributionally governed cognition-data manufacturing and runtime-governance domain; and
2. extract the reusable platform boundaries required for multi-domain, oracle-federated, distributionally assured, and governed open-ended reasoning.

The immediate objective remains to execute governed CSD semantics, synthesize deterministic trajectories, challenge declared models without claiming external truth, quarantine invalidated assets, compile governed releases, and produce multiple training and evaluation products from one verified episode.

The longer-term platform objective is:

> A proof-carrying cognition manufacturing and governance platform that combines bounded executable semantics, external specialist oracles, empirical evidence, adjudicated processes, governed exploration, and distributionally assured cognition manufacturing while preserving an exact claim boundary for every material result.

The platform charter is normative for strategic direction and constitutional boundaries. `docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md` defines the approved subsystem doctrine and initial contract model. This roadmap remains normative for sequencing and release gates. Exact syntax, schemas, algorithms, model choices, thresholds, quotas, and deployment topology remain versioned implementation decisions.

The governing quality model is:

```text
Foundry quality
=
Oracle integrity
× Structural assurance
× Distributional assurance
```

No plane substitutes for another.

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

The repository now contains approved architecture documents for Distributional Assurance, but it has not implemented their executable contracts or empirical gates.

The repository has not yet completed:

- substantive governed registries;
- a substantive disposition oracle;
- synchronous quarantine eligibility;
- the committed M-03/M-15 governed vertical slice;
- event-triggered release and promotion;
- complete trajectory planning and construction;
- structural canonicalization and holdouts;
- executable Distributional Assurance schemas, validators, contracts, contrasts, or reports;
- a canonical Verified Cognition Episode and data compilers;
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
Phase 5   Prove the committed M-03 / M-15 governed vertical slice
Phase 6   Implement event-triggered release and promotion
Phase 7   Build performance harness and constraint-valid synthesis
Phase 8   Add structural and distributional assurance
Phase 9   Build Verified Cognition Episode and data compilers
Phase 10  Run the empirical model-training pilot
Phase 11  Freeze scale policies and compile the governed corpus
Phase 12  Deploy runtime governance and failure/distribution-gap harvesting

Platform extraction and breadth
Phase 13  Extract the domain-neutral microkernel and make CSD the first domain pack
Phase 14  Implement CognitionDL and the minimal Domain Entry Compiler
Phase 15  Implement the Reasoning ABI, assurance classes, and cross-domain composition
Phase 16  Prove a second domain and one cross-domain governed decision
Phase 17  Implement the governed exploration plane and Open Reasoning Episode
Phase 18  Connect domain and distribution gaps to progressive formalization
```

Phases 13–18 must not interrupt completion of the governed CSD vertical slice. New v0.5 work should avoid unnecessary CSD-specific coupling where the domain-neutral boundary is already clear, but premature refactoring is prohibited.

Distributional Assurance implementation belongs in Phases 7–12. Its documentation work may proceed earlier, but its executable work may not displace Phases 3–6.

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

### Gate C1 — Semantic synthesis readiness

Proceed to structural and distributional assurance only after:

- joint semantic coverage planning is complete;
- constraint-valid state and event construction is executable;
- complete semantic and disposition rollout is available;
- failed attempts produce typed rejection evidence;
- search exhaustion remains distinct from infeasibility;
- accepted trajectories replay deterministically.

### Gate C2 — Structural readiness

Proceed to the empirical model pilot only after:

- state, basis, dependency, event, assumption, disposition, and trajectory structures are canonicalized;
- train, validation, and test splits are structurally isolated;
- severity-aware mutation gates pass;
- right-answer/wrong-basis defects are represented and killed;
- structural holdout identities are frozen and reproducible.

### Gate C3 — Distributional readiness

Proceed to the empirical model pilot only after:

- a versioned descriptor ontology and distribution contract exist;
- required marginal, pairwise, selected three-way, and risk-selected higher-order cells are resolved;
- causal invariance, sensitivity, information-removal, and failure/repair families are compiled;
- typed failure ecology and minimal-repair conformance vectors pass;
- generating-process and recursive-ancestry provenance is complete;
- filter stages emit before-and-after coverage loss;
- required rare cells remain present or carry approved exceptions;
- distributional holdouts remain isolated;
- no unresolved critical distributional gap remains.

### Gate D — Scale authorized

Proceed to release-scale generation only after the controlled model pilot demonstrates:

- structural-holdout improvement;
- reduced forbidden inference;
- controlled abstention and over-conservatism;
- causal invariance consistency;
- counterfactual sensitivity correctness;
- ambiguity handling with bounded missed and unnecessary clarification;
- failure localization and minimal-repair fidelity;
- reduced right-answer/wrong-basis defects;
- independent source, process, discourse, tool, temporal, and structural transfer where declared;
- rare-cell and worst-group retention;
- actual optimizer exposure consistent with the approved contract;
- acceptable verified-episode economics;
- reproducible results;
- zero unresolved critical mutation escapes.

Training loss, aggregate accuracy, row count, or one scalar entropy score cannot authorize scale.

### Gate E — Runtime deployment authorized

Deploy runtime governance only after deterministic receipts, escalation ownership, quarantine, historical reconstruction, incident replay, and distribution-gap capture pass production-like fault testing.

### Gate F — Multi-domain platform architecture proven

Proceed to broad domain expansion only after:

- CSD operates as a versioned domain pack over a domain-neutral microkernel;
- a second domain is compiled through the domain-definition toolchain;
- at least one external oracle is integrated through the Reasoning ABI;
- one cross-domain decision is composed under assurance policy;
- domain-pack constitutional violations fail closed;
- cross-domain distributional claims remain contract-bounded.

### Gate G — Governed exploration proven

Proceed to open-ended curriculum scaling only after:

- hypotheses remain distinct from verified claims;
- epistemic type and assurance class are independently checked;
- structurally distinct hypotheses are distinguished from paraphrases;
- a selected question or test updates the hypothesis graph;
- unsupported epistemic promotion is mechanically rejected;
- outcome and search-quality evaluation are defined;
- novelty and distribution-gap discovery cannot override relevance, coherence, or claim boundaries.

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

### Phase 5 — M-03/M-15 governed vertical slice

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

Phase 5 proves the governed execution substrate. Later Distributional Assurance work reuses M-03 and M-15 to create controlled world and contrast families; it does not weaken or redefine this governed proof.

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

Build a joint semantic and distributional planning boundary across:

### Semantic and structural dimensions

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

### Scenario-world dimensions

- context family;
- actor intention;
- information state;
- ambiguity class;
- expertise relation;
- discourse form;
- tool condition;
- authority state;
- risk class;
- reasoning-policy family;
- failure topology;
- outcome class.

Implement:

- canonical scenario-world descriptors;
- generating-process and recursive-ancestry provenance;
- a versioned distribution-contract compiler;
- marginal, weighted pairwise, selected three-way, and risk-selected higher-order planning;
- separate `OBSERVED_FREQUENCY`, `RISK_WEIGHTED`, `CURRICULUM`, `TRANSFER`, `ASSURANCE`, and `EXPLORATION` quota authorities;
- explicit impossible, forbidden, unsupported, unresolved, required, and holdout dispositions.

Every accepted trajectory requires a target, constraint proof, eligibility proof, deterministic identities, validated events, complete semantic/disposition replay, process provenance, contract-cell assignment, and typed rejection evidence for failed attempts.

## 8. Phase 8 — Structural and Distributional Assurance

### 8.1 Structural assurance

Canonicalize state, basis, dependency, event, assumption, disposition, and reasoning-policy structures before split assignment.

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

### 8.2 Distributional Assurance

Implement:

- causal `INVARIANCE` families for irrelevant changes;
- causal `SENSITIVITY` families for consequential changes;
- `INFORMATION_REMOVAL` families for clarification, observation, qualification, abstention, or escalation;
- `FAILURE_AND_REPAIR` families with exact failure point, affected consequences, unaffected work, minimum legal repair, prohibited overcorrection, and post-repair conformance;
- typed failure ecology;
- conditional coverage matrices;
- source and generating-process concentration reports;
- recursive-ancestry reports;
- pre-filter and post-filter coverage-loss reports;
- rare-cell retention and explicit exception receipts;
- distributional holdouts across source, process, discourse, tool, time, organization, and selected high-order worlds.

Do not count surface paraphrases as new causal worlds. Do not maximize friction or path diversity when the governed problem has one valid efficient route.

### 8.3 Initial CSD distributional families

Use the governed M-03 and M-15 slices as the first executable Distributional Assurance families.

M-03 shall cover selected:

- complete, incomplete, contradictory, stale, and ambiguous evidence states;
- available, partial, malformed, unavailable, timeout, and unknown-commit tool conditions;
- sufficient, insufficient, and contested authority;
- novice, peer, expert, and mixed-audience interactions;
- unsupported verdict, wrong basis, right-answer/wrong-basis, missed clarification, unnecessary clarification, failed repair, and overbroad rollback cases.

M-15 shall cover selected:

- hidden-dependency changes;
- materially different alternative models;
- inappropriate irrelevance certification;
- correct conclusions from incomplete structures;
- invariant versus divergent classifications;
- unresolved external truth without unsupported promotion.

## 9. Phase 9 — Verified Cognition Episode and compilers

Make the Verified Cognition Episode the canonical CSD product.

Each episode contains linked views over one immutable identity.

### Semantic view

- initial state;
- validated events;
- semantic receipts;
- operation traces;
- final state;
- registry roots;
- shadow replays.

### Epistemic view

- active and eliminated hypotheses where applicable;
- support status;
- ambiguity class;
- permitted and forbidden commitments;
- abstention or escalation basis.

### Interaction view

- user or actor turns;
- tool calls and environment observations;
- failures, retries, fallback, escalation, and repair;
- exact execution receipts where applicable.

### Distributional view

- scenario-world digest;
- distribution-contract digest and contract-cell identities;
- causal contrast-family identity;
- failure-topology identity;
- reasoning-policy family;
- generating-process identity and ancestry;
- distributional claim boundary.

The episode also binds:

- disposition receipts;
- quarantine context;
- release eligibility;
- complete provenance.

Compile each episode into:

- SFT;
- preference pairs;
- process supervision;
- verifier-positive and verifier-negative records;
- critique and repair trajectories;
- verifiable-reward episodes;
- uncertainty and epistemic-status tasks;
- causal contrast and failure-repair benchmarks;
- distributional transfer records.

Every rendered artifact must trace to one immutable episode digest. Rendered wording cannot change semantic or distributional identity without a new episode or explicit rendering contract.

## 10. Phase 10 — Empirical model pilot

### 10.1 Training-method comparison

Compare:

1. base model;
2. SFT;
3. SFT plus preference optimization;
4. SFT plus trained verifier;
5. verifiable-reward training when stable.

### 10.2 Corpus ablations

For the selected model methods, compare controlled corpus variants:

1. current structural baseline;
2. surface-expanded baseline;
3. scenario-world contract coverage;
4. causal contrast coverage;
5. failure-and-repair coverage;
6. full Distributional Assurance vertical slice.

Control accepted episode or token volume where practical.

### 10.3 Primary semantic and structural metrics

- forbidden-inference rate;
- evidence-impact accuracy;
- basis-survival accuracy;
- restoration integrity;
- assumption-boundary accuracy;
- right-answer/wrong-basis rejection;
- verifier discrimination;
- in-distribution versus structural-holdout gap.

### 10.4 Distributional and behavioral metrics

- invariance consistency;
- counterfactual sensitivity;
- ambiguity detection;
- clarification precision;
- missed clarification;
- unnecessary clarification;
- abstention and over-abstention;
- failure localization;
- minimal-repair fidelity;
- preservation of unaffected valid work;
- tool recovery and escalation;
- unseen-world transfer;
- leave-source-out and leave-process-out transfer;
- temporal and tool-environment transfer;
- worst-group and rare-cell performance;
- clean-case regression.

### 10.5 Economics and exposure

- cost per accepted episode;
- token and tool-call cost;
- retry and branching overhead;
- planned versus actual training mixture;
- cumulative optimizer exposure by contract cell, source, process, failure, and contrast family;
- checkpoint retention and forgetting.

Do not authorize scale from training loss, aggregate accuracy, output style, corpus inclusion, or one diversity score alone.

## 11. Phases 11–12 — Governed scale and runtime loop

### Phase 11 — Measured scale-policy freeze

After pilot evidence, freeze only the policies justified by measurements:

- performance SLOs;
- retry budgets;
- exact-enumeration limits;
- cache and replay policy;
- mutation-risk thresholds;
- distribution-contract quotas;
- source and generator concentration limits;
- recursive-ancestry limits;
- rare-cell floors;
- filter-loss thresholds;
- causal contrast and transfer thresholds;
- regression tolerances;
- release volume.

Compile the governed corpus only after Gates C1, C2, C3, and D pass.

### Phase 12 — Runtime governance and gap harvesting

At runtime:

```text
model proposal
  → structured parse
  → semantic verification
  → evidence / assumption / model resolution
  → disposition
  → permit / flag / request evidence / escalate / block
```

Runtime failures feed:

- assumption and dependency challenges;
- full replay;
- quarantine;
- mutation families;
- curriculum and retraining;
- reevaluation;
- distribution-gap records;
- new failure-topology candidates;
- previously unseen high-order world combinations;
- temporal-shift and tool-drift cases;
- distribution-contract revision proposals.

Runtime observations do not enter training automatically. They require privacy, provenance, semantic, disposition, and release governance.

## 12. Phases 13–16 — Extract the multi-domain platform

### Phase 13 — Microkernel and CSD domain pack

Separate:

```text
domain-neutral governance microkernel
        +
CSD domain pack
```

The microkernel owns immutable identity, evidence lifecycle, support expressions, dependencies, temporal admissibility, authority, assumptions, alternative models, disposition, quarantine, release eligibility, and provenance.

The CSD pack owns CSD states, events, invariants, policies, constructors, mutations, renderers, benchmarks, claim boundaries, and domain-specific distributional descriptors and contracts.

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
- scenario-world and causal-contrast interfaces;
- versioned domain-pack manifests.

LLMs may propose candidate doctrine or descriptors from source materials, but independent approval is required before release.

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

Cross-domain distributional claims must validate descriptor and contract compatibility and may not silently inherit broader coverage than their components support.

### Phase 16 — Second domain and composition proof

Recommended first domains:

1. software release management;
2. ML evaluation and data governance.

Prove one composed model-release decision using receipts from both domains plus promotion authority, disposition, and a bounded distribution contract.

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
- candidate doctrine gaps;
- candidate scenario worlds and distribution gaps.

Its canonical object is an Open Reasoning Episode or governed exploration graph. Every material node carries epistemic status, assumptions, evidence, provenance, and a discriminating test or explicit limitation where applicable.

Exploration never becomes verification by model agreement, novelty, or distributional rarity alone.

### Phase 18 — Formalization and distributional flywheel

Connect unsupported runtime requests and repeated gaps to structured records:

```text
unsupported request or distribution gap
→ hypotheses and candidate concepts
→ repeated gap pattern
→ candidate ontology, descriptor, rule, contrast, or failure topology
→ counterexample-guided review
→ shadow execution
→ approved formal island or distribution-contract revision
→ new domain-pack or contract version
→ verified curriculum
```

Domain breadth grows from observed demand, reusable structure, and measured gaps rather than speculative ontology expansion or indiscriminate row generation.

## 14. Workstreams

| Workstream | Responsibility |
|---|---|
| Semantic Kernel | Current CSD states, events, transitions, traces, invariants |
| Deterministic Substrate | Choice, identity, replay, execution, sharding, storage, publication |
| Reality Assurance | Evidence, assumptions, alternative models, disposition, quarantine, promotion |
| Synthesis and Data | Semantic targets, constructors, episodes, canonicalization, mutations, compilers |
| Distributional Assurance | Scenario worlds, distribution contracts, causal contrasts, failure ecology, process provenance, conditional coverage, filter-loss audits, optimizer-exposure audits, independent transfer gates |
| Learning and Evaluation | Training, verifiers, benchmarks, structural and distributional evaluation, runtime gate |
| Platform Compiler | Microkernel extraction, CognitionDL, domain packs, static analysis |
| Oracle Federation | Reasoning ABI, adapters, witness validation, assurance composition |
| Governed Exploration | Hypothesis graphs, search control, epistemic typing, delayed outcomes, gap discovery |

No workstream may silently absorb another workstream's authority. Distributional Assurance may block a distributional release claim but may not rewrite semantic state or disposition policy.

## 15. Immediate repository sequence

1. Implement evidence-unit, assumption, and alternative-model registry reducers and roots.
2. Implement the separate disposition oracle and synchronous quarantine.
3. Execute M-03 and M-15 through the committed governed pipeline.
4. Implement event-triggered release and promotion.
5. Benchmark the governed vertical slice and freeze reference pilot policies only from measurements.
6. Resume planner, constructor, rollout, semantic coverage, and structural assurance.
7. Implement the Distributional Assurance contract, causal contrast, failure ecology, provenance, and report vertical slice over M-03/M-15.
8. Extend the Verified Cognition Episode and compilers with epistemic, interaction, and distributional views.
9. Run controlled corpus ablations and the empirical model pilot before authorizing release-scale generation.
10. Freeze scale policies only from semantic, structural, distributional, transfer, and economic evidence.
11. After the governed CSD vertical slice, extract the domain-neutral microkernel and make CSD the first domain pack.
12. Implement the minimal domain compiler and Reasoning ABI.
13. Prove one second domain and one cross-domain composition.
14. Implement a minimal governed exploration vertical slice.

## 16. Explicit deferrals

Do not implement prematurely:

- replay pruning without a mechanically verified relevance certificate;
- approximate cut sets without measurements;
- release compilation on every tick;
- mutable assumption contents inside semantic state;
- high-assurance gating from unverified evidence or models;
- search exhaustion as infeasibility;
- raw row expansion without executable semantic, structural, or behaviorally consequential distributional coverage;
- a universal ontology or universal distributional taxonomy;
- LLM judging presented as exact verification;
- one scalar entropy score as sufficient assurance;
- fixed universal human/synthetic ratios;
- uncontrolled or non-replayable fault injection;
- model architecture or loss changes before corpus, sampling, and evaluation causes are isolated;
- unrestricted online weight adaptation from deployment interactions;
- broad multi-domain expansion before the microkernel, pack, ABI, and assurance contracts are proven;
- open-ended curriculum scaling before epistemic-promotion failures are mechanically detectable.

## 17. Strategic position

The program has three successive milestones:

> **Milestone A — Complete governed CSD execution.**

> **Milestone B — Scale semantically valid, structurally assured, distributionally governed cognition-episode manufacturing and prove learning value.**

> **Milestone C — Extract the multi-domain, oracle-federated, distributionally assured, governed-exploration platform.**

This ordering protects deterministic replay, semantic/disposition separation, auditable uncertainty, append-only correction, distributional claim boundaries, and exact provenance while preserving a credible path to broad reasoning coverage.
