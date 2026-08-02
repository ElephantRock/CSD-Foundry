# Foundry Platform Architecture Charter v1.0

**Status:** Proposed normative architecture charter  
**Version:** 1.0  
**Date:** 2026-08-02  
**Scope:** Project direction and constitutional boundaries  
**Implementation status:** The current CSD implementation is the first governed domain and has not yet been extracted into a domain-neutral platform.

## 1. Purpose

This charter freezes the strategic architecture required to evolve CSD Foundry from a verifier-backed CSD reasoning-data system into a proof-carrying cognition manufacturing and governance platform.

The charter is:

- **normative for project direction, authority boundaries, claim boundaries, and required architectural separation**;
- **non-normative for language syntax, exact schemas, algorithms, model choices, vendor choices, performance limits, and deployment topology**.

The purpose of the freeze is to prevent two forms of drift:

1. allowing the project to harden into a permanently CSD-specific data generator; and
2. increasing breadth by replacing verification with undifferentiated LLM judgment while continuing to describe the result as verified.

The project may change implementation details aggressively. It may not silently abandon the architectural commitments in this charter.

## 2. Platform identity

CSD Foundry is intended to become:

> **A proof-carrying cognition manufacturing and governance platform that combines bounded executable semantics, external specialist oracles, empirical evidence, adjudicated processes, and governed exploration while preserving an exact claim boundary for every material result.**

The platform must support both:

- **bounded reasoning**, where conclusions can be verified relative to an executable doctrine, formal model, deterministic process, or external oracle; and
- **open-ended reasoning**, where hypotheses, representations, plans, analogies, questions, and candidate models are explored without being silently promoted into established facts.

The governing maxim is:

> **Open at ingestion, bounded at assertion.**

The platform may ingest broad, ambiguous, incomplete, empirical, contested, or speculative material. It may assert only what the available semantics, evidence, oracle, adjudication, and assurance policy support.

## 3. Strategic architecture

The target architecture consists of four distinct substrates:

```text
Governed execution substrate
        +
Domain-compilation substrate
        +
Oracle-federation and assurance substrate
        +
Governed-exploration substrate
        ↓
Proof-carrying cognition episodes
        ↓
Training / verifier / reward / repair / benchmark products
        ↓
Runtime reasoning governance
```

These substrates cooperate but do not absorb one another's authority.

### 3.1 Governed execution substrate

Provides:

- immutable identity;
- validated-event admission;
- deterministic execution;
- atomic temporal completion;
- canonical receipts and replay;
- append-only history;
- quarantine;
- release eligibility;
- provenance and historical reconstruction.

The current CSD v0.3-v0.5 work is the first implementation of this substrate.

### 3.2 Domain-compilation substrate

Provides:

- a domain-neutral reasoning intermediate representation;
- a declarative domain-definition language;
- static analysis;
- domain-pack compilation;
- generated conformance vectors;
- generated mutation families;
- typed renderer interfaces;
- expert approval and supersession workflows.

### 3.3 Oracle-federation and assurance substrate

Provides:

- a stable Reasoning ABI;
- external oracle receipts;
- oracle identity and version governance;
- witness and counterexample validation;
- explicit assurance classes;
- assurance propagation;
- cross-domain receipt composition;
- oracle revocation and quarantine.

### 3.4 Governed-exploration substrate

Provides:

- problem framing;
- plural hypothesis generation;
- representation search;
- abductive reasoning;
- analogy generation;
- question and experiment design;
- search-budget allocation;
- hypothesis lifecycle;
- epistemic typing;
- delayed outcome feedback;
- conversion of repeated domain gaps into candidate formal islands.

Exploration outputs are candidates. They are not semantic authority.

## 4. Constitutional invariants

The following invariants are non-overridable. No domain pack, oracle adapter, model, compiler extension, exploration process, release policy, or runtime integration may weaken them silently.

### 4.1 Identity immutability

Issued evidence, assumptions, models, receipts, episodes, manifests, releases, and authoritative records are immutable. Corrections create new identities or explicit supersession records.

### 4.2 Append-only correction

Historical records remain addressable and reconstructable. Current views may change, but history may not be rewritten to make later knowledge appear original.

### 4.3 Validation before reduction

Reducers consume only accepted, committed, policy-pinned validation receipts. Raw inputs and rejected inputs do not enter authoritative semantic reduction.

### 4.4 Atomic temporal completion

No consumer may observe a partially completed logical transition. A failed projection does not advance committed time. Successor completion must be no-clobber and historically reconstructable.

### 4.5 Semantic/disposition separation

Operational disposition may permit, flag, hold, escalate, quarantine, or block use. It may not establish, replace, or rewrite a substantive semantic conclusion.

### 4.6 Exploration/promotion separation

A hypothesis, analogy, plan, candidate model, heuristic judgment, or model-generated critique is not an established claim merely because it is plausible, fluent, novel, or preferred by another model.

### 4.7 Explicit assurance and epistemic status

Every material conclusion must declare:

- its epistemic type;
- its oracle or evidence class;
- its decision-critical assumptions;
- its provenance;
- its limitations;
- the maximum claim it permits.

### 4.8 Assumption visibility

Decision-critical assumptions and dependencies must be explicit, versioned, challengeable, and historically traceable. Missing edges may not be treated as proven independence.

### 4.9 Conservative alternative-model replay

Every material primary/shadow model difference requires full replay until irrelevance can be mechanically certified. Primary-model structure cannot certify its own completeness.

### 4.10 Quarantine

When an authoritative basis, assumption, oracle, validator, domain pack, dependency, or policy is invalidated, dependent current use must fail closed at the eligibility layer before asynchronous impact materialization completes.

### 4.11 Provenance closure

Every promoted artifact must trace to immutable inputs, semantic or assurance receipts, applicable policies, compiler and oracle versions, and release eligibility evidence.

### 4.12 Claim-boundary enforcement

Internal consistency does not establish external truth. Simulation does not establish real-world outcome. Expert adjudication does not become mechanical proof. LLM judgment does not become verified truth. The platform must preserve these distinctions in data, APIs, training products, and user-facing outputs.

## 5. Microkernel and domain-pack boundary

CSD must become the first domain pack, not the universal ontology.

### 5.1 Domain-neutral microkernel responsibilities

The microkernel owns only cross-domain constitutional mechanisms and primitives:

- immutable entities and identities;
- evidence lifecycle;
- support or basis expressions;
- dependencies;
- claims and current support status;
- temporal admissibility;
- authority and approval;
- assumptions;
- alternative models;
- invalidation and reassessment;
- append-only history;
- disposition;
- quarantine;
- release eligibility;
- receipt and provenance infrastructure.

### 5.2 Domain-pack responsibilities

A domain pack supplies what varies:

- domain vocabulary;
- domain state schemas;
- domain event schemas;
- substantive invariants;
- authority policies;
- temporal policies;
- external-oracle adapters;
- constructors;
- mutation families;
- renderers;
- benchmarks;
- claim boundaries;
- release policy constraints.

### 5.3 Non-overridable microkernel rules

Domain packs may specialize substantive doctrine but may not override the constitutional invariants in Section 4.

## 6. Domain compilation contract

The project shall provide a versioned declarative domain-definition mechanism, provisionally named `CognitionDL`.

The exact syntax is not frozen by this charter. The following capabilities are required:

- typed entities, propositions, evidence, support expressions, states, claims, and events;
- explicit dependency, authority, temporal, and assumption semantics;
- unsupported-scope declarations;
- external-oracle declarations;
- composition contracts;
- claim boundaries;
- versioned and immutable domain-pack manifests.

The compiler must be capable of generating or validating:

- runtime types;
- canonical serialization;
- transition reducers;
- invariant checks;
- valid-state and event constructors;
- model graders;
- invariant-targeted mutations;
- conformance vectors;
- structural fingerprints;
- episode interfaces;
- rendering interfaces.

The compiler must perform static analysis for at least:

- contradictory invariants;
- nondeterministic transitions;
- unreachable states;
- missing authority paths;
- missing restoration paths;
- ambiguous support semantics;
- history-destructive transitions;
- circular dependencies;
- rules without independent tests;
- invalid assurance promotion.

LLMs may assist source extraction and candidate doctrine generation. They may not become the final doctrine authority.

## 7. Oracle and assurance contract

The platform shall define a stable Reasoning ABI for specialist systems including:

- theorem provers;
- SAT and SMT solvers;
- compilers and test runners;
- model checkers;
- deterministic simulators;
- numerical and statistical systems;
- database and graph engines;
- policy engines;
- structured expert-adjudication systems;
- heterogeneous model-review systems.

An oracle receipt must bind at least:

- oracle identity and version;
- execution environment or policy identity;
- input digest;
- evaluated claim;
- result;
- witness, counterexample, or evidence reference where applicable;
- assumptions;
- limitations;
- temporal validity;
- canonical receipt identity.

The platform shall distinguish assurance classes such as:

- exact mechanical result;
- deterministic model-relative result;
- constrained empirical support;
- accepted adjudication;
- heuristic candidate;
- unassessed material.

The exact names and numbering remain versioned implementation details.

A composite result may not silently inherit stronger assurance than its decision-critical dependencies permit. The project must implement a formal assurance-propagation and composition policy before high-assurance cross-domain releases.

## 8. Formal islands and cross-domain composition

The platform shall not require an entire domain to be formalizable.

A broad task may contain:

```text
verified core
+ model-relative shell
+ empirical evidence
+ contested interpretation
+ unresolved assumptions
+ operational disposition
```

Each component retains its own epistemic and assurance type.

Cross-domain decisions must be composed through typed receipts rather than a universal ontology. Composition must validate:

- identity alignment;
- scope compatibility;
- temporal compatibility;
- schema and pack versions;
- authority boundaries;
- assumption overlap;
- dependency cycles;
- disposition conflicts;
- assurance degradation;
- veto and precedence policy.

Breadth is achieved through composable bounded domains, not by making one kernel semantically universal.

## 9. Governed exploration contract

Open-ended reasoning requires a separate exploration plane.

The exploration plane may generate:

- problem interpretations;
- hypotheses;
- causal models;
- alternative representations;
- candidate plans;
- analogies;
- questions;
- experiments;
- candidate oracles;
- candidate doctrine and domain gaps.

Its canonical product is a governed exploration or Open Reasoning Episode containing at least:

- problem statement and interpretations;
- known constraints and unknowns;
- candidate representations;
- plural hypotheses;
- supporting and challenging evidence;
- assumptions;
- discriminating predictions or tests;
- oracle routes;
- unresolved disagreement;
- selected next information action;
- epistemic status and claim boundaries;
- provenance and lifecycle.

The platform must distinguish epistemic states such as:

- entailed;
- model-relative;
- empirically supported;
- adjudicated;
- plausible;
- speculative;
- contested;
- underdetermined;
- refuted;
- unknown.

The exact vocabulary remains versioned, but the distinctions may not be collapsed into one confidence number.

A broad exploration process may be rewarded for novelty, diversity, analogy, or search efficiency only when relevance, coherence, constraint compatibility, and epistemic labeling remain intact.

## 10. Training-product contract

The primary product is a proof-carrying cognition episode, not a rendered JSONL row.

Depending on episode type and assurance, the platform may compile:

- supervised fine-tuning records;
- preference pairs;
- process supervision;
- verifier-positive and verifier-negative records;
- critique and repair trajectories;
- verifiable-reward episodes;
- uncertainty and epistemic-classification tasks;
- oracle-selection tasks;
- question and experiment-selection tasks;
- structural benchmarks.

Every derivative artifact must trace to one immutable episode identity and retain its assurance and claim boundary.

Rendered prose is never the semantic authority.

## 11. Breadth strategy

The project shall pursue breadth through:

- reusable reasoning archetypes;
- domain-family kernels;
- domain packs;
- external-oracle adapters;
- formal islands;
- typed cross-domain composition;
- modular models and routing;
- progressive formalization;
- domain-gap and runtime-failure harvesting.

The project shall not measure breadth primarily by domain count or rendered row count.

Preferred breadth metrics include:

- verified reasoning archetypes;
- oracle classes and adapters integrated;
- composition depth;
- percentage of decisions decomposable into governed subclaims;
- cross-domain transfer;
- cost and expert effort to onboard a new pack;
- formal-island expansion over time;
- unsupported-assertion and assurance-promotion error rates.

## 12. Required proof sequence

The architecture is not considered demonstrated until the following sequence works end to end:

```text
CSD extracted as a domain pack
→ second domain compiled through the domain-definition toolchain
→ external oracle receipt accepted through the Reasoning ABI
→ cross-domain result composed under assurance policy
→ open hypothesis represented separately from verified claims
→ epistemic promotion enforced
→ cognition episodes compiled into training and evaluation products
→ empirical learning value demonstrated
```

A recommended first integrated demonstration is a model-release decision combining:

- software build and test evidence;
- ML dataset and benchmark governance;
- promotion authority;
- open hypotheses about unresolved quality or risk;
- explicit release disposition.

## 13. Relationship to the current roadmap

The current v0.5 governed-execution work remains the immediate priority and is not discarded.

The sequence is:

1. complete the first governed CSD vertical slice;
2. preserve the implemented event, temporal, registry, disposition, quarantine, and release boundaries;
3. extract the domain-neutral microkernel boundary;
4. make CSD the first domain pack;
5. implement the minimal domain compiler and Reasoning ABI;
6. prove a second domain and one cross-domain composition;
7. add the governed-exploration vertical slice;
8. connect domain-gap harvesting to progressive formalization.

New v0.5 registry and disposition implementations should avoid unnecessary CSD-specific coupling where the required abstraction is already clear, but this charter does not require premature refactoring before the CSD governed vertical slice is complete.

## 14. Explicit non-goals and prohibited shortcuts

The project shall not:

- build a universal ontology;
- describe LLM judging as exact verification;
- let domain packs override constitutional invariants;
- formalize inherently subjective outcomes as objective truth;
- rebuild mature specialist solvers without a compelling platform-specific need;
- treat internal consistency as proof of world-model completeness;
- treat simulation as proof of real-world outcome;
- treat search exhaustion as infeasibility;
- expand rendered rows without increasing semantic or exploratory coverage;
- merge exploration and verification into one untyped reasoning trace;
- authorize release-scale breadth from training loss alone.

## 15. Change procedure

This charter is append-only in project history.

A change to its normative commitments requires:

1. a numbered architecture proposal;
2. the exact current clause being changed;
3. rationale and motivating evidence;
4. safety and claim-boundary analysis;
5. compatibility and migration analysis;
6. impact on released artifacts and domain packs;
7. explicit approval;
8. publication as a new charter version.

Implementation details may change through ordinary specifications and pull requests without a charter revision, provided the constitutional commitments remain intact.

## 16. Claim boundary

This charter defines project direction. It does not establish that:

- the domain-neutral microkernel has been extracted;
- CognitionDL has been designed or implemented;
- external oracle adapters are trustworthy;
- assurance propagation is complete;
- cross-domain composition is correct;
- open-ended reasoning has improved;
- any trained model generalizes;
- any world model is complete;
- the platform is production safe.

Those remain implementation and empirical claims requiring executable evidence.
