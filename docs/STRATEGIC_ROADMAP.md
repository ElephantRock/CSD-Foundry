# CSD Foundry Strategic Roadmap

**Status:** Active program roadmap upon containing-commit merge  
**Version:** 2.0  
**Date:** 2026-08-08  
**Authorization issue:** #101  
**Supersedes:** Version 1.3 upon merge  
**Repository authority:** containing merged commit  
**Governing architecture:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md`  
**Distributional doctrine:** `docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md`  
**G1 terminal record:** `docs/G1_TERMINAL_DECISION_v1.0.md`

## 1. Strategic objective

Build CSD Foundry as a proof-carrying cognition manufacturing and governance platform while separating two questions that Version 1.3 coupled too tightly:

1. **Can the platform manufacture, verify, govern, replay, quarantine, release, and use reasoning artifacts correctly?**
2. **Does a particular model-training formulation measurably improve because it consumes those artifacts?**

Version 2.0 adopts a platform-first dual-track program:

- **Track I — Verified Reasoning Infrastructure** builds and proves the executable, deterministic, structurally assured, distributionally governed platform. Track I may progress without a positive model-learning result.
- **Track L — Empirical Learning** tests prospectively specified learning hypotheses against immutable Track-I releases. Track L remains separately authorized, compute-bounded, and falsifiable.

The stronger learning-oriented product still requires both tracks to succeed. Infrastructure success does not become evidence of model improvement, and model improvement may not compensate for invalid semantics, weak provenance, structural leakage, or distributional defects.

The immediate infrastructure objective remains to execute governed CSD semantics, resolve evidence and assumptions under explicit authority, replay materially different alternative models, separate semantic conclusions from operational disposition, quarantine invalidated assets, compile governed releases, and produce immutable proof-carrying cognition episodes.

The longer-term platform objective remains:

> A proof-carrying cognition manufacturing and governance platform that combines bounded executable semantics, external specialist oracles, empirical evidence, adjudicated processes, governed exploration, and distributionally assured cognition manufacturing while preserving an exact claim boundary for every material result.

The platform charter remains normative for strategic direction, authority boundaries, claim boundaries, and constitutional invariants. `docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md` remains normative for Distributional Assurance doctrine. This roadmap is normative for sequencing and release gates. Exact syntax, schemas, algorithms, models, thresholds, quotas, and deployment topology remain versioned implementation decisions.

The governing quality model remains:

```text
Foundry quality
=
Oracle integrity
× Structural assurance
× Distributional assurance
```

No plane substitutes for another.

## 2. Roadmap decision and claim boundary

### 2.1 G1-v1 is closed, failed, and permanent history

The E1 → calibration → E2 → E3 learning-signal sequence is repository-effective and closed.

```text
E1     NO_OBSERVED_SIGNAL
E2     HARMFUL
E3     HARMFUL
G1     NOT PASSED
```

The durable terminal conclusion is:

> Under the current small paired-SFT formulation, replacing conventional synthetic label authority with executable-semantic label authority has not demonstrated a robust incremental learning benefit.

Version 2.0 does **not** weaken, relabel, supersede, reinterpret, or retry that conclusion. There is no E4 implied by this roadmap. A future learning program must begin from a materially new hypothesis and its own authorization gate.

### 2.2 Why the roadmap changes

G1 tested one model-consumable use of the infrastructure: small paired SFT over a terminal semantic-decision representation. It did not test whether the executable kernel, registry governance, alternative-model replay, disposition, quarantine, release provenance, verifier data, repair data, runtime decision gating, or proof-carrying cognition episodes have independent value.

Version 1.3 allowed a learning result to become a linear dependency for infrastructure whose correctness does not logically depend on model internalization. Version 2.0 removes that dependency without converting infrastructure progress into a learning claim.

### 2.3 Three permitted product claims

The roadmap distinguishes three increasingly strong product states.

**Verified Reasoning Infrastructure** may claim that the platform deterministically manufactures and governs proof-carrying reasoning artifacts under declared semantics, assurance, provenance, and distribution contracts.

**Governed Runtime Reasoning System** may additionally claim that model or agent proposals can be accepted, rejected, held, escalated, quarantined, or otherwise dispositioned through the executable governance boundary. Correctness does not require the proposing model to internalize CSD semantics.

**Learning-Validated Reasoning Foundry** may additionally claim measured model improvement attributable to a pinned Foundry product under a prospectively governed empirical program.

Only the third state is a learning-success claim.

## 3. Current position

The repository has completed:

- executable CSD semantics and independent invariant checks;
- manifest-complete coverage of the 21 seed scenarios;
- deterministic choice, identity, replay, execution inventory, publication, reconciliation, and sealing;
- v0.5 foundational governance contracts and conformance vectors;
- v0.5-A canonicalization and typed contract objects;
- v0.5-B `ValidatedEvent` admission and failure receipts;
- v0.5-C atomic temporal claim, ordered projections, failure-no-advance, crash recovery, and committed-head visibility;
- E0-H single-host GPU harness qualification;
- the executable-semantics artifact compiler, strict A-E response ABI, parser, protected evaluation, and sealed execution path required for G1-v1;
- repository-effective G1-v1 closure with durable E1/E2/E3 evidence and provenance correction.

The empirical record established that task acquisition is achievable under response-token-only supervision, that E2's positive Foundry differential was non-ratifiable because safety failed, and that the differential did not survive the precommitted equal safety correction in E3. No robust Foundry learning advantage was demonstrated.

The current implementation frontier remains v0.5-D and the assumption-policy read path. In particular, historical policy resolution and grant selection are not complete while a selected grant tuple can be trusted without cryptographic or mechanical binding back to its authoritative source ledger.

The repository has not yet completed:

- the remaining assumption-policy binding and historical-stability correction;
- substantive evidence-unit, assumption, and alternative-model registry reducers and roots;
- separation-of-duty execution and related governed authority checks required by later assumption work;
- a substantive disposition oracle;
- synchronous quarantine eligibility;
- the committed M-03/M-15 governed vertical slice;
- event-triggered release and promotion;
- complete trajectory planning and constraint-valid construction;
- structural canonicalization and holdouts;
- executable Distributional Assurance schemas, validators, contracts, contrasts, and reports;
- the canonical Verified Cognition Episode and its compilers;
- runtime decision-gate fault qualification;
- a domain-neutral microkernel/domain-pack split;
- CognitionDL or the Domain Entry Compiler;
- the Reasoning ABI and oracle federation;
- governed open-ended exploration.

No empirical learning work is currently authorized.

## 4. Dual-track architecture

```text
                         Constitutional invariants
                                 │
                         CSD semantic kernel
                                 │
                 deterministic identity / replay
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
                ▼                                 ▼
   TRACK I — VERIFIED REASONING          TRACK L — EMPIRICAL LEARNING
          INFRASTRUCTURE
                │                                 │
 authority / registries                  immutable Track-I release
 assumptions / evidence                           │
 alternative models                              ▼
 disposition / quarantine               L0 hypothesis authorization
 release / assurance                              │
 synthesis / VCEs                                 ▼
 runtime decision gate                   bounded learning experiments
 platform extraction                              │
                │                                 ▼
                │                         structural replication
                │                                 │
                └──────────────┬──────────────────┘
                               ▼
                    LEARNING-VALIDATED PRODUCT
```

### 4.1 Track I — Verified Reasoning Infrastructure

Track I establishes mechanical and governance properties. Its evidence is deterministic execution, independent verification, adversarial mutation, concurrency and restart behavior, provenance, release reconstruction, structural isolation, distribution-contract conformance, fault testing, and measured economics.

Track I does not need a positive model-training result to progress.

### 4.2 Track L — Empirical Learning

Track L asks whether a specific model-consumable product causes a useful model-behavior change. It consumes pinned Track-I releases and may test SFT, process supervision, verifiers, repair learning, counterfactual contrasts, preference or reward formulations, or other prospectively specified products.

Track L may not mutate the semantic authority, provenance, or released bytes of the Track-I artifact used by an experiment.

### 4.3 Verified Cognition Episode boundary

The **Verified Cognition Episode (VCE)** is the canonical boundary object between the tracks.

Track I produces immutable VCE releases. A VCE binds the semantic, epistemic, interaction, disposition, quarantine, provenance, structural, and distributional views applicable to one governed reasoning episode.

Track L consumes versioned views of a pinned VCE release. Rendering or training choices may create new view artifacts, but they do not rewrite the underlying episode identity or authority.

### 4.4 Cross-track firewall

The following rules are mandatory:

1. A Track-I release is immutable once issued.
2. Track-L experiments bind the exact Track-I release identity, renderer or compiler version, model revision, training objective, controls, evaluation identities, and budget.
3. A learning failure may motivate a future infrastructure proposal but may not retroactively change the release used by that experiment.
4. Infrastructure invariants may not be weakened to make a learning metric easier to pass.
5. Infrastructure success may not be reported as model-learning success.
6. No implementation stage automatically schedules a GPU probe.
7. Future learning work requires explicit authorization after L0, even when Track I materially changes a model-consumable view.

## 5. Program sequence

### 5.1 Completed history

```text
Phase 0    Freeze foundational v0.5 contracts
Phase 1    Complete v0.4 streaming reconciliation and canonical merge
Phase 2A   Implement v0.5 canonicalization and typed contracts
Phase 2B   Implement validated-event admission
Phase 2C   Implement atomic temporal claim and completion
E0-H       Qualify the bounded GPU training/evaluation harness
G1-v1      E1 → calibration → E2 → E3
           terminal: G1 NOT PASSED; empirical sequence CLOSED
```

### 5.2 Track-I implementation sequence

The existing phase vocabulary is retained where practical so historical issues and PRs remain intelligible.

```text
Current frontier
Phase 3    Finish authority/read-path work and implement governed registries
Phase 4    Implement separate disposition oracle and synchronous quarantine
Phase 5    Prove M-03 / M-15 governed vertical slice
Phase 6    Implement event-triggered release and promotion
Phase 7    Build performance harness and constraint-valid synthesis
Phase 8    Add structural and Distributional Assurance
Phase 9    Build Verified Cognition Episode and product compilers
Phase 11-I Freeze measured infrastructure release policies and manufacture governed episodes
Phase 12   Qualify runtime decision governance and failure/distribution-gap harvesting

Platform extraction and breadth
Phase 13   Extract domain-neutral microkernel and make CSD the first domain pack
Phase 14   Implement CognitionDL and the minimal Domain Entry Compiler
Phase 15   Implement Reasoning ABI, assurance classes, and cross-domain composition
Phase 16   Prove a second domain and one cross-domain governed decision
Phase 17   Implement governed exploration and Open Reasoning Episode
Phase 18   Connect domain and distribution gaps to progressive formalization
```

`Phase 10 — Final scale confirmation` from Version 1.3 is removed from the Track-I dependency graph. Its legitimate function survives only as **L4 — Target-scale confirmation** if a future learning hypothesis earns that stage.

The old automatic semantic-stage probe concept is retired. Infrastructure-only changes rely on appropriate deterministic, adversarial, concurrency, restart, publication, structural, distributional, and fault tests. They do not trigger retraining by default.

### 5.3 Track-L sequence

```text
Historical
G1-v1   CLOSED / NOT PASSED

Future, inactive until separately authorized
L0      New-hypothesis authorization
L1      Bounded acquisition / screening
L2      Structural replication
L3      Product-view or curriculum comparison
L4      Target-scale confirmation
L5      Learning-product authorization
```

There is no automatic arrow from Track I into L0 and no automatic arrow from a failed learning experiment back into infrastructure changes.

## 6. Track-I program gates

### I0 — Deterministic foundation

**Status: PASSED for the single-host reference implementation.**

This gate includes the former Gate A and Gate B1 substance:

- shard-independent reconciliation and canonical publication;
- independent full replay;
- immutable identity and no-clobber publication;
- `ValidatedEvent` as the sole temporal coordinator input;
- exactly one concurrent successor winner;
- failure-no-advance;
- prepared completion hidden until committed-head publication;
- idempotent recovery;
- explicit exclusion of release compilation from ordinary clock ticks.

This does not establish production key management, distributed consensus, multi-host lease safety, or a general-purpose live governance service.

### I1 — Authority integrity

Proceed to substantive epistemic governance only after:

- historical policy resolution is deterministically reconstructable;
- selected grant and authority tuples are mechanically bound to their authoritative ledger state rather than trusted as detached caller-supplied data;
- action, authority, scope, materiality, and effective interval checks fail closed;
- policy and grant identities remain stable under historical replay;
- required separation-of-duty and authority-path checks are executable where the governed transition requires them;
- authority resolution cannot silently substitute a current policy for the policy effective at the governed snapshot.

The current assumption-policy read-path defect belongs here.

### I2 — Epistemic governance

Proceed to governed disposition only after substantive event-sourced registries exist for:

- evidence units;
- assumptions;
- alternative models.

The registries must be deterministic, append-only, digest-rooted, reconstructable, versioned, and policy-pinned. They must preserve provenance, authority, temporal validity, challenge state, dependency impact, and historical lifecycle.

Decision-critical assumptions must be falsifiable, expirable, challengeable, and linked to impact. Evidence must represent scope, lineage, correlation, independence, expiry, and separation status. Alternative models must carry material difference, scope, challenge basis, and admission state.

### I3 — Governed vertical slice

Proceed to release and synthesis work only after:

- a structurally separate `DispositionOracle` cites committed semantic evidence and cannot rewrite semantic state;
- immediate eligibility-layer quarantine exists for known-questionable assets;
- every material primary/shadow graph difference triggers full replay until irrelevance is independently certified;
- historical reconstruction remains available;
- M-03 passes end to end through expiry, basis recomputation, semantic projection, registry updates, disposition, quarantine, and committed completion;
- M-15 passes end to end through primary/shadow replay, invariant or divergent classification, and disposition without external-truth promotion.

### I4 — Governed release and synthesis

Proceed to structural and Distributional Assurance only after:

- release compilation occurs only after explicit requests against completed snapshots;
- promotion uses evidence current at the request snapshot;
- required assurance checks are rerun;
- quarantined assets are rejected;
- earlier releases remain immutable;
- joint semantic coverage planning is complete;
- constraint-valid state and event construction is executable;
- complete semantic and disposition rollout is available;
- failed attempts emit typed rejection evidence;
- search exhaustion remains distinct from infeasibility;
- accepted trajectories replay deterministically.

### I5 — Structural and distributional readiness

Proceed to canonical VCE product release only after structural and Distributional Assurance requirements are executable.

Structural readiness requires:

- canonical state, basis, dependency, event, assumption, disposition, and trajectory structures;
- structurally isolated train/development/test or benchmark partitions where such views exist;
- severity-aware mutation gates;
- right-answer/wrong-basis defects represented and killed;
- reproducible structural holdout identities.

Distributional readiness requires:

- a versioned scenario-world descriptor ontology and distribution contract;
- required marginal, pairwise, selected three-way, and risk-selected higher-order cells resolved;
- causal `INVARIANCE`, `SENSITIVITY`, `INFORMATION_REMOVAL`, and `FAILURE_AND_REPAIR` families;
- typed failure ecology and minimal-repair conformance vectors;
- generating-process and recursive-ancestry provenance;
- before/after filter-loss reports;
- rare-cell retention or explicit exception receipts;
- isolated distributional holdouts where declared;
- no unresolved critical distributional gap for the release claim.

Distributional adequacy may block a distributional release claim. It may not establish or rewrite semantic truth.

### I6 — Verified Cognition Product

The VCE is ready as the canonical CSD product only after each released episode can bind, where applicable:

- initial state and validated events;
- semantic receipts and operation traces;
- final state and registry roots;
- alternative-model replays;
- evidence, assumptions, ambiguity, and epistemic status;
- disposition and quarantine context;
- actor turns, tool observations, failure, retry, escalation, and repair;
- scenario-world and distribution-contract identity;
- causal contrast and failure-topology identity;
- generating-process provenance and ancestry;
- release eligibility and complete provenance.

Compilers may then derive SFT, verifier, repair, preference, process, reward, uncertainty, benchmark, and transfer views from the immutable episode. A rendered row is not the canonical product.

### I7 — Runtime governance

Deploy or rely on runtime decision governance only after production-like single-host fault qualification demonstrates:

```text
model or agent proposal
→ structured parse
→ semantic verification
→ evidence / assumption / model resolution
→ disposition
→ permit / flag / request evidence / escalate / block
→ audit receipt
```

Required evidence includes deterministic receipts, escalation ownership, quarantine, historical reconstruction, incident replay, privacy/provenance handling for captured failures, and distribution-gap recording.

Runtime observations do not enter training automatically.

### I8 — Multi-domain platform architecture

Proceed to broad domain expansion only after:

- CSD operates as a versioned domain pack over a domain-neutral microkernel;
- the microkernel retains only cross-domain constitutional primitives and mechanisms;
- a second domain is compiled through the domain-definition toolchain;
- at least one external oracle is integrated through the Reasoning ABI;
- one cross-domain decision is composed under assurance policy;
- domain-pack constitutional violations fail closed;
- cross-domain distributional claims remain contract-bounded.

### I9 — Governed exploration

Proceed to open-ended cognition-product scaling only after:

- hypotheses remain distinct from verified claims;
- epistemic type and assurance class are independently checked;
- structurally distinct hypotheses are distinguished from paraphrases;
- selected questions or tests update the hypothesis graph;
- unsupported epistemic promotion is mechanically rejected;
- outcome and search-quality evaluation are defined;
- novelty and distribution-gap discovery cannot override relevance, coherence, constraints, or claim boundaries.

## 7. Track-L program gates

Track L is inactive after G1-v1 closure until L0 is separately authorized.

### L0 — New-hypothesis authorization

No GPU execution may begin until a new hypothesis is recorded in GitHub and prospectively freezes:

- the unique Foundry capability being tested;
- why G1-v1 does not already answer the question;
- the pinned Track-I release and exact model-consumable view;
- matched control or controls;
- model and tokenizer revisions;
- training objective and inference ABI;
- structural and distributional split isolation;
- one primary capability metric and explicit safety criteria;
- minimum decision-relevant effect or classification rule;
- protected-metric visibility rules;
- seeds and stopping rule;
- GPU budget ceiling;
- terminal classes;
- artifact retention and provenance requirements.

Changing model size, training steps, representation, anchors, class balance, loss, or control after a failed experiment is not automatically a new hypothesis. The proposal must identify a new causal question rather than an E4-like retry by renaming.

### L1 — Bounded acquisition / screening

L1 asks whether the proposed target can be acquired at all under the frozen low-cost recipe. It is a technical and causal screening stage, not evidence of Foundry advantage.

If the task cannot be acquired, stop or return to L0 with a materially revised hypothesis. Do not spend scale budget to diagnose basic acquisition.

### L2 — Structural replication

A learning signal must replicate on fresh structural families or other prospectively isolated units relevant to the claim. The replication must preserve control parity and safety rules.

A one-off positive development differential does not pass L2.

### L3 — Product-view or curriculum comparison

L3 compares the specific Foundry product against the minimum matched control required by the hypothesis. Examples of legitimate future questions include, if separately authorized:

- proof-carrying process supervision versus terminal-label supervision;
- verifier training on invariant-breaking mutations versus conventional negatives;
- repair learning from mechanically localized defects versus generic critique data;
- controlled counterfactual contrasts versus ordinary synthetic examples;
- semantic/disposition separation training versus answer-only supervision.

These examples are not pre-authorized experiments.

### L4 — Target-scale confirmation

L4 replaces the old Version-1.3 Phase 10. It exists only after L2 and L3 establish a reproducible, safety-compatible effect worth confirming.

The target-scale experiment must be prospectively specified, appropriately powered for its decision, and evaluated against a blind holdout introduced only after all criteria are frozen. It must determine whether the bounded effect transfers, attenuates, amplifies, vanishes, reverses, or remains unresolved at the target confirmation scale.

Training loss, aggregate accuracy, row count, one scalar diversity score, or a positive small-model run cannot authorize L4 or L5.

### L5 — Learning-product authorization

A learning-oriented release may claim Foundry-attributable benefit only after the approved empirical program demonstrates, as applicable to its declared claim:

- reproducible structural-holdout improvement;
- reduced forbidden inference;
- controlled abstention and over-conservatism;
- causal invariance consistency;
- counterfactual sensitivity correctness;
- ambiguity handling;
- failure localization and minimal-repair fidelity;
- reduced right-answer/wrong-basis defects;
- independent transfer where declared;
- rare-cell and worst-group retention;
- optimizer exposure consistent with contract;
- acceptable verified-episode economics;
- zero unresolved critical mutation escapes relevant to the release.

The exact acceptance thresholds belong to the L0 contract for that program, not to this roadmap.

## 8. Success states

The program must report infrastructure and learning state separately.

| Track-I state | Track-L state | Permitted interpretation |
|---|---|---|
| fail | fail | architecture and learning program unsuccessful |
| pass | fail / unvalidated | verified reasoning platform works within its claim boundary; learning product unvalidated |
| fail | apparent pass | learning claim rejected because trustworthy semantic/assurance foundation is absent |
| pass | pass | full Learning-Validated Reasoning Foundry success |

This matrix prevents two opposite errors: discarding a mechanically useful platform because one training formulation failed, and declaring the overall learning thesis solved merely because the infrastructure is rigorous.

## 9. Track-I implementation details

### Phase 3 — Authority completion and governed registries

First close the remaining assumption-policy read-path binding defect. The selected policy/grant result must be inseparable from, or independently reconstructable against, the authoritative ledger state it claims to represent.

Then implement event-sourced registries for evidence units, assumptions, and alternative models.

Each registry must be deterministic, append-only, digest-rooted, reconstructable, and versioned. It must preserve provenance, authority, temporal validity, challenge state, dependency impact, and historical lifecycle.

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

M-03 must prove:

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

M-15 must prove:

```text
primary graph
+ materially different shadow graph
→ full replay of both
→ invariant or divergent classification
→ disposition change without external-truth assertion
```

### Phase 6 — Event-triggered release and promotion

Release compilation runs only after explicit requests against completed snapshots.

Promotion must use current evidence, rerun required assurance checks, reject quarantined assets, enforce reuse class externally, create a new immutable release identity and manifest, and preserve earlier releases unchanged.

### Phase 7 — Performance and constraint-valid synthesis

Measure before freezing policy. Benchmark assumption counts, full primary/shadow replay, registry reduction, temporal commit latency, disposition by class, quarantine indexes, release compilation, and verified-episode cost.

Build joint semantic, structural, and distributional planning over rule composition, state and basis topology, dependency structure, alternative-basis count, event depth, temporal/governance composition, authority path, decision class, assumption fragility, mutation family, context, actor intention, information state, ambiguity, expertise, discourse, tool condition, authority state, risk, reasoning-policy family, failure topology, and outcome class.

Implement canonical scenario-world descriptors, generating-process and recursive-ancestry provenance, a versioned distribution-contract compiler, required quota authorities, explicit impossible/forbidden/unsupported/unresolved/required/holdout dispositions, and typed rejection evidence.

Every accepted trajectory requires a target, constraint proof, eligibility proof, deterministic identities, validated events, complete semantic/disposition replay, process provenance, contract-cell assignment, and exact rejection evidence for failed attempts.

### Phase 8 — Structural and Distributional Assurance

Canonicalize state, basis, dependency, event, assumption, disposition, and reasoning-policy structures before split assignment.

Hold out topology, rule composition, event depth, basis-survival form, hidden-dependency pattern, temporal/governance path, assumption family, disposition family, and declared distributional worlds.

Run deterministic and stochastic mutation campaigns across semantic decisions, evidence impact, basis recomputation, history, authority, admission, graphs, disposition, quarantine, promotion, and release eligibility.

Implement causal `INVARIANCE`, `SENSITIVITY`, `INFORMATION_REMOVAL`, and `FAILURE_AND_REPAIR` families; typed failure ecology; conditional coverage matrices; source and process concentration reports; ancestry reports; filter-loss reports; rare-cell retention; and distributional holdouts.

Search exhaustion remains unresolved and never becomes infeasibility without a machine-checkable witness.

### Phase 9 — Verified Cognition Episode and compilers

Make the VCE the canonical CSD product.

Each episode contains linked semantic, epistemic, interaction, distributional, disposition, quarantine, and provenance views over one immutable identity.

Compile each eligible episode into versioned views including:

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

### Phase 11-I — Measured infrastructure release policy

After I4-I6 evidence, freeze only policies justified by measurements:

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
- release volume and retention policy.

This phase may authorize governed VCE manufacturing within the infrastructure claim boundary. It does **not** authorize a learning-benefit claim or target-scale model training. A learning corpus intended to carry a Foundry-improvement claim remains gated by L5.

### Phase 12 — Runtime governance and gap harvesting

At runtime or production-like batch decision time:

```text
model proposal
  → structured parse
  → semantic verification
  → evidence / assumption / model resolution
  → disposition
  → permit / flag / request evidence / escalate / block
```

Failures may generate governed assumption/dependency challenges, replay requests, quarantine, mutation candidates, distribution-gap records, failure-topology candidates, unseen high-order world combinations, temporal-shift cases, tool-drift cases, and formalization proposals.

Runtime observations require privacy, provenance, semantic, disposition, and release governance before any later training use.

### Phases 13–16 — Multi-domain platform extraction

Extract the domain-neutral governance microkernel and make CSD the first domain pack. The microkernel owns only cross-domain constitutional mechanisms and primitives. CSD retains its domain states, events, invariants, policies, constructors, mutations, renderers, benchmarks, claim boundaries, and domain-specific distributional contracts.

Implement the minimal CognitionDL / Domain Entry Compiler, then the Reasoning ABI, oracle receipt schema, oracle identity and version governance, assurance classes, assurance propagation, revocation, and cross-domain composition.

Prove a second domain and at least one cross-domain governed decision before broad domain expansion.

### Phases 17–18 — Governed open-ended reasoning

Implement a separate exploration plane for interpretations, hypotheses, candidate representations, analogies, plans, questions, experiments, candidate oracles, doctrine gaps, scenario worlds, and distribution gaps.

Its outputs remain candidates until promoted through explicit evidence, oracle, adjudication, or domain-governance routes.

Connect repeated unsupported requests and measured gaps to candidate formal islands and distribution-contract revisions through counterexample-guided review and shadow execution.

## 10. Distributional Assurance execution requirements

Distributional Assurance remains cross-cutting and does not become semantic authority.

The infrastructure must distinguish meaningful behavioral support from row, topic, format, source, persona, or paraphrase counts. Distributional claims require explicit descriptor ontology, distribution contract, generating-process provenance, causal contrast evidence, filter-loss accounting, ancestry, concentration, rare-cell retention, and bounded claim language.

Initial CSD distributional families continue to use M-03 and M-15.

M-03 families should exercise complete, incomplete, contradictory, stale, and ambiguous evidence; tool availability and failure modes; sufficient, insufficient, and contested authority; audience/expertise variation; unsupported verdicts; wrong basis; right-answer/wrong-basis; missed and unnecessary clarification; failed repair; and overbroad rollback.

M-15 families should exercise hidden-dependency changes, materially different alternative models, inappropriate irrelevance certification, correct conclusions from incomplete structures, invariant versus divergent classifications, and unresolved external truth without unsupported promotion.

Do not count surface paraphrases as new causal worlds. Do not maximize friction or path diversity when the governed problem has one valid efficient route.

## 11. Track-L empirical protocol

Track L is a bounded empirical decision system, not a second semantic authority.

The following rules survive from the useful parts of the Version-1.3 empirical protocol:

1. Freeze the experiment contract before GPU execution.
2. Protected primary metrics remain hidden until predetermined checkpoints or terminal execution are complete.
3. Live monitoring is limited to infrastructure and optimization health unless the contract explicitly authorizes otherwise.
4. Canonical symbolic-family and structural isolation precede metric-bearing evaluation.
5. Controls must be sufficient to isolate the causal question, including token and task-format parity where relevant.
6. Independent verification remains separate from the executable label oracle where the claim depends on semantic correctness.
7. Budgets and stop conditions are frozen prospectively; ambiguous outcomes do not authorize more compute automatically.
8. Terminal classifications are applied exactly as committed. Failed criteria are not weakened after observing the result.
9. GPU results return through durable GitHub evidence and digest-bound receipts.
10. No empirical governance layer is added merely for ceremony. New controls require an observed failure, near-miss, or concrete unresolved decision.

The missing standalone calibration receipt remains historical fact and must not be reconstructed as if it had existed at execution time.

## 12. Economics

Track I and Track L use different economic measures.

Track-I measurements may include:

- verified semantic decisions per CPU-second;
- verified episodes per dollar;
- mutation pairs per episode;
- independent checks per episode;
- replay cost per alternative model;
- quarantine propagation latency;
- release compilation latency;
- provenance and storage overhead;
- deterministic rebuild cost.

Track-L measurements may include:

- model improvement per verified training token;
- model improvement per GPU-dollar;
- forbidden-inference reduction per GPU-dollar;
- verifier or repair gain per VCE family;
- worst-group gain per verified episode.

Cheap infrastructure is not evidence of learning value, and expensive learning is not justified by infrastructure sunk cost.

## 13. Workstreams

| Workstream | Responsibility |
|---|---|
| Semantic Kernel | CSD states, events, transitions, traces, invariants |
| Deterministic Substrate | Choice, identity, replay, execution, sharding, storage, publication |
| Authority and Epistemic Governance | Policy/grant resolution, evidence, assumptions, alternative models, dependency and authority paths |
| Disposition and Quarantine | Separate operational disposition, eligibility, quarantine, historical reconstruction |
| Synthesis and VCE Products | Semantic targets, constructors, episodes, canonicalization, mutations, compilers |
| Distributional Assurance | Scenario worlds, distribution contracts, causal contrasts, failure ecology, process provenance, coverage and filter-loss audits |
| Runtime Governance | Proposal parsing, decision gate, incident replay, escalation, runtime gap harvesting |
| Empirical Learning | L0-L5 experiment design, training, verifiers, repair learning, benchmarks, target-scale confirmation |
| Platform Compiler | Microkernel extraction, CognitionDL, domain packs, static analysis |
| Oracle Federation | Reasoning ABI, adapters, witness validation, assurance composition |
| Governed Exploration | Hypothesis graphs, search control, epistemic typing, delayed outcomes, gap discovery |

No workstream may silently absorb another workstream's authority.

## 14. Immediate repository sequence

The next repository work is Track I only unless a separate L0 authorization is issued.

1. Close the outstanding assumption-policy historical-resolution/grant-binding defect before merging the read-path slice.
2. Complete authority checks required by governed assumption work, including separation-of-duty and dependency validation where specified by the frozen contracts.
3. Implement substantive evidence-unit, assumption, and alternative-model registry reducers and roots.
4. Implement the separate disposition oracle and synchronous quarantine eligibility.
5. Execute M-03 and M-15 through the committed governed pipeline.
6. Implement event-triggered release and promotion.
7. Benchmark the governed vertical slice and freeze only measured infrastructure policies.
8. Resume constraint-valid planning, construction, rollout, semantic coverage, and structural assurance.
9. Implement the Distributional Assurance contract, causal contrast, failure ecology, provenance, and report vertical slice over M-03/M-15.
10. Implement the canonical Verified Cognition Episode and deterministic product compilers.
11. Qualify the runtime decision gate and distribution-gap harvesting under production-like single-host fault conditions.
12. After the governed CSD vertical slice and VCE boundary are stable, extract the domain-neutral microkernel and make CSD the first domain pack.
13. Implement the minimal domain compiler and Reasoning ABI.
14. Prove one second domain and one cross-domain composition.
15. Implement a minimal governed exploration vertical slice.

No item in this sequence authorizes model training.

## 15. Explicit deferrals and prohibitions

Do not implement or authorize prematurely:

- E4 or any continuation of G1-v1 under a new experiment number without L0;
- automatic learning probes after infrastructure stages;
- model architecture, loss, representation, class-balance, anchor, or scale changes merely to rescue G1-v1;
- target-scale training before L2/L3 evidence and explicit L4 authorization;
- release-scale learning claims before L5;
- replay pruning without a mechanically verified relevance certificate;
- approximate cut sets without measurements;
- release compilation on every tick;
- mutable assumption contents inside semantic state;
- high-assurance gating from unverified evidence or models;
- search exhaustion as infeasibility;
- raw row expansion without executable semantic, structural, or behaviorally consequential distributional coverage;
- a universal ontology or universal distributional taxonomy;
- LLM judging presented as exact verification;
- one scalar entropy or diversity score as sufficient assurance;
- fixed universal human/synthetic ratios;
- uncontrolled or non-replayable fault injection;
- unrestricted online weight adaptation from deployment interactions;
- broad multi-domain expansion before the microkernel, pack, ABI, and assurance contracts are proven;
- open-ended curriculum scaling before epistemic-promotion failures are mechanically detectable;
- multi-host, multi-tenant, distributed-consensus, or general-purpose live-service expansion without a separate accepted architectural decision;
- additional empirical governance layers without an observed failure, documented near-miss, or concrete unresolved decision.

## 16. Strategic milestones

The program now has four milestones rather than one learning-dependent linear chain.

> **Milestone A — Complete governed CSD execution.**  
> Close authority, registries, disposition, quarantine, and M-03/M-15 under I1-I3.

> **Milestone B — Manufacture Verified Cognition Episodes.**  
> Complete release, synthesis, structural and Distributional Assurance, VCEs, and measured infrastructure release policy under I4-I6.

> **Milestone C — Deploy governed reasoning control and extract the platform.**  
> Qualify runtime governance, then prove the microkernel/domain-pack/ABI boundary and a second domain under I7-I9.

> **Milestone L — Demonstrate learning value if and only if a new empirical hypothesis earns it.**  
> L0-L5 is independent of Milestones A-C. G1-v1 remains closed and does not become retroactively successful if a later hypothesis passes.

This ordering preserves deterministic replay, semantic/disposition separation, auditable uncertainty, append-only correction, quarantine, Distributional Assurance, exact provenance, and a credible path to broad reasoning coverage while keeping empirical learning claims falsifiable and separately governed.

## 17. Strategic position

Version 2.0 changes the dependency graph, not the constitutional architecture.

The platform will first prove that it can manufacture and govern reasoning artifacts whose authority is executable, replayable, independently checkable, structurally isolated, distributionally bounded, and provenance-complete. The canonical product is the Verified Cognition Episode, not a rendered training row.

Models may consume those products as proposers, verifiers, repair systems, policy learners, or training targets, but no model becomes semantic authority merely because it was trained on Foundry data.

The project therefore asks two independent questions:

> **Can we build an executable system that knows what a valid reasoning transition is relative to its declared doctrine, evidence, oracle, and policy?**

and

> **Given such a system, what model-consumable products, if any, transfer that structure into useful learned behavior?**

Track I answers the first. Track L answers the second. The full Learning-Validated Reasoning Foundry requires both.