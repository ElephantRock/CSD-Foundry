# CSD Foundry Distributional Assurance v0.1

**Status:** APPROVED FOR CONTRACT DESIGN  
**Version:** 0.1  
**Date:** 2026-08-04  
**Approved:** 2026-08-04  
**Approval PR:** #61  
**Approval commit:** `f61a1ef4e95a988d943a9e0dce58e1553ae82d32`  
**Issue:** #57  
**Parent epic:** #54  
**Constitutional authority:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md`  
**Change proposal:** `docs/ARCHITECTURE_PROPOSAL_001_DISTRIBUTIONAL_ASSURANCE.md`  
**Implementation status:** Not implemented

## 1. Purpose

This document defines the initial doctrine, authority boundaries, contract model, evidence model, and pilot boundary for Distributional Assurance in CSD Foundry.

Distributional Assurance asks:

> Does a corpus and its actual training exposure cover declared, realistic, behaviorally consequential variations, or does it merely contain mechanically different realizations of one narrow generative pattern?

The subsystem exists because the following properties are individually insufficient:

- valid schemas;
- correct labels;
- executable semantic traces;
- structural canonicalization;
- mutation coverage;
- split isolation;
- lexical, topic, format, persona, or embedding diversity.

A corpus can satisfy all of them while repeatedly teaching one latent trajectory:

```text
well-specified request
→ orderly decomposition
→ predictable evidence or tool action
→ clean success
→ polished conclusion
```

Distributional Assurance governs the effective support of proof-carrying cognition episodes and their training use. It does not establish substantive semantic truth.

## 2. Governing quality model

```text
Foundry quality
=
Oracle integrity
× Structural assurance
× Distributional assurance
```

The product is multiplicative in the practical sense that a critical failure in any one plane can invalidate the intended training or evaluation claim.

| Plane | Governing question | Authority |
|---|---|---|
| Oracle integrity | Is the substantive state, transition, support relation, conclusion, or repair valid? | Semantic oracle and approved external oracles |
| Structural assurance | Are required semantic structures canonicalized, isolated, and challenged correctly? | Structural canonicalizer, holdout policy, mutation assurance |
| Distributional assurance | Are those structures exercised across declared consequential worlds, interactions, failures, and processes? | Distribution contract, causal contrasts, provenance, behavioral evaluation |
| Disposition | May the artifact proceed, be held, quarantined, blocked, or excluded? | Separate disposition authority |
| Empirical evaluation | Did training produce useful transfer, calibration, and recovery? | Controlled model pilot and independent evaluation |

No plane may silently absorb another's authority.

## 3. Claim boundary

Passing Distributional Assurance establishes only that:

- the release satisfies the declared descriptor ontology and distribution contract;
- required contrast, failure, provenance, concentration, and release-evidence checks passed;
- the reported behavioral evaluation passed on the declared holdouts.

It does not establish that:

- the ontology is complete;
- all real users, intentions, cultures, tools, organizations, failures, or future deployments are represented;
- natural or human-origin data is correct or representative;
- source processes are fully independent;
- a model will generalize outside the evaluated distributions;
- recursive synthetic collapse has been eliminated;
- a global entropy value has been estimated for real-world cognition.

Every distributional report must state this boundary or a stricter one.

## 4. Core terms

### 4.1 Effective behavioral support

The set of materially different world and trajectory regions represented by a release after collapsing differences that do not change the relevant semantic state, decision, information action, tool policy, escalation, or repair structure.

### 4.2 Mechanical variation

A change in wording, names, numbers, formatting, persona label, topic label, or style that does not create a consequentially different world or required behavior.

Mechanical variation can be useful for rendering robustness. It does not automatically count as new effective behavioral support.

### 4.3 Canonical scenario world

A content-addressed description of the consequential conditions under which a cognition episode occurs.

The initial descriptor model is defined in Section 6. Exact executable schemas remain future versioned contracts.

### 4.4 Consequential factor

A factor whose change requires a different substantive conclusion, information-acquisition action, tool policy, clarification behavior, abstention, escalation, or repair.

### 4.5 Reasoning-policy family

A canonical family of materially distinct approaches, such as direct deduction, clarification-first resolution, evidence acquisition, hypothesis elimination, tool-assisted verification, fallback recovery, conservative abstention, or authority escalation.

Different wording around the same policy does not create a new family.

### 4.6 Causal contrast family

A controlled set of world variants used to test invariance, sensitivity, information removal, and failure or repair behavior.

### 4.7 Failure topology

A typed description of a failure's cause, affected state, observable symptom, permitted recovery, forbidden recovery, and terminal condition.

### 4.8 Generating-process identity

The immutable identity of the causal process that produced an episode, including source seed, generator, objective, environment, interaction policy, filters, annotation, and recursive ancestry.

### 4.9 Distribution contract

A versioned declaration of required support, interactions, tails, failure ecology, provenance, concentration, holdouts, and claim boundary.

### 4.10 Contract cell

A declared combination of descriptor values whose population, exclusion, infeasibility, holdout status, or exception status is explicitly governed by the distribution contract.

### 4.11 Distribution gap

A required, risk-selected, or empirically important contract region that lacks sufficient accepted episodes, evaluation evidence, or optimizer exposure.

## 5. Non-goals

Distributional Assurance v0.1 does not:

- define one universal ontology of human reasoning;
- maximize entropy for its own sake;
- require the full Cartesian product of descriptor values;
- establish universal source-mixture ratios;
- prescribe a model architecture or training loss;
- equate human-origin data with truth;
- treat multi-agent generation as independent by default;
- treat synthetic-origin detection as a release authority;
- require unrestricted internal chain-of-thought capture;
- authorize uncontrolled or non-replayable environment faults;
- replace semantic, structural, disposition, or empirical gates.

## 6. Canonical scenario-world descriptor model

Each episode that participates in a distributional claim shall bind a canonical scenario-world description.

The initial minimum axes are:

| Axis | Purpose | Example values |
|---|---|---|
| `semantic_family` | Underlying governed problem or transition family | evidence expiry, basis survival, restoration, alternative-model replay |
| `context_family` | Operational setting and stakes | routine review, incident, release gate, audit, constrained operation |
| `actor_intention` | What the actor is trying to accomplish through the interaction | explain, verify, diagnose, challenge, recover, persuade, test, escalate |
| `information_state` | Availability and reliability of decision-relevant information | complete, incomplete, contradictory, stale, misleading, inaccessible |
| `ambiguity_class` | Why a unique interpretation may or may not be available | none, context-resolvable, clarification-required, tool-observation-required, multiple-valid, irreducible, strategic, contradictory |
| `expertise_relation` | Relative expertise among participants | novice-to-expert, peer-to-peer, expert-to-novice, user-more-expert, mixed audience |
| `discourse_form` | Interaction architecture | terse request, dialogue, log, ticket, specification, fragmented notes, review exchange |
| `tool_condition` | Availability and behavior of external tools | unnecessary, available, restricted, unavailable, partial, stale, malformed, timeout, conflicting |
| `authority_state` | Whether required action authority exists | sufficient, insufficient, contested, expired, scope-mismatched |
| `risk_class` | Consequence class relevant to response policy | routine, elevated, high-impact, irreversible |
| `reasoning_policy_family` | Material approach used | direct deduction, clarification-first, evidence acquisition, hypothesis elimination, tool verification, fallback, abstention, escalation |
| `failure_topology` | Typed failure or absence of failure | none or one registered failure topology |
| `outcome_class` | Terminal result | success, partial success, recovery, abstention, escalation, block, unresolved |

### 6.1 Descriptor requirements

Each axis and value must declare whether it is:

- semantic;
- behaviorally consequential;
- rendering-only;
- environment-observed;
- inferred;
- adjudicated;
- unsupported for the current domain pack.

### 6.2 Impossible and forbidden combinations

The contract system must distinguish:

- **impossible:** no valid world can satisfy the combination under the applicable semantics;
- **forbidden:** the release policy prohibits constructing or using the combination;
- **unsupported:** the current constructor or oracle cannot establish the combination;
- **unresolved:** search or implementation did not determine feasibility;
- **holdout:** intentionally excluded from training for evaluation;
- **required:** must be populated before the contract passes.

Search exhaustion never establishes impossibility.

### 6.3 Canonicalization boundary

Scenario-world identity must derive from canonical descriptors and bound semantic references. It must not derive from rendered wording, worker identity, timestamps, storage paths, or shard topology.

## 7. Distribution contract

A release-scale synthesis or training claim requires an explicit, versioned distribution contract.

The contract shall define at least:

- descriptor schema identity;
- target domain and semantic release identities;
- required marginal coverage;
- required weighted pairwise coverage;
- selected three-way coverage;
- risk-selected higher-order combinations;
- required failure ecology;
- impossible, forbidden, unsupported, unresolved, and holdout combinations;
- source and generating-process concentration limits;
- recursive-ancestry policy;
- rare-cell retention policy;
- filtering and selection evidence requirements;
- training-exposure requirements where a learning claim is made;
- independent holdout policy;
- release-blocking gaps;
- claim boundary.

### 7.1 No full Cartesian-product requirement

The contract shall use:

1. marginal coverage as a baseline;
2. weighted pairwise coverage for important interactions;
3. selected three-way coverage;
4. risk-, mutation-, runtime-, or expert-selected higher-order cases.

The full Cartesian product is neither required nor presumed realistic.

### 7.2 Quota authority separation

Target proportions and quotas must identify their authority class:

- `OBSERVED_FREQUENCY` — measured deployment prevalence;
- `RISK_WEIGHTED` — cost or severity of failure;
- `CURRICULUM` — current model learning need;
- `TRANSFER` — structural or compositional generalization need;
- `ASSURANCE` — release evidence and regression requirement;
- `EXPLORATION` — bounded unknown-region discovery.

A mixture compiler may combine these only through an explicit policy. It may not hide them inside one unexplained quota.

### 7.3 Coverage is not uniformity

The contract need not seek a uniform distribution. It seeks sufficient support under realism, validity, deployment relevance, and resource constraints.

### 7.4 Conditional coverage

The contract shall be able to express conditions such as:

```text
reasoning policy | semantic family
tool policy | tool condition
response policy | ambiguity class
explanation depth | expertise relation
repair policy | failure topology
decision | authority and evidence state
```

High marginal coverage with fixed conditional behavior is a distributional warning.

## 8. Causal contrast families

Every high-value semantic family should support controlled causal contrasts.

### 8.1 `INVARIANCE`

Change factors that should not alter the substantive governed result, such as:

- wording;
- names;
- formatting;
- discourse rendering;
- ordering of equivalent evidence;
- superficial domain terminology.

Expected result: the semantic conclusion and policy-relevant action remain stable, subject to permitted rendering adaptation.

### 8.2 `SENSITIVITY`

Change exactly one consequential factor, such as:

- evidence validity;
- authority;
- dependency state;
- tool availability;
- risk class;
- user objective;
- temporal state.

Expected result: the conclusion or action changes exactly as the doctrine and policy require.

### 8.3 `INFORMATION_REMOVAL`

Remove decisive information or make its reliability unresolved.

Expected result: the model or reference policy requests information, uses an approved tool, states assumptions, qualifies, abstains, escalates, or blocks as required. It must not silently reconstruct unavailable ground truth from the generator's intent.

### 8.4 `FAILURE_AND_REPAIR`

Inject one typed failure and bind:

- the exact failure point;
- the affected state;
- valid work before the failure;
- dependent consequences;
- unaffected work;
- minimum legal repair;
- prohibited overcorrection;
- final conformance test;
- justified terminal non-completion where repair is impossible or unsafe.

### 8.5 Contrast-family integrity

A contrast family is valid only when:

- all variants share one source-world lineage;
- the changed factor is explicit;
- unintended semantic changes are absent or declared;
- expected invariance or sensitivity is mechanically or independently validated;
- surface paraphrases are not counted as distinct causal variants.

## 9. Failure ecology

The initial failure catalog shall include at least:

| Failure topology | Required capability |
|---|---|
| `MISSING_DECISIVE_INFORMATION` | Detect missing information and select clarification, observation, qualification, abstention, or escalation |
| `CONTRADICTORY_EVIDENCE` | Expose conflict and avoid unsupported certainty |
| `STALE_EVIDENCE` | Reject, refresh, or qualify stale support |
| `AUTHORITY_INSUFFICIENT` | Avoid unauthorized action and escalate or block |
| `TOOL_UNAVAILABLE` | Use permitted fallback or terminate honestly |
| `TOOL_TIMEOUT` | Distinguish safe retry from unsafe retry and preserve state |
| `PARTIAL_TOOL_RESULT` | Use only supported portions and acquire missing information |
| `MALFORMED_TOOL_RESULT` | Reject malformed output and recover through an allowed route |
| `UNKNOWN_COMMIT_STATUS` | Avoid non-idempotent retry until state is reconstructed |
| `DUPLICATE_EVENT` | Preserve idempotence and detect duplicate delivery |
| `WRONG_DEPENDENCY_MATCH` | Localize the incorrect dependency and recompute affected support |
| `UNSUPPORTED_CONCLUSION` | Reject a conclusion without a valid basis |
| `RIGHT_ANSWER_WRONG_BASIS` | Reject a correct output produced through invalid support or inference |
| `MISSED_CLARIFICATION` | Detect material ambiguity before commitment |
| `UNNECESSARY_CLARIFICATION` | Proceed when evidence is sufficient instead of obstructing the task |
| `FAILED_REPAIR` | Detect that the attempted repair did not restore conformance |
| `OVERBROAD_ROLLBACK` | Preserve unaffected valid work while repairing only dependent consequences |
| `UNRECOVERABLE_STATE` | Fail closed, preserve evidence, and escalate rather than fabricate recovery |

### 9.1 Failure contract

Each registered failure topology must bind:

- trigger and preconditions;
- designated invariant or policy;
- affected state and scope;
- observable symptom;
- valid detection route;
- permitted recoveries;
- forbidden recoveries;
- terminal disposition;
- replay seed or deterministic fixture where applicable;
- post-repair conformance vector.

### 9.2 Failure distribution

The contract must include clean success as well as failure. Maximum friction is not the objective.

A balanced ecology may include:

- clean success;
- minor retry-safe failure;
- retry-unsafe ambiguous state;
- fallback recovery;
- human or authority escalation;
- unrecoverable block;
- selected multi-fault composition.

Frequencies remain empirical policy, not doctrine.

## 10. Generating-process provenance

Every episode used in a distributional release shall bind the process that produced it.

The future process identity must include at least:

- generator family and checkpoint digest;
- generation-policy digest;
- source-seed digest;
- objective class;
- interaction configuration;
- environment digest;
- fault-policy digest;
- filter-policy digest;
- annotation-policy digest;
- judge or adjudication policy where applicable;
- parent process and recursive-ancestry digest;
- claimed independence basis.

### 10.1 Independence is graded

The system must not treat independence as a boolean without evidence.

Possible evidence dimensions include:

- semantic independence;
- observational independence;
- source-corpus independence;
- model-lineage independence;
- objective independence;
- environmental independence;
- organizational independence;
- authority independence.

Two model families may share data and objectives. Two human sources may share one institutional doctrine. Multiple agents using one base model may remain one correlated process family.

### 10.2 Natural and human-origin material

Natural or human-origin material can provide independent interaction structures and failures, but it is not automatically:

- correct;
- complete;
- representative;
- consented or licensed;
- privacy-safe;
- uncontaminated by synthetic ancestry.

It requires governance and separate semantic validation.

## 11. Filtering and selection assurance

Every filtering stage that affects a distributional release must emit a before-and-after profile containing:

- incoming and outgoing contract-cell counts;
- removed semantic and trajectory families;
- removed ambiguity and expertise classes;
- removed failure and recovery topologies;
- removed source and process identities;
- reason codes;
- rare-cell losses;
- exception receipts.

A filter must be audited for disproportionate rejection of:

- novice reasoning;
- terse expert discourse;
- unresolved but legitimate ambiguity;
- valid failed attempts and repair trajectories;
- unusual but valid tool recovery;
- noncanonical valid policies;
- minority source or process families.

Cleanliness, politeness, verbosity, and formatting cannot serve as universal quality authorities.

## 12. Authority separation

| Authority | Decides | Must not decide |
|---|---|---|
| Semantic oracle | State, transition, support, conclusion, repair validity | Distributional adequacy or release usefulness |
| Execution verifier | Actual environment and tool observations | Semantic implication beyond its receipt |
| Structural assurance | Canonical structure, holdout identity, mutation outcome | Realism or deployment prevalence |
| Distributional assessor | Contract-cell membership, coverage, concentration, gaps | Semantic truth or disposition replacement |
| Provenance validator | Lineage completeness and consistency | Source correctness or independence beyond evidence |
| Behavioral evaluator | Invariance, sensitivity, ambiguity, recovery behavior | Semantic authority when no oracle exists |
| Disposition oracle | Permit, hold, quarantine, block, exclude | Rewrite substantive conclusions |
| Human adjudicator | High-impact unresolved disputes under an explicit process | Mechanical proof by assertion |

No one learned score may combine all authorities.

## 13. Distributional release evidence

A future Distributional Release Report shall contain at least:

- contract and descriptor identities;
- semantic and structural release identities;
- marginal coverage;
- required pairwise coverage;
- selected higher-order coverage;
- uncovered and unresolved cells;
- impossible cells and witnesses;
- forbidden and holdout cells;
- failure-topology coverage;
- causal contrast pass rates;
- source and process concentration;
- recursive-ancestry profile;
- pre-filter and post-filter coverage loss;
- train, validation, and test isolation;
- optimizer exposure where a training claim is made;
- independent transfer results where a capability claim is made;
- exceptions and approval identities;
- exact claim boundary.

### 13.1 Release-blocking conditions

A release shall fail closed when:

- a required semantic or structural gate fails;
- a required contract cell is missing without an approved infeasibility witness or exception;
- a critical causal contrast fails;
- provenance closure is incomplete;
- a critical rare cell is removed without an approved exception;
- train and holdout isolation is violated;
- a distributional claim exceeds the declared contract;
- report reconstruction is nondeterministic.

Empirical thresholds remain unfrozen until the pilot.

## 14. Optimizer exposure

A rich corpus can produce narrow learning if batches repeatedly emphasize the dense center.

A training run that makes a distributional claim shall eventually record:

- planned mixture;
- actual sampled mixture;
- cumulative exposure by contract cell;
- source and process exposure;
- failure and contrast-family exposure;
- per-cell loss or evaluation where feasible;
- checkpoint-level retention and forgetting;
- deviations from the approved mixture.

Nominal corpus inclusion does not establish meaningful training influence.

Signals such as gradient similarity or marginal learning value remain experimental and model-dependent.

## 15. Independent evaluation

Distributional Assurance requires evaluation outside the immediate generation and selection loop.

Holdouts should include selected combinations of:

- unseen semantic topology;
- unseen causal contrast;
- unseen rendering or discourse form;
- unseen source or generating process;
- unseen tool condition;
- future temporal slice;
- different organization or workflow;
- naturally occurring interaction where lawful and governed.

Evaluation should measure:

- semantic correctness;
- invariance consistency;
- counterfactual sensitivity;
- ambiguity detection and clarification precision;
- unnecessary clarification;
- abstention and over-abstention;
- failure localization;
- minimal-repair fidelity;
- right-answer/wrong-basis rejection;
- tool recovery and escalation;
- worst-group and rare-cell performance;
- clean-case regression;
- cost and operational efficiency.

Synthetic-origin or generator-origin detection may be monitored as a canary. It is not a primary capability objective.

## 16. CSD vertical-slice pilot

The first implementation shall remain narrow and executable.

### 16.1 Primary family: M-03

Use M-03 to exercise:

```text
validated clock event
→ evidence expiry
→ basis recomputation
→ semantic projection
→ registry updates
→ disposition
→ quarantine
→ committed completion
```

The pilot should construct controlled world families covering:

- clean deterministic success;
- missing, contradictory, stale, and ambiguous evidence conditions;
- tool availability, partial result, malformed result, timeout, and unknown commit status;
- sufficient, insufficient, and contested authority;
- novice, peer, expert, and mixed-audience renderings;
- unsupported verdict retention;
- wrong basis removal;
- right answer from an invalid basis;
- missed and unnecessary clarification;
- failed repair and overbroad rollback;
- abstention, escalation, block, and valid recovery.

### 16.2 Secondary family: M-15

Use M-15 to exercise:

```text
primary graph
+ materially different shadow graph
→ full replay
→ invariant or divergent classification
→ disposition without external-truth assertion
```

The pilot should cover:

- hidden-dependency changes;
- correct conclusion from incomplete structure;
- inappropriate irrelevance certification;
- model disagreement versus semantic disagreement;
- unresolved external truth;
- invariant and sensitivity contrasts across renderings.

### 16.3 Pilot corpus ablations

Compare at least:

1. current structural baseline;
2. surface-expanded baseline;
3. scenario-world contract coverage;
4. causal contrast coverage;
5. failure-and-repair coverage;
6. full Distributional Assurance vertical slice.

Where practical, control for accepted-token or episode volume.

### 16.4 Pilot authorization

The pilot does not authorize release scale unless it demonstrates:

- improved independent causal and failure holdout performance;
- no unacceptable clean-case regression;
- bounded unnecessary clarification and over-abstention;
- reduced right-answer/wrong-basis defects;
- reproducibility across approved seeds;
- complete optimizer exposure evidence;
- zero unresolved critical semantic mutation escapes.

## 17. Experimental backlog

The following may be tested but are not required architecture in v0.1:

- perplexity or surprise-based selection;
- embedding-space or effective-rank metrics;
- synthetic-origin classifiers;
- gradient-similarity or gradient-novelty sampling;
- distributionally robust optimization;
- entropy regularization;
- path-diversity losses;
- Monte Carlo tree search;
- auxiliary uncertainty or syntheticness heads;
- mixture-of-experts or architecture modifications;
- fixed real/synthetic mixture ratios;
- online adaptation;
- multi-agent generation as an independence mechanism.

Each experiment requires:

- a defined causal hypothesis;
- a primary metric;
- a symmetrical guardrail;
- a controlled baseline;
- a regression analysis;
- an intervention receipt;
- explicit evidence before policy freeze.

## 18. Required implementation artifacts

Under this approved doctrine, future implementation shall add separately versioned:

- scenario-world schema;
- generation-process schema;
- distribution-contract schema;
- causal-contrast policy;
- failure-topology catalog;
- release-report schema;
- optimizer-exposure schema;
- accepted and rejected canary vectors;
- validators;
- deterministic coverage compiler;
- pilot reports.

No implementation version number is frozen by this document.

## 19. Completion boundary

Distributional Assurance v0.1 doctrine documentation is complete because:

- AP-001 was approved through PR #59;
- Platform Charter v1.1 was published through PR #60;
- this document was accepted through PR #61;
- the roadmap and README were integrated through PR #62;
- exact executable schemas remain explicitly deferred to a future contract freeze.

Distributional Assurance as an implemented subsystem is not complete until the vertical slice, reports, optimizer exposure, and empirical transfer gates pass.
