# Architecture Proposal 001 — Distributional Assurance

**Status:** APPROVED  
**Proposal:** AP-001  
**Date:** 2026-08-04  
**Approved:** 2026-08-04  
**Approval PR:** #59  
**Approval commit:** `4ccc60c06b7f97703d1d3a574475f54b5cc34dde`  
**Issue:** #55  
**Parent epic:** #54  
**Affected constitutional document:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.0.md`

## 1. Decision requested

Approve Distributional Assurance as an independent, cross-cutting quality plane of CSD Foundry.

The proposed governing model is:

```text
Foundry quality
=
Oracle integrity
× Structural assurance
× Distributional assurance
```

The three planes are jointly necessary and have separate authority:

- **Oracle integrity** establishes whether a state, transition, support relation, conclusion, or repair is valid relative to the applicable executable semantics, oracle, evidence, and policy.
- **Structural assurance** establishes whether required semantic structures are represented, canonicalized, isolated into valid splits, and challenged by mutation and holdout policy.
- **Distributional assurance** establishes whether those structures are exercised across declared, realistic, behaviorally consequential worlds, information states, intentions, policies, tool conditions, failures, recoveries, sources, and generating processes.

Passing one plane does not imply passage of another.

## 2. Motivation

The repository already prevents several forms of false confidence:

- internal consistency is not external truth;
- simulation is not real-world outcome;
- model agreement is not verification;
- search exhaustion is not infeasibility;
- semantic conclusion and operational disposition remain separate;
- rendered rows are not the authoritative product.

A remaining failure mode sits above ordinary schema validity, label correctness, lexical diversity, and semantic-topic coverage.

A corpus may be:

- perfectly labeled;
- executable against the encoded doctrine;
- structurally canonicalized;
- mutation-tested;
- split-isolated;
- diverse in wording, names, topics, formats, and personas;

while repeatedly encoding one narrow latent pattern:

```text
well-specified request
→ orderly decomposition
→ predictable evidence or tool use
→ clean successful transition
→ polished conclusion
```

Such a corpus can satisfy mechanical diversity checks while providing weak support for transfer under ambiguity, changing intentions, expertise differences, tool failures, contradictory evidence, non-linear recovery, authority limits, or unfamiliar discourse forms.

This proposal names that risk **distributional collapse** and introduces a governed response: **Distributional Assurance**.

## 3. Proposed constitutional change

Publish `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md` with the following additions.

### 3.1 Cross-cutting assurance plane

Distributional Assurance shall apply across:

- domain compilation;
- scenario and trajectory synthesis;
- executable environments and tool traces;
- canonical cognition episodes;
- filtering and selection;
- training mixtures and optimizer exposure;
- evaluation and independent transfer;
- runtime failure and distribution-gap harvesting.

It is not a fifth semantic substrate and does not absorb the authority of the governed execution, domain-compilation, oracle-federation, or governed-exploration substrates.

### 3.2 Constitutional invariant

Add:

> **`DIST-SAFE-01` — Distributional-assurance separation**  
> Semantic validity and structural coverage do not establish distributional adequacy. Every corpus, training, benchmark, or runtime-governance release that makes a distributional claim must bind that claim to an explicit distribution contract, scenario-world ontology, generating-process provenance, causal contrast evidence, and claim boundary. Distributional novelty may govern selection, coverage, or release eligibility, but it may not establish or rewrite a substantive semantic conclusion.

### 3.3 Provenance extension

Extend provenance closure so promoted cognition artifacts can trace, where applicable, to:

- canonical scenario-world identity;
- source and seed identity;
- generator model and generation policy;
- objective and interaction configuration;
- environment and fault policy;
- transformation chain;
- filter and annotation policy;
- recursive synthetic ancestry;
- distribution contract and contract-cell assignment;
- causal contrast and failure-topology identity.

### 3.4 Training-product extension

Extend the proof-carrying cognition episode boundary so an episode may carry linked:

- semantic state and receipts;
- epistemic state and support status;
- interaction and tool topology;
- failure and repair topology;
- scenario-world descriptors;
- generation-process provenance;
- distribution-contract membership and claim boundary.

Rendered prose remains non-authoritative.

### 3.5 Breadth extension

Extend preferred breadth and quality evidence beyond domain count, row count, topic labels, and format counts to include:

- effective behavioral support;
- marginal, conditional, and interaction coverage;
- causal invariance and sensitivity;
- ambiguity and information-state coverage;
- failure, recovery, abstention, and escalation coverage;
- source, generator, judge, and process concentration;
- rare-cell retention;
- independent source, process, temporal, discourse, tool, and structural transfer;
- actual optimizer exposure rather than nominal corpus inclusion.

### 3.6 Prohibited shortcuts

Add explicit prohibitions against:

- treating one scalar entropy or diversity score as sufficient release evidence;
- treating paraphrase, topic, persona, format, or vocabulary counts as proof of meaningful support;
- promoting semantically invalid material because it is novel or rare;
- allowing a generator or one learned judge to certify its own distributional adequacy;
- combining semantic and distributional authority in one undifferentiated learned score;
- claiming real-world completeness from conformance to a declared ontology or contract;
- fixing universal human/synthetic ratios, entropy thresholds, or training objectives without measured evidence.

## 4. Definitions

### 4.1 Effective distributional support

The set of materially different scenario worlds and cognition trajectories represented by a corpus or training process, after collapsing differences that do not change the relevant state, decision, policy, or recovery structure.

Ten thousand differently worded examples that require the same operation sequence and decision may occupy one effective support region.

### 4.2 Canonical scenario world

A machine-identifiable world description that binds the consequential conditions under which cognition occurs, including semantic family, context, actor intention, information state, ambiguity, expertise relation, discourse form, tool condition, authority, risk, reasoning-policy family, failure topology, and outcome class.

The exact schema is not frozen by this proposal.

### 4.3 Consequential behavioral distinction

A change in the scenario world that requires a different substantive decision, information-acquisition action, tool policy, clarification behavior, abstention, escalation, or repair.

### 4.4 Causal contrast family

A group of controlled scenario variants derived from one canonical world and used to test:

- **invariance:** irrelevant changes preserve the substantive result;
- **sensitivity:** one consequential change produces the required behavioral change;
- **information removal:** missing decisive information causes clarification, observation, qualification, abstention, or escalation;
- **failure and repair:** a typed failure is detected, localized, and repaired or terminated safely.

### 4.5 Failure ecology

A governed set of failure types and recovery obligations, including incomplete or contradictory information, stale evidence, insufficient authority, malformed or partial tool output, unknown commit state, unsupported conclusions, correct answers from invalid bases, missed or unnecessary clarification, failed repair, and overbroad rollback.

### 4.6 Generating-process provenance

The immutable identity and lineage of the causal process that produced an episode, including generator, objective, source seed, environment, interaction configuration, filters, annotation, and recursive ancestry.

Different prompts, personas, or temperatures do not by themselves establish independent generating processes.

### 4.7 Distribution contract

A versioned declaration of the support a release is required to cover. It may specify marginal, pairwise, selected higher-order, risk-driven, failure, source, ancestry, and holdout requirements together with forbidden combinations, infeasibility evidence, and claim boundaries.

### 4.8 Distributional claim boundary

The maximum claim permitted by the declared ontology, contract, evidence, and evaluation. Passing a distribution contract establishes coverage relative to that declared contract. It does not establish completeness relative to all real users, future tools, organizations, domains, cultures, or deployment conditions.

## 5. Authority boundaries

Distributional Assurance introduces no new semantic authority.

| Authority | Permitted decision |
|---|---|
| Semantic oracle | Whether the substantive state, transition, support relation, conclusion, or repair is valid |
| Execution verifier | What an environment or tool executed or returned |
| Structural assurance | Whether semantic structures are canonical, isolated, and mutation-tested |
| Distributional assessor | Which declared world, contrast, failure, source, and process regions an episode occupies |
| Provenance validator | Whether source and process lineage are complete and internally consistent |
| Behavioral evaluator | Whether behavior changes appropriately under controlled contrasts |
| Disposition authority | Whether an asset may proceed, be held, quarantined, or excluded |
| Human adjudicator | High-impact disputes that cannot be mechanically resolved under the current doctrine |

A distributional assessor may reject a release claim or mark a contract gap. It may not convert an invalid semantic trajectory into a valid one.

## 6. Compatibility and migration

### 6.1 Historical immutability

This proposal does not modify or reinterpret:

- the immutable CSD Reasoning Seed v0.1;
- v0.3 temporal/governance semantics;
- v0.4 synthesis and deterministic execution contracts;
- frozen v0.5 schemas, policies, vectors, digests, receipts, or semantic artifacts.

### 6.2 Successor capability

Distributional Assurance will be implemented only through successor documents and future contract versions. Existing artifacts may be referenced as baselines, anchors, or inputs, but their historical claims remain unchanged.

### 6.3 Roadmap integration

The current v0.5 governed-execution frontier remains the immediate implementation priority. Executable Distributional Assurance work is sequenced with constraint-valid synthesis, structural assurance, Verified Cognition Episodes, and the empirical model pilot after the governed v0.5 vertical slice and release boundary are complete.

### 6.4 No implied implementation

Approval of this proposal does not establish that:

- a scenario-world schema exists;
- a distribution contract has been compiled;
- causal contrasts have been generated;
- failure topologies have been implemented;
- source processes are independent;
- optimizer exposure is adequate;
- any trained model transfers better;
- recursive synthetic collapse has been prevented.

Those remain implementation and empirical claims.

## 7. Safety and claim-boundary analysis

Distributional Assurance can itself create new failure modes if implemented carelessly.

### 7.1 Novelty over correctness

Maximizing unusual examples may admit invalid, incoherent, or irrelevant data. Semantic correctness remains a hard gate.

### 7.2 Artificial complexity

Forcing multiple paths or failures can teach unnecessary branching, retries, clarification, pessimism, or theatrical self-correction. Coverage must be conditioned on realistic and consequential distinctions.

### 7.3 Taxonomy completion illusion

A frozen ontology can omit important worlds while reporting complete coverage. Every contract must state its claim boundary and accept runtime or external challenge.

### 7.4 Evaluator monoculture

One judge may erase generator diversity by selecting one preferred style or reasoning geometry. Judge authority must be separated and disagreement preserved when legitimate.

### 7.5 Recursive lineage opacity

Immediate source labels may conceal deeper synthetic ancestry. Provenance must support ancestry reconstruction rather than only first-generation labels.

### 7.6 Deployment contamination

Real logs are not automatically correct, lawful, private, representative, or independent. External observations require governance, sanitization, and separate semantic validation.

## 8. Rejected alternatives

### 8.1 Add more personas and topics

Rejected as sufficient architecture. These may improve rendering coverage but do not establish distinct world states, policies, or failures.

### 8.2 Maximize a global entropy score

Rejected. The relevant variables and target distribution are not fully observable, and maximum entropy can reward unrealistic combinations.

### 8.3 Require a fixed human-data percentage

Rejected as a universal policy. Source independence, semantic quality, deployment relevance, ancestry, and empirical transfer matter more than one fixed ratio.

### 8.4 Use synthetic-origin detection as the gate

Rejected as semantic or distributional authority. Detectability can expose production signatures but may measure style rather than reasoning support.

### 8.5 Change model architecture or training loss first

Rejected as the initial intervention. The project must first isolate effects from world construction, contrasts, failure ecology, provenance, selection, sampling, and evaluation.

### 8.6 Let multi-agent agreement certify diversity

Rejected. Multiple agents may share weights, sources, objectives, and blind spots. Independence requires provenance and evidence.

## 9. Approved successor documents

Approval of AP-001 authorized publication of:

1. `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md` through PR #60;
2. `docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md` through PR #61;
3. `docs/STRATEGIC_ROADMAP.md` v1.2 through PR #62;
4. README navigation and boundary updates through PR #62.

Future executable work shall use separately versioned schemas, policies, conformance vectors, validators, reports, and pilot evidence.

## 10. Approval record

AP-001 was approved through PR #59 on 2026-08-04.

Approval authorizes:

- Platform Charter v1.1;
- Distributional Assurance v0.1 contract design;
- Roadmap v1.2 integration;
- future executable work under separately versioned contracts.

Approval does not establish:

- executable Distributional Assurance schemas;
- causal contrast implementation;
- distributional completeness;
- generating-process independence;
- optimizer-exposure adequacy;
- empirical model transfer;
- readiness for release-scale generation.
