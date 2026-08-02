# Evidence Conformance v0.5-D2.3-A

## Status

This document defines the committed conformance boundary for the v0.5-D2 evidence-unit registry under Issue #37.

D2.3-A freezes a versioned evidence conformance corpus, an independent serialized-artifact validator, a validation report, and an installed-package CLI gate. It does not modify the frozen public `registry-event/1` envelope or any released v0.5 contract bytes.

## Objective

Establish that evidence histories, authority decisions, registry roots, and decision-specific admissibility can be reconstructed and checked from committed serialized artifacts without trusting the D2.1 lifecycle reducer or D2.2 admissibility evaluator that produced them.

```text
committed event and policy bytes
        ↓
independent contract parsing
        ↓
independent history reconstruction
        ↓
independent authority evaluation
        ↓
independent admissibility evaluation
        ↓
known-answer roots and receipts
```

## Committed corpus

The corpus is stored under:

```text
data/canary/v0.5/evidence-v1/
```

The manifest commits:

- vector schema version;
- authority-policy bytes and digest;
- challenge-policy bytes and digest;
- accepted and rejected vector file lists;
- vector catalog digest;
- claim boundary.

The catalog digest is:

```text
sha256:32a7b0e3d3ba7ebd50f88b4c0c939fdd23f4a2394592d4e049bf717bb65701b4
```

### Accepted histories

The five accepted vectors cover:

1. registration and verification;
2. a material challenge that blocks use;
3. an advisory challenge that remains visible but permits use;
4. a verified dependency chain;
5. explicit acceptance of a declared limitation.

Each accepted vector commits:

- exact `RegistryEvent` objects;
- expected authority-decision digests;
- expected current statuses;
- expected current event digests;
- expected registry root;
- exact evidence-use request;
- expected admissibility result and receipt digest.

### Rejected histories and uses

The eight rejected vectors cover:

- unauthorized verification;
- terminal identity revival;
- predecessor mismatch;
- event-digest mismatch;
- insufficient use scope;
- reuse-class escalation;
- dependency cycle;
- expiry enforced at use time.

Each rejected vector declares the validation stage and expected stable failure code.

## Independent validator

`evidence_validation.py` deliberately does not call:

- `reduce_evidence`;
- `project_evidence_history`;
- `EvidenceAuthorityResolver`;
- `EvidenceAdmissibilityEvaluator`.

It independently verifies:

- `RegistryEvent` contract identity;
- registry type, projection phase, and payload version;
- entity sequence and predecessor linkage;
- strictly advancing entity-local clock values;
- lifecycle transition legality;
- terminal identity non-reactivation;
- immutable registration fields;
- operation-specific authority grants;
- authority decision digests;
- proposition, scope, validity, reuse, and limitation constraints;
- material and advisory challenge behavior;
- recursive dependency admissibility and cycle rejection;
- current registry root;
- evidence-use request identity;
- admissibility receipt identity.

The validator emits `EvidenceRegistryValidationReport` with accepted roots, accepted receipt digests, rejected failure codes, the vector catalog digest, and any errors.

## CLI and packaging

The validation gate is exposed as:

```text
csd-foundry-evidence-v0-5 --release v0.5
```

All evidence canary files are installed under the package shared-data root and the CI workflow executes the gate both:

- from an editable repository installation;
- from a wheel installed outside the repository.

## Claim boundary

This slice establishes deterministic evidence-history, authority, dependency, and admissibility behavior relative to the committed vectors and encoded policies.

It does not establish:

- external truth;
- source truthfulness or completeness;
- real-world dependency completeness;
- semantic completeness of the CSD ontology;
- production cryptographic validity;
- distributed consensus;
- production safety.

## Deliberate deferrals

D2.3-A does not implement:

- the evidence mutation campaign and kill matrix;
- deterministic automatic expiry-event planning;
- evidence invalidation impact receipts;
- the standalone evidence projection adapter for D5;
- assumption or alternative-model registries;
- temporal coordinator installation;
- disposition, quarantine, release, or promotion.

Those remain D2.3-B, D2.3-C, D3, D4, D5, and later v0.5 slices.
