# v0.5-D2.3-C Evidence Expiry and Projection Boundary

## Status

This document defines the implemented D2.3-C internal evidence projection boundary. It does not change the frozen v0.5 public contract catalog.

## Purpose

D2.3-C completes the operational surface of the evidence-unit registry by adding:

1. deterministic logical-clock expiry planning;
2. explicit evidence impact receipts;
3. an attempt-local evidence projection adapter suitable for later D5 temporal installation.

The implementation preserves the governing separation:

```text
evidence transition
→ candidate reassessment impact
→ later semantic projector decision
```

The evidence registry does not rewrite `ControlState`, decide whether a CSD basis survives, or publish a temporal successor.

## Logical-clock expiry

`EvidenceExpiryPlanner` reads a committed evidence snapshot and proposes `EXPIRE` events only when:

- the evidence is `VERIFIED` or `CHALLENGED`;
- an `expires_at_sequence` was declared;
- the supplied committed logical clock is at or beyond that sequence;
- the evidence identity has not already received an event at the same clock sequence;
- the identity is not terminal;
- the committed authority policy permits the configured expiry authority.

The planner:

- never uses wall-clock time;
- orders proposals by evidence identity;
- preserves exact predecessor and entity sequence linkage;
- produces byte-identical plans for byte-identical inputs;
- does not mutate the supplied registry store.

## Evidence impact receipts

`EvidenceImpactReceipt` is emitted for `CHALLENGE`, `EXPIRE`, `INVALIDATE`, and `SUPERSEDE` transitions. It records:

- the changed evidence identity;
- previous and current lifecycle states;
- the triggering event digest;
- known transitive evidence dependents;
- resolver-supplied candidate CSD basis identities;
- resolver-supplied candidate semantic-object identities;
- the staged evidence root at the point of impact;
- an explicit completeness boundary.

The receipt means `REASSESSMENT_REQUIRED`. It is not a semantic verdict, external-truth claim, disposition decision, or quarantine decision.

## Staged projection

`StagedEvidenceProjectionAdapter` accepts:

```text
ClockClaim
+ ValidatedEvent
+ SemanticProjectionReceipt
+ committed evidence registry snapshot
+ committed evidence authority policy
→ EvidenceProjectionPlan
```

The adapter:

1. validates claim, event, semantic-receipt, and sequence binding;
2. clones the committed evidence registry into an isolated attempt-local store;
3. resolves and applies explicit evidence intents in canonical entity/sequence order;
4. plans and applies logical-clock expiry events against the resulting staged state;
5. emits authority-decision and impact-receipt digests;
6. computes the projected evidence registry root;
7. returns one digest-bound `EvidenceProjectionPlan`.

The committed evidence store remains unchanged on success and failure.

## D5 boundary

D2.3-C deliberately does not publish staged events or roots. D5 must provide the atomic publication protocol that binds:

```text
predecessor evidence root
+ staged evidence events
+ projected evidence root
+ clock completion
```

A D5 implementation must ensure that a failed registry phase exposes neither a partial current registry root nor a committed temporal successor.

## Claim boundary

D2.3-C establishes deterministic expiry proposals, staged evidence projection, authority binding, dependency-impact enumeration, and root commitments relative to the encoded CSD evidence semantics and supplied resolvers.

It does not establish:

- external truth;
- completeness of real-world evidence dependencies;
- completeness of CSD basis indexing;
- correctness of later semantic reassessment;
- atomic cross-registry publication;
- disposition or quarantine correctness;
- distributed consensus;
- production safety.
