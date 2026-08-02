# Evidence mutation assurance — v0.5-D2.3-B

## Status

This document defines the implemented D2.3-B assurance boundary for the v0.5 evidence-unit registry.

The campaign is committed by:

```text
data/canary/v0.5/evidence-mutations-v1/manifest.json
```

Its catalog digest is:

```text
sha256:e2fde18a05ef22069db68fcf74291f9f8380139d369489479410b5a8fcbf70da
```

## Purpose

D2.3-A proved that an independent validator reconstructs the committed evidence histories and expected decisions. D2.3-B tests whether that validator detects declared corruptions and semantic defects.

The campaign mutates serialized artifacts before validation. It does not mutate already-approved Python projections or bypass the contract parser.

```text
committed evidence-v1 catalog
        ↓
one declared serialized mutation
        ↓
recomputed specimen commitment where appropriate
        ↓
independent evidence validator
        ↓
stable detector and kill classification
```

## Classification

Every declared mutation is classified as exactly one of:

- `KILLED` — the expected detector rejected the specimen;
- `SURVIVED` — the specimen passed without the expected rejection;
- `EQUIVALENT` — the mutation is mechanically equivalent under the stated claim boundary;
- `INVALID_MUTATION` — the campaign failed to construct or evaluate the declared specimen as specified.

The D2.3-B merge gate permits no `SURVIVED` or `INVALID_MUTATION` result. Equivalent mutations require an explicit committed classification and rationale; the initial campaign contains none.

## Initial mutation families

The first campaign contains 17 mutations covering:

- authority substitution;
- material-challenge suppression;
- dependency removal and dependency cycles;
- expiry suppression;
- history deletion;
- event-digest and predecessor corruption;
- terminal-identity revival;
- limitation removal;
- noncanonical event order;
- authority-policy corruption;
- provenance rewriting;
- admissibility-receipt corruption;
- reuse escalation;
- registry-root corruption;
- scope widening.

Mutation operators either:

1. produce a validly committed but semantically defective rejected specimen and require the exact stable failure code; or
2. preserve the accepted-vector claim and require an expected known-answer mismatch.

Catalog commitments are recomputed after each mutation so ordinary catalog-digest failure cannot mask the intended detector, except for the mutation that explicitly targets the authority-policy commitment.

## Determinism

Identical baseline vectors and mutation manifests must produce byte-identical:

- mutated catalog commitments;
- specimen digests;
- observed detector codes;
- classification matrix;
- report digest.

The campaign runs through:

```text
csd-foundry-evidence-mutations-v0-5 --release v0.5
```

It is required in editable CI and in an external installed-wheel environment.

## Claim boundary

Successful execution establishes that the declared mutation inventory is killed relative to the committed `evidence-v1` corpus and the independent D2.3-A validator.

It does not establish:

- completeness of the mutation space;
- external truth of evidence;
- source completeness;
- real-world dependency completeness;
- distributed-consensus safety;
- production safety.

New escaped mutations must be retained and classified. They must not be deleted merely to restore a green campaign.
