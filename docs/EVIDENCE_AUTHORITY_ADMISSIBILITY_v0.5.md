# Evidence Authority and Admissibility v0.5-D2.2

## Status

This document defines the second evidence-unit registry slice under Issue #37.

D2.2 adds two deterministic layers above the D2.1 lifecycle reducer:

```text
committed operation authority policy
        ↓
authority-gated append

current evidence projection
+ full authority-validated history
+ decision-specific use request
+ dependency graph
+ challenge materiality policy
        ↓
admissibility receipt
```

The implementation does not change the frozen public `registry-event/1` envelope, the internal `evidence-unit-event/1` lifecycle payload, or any released v0.5 contract bytes.

## Authority policy

An immutable evidence authority policy contains:

- a policy identity;
- the sequence at which it becomes effective;
- the committed authority-root digest;
- canonical operation-specific grants;
- a domain-separated policy digest.

Each grant binds:

```text
operation
+ authority identity
+ permitted evidence scopes
```

An empty grant scope means all scopes. A nonempty scope requires every evidence scope to be covered by the grant.

The governed registry checks authority before an event is appended. A denied event does not advance the entity head or alter the registry root.

The use-time evaluator independently revalidates every historical event against the supplied committed policy. This catches evidence histories that entered through the raw lifecycle reducer or that are no longer acceptable under a different policy context.

## Admissibility request

A decision-specific evidence-use request binds:

- decision identity;
- evidence identity;
- required proposition;
- required scopes;
- required reuse class;
- evaluation clock sequence;
- explicitly accepted limitation codes;
- a domain-separated request digest.

The evaluator checks:

1. the evidence identity exists;
2. every event in its history was authorized;
3. the root proposition matches;
4. requested scopes are covered;
5. the evidence is within its validity window;
6. the required reuse class does not exceed the maximum class;
7. every declared limitation is explicitly accepted;
8. the lifecycle status is usable;
9. active challenge materiality permits use;
10. every dependency is recursively admissible;
11. the dependency graph is acyclic.

## Challenge materiality

Challenge reasons are classified as `MATERIAL` or `ADVISORY` under a canonical challenge policy.

- `MATERIAL` blocks evidence use.
- `ADVISORY` permits use only when every other gate passes and records an advisory code in the receipt.
- an unknown challenge reason fails closed as `MATERIAL`.

The lifecycle remains `CHALLENGED`; admissibility does not rewrite the substantive evidence projection.

## Reuse classes

D2.2 applies this internal ordering:

```text
D0 < D1 < D2 < D3 < BENCHMARK
```

A use request is denied when its required class exceeds the evidence unit's declared maximum reuse class.

## Dependency semantics

Dependencies are evaluated recursively under the same decision scope, clock, reuse requirement, limitation acceptance, authority policy, and challenge policy.

A missing, inactive, expired, insufficient, unauthorized, materially challenged, or cyclic dependency makes the root evidence inadmissible.

The admissibility receipt records the current event digests of accepted dependencies. It does not mutate evidence history or CSD `ControlState`.

## Internal receipts

D2.2 produces domain-separated internal receipts for:

- authority decisions;
- evidence-use requests;
- admissibility decisions.

These objects are implementation commitments for deterministic validation. They are not additions to the frozen public v0.5 contract catalog.

## Claim boundary

D2.2 establishes deterministic authority and admissibility relative to:

- the supplied committed authority policy;
- the declared evidence lifecycle history;
- the declared scopes, validity, dependencies, limitations, and reuse class;
- the supplied challenge materiality policy.

It does not establish external truth, source authenticity beyond admitted receipts, policy correctness, dependency completeness, substantive CSD entailment, disposition, quarantine, release eligibility, or production safety.

## Remaining D2 work

D2.3 still needs:

- committed conformance vectors and validation report;
- mutation campaigns for authority bypass, scope widening, reuse escalation, expiry omission, challenge suppression, dependency omission, and cycle acceptance;
- temporal expiry-event construction;
- invalidation propagation into affected CSD bases;
- integration with the frozen temporal projection sequence.
