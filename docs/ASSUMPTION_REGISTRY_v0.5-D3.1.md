# v0.5-D3.1 Assumption Lifecycle and Challenge Ledger

## Status

This document defines the implemented D3.0/D3.1 internal assumption contract. It does not alter the frozen v0.5 public contract catalog or install the assumption registry into the atomic temporal coordinator.

## Core model

The assumption registry uses two distinct state surfaces:

```text
ordered event history
→ order-sensitive lifecycle fold
→ standing + canonical active-challenge set
→ derived externally visible status
```

Stored standing is one of:

```text
PROPOSED | ADMITTED | CONFIRMED | REJECTED | EXPIRED | SUPERSEDED
```

`CHALLENGED` is derived when an admitted or confirmed assumption has at least one unresolved challenge. It is not the sole stored lifecycle state.

This preserves the corrected reduction split:

1. events are folded in predecessor and logical-clock order;
2. the resulting current challenge records are canonicalized by `challenge_id`;
3. later materiality and usability evaluation may aggregate over that current set commutatively.

D3.1 does not treat the event log itself as commutative.

## Proposal identity

`PROPOSE` freezes:

- exact proposition identity;
- exact scope identities;
- declared materiality;
- proposer authority identity;
- proposal and validity sequences;
- optional expiry sequence;
- typed assumption dependencies;
- typed evidence dependencies;
- limitations;
- maximum reuse class.

A proposal cannot depend on its own assumption identity. Cross-assumption missing-dependency and cycle checks are deliberately deferred to the D3.2 admission gate because the pure D3.1 reducer operates on one entity chain.

## Challenge identities

Every challenge declares:

- `challenge_id`;
- challenger authority identity;
- reason code;
- challenge receipt digest.

Multiple active challenges may coexist. The projection stores them canonically by challenge identity while preserving the order-sensitive history that produced the set.

`RESOLVE_CHALLENGES` targets an explicit, canonical, nonempty set of active challenge IDs and freezes:

- resolution outcome;
- resolver authority identity;
- resolution receipt digest;
- resolution basis code;
- resolved challenge identities;
- replacement assumption identity when the outcome is supersession.

Resolving one challenge does not clear unrelated active challenges. Therefore an assumption may have standing `ADMITTED` or `CONFIRMED` while its externally visible status remains `CHALLENGED`.

## Resolution outcomes

D3.1 recognizes four structural outcomes:

```text
RETURN_TO_ADMITTED
CONFIRM
REJECT
SUPERSEDE
```

D3.1 validates shape and lifecycle legality only. D3.2 must provide committed outcome-specific authority grants, including distinct authorization for confirmation versus return to admitted standing and any separation-of-duty rules.

`CONFIRMED` means affirmed under the declared governance process. It does not mean externally proven true.

## Expiry

`EXPIRED` is a first-class terminal standing and is distinct from `SUPERSEDED`.

```text
EXPIRED    = declared temporal validity ended
SUPERSEDED = a distinct replacement identity took its place
```

An explicit `EXPIRE` event is accepted only for admitted or confirmed standing, only when an expiry was declared, and only at or after the declared logical sequence. Automatic clock-driven expiry planning remains D3.3-C work.

A rejected, expired, or superseded identity cannot be reactivated. Renewal or replacement requires a new assumption identity.

## Store boundary

D3.1 uses the unchanged D1 `RegistryStore` protocol and the frozen `registry-event/1` envelope under:

```text
registry_type    = ASSUMPTION
projection_phase = ASSUMPTION_REGISTRY
payload version  = assumption-event/1
```

The store remains responsible for immutable event bytes, contiguous entity sequences, predecessor linkage, deterministic roots, restart reconstruction, and idempotent identical append handling.

## Deferred D3.2 work

D3.2 must add:

- committed operation- and outcome-specific authority policies;
- separation-of-duty enforcement;
- admission-time missing-dependency and cycle rejection;
- full-history authority revalidation at use time;
- materiality evaluation over the canonical current challenge set;
- decision-specific scope, limitation, validity, and reuse checks;
- deterministic work counters for replay and dependency traversal.

## Deferred D3.3 work

D3.3 must add independent conformance vectors, mutation assurance, logical-clock expiry planning, structured reassessment boundaries, impact receipts, and an attempt-local staged projection adapter.

The reassessment boundary must eventually bind an assumption transition to the exact downstream dependency-index root used to enumerate affected decisions, episodes, and artifacts. It requests reassessment; it does not itself invalidate those objects or rewrite `ControlState`.

## Claim boundary

D3.1 establishes deterministic assumption lifecycle reconstruction relative to the encoded payloads and registry history. It does not establish external truth, authority correctness, dependency-graph completeness, cycle freedom across identities, decision admissibility, disposition, quarantine, temporal atomic publication, or production safety.
