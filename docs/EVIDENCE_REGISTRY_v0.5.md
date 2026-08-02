# Evidence-Unit Registry v0.5-D2.1

## Status

This document describes the first substantive governed-registry slice under Issue #37.

D2.1 defines the internal `evidence-unit-event/1` payload semantics, typed current projection, deterministic lifecycle reducer, append-only registry integration, and lifecycle conformance tests. It does not alter the frozen public `registry-event/1` envelope or any released v0.5 contract bytes.

Authority-policy resolution, dependency admissibility, decision-class queries, temporal projection integration, disposition, and quarantine remain later work.

## Architectural boundary

```text
frozen RegistryEvent envelope
        +
internal evidence payload
        +
pure evidence reducer
        +
D1 append-only registry store
        ↓
current EvidenceUnit projection
```

The current projection is derived from immutable history. It is not stored inside mutable CSD `ControlState`.

## Lifecycle

```text
REGISTERED
    ├── VERIFIED
    │     ├── CHALLENGED
    │     │     ├── VERIFIED
    │     │     └── INVALIDATED
    │     ├── EXPIRED
    │     ├── INVALIDATED
    │     └── SUPERSEDED
    └── REJECTED
```

The terminal states are:

- `EXPIRED`;
- `INVALIDATED`;
- `REJECTED`;
- `SUPERSEDED`.

A terminal evidence identity cannot be restored or reverified. Restoration requires a new evidence identity, new source receipt, and later authority validation.

## Registration fields

The registration operation freezes:

- evidence identity from the registry envelope;
- proposition identity;
- sorted nonempty scope identities;
- source identity;
- issuer authority identity;
- issuance sequence;
- validity start;
- optional expiry sequence;
- sorted dependency identities;
- sorted limitation codes;
- maximum reuse class;
- registration receipt identity.

Subsequent operations cannot rewrite those registration fields.

## Operations

D2.1 admits these payload operations:

| Operation | Allowed prior state | Result |
|---|---|---|
| `REGISTER` | none | `REGISTERED` |
| `VERIFY` | `REGISTERED` | `VERIFIED` |
| `REJECT` | `REGISTERED` | `REJECTED` |
| `CHALLENGE` | `VERIFIED` | `CHALLENGED` |
| `RESOLVE_CHALLENGE: UPHOLD` | `CHALLENGED` | `VERIFIED` |
| `RESOLVE_CHALLENGE: INVALIDATE` | `CHALLENGED` | `INVALIDATED` |
| `EXPIRE` | `VERIFIED`, `CHALLENGED` | `EXPIRED` |
| `INVALIDATE` | `VERIFIED`, `CHALLENGED` | `INVALIDATED` |
| `SUPERSEDE` | `VERIFIED`, `CHALLENGED` | `SUPERSEDED` |

Every operation payload has an exact closed field set. Unknown, missing, or operation-inappropriate fields fail closed.

## Time and identity rules

- registration `issued_at_sequence` must equal the event clock sequence;
- `valid_from_sequence` cannot precede issuance;
- expiry must be strictly after validity begins;
- an `EXPIRE` operation cannot occur before the declared expiry sequence;
- entity-local sequence and predecessor identity must advance exactly;
- evidence clock sequence must advance strictly;
- an evidence identity cannot depend on itself;
- supersession must name a distinct replacement identity.

## Projection and persistence

`EvidenceRegistry.apply` performs:

```text
reconstruct current evidence history
→ validate and reduce candidate event
→ compare-and-append frozen RegistryEvent
→ return immutable current projection
```

An exact repeated event is idempotent. A competing writer that changes the entity head causes the D1 compare-and-append store to fail closed.

The projection retains both the registration source receipt and the current event source receipt. Complete event history remains reconstructable from the D1 registry store.

## Deliberate deferrals

D2.1 does not establish:

- whether a claimed authority is permitted to perform an operation;
- decision-specific evidence admissibility;
- dependency-cycle checks across multiple evidence identities;
- invalidation propagation into CSD bases;
- automatic expiry event construction by the temporal coordinator;
- evidence assurance beyond the declared maximum reuse class;
- external truth or real-world source completeness.

Those remain D2.2, D2.3, and later v0.5-D/E/F gates.
