# Governed Registry Substrate v0.5-D1

## Status

This document describes the first implementation slice of Issue #37: the deterministic append-only substrate shared by the evidence-unit, assumption, and alternative-model registries.

It implements storage and reconstruction mechanics only. CSD-specific lifecycle reducers, authority policies, full alternative-model replay binding, temporal projection integration, disposition, and quarantine remain subsequent slices.

## Frozen contract boundary

The substrate consumes the existing frozen `registry-event/1` envelope without changing its schema, catalog entry, canonicalization, digest domain, or known-answer vectors.

Every event carries:

```text
registry type
entity identity
entity-local sequence
previous entity event digest
committed clock sequence
frozen projection phase
source receipt digest
payload schema version
payload
content identity
```

The registry type fixes the only permitted projection phase:

| Registry type | Projection phase |
|---|---|
| `EVIDENCE_UNIT` | `EVIDENCE_REGISTRY` |
| `ASSUMPTION` | `ASSUMPTION_REGISTRY` |
| `ALTERNATIVE_MODEL` | `ALTERNATIVE_MODEL_REGISTRY` |

## Persistence model

Each event is installed at a content-addressed immutable path before a current head may cite it.

Each `(registry_type, entity_id)` has one compare-and-append head containing:

- entity-local sequence;
- current event digest;
- a domain-separated head commitment.

Head paths are derived from a domain-separated hash of registry type and entity identity. Entity values never become filesystem paths.

The POSIX reference store uses a process-shared file lock, fsynced temporary files, atomic replacement for current heads, hard-link no-clobber installation for immutable objects, and directory synchronization.

## Append protocol

```text
validate frozen RegistryEvent envelope
→ install immutable event object
→ lock registry state
→ load current entity head
→ verify exact next sequence
→ verify exact predecessor digest
→ publish new head atomically
→ unlock
```

An exact repeated event is idempotent. A different event at an occupied sequence, a missing or wrong predecessor, a malformed head, or conflicting immutable bytes fails closed.

Unreferenced immutable event objects created by losing or invalid append attempts never become current registry state.

## Snapshot and root semantics

A snapshot is computed separately for each registry type.

```text
sorted current entity heads
→ canonical internal snapshot value
→ REGISTRY_SNAPSHOT domain digest
```

The root is independent of event arrival order across different entities. The root is sensitive to registry type, entity identity, entity sequence, and current event identity.

The D1 root is an internal implementation commitment. It is not a new frozen public v0.5 contract and must not be represented as such without a versioned contract proposal.

## Historical reconstruction

Entity reconstruction follows `previous_entity_event_digest` from the captured current head to genesis and verifies:

- registry type;
- entity identity;
- exact descending sequence;
- predecessor continuity;
- event content identity;
- cycle absence;
- genesis termination.

Snapshot reconstruction returns one complete ordered chain for each entity in canonical entity order.

Invalidation, challenge, expiry, and supersession in later reducers will change current heads while preserving all historical event objects and reconstructable chains.

## Deliberate boundaries

This slice does not establish:

- evidence-unit lifecycle correctness;
- assumption lifecycle correctness;
- alternative-model replay correctness;
- authority or signature validity;
- substantive semantic projection;
- atomic integration with the temporal completion coordinator;
- disposition or quarantine behavior;
- distributed consensus;
- external truth;
- production safety.

Those remain explicit gates under Issue #37 and Epic #28.
