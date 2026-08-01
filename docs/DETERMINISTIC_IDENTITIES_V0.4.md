# CSD Foundry v0.4 Deterministic Identities

## Canonical payload boundary

Digest-bearing identity inputs use an immutable canonical-value algebra. It accepts only
null, exact booleans, exact integers, UTF-8 strings, immutable arrays, and immutable
objects with unique keys in unsigned UTF-8 byte order. Floats, mutable containers,
bytes, sets, arbitrary enums, dataclasses, and arbitrary Python objects are rejected.
The values `1`, `"1"`, and `true` are distinct.

## Generation namespace

Every identity is permanently bound to one generation namespace containing the choice
algorithm, identity algorithm, target-definition digest, release-policy digest,
arithmetic-policy digest, replay-policy contract, and shard-policy contract. Adding an
unrelated target does not change an existing identity because the collection-level target
catalog digest is excluded. A changed target definition creates a new namespace.
Committed canary, pilot, and release artifacts are immutable within their namespace;
behavior-affecting changes coexist under a new version rather than rewriting evidence.

## Identity algorithm

Algorithm version 1 is `csd-identity-hmac-sha256`. The HMAC key is the exact root seed.
The message is:

```text
b"csd-identity-hmac-sha256/v1\x00"
|| uint64_be(len(canonical_material))
|| canonical_material
```

The full 256-bit digest is retained in the ledger. Display identifiers retain 128 digest
bits and use an entity-kind prefix. Duplicate semantic allocations, unknown role lookup,
full-digest collisions, and display-prefix collisions fail closed. No encounter-order
repair or suffixing is permitted.

## Exact collision assurance

For `n` identities and `b` retained digest bits, the conservative birthday union bound is:

```text
P(collision) <= n(n - 1) / 2^(b + 1)
```

At `n = 10,000,000` and `b = 128`, the exact bound is
`99,999,990,000,000 / 2^129`, which is below the exact policy ceiling
`15 / 100,000,000,000,000,000,000,000,000`. The ten-million count remains a
provisional design envelope. It must be recalculated from pilot-derived per-kind volumes
before release-scale policy freeze.

## Claim boundary

Passing identity validation establishes canonical payload typing, generation-namespace
binding, deterministic concrete identities, immutable known-answer vectors, collision
injection handling, and provisional collision mathematics. It does not establish attempt
replay, shard merging, structural identity, planner completeness, state construction, or
release-scale output.
