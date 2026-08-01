# CSD Foundry v0.4 Deterministic Choices

## Normative algorithm

Algorithm version 1 is `csd-choice-hmac-sha256-rejection`. It uses only
HMAC-SHA-256. Plain concatenated SHA-256 is not an alternative implementation.

The HMAC key is the exact 32-byte root seed. The message is:

```text
b"csd-choice-hmac-sha256-rejection/v1\x00"
|| uint64_be(len(canonical_material))
|| canonical_material
|| uint64_be(draw_index)
|| uint64_be(block_index)
```

Both counters are local to one choice, zero-based, unsigned 64-bit, and big-endian.
Canonical material is the existing integer-only canonical JSON representation, including
its terminal newline.

## Rejection and redraw

For bound `u`, candidate width is the smallest whole-byte width representing `u - 1`,
with a minimum of one byte. `limit = 256**width - (256**width % u)`. Blocks are
concatenated in ascending block-index order and truncated to the candidate width. A
candidate below `limit` returns `candidate % u`.

A rejected candidate is discarded completely. The next draw increments `draw_index`,
resets `block_index` to zero, and derives a new candidate. Rejected bytes are never
reused. Frozen known-answer vectors include two consecutive rejected draws and a 34-byte
candidate requiring two HMAC blocks.

## Attempts and timeouts

Attempt indices are unsigned 32-bit values. A declared attempt range contains between
one and 2^32 attempts. The accepted result is the lowest valid attempt index. Speculative
parallel execution cannot commit a higher successful attempt until every lower attempt
is resolved; this is a deliberate correctness-over-throughput trade-off.

Wall-clock expiry is an operational worker failure, not semantic search exhaustion. An
interrupted sample must be rescheduled from its immutable sample key. Future shard
sealing must reject missing, unexpected, or conflicting sample completions.

## Seeds

Release mode requires exactly 32 bytes represented as 64 lowercase hexadecimal
characters and `uniform-random-256` provenance. Text-derived seeds are restricted to
development and frozen known-answer fixtures and are release-ineligible.

## Identity sizing and immutability

The future display-identity layer is pinned to at least 128 digest bits for a design
ceiling of ten million identities. The exact birthday-bound upper estimate must remain
below the exact policy ceiling.

Once canary, pilot, or release evidence is committed under algorithm version 1, it is
immutable. Any behavior-affecting change requires a new algorithm version and a
coexisting artifact namespace; it cannot rewrite version-1 evidence.

## Claim boundary

Passing deterministic validation establishes the algorithm, seed, path, counter, and
committed known-answer-vector contract. It does not establish entity identity
allocation, production shard orchestration, planner completeness, state construction,
or release-scale output.
