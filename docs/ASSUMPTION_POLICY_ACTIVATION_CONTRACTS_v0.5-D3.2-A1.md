# v0.5-D3.2-A1 Assumption Policy Activation Contract Freeze

This slice freezes the executable contract boundary required before persistent policy publication and cryptographic activation are implemented.

## Cryptographic profile

An executable policy generation uses `assumption-authority-policy-commit/2`. The commit binds:

- the immutable authority policy;
- predecessor policy and commit digests;
- logical activation sequence;
- approval policy;
- signature-set digest;
- `assumption-policy-signature-profile/1`;
- `assumption-challenge-classification-policy/1`.

The signature profile pins the accepted `signature-set/1` schema, signature-record semantics, exact algorithm profile identifiers, authority scope, key-authority root, and one-signer-one-vote duplicate handling. A version-1 assumption policy commit remains parseable historical data but is not executable by A1.

## Fail-fast validation order

The normative order is:

```text
closed schemas and self-digests
→ exact idempotence lookup
→ policy structure and overlap
→ commit bindings
→ ledger position
→ resolve approval/profile/classification/signature objects
→ signature-set canonical validation
→ cryptographic verification
→ signer-authority validation
→ threshold and required signers
→ activation proof and ledger entry
→ compare-and-append
→ activation result
```

Structural grant overlap therefore fails before cryptographic work.

## Entry and result separation

`assumption-policy-ledger-entry/2` is the activated generation. It contains complete policy content, commit v2, approval policy, signature profile, challenge-classification policy, and a pre-append activation proof.

The append result is separate because it binds predecessor and resulting ledger roots. Including it inside the entry would create a circular digest dependency.

## Ledger root

`assumption-policy-ledger/2` preserves the A0 root algorithm:

```text
sha256(
  "ASSUMPTION_POLICY_LEDGER" || NUL ||
  canonical_json({
    schema_version,
    complete ordered ledger entries
  })
)
```

The visible root is not a Merkle root, head-only hash, concatenated digest, or storage-engine checksum.

## Idempotence and collisions

Exact idempotence requires both:

```text
candidate ledger-entry digest == committed digest
and
candidate canonical bytes == committed canonical bytes
```

The error precedence is:

```text
exact idempotence
→ predecessor/head match
→ effective-sequence monotonicity
```

A current-head successor with an equal sequence fails with `ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING`. Once a competing successor has committed, a stale sibling fails with `ASSUMPTION_POLICY_CHAIN_FORK`.

## Challenge-derived grant inputs

Resolution authority may not trust caller-supplied challenge materiality. The resolver must bind the candidate event to the current assumption head, read `resolved_challenge_ids` from that event, verify every identity is currently unresolved, and classify the corresponding committed reason codes through the policy generation's challenge-classification policy.

Unknown reason codes fail closed as `CRITICAL` in version 1.

## Deliberate boundary

This slice does not implement signature verification, signer-key resolution, persistent ledger publication, exact grant selection, separation-of-duty execution, governed assumption append, use-time admissibility, staged projection, or temporal publication. Those operations must consume these frozen contracts rather than inventing parallel semantics.
