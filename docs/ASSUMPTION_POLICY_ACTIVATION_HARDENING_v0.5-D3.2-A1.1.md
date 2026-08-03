# v0.5-D3.2-A1.1 Assumption Policy Activation Hardening

This slice closes the remaining contract gaps before cryptographic verification and persistent policy publication are implemented.

## Typed serialized boundary

The execution path accepts `AssumptionAuthorityPolicyCommitV2`, never `dict[str, object]`.

Untrusted JSON is parsed by `parse_policy_commit_v2`. The parser requires the exact closed field set and rejects unknown or missing fields, floats, booleans used as integers, nested collections in scalar fields, integers outside the interoperable JSON range, and non-version-2 commits. No mutable input object is retained after parsing.

## Exact ledger-state expectation

`ExpectedPolicyLedgerState` binds both the complete ledger root and the head entry digest. A `None` head is valid only with the canonical empty-ledger root. It therefore means “I observed the exact empty ledger,” never “I do not know the head.”

Publication APIs consume this exact expectation. Callers that have not reconstructed or read the ledger cannot append.

## Activation-proof binding

The executable entry now requires the activation proof to bind the exact:

- policy commit;
- approval policy and approval rule;
- signature profile;
- challenge-classification policy;
- authority root across the policy, approval policy, and key-authority profile;
- signature set.

Any mismatch fails as `ASSUMPTION_POLICY_ACTIVATION_PROOF_BINDING_MISMATCH`.

## Success-only execution API

The frozen service boundary separates:

```text
prepare(...) -> PreparedPolicyActivation
publish(prepared, expected_state) -> AssumptionPolicyActivationResult
```

Preparation and publication denials raise typed exceptions. `AssumptionPolicyActivationResult` remains success-only and represents only `COMMITTED` or `IDEMPOTENT_APPEND`.

`PreparedPolicyActivation` binds one validated ledger entry and makes no claim about a resulting ledger root.

## Deterministic competing append semantics

The normative concurrency vector uses deterministic interleaving:

```text
observe S0
build A against S0
build B against S0
append A against S0
append B against S0
```

Exactly one candidate commits. The stale sibling fails as `ASSUMPTION_POLICY_CHAIN_FORK`. Reversing A and B reverses the winner without changing the invariant.

A later filesystem implementation must additionally prove the physical no-clobber primitive with a bounded two-process test. That test is implementation assurance, not the normative semantic definition.

## Idempotence and corruption terminology

The relevant cases are distinct:

- identical entry digest and canonical bytes: `IDEMPOTENT_APPEND`;
- same policy commit with a different entry: `ASSUMPTION_POLICY_ENTRY_DIVERGENCE`;
- stored claimed digest or bytes inconsistent with the parsed entry: `ASSUMPTION_POLICY_STORED_OBJECT_DIGEST_MISMATCH`.

No conformance test attempts to construct a SHA-256 collision.

## Version lineage

Version 1 originated in D3.2-A0:

```text
assumption-policy-ledger-entry/1
assumption-policy-ledger/1
```

It represented structural approval-policy commitments using `AssumptionAuthorityPolicyCommit` and an approval receipt. It did not pin executable cryptographic verification semantics.

Version 2 originated in D3.2-A1:

```text
assumption-policy-ledger-entry/2
assumption-policy-ledger/2
```

It adds `AssumptionAuthorityPolicyCommitV2`, a pinned signature profile, a committed challenge-classification policy, and a cryptographic activation proof. Version-1 entries remain parseable historical contract artifacts but cannot be appended to or mixed with a version-2 executable ledger.

## Deliberate boundary

This hardening slice still does not implement cryptographic verification, signer-key resolution, persistent filesystem publication, exact grant execution, separation-of-duty execution, governed assumption append, use-time admissibility, staged projection, or temporal publication.
