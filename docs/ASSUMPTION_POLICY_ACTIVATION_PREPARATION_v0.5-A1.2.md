# Assumption Policy Activation Preparation v0.5-D3.2-A1.2

**Status:** Implemented preparation slice
**Date:** 2026-08-03
**Scope:** Deterministic activation preparation only; no publication
**Branch:** `feature/37-v0-5-assumption-policy-activation-preparation`

## 1. Purpose

This slice implements the preparation half of the D3.2-A1 activation order.
`ReferenceAssumptionPolicyActivationPreparer.prepare()` validates a candidate
policy activation against the frozen A1 contracts, runs cryptographic and
authority checks over the committed signature set, enforces the unique-signer
approval threshold, and returns a `PreparedPolicyActivation`.

It does not publish, does not touch a ledger store, and does not claim a
resulting root. A1.3 will compose this preparer with the persistent publisher
to provide the complete `AssumptionPolicyActivationService`.

## 2. Phase partition of the frozen activation order

`ACTIVATION_VALIDATION_ORDER` is frozen. A1.2 owns the preparation stages; A1.3
owns the ledger-dependent stages. This is a phase partition, not a change to
the overall order.

| Stage | Owner |
|---|---|
| `PARSE_AND_SELF_DIGESTS` | A1.2 (frozen contracts self-validate) |
| `EXACT_IDEMPOTENCE` | A1.3 |
| `POLICY_STRUCTURE_AND_OVERLAP` | A1.2 |
| `COMMIT_BINDINGS` | A1.2 |
| `LEDGER_POSITION` | A1.3 |
| `RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET` | A1.2 |
| `SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM` | A1.2 |
| `CRYPTOGRAPHIC_VERIFICATION` | A1.2 |
| `SIGNER_AUTHORITY` | A1.2 |
| `THRESHOLD_AND_REQUIRED_SIGNERS` | A1.2 |
| `ACTIVATION_PROOF_AND_ENTRY` | A1.2 |
| `COMPARE_AND_APPEND` | A1.3 |
| `ACTIVATION_RESULT` | A1.3 |

## 3. Architecture

### 3.1 Public types

```text
ResolvedAssumptionPolicyVerificationKey   # key material under committed root
ResolvedAssumptionPolicySignerAuthority   # scope/validity/revocation under root
AssumptionPolicyVerificationKeyResolver   # Protocol: resolve key material
AssumptionPolicySignerAuthorityResolver   # Protocol: resolve signer authority
AssumptionPolicySignatureVerifier         # Protocol: supports() + verify()
DeterministicAssumptionPolicySignatureVerifier  # conformance test double
ReferenceAssumptionPolicyActivationPreparer      # concrete prepare() impl
```

### 3.2 Separate verification-key resolution from signer authority

The frozen order places `CRYPTOGRAPHIC_VERIFICATION` before `SIGNER_AUTHORITY`.
A single resolver that authorized the signer before returning public-key bytes
would violate that order. Two separate protocols are defined:

* `AssumptionPolicyVerificationKeyResolver`: key-material resolution under the
  committed key root. Not a signer-authorization decision.
* `AssumptionPolicySignerAuthorityResolver`: scope, algorithm, logical validity,
  and revocation under the committed authority root.

### 3.3 Verifier capability distinction

`AssumptionPolicySignatureVerifier.supports()` distinguishes:

```text
algorithm absent from committed profile
  -> ASSUMPTION_POLICY_SIGNATURE_ALGORITHM_NOT_PINNED (structural, earlier stage)

algorithm/profile pinned but backend cannot execute it
  -> ASSUMPTION_POLICY_SIGNATURE_PROFILE_UNSUPPORTED

backend supports profile but signature does not verify
  -> ASSUMPTION_POLICY_SIGNATURE_INVALID
```

These are not collapsed into one Boolean.

## 4. Explicit fail-fast commit-binding checks

Before signature processing, the preparer explicitly verifies:

```text
commit.policy_id                      = policy.policy_id
commit.policy_digest                  = policy.policy_digest
commit.approval_policy_digest         = approval_policy.approval_policy_digest
commit.signature_profile_digest       = signature_profile.profile_digest
commit.challenge_classification...    = challenge_policy.policy_digest
commit.signature_set_digest           = signature_set.digest
commit.authority_root_digest          = policy.authority_root_digest
                                      = approval_policy.authority_root_digest
                                      = signature_profile.key_authority_root_digest
commit.grant_set_digest               = policy.grant_set_digest
commit.separation_duty_rule_set_digest = policy.separation_duty_rule_set_digest
commit.exception_set_digest           = policy.exception_set_digest
commit.exception_count                = len(policy.duty_exceptions)
commit.approval_class                 = STANDARD | DUTY_EXCEPTION per exceptions
```

The hardened ledger entry repeats these as defense in depth, but they are
detected here first so denials carry the `COMMIT_BINDINGS` stage.

## 5. Canonicalization, not input-order rejection

`signature-set/1` declares `signatures` as a semantic `SET`. The contract
canonicalizer sorts set members and makes the digest independent of input
ordering. The preparer derives a deterministic processing order; it does not
require the caller's array order to already be canonical.

Rejected: exact duplicate set members (contract layer); two distinct records
with the same `signer_id` (`ASSUMPTION_POLICY_DUPLICATE_SIGNER_RECORD`).

## 6. Per-record failure behavior

### Whole-attempt structural denial

Immediately denied: commit/object binding mismatch, policy overlap, signature-set
schema failure, duplicate signer identity, malformed Base64, algorithm absent
from profile, authority-scope field mismatch.

### Record-level rejected signer

Recorded as a stable rejection code, processing continues: unknown verification
key, cryptographically invalid signature, unknown signer authority, unauthorized
signer/key pairing, expired or revoked authority. The approval rule is enforced
over only valid authorized signer IDs. `rejected_signer_codes` carries the
canonical unique set of codes when preparation succeeds.

No backend diagnostic strings, signer-specific free text, or platform errors
appear in the proof.

## 7. Deterministic processing rules

```text
records processed in canonical order
valid signer IDs: unique, sorted, one signer = one vote
rejected signer codes: unique, sorted
all comparisons: exact and case-sensitive
logical-time intervals:
  valid_from_sequence <= effective_from_sequence
  valid_until_sequence is absent or effective_from_sequence < valid_until_sequence
  revocation_sequence is absent or effective_from_sequence < revocation_sequence
```

The profile-required authority scope must match exactly. No wildcard scope
interpretation unless the committed profile contract explicitly defines it.

## 8. Threshold enforcement (V2-specific)

`_validate_approval_threshold` reuses the A0 stable codes
(`ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE`, `_THRESHOLD_NOT_MET`,
`REQUIRED_SIGNER_MISSING`) but does not construct an A0 approval receipt (ledger
entry V2 does not contain one). Returns the selected approval rule so its digest
can be placed in the activation proof.

## 9. Boundary guarantee: no publication on any path

The preparer has no store and no publisher reference. Denials are therefore
architecturally incapable of:

* calling a ledger store;
* publishing a ledger entry;
* changing a ledger root;
* producing an `AssumptionPolicyActivationResult`;
* claiming a resulting root.

`prepare()` is success-only: success returns `PreparedPolicyActivation`; every
denial raises `AssumptionPolicyActivationDenied(code, stage, detail)`.

## 10. Claim boundary

The deterministic verifier is a conformance test double. It makes no production
cryptographic claim.

### 10.1 Signed-target binding under the frozen contract

Under the frozen A1 contract, `signature_set_digest` is a commit field, so
`commit_receipt_digest` transitively depends on the signature records. Requiring
`signed_digest == commit_receipt_digest` as a structural field equality creates a
non-converging fixpoint (changing the target changes the signature/set/commit
digest cycle). A real cryptographic backend binds the signature to the signed
digest natively; the deterministic conformance double does not fold
`signed_digest` into the expected signature bytes for this reason. The
`signed_digest` field is still schema-validated as a well-formed digest, and the
commit's `signature_set_digest` pinning binds the set to the commit.

This does not establish:

* production cryptographic key validity;
* production signature verification;
* external truth;
* general reasoning transfer;
* production safety.

## 11. Out of scope (A1.3)

* persistent policy-ledger publication;
* filesystem compare-and-append;
* historical `resolve_at`;
* exact grant selection.

## 12. Tests

27 tests in `tests/test_v0_5_assumption_policy_activation.py`:

* successful STANDARD/DUTY_EXCEPTION activation;
* exact threshold; permutation invariance; byte-identical determinism;
* extra invalid signer recorded while threshold succeeds;
* structural denials (policy overlap, commit binding mismatches, wrong scope,
  duplicate signer, malformed Base64, unpinned algorithm);
* cryptographic/key failures (unknown key, invalid signature, profile
  unsupported);
* signer-authority failures (unknown authority, expired, revoked, not-yet-valid);
* approval failures (ineligible signer, threshold minus one, missing mandatory);
* boundary guarantee (preparer has no store/publisher attribute).
