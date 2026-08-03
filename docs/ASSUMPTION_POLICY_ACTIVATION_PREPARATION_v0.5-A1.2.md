# Assumption Policy Activation Preparation v0.5-A1.2

**Status:** Implemented preparation slice (PR #50, draft)
**Date:** 2026-08-03
**Scope:** Deterministic activation preparation against the non-circular V3 signing envelope
**Branch:** `feature/37-v0-5-assumption-policy-activation-preparation`

## 1. Purpose

Executable preparation against the non-circular V3 signing envelope.
`ReferenceAssumptionPolicyActivationPreparer.prepare()` validates a candidate
policy activation, runs cryptographic and authority checks over the committed
signature set targeting `signing_payload_digest`, enforces the unique-signer
approval threshold, and returns a `PreparedPolicyActivation`.

It does not publish, does not touch a ledger store, and does not claim a
resulting root.

## 2. Construction sequence

```text
policy-generation facts
→ signing-payload/1
→ exact signing_payload_digest target
→ signature-set/1
→ commit/3
→ proof/2
→ entry/3
→ PreparedPolicyActivation
```

The signing payload excludes all signature-derived fields. Signatures target
`signing_payload_digest`:

```text
record.signed_digest
=
signing_payload.signing_payload_digest
```

There is no self-referential dependency.

## 3. Phase partition

A1.2 owns the preparation stages; A1.3 owns the ledger-dependent stages.

| Stage | Owner |
|---|---|
| PARSE_AND_SELF_DIGESTS (+ version gate) | A1.2 |
| EXACT_IDEMPOTENCE | A1.3 |
| POLICY_STRUCTURE_AND_OVERLAP | A1.2 |
| COMMIT_BINDINGS (V3 envelope) | A1.2 |
| LEDGER_POSITION | A1.3 |
| RESOLVE_APPROVAL_PROFILE_CLASSIFICATION_AND_SIGNATURE_SET | A1.2 |
| SIGNATURE_SET_SCHEMA_AND_CANONICAL_FORM | A1.2 |
| CRYPTOGRAPHIC_VERIFICATION | A1.2 |
| SIGNER_AUTHORITY | A1.2 |
| THRESHOLD_AND_REQUIRED_SIGNERS | A1.2 |
| ACTIVATION_PROOF_AND_ENTRY | A1.2 |
| COMPARE_AND_APPEND | A1.3 |
| ACTIVATION_RESULT | A1.3 |

## 4. Deterministic verifier

The deterministic verifier commits to:

```text
algorithm
verification profile
public-key bytes
signed digest
```

Changing only `signed_digest` changes the expected signature bytes. The verifier
is a conformance test double; it makes no production cryptographic claim.

## 5. Stable approval codes

The established A0 codes are used:

```text
ASSUMPTION_APPROVAL_SIGNER_INELIGIBLE
ASSUMPTION_APPROVAL_THRESHOLD_NOT_MET
ASSUMPTION_APPROVAL_REQUIRED_SIGNER_MISSING
```

Precedence: ineligible → threshold → required-signer.

## 6. Resolver output revalidation

After resolution, the preparer validates the returned object against the
request parameters:

* verification key: key_id, algorithm, key_authority_root_digest
* signer authority: signer_id, key_id, authority_root_digest

## 7. Backend exception normalization

All resolver and verifier calls are wrapped. Backend exceptions map to stable
record-level rejection codes, never leaking exception type, text, platform
diagnostics, or library-specific errors.

## 8. Typed denial contract

```text
success → PreparedPolicyActivation
denial → AssumptionPolicyActivationDenied(code, stage, detail)
```

No contract exception escapes from `prepare()`.

## 9. Boundary guarantee

The preparer has no store and no publisher reference. Denials are
architecturally incapable of publishing an entry, changing a ledger root, or
producing an activation result.

## 10. Out of scope (A1.3)

* persistent policy-ledger publication
* filesystem compare-and-append
* restart reconstruction
* historical resolve_at
* policy-at-event selection
* exact grant selection
* activation results
