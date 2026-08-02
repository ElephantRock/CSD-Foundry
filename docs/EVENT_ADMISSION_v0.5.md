# Validated Event Admission v0.5

## Status

This document describes the executable v0.5-B admission boundary implemented under Issue #31. The frozen schemas and digest rules remain governed by `docs/CONTRACT_FREEZE_v0.5.md`.

## Purpose

Event admission converts untrusted event material into exactly one immutable outcome:

```text
RawEvent + SignatureSet + ValidationPolicy + committed context
                         |
                 deterministic admission
                  /                    \
         ValidatedEvent       EventValidationFailure
         reducer-consumable       audit-only
```

Admission establishes that the input passed the pinned validation policy, signature-verifier result, signer-authority resolution, and committed-context checks. It does not establish that the event is true or semantically valid under CSD.

## Authority boundary

The engine depends on five explicit interfaces:

- `CommittedContextResolver`
- `SignatureVerifier`
- `SignerAuthorityResolver`
- `ValidationPolicyRegistry`
- `EventAdmissionStore`

Cryptographic verification is delegated to `SignatureVerifier`. The committed reference validator uses a deterministic test double and makes no production-key claim.

## Processing order

The engine performs the following fail-closed sequence:

1. Parse and validate `RawEvent`, `SignatureSet`, and `ValidationPolicy` identities.
2. Resolve the requested tick and verify that it is the latest committed validation context.
3. Resolve the exact policy digest and verify that the policy is allowed for that context.
4. Verify the event payload schema against the policy.
5. Verify each signature's event digest, algorithm, verifier result, signer identity, authority scope, and duplicate-signer status.
6. Evaluate the integer signature threshold.
7. Persist the reconstructable inputs and emit exactly one accepted or failure receipt.

No `CsdOracle` call or semantic state transition occurs in this layer.

## Accepted outcome

A `ValidatedEvent` pins:

- `raw_event_digest`
- `validation_policy_digest`
- `signature_set_digest`
- `validated_at_tick`
- `validation_result = ACCEPTED`

Reducers must call `require_validated_event` or accept an equivalent statically restricted type. `RawEvent` and `EventValidationFailure` are rejected at this boundary.

## Failure outcome

Every rejected request produces one `EventValidationFailure` and no `ValidatedEvent`. Failure codes come from the frozen v0.5 registry and are stored as a canonical set.

The committed validation campaign covers:

- raw schema rejection;
- raw digest mismatch;
- signature digest mismatch;
- disallowed signature algorithm;
- invalid signature result;
- insufficient signature threshold;
- authority-scope rejection;
- duplicate signer identity;
- unregistered policy;
- unavailable context;
- proposed or uncommitted context;
- stale committed context.

## Persistence and reconstruction

The reference filesystem store uses append-only content-addressed contract paths and atomic no-clobber installation. A context tick is immutable: the same tick cannot be rebound to different context bytes.

`reconstruct_accepted` resolves the exact raw event, signature set, validation policy, and committed context cited by an accepted receipt. Reconstruction verifies canonical bytes and contract identities but does not repeat signature interpretation.

## Determinism evidence

The frozen known-answer evidence is located at:

- `data/canary/v0.5/admission-v1/admission_vectors.json`
- `reports/event_admission_v0.5.json`

The campaign contains two accepted receipts and twelve rejected receipts. Identical admission inputs produce byte-identical receipts across filesystem-store restart. Changing the raw event, policy, signature set, or committed tick changes accepted-receipt identity.

## CI gate

Run:

```bash
csd-foundry-admission --release v0.5
```

The command runs in both editable and externally installed-wheel CI environments. All v0.1-v0.4 gates and the v0.5 contract-freeze gate must remain green.

## Claim boundary

This layer establishes deterministic event admission relative to declared policy and resolver results. It does not establish:

- signer truthfulness;
- external reality;
- production cryptographic key validity;
- CSD semantic correctness;
- temporal successor serialization;
- registry, disposition, quarantine, or release correctness;
- production safety.
