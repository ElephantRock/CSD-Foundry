# Assumption Governance Execution Contracts v0.5-D3.2-A0

## Status

Normative internal contract correction before D3.2-A governed append. This slice does not
change the released `registry-event/1` envelope or any frozen v0.5 public artifact.

## Purpose

D3.2-A0 closes six execution ambiguities left after the D3.2-0 governance-content freeze:

1. exact policy-ledger ordering and historical `resolve_at` behavior;
2. quantified approval thresholds and signer-set semantics;
3. policy-chain fork rejection;
4. structural/current-status evidence eligibility at assumption admission;
5. exact same-head race failure and retry behavior;
6. explicit separation of normative correctness work from non-normative performance telemetry.

## Linear policy ledger

An `AssumptionPolicyLedger` is a single predecessor-linked chain. Every successor must satisfy:

```text
successor.predecessor_commit_receipt_digest = current.commit_receipt_digest
successor.predecessor_policy_digest = current.policy_digest
successor.effective_from_sequence > current.effective_from_sequence
```

Consequences:

- exactly one genesis commit exists;
- effective sequences are strictly increasing;
- equal effective sequences are rejected;
- retroactive insertion is rejected;
- a predecessor may have at most one child;
- two distinct children of one predecessor are a policy-chain fork;
- disconnected, cyclic, or predecessor-mismatched records fail closed.

Stable failures include:

```text
ASSUMPTION_POLICY_EFFECTIVE_SEQUENCE_NOT_INCREASING
ASSUMPTION_POLICY_PREDECESSOR_MISSING
ASSUMPTION_POLICY_PREDECESSOR_CONFLICT
ASSUMPTION_POLICY_CHAIN_FORK
ASSUMPTION_POLICY_CHAIN_INVALID
ASSUMPTION_POLICY_NOT_ACTIVE
```

## Historical policy resolution

For chain generations `P0(e0) -> P1(e1) -> P2(e2)`, `resolve_at(t)` returns the unique policy
whose half-open activation interval contains `t`:

```text
P0: [e0, e1)
P1: [e1, e2)
P2: [e2, infinity)
```

Therefore:

```text
resolve_at(e1 - 1) = P0
resolve_at(e1)     = P1
```

A future committed policy does not change the policy selected for a historical event. A
sequence before the genesis effective sequence fails with `ASSUMPTION_POLICY_NOT_ACTIVE`.

## Approval policy

Version 1 uses an unweighted unique-signer model. Weighted voting is not permitted.

Each `AssumptionPolicyApprovalRule` commits:

- one exact approval class;
- sorted unique eligible signer identities;
- a required unique-signature count;
- sorted unique mandatory signer identities;
- a rule digest.

An `AssumptionPolicyApprovalPolicy` contains exactly one `STANDARD` rule and one
`DUTY_EXCEPTION` rule under one authority root.

The duty-exception rule must be mechanically stronger:

```text
duty.required_signature_count > standard.required_signature_count
duty.required_signer_ids is a superset of standard.required_signer_ids
duty.eligible_signer_ids is not wider than standard.eligible_signer_ids
```

## Approval receipt

`AssumptionPolicyApprovalReceipt` binds:

- exact approval-policy digest;
- authority-root digest;
- exact policy-commit receipt digest;
- derived approval class;
- sorted unique verified signer identities;
- signature-set digest;
- approval-receipt digest.

Approval succeeds only when all unique signers are eligible, the unique signer count reaches
the threshold, and every mandatory signer is present. Duplicate signatures from one identity
never increase the count.

Cryptographic signature verification and authority-root resolution remain D3.2-A1 execution
responsibilities. A0 freezes the deterministic receipt and threshold semantics consumed by
that resolver.

## Policy ledger entries

Each `AssumptionPolicyLedgerEntry` binds together:

- immutable authority-policy content;
- its predecessor-linked policy commit;
- the approval policy used by the commit;
- the threshold-satisfying approval receipt;
- a ledger-entry digest.

The entry rechecks policy ID, content digest, authority root, grant/rule/exception set digests,
exception count, approval-policy digest, approval class, commit receipt, and signature-set
identity before it can enter the ledger.

## Evidence eligibility for assumption admission

D3.2-A admission is stricter than evidence existence but narrower than D3.2-B decision-specific
admissibility.

An evidence dependency is admission-eligible only when:

1. the identity exists;
2. its complete D2 event chain reconstructs from genesis;
3. the lifecycle projection is valid;
4. its current status is `VERIFIED`;
5. the candidate admission sequence is within its declared validity interval.

The following are rejected:

```text
REGISTERED   -> ASSUMPTION_EVIDENCE_NOT_VERIFIED
CHALLENGED   -> ASSUMPTION_EVIDENCE_CHALLENGED
EXPIRED      -> ASSUMPTION_EVIDENCE_EXPIRED
INVALIDATED  -> ASSUMPTION_EVIDENCE_TERMINAL
REJECTED     -> ASSUMPTION_EVIDENCE_TERMINAL
SUPERSEDED   -> ASSUMPTION_EVIDENCE_TERMINAL
```

A verified unit whose expiry sequence has arrived is rejected even if an explicit D2 `EXPIRE`
event has not yet been appended.

D3.2-A does not evaluate decision-specific proposition matching, scope, reuse, limitations,
`DecisionAssumptionBinding`, or recursive D2 admissibility. Those remain D3.2-B obligations.

## Same-head race semantics

Two events built against one assumption head may not both append. The first successful event
advances the entity sequence. The stale loser fails exactly with:

```text
REGISTRY_SEQUENCE_CONFLICT
```

The registry performs no implicit retry. The stale event is permanently rejected as that
event. A caller may reconstruct the new head, build a new candidate, rerun all governance, and
submit the new event once under an externally bounded retry policy.

Content-addressed bytes for the losing event may already exist in the object store because D1
installs immutable objects before the head compare-and-append. Such bytes are unreachable from
the entity head and do not affect the registry root.

## Performance boundary

Complete history replay remains the correctness reference path even though repeated append
validation is quadratic over a long-lived entity history.

`AssumptionAppendValidationTelemetry` records non-normative measurements:

- entity events replayed;
- policy commits traversed;
- authority decisions recomputed;
- dependency nodes examined;
- append validation duration.

It deliberately has no digest and must not influence authority or admissibility receipts.
Content-addressed prefix checkpoints remain a pre-D5 optimization candidate; genesis replay
remains the independent conformance oracle.

## Deliberate boundary

D3.2-A0 does not implement:

- cryptographic policy-signature verification;
- policy persistence or compare-and-append publication;
- action-specific grant selection;
- authority-decision receipts;
- separation-of-duty execution;
- assumption dependency traversal;
- governed `AssumptionRegistry.apply()`;
- use-time assumption admissibility;
- staged projection or temporal publication.

Those proceed in D3.2-A1 through D3.2-B after these execution semantics are frozen.
