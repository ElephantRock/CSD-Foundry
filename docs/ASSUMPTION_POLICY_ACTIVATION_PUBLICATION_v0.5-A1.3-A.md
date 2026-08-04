# Assumption Policy Activation Publication v0.5-A1.3-A

**Status:** Implemented in-memory publication (PR #52, draft)
**Date:** 2026-08-04
**Scope:** V3 publication contracts, in-memory atomic publisher, service composition

## 1. Claim boundary

A1.3-A guarantees thread-safe atomic publication within one Python process.

It does not guarantee:

```text
interprocess exclusion
filesystem durability
atomic file replacement
restart reconstruction
power-loss durability
```

Those belong to A1.3-B.

## 2. Architecture

```text
PreparedPolicyActivation
  → InMemoryAssumptionPolicyPublisher.publish()
    → RLock acquired
    → compare_and_append_policy_entry_v3()
      → exact idempotence scan
      → expected-state comparison
      → predecessor-pair fork classification
      → effective-sequence monotonicity
      → append + resulting root
      → activation result
    → state assignment (if COMMITTED)
    → RLock released
  → AssumptionPolicyActivationResult
```

## 3. Process-local RLock

A reentrant lock protects the complete mutable state. The entire
compare-and-append transition — actual-state read, idempotence classification,
expected-state comparison, successor validation, updated-ledger construction,
activation-result construction, and state assignment — occurs under the lock.

`read_state()` and `read_ledger()` also hold the lock.

## 4. Exact-idempotence precedence

Idempotence is checked before state conflict. If the candidate is already in
the ledger (exact digest + exact canonical bytes), the result is
`IDEMPOTENT_APPEND` without mutating the ledger.

## 5. Expected-state comparison

Expected state contains the exact ledger root and the exact head entry digest
(or explicit empty state). A mismatch is classified:

```text
expected empty + genesis candidate (no predecessor)
→ ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH

stale snapshot + wrong nonempty predecessor pair
→ ASSUMPTION_POLICY_CHAIN_V3_FORK

stale snapshot + correct current predecessor pair
→ ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH
```

## 6. Competing-genesis state mismatch

Two distinct genesis candidates prepared against the same empty snapshot: the
first commits; the second receives `ASSUMPTION_POLICY_LEDGER_STATE_MISMATCH`
because the observed state advanced. This is not a fork — both candidates
were valid against the snapshot they observed.

## 7. Complete predecessor-pair fork classification

Fork detection compares both:

```text
candidate.signing_payload.predecessor_policy_digest
  vs head.policy.policy_digest

candidate.signing_payload.predecessor_commit_receipt_digest
  vs head.policy_commit.commit_receipt_digest
```

A mismatch in either is a chain fork.

## 8. V3 service protocol

`AssumptionPolicyActivationServiceV3` is a `@runtime_checkable` protocol with
`prepare()` and `publish()`. `ReferenceAssumptionPolicyActivationService`
explicitly inherits from it; strict mypy verifies every method signature.

The historical V2 `AssumptionPolicyActivationService` is preserved unchanged
for compatibility.

## 9. Thread-contention evidence

True concurrent tests using `threading.Barrier` + `threading.Thread`:

* **distinct candidates:** one COMMITTED, one STATE_MISMATCH; winner's
  head/root preserved, loser absent.
* **exact retry:** one COMMITTED, one IDEMPOTENT_APPEND; same entry digest,
  same root, one final entry.
* **25-round contention:** fresh publisher each round, two threads, same
  invariants.

No sleeps used as synchronization.

## 10. Success-only activation results

```text
COMMITTED
IDEMPOTENT_APPEND
```

Every conflict raises `AssumptionPolicyPublicationConflict`, returns no
activation result, claims no resulting root, and leaves publisher state
unchanged.

## 11. Out of scope

A1.3-B: filesystem persistence, interprocess locking, atomic replace, restart
reconstruction, corruption detection.

A1.3-C: `resolve_at`, exact active policy generation, exact applicable grant
selection, scope/action/materiality/time matching, deterministic ambiguity
rejection.
