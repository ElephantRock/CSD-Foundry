# Assumption Policy Resolution and Grant Selection v0.5-A1.3-C

**Status:** Implemented historical V3 policy resolution and exact grant selection
**Date:** 2026-08-04
**Scope:** `resolve_policy_at_v3`, `select_applicable_grant_v3`,
`resolve_policy_and_select_grant`, `FilesystemAssumptionPolicyPublisher.resolve_at`

This module closes the A1 activation read path against the non-circular V3
signing envelope. The pure A1.3-A function `compare_and_append_policy_entry_v3`
remains the semantic oracle for publication; A1.3-C provides the pure, deterministic
read path that answers:

> At event sequence `s`, which activated authority policy governed this decision,
> and which exact grant authorized this action by this authority for this scope at
> this materiality?

The filesystem layer (A1.3-B) owns locking, stored-byte validation, atomic
replacement, restart reconstruction, and post-write verification. A1.3-C adds a
read-only `resolve_at` method to that publisher that reuses the same strict lock
scope but performs no writes.

## 1. Half-open interval semantics

A validated `AssumptionPolicyLedgerV3` is a strictly-increasing chain of entries
`e_0, e_1, ..., e_{n-1}` where entry `e_i` activates at sequence
`s_i = e_i.signing_payload.effective_from_sequence` and `s_i` is strictly greater
than `s_{i-1}` (enforced by `validate_successor_position_v3` from A1.2-0).

Resolution of a queried event sequence `q` is the unique entry `e_i` such that:

```
s_i <= q   AND   (i == n-1  OR  q < s_{i+1})
```

That is, the half-open interval `[s_i, s_{i+1})` contains `q`. Concretely:

| Query `q`                  | Resolved entry | Outcome                                |
|----------------------------|----------------|----------------------------------------|
| `q < s_0`                  | none           | `ASSUMPTION_POLICY_NOT_ACTIVE`         |
| `q == s_i`                 | `e_i`          | exact boundary: new policy is active   |
| `s_i < q < s_{i+1}`        | `e_i`          | preceding policy governs               |
| `q >= s_{n-1}`             | `e_{n-1}`      | latest policy governs                  |

The interval is **closed on the left** (a policy is active at its own
`effective_from_sequence`) and **open on the right** (a policy is superseded at
the successor's `effective_from_sequence`, not after). This mirrors the V2
`resolve_at` semantics from D3.2-A0 exactly.

## 2. Activation-boundary behavior

At the exact activation boundary `s_i`, the new policy `e_i` is active, not the
predecessor `e_{i-1}`. This is a direct consequence of the closed-left interval:
`resolve_policy_at_v3(ledger, s_i)` returns `e_i` because
`e_i.signing_payload.effective_from_sequence == s_i <= s_i`, and the reverse walk
encounters `e_i` before `e_{i-1}`.

The resolver walks the chain in reverse and returns the first (latest) entry
whose `effective_from_sequence <= q`. Because the chain is strictly increasing,
this is the unique entry whose half-open interval contains `q`.

## 3. Future isolation

Future entries (those with `s_i > q`) never affect the resolution of `q`. The
reverse walk skips them: their `effective_from_sequence` exceeds the query, so
the `<=` test fails and the walk continues to earlier entries.

Consequently, appending a new entry `e_n` after a query of `q < s_n` leaves the
**resolved policy generation** byte-identical. The generation bindings
(`policy_id`, `policy_digest`, `effective_from_sequence`,
`signing_payload_digest`, `commit_receipt_digest`, `ledger_entry_digest`) are
identical before and after the append. The `ledger_root_digest` and
`resolution_digest` fields legitimately differ: they bind the ledger observed at
resolution time, which grows on append. The future-isolation guarantee is about
the resolved policy generation, not the enclosing ledger root.

## 4. V3-only boundary

`resolve_policy_at_v3` rejects any ledger that is not exactly an
`AssumptionPolicyLedgerV3` via an exact `type(ledger) is not
AssumptionPolicyLedgerV3` check that runs **before any field is read**. This
ensures a V2 `AssumptionPolicyLedgerV2` (or any foreign object) surfaces the
stable `ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE` code rather
than an `AttributeError` from a missing V3 field.

This mirrors the V3 ledger's own runtime version enforcement
(`AssumptionPolicyLedgerV3.__post_init__` rejects any entry that is not exactly
`AssumptionPolicyLedgerEntryV3`), applied at the resolution boundary.

## 5. Strict sequence typing

The `event_sequence` argument is validated with a strict `type(...) is not int`
check plus an explicit `isinstance(..., bool)` guard. A `bool` is rejected even
though `bool` subclasses `int` in Python, so a stored `True` can never
masquerade as `1`. This matches the boundary typing used throughout the A1
contract layer (e.g. `effective_from_sequence` validation in
`AssumptionPolicySigningPayload`).

A negative integer is rejected with the same
`ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID` code. A non-integer (string,
float, None) is likewise rejected.

## 6. Ledger reconstruction (read-only)

`FilesystemAssumptionPolicyPublisher.resolve_at(event_sequence)`:

1. validates the store root exists and is a directory (no creation);
2. acquires the strict publication lock (the same lock used by `publish`);
3. reads the authoritative `ledger.json` bytes at the start of the locked
   region;
4. reconstructs and fully revalidates the ledger (every nested contract
   re-parsed through its hardened parser, every digest self-checked);
5. runs the pure `resolve_policy_at_v3` resolver against the reconstructed
   ledger;
6. reads the authoritative bytes again at the end of the locked region;
7. releases the lock;
8. compares the two byte snapshots and raises
   `ASSUMPTION_POLICY_RESOLVE_AT_BYTES_MUTATED` if they differ (impossible by
   construction since the path performs no writes; defense-in-depth against
   external tampering that bypasses the lock).

The reconstruction is identical to `read_ledger`: no in-memory cache, full
revalidation on every call. An unmodified store can be reopened from any process
at any time and yields byte-identical resolution.

## 7. Grant applicability dimensions

`select_applicable_grant_v3` scans the resolved policy's grant set for every
grant applicable to the request. A grant is applicable if and only if ALL of the
following hold:

| Dimension                | Match rule                                                        |
|--------------------------|-------------------------------------------------------------------|
| `action`                 | exact, case-sensitive equality                                    |
| `authority_id`           | exact, case-sensitive equality                                    |
| `scope_id`               | see scope coverage rules below                                    |
| `assumption_materiality` | exact membership in `grant.assumption_materialities`              |
| `challenge_materiality`  | exact membership in `grant.challenge_materialities` (resolution   |
|                          | actions only; `None` for non-resolution actions)                  |
| effective interval       | `grant.effective_from_sequence <= event_sequence` AND            |
|                          | (`effective_until_sequence is None` OR                            |
|                          | `event_sequence < grant.effective_until_sequence`)                |

The effective interval is half-open: closed on the left (inclusive lower bound),
open on the right (exclusive upper bound). A grant is active at exactly its
`effective_from_sequence` and expires AT its `effective_until_sequence` (not
after).

## 8. scope:* behavior

A global grant whose `scope_ids == ("scope:*",)` matches any narrow request
scope. A narrow grant matches only if the request scope is exactly in its scope
set. A narrow grant **never** matches a global request: `scope:*` as a request
scope is rejected upstream as an invalid token-shape scope
(`ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID`), so the matcher never observes it,
but the rule is stated here as defense-in-depth.

This mirrors `_scope_is_subset` from the D3.2-0 contracts layer, where a global
boundary covers any narrow candidate but a narrow boundary never covers a global
candidate.

## 9. Zero / one / multiple outcomes

`select_applicable_grant_v3` returns exactly one of three decision types:

* **`SELECTED`** — exactly one grant in the resolved policy is applicable. The
  decision carries `selected_grant_id` and `grant_digest` binding the exact
  grant.
* **`NO_APPLICABLE_GRANT`** — zero grants are applicable. This is a **denial**,
  not an error: the caller is not authorized, and the decision is a deterministic
  outcome the caller may persist.
* **`AMBIGUOUS_GRANTS`** — two or more grants are applicable. This is a
  **fail-closed denial**: a well-formed policy never has two applicable grants
  for one request (the overlap validator at construction would normally reject
  this), so observing it is a configuration error the operator must reconcile.
  The decision carries no grant bindings (it is a denial).

Denials (`NO_APPLICABLE_GRANT`, `AMBIGUOUS_GRANTS`) are returned as decisions,
not raised. Genuine input-contract violations (unknown action, bad materiality,
negative sequence, action/materiality inconsistency, event before the policy's
effective sequence) **raise** `AssumptionPolicyActivationContractError` with a
stable code, because they indicate a caller bug rather than an authorization
outcome.

The scan is deterministic because the resolved policy's grant tuple is canonical
(sorted by `grant_id`), so the same request always yields the same selected
grant or the same ambiguity.

## 10. Read-only lock scope

`resolve_at` acquires the same strict publication lock used by `publish`, so a
concurrent publisher cannot append while a reader reconstructs. The lock scope is
identical; only the body differs:

* `publish`: reconstruct → compare-and-append → (if committed) write temp →
  atomic replace → fsync → reread → verify;
* `resolve_at`: read bytes → reconstruct → resolve → read bytes → compare.

`resolve_at` performs NO writes: no temp file, no atomic replace, no orphan
cleanup sweep. The authoritative `ledger.json` bytes are proven unchanged across
the locked region (the two in-lock byte snapshots are compared on exit).

A reader and a concurrent publisher are therefore serialized: the reader
observes either the complete old ledger or the complete new ledger, never a torn
read. The lock is held across reconstruction and resolution, so the resolver
sees a single consistent snapshot.

## 11. A2 / A3 exclusions

A1.3-C explicitly does NOT claim (deferred to later milestones):

* **Signature or approval re-verification at resolution time.** The V3 ledger is
  already fully self-validating: A1.2 verified every signature and threshold at
  publication, and the A1.3-B filesystem layer revalidates every nested
  contract's schema and digest on every read. Resolution does not re-verify
  signatures; it trusts the reconstructed, self-validating ledger.
* **Separation-of-duty rule evaluation (A2).** A grant may be applicable yet
  forbidden by a separation-of-duty rule (e.g. the same authority proposed and
  now confirms). A1.3-C selects the grant; A2 will evaluate duty rules against
  the selection and the actor's prior roles.
* **Active-challenge suppression or materiality aggregation (A3).** An
  assumption may have active challenges that suppress or upgrade its
  materiality. A1.3-C takes the request materiality as given; A3 will compose
  resolution with the assumption registry read path to derive the effective
  materiality.
* **Evaluation-work accounting (A3).** A1.3-C does not produce an
  `AssumptionEvaluationWork` receipt; A3 will account for the
  assumption-histories-reconstructed, events-replayed, and decisions-evaluated
  counters.

## 12. Composite: resolve_policy_and_select_grant

The composite `resolve_policy_and_select_grant(ledger, event_sequence, action,
...)` performs the read-path order:

1. `resolve_policy_at_v3(ledger, event_sequence)` — pure resolution, yielding the
   resolved policy binding (which carries the grant set of the located entry);
2. `select_applicable_grant_v3(resolved, ...)` — pure exact grant selection
   against the carried grant set.

The composite performs no I/O and no locking: it is the pure read path over an
already-validated in-memory `AssumptionPolicyLedgerV3`. For the durable
filesystem path, call `FilesystemAssumptionPolicyPublisher.resolve_at` (which
holds the lock across reconstruction) to obtain the resolved policy, then call
`select_applicable_grant_v3`.

The composite guarantees the resolution and selection share the same entry: the
binding returned by resolution carries the grants of the located entry, so a
concurrent append cannot split the read across two generations.

## 13. Error codes

Resolution errors (`resolve_policy_at_v3`):

| Code                                                    | Trigger                                |
|---------------------------------------------------------|----------------------------------------|
| `ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE` | ledger is not exactly `AssumptionPolicyLedgerV3` |
| `ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID`         | `event_sequence` is not a nonnegative `int` (bool rejected) |
| `ASSUMPTION_POLICY_NOT_ACTIVE`                          | query precedes genesis, or ledger is empty |

Grant-selection errors (`select_applicable_grant_v3`, raised not returned):

| Code                                                    | Trigger                                |
|---------------------------------------------------------|----------------------------------------|
| `ASSUMPTION_GRANT_SELECTION_ACTION_INVALID`             | unknown action                         |
| `ASSUMPTION_GRANT_SELECTION_ASSUMPTION_MATERIALITY_INVALID` | unknown assumption materiality     |
| `ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_INVALID` | unknown challenge materiality       |
| `ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_REQUIRED` | resolution action without challenge materiality |
| `ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_UNEXPECTED` | non-resolution action with challenge materiality |
| `ASSUMPTION_GRANT_SELECTION_SEQUENCE_INVALID`           | negative or non-int `event_sequence`   |
| `ASSUMPTION_GRANT_SELECTION_EVENT_BEFORE_POLICY_EFFECTIVE` | `event_sequence` < resolved policy's `effective_from_sequence` |

Filesystem errors (`resolve_at`, same codes as `read_ledger`):

| Code                                                    | Trigger                                |
|---------------------------------------------------------|----------------------------------------|
| `ASSUMPTION_POLICY_STORE_ROOT_MISSING`                  | root does not exist                     |
| `ASSUMPTION_POLICY_STORE_ROOT_NOT_DIRECTORY`            | root is not a directory                 |
| `ASSUMPTION_POLICY_STORE_LOCK_INVALID`                  | lock path is a symlink/directory/other  |
| `ASSUMPTION_POLICY_STORE_LOCK_FAILED`                   | advisory lock could not be acquired     |
| `ASSUMPTION_POLICY_STORED_BYTES_MISSING`                | ledger file absent                      |
| `ASSUMPTION_POLICY_STORED_BYTES_INVALID`                | bytes not valid UTF-8 JSON              |
| `ASSUMPTION_POLICY_STORED_BYTES_NONCANONICAL`           | bytes valid JSON but not canonical      |
| `ASSUMPTION_POLICY_STORED_*`                            | (full set in A1.3-B docs)               |
| `ASSUMPTION_POLICY_RESOLVE_AT_BYTES_MUTATED`            | authoritative bytes changed across the read-only locked region (impossible by construction; defense-in-depth) |
