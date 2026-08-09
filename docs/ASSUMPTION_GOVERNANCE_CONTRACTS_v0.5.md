# Assumption Governance Contracts v0.5

## Status

Normative internal D3.2-0 contract freeze. These contracts do not alter the released
`registry-event/1` envelope or the frozen v0.5 public contract catalog.

## Purpose

D3.2-0 freezes the byte-deterministic inputs and receipts required before implementing
assumption authority enforcement and decision-specific admissibility.

It resolves six previously underspecified boundaries:

1. the exact contents of an authority grant;
2. independent authorization of policy activation and duty exceptions;
3. deterministic challenge and dependency evaluation order;
4. semantic-only normative work counters;
5. independently re-derived use-time cycle safety;
6. the concrete decision context bound to assumption use.

## Authority actions

The closed action set is:

```text
PROPOSE
ADMIT
CONFIRM
CHALLENGE
RESOLVE_TO_ADMITTED
RESOLVE_TO_CONFIRMED
RESOLVE_TO_REJECTED
RESOLVE_TO_SUPERSEDED
REJECT
EXPIRE
SUPERSEDE
```

`RESOLVE_CHALLENGES` is not an authority action. The resolution outcome selects one exact
outcome-specific action.

## AssumptionAuthorityGrant

Each `assumption-authority-grant/1` commits:

- stable `grant_id`;
- exact action;
- exact `authority_id`;
- explicit scopes;
- covered assumption materialities;
- covered challenge materialities for resolution actions;
- half-open logical-time interval;
- domain-separated `grant_digest`.

An empty scope does not mean global authority. Global authority is represented only by the
single explicit scope `scope:*`. Mixing `scope:*` with narrower scopes is invalid.

Resolution grants must declare the challenge materialities they may resolve. Non-resolution
grants must not carry challenge materialities.

## Separation of duties

An `assumption-separation-duty-rule/1` binds one action to the prior roles that the action
actor must not share, together with scope and assumption-materiality boundaries.

An `assumption-duty-exception/1` must:

- reference one exact rule;
- name one exact authority;
- be scope- and materiality-narrower than the rule;
- be covered by an existing action grant for that authority;
- be bounded by the grant's logical-time interval;
- carry a reason code and a finite expiry sequence.

An exception cannot create authority. It can only relax one named separation rule for an
authority that already possesses the underlying action grant.

## Authoritative governance-role derivation (D3.2-A2-pre)

The frozen eight-role vocabulary (`ASSUMPTION_GOVERNANCE_ROLES`) is connected to
the eight actor-bearing lifecycle operations by a single mechanically frozen
mapping. Every lifecycle operation carries exactly one authority-identity field;
the derivation produces exactly one `(authority_id, governance_role)` fact per
event.

| Lifecycle operation | Authority payload field | Governance role |
|---|---|---|
| `PROPOSE` | `proposer_authority_id` | `PROPOSER` |
| `ADMIT` | `admitting_authority_id` | `ADMITTER` |
| `CONFIRM` | `confirming_authority_id` | `CONFIRMER` |
| `CHALLENGE` | `challenger_authority_id` | `CHALLENGER` |
| `RESOLVE_CHALLENGES` | `resolver_authority_id` | `RESOLVER` |
| `REJECT` | `rejecting_authority_id` | `REJECTOR` |
| `EXPIRE` | `expiry_authority_id` | `EXPIRY_AUTHORITY` |
| `SUPERSEDE` | `superseding_authority_id` | `SUPERSEDER` |

`RESOLVE_CHALLENGES` always derives `RESOLVER` regardless of `resolution_outcome`
(`RETURN_TO_ADMITTED`, `CONFIRM`, `REJECT`, `SUPERSEDE`). The outcome changes the
authority action required for a candidate event; it does not retroactively
create four historical roles.

"Prior" means: all successfully reconstructed events in the canonical history of
the same assumption identity strictly preceding the candidate event. Not the
actor's global registry history. Not cross-assumption scope. Not events at or
after the candidate logical clock. The history-level derivation replays the
chain through the existing lifecycle reducer (`reduce_assumption`) to prove
canonical order and chain integrity before deriving any role.

The candidate action actor is the authority identity selected by the
authoritative I1-A grant-selection decision. The derivation itself does not
decide who the candidate actor is; it only reconstructs historical
`(authority_id, role)` facts.

This derivation is a read-side projection. It performs no registry write, policy
write, root advancement, assumption append, or temporal staging.

## Policy content versus activation

`assumption-authority-policy/1` is immutable content. It binds canonical grant, duty-rule,
and exception sets and their set digests.

It is not active merely because its policy digest is valid.

`assumption-authority-policy-commit/1` independently binds:

- policy and predecessor policy digests;
- predecessor commit receipt;
- authority root;
- grant, rule, and exception set digests;
- exception count;
- effective logical-clock sequence;
- approval class;
- approval-policy digest;
- signature-set digest;
- commit-receipt digest.

Policies without exceptions derive approval class `STANDARD`. Policies containing one or
more duty exceptions derive approval class `DUTY_EXCEPTION`. This derivation is part of the
receipt and cannot be caller-downgraded. The approval-policy resolver implemented in D3.2-A
must enforce a stronger committed authorization threshold for `DUTY_EXCEPTION` activation.

## Deterministic evaluation order

The normative phase order is:

```text
SELF_HISTORY
ACTIVE_CHALLENGES
ASSUMPTION_DEPENDENCIES
EVIDENCE_DEPENDENCIES
```

Within a phase:

- current challenges are ordered by `challenge_id`;
- assumption dependencies are ordered by `assumption_id`;
- evidence dependencies are ordered by `evidence_id`.

D3.2-B initially uses deterministic fail-fast evaluation. The first invalid identity in this
canonical order determines the primary failure code.

## Use-time cycle safety

Admission-time acyclicity is not trusted at use time. The use-time evaluator must maintain:

- `visiting`: the active directed DFS stack;
- `evaluated`: invocation-local completed results under one exact evaluation context.

Re-entering a node in `visiting` fails with `ASSUMPTION_DEPENDENCY_CYCLE` and a canonical
cycle witness. A directed witness is rotated so the lexicographically smallest identity is
first; direction is never reversed.

Invocation-local reuse is valid only because one evaluation fixes the assumption root,
evidence root, authority-policy commit, challenge policy, and request binding. Cross-request
caching is outside D3.2-0.

## DecisionAssumptionBinding

`decision-assumption-binding/1` replaces an opaque decision-context digest. It commits:

- decision identity;
- admitted `ValidatedEvent` digest;
- semantic-projection receipt digest;
- resulting `ControlState` digest;
- assumption registry root;
- evidence registry root;
- logical-clock sequence;
- exact sorted required assumption identities;
- binding digest.

A later `AssumptionUseRequest` must embed this binding or resolve the complete binding by its
digest and recompute it. An uninterpreted caller-supplied digest is insufficient.

## Normative work counters

`assumption-evaluation-work/1` contains only semantic operation counts:

- assumption histories reconstructed;
- assumption events replayed;
- authority decisions evaluated;
- unique assumption nodes evaluated;
- assumption dependency edges examined;
- evidence dependency references evaluated;
- active current challenges evaluated;
- separation-duty rules evaluated.

Elapsed time, serialized byte counts, allocations, cache hits, filesystem reads, and hashing
implementation details are non-normative telemetry and must not influence an admissibility
receipt digest.

## Multi-challenge resolution binding

`assumption-resolution-authority-binding/1` binds an authorized targeted resolution to:

- exact outcome-specific action;
- assumption and resolver identities;
- resolution event digest;
- sorted resolved challenge identities;
- exact pre-resolution active challenge set;
- exact post-resolution active challenge set;
- policy and policy-commit digests;
- grant identity and digest.

The post-set must equal the pre-set minus exactly the resolved identities. A resolution cannot
silently remove an unrelated unresolved challenge.

D3.2-A must add a named test where two challenges are active, one is resolved under authority,
and the other remains. D3.2-B must then recompute materiality solely from the remaining
current set. A separate same-head concurrency test must prove that competing resolution writes
cannot both append.

## Deliberate deferrals

D3.2-0 does not implement:

- policy signature verification or approval-threshold resolution;
- grant selection or authority decisions;
- separation-duty evaluation against assumption history;
- admission-time dependency graph validation;
- assumption-use requests or admissibility receipts;
- evidence-dependency invocation;
- staged projection or temporal publication.

Those belong to D3.2-A and D3.2-B. Evidence authority-policy activation must be aligned to the
same policy-commit model before D5 temporal integration.
