# CSD Foundry v0.4 Synthesis Contracts

This document defines the contract boundary for the Constraint-Valid Synthesis Engine. It does
not implement planning, state construction, structural canonicalization, mutation campaigns, or
release-scale trajectory generation.

## Contract boundary

The v0.4 engine must separate the following failure surfaces:

- target-catalog contradictions;
- planner search exhaustion;
- state-construction defects;
- event-sampler precondition defects;
- kernel execution defects;
- independent-verifier defects;
- replay divergence;
- canonicalization divergence;
- structural holdout conflicts;
- mutation operator quality and verifier escapes;
- duplicate-rate anomalies;
- artifact serialization failures.

Every rejected generation attempt records exactly one `RejectionCause`. The cause has a stable
subsystem owner, so release evidence cannot hide sampler incompleteness inside generic kernel
rejection counts.

## Target dispositions

Targets may be:

- `required`;
- `exploratory`;
- `machine_proven_infeasible`;
- `unresolved`.

Search exhaustion never establishes infeasibility. A machine-proven-infeasible target requires a
nonempty witness using one of the permitted methods: exhaustive enumeration, typed contradiction,
checked unsatisfiable core, or verified pattern reduction.

Required targets must have positive quotas, positive deterministic search budgets, and declared
completeness evidence. The initial catalog maps every target to a bounded, projected-bounded, or
alternative assurance witness.

## Deterministic arithmetic

Semantic generation and release decisions prohibit floating-point values. Canonical semantic JSON
uses UTF-8, integer-only numbers, sorted object keys, and unsigned-byte lexicographic ordering.
Statistical thresholds are represented as exact decimal strings and remain unfrozen until the
performance and mutation-risk calibration milestones.

## Mutation severity

Mutation escapes are classified by semantic consequence:

- critical: verdict or source fabrication, unsupported verdict retention, evidence resurrection,
  retirement bypass, unauthorized governance, substantive history rewriting, or trust-boundary
  crossing;
- high: expiry errors, incompatible basis retention, wrong request closure, profile-consequence
  errors, causal-order violations, substantive audit omission, or cross-step inconsistency;
- moderate: non-substantive audit, request metadata, ordering, or trace defects;
- low: reporting, counter, explanation, or performance-metadata defects.

A classification cannot declare a severity below the minimum implied by its semantic effects.

## Release-scale boundary

The contract validator reports `release_scale_blocked: true` while performance SLOs and stochastic
mutation-risk budgets remain unfrozen. Contract validity is therefore not a claim that the
100,000-trajectory release may run.

Validate the contract release with:

```bash
csd-foundry synthesize contracts --release v0.4
```

The repository copies under `specs/v0.4/` are reviewable source documents. Immutable packaged
representations support the same validation from a non-editable installed wheel.
