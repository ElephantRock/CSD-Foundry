# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, and evaluation evidence.

## Status

**Temporal and Governance Kernel v0.3, completed v0.4 deterministic execution substrate, and
frozen v0.5 governance contracts**. The repository contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, retirement,
  logical time, expiry, profile changes, reassessment requests, and heartbeat obligations;
- independent state, transition, and event-specific invariant checks;
- a manifest-complete executable registry for all 21 CSD Reasoning Seed v0.1 scenarios;
- transition, sequence, multi-control, observation, and rejected-transition case types;
- ten deterministic temporal/governance scenarios with complete replay evidence;
- legacy and temporal mutation kill-matrix evaluators;
- typed v0.4 synthesis targets, rejection causes, search budgets, completeness witnesses,
  structural holdout rules, mutation severity, and deterministic serialization policies;
- deterministic HMAC choices, canonical identities, bounded attempt replay, immutable execution
  inventories, append-only publication, sealed shard manifests, and crash recovery;
- bounded cross-shard reconciliation, global lowest-valid-attempt resolution, independent
  `FULL_REPLAY`, topology-independent semantic manifests, separate run evidence, and final seals;
- frozen v0.5 event-validation, temporal-completion, registry, disposition, quarantine, release,
  and promotion contracts with commit-blocking conformance vectors;
- the immutable CSD Reasoning Seed v0.1 and its original generator and validator.

The included seed remains an unbenchmarked synthetic seed. Passing validation establishes
coverage relative to the encoded CSD semantics; it does not prove real-world dependency
completeness, model generalization, scheduler fairness, or production safety. Release-scale
generation remains blocked until performance and stochastic mutation-risk policies are
empirically frozen.

## Architecture

```text
manifest-aligned scenario registry
        +
logical-time and governance trajectories
        ↓
executable CSD kernel
        ↓
canonical state transitions and traces
        ↓
independent state, transition, and event verification
        ↓
invariant-targeted mutations and kill matrices
        ↓
versioned joint coverage and synthesis contracts
        ↓
deterministic choice, identity, replay, execution, publication, and reconciliation
        ↓
validated-event admission and atomic temporal completion
        ↓
Reality Assurance registries, disposition, and quarantine
        ↓
constraint-valid state/event planning and construction
        ↓
structural canonicalization and holdout assignment
        ↓
natural-language rendering
        ↓
SFT / preference / evaluation releases
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

ruff format --check .
ruff check .
mypy src
pytest

csd-foundry scenarios validate --release v0.1
csd-foundry mutations evaluate --release v0.1
csd-foundry temporal validate --release v0.3
csd-foundry temporal mutations --release v0.3
csd-foundry synthesize contracts --release v0.4
csd-foundry synthesize determinism --release v0.4
csd-foundry synthesize identities --release v0.4
csd-foundry synthesize replay --release v0.4
csd-foundry synthesize execution --release v0.4
csd-foundry synthesize publication --release v0.4
csd-foundry synthesize reconciliation --release v0.4
python scripts/validate_contract_freeze_v0_5.py
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

The scenario validator enforces exact agreement between the immutable manifest and executable
registry. The temporal validator executes canonical logical-time and governance trajectories,
retains complete ordered oracle results, checks full replay identity, and verifies exact event
consequences. The v0.4 validators check contracts, choice determinism, identity allocation,
attempt replay, immutable execution authority, no-clobber publication, sealed shard evidence,
bounded streaming reconciliation, topology-independent semantic commitments, and complete
independent replay. The v0.5 contract validator checks the frozen identity, authority, ordering,
quarantine, and release boundaries before runtime implementation.

## Current coverage

```text
Manifest scenarios:                     21
Executable registry scenarios:          21
Accepted registry scenarios:            21
Legacy targeted mutations killed:      10 / 10

Temporal/governance scenarios:          10
Accepted temporal scenarios:            10
Identical full temporal replays:         10
Retained oracle transition steps:        16
Temporal targeted mutations killed:    23 / 23
Temporal mutation escapes:                0
Valid canonical trajectories rejected:    0

v0.4 synthesis targets:                   5
Required synthesis targets:               4
Exploratory synthesis targets:             1
Unresolved synthesis targets:              0

Reconciliation fixture samples:            5
Replayed semantic attempts:                11
Accepted canonical samples:                 4
Complete nonsemantic exhaustions:            1
Validated shard topologies:              1 / 2 / 7
Reconciliation vector commitments:        6 / 6

Frozen v0.5 foundational contracts:      16
v0.5 accepted contract fixtures:         16
v0.5 rejection vectors:                    5
```

Machine-readable evidence and specifications are committed at:

- `reports/scenario_coverage_v0.2.json`
- `reports/temporal_kernel_coverage_v0.3.json`
- `reports/mutation_policy_v0.3.json`
- `reports/publication_protocol_v0.4.json`
- `reports/reconciliation_protocol_v0.4.json`
- `reports/contract_freeze_v0.5.json`
- `specs/v0.4/`
- `specs/v0.5/`

## Temporal and governance semantics

The v0.3 kernel uses a serialized logical clock rather than wall-clock time. It directly
represents:

- evidence issuance and governed expiry;
- required-profile identity and version;
- profile-scoped current-basis eligibility while preserving historical evidence and bases;
- pending and closed reassessment requests;
- heartbeat interval, last receipt, and deadline;
- deterministic demotion after evidence expiry or a missed heartbeat;
- named request closure during governed reassessment;
- append-only audit history and identical replay from identical inputs;
- legacy expired evidence whose historical source did not record an expiry timestamp.

Heartbeat receipt and reassessment requests cannot promote source state or assurance. Expired
or invalidated evidence cannot be restored under the same identity. A profile change does not
rewrite or invalidate historical evidence; it recomputes which preserved bases remain eligible
for the current required profile. Profile changes, reassessment requests, and heartbeat records
require I3 authority in both transition execution and independent verification. Request closure
must target known requests that are pending in the pre-state. Every temporal/governance event
must preserve unrelated historical state and append its exact canonical audit record.

## v0.4 synthesis and execution boundary

The v0.4 contract layer distinguishes target contradiction, planner budget exhaustion, state
construction failure, sampler precondition failure, kernel failure, verifier failure, replay
divergence, canonicalization divergence, holdout conflict, mutation outcomes, duplicate
anomalies, and release serialization failure. Each cause has one stable subsystem owner.

Targets may be required, exploratory, machine-proven infeasible, or unresolved. Search exhaustion
is never treated as proof of infeasibility. Machine-proven infeasibility requires an explicit
witness using an approved proof method. Semantic generation decisions prohibit floating-point
values; statistical thresholds are exact decimal strings until calibrated and frozen.

The completed execution substrate keeps semantic attempt evidence independent of workers,
retries, timestamps, run identities, shard indexes, and storage paths. Streaming reconciliation
consumes every sealed logical shard, reconstructs inventory authority, replays every semantic
completion, resolves the global attempt prefix, and publishes semantic and operational manifests
separately. Whole-corpus in-memory materialization is prohibited.

See `docs/SYNTHESIS_V0_4_CONTRACTS.md`, `docs/publication_protocol_v0.4.md`, and
`docs/reconciliation_protocol_v0.4.md`.

## v0.5 foundational contract boundary

The v0.5 freeze defines `ValidatedEvent`, validation failures, atomic clock claims and completion
receipts, semantic and disposition projection ordering, event-sourced registries, quarantine,
and event-triggered release and promotion. It freezes authority, identity, ordering, replay, and
safety contracts while leaving performance limits and replay optimizations measurement-dependent.

See `docs/CONTRACT_FREEZE_v0.5.md` and `docs/STRATEGIC_ROADMAP.md`.

## Project layout

```text
src/csd_foundry/kernel/             State, events, transitions, invariants, oracle
src/csd_foundry/scenarios/          Typed scenario contracts, registry, release runner
src/csd_foundry/scenarios/v0_1/     Manifest-complete v0.1 scenario definitions
src/csd_foundry/temporal/           Canonical temporal/governance release scenarios
src/csd_foundry/synthesis/          Mutation evaluation and synthesis protocols
src/csd_foundry/synthesis/v0_4/     Deterministic synthesis and execution substrate
src/csd_foundry/fixtures/v0_1/      Compatibility fixtures for the bootstrap API
specs/v0.4/                         Reviewable synthesis and execution schemas
specs/v0.5/                         Frozen governance and Reality Assurance policies
scripts/                            Seed and contract validation utilities
data/seed/v0.1/                     Immutable v0.1 seed release
data/canary/                        Frozen known-answer evidence
reports/                            Machine-readable coverage and protocol evidence
tests/                              Kernel, protocol, mutation, and synthesis tests
```

## Explicit boundaries

The current implementation does not establish:

- a production `ValidatedEvent` admission engine or signature/key verification;
- an atomic committed temporal-head store;
- evidence, assumption, or alternative-model registry reducers;
- a disposition oracle, quarantine index, or governed release compiler;
- a complete trajectory planner or state/event constructor;
- fairness or liveness of a real scheduler;
- completeness of real-world dependency declarations;
- correspondence between encoded evidence and external truth;
- model learning or generalization from generated records;
- production safety.

These remain release boundaries rather than inferred capabilities.

## Immediate roadmap

1. Implement the v0.5 canonicalization library and typed contract objects.
2. Implement `ValidatedEvent` admission and validation-policy receipts.
3. Implement the atomic temporal claim, projection, failure, and completion protocol.
4. Implement evidence, assumption, and alternative-model registries.
5. Implement the separate disposition oracle and synchronous quarantine.
6. Prove the committed M-03/M-15 governed vertical slice.
7. Implement event-triggered release and promotion.
8. Build the performance benchmark harness and freeze reference SLOs.
9. Resume joint coverage planning, state/event construction, structural assurance, and the empirical pilot.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics and test
coverage. It does not establish dependency completeness, external truth, general reasoning
transfer, scheduler fairness, or production safety.
