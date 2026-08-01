# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, and evaluation evidence.

## Status

**Temporal and Governance Kernel v0.3 with the v0.4 synthesis contract foundation**. The
repository contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, retirement,
  logical time, expiry, profile changes, reassessment requests, and heartbeat obligations;
- independent state, transition, and event-specific invariant checks;
- a manifest-complete executable registry for all 21 CSD Reasoning Seed v0.1 scenarios;
- transition, sequence, multi-control, observation, and rejected-transition case types;
- ten deterministic temporal/governance scenarios with complete replay evidence;
- legacy and temporal mutation kill-matrix evaluators;
- typed v0.4 synthesis targets, rejection causes, search budgets, completeness witnesses,
  structural holdout rules, mutation severity, and deterministic serialization policies;
- the immutable CSD Reasoning Seed v0.1 and its original generator and validator.

The included seed remains an unbenchmarked synthetic seed. Passing validation establishes
coverage relative to the encoded CSD semantics; it does not prove real-world dependency
completeness, model generalization, scheduler fairness, or production safety. The v0.4 contract
validator intentionally reports that release-scale generation is blocked until performance and
stochastic mutation-risk policies are empirically frozen.

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
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

The scenario validator enforces exact agreement between the immutable manifest and executable
registry. The temporal validator executes canonical logical-time and governance trajectories,
retains complete ordered oracle results, checks full replay identity, and verifies exact event
consequences. The synthesis contract validator checks the v0.4 target catalog, rejection
ownership, machine-checkable infeasibility boundary, search budgets, completeness evidence,
structural holdout grammar, severity policy, and integer-only canonical serialization.

## Current coverage

```text
Manifest scenarios:                   21
Executable registry scenarios:        21
Accepted registry scenarios:          21
Legacy targeted mutations killed:    10 / 10

Temporal/governance scenarios:        10
Accepted temporal scenarios:          10
Identical full temporal replays:       10
Retained oracle transition steps:      16
Temporal targeted mutations killed:  23 / 23
Temporal mutation escapes:              0
Valid canonical trajectories rejected:  0

v0.4 synthesis targets:                 5
Required synthesis targets:             4
Exploratory synthesis targets:           1
Unresolved synthesis targets:            0
```

Machine-readable evidence and specifications are committed at:

- `reports/scenario_coverage_v0.2.json`
- `reports/temporal_kernel_coverage_v0.3.json`
- `reports/mutation_policy_v0.3.json`
- `specs/v0.4/`

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

## v0.4 synthesis contract boundary

The v0.4 contract layer distinguishes target contradiction, planner budget exhaustion, state
construction failure, sampler precondition failure, kernel failure, verifier failure, replay
divergence, canonicalization divergence, holdout conflict, mutation outcomes, duplicate
anomalies, and release serialization failure. Each cause has one stable subsystem owner.

Targets may be required, exploratory, machine-proven infeasible, or unresolved. Search exhaustion
is never treated as proof of infeasibility. Machine-proven infeasibility requires an explicit
witness using an approved proof method. Semantic generation decisions prohibit floating-point
values; statistical thresholds are exact decimal strings until calibrated and frozen.

See `docs/SYNTHESIS_V0_4_CONTRACTS.md` for the contract and claim boundary.

## Project layout

```text
src/csd_foundry/kernel/             State, events, transitions, invariants, oracle
src/csd_foundry/scenarios/          Typed scenario contracts, registry, release runner
src/csd_foundry/scenarios/v0_1/     Manifest-complete v0.1 scenario definitions
src/csd_foundry/temporal/           Canonical temporal/governance release scenarios
src/csd_foundry/synthesis/          Mutation evaluation and v0.4 synthesis contracts
src/csd_foundry/synthesis/v0_4/     Typed targets, policies, serialization, validation
src/csd_foundry/fixtures/v0_1/      Compatibility fixtures for the bootstrap API
specs/v0.4/                         Reviewable synthesis policy and schema documents
scripts/                            Seed generation and validation utilities
data/seed/v0.1/                     Immutable v0.1 seed release
reports/                            Machine-readable coverage and release evidence
tests/                              Kernel, registry, temporal, mutation, and synthesis tests
```

## Explicit boundaries

The current implementation does not establish:

- a complete trajectory planner or state/event constructor;
- fairness or liveness of a real scheduler;
- completeness of real-world dependency declarations;
- correspondence between encoded evidence and external truth;
- model learning or generalization from generated records;
- production safety.

These remain release boundaries rather than inferred capabilities.

## Immediate roadmap

1. Complete deterministic identities and shard-independent replay on the frozen HMAC choice substrate.
2. Add the performance benchmark harness and freeze reference SLOs.
3. Build the joint coverage planner with retry budgets and infeasibility witnesses.
4. Build constraint-valid state and event constructors with eligibility proofs.
5. Generate complete oracle-replayed trajectories.
6. Add structural canonicalization, holdouts, completeness fuzzing, and mutation-risk campaigns.
7. Compile the reproducible 100,000-trajectory v0.4 release.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics and test
coverage. It does not establish dependency completeness, external truth, general reasoning
transfer, scheduler fairness, or production safety.
