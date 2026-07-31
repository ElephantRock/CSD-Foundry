# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, and evaluation evidence.

## Status

**Temporal and Governance Kernel v0.3**. The repository contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, retirement,
  logical time, expiry, profile changes, reassessment requests, and heartbeat obligations;
- independent state, transition, and event-specific invariant checks;
- a manifest-complete executable registry for all 21 CSD Reasoning Seed v0.1 scenarios;
- transition, sequence, multi-control, observation, and rejected-transition case types;
- ten deterministic temporal/governance scenarios with complete replay evidence;
- legacy and temporal mutation kill-matrix evaluators;
- the immutable CSD Reasoning Seed v0.1 and its original generator and validator.

The included seed remains an unbenchmarked synthetic seed. Passing validation establishes
coverage relative to the encoded CSD semantics; it does not prove real-world dependency
completeness, model generalization, scheduler fairness, or production safety.

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
constraint-valid state/event sampling
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
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

The scenario validator enforces exact agreement between the immutable manifest and executable
registry. The temporal validator executes canonical logical-time and governance trajectories,
retains complete ordered oracle results, checks full replay identity, and verifies exact event
consequences.

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
```

Machine-readable evidence is committed at:

- `reports/scenario_coverage_v0.2.json`
- `reports/temporal_kernel_coverage_v0.3.json`
- `reports/mutation_policy_v0.3.json`

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

## Project layout

```text
src/csd_foundry/kernel/          State, events, transitions, invariants, oracle
src/csd_foundry/scenarios/       Typed scenario contracts, registry, release runner
src/csd_foundry/scenarios/v0_1/  Manifest-complete v0.1 scenario definitions
src/csd_foundry/temporal/        Canonical temporal/governance release scenarios
src/csd_foundry/synthesis/       Legacy and temporal mutation evaluation
src/csd_foundry/fixtures/v0_1/   Compatibility fixtures for the bootstrap API
scripts/                         Seed generation and validation utilities
data/seed/v0.1/                  Immutable v0.1 seed release
reports/                         Machine-readable coverage and release evidence
tests/                           Kernel, registry, temporal, mutation, and determinism tests
```

## Explicit boundaries

The current implementation does not establish:

- fairness or liveness of a real scheduler;
- completeness of real-world dependency declarations;
- correspondence between encoded evidence and external truth;
- model learning or generalization from generated records;
- production safety.

These remain release boundaries rather than inferred capabilities.

## Immediate roadmap

1. Build constraint-valid state and event samplers.
2. Generate canonical multi-event trajectories from sampled states.
3. Derive one mutation operator per invariant family with release thresholds.
4. Render verified trajectories into SFT, preference, critique, and evaluation records.
5. Create topology, composition, temporal, and surface holdouts.
6. Benchmark base, SFT, and preference-trained models against the executable oracle.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics and test
coverage. It does not establish dependency completeness, external truth, general reasoning
transfer, scheduler fairness, or production safety.
