# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, and evaluation evidence.

## Status

**Executable Scenario Registry v0.2**. The repository contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, and retirement;
- independent state, transition, and event-specific invariant checks;
- a manifest-complete executable registry for all 21 CSD Reasoning Seed v0.1 scenarios;
- transition, sequence, multi-control, observation, and rejected-transition case types;
- deterministic state and trace expectation checks;
- targeted mutation probes and a mutation kill-matrix evaluator;
- the immutable CSD Reasoning Seed v0.1 and its original generator and validator.

The included seed remains an unbenchmarked synthetic seed. Registry validation establishes
coverage relative to the encoded CSD semantics; it does not prove that CSD covers all
real-world dependencies or that a trained model generalizes.

## Architecture

```text
manifest-aligned scenario registry
        ↓
symbolic state and event cases
        ↓
executable CSD kernel
        ↓
canonical transition traces
        ↓
independent state, transition, and event verification
        ↓
invariant-targeted mutations and kill matrix
        ↓
future state-space sampling and natural-language rendering
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
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

The scenario validator enforces exact agreement between the immutable manifest and executable
registry for scenario identity, split, family, source section, and declared rule set. It then
runs every executable case and checks deterministic state and trace outcomes.

## Current coverage

```text
Manifest scenarios:             21
Executable registry scenarios:  21
Accepted scenarios:             21
Oracle-backed transition cases: 20
Observation cases:               7
Rejected-transition cases:       1
Targeted mutations killed:      10 / 10
Valid canonical cases rejected:  0
```

The machine-readable report is committed at
`reports/scenario_coverage_v0.2.json`.

## Project layout

```text
src/csd_foundry/kernel/          State, events, transitions, invariants, oracle
src/csd_foundry/scenarios/       Typed scenario contracts, registry, release runner
src/csd_foundry/scenarios/v0_1/  Manifest-complete v0.1 scenario definitions
src/csd_foundry/synthesis/       Mutation operators and kill-matrix evaluation
src/csd_foundry/fixtures/v0_1/   Compatibility fixtures for the bootstrap API
scripts/                         Seed generation and validation utilities
data/seed/v0.1/                  Immutable v0.1 seed release
reports/                         Coverage and future benchmark evidence
tests/                           Kernel, registry, invariant, mutation, and determinism tests
```

## Explicit representation boundaries

The v0.1 kernel does not directly represent every semantic dimension named by the source
scenarios. The registry marks the following as explicit assumptions or observational cases
rather than silently pretending they are executable transitions:

- clock-trigger execution and expiry scheduling;
- required-profile structure and profile-change events;
- real-world dependency completeness beyond the declared graph;
- temporal fairness and scheduler liveness.

These are kernel-extension targets, not inferred capabilities.

## Immediate roadmap

1. Add native clock, profile-change, reassessment-request, and heartbeat events.
2. Replace curated mutation probes with one generated operator per invariant family.
3. Add mutation-coverage and false-positive thresholds as release policy.
4. Build constraint-valid state and event samplers.
5. Generate v0.2 records from executable states and traces rather than prose templates.
6. Benchmark base, SFT, and preference-trained models on topology and composition holdouts.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics and test
coverage. It does not establish dependency completeness, external truth, general reasoning
transfer, or production safety.
