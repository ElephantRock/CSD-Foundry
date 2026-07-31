# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, and evaluation evidence.

## Status

**Bootstrap v0.1**. The repository contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, and retirement;
- independent invariant checks and an oracle trace;
- targeted mutation operators and a kill-matrix evaluator;
- executable regression fixtures for representative CSD scenarios;
- the deterministic CSD Reasoning Seed v0.1 and its original generator/validator.

The included seed is reproducible and structurally validated, but remains an unbenchmarked
synthetic seed. Kernel and invariant checks are an additional semantic control layer; they
do not prove that CSD covers all real-world reasoning or that a trained model generalizes.

## Architecture

```text
symbolic state sampler
        ↓
executable CSD kernel
        ↓
canonical transition trace
        ↓
independent invariant verifier
        ↓
adversarial mutation engine + kill matrix
        ↓
natural-language renderers
        ↓
SFT / preference / evaluation releases
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
python -m csd_foundry demo
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

## Project layout

```text
src/csd_foundry/kernel/       State, events, transitions, invariants, oracle
src/csd_foundry/synthesis/    Mutation operators and kill-matrix evaluation
fixtures/v0_1/                Executable regression fixtures
scripts/                      Seed generation and validation utilities
data/seed/v0.1/               Immutable v0.1 seed release
reports/                      Future benchmark and decision records
tests/                        Kernel, invariant, mutation, and determinism tests
```

## Immediate roadmap

1. Encode all M-01 through H-01 scenarios as symbolic fixtures.
2. Add one targeted mutation operator per invariant family.
3. Establish mutation-kill and valid-state false-positive gates.
4. Generate v0.2 from state-space execution rather than prose templates.
5. Benchmark base, SFT, and preference-trained models on topology and composition holdouts.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics and test
coverage. It does not establish dependency completeness, external truth, general reasoning
transfer, or production safety.
