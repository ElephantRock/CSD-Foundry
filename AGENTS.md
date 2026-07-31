# AGENTS.md

## Scope

CSD Foundry owns executable CSD semantics, state-space generation, invariant verification,
mutation testing, reasoning-dataset release construction, and benchmark evaluation.

## Source of truth

The default branch is canonical. Prose examples are not the semantic oracle; executable
state transitions and independent invariant checks are.

## Required workflow

1. Open an issue describing the invariant, transition, generator, or benchmark change.
2. Work on a branch.
3. Add or update tests before claiming completion.
4. Run `ruff format --check .`, `ruff check .`, `mypy src`, and `pytest`.
5. Open a pull request containing commands and observed results.

## Prohibited shortcuts

- Do not silently edit released dataset records.
- Do not make the generator its own only correctness oracle.
- Do not split variants of one symbolic scenario across train and test.
- Do not claim reasoning transfer from training loss.
- Do not reactivate invalidated evidence or overwrite append-only history.
