# AGENTS.md

## Scope

CSD Foundry owns executable CSD semantics, state-space generation, invariant verification,
mutation testing, reasoning-dataset release construction, benchmark evaluation, and the durable
single-host governance substrate required for deterministic batch manufacturing.

The project is batch-first. It does not currently claim a general-purpose live governance
service, multi-tenant operation, multi-host coordination, or distributed consensus. See
`docs/ARCHITECTURAL_INTENT_v1.md`.

## Source of truth

GitHub is the sole shared coordination and authority surface. The default branch is canonical.
Prose examples are not the semantic oracle; executable state transitions and independent
invariant checks are.

Chat messages, local notes, terminal output, unpushed commits, and local artifacts are
non-authoritative until represented by a commit, issue, pull request, CI run, or digest-bound
receipt.

## Work lanes

Classify work by capability rather than participant identity:

- `lane:repository` — architecture, specifications, CPU-compatible implementation, tests,
  review, documentation, CI, and merge preparation;
- `lane:gpu` — work that materially requires GPU hardware or a target accelerated environment.

Lane labels classify work. They do not authenticate or prove which actor performed it.
Governed repository artifacts must not attribute work to participants, assistants, vendors, or
machine owners. Trust derives from exact commits, reproducible artifacts, CI, receipts, and
review.

See `docs/PROJECT_OPERATING_MODEL.md` for the complete handoff and evidence protocol.

## Required workflow

1. Open or identify an issue describing the invariant, transition, generator, experiment, or
   benchmark change and its acceptance gates.
2. Record the work lane and exact base commit.
3. Work on a dedicated branch.
4. Add or update tests and evidence before claiming completion.
5. Run `ruff format --check .`, `ruff check .`, `mypy src`, and `pytest`.
6. Run all applicable historical validation gates.
7. Push the complete branch and open a draft pull request containing exact commands and observed
   results.
8. Review the exact remote head; do not accept a local completion report as sufficient evidence.
9. Require GitHub CI on the reviewed head.
10. Merge only the exact accepted head and update related issues after merge.

## GPU execution

A `lane:gpu` task must begin from a GitHub issue or committed experiment specification bound to
an exact source SHA. It must define the model revision, dataset digest, configuration,
environment, seeds, commands, resource ceiling, outputs, acceptance criteria, failure criteria,
and artifact retention policy.

GPU results return through a branch and draft pull request with committed scripts,
configurations, manifests, summarized metrics, and digest-bound artifact receipts. Large
artifacts should remain outside ordinary Git history with immutable references committed to the
repository. GPU execution must not merge its own work or declare roadmap gates passed.

## Prohibited shortcuts

- Do not silently edit released dataset records.
- Do not make the generator its own only correctness oracle.
- Do not split variants of one symbolic scenario across train and test.
- Do not claim reasoning transfer from training loss.
- Do not reactivate invalidated evidence or overwrite append-only history.
- Do not treat lane metadata or GitHub account metadata as participant authentication.
- Do not accept local-only results as authoritative.
- Do not expand Phase 3 into a live service without a separate accepted architectural decision.
