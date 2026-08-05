# Architectural Intent: Batch-First Foundry with a Durable Embedded Governance Substrate

## Status

**Accepted — 2026-08-05.**

This document records the intended deployment and operating boundary for CSD Foundry. Downstream architecture, implementation, and claim documents may rely on this decision.

## Decision

CSD Foundry is a **batch-first cognition-data manufacturing system with a durable, restartable, single-host governance substrate**.

The primary product runs governed construction, verification, mutation, evaluation, and release workflows to produce machine-verifiable reasoning data and evidence. It may use multiple local processes or overlapping invocations. Its authoritative registries and temporal state must therefore survive interruption, reconstruct deterministically, and reject conflicting publication.

The current system is **not** claimed to be a general-purpose live governance service. It is not a multi-tenant network service, a multi-host coordination system, or a distributed consensus implementation.

## Rationale

The project requires stronger guarantees than a disposable one-process script:

- deterministic reconstruction after interruption;
- atomic no-clobber publication;
- safe same-host process concurrency;
- complete old-or-new snapshot visibility;
- exact retry and uncertain-outcome reconciliation;
- immutable evidence bound to exact source commits;
- reproducible batch manufacturing across CI and local execution environments.

These guarantees protect the integrity of batch manufacturing. They do not, by themselves, imply a continuously running service or authorize service-oriented scope.

## Independent architectural dimensions

The following properties are separate decisions and must not be conflated:

| Dimension | Accepted boundary |
|---|---|
| Product lifetime | Batch-first workflows |
| Persistence | Durable and restartable |
| Local concurrency | Supported and fail-closed |
| Host topology | Single-host reference boundary |
| Exposure | Embedded library, CLI, and repository workflows |
| Network service | Not claimed |
| Multi-tenancy | Not claimed |
| Distributed consensus | Not claimed |
| Runtime governance | Future gated phase, not current product scope |

A durable component is not necessarily a long-running service. A long-running process is not necessarily a network service. A network service is not necessarily a multi-host distributed authority.

## Guarantees retained

The following properties remain justified within the accepted batch-first boundary:

- canonical append-only state;
- content-addressed and digest-bound receipts;
- atomic temporary-write and replacement protocols;
- deterministic restart reconstruction;
- explicit create and open lifecycle boundaries;
- same-host interprocess advisory locking where shared state permits overlapping access;
- complete old-or-new reader visibility;
- exact idempotence and conflict classification;
- pre-commit versus post-commit failure distinction;
- uncertain-outcome reconciliation;
- fault-injection and spawned-process race evidence;
- platform-specific claims stated only where established;
- no-clobber temporal and registry publication.

Existing established guarantees are not removed merely to simplify the product description. Further durability work requires a concrete downstream manufacturing or integration need.

## Service-oriented work excluded

The following work is outside the present boundary unless a separate architectural decision is accepted:

- public or private network API deployment;
- daemon or server productization;
- multi-tenant caller identity and authorization;
- arbitrary external writers;
- multi-host leader election or consensus;
- high-availability and failover objectives;
- service-level objectives;
- rolling deployment and online migration;
- geographic replication;
- production monitoring and service discovery.

A future runtime governance service requires its own charter identifying actual callers, deployment topology, authority model, operational requirements, migration policy, and evidence that embedded batch execution is insufficient.

## Repository operating boundary

GitHub is the sole shared coordination and authority surface for project work.

The repository distinguishes work by lane, not by participant:

- `lane:repository` — architecture, specifications, CPU-compatible implementation, tests, review, documentation, CI, and merge preparation;
- `lane:gpu` — work that materially requires GPU hardware or a target accelerated environment.

Lane metadata classifies work. It does not authenticate or prove which actor performed an action. Participant attribution is outside the project assurance model.

Authoritative trust comes from exact Git commits, committed specifications, reproducible artifacts, independent validation, CI evidence, artifact digests, review records, and guarded merges.

## Consequences

1. The durable Phase 3 publication and reconstruction work remains in scope.
2. Correctness defects involving stale authority, mixed snapshots, no-clobber publication, or restart reconstruction remain release-blocking.
3. Phase 3 must not expand into service deployment, tenancy, multi-host coordination, or operational SLA work.
4. GPU-dependent work must begin from a GitHub issue or committed experiment specification bound to an exact source commit.
5. GPU results return through GitHub branches, draft pull requests, manifests, summaries, and artifact receipts.
6. No local report or chat statement becomes authoritative until represented in GitHub and bound to exact evidence.
7. The empirical model pilot remains the gate for proving learning value; service productization cannot displace it.

## Non-goals

This decision does not:

- weaken executable semantics, independent verification, mutation testing, or temporal safety;
- establish external truth, dependency completeness, learning effectiveness, or production safety;
- approve a general-purpose governance service;
- approve multi-host distributed operation;
- decide the final form of the later runtime phase;
- authenticate participant identity from lane labels or GitHub account metadata.

## Supersession

Any proposal to replace this batch-first boundary with a durable governance service must be made through a new accepted architectural decision. Implementation choices alone cannot silently supersede this document.
