# CSD Foundry

CSD Foundry is an executable reasoning-data foundry for the Control-Status Discipline (CSD).
It turns governed state transitions into machine-verifiable labels, adversarial mutations,
training records, evaluation evidence, and eventually runtime decision receipts.

## Status

**Temporal and Governance Kernel v0.3, completed v0.4 deterministic execution substrate,
and implemented v0.5-A through v0.5-C governed-execution slices.**

The repository currently contains:

- a typed CSD kernel for dependency invalidation, basis survival, restoration, retirement,
  logical time, expiry, profile changes, reassessment requests, and heartbeat obligations;
- independent state, transition, temporal, and event-specific invariant checks;
- a manifest-complete executable registry for all 21 CSD Reasoning Seed v0.1 scenarios;
- deterministic temporal/governance scenarios and mutation kill matrices;
- typed v0.4 synthesis targets, rejection causes, search budgets, completeness witnesses,
  structural holdout rules, mutation severity, and deterministic serialization policies;
- deterministic HMAC choices, canonical identities, bounded attempt replay, immutable execution
  inventories, append-only publication, sealed shard manifests, and crash recovery;
- bounded cross-shard reconciliation, global lowest-valid-attempt resolution, independent
  `FULL_REPLAY`, topology-independent semantic manifests, separate run evidence, and final seals;
- frozen v0.5 event-validation, temporal-completion, registry, disposition, quarantine, release,
  and promotion contracts with commit-blocking conformance vectors;
- executable v0.5 canonicalization and immutable typed contract objects;
- deterministic `ValidatedEvent` admission and reconstruction boundaries;
- atomic compare-and-append temporal claims, ordered projection commitments, failure-no-advance,
  crash recovery, and committed-head visibility;
- proposed Distributional Assurance architecture and doctrine for scenario worlds, causal
  contrasts, failure ecology, process provenance, optimizer exposure, and independent transfer;
- the immutable CSD Reasoning Seed v0.1 and its original generator and validator.

The included seed remains an unbenchmarked synthetic seed. Passing validation establishes
coverage relative to the encoded CSD semantics and committed test evidence. It does not prove
real-world dependency completeness, external truth, structural or distributional completeness,
model generalization, scheduler fairness, or production safety. Release-scale generation remains
blocked until governed registries, disposition, quarantine, the governed vertical slice,
synthesis, structural and distributional assurance, and empirical policy gates are complete.

## Platform direction

The repository is completing CSD as the first governed reasoning domain. The frozen platform
direction is broader:

```text
narrow domain-neutral governance microkernel
        +
versioned domain packs
        +
external specialist oracles
        +
governed open-ended exploration
        ×
Distributional Assurance
        ↓
proof-carrying cognition episodes
```

CSD is intended to become the first domain pack, not a universal ontology. Domain breadth will
come from a domain-definition toolchain, reusable reasoning archetypes, a Reasoning ABI,
assurance-aware cross-domain composition, declared scenario worlds, causal contrast families,
and a separate exploration plane whose hypotheses remain distinct from verified assertions.

The governing quality model is:

```text
Foundry quality
=
Oracle integrity
× Structural assurance
× Distributional assurance
```

The governing principle is:

> **Open at ingestion, bounded at assertion.**

See `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md` for the proposed normative strategic boundary and
`docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md` for the proposed Distributional Assurance doctrine. The
charter is normative for project direction and constitutional invariants, but not for exact
syntax, schemas, algorithms, model choices, thresholds, quotas, or deployment topology.

## Current architecture

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
canonical scenario worlds, distribution contracts, causal contrasts, and failure ecology
        ↓
Verified Cognition Episodes with semantic, epistemic, interaction, and distributional views
        ↓
SFT / preference / process / verifier / repair / RL / benchmark releases
        ↓
independent transfer evaluation and runtime distribution-gap harvesting
```

The first seven lines are substantially implemented. Registry, disposition, quarantine,
trajectory synthesis, structural and distributional assurance, episode compilation, and
empirical-learning layers remain ahead.

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
csd-foundry-governance --release v0.5
csd-foundry-admission --release v0.5
csd-foundry-temporal-v0-5 --release v0.5
python scripts/validate_csd_reasoning_seed.py --directory data/seed/v0.1
```

The scenario validator enforces exact agreement between the immutable manifest and executable
registry. The temporal validator executes canonical logical-time and governance trajectories,
retains complete ordered oracle results, checks full replay identity, and verifies exact event
consequences.

The v0.4 validators check contracts, choice determinism, identity allocation, attempt replay,
immutable execution authority, no-clobber publication, sealed shard evidence, bounded streaming
reconciliation, topology-independent semantic commitments, and complete independent replay.

The v0.5 gates validate frozen contracts, canonicalization, accepted and rejected event admission,
and atomic temporal completion in editable and installed-wheel environments.

Distributional Assurance currently has proposed architecture documents only. No executable
scenario-world schema, distribution contract, causal contrast compiler, failure-topology catalog,
optimizer-exposure ledger, or distributional release report is yet claimed.

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
Atomic temporal concurrent claimants:     12
Atomic temporal concurrent winners:        1
Atomic temporal concurrent losers:        11
Release compilation during clock tick:     0
```

Machine-readable evidence and specifications are committed at:

- `reports/scenario_coverage_v0.2.json`
- `reports/temporal_kernel_coverage_v0.3.json`
- `reports/mutation_policy_v0.3.json`
- `reports/publication_protocol_v0.4.json`
- `reports/reconciliation_protocol_v0.4.json`
- `reports/contract_freeze_v0.5.json`
- `reports/atomic_temporal_v0.5.json`
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
or invalidated evidence cannot be restored under the same identity. A profile change preserves
historical evidence and bases while recomputing the eligible current view. Protected governance
events require I3 authority in both transition execution and independent verification.

## v0.4 synthesis and execution boundary

The v0.4 contract layer distinguishes target contradiction, planner budget exhaustion, state
construction failure, sampler precondition failure, kernel failure, verifier failure, replay
divergence, canonicalization divergence, holdout conflict, mutation outcomes, duplicate
anomalies, and release serialization failure. Each cause has one stable subsystem owner.

Targets may be required, exploratory, machine-proven infeasible, or unresolved. Search exhaustion
is never treated as proof of infeasibility. Machine-proven infeasibility requires an explicit
witness using an approved proof method. Semantic generation decisions prohibit floating-point
values; statistical thresholds remain exact decimal strings until calibrated and frozen.

The completed execution substrate keeps semantic attempt evidence independent of workers,
retries, timestamps, run identities, shard indexes, and storage paths. Streaming reconciliation
consumes every sealed logical shard, reconstructs inventory authority, replays every semantic
completion, resolves the global attempt prefix, and publishes semantic and operational manifests
separately. Whole-corpus in-memory materialization is prohibited.

See `docs/SYNTHESIS_V0_4_CONTRACTS.md`, `docs/publication_protocol_v0.4.md`, and
`docs/reconciliation_protocol_v0.4.md`.

## v0.5 governed-execution boundary

The v0.5 contract freeze defines `ValidatedEvent`, validation failures, atomic clock claims and
completion receipts, semantic and disposition projection ordering, event-sourced registries,
quarantine, and event-triggered release and promotion.

The implemented v0.5-A through v0.5-C slices now provide:

- executable canonicalization and typed contract objects;
- accepted or rejected event-admission receipts;
- reconstruction of accepted events without signature reinterpretation;
- compare-and-append temporal claims;
- ordered projection commitments;
- failure receipts without sequence advancement;
- prepared-completion recovery;
- current visibility only through the committed temporal head;
- exclusion of release compilation from ordinary ticks.

Registry, disposition, and quarantine references in v0.5-C are orchestration placeholders. Their
substantive reducers and eligibility semantics remain v0.5-D and v0.5-E work.

See `docs/CONTRACT_FREEZE_v0.5.md`, `docs/ATOMIC_TEMPORAL_v0.5.md`,
`docs/STRATEGIC_ROADMAP.md`, `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md`, and
`docs/DISTRIBUTIONAL_ASSURANCE_v0.1.md`.

## Project layout

```text
src/csd_foundry/kernel/             CSD state, events, transitions, invariants, oracle
src/csd_foundry/scenarios/          Typed scenario contracts, registry, release runner
src/csd_foundry/scenarios/v0_1/     Manifest-complete v0.1 scenario definitions
src/csd_foundry/temporal/           Canonical temporal/governance release scenarios
src/csd_foundry/synthesis/          Mutation evaluation and synthesis protocols
src/csd_foundry/synthesis/v0_4/     Deterministic synthesis and execution substrate
src/csd_foundry/governance/v0_5/    Contract, admission, and atomic temporal substrate
src/csd_foundry/fixtures/v0_1/      Compatibility fixtures for the bootstrap API
specs/v0.4/                         Reviewable synthesis and execution schemas
specs/v0.5/                         Frozen governance and Reality Assurance policies
scripts/                            Seed and contract validation utilities
data/seed/v0.1/                     Immutable v0.1 seed release
data/canary/                        Frozen known-answer evidence
reports/                            Machine-readable coverage and protocol evidence
tests/                              Kernel, protocol, mutation, and synthesis tests
```

The future Distributional Assurance implementation will add separately versioned contracts,
canaries, validators, reports, and source modules. No implementation version is reserved by the
current doctrine.

## Explicit boundaries

The current implementation does not establish:

- production cryptographic key management or distributed event-admission authority;
- distributed consensus or multi-host temporal-head safety;
- substantive evidence, assumption, or alternative-model registry reducers;
- a substantive disposition oracle, quarantine index, or governed release compiler;
- full primary/shadow model replay as an operational subsystem;
- a complete trajectory planner or state/event constructor;
- structural canonicalization and holdout assignment at release scale;
- an executable Distributional Assurance descriptor ontology or distribution contract;
- causal contrast, failure-topology, process-provenance, filter-loss, or optimizer-exposure contracts;
- distributional completeness, generating-process independence, or protection from recursive synthetic collapse;
- a canonical Verified Cognition Episode or data compilers;
- a domain-neutral microkernel, CognitionDL, domain-pack compiler, or Reasoning ABI;
- a governed open-ended exploration plane;
- fairness or liveness of a real scheduler;
- completeness of real-world dependency declarations;
- correspondence between encoded evidence and external truth;
- model learning, causal transfer, or generalization from generated records;
- production safety.

These remain release boundaries rather than inferred capabilities.

## Immediate roadmap

1. Implement evidence-unit, assumption, and alternative-model registries and roots.
2. Implement the separate disposition oracle and synchronous quarantine.
3. Prove the committed M-03/M-15 governed vertical slice.
4. Implement event-triggered release and promotion.
5. Build the performance benchmark harness and freeze reference pilot SLOs.
6. Resume joint coverage planning, state/event construction, and structural assurance.
7. Implement the Distributional Assurance contract, causal contrasts, failure ecology, process provenance, and release-report vertical slice over M-03/M-15.
8. Extend Verified Cognition Episodes and compilers with epistemic, interaction, and distributional views.
9. Run controlled corpus ablations and the empirical model pilot before authorizing release-scale generation.
10. Freeze scale policies only from semantic, structural, distributional, transfer, and economic evidence.
11. After the governed CSD vertical slice, extract the domain-neutral microkernel boundary and make CSD the first domain pack.
12. Implement the minimal domain-definition compiler and Reasoning ABI before broad multi-domain expansion.
13. Add governed open-ended exploration only with explicit epistemic typing, promotion boundaries, and distribution-gap governance.

## Claim boundary

Passing tests establishes correctness relative to the implemented CSD semantics, frozen
contracts, and test coverage. Proposed architecture documents define intended boundaries but do
not establish implementation. The repository does not yet establish dependency completeness,
external truth, structural or distributional completeness, generating-process independence,
causal transfer, model generalization, scheduler fairness, production safety, or completion of
the broader platform architecture.
