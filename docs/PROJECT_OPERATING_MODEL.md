# Project Operating Model

## Status

**Accepted — 2026-08-05.**

This document defines how project work is assigned, transferred, validated, and accepted. It implements the architectural boundary in `docs/ARCHITECTURAL_INTENT_v1.md`.

## 1. Source of truth

GitHub is the sole shared coordination and authority surface.

The following are authoritative only when represented in GitHub and bound to an exact repository state:

- architectural decisions and specifications;
- implementation and tests;
- issue and pull-request state;
- CI and validation evidence;
- experiment definitions;
- environment and configuration manifests;
- result summaries and artifact receipts;
- merge and roadmap history.

Chat messages, terminal output, local notes, unpushed commits, local artifacts, and verbal completion reports are non-authoritative inputs until represented by a commit, issue, pull request, CI run, or digest-bound receipt.

## 2. Work lanes

The repository classifies work by capability lane rather than participant identity.

### `lane:repository`

Use for work that does not materially require GPU hardware or a target accelerated environment, including:

- architecture and contract design;
- roadmap and issue decomposition;
- CPU-compatible implementation;
- unit, contract, mutation, parser, concurrency, and restart tests;
- documentation and claim boundaries;
- pull-request preparation and exact-head review;
- CI investigation;
- merge preparation and roadmap updates;
- GPU experiment design and result interpretation.

### `lane:gpu`

Use only for work that materially depends on GPU hardware or a target accelerated environment, including:

- training and fine-tuning;
- GPU inference evaluation;
- memory and throughput profiling;
- CUDA- or driver-specific debugging;
- multi-GPU execution;
- checkpoint conversion and quantization;
- GPU-dependent output generation;
- checkpoint inspection and hardware reproducibility runs.

Lane labels describe the work. They do not identify, authenticate, or prove which participant performed it.

## 3. Attribution boundary

Governed repository artifacts must not name or attribute work to participants, assistants, vendors, or machine owners.

Do not include claims such as:

- implemented by a named participant;
- reviewed by a named assistant;
- executed by a named local process owner;
- approved because of actor identity.

Use evidence statements instead:

```text
Execution lane: lane:gpu
Source commit: <exact SHA>
Result commit: <exact SHA>
Validation run: <run ID>
Artifact digest: sha256:...
Review status: accepted
```

The project assurance model validates artifacts and derivations, not actor identity. GitHub account metadata may identify the single account used for repository operations, but that identity is not treated as proof of who performed a particular action.

## 4. Required repository workflow

Every substantive change follows this sequence:

1. Open or identify a GitHub issue containing the objective and acceptance gates.
2. Assign the appropriate work lane.
3. Record the exact base commit.
4. Work on a dedicated branch.
5. Add or update tests and evidence before claiming completion.
6. Push the complete branch to GitHub.
7. Open a draft pull request with commands and observed results.
8. Review the exact remote head, not a local summary.
9. Require CI and all applicable historical gates to pass on the reviewed head.
10. Resolve every blocking review finding.
11. Merge only the exact accepted head using an expected-head guard where supported.
12. Update related issues and roadmap records after merge.

A local green result is review input. It does not substitute for remote exact-head inspection and GitHub CI.

## 5. GPU task specification

Every `lane:gpu` task must begin with a GitHub issue or committed experiment specification containing at least:

```text
experiment_id
objective
hypothesis
base_commit_sha
input_dataset_and_digest
model_and_exact_revision
environment_manifest
random_seeds
training_or_inference_command
resource_ceiling
expected_outputs
acceptance_criteria
failure_criteria
artifact_retention_policy
```

The task must be executable from the specified commit without relying on unstated chat context.

## 6. GPU execution handoff

A GPU execution run follows this protocol:

1. Check out the exact specified base commit.
2. Create a `gpu-experiment/` or `gpu-evaluation/` branch when repository changes or committed evidence are required.
3. Execute only the committed or issue-defined protocol.
4. Record deviations explicitly; do not silently adapt the experiment.
5. Store large artifacts outside ordinary Git history when necessary.
6. Compute immutable digests for every retained external artifact.
7. Commit scripts, configurations, manifests, summarized metrics, and receipts.
8. Open or update a draft pull request linked to the task issue.
9. Stop without merging or declaring a roadmap gate passed.

The repository lane then reviews the exact branch, protocol compliance, logs, metrics, artifact bindings, and supported claims.

## 7. Artifact receipts

Large checkpoints, raw generated corpora, and other oversized artifacts should not normally be committed directly to Git. Commit a receipt such as:

```json
{
  "schema_version": "gpu-artifact-receipt/1",
  "experiment_id": "EXP-001",
  "execution_lane": "lane:gpu",
  "source_commit": "<git-sha>",
  "artifact_type": "model-checkpoint",
  "artifact_uri": "<controlled-storage-reference>",
  "artifact_digest": "sha256:...",
  "byte_size": 0,
  "model_revision": "<exact-revision>",
  "dataset_digest": "sha256:...",
  "configuration_digest": "sha256:...",
  "environment_digest": "sha256:...",
  "result_status": "COMPLETED"
}
```

A summary without immutable artifact and configuration bindings is observational evidence, not a reproducible result.

## 8. Branch conventions

Recommended branch prefixes:

```text
feature/          repository implementation
fix/              reviewed correctness correction
docs/             specifications and governance documents
gpu-experiment/   GPU training or generation
gpu-evaluation/   GPU-dependent evaluation or profiling
```

Every report must state its exact base and head SHAs.

## 9. Review and acceptance

Acceptance is based on:

- agreement with accepted architecture and frozen contracts;
- exact-head code and document review;
- deterministic and adversarial tests;
- applicable historical gates;
- GitHub CI;
- committed experiment specifications;
- digest-bound artifacts and manifests;
- explicit claim boundaries.

No lane may treat its own completion report as sufficient evidence. The repository record must permit independent reconstruction of what was proposed, executed, observed, and accepted.

## 10. Source hierarchy

When records disagree, use this order:

1. merged accepted architectural documents and frozen contracts;
2. merged implementation and tests;
3. current open pull-request head and diff;
4. GitHub Actions evidence for that exact head;
5. committed experiment manifests and artifact receipts;
6. issue and pull-request discussions;
7. local execution reports;
8. chat descriptions and memory.

## 11. Scope control

The accepted operating model must not be used to introduce service-oriented work into Phase 3. Durable same-host batch integrity is in scope. Network deployment, tenancy, multi-host coordination, service SLOs, and production operations require a separate accepted decision.

GPU execution must remain a specialized downstream lane. It must not redefine architecture, weaken acceptance gates, or become a second source of truth.
