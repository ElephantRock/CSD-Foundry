# E0-H Concrete Run Package v1

This directory instantiates the E0-H release compiler on one bounded reference stack. It qualifies infrastructure only. It does not authorize a reasoning-improvement claim or E1 execution.

## Frozen stack

- Model: `HuggingFaceTB/SmolLM2-135M-Instruct`
- Revision: `12fd25f77366fa6b3b4b768ec3050bf629380bac`
- Hardware: one NVIDIA L4 24 GB
- Python: 3.11.13
- PyTorch: 2.8.0+cu128
- CUDA runtime family: 12.8
- Transformers: 4.55.0
- Accelerate: 1.10.0
- Maximum training: eight optimizer steps
- E0-H allocation: 60 GPU minutes from a 600 GPU-minute aggregate program budget

## External asset and access assumptions

- The exact model revision must remain retrievable from the declared repository or an equivalent trusted mirror that reproduces the committed file receipts.
- The operator is responsible for lawful model access and acceptance of all applicable license terms.
- This package records immutable identities and digests. It does not redistribute model weights or mechanically establish legal authority to use them.
- These assumptions govern execution availability only; they are not semantic evidence and cannot support a model-quality claim.

## Build

```bash
docker build \
  -f experiments/e0h/v1/container/Dockerfile \
  -t csd-foundry-e0h:v1 \
  .
```

The base image is digest pinned. All Python distributions are version and SHA-256 pinned in `requirements-cu128.lock`; `python_lock.json` preserves filenames, sizes, versions, and hashes for the complete resolved graph. The lock validator requires the exact `torch==2.8.0+cu128` wheel and a CUDA 12.8 runtime package family.

## Prepare immutable assets

```bash
python -m csd_foundry.empirical.e0h.harness.fetch_assets \
  --run-root experiments/e0h/v1
```

The downloader uses the exact model revision and rejects missing, additional, symlinked, size-mismatched, or digest-mismatched snapshot members.

## Validate before GPU work

```bash
python -m csd_foundry.empirical.e0h.harness.preflight \
  --run-root experiments/e0h/v1 \
  --mode gpu \
  --require-snapshot
```

Preflight validates the static dataset and smoke-fixture bytes, model snapshot, Python graph, execution-package manifest, committed compiled release, runtime versions, GPU count/model, CUDA availability, exact CUDA 12.8 runtime identity, and bf16 support. It still reports `gpu_execution_authorized=false`; execution requires the separate human authorization recorded in issue #69.

## Bounded execution sequence

```bash
python -m csd_foundry.empirical.e0h.harness.tokenize --run-root experiments/e0h/v1
python -m csd_foundry.empirical.e0h.harness.train --run-root experiments/e0h/v1
python -m csd_foundry.empirical.e0h.harness.reload --run-root experiments/e0h/v1
python -m csd_foundry.empirical.e0h.harness.infer --run-root experiments/e0h/v1
python -m csd_foundry.empirical.e0h.harness.smoke_eval --run-root experiments/e0h/v1
```

Only infrastructure and optimization-health evidence is produced. Protected task accuracy, structural-holdout metrics, mutation efficacy, subgroup efficacy, curriculum comparisons, and reasoning-improvement conclusions are prohibited.

## Final classification

```bash
python -m csd_foundry.empirical.e0h.harness.finalize \
  --run-root experiments/e0h/v1 \
  --classification HARNESS_PASSED \
  --actual-gpu-minutes <canonical-decimal>
```

A failed run must use `HARNESS_FAILED` and supply `--failure-reason`. `HARNESS_PASSED` is rejected unless all five required evidence receipts exist, deny protected metrics, bind the checkpoint and fixtures, prove finite reload logits, and prove identical repeated greedy outputs.

## Durable outputs

- Checkpoint target: `github-release://ElephantRock/CSD-Foundry/e0h-v1-checkpoint`
- Evidence target: `github-release://ElephantRock/CSD-Foundry/e0h-v1-evidence`

Transient local or Actions artifacts are staging media only and cannot be the sole accepted evidence location.
