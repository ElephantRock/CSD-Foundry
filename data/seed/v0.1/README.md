# CSD Reasoning Synthesis v0.1

This package applies the Control-Status Discipline (CSD) as both the subject
matter and the governance method for a synthetic LLM reasoning seed corpus.

It contains:

- `csd_reasoning_sft_v0.1.jsonl`: supervised examples;
- `csd_reasoning_preference_v0.1.jsonl`: contrastive chosen/rejected pairs;
- `csd_reasoning_manifest_v0.1.json`: counts, splits, source baselines, and
  SHA-256 fingerprints;
- `generate_csd_reasoning_seed.py`: deterministic, zero-provider-call generator;
- `validate_csd_reasoning_seed.py`: schema, split, count, and digest validator;
- `CSD_REASONING_SYNTHESIS_SPEC_v0.1.md`: design and scaling specification.

## Generate and validate

```bash
python3 generate_csd_reasoning_seed.py
python3 validate_csd_reasoning_seed.py
```

The seed uses source-scenario-exclusive splits. All paraphrases and surface
variants of one underlying CSD scenario stay in a single split.

## Training boundary

The examples contain concise public decision traces: evidence impact, basis
survival, resulting state, rejected inference, rule identifiers, and next
governed step. They do not attempt to capture a model's private chain of
thought.

This is an unbenchmarked synthetic seed. Deterministic generation and validation
establish reproducibility and internal declared-rule consistency; they do not
establish general reasoning transfer or pedagogical effectiveness.
