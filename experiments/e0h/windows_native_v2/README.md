# E0-H Windows-native v2 dependency repair

This package is an additive repair of the failed
`e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1` execution.

The v1 run remains immutable at:

- run ID: `e0h-windows-native-20260806T081010Z`
- classification: `HARNESS_FAILED`
- evidence SHA-256: `bd8228f3c10e42afe1002b1b2cd44138e6ee7ae03f9a5ae94c304943c75155b1`
- failure: `transformers.Trainer` imported `datasets`, which imported missing `pyarrow`

## Repair boundary

The repaired release:

`e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2`

adds the exact `datasets` training-import closure to the normative dependency
lock and binds the CPython 3.12 Windows wheel:

`pyarrow-19.0.1-cp312-cp312-win_amd64.whl`

SHA-256:

`5bd1618ae5e5476b7654c7b55a6364ae87686d4724538c24185bbb2952679960`

The model, tokenizer, dataset, training recipe, smoke fixture, budget, protected
metric boundary, and reviewed training implementation are unchanged.

## Environment mutation

Do not install the repair dependency until this PR is reviewed. The only
permitted environment mutation is:

```powershell
python -m pip download `
  --only-binary=:all: `
  --no-deps `
  --require-hashes `
  --dest artifacts/e0h-windows-native-v2-wheelhouse `
  -r experiments/e0h/windows_native_v2/repair_requirements.txt

python -m pip install `
  --no-index `
  --no-deps `
  --require-hashes `
  --find-links artifacts/e0h-windows-native-v2-wheelhouse `
  -r experiments/e0h/windows_native_v2/repair_requirements.txt
```

The wheel filename and SHA-256 must match the committed dependency lock.

## Read-only qualification

After the exact wheel installation, run only:

```powershell
python experiments/e0h/windows_native_v2/native_controller.py `
  --inputs experiments/e0h/windows_native_v2/run_inputs.json `
  --artifact-root artifacts/e0h-windows-native-v2 `
  --preflight-only
```

The v2 preflight now verifies:

- the exact post-repair pip inventory digest;
- every exact dependency pin;
- all non-extra `datasets==3.4.1` requirement metadata;
- import of the same `transformers.Trainer` and `TrainingArguments` path used
  by training;
- exact `datasets` and `pyarrow` versions;
- source-tree provenance;
- model/tokenizer assets;
- deterministic tokenization;
- finite CPU forward pass.

No GPU execution is authorized by this package or by a successful preflight.
The one permitted infrastructure-invalid rerun requires a separate canonical
authorization bound to the exact merged v2 commit.
