# E0-H Windows-native execution — `e0h-windows-native-20260806T081010Z`

## Outcome

**Classification: `HARNESS_FAILED`**

This is a failed, single authorized Windows-native E0-H execution. The governed
controller ran exactly once under `--authorization-file`. It reached the
training stage; the training subprocess exited non-zero at import time before
any CUDA kernel ran. No checkpoint, reload, inference, or smoke output was
produced. No E0-H GPU budget was consumed.

This record makes **no** reasoning, capability, accuracy, holdout, mutation,
subgroup, transfer, statistical-power, or scale-readiness claim.

## Frozen identities

- source commit: `5d4d487395b742f33ba29c4dee71ef2922222ff7`
- release: `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1`
- run ID: `e0h-windows-native-20260806T081010Z`
- execution branch: `gpu-experiment/69-e0h-windows-native-20260806T081010Z`
- hardware: 1 × `NVIDIA GeForce RTX 3080 Ti` (driver `610.47`)
- Python: CPython `3.12.10` (sha256 `4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a`)
- torch: `2.6.0+cu124`, CUDA runtime `12.4`
- transformers `4.50.0`, accelerate `1.1.1`
- authorization sha256: `f529c8292c7c1ee69da99866854efd706fa9b3be545f70bdd265422ec4f499c2`

## Root cause of failure

The training stage crashed at import time:

```
transformers.trainer (line 196) -> import datasets
datasets.__init__ (line 17)     -> import pyarrow as pa
ModuleNotFoundError: No module named 'pyarrow'
```

`pyarrow` is not installed in the shared Windows Python 3.12 environment, and
it is not part of the frozen E0-H dependency lock (`dependency_lock.json`).
The frozen lock pins `transformers==4.50.0`, whose `Trainer` import path
unconditionally imports `datasets`, which requires `pyarrow`. The breakage is
an ambient host-package condition outside the frozen lock, not a defect in the
frozen E0-H inputs or recipe. Preflight does not import `transformers.Trainer`
and therefore did not surface this; the failure appeared only at training.

GPU telemetry confirms the process never reached the GPU: 0% utilization,
840 MiB (idle desktop) across all samples.

## Published evidence

Per runbook section 13, no successful checkpoint was published for this failed
run. Failure evidence was published to the evidence release and independently
verified by re-download.

- evidence release tag: `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1-evidence`
- asset `e0h-windows-native-20260806T081010Z-evidence.zip` — sha256 `bd8228f3c10e42afe1002b1b2cd44138e6ee7ae03f9a5ae94c304943c75155b1`
- asset `e0h-windows-native-20260806T081010Z-evidence.zip.sha256` — sha256 `2c7166c8b6ec5b5e34f2e21f4781b61a3c6009c244b04af1512c4fb33ccd3eea`
- checkpoint release tag `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1-checkpoint`: **not created** (failed run)

## Verify the published evidence

```powershell
# Download both assets from the evidence release and check the digest:
#   e0h-windows-native-20260806T081010Z-evidence.zip
#   e0h-windows-native-20260806T081010Z-evidence.zip.sha256
sha256sum e0h-windows-native-20260806T081010Z-evidence.zip
# expected: bd8228f3c10e42afe1002b1b2cd44138e6ee7ae03f9a5ae94c304943c75155b1
```

The evidence archive contains the controller receipt, classification
failures, GPU telemetry, the preflight receipts, and the failed training
logs that record the `pyarrow` import error.

## Rerun policy

No automatic rerun was performed. The controller was executed exactly once.
A second attempt requires explicit owner authorization after this
`HARNESS_FAILED` classification and resolution of the missing `pyarrow`
dependency in the host environment.
