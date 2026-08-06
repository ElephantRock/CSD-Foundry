# E0-H Windows-native v2 execution — `e0h-windows-native-v2-20260806T093910Z`

## Outcome

**Classification: `HARNESS_PASSED`**

This is the single authorized Windows-native E0-H v2 rerun permitted by the
frozen `max_reruns=1` contract. The governed v2 controller ran exactly once
under `--authorization-file`. All five stages (preflight, training, reload,
inference, smoke_evaluation) executed with exit code 0 and no timeouts. The
controller classified `HARNESS_PASSED` with zero classification failures.

This record makes **no** reasoning, capability, accuracy, holdout, mutation,
subgroup, transfer, statistical-power, or scale-readiness claim. The smoke
fixture evaluates greedy-decode execution completeness on a tiny frozen model;
`exact_text_matches` is a textual-agreement field, not a capability metric.

## Frozen identities

- source commit: `e91d00ae36367fe5b00d4d94ac58b47ce503c9c7`
- release: `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2`
- run ID: `e0h-windows-native-v2-20260806T093910Z`
- execution branch: `gpu-experiment/69-e0h-windows-native-v2-20260806T093910Z`
- hardware: 1 × `NVIDIA GeForce RTX 3080 Ti` (driver `610.47`)
- Python: CPython `3.12.10` (sha256 `4d6f5f81a4bca11191c4c7c6b43632694d0a4ce74e068619d8fdc161d469859a`)
- torch `2.6.0+cu124`, CUDA runtime `12.4`, transformers `4.50.0`, accelerate `1.1.1`
- datasets `3.4.1`, pyarrow `19.0.1`
- authorization sha256: `c66ac73ce5096969e674d5d5fe3ed7d1f40402ddddb2bb5bf63f31a80bb9de1b`

## Rerun context

This run is the permitted rerun after the prior v1 run
(`e0h-windows-native-20260806T081010Z`) classified `HARNESS_FAILED` because
`transformers==4.50.0` `Trainer` imports `datasets`, which imports `pyarrow`,
which was absent. The repair installed the hash-locked wheel
`pyarrow-19.0.1-cp312-cp312-win_amd64.whl` (sha256
`5bd1618ae5e5476b7654c7b55a6364ae87686d4724538c24185bbb2952679960`),
yielding the post-repair environment (445 packages, inventory digest
`c0dcea8f…`, candidate sha256 `d9a5d20e…`).

## Published evidence

All assets independently verified by re-download through the GitHub API.

- checkpoint release: `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2-checkpoint`
  - `e0h-windows-native-v2-20260806T093910Z-checkpoint.zip` — sha256 `0afab18d56d02a5c0502f8d85e14339ca2799b49eb871ed53f4956397814f45d`
- evidence release: `e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v2-evidence`
  - `e0h-windows-native-v2-20260806T093910Z-evidence.zip` — sha256 `a92e44b535713f7028d36a615e99cf4968dfab264931ee083f9847e1794bb8e8`

## Verify the published assets

```powershell
# Download both checkpoint assets and check the digest:
sha256sum e0h-windows-native-v2-20260806T093910Z-checkpoint.zip
# expected: 0afab18d56d02a5c0502f8d85e14339ca2799b49eb871ed53f4956397814f45d
```

## Stage results and resource use

| stage | exit | elapsed_s |
|---|---|---|
| preflight | 0 | 15 |
| training | 0 | 13 |
| reload | 0 | 9 |
| inference | 0 | 9 |
| smoke_evaluation | 0 | 1 |

- training: global_steps 8, finite loss 10.791, checkpoint created
- checkpoints: `checkpoint-4`, `checkpoint-8`, `checkpoint-final` all present
- checkpoint-final size: 5,233,216 bytes (< 1 GiB ceiling)
- actual GPU minutes: ~1; remaining aggregate budget: 239 minutes
- protected-metric access: false
