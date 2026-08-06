# E0-H Windows-native qualification release

This package qualifies the shared bare-metal Windows execution profile for E0-H. It is additive: the historical container releases under `experiments/e0h/v1` remain unchanged and reconstructable.

## Frozen target

- native Windows AMD64, build `26200`;
- CPython `3.12.10`, exact `python.exe` SHA-256 bound in `run_inputs.json`;
- PyTorch `2.6.0+cu124`, with `torch.version.cuda == "12.4"`;
- Transformers `4.50.0` and Accelerate `1.1.1`;
- exactly one `NVIDIA GeForce RTX 3080 Ti`;
- normative E0-H dependency closure in `dependency_lock.json`;
- uploaded host inventory retained only as observational evidence by digest;
- PowerShell is a non-semantic launcher.

The private candidate artifact is not committed because it contains a user path and GPU UUID. `environment_candidate_reference.json` is the sanitized binding.

## Reconstruct the compiled release

```powershell
python experiments/e0h/windows_native_v1/compile_release.py `
  --inputs experiments/e0h/windows_native_v1/run_inputs.json `
  --dependency-lock experiments/e0h/windows_native_v1/dependency_lock.json `
  --output-dir experiments/e0h/windows_native_v1/compiled_release `
  --validate
```

## Read-only local preflight

The controller can execute preflight without GPU-training authorization:

```powershell
python experiments/e0h/windows_native_v1/native_controller.py `
  --inputs experiments/e0h/windows_native_v1/run_inputs.json `
  --artifact-root artifacts/e0h-windows-native `
  --preflight-only
```

The output directory is no-clobber. Use a new path for another preflight.

## Full execution gate

Full execution requires `--authorization-file`. The canonical authorization file must contain only:

```json
{"gpu_execution_authorized":true,"release":"e0h-harness-windows-native-py312-torch260-cu124-rtx3080ti-v1","source_commit":"<exact checked-out merged commit>"}
```

The controller compares `source_commit` with `git rev-parse HEAD`, launches every stage with `sys.executable` and `shell=False`, enforces the 1,800-second training limit, terminates the process tree on timeout, performs no automatic rerun, and emits only `HARNESS_PASSED` or `HARNESS_FAILED` for a full run.

No GPU training is authorized by this qualification package itself. The compiled run contract preserves `gpu_execution_authorized=false`.
