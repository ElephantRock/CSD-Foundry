#!/usr/bin/env python3
"""Sealed execution controller for the Windows-native E1 release.

This controller orchestrates the E1 sealed execution boundary: BASE, CONTROL,
and FOUNDRY conditions in independent fresh processes, the sealed inference
pass over the compiled prompt inventory, and the sealed execution receipt
publication. It does NOT compute protected metrics; that is the metric
controller's domain.

The controller follows the E0-H ``native_controller.py`` pattern with
``--preflight-only`` and ``--authorization-file`` modes. For E1 the execution
authorization is a distinct domain from the metric-release authorization:
this controller accepts only the execution authorization
(``gpu_execution_authorized=true, metric_release_authorized=false``) and
rejects a metric-release authorization, and vice versa for the metric
controller.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e0h.windows_native import (
    ProcessResult,
    canonical_json_text,
    run_process,
    write_canonical_json,
)

# Avoid importing the compiler at module load (it pulls the tokenizer); the
# controller only needs the RELEASE constant and the authorization helpers.
RELEASE = "e1-windows-native-v1"

_TIMEOUTS = {
    "preflight": 900,
    "control_train": 900,
    "foundry_train": 900,
    "base_inference": 600,
    "control_checkpoint4_inference": 600,
    "control_final_inference": 600,
    "foundry_checkpoint4_inference": 600,
    "foundry_final_inference": 600,
}
# Eight sealed execution stages: preflight, two training arms, then five
# separate inference invocations (one model source + one prediction set each).
# BASE is never trained: its prediction set is produced by base_inference,
# which loads the frozen base model directly.
_ORDER = (
    "preflight",
    "control_train",
    "foundry_train",
    "base_inference",
    "control_checkpoint4_inference",
    "control_final_inference",
    "foundry_checkpoint4_inference",
    "foundry_final_inference",
)
_TRAIN_STAGES = ("control_train", "foundry_train")
_INFERENCE_STAGES = (
    "base_inference",
    "control_checkpoint4_inference",
    "control_final_inference",
    "foundry_checkpoint4_inference",
    "foundry_final_inference",
)


def _load_canonical(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict) or canonical_json_text(value) != text:
        raise ValueError(f"{path} must contain canonical UTF-8 LF JSON")
    return value


def _current_commit(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return completed.stdout.strip()


def _require_execution_authorization(path: Path, repo_root: Path) -> dict[str, object]:
    """Authenticate the GPU execution authorization file.

    The execution authorization domain is exactly:
    ``{gpu_execution_authorized: true, metric_release_authorized: false,
    release, source_commit}``. A metric-release authorization must be
    rejected so the two domains cannot be confused.
    """

    value = _load_canonical(path)
    expected_fields = {
        "gpu_execution_authorized",
        "metric_release_authorized",
        "release",
        "source_commit",
    }
    if set(value) != expected_fields:
        raise ValueError("execution authorization file has unexpected fields")
    if value["gpu_execution_authorized"] is not True:
        raise ValueError("GPU execution is not authorized")
    if value["metric_release_authorized"] is not False:
        raise ValueError(
            "execution authorization must deny metric release (metric release is a separate domain)"
        )
    if value["release"] != RELEASE:
        raise ValueError("authorization release does not match the E1 native release")
    observed_commit = _current_commit(repo_root)
    if value["source_commit"] != observed_commit:
        raise ValueError(
            f"authorization source commit {value['source_commit']} != checked-out {observed_commit}"
        )
    return value


def _command_argv(commands: Mapping[str, object], name: str) -> list[str]:
    raw = commands.get(name)
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"commands.{name} must be a nonempty string array")
    if raw[0] != "python":
        raise ValueError(f"commands.{name} must be bound to the active Python interpreter")
    return [sys.executable, *raw[1:]]


# Repo-relative path prefixes used by the canonical launch commands that must
# be rewritten to match the gold-free execution-root layout. The commands are
# authored against the repository checkout (so they are human-auditable and
# digest-bound in launch_commands.json); the controller rewrites them to the
# execution-root layout before invoking the sealed stages.
_HARNESS_REPO_PREFIX = "experiments/e1/windows_native_v1/e1_native_harness.py"
_RUN_INPUTS_REPO_PREFIX = "experiments/e1/windows_native_v1/run_inputs.json"
_COMPILED_RELEASE_REPO_PREFIX = "experiments/e1/windows_native_v1/compiled_release/"


def _rewrite_argv_for_execution_root(argv: Sequence[str]) -> list[str]:
    """Rewrite repo-relative command paths to execution-root-relative paths.

    The canonical launch commands reference repository-relative paths
    (``experiments/e1/windows_native_v1/e1_native_harness.py``,
    ``experiments/e1/windows_native_v1/run_inputs.json``,
    ``experiments/e1/windows_native_v1/compiled_release/...``). Those paths do
    not exist beneath the gold-free execution root, whose layout places the
    harness at the root, ``run_inputs.json`` at the root, and the compiled
    release under ``compiled_release/``. ``data/e1/v6/`` paths are already
    correct under the execution root and are left untouched.
    """

    rewritten: list[str] = []
    for item in argv:
        if item == _HARNESS_REPO_PREFIX:
            rewritten.append("e1_native_harness.py")
        elif item == _RUN_INPUTS_REPO_PREFIX:
            rewritten.append("run_inputs.json")
        elif item.startswith(_COMPILED_RELEASE_REPO_PREFIX):
            rewritten.append("compiled_release/" + item[len(_COMPILED_RELEASE_REPO_PREFIX) :])
        else:
            rewritten.append(item)
    return rewritten


def _load_launch_commands_from(compiled_release_dir: Path) -> dict[str, object]:
    """Load the authenticated launch commands from a compiled_release dir.

    ``run_inputs.json`` does not carry ``commands``; the command vectors (and
    their digest binding) live in the authenticated
    ``launch_commands.json``. The same file is read from the repository
    ``compiled_release/`` (for the preflight, which runs from repo_root) and
    from the exported execution root's ``compiled_release/`` (for the sealed
    stages).
    """

    launch_path = compiled_release_dir / "launch_commands.json"
    launch_data: dict[str, Any] = json.loads(launch_path.read_text(encoding="utf-8"))
    commands = launch_data.get("commands")
    if not isinstance(commands, dict):
        raise ValueError("launch_commands.json commands must be an object")
    return commands


def _append(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def _classify(
    results: Mapping[str, ProcessResult],
    required_outputs: Mapping[str, object],
    repo_root: Path,
) -> tuple[str, list[str]]:
    """Classify the sealed execution against the committed requirements.

    The sealed execution classification is bounded to PASSED/FAILED; the E1
    PROMISING/HARMFUL/etc. terminal classification belongs to the metric
    controller and is never produced here (no protected metrics are visible).

    The required outputs are the two trained checkpoint directories (CONTROL
    and FOUNDRY) and the five inference prediction manifests. BASE is never
    trained, so no base checkpoint directory is required.
    """

    failures: list[str] = []

    _append(
        set(results) == set(_ORDER),
        failures,
        "not all sealed execution stages executed",
    )
    for name in _ORDER:
        result = results.get(name)
        if result is None:
            continue
        _append(result.exit_code == 0, failures, f"{name} exited with {result.exit_code}")
        _append(not result.timed_out, failures, f"{name} timed out")

    checkpoint_fields = ("control_checkpoint_directory", "foundry_checkpoint_directory")
    manifest_fields = (
        "base_inference_manifest",
        "control_checkpoint4_inference_manifest",
        "control_final_inference_manifest",
        "foundry_checkpoint4_inference_manifest",
        "foundry_final_inference_manifest",
    )
    for field in checkpoint_fields:
        raw = required_outputs.get(field)
        if not isinstance(raw, str) or not raw:
            failures.append(f"required_outputs.{field} must be a nonempty path")
            continue
        _append((repo_root / raw).is_dir(), failures, f"{field} directory is missing")
    for field in manifest_fields:
        raw = required_outputs.get(field)
        if not isinstance(raw, str) or not raw:
            failures.append(f"required_outputs.{field} must be a nonempty path")
            continue
        path = repo_root / raw
        _append(
            path.is_file() and path.stat().st_size > 0,
            failures,
            f"{field} is missing or empty",
        )

    classification = "SEALED_EXECUTION_PASSED" if not failures else "SEALED_EXECUTION_FAILED"
    return classification, failures


# ---------------------------------------------------------------------------
# Gold-free execution root (Defect 2).
#
# The sealed controller executes from a temporary directory that contains ONLY
# the installed package code, the run contract, the model/tokenizer identities,
# the training curriculum, the sealed prompt inventory, and the command/lock
# files. It must NOT contain any gold file (development/clean evaluation),
# metric code, classification outputs, or a ``.git`` directory. This is a
# filesystem-level enforcement: a forbidden file beneath the root is rejected
# before any sealed process is launched.
# ---------------------------------------------------------------------------

# File basenames that are forbidden anywhere beneath the execution root.
_FORBIDDEN_GOLD_BASENAMES = frozenset(
    {
        "development_evaluation.jsonl",
        "clean_evaluation.jsonl",
        "evaluation_cases.jsonl",
    }
)
# Substrings that mark a path as forbidden (metric code or classification
# outputs) when they appear in any path component beneath the root.
_FORBIDDEN_PATH_PARTS = frozenset(
    {
        "response_abi_metrics.py",
        "e1_metric_controller.py",
    }
)
# Explicitly allowlisted basenames that may be copied into the root.
_ALLOWLIST_ROOT_BASENAMES = frozenset(
    {
        # Compiled release artifacts the sealed runtime consumes.
        "run_inputs.json",
        "e1_run_contract.json",
        "run_inputs_lock.json",
        "reconstruction_receipt.json",
        "environment_lock.json",
        "training_recipe.json",
        "budget_contract.json",
        "checkpoint_contract.json",
        "classification_contract.json",
        "storage_contract.json",
        "evaluation_access_contract.json",
        "launch_commands.json",
        "sealed_prompt_manifest.json",
        "artifact_manifest.json",
        "sealed_prompt_inventory.jsonl",
        # Authenticated curriculum arms (training data only).
        "control_train.jsonl",
        "foundry_train.jsonl",
        "paired_task_format.json",
        "paired_e1_contract.json",
        "tokenization_manifest.json",
        # Dependency lock.
        "dependency_lock.json",
    }
)


def _reject_forbidden_paths(root: Path) -> None:
    """Walk ``root`` and reject any forbidden file/dir.

    Rejects ``.git`` directories, gold evaluation files, metric/controller
    code, and classification output artifacts anywhere beneath the root.
    """

    for path in root.rglob("*"):
        parts = set(path.relative_to(root).parts)
        name = path.name
        if name == ".git" or ".git" in parts:
            raise ValueError(f"execution root leaks forbidden path: {path}")
        if name in _FORBIDDEN_GOLD_BASENAMES:
            raise ValueError(f"execution root leaks gold file: {path}")
        if parts & _FORBIDDEN_PATH_PARTS or name in _FORBIDDEN_PATH_PARTS:
            raise ValueError(f"execution root leaks metric/controller code: {path}")
        if name == "metric_release_receipt.json" or name.endswith(".classification.json"):
            raise ValueError(f"execution root leaks classification output: {path}")


def export_execution_root(
    *,
    repo_root: Path,
    release_dir: Path,
    dependency_lock: Path,
    compiled_release: Path,
    v6_dir: Path,
) -> Path:
    """Create a temporary gold-free execution root and return its path.

    Copies ONLY: installed package code, the run contract and other compiled
    release artifacts, the model/tokenizer identities, the training curriculum
    arms, the sealed prompt inventory, and the command/lock files. Rejects if
    ``.git``, ``development_evaluation.jsonl``, ``clean_evaluation.jsonl``,
    ``evaluation_cases.jsonl``, metric code, or classification outputs are
    found beneath the root (filesystem-level enforcement, not just logical).

    The sealed controller executes its training/inference stages from this
    root, so the gold labels and metric implementations it could otherwise
    reach in the repository checkout are physically absent.
    """

    root = Path(tempfile.mkdtemp(prefix="e1-sealed-exec-"))
    try:
        # 1. Installed package code (src/csd_foundry -> root/src/csd_foundry),
        #    with the protected metric implementation modules pruned out so the
        #    sealed runtime cannot locally compute the protected metrics. The
        #    gold evaluation files, the metric controller script, and
        #    classification outputs are never copied in the first place.
        package_src = repo_root / "src" / "csd_foundry"
        if not package_src.is_dir():
            raise ValueError(f"installed package source missing: {package_src}")

        def _prune_metric_code(directory: Path, names: list[str]) -> list[str]:
            """shutil.ignore_patterns callback: drop metric code from the copy."""

            pruned: list[str] = []
            for forbidden in _FORBIDDEN_PATH_PARTS | _FORBIDDEN_GOLD_BASENAMES:
                if forbidden in names:
                    pruned.append(forbidden)
            return pruned

        shutil.copytree(package_src, root / "src" / "csd_foundry", ignore=_prune_metric_code)

        # 2. Compiled release artifacts (the run contract, model/tokenizer
        #    identities, sealed prompt inventory, command files).
        if not compiled_release.is_dir():
            raise ValueError(f"compiled release directory missing: {compiled_release}")
        sealed_root = root / "compiled_release"
        sealed_root.mkdir()
        for name in _ALLOWLIST_ROOT_BASENAMES:
            src = compiled_release / name
            if src.is_file():
                shutil.copy2(src, sealed_root / name)

        # 3. run_inputs.json and the dependency lock at the root.
        shutil.copy2(release_dir / "run_inputs.json", root / "run_inputs.json")
        shutil.copy2(dependency_lock, root / "dependency_lock.json")

        # 4. The standalone training/inference harness script. It is needed by
        #    every training and inference stage (control_train, foundry_train,
        #    and the five inference invocations). The metric controller and the
        #    preflight are deliberately NOT copied: the preflight runs from
        #    repo_root before this root is exported, and the metric controller
        #    is forbidden beneath the execution root.
        harness_src = release_dir / "e1_native_harness.py"
        if not harness_src.is_file():
            raise ValueError(f"harness script missing: {harness_src}")
        shutil.copy2(harness_src, root / "e1_native_harness.py")

        # 5. Authenticated training curriculum arms (training data only).
        curriculum_root = root / "data" / "e1" / "v6"
        curriculum_root.mkdir(parents=True)
        for name in ("control_train.jsonl", "foundry_train.jsonl", "paired_task_format.json"):
            src = v6_dir / name
            if src.is_file():
                shutil.copy2(src, curriculum_root / name)

        # 6. Filesystem-level enforcement: reject any forbidden file beneath
        #    the root BEFORE returning it for sealed execution.
        _reject_forbidden_paths(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--authorization-file", type=Path)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    if inputs.get("release") != RELEASE:
        raise ValueError("run input release does not match the E1 native controller")
    required_outputs = inputs.get("required_outputs")
    if not isinstance(required_outputs, dict):
        raise ValueError("run inputs required_outputs must be an object")

    repo_root = Path(__file__).resolve().parents[3]
    release_dir = Path(__file__).resolve().parent
    repo_compiled_release = release_dir / "compiled_release"
    artifact_root = args.artifact_root.resolve()
    if artifact_root.exists():
        raise FileExistsError(f"artifact root already exists: {artifact_root}")
    log_root = artifact_root / "logs"
    log_root.mkdir(parents=True)

    # Preflight runs from repo_root against the repository checkout (it needs
    # data/e1/v6 and the compiled release, and runs before the gold-free
    # execution root is exported). Its command vector comes from the
    # authenticated repo compiled_release/launch_commands.json.
    repo_commands = _load_launch_commands_from(repo_compiled_release)
    results: dict[str, ProcessResult] = {}
    preflight = run_process(
        _command_argv(repo_commands, "preflight"),
        cwd=repo_root,
        stdout_path=log_root / "01-preflight.stdout.log",
        stderr_path=log_root / "01-preflight.stderr.log",
        timeout_seconds=_TIMEOUTS["preflight"],
    )
    results["preflight"] = preflight
    if args.preflight_only:
        write_canonical_json(
            artifact_root / "controller_receipt.json",
            {
                "schema_version": "e1-windows-native-controller-receipt/1",
                "release": RELEASE,
                "mode": "preflight_only",
                "results": {"preflight": preflight.to_dict()},
                "gpu_training_executed": False,
                "terminal_classification": None,
            },
        )
        if preflight.exit_code != 0 or preflight.timed_out:
            raise SystemExit(1)
        return

    if args.authorization_file is None:
        raise ValueError("sealed execution requires --authorization-file")
    authorization = _require_execution_authorization(args.authorization_file, repo_root)
    # Materialize a gold-free execution root and verify it contains no gold,
    # metric code, classification outputs, or ``.git`` directory. The sealed
    # training/inference stages execute against this verified boundary. Their
    # canonical (repository-relative) launch commands are rewritten to the
    # execution-root layout so every path the sealed stages touch resolves
    # beneath the gold-free root, and their outputs land under the execution
    # root (the single artifact root for output search and classification).
    dependency_lock = (
        repo_root / "experiments" / "e0h" / "windows_native_v2" / "dependency_lock.json"
    )
    v6_dir = repo_root / "data" / "e1" / "v6"
    execution_root = export_execution_root(
        repo_root=repo_root,
        release_dir=release_dir,
        dependency_lock=dependency_lock,
        compiled_release=repo_compiled_release,
        v6_dir=v6_dir,
    )
    # Load the (authenticated) commands from the exported root and rewrite the
    # repo-relative paths to the execution-root layout for the sealed stages.
    exec_commands = _load_launch_commands_from(execution_root / "compiled_release")
    failures: list[str] = []
    sealed_prediction_manifest_sha256: str | None = None
    if preflight.exit_code != 0 or preflight.timed_out:
        classification = "SEALED_EXECUTION_FAILED"
        failures.append("preflight did not complete successfully")
    else:
        for index, name in enumerate(_ORDER[1:], 2):
            argv = _rewrite_argv_for_execution_root(_command_argv(exec_commands, name))
            result = run_process(
                argv,
                cwd=execution_root,
                stdout_path=log_root / f"{index:02d}-{name}.stdout.log",
                stderr_path=log_root / f"{index:02d}-{name}.stderr.log",
                timeout_seconds=_TIMEOUTS[name],
            )
            results[name] = result
            if result.exit_code != 0 or result.timed_out:
                break

        # Aggregate the five inference manifests into one canonical 40-record
        # sealed prediction manifest (5 sets x 8 cases = 40 records). The
        # subprocesses wrote under execution_root (their cwd), so the inference
        # manifests and trained checkpoints are located there. Each record is
        # preserved verbatim with its full schema and tagged with its
        # prediction_set_name.
        _INFERENCE_TO_SET = {
            "base_inference": "BASE",
            "control_checkpoint4_inference": "CONTROL-checkpoint-4",
            "control_final_inference": "CONTROL-final",
            "foundry_checkpoint4_inference": "FOUNDRY-checkpoint-4",
            "foundry_final_inference": "FOUNDRY-final",
        }
        # Load the authenticated sealed prompt inventory to get the frozen
        # evaluation IDs that every prediction set must cover.
        sealed_inventory_path = (
            execution_root / "compiled_release" / "sealed_prompt_inventory.jsonl"
        )
        expected_eval_ids: set[str] = set()
        for line in sealed_inventory_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                inv_rec = json.loads(line)
                expected_eval_ids.add(str(inv_rec.get("evaluation_id", "")))
        if len(expected_eval_ids) != 8:
            failures.append(
                f"sealed prompt inventory must have exactly 8 evaluation IDs, "
                f"observed {len(expected_eval_ids)}"
            )

        sealed_manifest_path = (
            artifact_root.parent / "sealed_inference" / "prediction_manifest.json"
        )
        sealed_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        aggregated_records: list[dict[str, object]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for inf_stage, set_name in _INFERENCE_TO_SET.items():
            inf_manifest_rel = required_outputs.get(f"{inf_stage}_manifest")
            if not isinstance(inf_manifest_rel, str):
                failures.append(f"required_outputs.{inf_stage}_manifest must be a path")
                continue
            inf_path = execution_root / inf_manifest_rel
            if not inf_path.is_file():
                failures.append(f"{inf_stage} manifest missing: {inf_path}")
                continue
            inf_data: dict[str, Any] = json.loads(inf_path.read_text(encoding="utf-8"))
            inf_records = inf_data.get("predictions")
            if not isinstance(inf_records, list):
                failures.append(f"{inf_stage} manifest has no predictions list")
                continue
            for rec in inf_records:
                if not isinstance(rec, dict):
                    failures.append(f"{inf_stage} manifest has a non-object prediction")
                    continue
                eval_id = str(rec.get("evaluation_id", ""))
                pair = (set_name, eval_id)
                if pair in seen_pairs:
                    failures.append(f"duplicate prediction pair: {pair}")
                    continue
                seen_pairs.add(pair)
                # Preserve the complete record schema. Reject (do not repair)
                # a source prediction_set_name that is missing, empty, or
                # disagrees with the scheduled set identity.
                source_set = rec.get("prediction_set_name")
                if source_set != set_name:
                    failures.append(
                        f"{inf_stage}: source prediction_set_name {source_set!r} "
                        f"!= scheduled {set_name!r}"
                    )
                    continue
                preserved: dict[str, object] = dict(rec)
                aggregated_records.append(preserved)
        # Canonically sort by (prediction_set_name, evaluation_id) and require
        # exactly 40 unique (prediction_set_name, evaluation_id) pairs.
        aggregated_records.sort(
            key=lambda r: (str(r["prediction_set_name"]), str(r["evaluation_id"]))
        )
        if len(seen_pairs) != 40:
            failures.append(
                f"expected exactly 40 unique (prediction_set_name, evaluation_id) "
                f"pairs, observed {len(seen_pairs)}"
            )
        import hashlib as _hashlib

        sealed_manifest = {
            "schema_version": "e1-sealed-prediction-manifest/1",
            "prediction_sets": sorted(
                set(str(r["prediction_set_name"]) for r in aggregated_records)
            ),
            "record_count": len(aggregated_records),
            "predictions": aggregated_records,
            "manifest_sha256": _hashlib.sha256(
                json.dumps(aggregated_records, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        sealed_manifest_path.write_text(
            json.dumps(sealed_manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        sealed_prediction_manifest_sha256 = _hashlib.sha256(
            sealed_manifest_path.read_bytes()
        ).hexdigest()

        # Validate per-set coverage: exactly 8 records per set, matching the
        # exact frozen evaluation IDs from the sealed prompt inventory.
        for _inf_stage, set_name in _INFERENCE_TO_SET.items():
            set_records = [
                r for r in aggregated_records if str(r.get("prediction_set_name")) == set_name
            ]
            if len(set_records) != 8:
                failures.append(
                    f"prediction set {set_name} must have exactly 8 records, "
                    f"observed {len(set_records)}"
                )
            set_eval_ids = {str(r.get("evaluation_id", "")) for r in set_records}
            if set_eval_ids != expected_eval_ids:
                missing = expected_eval_ids - set_eval_ids
                extra = set_eval_ids - expected_eval_ids
                failures.append(
                    f"prediction set {set_name} evaluation IDs mismatch: "
                    f"missing={sorted(missing)}, extra={sorted(extra)}"
                )

        # Combine aggregation failures with classification failures so an
        # aggregation failure forces SEALED_EXECUTION_FAILED.
        classification, classify_failures = _classify(results, required_outputs, execution_root)
        failures.extend(classify_failures)
        if failures:
            classification = "SEALED_EXECUTION_FAILED"

    receipt: dict[str, object] = {
        "schema_version": "e1-windows-native-controller-receipt/1",
        "release": RELEASE,
        "mode": "sealed_execution",
        "authorization_domain": "gpu_execution",
        "authorization": authorization,
        "results": {name: result.to_dict() for name, result in results.items()},
        "gpu_training_executed": any(name in results for name in _TRAIN_STAGES),
        "gold_free_execution_root": execution_root.as_posix(),
        "gold_free_execution_root_verified": True,
        "classification_failures": failures,
        "terminal_classification": classification,
    }
    # Bind the sealed prediction manifest SHA-256 into the receipt so the
    # metric-release authorization can authenticate it. Only present when the
    # sealed stages ran far enough to emit the manifest.
    if sealed_prediction_manifest_sha256 is not None:
        receipt["sealed_prediction_manifest_sha256"] = sealed_prediction_manifest_sha256
    write_canonical_json(artifact_root / "controller_receipt.json", receipt)
    print(classification)
    if classification != "SEALED_EXECUTION_PASSED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
