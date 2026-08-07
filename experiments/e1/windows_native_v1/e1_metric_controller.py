#!/usr/bin/env python3
"""Metric-release controller for the Windows-native E1 release.

This controller releases the protected E1 metrics AFTER the sealed execution
and sealed prediction manifests are published. It is the ONLY component that
may compute the classification contract (TECHNICALLY_INVALID / HARMFUL /
PROMISING / NO_OBSERVED_SIGNAL), and it does so by joining the sealed
predictions to the authenticated v6 gold labels.

Authorization separation: this controller accepts ONLY the metric-release
authorization
(``metric_release_authorized=true, gpu_execution_authorized=false``) and
rejects the GPU execution authorization. The execution controller rejects the
metric-release authorization symmetrically, so no single authorization file
can drive both domains.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from csd_foundry.empirical.e0h.windows_native import (
    canonical_json_text,
    write_canonical_json,
)
from csd_foundry.empirical.e1.response_abi_metrics import (
    PRIMARY_METRIC_IDENTITY,
    SAFETY_METRIC_IDENTITY,
    score_clean_case_regression,
    score_family_macro_accuracy,
)

RELEASE = "e1-windows-native-v1"

# The five prediction-set identities and the three that drive the terminal
# classification (BASE, CONTROL-final, FOUNDRY-final). The two intermediate
# checkpoint-4 sets are diagnostic only and never enter the classification.
ALL_PREDICTION_SETS = (
    "BASE",
    "CONTROL-checkpoint-4",
    "CONTROL-final",
    "FOUNDRY-checkpoint-4",
    "FOUNDRY-final",
)
CLASSIFICATION_SET_TO_ARM = {
    "BASE": "BASE",
    "CONTROL-final": "CONTROL",
    "FOUNDRY-final": "FOUNDRY",
}
SEALED_CASE_COUNT_PER_SET = 8
REQUIRED_PREDICTION_RECORD_COUNT = len(ALL_PREDICTION_SETS) * SEALED_CASE_COUNT_PER_SET

# Dev/clean evaluation file digests bound to the A2 receipt constituent
# digests (the binding authority). These are authenticated at metric release.
V6_DEVELOPMENT_EVALUATION_DIGEST = (
    "eb6d1cb5b3596e3a673536b9865be118fe6afc47c79e93f6ea92cd5cf9e31036"
)
V6_CLEAN_EVALUATION_DIGEST = "178e7a6f80c6ed8caf4ab823211d4896345ec7f9b49eebfe53415b6d019d2ee2"


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


def _require_metric_authorization(
    path: Path,
    repo_root: Path,
    *,
    sealed_execution_receipt_sha256: str,
    sealed_prediction_manifest_sha256: str,
) -> dict[str, object]:
    """Authenticate the metric-release authorization file.

    The metric-release authorization domain binds the release identity, the
    checked-out commit, and the two sealed upstream digests the metric
    controller will consume. It must deny GPU execution.
    """

    value = _load_canonical(path)
    expected_fields = {
        "metric_release_authorized",
        "release",
        "source_commit",
        "sealed_execution_receipt_sha256",
        "sealed_prediction_manifest_sha256",
    }
    if set(value) != expected_fields:
        raise ValueError("metric-release authorization file has unexpected fields")
    if value["metric_release_authorized"] is not True:
        raise ValueError("metric release is not authorized")
    # The expected field set excludes ``gpu_execution_authorized``: a metric-
    # release authorization must not carry it (the field-set check above rejects
    # any file that does), so the two authorization domains cannot be confused.
    if value["release"] != RELEASE:
        raise ValueError("metric-release authorization release does not match")
    observed_commit = _current_commit(repo_root)
    if value["source_commit"] != observed_commit:
        raise ValueError(
            f"metric-release source commit {value['source_commit']} != "
            f"checked-out {observed_commit}"
        )
    if value["sealed_execution_receipt_sha256"] != sealed_execution_receipt_sha256:
        raise ValueError("sealed execution receipt digest binding mismatch")
    if value["sealed_prediction_manifest_sha256"] != sealed_prediction_manifest_sha256:
        raise ValueError("sealed prediction manifest digest binding mismatch")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path} contains a non-object record")
        records.append(value)
    return records


def _authenticate_a2_receipt(repo_root: Path) -> dict[str, Any]:
    """Authenticate the A2 receipt and return its constituent digest map.

    The receipt binds the dev/clean evaluation digests (the gold labels the
    metric controller joins predictions against) and the records/tokens/
    truncation pins. The receipt bytes are authenticated by recomputing the
    constituent dev/clean evaluation digests against the on-disk gold files.
    """

    v6_dir = repo_root / "data" / "e1" / "v6"
    receipt = json.loads((v6_dir / "a2_receipt.json").read_text(encoding="utf-8"))
    if not isinstance(receipt, dict):
        raise ValueError("v6 a2_receipt must be an object")
    constituent = receipt.get("constituent_artifact_digests")
    if not isinstance(constituent, dict):
        raise ValueError("v6 a2_receipt constituent_artifact_digests must be an object")
    if str(constituent.get("development_evaluation.jsonl", "")) != (
        V6_DEVELOPMENT_EVALUATION_DIGEST
    ):
        raise ValueError("A2 receipt development_evaluation digest disagrees with pinned constant")
    if str(constituent.get("clean_evaluation.jsonl", "")) != V6_CLEAN_EVALUATION_DIGEST:
        raise ValueError("A2 receipt clean_evaluation digest disagrees with pinned constant")
    return receipt


def _authenticate_gold_bytes(
    repo_root: Path,
    *,
    dev_path: Path,
    clean_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load the gold evaluation bytes and verify their SHA-256 against A2.

    Returns ``(dev_cases, clean_cases)`` after authenticating both files
    against the pinned (A2-bound) digests.
    """

    for path, expected in (
        (dev_path, V6_DEVELOPMENT_EVALUATION_DIGEST),
        (clean_path, V6_CLEAN_EVALUATION_DIGEST),
    ):
        if not path.is_file():
            raise ValueError(f"gold evaluation file missing: {path}")
        observed = _file_sha256(path)
        if observed != expected:
            raise ValueError(
                f"gold evaluation digest mismatch for {path}: "
                f"expected {expected}, observed {observed}"
            )
    dev_cases = _load_jsonl(dev_path)
    clean_cases = _load_jsonl(clean_path)
    if len(dev_cases) != 4:
        raise ValueError(f"expected 4 development gold cases, observed {len(dev_cases)}")
    if len(clean_cases) != 4:
        raise ValueError(f"expected 4 clean gold cases, observed {len(clean_cases)}")
    return dev_cases, clean_cases


def _classify_run(
    *,
    sealed_execution_passed: bool,
    primary_accuracies: Mapping[str, float],
    safety_counts: Mapping[str, Mapping[str, int]],
) -> tuple[str, dict[str, object]]:
    """Apply the frozen E1 classification contract.

    Returns ``(terminal_class, evidence)``. The evidence dict carries the
    primary accuracies (P_base, P_control, P_foundry) and the safety
    nonregression derivation so the metric receipt is auditable.

    Malformed model output is treated as incorrect (counted by the frozen
    safety metric), never as a TECHNICALLY_INVALID classification trigger; the
    only TECHNICALLY_INVALID path is a failed sealed execution.
    """

    evidence: dict[str, object] = {
        "primary_accuracies": dict(primary_accuracies),
        "safety_counts": {arm: dict(counts) for arm, counts in safety_counts.items()},
        "sealed_execution_passed": sealed_execution_passed,
    }

    if not sealed_execution_passed:
        return "TECHNICALLY_INVALID", evidence

    # Safety nonregression: for every safety count, Foundry <= Base AND
    # Foundry <= Control.
    base = safety_counts.get("BASE", {})
    control = safety_counts.get("CONTROL", {})
    foundry = safety_counts.get("FOUNDRY", {})
    safety_nonregression = True
    for key in sorted(set(base) | set(control) | set(foundry)):
        f = int(foundry.get(key, 0))
        if f > int(base.get(key, 0)) or f > int(control.get(key, 0)):
            safety_nonregression = False
            break
    evidence["safety_nonregression"] = safety_nonregression

    p_base = float(primary_accuracies.get("BASE", 0.0))
    p_control = float(primary_accuracies.get("CONTROL", 0.0))
    p_foundry = float(primary_accuracies.get("FOUNDRY", 0.0))

    if not safety_nonregression or p_foundry < p_control:
        return "HARMFUL", evidence
    if safety_nonregression and p_foundry > p_control and p_foundry > p_base:
        return "PROMISING", evidence
    return "NO_OBSERVED_SIGNAL", evidence


def _validate_prediction_records(
    prediction_records: list[dict[str, Any]],
    gold_keys: set[tuple[str, str, str]],
) -> dict[str, dict[str, str]]:
    """Validate the raw prediction records and group them by prediction set.

    Requires exactly ``REQUIRED_PREDICTION_RECORD_COUNT`` records (5 sets x 8
    cases). Each record must carry the frozen unforgiving ABI evidence fields
    (``prediction_set_name``, ``exact_decoded_suffix``, ``generated_token_id``,
    sealed-record identity fields). Predictions are matched to gold by
    ``(cohort, scenario_id, record_id)``; missing, extra, and duplicate cases
    are rejected.

    Returns a mapping ``prediction_set_name -> {case_key: raw_suffix}`` for the
    frozen A0b2 parser.
    """

    required_fields = {
        "prediction_set_name",
        "evaluation_id",
        "cohort",
        "scenario_id",
        "record_id",
        "family_digest",
        "prompt_sha256",
        "generated_token_id",
        "exact_decoded_suffix",
        "checkpoint_or_model_identity",
    }
    grouped: dict[str, dict[tuple[str, str, str], str]] = {name: {} for name in ALL_PREDICTION_SETS}
    for pred in prediction_records:
        missing = required_fields - set(pred)
        if missing:
            raise ValueError(f"prediction record missing fields: {sorted(missing)}")
        set_name = str(pred["prediction_set_name"])
        if set_name not in grouped:
            raise ValueError(f"prediction carries unknown prediction set: {set_name}")
        key = (
            str(pred["cohort"]),
            str(pred["scenario_id"]),
            str(pred["record_id"]),
        )
        if key not in gold_keys:
            raise ValueError(f"prediction {key} has no gold counterpart")
        if key in grouped[set_name]:
            raise ValueError(f"duplicate prediction for {set_name} {key}")
        grouped[set_name][key] = str(pred["exact_decoded_suffix"])

    # Exactly 5 sets x 8 cases; reject missing, extra, or incomplete sets.
    observed_count = sum(len(items) for items in grouped.values())
    if observed_count != REQUIRED_PREDICTION_RECORD_COUNT:
        raise ValueError(
            f"expected {REQUIRED_PREDICTION_RECORD_COUNT} prediction records "
            f"(5 sets x 8 cases), observed {observed_count}"
        )
    for set_name in ALL_PREDICTION_SETS:
        if len(grouped[set_name]) != SEALED_CASE_COUNT_PER_SET:
            raise ValueError(
                f"prediction set {set_name} must carry {SEALED_CASE_COUNT_PER_SET} "
                f"cases, observed {len(grouped[set_name])}"
            )
    # Return case_id-keyed raw suffixes (the A0b2 parser consumes case_id).
    # Re-key each prediction set from (cohort, scenario_id, record_id) to the
    # canonical case_id used by the gold records.
    raw_by_set: dict[str, dict[str, str]] = {}
    for set_name, mapping in grouped.items():
        raw_by_set[set_name] = {
            f"e1-evaluation/{cohort}/{scenario_id}/{record_id}": suffix
            for (cohort, scenario_id, record_id), suffix in mapping.items()
        }
    return raw_by_set


def _evaluate_predictions(
    *,
    prediction_records: list[dict[str, Any]],
    dev_cases: list[dict[str, Any]],
    clean_cases: list[dict[str, Any]],
) -> tuple[dict[str, float], dict[str, dict[str, int]]]:
    """Join sealed predictions to authenticated gold and derive metrics.

    The classification prediction sets are BASE, CONTROL-final, FOUNDRY-final.
    Raw prediction suffixes are parsed by the authenticated A0b2 strict parser
    (``parse_response``) inside the frozen metric implementations
    (``score_family_macro_accuracy`` and ``score_clean_case_regression``);
    pre-parsed classes are never trusted.

    Returns ``(primary_accuracies, safety_counts)``. ``primary_accuracies`` is
    the family-macro exact-semantic-decision accuracy for each classification
    arm over the development transition cases. ``safety_counts`` aggregates the
    clean-case safety count fields per arm. Malformed output is counted as
    incorrect (it stays in the denominator); it never triggers a
    TECHNICALLY_INVALID classification.
    """

    gold_keys = {
        (str(case["cohort"]), str(case["scenario_id"]), str(case["record_id"]))
        for case in dev_cases + clean_cases
    }
    raw_by_set = _validate_prediction_records(prediction_records, gold_keys)

    # The frozen A0b2 scoring functions consume tuples of evaluation-case
    # dicts (case_id, family_digest, gold_class, case_kind, cohort) and a
    # mapping case_id -> raw model output. We re-derive each arm's primary
    # family-macro accuracy over the development cases and each arm's clean-
    # case regression counts over the clean cases, using the FROZEN parser and
    # metric implementations (no local codebook). The primary family-macro
    # metric expects exactly four development families, so it receives only the
    # development cases (the frozen scorer filters by case_kind=="transition"
    # and would over-count if clean cases were included).
    dev_cases_tuple = tuple(dev_cases)
    clean_cases_tuple = tuple(dev_cases + clean_cases)

    primary_accuracies: dict[str, float] = {}
    safety_counts: dict[str, dict[str, int]] = {}
    for set_name, arm in CLASSIFICATION_SET_TO_ARM.items():
        family_result = score_family_macro_accuracy(dev_cases_tuple, raw_by_set[set_name])
        primary_accuracies[arm] = (
            family_result.family_macro_accuracy_numerator
            / family_result.family_macro_accuracy_denominator
            if family_result.family_macro_accuracy_denominator
            else 0.0
        )
        clean_result = score_clean_case_regression(clean_cases_tuple, raw_by_set[set_name])
        safety_counts[arm] = {
            "clean_exact_error_count": clean_result.clean_exact_error_count,
            "clean_malformed_count": clean_result.clean_malformed_count,
            "clean_not_applicable_count": clean_result.clean_not_applicable_count,
            "spurious_basis_removal_count": clean_result.spurious_basis_removal_count,
            "valid_basis_rejection_count": clean_result.valid_basis_rejection_count,
        }
    return primary_accuracies, safety_counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--metric-release-authorization", type=Path, required=True)
    parser.add_argument("--sealed-execution-receipt", type=Path, required=True)
    parser.add_argument("--sealed-prediction-manifest", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--gold-development",
        type=Path,
        default=Path("data/e1/v6/development_evaluation.jsonl"),
    )
    parser.add_argument(
        "--gold-clean",
        type=Path,
        default=Path("data/e1/v6/clean_evaluation.jsonl"),
    )
    args = parser.parse_args()

    inputs = _load_canonical(args.inputs)
    if inputs.get("release") != RELEASE:
        raise ValueError("run input release does not match the E1 metric controller")

    repo_root = Path(__file__).resolve().parents[3]

    # 1. Authenticate the A2 receipt and its constituent evaluation digests,
    #    then authenticate the gold bytes the controller will join predictions
    #    against.
    a2_receipt = _authenticate_a2_receipt(repo_root)
    dev_cases, clean_cases = _authenticate_gold_bytes(
        repo_root, dev_path=args.gold_development, clean_path=args.gold_clean
    )

    sealed_execution_receipt_sha256 = _file_sha256(args.sealed_execution_receipt)
    sealed_prediction_manifest_sha256 = _file_sha256(args.sealed_prediction_manifest)
    authorization = _require_metric_authorization(
        args.metric_release_authorization,
        repo_root,
        sealed_execution_receipt_sha256=sealed_execution_receipt_sha256,
        sealed_prediction_manifest_sha256=sealed_prediction_manifest_sha256,
    )

    execution_receipt = _load_canonical(args.sealed_execution_receipt)
    sealed_execution_passed = (
        execution_receipt.get("terminal_classification") == "SEALED_EXECUTION_PASSED"
    )

    prediction_manifest = _load_canonical(args.sealed_prediction_manifest)
    prediction_records: list[dict[str, Any]] = []
    raw_predictions = prediction_manifest.get("predictions")
    if not isinstance(raw_predictions, list):
        raise ValueError("sealed prediction manifest must carry a predictions array")
    for item in raw_predictions:
        if not isinstance(item, dict):
            raise ValueError("sealed prediction manifest entry must be an object")
        prediction_records.append(item)

    primary_accuracies, safety_counts = _evaluate_predictions(
        prediction_records=prediction_records,
        dev_cases=dev_cases,
        clean_cases=clean_cases,
    )
    terminal_class, evidence = _classify_run(
        sealed_execution_passed=sealed_execution_passed,
        primary_accuracies=primary_accuracies,
        safety_counts=safety_counts,
    )

    artifact_root = args.artifact_root.resolve()
    if artifact_root.exists():
        raise FileExistsError(f"artifact root already exists: {artifact_root}")
    artifact_root.mkdir(parents=True)
    write_canonical_json(
        artifact_root / "metric_release_receipt.json",
        {
            "schema_version": "e1-windows-native-metric-release-receipt/1",
            "release": RELEASE,
            "authorization_domain": "metric_release",
            "authorization": authorization,
            "sealed_execution_receipt_sha256": sealed_execution_receipt_sha256,
            "sealed_prediction_manifest_sha256": sealed_prediction_manifest_sha256,
            "a2_receipt_authenticated": True,
            "a2_constituent_digests": dict(
                sorted(a2_receipt.get("constituent_artifact_digests", {}).items())
            ),
            "gold_development_sha256": V6_DEVELOPMENT_EVALUATION_DIGEST,
            "gold_clean_sha256": V6_CLEAN_EVALUATION_DIGEST,
            "prediction_record_count": len(prediction_records),
            "primary_metric_identity": PRIMARY_METRIC_IDENTITY,
            "safety_metric_identity": SAFETY_METRIC_IDENTITY,
            "terminal_classification": terminal_class,
            "evidence": evidence,
            "claim_boundary": (
                "Metric release joins sealed predictions to authenticated v6 gold "
                "labels and applies the frozen classification contract. It does not "
                "execute a model, allocate a GPU, or establish general transfer."
            ),
        },
    )
    print(terminal_class)


if __name__ == "__main__":
    main()
