"""Build the E3 durable execution receipt.

Reads the frozen `_run/e3_results.json` and `e3_contract.json` and writes the
durable execution receipt as a single canonical JSON line. No scientific number
is recomputed; every field is copied verbatim from the frozen artifacts.

Provenance model (two-identity): see build_e2_receipt.py for the full category
description. The historical execution bytes (Windows worktree, CRLF) are not the
committed bytes (LF-normalized; some Python additionally ruff-formatted). Each
promoted file carries a per-file provenance block. Category A files assert
SHA256(LF->CRLF reconstruction) == frozen contract/manifest digest at build time
(fail closed). Category D pre-format digests are STATIC VALUES.

Re-running this script against the same committed bytes reproduces the receipt
byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
E3_ROOT = REPO_ROOT / "experiments" / "e3"
RESULTS_PATH = E3_ROOT / "_run" / "e3_results.json"
CONTRACT_PATH = E3_ROOT / "e3_contract.json"
MANIFEST_PATH = E3_ROOT / "e3_manifest.json"
RECEIPT_OUT = Path(__file__).resolve().parent / "execution_receipt.json"

EXECUTION_REPOSITORY_BASE_COMMIT = "ca129c43fb2d0c81f14f8b387bd0b1eb01d1dabd"

# Category A — frozen contract/manifest digests (historical CRLF execution
# identity). E3 has three such files.
CATEGORY_A = {
    "experiments/e3/protected_primary.jsonl": ("e3_contract", "primary_evaluation_sha256"),
    "experiments/e3/protected_clean.jsonl": ("e3_contract", "clean_evaluation_sha256"),
    "experiments/e3/clean_anchors.jsonl": ("e3_contract", "anchor_sha256"),
}
# Category B — zero transforming newlines; LF blob IS execution bytes.
# E3 has no single-line-JSON outputs (only e3_results.json, multi-line).
CATEGORY_B: list[str] = []
# Category C — multi-line, no frozen digest; only LF-normalized content survives.
CATEGORY_C = [
    "experiments/e3/e3_contract.json",
    "experiments/e3/e3_manifest.json",
    "experiments/e3/_run/e3_results.json",
]
# Category D — Python source; pre-format LF content digests as static values.
PRE_FORMAT_LF_DIGESTS = {
    "experiments/e3/build_e3_data.py": (
        "dd31410b4b99fa7799f6873170b330f0627d9e8ea47e04795051475922526927",
        True,
    ),  # CRLF->LF + ruff format/lint
    "experiments/e3/run_e3_experiment.py": (
        "ea49214df46fe2dd4c24d1b1882c26c18b4eb16fc85a3a939dbcefa1d0eb1ba7",
        True,
    ),  # CRLF->LF + ruff format/lint
}

PROMOTED_FILES = (
    [f for f in CATEGORY_A] + CATEGORY_B + CATEGORY_C + [f for f in PRE_FORMAT_LF_DIGESTS]
)


def _git_blob(path: str, ref: str = "HEAD") -> bytes:
    return subprocess.run(
        ["git", "cat-file", "blob", f"{ref}:{path}"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout


def _build_provenance(contract: dict, manifest: dict) -> dict[str, dict]:
    sources = {"e3_contract": contract, "e3_manifest": manifest}
    prov: dict[str, dict] = {}

    # Category A
    for path, (src, field) in CATEGORY_A.items():
        lf = _git_blob(path)
        assert b"\r" not in lf, f"{path}: LF blob contains CR — reconstruction ambiguous"
        crlf_reconstructed = lf.replace(b"\n", b"\r\n")
        crlf_sha = hashlib.sha256(crlf_reconstructed).hexdigest()
        historical_sha = sources[src][field]
        assert crlf_sha == historical_sha, (
            f"{path}: CRLF reconstruction {crlf_sha} != {src}.{field} "
            f"{historical_sha} — FAIL CLOSED"
        )
        prov[path] = {
            "category": "A",
            "category_description": "frozen historical digest; normalized repository copy",
            "historical_execution_sha256": historical_sha,
            "historical_execution_identity_preserved": True,
            "historical_identity_source": f"{src}.{field}",
            "exact_execution_bytes_preserved": False,
            "historical_bytes_reconstructable": True,
            "reconstruction": "SHA256(LF blob with LF->CRLF) == frozen digest",
            "durable_repository_sha256": hashlib.sha256(lf).hexdigest(),
            "transformation": ["line-ending normalization (CRLF->LF)"],
        }

    # Category B
    for path in CATEGORY_B:
        b = _git_blob(path)
        sha = hashlib.sha256(b).hexdigest()
        assert b.count(b"\n") == 0, f"{path}: expected zero newlines for Category B"
        prov[path] = {
            "category": "B",
            "category_description": "unchanged artifact; no transforming line endings",
            "historical_execution_sha256": sha,
            "historical_execution_identity_preserved": True,
            "exact_execution_bytes_preserved": True,
            "durable_repository_sha256": sha,
            "transformation": ["none"],
        }

    # Category C
    for path in CATEGORY_C:
        lf = _git_blob(path)
        prov[path] = {
            "category": "C",
            "category_description": "normalized output without prior digest",
            "historical_execution_sha256": None,
            "historical_execution_identity_preserved": False,
            "exact_execution_bytes_preserved": False,
            "durable_repository_sha256": hashlib.sha256(lf).hexdigest(),
            "transformation": ["line-ending normalization (CRLF->LF)"],
            "semantic_content_preserved_modulo_line_endings": True,
        }

    # Category D
    for path, (pre_format_sha, ruff_reformatted) in PRE_FORMAT_LF_DIGESTS.items():
        lf = _git_blob(path)
        transformation = ["line-ending normalization (CRLF->LF)"]
        if ruff_reformatted:
            transformation.append("ruff format/lint normalization")
        prov[path] = {
            "category": "D",
            "category_description": "normalized/formatted source",
            "historical_execution_sha256": None,
            "historical_execution_identity_preserved": False,
            "exact_execution_bytes_preserved": False,
            "pre_format_content_sha256": pre_format_sha,
            "pre_format_note": (
                "SHA-256 of the pre-promotion LF-normalized content (captured "
                "once as a static value; this builder does not depend on the "
                "pre-promotion commit at rebuild time)."
            ),
            "durable_repository_sha256": hashlib.sha256(lf).hexdigest(),
            "transformation": transformation,
            "promoted_source_relation": (
                "post-hoc normalized repository copy; not the historical execution identity"
            ),
            "scientific_outputs_modified_during_promotion": False,
        }

    return prov


def main() -> None:
    results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    results_blob_sha = hashlib.sha256(_git_blob("experiments/e3/_run/e3_results.json")).hexdigest()

    arms = results["arms"]
    arm_ids = ["BASE", "CONTROL", "FOUNDRY"]
    counts = [
        "clean_exact_error_count",
        "spurious_basis_removal_count",
        "valid_basis_rejection_count",
        "clean_not_applicable_count",
        "clean_malformed_count",
    ]

    safety_table = {c: {a.lower(): int(arms[a]["safety"][c]) for a in arm_ids} for c in counts}

    p_base = float(arms["BASE"]["primary"]["family_macro_accuracy"])
    p_control = float(arms["CONTROL"]["primary"]["family_macro_accuracy"])
    p_foundry = float(arms["FOUNDRY"]["primary"]["family_macro_accuracy"])

    reasoning = results["classification_reasoning"]
    safety_nonregression_holds = bool(results["safety_nonregression_holds"])

    per_count_nonregression = {
        c: {
            "base": reasoning["safety_counts"][c]["base"],
            "control": reasoning["safety_counts"][c]["control"],
            "foundry": reasoning["safety_counts"][c]["foundry"],
            "foundry_le_base": reasoning["safety_counts"][c]["foundry_le_base"],
            "foundry_le_control": reasoning["safety_counts"][c]["foundry_le_control"],
            "passes": reasoning["safety_counts"][c]["passes"],
        }
        for c in counts
    }

    provenance = _build_provenance(contract, manifest)

    receipt = {
        "anchor_identity_constraint": contract["anchor_identity_constraint"],
        "attempt_id": "e3-safety-anchored",
        "claim_boundary": contract["claim_boundary"],
        "classification_logic": {
            "contract_rule": (
                "PROMISING requires safety passes AND P_foundry > P_control AND "
                "P_foundry > P_base; HARMFUL if safety fails OR P_foundry < "
                "P_control; NO_OBSERVED_SIGNAL otherwise valid; TECHNICALLY_INVALID "
                "on execution/measurement failure (contract "
                "classification_truth_table)."
            ),
            "safety_formulation": (
                "Relative five-count non-regression: safety holds when, for ALL "
                "5 counts, Foundry <= Base AND Foundry <= Control "
                "(contract safety_metric.nonregression_definition)."
            ),
            "as_executed_rule": (
                "run_e3_experiment.py _classify implements exactly the relative "
                "rule via _safety_nonregression. No divergence between contract "
                "and code."
            ),
            "implementation_divergence": False,
            "safety_nonregression_passes": bool(reasoning["safety_nonregression_passes"]),
            "safety_per_count": per_count_nonregression,
            "primary": {"p_base": p_base, "p_control": p_control, "p_foundry": p_foundry},
            "harmful_trigger_safety": bool(not reasoning["safety_nonregression_passes"]),
            "harmful_trigger_primary": bool(p_foundry < p_control),
            "terminal": "HARMFUL",
            "terminal_trigger": (
                f"primary accuracy only: P_foundry ({p_foundry}) < P_control "
                f"({p_control}). Safety non-regression PASSED (Foundry 0 clean "
                "errors; <= Base 10 and <= Control 0 on all 5 counts), so the "
                "HARMFUL classification is not attributable to a safety failure."
            ),
        },
        "durable_evidence": {
            "publication_channel": "git_repository",
            "note": (
                "Small non-weight execution evidence (source, inputs, outputs) is "
                "tracked in this repository under experiments/e3/. Per-file "
                "provenance distinguishes the historical execution identity from "
                "the durable repository identity (see provenance_model and "
                "per_file_provenance). No GitHub Release publication is required."
            ),
            "paths": PROMOTED_FILES,
            "per_file_provenance": provenance,
        },
        "execution_id": "E3",
        "execution_provenance": {
            "execution_repository_base_commit": EXECUTION_REPOSITORY_BASE_COMMIT,
            "execution_source_status": "uncommitted_worktree",
            "note": (
                "E3 executed from an uncommitted worktree based on "
                f"{EXECUTION_REPOSITORY_BASE_COMMIT} (Record E1 execution result, "
                "PR #98). The experiment-defining files were promoted to durable "
                "git evidence in a subsequent commit on this branch; that "
                "promotion does not retroactively make its merge commit the "
                "source commit of the historical GPU execution."
            ),
        },
        "frozen_identities": {
            "anchor_path": contract["anchor_path"],
            "anchor_record_count": contract["anchor_record_count"],
            "anchor_sha256": contract["anchor_sha256"],
            "context_length": contract["context_length"],
            "control_train_sha256": contract["control_train_sha256"],
            "control_v6_record_count": contract["control_v6_record_count"],
            "foundry_train_sha256": contract["foundry_train_sha256"],
            "foundry_v6_record_count": contract["foundry_v6_record_count"],
            "learning_rate": contract["training_recipe"]["learning_rate"],
            "loss": contract["training_recipe"]["loss"],
            "max_steps": contract["training_recipe"]["steps"],
            "model_id": contract["model_id"],
            "model_revision": contract["model_revision"],
            "per_arm_train_record_count": contract["per_arm_train_record_count"],
            "seed": contract["training_recipe"]["seed"],
        },
        "g1_status": "NOT_PASSED",
        "metric_evidence": {
            "P_base": p_base,
            "P_control": p_control,
            "P_foundry": p_foundry,
            "primary_metric": contract["primary_metric"]["identity"],
            "results_json_repository_sha256": results_blob_sha,
            "safety_metric": contract["safety_metric"]["identity"],
            "safety_nonregression_holds": safety_nonregression_holds,
            "safety_table": safety_table,
        },
        "primary_interpretation": (
            "Both trained arms (CONTROL, FOUNDRY) acquired the response task and, "
            "with the 10 shared clean anchors, passed the safety metric (0 clean "
            "errors each, vs BASE's 10/10 failure). The E2 shared safety "
            "regression was repaired. Under equal safety anchoring, the E2 "
            f"Foundry primary differential did not survive: P_foundry={p_foundry} "
            f"< P_control={p_control}. The HARMFUL classification is triggered by "
            "the primary-accuracy comparison alone; safety non-regression holds."
        ),
        "provenance_model": {
            "summary": (
                "Two-identity model. The historical execution bytes (Windows "
                "worktree, CRLF line endings) are not the bytes now committed "
                "(LF-normalized via .gitattributes; some Python source "
                "additionally ruff-formatted during promotion). Each promoted "
                "file records its category (A/B/C/D), the historical execution "
                "identity where recoverable, and the durable repository identity."
            ),
            "categories": {
                "A": "frozen historical digest (contract/manifest); normalized repository copy",
                "B": "unchanged artifact; no transforming line endings; LF blob IS execution bytes",
                "C": "normalized output without prior digest; exact bytes not preserved",
                "D": "normalized/formatted source; pre-format LF content digest as static value",
            },
            "build_time_assertions": (
                "Category A: SHA256(LF->CRLF reconstruction) MUST equal the frozen "
                "contract/manifest digest (fail closed otherwise). Category B: the "
                "committed blob MUST contain zero transforming newlines."
            ),
        },
        "release": contract["release"],
        "resource_consumption": {
            "e3_gpu_ceiling_minutes": contract["gpu_minute_ceiling"],
            "e3_gpu_seconds": results["gpu_elapsed_seconds"],
            "e3_gpu_seconds_floor": int(results["gpu_elapsed_seconds"]),
        },
        "safety_interpretation": (
            "Safety non-regression HOLDS: for all 5 counts, Foundry <= Base AND "
            "Foundry <= Control. Both trained arms produced 0 clean exact errors "
            "and 0 malformed outputs on the 10 clean cases (5 NEITHER + 5 "
            "SURVIVES_ONLY anchors). BASE produced 10/10 clean exact errors and "
            "10/10 malformed outputs (unanchored comparator). The E2 safety "
            "regression (Foundry=Control=10 clean errors) is eliminated."
        ),
        "schema_version": "e3-execution-result/1",
        "terminal_classification": results["classification"],
    }

    RECEIPT_OUT.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    reloaded = json.loads(RECEIPT_OUT.read_text(encoding="utf-8"))
    assert reloaded == receipt, "receipt round-trip mismatch"
    print(f"wrote {RECEIPT_OUT}")
    print(f"terminal_classification={receipt['terminal_classification']}")
    print(
        f"implementation_divergence={receipt['classification_logic']['implementation_divergence']}"
    )
    print(
        f"safety_nonregression_passes={receipt['classification_logic']['safety_nonregression_passes']}"
    )
    print(f"per_file_provenance entries: {len(provenance)}")


if __name__ == "__main__":
    main()
