"""Build the E2 durable execution receipt.

Reads the frozen `_run/e2_results.json` and `e2_contract.json` and writes the
durable execution receipt as a single canonical JSON line. No scientific number
is recomputed; every field is copied verbatim from the frozen artifacts.

Provenance model (two-identity):
  The historical execution bytes (Windows worktree, CRLF line endings) are NOT
  the bytes now committed (LF-normalized via .gitattributes; some Python source
  additionally ruff-formatted/lint-fixed during promotion). Each promoted file
  carries a per-file provenance block distinguishing:

    historical_execution_sha256        the digest of the bytes used at execution
                                       (null when unrecoverable)
    historical_execution_identity_preserved
                                       whether that digest is durably known
    exact_execution_bytes_preserved    whether the literal bytes survive
    durable_repository_sha256          the digest of the committed LF blob

  Categories:
    A — frozen historical digest (contract/manifest) == SHA256(CRLF
        reconstruction of the LF blob); fail-closed assertion at build time.
    B — zero transforming newlines; LF blob IS the execution bytes.
    C — multi-line output with no recorded digest; exact bytes not preserved.
    D — Python source; pre-format LF content digest captured as a static value
        (from the pre-promotion commit); ruff format/lint may also apply.

  The pre-format digests for Category D are STATIC VALUES captured once from the
  pre-promotion commit and embedded here as literals. This builder must NOT
  depend on any dangling/reflog commit at rebuild time.

Re-running this script against the same committed bytes reproduces the receipt
byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
E2_ROOT = REPO_ROOT / "experiments" / "e2"
RESULTS_PATH = E2_ROOT / "_run" / "e2_results.json"
CONTRACT_PATH = E2_ROOT / "e2_contract.json"
RECEIPT_OUT = Path(__file__).resolve().parent / "execution_receipt.json"

EXECUTION_REPOSITORY_BASE_COMMIT = "ca129c43fb2d0c81f14f8b387bd0b1eb01d1dabd"

# Frozen contract digests for Category A files (historical CRLF execution
# identity). These are read from the contract at build time and asserted to
# equal SHA256(CRLF reconstruction of the committed LF blob).
CATEGORY_A = {
    "experiments/e2/protected_primary.jsonl": "primary_evaluation_sha256",
    "experiments/e2/protected_clean.jsonl": "clean_evaluation_sha256",
}
# Category B files: zero transforming newlines, so the committed LF blob IS the
# execution bytes. Verified at build time (newline count must be 0).
CATEGORY_B = [
    "experiments/e2/_run/predictions-base.json",
    "experiments/e2/_run/predictions-control.json",
    "experiments/e2/_run/predictions-foundry.json",
]
# Category C files: multi-line, CRLF at execution, no frozen digest; only the
# LF-normalized semantic content survives.
CATEGORY_C = [
    "experiments/e2/e2_contract.json",
    "experiments/e2/protected_manifest.json",
    "experiments/e2/_run/e2_results.json",
    "experiments/e2/_run/cases-base.jsonl",
    "experiments/e2/_run/cases-control.jsonl",
    "experiments/e2/_run/cases-foundry.jsonl",
]
# Category D files: Python source. Pre-format LF-normalized content digests are
# STATIC VALUES (captured once from the pre-promotion commit; this builder does
# not depend on that commit at rebuild time). Transformation is CRLF->LF for
# all; files additionally reformatted via ruff are marked.
PRE_FORMAT_LF_DIGESTS = {
    "experiments/e2/build_protected_evaluation.py": (
        "78b2608efd005f9dbe2eb2b02fecbc9d0f1fc20cc9c1b467d04788cd0933961c",
        False,
    ),  # CRLF->LF only (not ruff-formatted)
    "experiments/e2/run_e2_experiment.py": (
        "70f66987755bc103f23cdf7b3c3c9ca382a22767a1b77a0751c126398741c6b2",
        False,
    ),  # CRLF->LF only
    "experiments/e2/_run/_arm_worker.py": (
        "ed71ee66a662893b71047e2687db1dd67c3a66a8b1eb5df86b971bc9b3545163",
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


def _build_provenance(contract: dict) -> dict[str, dict]:
    """Build per-file provenance blocks with fail-closed assertions."""

    prov: dict[str, dict] = {}

    # Category A — frozen historical digest; reconstruct CRLF and assert match.
    for path, contract_field in CATEGORY_A.items():
        lf = _git_blob(path)
        assert b"\r" not in lf, f"{path}: LF blob contains CR — reconstruction ambiguous"
        crlf_reconstructed = lf.replace(b"\n", b"\r\n")
        crlf_sha = hashlib.sha256(crlf_reconstructed).hexdigest()
        contract_sha = contract[contract_field]
        assert crlf_sha == contract_sha, (
            f"{path}: CRLF reconstruction {crlf_sha} != contract "
            f"{contract_field} {contract_sha} — FAIL CLOSED"
        )
        prov[path] = {
            "category": "A",
            "category_description": "frozen historical digest; normalized repository copy",
            "historical_execution_sha256": contract_sha,
            "historical_execution_identity_preserved": True,
            "historical_identity_source": f"e2_contract.{contract_field}",
            "exact_execution_bytes_preserved": False,
            "historical_bytes_reconstructable": True,
            "reconstruction": "SHA256(LF blob with LF->CRLF) == contract digest",
            "durable_repository_sha256": hashlib.sha256(lf).hexdigest(),
            "transformation": ["line-ending normalization (CRLF->LF)"],
        }

    # Category B — zero transforming newlines; committed blob IS execution bytes.
    for path in CATEGORY_B:
        b = _git_blob(path)
        sha = hashlib.sha256(b).hexdigest()
        newline_count = b.count(b"\n")
        assert newline_count == 0, (
            f"{path}: expected zero newlines for Category B, got {newline_count}"
        )
        prov[path] = {
            "category": "B",
            "category_description": "unchanged artifact; no transforming line endings",
            "historical_execution_sha256": sha,
            "historical_execution_identity_preserved": True,
            "exact_execution_bytes_preserved": True,
            "durable_repository_sha256": sha,
            "transformation": ["none"],
        }

    # Category C — multi-line output; no frozen digest; exact bytes not preserved.
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

    # Category D — Python source; pre-format LF content digest as static value.
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

    results_blob_sha = hashlib.sha256(_git_blob("experiments/e2/_run/e2_results.json")).hexdigest()

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

    # Classification logic — record the divergence, do not canonize.
    rule_a_safety_passes = safety_table["clean_exact_error_count"]["foundry"] == 0
    rule_a_harmful = (not rule_a_safety_passes) or (p_foundry < p_control)

    rule_b_per_count = {}
    rule_b_safety_passes = True
    for c in counts:
        f = safety_table[c]["foundry"]
        b = safety_table[c]["base"]
        ctrl = safety_table[c]["control"]
        ok = (f <= b) and (f <= ctrl)
        rule_b_per_count[c] = {
            "foundry": f,
            "base": b,
            "control": ctrl,
            "foundry_le_base": bool(f <= b),
            "foundry_le_control": bool(f <= ctrl),
            "passes": bool(ok),
        }
        if not ok:
            rule_b_safety_passes = False
    rule_b_harmful = (not rule_b_safety_passes) or (p_foundry < p_control)

    provenance = _build_provenance(contract)

    receipt = {
        "attempt_id": "e2-foundry-vs-control",
        "claim_boundary": contract["claim_boundary"],
        "classification_logic": {
            "contract_rule": (
                "PROMISING requires safety passes AND P_foundry > P_control AND "
                "P_foundry > P_base; HARMFUL if safety fails OR P_foundry < "
                "P_control; NO_OBSERVED_SIGNAL otherwise valid; TECHNICALLY_INVALID "
                "on execution/measurement failure (contract "
                "classification_truth_table)."
            ),
            "contract_safety_formulation": (
                "Relative five-count non-regression: safety holds when, for ALL "
                "5 counts, Foundry <= Base AND Foundry <= Control (the rule "
                "E3 later formalized and the rule the E2 contract prose describes)."
            ),
            "as_executed_rule": (
                "run_e2_experiment.py _classify implemented an ABSOLUTE rule: "
                "safety_passes = (FOUNDRY.clean_exact_error_count == 0). Only "
                "FOUNDRY's clean_exact_error_count is consulted; no comparison to "
                "Base or Control is made in the safety gate."
            ),
            "implementation_divergence": True,
            "rule_a_as_executed": {
                "formulation": "absolute",
                "safety_gate": "FOUNDRY.clean_exact_error_count == 0",
                "safety_passes": bool(rule_a_safety_passes),
                "primary": {
                    "p_base": p_base,
                    "p_control": p_control,
                    "p_foundry": p_foundry,
                },
                "harmful_trigger_safety": bool(not rule_a_safety_passes),
                "harmful_trigger_primary": bool(p_foundry < p_control),
                "terminal": "HARMFUL" if rule_a_harmful else "NOT_HARMFUL",
                "terminal_trigger": (
                    "safety (clean_exact_error_count=10 != 0)"
                    if not rule_a_safety_passes
                    else ("primary (P_foundry < P_control)" if p_foundry < p_control else "none")
                ),
            },
            "rule_b_contract": {
                "formulation": "relative",
                "safety_gate": "for all 5 counts: Foundry <= Base AND Foundry <= Control",
                "safety_passes": bool(rule_b_safety_passes),
                "per_count": rule_b_per_count,
                "primary": {
                    "p_base": p_base,
                    "p_control": p_control,
                    "p_foundry": p_foundry,
                },
                "harmful_trigger_safety": bool(not rule_b_safety_passes),
                "harmful_trigger_primary": bool(p_foundry < p_control),
                "terminal": "HARMFUL" if rule_b_harmful else "NOT_HARMFUL",
                "terminal_trigger": (
                    "safety (Foundry > Base on spurious_basis_removal_count, "
                    "valid_basis_rejection_count, clean_not_applicable_count; "
                    "each 5 > 0)"
                    if not rule_b_safety_passes
                    else ("primary (P_foundry < P_control)" if p_foundry < p_control else "none")
                ),
            },
            "terminal_invariant_to_divergence": bool(rule_a_harmful and rule_b_harmful),
            "divergence_material_to_terminal": False,
            "divergence_note": (
                "E2's classifier implementation diverged from the contract's "
                "relative safety formulation. The divergence is preserved as an "
                "execution defect, but the terminal HARMFUL result is invariant: "
                "the recorded E2 safety evidence fails both formulations. Rule A "
                "fails on the absolute bar (clean_exact_error_count=10 != 0); "
                "Rule B fails on the relative-to-Base test for three counts "
                "(spurious_basis_removal, valid_basis_rejection, "
                "clean_not_applicable; Foundry 5 > Base 0 each). Foundry equals "
                "Control on every safety count, so Rule B's failure is purely "
                "Foundry-vs-Base. No GPU rerun and no metric recomputation are "
                "warranted by this divergence."
            ),
        },
        "durable_evidence": {
            "publication_channel": "git_repository",
            "note": (
                "Small non-weight execution evidence (source, inputs, outputs) is "
                "tracked in this repository under experiments/e2/. Per-file "
                "provenance distinguishes the historical execution identity from "
                "the durable repository identity (see provenance_model and "
                "per_file_provenance). No GitHub Release publication is required."
            ),
            "paths": PROMOTED_FILES,
            "per_file_provenance": provenance,
        },
        "execution_id": "E2",
        "execution_provenance": {
            "execution_repository_base_commit": EXECUTION_REPOSITORY_BASE_COMMIT,
            "execution_source_status": "uncommitted_worktree",
            "note": (
                "E2 executed from an uncommitted worktree based on "
                f"{EXECUTION_REPOSITORY_BASE_COMMIT} (Record E1 execution result, "
                "PR #98). The experiment-defining files were promoted to durable "
                "git evidence in a subsequent commit on this branch; that "
                "promotion does not retroactively make its merge commit the "
                "source commit of the historical GPU execution."
            ),
        },
        "frozen_identities": {
            "context_length": contract["context_length"],
            "control_train_path": contract["control_train_path"],
            "control_train_record_count": contract["control_train_record_count"],
            "control_train_sha256": contract["control_train_sha256"],
            "foundry_train_path": contract["foundry_train_path"],
            "foundry_train_record_count": contract["foundry_train_record_count"],
            "foundry_train_sha256": contract["foundry_train_sha256"],
            "learning_rate": contract["training_recipe"]["learning_rate"],
            "loss": contract["training_recipe"]["loss"],
            "max_steps": contract["training_recipe"]["steps"],
            "model_id": contract["model_id"],
            "model_revision": contract["model_revision"],
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
            "safety_table": safety_table,
        },
        "primary_interpretation": (
            "Both trained arms (CONTROL, FOUNDRY) acquired the response task "
            "under the response-token-only loss, unlike E1 where no arm acquired "
            "it. FOUNDRY shows a positive primary differential over CONTROL "
            f"(P_foundry={p_foundry} > P_control={p_control}). This differential "
            "is non-ratifiable for G1 because both trained arms fail the safety "
            "metric: all 10 clean cases were classified into wrong codewords "
            "(clean_exact_error_count=10 for BASE, CONTROL, and FOUNDRY). The "
            "safety failure is shared, not Foundry-specific; Foundry equals "
            "Control on every safety count."
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
            "e2_gpu_ceiling_minutes": contract["gpu_minute_ceiling"],
            "e2_gpu_seconds": results["gpu_elapsed_seconds"],
            "e2_gpu_seconds_floor": int(results["gpu_elapsed_seconds"]),
        },
        "safety_interpretation": (
            "All three arms produced 10/10 clean-case exact errors "
            "(clean_exact_error_count=10 each). BASE additionally produced 10/10 "
            "malformed outputs (clean_malformed_count=10); both trained arms "
            "produced zero malformed but systematically wrong codewords on clean "
            "cases. Both trained arms regressed on three relative-vs-Base counts "
            "(spurious_basis_removal=5, valid_basis_rejection=5, "
            "clean_not_applicable=5; BASE=0 each) because the trained arms emit "
            "valid A-E codewords on clean cases where BASE emits malformed output."
        ),
        "schema_version": "e2-execution-result/1",
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
        f"terminal_invariant_to_divergence={receipt['classification_logic']['terminal_invariant_to_divergence']}"
    )
    print(f"per_file_provenance entries: {len(provenance)}")


if __name__ == "__main__":
    main()
