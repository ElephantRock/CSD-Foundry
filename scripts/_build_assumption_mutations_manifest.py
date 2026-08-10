"""Generate the v0.5-D3.1 assumption-mutations-v1 manifest (one-shot build helper).

For each of the 18 mutation families, this script applies the operator to the
appropriate baseline vector, runs the independent validator, records the
observed detector, and emits a committed manifest pinned to the baseline
vector catalog digest.

Run: python scripts/_build_assumption_mutations_manifest.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from csd_foundry.governance.v0_5.assumption_mutations import (
    AssumptionMutationError,
    _mutate_catalog,
)
from csd_foundry.governance.v0_5.assumption_validation import (
    GovernanceContractError,
    validate_assumption_registry,
)
from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.resources import assumption_vectors

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data/canary/v0.5/assumption-mutations-v1/manifest.json"


# Each entry: (mutation_id, family, baseline_vector_id, operator, mode, parameters)
# The expected_detector is filled in empirically by running the mutation.
SPECS: list[tuple[str, str, str, str, str, dict[str, Any]]] = [
    # HISTORY (2)
    (
        "AM-HISTORY-001",
        "HISTORY",
        "AV-A02",
        "CORRUPT_PREDECESSOR",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    (
        "AM-HISTORY-002",
        "HISTORY",
        "AV-A02",
        "CORRUPT_ENTITY_SEQUENCE",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    # LIFECYCLE (1)
    (
        "AM-LIFECYCLE-001",
        "LIFECYCLE",
        "AV-A07",
        "APPEND_TERMINAL_REVIVAL",
        "REJECTED",
        {"stage": "LIFECYCLE"},
    ),
    # IDENTITY (1)
    (
        "AM-IDENTITY-001",
        "IDENTITY",
        "AV-A02",
        "SUBSTITUTE_ASSUMPTION_ID",
        "REJECTED",
        {"stage": "HISTORY", "replacement_id": "assumption:intruder"},
    ),
    # AUTHORITY (1)
    (
        "AM-AUTHORITY-001",
        "AUTHORITY",
        "AV-A02",
        "SUBSTITUTE_ADMITTING_AUTHORITY",
        "REJECTED",
        {"stage": "AUTHORITY", "authority_id": "authority:intruder"},
    ),
    # SOD (1)
    (
        "AM-SOD-001",
        "SOD",
        "AV-A01",
        "SUBSTITUTE_PROPOSER_AUTHORITY",
        "REJECTED",
        {"stage": "AUTHORITY", "authority_id": "authority:admitter"},
    ),
    # ADMISSION (2)
    (
        "AM-ADMISSION-001",
        "ADMISSION",
        "AV-A10",
        "REMOVE_ASSUMPTION_DEPENDENCY",
        "ACCEPTED_ERROR",
        {"assumption_id": "assumption:a10a"},
    ),
    (
        "AM-ADMISSION-002",
        "ADMISSION",
        "AV-A11",
        "REPLACE_EVIDENCE_DEPENDENCY",
        "ACCEPTED_ERROR",
        {"evidence_dependency_ids": ["evidence:wrong"]},
    ),
    # CHALLENGE (2)
    ("AM-CHALLENGE-001", "CHALLENGE", "AV-A03", "REMOVE_ACTIVE_CHALLENGE", "ACCEPTED_ERROR", {}),
    (
        "AM-CHALLENGE-002",
        "CHALLENGE",
        "AV-A05",
        "CORRUPT_RESOLVED_CHALLENGE_SET",
        "REJECTED",
        {"stage": "LIFECYCLE", "resolved_challenge_ids": ["challenge:unknown"]},
    ),
    # TEMPORAL (1)
    (
        "AM-TEMPORAL-001",
        "TEMPORAL",
        "AV-A02",
        "ALTER_VALID_FROM",
        "ACCEPTED_ERROR",
        {"valid_from_sequence": 100},
    ),
    # DFS (3)
    (
        "AM-DFS-001",
        "DFS",
        "AV-A10",
        "REORDER_DEPENDENCY_TRAVERSAL",
        "ACCEPTED_ERROR",
        {
            "assumption_id": "assumption:a10a",
            "dependency_ids": ["assumption:a10c", "assumption:a10b"],
        },
    ),
    (
        "AM-DFS-002",
        "DFS",
        "AV-A10",
        "REMOVE_TRAVERSED_DEPENDENCY",
        "ACCEPTED_ERROR",
        {"assumption_id": "assumption:a10a", "dependency_id": "assumption:a10b"},
    ),
    (
        "AM-DFS-003",
        "DFS",
        "AV-A12",
        "INTRODUCE_DEPENDENCY_CYCLE",
        "REJECTED",
        {"stage": "USE", "assumption_id": "assumption:a12c", "dependency_id": "assumption:a12a"},
    ),
    # USE_TIME_EVIDENCE (1)
    (
        "AM-USE-EVIDENCE-001",
        "USE_TIME_EVIDENCE",
        "AV-A11",
        "SUBSTITUTE_EVIDENCE_REQUEST",
        "ACCEPTED_ERROR",
        {"evidence_id": "evidence:a11e"},
    ),
    # RECEIPT (1)
    (
        "AM-RECEIPT-001",
        "RECEIPT",
        "AV-A11",
        "CORRUPT_CHILD_RECEIPT",
        "ACCEPTED_ERROR",
        {"evidence_id": "evidence:a11e"},
    ),
    # WORK (1)
    ("AM-WORK-001", "WORK", "AV-A02", "ALTER_WORK_COUNTER", "ACCEPTED_ERROR", {}),
    # ROOT (1)
    ("AM-ROOT-001", "ROOT", "AV-A02", "CORRUPT_EXPECTED_ROOT", "ACCEPTED_ERROR", {}),
]


def _detect(catalog: dict[str, Any], mode: str, mutation_id: str) -> tuple[str, str | None]:
    """Run the validator on the mutated catalog and extract (classification, detector).

    For REJECTED mode the MUT vector's ``expected_error`` carries a placeholder
    during detection, so the validator will report a mismatch error containing
    the OBSERVED code. We parse that line to recover the detector.
    """
    report = validate_assumption_registry(vectors=catalog)
    if mode == "REJECTED":
        observed = dict(report.rejected_failure_codes).get(f"MUT-{mutation_id}")
        if observed is not None:
            return "KILLED", observed
        # Placeholder mismatch: parse the observed code from the error line.
        prefix = f"MUT-{mutation_id}: expected "
        for line in report.errors:
            if line.startswith(prefix):
                # Format: "MUT-<id>: expected <PLACEHOLDER>, observed <CODE>"
                tail = line.split("observed ", 1)
                if len(tail) == 2:
                    return "KILLED", tail[1].strip()
        return "INVALID_MUTATION", _first_token(report)
    if report.success:
        return "SURVIVED", None
    # ACCEPTED_ERROR / CATALOG_ERROR: the detector is the ASSUMPTION_* code in
    # the "{vector_id}: accepted vector failed with CODE" or policy error line.
    for line in report.errors:
        for token in line.replace(":", " ").replace(",", " ").split():
            if token.startswith("ASSUMPTION_") and "_" in token:
                return "KILLED", token
    return "INVALID_MUTATION", _first_token(report)


def _first_token(report: Any) -> str | None:
    if report.errors:
        text = report.errors[0]
        for token in text.replace(":", " ").replace(",", " ").split():
            if token.isupper() and "_" in token:
                return token
        return text
    return None


def main() -> None:
    baseline = assumption_vectors()
    baseline_digest = baseline["catalog_digest"]
    mutations: list[dict[str, Any]] = []
    for mutation_id, family, baseline_vector_id, operator, mode, parameters in SPECS:
        try:
            mutated = _mutate_catalog(
                baseline,
                mutation_id=mutation_id,
                baseline_vector_id=baseline_vector_id,
                operator=operator,
                mode=mode,
                expected_detector="PLACEHOLDER",
                parameters=parameters,
            )
        except (AssumptionMutationError, GovernanceContractError, KeyError, TypeError) as exc:
            print(f"  {mutation_id}: operator raised {exc}")
            continue
        classification, detector = _detect(mutated, mode, mutation_id)
        if classification != "KILLED" or detector is None:
            print(
                f"  {mutation_id} ({operator}): NOT KILLED -> {classification} detector={detector}"
            )
            continue
        mutations.append(
            {
                "mutation_id": mutation_id,
                "family": family,
                "baseline_vector_id": baseline_vector_id,
                "operator": operator,
                "mode": mode,
                "parameters": parameters,
                "expected_classification": "KILLED",
                "expected_detector": detector,
            }
        )
        print(f"  {mutation_id} ({operator}): KILLED by {detector}")

    mutations.sort(key=lambda item: item["mutation_id"])
    manifest: dict[str, Any] = {
        "schema_version": "assumption-mutation-campaign/1",
        "mutation_version": 1,
        "baseline_vector_catalog_digest": baseline_digest,
        "classification_values": ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"],
        "mutations": mutations,
        "claim_boundary": (
            "This campaign establishes that declared serialized assumption defects are detected "
            "relative to the committed assumption-v1 corpus and independent validator. It does "
            "not establish completeness of the mutation space, external truth, real-world "
            "dependency completeness, or production safety."
        ),
    }
    manifest["catalog_digest"] = catalog_digest(manifest, b"ASSUMPTION_MUTATION_CATALOG\0")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    DEST.write_text(rendered + "\n", encoding="utf-8")
    print(f"\nWrote {len(mutations)} mutations to {DEST}")
    print(f"catalog_digest={manifest['catalog_digest']}")


if __name__ == "__main__":
    main()
