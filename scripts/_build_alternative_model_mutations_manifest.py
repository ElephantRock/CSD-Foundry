"""Generate the v0.5-D4 alternative-model-mutations-v1 manifest (one-shot build helper).

For each mutation family, this script applies the operator to the appropriate
baseline vector, runs the independent validator, records the observed detector,
and emits a committed manifest pinned to the baseline vector catalog digest.

Run: python scripts/_build_alternative_model_mutations_manifest.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from csd_foundry.governance.v0_5.alternative_model_mutations import (
    AlternativeModelMutationError,
    _mutate_catalog,
)
from csd_foundry.governance.v0_5.alternative_model_validation import (
    validate_alternative_model_registry,
)
from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    catalog_digest,
)
from csd_foundry.governance.v0_5.resources import alternative_model_vectors

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data/canary/v0.5/alternative-model-mutations-v1/manifest.json"

# Each entry: (mutation_id, family, baseline_vector_id, operator, mode, parameters)
SPECS: list[tuple[str, str, str, str, str, dict[str, Any]]] = [
    # HISTORY: event identity/sequence/predecessor/ordering (3)
    (
        "AM-HISTORY-001",
        "HISTORY",
        "AMV-A01",
        "CORRUPT_PREDECESSOR",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    (
        "AM-HISTORY-002",
        "HISTORY",
        "AMV-A01",
        "CORRUPT_ENTITY_SEQUENCE",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    (
        "AM-HISTORY-003",
        "HISTORY",
        "AMV-A01",
        "CORRUPT_CLOCK_SEQUENCE",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    # HISTORY: event ordering (1)
    (
        "AM-HISTORY-004",
        "HISTORY",
        "AMV-A02",
        "SWAP_EVENT_ORDER",
        "REJECTED",
        {"stage": "HISTORY"},
    ),
    # IDENTITY (1)
    (
        "AM-IDENTITY-001",
        "IDENTITY",
        "AMV-A01",
        "SUBSTITUTE_MODEL_ID",
        "REJECTED",
        {"stage": "HISTORY", "replacement_id": "alt-model:intruder"},
    ),
    # LIFECYCLE: illegal transition / terminal revival (2)
    (
        "AM-LIFECYCLE-001",
        "LIFECYCLE",
        "AMV-A07",
        "APPEND_TERMINAL_REVIVAL",
        "REJECTED",
        {"stage": "LIFECYCLE"},
    ),
    (
        "AM-LIFECYCLE-002",
        "LIFECYCLE",
        "AMV-A02",
        "CORRUPT_ADMIT_TRANSITION",
        "ACCEPTED_ERROR",
        {},
    ),
    # CHALLENGE / RESOLUTION state (2)
    (
        "AM-CHALLENGE-001",
        "CHALLENGE",
        "AMV-A03",
        "REMOVE_ACTIVE_CHALLENGE",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-CHALLENGE-002",
        "CHALLENGE",
        "AMV-A03",
        "CORRUPT_RESOLVED_CHALLENGE_SET",
        "REJECTED",
        {"stage": "LIFECYCLE", "resolved_challenge_ids": ["challenge:unknown"]},
    ),
    # GRAPH canonical bytes/digest (2)
    (
        "AM-GRAPH-001",
        "GRAPH",
        "AMV-A01",
        "CORRUPT_GRAPH_BYTES",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-GRAPH-002",
        "GRAPH",
        "AMV-A01",
        "CORRUPT_GRAPH_DIGEST",
        "ACCEPTED_ERROR",
        {},
    ),
    # RFC 6901 difference path / escaping (2)
    (
        "AM-DIFFERENCE-PATH-001",
        "DIFFERENCE_PATH",
        "AMV-A01",
        "CORRUPT_DIFFERENCE_PATH",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-DIFFERENCE-PATH-002",
        "DIFFERENCE_PATH",
        "AMV-A01",
        "ESCAPE_DIFFERENCE_PATH",
        "ACCEPTED_ERROR",
        {},
    ),
    # DIFFERENCE family / digest (2)
    (
        "AM-DIFFERENCE-001",
        "DIFFERENCE",
        "AMV-A01",
        "CORRUPT_DIFFERENCE_FAMILY",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-DIFFERENCE-002",
        "DIFFERENCE",
        "AMV-A01",
        "CORRUPT_DIFFERENCE_DIGEST",
        "ACCEPTED_ERROR",
        {},
    ),
    # MATERIAL-DIFFERENCE admission (1)
    (
        "AM-MATERIAL-001",
        "MATERIAL_ADMISSION",
        "AMV-A01",
        "SUPPRESS_MATERIAL_DIFFERENCE",
        "ACCEPTED_ERROR",
        {},
    ),
    # AUTHORIZATION bindings (2)
    (
        "AM-AUTHORIZATION-001",
        "AUTHORIZATION",
        "AMV-A01",
        "CORRUPT_AUTHORIZATION_BINDING",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-AUTHORIZATION-002",
        "AUTHORIZATION",
        "AMV-A01",
        "REMOVE_ADMISSION_EVIDENCE",
        "ACCEPTED_ERROR",
        {"model_id": "alt-model:a01"},
    ),
    # ADMIT source-receipt binding (1)
    (
        "AM-ADMIT-001",
        "ADMIT_BINDING",
        "AMV-A01",
        "CORRUPT_AUTHORIZATION_DIGEST",
        "REJECTED",
        {"stage": "ADMISSION"},
    ),
    # REPLAY inventory bindings (2)
    (
        "AM-REPLAY-001",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_EXECUTED",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-REPLAY-002",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_SKIPPED",
        "ACCEPTED_ERROR",
        {},
    ),
    # COMPARISON bindings (2)
    (
        "AM-COMPARISON-001",
        "COMPARISON",
        "AMV-A09",
        "CORRUPT_COMPARISON_RESULT",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-COMPARISON-002",
        "COMPARISON",
        "AMV-A09",
        "CORRUPT_COMPARISON_GRAPH_BINDING",
        "ACCEPTED_ERROR",
        {},
    ),
    # USE-TIME gates (2)
    (
        "AM-USE-001",
        "USE_TIME",
        "AMV-A02",
        "CORRUPT_USE_AUTHORITY_DECISION",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-USE-002",
        "USE_TIME",
        "AMV-A02",
        "CORRUPT_USE_AUTHORITY_SCOPE",
        "ACCEPTED_ERROR",
        {"scope_id": "scope:intruder"},
    ),
    # RECEIPT / CATALOG integrity (3)
    (
        "AM-RECEIPT-001",
        "RECEIPT",
        "AMV-A01",
        "CORRUPT_RECEIPT_SELF_DIGEST",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-ROOT-001",
        "ROOT",
        "AMV-A01",
        "CORRUPT_EXPECTED_ROOT",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-EXPECTED-AUTH-001",
        "EXPECTED_AUTH",
        "AMV-A01",
        "CORRUPT_EXPECTED_AUTHORIZATION",
        "ACCEPTED_ERROR",
        {"model_id": "alt-model:a01"},
    ),
    # IMMUTABLE FIELD: challenge_basis_code is an immutable PROPOSE field (1)
    (
        "AM-IMMUTABLE-001",
        "IMMUTABLE_FIELD",
        "AMV-A01",
        "CORRUPT_CHALLENGE_BASIS",
        "ACCEPTED_ERROR",
        {"challenge_basis_code": "basis:tampered"},
    ),
    # REPLAY: nonempty pruned_inventory + context/state/runner binding mutations (4)
    (
        "AM-REPLAY-003",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_PRUNED",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-REPLAY-004",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_RUNNER",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-REPLAY-005",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_DECISION_CONTEXT",
        "ACCEPTED_ERROR",
        {},
    ),
    (
        "AM-REPLAY-006",
        "REPLAY",
        "AMV-A09",
        "CORRUPT_REPLAY_INITIAL_STATE",
        "ACCEPTED_ERROR",
        {},
    ),
    # COMPARISON: context binding mutation (1)
    (
        "AM-COMPARISON-003",
        "COMPARISON",
        "AMV-A09",
        "CORRUPT_COMPARISON_CONTEXT",
        "ACCEPTED_ERROR",
        {},
    ),
    # COMPARISON: logical_clock binding mutation (1)
    (
        "AM-COMPARISON-004",
        "COMPARISON",
        "AMV-A09",
        "CORRUPT_COMPARISON_LOGICAL_CLOCK",
        "ACCEPTED_ERROR",
        {},
    ),
    # AUTHORIZATION: root/authority binding mutations (2)
    (
        "AM-AUTHORIZATION-003",
        "AUTHORITY",
        "AMV-A01",
        "SUBSTITUTE_ADMITTING_AUTHORITY",
        "ACCEPTED_ERROR",
        {"authority_id": "authority:intruder"},
    ),
    (
        "AM-AUTHORIZATION-004",
        "AUTHORIZATION_ROOT",
        "AMV-A01",
        "CORRUPT_AUTHORIZATION_ROOT",
        "ACCEPTED_ERROR",
        {"extra_model_id": "alt-model:extra-root"},
    ),
    # USE-TIME: terminal/expiry/reuse-class mutations (3)
    (
        "AM-USE-003",
        "USE_TIME",
        "AMV-A02",
        "CORRUPT_USE_REUSE_CLASS",
        "REJECTED",
        {"stage": "USE"},
    ),
    (
        "AM-USE-004",
        "USE_TIME",
        "AMV-A02",
        "CORRUPT_USE_EXPIRY",
        "REJECTED",
        {"stage": "USE", "logical_clock": 200},
    ),
    (
        "AM-USE-005",
        "USE_TIME",
        "AMV-A02",
        "CORRUPT_USE_TERMINAL",
        "REJECTED",
        {"stage": "USE"},
    ),
    # USE-TIME: UNVERIFIED downgrade gate (1)
    (
        "AM-USE-006",
        "USE_TIME",
        "AMV-A02",
        "DOWNGRADE_TO_UNVERIFIED",
        "REJECTED",
        {"stage": "USE"},
    ),
]


def _detect(catalog: dict[str, Any], mode: str, mutation_id: str) -> tuple[str, str | None]:
    """Run the validator on the mutated catalog and extract (classification, detector)."""
    report = validate_alternative_model_registry(vectors=catalog)
    if mode == "REJECTED":
        observed = dict(report.rejected_failure_codes).get(f"MUT-{mutation_id}")
        if observed is not None:
            return "KILLED", observed
        prefix = f"MUT-{mutation_id}: expected "
        for line in report.errors:
            if line.startswith(prefix):
                tail = line.split("observed ", 1)
                if len(tail) == 2:
                    return "KILLED", tail[1].strip()
        return "INVALID_MUTATION", _first_token(report)
    if report.success:
        return "SURVIVED", None
    joined = "\n".join(report.errors)
    # ACCEPTED_ERROR / CATALOG_ERROR: the detector is an ALTERNATIVE_MODEL_* or
    # STRUCTURAL_DIFFERENCE_* / REPLAY_* / COMPARISON_* / USE_* code.
    for line in report.errors:
        for token in line.replace(":", " ").replace(",", " ").split():
            if (
                token.startswith("ALTERNATIVE_MODEL_")
                or token.startswith("STRUCTURAL_DIFFERENCE_")
                or token.startswith("REPLAY_")
                or token.startswith("COMPARISON_")
                or token.startswith("USE_")
            ) and "_" in token:
                return "KILLED", token
    if "ALTERNATIVE_MODEL_" in joined or "STRUCTURAL_DIFFERENCE_" in joined:
        return "INVALID_MUTATION", _first_token(report)
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
    baseline = alternative_model_vectors()
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
        except (
            AlternativeModelMutationError,
            GovernanceContractError,
            KeyError,
            TypeError,
        ) as exc:
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
        "schema_version": "alternative-model-mutation-campaign/1",
        "mutation_version": 1,
        "baseline_vector_catalog_digest": baseline_digest,
        "classification_values": ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"],
        "mutations": mutations,
        "claim_boundary": (
            "This campaign establishes that declared serialized alternative-model defects "
            "are detected relative to the committed alternative-model-v1 corpus and "
            "independent validator. It does not establish completeness of the mutation space, "
            "external truth, real-world dependency completeness, or production safety."
        ),
    }
    manifest["catalog_digest"] = catalog_digest(manifest, b"ALTERNATIVE_MODEL_MUTATION_CATALOG\0")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    DEST.write_text(rendered + "\n", encoding="utf-8")
    print(f"\nWrote {len(mutations)} mutations to {DEST}")
    print(f"catalog_digest={manifest['catalog_digest']}")


if __name__ == "__main__":
    main()
