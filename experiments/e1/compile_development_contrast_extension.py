#!/usr/bin/env python3
"""Compile the E1 development-contrast extension artifacts.

Standalone orchestration. Builds the E1 overlay catalog, the successor
selection contract, the successor Foundry bundle, and the successor
label-space audit; binds them into a governed extension receipt; and writes
(or validates) three canonical artifacts under ``data/e1/v2/``.

Pure CPU. No tokenizer, no model, no GPU.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from csd_foundry.empirical.e1.development_contrast_extension import (
    CLAIM_BOUNDARY,
    RELEASE,
    SCHEMAS_VERSION,
    E1DevelopmentContrastError,
    E1DevelopmentContrastExtension,
    build_e1_development_contrast_catalog,
    development_contrast_overlay_catalog_digest,
)
from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
from csd_foundry.empirical.e1.foundry_artifact_compiler import (
    compile_e1_foundry_artifacts,
)
from csd_foundry.empirical.e1.label_space_audit import audit_e1_label_space
from csd_foundry.empirical.e1.scenario_splits import derive_scenario_family_identity
from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.kernel.transitions import apply_event
from csd_foundry.scenarios.registry import SCENARIOS
from csd_foundry.scenarios.runner import run_scenario
from csd_foundry.scenarios.spec import TransitionCase
from csd_foundry.synthesis.v0_4.serialization import (
    canonical_json_bytes,
    canonical_json_text,
    canonical_sha256,
)

_DEFAULT_OUTPUT_DIRECTORY = Path("data/e1/v2")

# Successor releases advance to /2 to distinguish immutable identity from the
# predecessor /1 releases (different bytes, different family identities).
_SELECTION_RELEASE = "e1-candidate/2"
_FOUNDRY_RELEASE = "e1-foundry-artifacts/2"
_AUDIT_RELEASE = "e1-label-space-audit/2"

# Predecessor releases remain /1 (the original A0a audit + base selection).
_PREDECESSOR_SELECTION_RELEASE = "e1-candidate/1"
_PREDECESSOR_FOUNDRY_RELEASE = "e1-foundry-artifacts/1"

# Predecessor base commit (the original main before this overlay). The
# successor source_commit is supplied separately via --source-commit.
_PREDECESSOR_BASE_COMMIT = "2cf5875f3a78bb5aa14578bc1bf1f33c18b7a199"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python experiments/e1/compile_development_contrast_extension.py",
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument(
        "--predecessor-audit",
        type=Path,
        default=Path("data/e1/v1/label_space_audit.json"),
        help="Predecessor (A0a) audit artifact path",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=_DEFAULT_OUTPUT_DIRECTORY,
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Recompile and byte-compare all three artifacts on disk.",
    )
    return parser


def _module_sha256() -> str:
    """SHA-256 of the exact extension module bytes (implementation identity)."""

    module_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "csd_foundry"
        / "empirical"
        / "e1"
        / "development_contrast_extension.py"
    )
    return hashlib.sha256(module_path.read_bytes()).hexdigest()


def _base_catalog_digest() -> str:
    return development_contrast_overlay_catalog_digest(SCENARIOS)


def _build_transition_receipt(
    scenario_id: str,
    case: TransitionCase,
) -> dict[str, object]:
    oracle = CsdOracle()
    result = oracle.apply(case.before, case.event)
    replay_after, replay_trace = apply_event(case.before, case.event)
    if (replay_after, replay_trace) != (result.after, result.trace):
        raise E1DevelopmentContrastError(
            f"{case.case_id}: independent replay disagrees with oracle"
        )
    before_digest = canonical_sha256(case.before)
    event_digest = canonical_sha256(case.event)
    after_digest = canonical_sha256(result.after)
    trace_digest = canonical_sha256(result.trace)
    oracle_receipt_digest = canonical_sha256(
        {
            "scenario_id": scenario_id,
            "case_id": case.case_id,
            "before_state_digest": before_digest,
            "event_digest": event_digest,
            "after_state_digest": after_digest,
            "trace_digest": trace_digest,
        }
    )
    verification_digest = canonical_sha256(
        {
            "scenario_id": scenario_id,
            "case_id": case.case_id,
            "replay_after_digest": canonical_sha256(replay_after),
            "replay_trace_digest": canonical_sha256(replay_trace),
            "matches_oracle": True,
        }
    )
    if oracle_receipt_digest == verification_digest:
        raise E1DevelopmentContrastError(
            f"{case.case_id}: oracle and verification digests must be distinct"
        )
    return {
        "scenario_id": scenario_id,
        "case_id": case.case_id,
        "event_type": type(case.event).__name__,
        "before_state_digest": before_digest,
        "event_digest": event_digest,
        "after_state_digest": after_digest,
        "trace_digest": trace_digest,
        "oracle_receipt_digest": oracle_receipt_digest,
        "independent_verification_receipt_digest": verification_digest,
        "required_trace_rules": sorted(case.required_trace_rules),
        "observed_trace_rules": sorted(result.trace.rules_fired),
    }


def _family_digests(catalog: dict[str, object]) -> dict[str, str]:
    """Return scenario_id -> family_digest for a catalog of ScenarioSpec."""

    identities: dict[str, str] = {}
    for scenario_id, spec in sorted(catalog.items()):
        identity = derive_scenario_family_identity(spec)  # type: ignore[arg-type]
        identities[scenario_id] = identity.family_digest
    return identities


def _outcome_from_audit(audit_payload: dict[str, object]) -> str:
    primary_supported = bool(audit_payload.get("primary_population_supported"))
    return "PRIMARY_POPULATION_SUPPORTED" if primary_supported else "PRIMARY_POPULATION_UNSUPPORTED"


def compile_extension(
    *,
    source_commit: str,
    predecessor_audit_path: Path,
) -> tuple[dict[str, bytes], E1DevelopmentContrastExtension]:
    """Compile the three canonical artifacts and the governed extension receipt."""

    predecessor_audit_text = predecessor_audit_path.read_text(encoding="utf-8")
    predecessor_audit_payload = __import__("json").loads(predecessor_audit_text)
    predecessor_audit_sha256 = hashlib.sha256(predecessor_audit_text.encode("utf-8")).hexdigest()
    predecessor_selection_digest = str(predecessor_audit_payload["selection_contract_digest"])

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    overlay_catalog_digest = development_contrast_overlay_catalog_digest(overlay_catalog)

    # Successor selection + Foundry bundle from the overlay catalog. The
    # predecessor family digests are derived directly from the base registry
    # via _family_digests(SCENARIOS) for the changed-family mapping; no
    # predecessor bundle compilation is required.
    successor_selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release=_SELECTION_RELEASE,
        source_commit=source_commit,
    )
    successor_bundle = compile_e1_foundry_artifacts(
        overlay_catalog,
        successor_selection,
        release=_FOUNDRY_RELEASE,
        selection_release=_SELECTION_RELEASE,
        source_commit=source_commit,
    )

    # Successor audit.
    successor_audit = audit_e1_label_space(
        successor_bundle,
        successor_selection,
        release=_AUDIT_RELEASE,
        source_commit=source_commit,
    )
    successor_audit_text = canonical_json_text(successor_audit.to_dict())
    successor_audit_sha256 = hashlib.sha256(successor_audit_text.encode("utf-8")).hexdigest()

    # Family-digest accounting.
    base_family_by_scenario = _family_digests(SCENARIOS)
    successor_family_by_scenario = _family_digests(overlay_catalog)
    changed_family_mapping = {
        scenario_id: {
            "predecessor_family_digest": base_family_by_scenario[scenario_id],
            "successor_family_digest": successor_family_by_scenario[scenario_id],
        }
        for scenario_id in ("M-12", "M-14")
    }

    # Transition receipts.
    m12 = overlay_catalog["M-12"]
    m14 = overlay_catalog["M-14"]
    m12_transition = next(c for c in m12.cases if isinstance(c, TransitionCase))
    m14_transition = next(c for c in m14.cases if isinstance(c, TransitionCase))
    transition_receipts = (
        _build_transition_receipt("M-12", m12_transition),
        _build_transition_receipt("M-14", m14_transition),
    )

    # Canonical-runner admission gate (must pass before binding).
    for spec in (m12, m14):
        runner = run_scenario(spec)
        if not runner.accepted:
            raise E1DevelopmentContrastError(
                f"canonical runner rejected successor scenario: {spec.scenario_id}"
            )

    successor_file_receipts = tuple(
        {"path": item.path, "role": item.role, "sha256": item.sha256}
        for item in successor_bundle.files
    )

    selection_contract_text = canonical_json_text(successor_selection.to_dict())

    extension = E1DevelopmentContrastExtension(
        schema_version=SCHEMAS_VERSION,
        release=RELEASE,
        base_source_commit=_PREDECESSOR_BASE_COMMIT,
        extension_implementation_sha256=_module_sha256(),
        predecessor_audit_sha256=predecessor_audit_sha256,
        predecessor_selection_contract_digest=predecessor_selection_digest,
        base_catalog_digest=_base_catalog_digest(),
        overlay_catalog_digest=overlay_catalog_digest,
        modified_scenario_ids=("M-12", "M-14"),
        unchanged_training_scenario_ids=tuple(
            sorted(
                sid for sid in successor_bundle.training_scenario_ids if sid not in ("M-12", "M-14")
            )
        ),
        unchanged_test_scenario_ids=successor_selection.excluded_source_test_scenario_ids,
        base_family_digest_by_scenario=base_family_by_scenario,
        successor_family_digest_by_scenario=successor_family_by_scenario,
        changed_family_digest_mapping=changed_family_mapping,
        successor_selection_contract=successor_selection.to_dict(),
        successor_selection_contract_digest=successor_selection.contract_digest,
        successor_foundry_bundle_manifest_sha256=successor_bundle.file(
            "bundle_manifest.json"
        ).sha256,
        successor_foundry_file_receipts=successor_file_receipts,
        transition_receipts=transition_receipts,
        successor_audit_sha256=successor_audit_sha256,
        extension_outcome=_outcome_from_audit(successor_audit.to_dict()),
        claim_boundary=CLAIM_BOUNDARY,
    )

    artifacts = {
        "development_contrast_extension.json": canonical_json_bytes(extension.to_dict()),
        "selection_contract.json": canonical_json_bytes(successor_selection.to_dict()),
        "label_space_audit.json": successor_audit_text.encode("utf-8"),
    }
    if (
        "selection_contract.json" in artifacts
        and selection_contract_text.encode("utf-8") != artifacts["selection_contract.json"]
    ):
        raise E1DevelopmentContrastError("selection contract canonical form mismatch")
    return artifacts, extension


def main() -> None:
    args = _parser().parse_args()
    artifacts, _ = compile_extension(
        source_commit=args.source_commit,
        predecessor_audit_path=args.predecessor_audit,
    )

    if args.validate:
        for name, content in artifacts.items():
            path = args.output_directory / name
            if not path.exists() or path.read_bytes() != content:
                print(f"artifact mismatch: {path}", file=sys.stderr)
                raise SystemExit(1)
        print(f"all artifacts verified under {args.output_directory}")
        return

    args.output_directory.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (args.output_directory / name).write_bytes(content)
    print(f"artifacts written under {args.output_directory}")


if __name__ == "__main__":
    main()
