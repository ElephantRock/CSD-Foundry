"""Deterministic reconstruction tests for the E1 development-contrast extension."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ORCHESTRATION = _REPO_ROOT / "experiments" / "e1" / "compile_development_contrast_extension.py"


def _committed_source_commit() -> str:
    """Read the source commit bound in the committed extension receipt."""

    receipt = json.loads(
        (_REPO_ROOT / "data" / "e1" / "v2" / "development_contrast_extension.json").read_text(
            encoding="utf-8"
        )
    )
    return str(receipt["successor_selection_contract"]["source_commit"])


def _load_orchestration():
    sys.path.insert(0, str(_REPO_ROOT / "src"))
    spec = importlib.util.spec_from_file_location(
        "compile_development_contrast_extension", _ORCHESTRATION
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_all_three_artifacts_byte_identical_on_recompile():
    orchestrator = _load_orchestration()
    artifacts, _ = orchestrator.compile_extension(
        source_commit=_committed_source_commit(),
        predecessor_audit_path=Path("data/e1/v1/label_space_audit.json"),
    )
    for name, content in artifacts.items():
        path = Path("data/e1/v2") / name
        assert path.read_bytes() == content, f"artifact mismatch: {name}"


def test_extension_outcome_is_primary_population_supported():
    orchestrator = _load_orchestration()
    _, extension = orchestrator.compile_extension(
        source_commit=_committed_source_commit(),
        predecessor_audit_path=Path("data/e1/v1/label_space_audit.json"),
    )
    assert extension.extension_outcome == "PRIMARY_POPULATION_SUPPORTED"


def test_oracle_and_verification_receipts_globally_distinct():
    orchestrator = _load_orchestration()
    _, extension = orchestrator.compile_extension(
        source_commit=_committed_source_commit(),
        predecessor_audit_path=Path("data/e1/v1/label_space_audit.json"),
    )
    all_digests = []
    for receipt in extension.transition_receipts:
        all_digests.append(receipt["oracle_receipt_digest"])
        all_digests.append(receipt["independent_verification_receipt_digest"])
    assert len(all_digests) == len(set(all_digests)), "receipt digests must be globally distinct"


def test_successor_training_artifact_semantic_content_matches_predecessor():
    """Training records must remain semantically identical to the predecessor."""
    import sys

    sys.path.insert(0, str(_REPO_ROOT / "src"))
    from csd_foundry.empirical.e1.experiment_contract import compile_e1_experiment_contract
    from csd_foundry.empirical.e1.foundry_artifact_compiler import (
        compile_e1_foundry_artifacts,
    )
    from csd_foundry.scenarios.registry import SCENARIOS

    # Predecessor training bytes.
    base_selection = compile_e1_experiment_contract(
        SCENARIOS.values(),
        release="e1-candidate/1",
        source_commit=_committed_source_commit(),
    )
    base_bundle = compile_e1_foundry_artifacts(
        SCENARIOS,
        base_selection,
        release="e1-foundry-artifacts/1",
        selection_release="e1-candidate/1",
        source_commit=_committed_source_commit(),
    )
    base_train = base_bundle.file("foundry_train.jsonl").content

    # Successor training bytes (overlay catalog; only M-12/M-14 differ, both
    # are validation-split, so training records are unaffected).
    from csd_foundry.empirical.e1.development_contrast_extension import (
        build_e1_development_contrast_catalog,
    )

    overlay_catalog = build_e1_development_contrast_catalog(SCENARIOS)
    successor_selection = compile_e1_experiment_contract(
        overlay_catalog.values(),
        release="e1-candidate/1",
        source_commit=_committed_source_commit(),
    )
    successor_bundle = compile_e1_foundry_artifacts(
        overlay_catalog,
        successor_selection,
        release="e1-foundry-artifacts/1",
        selection_release="e1-candidate/1",
        source_commit=_committed_source_commit(),
    )
    successor_train = successor_bundle.file("foundry_train.jsonl").content

    # Training record content must be byte-identical (training scenarios unchanged).
    assert base_train == successor_train
    assert successor_bundle.training_record_count == base_bundle.training_record_count == 19
