from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

from csd_foundry.governance.v0_5.alternative_model_validation import (
    validate_alternative_model_registry,
)
from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.resources import alternative_model_vectors

_VALIDATOR_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "csd_foundry"
    / "governance"
    / "v0_5"
    / "alternative_model_validation.py"
)

# Production governance modules the independent validator must NOT import.
_FORBIDDEN_MODULES = {
    "alternative_model",
    "_governed_alternative_model",
    "governed_alternative_model",
    "_alternative_model_projection",
    "alternative_model_projection",
    "alternative_model_mutations",
    "alternative_model_validation_cli",
    "alternative_model_mutation_cli",
    "registry",
    "assumption",
    "_assumption_projection",
    "assumption_validation",
    "evidence",
    "evidence_validation",
}


def test_committed_alternative_model_vectors_validate_independently() -> None:
    report = validate_alternative_model_registry()

    assert report.success
    assert report.accepted_vector_count == 11
    assert report.rejected_vector_count == 10
    assert len(report.accepted_registry_roots) == 11
    assert len(report.rejected_failure_codes) == 10
    assert report.vector_catalog_digest == (
        "sha256:ff521c8095c662a07be5e7dc798e37cc6be73964e2b489dfabcaa1e3e26b3b3f"
    )
    # Import boundary: the validator must not import any production governance
    # module other than canonicalization, contracts, and resources.
    tree = ast.parse(_VALIDATOR_PATH.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("csd_foundry.governance.v0_5.")
        ):
            imported.add(node.module.rsplit(".", 1)[-1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("csd_foundry.governance.v0_5."):
                    imported.add(alias.name.rsplit(".", 1)[-1])
    assert imported, "expected the validator to import at least one governance module"
    forbidden = imported & _FORBIDDEN_MODULES
    assert not forbidden, f"validator imports forbidden production modules: {forbidden}"


def test_alternative_model_vector_loader_returns_defensive_copies() -> None:
    first = alternative_model_vectors()
    second = alternative_model_vectors()

    first["accepted_vectors"][0]["vector_id"] = "mutated"
    assert second["accepted_vectors"][0]["vector_id"] == "AMV-A01"


def test_validator_detects_expected_root_tampering_even_with_recommitted_catalog() -> None:
    vectors = deepcopy(alternative_model_vectors())
    vectors["accepted_vectors"][0]["expected_registry_root"] = "sha256:" + "0" * 64
    vectors["catalog_digest"] = catalog_digest(vectors, b"ALTERNATIVE_MODEL_VECTOR_CATALOG\0")

    report = validate_alternative_model_registry(vectors=vectors)

    assert not report.success
    assert any("ALTERNATIVE_MODEL_EXPECTED_ROOT_MISMATCH" in error for error in report.errors)


def test_validator_rejects_unsupported_release() -> None:
    report = validate_alternative_model_registry("v0.6")

    assert not report.success
    assert "alternative model registry validation supports only v0.5" in report.errors
