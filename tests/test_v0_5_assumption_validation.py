from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

from csd_foundry.governance.v0_5.assumption_validation import validate_assumption_registry
from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.resources import assumption_vectors

_VALIDATOR_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "csd_foundry"
    / "governance"
    / "v0_5"
    / "assumption_validation.py"
)

# Production governance modules the independent validator must NOT import.
_FORBIDDEN_MODULES = {
    "assumption",
    "_assumption_dependency_validator",
    "_assumption_governance_contracts",
    "_assumption_governance_role_derivation",
    "_assumption_policy_activation_common",
    "_assumption_policy_activation_envelope",
    "_assumption_policy_activation_ledger",
    "_assumption_policy_activation_rules",
    "_assumption_policy_filesystem_publication",
    "_assumption_separation_duty_evaluator",
    "_assumption_use_admissibility",
    "_governed_admit_append",
    "assumption_governance_contracts",
    "assumption_governance_execution_contracts",
    "assumption_policy_filesystem_publication",
    "assumption_policy_resolution",
    "assumption_use_admissibility",
    "assumption_dependency_validator",
    "evidence_governance",
    "evidence",
    "registry",
}


def test_committed_assumption_vectors_validate_independently() -> None:
    report = validate_assumption_registry()

    assert report.success
    assert report.accepted_vector_count == 14
    assert report.rejected_vector_count == 12
    assert len(report.accepted_registry_roots) == 14
    assert len(report.accepted_decision_digests) == 14
    assert len(report.rejected_failure_codes) == 12
    assert report.vector_catalog_digest == (
        "sha256:c0c6bb3e32530848b714f95fe629ea2b5c53d51272a5871a4e867b8d4aaef9ff"
    )
    # Import boundary: the validator must not import any production governance
    # module other than canonicalization, contracts, and resources. The check
    # inspects the imported MODULE name (the final path segment), not the
    # imported member names: ``from csd_foundry.governance.v0_5.foo import Bar``
    # is a violation because of ``foo``, regardless of what ``Bar`` is named.
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


def test_assumption_vector_loader_returns_defensive_copies() -> None:
    first = assumption_vectors()
    second = assumption_vectors()

    first["accepted_vectors"][0]["vector_id"] = "mutated"
    assert second["accepted_vectors"][0]["vector_id"] == "AV-A01"


def test_validator_detects_expected_root_tampering_even_with_recommitted_catalog() -> None:
    vectors = deepcopy(assumption_vectors())
    vectors["accepted_vectors"][0]["expected_registry_root"] = "sha256:" + "0" * 64
    vectors["catalog_digest"] = catalog_digest(vectors, b"ASSUMPTION_VECTOR_CATALOG\0")

    report = validate_assumption_registry(vectors=vectors)

    assert not report.success
    assert any("ASSUMPTION_EXPECTED_ROOT_MISMATCH" in error for error in report.errors)


def test_validator_rejects_unsupported_release() -> None:
    report = validate_assumption_registry("v0.6")

    assert not report.success
    assert "assumption registry validation supports only v0.5" in report.errors
