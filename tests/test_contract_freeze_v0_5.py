from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_contract_freeze_v0_5",
    ROOT / "scripts/validate_contract_freeze_v0_5.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_contract_freeze_v0_5() -> None:
    report = MODULE.validate(ROOT)
    assert report["status"] == "valid", report["errors"]
    assert report["contract_count"] == 16
    assert report["contract_vector_count"] == 16
    assert report["invalid_vector_count"] == 5
    assert report["release_compilation_event_triggered"] is True
