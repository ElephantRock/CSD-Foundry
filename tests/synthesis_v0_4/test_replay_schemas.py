from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC_ROOT = ROOT / "specs" / "v0.4"
REPLAY_SCHEMAS = (
    "replay_policy.schema.json",
    "attempt_input.schema.json",
    "search_branch.schema.json",
    "choice_record.schema.json",
    "choice_ledger.schema.json",
    "attempt_replay.schema.json",
    "exhaustion_evidence.schema.json",
)


def test_replay_schemas_are_strict_draft_2020_12_documents() -> None:
    for name in REPLAY_SCHEMAS:
        schema = json.loads((SPEC_ROOT / name).read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"


def test_replay_contract_schemas_freeze_record_versions() -> None:
    expected_versions = {
        "attempt_input.schema.json": "csd-attempt-input/0.4",
        "search_branch.schema.json": "csd-search-branch/0.4",
        "choice_record.schema.json": "csd-choice-record/0.4",
        "choice_ledger.schema.json": "csd-choice-ledger/0.4",
        "attempt_replay.schema.json": "csd-attempt-replay/0.4",
        "exhaustion_evidence.schema.json": "csd-exhaustion-evidence/0.4",
    }
    for name, version in expected_versions.items():
        text = (SPEC_ROOT / name).read_text(encoding="utf-8")
        assert version in text
