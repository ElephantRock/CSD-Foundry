#!/usr/bin/env python3
"""Validate generated CSD reasoning seed files and their manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: record is not an object")
            records.append(value)
    return records


def validate_unique_ids(records: list[dict[str, object]], label: str) -> None:
    counts = Counter(str(record.get("id")) for record in records)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    if duplicates:
        raise ValueError(f"{label}: duplicate ids: {duplicates[:5]}")


def validate_split_isolation(records: list[dict[str, object]], label: str) -> None:
    by_scenario: dict[str, set[str]] = defaultdict(set)
    for record in records:
        by_scenario[str(record["source_scenario"])].add(str(record["split"]))
    leaking = {key: sorted(value) for key, value in by_scenario.items() if len(value) != 1}
    if leaking:
        raise ValueError(f"{label}: scenario leakage: {leaking}")


def validate_sft(records: list[dict[str, object]]) -> None:
    validate_unique_ids(records, "sft")
    validate_split_isolation(records, "sft")
    required = {
        "schema_version",
        "dataset_version",
        "id",
        "split",
        "synthetic",
        "task_type",
        "scenario_family",
        "source_scenario",
        "messages",
        "expected",
        "provenance",
    }
    for record in records:
        missing = required - record.keys()
        if missing:
            raise ValueError(f"{record.get('id')}: missing fields {sorted(missing)}")
        if record["synthetic"] is not True:
            raise ValueError(f"{record['id']}: synthetic flag is not true")
        messages = record["messages"]
        if not isinstance(messages, list):
            raise ValueError(f"{record['id']}: messages is not a list")
        if [message.get("role") for message in messages] != ["system", "user", "assistant"]:
            raise ValueError(f"{record['id']}: invalid message roles")
        if any(not str(message.get("content", "")).strip() for message in messages):
            raise ValueError(f"{record['id']}: empty message content")
        expected = record["expected"]
        if not isinstance(expected, dict) or not expected.get("rule_ids"):
            raise ValueError(f"{record['id']}: expected rule_ids missing")


def validate_preferences(records: list[dict[str, object]]) -> None:
    validate_unique_ids(records, "preference")
    validate_split_isolation(records, "preference")
    for record in records:
        if record.get("synthetic") is not True:
            raise ValueError(f"{record.get('id')}: synthetic flag is not true")
        prompt_messages = record.get("prompt_messages")
        if not isinstance(prompt_messages, list) or [
            message.get("role") for message in prompt_messages
        ] != ["system", "user"]:
            raise ValueError(f"{record.get('id')}: invalid preference prompt")
        chosen = str(record.get("chosen", ""))
        rejected = str(record.get("rejected", ""))
        if not chosen or not rejected or chosen == rejected:
            raise ValueError(f"{record.get('id')}: invalid preference pair")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parent,
    )
    args = parser.parse_args()
    manifest_path = args.directory / "csd_reasoning_manifest_v0.1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sft_path = args.directory / manifest["sft"]["file"]
    preference_path = args.directory / manifest["preference"]["file"]
    sft = load_jsonl(sft_path)
    preferences = load_jsonl(preference_path)

    validate_sft(sft)
    validate_preferences(preferences)
    if len(sft) != manifest["sft"]["records"]:
        raise ValueError("SFT record count does not match manifest")
    if len(preferences) != manifest["preference"]["records"]:
        raise ValueError("preference record count does not match manifest")
    if sha256_file(sft_path) != manifest["sft"]["sha256"]:
        raise ValueError("SFT digest does not match manifest")
    if sha256_file(preference_path) != manifest["preference"]["sha256"]:
        raise ValueError("preference digest does not match manifest")

    print(
        json.dumps(
            {
                "status": "valid",
                "sft_records": len(sft),
                "preference_records": len(preferences),
                "sft_splits": dict(Counter(record["split"] for record in sft)),
                "preference_splits": dict(Counter(record["split"] for record in preferences)),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
