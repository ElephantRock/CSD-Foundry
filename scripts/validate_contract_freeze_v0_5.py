#!/usr/bin/env python3
"""Validate frozen CSD Foundry v0.5 foundational contracts."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


class ContractFreezeError(ValueError):
    """Raised when frozen contract evidence is invalid."""


PHASES = [
    "SEMANTIC",
    "EVIDENCE_REGISTRY",
    "ASSUMPTION_REGISTRY",
    "ALTERNATIVE_MODEL_REGISTRY",
    "DISPOSITION",
    "QUARANTINE_COMMIT",
]
INVARIANTS = {
    "TEMP-SAFE-01",
    "RAP-SAFE-01",
    "REL-ARCH-01",
    "VAL-SAFE-01",
    "RAP-INV-01",
    "RAP-INV-02",
}
RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _ordered_keys(value: dict[str, Any]) -> list[str]:
    keys = list(value)
    first: list[str] = []
    if "schema_version" in keys:
        first.append("schema_version")
        keys.remove("schema_version")
    return first + sorted(keys, key=lambda key: key.encode("utf-8"))


def _normalize(value: Any, schema: dict[str, Any]) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        raise ContractFreezeError("FLOAT_PROHIBITED")
    if isinstance(value, dict):
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        return {
            key: _normalize(value[key], properties.get(key, {}))
            for key in _ordered_keys(value)
        }
    if isinstance(value, list):
        item_schema = schema.get("items", {}) if isinstance(schema, dict) else {}
        items = [_normalize(item, item_schema) for item in value]
        kind = schema.get("x-csd-collection-kind", "ORDERED_SEQUENCE")
        if kind in {"SET", "MULTISET"}:
            keyed = sorted(
                (
                    json.dumps(
                        item, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8"),
                    item,
                )
                for item in items
            )
            if kind == "SET" and any(
                previous[0] == current[0]
                for previous, current in zip(keyed, keyed[1:], strict=False)
            ):
                raise ContractFreezeError("DUPLICATE_SET_MEMBER")
            return [item for _, item in keyed]
        if kind != "ORDERED_SEQUENCE":
            raise ContractFreezeError(f"UNKNOWN_COLLECTION_KIND:{kind}")
        return items
    raise ContractFreezeError(f"UNSUPPORTED_TYPE:{type(value).__qualname__}")


def canonical_bytes(value: Any, schema: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            _normalize(value, schema),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def domain_digest(
    value: dict[str, Any], schema: dict[str, Any], field: str, prefix: str
) -> str:
    unsigned = deepcopy(value)
    unsigned.pop(field, None)
    payload = prefix.encode("utf-8") + canonical_bytes(unsigned, schema)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _catalog_digest(value: dict[str, Any], domain: bytes) -> str:
    unsigned = deepcopy(value)
    unsigned.pop("catalog_digest", None)
    payload = (
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain + payload).hexdigest()


def _check_arrays(node: Any, path: str, errors: list[str]) -> None:
    if not isinstance(node, dict):
        return
    if node.get("type") == "array" and node.get("x-csd-collection-kind") not in {
        "SET",
        "MULTISET",
        "ORDERED_SEQUENCE",
    }:
        errors.append(f"{path}: array lacks collection kind")
    for keyword in ("properties", "$defs"):
        for name, child in node.get(keyword, {}).items():
            _check_arrays(child, f"{path}/{keyword}/{name}", errors)
    for keyword in ("items", "additionalProperties"):
        if isinstance(node.get(keyword), dict):
            _check_arrays(node[keyword], f"{path}/{keyword}", errors)
    for keyword in ("allOf", "anyOf", "oneOf"):
        for index, child in enumerate(node.get(keyword, [])):
            _check_arrays(child, f"{path}/{keyword}/{index}", errors)


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    if not reference.startswith("#/"):
        raise ContractFreezeError("EXTERNAL_SCHEMA_REFERENCE_PROHIBITED")
    value: Any = root
    for part in reference[2:].split("/"):
        value = value[part]
    return value


def _fixture(schema: dict[str, Any], root: dict[str, Any]) -> Any:
    schema = _resolve(schema, root)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    for choice_keyword in ("anyOf", "oneOf"):
        if choice_keyword in schema:
            choices = schema[choice_keyword]
            selected = next(
                (choice for choice in choices if _resolve(choice, root).get("type") != "null"),
                choices[0],
            )
            return _fixture(selected, root)
    type_name = schema.get("type")
    if isinstance(type_name, list):
        type_name = next(item for item in type_name if item != "null")
    if type_name == "object" or "properties" in schema:
        properties = schema.get("properties", {})
        return {
            name: _fixture(properties[name], root)
            for name in schema.get("required", [])
        }
    if type_name == "array":
        count = max(1, schema.get("minItems", 0))
        return [_fixture(schema.get("items", {}), root) for _ in range(count)]
    if type_name == "integer":
        return schema.get("minimum", 0)
    if type_name == "boolean":
        return False
    if type_name == "null":
        return None
    if type_name == "string" or type_name is None:
        pattern = schema.get("pattern", "")
        if "sha256:" in pattern:
            return "sha256:" + "0" * 64
        minimum = max(1, schema.get("minLength", 1))
        return "x" * minimum
    raise ContractFreezeError(f"FIXTURE_TYPE_UNSUPPORTED:{type_name}")


def _semantic_validate(name: str, value: dict[str, Any]) -> None:
    if name in {"clock-claim", "clock-projection-failure"} and value[
        "proposed_sequence"
    ] != value["previous_committed_sequence"] + 1:
        raise ContractFreezeError("CLOCK_SEQUENCE_NOT_SUCCESSOR")
    if name == "clock-projection-failure" and value[
        "recorded_against_tick"
    ] != value["previous_committed_sequence"]:
        raise ContractFreezeError("FAILURE_CONTEXT_TICK_MISMATCH")
    if (
        name == "semantic-projection-receipt"
        and value["projection_result"] != "COMPLETED"
    ):
        raise ContractFreezeError("SEMANTIC_PROJECTION_NOT_COMPLETED")
    if name == "validated-event" and value["validation_result"] != "ACCEPTED":
        raise ContractFreezeError("VALIDATION_RESULT_NOT_ACCEPTED")
    if name == "release-manifest" and RANK[value["release_class"]] > RANK[
        value["maximum_reuse_class"]
    ]:
        raise ContractFreezeError("REUSE_CLASS_BELOW_RELEASE_CLASS")


def validate(root: Path) -> dict[str, Any]:
    errors: list[str] = []
    spec = root / "specs/v0.5"
    vectors = _load(root / "data/canary/v0.5/contract-v1/contract_vectors.json")
    catalog = _load(spec / "contract_catalog_v1.json")
    policy = _load(spec / "canonicalization_policy_v1.json")
    phases = _load(spec / "projection_phase_order_v1.json")
    invariants = _load(spec / "charter_invariants_v1.json")
    codes = _load(spec / "rejection_code_registry_v1.json")
    apis = _load(spec / "api_contracts_v1.json")

    if catalog.get("catalog_digest") != _catalog_digest(
        catalog, b"CONTRACT_CATALOG\0"
    ):
        errors.append("contract catalog digest changed")
    if vectors.get("catalog_digest") != _catalog_digest(
        vectors, b"CONTRACT_VECTOR_CATALOG\0"
    ):
        errors.append("vector catalog digest changed")
    if catalog.get("status") != "FROZEN_FOR_IMPLEMENTATION":
        errors.append("catalog is not frozen")
    if (
        policy.get("object_field_order")
        != "SCHEMA_VERSION_FIRST_THEN_ASCENDING_UTF8_KEY_BYTES"
        or policy.get("number_policy") != "EXACT_INTEGERS_ONLY"
    ):
        errors.append("canonical policy changed")
    if (
        phases.get("ordered_phases") != PHASES
        or phases.get("release_compilation_phase") is not None
        or phases.get("release_compilation_rule")
        != "EVENT_TRIGGERED_AFTER_COMPLETED_SNAPSHOT"
    ):
        errors.append("projection or release policy changed")

    actual_invariants = {
        item["invariant_id"] for item in invariants.get("invariants", [])
    }
    if actual_invariants != INVARIANTS:
        errors.append("charter invariant registry changed")
    code_values = [item["code"] for item in codes.get("codes", [])]
    if len(code_values) != len(set(code_values)):
        errors.append("duplicate rejection codes")
    api_values = [item["api_id"] for item in apis.get("apis", [])]
    if len(api_values) != len(set(api_values)):
        errors.append("duplicate API ids")

    schemas: dict[str, dict[str, Any]] = {}
    entries: dict[str, dict[str, Any]] = {}
    generated: dict[str, dict[str, Any]] = {}
    for entry in catalog.get("contracts", []):
        name = entry["name"]
        entries[name] = entry
        path = root / entry["schema_path"]
        if not path.is_file():
            errors.append(f"missing schema: {entry['schema_path']}")
            continue
        schema = _load(path)
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            errors.append(f"{name}: invalid schema: {exc}")
            continue
        _check_arrays(schema.get("properties", {}), name, errors)
        actual_version = (
            schema.get("properties", {}).get("schema_version", {}).get("const")
        )
        if actual_version != entry["schema_version"]:
            errors.append(f"{name}: version mismatch")
        schemas[name] = schema
        fixture = _fixture(schema, schema)
        fixture[entry["digest_field"]] = domain_digest(
            fixture, schema, entry["digest_field"], entry["domain_prefix"]
        )
        try:
            Draft202012Validator(schema).validate(fixture)
            _semantic_validate(name, fixture)
        except Exception as exc:
            errors.append(f"{name}: generated accepted fixture rejected: {exc}")
        generated[name] = fixture

    expected_digests = vectors.get("contract_fixture_digests", {})
    for name, fixture in generated.items():
        entry = entries[name]
        digest = domain_digest(
            fixture, schemas[name], entry["digest_field"], entry["domain_prefix"]
        )
        if expected_digests.get(name) != digest:
            errors.append(f"{name}: frozen generated-fixture digest changed")

    for vector in vectors.get("canonicalization_vectors", []):
        try:
            actual = canonical_bytes(vector["value"], vector["schema"])
            expected = base64.b64decode(vector["expected_canonical_utf8_base64"])
            if actual != expected:
                errors.append(f"{vector['vector_id']}: canonical bytes changed")
        except Exception as exc:
            errors.append(f"{vector['vector_id']}: {exc}")

    for vector in vectors.get("invalid_vectors", []):
        observed: str | None = None
        try:
            if vector["kind"] == "canonicalization":
                canonical_bytes(vector["value"], vector["schema"])
            else:
                name = vector["contract_name"]
                mutated = deepcopy(generated[name])
                mutated.update(vector["mutations"])
                Draft202012Validator(schemas[name]).validate(mutated)
                if vector["kind"] == "semantic":
                    _semantic_validate(name, mutated)
        except ContractFreezeError as exc:
            observed = str(exc)
        except ValidationError:
            observed = "SCHEMA_REJECTED"
        if observed != vector["expected_error"]:
            errors.append(
                f"{vector['vector_id']}: expected {vector['expected_error']}, "
                f"observed {observed or 'ACCEPTED'}"
            )

    if set(expected_digests) != set(schemas):
        errors.append("fixture digest catalog does not cover exactly every contract")
    if len(schemas) != len(catalog.get("contracts", [])):
        errors.append("not every catalog contract has a valid schema")

    return {
        "schema_version": "contract-freeze-validation-report/0.5",
        "status": "valid" if not errors else "invalid",
        "contract_count": len(schemas),
        "canonicalization_vector_count": len(
            vectors.get("canonicalization_vectors", [])
        ),
        "contract_vector_count": len(expected_digests),
        "invalid_vector_count": len(vectors.get("invalid_vectors", [])),
        "catalog_digest": catalog.get("catalog_digest"),
        "vector_catalog_digest": vectors.get("catalog_digest"),
        "charter_invariants": sorted(actual_invariants),
        "projection_phases": phases.get("ordered_phases"),
        "release_compilation_event_triggered": phases.get(
            "release_compilation_phase"
        )
        is None,
        "errors": errors,
        "claim_boundary": (
            "This report establishes schema, canonical-byte, digest-domain, selected "
            "cross-field, and frozen-policy consistency. It does not establish production "
            "storage atomicity, cryptographic key validity, external truth, or production safety."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    report = validate(args.root)
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["status"] == "valid" else 1)


if __name__ == "__main__":
    main()
