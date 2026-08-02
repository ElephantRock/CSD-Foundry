"""Independent runtime validation for the executable v0.5 contract layer."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    canonical_bytes,
    catalog_digest,
)
from csd_foundry.governance.v0_5.contracts import (
    CONTRACT_TYPES,
    ContractObject,
    build_contract,
    contract_entry,
    contract_schema,
    parse_contract,
)
from csd_foundry.governance.v0_5.resources import (
    api_contracts,
    canonicalization_policy,
    charter_invariants,
    contract_catalog,
    contract_vectors,
    projection_phase_policy,
    rejection_code_registry,
)

_PHASES = [
    "SEMANTIC",
    "EVIDENCE_REGISTRY",
    "ASSUMPTION_REGISTRY",
    "ALTERNATIVE_MODEL_REGISTRY",
    "DISPOSITION",
    "QUARANTINE_COMMIT",
]
_INVARIANTS = {
    "TEMP-SAFE-01",
    "RAP-SAFE-01",
    "REL-ARCH-01",
    "VAL-SAFE-01",
    "RAP-INV-01",
    "RAP-INV-02",
}


@dataclass(frozen=True, slots=True)
class GovernanceContractValidationReport:
    contract_count: int
    canonicalization_vector_count: int
    contract_vector_count: int
    invalid_vector_count: int
    catalog_digest: object
    vector_catalog_digest: object
    charter_invariants: tuple[str, ...]
    projection_phases: tuple[str, ...]
    release_compilation_event_triggered: bool
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "canonicalization_vector_count": self.canonicalization_vector_count,
            "catalog_digest": self.catalog_digest,
            "charter_invariants": list(self.charter_invariants),
            "claim_boundary": (
                "This report establishes schema, canonical-byte, digest-domain, selected "
                "cross-field, and frozen-policy consistency. It does not establish production "
                "storage atomicity, cryptographic key validity, external truth, or production safety."
            ),
            "contract_count": self.contract_count,
            "contract_vector_count": self.contract_vector_count,
            "errors": list(self.errors),
            "invalid_vector_count": self.invalid_vector_count,
            "projection_phases": list(self.projection_phases),
            "release_compilation_event_triggered": self.release_compilation_event_triggered,
            "schema_version": "contract-freeze-validation-report/0.5",
            "status": "valid" if self.success else "invalid",
            "vector_catalog_digest": self.vector_catalog_digest,
        }


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    if not reference.startswith("#/"):
        raise GovernanceContractError("EXTERNAL_SCHEMA_REFERENCE_PROHIBITED")
    value: Any = root
    for part in reference[2:].split("/"):
        value = value[part]
    if type(value) is not dict:
        raise GovernanceContractError("SCHEMA_REFERENCE_NOT_OBJECT")
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
        return {name: _fixture(properties[name], root) for name in schema.get("required", [])}
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
    raise GovernanceContractError("FIXTURE_TYPE_UNSUPPORTED", str(type_name))


def generated_contract_fixture(name: str) -> ContractObject:
    schema = contract_schema(name)
    fixture = _fixture(schema, schema)
    if type(fixture) is not dict:
        raise GovernanceContractError("CONTRACT_FIXTURE_NOT_OBJECT", name)
    entry = contract_entry(name)
    fixture.pop(entry.digest_field, None)
    return build_contract(name, fixture)


def validate_governance_contracts(release: str = "v0.5") -> GovernanceContractValidationReport:
    errors: list[str] = []
    catalog = contract_catalog()
    vectors = contract_vectors()
    policy = canonicalization_policy()
    phases = projection_phase_policy()
    invariants = charter_invariants()
    codes = rejection_code_registry()
    apis = api_contracts()

    if release != "v0.5":
        errors.append("governance contracts support only v0.5")
    if catalog.get("catalog_digest") != catalog_digest(catalog, b"CONTRACT_CATALOG\0"):
        errors.append("contract catalog digest changed")
    if vectors.get("catalog_digest") != catalog_digest(vectors, b"CONTRACT_VECTOR_CATALOG\0"):
        errors.append("vector catalog digest changed")
    if catalog.get("status") != "FROZEN_FOR_IMPLEMENTATION":
        errors.append("catalog is not frozen")
    if (
        policy.get("object_field_order") != "SCHEMA_VERSION_FIRST_THEN_ASCENDING_UTF8_KEY_BYTES"
        or policy.get("number_policy") != "EXACT_INTEGERS_ONLY"
    ):
        errors.append("canonical policy changed")
    if (
        phases.get("ordered_phases") != _PHASES
        or phases.get("release_compilation_phase") is not None
        or phases.get("release_compilation_rule") != "EVENT_TRIGGERED_AFTER_COMPLETED_SNAPSHOT"
    ):
        errors.append("projection or release policy changed")

    actual_invariants = {item["invariant_id"] for item in invariants.get("invariants", [])}
    if actual_invariants != _INVARIANTS:
        errors.append("charter invariant registry changed")
    code_values = [item["code"] for item in codes.get("codes", [])]
    if len(code_values) != len(set(code_values)):
        errors.append("duplicate rejection codes")
    api_values = [item["api_id"] for item in apis.get("apis", [])]
    if len(api_values) != len(set(api_values)):
        errors.append("duplicate API ids")

    generated: dict[str, ContractObject] = {}
    expected_digests = vectors.get("contract_fixture_digests", {})
    for name in CONTRACT_TYPES:
        try:
            contract = generated_contract_fixture(name)
            generated[name] = contract
            if expected_digests.get(name) != contract.digest:
                errors.append(f"{name}: frozen generated-fixture digest changed")
            if (
                parse_contract(name, contract.to_json_value()).canonical_bytes
                != contract.canonical_bytes
            ):
                errors.append(f"{name}: parse/build canonical bytes diverged")
        except Exception as exc:
            errors.append(f"{name}: generated accepted fixture rejected: {exc}")

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
                mutated = deepcopy(generated[name].to_json_value())
                mutated.update(vector["mutations"])
                parse_contract(name, mutated)
        except GovernanceContractError as exc:
            observed = exc.code
        except ValidationError:
            observed = "SCHEMA_REJECTED"
        if observed != vector["expected_error"]:
            errors.append(
                f"{vector['vector_id']}: expected {vector['expected_error']}, "
                f"observed {observed or 'ACCEPTED'}"
            )

    if set(expected_digests) != set(CONTRACT_TYPES):
        errors.append("fixture digest catalog does not cover exactly every contract")
    if len(CONTRACT_TYPES) != len(catalog.get("contracts", [])):
        errors.append("typed contract registry does not cover exactly every catalog contract")

    return GovernanceContractValidationReport(
        contract_count=len(CONTRACT_TYPES),
        canonicalization_vector_count=len(vectors.get("canonicalization_vectors", [])),
        contract_vector_count=len(expected_digests),
        invalid_vector_count=len(vectors.get("invalid_vectors", [])),
        catalog_digest=catalog.get("catalog_digest"),
        vector_catalog_digest=vectors.get("catalog_digest"),
        charter_invariants=tuple(sorted(actual_invariants)),
        projection_phases=tuple(phases.get("ordered_phases", [])),
        release_compilation_event_triggered=phases.get("release_compilation_phase") is None,
        errors=tuple(errors),
    )
