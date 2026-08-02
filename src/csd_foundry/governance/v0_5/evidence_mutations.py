"""Deterministic serialized-artifact mutation campaign for v0.5-D2 evidence assurance."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    catalog_digest,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.evidence_validation import (
    EvidenceRegistryValidationReport,
    validate_evidence_registry,
)
from csd_foundry.governance.v0_5.resources import (
    evidence_mutation_manifest,
    evidence_vectors,
)

_VECTOR_CATALOG_DOMAIN = b"EVIDENCE_VECTOR_CATALOG\0"
_MUTATION_CATALOG_DOMAIN = b"EVIDENCE_MUTATION_CATALOG\0"
_MUTATION_CLASSES = {"KILLED", "SURVIVED", "EQUIVALENT", "INVALID_MUTATION"}
_MODES = {"REJECTED", "ACCEPTED_ERROR", "CATALOG_ERROR"}
_ZERO_DIGEST = "sha256:" + ("0" * 64)


class EvidenceMutationError(RuntimeError):
    """Stable mutation-campaign construction or evaluation failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class EvidenceMutationResult:
    mutation_id: str
    family: str
    baseline_vector_id: str
    operator: str
    expected_classification: str
    observed_classification: str
    expected_detector: str
    observed_detector: str | None
    specimen_digest: str | None
    mutated_catalog_digest: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_vector_id": self.baseline_vector_id,
            "expected_classification": self.expected_classification,
            "expected_detector": self.expected_detector,
            "family": self.family,
            "mutated_catalog_digest": self.mutated_catalog_digest,
            "mutation_id": self.mutation_id,
            "observed_classification": self.observed_classification,
            "observed_detector": self.observed_detector,
            "operator": self.operator,
            "specimen_digest": self.specimen_digest,
        }


@dataclass(frozen=True, slots=True)
class EvidenceMutationReport:
    baseline_vector_catalog_digest: str | None
    mutation_catalog_digest: str | None
    results: tuple[EvidenceMutationResult, ...]
    errors: tuple[str, ...]

    @property
    def killed_count(self) -> int:
        return sum(item.observed_classification == "KILLED" for item in self.results)

    @property
    def survived_count(self) -> int:
        return sum(item.observed_classification == "SURVIVED" for item in self.results)

    @property
    def equivalent_count(self) -> int:
        return sum(item.observed_classification == "EQUIVALENT" for item in self.results)

    @property
    def invalid_mutation_count(self) -> int:
        return sum(item.observed_classification == "INVALID_MUTATION" for item in self.results)

    @property
    def unexplained_escape_count(self) -> int:
        return self.survived_count + self.invalid_mutation_count

    @property
    def success(self) -> bool:
        return not self.errors and self.unexplained_escape_count == 0

    def _unsigned_value(self) -> dict[str, object]:
        matrix = {
            item.mutation_id: {
                "baseline_vector_id": item.baseline_vector_id,
                "expected_classification": item.expected_classification,
                "expected_detector": item.expected_detector,
                "family": item.family,
                "mutated_catalog_digest": item.mutated_catalog_digest,
                "observed_classification": item.observed_classification,
                "observed_detector": item.observed_detector,
                "operator": item.operator,
                "specimen_digest": item.specimen_digest,
            }
            for item in self.results
        }
        return {
            "schema_version": "evidence-mutation-report/0.5",
            "baseline_vector_catalog_digest": self.baseline_vector_catalog_digest,
            "declared_mutation_count": len(self.results),
            "equivalent_count": self.equivalent_count,
            "errors": list(self.errors),
            "invalid_mutation_count": self.invalid_mutation_count,
            "kill_matrix": matrix,
            "killed_count": self.killed_count,
            "mutation_catalog_digest": self.mutation_catalog_digest,
            "status": "valid" if self.success else "invalid",
            "survived_count": self.survived_count,
            "unexplained_escape_count": self.unexplained_escape_count,
            "claim_boundary": (
                "This report establishes that the declared serialized evidence mutations are "
                "detected relative to the committed evidence-v1 corpus and independent validator. "
                "It does not establish completeness of the mutation space, external truth, "
                "real-world dependency completeness, or production safety."
            ),
        }

    @property
    def report_digest(self) -> str:
        return _domain_digest("EVIDENCE_MUTATION_REPORT", self._unsigned_value())

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_value(), "report_digest": self.report_digest}


def evaluate_evidence_mutations(
    release: str = "v0.5",
    *,
    manifest: dict[str, Any] | None = None,
    vectors: dict[str, Any] | None = None,
) -> EvidenceMutationReport:
    errors: list[str] = []
    campaign = evidence_mutation_manifest() if manifest is None else deepcopy(manifest)
    baseline = evidence_vectors() if vectors is None else deepcopy(vectors)
    mutation_specs: list[dict[str, Any]] = []

    if release != "v0.5":
        errors.append("evidence mutation assurance supports only v0.5")

    try:
        mutation_specs = _validate_campaign(campaign, baseline)
    except (EvidenceMutationError, GovernanceContractError) as exc:
        errors.append(str(exc))

    baseline_report = validate_evidence_registry(release=release, vectors=baseline)
    if not baseline_report.success:
        errors.append("baseline evidence vector catalog is not valid")

    results: list[EvidenceMutationResult] = []
    for spec in mutation_specs:
        try:
            result = _evaluate_mutation(spec, baseline)
        except (EvidenceMutationError, GovernanceContractError, KeyError, TypeError) as exc:
            result = EvidenceMutationResult(
                mutation_id=_string_or_placeholder(spec.get("mutation_id"), "UNKNOWN-MUTATION"),
                family=_string_or_placeholder(spec.get("family"), "UNKNOWN_FAMILY"),
                baseline_vector_id=_string_or_placeholder(
                    spec.get("baseline_vector_id"),
                    "UNKNOWN-VECTOR",
                ),
                operator=_string_or_placeholder(spec.get("operator"), "UNKNOWN_OPERATOR"),
                expected_classification=_string_or_placeholder(
                    spec.get("expected_classification"),
                    "KILLED",
                ),
                observed_classification="INVALID_MUTATION",
                expected_detector=_string_or_placeholder(
                    spec.get("expected_detector"),
                    "UNKNOWN_DETECTOR",
                ),
                observed_detector=getattr(exc, "code", type(exc).__name__),
                specimen_digest=None,
                mutated_catalog_digest=None,
            )
        results.append(result)
        if result.observed_classification != result.expected_classification:
            errors.append(
                f"{result.mutation_id}: expected {result.expected_classification}, "
                f"observed {result.observed_classification}"
            )
        elif result.observed_detector != result.expected_detector:
            errors.append(
                f"{result.mutation_id}: expected detector {result.expected_detector}, "
                f"observed {result.observed_detector or 'NONE'}"
            )

    baseline_digest = baseline.get("catalog_digest")
    mutation_digest = campaign.get("catalog_digest")
    return EvidenceMutationReport(
        baseline_vector_catalog_digest=(
            cast(str, baseline_digest) if type(baseline_digest) is str else None
        ),
        mutation_catalog_digest=(
            cast(str, mutation_digest) if type(mutation_digest) is str else None
        ),
        results=tuple(results),
        errors=tuple(errors),
    )


def _validate_campaign(
    campaign: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    if type(campaign) is not dict:
        raise EvidenceMutationError("EVIDENCE_MUTATION_MANIFEST_NOT_OBJECT")
    if campaign.get("schema_version") != "evidence-mutation-campaign/1":
        raise EvidenceMutationError("EVIDENCE_MUTATION_MANIFEST_SCHEMA_INVALID")
    if campaign.get("mutation_version") != 1:
        raise EvidenceMutationError("EVIDENCE_MUTATION_VERSION_INVALID")
    if campaign.get("baseline_vector_catalog_digest") != baseline.get("catalog_digest"):
        raise EvidenceMutationError("EVIDENCE_MUTATION_BASELINE_DIGEST_MISMATCH")
    expected_catalog_digest = catalog_digest(campaign, _MUTATION_CATALOG_DOMAIN)
    if campaign.get("catalog_digest") != expected_catalog_digest:
        raise EvidenceMutationError("EVIDENCE_MUTATION_CATALOG_DIGEST_MISMATCH")
    classifications = campaign.get("classification_values")
    if classifications != ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"]:
        raise EvidenceMutationError("EVIDENCE_MUTATION_CLASSIFICATIONS_INVALID")
    raw_specs = campaign.get("mutations")
    if type(raw_specs) is not list or not raw_specs:
        raise EvidenceMutationError("EVIDENCE_MUTATION_INVENTORY_INVALID")
    specs = [cast(dict[str, Any], item) for item in raw_specs if type(item) is dict]
    if len(specs) != len(raw_specs):
        raise EvidenceMutationError("EVIDENCE_MUTATION_SPEC_NOT_OBJECT")
    identifiers = [_required_string(item, "mutation_id") for item in specs]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
        raise EvidenceMutationError("EVIDENCE_MUTATION_IDS_NOT_CANONICAL")
    for spec in specs:
        if set(spec) != {
            "baseline_vector_id",
            "expected_classification",
            "expected_detector",
            "family",
            "mode",
            "mutation_id",
            "operator",
            "parameters",
        }:
            raise EvidenceMutationError(
                "EVIDENCE_MUTATION_SPEC_KEYS_INVALID",
                _required_string(spec, "mutation_id"),
            )
        if _required_string(spec, "expected_classification") not in _MUTATION_CLASSES:
            raise EvidenceMutationError("EVIDENCE_MUTATION_CLASSIFICATION_INVALID")
        if _required_string(spec, "mode") not in _MODES:
            raise EvidenceMutationError("EVIDENCE_MUTATION_MODE_INVALID")
        if type(spec.get("parameters")) is not dict:
            raise EvidenceMutationError("EVIDENCE_MUTATION_PARAMETERS_INVALID")
        _required_string(spec, "family")
        _required_string(spec, "baseline_vector_id")
        _required_string(spec, "operator")
        _required_string(spec, "expected_detector")
    return specs


def _evaluate_mutation(
    spec: dict[str, Any],
    baseline: dict[str, Any],
) -> EvidenceMutationResult:
    mutation_id = _required_string(spec, "mutation_id")
    family = _required_string(spec, "family")
    baseline_vector_id = _required_string(spec, "baseline_vector_id")
    operator = _required_string(spec, "operator")
    mode = _required_string(spec, "mode")
    expected_classification = _required_string(spec, "expected_classification")
    expected_detector = _required_string(spec, "expected_detector")
    parameters = cast(dict[str, Any], spec["parameters"])

    mutated = _mutate_catalog(
        baseline,
        mutation_id=mutation_id,
        baseline_vector_id=baseline_vector_id,
        operator=operator,
        mode=mode,
        expected_detector=expected_detector,
        parameters=parameters,
    )
    specimen_digest = _domain_digest("EVIDENCE_MUTATION_SPECIMEN", mutated)
    observed_classification, observed_detector = _classify_mutation(
        mutated,
        mutation_id=mutation_id,
        mode=mode,
        expected_detector=expected_detector,
    )
    return EvidenceMutationResult(
        mutation_id=mutation_id,
        family=family,
        baseline_vector_id=baseline_vector_id,
        operator=operator,
        expected_classification=expected_classification,
        observed_classification=observed_classification,
        expected_detector=expected_detector,
        observed_detector=observed_detector,
        specimen_digest=specimen_digest,
        mutated_catalog_digest=cast(str, mutated["catalog_digest"]),
    )


def _mutate_catalog(
    baseline: dict[str, Any],
    *,
    mutation_id: str,
    baseline_vector_id: str,
    operator: str,
    mode: str,
    expected_detector: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    catalog = deepcopy(baseline)
    if operator == "CORRUPT_AUTHORITY_POLICY_DIGEST":
        policy = _object(catalog, "authority_policy")
        policy["policy_digest"] = _ZERO_DIGEST
        return _finalize_catalog(catalog)

    accepted = _array_of_objects(catalog, "accepted_vectors")
    index, vector = _find_vector(accepted, baseline_vector_id)
    mutated = deepcopy(vector)

    if operator == "SUBSTITUTE_VERIFY_AUTHORITY":
        event = _find_event(mutated, operation="VERIFY")
        payload = _object(event, "payload")
        payload["verifier_authority_id"] = _required_string(parameters, "authority_id")
        _rebuild_events(mutated)
    elif operator == "WIDEN_USE_SCOPE":
        request = _object(mutated, "use_request")
        request["scope_ids"] = _string_list(parameters, "scope_ids")
        _rebuild_use_request(request)
    elif operator == "ESCALATE_REUSE_CLASS":
        request = _object(mutated, "use_request")
        request["required_reuse_class"] = _required_string(
            parameters,
            "required_reuse_class",
        )
        _rebuild_use_request(request)
    elif operator == "SUPPRESS_EXPIRY":
        event = _find_event(mutated, operation="REGISTER")
        _object(event, "payload")["expires_at_sequence"] = None
        _rebuild_events(mutated)
    elif operator == "DOWNGRADE_MATERIAL_CHALLENGE":
        event = _find_event(mutated, operation="CHALLENGE")
        _object(event, "payload")["challenge_reason_code"] = _required_string(
            parameters,
            "reason_code",
        )
        _rebuild_events(mutated)
    elif operator == "REMOVE_DEPENDENCY":
        event = _find_event(
            mutated,
            operation="REGISTER",
            evidence_id=_required_string(parameters, "evidence_id"),
        )
        _object(event, "payload")["dependency_ids"] = []
        _rebuild_events(mutated)
    elif operator == "INTRODUCE_DEPENDENCY_CYCLE":
        event = _find_event(
            mutated,
            operation="REGISTER",
            evidence_id=_required_string(parameters, "evidence_id"),
        )
        _object(event, "payload")["dependency_ids"] = [
            _required_string(parameters, "dependency_id")
        ]
        _rebuild_events(mutated)
    elif operator == "REMOVE_LIMITATION":
        event = _find_event(mutated, operation="REGISTER")
        _object(event, "payload")["limitations"] = []
        _rebuild_events(mutated)
    elif operator == "APPEND_TERMINAL_REVIVAL":
        _append_terminal_revival(mutated, mutation_id)
    elif operator == "REWRITE_SOURCE_ID":
        event = _find_event(mutated, operation="REGISTER")
        _object(event, "payload")["source_id"] = _required_string(parameters, "source_id")
        _rebuild_events(mutated)
    elif operator == "DELETE_VERIFY_EVENT":
        events = _array_of_objects(mutated, "events")
        mutated["events"] = [
            item for item in events if _object(item, "payload").get("operation") != "VERIFY"
        ]
    elif operator == "CORRUPT_EXPECTED_ROOT":
        mutated["expected_registry_root"] = _ZERO_DIGEST
    elif operator == "CORRUPT_EVENT_DIGEST":
        event = _find_event(mutated, operation="VERIFY")
        event["registry_event_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_PREDECESSOR":
        event = _find_event(mutated, operation="VERIFY")
        event["previous_entity_event_digest"] = _ZERO_DIGEST
        _rebuild_single_event(event)
    elif operator == "CORRUPT_EXPECTED_RECEIPT":
        _object(mutated, "expected_admissibility")["receipt_digest"] = _ZERO_DIGEST
    elif operator == "REORDER_EVENTS":
        events = _array_of_objects(mutated, "events")
        if len(events) < 2:
            raise EvidenceMutationError("EVIDENCE_MUTATION_REORDER_REQUIRES_TWO_EVENTS")
        events[0], events[1] = events[1], events[0]
    else:
        raise EvidenceMutationError("EVIDENCE_MUTATION_OPERATOR_UNSUPPORTED", operator)

    if mode == "REJECTED":
        stage = _required_string(parameters, "stage")
        rejected = _as_rejected_vector(
            mutated,
            mutation_id=mutation_id,
            expected_detector=expected_detector,
            stage=stage,
        )
        accepted.pop(index)
        rejected_vectors = _array_of_objects(catalog, "rejected_vectors")
        rejected_vectors.append(rejected)
    elif mode == "ACCEPTED_ERROR":
        accepted[index] = mutated
    elif mode != "CATALOG_ERROR":
        raise EvidenceMutationError("EVIDENCE_MUTATION_MODE_INVALID", mode)

    return _finalize_catalog(catalog)


def _classify_mutation(
    catalog: dict[str, Any],
    *,
    mutation_id: str,
    mode: str,
    expected_detector: str,
) -> tuple[str, str | None]:
    report = validate_evidence_registry(vectors=catalog)
    if mode == "REJECTED":
        observed = dict(report.rejected_failure_codes).get(f"MUT-{mutation_id}")
        if report.success and observed == expected_detector:
            return "KILLED", observed
        if report.success:
            return "INVALID_MUTATION", observed
        return "INVALID_MUTATION", _first_detector(report)
    if report.success:
        return "SURVIVED", None
    joined = "\n".join(report.errors)
    if expected_detector in joined:
        return "KILLED", expected_detector
    return "INVALID_MUTATION", _first_detector(report)


def _first_detector(report: EvidenceRegistryValidationReport) -> str | None:
    if report.errors:
        text = report.errors[0]
        for token in text.replace(":", " ").replace(",", " ").split():
            if token.isupper() and "_" in token:
                return token
        return text
    return None


def _append_terminal_revival(vector: dict[str, Any], mutation_id: str) -> None:
    events = _array_of_objects(vector, "events")
    evidence_id = _required_string(events[-1], "entity_id")
    events.extend(
        [
            {
                "schema_version": "registry-event/1",
                "registry_type": "EVIDENCE_UNIT",
                "entity_id": evidence_id,
                "entity_sequence": 3,
                "previous_entity_event_digest": None,
                "clock_sequence": 20,
                "projection_phase": "EVIDENCE_REGISTRY",
                "source_receipt_digest": _literal_digest(f"{mutation_id}:expire"),
                "payload_schema_version": "evidence-unit-event/1",
                "payload": {
                    "operation": "EXPIRE",
                    "expiry_authority_id": "authority:clock",
                },
                "registry_event_digest": _ZERO_DIGEST,
            },
            {
                "schema_version": "registry-event/1",
                "registry_type": "EVIDENCE_UNIT",
                "entity_id": evidence_id,
                "entity_sequence": 4,
                "previous_entity_event_digest": None,
                "clock_sequence": 21,
                "projection_phase": "EVIDENCE_REGISTRY",
                "source_receipt_digest": _literal_digest(f"{mutation_id}:revive"),
                "payload_schema_version": "evidence-unit-event/1",
                "payload": {
                    "operation": "VERIFY",
                    "verifier_authority_id": "authority:verifier",
                },
                "registry_event_digest": _ZERO_DIGEST,
            },
        ]
    )
    _rebuild_events(vector)


def _as_rejected_vector(
    vector: dict[str, Any],
    *,
    mutation_id: str,
    expected_detector: str,
    stage: str,
) -> dict[str, Any]:
    return {
        "description": f"Mutation {mutation_id} must fail closed.",
        "events": deepcopy(_array_of_objects(vector, "events")),
        "expected_error": expected_detector,
        "stage": stage,
        "use_request": deepcopy(vector.get("use_request")),
        "vector_id": f"MUT-{mutation_id}",
    }


def _rebuild_events(vector: dict[str, Any]) -> None:
    heads: dict[str, str] = {}
    rebuilt: list[dict[str, Any]] = []
    for raw_event in _array_of_objects(vector, "events"):
        unsigned = deepcopy(raw_event)
        unsigned.pop("registry_event_digest", None)
        entity_id = _required_string(unsigned, "entity_id")
        unsigned["previous_entity_event_digest"] = heads.get(entity_id)
        event = cast(RegistryEvent, RegistryEvent.build(unsigned))
        value = event.to_json_value()
        heads[entity_id] = event.digest
        rebuilt.append(value)
    vector["events"] = rebuilt


def _rebuild_single_event(event: dict[str, Any]) -> None:
    unsigned = deepcopy(event)
    unsigned.pop("registry_event_digest", None)
    rebuilt = cast(RegistryEvent, RegistryEvent.build(unsigned)).to_json_value()
    event.clear()
    event.update(rebuilt)


def _rebuild_use_request(request: dict[str, Any]) -> None:
    request["scope_ids"] = sorted(_string_list(request, "scope_ids"))
    request["accepted_limitation_codes"] = sorted(
        _string_list(request, "accepted_limitation_codes")
    )
    unsigned = {key: value for key, value in request.items() if key != "request_digest"}
    request["request_digest"] = _domain_digest("EVIDENCE_USE_REQUEST", unsigned)


def _finalize_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    catalog["catalog_digest"] = catalog_digest(catalog, _VECTOR_CATALOG_DOMAIN)
    return catalog


def _find_vector(
    vectors: list[dict[str, Any]],
    vector_id: str,
) -> tuple[int, dict[str, Any]]:
    for index, vector in enumerate(vectors):
        if vector.get("vector_id") == vector_id:
            return index, vector
    raise EvidenceMutationError("EVIDENCE_MUTATION_BASELINE_VECTOR_MISSING", vector_id)


def _find_event(
    vector: dict[str, Any],
    *,
    operation: str,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    for event in _array_of_objects(vector, "events"):
        if evidence_id is not None and event.get("entity_id") != evidence_id:
            continue
        if _object(event, "payload").get("operation") == operation:
            return event
    raise EvidenceMutationError("EVIDENCE_MUTATION_EVENT_MISSING", operation)


def _array_of_objects(value: dict[str, Any], field: str) -> list[dict[str, Any]]:
    raw = value.get(field)
    if type(raw) is not list or any(type(item) is not dict for item in raw):
        raise EvidenceMutationError("EVIDENCE_MUTATION_ARRAY_INVALID", field)
    return cast(list[dict[str, Any]], raw)


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    item = value.get(field)
    if type(item) is not dict:
        raise EvidenceMutationError("EVIDENCE_MUTATION_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _required_string(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or not item:
        raise EvidenceMutationError("EVIDENCE_MUTATION_STRING_INVALID", field)
    return item


def _string_list(value: dict[str, Any], field: str) -> list[str]:
    item = value.get(field)
    if type(item) is not list or any(type(entry) is not str for entry in item):
        raise EvidenceMutationError("EVIDENCE_MUTATION_STRING_LIST_INVALID", field)
    return cast(list[str], item)


def _string_or_placeholder(value: object, placeholder: str) -> str:
    return cast(str, value) if type(value) is str and value else placeholder


def _literal_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _domain_digest(domain: str, value: object) -> str:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()
