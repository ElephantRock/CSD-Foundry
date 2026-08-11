"""Deterministic serialized-artifact mutation campaign for v0.5-D4 alternative-model assurance.

Mirrors :mod:`csd_foundry.governance.v0_5.assumption_mutations` exactly in
structure. Each declared operator deep-copies the baseline vector catalog,
applies a single defect, re-finalizes the catalog digest, and feeds the mutated
catalog to the independent alternative-model validator. The campaign requires
every declared mutation to be KILLED with the expected detector and records zero
unexplained escapes.

The operators cover: event identity/sequence/predecessor/ordering, illegal
lifecycle transition/terminal revival, challenge/resolution state, graph
canonical bytes/digest, RFC 6901 difference path/escaping, difference
family/digest, material-difference admission, authorization bindings, ADMIT
source-receipt binding, replay inventory bindings, comparison bindings, use-time
gates, and receipt/catalog integrity.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.alternative_model_validation import (
    AlternativeModelRegistryValidationReport,
    validate_alternative_model_registry,
)
from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    catalog_digest,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.resources import (
    alternative_model_mutation_manifest,
    alternative_model_vectors,
)

_VECTOR_CATALOG_DOMAIN = b"ALTERNATIVE_MODEL_VECTOR_CATALOG\0"
_MUTATION_CATALOG_DOMAIN = b"ALTERNATIVE_MODEL_MUTATION_CATALOG\0"
_MUTATION_CLASSES = {"KILLED", "SURVIVED", "EQUIVALENT", "INVALID_MUTATION"}
_MODES = {"REJECTED", "ACCEPTED_ERROR", "CATALOG_ERROR"}
_ZERO_DIGEST = "sha256:" + ("0" * 64)


class AlternativeModelMutationError(RuntimeError):
    """Stable mutation-campaign construction or evaluation failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class AlternativeModelMutationResult:
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
class AlternativeModelMutationReport:
    baseline_vector_catalog_digest: str | None
    mutation_catalog_digest: str | None
    results: tuple[AlternativeModelMutationResult, ...]
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
            "schema_version": "alternative-model-mutation-report/0.5",
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
                "This report establishes that the declared serialized alternative-model "
                "mutations are detected relative to the committed alternative-model-v1 corpus "
                "and independent validator. It does not establish completeness of the mutation "
                "space, external truth, real-world dependency completeness, or production safety."
            ),
        }

    @property
    def report_digest(self) -> str:
        return _domain_digest("ALTERNATIVE_MODEL_MUTATION_REPORT", self._unsigned_value())

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_value(), "report_digest": self.report_digest}


def evaluate_alternative_mutations(
    release: str = "v0.5",
    *,
    manifest: dict[str, Any] | None = None,
    vectors: dict[str, Any] | None = None,
) -> AlternativeModelMutationReport:
    errors: list[str] = []
    campaign = alternative_model_mutation_manifest() if manifest is None else deepcopy(manifest)
    baseline = alternative_model_vectors() if vectors is None else deepcopy(vectors)
    mutation_specs: list[dict[str, Any]] = []

    if release != "v0.5":
        errors.append("alternative model mutation assurance supports only v0.5")

    try:
        mutation_specs = _validate_campaign(campaign, baseline)
    except (AlternativeModelMutationError, GovernanceContractError) as exc:
        errors.append(str(exc))

    baseline_report = validate_alternative_model_registry(release=release, vectors=baseline)
    if not baseline_report.success:
        errors.append("baseline alternative model vector catalog is not valid")

    results: list[AlternativeModelMutationResult] = []
    for spec in mutation_specs:
        try:
            result = _evaluate_mutation(spec, baseline)
        except (
            AlternativeModelMutationError,
            GovernanceContractError,
            KeyError,
            TypeError,
        ) as exc:
            result = AlternativeModelMutationResult(
                mutation_id=_string_or_placeholder(spec.get("mutation_id"), "UNKNOWN-MUTATION"),
                family=_string_or_placeholder(spec.get("family"), "UNKNOWN_FAMILY"),
                baseline_vector_id=_string_or_placeholder(
                    spec.get("baseline_vector_id"), "UNKNOWN-VECTOR"
                ),
                operator=_string_or_placeholder(spec.get("operator"), "UNKNOWN_OPERATOR"),
                expected_classification=_string_or_placeholder(
                    spec.get("expected_classification"), "KILLED"
                ),
                observed_classification="INVALID_MUTATION",
                expected_detector=_string_or_placeholder(
                    spec.get("expected_detector"), "UNKNOWN_DETECTOR"
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
    return AlternativeModelMutationReport(
        baseline_vector_catalog_digest=(baseline_digest if type(baseline_digest) is str else None),
        mutation_catalog_digest=(mutation_digest if type(mutation_digest) is str else None),
        results=tuple(results),
        errors=tuple(errors),
    )


def _validate_campaign(
    campaign: dict[str, Any],
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    if type(campaign) is not dict:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_MANIFEST_NOT_OBJECT")
    if campaign.get("schema_version") != "alternative-model-mutation-campaign/1":
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_MANIFEST_SCHEMA_INVALID")
    if campaign.get("mutation_version") != 1:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_VERSION_INVALID")
    if campaign.get("baseline_vector_catalog_digest") != baseline.get("catalog_digest"):
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_BASELINE_DIGEST_MISMATCH")
    expected_catalog_digest = catalog_digest(campaign, _MUTATION_CATALOG_DOMAIN)
    if campaign.get("catalog_digest") != expected_catalog_digest:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_CATALOG_DIGEST_MISMATCH")
    classifications = campaign.get("classification_values")
    if classifications != ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"]:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_CLASSIFICATIONS_INVALID")
    raw_specs = campaign.get("mutations")
    if type(raw_specs) is not list or not raw_specs:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_INVENTORY_INVALID")
    specs = [cast(dict[str, Any], item) for item in raw_specs if type(item) is dict]
    if len(specs) != len(raw_specs):
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_SPEC_NOT_OBJECT")
    identifiers = [_required_string(item, "mutation_id") for item in specs]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_IDS_NOT_CANONICAL")
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
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_SPEC_KEYS_INVALID",
                _required_string(spec, "mutation_id"),
            )
        if _required_string(spec, "expected_classification") not in _MUTATION_CLASSES:
            raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_CLASSIFICATION_INVALID")
        if _required_string(spec, "mode") not in _MODES:
            raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_MODE_INVALID")
        if type(spec.get("parameters")) is not dict:
            raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_PARAMETERS_INVALID")
        _required_string(spec, "family")
        _required_string(spec, "baseline_vector_id")
        _required_string(spec, "operator")
        _required_string(spec, "expected_detector")
    return specs


def _evaluate_mutation(
    spec: dict[str, Any],
    baseline: dict[str, Any],
) -> AlternativeModelMutationResult:
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
    specimen_digest = _domain_digest("ALTERNATIVE_MODEL_MUTATION_SPECIMEN", mutated)
    observed_classification, observed_detector = _classify_mutation(
        mutated,
        mutation_id=mutation_id,
        mode=mode,
        expected_detector=expected_detector,
    )
    return AlternativeModelMutationResult(
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


# =====================================================================
# Mutation operators.
# =====================================================================


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

    accepted = _array_of_objects(catalog, "accepted_vectors")
    index, vector = _find_vector(accepted, baseline_vector_id)
    mutated = deepcopy(vector)

    if operator == "CORRUPT_PREDECESSOR":
        event = _find_event(mutated, operation="ADMIT")
        event["previous_entity_event_digest"] = _ZERO_DIGEST
        _rebuild_single_event(event)
    elif operator == "CORRUPT_ENTITY_SEQUENCE":
        event = _find_event(mutated, operation="ADMIT")
        event["entity_sequence"] = cast(int, event["entity_sequence"]) + 100
        _rebuild_single_event(event)
    elif operator == "CORRUPT_CLOCK_SEQUENCE":
        event = _find_event(mutated, operation="ADMIT")
        event["clock_sequence"] = cast(int, event["clock_sequence"]) - 1
        _rebuild_single_event(event)
    elif operator == "APPEND_TERMINAL_REVIVAL":
        _append_terminal_revival(mutated, mutation_id)
    elif operator == "SUBSTITUTE_MODEL_ID":
        event = _find_event(mutated, operation="ADMIT")
        event["entity_id"] = _required_string(parameters, "replacement_id")
        _rebuild_single_event(event)
    elif operator == "SUBSTITUTE_ADMITTING_AUTHORITY":
        event = _find_event(mutated, operation="ADMIT")
        _object(event, "payload")["admitting_authority_id"] = _required_string(
            parameters, "authority_id"
        )
        _rebuild_events(mutated)
    elif operator == "CORRUPT_ADMIT_TRANSITION":
        # Force an ADMIT on an already-UNVERIFIED model by re-pointing its
        # predecessor at the ADMIT head (entity_sequence 3 -> duplicate ADMIT).
        events = _array_of_objects(mutated, "events")
        admit_event = _find_event(mutated, operation="ADMIT")
        model_id = admit_event["entity_id"]
        head = max(
            (e for e in events if e["entity_id"] == model_id),
            key=lambda e: cast(int, e["entity_sequence"]),
        )
        revival = deepcopy(admit_event)
        revival["entity_sequence"] = cast(int, head["entity_sequence"]) + 1
        revival["previous_entity_event_digest"] = head["registry_event_digest"]
        revival["clock_sequence"] = cast(int, head["clock_sequence"]) + 1
        events.append(revival)
        _rebuild_events(mutated)
    elif operator == "REMOVE_ACTIVE_CHALLENGE":
        events = _array_of_objects(mutated, "events")
        mutated["events"] = [
            item for item in events if _object(item, "payload").get("operation") != "CHALLENGE"
        ]
    elif operator == "CORRUPT_RESOLVED_CHALLENGE_SET":
        event = _find_event(mutated, operation="RESOLVE_CHALLENGES")
        _object(event, "payload")["resolved_challenge_ids"] = _string_list(
            parameters, "resolved_challenge_ids"
        )
        _rebuild_events(mutated)
    elif operator == "CORRUPT_GRAPH_BYTES":
        # Tamper the admission's primary_graph so it no longer canonicalizes to
        # the receipt's primary_graph_digest, breaking the graph-byte binding.
        admission = _find_admission(mutated)
        primary = _object(admission, "primary_graph")
        primary["tampered_field"] = "mutation"
    elif operator == "CORRUPT_GRAPH_DIGEST":
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        receipt["primary_graph_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_DIFFERENCE_PATH":
        # Tamper one difference path (breaks both escaping + the family/path
        # consistency with the re-derived set, and the computed digest).
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        paths = cast(list[str], receipt["difference_paths"])
        if not paths:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no difference paths"
            )
        paths[0] = "/tampered/path"
    elif operator == "CORRUPT_DIFFERENCE_FAMILY":
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        families = cast(list[str], receipt["difference_families"])
        if not families:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no difference families"
            )
        families[0] = "ADDED_REMOVED" if families[0] != "ADDED_REMOVED" else "RELABELED"
        receipt["difference_families"] = sorted(set(families))
    elif operator == "CORRUPT_DIFFERENCE_DIGEST":
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        receipt["computed_difference_digest"] = _ZERO_DIGEST
    elif operator == "SUPPRESS_MATERIAL_DIFFERENCE":
        # Replace the shadow graph with the primary graph so the difference set
        # is empty, contradicting has_material_difference and breaking the
        # material-difference admission requirement.
        admission = _find_admission(mutated)
        primary_graph = admission.get("primary_graph")
        if type(primary_graph) is not dict:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "primary graph missing"
            )
        admission["shadow_graph"] = deepcopy(primary_graph)
    elif operator == "CORRUPT_AUTHORIZATION_DIGEST":
        # Tamper the ADMIT event's source_receipt_digest (must equal the
        # authorization_digest reconstructed from the PROPOSE state + receipt).
        event = _find_event(mutated, operation="ADMIT")
        event["source_receipt_digest"] = _ZERO_DIGEST
        _rebuild_single_event(event)
    elif operator == "CORRUPT_AUTHORIZATION_BINDING":
        # Tamper the structural-difference receipt so the shadow_graph_digest no
        # longer matches the model's graph_digest (SHADOW_GRAPH_MISMATCH).
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        receipt["shadow_graph_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_REPLAY_EXECUTED":
        replay = _find_replay_receipt(mutated)
        required = cast(list[str], replay["required_inventory"])
        replay["executed_inventory"] = required[:-1] if len(required) > 1 else []
    elif operator == "CORRUPT_REPLAY_SKIPPED":
        replay = _find_replay_receipt(mutated)
        required = cast(list[str], replay["required_inventory"])
        replay["skipped_inventory"] = required[:1]
    elif operator == "CORRUPT_REPLAY_DIGEST":
        replay = _find_replay_receipt(mutated)
        replay["receipt_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_COMPARISON_RESULT":
        comparison = _find_comparison_receipt(mutated)
        current = cast(str, comparison["comparison_result"])
        comparison["comparison_result"] = "DIVERGENT" if current == "INVARIANT" else "INVARIANT"
    elif operator == "CORRUPT_COMPARISON_GRAPH_BINDING":
        comparison = _find_comparison_receipt(mutated)
        primary = _object(comparison, "primary_replay_receipt")
        primary["graph_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_COMPARISON_DIGEST":
        comparison = _find_comparison_receipt(mutated)
        comparison["comparison_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_USE_AUTHORITY_DECISION":
        binding = _optional_object(mutated, "use_authority")
        if binding is None:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no use_authority binding"
            )
        expected = _optional_object(mutated, "expected_use_authority")
        if expected is None:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no expected_use_authority"
            )
        # Flip the decision field so the expected outcome no longer matches the
        # independently-evaluated decision.
        current = cast(str, expected.get("decision", ""))
        expected["decision"] = "DENY" if current != "DENY" else "ALLOW"
    elif operator == "CORRUPT_USE_AUTHORITY_DIGEST":
        binding = _optional_object(mutated, "use_authority")
        if binding is None:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no use_authority binding"
            )
        expected = _optional_object(mutated, "expected_use_authority")
        if expected is None:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "no expected_use_authority"
            )
        expected["decision_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_USE_AUTHORITY_SCOPE":
        binding = _object(mutated, "use_authority")
        binding["scope_id"] = _required_string(parameters, "scope_id")
    elif operator == "CORRUPT_EXPECTED_ROOT":
        mutated["expected_registry_root"] = _ZERO_DIGEST
    elif operator == "CORRUPT_EXPECTED_AUTHORIZATION":
        auth = _object(mutated, "expected_authorization_digests")
        model_id = _required_string(parameters, "model_id")
        auth[model_id] = _ZERO_DIGEST
    elif operator == "REMOVE_ADMISSION_EVIDENCE":
        # Drop the admission evidence for the model so the ADMIT authorization
        # cannot be reconstructed (ADMISSION_EVIDENCE_MISSING).
        admissions = cast(list[dict[str, Any]], mutated.get("admissions", []))
        model_id = _required_string(parameters, "model_id")
        mutated["admissions"] = [a for a in admissions if a.get("model_id") != model_id]
    elif operator == "CORRUPT_CHALLENGE_BASIS":
        # challenge_basis_code is an immutable PROPOSE field; mutating it
        # changes the event digest and breaks the chain.
        event = _find_event(mutated, operation="PROPOSE")
        _object(event, "payload")["challenge_basis_code"] = _required_string(
            parameters, "challenge_basis_code"
        )
        _rebuild_events(mutated)
    elif operator == "CORRUPT_RECEIPT_SELF_DIGEST":
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        receipt["receipt_digest"] = _ZERO_DIGEST
    elif operator == "ESCAPE_DIFFERENCE_PATH":
        # Insert a path containing characters requiring RFC 6901 escaping (~ and /)
        # to verify the detector rejects non-canonical path sets.
        admission = _find_admission(mutated)
        receipt = _object(admission, "structural_difference_receipt")
        paths = cast(list[str], receipt["difference_paths"])
        paths.append("/node/with~0escape")
        receipt["difference_paths"] = sorted(set(paths))
    elif operator == "CORRUPT_REPLAY_PRUNED":
        # Set pruned_inventory to nonempty, violating the FULL_REPLAY invariant.
        replay = _find_replay_receipt(mutated)
        required = cast(list[str], replay["required_inventory"])
        replay["pruned_inventory"] = required[:1] if required else ["node:pruned"]
    elif operator == "CORRUPT_REPLAY_RUNNER":
        # Corrupt runner_revision to an invalid token format.
        replay = _find_replay_receipt(mutated)
        replay["runner_revision"] = "runner invalid token"
    elif operator == "CORRUPT_REPLAY_DECISION_CONTEXT":
        # Change decision_context_digest so the self-digest no longer matches.
        replay = _find_replay_receipt(mutated)
        replay["decision_context_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_REPLAY_INITIAL_STATE":
        # Change initial_state_digest so the self-digest no longer matches.
        replay = _find_replay_receipt(mutated)
        replay["initial_state_digest"] = _ZERO_DIGEST
    elif operator == "CORRUPT_COMPARISON_CONTEXT":
        # Change the shadow replay's decision_context_digest and recompute its
        # self-digest so both replays pass individual validation but the
        # comparison's identical-decision-context binding check fails.
        comparison = _find_comparison_receipt(mutated)
        shadow = _object(comparison, "shadow_replay_receipt")
        shadow["decision_context_digest"] = _ZERO_DIGEST
        _recompute_replay_receipt_digest(shadow)
    elif operator == "CORRUPT_AUTHORIZATION_ROOT":
        # Insert a PROPOSE for a second model before the ADMIT, changing the
        # pre-ADMIT registry root. The ADMIT's source_receipt_digest was bound
        # to the original single-model root, so the reconstructed authorization
        # digest differs (ADMISSION_AUTHORIZATION_MISMATCH).
        events = _array_of_objects(mutated, "events")
        admit = _find_event(mutated, operation="ADMIT")
        admit_idx = events.index(admit)
        extra_id = _required_string(parameters, "extra_model_id")
        extra_propose = {
            "schema_version": "registry-event/1",
            "registry_type": "ALTERNATIVE_MODEL",
            "entity_id": extra_id,
            "entity_sequence": 1,
            "previous_entity_event_digest": None,
            "clock_sequence": 1,
            "projection_phase": "ALTERNATIVE_MODEL_REGISTRY",
            "source_receipt_digest": _literal_digest(f"{mutation_id}:extra-propose"),
            "payload_schema_version": "alternative-model-event/1",
            "payload": {
                "operation": "PROPOSE",
                "model_version": "v1",
                "primary_model_id": "model:primary",
                "graph_digest": _ZERO_DIGEST,
                "declared_difference_digest": _ZERO_DIGEST,
                "challenge_basis_code": "basis:extra",
                "scope_ids": ["scope:extra"],
                "assumption_ids": [],
                "evidence_ids": [],
                "proposer_authority_id": "authority:extra-proposer",
                "materiality": "MATERIAL",
                "valid_from_sequence": 1,
                "expires_at_sequence": 100,
                "limitations": [],
                "maximum_reuse_class": "D2",
            },
            "registry_event_digest": _ZERO_DIGEST,
        }
        events.insert(admit_idx, extra_propose)
        _rebuild_events(mutated)
    elif operator == "CORRUPT_USE_REUSE_CLASS":
        # Change required_reuse_class to exceed the model's maximum (D2),
        # triggering USE_DENIED_REUSE_CLASS.
        binding = _object(mutated, "use_authority")
        binding["required_reuse_class"] = "BENCHMARK"
    elif operator == "CORRUPT_USE_EXPIRY":
        # Change logical_clock past the model's expiry, triggering
        # USE_DENIED_EXPIRED.
        binding = _object(mutated, "use_authority")
        clock = parameters.get("logical_clock")
        if type(clock) is not int or isinstance(clock, bool) or clock < 1:
            raise AlternativeModelMutationError(
                "ALTERNATIVE_MODEL_MUTATION_PARAMETER_INVALID", "logical_clock"
            )
        binding["logical_clock"] = clock
    elif operator == "CORRUPT_USE_TERMINAL":
        # Append a REJECT event after the model's head, making it terminal, then
        # the use-authority gate denies with USE_DENIED_TERMINAL.
        events = _array_of_objects(mutated, "events")
        head = max(
            events,
            key=lambda e: cast(int, e["entity_sequence"]),
        )
        model_id = cast(str, head["entity_id"])
        reject = {
            "schema_version": "registry-event/1",
            "registry_type": "ALTERNATIVE_MODEL",
            "entity_id": model_id,
            "entity_sequence": cast(int, head["entity_sequence"]) + 1,
            "previous_entity_event_digest": head["registry_event_digest"],
            "clock_sequence": cast(int, head["clock_sequence"]) + 1,
            "projection_phase": "ALTERNATIVE_MODEL_REGISTRY",
            "source_receipt_digest": _literal_digest(f"{mutation_id}:reject"),
            "payload_schema_version": "alternative-model-event/1",
            "payload": {
                "operation": "REJECT",
                "rejecting_authority_id": "authority:rejector",
                "reason_code": "reason:terminal-mutation",
            },
            "registry_event_digest": _ZERO_DIGEST,
        }
        events.append(reject)
        _rebuild_events(mutated)
    else:
        raise AlternativeModelMutationError(
            "ALTERNATIVE_MODEL_MUTATION_OPERATOR_UNSUPPORTED", operator
        )

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
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_MODE_INVALID", mode)

    return _finalize_catalog(catalog)


def _classify_mutation(
    catalog: dict[str, Any],
    *,
    mutation_id: str,
    mode: str,
    expected_detector: str,
) -> tuple[str, str | None]:
    report = validate_alternative_model_registry(vectors=catalog)
    if mode == "REJECTED":
        observed = dict(report.rejected_failure_codes).get(f"MUT-{mutation_id}")
        if observed == expected_detector:
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


def _first_detector(report: AlternativeModelRegistryValidationReport) -> str | None:
    if report.errors:
        text = report.errors[0]
        for token in text.replace(":", " ").replace(",", " ").split():
            if token.isupper() and "_" in token:
                return token
        return text
    return None


def _append_terminal_revival(vector: dict[str, Any], mutation_id: str) -> None:
    events = _array_of_objects(vector, "events")
    model_id = _required_string(events[-1], "entity_id")
    head_digest = events[-1]["registry_event_digest"]
    head_sequence = cast(int, events[-1]["entity_sequence"])
    head_clock = cast(int, events[-1]["clock_sequence"])
    events.extend(
        [
            {
                "schema_version": "registry-event/1",
                "registry_type": "ALTERNATIVE_MODEL",
                "entity_id": model_id,
                "entity_sequence": head_sequence + 1,
                "previous_entity_event_digest": head_digest,
                "clock_sequence": head_clock + 100,
                "projection_phase": "ALTERNATIVE_MODEL_REGISTRY",
                "source_receipt_digest": _literal_digest(f"{mutation_id}:reject"),
                "payload_schema_version": "alternative-model-event/1",
                "payload": {
                    "operation": "REJECT",
                    "rejecting_authority_id": "authority:rejector",
                    "reason_code": "reason:terminal",
                },
                "registry_event_digest": _ZERO_DIGEST,
            },
            {
                "schema_version": "registry-event/1",
                "registry_type": "ALTERNATIVE_MODEL",
                "entity_id": model_id,
                "entity_sequence": head_sequence + 2,
                "previous_entity_event_digest": None,
                "clock_sequence": head_clock + 101,
                "projection_phase": "ALTERNATIVE_MODEL_REGISTRY",
                "source_receipt_digest": _literal_digest(f"{mutation_id}:revive"),
                "payload_schema_version": "alternative-model-event/1",
                "payload": {
                    "operation": "ADMIT",
                    "admitting_authority_id": "authority:admitter",
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
    result: dict[str, Any] = {
        "description": f"Mutation {mutation_id} must fail closed.",
        "events": deepcopy(_array_of_objects(vector, "events")),
        "expected_error": expected_detector,
        "stage": stage,
        "admissions": deepcopy(vector.get("admissions", [])),
        "expected_authorization_digests": deepcopy(
            vector.get("expected_authorization_digests", {})
        ),
        "vector_id": f"MUT-{mutation_id}",
    }
    use_authority = deepcopy(vector.get("use_authority"))
    if use_authority is not None:
        result["use_authority"] = use_authority
    return result


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
    raise AlternativeModelMutationError(
        "ALTERNATIVE_MODEL_MUTATION_BASELINE_VECTOR_MISSING", vector_id
    )


def _find_event(
    vector: dict[str, Any],
    *,
    operation: str,
    entity_id: str | None = None,
) -> dict[str, Any]:
    for event in _array_of_objects(vector, "events"):
        if entity_id is not None and event.get("entity_id") != entity_id:
            continue
        if _object(event, "payload").get("operation") == operation:
            return event
    raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_EVENT_MISSING", operation)


def _find_admission(vector: dict[str, Any]) -> dict[str, Any]:
    admissions = cast(list[dict[str, Any]], vector.get("admissions", []))
    if not admissions:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_ADMISSION_MISSING")
    return admissions[0]


def _find_replay_receipt(vector: dict[str, Any]) -> dict[str, Any]:
    receipts = cast(list[dict[str, Any]], vector.get("replay_receipts", []))
    if not receipts:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_REPLAY_MISSING")
    return receipts[0]


def _find_comparison_receipt(vector: dict[str, Any]) -> dict[str, Any]:
    receipts = cast(list[dict[str, Any]], vector.get("comparison_receipts", []))
    if not receipts:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_COMPARISON_MISSING")
    return receipts[0]


def _array_of_objects(value: dict[str, Any], field: str) -> list[dict[str, Any]]:
    raw = value.get(field)
    if type(raw) is not list or any(type(item) is not dict for item in raw):
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_ARRAY_INVALID", field)
    return cast(list[dict[str, Any]], raw)


def _object(value: dict[str, Any], field: str) -> dict[str, Any]:
    item = value.get(field)
    if type(item) is not dict:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _optional_object(value: dict[str, Any], field: str) -> dict[str, Any] | None:
    item = value.get(field)
    if item is None:
        return None
    if type(item) is not dict:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_OBJECT_INVALID", field)
    return cast(dict[str, Any], item)


def _required_string(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or not item:
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_STRING_INVALID", field)
    return item


def _string_list(value: dict[str, Any], field: str) -> list[str]:
    item = value.get(field)
    if type(item) is not list or any(type(entry) is not str for entry in item):
        raise AlternativeModelMutationError("ALTERNATIVE_MODEL_MUTATION_STRING_LIST_INVALID", field)
    return cast(list[str], item)


def _string_or_placeholder(value: object, placeholder: str) -> str:
    return value if type(value) is str and value else placeholder


def _literal_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


_REPLAY_RECEIPT_SCHEMA_VERSION = "alternative-model-replay-receipt/1"


def _recompute_replay_receipt_digest(replay: dict[str, Any]) -> None:
    """Recompute a serialized replay receipt's self-digest in-place.

    Mirrors the production ``ReplayReceipt._unsigned_value`` + domain digest
    exactly so the mutated receipt still passes individual self-digest
    validation while breaking a cross-receipt binding (e.g. comparison context).
    """
    unsigned: dict[str, object] = {
        "schema_version": _REPLAY_RECEIPT_SCHEMA_VERSION,
        "graph_digest": replay["graph_digest"],
        "decision_context_digest": replay["decision_context_digest"],
        "initial_state_digest": replay["initial_state_digest"],
        "logical_clock": replay["logical_clock"],
        "runner_revision": replay["runner_revision"],
        "required_inventory": list(replay["required_inventory"]),
        "executed_inventory": list(replay["executed_inventory"]),
        "skipped_inventory": list(replay["skipped_inventory"]),
        "pruned_inventory": list(replay["pruned_inventory"]),
        "semantic_outcome_digest": replay["semantic_outcome_digest"],
    }
    replay["receipt_digest"] = _domain_digest("ALTERNATIVE_MODEL_REPLAY_RECEIPT", unsigned)


def _domain_digest(domain: str, value: object) -> str:
    import json

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
