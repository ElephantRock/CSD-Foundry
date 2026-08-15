"""Deterministic serialized-artifact mutation campaign for the P3.7 Phase-3
qualification layer.

Mirrors :mod:`csd_foundry.governance.v0_5.assumption_mutations` in structure.
Each declared operator deep-copies the serialized Phase-3 canary corpus,
applies a single defect (re-finalizing every dependent self-digest so the
intended binding — not a stale digest — is what breaks), and feeds the mutated
corpus to the independent Phase-3 validator. The campaign requires every
declared mutation to be KILLED with the expected detector and records zero
unexplained escapes.

Covered mutation families: current pointer corruption, active marker
corruption, generation chain (sequence gap / predecessor break / self-digest /
fork / cycle / missing), projection-plan digest + root + predecessor + claim
bindings, plan event inventories, cross-root bindings (E->A->M), canonical head
sets, entity identity/sequence/predecessor links, event inventory corruption,
completion sequence/root/predecessor/quarantine bindings, semantic and
disposition reference receipts, D4 comparison receipts and their FULL_REPLAY
proof bindings (graph / context / state / clock / runner / inventory).
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.canonicalization import (
    GovernanceContractError,
    catalog_digest,
)
from csd_foundry.governance.v0_5.contracts import (
    RegistryEvent,
    build_contract,
    contract_entry,
)
from csd_foundry.governance.v0_5.phase3_validation import (
    Phase3ValidationReport,
    _flat_domain_digest,
    _json_bytes,
    compute_generation_digest,
    validate_phase3_generations,
)

_MUTATION_CATALOG_DOMAIN = b"PHASE3_MUTATION_CATALOG\0"
_MUTATION_CLASSES = {"KILLED", "SURVIVED", "EQUIVALENT", "INVALID_MUTATION"}
_CAMPAIGN_SCHEMA_VERSION = "phase3-mutation-campaign/1"
_ZERO_DIGEST = "sha256:" + ("0" * 64)
_PLAN_DIGEST_DOMAINS = {
    "evidence": "EVIDENCE_PROJECTION_PLAN",
    "assumption": "ASSUMPTION_PROJECTION_PLAN",
    "alt_model": "ALTERNATIVE_MODEL_PROJECTION_PLAN",
}


class Phase3MutationError(RuntimeError):
    """Stable mutation-campaign construction or evaluation failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def phase3_corpus_digest(corpus: dict[str, Any]) -> str:
    """Deterministic corpus commitment over the canonical serialized form."""

    payload = _json_bytes(corpus)
    return "sha256:" + hashlib.sha256(b"PHASE3_CANARY_CORPUS\0" + payload).hexdigest()


@dataclass(frozen=True, slots=True)
class Phase3MutationResult:
    mutation_id: str
    family: str
    operator: str
    expected_classification: str
    observed_classification: str
    expected_detector: str
    observed_detector: str | None
    specimen_digest: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_classification": self.expected_classification,
            "expected_detector": self.expected_detector,
            "family": self.family,
            "mutation_id": self.mutation_id,
            "observed_classification": self.observed_classification,
            "observed_detector": self.observed_detector,
            "operator": self.operator,
        }


@dataclass(frozen=True, slots=True)
class Phase3MutationReport:
    baseline_corpus_digest: str | None
    mutation_catalog_digest: str | None
    results: tuple[Phase3MutationResult, ...]
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
                "expected_classification": item.expected_classification,
                "expected_detector": item.expected_detector,
                "family": item.family,
                "mutation_id": item.mutation_id,
                "observed_classification": item.observed_classification,
                "observed_detector": item.observed_detector,
                "operator": item.operator,
            }
            for item in self.results
        }
        return {
            "schema_version": "phase3-mutation-report/1",
            "baseline_corpus_digest": self.baseline_corpus_digest,
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
                "This report establishes that the declared serialized Phase-3 mutations are "
                "detected relative to the committed canary corpus and independent validator. "
                "It does not establish completeness of the mutation space, external truth, "
                "real-world dependency completeness, or production safety."
            ),
        }

    @property
    def report_digest(self) -> str:
        return _flat_domain_digest("PHASE3_MUTATION_REPORT", self._unsigned_value())

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_value(), "report_digest": self.report_digest}


# --------------------------------------------------------------------------- #
# Campaign construction + evaluation
# --------------------------------------------------------------------------- #


def build_phase3_mutation_manifest(corpus: dict[str, Any]) -> dict[str, Any]:
    """Build the deterministic Phase-3 mutation campaign manifest for a corpus."""

    campaign: dict[str, Any] = {
        "schema_version": _CAMPAIGN_SCHEMA_VERSION,
        "mutation_version": 1,
        "baseline_corpus_digest": phase3_corpus_digest(corpus),
        "classification_values": ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"],
        "mutations": [dict(spec) for spec in _declared_mutations()],
    }
    campaign["catalog_digest"] = catalog_digest(campaign, _MUTATION_CATALOG_DOMAIN)
    return campaign


def evaluate_phase3_mutations(
    corpus: dict[str, Any],
    manifest: dict[str, Any] | None = None,
) -> Phase3MutationReport:
    """Run the declared mutation campaign against the independent validator."""

    errors: list[str] = []
    campaign = build_phase3_mutation_manifest(corpus) if manifest is None else deepcopy(manifest)
    specs: list[dict[str, Any]] = []
    try:
        specs = _validate_campaign(campaign, corpus)
    except (Phase3MutationError, GovernanceContractError) as exc:
        errors.append(str(exc))

    baseline_report = validate_phase3_generations(deepcopy(corpus))
    if not baseline_report.success:
        errors.append("baseline phase3 corpus is not valid")

    results: list[Phase3MutationResult] = []
    for spec in specs:
        try:
            result = _evaluate_mutation(spec, corpus)
        except (
            Phase3MutationError,
            GovernanceContractError,
            KeyError,
            TypeError,
            IndexError,
        ) as exc:
            result = Phase3MutationResult(
                mutation_id=_string_or_placeholder(spec.get("mutation_id"), "UNKNOWN-MUTATION"),
                family=_string_or_placeholder(spec.get("family"), "UNKNOWN_FAMILY"),
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

    return Phase3MutationReport(
        baseline_corpus_digest=campaign.get("baseline_corpus_digest")
        if type(campaign.get("baseline_corpus_digest")) is str
        else None,
        mutation_catalog_digest=campaign.get("catalog_digest")
        if type(campaign.get("catalog_digest")) is str
        else None,
        results=tuple(results),
        errors=tuple(errors),
    )


def _validate_campaign(
    campaign: dict[str, Any],
    corpus: dict[str, Any],
) -> list[dict[str, Any]]:
    if type(campaign) is not dict:
        raise Phase3MutationError("PHASE3_MUTATION_MANIFEST_NOT_OBJECT")
    if campaign.get("schema_version") != _CAMPAIGN_SCHEMA_VERSION:
        raise Phase3MutationError("PHASE3_MUTATION_MANIFEST_SCHEMA_INVALID")
    if campaign.get("mutation_version") != 1:
        raise Phase3MutationError("PHASE3_MUTATION_VERSION_INVALID")
    if campaign.get("baseline_corpus_digest") != phase3_corpus_digest(corpus):
        raise Phase3MutationError("PHASE3_MUTATION_BASELINE_DIGEST_MISMATCH")
    expected_catalog_digest = catalog_digest(campaign, _MUTATION_CATALOG_DOMAIN)
    if campaign.get("catalog_digest") != expected_catalog_digest:
        raise Phase3MutationError("PHASE3_MUTATION_CATALOG_DIGEST_MISMATCH")
    classifications = campaign.get("classification_values")
    if classifications != ["EQUIVALENT", "INVALID_MUTATION", "KILLED", "SURVIVED"]:
        raise Phase3MutationError("PHASE3_MUTATION_CLASSIFICATIONS_INVALID")
    raw_specs = campaign.get("mutations")
    if type(raw_specs) is not list or not raw_specs:
        raise Phase3MutationError("PHASE3_MUTATION_INVENTORY_INVALID")
    specs = [cast(dict[str, Any], item) for item in raw_specs if type(item) is dict]
    if len(specs) != len(raw_specs):
        raise Phase3MutationError("PHASE3_MUTATION_SPEC_NOT_OBJECT")
    identifiers = [_required_string(item, "mutation_id") for item in specs]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(identifiers):
        raise Phase3MutationError("PHASE3_MUTATION_IDS_NOT_CANONICAL")
    for spec in specs:
        if set(spec) != {
            "expected_classification",
            "expected_detector",
            "family",
            "mutation_id",
            "operator",
            "parameters",
        }:
            raise Phase3MutationError(
                "PHASE3_MUTATION_SPEC_KEYS_INVALID",
                _required_string(spec, "mutation_id"),
            )
        if _required_string(spec, "expected_classification") not in _MUTATION_CLASSES:
            raise Phase3MutationError("PHASE3_MUTATION_CLASSIFICATION_INVALID")
        if type(spec.get("parameters")) is not dict:
            raise Phase3MutationError("PHASE3_MUTATION_PARAMETERS_INVALID")
        _required_string(spec, "family")
        _required_string(spec, "operator")
        _required_string(spec, "expected_detector")
    return specs


def _evaluate_mutation(spec: dict[str, Any], corpus: dict[str, Any]) -> Phase3MutationResult:
    mutation_id = _required_string(spec, "mutation_id")
    family = _required_string(spec, "family")
    operator = _required_string(spec, "operator")
    expected_classification = _required_string(spec, "expected_classification")
    expected_detector = _required_string(spec, "expected_detector")
    parameters = cast(dict[str, Any], spec["parameters"])

    mutated = deepcopy(corpus)
    _apply_operator(mutated, operator, parameters)
    specimen_digest = _flat_domain_digest("PHASE3_MUTATION_SPECIMEN", _specimen_value(mutated))
    observed_classification, observed_detector = _classify_mutation(mutated, expected_detector)
    return Phase3MutationResult(
        mutation_id=mutation_id,
        family=family,
        operator=operator,
        expected_classification=expected_classification,
        observed_classification=observed_classification,
        expected_detector=expected_detector,
        observed_detector=observed_detector,
        specimen_digest=specimen_digest,
    )


def _specimen_value(corpus: dict[str, Any]) -> dict[str, object]:
    return {
        "generations": corpus.get("generations"),
        "current_pointer": corpus.get("current_pointer"),
    }


def _classify_mutation(
    mutated: dict[str, Any],
    expected_detector: str,
) -> tuple[str, str | None]:
    report = validate_phase3_generations(mutated)
    if report.success:
        return "SURVIVED", None
    joined = "\n".join(report.errors)
    if expected_detector in joined:
        return "KILLED", expected_detector
    return "INVALID_MUTATION", _first_detector(report)


def _first_detector(report: Phase3ValidationReport) -> str | None:
    if report.errors:
        text = report.errors[0]
        for token in text.replace(":", " ").replace(",", " ").split():
            if token.isupper() and "_" in token:
                return token
        return text
    return None


# --------------------------------------------------------------------------- #
# Re-finalization helpers (rebuild self-digests after tampering)
# --------------------------------------------------------------------------- #


def _recompute_manifest(manifest: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in manifest.items() if key != "generation_digest"}
    manifest["generation_digest"] = compute_generation_digest(unsigned)


def _rebuild_event(event: dict[str, Any]) -> str:
    unsigned = deepcopy(event)
    unsigned.pop("registry_event_digest", None)
    rebuilt = cast(RegistryEvent, RegistryEvent.build(unsigned)).to_json_value()
    event.clear()
    event.update(rebuilt)
    return cast(str, rebuilt["registry_event_digest"])


def _rebuild_contract(name: str, value: dict[str, Any]) -> str:
    digest_field = contract_entry(name).digest_field
    unsigned = deepcopy(value)
    unsigned.pop(digest_field, None)
    rebuilt = build_contract(name, unsigned).to_json_value()
    value.clear()
    value.update(rebuilt)
    return cast(str, rebuilt[digest_field])


def _recompute_plan(plan: dict[str, Any], registry: str) -> None:
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    domain = _PLAN_DIGEST_DOMAINS[registry]
    plan["plan_digest"] = (
        "sha256:"
        + hashlib.sha256(domain.encode("ascii") + b"\0" + _json_bytes(unsigned)).hexdigest()
    )


def _recompute_replay(replay: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in replay.items() if key != "receipt_digest"}
    replay["receipt_digest"] = _flat_domain_digest("ALTERNATIVE_MODEL_REPLAY_RECEIPT", unsigned)


def _recompute_comparison(comparison: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in comparison.items() if key != "comparison_digest"}
    comparison["comparison_digest"] = _flat_domain_digest(
        "ALTERNATIVE_MODEL_COMPARISON_RECEIPT", unsigned
    )
    return cast(str, comparison["comparison_digest"])


def _last_manifest(corpus: dict[str, Any]) -> dict[str, Any]:
    generations = cast(list[dict[str, Any]], corpus["generations"])
    if not generations:
        raise Phase3MutationError("PHASE3_MUTATION_GENERATION_MISSING")
    return generations[-1]


def _manifest_at(corpus: dict[str, Any], index: int) -> dict[str, Any]:
    generations = cast(list[dict[str, Any]], corpus["generations"])
    if index >= len(generations):
        raise Phase3MutationError("PHASE3_MUTATION_GENERATION_MISSING")
    return generations[index]


def _longest_head(manifest: dict[str, Any], registry: str) -> dict[str, Any]:
    heads = cast(list[dict[str, Any]], manifest[f"{registry}_heads"])
    if not heads:
        raise Phase3MutationError("PHASE3_MUTATION_HEAD_MISSING", registry)
    return max(heads, key=lambda item: cast(int, item["entity_sequence"]))


def _inventory_head(manifest: dict[str, Any], registry: str) -> dict[str, Any]:
    """Longest head whose event is cited by THIS manifest's event inventory."""

    inventory = set(cast(list[str], manifest[f"{registry}_event_digests"]))
    heads = [
        item
        for item in cast(list[dict[str, Any]], manifest[f"{registry}_heads"])
        if item["event_digest"] in inventory
    ]
    if not heads:
        raise Phase3MutationError("PHASE3_MUTATION_HEAD_MISSING", registry)
    return max(heads, key=lambda item: cast(int, item["entity_sequence"]))


def _rebind_head_event(
    corpus: dict[str, Any],
    manifest: dict[str, Any],
    registry: str,
    head: dict[str, Any],
    event: dict[str, Any],
    new_digest: str,
) -> None:
    old_digest = cast(str, head["event_digest"])
    events = cast(dict[str, Any], corpus["events"])
    del events[old_digest]
    events[new_digest] = event
    head["event_digest"] = new_digest
    inventory = cast(list[str], manifest[f"{registry}_event_digests"])
    manifest[f"{registry}_event_digests"] = [
        new_digest if item == old_digest else item for item in inventory
    ]
    _recompute_manifest(manifest)


def _rebind_completion(
    corpus: dict[str, Any],
    manifest: dict[str, Any],
    completion: dict[str, Any],
    new_digest: str,
) -> None:
    old_digest = cast(str, manifest["clock_completion_digest"])
    completions = cast(dict[str, Any], corpus["completions"])
    del completions[old_digest]
    completions[new_digest] = completion
    manifest["clock_completion_digest"] = new_digest
    pointer = cast(dict[str, Any], corpus["current_pointer"])
    if pointer.get("generation_digest") == manifest.get("generation_digest"):
        pointer["clock_completion_digest"] = new_digest
    _recompute_manifest(manifest)


# --------------------------------------------------------------------------- #
# Mutation operators
# --------------------------------------------------------------------------- #


def _apply_operator(
    corpus: dict[str, Any],
    operator: str,
    parameters: dict[str, Any],
) -> None:
    del parameters
    generations = cast(list[dict[str, Any]], corpus["generations"])
    events = cast(dict[str, Any], corpus["events"])

    if operator == "CURRENT_POINTER_SEQUENCE":
        pointer = cast(dict[str, Any], corpus["current_pointer"])
        pointer["clock_sequence"] = cast(int, pointer["clock_sequence"]) + 1
    elif operator == "CURRENT_POINTER_GENERATION":
        cast(dict[str, Any], corpus["current_pointer"])["generation_digest"] = _ZERO_DIGEST
    elif operator == "CURRENT_POINTER_COMPLETION":
        cast(dict[str, Any], corpus["current_pointer"])["clock_completion_digest"] = _ZERO_DIGEST

    elif operator == "ACTIVE_MARKER_CLAIM_DIGEST":
        last = _last_manifest(corpus)
        corpus["active_marker"] = {
            "schema_version": "active-d5-generation/1",
            "clock_claim_digest": _ZERO_DIGEST,
            "generation_digest": last["generation_digest"],
        }
    elif operator == "ACTIVE_MARKER_GENERATION_DIGEST":
        last = _last_manifest(corpus)
        corpus["active_marker"] = {
            "schema_version": "active-d5-generation/1",
            "clock_claim_digest": last["clock_claim_digest"],
            "generation_digest": _ZERO_DIGEST,
        }

    elif operator == "GENERATION_SEQUENCE_GAP":
        last = _last_manifest(corpus)
        last["clock_sequence"] = cast(int, last["clock_sequence"]) + 1
        _recompute_manifest(last)
    elif operator == "GENERATION_PREDECESSOR_BREAK":
        last = _last_manifest(corpus)
        last["previous_generation_digest"] = _ZERO_DIGEST
        _recompute_manifest(last)
    elif operator == "GENERATION_SELF_DIGEST_CORRUPT":
        _manifest_at(corpus, 1)["clock_claim_digest"] = _ZERO_DIGEST
    elif operator == "GENERATION_FORK":
        last = _last_manifest(corpus)
        fork = deepcopy(last)
        fork["clock_claim_digest"] = _ZERO_DIGEST
        _recompute_manifest(fork)
        generations.append(fork)
    elif operator == "GENERATION_CHAIN_CYCLE":
        last = _last_manifest(corpus)
        _manifest_at(corpus, 0)["previous_generation_digest"] = last["generation_digest"]
    elif operator == "GENERATION_MISSING":
        del generations[1]

    elif operator == "PLAN_DIGEST_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        manifest["evidence_plan_digest"] = _ZERO_DIGEST
        _recompute_manifest(manifest)
    elif operator == "PLAN_SELF_DIGEST_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["expiry_plan_digest"] = _ZERO_DIGEST
    elif operator == "PLAN_ROOT_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["projected_root_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "evidence")
    elif operator == "PLAN_PREDECESSOR_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["predecessor_root_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "evidence")
    elif operator == "PLAN_CLAIM_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["clock_claim_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "evidence")
    elif operator == "PLAN_EVENT_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["validated_event_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "evidence")
    elif operator == "PLAN_SEMANTIC_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["evidence_plan_digest"]])
        plan["semantic_receipt_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "evidence")
    elif operator == "PLAN_EVENT_INVENTORY_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        inventory = cast(list[str], manifest["evidence_event_digests"])
        manifest["evidence_event_digests"] = inventory[:-1]
        _recompute_manifest(manifest)

    elif operator == "CROSS_ROOT_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        manifest["assumption_evidence_root_binding"] = _ZERO_DIGEST
        _recompute_manifest(manifest)
    elif operator == "PLAN_EVIDENCE_ROOT_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 1)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["assumption_plan_digest"]])
        plan["evidence_root_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "assumption")
    elif operator == "PLAN_ASSUMPTION_ROOT_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 1)
        plan = cast(dict[str, Any], corpus["projection_plans"][manifest["alt_model_plan_digest"]])
        plan["assumption_root_digest"] = _ZERO_DIGEST
        _recompute_plan(plan, "alt_model")

    elif operator == "CANONICAL_HEAD_SET_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        head = _longest_head(manifest, "evidence")
        head["event_digest"] = _ZERO_DIGEST
        _recompute_manifest(manifest)
    elif operator == "ENTITY_SEQUENCE_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        head = _longest_head(manifest, "evidence")
        head["entity_sequence"] = cast(int, head["entity_sequence"]) + 1
        _recompute_manifest(manifest)
    elif operator == "ENTITY_IDENTITY_CORRUPT":
        manifest = _last_manifest(corpus)
        head = _inventory_head(manifest, "evidence")
        event = cast(dict[str, Any], events[cast(str, head["event_digest"])])
        event["entity_id"] = "evidence:phase3-rogue-identity"
        new_digest = _rebuild_event(event)
        _rebind_head_event(corpus, manifest, "evidence", head, event, new_digest)
    elif operator == "ENTITY_PREDECESSOR_LINK_CORRUPT":
        manifest = _last_manifest(corpus)
        head = _inventory_head(manifest, "evidence")
        event = cast(dict[str, Any], events[cast(str, head["event_digest"])])
        event["previous_entity_event_digest"] = _ZERO_DIGEST
        new_digest = _rebuild_event(event)
        _rebind_head_event(corpus, manifest, "evidence", head, event, new_digest)
    elif operator == "EVENT_CLOCK_BINDING_CORRUPT":
        manifest = _last_manifest(corpus)
        head = _inventory_head(manifest, "evidence")
        event = cast(dict[str, Any], events[cast(str, head["event_digest"])])
        event["clock_sequence"] = cast(int, event["clock_sequence"]) + 1
        new_digest = _rebuild_event(event)
        _rebind_head_event(corpus, manifest, "evidence", head, event, new_digest)
    elif operator == "MISSING_EVENT_OBJECT":
        # Delete a mid-chain evidence event (the gen-3 CHALLENGE of ev-1, which
        # has a successor at gen 4) so both the inventory and the chain walk
        # hit the missing object.
        manifest = _manifest_at(corpus, 2)
        manifest_events = cast(list[str], manifest["evidence_event_digests"])
        if not manifest_events:
            raise Phase3MutationError("PHASE3_MUTATION_EVENT_MISSING", "evidence")
        del events[manifest_events[0]]
    elif operator == "EVIDENCE_EVENT_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        digest = cast(list[str], manifest["evidence_event_digests"])[0]
        cast(dict[str, Any], events[digest])["clock_sequence"] = 999
    elif operator == "ASSUMPTION_EVENT_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        digest = cast(list[str], manifest["assumption_event_digests"])[0]
        cast(dict[str, Any], events[digest])["clock_sequence"] = 999
    elif operator == "ALT_MODEL_EVENT_CORRUPT":
        manifest = _manifest_at(corpus, 1)
        digest = cast(list[str], manifest["alt_model_event_digests"])[0]
        cast(dict[str, Any], events[digest])["clock_sequence"] = 999

    elif operator == "COMPLETION_SEQUENCE_CORRUPT":
        manifest = _last_manifest(corpus)
        completion = cast(
            dict[str, Any], corpus["completions"][manifest["clock_completion_digest"]]
        )
        completion["clock_sequence"] = cast(int, completion["clock_sequence"]) + 1
        new_digest = _rebuild_contract("clock-completion-receipt", completion)
        _rebind_completion(corpus, manifest, completion, new_digest)
    elif operator == "COMPLETION_ROOT_CORRUPT":
        manifest = _last_manifest(corpus)
        completion = cast(
            dict[str, Any], corpus["completions"][manifest["clock_completion_digest"]]
        )
        cast(dict[str, Any], completion["registry_root_digests"])["evidence_unit"] = _ZERO_DIGEST
        new_digest = _rebuild_contract("clock-completion-receipt", completion)
        _rebind_completion(corpus, manifest, completion, new_digest)
    elif operator == "COMPLETION_PREDECESSOR_CORRUPT":
        manifest = _last_manifest(corpus)
        completion = cast(
            dict[str, Any], corpus["completions"][manifest["clock_completion_digest"]]
        )
        completion["previous_completion_digest"] = _ZERO_DIGEST
        new_digest = _rebuild_contract("clock-completion-receipt", completion)
        _rebind_completion(corpus, manifest, completion, new_digest)
    elif operator == "COMPLETION_MISSING":
        manifest = _last_manifest(corpus)
        del cast(dict[str, Any], corpus["completions"])[manifest["clock_completion_digest"]]
    elif operator == "QUARANTINE_BINDING_CORRUPT":
        manifest = _last_manifest(corpus)
        completion = cast(
            dict[str, Any], corpus["completions"][manifest["clock_completion_digest"]]
        )
        completion["quarantine_epoch"] = 1
        new_digest = _rebuild_contract("clock-completion-receipt", completion)
        _rebind_completion(corpus, manifest, completion, new_digest)

    elif operator == "SEMANTIC_RECEIPT_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        receipt = cast(
            dict[str, Any],
            corpus["semantic_receipts"][manifest["semantic_projection_receipt_digest"]],
        )
        receipt["projection_sequence"] = cast(int, receipt["projection_sequence"]) + 1
    elif operator == "SEMANTIC_RECEIPT_MISSING":
        manifest = _manifest_at(corpus, 0)
        del cast(dict[str, Any], corpus["semantic_receipts"])[
            manifest["semantic_projection_receipt_digest"]
        ]
    elif operator == "DISPOSITION_BINDING_CORRUPT":
        manifest = _manifest_at(corpus, 0)
        receipt = cast(
            dict[str, Any],
            corpus["disposition_receipts"][manifest["disposition_receipt_digest"]],
        )
        cast(dict[str, Any], receipt["registry_root_digests"])["assumption"] = _ZERO_DIGEST
        new_digest = _rebuild_contract("disposition-receipt", receipt)
        old_digest = cast(str, manifest["disposition_receipt_digest"])
        del cast(dict[str, Any], corpus["disposition_receipts"])[old_digest]
        cast(dict[str, Any], corpus["disposition_receipts"])[new_digest] = receipt
        manifest["disposition_receipt_digest"] = new_digest
        _recompute_manifest(manifest)
    elif operator == "DISPOSITION_RECEIPT_MISSING":
        manifest = _manifest_at(corpus, 0)
        del cast(dict[str, Any], corpus["disposition_receipts"])[
            manifest["disposition_receipt_digest"]
        ]

    elif operator == "D4_COMPARISON_DIGEST_CORRUPT":
        comparison = _sole_comparison(corpus)
        comparison["comparison_result"] = (
            "DIVERGENT" if comparison["comparison_result"] == "INVARIANT" else "INVARIANT"
        )
    elif operator == "D4_COMPARISON_BINDING_MISSING":
        comparison_digest = _sole_comparison_digest(corpus)
        del cast(dict[str, Any], corpus["comparison_receipts"])[comparison_digest]
    elif operator == "D4_REPLAY_INVENTORY_CORRUPT":
        comparison = _sole_comparison(corpus)
        shadow = cast(dict[str, Any], comparison["shadow_replay_receipt"])
        required = cast(list[str], shadow["required_inventory"])
        shadow["executed_inventory"] = required[:-1] if len(required) > 1 else []
        _recompute_replay(shadow)
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_REPLAY_CONTEXT_CORRUPT":
        comparison = _sole_comparison(corpus)
        cast(dict[str, Any], comparison["shadow_replay_receipt"])["decision_context_digest"] = (
            _ZERO_DIGEST
        )
        _recompute_replay(cast(dict[str, Any], comparison["shadow_replay_receipt"]))
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_REPLAY_STATE_CORRUPT":
        comparison = _sole_comparison(corpus)
        cast(dict[str, Any], comparison["shadow_replay_receipt"])["initial_state_digest"] = (
            _ZERO_DIGEST
        )
        _recompute_replay(cast(dict[str, Any], comparison["shadow_replay_receipt"]))
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_REPLAY_CLOCK_CORRUPT":
        comparison = _sole_comparison(corpus)
        shadow = cast(dict[str, Any], comparison["shadow_replay_receipt"])
        shadow["logical_clock"] = cast(int, shadow["logical_clock"]) + 1
        _recompute_replay(shadow)
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_REPLAY_RUNNER_CORRUPT":
        comparison = _sole_comparison(corpus)
        cast(dict[str, Any], comparison["shadow_replay_receipt"])["runner_revision"] = (
            "runner:rogue-phase3"
        )
        _recompute_replay(cast(dict[str, Any], comparison["shadow_replay_receipt"]))
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_COMPARISON_GRAPH_BINDING_CORRUPT":
        comparison = _sole_comparison(corpus)
        cast(dict[str, Any], comparison["primary_replay_receipt"])["graph_digest"] = _ZERO_DIGEST
        _recompute_replay(cast(dict[str, Any], comparison["primary_replay_receipt"]))
        _rekey_comparison(corpus, _recompute_comparison(comparison))
    elif operator == "D4_REPLAY_DIGEST_CORRUPT":
        comparison = _sole_comparison(corpus)
        cast(dict[str, Any], comparison["shadow_replay_receipt"])["receipt_digest"] = _ZERO_DIGEST

    else:
        raise Phase3MutationError("PHASE3_MUTATION_OPERATOR_UNSUPPORTED", operator)


def _sole_comparison(corpus: dict[str, Any]) -> dict[str, Any]:
    receipts = cast(dict[str, Any], corpus["comparison_receipts"])
    if len(receipts) != 1:
        raise Phase3MutationError("PHASE3_MUTATION_COMPARISON_COUNT_INVALID")
    return cast(dict[str, Any], next(iter(receipts.values())))


def _sole_comparison_digest(corpus: dict[str, Any]) -> str:
    receipts = cast(dict[str, Any], corpus["comparison_receipts"])
    if len(receipts) != 1:
        raise Phase3MutationError("PHASE3_MUTATION_COMPARISON_COUNT_INVALID")
    return next(iter(receipts))


def _rekey_comparison(corpus: dict[str, Any], new_digest: str) -> None:
    receipts = cast(dict[str, Any], corpus["comparison_receipts"])
    old_digest = _sole_comparison_digest(corpus)
    receipt = cast(dict[str, Any], receipts[old_digest])
    del receipts[old_digest]
    receipts[new_digest] = receipt


# --------------------------------------------------------------------------- #
# Declared campaign
# --------------------------------------------------------------------------- #


def _spec(
    mutation_id: str,
    family: str,
    operator: str,
    expected_detector: str,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "expected_classification": "KILLED",
        "expected_detector": expected_detector,
        "family": family,
        "mutation_id": mutation_id,
        "operator": operator,
        "parameters": dict(parameters or {}),
    }


def _declared_mutations() -> list[dict[str, Any]]:
    return [
        # Current pointer corruption.
        _spec(
            "P3M-001",
            "current-pointer",
            "CURRENT_POINTER_SEQUENCE",
            "PHASE3_POINTER_SEQUENCE_MISMATCH",
        ),
        _spec(
            "P3M-002",
            "current-pointer",
            "CURRENT_POINTER_GENERATION",
            "PHASE3_POINTER_GENERATION_MISMATCH",
        ),
        _spec(
            "P3M-003",
            "current-pointer",
            "CURRENT_POINTER_COMPLETION",
            "PHASE3_POINTER_COMPLETION_MISMATCH",
        ),
        # Active marker corruption.
        _spec(
            "P3M-004", "active-marker", "ACTIVE_MARKER_CLAIM_DIGEST", "PHASE3_ACTIVE_CLAIM_MISMATCH"
        ),
        _spec(
            "P3M-005",
            "active-marker",
            "ACTIVE_MARKER_GENERATION_DIGEST",
            "PHASE3_ACTIVE_UNKNOWN_GENERATION",
        ),
        # Generation chain.
        _spec(
            "P3M-010",
            "generation-chain",
            "GENERATION_SEQUENCE_GAP",
            "PHASE3_GENERATION_SEQUENCE_GAP",
        ),
        _spec(
            "P3M-011",
            "generation-chain",
            "GENERATION_PREDECESSOR_BREAK",
            "PHASE3_GENERATION_PREDECESSOR_BREAK",
        ),
        _spec(
            "P3M-012",
            "generation-chain",
            "GENERATION_SELF_DIGEST_CORRUPT",
            "PHASE3_GENERATION_SELF_DIGEST_MISMATCH",
        ),
        _spec("P3M-013", "generation-chain", "GENERATION_FORK", "PHASE3_GENERATION_FORK"),
        _spec(
            "P3M-014", "generation-chain", "GENERATION_CHAIN_CYCLE", "PHASE3_GENERATION_CHAIN_CYCLE"
        ),
        _spec(
            "P3M-015",
            "generation-chain",
            "GENERATION_MISSING",
            "PHASE3_GENERATION_PREDECESSOR_BREAK",
        ),
        # Projection-plan digest + binding corruption.
        _spec("P3M-020", "projection-plan", "PLAN_DIGEST_CORRUPT", "PHASE3_PLAN_MISSING"),
        _spec(
            "P3M-021",
            "projection-plan",
            "PLAN_SELF_DIGEST_CORRUPT",
            "PHASE3_PLAN_SELF_DIGEST_MISMATCH",
        ),
        _spec(
            "P3M-022",
            "projection-plan",
            "PLAN_ROOT_BINDING_CORRUPT",
            "PHASE3_PLAN_ROOT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-023",
            "projection-plan",
            "PLAN_PREDECESSOR_BINDING_CORRUPT",
            "PHASE3_PLAN_PREDECESSOR_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-024",
            "projection-plan",
            "PLAN_CLAIM_BINDING_CORRUPT",
            "PHASE3_PLAN_CLAIM_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-025",
            "projection-plan",
            "PLAN_EVENT_INVENTORY_CORRUPT",
            "PHASE3_PLAN_EVENT_INVENTORY_MISMATCH",
        ),
        _spec(
            "P3M-026",
            "projection-plan",
            "PLAN_EVENT_BINDING_CORRUPT",
            "PHASE3_PLAN_EVENT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-027",
            "projection-plan",
            "PLAN_SEMANTIC_BINDING_CORRUPT",
            "PHASE3_PLAN_SEMANTIC_BINDING_MISMATCH",
        ),
        # Cross-root bindings (E -> A -> M).
        _spec(
            "P3M-030",
            "cross-root",
            "CROSS_ROOT_BINDING_CORRUPT",
            "PHASE3_CROSS_ROOT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-031",
            "cross-root",
            "PLAN_EVIDENCE_ROOT_BINDING_CORRUPT",
            "PHASE3_PLAN_EVIDENCE_ROOT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-032",
            "cross-root",
            "PLAN_ASSUMPTION_ROOT_BINDING_CORRUPT",
            "PHASE3_PLAN_ASSUMPTION_ROOT_BINDING_MISMATCH",
        ),
        # Canonical head sets + entity chains.
        _spec(
            "P3M-040",
            "event-chain",
            "CANONICAL_HEAD_SET_CORRUPT",
            "PHASE3_ROOT_RECONSTRUCTION_MISMATCH",
        ),
        _spec(
            "P3M-041",
            "event-chain",
            "ENTITY_SEQUENCE_CORRUPT",
            "PHASE3_EVENT_CHAIN_SEQUENCE_MISMATCH",
        ),
        _spec(
            "P3M-042",
            "event-chain",
            "ENTITY_PREDECESSOR_LINK_CORRUPT",
            "PHASE3_EVENT_PREDECESSOR_MISSING",
        ),
        _spec(
            "P3M-043",
            "event-chain",
            "EVENT_CLOCK_BINDING_CORRUPT",
            "PHASE3_EVENT_CLOCK_BINDING_MISMATCH",
        ),
        _spec("P3M-044", "event-chain", "MISSING_EVENT_OBJECT", "PHASE3_EVENT_MISSING"),
        _spec(
            "P3M-045", "event-chain", "EVIDENCE_EVENT_CORRUPT", "PHASE3_EVENT_SELF_DIGEST_MISMATCH"
        ),
        _spec(
            "P3M-046",
            "event-chain",
            "ASSUMPTION_EVENT_CORRUPT",
            "PHASE3_EVENT_SELF_DIGEST_MISMATCH",
        ),
        _spec(
            "P3M-047", "event-chain", "ALT_MODEL_EVENT_CORRUPT", "PHASE3_EVENT_SELF_DIGEST_MISMATCH"
        ),
        _spec(
            "P3M-048",
            "event-chain",
            "ENTITY_IDENTITY_CORRUPT",
            "PHASE3_EVENT_CHAIN_ENTITY_MISMATCH",
        ),
        # Completion bindings.
        _spec(
            "P3M-050",
            "completion",
            "COMPLETION_SEQUENCE_CORRUPT",
            "PHASE3_COMPLETION_SEQUENCE_MISMATCH",
        ),
        _spec(
            "P3M-051",
            "completion",
            "COMPLETION_ROOT_CORRUPT",
            "PHASE3_COMPLETION_ROOT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-052",
            "completion",
            "COMPLETION_PREDECESSOR_CORRUPT",
            "PHASE3_COMPLETION_PREDECESSOR_MISMATCH",
        ),
        _spec("P3M-053", "completion", "COMPLETION_MISSING", "PHASE3_COMPLETION_MISSING"),
        _spec(
            "P3M-054",
            "completion",
            "QUARANTINE_BINDING_CORRUPT",
            "PHASE3_QUARANTINE_BINDING_MISMATCH",
        ),
        # Semantic / disposition reference receipts.
        _spec(
            "P3M-060",
            "reference-receipt",
            "SEMANTIC_RECEIPT_CORRUPT",
            "PHASE3_SEMANTIC_RECEIPT_DIGEST_INVALID",
        ),
        _spec(
            "P3M-061",
            "reference-receipt",
            "SEMANTIC_RECEIPT_MISSING",
            "PHASE3_SEMANTIC_RECEIPT_MISSING",
        ),
        _spec(
            "P3M-062",
            "reference-receipt",
            "DISPOSITION_BINDING_CORRUPT",
            "PHASE3_DISPOSITION_ROOT_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-063",
            "reference-receipt",
            "DISPOSITION_RECEIPT_MISSING",
            "PHASE3_DISPOSITION_RECEIPT_MISSING",
        ),
        # D4 comparison / FULL_REPLAY proof references.
        _spec(
            "P3M-070",
            "d4-comparison",
            "D4_COMPARISON_DIGEST_CORRUPT",
            "PHASE3_D4_COMPARISON_DIGEST_MISMATCH",
        ),
        _spec(
            "P3M-071",
            "d4-comparison",
            "D4_COMPARISON_BINDING_MISSING",
            "PHASE3_D4_COMPARISON_BINDING_MISSING",
        ),
        _spec(
            "P3M-072",
            "d4-comparison",
            "D4_REPLAY_INVENTORY_CORRUPT",
            "PHASE3_D4_REPLAY_INVENTORY_MISMATCH",
        ),
        _spec(
            "P3M-073",
            "d4-comparison",
            "D4_REPLAY_CONTEXT_CORRUPT",
            "PHASE3_D4_REPLAY_CONTEXT_MISMATCH",
        ),
        _spec(
            "P3M-074", "d4-comparison", "D4_REPLAY_STATE_CORRUPT", "PHASE3_D4_REPLAY_STATE_MISMATCH"
        ),
        _spec(
            "P3M-075", "d4-comparison", "D4_REPLAY_CLOCK_CORRUPT", "PHASE3_D4_REPLAY_CLOCK_MISMATCH"
        ),
        _spec(
            "P3M-076",
            "d4-comparison",
            "D4_REPLAY_RUNNER_CORRUPT",
            "PHASE3_D4_REPLAY_RUNNER_MISMATCH",
        ),
        _spec(
            "P3M-077",
            "d4-comparison",
            "D4_COMPARISON_GRAPH_BINDING_CORRUPT",
            "PHASE3_D4_COMPARISON_GRAPH_BINDING_MISMATCH",
        ),
        _spec(
            "P3M-078",
            "d4-comparison",
            "D4_REPLAY_DIGEST_CORRUPT",
            "PHASE3_D4_REPLAY_DIGEST_MISMATCH",
        ),
    ]


def _required_string(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if type(item) is not str or not item:
        raise Phase3MutationError("PHASE3_MUTATION_STRING_INVALID", field)
    return item


def _string_or_placeholder(value: object, placeholder: str) -> str:
    return value if type(value) is str and value else placeholder


__all__ = [
    "Phase3MutationError",
    "Phase3MutationReport",
    "Phase3MutationResult",
    "build_phase3_mutation_manifest",
    "evaluate_phase3_mutations",
    "phase3_corpus_digest",
]
