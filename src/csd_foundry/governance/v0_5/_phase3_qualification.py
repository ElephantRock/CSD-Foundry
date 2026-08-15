"""P3.7 Phase-3 integrated qualification: canary corpus + qualification runner.

Builds the deterministic Phase-3 canary corpus with REAL production adapters
(P3.1 evidence, P3.2 assumption, P3.5 alternative-model) against a real
``D5GenerationStore`` over a filesystem root, commits a five-generation chain
that exercises actual state movement in all three registries — registration,
verification, challenge, evidence invalidation, logical expiry, supersession,
and one genuine material D4 ADMIT with a ``ComparisonReceipt`` containing
primary/shadow FULL_REPLAY receipts — then serializes every committed artifact
into the canary corpus consumed by the independent validator and mutation
campaign.

Determinism: every committed artifact is content-addressed and derived from
fixed inputs (no timestamps, no randomness, no machine-specific paths), so
identical inputs produce byte-identical outputs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelExpiryAuthorization,
    StagedAlternativeModelProjectionAdapter,
)
from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionExpiryAuthorization,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5._d5_generation import (
    D5GenerationManifest,
    D5GenerationStore,
)
from csd_foundry.governance.v0_5._governed_alternative_model import (
    ComparisonReceipt,
    GovernedAlternativeModelAuthorization,
    ReplayReceipt,
    append_governed_alternative_model_admit,
    compare_alternative_model_replays,
    compute_structural_difference_digest,
    detect_structural_difference,
)
from csd_foundry.governance.v0_5.alternative_model import build_alternative_model_event
from csd_foundry.governance.v0_5.assumption import build_assumption_event
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.evidence import build_evidence_event
from csd_foundry.governance.v0_5.evidence_governance import (
    EvidenceAuthorityGrant,
    EvidenceAuthorityPolicy,
)
from csd_foundry.governance.v0_5.evidence_projection import StagedEvidenceProjectionAdapter
from csd_foundry.governance.v0_5.phase3_mutations import (
    Phase3MutationReport,
    build_phase3_mutation_manifest,
    evaluate_phase3_mutations,
    phase3_corpus_digest,
)
from csd_foundry.governance.v0_5.phase3_validation import (
    CORPUS_SCHEMA_VERSION,
    Phase3ValidationReport,
    validate_phase3_generations,
)
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    InMemoryRegistryStore,
)
from csd_foundry.governance.v0_5.temporal_validation import (
    ReferenceSemanticProjector,
    build_reference_validated_event,
)

QUALIFICATION_SCHEMA_VERSION = "phase3-qualification-report/1"
_CANARY_GENERATIONS = 5
_GOVERNED_MODEL_ID = "alt-model:phase3-am-1"


# --------------------------------------------------------------------------- #
# Digest helpers
# --------------------------------------------------------------------------- #


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _projection_source(
    domain: str, claim: ClockClaim, event: ValidatedEvent, semantic: SemanticProjectionReceipt
) -> str:
    payload = _canonical_json(
        {
            "clock_claim_digest": claim.digest,
            "semantic_receipt_digest": semantic.digest,
            "validated_event_digest": event.digest,
        }
    )
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


# --------------------------------------------------------------------------- #
# Authority policies + expiry authorities (deterministic)
# --------------------------------------------------------------------------- #


def _evidence_authority_policy() -> EvidenceAuthorityPolicy:
    grants = (
        EvidenceAuthorityGrant("CHALLENGE", "authority:challenger", ()),
        EvidenceAuthorityGrant("EXPIRE", "authority:clock", ()),
        EvidenceAuthorityGrant("INVALIDATE", "authority:resolver", ()),
        EvidenceAuthorityGrant("REGISTER", "authority:issuer", ()),
        EvidenceAuthorityGrant("REJECT", "authority:verifier", ()),
        EvidenceAuthorityGrant("RESOLVE_CHALLENGE", "authority:resolver", ()),
        EvidenceAuthorityGrant("SUPERSEDE", "authority:issuer", ()),
        EvidenceAuthorityGrant("VERIFY", "authority:verifier", ()),
    )
    return EvidenceAuthorityPolicy.build(
        policy_id="policy:evidence-phase3",
        committed_at_sequence=0,
        authority_root_digest=_digest("phase3-evidence-authority-root"),
        grants=grants,
    )


class _StaticAssumptionExpiryAuthority:
    def __init__(self, *, authority_id: str = "authority:clock") -> None:
        self._authority_id = authority_id

    @property
    def expiry_authority_id(self) -> str:
        return self._authority_id

    def expiry_authorization(
        self, *, assumption_id: str, clock_sequence: int
    ) -> AssumptionExpiryAuthorization | None:
        return AssumptionExpiryAuthorization.build(
            assumption_id=assumption_id,
            clock_sequence=clock_sequence,
            expiry_authority_id=self._authority_id,
            expiry_receipt_digest=_digest(f"phase3-expiry:{assumption_id}:{clock_sequence}"),
        )


class _StaticAltModelExpiryAuthority:
    def __init__(self, *, authority_id: str = "authority:clock") -> None:
        self._authority_id = authority_id

    @property
    def expiry_authority_id(self) -> str:
        return self._authority_id

    def expiry_authorization(
        self, *, model_id: str, clock_sequence: int
    ) -> AlternativeModelExpiryAuthorization | None:
        return AlternativeModelExpiryAuthorization.build(
            model_id=model_id,
            clock_sequence=clock_sequence,
            expiry_authority_id=self._authority_id,
            expiry_receipt_digest=_digest(f"phase3-expiry:{model_id}:{clock_sequence}"),
        )


class _StaticIntent:
    """Deterministic intent resolver returning pre-built events."""

    def __init__(self, events: tuple[RegistryEvent, ...]) -> None:
        self._events = events

    def resolve(self, **kwargs: object) -> tuple[RegistryEvent, ...]:
        del kwargs
        return self._events


# --------------------------------------------------------------------------- #
# Governed D4 ADMIT fixture (genuine material difference + FULL_REPLAY pair)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _GovernedAdmitFixture:
    propose_event: RegistryEvent
    admit_event: RegistryEvent
    authorization: GovernedAlternativeModelAuthorization
    comparison: ComparisonReceipt


def _build_replay_receipt(
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    semantic_outcome_digest: str,
) -> ReplayReceipt:
    required = ("node:n1",)
    unsigned: dict[str, object] = {
        "schema_version": "alternative-model-replay-receipt/1",
        "graph_digest": graph_digest,
        "decision_context_digest": decision_context_digest,
        "initial_state_digest": initial_state_digest,
        "logical_clock": 5,
        "runner_revision": "runner:phase3-v1",
        "required_inventory": list(required),
        "executed_inventory": list(required),
        "skipped_inventory": [],
        "pruned_inventory": [],
        "semantic_outcome_digest": semantic_outcome_digest,
    }
    receipt_digest = (
        "sha256:"
        + hashlib.sha256(
            b"ALTERNATIVE_MODEL_REPLAY_RECEIPT" + _canonical_json(unsigned)
        ).hexdigest()
    )
    return ReplayReceipt(
        graph_digest=graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=5,
        runner_revision="runner:phase3-v1",
        required_inventory=required,
        executed_inventory=required,
        skipped_inventory=(),
        pruned_inventory=(),
        semantic_outcome_digest=semantic_outcome_digest,
        receipt_digest=receipt_digest,
    )


def _build_governed_admit_fixture() -> _GovernedAdmitFixture:
    primary_graph = {
        "nodes": [{"node_id": "n1", "authority_id": "authority:primary"}],
        "semantic_seed": "phase3-primary",
    }
    shadow_graph = {
        "nodes": [
            {"node_id": "n1", "authority_id": "authority:shadow"},
            {"node_id": "n2", "authority_id": "authority:shadow"},
        ],
        "semantic_seed": "phase3-shadow",
    }
    primary_bytes = _canonical_json(primary_graph)
    shadow_bytes = _canonical_json(shadow_graph)
    primary_digest = "sha256:" + hashlib.sha256(primary_bytes).hexdigest()
    shadow_digest = "sha256:" + hashlib.sha256(shadow_bytes).hexdigest()
    declared_digest = compute_structural_difference_digest(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
    )
    receipt = detect_structural_difference(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        primary_graph_digest=primary_digest,
        shadow_graph_digest=shadow_digest,
        declared_difference_digest=declared_digest,
    )

    propose_event = build_alternative_model_event(
        model_id=_GOVERNED_MODEL_ID,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=1,
        source_receipt_digest=_digest("phase3-propose:alt-model"),
        payload={
            "operation": "PROPOSE",
            "model_version": "v1",
            "primary_model_id": "model:phase3-primary",
            "graph_digest": shadow_digest,
            "declared_difference_digest": declared_digest,
            "challenge_basis_code": "basis:phase3-shadow-divergence",
            "scope_ids": ["scope:phase3"],
            "assumption_ids": [],
            "evidence_ids": [],
            "proposer_authority_id": "authority:proposer",
            "materiality": "MATERIAL",
            "valid_from_sequence": 1,
            "expires_at_sequence": 99,
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )

    seed = InMemoryRegistryStore()
    seed.append(propose_event)
    result = append_governed_alternative_model_admit(
        store=seed,
        model_id=_GOVERNED_MODEL_ID,
        structural_difference_receipt=receipt,
        admitting_authority_id="authority:admitter",
        event_sequence=2,
    )

    decision_context = _digest("phase3-decision-context")
    initial_state = _digest("phase3-initial-state")
    primary_replay = _build_replay_receipt(
        graph_digest=primary_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("phase3-outcome:primary"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=shadow_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("phase3-outcome:shadow"),
    )
    comparison = compare_alternative_model_replays(
        structural_difference_receipt=receipt,
        primary_replay_receipt=primary_replay,
        shadow_replay_receipt=shadow_replay,
    )
    return _GovernedAdmitFixture(
        propose_event=propose_event,
        admit_event=result.event,
        authorization=result.authorization,
        comparison=comparison,
    )


# --------------------------------------------------------------------------- #
# Canary generation program
# --------------------------------------------------------------------------- #
#
# Five generations of actual state movement across all three registries:
#
#   gen 1: evidence REGISTER ev-1            assumption PROPOSE as-1    alt PROPOSE am-1
#   gen 2: evidence VERIFY ev-1              assumption PROPOSE as-2    alt ADMIT am-1 (D4)
#   gen 3: evidence CHALLENGE ev-1,           assumption SUPERSEDE      alt CONFIRM am-1
#          REGISTER ev-2                      as-1 -> as-2
#   gen 4: evidence INVALIDATE ev-1,          assumption PROPOSE as-3    alt CHALLENGE am-1
#          VERIFY ev-2
#   gen 5: evidence REGISTER ev-3 (+planner  assumption SUPERSEDE      alt RESOLVE am-1
#          logical EXPIRE of ev-2)            as-2 -> as-3
#
# Lifecycle conditions exercised: registration, verification, challenge
# (evidence + alternative-model), evidence invalidation, logical expiry
# (evidence planner), supersession (assumption), and a genuine material D4
# ADMIT with primary/shadow FULL_REPLAY comparison receipts.


def _register_payload(tag: str, sequence: int, expires: int | None) -> dict[str, object]:
    return {
        "operation": "REGISTER",
        "proposition_id": f"proposition:phase3-{tag}",
        "scope_ids": ["scope:phase3"],
        "source_id": f"source:phase3-{tag}",
        "issuer_authority_id": "authority:issuer",
        "issued_at_sequence": sequence,
        "valid_from_sequence": sequence,
        "expires_at_sequence": expires,
        "dependency_ids": [],
        "limitations": [],
        "maximum_reuse_class": "D2",
    }


def _propose_payload(tag: str, sequence: int, expires: int) -> dict[str, object]:
    return {
        "operation": "PROPOSE",
        "proposition_id": f"proposition:phase3-{tag}",
        "scope_ids": ["scope:phase3"],
        "materiality": "MATERIAL",
        "proposer_authority_id": "authority:proposer",
        "proposed_at_sequence": sequence,
        "valid_from_sequence": sequence,
        "expires_at_sequence": expires,
        "assumption_dependency_ids": [],
        "evidence_dependency_ids": [],
        "limitations": [],
        "maximum_reuse_class": "D2",
    }


_EV_1 = "evidence:phase3-ev-1"
_EV_2 = "evidence:phase3-ev-2"
_EV_3 = "evidence:phase3-ev-3"
_AS_1 = "assumption:phase3-as-1"
_AS_2 = "assumption:phase3-as-2"
_AS_3 = "assumption:phase3-as-3"

_EVIDENCE_PROGRAM: dict[int, list[tuple[str, dict[str, object]]]] = {
    1: [(_EV_1, _register_payload("ev-1", 1, 99))],
    2: [(_EV_1, {"operation": "VERIFY", "verifier_authority_id": "authority:verifier"})],
    3: [
        (
            _EV_1,
            {
                "operation": "CHALLENGE",
                "challenger_authority_id": "authority:challenger",
                "challenge_reason_code": "reason:phase3-evidence-challenge",
                "challenge_receipt_digest": _digest("phase3-challenge:ev-1"),
            },
        ),
        (_EV_2, _register_payload("ev-2", 3, 5)),
    ],
    4: [
        (
            _EV_1,
            {
                "operation": "INVALIDATE",
                "invalidating_authority_id": "authority:resolver",
                "reason_code": "reason:phase3-evidence-invalidation",
            },
        ),
        (_EV_2, {"operation": "VERIFY", "verifier_authority_id": "authority:verifier"}),
    ],
    5: [(_EV_3, _register_payload("ev-3", 5, None))],
}

_ASSUMPTION_PROGRAM: dict[int, list[tuple[str, dict[str, object]]]] = {
    1: [(_AS_1, _propose_payload("as-1", 1, 99))],
    2: [(_AS_2, _propose_payload("as-2", 2, 99))],
    3: [
        (
            _AS_1,
            {
                "operation": "SUPERSEDE",
                "replacement_assumption_id": _AS_2,
                "superseding_authority_id": "authority:issuer",
                "supersession_receipt_digest": _digest("phase3-supersession:as-1"),
                "reason_code": "reason:phase3-supersession",
            },
        )
    ],
    4: [(_AS_3, _propose_payload("as-3", 4, 99))],
    5: [
        (
            _AS_2,
            {
                "operation": "SUPERSEDE",
                "replacement_assumption_id": _AS_3,
                "superseding_authority_id": "authority:issuer",
                "supersession_receipt_digest": _digest("phase3-supersession:as-2"),
                "reason_code": "reason:phase3-supersession",
            },
        )
    ],
}

_ALT_MODEL_PAYLOADS: dict[int, dict[str, object]] = {
    3: {"operation": "CONFIRM", "confirming_authority_id": "authority:confirmer"},
    4: {
        "operation": "CHALLENGE",
        "challenge_id": "challenge:phase3-am-1",
        "challenger_authority_id": "authority:challenger",
        "challenge_reason_code": "reason:phase3-model-divergence",
        "challenge_receipt_digest": _digest("phase3-challenge:am-1"),
    },
    5: {
        "operation": "RESOLVE_CHALLENGES",
        "resolution_outcome": "UPHOLD",
        "resolver_authority_id": "authority:resolver",
        "resolution_receipt_digest": _digest("phase3-resolution:am-1"),
        "resolution_basis_code": "basis:phase3-resolution",
        "resolved_challenge_ids": ["challenge:phase3-am-1"],
        "replacement_model_id": None,
    },
}


def _registry_heads_of(
    manifest: D5GenerationManifest | None, registry: str
) -> dict[str, dict[str, object]]:
    if manifest is None:
        return {}
    raw = {
        "evidence": manifest.evidence_heads,
        "assumption": manifest.assumption_heads,
        "alt_model": manifest.alt_model_heads,
    }[registry]
    return {cast(str, item["entity_id"]): item for item in raw}


def _entity_id_kwarg(registry: str, entity_id: str) -> dict[str, str]:
    if registry == "evidence":
        return {"evidence_id": entity_id}
    if registry == "assumption":
        return {"assumption_id": entity_id}
    return {"model_id": entity_id}


def _build_program_events(
    *,
    builder: Any,
    manifest: D5GenerationManifest | None,
    registry: str,
    program: list[tuple[str, dict[str, object]]],
    sequence: int,
    source_domain: str,
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
) -> tuple[RegistryEvent, ...]:
    heads = _registry_heads_of(manifest, registry)
    source = _projection_source(source_domain, claim, validated_event, semantic)
    events: list[RegistryEvent] = []
    for entity_id, payload in program:
        head = heads.get(entity_id)
        entity_sequence = 1 if head is None else cast(int, head["entity_sequence"]) + 1
        previous = None if head is None else cast(str, head["event_digest"])
        event = builder(
            **_entity_id_kwarg(registry, entity_id),
            entity_sequence=entity_sequence,
            previous_entity_event_digest=previous,
            clock_sequence=sequence,
            source_receipt_digest=source,
            payload=payload,
        )
        events.append(event)
        heads[entity_id] = {
            "entity_id": entity_id,
            "entity_sequence": entity_sequence,
            "event_digest": event.digest,
        }
    return tuple(events)


# --------------------------------------------------------------------------- #
# Scenario construction
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Phase3CanaryScenario:
    """A committed canary scenario over a real filesystem root."""

    store: D5GenerationStore
    evidence_store: FilesystemRegistryStore
    assumption_store: FilesystemRegistryStore
    alt_model_store: FilesystemRegistryStore
    manifests: tuple[D5GenerationManifest, ...]


def phase3_context(
    sequence: int, previous_completion_digest: str | None = None
) -> tuple[ClockClaim, ValidatedEvent, SemanticProjectionReceipt]:
    """Deterministic temporal context for one canary generation."""

    validated_event = build_reference_validated_event()
    claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": f"attempt-phase3-{sequence}",
                "previous_committed_sequence": sequence - 1,
                "previous_completion_digest": previous_completion_digest,
                "proposed_sequence": sequence,
                "validated_event_digest": validated_event.digest,
                "claimant_id": "validator",
                "claim_policy_digest": _digest("phase3-claim-policy"),
            }
        ),
    )
    semantic = ReferenceSemanticProjector().project(
        claim=claim,
        validated_event=validated_event,
    )
    return claim, validated_event, semantic


def phase3_adapters(
    store: D5GenerationStore,
    sequence: int,
    previous_completion_digest: str | None = None,
) -> tuple[
    StagedEvidenceProjectionAdapter,
    StagedAssumptionProjectionAdapter,
    StagedAlternativeModelProjectionAdapter,
    tuple[tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...],
    tuple[ClockClaim, ValidatedEvent, SemanticProjectionReceipt],
]:
    """Build the three real staged adapters + governed evidence for a generation."""

    claim, validated_event, semantic = phase3_context(sequence, previous_completion_digest)
    manifest = store.current_generation()

    evidence_events = _build_program_events(
        builder=build_evidence_event,
        manifest=manifest,
        registry="evidence",
        program=_EVIDENCE_PROGRAM[sequence],
        sequence=sequence,
        source_domain="EVIDENCE_PROJECTION_SOURCE",
        claim=claim,
        validated_event=validated_event,
        semantic=semantic,
    )
    assumption_events = _build_program_events(
        builder=build_assumption_event,
        manifest=manifest,
        registry="assumption",
        program=_ASSUMPTION_PROGRAM[sequence],
        sequence=sequence,
        source_domain="ASSUMPTION_PROJECTION_SOURCE",
        claim=claim,
        validated_event=validated_event,
        semantic=semantic,
    )

    fixture = _build_governed_admit_fixture()
    governed: tuple[tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...] = ()
    if sequence == 1:
        alt_model_events: tuple[RegistryEvent, ...] = (fixture.propose_event,)
    elif sequence == 2:
        alt_model_events = (fixture.admit_event,)
        governed = ((fixture.authorization, fixture.comparison),)
    else:
        alt_model_events = _build_program_events(
            builder=build_alternative_model_event,
            manifest=manifest,
            registry="alt_model",
            program=[(_GOVERNED_MODEL_ID, _ALT_MODEL_PAYLOADS[sequence])],
            sequence=sequence,
            source_domain="ALTERNATIVE_MODEL_PROJECTION_SOURCE",
            claim=claim,
            validated_event=validated_event,
            semantic=semantic,
        )

    evidence_adapter = StagedEvidenceProjectionAdapter(
        authority_policy=_evidence_authority_policy(),
        expiry_authority_id="authority:clock",
        intent_resolver=_StaticIntent(evidence_events),
    )
    assumption_adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticAssumptionExpiryAuthority(),
        intent_resolver=_StaticIntent(assumption_events),
    )
    alt_model_adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticAltModelExpiryAuthority(),
        intent_resolver=_StaticIntent(alt_model_events),
    )
    return (
        evidence_adapter,
        assumption_adapter,
        alt_model_adapter,
        governed,
        (
            claim,
            validated_event,
            semantic,
        ),
    )


def commit_phase3_generation(
    store: D5GenerationStore,
    *,
    sequence: int,
    previous_completion_digest: str | None = None,
    adapters: tuple[Any, Any, Any] | None = None,
    governed_admit_evidence: tuple[
        tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...
    ] = (),
) -> D5GenerationManifest:
    """Prepare + commit one canary generation through the real D5 store."""

    (
        default_evidence,
        default_assumption,
        default_alt,
        governed,
        (
            claim,
            validated_event,
            semantic,
        ),
    ) = phase3_adapters(store, sequence, previous_completion_digest)
    evidence_adapter, assumption_adapter, alt_model_adapter = (
        adapters if adapters is not None else (default_evidence, default_assumption, default_alt)
    )
    governed_evidence = governed_admit_evidence or governed
    manifest = store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=evidence_adapter,
        assumption_adapter=assumption_adapter,
        alt_model_adapter=alt_model_adapter,
        governed_admit_evidence=governed_evidence,
    )
    store.commit_generation(manifest)
    return manifest


def build_phase3_scenario(
    root: Path, *, generations: int = _CANARY_GENERATIONS
) -> Phase3CanaryScenario:
    """Build and commit the canary scenario against a real filesystem root."""

    evidence_store = FilesystemRegistryStore(root / "evidence")
    assumption_store = FilesystemRegistryStore(root / "assumption")
    alt_model_store = FilesystemRegistryStore(root / "alt-model")
    store = D5GenerationStore(
        evidence_store=evidence_store,
        assumption_store=assumption_store,
        alt_model_store=alt_model_store,
        generations_dir=root / "generations",
    )
    manifests: list[D5GenerationManifest] = []
    previous_completion: str | None = None
    for sequence in range(1, generations + 1):
        manifest = commit_phase3_generation(
            store,
            sequence=sequence,
            previous_completion_digest=previous_completion,
        )
        manifests.append(manifest)
        previous_completion = manifest.clock_completion_digest
    return Phase3CanaryScenario(
        store=store,
        evidence_store=evidence_store,
        assumption_store=assumption_store,
        alt_model_store=alt_model_store,
        manifests=tuple(manifests),
    )


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def _digest_hex(digest: str) -> str:
    return digest.removeprefix("sha256:")


def _read_object(directory: Path, digest: str) -> dict[str, Any]:
    hex_digest = _digest_hex(digest)
    path = directory / hex_digest[:2] / f"{hex_digest[2:]}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise RuntimeError(f"serialized phase3 artifact is not an object: {path}")
    return cast(dict[str, Any], value)


def _read_all_objects(directory: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob("*/*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if type(value) is not dict:
            raise RuntimeError(f"serialized phase3 artifact is not an object: {path}")
        digest = value.get("comparison_digest")
        if type(digest) is not str:
            raise RuntimeError(f"serialized comparison receipt lacks digest: {path}")
        result[digest] = cast(dict[str, Any], value)
    return result


def serialize_phase3_corpus(scenario: Phase3CanaryScenario) -> dict[str, Any]:
    """Serialize every committed artifact of the scenario into the corpus."""

    store = scenario.store
    chain = store.reconstruct_generations()
    completions: dict[str, Any] = {}
    semantic_receipts: dict[str, Any] = {}
    projection_plans: dict[str, Any] = {}
    disposition_receipts: dict[str, Any] = {}
    events: dict[str, Any] = {}
    for manifest in chain:
        completions[manifest.clock_completion_digest] = _read_object(
            store.completions, manifest.clock_completion_digest
        )
        semantic_receipts[manifest.semantic_projection_receipt_digest] = _read_object(
            store.semantic_receipts, manifest.semantic_projection_receipt_digest
        )
        projection_plans[manifest.evidence_plan_digest] = _read_object(
            store.projection_plans, manifest.evidence_plan_digest
        )
        projection_plans[manifest.assumption_plan_digest] = _read_object(
            store.projection_plans, manifest.assumption_plan_digest
        )
        projection_plans[manifest.alt_model_plan_digest] = _read_object(
            store.projection_plans, manifest.alt_model_plan_digest
        )
        disposition_receipts[manifest.disposition_receipt_digest] = _read_object(
            store.disposition_receipts, manifest.disposition_receipt_digest
        )
        for registry, registry_store in (
            ("evidence", scenario.evidence_store),
            ("assumption", scenario.assumption_store),
            ("alt_model", scenario.alt_model_store),
        ):
            for digest in _manifest_event_digests(manifest, registry):
                if digest not in events:
                    events[digest] = _read_object(registry_store.objects, digest)
    comparison_receipts = _read_all_objects(store.comparison_receipts)
    pointer = json.loads(store.current_path.read_text(encoding="utf-8"))
    if type(pointer) is not dict:
        raise RuntimeError("serialized current pointer is not an object")
    return {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "current_pointer": cast(dict[str, Any], pointer),
        "active_marker": None,
        "generations": [manifest.to_json_value() for manifest in chain],
        "completions": completions,
        "semantic_receipts": semantic_receipts,
        "projection_plans": projection_plans,
        "disposition_receipts": disposition_receipts,
        "comparison_receipts": comparison_receipts,
        "events": events,
    }


def _manifest_event_digests(manifest: D5GenerationManifest, registry: str) -> tuple[str, ...]:
    if registry == "evidence":
        return manifest.evidence_event_digests
    if registry == "assumption":
        return manifest.assumption_event_digests
    return manifest.alt_model_event_digests


def build_phase3_canary_corpus(root: Path | None = None) -> dict[str, Any]:
    """Build the deterministic Phase-3 canary corpus (serialized artifacts)."""

    if root is None:
        with TemporaryDirectory(prefix="phase3-canary-") as temporary:
            return serialize_phase3_corpus(build_phase3_scenario(Path(temporary)))
    return serialize_phase3_corpus(build_phase3_scenario(root))


# --------------------------------------------------------------------------- #
# Qualification runner
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Phase3QualificationReport:
    """Complete P3.7 Phase-3 integrated qualification report."""

    corpus_digest: str
    replay_corpus_digest: str
    validation_report_digest: str
    mutation_report_digest: str
    generation_count: int
    mutation_count: int
    determinism_confirmed: bool
    validation_success: bool
    mutation_success: bool
    validation_errors: tuple[str, ...]
    mutation_errors: tuple[str, ...]
    mutation_unexplained_escapes: int
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return (
            not self.errors
            and self.determinism_confirmed
            and self.validation_success
            and self.mutation_success
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": QUALIFICATION_SCHEMA_VERSION,
            "status": "valid" if self.success else "invalid",
            "corpus_digest": self.corpus_digest,
            "replay_corpus_digest": self.replay_corpus_digest,
            "determinism_confirmed": self.determinism_confirmed,
            "generation_count": self.generation_count,
            "mutation_count": self.mutation_count,
            "mutation_report_digest": self.mutation_report_digest,
            "mutation_success": self.mutation_success,
            "mutation_unexplained_escapes": self.mutation_unexplained_escapes,
            "validation_report_digest": self.validation_report_digest,
            "validation_success": self.validation_success,
            "errors": list(self.errors),
            "claim_boundary": (
                "This report establishes deterministic reconstruction, corruption detection, "
                "and crash-recovery behavior of the serialized Phase-3 canary corpus relative "
                "to the committed independent validator and mutation campaign. It does not "
                "establish external truth, source completeness, real-world dependency "
                "completeness, or production safety."
            ),
        }

    @property
    def report_digest(self) -> str:
        payload = _canonical_json(self._unsigned_value())
        return "sha256:" + hashlib.sha256(b"PHASE3_QUALIFICATION_REPORT\0" + payload).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {**self._unsigned_value(), "report_digest": self.report_digest}


def run_phase3_qualification() -> Phase3QualificationReport:
    """Run the complete P3.7 Phase-3 integrated qualification."""

    errors: list[str] = []
    corpus = build_phase3_canary_corpus()
    replay_corpus = build_phase3_canary_corpus()

    corpus_digest = phase3_corpus_digest(corpus)
    replay_digest = phase3_corpus_digest(replay_corpus)
    determinism = corpus_digest == replay_digest
    if not determinism:
        errors.append("phase3 canary corpus is not deterministic across repeated builds")

    validation: Phase3ValidationReport = validate_phase3_generations(corpus)
    if not validation.success:
        errors.append("phase3 canary corpus failed independent validation")
    if validation.generation_count < 2:
        errors.append("phase3 canary corpus does not contain a generation chain")

    campaign = build_phase3_mutation_manifest(corpus)
    mutations: Phase3MutationReport = evaluate_phase3_mutations(corpus, campaign)
    if not mutations.success:
        errors.append("phase3 mutation campaign did not kill every declared mutation")

    validation_digest = _flat_report_digest("PHASE3_VALIDATION_REPORT", validation.to_dict())
    return Phase3QualificationReport(
        corpus_digest=corpus_digest,
        replay_corpus_digest=replay_digest,
        validation_report_digest=validation_digest,
        mutation_report_digest=mutations.report_digest,
        generation_count=validation.generation_count,
        mutation_count=len(mutations.results),
        determinism_confirmed=determinism,
        validation_success=validation.success,
        mutation_success=mutations.success,
        validation_errors=validation.errors,
        mutation_errors=mutations.errors,
        mutation_unexplained_escapes=mutations.unexplained_escape_count,
        errors=tuple(errors),
    )


def _flat_report_digest(domain: str, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + _canonical_json(value)).hexdigest()


__all__ = [
    "Phase3CanaryScenario",
    "Phase3QualificationReport",
    "build_phase3_canary_corpus",
    "build_phase3_scenario",
    "commit_phase3_generation",
    "phase3_adapters",
    "phase3_context",
    "run_phase3_qualification",
    "serialize_phase3_corpus",
]
