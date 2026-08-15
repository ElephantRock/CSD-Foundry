"""Full P3.6 acceptance campaign for the D5 atomic multi-registry integration layer.

Exercises three-registry state movement, cross-phase root binding, atomic
commit-point visibility, recovery, determinism, and every pre-commit failure
path. Uses real projection adapters (P3.1/P3.2/P3.5) with deterministic intent
resolvers and expiry authorities.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelExpiryAuthorization,
    StagedAlternativeModelProjectionAdapter,
)
from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionExpiryAuthorization,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5._d5_generation import (
    D5GenerationConflictError,
    D5GenerationError,
    D5GenerationManifest,
    D5GenerationStore,
    GenerationRegistryView,
    ReferenceDispositionAdapter,
    ReferenceQuarantineAdapter,
    _validate_cross_phase_bindings,
)
from csd_foundry.governance.v0_5._governed_alternative_model import (
    ComparisonReceipt,
    GovernedAlternativeModelAuthorization,
    StructuralDifferenceReceipt,
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
from csd_foundry.governance.v0_5.evidence_projection import (
    StagedEvidenceProjectionAdapter,
)
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    InMemoryRegistryStore,
    RegistryEntityHead,
    RegistryStoreError,
)
from csd_foundry.governance.v0_5.temporal_validation import (
    ReferenceSemanticProjector,
    build_reference_validated_event,
)

# --------------------------------------------------------------------------- #
# Digest + JSON helpers
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
# Authority policies + expiry authorities
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
        policy_id="policy:evidence-d5",
        committed_at_sequence=0,
        authority_root_digest=_digest("evidence-authority-root"),
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
            expiry_receipt_digest=_digest(f"expiry:{assumption_id}:{clock_sequence}"),
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
            expiry_receipt_digest=_digest(f"expiry:{model_id}:{clock_sequence}"),
        )


# --------------------------------------------------------------------------- #
# Intent resolvers
# --------------------------------------------------------------------------- #


class _EvidenceIntent:
    def __init__(self, event: RegistryEvent) -> None:
        self._event = event

    def resolve(self, **kwargs: object) -> tuple[RegistryEvent, ...]:
        del kwargs
        return (self._event,)


class _AssumptionIntent:
    def __init__(self, event: RegistryEvent) -> None:
        self._event = event

    def resolve(self, **kwargs: object) -> tuple[RegistryEvent, ...]:
        del kwargs
        return (self._event,)


class _AltModelIntent:
    def __init__(self, event: RegistryEvent) -> None:
        self._event = event

    def resolve(self, **kwargs: object) -> tuple[RegistryEvent, ...]:
        del kwargs
        return (self._event,)


# --------------------------------------------------------------------------- #
# Event builders
# --------------------------------------------------------------------------- #


def _build_evidence_event(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
    sequence: int,
    tag: str,
) -> RegistryEvent:
    source = _projection_source("EVIDENCE_PROJECTION_SOURCE", claim, validated_event, semantic)
    return build_evidence_event(
        evidence_id=f"evidence:d5-{tag}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=sequence,
        source_receipt_digest=source,
        payload={
            "operation": "REGISTER",
            "proposition_id": f"proposition:d5-evidence-{tag}",
            "scope_ids": ["scope:d5"],
            "source_id": f"source:d5-{tag}",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": sequence,
            "valid_from_sequence": sequence,
            "expires_at_sequence": sequence + 100,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _build_assumption_event(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
    sequence: int,
    tag: str,
) -> RegistryEvent:
    source = _projection_source("ASSUMPTION_PROJECTION_SOURCE", claim, validated_event, semantic)
    return build_assumption_event(
        assumption_id=f"assumption:d5-{tag}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=sequence,
        source_receipt_digest=source,
        payload={
            "operation": "PROPOSE",
            "proposition_id": f"proposition:d5-assumption-{tag}",
            "scope_ids": ["scope:d5"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": sequence,
            "valid_from_sequence": sequence,
            "expires_at_sequence": sequence + 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _build_alt_model_event(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
    sequence: int,
    tag: str,
) -> RegistryEvent:
    source = _projection_source(
        "ALTERNATIVE_MODEL_PROJECTION_SOURCE", claim, validated_event, semantic
    )
    return build_alternative_model_event(
        model_id=f"alt-model:d5-{tag}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=sequence,
        source_receipt_digest=source,
        payload={
            "operation": "PROPOSE",
            "model_version": "v1",
            "primary_model_id": "model:primary",
            "graph_digest": _digest(f"graph:d5-{tag}"),
            "declared_difference_digest": _digest(f"difference:d5-{tag}"),
            "challenge_basis_code": "basis:d5-shadow-divergence",
            "scope_ids": ["scope:d5"],
            "assumption_ids": [],
            "evidence_ids": [],
            "proposer_authority_id": "authority:proposer",
            "materiality": "MATERIAL",
            "valid_from_sequence": sequence,
            "expires_at_sequence": sequence + 100,
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


# --------------------------------------------------------------------------- #
# Context + fixture
# --------------------------------------------------------------------------- #


def _context(
    sequence: int, previous_completion_digest: str | None = None
) -> tuple[ClockClaim, ValidatedEvent, SemanticProjectionReceipt]:
    validated_event = build_reference_validated_event()
    claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": f"attempt-d5-{sequence}",
                "previous_committed_sequence": sequence - 1,
                "previous_completion_digest": previous_completion_digest,
                "proposed_sequence": sequence,
                "validated_event_digest": validated_event.digest,
                "claimant_id": "validator",
                "claim_policy_digest": _digest("d5-claim-policy"),
            }
        ),
    )
    semantic = ReferenceSemanticProjector().project(
        claim=claim,
        validated_event=validated_event,
    )
    return claim, validated_event, semantic


def _build_adapters(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
    sequence: int,
    tag: str,
) -> tuple[
    StagedEvidenceProjectionAdapter,
    StagedAssumptionProjectionAdapter,
    StagedAlternativeModelProjectionAdapter,
]:
    evidence_event = _build_evidence_event(claim, validated_event, semantic, sequence, tag)
    assumption_event = _build_assumption_event(claim, validated_event, semantic, sequence, tag)
    alt_model_event = _build_alt_model_event(claim, validated_event, semantic, sequence, tag)
    evidence_adapter = StagedEvidenceProjectionAdapter(
        authority_policy=_evidence_authority_policy(),
        expiry_authority_id="authority:clock",
        intent_resolver=_EvidenceIntent(evidence_event),
    )
    assumption_adapter = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticAssumptionExpiryAuthority(),
        intent_resolver=_AssumptionIntent(assumption_event),
    )
    alt_model_adapter = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticAltModelExpiryAuthority(),
        intent_resolver=_AltModelIntent(alt_model_event),
    )
    return evidence_adapter, assumption_adapter, alt_model_adapter


def _build_store(tmp_path: Path) -> D5GenerationStore:
    return D5GenerationStore(
        evidence_store=FilesystemRegistryStore(tmp_path / "evidence"),
        assumption_store=FilesystemRegistryStore(tmp_path / "assumption"),
        alt_model_store=FilesystemRegistryStore(tmp_path / "alt-model"),
        generations_dir=tmp_path / "generations",
    )


def _build_store_with_factories(
    tmp_path: Path,
    *,
    disposition_adapter_factory: object = None,
    quarantine_adapter_factory: object = None,
) -> D5GenerationStore:
    """Build a D5 store against ``tmp_path`` with injected adapter factories."""

    kwargs: dict[str, object] = {
        "evidence_store": FilesystemRegistryStore(tmp_path / "evidence"),
        "assumption_store": FilesystemRegistryStore(tmp_path / "assumption"),
        "alt_model_store": FilesystemRegistryStore(tmp_path / "alt-model"),
        "generations_dir": tmp_path / "generations",
    }
    if disposition_adapter_factory is not None:
        kwargs["disposition_adapter_factory"] = disposition_adapter_factory
    if quarantine_adapter_factory is not None:
        kwargs["quarantine_adapter_factory"] = quarantine_adapter_factory
    return D5GenerationStore(**kwargs)  # type: ignore[arg-type]


def _reopen_store(tmp_path: Path) -> D5GenerationStore:
    """Reopen the D5 store against the same on-disk directories (restart)."""

    return D5GenerationStore(
        evidence_store=FilesystemRegistryStore(tmp_path / "evidence"),
        assumption_store=FilesystemRegistryStore(tmp_path / "assumption"),
        alt_model_store=FilesystemRegistryStore(tmp_path / "alt-model"),
        generations_dir=tmp_path / "generations",
    )


def _capture_state(store: D5GenerationStore) -> tuple[str, str, str, str, int, str | None]:
    """Capture the byte-identical D5 authority tuple.

    Used by phase-failure isolation tests to assert the current-generation
    pointer, all three current roots, and the temporal head (clock sequence +
    completion digest) are byte-identical before and after a failed attempt.
    """

    completion = store.current_completion()
    return (
        store.current_generation_digest(),
        store.current_evidence_root(),
        store.current_assumption_root(),
        store.current_alt_model_root(),
        store.current_clock_sequence(),
        completion.digest if completion is not None else None,
    )


def _prepare_one(
    store: D5GenerationStore,
    sequence: int,
    tag: str,
    previous_completion_digest: str | None = None,
    governed_admit_evidence: tuple[
        tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...
    ] = (),
    evidence_adapter: StagedEvidenceProjectionAdapter | None = None,
    assumption_adapter: StagedAssumptionProjectionAdapter | None = None,
    alt_model_adapter: StagedAlternativeModelProjectionAdapter | None = None,
) -> D5GenerationManifest:
    claim, validated_event, semantic = _context(sequence, previous_completion_digest)
    default_ev, default_as, default_am = _build_adapters(
        claim, validated_event, semantic, sequence, tag
    )
    return store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=evidence_adapter or default_ev,
        assumption_adapter=assumption_adapter or default_as,
        alt_model_adapter=alt_model_adapter or default_am,
        governed_admit_evidence=governed_admit_evidence,
    )


@pytest.fixture
def d5(tmp_path: Path) -> SimpleNamespace:
    store = _build_store(tmp_path)
    return SimpleNamespace(
        store=store,
        tmp_path=tmp_path,
        evidence_store=store._evidence_store,
        assumption_store=store._assumption_store,
        alt_model_store=store._alt_model_store,
    )


# --------------------------------------------------------------------------- #
# Success path
# --------------------------------------------------------------------------- #


def test_three_registry_state_movement_in_one_tick(d5: SimpleNamespace) -> None:
    """All three registries advance in a single D5 generation tick."""

    empty_evidence = d5.store.current_evidence_root()
    empty_assumption = d5.store.current_assumption_root()
    empty_alt_model = d5.store.current_alt_model_root()

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)

    assert d5.store.current_evidence_root() != empty_evidence
    assert d5.store.current_assumption_root() != empty_assumption
    assert d5.store.current_alt_model_root() != empty_alt_model

    assert d5.store.current_evidence_root() == manifest.evidence_projected_root
    assert d5.store.current_assumption_root() == manifest.assumption_projected_root
    assert d5.store.current_alt_model_root() == manifest.alt_model_projected_root

    assert len(manifest.evidence_event_digests) >= 1
    assert len(manifest.assumption_event_digests) >= 1
    assert len(manifest.alt_model_event_digests) >= 1


def test_exact_phase_order_observed(d5: SimpleNamespace) -> None:
    """Cross-phase root bindings prove the frozen phase order was followed."""

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)

    assert manifest.assumption_evidence_root_binding == manifest.evidence_projected_root
    assert manifest.alt_model_evidence_root_binding == manifest.evidence_projected_root
    assert manifest.alt_model_assumption_root_binding == manifest.assumption_projected_root
    assert manifest.quarantine_epoch == 0
    assert manifest.quarantine_marker_digests == ()


def test_assumption_consumes_candidate_evidence_root(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    assert manifest.assumption_evidence_root_binding == manifest.evidence_projected_root
    d5.store.commit_generation(manifest)


def test_alt_model_consumes_candidate_evidence_and_assumption_roots(
    d5: SimpleNamespace,
) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    assert manifest.alt_model_evidence_root_binding == manifest.evidence_projected_root
    assert manifest.alt_model_assumption_root_binding == manifest.assumption_projected_root
    d5.store.commit_generation(manifest)


def test_completion_cites_exactly_three_candidate_roots(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)
    completion = d5.store.current_completion()
    assert completion is not None
    roots = cast(dict[str, str], completion.to_json_value()["registry_root_digests"])
    assert roots["evidence_unit"] == manifest.evidence_projected_root
    assert roots["assumption"] == manifest.assumption_projected_root
    assert roots["alternative_model"] == manifest.alt_model_projected_root


def test_after_commit_all_three_roots_visible_together(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    assert d5.store.current_evidence_root() == manifest.evidence_projected_root
    assert d5.store.current_assumption_root() == manifest.assumption_projected_root
    assert d5.store.current_alt_model_root() == manifest.alt_model_projected_root


def test_previous_generation_reconstructable_after_successor(
    d5: SimpleNamespace,
) -> None:
    manifest1 = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest1)
    manifest2 = _prepare_one(
        d5.store,
        sequence=2,
        tag="gen2",
        previous_completion_digest=manifest1.clock_completion_digest,
    )
    d5.store.commit_generation(manifest2)

    chain = d5.store.reconstruct_generations()
    assert len(chain) == 2
    assert chain[0].generation_digest == manifest1.generation_digest
    assert chain[1].generation_digest == manifest2.generation_digest
    assert chain[1].previous_generation_digest == manifest1.generation_digest


def test_every_root_reconstructs_from_canonical_heads(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)

    # Defect 1: D5 authority flows from the manifest head sets + generation
    # pointer, NOT from the live per-entity registry heads (which D5 never
    # advances). The generation views reconstruct the canonical state.
    evidence_view = d5.store.evidence_view()
    assumption_view = d5.store.assumption_view()
    alt_model_view = d5.store.alt_model_view()

    evidence_snap = evidence_view.snapshot("EVIDENCE_UNIT")
    assumption_snap = assumption_view.snapshot("ASSUMPTION")
    alt_model_snap = alt_model_view.snapshot("ALTERNATIVE_MODEL")

    assert evidence_snap.root_digest == manifest.evidence_projected_root
    assert assumption_snap.root_digest == manifest.assumption_projected_root
    assert alt_model_snap.root_digest == manifest.alt_model_projected_root

    assert tuple(manifest.evidence_heads) == _heads_to_dicts(evidence_snap.heads)
    assert tuple(manifest.assumption_heads) == _heads_to_dicts(assumption_snap.heads)
    assert tuple(manifest.alt_model_heads) == _heads_to_dicts(alt_model_snap.heads)

    for head in evidence_snap.heads:
        history = evidence_view.reconstruct_entity("EVIDENCE_UNIT", head.entity_id)
        assert history[-1].digest == head.event_digest


def test_d4_admit_comparison_evidence_consumed_from_p3_5_plans(
    d5: SimpleNamespace,
) -> None:
    """The alt-model plan (including comparison bindings) is consumed by digest."""

    claim, validated_event, semantic = _context(1)
    evidence_adapter, assumption_adapter, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, sequence=1, tag="gen1"
    )
    evidence_plan = evidence_adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=d5.evidence_store,
    )
    assumption_plan = assumption_adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=d5.assumption_store,
        evidence_root_digest=evidence_plan.projected_root_digest,
    )
    alt_model_plan = alt_model_adapter.project(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        committed_store=d5.alt_model_store,
        evidence_root_digest=evidence_plan.projected_root_digest,
        assumption_root_digest=assumption_plan.projected_root_digest,
    )
    manifest = d5.store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=evidence_adapter,
        assumption_adapter=assumption_adapter,
        alt_model_adapter=alt_model_adapter,
    )
    # The D5 manifest captures the P3.5 plan by digest, including its
    # admit_comparison_bindings — the D5 layer does not re-run the comparison.
    assert manifest.alt_model_plan_digest == alt_model_plan.plan_digest
    assert manifest.alt_model_plan_digest == alt_model_plan.to_json_value()["plan_digest"]
    # Corrupting the plan digest must make the manifest unverifiable.
    corrupted = dict(manifest.to_json_value())
    corrupted["alt_model_plan_digest"] = _digest("corrupted-plan")
    with pytest.raises(D5GenerationError):
        D5GenerationManifest.from_json(corrupted)


# --------------------------------------------------------------------------- #
# Failure paths (pre-commit)
# --------------------------------------------------------------------------- #


def test_commit_isolated_from_evidence_store_head_mutation(d5: SimpleNamespace) -> None:
    """Defect 1: a rogue evidence-store append between prepare and commit must
    not corrupt or block the D5 generation. D5 reads from generation-bound views
    (the current generation's head sets), not the live mutable registry heads,
    so a standalone head advancement is invisible to the atomic commit."""

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    _append_direct_evidence(d5.evidence_store, clock=99)
    # Commit succeeds — D5 does not consult the live evidence head.
    d5.store.commit_generation(manifest)
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    # The committed evidence root is the manifest's projected root, NOT the
    # rogue append's root.
    assert d5.store.current_evidence_root() == manifest.evidence_projected_root


def test_commit_isolated_from_assumption_store_head_mutation(d5: SimpleNamespace) -> None:
    """Defect 1: rogue assumption-store append does not affect the D5 commit."""

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    _append_direct_assumption(d5.assumption_store, clock=99)
    d5.store.commit_generation(manifest)
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    assert d5.store.current_assumption_root() == manifest.assumption_projected_root


def test_commit_isolated_from_alt_model_store_head_mutation(d5: SimpleNamespace) -> None:
    """Defect 1: rogue alt-model-store append does not affect the D5 commit."""

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    _append_direct_alt_model(d5.alt_model_store, clock=99)
    d5.store.commit_generation(manifest)
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    assert d5.store.current_alt_model_root() == manifest.alt_model_projected_root


def test_wrong_downstream_root_binding_detected() -> None:
    """Cross-phase binding validation catches a wrong downstream root."""

    claim, validated_event, semantic = _context(1)
    evidence_proj = _digest("evidence-projected-root")
    assumption_proj = _digest("assumption-projected-root")
    alt_model_proj = _digest("alt-model-projected-root")
    evidence_plan = _make_plan_stub(
        claim,
        validated_event,
        semantic,
        predecessor_root=_digest("ev-pred"),
        projected_root=evidence_proj,
    )
    assumption_plan = _make_plan_stub(
        claim,
        validated_event,
        semantic,
        predecessor_root=_digest("as-pred"),
        projected_root=assumption_proj,
        evidence_root_digest=_digest("wrong-evidence-root"),
    )
    alt_model_plan = _make_plan_stub(
        claim,
        validated_event,
        semantic,
        predecessor_root=_digest("am-pred"),
        projected_root=alt_model_proj,
        evidence_root_digest=evidence_proj,
        assumption_root_digest=assumption_proj,
    )
    with pytest.raises(D5GenerationConflictError) as exc:
        _validate_cross_phase_bindings(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_plan=evidence_plan,
            assumption_plan=assumption_plan,
            alt_model_plan=alt_model_plan,
            evidence_predecessor=_digest("ev-pred"),
            assumption_predecessor=_digest("as-pred"),
            alt_model_predecessor=_digest("am-pred"),
        )
    assert exc.value.code == "D5_ASSUMPTION_EVIDENCE_ROOT_BINDING_MISMATCH"


def test_wrong_claim_event_semantic_clock_binding_detected() -> None:
    """Cross-phase binding validation catches a wrong claim binding."""

    claim, validated_event, semantic = _context(1)
    evidence_plan = _make_plan_stub(
        claim,
        validated_event,
        semantic,
        predecessor_root=_digest("ev-pred"),
        clock_claim_digest=_digest("wrong-claim"),
    )
    assumption_plan = _make_plan_stub(
        claim, validated_event, semantic, predecessor_root=_digest("as-pred")
    )
    alt_model_plan = _make_plan_stub(
        claim, validated_event, semantic, predecessor_root=_digest("am-pred")
    )
    with pytest.raises(D5GenerationConflictError) as exc:
        _validate_cross_phase_bindings(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_plan=evidence_plan,
            assumption_plan=assumption_plan,
            alt_model_plan=alt_model_plan,
            evidence_predecessor=_digest("ev-pred"),
            assumption_predecessor=_digest("as-pred"),
            alt_model_predecessor=_digest("am-pred"),
        )
    assert exc.value.code == "D5_EVIDENCE_CLAIM_BINDING_MISMATCH"


def test_corrupted_projection_plan_digest_fails(d5: SimpleNamespace) -> None:
    """A plan whose self-digest is corrupted cannot be produced."""

    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    value = manifest.to_json_value()
    corrupted = dict(value)
    corrupted["evidence_plan_digest"] = _digest("corrupted")
    with pytest.raises(D5GenerationError):
        D5GenerationManifest.from_json(corrupted)


def test_corrupted_generation_manifest_fails(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    value = manifest.to_json_value()
    corrupted = dict(value)
    corrupted["clock_sequence"] = 999
    with pytest.raises(D5GenerationError):
        D5GenerationManifest.from_json(corrupted)


# --------------------------------------------------------------------------- #
# Atomicity / recovery
# --------------------------------------------------------------------------- #


def test_no_candidate_root_current_before_commit(d5: SimpleNamespace) -> None:
    empty_evidence = d5.store.current_evidence_root()
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    assert d5.store.current_evidence_root() == empty_evidence
    assert d5.store.current_generation() is None
    assert manifest.evidence_projected_root != empty_evidence


def test_no_reader_observes_mixed_generation(d5: SimpleNamespace) -> None:
    manifest1 = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest1)
    manifest2 = _prepare_one(
        d5.store,
        sequence=2,
        tag="gen2",
        previous_completion_digest=manifest1.clock_completion_digest,
    )
    # Before commit, the current generation is still gen1.
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest1.generation_digest
    d5.store.commit_generation(manifest2)
    # After commit, the current generation is gen2 — never a mix.
    current = d5.store.current_generation()
    assert current is not None
    assert current.generation_digest == manifest2.generation_digest


def test_restart_before_publication_exposes_only_predecessor(
    d5: SimpleNamespace,
) -> None:
    manifest1 = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest1)
    _prepare_one(
        d5.store,
        sequence=2,
        tag="gen2",
        previous_completion_digest=manifest1.clock_completion_digest,
    )
    # Simulate a crash that leaves the active claim but loses the prepared
    # bundle: recovery must fail the attempt closed and keep gen1 current.
    Path(d5.tmp_path / "generations" / "state" / "prepared-generation.json").unlink()
    reopened = _reopen_store(d5.tmp_path)
    result = reopened.recover()
    assert result == "INCOMPLETE_GENERATION_FAILED"
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest1.generation_digest


def test_restart_with_prepared_generation_publishes_idempotently(
    d5: SimpleNamespace,
) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    assert d5.store.current_generation() is None
    reopened = _reopen_store(d5.tmp_path)
    result = reopened.recover()
    assert result == "PREPARED_GENERATION_PUBLISHED"
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    # Second recovery is idempotent.
    reopened2 = _reopen_store(d5.tmp_path)
    assert reopened2.recover() == "NO_ACTIVE_GENERATION"
    assert reopened2.current_generation() is not None
    assert reopened2.current_generation().generation_digest == manifest.generation_digest


def test_restart_after_pointer_replacement_reconstructs_same_state(
    d5: SimpleNamespace,
) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)
    reopened = _reopen_store(d5.tmp_path)
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest.generation_digest
    assert reopened.current_evidence_root() == manifest.evidence_projected_root
    assert reopened.current_assumption_root() == manifest.assumption_projected_root
    assert reopened.current_alt_model_root() == manifest.alt_model_projected_root


def test_retry_after_failed_attempt_reuses_clock_sequence(
    d5: SimpleNamespace,
) -> None:
    assert d5.store.recover() == "NO_ACTIVE_GENERATION"
    _prepare_one(d5.store, sequence=1, tag="gen1")
    assert d5.store.current_clock_sequence() == 0
    # Simulate crash: remove the prepared bundle so recovery fails the attempt.
    Path(d5.tmp_path / "generations" / "state" / "prepared-generation.json").unlink()
    reopened = _reopen_store(d5.tmp_path)
    assert reopened.recover() == "INCOMPLETE_GENERATION_FAILED"
    assert reopened.current_clock_sequence() == 0
    # Retry uses the same clock sequence (1).
    manifest_retry = _prepare_one(reopened, sequence=1, tag="gen1")
    assert manifest_retry.clock_sequence == 1
    reopened.commit_generation(manifest_retry)
    assert reopened.current_clock_sequence() == 1


def test_release_compilation_count_remains_zero(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)
    completion = d5.store.current_completion()
    assert completion is not None
    value = completion.to_json_value()
    assert value["quarantine_epoch"] == 0
    assert value["quarantine_marker_digests"] == []
    # No release compilation is invoked by the D5 integration layer.
    assert manifest.quarantine_epoch == 0


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_same_inputs_produce_byte_identical_manifest_and_completion(
    d5: SimpleNamespace,
) -> None:
    claim, validated_event, semantic = _context(1)
    adapters1 = _build_adapters(claim, validated_event, semantic, 1, "gen1")
    adapters2 = _build_adapters(claim, validated_event, semantic, 1, "gen1")
    manifest1 = d5.store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=adapters1[0],
        assumption_adapter=adapters1[1],
        alt_model_adapter=adapters1[2],
    )
    # Clear active marker to allow a second prepare with the same claim.
    Path(d5.tmp_path / "generations" / "state" / "active-generation.json").unlink()
    Path(d5.tmp_path / "generations" / "state" / "prepared-generation.json").unlink()
    manifest2 = d5.store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=adapters2[0],
        assumption_adapter=adapters2[1],
        alt_model_adapter=adapters2[2],
    )
    assert manifest1.generation_digest == manifest2.generation_digest
    assert manifest1.to_json_value() == manifest2.to_json_value()
    completion1 = d5.store._read_completion(manifest1.clock_completion_digest)
    completion2 = d5.store._read_completion(manifest2.clock_completion_digest)
    assert completion1 is not None
    assert completion2 is not None
    assert completion1.canonical_bytes == completion2.canonical_bytes


# --------------------------------------------------------------------------- #
# Generation views
# --------------------------------------------------------------------------- #


def test_generation_view_append_fails_closed(d5: SimpleNamespace) -> None:
    manifest = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest)
    view = d5.store.evidence_view()
    assert isinstance(view, GenerationRegistryView)
    snap = view.snapshot("EVIDENCE_UNIT")
    assert snap.root_digest == manifest.evidence_projected_root
    event = _append_direct_evidence(FilesystemRegistryStore(d5.tmp_path / "other"), clock=5)
    with pytest.raises(RegistryStoreError):
        view.append(event)


def test_generation_view_reconstructs_historical_state(d5: SimpleNamespace) -> None:
    manifest1 = _prepare_one(d5.store, sequence=1, tag="gen1")
    d5.store.commit_generation(manifest1)
    manifest2 = _prepare_one(
        d5.store,
        sequence=2,
        tag="gen2",
        previous_completion_digest=manifest1.clock_completion_digest,
    )
    d5.store.commit_generation(manifest2)
    # The gen1 view must still reconstruct gen1 entities even after gen2 advanced.
    gen1 = D5GenerationManifest.from_json(cast(dict[str, Any], manifest1.to_json_value()))
    view = GenerationRegistryView(
        store=d5.evidence_store,
        registry_type="EVIDENCE_UNIT",
        heads=gen1.head_entities("evidence"),
    )
    snap = view.snapshot("EVIDENCE_UNIT")
    assert snap.root_digest == manifest1.evidence_projected_root
    histories = view.reconstruct_snapshot("EVIDENCE_UNIT")
    assert len(histories) == 1
    assert histories[0][-1].to_json_value()["entity_id"] == "evidence:d5-gen1"


# --------------------------------------------------------------------------- #
# Reference adapter determinism
# --------------------------------------------------------------------------- #


def test_reference_disposition_adapter_is_deterministic() -> None:
    claim, validated_event, semantic = _context(1)
    adapter = ReferenceDispositionAdapter()
    receipt1 = adapter.project(
        semantic_receipt=semantic,
        clock_sequence=1,
        evidence_root=_digest("ev"),
        assumption_root=_digest("as"),
        alt_model_root=_digest("am"),
    )
    receipt2 = adapter.project(
        semantic_receipt=semantic,
        clock_sequence=1,
        evidence_root=_digest("ev"),
        assumption_root=_digest("as"),
        alt_model_root=_digest("am"),
    )
    assert receipt1.canonical_bytes == receipt2.canonical_bytes
    assert receipt1.to_json_value()["disposition_action"] == "DOCUMENT_AND_PROCEED"
    assert receipt1.to_json_value()["assurance_status"] == "UNASSESSED"


def test_reference_quarantine_adapter_is_deterministic() -> None:
    adapter = ReferenceQuarantineAdapter()
    projection1 = adapter.project()
    projection2 = adapter.project()
    assert projection1.epoch == 0
    assert projection1.marker_digests == ()
    assert projection1 == projection2


# --------------------------------------------------------------------------- #
# Helpers for direct store mutation (failure-path tests)
# --------------------------------------------------------------------------- #


def _append_direct_evidence(store: FilesystemRegistryStore, *, clock: int) -> RegistryEvent:
    source = _digest(f"direct-evidence:{clock}")
    event = build_evidence_event(
        evidence_id=f"evidence:direct-{clock}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=source,
        payload={
            "operation": "REGISTER",
            "proposition_id": f"proposition:direct-{clock}",
            "scope_ids": ["scope:d5"],
            "source_id": f"source:direct-{clock}",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": clock + 100,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    store.append(event)
    return event


def _append_direct_assumption(store: FilesystemRegistryStore, *, clock: int) -> RegistryEvent:
    event = build_assumption_event(
        assumption_id=f"assumption:direct-{clock}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"direct-assumption:{clock}"),
        payload={
            "operation": "PROPOSE",
            "proposition_id": f"proposition:direct-{clock}",
            "scope_ids": ["scope:d5"],
            "materiality": "MATERIAL",
            "proposer_authority_id": "authority:proposer",
            "proposed_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": clock + 100,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    store.append(event)
    return event


def _append_direct_alt_model(store: FilesystemRegistryStore, *, clock: int) -> RegistryEvent:
    event = build_alternative_model_event(
        model_id=f"alt-model:direct-{clock}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest=_digest(f"direct-alt-model:{clock}"),
        payload={
            "operation": "PROPOSE",
            "model_version": "v1",
            "primary_model_id": "model:primary",
            "graph_digest": _digest(f"graph:direct-{clock}"),
            "declared_difference_digest": _digest(f"difference:direct-{clock}"),
            "challenge_basis_code": "basis:d5-shadow-divergence",
            "scope_ids": ["scope:d5"],
            "assumption_ids": [],
            "evidence_ids": [],
            "proposer_authority_id": "authority:proposer",
            "materiality": "MATERIAL",
            "valid_from_sequence": clock,
            "expires_at_sequence": clock + 100,
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )
    store.append(event)
    return event


def _heads_to_dicts(heads: tuple[RegistryEntityHead, ...]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "entity_id": head.entity_id,
            "entity_sequence": head.entity_sequence,
            "event_digest": head.event_digest,
        }
        for head in heads
    )


def _make_plan_stub(
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic: SemanticProjectionReceipt,
    *,
    predecessor_root: str,
    projected_root: str | None = None,
    clock_claim_digest: str | None = None,
    evidence_root_digest: str | None = None,
    assumption_root_digest: str | None = None,
) -> Any:
    """Build a minimal stub plan with overridable digest fields.

    Only used for cross-phase binding validation tests where we need to
    construct plans with specific (possibly wrong) binding digests.
    """

    stub_proj = projected_root or _digest("proj-root")
    stub_claim = clock_claim_digest or claim.digest
    stub_ev_root = evidence_root_digest or stub_proj
    stub_as_root = assumption_root_digest or stub_proj
    stub_event = validated_event.digest
    stub_semantic = semantic.digest
    stub_plan = _digest("plan")

    class _Stub:
        clock_claim_digest = stub_claim
        validated_event_digest = stub_event
        semantic_receipt_digest = stub_semantic
        clock_sequence = 1
        predecessor_root_digest = predecessor_root
        projected_root_digest = stub_proj
        evidence_root_digest = stub_ev_root
        assumption_root_digest = stub_as_root
        plan_digest = stub_plan

    return _Stub()


# --------------------------------------------------------------------------- #
# Defect 5: Phase-failure isolation (EVIDENCE_REGISTRY, ASSUMPTION_REGISTRY,
# ALTERNATIVE_MODEL_REGISTRY, DISPOSITION, QUARANTINE_COMMIT)
# --------------------------------------------------------------------------- #


class _FailingEvidenceAdapter:
    """Evidence adapter wrapper that raises on .project() (EVIDENCE_REGISTRY)."""

    def __init__(self, phase: str = "EVIDENCE_REGISTRY") -> None:
        self._phase = phase

    def project(self, **_kwargs: object) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


class _FailingAssumptionAdapter:
    """Assumption adapter wrapper that raises on .project() (ASSUMPTION_REGISTRY)."""

    def __init__(self, phase: str = "ASSUMPTION_REGISTRY") -> None:
        self._phase = phase

    def project(self, **_kwargs: object) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


class _FailingAltModelAdapter:
    """Alt-model adapter wrapper that raises on .project() (ALTERNATIVE_MODEL_REGISTRY)."""

    def __init__(self, phase: str = "ALTERNATIVE_MODEL_REGISTRY") -> None:
        self._phase = phase

    def project(self, **_kwargs: object) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


class _FailingDisposition:
    def __init__(self, phase: str = "DISPOSITION") -> None:
        self._phase = phase

    def project(self, **_kwargs: object) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


class _FailingQuarantine:
    def __init__(self, phase: str = "QUARANTINE_COMMIT") -> None:
        self._phase = phase

    def project(self) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


def _failing_disposition_factory() -> _FailingDisposition:
    return _FailingDisposition()


def _failing_quarantine_factory() -> _FailingQuarantine:
    return _FailingQuarantine()


def _establish_baseline(tmp_path: Path) -> tuple[D5GenerationStore, D5GenerationManifest]:
    """Commit generation 1 and return (store, manifest1) for isolation tests."""

    store = _build_store(tmp_path)
    manifest1 = _prepare_one(store, sequence=1, tag="gen1")
    store.commit_generation(manifest1)
    return store, manifest1


def test_evidence_adapter_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    store, manifest1 = _establish_baseline(tmp_path)
    baseline = _capture_state(store)

    claim, validated_event, semantic = _context(2, manifest1.clock_completion_digest)
    _ev, assumption_adapter, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, 2, "gen2"
    )
    with pytest.raises(RuntimeError, match="EVIDENCE_REGISTRY_INJECTED_FAILURE"):
        store.prepare_generation(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_adapter=cast("StagedEvidenceProjectionAdapter", _FailingEvidenceAdapter()),
            assumption_adapter=assumption_adapter,
            alt_model_adapter=alt_model_adapter,
        )
    assert _capture_state(store) == baseline


def test_assumption_adapter_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    store, manifest1 = _establish_baseline(tmp_path)
    baseline = _capture_state(store)

    claim, validated_event, semantic = _context(2, manifest1.clock_completion_digest)
    evidence_adapter, _as, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, 2, "gen2"
    )
    with pytest.raises(RuntimeError, match="ASSUMPTION_REGISTRY_INJECTED_FAILURE"):
        store.prepare_generation(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_adapter=evidence_adapter,
            assumption_adapter=cast(
                "StagedAssumptionProjectionAdapter", _FailingAssumptionAdapter()
            ),
            alt_model_adapter=alt_model_adapter,
        )
    assert _capture_state(store) == baseline


def test_alt_model_adapter_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    store, manifest1 = _establish_baseline(tmp_path)
    baseline = _capture_state(store)

    claim, validated_event, semantic = _context(2, manifest1.clock_completion_digest)
    evidence_adapter, assumption_adapter, _am = _build_adapters(
        claim, validated_event, semantic, 2, "gen2"
    )
    with pytest.raises(RuntimeError, match="ALTERNATIVE_MODEL_REGISTRY_INJECTED_FAILURE"):
        store.prepare_generation(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_adapter=evidence_adapter,
            assumption_adapter=assumption_adapter,
            alt_model_adapter=cast(
                "StagedAlternativeModelProjectionAdapter", _FailingAltModelAdapter()
            ),
        )
    assert _capture_state(store) == baseline


def test_disposition_adapter_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    store, manifest1 = _establish_baseline(tmp_path)
    baseline = _capture_state(store)

    # Reopen the store against the same directories with a failing disposition
    # factory. The factory is consulted fresh per prepare.
    failing_store = _build_store_with_factories(
        tmp_path, disposition_adapter_factory=_failing_disposition_factory
    )
    claim, validated_event, semantic = _context(2, manifest1.clock_completion_digest)
    evidence_adapter, assumption_adapter, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, 2, "gen2"
    )
    with pytest.raises(RuntimeError, match="DISPOSITION_INJECTED_FAILURE"):
        failing_store.prepare_generation(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_adapter=evidence_adapter,
            assumption_adapter=assumption_adapter,
            alt_model_adapter=alt_model_adapter,
        )
    assert _capture_state(store) == baseline


def test_quarantine_adapter_failure_leaves_state_unchanged(tmp_path: Path) -> None:
    store, manifest1 = _establish_baseline(tmp_path)
    baseline = _capture_state(store)

    failing_store = _build_store_with_factories(
        tmp_path, quarantine_adapter_factory=_failing_quarantine_factory
    )
    claim, validated_event, semantic = _context(2, manifest1.clock_completion_digest)
    evidence_adapter, assumption_adapter, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, 2, "gen2"
    )
    with pytest.raises(RuntimeError, match="QUARANTINE_COMMIT_INJECTED_FAILURE"):
        failing_store.prepare_generation(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic,
            evidence_adapter=evidence_adapter,
            assumption_adapter=assumption_adapter,
            alt_model_adapter=alt_model_adapter,
        )
    assert _capture_state(store) == baseline


# --------------------------------------------------------------------------- #
# Defect 4: durable projection-artifact retention + governed ADMIT vector
# --------------------------------------------------------------------------- #


def _graph_digest_of(graph_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(graph_bytes).hexdigest()


def _build_replay_receipt(
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    semantic_outcome_digest: str,
) -> object:
    """Build a self-digesting ReplayReceipt using the governance-contract digest."""

    from csd_foundry.governance.v0_5._governed_alternative_model import ReplayReceipt

    required = ("node:n1",)
    unsigned: dict[str, object] = {
        "schema_version": "alternative-model-replay-receipt/1",
        "graph_digest": graph_digest,
        "decision_context_digest": decision_context_digest,
        "initial_state_digest": initial_state_digest,
        "logical_clock": 5,
        "runner_revision": "runner:v1",
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
        runner_revision="runner:v1",
        required_inventory=required,
        executed_inventory=required,
        skipped_inventory=(),
        pruned_inventory=(),
        semantic_outcome_digest=semantic_outcome_digest,
        receipt_digest=cast(str, receipt_digest),
    )


def _build_governed_admit_fixture(
    *,
    propose_clock: int = 1,
    admit_clock: int = 2,
    model_id: str = "alt-model:admit-d5",
) -> tuple[
    RegistryEvent,
    RegistryEvent,
    GovernedAlternativeModelAuthorization,
    ComparisonReceipt,
    StructuralDifferenceReceipt,
]:
    """Build a complete governed ADMIT fixture across a seed store.

    Returns the PROPOSE event, ADMIT event, authorization, comparison receipt,
    and structural-difference receipt. The authorization's
    ``alternative_model_registry_root`` is the alt-model root immediately after
    the PROPOSE (which D5's gen1 will reproduce).
    """

    primary_graph = {
        "nodes": [{"node_id": "n1", "authority_id": "authority:primary"}],
        "semantic_seed": "primary",
    }
    shadow_graph = {
        "nodes": [
            {"node_id": "n1", "authority_id": "authority:shadow"},
            {"node_id": "n2", "authority_id": "authority:shadow"},
        ],
        "semantic_seed": "shadow",
    }
    primary_bytes = _canonical_json(primary_graph)
    shadow_bytes = _canonical_json(shadow_graph)
    primary_digest = _graph_digest_of(primary_bytes)
    shadow_digest = _graph_digest_of(shadow_bytes)
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
        model_id=model_id,
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=propose_clock,
        source_receipt_digest=_digest(f"propose:{model_id}"),
        payload={
            "operation": "PROPOSE",
            "model_version": "v1",
            "primary_model_id": "model:primary",
            "graph_digest": shadow_digest,
            "declared_difference_digest": declared_digest,
            "challenge_basis_code": "basis:d5-shadow-divergence",
            "scope_ids": ["scope:d5"],
            "assumption_ids": [],
            "evidence_ids": [],
            "proposer_authority_id": "authority:proposer",
            "materiality": "MATERIAL",
            "valid_from_sequence": propose_clock,
            "expires_at_sequence": propose_clock + 100,
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )

    seed = InMemoryRegistryStore()
    seed.append(propose_event)
    result = append_governed_alternative_model_admit(
        store=seed,
        model_id=model_id,
        structural_difference_receipt=receipt,
        admitting_authority_id="authority:admitter",
        event_sequence=admit_clock,
    )

    decision_context = _digest("decision-context:d5-admit")
    initial_state = _digest("initial-state:d5-admit")
    primary_replay = _build_replay_receipt(
        graph_digest=primary_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("outcome:primary:d5-admit"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=shadow_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        semantic_outcome_digest=_digest("outcome:shadow:d5-admit"),
    )
    comparison = compare_alternative_model_replays(
        structural_difference_receipt=receipt,
        primary_replay_receipt=cast("object", primary_replay),
        shadow_replay_receipt=cast("object", shadow_replay),
    )
    return propose_event, result.event, result.authorization, comparison, receipt


def test_projection_artifacts_durably_retained_across_commit_and_restart(
    d5: SimpleNamespace,
) -> None:
    """Defect 4: semantic receipt, three plans, and disposition receipt survive."""

    claim, validated_event, semantic = _context(1)
    evidence_adapter, assumption_adapter, alt_model_adapter = _build_adapters(
        claim, validated_event, semantic, 1, "gen1"
    )
    manifest = d5.store.prepare_generation(
        claim=claim,
        validated_event=validated_event,
        semantic_receipt=semantic,
        evidence_adapter=evidence_adapter,
        assumption_adapter=assumption_adapter,
        alt_model_adapter=alt_model_adapter,
    )
    d5.store.commit_generation(manifest)

    reopened = _reopen_store(d5.tmp_path)
    current = reopened.current_generation()
    assert current is not None

    # Semantic receipt survives.
    semantic_json = reopened.read_semantic_receipt(current.semantic_projection_receipt_digest)
    assert semantic_json is not None
    assert semantic_json == semantic.to_json_value()

    # Three projection plans survive.
    evidence_plan_json = reopened.read_projection_plan(current.evidence_plan_digest)
    assumption_plan_json = reopened.read_projection_plan(current.assumption_plan_digest)
    alt_model_plan_json = reopened.read_projection_plan(current.alt_model_plan_digest)
    assert evidence_plan_json is not None
    assert assumption_plan_json is not None
    assert alt_model_plan_json is not None

    # Reference disposition receipt survives.
    disposition_json = reopened.read_disposition_receipt(current.disposition_receipt_digest)
    assert disposition_json is not None


def test_governed_admit_comparison_evidence_survives_commit_and_restart(
    d5: SimpleNamespace,
) -> None:
    """Defect 4: a governed alternative-model ADMIT vector with FULL_REPLAY
    comparison evidence is durably retained across commit + restart."""

    propose_event, admit_event, authorization, comparison, _receipt = _build_governed_admit_fixture(
        propose_clock=1, admit_clock=2
    )

    # Generation 1: stage the PROPOSE for the governed model.
    claim1, validated_event1, semantic1 = _context(1)
    ev_adapter1 = StagedEvidenceProjectionAdapter(
        authority_policy=_evidence_authority_policy(),
        expiry_authority_id="authority:clock",
        intent_resolver=_EvidenceIntent(
            _build_evidence_event(claim1, validated_event1, semantic1, 1, "gen1")
        ),
    )
    as_adapter1 = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticAssumptionExpiryAuthority(),
        intent_resolver=_AssumptionIntent(
            _build_assumption_event(claim1, validated_event1, semantic1, 1, "gen1")
        ),
    )
    am_adapter1 = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticAltModelExpiryAuthority(),
        intent_resolver=_AltModelIntent(propose_event),
    )
    manifest1 = d5.store.prepare_generation(
        claim=claim1,
        validated_event=validated_event1,
        semantic_receipt=semantic1,
        evidence_adapter=ev_adapter1,
        assumption_adapter=as_adapter1,
        alt_model_adapter=am_adapter1,
    )
    d5.store.commit_generation(manifest1)

    # Generation 2: stage the governed ADMIT with comparison evidence.
    claim2, validated_event2, semantic2 = _context(2, manifest1.clock_completion_digest)
    ev_adapter2 = StagedEvidenceProjectionAdapter(
        authority_policy=_evidence_authority_policy(),
        expiry_authority_id="authority:clock",
        intent_resolver=_EvidenceIntent(
            _build_evidence_event(claim2, validated_event2, semantic2, 2, "gen2")
        ),
    )
    as_adapter2 = StagedAssumptionProjectionAdapter(
        expiry_authority=_StaticAssumptionExpiryAuthority(),
        intent_resolver=_AssumptionIntent(
            _build_assumption_event(claim2, validated_event2, semantic2, 2, "gen2")
        ),
    )
    am_adapter2 = StagedAlternativeModelProjectionAdapter(
        expiry_authority=_StaticAltModelExpiryAuthority(),
        intent_resolver=_AltModelIntent(admit_event),
    )
    manifest2 = d5.store.prepare_generation(
        claim=claim2,
        validated_event=validated_event2,
        semantic_receipt=semantic2,
        evidence_adapter=ev_adapter2,
        assumption_adapter=as_adapter2,
        alt_model_adapter=am_adapter2,
        governed_admit_evidence=((authorization, comparison),),
    )
    # The alt-model plan carries the ADMIT comparison binding.
    assert manifest2.alt_model_event_digests == (admit_event.digest,)
    d5.store.commit_generation(manifest2)

    # Restart: the comparison receipt and the alt-model plan (with its
    # admit_comparison_bindings) must survive.
    reopened = _reopen_store(d5.tmp_path)
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest2.generation_digest

    alt_model_plan_json = reopened.read_projection_plan(current.alt_model_plan_digest)
    assert alt_model_plan_json is not None
    bindings = alt_model_plan_json["admit_comparison_bindings"]
    assert len(bindings) == 1
    comparison_digest = bindings[0][1]
    assert comparison_digest == comparison.comparison_digest

    comparison_json = reopened.read_comparison_receipt(comparison_digest)
    assert comparison_json is not None
    assert comparison_json == comparison.to_json_value()

    # The semantic receipt + disposition receipt also survive for gen2.
    assert reopened.read_semantic_receipt(current.semantic_projection_receipt_digest) is not None
    assert reopened.read_disposition_receipt(current.disposition_receipt_digest) is not None


def test_wrong_active_claim_digest_rejected(d5: SimpleNamespace) -> None:
    """A mismatched active-claim marker cannot authorize publication."""
    manifest = _prepare_one(d5.store, 1, "auth1")

    # Corrupt the active marker's claim digest (already written by prepare).
    active_value = json.loads(d5.store.active_path.read_bytes())
    active_value["clock_claim_digest"] = _digest("wrong-active-claim")
    d5.store.active_path.write_text(
        json.dumps(active_value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    state_before = _capture_state(d5.store)

    with pytest.raises(D5GenerationConflictError, match="D5_ACTIVE_CLAIM_MISMATCH"):
        d5.store.commit_generation(manifest)

    assert _capture_state(d5.store) == state_before


def test_matching_generation_wrong_pointer_sequence_not_idempotent(
    d5: SimpleNamespace,
) -> None:
    """Matching generation digest + wrong pointer sequence → NOT idempotent success.

    Simulates a corrupted post-commit pointer by writing the pointer with the
    generation's own digest but wrong clock_sequence, then attempting recovery.
    """
    manifest = _prepare_one(d5.store, 1, "auth2")
    # Commit normally, then corrupt the pointer.
    d5.store.commit_generation(manifest)

    # Write a corrupted pointer: same generation digest, wrong sequence.
    ptr = {
        "schema_version": "current-d5-generation/1",
        "clock_sequence": manifest.clock_sequence + 100,
        "generation_digest": manifest.generation_digest,
        "clock_completion_digest": manifest.clock_completion_digest,
    }
    d5.store.current_path.write_text(
        json.dumps(ptr, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    # Any attempt to read the current manifest through the corrupted pointer
    # must fail closed (pointer/manifest mismatch detected).
    with pytest.raises(D5GenerationConflictError):
        d5.store.current_generation()


def test_matching_generation_wrong_pointer_completion_not_idempotent(
    d5: SimpleNamespace,
) -> None:
    """Matching generation digest + wrong pointer completion digest → NOT idempotent."""
    manifest = _prepare_one(d5.store, 1, "auth3")
    d5.store.commit_generation(manifest)

    ptr = {
        "schema_version": "current-d5-generation/1",
        "clock_sequence": manifest.clock_sequence,
        "generation_digest": manifest.generation_digest,
        "clock_completion_digest": _digest("wrong-completion"),
    }
    d5.store.current_path.write_text(
        json.dumps(ptr, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    with pytest.raises(D5GenerationConflictError):
        d5.store.current_generation()
