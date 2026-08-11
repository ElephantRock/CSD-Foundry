"""Acceptance campaign for the P3.4 governed alternative-model layer.

Covers governed ADMIT admission (material-difference authority), the six
structural-difference families, FULL_REPLAY receipt invariants, the canonical
INVARIANT/DIVERGENT comparison, the use-time authority gate, no-mutation
read-only behaviour, and the pure-function (no-external-truth) property.

Every fixture here is built from in-memory canonical JSON graphs and a
deterministic test replay executor whose semantic outcome is a pure function
of an injected ``semantic_seed`` graph field, making both INVARIANT and
DIVERGENT comparison cases constructible.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionGovernanceContractError,
    _domain_digest,
)
from csd_foundry.governance.v0_5._governed_alternative_model import (
    _COMPARISON_RECEIPT_DOMAIN,
    _COMPARISON_RECEIPT_SCHEMA_VERSION,
    _REPLAY_RECEIPT_DOMAIN,
    _REPLAY_RECEIPT_SCHEMA_VERSION,
    AlternativeModelReplayExecutor,
    ComparisonReceipt,
    GovernedAlternativeModelAdmitResult,
    GovernedAlternativeModelAuthorization,
    GovernedAlternativeModelError,
    ReplayReceipt,
    StructuralDifferenceReceipt,
    UseAuthorityDecision,
    append_governed_alternative_model_admit,
    compare_alternative_model_replays,
    compute_structural_difference_digest,
    detect_structural_difference,
    evaluate_alternative_model_use_authority,
    run_full_replay_comparison,
)
from csd_foundry.governance.v0_5.alternative_model import (
    STANDING_ADMITTED,
    STANDING_CONFIRMED,
    STANDING_EXPIRED,
    STANDING_REJECTED,
    STANDING_UNVERIFIED,
    AlternativeModel,
    AlternativeModelRegistry,
    build_alternative_model_event,
)
from csd_foundry.governance.v0_5.governed_alternative_model import (
    GovernedAlternativeModelError as FacadeGovernedAlternativeModelError,
)
from csd_foundry.governance.v0_5.registry import InMemoryRegistryStore

# --------------------------------------------------------------------------- #
# Canonicalization + digest helpers
# --------------------------------------------------------------------------- #


def _digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _canonical_json(obj: object) -> bytes:
    """Repository canonical JSON bytes (matches ``_json_bytes``)."""
    rendered = json.dumps(
        obj,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (rendered + "\n").encode("utf-8")


def _graph_digest_of(graph_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(graph_bytes).hexdigest()


def _graph(obj: dict[str, object]) -> bytes:
    """Build canonical graph bytes from a dict (already canonical by construction)."""
    return _canonical_json(obj)


# --------------------------------------------------------------------------- #
# Structural-difference receipt helper
# --------------------------------------------------------------------------- #


def _detect(primary: dict[str, object], shadow: dict[str, object]) -> StructuralDifferenceReceipt:
    """Build a StructuralDifferenceReceipt for a primary/shadow graph pair."""
    primary_bytes = _graph(primary)
    shadow_bytes = _graph(shadow)
    declared = compute_structural_difference_digest(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
    )
    return detect_structural_difference(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        primary_graph_digest=_graph_digest_of(primary_bytes),
        shadow_graph_digest=_graph_digest_of(shadow_bytes),
        declared_difference_digest=declared,
    )


# --------------------------------------------------------------------------- #
# Replay receipt + executor helpers
# --------------------------------------------------------------------------- #


def _build_replay_receipt(
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    logical_clock: int,
    runner_revision: str,
    required_inventory: tuple[str, ...],
    semantic_outcome_digest: str,
    executed_inventory: tuple[str, ...] | None = None,
    skipped_inventory: tuple[str, ...] = (),
    pruned_inventory: tuple[str, ...] = (),
) -> ReplayReceipt:
    """Build a self-digesting ReplayReceipt with FULL_REPLAY defaults.

    Defaults enforce executed == required and skipped/pruned empty. Tests that
    exercise the FULL_REPLAY invariants override the relevant field.
    """
    if executed_inventory is None:
        executed_inventory = required_inventory
    unsigned = {
        "schema_version": _REPLAY_RECEIPT_SCHEMA_VERSION,
        "graph_digest": graph_digest,
        "decision_context_digest": decision_context_digest,
        "initial_state_digest": initial_state_digest,
        "logical_clock": logical_clock,
        "runner_revision": runner_revision,
        "required_inventory": list(required_inventory),
        "executed_inventory": list(executed_inventory),
        "skipped_inventory": list(skipped_inventory),
        "pruned_inventory": list(pruned_inventory),
        "semantic_outcome_digest": semantic_outcome_digest,
    }
    receipt_digest = _domain_digest(_REPLAY_RECEIPT_DOMAIN, unsigned)
    return ReplayReceipt(
        graph_digest=graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required_inventory,
        executed_inventory=executed_inventory,
        skipped_inventory=skipped_inventory,
        pruned_inventory=pruned_inventory,
        semantic_outcome_digest=semantic_outcome_digest,
        receipt_digest=receipt_digest,
    )


class _TestReplayExecutor:
    """Deterministic replay executor.

    The semantic outcome digest is a pure function of the graph's
    ``semantic_seed`` field (default ``"default"``): two graphs with the same
    seed yield the same outcome (INVARIANT); different seeds diverge.

    Pass ``fail_on_seed`` to inject a replay failure for one seed (the executor
    raises instead of returning a partial receipt).
    """

    def __init__(self, *, fail_on_seed: str | None = None) -> None:
        self._fail_on_seed = fail_on_seed

    def replay(
        self,
        *,
        graph_bytes: bytes,
        graph_digest: str,
        decision_context_digest: str,
        initial_state_digest: str,
        logical_clock: int,
        runner_revision: str,
        required_inventory: tuple[str, ...],
    ) -> ReplayReceipt:
        canonical = _canonical_json(json.loads(graph_bytes.decode("utf-8")))
        # Faithful executor: re-derive and assert the graph digest binding.
        assert _graph_digest_of(canonical) == graph_digest, "executor graph digest binding"
        graph = json.loads(canonical.decode("utf-8"))
        seed = graph.get("semantic_seed", "default") if isinstance(graph, dict) else "default"
        if self._fail_on_seed is not None and seed == self._fail_on_seed:
            raise RuntimeError("injected replay failure")
        outcome = _digest(f"outcome:{seed}")
        inventory = tuple(sorted(set(required_inventory)))
        return _build_replay_receipt(
            graph_digest=graph_digest,
            decision_context_digest=decision_context_digest,
            initial_state_digest=initial_state_digest,
            logical_clock=logical_clock,
            runner_revision=runner_revision,
            required_inventory=inventory,
            semantic_outcome_digest=outcome,
        )


def _run_comparison(
    executor: AlternativeModelReplayExecutor,
    diff_receipt: StructuralDifferenceReceipt,
    *,
    primary_bytes: bytes,
    shadow_bytes: bytes,
    decision_context_digest: str = _digest("ctx"),
    initial_state_digest: str = _digest("init"),
    logical_clock: int = 7,
    runner_revision: str = "runner:test-rev-1",
    required_inventory: tuple[str, ...] = ("inv:a", "inv:b"),
) -> ComparisonReceipt:
    """Run primary + shadow replays through an executor and compare them."""
    primary_replay = executor.replay(
        graph_bytes=primary_bytes,
        graph_digest=diff_receipt.primary_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required_inventory,
    )
    shadow_replay = executor.replay(
        graph_bytes=shadow_bytes,
        graph_digest=diff_receipt.shadow_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required_inventory,
    )
    return compare_alternative_model_replays(
        structural_difference_receipt=diff_receipt,
        primary_replay_receipt=primary_replay,
        shadow_replay_receipt=shadow_replay,
    )


# --------------------------------------------------------------------------- #
# Alternative-model PROPOSE helpers
# --------------------------------------------------------------------------- #


_PRIMARY_GRAPH: dict[str, object] = {
    "authority_id": "authority:primary",
    "scope_ref": "scope:control",
    "semantic_seed": "same",
}
_SHADOW_GRAPH: dict[str, object] = {
    "authority_id": "authority:shadow",
    "scope_ref": "scope:alt",
    "semantic_seed": "same",
}


def _propose_model(
    store: InMemoryRegistryStore,
    *,
    model_id: str = "model:shadow",
    primary_model_id: str = "model:primary",
    shadow_graph: dict[str, object] | None = None,
    primary_graph: dict[str, object] | None = None,
    scope_ids: tuple[str, ...] = ("scope:control",),
    materiality: str = "MATERIAL",
    maximum_reuse_class: str = "D2",
    expires_at_sequence: int | None = 100,
    declared_difference_digest: str | None = None,
    clock: int = 10,
) -> AlternativeModel:
    """Apply a PROPOSE event for a shadow alternative model."""
    shadow = _SHADOW_GRAPH if shadow_graph is None else shadow_graph
    primary = _PRIMARY_GRAPH if primary_graph is None else primary_graph
    shadow_bytes = _graph(shadow)
    shadow_digest = _graph_digest_of(shadow_bytes)
    if declared_difference_digest is None:
        declared_difference_digest = compute_structural_difference_digest(
            primary_graph_bytes=_graph(primary),
            shadow_graph_bytes=shadow_bytes,
        )
    registry = AlternativeModelRegistry(store)
    return registry.apply(
        build_alternative_model_event(
            model_id=model_id,
            entity_sequence=1,
            previous_entity_event_digest=None,
            clock_sequence=clock,
            source_receipt_digest=_digest(f"propose:{model_id}"),
            payload={
                "operation": "PROPOSE",
                "model_version": "v1",
                "primary_model_id": primary_model_id,
                "graph_digest": shadow_digest,
                "declared_difference_digest": declared_difference_digest,
                "challenge_basis_code": "basis:structural-divergence",
                "scope_ids": list(scope_ids),
                "assumption_ids": [],
                "evidence_ids": [],
                "proposer_authority_id": "authority:proposer",
                "materiality": materiality,
                "valid_from_sequence": 1,
                "expires_at_sequence": expires_at_sequence,
                "limitations": [],
                "maximum_reuse_class": maximum_reuse_class,
            },
        )
    )


def _build_store_with_proposed_model(
    **kwargs: Any,
) -> tuple[InMemoryRegistryStore, AlternativeModel, StructuralDifferenceReceipt]:
    """Build a store with one PROPOSED alternative model + its difference receipt."""
    store = InMemoryRegistryStore()
    model = _propose_model(store, **kwargs)
    shadow = kwargs.get("shadow_graph", _SHADOW_GRAPH)
    primary = kwargs.get("primary_graph", _PRIMARY_GRAPH)
    receipt = _detect(primary, shadow)
    return store, model, receipt


def _governed_admit(
    *,
    store: InMemoryRegistryStore,
    model_id: str,
    structural_difference_receipt: StructuralDifferenceReceipt,
    admitting_authority_id: str = "authority:admitter",
    event_sequence: int = 11,
    retry_authorization: GovernedAlternativeModelAuthorization | None = None,
) -> GovernedAlternativeModelAdmitResult:
    return append_governed_alternative_model_admit(
        store=store,
        model_id=model_id,
        structural_difference_receipt=structural_difference_receipt,
        admitting_authority_id=admitting_authority_id,
        event_sequence=event_sequence,
        retry_authorization=retry_authorization,
    )


def _roots(store: InMemoryRegistryStore) -> str:
    return store.snapshot("ALTERNATIVE_MODEL").root_digest


# --------------------------------------------------------------------------- #
# AlternativeModel direct-construction helper (use-time gate tests)
# --------------------------------------------------------------------------- #


def _make_model(
    *,
    model_id: str = "model:alt",
    separation_status: str = STANDING_ADMITTED,
    scope_ids: tuple[str, ...] = ("scope:control",),
    maximum_reuse_class: str = "D2",
    expires_at_sequence: int | None = None,
    active_challenges: tuple[Any, ...] = (),
) -> AlternativeModel:
    return AlternativeModel(
        model_id=model_id,
        model_version="v1",
        primary_model_id="model:primary",
        graph_digest=_digest("graph:shadow"),
        declared_difference_digest=_digest("diff:declared"),
        challenge_basis_code="basis:structural-divergence",
        scope_ids=tuple(sorted(scope_ids)),
        assumption_ids=(),
        evidence_ids=(),
        proposer_authority_id="authority:proposer",
        admitting_authority_id="authority:admitter",
        confirming_authority_id=None,
        materiality="MATERIAL",
        separation_status=separation_status,
        valid_from_sequence=1,
        expires_at_sequence=expires_at_sequence,
        active_challenges=active_challenges,
        superseded_by_id=None,
        limitations=(),
        maximum_reuse_class=maximum_reuse_class,
        proposal_source_receipt_digest=_digest("propose:receipt"),
        current_source_receipt_digest=_digest("current:receipt"),
        current_event_digest=_digest("event:current"),
        current_entity_sequence=2,
        last_clock_sequence=10,
    )


# --------------------------------------------------------------------------- #
# A. Governed ADMIT
# --------------------------------------------------------------------------- #


def test_01_valid_admission_with_material_difference_appended() -> None:
    """A valid governed ADMIT (material difference) -> APPENDED at seq 2 / UNVERIFIED."""
    store, model, receipt = _build_store_with_proposed_model()
    root_before = _roots(store)

    result = _governed_admit(
        store=store, model_id=model.model_id, structural_difference_receipt=receipt
    )

    assert result.applied is True
    assert result.reason == "APPENDED"
    assert result.head.entity_sequence == 2
    assert result.projected.separation_status == STANDING_UNVERIFIED
    assert result.projected.admitting_authority_id == "authority:admitter"
    # The ADMIT event source receipt is the authorization digest (which
    # transitively binds the structural-difference receipt).
    assert (
        result.event.to_json_value()["source_receipt_digest"]
        == result.authorization.authorization_digest
    )
    # Root advanced.
    assert _roots(store) != root_before
    # Head observable through the store.
    head = store.entity_head("ALTERNATIVE_MODEL", model.model_id)
    assert head is not None and head.entity_sequence == 2


def test_02_stale_clock_not_advancing_rejected() -> None:
    """event_sequence <= propose clock -> NOT_PROPOSED (clock not advancing)."""
    store, model, receipt = _build_store_with_proposed_model(clock=11)
    root_before = _roots(store)
    head_before = store.entity_head("ALTERNATIVE_MODEL", model.model_id)

    with pytest.raises(GovernedAlternativeModelError, match="GOVERNED_ALT_MODEL_NOT_PROPOSED"):
        _governed_admit(
            store=store,
            model_id=model.model_id,
            structural_difference_receipt=receipt,
            event_sequence=11,  # == propose clock
        )

    assert _roots(store) == root_before
    assert store.entity_head("ALTERNATIVE_MODEL", model.model_id) == head_before


def test_03_stale_predecessor_already_admitted_rejected() -> None:
    """Second governed ADMIT without retry auth -> ALREADY_ADMITTED."""
    store, model, receipt = _build_store_with_proposed_model()

    first = _governed_admit(
        store=store, model_id=model.model_id, structural_difference_receipt=receipt
    )
    assert first.applied is True

    root_before = _roots(store)
    head_before = store.entity_head("ALTERNATIVE_MODEL", model.model_id)

    with pytest.raises(GovernedAlternativeModelError, match="GOVERNED_ALT_MODEL_ALREADY_ADMITTED"):
        _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)

    assert _roots(store) == root_before
    assert store.entity_head("ALTERNATIVE_MODEL", model.model_id) == head_before


def test_04_shadow_graph_digest_mismatch_rejected() -> None:
    """Receipt shadow digest != model graph digest -> SHADOW_GRAPH_MISMATCH."""
    store, model, _ = _build_store_with_proposed_model()
    # Build a receipt for a *different* shadow graph.
    other_shadow = {"authority_id": "authority:other", "scope_ref": "scope:other"}
    receipt = _detect(_PRIMARY_GRAPH, other_shadow)
    root_before = _roots(store)

    with pytest.raises(
        GovernedAlternativeModelError, match="GOVERNED_ALT_MODEL_SHADOW_GRAPH_MISMATCH"
    ):
        _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)

    assert _roots(store) == root_before


def test_05_detect_rejects_declared_vs_computed_mismatch() -> None:
    """detect_structural_difference rejects a declared digest != computed digest."""
    primary_bytes = _graph(_PRIMARY_GRAPH)
    shadow_bytes = _graph(_SHADOW_GRAPH)
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="STRUCTURAL_DIFFERENCE_DECLARED_MISMATCH",
    ):
        detect_structural_difference(
            primary_graph_bytes=primary_bytes,
            shadow_graph_bytes=shadow_bytes,
            primary_graph_digest=_graph_digest_of(primary_bytes),
            shadow_graph_digest=_graph_digest_of(shadow_bytes),
            declared_difference_digest=_digest("wrong-declared"),
        )


def test_06_governed_admit_rejects_model_declared_mismatch() -> None:
    """Model's declared_difference_digest != receipt's -> DECLARED_DIFFERENCE_MISMATCH."""
    store, model, _ = _build_store_with_proposed_model(
        declared_difference_digest=_digest("declared:mismatch")
    )
    receipt = _detect(_PRIMARY_GRAPH, _SHADOW_GRAPH)
    root_before = _roots(store)

    with pytest.raises(
        GovernedAlternativeModelError,
        match="GOVERNED_ALT_MODEL_DECLARED_DIFFERENCE_MISMATCH",
    ):
        _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)

    assert _roots(store) == root_before


def test_07_identical_graphs_no_material_difference_rejected() -> None:
    """Identical primary/shadow graphs -> no material difference -> ADMIT denied."""
    identical = {"semantic_seed": "same", "authority_id": "authority:same"}
    store = InMemoryRegistryStore()
    primary_bytes = _graph(identical)
    declared = compute_structural_difference_digest(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=primary_bytes,
    )
    model = _propose_model(
        store,
        shadow_graph=identical,
        primary_graph=identical,
        declared_difference_digest=declared,
    )
    receipt = _detect(identical, identical)
    # The receipt itself records no material difference.
    assert receipt.has_material_difference is False
    assert receipt.difference_paths == ()

    root_before = _roots(store)
    with pytest.raises(
        GovernedAlternativeModelError, match="GOVERNED_ALT_MODEL_NO_MATERIAL_DIFFERENCE"
    ):
        _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)

    assert _roots(store) == root_before


def test_08_denied_admission_leaves_registry_unchanged() -> None:
    """A pre-commit denial leaves the alt-model head/root byte-identical."""
    store, model, _ = _build_store_with_proposed_model(
        declared_difference_digest=_digest("declared:mismatch")
    )
    receipt = _detect(_PRIMARY_GRAPH, _SHADOW_GRAPH)
    root_before = _roots(store)
    head_before = store.entity_head("ALTERNATIVE_MODEL", model.model_id)
    assert head_before is not None and head_before.entity_sequence == 1

    with pytest.raises(GovernedAlternativeModelError):
        _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)

    assert _roots(store) == root_before
    after = store.entity_head("ALTERNATIVE_MODEL", model.model_id)
    assert after == head_before and after.entity_sequence == 1


def test_09_stale_registry_root_retry_mismatch() -> None:
    """Retry after an unrelated alt-model root change -> RETRY_SNAPSHOT_MISMATCH."""
    store = InMemoryRegistryStore()
    # Propose two models.
    model_a = _propose_model(store, model_id="model:a", clock=10)
    model_b = _propose_model(store, model_id="model:b", clock=9)
    receipt_a = _detect(_PRIMARY_GRAPH, _SHADOW_GRAPH)
    receipt_b = _detect(_PRIMARY_GRAPH, _SHADOW_GRAPH)

    first = _governed_admit(
        store=store, model_id="model:a", structural_difference_receipt=receipt_a
    )
    assert first.applied is True
    # Admit the unrelated model B -> alt-model root changes.
    other = _governed_admit(
        store=store, model_id="model:b", structural_difference_receipt=receipt_b
    )
    assert other.applied is True
    # model_b is now admitted; silence unused-var lint via assertion.
    assert model_a.model_id == "model:a"
    assert model_b.model_id == "model:b"

    with pytest.raises(
        GovernedAlternativeModelError, match="GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH"
    ):
        _governed_admit(
            store=store,
            model_id="model:a",
            structural_difference_receipt=receipt_a,
            retry_authorization=first.authorization,
        )


def test_10_exact_retry_idempotent() -> None:
    """Exact retry with the original authorization -> IDEMPOTENT_APPEND."""
    store, model, receipt = _build_store_with_proposed_model()

    first = _governed_admit(
        store=store, model_id=model.model_id, structural_difference_receipt=receipt
    )
    assert first.applied is True
    root_before = _roots(store)

    retry = _governed_admit(
        store=store,
        model_id=model.model_id,
        structural_difference_receipt=receipt,
        retry_authorization=first.authorization,
    )

    assert retry.applied is False
    assert retry.reason == "IDEMPOTENT_APPEND"
    assert retry.event.digest == first.event.digest
    assert retry.head == first.head
    assert _roots(store) == root_before


def test_11_authorization_digest_deterministic() -> None:
    """Replaying the governed append from byte-identical inputs yields identical auth digests."""
    store_a, model_a, receipt_a = _build_store_with_proposed_model(model_id="model:x")
    store_b, model_b, receipt_b = _build_store_with_proposed_model(model_id="model:x")
    assert model_a.model_id == model_b.model_id

    result_a = _governed_admit(
        store=store_a, model_id="model:x", structural_difference_receipt=receipt_a
    )
    result_b = _governed_admit(
        store=store_b, model_id="model:x", structural_difference_receipt=receipt_b
    )

    assert (
        result_a.authorization.authorization_digest == result_b.authorization.authorization_digest
    )
    # And it matches the deterministic domain-separated digest.
    expected = _domain_digest(
        "ALTERNATIVE_MODEL_GOVERNED_ADMIT_AUTHORIZATION",
        result_a.authorization._unsigned_value(),
    )
    assert result_a.authorization.authorization_digest == expected
    # The structural-difference receipt digest is likewise deterministic.
    assert receipt_a.receipt_digest == receipt_b.receipt_digest


def test_12_noncanonical_graph_bytes_rejected() -> None:
    """Non-canonical supplied graph bytes -> GRAPH_BYTES_NONCANONICAL."""
    noncanonical = b'{\n  "authority_id": "authority:primary"\n}\n'  # pretty-printed
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="ALTERNATIVE_MODEL_GRAPH_BYTES_NONCANONICAL",
    ):
        detect_structural_difference(
            primary_graph_bytes=noncanonical,
            shadow_graph_bytes=_graph(_SHADOW_GRAPH),
            primary_graph_digest=_digest("ignored"),
            shadow_graph_digest=_graph_digest_of(_graph(_SHADOW_GRAPH)),
            declared_difference_digest=_digest("ignored"),
        )


# --------------------------------------------------------------------------- #
# B. Structural-difference families (each triggers FULL_REPLAY)
# --------------------------------------------------------------------------- #


_FAMILY_GRAPH_PAIRS = {
    "SCOPE": (
        {"scope_ref": "a", "semantic_seed": "s"},
        {"scope_ref": "b", "semantic_seed": "s"},
    ),
    "TEMPORAL": (
        {"valid_from": 1, "semantic_seed": "s"},
        {"valid_from": 2, "semantic_seed": "s"},
    ),
    "AUTHORITY": (
        {"authority_id": "x", "semantic_seed": "s"},
        {"authority_id": "y", "semantic_seed": "s"},
    ),
    "EVIDENCE_ADMISSION": (
        {"evidence_ref": "e1", "semantic_seed": "s"},
        {"evidence_ref": "e2", "semantic_seed": "s"},
    ),
    "ADDED_REMOVED": (
        {"semantic_seed": "s", "extra_key": "x"},
        {"semantic_seed": "s"},
    ),
    "RELABELED": (
        {"config": {"x": 1}, "semantic_seed": "s"},
        {"config": "scalar", "semantic_seed": "s"},
    ),
}


@pytest.mark.parametrize("family", sorted(_FAMILY_GRAPH_PAIRS))
def test_13_each_family_triggers_full_replay(family: str) -> None:
    """Each of the 6 difference families classifies correctly and supports a
    full replay comparison (INVARIANT, since seeds match)."""
    primary_obj, shadow_obj = _FAMILY_GRAPH_PAIRS[family]
    primary_bytes = _graph(primary_obj)
    shadow_bytes = _graph(shadow_obj)
    receipt = _detect(primary_obj, shadow_obj)

    assert receipt.has_material_difference is True
    assert family in receipt.difference_families
    # FULL_REPLAY comparison completes through the production orchestration.
    comparison = run_full_replay_comparison(
        executor=_TestReplayExecutor(),
        structural_difference_receipt=receipt,
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=7,
        runner_revision="runner:test-rev-1",
        required_inventory=("inv:a", "inv:b"),
    )
    assert comparison.comparison_result == "INVARIANT"


def test_14_relabeled_family_on_same_key_value_change() -> None:
    """RELABELED fires on any same-key value/type change at a non-keyword path."""
    # Object vs scalar (type mismatch).
    receipt_a = _detect({"config": {"x": 1}}, {"config": "scalar"})
    assert receipt_a.difference_paths == ("/config",)
    assert receipt_a.difference_families == ("RELABELED",)
    # Scalar value change (no type mismatch).
    receipt_b = _detect({"notes": "a"}, {"notes": "b"})
    assert receipt_b.difference_paths == ("/notes",)
    assert receipt_b.difference_families == ("RELABELED",)


def test_15_multiple_families_collected_sorted_unique() -> None:
    """A graph pair differing across several keyword domains collects all families."""
    primary = {
        "scope_ref": "a",
        "authority_id": "x",
        "evidence_ref": "e1",
        "valid_from": 1,
        "notes": "a",
    }
    shadow = {
        "scope_ref": "b",
        "authority_id": "y",
        "evidence_ref": "e2",
        "valid_from": 2,
        "notes": "b",
    }
    receipt = _detect(primary, shadow)
    assert receipt.difference_families == (
        "AUTHORITY",
        "EVIDENCE_ADMISSION",
        "RELABELED",
        "SCOPE",
        "TEMPORAL",
    )
    assert len(receipt.difference_paths) == 5
    # Self-digest verification survives a tamper attempt.
    from dataclasses import replace as dc_replace

    with pytest.raises(AssumptionGovernanceContractError):
        dc_replace(receipt, receipt_digest=_digest("forged"))


# --------------------------------------------------------------------------- #
# C. FULL_REPLAY receipt invariants
# --------------------------------------------------------------------------- #


def test_16_replay_incomplete_inventory_rejected() -> None:
    """executed_inventory != required_inventory -> NOT_FULLY_EXECUTED."""
    with pytest.raises(
        AssumptionGovernanceContractError, match="REPLAY_RECEIPT_NOT_FULLY_EXECUTED"
    ):
        _build_replay_receipt(
            graph_digest=_digest("g"),
            decision_context_digest=_digest("ctx"),
            initial_state_digest=_digest("init"),
            logical_clock=3,
            runner_revision="runner:r1",
            required_inventory=("inv:a", "inv:b"),
            executed_inventory=("inv:a",),
            semantic_outcome_digest=_digest("out"),
        )


def test_17_replay_skipped_inventory_rejected() -> None:
    """Non-empty skipped_inventory -> SKIPPED_NONEMPTY."""
    with pytest.raises(AssumptionGovernanceContractError, match="REPLAY_RECEIPT_SKIPPED_NONEMPTY"):
        _build_replay_receipt(
            graph_digest=_digest("g"),
            decision_context_digest=_digest("ctx"),
            initial_state_digest=_digest("init"),
            logical_clock=3,
            runner_revision="runner:r1",
            required_inventory=("inv:a",),
            skipped_inventory=("inv:skip",),
            semantic_outcome_digest=_digest("out"),
        )


def test_18_replay_pruned_inventory_rejected() -> None:
    """Non-empty pruned_inventory -> PRUNED_NONEMPTY."""
    with pytest.raises(AssumptionGovernanceContractError, match="REPLAY_RECEIPT_PRUNED_NONEMPTY"):
        _build_replay_receipt(
            graph_digest=_digest("g"),
            decision_context_digest=_digest("ctx"),
            initial_state_digest=_digest("init"),
            logical_clock=3,
            runner_revision="runner:r1",
            required_inventory=("inv:a",),
            pruned_inventory=("inv:prune",),
            semantic_outcome_digest=_digest("out"),
        )


def test_19_replay_failure_produces_no_comparison() -> None:
    """A failing shadow replay raises; no ComparisonReceipt is produced."""
    primary = {"semantic_seed": "alpha", "notes": "x"}
    shadow = {"semantic_seed": "beta-fails", "notes": "y"}
    receipt = _detect(primary, shadow)
    executor = _TestReplayExecutor(fail_on_seed="beta-fails")

    primary_bytes = _graph(primary)
    # Primary replay succeeds.
    executor.replay(
        graph_bytes=primary_bytes,
        graph_digest=receipt.primary_graph_digest,
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=3,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
    )
    # Shadow replay raises -> no comparison can be built.
    with pytest.raises(RuntimeError, match="injected replay failure"):
        executor.replay(
            graph_bytes=_graph(shadow),
            graph_digest=receipt.shadow_graph_digest,
            decision_context_digest=_digest("ctx"),
            initial_state_digest=_digest("init"),
            logical_clock=3,
            runner_revision="runner:r1",
            required_inventory=("inv:a",),
        )


def test_20_replay_receipts_deterministic() -> None:
    """Replaying the same graph twice yields byte-identical receipts."""
    executor = _TestReplayExecutor()
    graph = {"semantic_seed": "same", "notes": "x"}
    graph_bytes = _graph(graph)
    a = executor.replay(
        graph_bytes=graph_bytes,
        graph_digest=_graph_digest_of(graph_bytes),
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=4,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
    )
    b = executor.replay(
        graph_bytes=graph_bytes,
        graph_digest=_graph_digest_of(graph_bytes),
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=4,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
    )
    assert a.receipt_digest == b.receipt_digest
    assert a.canonical_bytes == b.canonical_bytes


# --------------------------------------------------------------------------- #
# D. Canonical comparison
# --------------------------------------------------------------------------- #


def test_21_comparison_invariant_same_outcome() -> None:
    """Same semantic_seed -> equal outcome -> INVARIANT."""
    primary = {"semantic_seed": "same", "notes": "x"}
    shadow = {"semantic_seed": "same", "notes": "y"}
    receipt = _detect(primary, shadow)
    comparison = _run_comparison(
        _TestReplayExecutor(),
        receipt,
        primary_bytes=_graph(primary),
        shadow_bytes=_graph(shadow),
    )
    assert comparison.comparison_result == "INVARIANT"
    # Self-digest is the deterministic domain digest.
    diff_receipt_value = comparison.structural_difference_receipt.to_json_value()
    expected = _domain_digest(
        _COMPARISON_RECEIPT_DOMAIN,
        {
            "schema_version": _COMPARISON_RECEIPT_SCHEMA_VERSION,
            "primary_replay_receipt": comparison.primary_replay_receipt.to_json_value(),
            "shadow_replay_receipt": comparison.shadow_replay_receipt.to_json_value(),
            "structural_difference_receipt": diff_receipt_value,
            "comparison_result": "INVARIANT",
        },
    )
    assert comparison.comparison_digest == expected


def test_22_comparison_divergent_different_outcome() -> None:
    """Different semantic_seed -> different outcome -> DIVERGENT."""
    primary = {"semantic_seed": "alpha", "notes": "x"}
    shadow = {"semantic_seed": "beta", "notes": "y"}
    receipt = _detect(primary, shadow)
    comparison = _run_comparison(
        _TestReplayExecutor(),
        receipt,
        primary_bytes=_graph(primary),
        shadow_bytes=_graph(shadow),
    )
    assert comparison.comparison_result == "DIVERGENT"


def test_23_comparison_context_mismatch_rejected() -> None:
    """Replays binding different decision contexts cannot be compared."""
    primary = {"semantic_seed": "same", "notes": "x"}
    shadow = {"semantic_seed": "same", "notes": "y"}
    receipt = _detect(primary, shadow)
    primary_replay = _build_replay_receipt(
        graph_digest=receipt.primary_graph_digest,
        decision_context_digest=_digest("ctx-a"),
        initial_state_digest=_digest("init"),
        logical_clock=5,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
        semantic_outcome_digest=_digest("out"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=receipt.shadow_graph_digest,
        decision_context_digest=_digest("ctx-b"),  # different context
        initial_state_digest=_digest("init"),
        logical_clock=5,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
        semantic_outcome_digest=_digest("out"),
    )
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="COMPARISON_RECEIPT_DECISION_CONTEXT_MISMATCH",
    ):
        compare_alternative_model_replays(
            structural_difference_receipt=receipt,
            primary_replay_receipt=primary_replay,
            shadow_replay_receipt=shadow_replay,
        )


def test_24_comparison_graph_binding_mismatch_rejected() -> None:
    """A replay whose graph digest does not match the diff receipt is rejected."""
    primary = {"semantic_seed": "same", "notes": "x"}
    shadow = {"semantic_seed": "same", "notes": "y"}
    receipt = _detect(primary, shadow)
    # Primary replay binds the WRONG graph digest (the shadow's).
    primary_replay = _build_replay_receipt(
        graph_digest=receipt.shadow_graph_digest,
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=5,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
        semantic_outcome_digest=_digest("out"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=receipt.shadow_graph_digest,
        decision_context_digest=_digest("ctx"),
        initial_state_digest=_digest("init"),
        logical_clock=5,
        runner_revision="runner:r1",
        required_inventory=("inv:a",),
        semantic_outcome_digest=_digest("out"),
    )
    with pytest.raises(
        AssumptionGovernanceContractError,
        match="COMPARISON_RECEIPT_PRIMARY_GRAPH_BINDING_MISMATCH",
    ):
        compare_alternative_model_replays(
            structural_difference_receipt=receipt,
            primary_replay_receipt=primary_replay,
            shadow_replay_receipt=shadow_replay,
        )


# --------------------------------------------------------------------------- #
# E. Use-time authority gate
# --------------------------------------------------------------------------- #


def test_25_use_unverified_denied() -> None:
    """UNVERIFIED standing -> DENY (USE_DENIED_UNVERIFIED)."""
    model = _make_model(separation_status=STANDING_UNVERIFIED)
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=5, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "USE_DENIED_UNVERIFIED"


def test_26_use_terminal_denied() -> None:
    """Terminal standing (EXPIRED) -> DENY (USE_DENIED_TERMINAL)."""
    model = _make_model(separation_status=STANDING_EXPIRED)
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=5, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "USE_DENIED_TERMINAL"


@pytest.mark.parametrize("terminal_status", [STANDING_REJECTED, STANDING_EXPIRED])
def test_27_use_terminal_variants_denied(terminal_status: str) -> None:
    model = _make_model(separation_status=terminal_status)
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=5, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "USE_DENIED_TERMINAL"


def test_28_use_expired_denied() -> None:
    """logical_clock >= expires_at_sequence -> DENY (USE_DENIED_EXPIRED)."""
    model = _make_model(separation_status=STANDING_ADMITTED, expires_at_sequence=5)
    denied = evaluate_alternative_model_use_authority(
        model=model, logical_clock=5, scope_id="scope:control", required_reuse_class="D2"
    )
    assert denied.decision == "DENY"
    assert denied.reason_code == "USE_DENIED_EXPIRED"
    # One tick before expiry is allowed.
    allowed = evaluate_alternative_model_use_authority(
        model=model, logical_clock=4, scope_id="scope:control", required_reuse_class="D2"
    )
    assert allowed.decision == "ALLOW"


def test_29_use_scope_mismatch_denied() -> None:
    """scope_id not in model scope_ids -> DENY (USE_DENIED_SCOPE)."""
    model = _make_model(separation_status=STANDING_ADMITTED, scope_ids=("scope:control",))
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=3, scope_id="scope:other", required_reuse_class="D2"
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "USE_DENIED_SCOPE"


def test_30_use_reuse_class_denied() -> None:
    """required_reuse_class rank > maximum_reuse_class rank -> DENY."""
    model = _make_model(separation_status=STANDING_ADMITTED, maximum_reuse_class="D1")
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=3, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "USE_DENIED_REUSE_CLASS"
    # Required at or below max is allowed.
    allowed = evaluate_alternative_model_use_authority(
        model=model, logical_clock=3, scope_id="scope:control", required_reuse_class="D1"
    )
    assert allowed.decision == "ALLOW"


def test_31_use_admitted_valid_allowed() -> None:
    """ADMITTED + in scope + reuse class OK + not expired -> ALLOW."""
    model = _make_model(
        separation_status=STANDING_ADMITTED,
        scope_ids=("scope:control",),
        maximum_reuse_class="D2",
        expires_at_sequence=100,
    )
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=10, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "ALLOW"
    assert decision.reason_code == "USE_ALLOWED"


def test_32_use_confirmed_standing_allowed() -> None:
    """CONFIRMED is also a usable standing."""
    model = _make_model(separation_status=STANDING_CONFIRMED)
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=3, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "ALLOW"


def test_33_use_decision_self_digesting() -> None:
    """The use-time decision is self-digesting and tamper-evident."""
    from dataclasses import replace as dc_replace

    model = _make_model(separation_status=STANDING_ADMITTED)
    decision = evaluate_alternative_model_use_authority(
        model=model, logical_clock=3, scope_id="scope:control", required_reuse_class="D2"
    )
    assert decision.decision == "ALLOW"
    with pytest.raises(AssumptionGovernanceContractError):
        dc_replace(decision, decision_digest=_digest("forged"))
    with pytest.raises(AssumptionGovernanceContractError):
        dc_replace(decision, reason_code="USE_FORGED")


# --------------------------------------------------------------------------- #
# F. No-mutation + no-external-truth
# --------------------------------------------------------------------------- #


def test_34_read_replay_operations_leave_registry_unchanged() -> None:
    """P3.4 read/replay operations (detect, replay, compare) leave the registry unchanged."""
    store, model, receipt = _build_store_with_proposed_model()
    # Admit the model so it has a stable state to inspect.
    _governed_admit(store=store, model_id=model.model_id, structural_difference_receipt=receipt)
    root_before = _roots(store)
    head_before = store.entity_head("ALTERNATIVE_MODEL", model.model_id)

    # Read-only: detect + replay + compare against the admitted model's graphs.
    primary_bytes = _graph(_PRIMARY_GRAPH)
    shadow_bytes = _graph(_SHADOW_GRAPH)
    diff_receipt = _detect(_PRIMARY_GRAPH, _SHADOW_GRAPH)
    _run_comparison(
        _TestReplayExecutor(),
        diff_receipt,
        primary_bytes=primary_bytes,
        shadow_bytes=shadow_bytes,
    )
    # Use-time evaluation.
    admitted_model = AlternativeModelRegistry(store).current(model.model_id)
    assert admitted_model is not None
    evaluate_alternative_model_use_authority(
        model=admitted_model,
        logical_clock=20,
        scope_id="scope:control",
        required_reuse_class="D2",
    )

    assert _roots(store) == root_before
    assert store.entity_head("ALTERNATIVE_MODEL", model.model_id) == head_before


def test_35_no_external_truth_pure_function() -> None:
    """detect_structural_difference is a pure function of the graph bytes; its
    receipt digest is independently computable with no registry or state."""
    primary_bytes = _graph(_PRIMARY_GRAPH)
    shadow_bytes = _graph(_SHADOW_GRAPH)

    receipt_a = detect_structural_difference(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        primary_graph_digest=_graph_digest_of(primary_bytes),
        shadow_graph_digest=_graph_digest_of(shadow_bytes),
        declared_difference_digest=compute_structural_difference_digest(
            primary_graph_bytes=primary_bytes, shadow_graph_bytes=shadow_bytes
        ),
    )
    receipt_b = detect_structural_difference(
        primary_graph_bytes=primary_bytes,
        shadow_graph_bytes=shadow_bytes,
        primary_graph_digest=_graph_digest_of(primary_bytes),
        shadow_graph_digest=_graph_digest_of(shadow_bytes),
        declared_difference_digest=compute_structural_difference_digest(
            primary_graph_bytes=primary_bytes, shadow_graph_bytes=shadow_bytes
        ),
    )
    # Deterministic across independent calls (no hidden state).
    assert receipt_a.receipt_digest == receipt_b.receipt_digest
    assert receipt_a.canonical_bytes == receipt_b.canonical_bytes
    # The receipt digest equals the offline domain digest over the unsigned value.
    expected = _domain_digest(
        "ALTERNATIVE_MODEL_STRUCTURAL_DIFFERENCE_RECEIPT",
        receipt_a._unsigned_value(),
    )
    assert receipt_a.receipt_digest == expected


# --------------------------------------------------------------------------- #
# Facade re-export sanity
# --------------------------------------------------------------------------- #


def test_facade_reexports_governed_error() -> None:
    """The public facade exports GovernedAlternativeModelError (same class)."""
    assert FacadeGovernedAlternativeModelError is GovernedAlternativeModelError
    # The UseAuthorityDecision type is exported through the facade too.
    from csd_foundry.governance.v0_5.governed_alternative_model import (
        UseAuthorityDecision as FacadeUseAuthorityDecision,
    )

    assert FacadeUseAuthorityDecision is UseAuthorityDecision


def test_array_authority_member_change_classified_as_authority() -> None:
    """A change inside a list element's authority_id field is classified as AUTHORITY."""
    primary = _canonical_json({"nodes": [{"authority_id": "authority:a"}]})
    shadow = _canonical_json({"nodes": [{"authority_id": "authority:b"}]})
    primary_digest = _graph_digest_of(primary)
    shadow_digest = _graph_digest_of(shadow)
    diff_digest = compute_structural_difference_digest(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
    )
    receipt = detect_structural_difference(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
        primary_graph_digest=primary_digest,
        shadow_graph_digest=shadow_digest,
        declared_difference_digest=diff_digest,
    )
    assert "AUTHORITY" in receipt.difference_families
    assert receipt.has_material_difference is True
    assert receipt.difference_paths == ("/nodes/0/authority_id",)


def test_array_member_added_classified_as_added_removed() -> None:
    """A list member present on one side only is classified as ADDED_REMOVED."""
    primary = _canonical_json({"nodes": [{"id": "a"}]})
    shadow = _canonical_json({"nodes": [{"id": "a"}, {"id": "b"}]})
    primary_digest = _graph_digest_of(primary)
    shadow_digest = _graph_digest_of(shadow)
    diff_digest = compute_structural_difference_digest(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
    )
    receipt = detect_structural_difference(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
        primary_graph_digest=primary_digest,
        shadow_graph_digest=shadow_digest,
        declared_difference_digest=diff_digest,
    )
    assert "ADDED_REMOVED" in receipt.difference_families
    assert receipt.has_material_difference is True
    assert receipt.difference_paths == ("/nodes/1",)


def test_nested_list_scope_key_classified_as_scope() -> None:
    """A change in a nested list element's scope_id field is classified as SCOPE."""
    primary = _canonical_json({"layers": [{"scope_ids": ["scope:alpha"]}]})
    shadow = _canonical_json({"layers": [{"scope_ids": ["scope:beta"]}]})
    primary_digest = _graph_digest_of(primary)
    shadow_digest = _graph_digest_of(shadow)
    diff_digest = compute_structural_difference_digest(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
    )
    receipt = detect_structural_difference(
        primary_graph_bytes=primary,
        shadow_graph_bytes=shadow,
        primary_graph_digest=primary_digest,
        shadow_graph_digest=shadow_digest,
        declared_difference_digest=diff_digest,
    )
    assert "SCOPE" in receipt.difference_families
    assert receipt.has_material_difference is True
    assert receipt.difference_paths == ("/layers/0/scope_ids/0",)


def test_json_pointer_collision_and_escaping() -> None:
    """RFC 6901 JSON Pointer paths are unambiguous: object keys containing
    ``/`` and ``~`` are escaped so they cannot collide with structural segments.

    Two structurally different representations that would collide under
    dot/bracket notation produce distinct JSON Pointer paths:

    - Object key ``"nodes[0]"`` containing an authority_id → ``/nodes[0]/authority_id``
    - Array ``nodes`` index 0 containing an authority_id → ``/nodes/0/authority_id``

    Additionally, keys containing ``/`` and ``~`` are properly escaped:
    ``"a/b~c"`` → ``/a~1b~0c``.
    """
    # 1. Object key "nodes[0]" — brackets are NOT escaped (only / and ~ are).
    primary_a = _canonical_json({"nodes[0]": {"authority_id": "authority:a"}})
    shadow_a = _canonical_json({"nodes[0]": {"authority_id": "authority:b"}})
    receipt_a = detect_structural_difference(
        primary_graph_bytes=primary_a,
        shadow_graph_bytes=shadow_a,
        primary_graph_digest=_graph_digest_of(primary_a),
        shadow_graph_digest=_graph_digest_of(shadow_a),
        declared_difference_digest=compute_structural_difference_digest(
            primary_graph_bytes=primary_a, shadow_graph_bytes=shadow_a
        ),
    )
    assert receipt_a.difference_paths == ("/nodes[0]/authority_id",)

    # 2. Actual array path — distinct from the object-key path above.
    primary_b = _canonical_json({"nodes": [{"authority_id": "authority:a"}]})
    shadow_b = _canonical_json({"nodes": [{"authority_id": "authority:b"}]})
    receipt_b = detect_structural_difference(
        primary_graph_bytes=primary_b,
        shadow_graph_bytes=shadow_b,
        primary_graph_digest=_graph_digest_of(primary_b),
        shadow_graph_digest=_graph_digest_of(shadow_b),
        declared_difference_digest=compute_structural_difference_digest(
            primary_graph_bytes=primary_b, shadow_graph_bytes=shadow_b
        ),
    )
    assert receipt_b.difference_paths == ("/nodes/0/authority_id",)

    # The two paths must be distinct.
    assert receipt_a.difference_paths != receipt_b.difference_paths

    # 3. Keys containing / and ~ are escaped: "a/b~c" → segment "a~1b~0c".
    primary_c = _canonical_json({"a/b~c": 1})
    shadow_c = _canonical_json({"a/b~c": 2})
    receipt_c = detect_structural_difference(
        primary_graph_bytes=primary_c,
        shadow_graph_bytes=shadow_c,
        primary_graph_digest=_graph_digest_of(primary_c),
        shadow_graph_digest=_graph_digest_of(shadow_c),
        declared_difference_digest=compute_structural_difference_digest(
            primary_graph_bytes=primary_c, shadow_graph_bytes=shadow_c
        ),
    )
    assert receipt_c.difference_paths == ("/a~1b~0c",)
