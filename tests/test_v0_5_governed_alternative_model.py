ke_model(
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
    assert any("authority_id" in p for p in receipt.difference_paths)


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
    assert any("[1]" in p for p in receipt.difference_paths)


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
