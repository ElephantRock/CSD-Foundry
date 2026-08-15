"""Complete P3.7 Phase-3 integrated qualification acceptance campaign.

Exercises the serialized canary corpus through the independent validator and
mutation campaign, plus crash/fault injection, post-finalization recovery,
corruption-at-rest detection, historical invariants, and the frozen phase
order + determinism guarantees of the D5 atomic integration layer.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from csd_foundry.governance.v0_5._d5_generation import (
    D5GenerationConflictError,
    D5GenerationStore,
    ReferenceDispositionAdapter,
    ReferenceQuarantineAdapter,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    parse_contract,
)
from csd_foundry.governance.v0_5.evidence import build_evidence_event
from csd_foundry.governance.v0_5.phase3_qualification import (
    Phase3QualificationReport,
    build_phase3_canary_corpus,
    build_phase3_mutation_manifest,
    build_phase3_scenario,
    commit_phase3_generation,
    evaluate_phase3_mutations,
    phase3_adapters,
    phase3_corpus_digest,
    run_phase3_qualification,
    serialize_phase3_corpus,
    validate_phase3_generations,
)
from csd_foundry.governance.v0_5.phase3_validation import compute_generation_digest
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    RegistryEntityHead,
    RegistryStoreError,
    _snapshot_root,
)
from csd_foundry.governance.v0_5.temporal_validation import (
    ReferenceSemanticProjector,
)

_GENESIS = "sha256:" + hashlib.sha256(b"D5_GENERATION_GENESIS").hexdigest()
_REGISTRIES = {
    "evidence": "EVIDENCE_UNIT",
    "assumption": "ASSUMPTION",
    "alt_model": "ALTERNATIVE_MODEL",
}
_PLAN_DOMAINS = {
    "evidence": "EVIDENCE_PROJECTION_PLAN",
    "assumption": "ASSUMPTION_PROJECTION_PLAN",
    "alt_model": "ALTERNATIVE_MODEL_PROJECTION_PLAN",
}


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def corpus() -> dict[str, Any]:
    return build_phase3_canary_corpus()


@pytest.fixture(scope="session")
def validation(corpus: dict[str, Any]):
    return validate_phase3_generations(corpus)


@pytest.fixture(scope="session")
def qualification() -> Phase3QualificationReport:
    return run_phase3_qualification()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _canonical(value: object) -> bytes:
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


def _capture_state(store: D5GenerationStore) -> tuple[str, str, str, str, int, str | None]:
    completion = store.current_completion()
    return (
        store.current_generation_digest(),
        store.current_evidence_root(),
        store.current_assumption_root(),
        store.current_alt_model_root(),
        store.current_clock_sequence(),
        completion.digest if completion is not None else None,
    )


def _prepare_only(store: D5GenerationStore, sequence: int, previous: str | None):
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        store, sequence, previous
    )
    return store.prepare_generation(
        claim=claim,
        validated_event=event,
        semantic_receipt=semantic,
        evidence_adapter=evidence,
        assumption_adapter=assumption,
        alt_model_adapter=alt_model,
        governed_admit_evidence=governed,
    )


def _reopen(scenario) -> D5GenerationStore:
    return D5GenerationStore(
        evidence_store=scenario.evidence_store,
        assumption_store=scenario.assumption_store,
        alt_model_store=scenario.alt_model_store,
        generations_dir=scenario.store.root,
    )


def _first_code(report) -> str:
    assert report.errors
    return report.errors[0].split(":")[0]


class _FailingAdapter:
    def __init__(self, phase: str) -> None:
        self._phase = phase

    def project(self, **_kwargs: object) -> object:
        raise RuntimeError(f"{self._phase}_INJECTED_FAILURE")


def _rogue_evidence_event(clock: int):
    return build_evidence_event(
        evidence_id=f"evidence:rogue-{clock}",
        entity_sequence=1,
        previous_entity_event_digest=None,
        clock_sequence=clock,
        source_receipt_digest="sha256:" + hashlib.sha256(f"rogue:{clock}".encode()).hexdigest(),
        payload={
            "operation": "REGISTER",
            "proposition_id": f"proposition:rogue-{clock}",
            "scope_ids": ["scope:phase3"],
            "source_id": f"source:rogue-{clock}",
            "issuer_authority_id": "authority:issuer",
            "issued_at_sequence": clock,
            "valid_from_sequence": clock,
            "expires_at_sequence": clock + 100,
            "dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": "D2",
        },
    )


def _typed_heads(manifest: dict[str, Any], registry: str) -> tuple[RegistryEntityHead, ...]:
    return tuple(
        RegistryEntityHead(
            _REGISTRIES[registry],
            cast(str, item["entity_id"]),
            cast(int, item["entity_sequence"]),
            cast(str, item["event_digest"]),
        )
        for item in manifest[f"{registry}_heads"]
    )


def _walk_entity(events: dict[str, Any], head: RegistryEntityHead) -> int:
    """Independently walk one entity chain to genesis; returns chain length."""

    digest: str | None = head.event_digest
    expected = head.entity_sequence
    seen: set[str] = set()
    while digest is not None:
        assert digest not in seen
        seen.add(digest)
        value = cast(dict[str, Any], events[digest])
        parsed = parse_contract("registry-event", value)
        assert parsed.digest == digest
        assert value["entity_id"] == head.entity_id
        assert value["entity_sequence"] == expected
        digest = value["previous_entity_event_digest"]
        expected -= 1
    assert expected == 0
    return head.entity_sequence


# ============================================================================ #
# Independent reconstruction
# ============================================================================ #


def test_multi_generation_chain_reconstructs_deterministically(
    corpus: dict[str, Any], validation
) -> None:
    """(1) The serialized multi-generation chain reconstructs deterministically."""

    assert validation.success, validation.errors
    generations = corpus["generations"]
    assert len(generations) == 5
    for index, manifest in enumerate(generations):
        assert manifest["clock_sequence"] == index + 1
        if index == 0:
            assert manifest["previous_generation_digest"] == _GENESIS
        else:
            assert (
                manifest["previous_generation_digest"]
                == generations[index - 1]["generation_digest"]
            )
    pointer = corpus["current_pointer"]
    assert pointer["generation_digest"] == generations[-1]["generation_digest"]
    assert pointer["clock_sequence"] == 5


def test_manifest_self_digests_verify(corpus: dict[str, Any]) -> None:
    """(2) Every generation manifest self-digest recomputes exactly."""

    for index, manifest in enumerate(corpus["generations"]):
        unsigned = {key: value for key, value in manifest.items() if key != "generation_digest"}
        assert compute_generation_digest(unsigned) == manifest["generation_digest"], index


def test_registry_roots_reconstruct_from_canonical_head_sets(
    corpus: dict[str, Any], validation
) -> None:
    """(3) All three registry roots re-derive from the canonical head sets."""

    assert validation.success, validation.errors
    for index, manifest in enumerate(corpus["generations"]):
        for registry, registry_type in _REGISTRIES.items():
            heads = _typed_heads(manifest, registry)
            assert heads, (index, registry)
            root = _snapshot_root(registry_type, heads)
            assert root == manifest[f"{registry}_projected_root"], (index, registry)
    for index, summary in enumerate(validation.generations):
        manifest = corpus["generations"][index]
        assert summary.evidence_root == manifest["evidence_projected_root"]
        assert summary.assumption_root == manifest["assumption_projected_root"]
        assert summary.alt_model_root == manifest["alt_model_projected_root"]


def test_event_chains_link_correctly(corpus: dict[str, Any]) -> None:
    """(4) Every entity chain walks to genesis with contiguous sequences."""

    events = corpus["events"]
    for manifest in corpus["generations"]:
        for registry in _REGISTRIES:
            for head in _typed_heads(manifest, registry):
                length = _walk_entity(events, head)
                assert length >= 1


def test_projection_plan_digests_cross_check(corpus: dict[str, Any]) -> None:
    """(5) All fifteen projection plans cross-check against their manifests."""

    plans = corpus["projection_plans"]
    for index, manifest in enumerate(corpus["generations"]):
        for registry in _REGISTRIES:
            digest = manifest[f"{registry}_plan_digest"]
            plan = plans[digest]
            assert plan["plan_digest"] == digest
            unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
            recomputed = (
                "sha256:"
                + hashlib.sha256(
                    _PLAN_DOMAINS[registry].encode("ascii") + b"\0" + _canonical(unsigned)
                ).hexdigest()
            )
            assert recomputed == digest, (index, registry)
            assert plan["projected_root_digest"] == manifest[f"{registry}_projected_root"]
            assert plan["predecessor_root_digest"] == manifest[f"{registry}_predecessor_root"]
            assert plan["event_digests"] == manifest[f"{registry}_event_digests"]


def test_cross_root_bindings_intact(corpus: dict[str, Any], validation) -> None:
    """(6) Evidence -> assumption -> alternative-model root bindings hold."""

    assert validation.success, validation.errors
    for index, manifest in enumerate(corpus["generations"]):
        assert (
            manifest["assumption_evidence_root_binding"] == manifest["evidence_projected_root"]
        ), index
        assert manifest["alt_model_evidence_root_binding"] == manifest["evidence_projected_root"], (
            index
        )
        assert (
            manifest["alt_model_assumption_root_binding"] == manifest["assumption_projected_root"]
        ), index
        assumption_plan = corpus["projection_plans"][manifest["assumption_plan_digest"]]
        assert assumption_plan["evidence_root_digest"] == manifest["evidence_projected_root"], index
        alt_plan = corpus["projection_plans"][manifest["alt_model_plan_digest"]]
        assert alt_plan["evidence_root_digest"] == manifest["evidence_projected_root"], index
        assert alt_plan["assumption_root_digest"] == manifest["assumption_projected_root"], index


def test_d4_admit_full_replay_comparison_evidence_present(corpus: dict[str, Any]) -> None:
    """The genuine D4 ADMIT carries primary/shadow FULL_REPLAY receipts."""

    comparisons = corpus["comparison_receipts"]
    assert len(comparisons) == 1
    comparison = next(iter(comparisons.values()))
    assert comparison["comparison_result"] in {"INVARIANT", "DIVERGENT"}
    gen2 = corpus["generations"][1]
    alt_plan = corpus["projection_plans"][gen2["alt_model_plan_digest"]]
    bindings = alt_plan["admit_comparison_bindings"]
    assert len(bindings) == 1
    assert bindings[0][1] in comparisons
    for label in ("primary_replay_receipt", "shadow_replay_receipt"):
        replay = comparison[label]
        assert replay["executed_inventory"] == replay["required_inventory"]
        assert replay["skipped_inventory"] == []
        assert replay["pruned_inventory"] == []


def test_mutation_campaign_kills_every_declared_mutation(
    corpus: dict[str, Any], qualification: Phase3QualificationReport
) -> None:
    """The independent mutation campaign records zero unexplained escapes."""

    campaign = build_phase3_mutation_manifest(corpus)
    report = evaluate_phase3_mutations(corpus, campaign)
    assert report.killed_count == len(report.results)
    assert report.unexplained_escape_count == 0
    assert report.success, report.errors
    assert qualification.mutation_success


# ============================================================================ #
# Crash / fault injection
# ============================================================================ #


def test_evidence_staging_failure_leaves_all_roots_unchanged(tmp_path: Path) -> None:
    """(7) An EVIDENCE-phase failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        scenario.store, 2, scenario.manifests[-1].clock_completion_digest
    )
    del evidence
    with pytest.raises(RuntimeError, match="EVIDENCE_REGISTRY_INJECTED_FAILURE"):
        scenario.store.prepare_generation(
            claim=claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=cast(Any, _FailingAdapter("EVIDENCE_REGISTRY")),
            assumption_adapter=assumption,
            alt_model_adapter=alt_model,
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


def test_assumption_staging_failure_leaves_all_roots_unchanged(tmp_path: Path) -> None:
    """(8) An ASSUMPTION-phase failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        scenario.store, 2, scenario.manifests[-1].clock_completion_digest
    )
    del assumption
    with pytest.raises(RuntimeError, match="ASSUMPTION_REGISTRY_INJECTED_FAILURE"):
        scenario.store.prepare_generation(
            claim=claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=cast(Any, _FailingAdapter("ASSUMPTION_REGISTRY")),
            alt_model_adapter=alt_model,
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


def test_alt_model_staging_failure_leaves_all_roots_unchanged(tmp_path: Path) -> None:
    """(9) An ALTERNATIVE_MODEL-phase failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        scenario.store, 2, scenario.manifests[-1].clock_completion_digest
    )
    del alt_model
    with pytest.raises(RuntimeError, match="ALTERNATIVE_MODEL_REGISTRY_INJECTED_FAILURE"):
        scenario.store.prepare_generation(
            claim=claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=assumption,
            alt_model_adapter=cast(Any, _FailingAdapter("ALTERNATIVE_MODEL_REGISTRY")),
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


def test_disposition_failure_leaves_all_roots_unchanged(tmp_path: Path) -> None:
    """(10) A DISPOSITION-phase failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)

    class _FailingDisposition:
        def project(self, **_kwargs: object) -> object:
            raise RuntimeError("DISPOSITION_INJECTED_FAILURE")

    failing = D5GenerationStore(
        evidence_store=scenario.evidence_store,
        assumption_store=scenario.assumption_store,
        alt_model_store=scenario.alt_model_store,
        generations_dir=scenario.store.root,
        disposition_adapter_factory=_FailingDisposition,
    )
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        failing, 2, scenario.manifests[-1].clock_completion_digest
    )
    with pytest.raises(RuntimeError, match="DISPOSITION_INJECTED_FAILURE"):
        failing.prepare_generation(
            claim=claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=assumption,
            alt_model_adapter=alt_model,
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


def test_quarantine_failure_leaves_all_roots_unchanged(tmp_path: Path) -> None:
    """(11) A QUARANTINE_COMMIT-phase failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)

    class _FailingQuarantine:
        def project(self) -> object:
            raise RuntimeError("QUARANTINE_COMMIT_INJECTED_FAILURE")

    failing = D5GenerationStore(
        evidence_store=scenario.evidence_store,
        assumption_store=scenario.assumption_store,
        alt_model_store=scenario.alt_model_store,
        generations_dir=scenario.store.root,
        quarantine_adapter_factory=_FailingQuarantine,
    )
    evidence, assumption, alt_model, governed, (claim, event, semantic) = phase3_adapters(
        failing, 2, scenario.manifests[-1].clock_completion_digest
    )
    with pytest.raises(RuntimeError, match="QUARANTINE_COMMIT_INJECTED_FAILURE"):
        failing.prepare_generation(
            claim=claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=assumption,
            alt_model_adapter=alt_model,
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


def test_event_object_installation_failure_leaves_all_roots_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(12) An Nth-object (event) installation failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    manifest2 = _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    baseline = _capture_state(scenario.store)
    pointer_before = scenario.store.current_path.read_bytes()

    original = FilesystemRegistryStore._install
    armed = {"on": False}

    def failing_install(self: FilesystemRegistryStore, path: Path, payload: bytes) -> None:
        if armed["on"] and path.parent.parent.name == "registry-event":
            raise RuntimeError("EVENT_OBJECT_INSTALL_INJECTED_FAILURE")
        original(self, path, payload)

    monkeypatch.setattr(FilesystemRegistryStore, "_install", failing_install)
    armed["on"] = True
    with pytest.raises(RuntimeError, match="EVENT_OBJECT_INSTALL_INJECTED_FAILURE"):
        scenario.store.commit_generation(manifest2)
    armed["on"] = False
    monkeypatch.undo()

    assert _capture_state(scenario.store) == baseline
    assert scenario.store.current_path.read_bytes() == pointer_before


def test_manifest_installation_failure_leaves_all_roots_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(13) A manifest installation failure changes no committed root."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    manifest2 = _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    baseline = _capture_state(scenario.store)
    pointer_before = scenario.store.current_path.read_bytes()

    original = D5GenerationStore._install

    def failing_install(self: D5GenerationStore, path: Path, payload: bytes) -> None:
        if path.parent.parent == self.manifests:
            raise RuntimeError("MANIFEST_INSTALL_INJECTED_FAILURE")
        original(self, path, payload)

    monkeypatch.setattr(D5GenerationStore, "_install", failing_install)
    with pytest.raises(RuntimeError, match="MANIFEST_INSTALL_INJECTED_FAILURE"):
        scenario.store.commit_generation(manifest2)
    monkeypatch.undo()

    assert _capture_state(scenario.store) == baseline
    assert scenario.store.current_path.read_bytes() == pointer_before


def test_pointer_replacement_failure_recovery_publishes_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(14) Pointer-replacement failure -> recovery publishes exactly once."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    manifest2 = _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    assert scenario.store.current_generation_digest() == (scenario.manifests[-1].generation_digest)

    original = D5GenerationStore._replace
    fired = {"once": False}

    def failing_replace(self: D5GenerationStore, path: Path, payload: bytes) -> None:
        if path == self.current_path and not fired["once"]:
            fired["once"] = True
            raise RuntimeError("POINTER_REPLACE_INJECTED_FAILURE")
        original(self, path, payload)

    monkeypatch.setattr(D5GenerationStore, "_replace", failing_replace)
    with pytest.raises(RuntimeError, match="POINTER_REPLACE_INJECTED_FAILURE"):
        scenario.store.commit_generation(manifest2)
    monkeypatch.undo()

    reopened = _reopen(scenario)
    assert reopened.recover() == "PREPARED_GENERATION_PUBLISHED"
    published_pointer = reopened.current_path.read_bytes()
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest2.generation_digest
    # Second recovery is a no-op: the generation is published exactly once.
    assert reopened.recover() == "NO_ACTIVE_GENERATION"
    assert reopened.current_path.read_bytes() == published_pointer
    assert reopened.current_generation_digest() == manifest2.generation_digest


# ============================================================================ #
# Post-finalization recovery
# ============================================================================ #


def test_finalized_pointer_not_replaced_recovery_publishes(tmp_path: Path) -> None:
    """(15) Finalized + pointer not replaced -> recovery publishes."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    manifest2 = _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    reopened = _reopen(scenario)
    assert reopened.current_generation_digest() == (scenario.manifests[-1].generation_digest)
    assert reopened.recover() == "PREPARED_GENERATION_PUBLISHED"
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest2.generation_digest
    assert reopened.current_clock_sequence() == 2
    assert reopened.current_evidence_root() == manifest2.evidence_projected_root


def test_pointer_replaced_with_stale_active_and_prepared_is_idempotent(
    tmp_path: Path,
) -> None:
    """(16) Pointer replaced + stale active/prepared -> idempotent success."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    manifest2 = _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    active_bytes = scenario.store.active_path.read_bytes()
    prepared_bytes = scenario.store.prepared_path.read_bytes()
    scenario.store.commit_generation(manifest2)
    # Simulate stale attempt state left behind by a crash after publication.
    scenario.store.active_path.write_bytes(active_bytes)
    scenario.store.prepared_path.write_bytes(prepared_bytes)

    reopened = _reopen(scenario)
    assert reopened.recover() == "IDEMPOTENT_SUCCESS"
    current = reopened.current_generation()
    assert current is not None
    assert current.generation_digest == manifest2.generation_digest
    assert reopened.current_clock_sequence() == 2
    # Stale attempt state is cleared.
    assert not scenario.store.active_path.exists()
    assert not scenario.store.prepared_path.exists()


def test_stale_attempt_state_cleared(tmp_path: Path) -> None:
    """(17) Recovery clears the stale active/prepared attempt state."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    assert scenario.store.active_path.exists()
    assert scenario.store.prepared_path.exists()
    reopened = _reopen(scenario)
    assert reopened.recover() == "PREPARED_GENERATION_PUBLISHED"
    assert not scenario.store.active_path.exists()
    assert not scenario.store.prepared_path.exists()
    assert reopened.recover() == "NO_ACTIVE_GENERATION"


# ============================================================================ #
# Corruption at rest
# ============================================================================ #


def test_corrupt_evidence_event_fails_closed(corpus: dict[str, Any]) -> None:
    """(18) A corrupted evidence event is detected fail-closed."""

    mutated = deepcopy(corpus)
    digest = mutated["generations"][0]["evidence_event_digests"][0]
    mutated["events"][digest]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated)
    assert not report.success
    assert _first_code(report) == "PHASE3_EVENT_SELF_DIGEST_MISMATCH"


def test_corrupt_assumption_event_fails_closed(corpus: dict[str, Any]) -> None:
    """(19) A corrupted assumption event is detected fail-closed."""

    mutated = deepcopy(corpus)
    digest = mutated["generations"][0]["assumption_event_digests"][0]
    mutated["events"][digest]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated)
    assert not report.success
    assert _first_code(report) == "PHASE3_EVENT_SELF_DIGEST_MISMATCH"


def test_corrupt_alt_model_event_fails_closed(corpus: dict[str, Any]) -> None:
    """(20) A corrupted D4 alternative-model event is detected fail-closed."""

    mutated = deepcopy(corpus)
    digest = mutated["generations"][1]["alt_model_event_digests"][0]
    mutated["events"][digest]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated)
    assert not report.success
    assert _first_code(report) == "PHASE3_EVENT_SELF_DIGEST_MISMATCH"


def test_corrupt_generation_manifest_fails_closed(corpus: dict[str, Any]) -> None:
    """(21) A corrupted generation manifest is detected fail-closed."""

    mutated = deepcopy(corpus)
    mutated["generations"][2]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated)
    assert not report.success
    assert _first_code(report) == "PHASE3_GENERATION_SELF_DIGEST_MISMATCH"


def test_corrupt_completion_semantic_disposition_receipt_fails_closed(
    corpus: dict[str, Any],
) -> None:
    """(22) Corrupted completion/semantic/disposition receipts fail closed."""

    last = corpus["generations"][-1]

    mutated_completion = deepcopy(corpus)
    completion_digest = last["clock_completion_digest"]
    mutated_completion["completions"][completion_digest]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated_completion)
    assert not report.success
    assert _first_code(report) == "PHASE3_COMPLETION_SELF_DIGEST_INVALID"

    mutated_semantic = deepcopy(corpus)
    semantic_digest = last["semantic_projection_receipt_digest"]
    mutated_semantic["semantic_receipts"][semantic_digest]["projection_sequence"] = 999
    report = validate_phase3_generations(mutated_semantic)
    assert not report.success
    assert _first_code(report) == "PHASE3_SEMANTIC_RECEIPT_DIGEST_INVALID"

    mutated_disposition = deepcopy(corpus)
    disposition_digest = last["disposition_receipt_digest"]
    mutated_disposition["disposition_receipts"][disposition_digest]["clock_sequence"] = 999
    report = validate_phase3_generations(mutated_disposition)
    assert not report.success
    assert _first_code(report) == "PHASE3_DISPOSITION_RECEIPT_DIGEST_INVALID"


# ============================================================================ #
# Historical invariants
# ============================================================================ #


def test_every_committed_generation_reconstructs_after_later_advancement(
    corpus: dict[str, Any], validation
) -> None:
    """(23) Every committed generation still reconstructs after advancement."""

    assert validation.success, validation.errors
    events = corpus["events"]
    for index, manifest in enumerate(corpus["generations"]):
        for registry, registry_type in _REGISTRIES.items():
            heads = _typed_heads(manifest, registry)
            assert _snapshot_root(registry_type, heads) == manifest[f"{registry}_projected_root"], (
                index,
                registry,
            )
            for head in heads:
                _walk_entity(events, head)
    # Later advancement never rewrites earlier state: heads are cumulative.
    first = corpus["generations"][0]
    last = corpus["generations"][-1]
    assert first["evidence_projected_root"] != last["evidence_projected_root"]
    assert first["assumption_projected_root"] != last["assumption_projected_root"]
    assert first["alt_model_projected_root"] != last["alt_model_projected_root"]


def test_generation_bound_views_reject_writes(tmp_path: Path) -> None:
    """(24) Generation-bound registry views fail closed on append."""

    scenario = build_phase3_scenario(tmp_path, generations=2)
    view = scenario.store.evidence_view()
    snapshot = view.snapshot("EVIDENCE_UNIT")
    assert snapshot.root_digest == scenario.manifests[-1].evidence_projected_root
    with pytest.raises(RegistryStoreError):
        view.append(_rogue_evidence_event(50))


def test_rogue_standalone_head_advance_cannot_alter_d5_authority(
    tmp_path: Path,
) -> None:
    """(25) A rogue standalone head advance is invisible to D5 authority."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    rogue = _rogue_evidence_event(99)
    scenario.evidence_store.append(rogue)
    live_root = scenario.evidence_store.snapshot("EVIDENCE_UNIT").root_digest

    manifest2 = commit_phase3_generation(
        scenario.store,
        sequence=2,
        previous_completion_digest=scenario.manifests[-1].clock_completion_digest,
    )
    # D5 authority is the manifest root, not the live (rogue-advanced) root.
    assert scenario.store.current_evidence_root() == manifest2.evidence_projected_root
    assert manifest2.evidence_predecessor_root == (scenario.manifests[-1].evidence_projected_root)
    assert live_root != scenario.store.current_evidence_root()

    corpus = serialize_phase3_corpus(scenario)
    report = validate_phase3_generations(corpus)
    assert report.success, report.errors
    assert rogue.digest not in corpus["events"]


def test_stale_predecessor_or_conflicting_claim_fails_closed(tmp_path: Path) -> None:
    """(26) Stale predecessor and conflicting claims both fail closed."""

    scenario = build_phase3_scenario(tmp_path, generations=1)
    baseline = _capture_state(scenario.store)
    evidence, assumption, alt_model, governed, (_claim, event, semantic) = phase3_adapters(
        scenario.store, 2, scenario.manifests[-1].clock_completion_digest
    )

    # Stale predecessor: claim proposes sequence 1 while current is 1.
    stale_claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": "attempt-phase3-stale",
                "previous_committed_sequence": 0,
                "previous_completion_digest": None,
                "proposed_sequence": 1,
                "validated_event_digest": event.digest,
                "claimant_id": "validator",
                "claim_policy_digest": "sha256:" + hashlib.sha256(b"stale").hexdigest(),
            }
        ),
    )
    with pytest.raises(D5GenerationConflictError, match="D5_CLAIM_NOT_SUCCESSOR_OF_CURRENT"):
        scenario.store.prepare_generation(
            claim=stale_claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=assumption,
            alt_model_adapter=alt_model,
        )
    assert _capture_state(scenario.store) == baseline

    # Conflicting claim: a different active claim already holds the attempt.
    _prepare_only(scenario.store, 2, scenario.manifests[-1].clock_completion_digest)
    previous_completion = scenario.manifests[-1].clock_completion_digest
    conflicting_claim = cast(
        ClockClaim,
        ClockClaim.build(
            {
                "schema_version": "clock-claim/1",
                "attempt_id": "attempt-phase3-conflicting",
                "previous_committed_sequence": 1,
                "previous_completion_digest": previous_completion,
                "proposed_sequence": 2,
                "validated_event_digest": event.digest,
                "claimant_id": "validator",
                "claim_policy_digest": "sha256:" + hashlib.sha256(b"conflict").hexdigest(),
            }
        ),
    )
    assert conflicting_claim.digest != _claim.digest
    with pytest.raises(D5GenerationConflictError, match="D5_ACTIVE_GENERATION_CONFLICT"):
        scenario.store.prepare_generation(
            claim=conflicting_claim,
            validated_event=event,
            semantic_receipt=semantic,
            evidence_adapter=evidence,
            assumption_adapter=assumption,
            alt_model_adapter=alt_model,
            governed_admit_evidence=governed,
        )
    assert _capture_state(scenario.store) == baseline


# ============================================================================ #
# Phase order + determinism
# ============================================================================ #


def test_exact_phase_order_observed(tmp_path: Path) -> None:
    """(27) SEMANTIC -> EVIDENCE -> ASSUMPTION -> ALT_MODEL -> DISPOSITION ->
    QUARANTINE -> publish, in exactly that order."""

    order: list[str] = []

    class RecordingEvidence:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def project(self, **kwargs: object) -> object:
            order.append("EVIDENCE")
            return self._inner.project(**kwargs)

    class RecordingAssumption:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def project(self, **kwargs: object) -> object:
            order.append("ASSUMPTION")
            return self._inner.project(**kwargs)

    class RecordingAltModel:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def project(self, **kwargs: object) -> object:
            order.append("ALT_MODEL")
            return self._inner.project(**kwargs)

    def disposition_factory() -> Any:
        inner = ReferenceDispositionAdapter()

        class RecordingDisposition:
            def project(self, **kwargs: object) -> object:
                order.append("DISPOSITION")
                return inner.project(**kwargs)

        return RecordingDisposition()

    def quarantine_factory() -> Any:
        inner = ReferenceQuarantineAdapter()

        class RecordingQuarantine:
            def project(self) -> object:
                order.append("QUARANTINE")
                return inner.project()

        return RecordingQuarantine()

    store = D5GenerationStore(
        evidence_store=FilesystemRegistryStore(tmp_path / "evidence"),
        assumption_store=FilesystemRegistryStore(tmp_path / "assumption"),
        alt_model_store=FilesystemRegistryStore(tmp_path / "alt-model"),
        generations_dir=tmp_path / "generations",
        disposition_adapter_factory=disposition_factory,
        quarantine_adapter_factory=quarantine_factory,
    )
    evidence, assumption, alt_model, governed, (claim, event, _semantic) = phase3_adapters(store, 1)
    order.append("SEMANTIC")
    semantic = ReferenceSemanticProjector().project(claim=claim, validated_event=event)
    manifest = store.prepare_generation(
        claim=claim,
        validated_event=event,
        semantic_receipt=semantic,
        evidence_adapter=cast(Any, RecordingEvidence(evidence)),
        assumption_adapter=cast(Any, RecordingAssumption(assumption)),
        alt_model_adapter=cast(Any, RecordingAltModel(alt_model)),
        governed_admit_evidence=governed,
    )
    order.append("PUBLISH")
    store.commit_generation(manifest)
    assert order == [
        "SEMANTIC",
        "EVIDENCE",
        "ASSUMPTION",
        "ALT_MODEL",
        "DISPOSITION",
        "QUARANTINE",
        "PUBLISH",
    ]


def test_same_inputs_produce_byte_identical_manifests_completions_roots() -> None:
    """(28) Same inputs -> byte-identical manifests, completions, roots."""

    corpus1 = build_phase3_canary_corpus()
    corpus2 = build_phase3_canary_corpus()
    assert len(corpus1["generations"]) == len(corpus2["generations"])
    for manifest1, manifest2 in zip(corpus1["generations"], corpus2["generations"], strict=True):
        assert _canonical(manifest1) == _canonical(manifest2)
    assert set(corpus1["completions"]) == set(corpus2["completions"])
    for digest, completion in corpus1["completions"].items():
        assert _canonical(completion) == _canonical(corpus2["completions"][digest])
    assert set(corpus1["events"]) == set(corpus2["events"])
    for digest, event_value in corpus1["events"].items():
        assert _canonical(event_value) == _canonical(corpus2["events"][digest])


def test_corpus_digest_deterministic_across_repeated_runs(
    corpus: dict[str, Any], qualification: Phase3QualificationReport
) -> None:
    """(29) The corpus digest is deterministic across repeated runs."""

    assert qualification.determinism_confirmed
    assert qualification.corpus_digest == qualification.replay_corpus_digest
    assert qualification.corpus_digest == phase3_corpus_digest(corpus)
    assert qualification.validation_success
    assert qualification.generation_count == 5


def test_no_external_truth_assertion_in_report(
    qualification: Phase3QualificationReport,
) -> None:
    """(30) The qualification report asserts no external truth."""

    value = qualification.to_dict()
    assert value["status"] == "valid"
    boundary = cast(str, value["claim_boundary"])
    assert "does not establish external truth" in boundary
    assert qualification.success
    assert qualification.errors == ()
    validation_value = validate_phase3_generations({}).to_dict()
    assert validation_value["status"] == "invalid"
    assert "does not establish external truth" in cast(str, validation_value["claim_boundary"])


# --------------------------------------------------------------------------- #
# Defensive check that the empty corpus fails closed (guard for test 30).
# --------------------------------------------------------------------------- #


def test_empty_corpus_fails_closed_with_schema_error() -> None:
    report = validate_phase3_generations({})
    assert not report.success
    assert _first_code(report) in {
        "PHASE3_CORPUS_SCHEMA_INVALID",
        "PHASE3_GENERATION_INVENTORY_INVALID",
    }


def test_validator_rejects_wrong_schema_version(corpus: dict[str, Any]) -> None:
    mutated = deepcopy(corpus)
    mutated["schema_version"] = "phase3-canary-corpus/rogue"
    report = validate_phase3_generations(mutated)
    assert not report.success
    assert _first_code(report) == "PHASE3_CORPUS_SCHEMA_INVALID"


def test_qualification_report_is_self_consistent(
    qualification: Phase3QualificationReport,
) -> None:
    value = qualification.to_dict()
    assert value["mutation_unexplained_escapes"] == 0
    assert value["mutation_count"] >= 40
    assert value["report_digest"].startswith("sha256:")
    assert qualification.report_digest == cast(str, value["report_digest"])
