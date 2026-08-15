"""Independent serialized-artifact validation for the P3.7 Phase-3 qualification.

This module re-implements the Phase-3 (D5 atomic multi-registry generation)
integrity derivation from SERIALIZED COMMITTED ARTIFACTS ONLY. It reads the
canary corpus (generation manifests, current pointer, clock completions,
semantic/disposition/comparison receipts, projection plans, and registry-event
envelopes) and independently re-derives every binding:

* generation-chain continuity (predecessor digests, contiguous clock sequences,
  fork/cycle freedom, genesis linkage),
* claim/completion continuity (``previous_completion_digest`` chaining),
* exact manifest self-digests (recomputed from the unsigned value),
* all three canonical head sets re-rooted via the snapshot-root digest,
* event-chain reconstruction (predecessor links, contiguous entity sequences,
  per-event self-digests, genesis linkage, cycle freedom),
* projection-plan digest cross-checks (plan digest, predecessor root, projected
  root, temporal bindings, event inventories),
* cross-root bindings (evidence -> assumption -> alternative-model),
* semantic/disposition reference digests and their root bindings,
* D4 comparison receipts with primary/shadow FULL_REPLAY proof references.

It MUST NOT call ``D5GenerationStore.prepare_generation``,
``D5GenerationStore.commit_generation``, ``D5GenerationStore.recover``,
``D5GenerationStore._verify_finalization``,
``D5GenerationStore._verify_authority_markers``, or any production registry
reducer. It imports only from ``canonicalization``, ``contracts``, and the
snapshot-root helper of the registry substrate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

from csd_foundry.governance.v0_5.canonicalization import GovernanceContractError
from csd_foundry.governance.v0_5.contracts import parse_contract
from csd_foundry.governance.v0_5.registry import RegistryEntityHead, _snapshot_root

CORPUS_SCHEMA_VERSION = "phase3-canary-corpus/1"
MANIFEST_SCHEMA_VERSION = "d5-generation-manifest/1"
CURRENT_POINTER_SCHEMA_VERSION = "current-d5-generation/1"
ACTIVE_MARKER_SCHEMA_VERSION = "active-d5-generation/1"
VALIDATION_REPORT_SCHEMA_VERSION = "phase3-validation-report/1"

_GENESIS_GENERATION_DIGEST = "sha256:" + hashlib.sha256(b"D5_GENERATION_GENESIS").hexdigest()

# Registries: manifest field prefix -> canonical registry type.
_REGISTRIES = {
    "evidence": "EVIDENCE_UNIT",
    "assumption": "ASSUMPTION",
    "alt_model": "ALTERNATIVE_MODEL",
}

# Domain prefixes used by the three projection plans' self-digests.
_PLAN_DIGEST_DOMAINS = {
    "evidence": "EVIDENCE_PROJECTION_PLAN",
    "assumption": "ASSUMPTION_PROJECTION_PLAN",
    "alt_model": "ALTERNATIVE_MODEL_PROJECTION_PLAN",
}

# Domain prefixes used by the D4 comparison/replay receipt self-digests. These
# use the flat (no NUL separator) domain form of the governed contracts.
_COMPARISON_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_COMPARISON_RECEIPT"
_REPLAY_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_REPLAY_RECEIPT"

_EMPTY_ROOTS = {key: _snapshot_root(value, ()) for key, value in _REGISTRIES.items()}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# Exact unsigned manifest field set (everything except ``generation_digest``).
_MANIFEST_UNSIGNED_KEYS = {
    "schema_version",
    "previous_generation_digest",
    "clock_sequence",
    "clock_claim_digest",
    "validated_event_digest",
    "semantic_projection_receipt_digest",
    "evidence_predecessor_root",
    "evidence_plan_digest",
    "evidence_event_digests",
    "evidence_projected_root",
    "evidence_heads",
    "assumption_predecessor_root",
    "assumption_evidence_root_binding",
    "assumption_plan_digest",
    "assumption_event_digests",
    "assumption_projected_root",
    "assumption_heads",
    "alt_model_predecessor_root",
    "alt_model_evidence_root_binding",
    "alt_model_assumption_root_binding",
    "alt_model_plan_digest",
    "alt_model_event_digests",
    "alt_model_projected_root",
    "alt_model_heads",
    "disposition_receipt_digest",
    "quarantine_epoch",
    "quarantine_marker_digests",
    "clock_completion_digest",
}


class Phase3ValidationError(RuntimeError):
    """Stable independent Phase-3 validation failure."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Phase3GenerationSummary:
    """Per-generation independently re-derived summary."""

    clock_sequence: int
    generation_digest: str
    previous_generation_digest: str
    evidence_root: str
    assumption_root: str
    alt_model_root: str
    clock_completion_digest: str


@dataclass(frozen=True, slots=True)
class Phase3ValidationReport:
    """Independent Phase-3 validation report over a serialized corpus."""

    corpus_schema_version: str | None
    generation_count: int
    clock_sequence_head: int
    generations: tuple[Phase3GenerationSummary, ...]
    errors: tuple[str, ...]

    @property
    def success(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": VALIDATION_REPORT_SCHEMA_VERSION,
            "status": "valid" if self.success else "invalid",
            "corpus_schema_version": self.corpus_schema_version,
            "generation_count": self.generation_count,
            "clock_sequence_head": self.clock_sequence_head,
            "generations": [
                {
                    "clock_sequence": item.clock_sequence,
                    "generation_digest": item.generation_digest,
                    "previous_generation_digest": item.previous_generation_digest,
                    "evidence_root": item.evidence_root,
                    "assumption_root": item.assumption_root,
                    "alt_model_root": item.alt_model_root,
                    "clock_completion_digest": item.clock_completion_digest,
                }
                for item in self.generations
            ],
            "errors": list(self.errors),
            "claim_boundary": (
                "This report establishes deterministic serialized Phase-3 generation-chain, "
                "completion-chain, manifest self-digest, canonical head-set rooting, event-chain, "
                "projection-plan, cross-root, semantic/disposition, and D4 comparison integrity "
                "relative to the committed canary corpus. It does not establish external truth, "
                "source completeness, real-world dependency completeness, or production safety."
            ),
        }


# --------------------------------------------------------------------------- #
# Digest helpers (independent re-implementation of the frozen digest forms)
# --------------------------------------------------------------------------- #


def _json_bytes(value: object) -> bytes:
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


def _domain_digest(domain: str, value: object) -> str:
    """NUL-separated domain digest (manifests and projection plans)."""

    return (
        "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + _json_bytes(value)).hexdigest()
    )


def _flat_domain_digest(domain: str, value: object) -> str:
    """Concatenated domain digest (D4 comparison and replay receipts)."""

    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + _json_bytes(value)).hexdigest()


def compute_generation_digest(unsigned_manifest: dict[str, Any]) -> str:
    """Independently recompute a generation manifest's self-digest."""

    return _domain_digest("D5_GENERATION_MANIFEST", unsigned_manifest)


def _is_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


# --------------------------------------------------------------------------- #
# Access helpers
# --------------------------------------------------------------------------- #


def _section(corpus: dict[str, Any], field: str, errors: list[str]) -> dict[str, Any] | None:
    value = corpus.get(field)
    if value is None:
        return None
    if type(value) is not dict or any(type(key) is not str for key in value):
        errors.append(f"PHASE3_CORPUS_SECTION_INVALID: {field}")
        return None
    return cast(dict[str, Any], value)


def _digest_list(value: object) -> list[str] | None:
    if type(value) is not list or any(not _is_digest(item) for item in value):
        return None
    return cast(list[str], value)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def validate_phase3_generations(corpus: dict[str, Any]) -> Phase3ValidationReport:
    """Independently validate a serialized Phase-3 canary corpus."""

    errors: list[str] = []
    if type(corpus) is not dict:
        return Phase3ValidationReport(None, 0, 0, (), ("PHASE3_CORPUS_NOT_OBJECT",))
    schema_version = corpus.get("schema_version")
    if schema_version != CORPUS_SCHEMA_VERSION:
        errors.append(f"PHASE3_CORPUS_SCHEMA_INVALID: {schema_version!r}")

    events = _section(corpus, "events", errors) or {}
    completions = _section(corpus, "completions", errors) or {}
    semantic_receipts = _section(corpus, "semantic_receipts", errors) or {}
    projection_plans = _section(corpus, "projection_plans", errors) or {}
    disposition_receipts = _section(corpus, "disposition_receipts", errors) or {}
    comparison_receipts = _section(corpus, "comparison_receipts", errors) or {}

    generations = _parse_generations(corpus, errors)
    _validate_generation_chain(generations, errors)
    _validate_current_pointer(corpus, generations, errors)
    _validate_active_marker(corpus, generations, errors)
    _validate_event_chains(generations, events, errors)
    _validate_plans(generations, projection_plans, comparison_receipts, errors)
    _validate_cross_root_bindings(generations, errors)
    _validate_semantic_receipts(generations, semantic_receipts, errors)
    _validate_disposition_receipts(generations, disposition_receipts, errors)
    _validate_completions(generations, completions, errors)
    _validate_comparison_receipts(comparison_receipts, errors)

    summaries = tuple(
        Phase3GenerationSummary(
            clock_sequence=cast(int, manifest.get("clock_sequence", 0)),
            generation_digest=cast(str, manifest.get("generation_digest", "")),
            previous_generation_digest=cast(str, manifest.get("previous_generation_digest", "")),
            evidence_root=cast(str, manifest.get("evidence_projected_root", "")),
            assumption_root=cast(str, manifest.get("assumption_projected_root", "")),
            alt_model_root=cast(str, manifest.get("alt_model_projected_root", "")),
            clock_completion_digest=cast(str, manifest.get("clock_completion_digest", "")),
        )
        for manifest in generations
    )
    head_sequence = 0
    if generations:
        last = generations[-1]
        value = last.get("clock_sequence")
        if type(value) is int:
            head_sequence = value
    return Phase3ValidationReport(
        corpus_schema_version=schema_version if type(schema_version) is str else None,
        generation_count=len(generations),
        clock_sequence_head=head_sequence,
        generations=summaries,
        errors=tuple(errors),
    )


# --------------------------------------------------------------------------- #
# Generation parsing + chain continuity
# --------------------------------------------------------------------------- #


def _parse_generations(corpus: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    raw = corpus.get("generations")
    if type(raw) is not list or not raw:
        errors.append("PHASE3_GENERATION_INVENTORY_INVALID")
        return []
    generations: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for index, value in enumerate(raw):
        if type(value) is not dict:
            errors.append(f"PHASE3_GENERATION_NOT_OBJECT: index {index}")
            continue
        if value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            errors.append(f"PHASE3_GENERATION_SCHEMA_INVALID: index {index}")
            continue
        if set(value) != _MANIFEST_UNSIGNED_KEYS | {"generation_digest"}:
            errors.append(f"PHASE3_GENERATION_FIELDS_INVALID: index {index}")
            continue
        claimed = value.get("generation_digest")
        if not _is_digest(claimed):
            errors.append(f"PHASE3_GENERATION_DIGEST_FIELD_INVALID: index {index}")
            continue
        claimed = cast(str, claimed)
        unsigned = {key: item for key, item in value.items() if key != "generation_digest"}
        recomputed = compute_generation_digest(unsigned)
        if recomputed != claimed:
            errors.append(f"PHASE3_GENERATION_SELF_DIGEST_MISMATCH: index {index}")
        if claimed in seen_digests:
            errors.append(f"PHASE3_GENERATION_DUPLICATE: index {index}")
        seen_digests.add(claimed)
        generations.append(value)
    return generations


def _validate_generation_chain(generations: list[dict[str, Any]], errors: list[str]) -> None:
    if not generations:
        return
    sequences: list[int] = []
    for index, manifest in enumerate(generations):
        sequence = manifest.get("clock_sequence")
        if type(sequence) is not int or sequence < 1:
            errors.append(f"PHASE3_GENERATION_SEQUENCE_INVALID: index {index}")
            return
        sequences.append(sequence)
    if sequences != list(range(1, len(generations) + 1)):
        # Either a gap in the contiguous successor ordering or a fork
        # (duplicate sequence) — both break the single-chain invariant.
        if len(set(sequences)) != len(sequences):
            errors.append("PHASE3_GENERATION_FORK: duplicate clock sequence")
        else:
            errors.append(f"PHASE3_GENERATION_SEQUENCE_GAP: {sequences}")
    for index, manifest in enumerate(generations):
        previous = manifest.get("previous_generation_digest")
        if index == 0:
            if previous != _GENESIS_GENERATION_DIGEST:
                errors.append("PHASE3_GENERATION_NOT_GENESIS_LINKED")
            continue
        if previous != generations[index - 1].get("generation_digest"):
            errors.append(f"PHASE3_GENERATION_PREDECESSOR_BREAK: index {index}")
    _walk_generation_chain(generations, errors)


def _walk_generation_chain(generations: list[dict[str, Any]], errors: list[str]) -> None:
    """Walk backward from the head generation via claimed predecessor digests."""

    by_digest = {cast(str, item.get("generation_digest")): item for item in generations}
    current: str | None = cast(str, generations[-1].get("generation_digest"))
    seen: set[str] = set()
    depth = 0
    while current is not None and current != _GENESIS_GENERATION_DIGEST:
        if current in seen:
            errors.append("PHASE3_GENERATION_CHAIN_CYCLE")
            return
        seen.add(current)
        manifest = by_digest.get(current)
        if manifest is None:
            errors.append(f"PHASE3_GENERATION_MISSING: {current}")
            return
        depth += 1
        if depth > len(generations):
            errors.append("PHASE3_GENERATION_CHAIN_CYCLE")
            return
        current = cast(str | None, manifest.get("previous_generation_digest"))
    if current != _GENESIS_GENERATION_DIGEST:
        errors.append("PHASE3_GENERATION_CHAIN_NOT_GENESIS_LINKED")


def _validate_current_pointer(
    corpus: dict[str, Any],
    generations: list[dict[str, Any]],
    errors: list[str],
) -> None:
    pointer = corpus.get("current_pointer")
    if type(pointer) is not dict:
        errors.append("PHASE3_POINTER_MISSING")
        return
    if pointer.get("schema_version") != CURRENT_POINTER_SCHEMA_VERSION:
        errors.append("PHASE3_POINTER_SCHEMA_INVALID")
        return
    if not generations:
        return
    last = generations[-1]
    if pointer.get("clock_sequence") != last.get("clock_sequence"):
        errors.append("PHASE3_POINTER_SEQUENCE_MISMATCH")
    if pointer.get("generation_digest") != last.get("generation_digest"):
        errors.append("PHASE3_POINTER_GENERATION_MISMATCH")
    if pointer.get("clock_completion_digest") != last.get("clock_completion_digest"):
        errors.append("PHASE3_POINTER_COMPLETION_MISMATCH")


def _validate_active_marker(
    corpus: dict[str, Any],
    generations: list[dict[str, Any]],
    errors: list[str],
) -> None:
    marker = corpus.get("active_marker")
    if marker is None:
        return
    if type(marker) is not dict:
        errors.append("PHASE3_ACTIVE_MARKER_INVALID")
        return
    if marker.get("schema_version") != ACTIVE_MARKER_SCHEMA_VERSION:
        errors.append("PHASE3_ACTIVE_MARKER_SCHEMA_INVALID")
        return
    generation_digest = marker.get("generation_digest")
    target = next(
        (item for item in generations if item.get("generation_digest") == generation_digest), None
    )
    if target is None:
        errors.append("PHASE3_ACTIVE_UNKNOWN_GENERATION")
        return
    if marker.get("clock_claim_digest") != target.get("clock_claim_digest"):
        errors.append("PHASE3_ACTIVE_CLAIM_MISMATCH")


# --------------------------------------------------------------------------- #
# Event-chain reconstruction
# --------------------------------------------------------------------------- #


def _typed_heads(manifest: dict[str, Any], registry: str) -> list[dict[str, Any]] | None:
    raw = manifest.get(f"{registry}_heads")
    if type(raw) is not list:
        return None
    heads = cast(list[dict[str, Any]], raw)
    if any(type(item) is not dict for item in heads):
        return None
    return heads


def _validate_event_chains(
    generations: list[dict[str, Any]],
    events: dict[str, Any],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        for registry, registry_type in _REGISTRIES.items():
            heads = _typed_heads(manifest, registry)
            if heads is None:
                errors.append(f"PHASE3_HEAD_SET_INVALID: generation {index} {registry}")
                continue
            entity_ids = [item.get("entity_id") for item in heads]
            if (
                any(type(item) is not str for item in entity_ids)
                or entity_ids != sorted(cast(list[str], entity_ids))
                or len(set(cast(list[str], entity_ids))) != len(entity_ids)
                or any(
                    set(item) != {"entity_id", "entity_sequence", "event_digest"}
                    or type(item.get("entity_sequence")) is not int
                    or not _is_digest(item.get("event_digest"))
                    for item in heads
                )
            ):
                errors.append(f"PHASE3_HEAD_SET_INVALID: generation {index} {registry}")
                continue
            typed = [
                RegistryEntityHead(
                    registry_type,
                    cast(str, item["entity_id"]),
                    cast(int, item["entity_sequence"]),
                    cast(str, item["event_digest"]),
                )
                for item in heads
            ]
            projected_root = manifest.get(f"{registry}_projected_root")
            if _snapshot_root(registry_type, tuple(typed)) != projected_root:
                errors.append(f"PHASE3_ROOT_RECONSTRUCTION_MISMATCH: generation {index} {registry}")
            for head in typed:
                _walk_entity_chain(events, registry_type, head, index, registry, errors)
            # Cross-generation root continuity + predecessor-root binding.
            predecessor_root = manifest.get(f"{registry}_predecessor_root")
            if index == 0:
                if predecessor_root != _EMPTY_ROOTS[registry]:
                    errors.append(f"PHASE3_GENERATION_PREDECESSOR_ROOT_NOT_EMPTY: {registry}")
            elif predecessor_root != generations[index - 1].get(f"{registry}_projected_root"):
                errors.append(
                    f"PHASE3_GENERATION_ROOT_CONTINUITY_MISMATCH: generation {index} {registry}"
                )
        _validate_event_inventory(manifest, events, index, errors)


def _walk_entity_chain(
    events: dict[str, Any],
    registry_type: str,
    head: RegistryEntityHead,
    generation_index: int,
    registry: str,
    errors: list[str],
) -> None:
    label = f"generation {generation_index} {registry} {head.entity_id}"
    digest: str | None = head.event_digest
    expected_sequence = head.entity_sequence
    seen: set[str] = set()
    at_head = True
    while digest is not None:
        if digest in seen:
            errors.append(f"PHASE3_EVENT_CHAIN_CYCLE: {label}")
            return
        seen.add(digest)
        value = events.get(digest)
        if type(value) is not dict:
            if at_head:
                errors.append(f"PHASE3_EVENT_MISSING: {label} at sequence {expected_sequence}")
            else:
                errors.append(
                    f"PHASE3_EVENT_PREDECESSOR_MISSING: {label} at sequence {expected_sequence}"
                )
            return
        if not _verify_event_self_digest(value):
            errors.append(
                f"PHASE3_EVENT_SELF_DIGEST_MISMATCH: {label} at sequence {expected_sequence}"
            )
            return
        if value.get("registry_type") != registry_type:
            errors.append(f"PHASE3_EVENT_REGISTRY_TYPE_MISMATCH: {label}")
            return
        if value.get("entity_id") != head.entity_id:
            errors.append(f"PHASE3_EVENT_CHAIN_ENTITY_MISMATCH: {label}")
            return
        sequence = value.get("entity_sequence")
        if sequence != expected_sequence:
            errors.append(f"PHASE3_EVENT_CHAIN_SEQUENCE_MISMATCH: {label}")
            return
        previous = value.get("previous_entity_event_digest")
        if expected_sequence == 1:
            if previous is not None:
                errors.append(f"PHASE3_EVENT_CHAIN_NOT_GENESIS_LINKED: {label}")
            return
        if not _is_digest(previous):
            errors.append(
                f"PHASE3_EVENT_PREDECESSOR_MISSING: {label} at sequence {expected_sequence}"
            )
            return
        digest = cast(str, previous)
        expected_sequence -= 1
        at_head = False


def _verify_event_self_digest(value: dict[str, Any]) -> bool:
    try:
        event = parse_contract("registry-event", value)
    except GovernanceContractError:
        return False
    return event.digest == value.get("registry_event_digest")


def _validate_event_inventory(
    manifest: dict[str, Any],
    events: dict[str, Any],
    generation_index: int,
    errors: list[str],
) -> None:
    clock_sequence = manifest.get("clock_sequence")
    for registry, registry_type in _REGISTRIES.items():
        digests = _digest_list(manifest.get(f"{registry}_event_digests"))
        if digests is None:
            errors.append(
                f"PHASE3_EVENT_INVENTORY_INVALID: generation {generation_index} {registry}"
            )
            continue
        for digest in digests:
            value = events.get(digest)
            if type(value) is not dict:
                errors.append(
                    f"PHASE3_EVENT_MISSING: generation {generation_index} {registry} {digest}"
                )
                continue
            if value.get("registry_type") != registry_type:
                errors.append(
                    f"PHASE3_EVENT_REGISTRY_TYPE_MISMATCH: generation {generation_index} {registry}"
                )
            if value.get("clock_sequence") != clock_sequence:
                errors.append(
                    f"PHASE3_EVENT_CLOCK_BINDING_MISMATCH: generation {generation_index} {registry}"
                )


# --------------------------------------------------------------------------- #
# Projection plans
# --------------------------------------------------------------------------- #


def _validate_plans(
    generations: list[dict[str, Any]],
    projection_plans: dict[str, Any],
    comparison_receipts: dict[str, Any],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        for registry in _REGISTRIES:
            plan_digest = manifest.get(f"{registry}_plan_digest")
            plan = projection_plans.get(cast(str, plan_digest)) if plan_digest is not None else None
            if type(plan) is not dict:
                errors.append(f"PHASE3_PLAN_MISSING: generation {index} {registry}")
                continue
            unsigned = {key: item for key, item in plan.items() if key != "plan_digest"}
            recomputed = _domain_digest(_PLAN_DIGEST_DOMAINS[registry], unsigned)
            if recomputed != plan.get("plan_digest"):
                errors.append(f"PHASE3_PLAN_SELF_DIGEST_MISMATCH: generation {index} {registry}")
                continue
            if plan.get("clock_sequence") != manifest.get("clock_sequence"):
                errors.append(f"PHASE3_PLAN_CLOCK_BINDING_MISMATCH: generation {index} {registry}")
            if plan.get("clock_claim_digest") != manifest.get("clock_claim_digest"):
                errors.append(f"PHASE3_PLAN_CLAIM_BINDING_MISMATCH: generation {index} {registry}")
            if plan.get("validated_event_digest") != manifest.get("validated_event_digest"):
                errors.append(f"PHASE3_PLAN_EVENT_BINDING_MISMATCH: generation {index} {registry}")
            if plan.get("semantic_receipt_digest") != manifest.get(
                "semantic_projection_receipt_digest"
            ):
                errors.append(
                    f"PHASE3_PLAN_SEMANTIC_BINDING_MISMATCH: generation {index} {registry}"
                )
            if plan.get("predecessor_root_digest") != manifest.get(f"{registry}_predecessor_root"):
                errors.append(
                    f"PHASE3_PLAN_PREDECESSOR_BINDING_MISMATCH: generation {index} {registry}"
                )
            if plan.get("projected_root_digest") != manifest.get(f"{registry}_projected_root"):
                errors.append(f"PHASE3_PLAN_ROOT_BINDING_MISMATCH: generation {index} {registry}")
            plan_events = _digest_list(plan.get("event_digests"))
            manifest_events = _digest_list(manifest.get(f"{registry}_event_digests"))
            if plan_events is None or plan_events != manifest_events:
                errors.append(
                    f"PHASE3_PLAN_EVENT_INVENTORY_MISMATCH: generation {index} {registry}"
                )
            if registry in {"assumption", "alt_model"} and plan.get(
                "evidence_root_digest"
            ) != manifest.get("evidence_projected_root"):
                errors.append(
                    f"PHASE3_PLAN_EVIDENCE_ROOT_BINDING_MISMATCH: generation {index} {registry}"
                )
            if registry == "alt_model":
                if plan.get("assumption_root_digest") != manifest.get("assumption_projected_root"):
                    errors.append(
                        "PHASE3_PLAN_ASSUMPTION_ROOT_BINDING_MISMATCH: "
                        f"generation {index} {registry}"
                    )
                bindings = plan.get("admit_comparison_bindings")
                if type(bindings) is list:
                    for pair in bindings:
                        if type(pair) is not list or len(pair) != 2:
                            errors.append(
                                f"PHASE3_D4_COMPARISON_BINDING_INVALID: generation {index}"
                            )
                            continue
                        if not _is_digest(pair[1]):
                            errors.append(
                                f"PHASE3_D4_COMPARISON_BINDING_INVALID: generation {index}"
                            )
                            continue
                        if type(comparison_receipts.get(pair[1])) is not dict:
                            errors.append(
                                f"PHASE3_D4_COMPARISON_BINDING_MISSING: generation {index}"
                            )
                else:
                    errors.append(f"PHASE3_D4_COMPARISON_BINDING_INVALID: generation {index}")


def _validate_cross_root_bindings(
    generations: list[dict[str, Any]],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        if manifest.get("assumption_evidence_root_binding") != manifest.get(
            "evidence_projected_root"
        ):
            errors.append(f"PHASE3_CROSS_ROOT_BINDING_MISMATCH: generation {index} assumption")
        if manifest.get("alt_model_evidence_root_binding") != manifest.get(
            "evidence_projected_root"
        ):
            errors.append(f"PHASE3_CROSS_ROOT_BINDING_MISMATCH: generation {index} alt_model")
        if manifest.get("alt_model_assumption_root_binding") != manifest.get(
            "assumption_projected_root"
        ):
            errors.append(f"PHASE3_CROSS_ROOT_BINDING_MISMATCH: generation {index} alt_model")


# --------------------------------------------------------------------------- #
# Semantic / disposition / completion receipts
# --------------------------------------------------------------------------- #


def _validate_semantic_receipts(
    generations: list[dict[str, Any]],
    semantic_receipts: dict[str, Any],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        digest = manifest.get("semantic_projection_receipt_digest")
        receipt = semantic_receipts.get(cast(str, digest)) if digest is not None else None
        if type(receipt) is not dict:
            errors.append(f"PHASE3_SEMANTIC_RECEIPT_MISSING: generation {index}")
            continue
        try:
            parsed = parse_contract("semantic-projection-receipt", receipt)
        except GovernanceContractError:
            errors.append(f"PHASE3_SEMANTIC_RECEIPT_DIGEST_INVALID: generation {index}")
            continue
        if parsed.digest != digest:
            errors.append(f"PHASE3_SEMANTIC_RECEIPT_DIGEST_INVALID: generation {index}")
            continue
        if receipt.get("clock_claim_digest") != manifest.get("clock_claim_digest"):
            errors.append(f"PHASE3_SEMANTIC_CLAIM_BINDING_MISMATCH: generation {index}")
        if receipt.get("validated_event_digest") != manifest.get("validated_event_digest"):
            errors.append(f"PHASE3_SEMANTIC_EVENT_BINDING_MISMATCH: generation {index}")


def _validate_disposition_receipts(
    generations: list[dict[str, Any]],
    disposition_receipts: dict[str, Any],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        digest = manifest.get("disposition_receipt_digest")
        receipt = disposition_receipts.get(cast(str, digest)) if digest is not None else None
        if type(receipt) is not dict:
            errors.append(f"PHASE3_DISPOSITION_RECEIPT_MISSING: generation {index}")
            continue
        try:
            parsed = parse_contract("disposition-receipt", receipt)
        except GovernanceContractError:
            errors.append(f"PHASE3_DISPOSITION_RECEIPT_DIGEST_INVALID: generation {index}")
            continue
        if parsed.digest != digest:
            errors.append(f"PHASE3_DISPOSITION_RECEIPT_DIGEST_INVALID: generation {index}")
            continue
        if receipt.get("semantic_projection_receipt_digest") != manifest.get(
            "semantic_projection_receipt_digest"
        ):
            errors.append(f"PHASE3_DISPOSITION_SEMANTIC_BINDING_MISMATCH: generation {index}")
        if receipt.get("clock_sequence") != manifest.get("clock_sequence"):
            errors.append(f"PHASE3_DISPOSITION_CLOCK_BINDING_MISMATCH: generation {index}")
        roots = receipt.get("registry_root_digests")
        if type(roots) is not dict:
            errors.append(f"PHASE3_DISPOSITION_ROOT_BINDING_MISMATCH: generation {index}")
            continue
        expected = {
            "evidence_unit": manifest.get("evidence_projected_root"),
            "assumption": manifest.get("assumption_projected_root"),
            "alternative_model": manifest.get("alt_model_projected_root"),
        }
        if dict(roots) != expected:
            errors.append(f"PHASE3_DISPOSITION_ROOT_BINDING_MISMATCH: generation {index}")


def _validate_completions(
    generations: list[dict[str, Any]],
    completions: dict[str, Any],
    errors: list[str],
) -> None:
    for index, manifest in enumerate(generations):
        digest = manifest.get("clock_completion_digest")
        completion = completions.get(cast(str, digest)) if digest is not None else None
        if type(completion) is not dict:
            errors.append(f"PHASE3_COMPLETION_MISSING: generation {index}")
            continue
        try:
            parsed = parse_contract("clock-completion-receipt", completion)
        except GovernanceContractError:
            errors.append(f"PHASE3_COMPLETION_SELF_DIGEST_INVALID: generation {index}")
            continue
        if parsed.digest != digest:
            errors.append(f"PHASE3_COMPLETION_SELF_DIGEST_INVALID: generation {index}")
            continue
        if completion.get("clock_sequence") != manifest.get("clock_sequence"):
            errors.append(f"PHASE3_COMPLETION_SEQUENCE_MISMATCH: generation {index}")
        if completion.get("clock_claim_digest") != manifest.get("clock_claim_digest"):
            errors.append(f"PHASE3_COMPLETION_CLAIM_BINDING_MISMATCH: generation {index}")
        if completion.get("validated_event_digest") != manifest.get("validated_event_digest"):
            errors.append(f"PHASE3_COMPLETION_EVENT_BINDING_MISMATCH: generation {index}")
        if completion.get("semantic_projection_receipt_digest") != manifest.get(
            "semantic_projection_receipt_digest"
        ):
            errors.append(f"PHASE3_COMPLETION_SEMANTIC_BINDING_MISMATCH: generation {index}")
        roots = completion.get("registry_root_digests")
        if type(roots) is not dict:
            errors.append(f"PHASE3_COMPLETION_ROOT_BINDING_MISMATCH: generation {index}")
        else:
            expected = {
                "evidence_unit": manifest.get("evidence_projected_root"),
                "assumption": manifest.get("assumption_projected_root"),
                "alternative_model": manifest.get("alt_model_projected_root"),
            }
            if dict(roots) != expected:
                errors.append(f"PHASE3_COMPLETION_ROOT_BINDING_MISMATCH: generation {index}")
        if completion.get("quarantine_epoch") != manifest.get("quarantine_epoch") or completion.get(
            "quarantine_marker_digests"
        ) != manifest.get("quarantine_marker_digests"):
            errors.append(f"PHASE3_QUARANTINE_BINDING_MISMATCH: generation {index}")
        expected_previous: str | None
        if index == 0:
            expected_previous = None
        else:
            expected_previous = cast(str, generations[index - 1].get("clock_completion_digest"))
        if completion.get("previous_completion_digest") != expected_previous:
            errors.append(f"PHASE3_COMPLETION_PREDECESSOR_MISMATCH: generation {index}")


# --------------------------------------------------------------------------- #
# D4 comparison receipts (FULL_REPLAY proof references)
# --------------------------------------------------------------------------- #


def _validate_comparison_receipts(
    comparison_receipts: dict[str, Any],
    errors: list[str],
) -> None:
    for digest, receipt in sorted(comparison_receipts.items()):
        if type(receipt) is not dict:
            errors.append(f"PHASE3_D4_COMPARISON_RECEIPT_INVALID: {digest}")
            continue
        unsigned = {key: value for key, value in receipt.items() if key != "comparison_digest"}
        recomputed = _flat_domain_digest(_COMPARISON_RECEIPT_DOMAIN, unsigned)
        if (
            recomputed != receipt.get("comparison_digest")
            or receipt.get("comparison_digest") != digest
        ):
            errors.append(f"PHASE3_D4_COMPARISON_DIGEST_MISMATCH: {digest}")
        primary = receipt.get("primary_replay_receipt")
        shadow = receipt.get("shadow_replay_receipt")
        structural = receipt.get("structural_difference_receipt")
        if type(primary) is not dict or type(shadow) is not dict or type(structural) is not dict:
            errors.append(f"PHASE3_D4_COMPARISON_RECEIPT_INVALID: {digest}")
            continue
        for label, replay in (("primary", primary), ("shadow", shadow)):
            replay_unsigned = {
                key: value for key, value in replay.items() if key != "receipt_digest"
            }
            replay_digest = _flat_domain_digest(_REPLAY_RECEIPT_DOMAIN, replay_unsigned)
            if replay_digest != replay.get("receipt_digest"):
                errors.append(f"PHASE3_D4_REPLAY_DIGEST_MISMATCH: {digest} {label}")
        for field, code in (
            ("decision_context_digest", "PHASE3_D4_REPLAY_CONTEXT_MISMATCH"),
            ("initial_state_digest", "PHASE3_D4_REPLAY_STATE_MISMATCH"),
            ("logical_clock", "PHASE3_D4_REPLAY_CLOCK_MISMATCH"),
            ("runner_revision", "PHASE3_D4_REPLAY_RUNNER_MISMATCH"),
            ("required_inventory", "PHASE3_D4_REPLAY_REQUIRED_INVENTORY_MISMATCH"),
        ):
            if primary.get(field) != shadow.get(field):
                errors.append(f"{code}: {digest}")
        for label, replay in (("primary", primary), ("shadow", shadow)):
            required = replay.get("required_inventory")
            executed = replay.get("executed_inventory")
            skipped = replay.get("skipped_inventory")
            pruned = replay.get("pruned_inventory")
            if type(required) is not list or executed != required or skipped != [] or pruned != []:
                errors.append(f"PHASE3_D4_REPLAY_INVENTORY_MISMATCH: {digest} {label}")
        if primary.get("graph_digest") != structural.get("primary_graph_digest"):
            errors.append(f"PHASE3_D4_COMPARISON_GRAPH_BINDING_MISMATCH: {digest} primary")
        if shadow.get("graph_digest") != structural.get("shadow_graph_digest"):
            errors.append(f"PHASE3_D4_COMPARISON_GRAPH_BINDING_MISMATCH: {digest} shadow")
        primary_outcome = primary.get("semantic_outcome_digest")
        shadow_outcome = shadow.get("semantic_outcome_digest")
        expected_result = "INVARIANT" if primary_outcome == shadow_outcome else "DIVERGENT"
        if receipt.get("comparison_result") != expected_result:
            errors.append(f"PHASE3_D4_COMPARISON_RESULT_MISMATCH: {digest}")


__all__ = [
    "CORPUS_SCHEMA_VERSION",
    "Phase3GenerationSummary",
    "Phase3ValidationError",
    "Phase3ValidationReport",
    "compute_generation_digest",
    "validate_phase3_generations",
]
