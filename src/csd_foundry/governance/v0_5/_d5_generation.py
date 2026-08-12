"""D5 atomic multi-registry temporal integration layer (P3.6).

Connects the three mature staged projection adapters (evidence P3.1, assumption
P3.2, alternative-model P3.5) into one atomic generation publication. The
generation manifest is INTERNAL (no public v0.5 schema). Disposition and
quarantine are typed reference adapters only — no substantive adjudication, no
new execution semantics, no VCE, no release compiler.

Atomicity model
---------------

* ``prepare_generation`` runs all three adapters in frozen phase order against
  the committed stores (read-only), cross-binds evidence -> assumption ->
  alternative-model roots, and produces a self-digesting
  :class:`D5GenerationManifest`. It does NOT mutate committed registry state.
* ``commit_generation`` is THE COMMIT POINT. It appends the planned events to
  the three committed registry stores (idempotent forward-recovery appends),
  verifies the resulting heads match the manifest, then atomically replaces the
  single current-generation pointer via ``os.replace``.
* Before the pointer replacement: all candidate artifacts are unreachable as
  current state. After: all three roots + completion become current together.
* No reader ever observes a mixed generation: readers consult the generation
  pointer, which is replaced atomically.

Recovery protocol
-----------------

* active claim + no finalized generation -> fail attempt; current unchanged.
* active claim + valid finalized generation -> verify; publish atomically.
* current pointer already cites exact finalized generation -> idempotent success.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from csd_foundry._platform import advisory_lock, fsync_directory
from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelProjectionPlan,
    StagedAlternativeModelProjectionAdapter,
)
from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionProjectionPlan,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5.contracts import (
    ClockClaim,
    ClockCompletionReceipt,
    DispositionReceipt,
    RegistryEvent,
    SemanticProjectionReceipt,
    ValidatedEvent,
)
from csd_foundry.governance.v0_5.evidence_projection import (
    EvidenceProjectionPlan,
    StagedEvidenceProjectionAdapter,
)
from csd_foundry.governance.v0_5.registry import (
    FilesystemRegistryStore,
    RegistryAppendResult,
    RegistryEntityHead,
    RegistrySnapshot,
    RegistryStoreError,
    _snapshot_root,
)

MANIFEST_SCHEMA_VERSION = "d5-generation-manifest/1"
CURRENT_POINTER_SCHEMA_VERSION = "current-d5-generation/1"
ACTIVE_MARKER_SCHEMA_VERSION = "active-d5-generation/1"
PREPARED_BUNDLE_SCHEMA_VERSION = "prepared-d5-generation/1"

_GENESIS_GENERATION_DIGEST = "sha256:" + hashlib.sha256(b"D5_GENERATION_GENESIS").hexdigest()
_DISPOSITION_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(b"D5_REFERENCE_DISPOSITION_POLICY").hexdigest()
)
_DEFAULT_COMPLETION_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(b"D5_COMPLETION_POLICY_V1").hexdigest()
)

_EMPTY_EVIDENCE_ROOT = _snapshot_root("EVIDENCE_UNIT", ())
_EMPTY_ASSUMPTION_ROOT = _snapshot_root("ASSUMPTION", ())
_EMPTY_ALT_MODEL_ROOT = _snapshot_root("ALTERNATIVE_MODEL", ())

_REFERENCE_FOLLOW_UP = (
    "Reference disposition: no substantive adjudication is performed by the D5 "
    "integration layer. Survival, escalation, and blocking decisions remain the "
    "responsibility of downstream semantic consumers."
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class D5GenerationError(RuntimeError):
    """Stable fail-closed error for the D5 atomic integration layer."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


class D5GenerationConflictError(D5GenerationError):
    """Raised when immutable bytes or a compare-and-append precondition conflict."""


# --------------------------------------------------------------------------- #
# D5GenerationManifest
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class D5GenerationManifest:
    """Self-digesting, INTERNAL manifest of one atomic D5 generation.

    Captures every digest needed to verify and reconstruct the generation: the
    temporal context (claim/event/semantic/completion), the three registry
    projection plans (by digest), the cross-phase root bindings, the canonical
    head sets, and the reference disposition/quarantine artifacts. The
    ``generation_digest`` is the self-digest over every other field.
    """

    previous_generation_digest: str
    clock_sequence: int
    clock_claim_digest: str
    validated_event_digest: str
    semantic_projection_receipt_digest: str
    # Evidence
    evidence_predecessor_root: str
    evidence_plan_digest: str
    evidence_event_digests: tuple[str, ...]
    evidence_projected_root: str
    evidence_heads: tuple[dict[str, object], ...]
    # Assumption
    assumption_predecessor_root: str
    assumption_evidence_root_binding: str
    assumption_plan_digest: str
    assumption_event_digests: tuple[str, ...]
    assumption_projected_root: str
    assumption_heads: tuple[dict[str, object], ...]
    # Alternative model
    alt_model_predecessor_root: str
    alt_model_evidence_root_binding: str
    alt_model_assumption_root_binding: str
    alt_model_plan_digest: str
    alt_model_event_digests: tuple[str, ...]
    alt_model_projected_root: str
    alt_model_heads: tuple[dict[str, object], ...]
    # Disposition + quarantine references
    disposition_receipt_digest: str
    quarantine_epoch: int
    quarantine_marker_digests: tuple[str, ...]
    # Completion
    clock_completion_digest: str
    # Self-digest
    generation_digest: str

    def __post_init__(self) -> None:
        for digest_field in (
            self.previous_generation_digest,
            self.clock_claim_digest,
            self.validated_event_digest,
            self.semantic_projection_receipt_digest,
            self.evidence_predecessor_root,
            self.evidence_plan_digest,
            self.evidence_projected_root,
            self.assumption_predecessor_root,
            self.assumption_evidence_root_binding,
            self.assumption_plan_digest,
            self.assumption_projected_root,
            self.alt_model_predecessor_root,
            self.alt_model_evidence_root_binding,
            self.alt_model_assumption_root_binding,
            self.alt_model_plan_digest,
            self.alt_model_projected_root,
            self.disposition_receipt_digest,
            self.clock_completion_digest,
            self.generation_digest,
        ):
            _require_digest(digest_field, "D5_GENERATION_DIGEST_FIELD_INVALID")
        if type(self.clock_sequence) is not int or self.clock_sequence < 1:
            raise D5GenerationError("D5_GENERATION_CLOCK_SEQUENCE_INVALID")
        if type(self.quarantine_epoch) is not int or self.quarantine_epoch < 0:
            raise D5GenerationError("D5_GENERATION_QUARANTINE_EPOCH_INVALID")
        _require_digest_tuple(self.evidence_event_digests, "D5_GENERATION_EVIDENCE_EVENTS")
        _require_digest_tuple(self.assumption_event_digests, "D5_GENERATION_ASSUMPTION_EVENTS")
        _require_digest_tuple(self.alt_model_event_digests, "D5_GENERATION_ALT_MODEL_EVENTS")
        _require_digest_tuple(self.quarantine_marker_digests, "D5_GENERATION_QUARANTINE_MARKERS")
        _require_head_set(self.evidence_heads, "D5_GENERATION_EVIDENCE_HEADS")
        _require_head_set(self.assumption_heads, "D5_GENERATION_ASSUMPTION_HEADS")
        _require_head_set(self.alt_model_heads, "D5_GENERATION_ALT_MODEL_HEADS")
        if self.generation_digest != _compute_generation_digest(self._unsigned_value()):
            raise D5GenerationError("D5_GENERATION_DIGEST_MISMATCH")

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "previous_generation_digest": self.previous_generation_digest,
            "clock_sequence": self.clock_sequence,
            "clock_claim_digest": self.clock_claim_digest,
            "validated_event_digest": self.validated_event_digest,
            "semantic_projection_receipt_digest": self.semantic_projection_receipt_digest,
            "evidence_predecessor_root": self.evidence_predecessor_root,
            "evidence_plan_digest": self.evidence_plan_digest,
            "evidence_event_digests": list(self.evidence_event_digests),
            "evidence_projected_root": self.evidence_projected_root,
            "evidence_heads": [dict(item) for item in self.evidence_heads],
            "assumption_predecessor_root": self.assumption_predecessor_root,
            "assumption_evidence_root_binding": self.assumption_evidence_root_binding,
            "assumption_plan_digest": self.assumption_plan_digest,
            "assumption_event_digests": list(self.assumption_event_digests),
            "assumption_projected_root": self.assumption_projected_root,
            "assumption_heads": [dict(item) for item in self.assumption_heads],
            "alt_model_predecessor_root": self.alt_model_predecessor_root,
            "alt_model_evidence_root_binding": self.alt_model_evidence_root_binding,
            "alt_model_assumption_root_binding": self.alt_model_assumption_root_binding,
            "alt_model_plan_digest": self.alt_model_plan_digest,
            "alt_model_event_digests": list(self.alt_model_event_digests),
            "alt_model_projected_root": self.alt_model_projected_root,
            "alt_model_heads": [dict(item) for item in self.alt_model_heads],
            "disposition_receipt_digest": self.disposition_receipt_digest,
            "quarantine_epoch": self.quarantine_epoch,
            "quarantine_marker_digests": list(self.quarantine_marker_digests),
            "clock_completion_digest": self.clock_completion_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        value = self._unsigned_value()
        value["generation_digest"] = self.generation_digest
        return value

    def head_entities(self, registry: str) -> tuple[RegistryEntityHead, ...]:
        """Return the canonical head set for one registry as typed heads."""

        source = _registry_heads(self, registry)
        registry_type = _REGISTRY_TYPES[registry]
        return tuple(
            RegistryEntityHead(
                registry_type,
                cast(str, item["entity_id"]),
                cast(int, item["entity_sequence"]),
                cast(str, item["event_digest"]),
            )
            for item in source
        )

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> D5GenerationManifest:
        if type(value) is not dict:
            raise D5GenerationConflictError("D5_GENERATION_MANIFEST_NOT_OBJECT")
        if value.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            raise D5GenerationConflictError("D5_GENERATION_MANIFEST_VERSION_INVALID")
        return cls(
            previous_generation_digest=cast(str, value["previous_generation_digest"]),
            clock_sequence=cast(int, value["clock_sequence"]),
            clock_claim_digest=cast(str, value["clock_claim_digest"]),
            validated_event_digest=cast(str, value["validated_event_digest"]),
            semantic_projection_receipt_digest=cast(
                str, value["semantic_projection_receipt_digest"]
            ),
            evidence_predecessor_root=cast(str, value["evidence_predecessor_root"]),
            evidence_plan_digest=cast(str, value["evidence_plan_digest"]),
            evidence_event_digests=tuple(cast(list[str], value["evidence_event_digests"])),
            evidence_projected_root=cast(str, value["evidence_projected_root"]),
            evidence_heads=tuple(
                item for item in cast(list[dict[str, object]], value["evidence_heads"])
            ),
            assumption_predecessor_root=cast(str, value["assumption_predecessor_root"]),
            assumption_evidence_root_binding=cast(str, value["assumption_evidence_root_binding"]),
            assumption_plan_digest=cast(str, value["assumption_plan_digest"]),
            assumption_event_digests=tuple(cast(list[str], value["assumption_event_digests"])),
            assumption_projected_root=cast(str, value["assumption_projected_root"]),
            assumption_heads=tuple(
                item for item in cast(list[dict[str, object]], value["assumption_heads"])
            ),
            alt_model_predecessor_root=cast(str, value["alt_model_predecessor_root"]),
            alt_model_evidence_root_binding=cast(str, value["alt_model_evidence_root_binding"]),
            alt_model_assumption_root_binding=cast(str, value["alt_model_assumption_root_binding"]),
            alt_model_plan_digest=cast(str, value["alt_model_plan_digest"]),
            alt_model_event_digests=tuple(cast(list[str], value["alt_model_event_digests"])),
            alt_model_projected_root=cast(str, value["alt_model_projected_root"]),
            alt_model_heads=tuple(
                item for item in cast(list[dict[str, object]], value["alt_model_heads"])
            ),
            disposition_receipt_digest=cast(str, value["disposition_receipt_digest"]),
            quarantine_epoch=cast(int, value["quarantine_epoch"]),
            quarantine_marker_digests=tuple(cast(list[str], value["quarantine_marker_digests"])),
            clock_completion_digest=cast(str, value["clock_completion_digest"]),
            generation_digest=cast(str, value["generation_digest"]),
        )


# --------------------------------------------------------------------------- #
# Reference adapters (disposition + quarantine)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ReferenceQuarantineProjection:
    """Deterministic reference quarantine projection (epoch=0, empty markers)."""

    epoch: int
    marker_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.epoch != 0:
            raise D5GenerationError("D5_REFERENCE_QUARANTINE_EPOCH_INVALID")
        if self.marker_digests != ():
            raise D5GenerationError("D5_REFERENCE_QUARANTINE_MARKERS_INVALID")


class ReferenceDispositionAdapter:
    """Produces a deterministic DispositionReceipt citing the semantic receipt.

    Plumbing only. No substantive adjudication is performed. The receipt cites
    the three candidate roots and records ``DOCUMENT_AND_PROCEED`` with
    ``UNASSESSED`` assurance, reflecting that the D5 layer makes no survival,
    escalation, or blocking decisions.
    """

    def __init__(self, *, disposition_policy_digest: str = _DISPOSITION_POLICY_DIGEST) -> None:
        self.disposition_policy_digest = _require_digest(
            disposition_policy_digest, "D5_DISPOSITION_POLICY_INVALID"
        )

    def project(
        self,
        *,
        semantic_receipt: SemanticProjectionReceipt,
        clock_sequence: int,
        evidence_root: str,
        assumption_root: str,
        alt_model_root: str,
    ) -> DispositionReceipt:
        if type(clock_sequence) is not int or clock_sequence < 1:
            raise D5GenerationError("D5_DISPOSITION_CLOCK_INVALID")
        for digest in (evidence_root, assumption_root, alt_model_root):
            _require_digest(digest, "D5_DISPOSITION_ROOT_INVALID")
        return cast(
            DispositionReceipt,
            DispositionReceipt.build(
                {
                    "schema_version": "disposition-receipt/1",
                    "semantic_projection_receipt_digest": semantic_receipt.digest,
                    "clock_sequence": clock_sequence,
                    "decision_id": f"decision:reference-d5-{clock_sequence}",
                    "decision_class": "D0",
                    "registry_root_digests": {
                        "evidence_unit": evidence_root,
                        "assumption": assumption_root,
                        "alternative_model": alt_model_root,
                    },
                    "assurance_status": "UNASSESSED",
                    "model_envelope_classification": "NOT_APPLICABLE",
                    "disposition_action": "DOCUMENT_AND_PROCEED",
                    "required_follow_up": _REFERENCE_FOLLOW_UP,
                    "disposition_policy_digest": self.disposition_policy_digest,
                }
            ),
        )


class ReferenceQuarantineAdapter:
    """Produces a deterministic quarantine projection (epoch=0, empty markers).

    Plumbing only. No substantive quarantine semantics. The projection
    establishes that no quarantine markers are raised and the epoch is zero.
    """

    def project(self) -> ReferenceQuarantineProjection:
        return ReferenceQuarantineProjection(epoch=0, marker_digests=())


# --------------------------------------------------------------------------- #
# Generation registry view (read-only)
# --------------------------------------------------------------------------- #


class GenerationRegistryView:
    """Read-only RegistryStore view bound to one generation's head set.

    ``append()`` fails closed. Reads reconstruct entity histories starting from
    the generation's head set (not the live registry heads), so historical
    generations remain reconstructable after newer generations advance the live
    heads. Events are read from the underlying immutable registry store.
    """

    def __init__(
        self,
        *,
        store: FilesystemRegistryStore,
        registry_type: str,
        heads: tuple[RegistryEntityHead, ...],
    ) -> None:
        _require_registry_type(registry_type)
        if type(heads) is not tuple:
            raise D5GenerationError("D5_VIEW_HEADS_INVALID")
        self._store = store
        self._registry_type = registry_type
        self._heads = {head.entity_id: head for head in heads}

    def append(self, event: RegistryEvent) -> RegistryAppendResult:
        raise RegistryStoreError("D5_GENERATION_VIEW_APPEND_FORBIDDEN")

    def get_event(self, digest: str) -> RegistryEvent | None:
        return self._store.get_event(digest)

    def entity_head(self, registry_type: str, entity_id: str) -> RegistryEntityHead | None:
        _require_registry_type(registry_type)
        if registry_type != self._registry_type:
            raise RegistryStoreError("D5_VIEW_REGISTRY_TYPE_MISMATCH")
        return self._heads.get(entity_id)

    def snapshot(self, registry_type: str) -> RegistrySnapshot:
        _require_registry_type(registry_type)
        if registry_type != self._registry_type:
            raise RegistryStoreError("D5_VIEW_REGISTRY_TYPE_MISMATCH")
        heads = tuple(sorted(self._heads.values(), key=lambda item: item.entity_id))
        return RegistrySnapshot(registry_type, heads, _snapshot_root(registry_type, heads))

    def reconstruct_entity(self, registry_type: str, entity_id: str) -> tuple[RegistryEvent, ...]:
        _require_registry_type(registry_type)
        if registry_type != self._registry_type:
            raise RegistryStoreError("D5_VIEW_REGISTRY_TYPE_MISMATCH")
        head = self._heads.get(entity_id)
        if head is None:
            return ()
        return self._walk_chain(head)

    def reconstruct_snapshot(self, registry_type: str) -> tuple[tuple[RegistryEvent, ...], ...]:
        _require_registry_type(registry_type)
        if registry_type != self._registry_type:
            raise RegistryStoreError("D5_VIEW_REGISTRY_TYPE_MISMATCH")
        return tuple(
            self._walk_chain(head)
            for head in sorted(self._heads.values(), key=lambda item: item.entity_id)
        )

    def _walk_chain(self, head: RegistryEntityHead) -> tuple[RegistryEvent, ...]:
        result: list[RegistryEvent] = []
        digest: str | None = head.event_digest
        expected_sequence = head.entity_sequence
        seen: set[str] = set()
        while digest is not None:
            if digest in seen:
                raise D5GenerationConflictError("D5_VIEW_EVENT_CYCLE")
            seen.add(digest)
            event = self._store.get_event(digest)
            if event is None:
                raise D5GenerationConflictError("D5_VIEW_EVENT_MISSING")
            value = event.to_json_value()
            if (
                value["registry_type"] != self._registry_type
                or value["entity_id"] != head.entity_id
            ):
                raise D5GenerationConflictError("D5_VIEW_CHAIN_ENTITY_MISMATCH")
            if value["entity_sequence"] != expected_sequence:
                raise D5GenerationConflictError("D5_VIEW_CHAIN_SEQUENCE_MISMATCH")
            result.append(event)
            digest = cast(str | None, value["previous_entity_event_digest"])
            expected_sequence -= 1
        if expected_sequence != 0:
            raise D5GenerationConflictError("D5_VIEW_CHAIN_NOT_GENESIS_LINKED")
        return tuple(reversed(result))


# --------------------------------------------------------------------------- #
# D5GenerationStore
# --------------------------------------------------------------------------- #

_REGISTRY_TYPES = {
    "evidence": "EVIDENCE_UNIT",
    "assumption": "ASSUMPTION",
    "alt_model": "ALTERNATIVE_MODEL",
}


class D5GenerationStore:
    """Integrated atomic store coordinating three registry projection adapters.

    Wraps three :class:`FilesystemRegistryStore` instances (one per registry
    type) and a generations directory for manifests. The single
    current-generation pointer is the atomic commit point.
    """

    def __init__(
        self,
        *,
        evidence_store: FilesystemRegistryStore,
        assumption_store: FilesystemRegistryStore,
        alt_model_store: FilesystemRegistryStore,
        generations_dir: Path,
        completion_policy_digest: str = _DEFAULT_COMPLETION_POLICY_DIGEST,
        disposition_policy_digest: str = _DISPOSITION_POLICY_DIGEST,
    ) -> None:
        if not isinstance(generations_dir, Path):
            raise D5GenerationError("D5_GENERATIONS_DIR_NOT_PATH")
        for store in (evidence_store, assumption_store, alt_model_store):
            if not isinstance(store, FilesystemRegistryStore):
                raise D5GenerationError("D5_REGISTRY_STORE_TYPE_INVALID")
        self._evidence_store = evidence_store
        self._assumption_store = assumption_store
        self._alt_model_store = alt_model_store
        self.root = generations_dir
        self.objects = generations_dir / "objects"
        self.manifests = self.objects / "d5-generation-manifest"
        self.completions = self.objects / "clock-completion-receipt"
        self.state = generations_dir / "state"
        self.temporary = generations_dir / ".tmp"
        self.lock_path = self.state / "d5.lock"
        self.current_path = self.state / "current-generation.json"
        self.active_path = self.state / "active-generation.json"
        self.prepared_path = self.state / "prepared-generation.json"
        self.completion_policy_digest = _require_digest(
            completion_policy_digest, "D5_COMPLETION_POLICY_INVALID"
        )
        self._disposition_adapter = ReferenceDispositionAdapter(
            disposition_policy_digest=disposition_policy_digest
        )
        self._quarantine_adapter = ReferenceQuarantineAdapter()
        for directory in (
            generations_dir,
            self.objects,
            self.manifests,
            self.completions,
            self.state,
            self.temporary,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)

    # ------------------------------------------------------------------ #
    # Public API: prepare / commit
    # ------------------------------------------------------------------ #

    def prepare_generation(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        evidence_adapter: StagedEvidenceProjectionAdapter,
        assumption_adapter: StagedAssumptionProjectionAdapter,
        alt_model_adapter: StagedAlternativeModelProjectionAdapter,
    ) -> D5GenerationManifest:
        with self._lock():
            return self._prepare(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                evidence_adapter=evidence_adapter,
                assumption_adapter=assumption_adapter,
                alt_model_adapter=alt_model_adapter,
            )

    def commit_generation(self, manifest: D5GenerationManifest) -> None:
        with self._lock():
            self._commit(manifest)

    def recover(self) -> str:
        with self._lock():
            return self._recover()

    # ------------------------------------------------------------------ #
    # Public API: current generation queries
    # ------------------------------------------------------------------ #

    def current_generation(self) -> D5GenerationManifest | None:
        with self._lock():
            return self._read_current_manifest()

    def current_clock_sequence(self) -> int:
        with self._lock():
            pointer = self._read_current_pointer()
            return 0 if pointer is None else pointer[0]

    def current_generation_digest(self) -> str:
        with self._lock():
            pointer = self._read_current_pointer()
            return _GENESIS_GENERATION_DIGEST if pointer is None else pointer[1]

    def current_evidence_root(self) -> str:
        manifest = self.current_generation()
        if manifest is None:
            return _EMPTY_EVIDENCE_ROOT
        return manifest.evidence_projected_root

    def current_assumption_root(self) -> str:
        manifest = self.current_generation()
        if manifest is None:
            return _EMPTY_ASSUMPTION_ROOT
        return manifest.assumption_projected_root

    def current_alt_model_root(self) -> str:
        manifest = self.current_generation()
        if manifest is None:
            return _EMPTY_ALT_MODEL_ROOT
        return manifest.alt_model_projected_root

    def current_completion(self) -> ClockCompletionReceipt | None:
        with self._lock():
            pointer = self._read_current_pointer()
            if pointer is None:
                return None
            return self._read_completion(pointer[2])

    def reconstruct_generations(self) -> tuple[D5GenerationManifest, ...]:
        """Return the full generation chain from genesis to current."""
        with self._lock():
            chain: list[D5GenerationManifest] = []
            digest: str | None = None
            pointer = self._read_current_pointer()
            if pointer is None:
                return ()
            digest = pointer[1]
            expected = pointer[0]
            while digest is not None and digest != _GENESIS_GENERATION_DIGEST:
                manifest = self._read_manifest(digest)
                if manifest.clock_sequence != expected:
                    raise D5GenerationConflictError("D5_GENERATION_CHAIN_DISCONTINUOUS")
                chain.append(manifest)
                digest = manifest.previous_generation_digest
                expected -= 1
            if expected != 0:
                raise D5GenerationConflictError("D5_GENERATION_CHAIN_NOT_GENESIS_LINKED")
            return tuple(reversed(chain))

    # ------------------------------------------------------------------ #
    # Public API: generation views
    # ------------------------------------------------------------------ #

    def evidence_view(self) -> GenerationRegistryView:
        return self._view("evidence", self._evidence_store)

    def assumption_view(self) -> GenerationRegistryView:
        return self._view("assumption", self._assumption_store)

    def alt_model_view(self) -> GenerationRegistryView:
        return self._view("alt_model", self._alt_model_store)

    def _view(self, registry: str, store: FilesystemRegistryStore) -> GenerationRegistryView:
        manifest = self.current_generation()
        if manifest is None:
            heads: tuple[RegistryEntityHead, ...] = ()
        else:
            heads = manifest.head_entities(registry)
        return GenerationRegistryView(
            store=store,
            registry_type=_REGISTRY_TYPES[registry],
            heads=heads,
        )

    # ------------------------------------------------------------------ #
    # Internal: prepare
    # ------------------------------------------------------------------ #

    def _prepare(
        self,
        *,
        claim: ClockClaim,
        validated_event: ValidatedEvent,
        semantic_receipt: SemanticProjectionReceipt,
        evidence_adapter: StagedEvidenceProjectionAdapter,
        assumption_adapter: StagedAssumptionProjectionAdapter,
        alt_model_adapter: StagedAlternativeModelProjectionAdapter,
    ) -> D5GenerationManifest:
        claim_value = claim.to_json_value()
        proposed_sequence = cast(int, claim_value["proposed_sequence"])
        previous_sequence = cast(int, claim_value["previous_committed_sequence"])

        pointer = self._read_current_pointer()
        current_sequence = 0 if pointer is None else pointer[0]
        if previous_sequence != current_sequence or proposed_sequence != current_sequence + 1:
            raise D5GenerationConflictError("D5_CLAIM_NOT_SUCCESSOR_OF_CURRENT")

        active = self._read_active_marker()
        if active is not None and active[0] != claim.digest:
            raise D5GenerationConflictError("D5_ACTIVE_GENERATION_CONFLICT")

        previous_generation_digest = _GENESIS_GENERATION_DIGEST if pointer is None else pointer[1]

        evidence_predecessor = self._evidence_store.snapshot("EVIDENCE_UNIT").root_digest
        assumption_predecessor = self._assumption_store.snapshot("ASSUMPTION").root_digest
        alt_model_predecessor = self._alt_model_store.snapshot("ALTERNATIVE_MODEL").root_digest

        if pointer is not None:
            prior_manifest = self._read_manifest(pointer[1])
            if (
                prior_manifest.evidence_projected_root != evidence_predecessor
                or prior_manifest.assumption_projected_root != assumption_predecessor
                or prior_manifest.alt_model_projected_root != alt_model_predecessor
            ):
                raise D5GenerationConflictError("D5_COMMITTED_STORES_DIVERGED_FROM_GENERATION")

        evidence_plan = evidence_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=self._evidence_store,
        )
        assumption_plan = assumption_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=self._assumption_store,
            evidence_root_digest=evidence_plan.projected_root_digest,
        )
        alt_model_plan = alt_model_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=self._alt_model_store,
            evidence_root_digest=evidence_plan.projected_root_digest,
            assumption_root_digest=assumption_plan.projected_root_digest,
        )

        _validate_cross_phase_bindings(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            evidence_plan=evidence_plan,
            assumption_plan=assumption_plan,
            alt_model_plan=alt_model_plan,
            evidence_predecessor=evidence_predecessor,
            assumption_predecessor=assumption_predecessor,
            alt_model_predecessor=alt_model_predecessor,
        )

        evidence_heads = _projected_heads(
            self._evidence_store.snapshot("EVIDENCE_UNIT").heads,
            evidence_plan.events,
            "EVIDENCE_UNIT",
        )
        assumption_heads = _projected_heads(
            self._assumption_store.snapshot("ASSUMPTION").heads,
            assumption_plan.events,
            "ASSUMPTION",
        )
        alt_model_heads = _projected_heads(
            self._alt_model_store.snapshot("ALTERNATIVE_MODEL").heads,
            alt_model_plan.events,
            "ALTERNATIVE_MODEL",
        )

        if _snapshot_root("EVIDENCE_UNIT", evidence_heads) != evidence_plan.projected_root_digest:
            raise D5GenerationConflictError("D5_EVIDENCE_PROJECTED_ROOT_MISMATCH")
        if _snapshot_root("ASSUMPTION", assumption_heads) != assumption_plan.projected_root_digest:
            raise D5GenerationConflictError("D5_ASSUMPTION_PROJECTED_ROOT_MISMATCH")
        if (
            _snapshot_root("ALTERNATIVE_MODEL", alt_model_heads)
            != alt_model_plan.projected_root_digest
        ):
            raise D5GenerationConflictError("D5_ALT_MODEL_PROJECTED_ROOT_MISMATCH")

        disposition = self._disposition_adapter.project(
            semantic_receipt=semantic_receipt,
            clock_sequence=proposed_sequence,
            evidence_root=evidence_plan.projected_root_digest,
            assumption_root=assumption_plan.projected_root_digest,
            alt_model_root=alt_model_plan.projected_root_digest,
        )
        quarantine = self._quarantine_adapter.project()

        previous_completion_digest = cast(str | None, claim_value["previous_completion_digest"])
        completion = cast(
            ClockCompletionReceipt,
            ClockCompletionReceipt.build(
                {
                    "schema_version": "clock-completion-receipt/1",
                    "clock_sequence": proposed_sequence,
                    "previous_completion_digest": previous_completion_digest,
                    "clock_claim_digest": claim.digest,
                    "validated_event_digest": validated_event.digest,
                    "semantic_projection_receipt_digest": semantic_receipt.digest,
                    "registry_root_digests": {
                        "evidence_unit": evidence_plan.projected_root_digest,
                        "assumption": assumption_plan.projected_root_digest,
                        "alternative_model": alt_model_plan.projected_root_digest,
                    },
                    "disposition_receipt_digest": disposition.digest,
                    "quarantine_epoch": quarantine.epoch,
                    "quarantine_marker_digests": list(quarantine.marker_digests),
                    "completion_policy_digest": self.completion_policy_digest,
                }
            ),
        )

        evidence_heads_dicts = _heads_to_dicts(evidence_heads)
        assumption_heads_dicts = _heads_to_dicts(assumption_heads)
        alt_model_heads_dicts = _heads_to_dicts(alt_model_heads)
        manifest_unsigned: dict[str, object] = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "previous_generation_digest": previous_generation_digest,
            "clock_sequence": proposed_sequence,
            "clock_claim_digest": claim.digest,
            "validated_event_digest": validated_event.digest,
            "semantic_projection_receipt_digest": semantic_receipt.digest,
            "evidence_predecessor_root": evidence_predecessor,
            "evidence_plan_digest": evidence_plan.plan_digest,
            "evidence_event_digests": list(evidence_plan.event_digests),
            "evidence_projected_root": evidence_plan.projected_root_digest,
            "evidence_heads": [dict(item) for item in evidence_heads_dicts],
            "assumption_predecessor_root": assumption_predecessor,
            "assumption_evidence_root_binding": evidence_plan.projected_root_digest,
            "assumption_plan_digest": assumption_plan.plan_digest,
            "assumption_event_digests": list(assumption_plan.event_digests),
            "assumption_projected_root": assumption_plan.projected_root_digest,
            "assumption_heads": [dict(item) for item in assumption_heads_dicts],
            "alt_model_predecessor_root": alt_model_predecessor,
            "alt_model_evidence_root_binding": evidence_plan.projected_root_digest,
            "alt_model_assumption_root_binding": assumption_plan.projected_root_digest,
            "alt_model_plan_digest": alt_model_plan.plan_digest,
            "alt_model_event_digests": list(alt_model_plan.event_digests),
            "alt_model_projected_root": alt_model_plan.projected_root_digest,
            "alt_model_heads": [dict(item) for item in alt_model_heads_dicts],
            "disposition_receipt_digest": disposition.digest,
            "quarantine_epoch": quarantine.epoch,
            "quarantine_marker_digests": list(quarantine.marker_digests),
            "clock_completion_digest": completion.digest,
        }
        manifest = D5GenerationManifest(
            previous_generation_digest=previous_generation_digest,
            clock_sequence=proposed_sequence,
            clock_claim_digest=claim.digest,
            validated_event_digest=validated_event.digest,
            semantic_projection_receipt_digest=semantic_receipt.digest,
            evidence_predecessor_root=evidence_predecessor,
            evidence_plan_digest=evidence_plan.plan_digest,
            evidence_event_digests=evidence_plan.event_digests,
            evidence_projected_root=evidence_plan.projected_root_digest,
            evidence_heads=evidence_heads_dicts,
            assumption_predecessor_root=assumption_predecessor,
            assumption_evidence_root_binding=evidence_plan.projected_root_digest,
            assumption_plan_digest=assumption_plan.plan_digest,
            assumption_event_digests=assumption_plan.event_digests,
            assumption_projected_root=assumption_plan.projected_root_digest,
            assumption_heads=assumption_heads_dicts,
            alt_model_predecessor_root=alt_model_predecessor,
            alt_model_evidence_root_binding=evidence_plan.projected_root_digest,
            alt_model_assumption_root_binding=assumption_plan.projected_root_digest,
            alt_model_plan_digest=alt_model_plan.plan_digest,
            alt_model_event_digests=alt_model_plan.event_digests,
            alt_model_projected_root=alt_model_plan.projected_root_digest,
            alt_model_heads=alt_model_heads_dicts,
            disposition_receipt_digest=disposition.digest,
            quarantine_epoch=quarantine.epoch,
            quarantine_marker_digests=quarantine.marker_digests,
            clock_completion_digest=completion.digest,
            generation_digest=_compute_generation_digest(manifest_unsigned),
        )

        self._install_manifest(manifest)
        self._install_completion(completion)
        self._install(
            self.prepared_path,
            _prepared_bundle_bytes(
                manifest=manifest,
                completion=completion,
                claim=claim,
                evidence_events=evidence_plan.events,
                assumption_events=assumption_plan.events,
                alt_model_events=alt_model_plan.events,
            ),
        )
        self._replace(
            self.active_path,
            _active_marker_bytes(claim.digest, manifest.generation_digest),
        )
        return manifest

    # ------------------------------------------------------------------ #
    # Internal: commit
    # ------------------------------------------------------------------ #

    def _commit(self, manifest: D5GenerationManifest) -> None:
        active = self._read_active_marker()
        if active is None:
            raise D5GenerationConflictError("D5_NO_ACTIVE_GENERATION")
        if active[1] != manifest.generation_digest:
            raise D5GenerationConflictError("D5_MANIFEST_NOT_ACTIVE")

        pointer = self._read_current_pointer()
        current_sequence = 0 if pointer is None else pointer[0]
        if manifest.previous_generation_digest == _GENESIS_GENERATION_DIGEST:
            if current_sequence != 0:
                raise D5GenerationConflictError("D5_PREDECESSOR_NOT_GENESIS")
        else:
            if pointer is None or pointer[1] != manifest.previous_generation_digest:
                raise D5GenerationConflictError("D5_PREDECESSOR_GENERATION_MISMATCH")

        if (
            self._evidence_store.snapshot("EVIDENCE_UNIT").root_digest
            != manifest.evidence_predecessor_root
        ):
            raise D5GenerationConflictError("D5_STALE_EVIDENCE_PREDECESSOR")
        if (
            self._assumption_store.snapshot("ASSUMPTION").root_digest
            != manifest.assumption_predecessor_root
        ):
            raise D5GenerationConflictError("D5_STALE_ASSUMPTION_PREDECESSOR")
        if (
            self._alt_model_store.snapshot("ALTERNATIVE_MODEL").root_digest
            != manifest.alt_model_predecessor_root
        ):
            raise D5GenerationConflictError("D5_STALE_ALT_MODEL_PREDECESSOR")

        bundle = self._read_prepared_bundle(manifest.generation_digest)
        self._append_events(self._evidence_store, "EVIDENCE_UNIT", bundle["evidence_events"])
        self._append_events(self._assumption_store, "ASSUMPTION", bundle["assumption_events"])
        self._append_events(self._alt_model_store, "ALTERNATIVE_MODEL", bundle["alt_model_events"])

        if (
            self._evidence_store.snapshot("EVIDENCE_UNIT").root_digest
            != manifest.evidence_projected_root
        ):
            raise D5GenerationConflictError("D5_EVIDENCE_ROOT_COMMIT_MISMATCH")
        if (
            self._assumption_store.snapshot("ASSUMPTION").root_digest
            != manifest.assumption_projected_root
        ):
            raise D5GenerationConflictError("D5_ASSUMPTION_ROOT_COMMIT_MISMATCH")
        if (
            self._alt_model_store.snapshot("ALTERNATIVE_MODEL").root_digest
            != manifest.alt_model_projected_root
        ):
            raise D5GenerationConflictError("D5_ALT_MODEL_ROOT_COMMIT_MISMATCH")

        self._install_manifest(manifest)
        completion = self._read_completion(manifest.clock_completion_digest)
        if completion is None:
            raise D5GenerationConflictError("D5_COMPLETION_UNAVAILABLE")
        self._install_completion(completion)

        self._replace(
            self.current_path,
            _current_pointer_bytes(
                manifest.clock_sequence,
                manifest.generation_digest,
                manifest.clock_completion_digest,
            ),
        )
        self._clear_active()

    def _append_events(
        self,
        store: FilesystemRegistryStore,
        registry_type: str,
        events: list[dict[str, Any]],
    ) -> None:
        for value in events:
            if value.get("registry_type") != registry_type:
                raise D5GenerationConflictError("D5_EVENT_REGISTRY_TYPE_MISMATCH")
            event = cast(RegistryEvent, RegistryEvent.from_json(value))
            store.append(event)

    # ------------------------------------------------------------------ #
    # Internal: recovery
    # ------------------------------------------------------------------ #

    def _recover(self) -> str:
        for path in self.temporary.glob("*.tmp"):
            path.unlink(missing_ok=True)
        active = self._read_active_marker()
        if active is None:
            return "NO_ACTIVE_GENERATION"
        claim_digest, generation_digest = active
        try:
            bundle = self._read_prepared_bundle(generation_digest)
            manifest = D5GenerationManifest.from_json(cast(dict[str, Any], bundle["manifest"]))
        except (D5GenerationConflictError, D5GenerationError, KeyError, TypeError):
            self._clear_active()
            return "INCOMPLETE_GENERATION_FAILED"

        pointer = self._read_current_pointer()
        if pointer is not None and pointer[1] == generation_digest:
            self._clear_active()
            return "IDEMPOTENT_SUCCESS"

        try:
            self._append_events(self._evidence_store, "EVIDENCE_UNIT", bundle["evidence_events"])
            self._append_events(self._assumption_store, "ASSUMPTION", bundle["assumption_events"])
            self._append_events(
                self._alt_model_store, "ALTERNATIVE_MODEL", bundle["alt_model_events"]
            )
            self._install_manifest(manifest)
            completion = self._read_completion(manifest.clock_completion_digest)
            if completion is None:
                raise D5GenerationConflictError("D5_COMPLETION_UNAVAILABLE")
            self._install_completion(completion)
            self._replace(
                self.current_path,
                _current_pointer_bytes(
                    manifest.clock_sequence,
                    manifest.generation_digest,
                    manifest.clock_completion_digest,
                ),
            )
        except (D5GenerationConflictError, D5GenerationError, RegistryStoreError):
            self._clear_active()
            return "INCOMPLETE_GENERATION_FAILED"
        self._clear_active()
        return "PREPARED_GENERATION_PUBLISHED"

    # ------------------------------------------------------------------ #
    # Internal: persistence helpers
    # ------------------------------------------------------------------ #

    def _read_current_pointer(self) -> tuple[int, str, str] | None:
        if not self.current_path.is_file():
            return None
        value = _json_object(self.current_path.read_bytes(), "current generation pointer")
        if value.get("schema_version") != CURRENT_POINTER_SCHEMA_VERSION:
            raise D5GenerationConflictError("D5_CURRENT_POINTER_VERSION_INVALID")
        sequence = cast(int, value["clock_sequence"])
        generation_digest = cast(str, value["generation_digest"])
        completion_digest = cast(str, value["clock_completion_digest"])
        return (sequence, generation_digest, completion_digest)

    def _read_current_manifest(self) -> D5GenerationManifest | None:
        pointer = self._read_current_pointer()
        if pointer is None:
            return None
        return self._read_manifest(pointer[1])

    def _read_active_marker(self) -> tuple[str, str] | None:
        if not self.active_path.is_file():
            return None
        value = _json_object(self.active_path.read_bytes(), "active generation marker")
        if value.get("schema_version") != ACTIVE_MARKER_SCHEMA_VERSION:
            raise D5GenerationConflictError("D5_ACTIVE_MARKER_VERSION_INVALID")
        return (cast(str, value["clock_claim_digest"]), cast(str, value["generation_digest"]))

    def _read_manifest(self, generation_digest: str) -> D5GenerationManifest:
        path = self._manifest_path(generation_digest)
        if not path.is_file():
            raise D5GenerationConflictError("D5_MANIFEST_UNAVAILABLE")
        value = _json_object(path.read_bytes(), "generation manifest")
        manifest = D5GenerationManifest.from_json(value)
        if manifest.generation_digest != generation_digest:
            raise D5GenerationConflictError("D5_MANIFEST_IDENTITY_MISMATCH")
        return manifest

    def _read_completion(self, completion_digest: str) -> ClockCompletionReceipt | None:
        path = self._completion_path(completion_digest)
        if not path.is_file():
            return None
        value = _json_object(path.read_bytes(), "clock completion receipt")
        completion = cast(ClockCompletionReceipt, ClockCompletionReceipt.from_json(value))
        if completion.digest != completion_digest:
            raise D5GenerationConflictError("D5_COMPLETION_IDENTITY_MISMATCH")
        return completion

    def _read_prepared_bundle(self, generation_digest: str) -> dict[str, Any]:
        if not self.prepared_path.is_file():
            raise D5GenerationConflictError("D5_PREPARED_BUNDLE_UNAVAILABLE")
        value = _json_object(self.prepared_path.read_bytes(), "prepared generation bundle")
        if value.get("schema_version") != PREPARED_BUNDLE_SCHEMA_VERSION:
            raise D5GenerationConflictError("D5_PREPARED_BUNDLE_VERSION_INVALID")
        manifest_value = cast(dict[str, Any], value["manifest"])
        if manifest_value.get("generation_digest") != generation_digest:
            raise D5GenerationConflictError("D5_PREPARED_BUNDLE_MISMATCH")
        return value

    def _manifest_path(self, generation_digest: str) -> Path:
        hex_digest = _digest_hex(generation_digest)
        return self.manifests / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _completion_path(self, completion_digest: str) -> Path:
        hex_digest = _digest_hex(completion_digest)
        return self.completions / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _install_manifest(self, manifest: D5GenerationManifest) -> None:
        self._install(
            self._manifest_path(manifest.generation_digest), _json_bytes(manifest.to_json_value())
        )

    def _install_completion(self, completion: ClockCompletionReceipt) -> None:
        self._install(self._completion_path(completion.digest), completion.canonical_bytes)

    def _clear_active(self) -> None:
        self.active_path.unlink(missing_ok=True)
        self.prepared_path.unlink(missing_ok=True)
        _fsync_directory(self.state)

    def _install(self, final_path: Path, payload: bytes) -> None:
        final_path.parent.mkdir(parents=True, exist_ok=True)
        if final_path.exists():
            if final_path.read_bytes() != payload:
                raise D5GenerationConflictError("D5_IMMUTABLE_PATH_CONFLICT")
            return
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        try:
            os.link(temporary, final_path)
        except FileExistsError:
            if final_path.read_bytes() != payload:
                raise D5GenerationConflictError("D5_CONCURRENT_INSTALL_CONFLICT") from None
        temporary.unlink(missing_ok=True)
        _fsync_directory(final_path.parent)

    def _replace(self, final_path: Path, payload: bytes) -> None:
        final_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.temporary / f"{uuid.uuid4().hex}.tmp"
        _write_fsync(temporary, payload, exclusive=True)
        os.replace(temporary, final_path)
        _fsync_directory(final_path.parent)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with advisory_lock(self.lock_path):
            yield


# --------------------------------------------------------------------------- #
# Cross-phase binding validation
# --------------------------------------------------------------------------- #


def _validate_cross_phase_bindings(
    *,
    claim: ClockClaim,
    validated_event: ValidatedEvent,
    semantic_receipt: SemanticProjectionReceipt,
    evidence_plan: EvidenceProjectionPlan,
    assumption_plan: AssumptionProjectionPlan,
    alt_model_plan: AlternativeModelProjectionPlan,
    evidence_predecessor: str,
    assumption_predecessor: str,
    alt_model_predecessor: str,
) -> None:
    # Temporal context bindings (evidence plan anchors the temporal chain).
    if evidence_plan.clock_claim_digest != claim.digest:
        raise D5GenerationConflictError("D5_EVIDENCE_CLAIM_BINDING_MISMATCH")
    if evidence_plan.validated_event_digest != validated_event.digest:
        raise D5GenerationConflictError("D5_EVIDENCE_EVENT_BINDING_MISMATCH")
    if evidence_plan.semantic_receipt_digest != semantic_receipt.digest:
        raise D5GenerationConflictError("D5_EVIDENCE_SEMANTIC_BINDING_MISMATCH")
    if evidence_plan.predecessor_root_digest != evidence_predecessor:
        raise D5GenerationConflictError("D5_EVIDENCE_PREDECESSOR_BINDING_MISMATCH")

    # Assumption downstream bindings.
    if assumption_plan.clock_claim_digest != claim.digest:
        raise D5GenerationConflictError("D5_ASSUMPTION_CLAIM_BINDING_MISMATCH")
    if assumption_plan.validated_event_digest != validated_event.digest:
        raise D5GenerationConflictError("D5_ASSUMPTION_EVENT_BINDING_MISMATCH")
    if assumption_plan.semantic_receipt_digest != semantic_receipt.digest:
        raise D5GenerationConflictError("D5_ASSUMPTION_SEMANTIC_BINDING_MISMATCH")
    if assumption_plan.predecessor_root_digest != assumption_predecessor:
        raise D5GenerationConflictError("D5_ASSUMPTION_PREDECESSOR_BINDING_MISMATCH")
    if assumption_plan.evidence_root_digest != evidence_plan.projected_root_digest:
        raise D5GenerationConflictError("D5_ASSUMPTION_EVIDENCE_ROOT_BINDING_MISMATCH")

    # Alternative-model downstream bindings.
    if alt_model_plan.clock_claim_digest != claim.digest:
        raise D5GenerationConflictError("D5_ALT_MODEL_CLAIM_BINDING_MISMATCH")
    if alt_model_plan.validated_event_digest != validated_event.digest:
        raise D5GenerationConflictError("D5_ALT_MODEL_EVENT_BINDING_MISMATCH")
    if alt_model_plan.semantic_receipt_digest != semantic_receipt.digest:
        raise D5GenerationConflictError("D5_ALT_MODEL_SEMANTIC_BINDING_MISMATCH")
    if alt_model_plan.predecessor_root_digest != alt_model_predecessor:
        raise D5GenerationConflictError("D5_ALT_MODEL_PREDECESSOR_BINDING_MISMATCH")
    if alt_model_plan.evidence_root_digest != evidence_plan.projected_root_digest:
        raise D5GenerationConflictError("D5_ALT_MODEL_EVIDENCE_ROOT_BINDING_MISMATCH")
    if alt_model_plan.assumption_root_digest != assumption_plan.projected_root_digest:
        raise D5GenerationConflictError("D5_ALT_MODEL_ASSUMPTION_ROOT_BINDING_MISMATCH")

    # Clock-sequence consistency across all three plans.
    sequence = evidence_plan.clock_sequence
    if assumption_plan.clock_sequence != sequence:
        raise D5GenerationConflictError("D5_ASSUMPTION_CLOCK_BINDING_MISMATCH")
    if alt_model_plan.clock_sequence != sequence:
        raise D5GenerationConflictError("D5_ALT_MODEL_CLOCK_BINDING_MISMATCH")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _registry_heads(manifest: D5GenerationManifest, registry: str) -> tuple[dict[str, object], ...]:
    if registry == "evidence":
        return manifest.evidence_heads
    if registry == "assumption":
        return manifest.assumption_heads
    if registry == "alt_model":
        return manifest.alt_model_heads
    raise D5GenerationError("D5_UNKNOWN_REGISTRY")


def _projected_heads(
    current_heads: tuple[RegistryEntityHead, ...],
    events: tuple[RegistryEvent, ...],
    registry_type: str,
) -> tuple[RegistryEntityHead, ...]:
    head_map = {head.entity_id: head for head in current_heads}
    for event in events:
        value = event.to_json_value()
        entity_id = cast(str, value["entity_id"])
        head_map[entity_id] = RegistryEntityHead(
            registry_type,
            entity_id,
            cast(int, value["entity_sequence"]),
            event.digest,
        )
    return tuple(sorted(head_map.values(), key=lambda item: item.entity_id))


def _heads_to_dicts(heads: tuple[RegistryEntityHead, ...]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "entity_id": head.entity_id,
            "entity_sequence": head.entity_sequence,
            "event_digest": head.event_digest,
        }
        for head in heads
    )


def _compute_generation_digest(unsigned: dict[str, object]) -> str:
    payload = _json_bytes(unsigned)
    return "sha256:" + hashlib.sha256(b"D5_GENERATION_MANIFEST\0" + payload).hexdigest()


def _current_pointer_bytes(
    clock_sequence: int, generation_digest: str, completion_digest: str
) -> bytes:
    return _json_bytes(
        {
            "schema_version": CURRENT_POINTER_SCHEMA_VERSION,
            "clock_sequence": clock_sequence,
            "generation_digest": generation_digest,
            "clock_completion_digest": completion_digest,
        }
    )


def _active_marker_bytes(claim_digest: str, generation_digest: str) -> bytes:
    return _json_bytes(
        {
            "schema_version": ACTIVE_MARKER_SCHEMA_VERSION,
            "clock_claim_digest": claim_digest,
            "generation_digest": generation_digest,
        }
    )


def _prepared_bundle_bytes(
    *,
    manifest: D5GenerationManifest,
    completion: ClockCompletionReceipt,
    claim: ClockClaim,
    evidence_events: tuple[RegistryEvent, ...],
    assumption_events: tuple[RegistryEvent, ...],
    alt_model_events: tuple[RegistryEvent, ...],
) -> bytes:
    value: dict[str, Any] = {
        "schema_version": PREPARED_BUNDLE_SCHEMA_VERSION,
        "manifest": manifest.to_json_value(),
        "completion": completion.to_json_value(),
        "claim": claim.to_json_value(),
        "evidence_events": [event.to_json_value() for event in evidence_events],
        "assumption_events": [event.to_json_value() for event in assumption_events],
        "alt_model_events": [event.to_json_value() for event in alt_model_events],
    }
    return _json_bytes(value)


def _require_registry_type(value: object) -> None:
    if type(value) is not str or value not in _REGISTRY_PHASE_SET:
        raise D5GenerationError("D5_REGISTRY_TYPE_INVALID")


_REGISTRY_PHASE_SET = {"EVIDENCE_UNIT", "ASSUMPTION", "ALTERNATIVE_MODEL"}


def _require_digest(value: object, code: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise D5GenerationError(code)
    return value


def _require_digest_tuple(values: tuple[str, ...], code: str) -> None:
    if type(values) is not tuple:
        raise D5GenerationError(code)
    for item in values:
        _require_digest(item, code)


def _require_head_set(heads: tuple[dict[str, object], ...], code: str) -> None:
    if type(heads) is not tuple:
        raise D5GenerationError(code)
    entity_ids: list[str] = []
    for item in heads:
        if type(item) is not dict:
            raise D5GenerationError(code)
        if set(item) != {"entity_id", "entity_sequence", "event_digest"}:
            raise D5GenerationError(code)
        entity_id = item["entity_id"]
        entity_sequence = item["entity_sequence"]
        event_digest = item["event_digest"]
        if type(entity_id) is not str or _TOKEN.fullmatch(entity_id) is None:
            raise D5GenerationError(code)
        if type(entity_sequence) is not int or entity_sequence < 1:
            raise D5GenerationError(code)
        _require_digest(event_digest, code)
        entity_ids.append(entity_id)
    if entity_ids != sorted(entity_ids) or len(set(entity_ids)) != len(entity_ids):
        raise D5GenerationError(code)


def _digest_hex(value: str) -> str:
    _require_digest(value, "D5_DIGEST_INVALID")
    return value.removeprefix("sha256:")


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D5GenerationConflictError(f"D5_{label.upper().replace(' ', '_')}_INVALID") from exc
    if type(value) is not dict:
        raise D5GenerationConflictError(f"D5_{label.upper().replace(' ', '_')}_INVALID")
    return cast(dict[str, Any], value)


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


def _write_fsync(path: Path, payload: bytes, *, exclusive: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    fsync_directory(path)


__all__ = [
    "D5GenerationConflictError",
    "D5GenerationError",
    "D5GenerationManifest",
    "D5GenerationStore",
    "GenerationRegistryView",
    "ReferenceDispositionAdapter",
    "ReferenceQuarantineAdapter",
    "ReferenceQuarantineProjection",
]
