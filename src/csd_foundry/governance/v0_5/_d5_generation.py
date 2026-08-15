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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from csd_foundry._platform import advisory_lock, fsync_directory
from csd_foundry.governance.v0_5._alternative_model_projection import (
    AlternativeModelProjectionPlan,
    StagedAlternativeModelProjectionAdapter,
)
from csd_foundry.governance.v0_5._assumption_projection import (
    AssumptionProjectionPlan,
    StagedAssumptionProjectionAdapter,
)
from csd_foundry.governance.v0_5._governed_alternative_model import (
    ComparisonReceipt,
    GovernedAlternativeModelAuthorization,
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
PREPARED_BUNDLE_SCHEMA_VERSION = "prepared-d5-generation/2"

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
# Injectable adapter protocols (phase-failure isolation)
# --------------------------------------------------------------------------- #


class DispositionProjector(Protocol):
    """Structural protocol for disposition adapters used by the D5 layer.

    ``ReferenceDispositionAdapter`` satisfies this structurally. Test code can
    inject a failing implementation via :class:`D5GenerationStore`'s factory hook
    to exercise DISPOSITION-phase failure isolation.
    """

    def project(
        self,
        *,
        semantic_receipt: SemanticProjectionReceipt,
        clock_sequence: int,
        evidence_root: str,
        assumption_root: str,
        alt_model_root: str,
    ) -> DispositionReceipt: ...


class QuarantineProjector(Protocol):
    """Structural protocol for quarantine adapters used by the D5 layer.

    ``ReferenceQuarantineAdapter`` satisfies this structurally. Test code can
    inject a failing implementation to exercise QUARANTINE_COMMIT-phase failure
    isolation.
    """

    def project(self) -> ReferenceQuarantineProjection: ...


DispositionAdapterFactory = Callable[[], DispositionProjector]
QuarantineAdapterFactory = Callable[[], QuarantineProjector]


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

# Domain prefixes used by the three projection plans' self-digests. D5
# recomputes these to verify persisted plan JSON is intact without needing
# ``from_json`` round-tripping of every nested receipt type.
_PLAN_DIGEST_DOMAINS = {
    "evidence": "EVIDENCE_PROJECTION_PLAN",
    "assumption": "ASSUMPTION_PROJECTION_PLAN",
    "alt_model": "ALTERNATIVE_MODEL_PROJECTION_PLAN",
}

# Domain prefix used by the alternative-model comparison receipt self-digest.
_COMPARISON_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_COMPARISON_RECEIPT"


class D5GenerationStore:
    """Integrated atomic store coordinating three registry projection adapters.

    The three :class:`FilesystemRegistryStore` instances serve ONLY as the
    content-addressed object store for :class:`RegistryEvent` bytes (and remain
    available for their own head-advancement gates by other consumers). D5
    authority is defined by the manifest's canonical head sets plus the single
    current-generation pointer; D5 never advances the standalone per-entity
    heads. ``_prepare`` reads from generation-bound views (current
    generation's head sets), and ``_commit`` advances only the generation
    pointer via ``os.replace`` — never the live registry heads.
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
        disposition_adapter_factory: DispositionAdapterFactory | None = None,
        quarantine_adapter_factory: QuarantineAdapterFactory | None = None,
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
        self.semantic_receipts = self.objects / "semantic-projection-receipt"
        self.projection_plans = self.objects / "projection-plan"
        self.disposition_receipts = self.objects / "disposition-receipt"
        self.comparison_receipts = self.objects / "comparison-receipt"
        self.state = generations_dir / "state"
        self.temporary = generations_dir / ".tmp"
        self.lock_path = self.state / "d5.lock"
        self.current_path = self.state / "current-generation.json"
        self.active_path = self.state / "active-generation.json"
        self.prepared_path = self.state / "prepared-generation.json"
        self.completion_policy_digest = _require_digest(
            completion_policy_digest, "D5_COMPLETION_POLICY_INVALID"
        )
        self._disposition_policy_digest = _require_digest(
            disposition_policy_digest, "D5_DISPOSITION_POLICY_INVALID"
        )
        # Defect 5: disposition/quarantine adapters are created fresh per
        # prepare via an injectable factory so test code can raise at the
        # DISPOSITION / QUARANTINE_COMMIT phase boundary.
        self._disposition_adapter_factory: DispositionAdapterFactory = (
            disposition_adapter_factory or self._default_disposition_factory
        )
        self._quarantine_adapter_factory: QuarantineAdapterFactory = (
            quarantine_adapter_factory or self._default_quarantine_factory
        )
        for directory in (
            generations_dir,
            self.objects,
            self.manifests,
            self.completions,
            self.semantic_receipts,
            self.projection_plans,
            self.disposition_receipts,
            self.comparison_receipts,
            self.state,
            self.temporary,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            _fsync_directory(directory)
        self.lock_path.touch(exist_ok=True)

    def _default_disposition_factory(self) -> DispositionProjector:
        return ReferenceDispositionAdapter(
            disposition_policy_digest=self._disposition_policy_digest
        )

    def _default_quarantine_factory(self) -> QuarantineProjector:
        return ReferenceQuarantineAdapter()

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
        governed_admit_evidence: tuple[
            tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...
        ] = (),
    ) -> D5GenerationManifest:
        with self._lock():
            return self._prepare(
                claim=claim,
                validated_event=validated_event,
                semantic_receipt=semantic_receipt,
                evidence_adapter=evidence_adapter,
                assumption_adapter=assumption_adapter,
                alt_model_adapter=alt_model_adapter,
                governed_admit_evidence=governed_admit_evidence,
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
        with self._lock():
            return self._generation_view("evidence")

    def assumption_view(self) -> GenerationRegistryView:
        with self._lock():
            return self._generation_view("assumption")

    def alt_model_view(self) -> GenerationRegistryView:
        with self._lock():
            return self._generation_view("alt_model")

    def _store_for(self, registry: str) -> FilesystemRegistryStore:
        if registry == "evidence":
            return self._evidence_store
        if registry == "assumption":
            return self._assumption_store
        return self._alt_model_store

    def _generation_view(self, registry: str) -> GenerationRegistryView:
        """Construct a read-only view bound to the current generation's heads.

        Lock-free: the caller must already hold ``self._lock()``. Reads from the
        current generation's manifest head set (not the live mutable registry
        heads), satisfying the defect-1 isolation requirement.
        """

        _require_registry_type(_REGISTRY_TYPES[registry])
        manifest = self._read_current_manifest()
        heads: tuple[RegistryEntityHead, ...] = ()
        if manifest is not None:
            heads = manifest.head_entities(registry)
        return GenerationRegistryView(
            store=self._store_for(registry),
            registry_type=_REGISTRY_TYPES[registry],
            heads=heads,
        )

    # ------------------------------------------------------------------ #
    # Public API: durable projection-artifact queries
    # ------------------------------------------------------------------ #

    def read_semantic_receipt(self, semantic_digest: str) -> dict[str, Any] | None:
        with self._lock():
            return self._read_artifact(
                self._semantic_receipt_path(semantic_digest), "semantic projection receipt"
            )

    def read_projection_plan(self, plan_digest: str) -> dict[str, Any] | None:
        with self._lock():
            return self._read_artifact(self._projection_plan_path(plan_digest), "projection plan")

    def read_disposition_receipt(self, disposition_digest: str) -> dict[str, Any] | None:
        with self._lock():
            return self._read_artifact(
                self._disposition_receipt_path(disposition_digest), "disposition receipt"
            )

    def read_comparison_receipt(self, comparison_digest: str) -> dict[str, Any] | None:
        with self._lock():
            return self._read_artifact(
                self._comparison_receipt_path(comparison_digest), "comparison receipt"
            )

    def _read_artifact(self, path: Path, label: str) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        return _json_object(path.read_bytes(), label)

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
        governed_admit_evidence: tuple[
            tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...
        ] = (),
    ) -> D5GenerationManifest:
        claim_value = claim.to_json_value()
        proposed_sequence = cast(int, claim_value["proposed_sequence"])
        previous_sequence = cast(int, claim_value["previous_committed_sequence"])
        claim_previous_completion = cast(str | None, claim_value["previous_completion_digest"])

        pointer = self._read_current_pointer()
        current_sequence = 0 if pointer is None else pointer[0]
        if previous_sequence != current_sequence or proposed_sequence != current_sequence + 1:
            raise D5GenerationConflictError("D5_CLAIM_NOT_SUCCESSOR_OF_CURRENT")

        # Defect 2: bind the temporal predecessor identity. The claim's
        # previous_completion_digest must equal the current generation's
        # clock_completion_digest (None for the genesis predecessor).
        if pointer is None:
            expected_previous_completion: str | None = None
        else:
            current_manifest = self._read_manifest(pointer[1])
            expected_previous_completion = current_manifest.clock_completion_digest
        if claim_previous_completion != expected_previous_completion:
            raise D5GenerationError("PREDECESSOR_COMPLETION_MISMATCH")

        active = self._read_active_marker()
        if active is not None and active[0] != claim.digest:
            raise D5GenerationConflictError("D5_ACTIVE_GENERATION_CONFLICT")

        previous_generation_digest = _GENESIS_GENERATION_DIGEST if pointer is None else pointer[1]

        # Defect 1: read predecessor roots from generation-bound views (the
        # current generation's canonical head sets), NOT from the live mutable
        # registry heads. The views also serve as the committed-store inputs to
        # the three staging adapters.
        evidence_view = self._generation_view("evidence")
        assumption_view = self._generation_view("assumption")
        alt_model_view = self._generation_view("alt_model")

        evidence_predecessor = evidence_view.snapshot("EVIDENCE_UNIT").root_digest
        assumption_predecessor = assumption_view.snapshot("ASSUMPTION").root_digest
        alt_model_predecessor = alt_model_view.snapshot("ALTERNATIVE_MODEL").root_digest

        evidence_plan = evidence_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=evidence_view,
        )
        assumption_plan = assumption_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=assumption_view,
            evidence_root_digest=evidence_plan.projected_root_digest,
        )
        alt_model_plan = alt_model_adapter.project(
            claim=claim,
            validated_event=validated_event,
            semantic_receipt=semantic_receipt,
            committed_store=alt_model_view,
            evidence_root_digest=evidence_plan.projected_root_digest,
            assumption_root_digest=assumption_plan.projected_root_digest,
            governed_admit_evidence=governed_admit_evidence,
        )

        # Defect 2: every plan must bind the claim's proposed clock sequence.
        for plan in (evidence_plan, assumption_plan, alt_model_plan):
            if plan.clock_sequence != proposed_sequence:
                raise D5GenerationError("CLOCK_SEQUENCE_MISMATCH")

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
            evidence_view.snapshot("EVIDENCE_UNIT").heads,
            evidence_plan.events,
            "EVIDENCE_UNIT",
        )
        assumption_heads = _projected_heads(
            assumption_view.snapshot("ASSUMPTION").heads,
            assumption_plan.events,
            "ASSUMPTION",
        )
        alt_model_heads = _projected_heads(
            alt_model_view.snapshot("ALTERNATIVE_MODEL").heads,
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

        # Defect 5: disposition and quarantine adapters are produced fresh per
        # prepare through an injectable factory, so the DISPOSITION and
        # QUARANTINE_COMMIT phases are fault-injectable.
        disposition_adapter = self._disposition_adapter_factory()
        disposition = disposition_adapter.project(
            semantic_receipt=semantic_receipt,
            clock_sequence=proposed_sequence,
            evidence_root=evidence_plan.projected_root_digest,
            assumption_root=assumption_plan.projected_root_digest,
            alt_model_root=alt_model_plan.projected_root_digest,
        )
        quarantine_adapter = self._quarantine_adapter_factory()
        quarantine = quarantine_adapter.project()

        completion = cast(
            ClockCompletionReceipt,
            ClockCompletionReceipt.build(
                {
                    "schema_version": "clock-completion-receipt/1",
                    "clock_sequence": proposed_sequence,
                    "previous_completion_digest": claim_previous_completion,
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

        # Defect 4: durably retain the semantic receipt, three projection plans,
        # and reference disposition receipt in the content-addressed object
        # store so they survive commit + restart (not just the ephemeral bundle).
        self._install_manifest(manifest)
        self._install_completion(completion)
        self._install_semantic_receipt(semantic_receipt)
        self._install_projection_plan(evidence_plan, "evidence")
        self._install_projection_plan(assumption_plan, "assumption")
        self._install_projection_plan(alt_model_plan, "alt_model")
        self._install_disposition_receipt(disposition)
        comparison_receipts = self._install_comparison_receipts(
            governed_admit_evidence, alt_model_plan
        )

        self._install(
            self.prepared_path,
            _prepared_bundle_bytes(
                manifest=manifest,
                completion=completion,
                claim=claim,
                semantic_receipt=semantic_receipt,
                evidence_plan=evidence_plan,
                assumption_plan=assumption_plan,
                alt_model_plan=alt_model_plan,
                disposition=disposition,
                evidence_events=evidence_plan.events,
                assumption_events=assumption_plan.events,
                alt_model_events=alt_model_plan.events,
                comparison_receipts=comparison_receipts,
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

        bundle = self._read_prepared_bundle(manifest.generation_digest)
        evidence_events, assumption_events, alt_model_events = (
            _deserialize_events(bundle["evidence_events"], "EVIDENCE_UNIT"),
            _deserialize_events(bundle["assumption_events"], "ASSUMPTION"),
            _deserialize_events(bundle["alt_model_events"], "ALTERNATIVE_MODEL"),
        )
        completion = cast(
            ClockCompletionReceipt, ClockCompletionReceipt.from_json(bundle["completion"])
        )
        claim = cast(ClockClaim, ClockClaim.from_json(bundle["claim"]))
        self._verify_authority_markers(active, manifest, claim=claim)

        # Defect 3: single authoritative finalization verifier, shared with
        # recovery. Runs BEFORE any pointer replacement.
        self._verify_finalization(
            manifest=manifest,
            completion=completion,
            claim=claim,
            evidence_events=evidence_events,
            assumption_events=assumption_events,
            alt_model_events=alt_model_events,
            evidence_plan_json=cast(dict[str, Any], bundle["evidence_plan"]),
            assumption_plan_json=cast(dict[str, Any], bundle["assumption_plan"]),
            alt_model_plan_json=cast(dict[str, Any], bundle["alt_model_plan"]),
        )

        # Defect 1: install immutable RegistryEvent objects into the
        # content-addressed object store WITHOUT advancing the live per-entity
        # heads. The manifest head sets + generation pointer define D5
        # authority; the standalone FilesystemRegistryStore head advancement is
        # left untouched.
        self._install_event_objects(self._evidence_store, "EVIDENCE_UNIT", evidence_events)
        self._install_event_objects(self._assumption_store, "ASSUMPTION", assumption_events)
        self._install_event_objects(self._alt_model_store, "ALTERNATIVE_MODEL", alt_model_events)

        # Re-derive the projected roots from the manifest head sets (now that
        # every event object is installed) and confirm they still match. This is
        # the post-install analogue of the old live-store projected-root check.
        _verify_projected_heads(manifest, self._evidence_store, "evidence")
        _verify_projected_heads(manifest, self._assumption_store, "assumption")
        _verify_projected_heads(manifest, self._alt_model_store, "alt_model")

        self._install_manifest(manifest)
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

    def _install_event_objects(
        self,
        store: FilesystemRegistryStore,
        registry_type: str,
        events: tuple[RegistryEvent, ...],
    ) -> None:
        """Install immutable event bytes into the object store without head advance.

        Content-addressed and idempotent: a re-install of identical bytes is a
        no-op, and any byte conflict is rejected. The standalone
        ``FilesystemRegistryStore`` per-entity heads are NOT advanced — D5
        authority flows from the manifest head sets + generation pointer.
        """

        for event in events:
            value = event.to_json_value()
            if value.get("registry_type") != registry_type:
                raise D5GenerationConflictError("D5_EVENT_REGISTRY_TYPE_MISMATCH")
            store._install(store._object_path(event.digest), event.canonical_bytes)

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
            evidence_events = _deserialize_events(bundle["evidence_events"], "EVIDENCE_UNIT")
            assumption_events = _deserialize_events(bundle["assumption_events"], "ASSUMPTION")
            alt_model_events = _deserialize_events(bundle["alt_model_events"], "ALTERNATIVE_MODEL")
            completion = cast(
                ClockCompletionReceipt, ClockCompletionReceipt.from_json(bundle["completion"])
            )
            claim = cast(ClockClaim, ClockClaim.from_json(bundle["claim"]))
        except (D5GenerationConflictError, D5GenerationError, KeyError, TypeError):
            self._clear_active()
            return "INCOMPLETE_GENERATION_FAILED"

        pointer = self._read_current_pointer()
        self._verify_authority_markers(active, manifest, claim=claim)
        if pointer is not None and pointer[1] == generation_digest:
            self._clear_active()
            return "IDEMPOTENT_SUCCESS"

        try:
            # Defect 3: same authoritative verifier as ordinary commit.
            self._verify_finalization(
                manifest=manifest,
                completion=completion,
                claim=claim,
                evidence_events=evidence_events,
                assumption_events=assumption_events,
                alt_model_events=alt_model_events,
                evidence_plan_json=cast(dict[str, Any], bundle["evidence_plan"]),
                assumption_plan_json=cast(dict[str, Any], bundle["assumption_plan"]),
                alt_model_plan_json=cast(dict[str, Any], bundle["alt_model_plan"]),
            )

            # Defect 1: install event objects only, no head advance.
            self._install_event_objects(self._evidence_store, "EVIDENCE_UNIT", evidence_events)
            self._install_event_objects(self._assumption_store, "ASSUMPTION", assumption_events)
            self._install_event_objects(
                self._alt_model_store, "ALTERNATIVE_MODEL", alt_model_events
            )
            _verify_projected_heads(manifest, self._evidence_store, "evidence")
            _verify_projected_heads(manifest, self._assumption_store, "assumption")
            _verify_projected_heads(manifest, self._alt_model_store, "alt_model")

            self._install_manifest(manifest)
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

    def _verify_finalization(
        self,
        *,
        manifest: D5GenerationManifest,
        completion: ClockCompletionReceipt,
        claim: ClockClaim,
        evidence_events: tuple[RegistryEvent, ...],
        assumption_events: tuple[RegistryEvent, ...],
        alt_model_events: tuple[RegistryEvent, ...],
        evidence_plan_json: dict[str, Any],
        assumption_plan_json: dict[str, Any],
        alt_model_plan_json: dict[str, Any],
    ) -> None:
        """Single authoritative finalization verifier.

        Used by BOTH ordinary commit and recovery immediately before the
        generation pointer replacement. Verifies:
        - claim.digest matches manifest.clock_claim_digest
        - manifest predecessor matches the current generation pointer
        - event lists match manifest event-digest inventories
        - plan digests match manifest plan digests (recomputed from JSON)
        - completion sequence matches manifest clock_sequence
        - completion root digests match manifest projected roots
        - completion-to-generation cross-binding intact
        """

        # 1. claim.digest matches manifest.clock_claim_digest
        if claim.digest != manifest.clock_claim_digest:
            raise D5GenerationConflictError("D5_FINALIZATION_CLAIM_DIGEST_MISMATCH")

        # 2. manifest predecessor matches current generation pointer
        pointer = self._read_current_pointer()
        if manifest.previous_generation_digest == _GENESIS_GENERATION_DIGEST:
            if pointer is not None:
                raise D5GenerationConflictError("D5_FINALIZATION_PREDECESSOR_NOT_GENESIS")
        else:
            if pointer is None or pointer[1] != manifest.previous_generation_digest:
                raise D5GenerationConflictError("D5_FINALIZATION_PREDECESSOR_MISMATCH")

        # 3. event lists match manifest event-digest inventories
        if tuple(event.digest for event in evidence_events) != manifest.evidence_event_digests:
            raise D5GenerationConflictError("D5_FINALIZATION_EVIDENCE_EVENTS_MISMATCH")
        if tuple(event.digest for event in assumption_events) != manifest.assumption_event_digests:
            raise D5GenerationConflictError("D5_FINALIZATION_ASSUMPTION_EVENTS_MISMATCH")
        if tuple(event.digest for event in alt_model_events) != manifest.alt_model_event_digests:
            raise D5GenerationConflictError("D5_FINALIZATION_ALT_MODEL_EVENTS_MISMATCH")

        # 4. plan digests match manifest plan digests (recompute from stored JSON)
        _verify_plan_json(
            evidence_plan_json,
            _PLAN_DIGEST_DOMAINS["evidence"],
            manifest.evidence_plan_digest,
        )
        _verify_plan_json(
            assumption_plan_json,
            _PLAN_DIGEST_DOMAINS["assumption"],
            manifest.assumption_plan_digest,
        )
        _verify_plan_json(
            alt_model_plan_json,
            _PLAN_DIGEST_DOMAINS["alt_model"],
            manifest.alt_model_plan_digest,
        )
        # Cross-bind plan projected roots to manifest projected roots.
        if evidence_plan_json["projected_root_digest"] != manifest.evidence_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_EVIDENCE_PLAN_ROOT_MISMATCH")
        if assumption_plan_json["projected_root_digest"] != manifest.assumption_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_ASSUMPTION_PLAN_ROOT_MISMATCH")
        if alt_model_plan_json["projected_root_digest"] != manifest.alt_model_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_ALT_MODEL_PLAN_ROOT_MISMATCH")

        # 5. completion sequence matches manifest clock_sequence
        completion_value = completion.to_json_value()
        if completion_value["clock_sequence"] != manifest.clock_sequence:
            raise D5GenerationConflictError("D5_FINALIZATION_COMPLETION_SEQUENCE_MISMATCH")

        # 6. completion root digests match manifest projected roots
        roots = cast(dict[str, str], completion_value["registry_root_digests"])
        if roots["evidence_unit"] != manifest.evidence_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_EVIDENCE_ROOT_MISMATCH")
        if roots["assumption"] != manifest.assumption_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_ASSUMPTION_ROOT_MISMATCH")
        if roots["alternative_model"] != manifest.alt_model_projected_root:
            raise D5GenerationConflictError("D5_FINALIZATION_ALT_MODEL_ROOT_MISMATCH")

        # 7. completion-to-generation cross-binding intact
        if completion_value["clock_claim_digest"] != manifest.clock_claim_digest:
            raise D5GenerationConflictError("D5_FINALIZATION_COMPLETION_CLAIM_MISMATCH")
        if completion_value["validated_event_digest"] != manifest.validated_event_digest:
            raise D5GenerationConflictError("D5_FINALIZATION_COMPLETION_EVENT_MISMATCH")
        if (
            completion_value["semantic_projection_receipt_digest"]
            != manifest.semantic_projection_receipt_digest
        ):
            raise D5GenerationConflictError("D5_FINALIZATION_COMPLETION_SEMANTIC_MISMATCH")
        if completion_value["clock_claim_digest"] != claim.digest:
            raise D5GenerationConflictError("D5_FINALIZATION_CLAIM_CROSSBIND_MISMATCH")
        if completion.digest != manifest.clock_completion_digest:
            raise D5GenerationConflictError("D5_FINALIZATION_COMPLETION_DIGEST_MISMATCH")

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
        manifest = self._read_manifest(pointer[1])
        # Fail closed if the pointer does not exactly cite the referenced manifest.
        if (
            pointer[0] != manifest.clock_sequence
            or pointer[1] != manifest.generation_digest
            or pointer[2] != manifest.clock_completion_digest
        ):
            raise D5GenerationConflictError("D5_POINTER_MANIFEST_MISMATCH")
        return manifest

    def _read_active_marker(self) -> tuple[str, str] | None:
        if not self.active_path.is_file():
            return None
        value = _json_object(self.active_path.read_bytes(), "active generation marker")
        if value.get("schema_version") != ACTIVE_MARKER_SCHEMA_VERSION:
            raise D5GenerationConflictError("D5_ACTIVE_MARKER_VERSION_INVALID")
        return (cast(str, value["clock_claim_digest"]), cast(str, value["generation_digest"]))

    def _verify_authority_markers(
        self,
        active: tuple[str, str],
        manifest: D5GenerationManifest,
        *,
        claim: ClockClaim | None,
    ) -> None:
        """Verify that the active marker and current pointer bind to the manifest.

        Checks:
        - Active marker's clock_claim_digest matches manifest.clock_claim_digest.
        - If a deserialized claim is provided, claim.digest also matches.
        - Current pointer (when present) exactly cites the referenced manifest's
          clock_sequence, generation_digest, and clock_completion_digest.
        """
        active_claim_digest, active_generation_digest = active
        if active_generation_digest != manifest.generation_digest:
            raise D5GenerationConflictError("D5_ACTIVE_GENERATION_MISMATCH")
        if active_claim_digest != manifest.clock_claim_digest:
            raise D5GenerationConflictError("D5_ACTIVE_CLAIM_MISMATCH")
        if claim is not None and claim.digest != manifest.clock_claim_digest:
            raise D5GenerationConflictError("D5_ACTIVE_CLAIM_MISMATCH")
        pointer = self._read_current_pointer()
        if pointer is not None:
            ptr_sequence, ptr_generation, ptr_completion = pointer
            if ptr_generation == manifest.generation_digest:
                if (
                    ptr_sequence != manifest.clock_sequence
                    or ptr_completion != manifest.clock_completion_digest
                ):
                    raise D5GenerationConflictError("D5_POINTER_MANIFEST_MISMATCH")

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

    def _install_semantic_receipt(self, receipt: SemanticProjectionReceipt) -> None:
        self._install(self._semantic_receipt_path(receipt.digest), receipt.canonical_bytes)

    def _install_projection_plan(
        self,
        plan: EvidenceProjectionPlan | AssumptionProjectionPlan | AlternativeModelProjectionPlan,
        registry: str,
    ) -> None:
        del registry  # plan digest is globally unique; registry tag is reserved
        self._install(
            self._projection_plan_path(plan.plan_digest), _json_bytes(plan.to_json_value())
        )

    def _install_disposition_receipt(self, receipt: DispositionReceipt) -> None:
        self._install(self._disposition_receipt_path(receipt.digest), receipt.canonical_bytes)

    def _install_comparison_receipts(
        self,
        governed_admit_evidence: tuple[
            tuple[GovernedAlternativeModelAuthorization, ComparisonReceipt], ...
        ],
        alt_model_plan: AlternativeModelProjectionPlan,
    ) -> tuple[dict[str, object], ...]:
        """Install P3.5 comparison receipts cited by the alt-model plan.

        Verifies that each supplied comparison receipt's digest appears in the
        plan's ``admit_comparison_bindings``, then installs the receipt bytes
        into the content-addressed object store so they survive commit +
        restart. Returns the JSON values for inclusion in the prepared bundle.
        """

        cited = {digest for _model_id, digest in alt_model_plan.admit_comparison_bindings}
        installed: list[dict[str, object]] = []
        seen: set[str] = set()
        for _authorization, comparison in governed_admit_evidence:
            if type(comparison) is not ComparisonReceipt:
                raise D5GenerationError("D5_COMPARISON_RECEIPT_TYPE_INVALID")
            if comparison.comparison_digest not in cited:
                raise D5GenerationError(
                    "D5_COMPARISON_RECEIPT_NOT_CITED_BY_PLAN", comparison.comparison_digest
                )
            if comparison.comparison_digest in seen:
                raise D5GenerationError(
                    "D5_COMPARISON_RECEIPT_DUPLICATE", comparison.comparison_digest
                )
            seen.add(comparison.comparison_digest)
            self._install(
                self._comparison_receipt_path(comparison.comparison_digest),
                comparison.canonical_bytes,
            )
            installed.append(comparison.to_json_value())
        # Every binding cited by the plan must have a persisted receipt.
        missing = cited - seen
        if missing:
            raise D5GenerationError("D5_COMPARISON_RECEIPT_MISSING", ",".join(sorted(missing)))
        return tuple(installed)

    def _semantic_receipt_path(self, semantic_digest: str) -> Path:
        hex_digest = _digest_hex(semantic_digest)
        return self.semantic_receipts / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _projection_plan_path(self, plan_digest: str) -> Path:
        hex_digest = _digest_hex(plan_digest)
        return self.projection_plans / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _disposition_receipt_path(self, disposition_digest: str) -> Path:
        hex_digest = _digest_hex(disposition_digest)
        return self.disposition_receipts / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _comparison_receipt_path(self, comparison_digest: str) -> Path:
        hex_digest = _digest_hex(comparison_digest)
        return self.comparison_receipts / hex_digest[:2] / f"{hex_digest[2:]}.json"

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
    semantic_receipt: SemanticProjectionReceipt,
    evidence_plan: EvidenceProjectionPlan,
    assumption_plan: AssumptionProjectionPlan,
    alt_model_plan: AlternativeModelProjectionPlan,
    disposition: DispositionReceipt,
    evidence_events: tuple[RegistryEvent, ...],
    assumption_events: tuple[RegistryEvent, ...],
    alt_model_events: tuple[RegistryEvent, ...],
    comparison_receipts: tuple[dict[str, object], ...],
) -> bytes:
    value: dict[str, Any] = {
        "schema_version": PREPARED_BUNDLE_SCHEMA_VERSION,
        "manifest": manifest.to_json_value(),
        "completion": completion.to_json_value(),
        "claim": claim.to_json_value(),
        "semantic_receipt": semantic_receipt.to_json_value(),
        "evidence_plan": evidence_plan.to_json_value(),
        "assumption_plan": assumption_plan.to_json_value(),
        "alt_model_plan": alt_model_plan.to_json_value(),
        "disposition_receipt": disposition.to_json_value(),
        "evidence_events": [event.to_json_value() for event in evidence_events],
        "assumption_events": [event.to_json_value() for event in assumption_events],
        "alt_model_events": [event.to_json_value() for event in alt_model_events],
        "comparison_receipts": [dict(item) for item in comparison_receipts],
    }
    return _json_bytes(value)


def _deserialize_events(raw_events: list[Any], registry_type: str) -> tuple[RegistryEvent, ...]:
    """Deserialize a list of JSON event values into typed RegistryEvent objects.

    Each event must target ``registry_type``; a mismatch is a finalization
    failure. Used by both commit and recovery to reconstruct the event tuples
    fed into :meth:`D5GenerationStore._verify_finalization`.
    """

    if type(raw_events) is not list:
        raise D5GenerationConflictError("D5_PREPARED_BUNDLE_EVENTS_INVALID")
    events: list[RegistryEvent] = []
    for value in raw_events:
        if type(value) is not dict:
            raise D5GenerationConflictError("D5_PREPARED_BUNDLE_EVENT_INVALID")
        if value.get("registry_type") != registry_type:
            raise D5GenerationConflictError("D5_EVENT_REGISTRY_TYPE_MISMATCH")
        events.append(cast(RegistryEvent, RegistryEvent.from_json(value)))
    return tuple(events)


def _verify_plan_json(plan_json: dict[str, Any], domain: str, expected_digest: str) -> None:
    """Verify a persisted plan JSON's self-digest matches the manifest citation.

    Recomputes the domain-separated digest from the unsigned fields (every key
    except ``plan_digest``) using the same canonicalization the projection
    modules use. This mechanically proves the persisted plan JSON is intact
    without requiring per-type ``from_json`` constructors for every nested
    receipt/decision type.
    """

    if plan_json.get("plan_digest") != expected_digest:
        raise D5GenerationConflictError("D5_FINALIZATION_PLAN_DIGEST_MISMATCH")
    unsigned = {key: value for key, value in plan_json.items() if key != "plan_digest"}
    recomputed = _domain_digest(domain, unsigned)
    if recomputed != expected_digest:
        raise D5GenerationConflictError("D5_FINALIZATION_PLAN_DIGEST_CORRUPT")


def _domain_digest(domain: str, value: object) -> str:
    """Domain-separated digest matching the projection modules' canonical form."""

    payload = _json_bytes(value)
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def _verify_projected_heads(
    manifest: D5GenerationManifest,
    store: FilesystemRegistryStore,
    registry: str,
) -> None:
    """Post-install verification that manifest heads reconstruct from installed objects.

    Walks each entity chain from the manifest head set through the object store
    (now that every event object has been installed) and recomputes the
    projected root, confirming it still matches the manifest. This is the
    defect-1 replacement for the old live-store projected-root check.
    """

    heads = manifest.head_entities(registry)
    reconstructed_root = _snapshot_root(_REGISTRY_TYPES[registry], heads)
    expected_root = _manifest_projected_root(manifest, registry)
    if reconstructed_root != expected_root:
        raise D5GenerationConflictError(f"D5_{registry.upper()}_PROJECTED_ROOT_INSTALL_MISMATCH")
    # Walk each chain to confirm every event object is retrievable.
    view = GenerationRegistryView(
        store=store,
        registry_type=_REGISTRY_TYPES[registry],
        heads=heads,
    )
    for head in heads:
        chain = view.reconstruct_entity(_REGISTRY_TYPES[registry], head.entity_id)
        if not chain or chain[-1].digest != head.event_digest:
            raise D5GenerationConflictError(f"D5_{registry.upper()}_CHAIN_RECONSTRUCTION_FAILED")


def _manifest_projected_root(manifest: D5GenerationManifest, registry: str) -> str:
    if registry == "evidence":
        return manifest.evidence_projected_root
    if registry == "assumption":
        return manifest.assumption_projected_root
    return manifest.alt_model_projected_root


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
    "DispositionAdapterFactory",
    "DispositionProjector",
    "GenerationRegistryView",
    "QuarantineAdapterFactory",
    "QuarantineProjector",
    "ReferenceDispositionAdapter",
    "ReferenceQuarantineAdapter",
    "ReferenceQuarantineProjection",
]
