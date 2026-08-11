"""P3.4 governed alternative-model authority, structural difference, FULL_REPLAY, comparison.

This module layers four frozen, self-digesting capabilities on top of the D4
alternative-model lifecycle registry:

* **Structural-difference detection** between a primary graph and a shadow
  graph, producing a canonical difference set classified into closed
  difference families. The detector is fail-closed on non-canonical graph
  bytes and on a declared difference digest that does not match the computed
  difference set.
* **Governed ADMIT admission** for a PROPOSED alternative model, atomically
  appending one ADMIT event under a single registry lock only when the
  supplied structural-difference receipt binds the model's shadow graph,
  declares a material difference, and matches the model's declared difference
  digest. Denials and stale-state conditions leave the registry head/root
  unadvanced.
* **FULL_REPLAY** of a model graph through an injectable executor protocol,
  producing a self-digesting replay receipt that mechanically proves the
  required inventory was fully executed with nothing skipped or pruned.
* **Canonical comparison** of a primary replay against a shadow replay
  against the same decision context, classifying the pair as INVARIANT
  (equal semantic outcome) or DIVERGENT.

It also provides the **use-time authority gate** that decides whether an
admitted alternative model may be reused at a given logical clock, scope, and
reuse class.

Every receipt here is frozen, exact-typed, and self-digesting under its own
domain-separated prefix. No receipt asserts external truth; each mechanically
re-derives its declared aggregates and verifies its self-digest in
``__post_init__`` before it can be observed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol, cast

from csd_foundry.governance.v0_5._assumption_governance_contracts import (
    AssumptionGovernanceContractError,
    _domain_digest,
    _json_bytes,
    _require_digest,
    _require_self_digest,
    _require_token,
)
from csd_foundry.governance.v0_5.alternative_model import (
    STANDING_ADMITTED,
    STANDING_CONFIRMED,
    STANDING_PROPOSED,
    STANDING_UNVERIFIED,
    AlternativeModel,
    AlternativeModelRegistryError,
    build_alternative_model_event,
    project_alternative_model_history,
    reduce_alternative_model,
)
from csd_foundry.governance.v0_5.contracts import RegistryEvent
from csd_foundry.governance.v0_5.registry import (
    GovernedRegistryStore,
    LockedRegistryView,
    RegistryEntityHead,
    _snapshot_root,
)

# --------------------------------------------------------------------------- #
# Frozen vocabulary
# --------------------------------------------------------------------------- #

_STRUCTURAL_DIFFERENCE_SCHEMA_VERSION = "alternative-model-structural-difference-receipt/1"
_AUTHORIZATION_SCHEMA_VERSION = "alternative-model-governed-admit-authorization/1"
_REPLAY_RECEIPT_SCHEMA_VERSION = "alternative-model-replay-receipt/1"
_COMPARISON_RECEIPT_SCHEMA_VERSION = "alternative-model-comparison-receipt/1"
_USE_AUTHORITY_DECISION_SCHEMA_VERSION = "alternative-model-use-authority-decision/1"

_STRUCTURAL_DIFFERENCE_SET_DOMAIN = "ALTERNATIVE_MODEL_STRUCTURAL_DIFFERENCE"
_STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_STRUCTURAL_DIFFERENCE_RECEIPT"
_AUTHORIZATION_DOMAIN = "ALTERNATIVE_MODEL_GOVERNED_ADMIT_AUTHORIZATION"
_REPLAY_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_REPLAY_RECEIPT"
_COMPARISON_RECEIPT_DOMAIN = "ALTERNATIVE_MODEL_COMPARISON_RECEIPT"
_USE_AUTHORITY_DECISION_DOMAIN = "ALTERNATIVE_MODEL_USE_AUTHORITY_DECISION"

_DIFFERENCE_FAMILIES = frozenset(
    {
        "ADDED_REMOVED",
        "RELABELED",
        "SCOPE",
        "TEMPORAL",
        "AUTHORITY",
        "EVIDENCE_ADMISSION",
    }
)

_MATERIALITIES = frozenset({"ADVISORY", "MATERIAL", "CRITICAL"})
_REUSE_CLASSES = frozenset({"D0", "D1", "D2", "D3", "BENCHMARK"})
_REUSE_CLASS_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}
_USABLE_STANDINGS = frozenset({STANDING_ADMITTED, STANDING_CONFIRMED})


class GovernedAlternativeModelError(Exception):
    """Stable error for governed alternative-model ADMIT failures."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        message = code if detail is None else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------- #
# A. Canonical graph-byte validation
# --------------------------------------------------------------------------- #


def _canonical_graph_bytes(supplied_bytes: bytes) -> bytes:
    """Parse supplied JSON, deterministically re-encode using repository
    canonicalization rules, and require ``supplied_bytes == canonical_bytes``.

    Fail closed on non-canonical input. Uses the same canonicalization as
    :func:`_json_bytes` from ``_assumption_governance_contracts``.
    """
    if type(supplied_bytes) is not bytes:
        raise AssumptionGovernanceContractError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID")
    try:
        value = json.loads(supplied_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AssumptionGovernanceContractError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID") from exc
    try:
        canonical = _json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise AssumptionGovernanceContractError("ALTERNATIVE_MODEL_GRAPH_BYTES_INVALID") from exc
    if canonical != supplied_bytes:
        raise AssumptionGovernanceContractError("ALTERNATIVE_MODEL_GRAPH_BYTES_NONCANONICAL")
    return canonical


def _graph_digest_of(canonical_bytes: bytes) -> str:
    """Compute the raw ``sha256:`` graph digest over canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


# --------------------------------------------------------------------------- #
# B. Structural-difference detector
# --------------------------------------------------------------------------- #


def _classify_difference(path: str, *, present_both_sides: bool) -> str:
    """Classify one difference path into a closed family by full-path inspection.

    Keyword families take precedence: if ANY segment of the full dot-joined path
    contains a keyword, the corresponding family applies regardless of presence.
    When no keyword matches, a path present on both sides (value/type changed)
    is RELABELED, and a path present on only one side is ADDED_REMOVED.
    """
    lower = path.lower()
    if "scope" in lower:
        return "SCOPE"
    if (
        "temporal" in lower
        or "time" in lower
        or "sequence" in lower
        or "valid_from" in lower
        or "expires" in lower
    ):
        return "TEMPORAL"
    if "authority" in lower:
        return "AUTHORITY"
    if "evidence" in lower or "admission" in lower:
        return "EVIDENCE_ADMISSION"
    return "RELABELED" if present_both_sides else "ADDED_REMOVED"


def _escape_pointer_segment(key: str) -> str:
    """RFC 6901 escape: ~ → ~0, / → ~1."""
    return key.replace("~", "~0").replace("/", "~1")


def _collect_differences(
    primary: dict[str, Any],
    shadow: dict[str, Any],
    prefix: str,
    paths: list[str],
    families: list[str],
) -> None:
    """Recursively walk two JSON object graphs recording differing paths.

    Paths use RFC 6901 JSON Pointer format (``/nodes/0/authority_id``) so
    object keys containing ``.``, ``[``, ``]`` cannot collide with structural
    path segments. Both inputs are JSON objects (validated by the caller).
    """
    all_keys = set(primary) | set(shadow)
    for key in sorted(all_keys):
        escaped = _escape_pointer_segment(key)
        path = f"{prefix}/{escaped}"
        in_primary = key in primary
        in_shadow = key in shadow
        if in_primary and in_shadow:
            primary_value = primary[key]
            shadow_value = shadow[key]
            if type(primary_value) is dict and type(shadow_value) is dict:
                _collect_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is list and type(shadow_value) is list:
                _collect_list_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is not type(shadow_value) or primary_value != shadow_value:
                paths.append(path)
                families.append(_classify_difference(path, present_both_sides=True))
        else:
            paths.append(path)
            families.append(_classify_difference(path, present_both_sides=False))


def _collect_list_differences(
    primary: list[Any],
    shadow: list[Any],
    prefix: str,
    paths: list[str],
    families: list[str],
) -> None:
    """Recursively walk two JSON arrays by canonical index.

    Indexes become ordinary JSON Pointer segments: ``/nodes/0/authority_id``.
    """
    max_len = max(len(primary), len(shadow))
    for i in range(max_len):
        path = f"{prefix}/{i}"
        in_primary = i < len(primary)
        in_shadow = i < len(shadow)
        if in_primary and in_shadow:
            primary_value = primary[i]
            shadow_value = shadow[i]
            if type(primary_value) is dict and type(shadow_value) is dict:
                _collect_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is list and type(shadow_value) is list:
                _collect_list_differences(primary_value, shadow_value, path, paths, families)
            elif type(primary_value) is not type(shadow_value) or primary_value != shadow_value:
                paths.append(path)
                families.append(_classify_difference(path, present_both_sides=True))
        else:
            paths.append(path)
            families.append(_classify_difference(path, present_both_sides=False))


def _require_canonical_tokens(value: object, code: str, *, allow_empty: bool) -> tuple[str, ...]:
    """Require a canonical (sorted, unique, valid-token) string tuple."""
    if type(value) is not tuple:
        raise AssumptionGovernanceContractError(code)
    if not allow_empty and not value:
        raise AssumptionGovernanceContractError(code)
    for item in value:
        if type(item) is not str:
            raise AssumptionGovernanceContractError(code)
        _require_token(item, code)
    if tuple(sorted(value)) != value:
        raise AssumptionGovernanceContractError(code)
    if len(set(value)) != len(value):
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


def _require_difference_paths(value: object, code: str) -> tuple[str, ...]:
    """Require a canonical (sorted, unique, non-empty-string) path tuple."""
    if type(value) is not tuple:
        raise AssumptionGovernanceContractError(code)
    for item in value:
        if type(item) is not str or not item:
            raise AssumptionGovernanceContractError(code)
    if tuple(sorted(value)) != value:
        raise AssumptionGovernanceContractError(code)
    if len(set(value)) != len(value):
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


def _require_difference_families(value: object, code: str) -> tuple[str, ...]:
    """Require a canonical (sorted, unique) family tuple drawn from the closed set."""
    if type(value) is not tuple:
        raise AssumptionGovernanceContractError(code)
    for item in value:
        if type(item) is not str or item not in _DIFFERENCE_FAMILIES:
            raise AssumptionGovernanceContractError(code)
    if tuple(sorted(value)) != value:
        raise AssumptionGovernanceContractError(code)
    if len(set(value)) != len(value):
        raise AssumptionGovernanceContractError(code)
    return cast(tuple[str, ...], value)


def _compute_difference_set_digest(
    difference_families: tuple[str, ...],
    difference_paths: tuple[str, ...],
) -> str:
    """Compute the canonical difference-set digest over families + paths."""
    return _domain_digest(
        _STRUCTURAL_DIFFERENCE_SET_DOMAIN,
        {
            "difference_families": list(difference_families),
            "difference_paths": list(difference_paths),
        },
    )


@dataclass(frozen=True, slots=True)
class StructuralDifferenceReceipt:
    """Self-digesting structural-difference receipt between two JSON graphs.

    Mechanically re-derives the computed difference-set digest from its own
    family/path tuples, requires it to match both the stored computed digest
    and the declared digest, and verifies its own self-digest. A receipt with
    no difference paths is constructible (``has_material_difference == False``)
    but cannot authorize a governed ADMIT.
    """

    primary_graph_digest: str
    shadow_graph_digest: str
    computed_difference_digest: str
    declared_difference_digest: str
    difference_families: tuple[str, ...]
    difference_paths: tuple[str, ...]
    has_material_difference: bool
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_digest(
            self.primary_graph_digest, "STRUCTURAL_DIFFERENCE_PRIMARY_GRAPH_DIGEST_INVALID"
        )
        _require_digest(
            self.shadow_graph_digest, "STRUCTURAL_DIFFERENCE_SHADOW_GRAPH_DIGEST_INVALID"
        )
        _require_digest(
            self.computed_difference_digest,
            "STRUCTURAL_DIFFERENCE_COMPUTED_DIGEST_INVALID",
        )
        _require_digest(
            self.declared_difference_digest,
            "STRUCTURAL_DIFFERENCE_DECLARED_DIGEST_INVALID",
        )
        families = _require_difference_families(
            self.difference_families, "STRUCTURAL_DIFFERENCE_FAMILIES_INVALID"
        )
        paths = _require_difference_paths(
            self.difference_paths, "STRUCTURAL_DIFFERENCE_PATHS_INVALID"
        )
        if type(self.has_material_difference) is not bool:
            raise AssumptionGovernanceContractError("STRUCTURAL_DIFFERENCE_MATERIALITY_NOT_BOOL")

        # Materiality consistency: families non-empty iff paths non-empty.
        if bool(families) != bool(paths):
            raise AssumptionGovernanceContractError(
                "STRUCTURAL_DIFFERENCE_FAMILY_PATH_INCONSISTENT"
            )
        if self.has_material_difference != (len(paths) > 0):
            raise AssumptionGovernanceContractError(
                "STRUCTURAL_DIFFERENCE_MATERIALITY_INCONSISTENT"
            )

        # Computed difference-set digest must match the canonical re-derivation.
        recomputed = _compute_difference_set_digest(families, paths)
        if recomputed != self.computed_difference_digest:
            raise AssumptionGovernanceContractError(
                "STRUCTURAL_DIFFERENCE_COMPUTED_DIGEST_MISMATCH"
            )
        # Declared must match computed.
        if self.computed_difference_digest != self.declared_difference_digest:
            raise AssumptionGovernanceContractError("STRUCTURAL_DIFFERENCE_DECLARED_MISMATCH")

        # Self-digest.
        _require_self_digest(
            _STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN,
            self._unsigned_value(),
            self.receipt_digest,
            "STRUCTURAL_DIFFERENCE_RECEIPT_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _STRUCTURAL_DIFFERENCE_SCHEMA_VERSION,
            "primary_graph_digest": self.primary_graph_digest,
            "shadow_graph_digest": self.shadow_graph_digest,
            "computed_difference_digest": self.computed_difference_digest,
            "declared_difference_digest": self.declared_difference_digest,
            "difference_families": list(self.difference_families),
            "difference_paths": list(self.difference_paths),
            "has_material_difference": self.has_material_difference,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "receipt_digest": self.receipt_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def compute_structural_difference_digest(
    *,
    primary_graph_bytes: bytes,
    shadow_graph_bytes: bytes,
) -> str:
    """Compute the declared difference-set digest for a graph pair.

    Convenience helper so callers can seed a PROPOSE event's
    ``declared_difference_digest`` before constructing the full receipt. Both
    graphs are canonicalized and parsed; the digest is taken over the canonical
    difference set (sorted unique families + sorted unique paths).
    """
    primary_canon = _canonical_graph_bytes(primary_graph_bytes)
    shadow_canon = _canonical_graph_bytes(shadow_graph_bytes)
    primary = json.loads(primary_canon.decode("utf-8"))
    shadow = json.loads(shadow_canon.decode("utf-8"))
    if type(primary) is not dict or type(shadow) is not dict:
        raise AssumptionGovernanceContractError("STRUCTURAL_DIFFERENCE_GRAPH_NOT_OBJECT")
    paths: list[str] = []
    families: list[str] = []
    _collect_differences(primary, shadow, "", paths, families)
    unique_paths = tuple(sorted(set(paths)))
    unique_families = tuple(sorted(set(families)))
    return _compute_difference_set_digest(unique_families, unique_paths)


def detect_structural_difference(
    *,
    primary_graph_bytes: bytes,
    shadow_graph_bytes: bytes,
    primary_graph_digest: str,
    shadow_graph_digest: str,
    declared_difference_digest: str,
) -> StructuralDifferenceReceipt:
    """Detect structural differences between two canonical JSON graphs.

    Validates that each supplied graph canonicalizes to the supplied digest,
    parses both, recursively diffs them, and constructs a self-digesting
    receipt. The receipt's ``__post_init__`` requires the computed difference
    digest to equal the supplied ``declared_difference_digest``.
    """
    primary_canon = _canonical_graph_bytes(primary_graph_bytes)
    shadow_canon = _canonical_graph_bytes(shadow_graph_bytes)
    if _graph_digest_of(primary_canon) != primary_graph_digest:
        raise AssumptionGovernanceContractError(
            "STRUCTURAL_DIFFERENCE_PRIMARY_GRAPH_DIGEST_MISMATCH"
        )
    if _graph_digest_of(shadow_canon) != shadow_graph_digest:
        raise AssumptionGovernanceContractError(
            "STRUCTURAL_DIFFERENCE_SHADOW_GRAPH_DIGEST_MISMATCH"
        )
    primary = json.loads(primary_canon.decode("utf-8"))
    shadow = json.loads(shadow_canon.decode("utf-8"))
    if type(primary) is not dict or type(shadow) is not dict:
        raise AssumptionGovernanceContractError("STRUCTURAL_DIFFERENCE_GRAPH_NOT_OBJECT")

    paths: list[str] = []
    families: list[str] = []
    _collect_differences(primary, shadow, "", paths, families)
    unique_paths = tuple(sorted(set(paths)))
    unique_families = tuple(sorted(set(families)))
    computed = _compute_difference_set_digest(unique_families, unique_paths)
    material = len(unique_paths) > 0

    unsigned = {
        "schema_version": _STRUCTURAL_DIFFERENCE_SCHEMA_VERSION,
        "primary_graph_digest": primary_graph_digest,
        "shadow_graph_digest": shadow_graph_digest,
        "computed_difference_digest": computed,
        "declared_difference_digest": declared_difference_digest,
        "difference_families": list(unique_families),
        "difference_paths": list(unique_paths),
        "has_material_difference": material,
    }
    receipt_digest = _domain_digest(_STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN, unsigned)

    return StructuralDifferenceReceipt(
        primary_graph_digest=primary_graph_digest,
        shadow_graph_digest=shadow_graph_digest,
        computed_difference_digest=computed,
        declared_difference_digest=declared_difference_digest,
        difference_families=unique_families,
        difference_paths=unique_paths,
        has_material_difference=material,
        receipt_digest=receipt_digest,
    )


# --------------------------------------------------------------------------- #
# C. Governed D4 admission
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class GovernedAlternativeModelAuthorization:
    """Cross-bound composite authorization for one governed alternative-model ADMIT.

    Mechanically cross-validates that the structural-difference receipt binds
    the same primary/shadow graph digests carried on the authorization, that
    the receipt declares a material difference, and that the candidate entity
    sequence is the exact ADMIT position (2). The authorization is the single
    admission authority receipt bound into the ADMIT event's source receipt.
    """

    model_id: str
    candidate_predecessor_event_digest: str
    candidate_entity_sequence: int
    event_sequence: int
    admitting_authority_id: str
    alternative_model_registry_root: str
    structural_difference_receipt: StructuralDifferenceReceipt
    primary_model_id: str
    primary_graph_digest: str
    shadow_graph_digest: str
    scope_ids: tuple[str, ...]
    materiality: str
    assumption_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    authorization_digest: str

    def __post_init__(self) -> None:
        _require_token(self.model_id, "GOVERNED_ALT_MODEL_AUTH_MODEL_ID_INVALID")
        _require_digest(
            self.candidate_predecessor_event_digest,
            "GOVERNED_ALT_MODEL_AUTH_PREDECESSOR_DIGEST_INVALID",
        )
        if (
            type(self.candidate_entity_sequence) is not int
            or isinstance(self.candidate_entity_sequence, bool)
            or self.candidate_entity_sequence != 2
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_AUTH_CANDIDATE_SEQUENCE_INVALID"
            )
        if (
            type(self.event_sequence) is not int
            or isinstance(self.event_sequence, bool)
            or self.event_sequence < 1
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_AUTH_EVENT_SEQUENCE_INVALID"
            )
        _require_token(self.admitting_authority_id, "GOVERNED_ALT_MODEL_AUTH_AUTHORITY_ID_INVALID")
        _require_digest(
            self.alternative_model_registry_root,
            "GOVERNED_ALT_MODEL_AUTH_REGISTRY_ROOT_INVALID",
        )
        if type(self.structural_difference_receipt) is not StructuralDifferenceReceipt:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_AUTH_RECEIPT_TYPE_INVALID")
        _require_token(self.primary_model_id, "GOVERNED_ALT_MODEL_AUTH_PRIMARY_MODEL_INVALID")
        _require_digest(
            self.primary_graph_digest, "GOVERNED_ALT_MODEL_AUTH_PRIMARY_GRAPH_DIGEST_INVALID"
        )
        _require_digest(
            self.shadow_graph_digest, "GOVERNED_ALT_MODEL_AUTH_SHADOW_GRAPH_DIGEST_INVALID"
        )
        _require_canonical_tokens(
            self.scope_ids, "GOVERNED_ALT_MODEL_AUTH_SCOPE_IDS_INVALID", allow_empty=False
        )
        if type(self.materiality) is not str or self.materiality not in _MATERIALITIES:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_AUTH_MATERIALITY_INVALID")
        _require_canonical_tokens(
            self.assumption_ids,
            "GOVERNED_ALT_MODEL_AUTH_ASSUMPTION_IDS_INVALID",
            allow_empty=True,
        )
        _require_canonical_tokens(
            self.evidence_ids,
            "GOVERNED_ALT_MODEL_AUTH_EVIDENCE_IDS_INVALID",
            allow_empty=True,
        )

        receipt = self.structural_difference_receipt
        if not receipt.has_material_difference:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_AUTH_NO_MATERIAL_DIFFERENCE"
            )
        if receipt.primary_graph_digest != self.primary_graph_digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_AUTH_PRIMARY_GRAPH_BINDING_MISMATCH"
            )
        if receipt.shadow_graph_digest != self.shadow_graph_digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_AUTH_SHADOW_GRAPH_BINDING_MISMATCH"
            )

        # Self-digest.
        _require_self_digest(
            _AUTHORIZATION_DOMAIN,
            self._unsigned_value(),
            self.authorization_digest,
            "GOVERNED_ALT_MODEL_AUTH_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
            "admitting_authority_id": self.admitting_authority_id,
            "alternative_model_registry_root": self.alternative_model_registry_root,
            "assumption_ids": list(self.assumption_ids),
            "candidate_entity_sequence": self.candidate_entity_sequence,
            "candidate_predecessor_event_digest": self.candidate_predecessor_event_digest,
            "evidence_ids": list(self.evidence_ids),
            "event_sequence": self.event_sequence,
            "materiality": self.materiality,
            "model_id": self.model_id,
            "primary_graph_digest": self.primary_graph_digest,
            "primary_model_id": self.primary_model_id,
            "scope_ids": list(self.scope_ids),
            "shadow_graph_digest": self.shadow_graph_digest,
            "structural_difference_receipt": self.structural_difference_receipt.to_json_value(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "authorization_digest": self.authorization_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


@dataclass(frozen=True, slots=True)
class GovernedAlternativeModelAdmitResult:
    """Output of a governed alternative-model ADMIT append.

    Mechanically validates event/head/root/projected/authorization consistency.
    Fully constructed and validated BEFORE the ``os.replace`` commit point.
    """

    event: Any  # RegistryEvent — typed as Any to avoid circular import
    head: RegistryEntityHead
    applied: bool
    reason: str
    alternative_model_registry_root: str
    projected: AlternativeModel
    authorization: GovernedAlternativeModelAuthorization

    def __post_init__(self) -> None:
        if type(self.event) is not RegistryEvent:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_EVENT_TYPE_INVALID")
        if type(self.head) is not RegistryEntityHead:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_HEAD_TYPE_INVALID")
        if type(self.projected) is not AlternativeModel:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_PROJECTED_TYPE_INVALID"
            )
        if type(self.authorization) is not GovernedAlternativeModelAuthorization:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_AUTH_TYPE_INVALID")
        if type(self.applied) is not bool:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_APPLIED_NOT_BOOL")
        if type(self.reason) is not str:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_REASON_INVALID")
        if self.reason not in ("APPENDED", "IDEMPOTENT_APPEND"):
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_REASON_INVALID")
        _require_digest(
            self.alternative_model_registry_root,
            "GOVERNED_ALT_MODEL_RESULT_ROOT_INVALID",
        )

        value = self.event.to_json_value()
        # Event binding.
        if value["registry_type"] != "ALTERNATIVE_MODEL":
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_EVENT_TYPE_MISMATCH")
        if value["entity_id"] != self.authorization.model_id:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_EVENT_ID_MISMATCH")
        if value["entity_sequence"] != 2:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_EVENT_SEQUENCE_MISMATCH"
            )
        if (
            value["previous_entity_event_digest"]
            != self.authorization.candidate_predecessor_event_digest
        ):
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_EVENT_PREDECESSOR_MISMATCH"
            )
        if value["clock_sequence"] != self.authorization.event_sequence:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_EVENT_CLOCK_MISMATCH"
            )
        if value["source_receipt_digest"] != self.authorization.authorization_digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_EVENT_SOURCE_RECEIPT_MISMATCH"
            )

        payload = value["payload"]
        if type(payload) is not dict:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_PAYLOAD_INVALID")
        if payload.get("operation") != "ADMIT":
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_OPERATION_MISMATCH")
        if payload.get("admitting_authority_id") != self.authorization.admitting_authority_id:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_AUTHORITY_MISMATCH")

        # Head binding.
        if self.head.registry_type != "ALTERNATIVE_MODEL":
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_HEAD_TYPE_MISMATCH")
        if self.head.entity_id != self.authorization.model_id:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_HEAD_ID_MISMATCH")
        if self.head.entity_sequence != 2:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_HEAD_SEQUENCE_MISMATCH"
            )
        if self.head.event_digest != self.event.digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_HEAD_DIGEST_MISMATCH"
            )

        # Projected binding.
        if self.projected.separation_status != STANDING_UNVERIFIED:
            raise AssumptionGovernanceContractError("GOVERNED_ALT_MODEL_RESULT_NOT_UNVERIFIED")
        if self.projected.admitting_authority_id != self.authorization.admitting_authority_id:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_PROJECTED_AUTHORITY_MISMATCH"
            )
        if self.projected.current_event_digest != self.event.digest:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_PROJECTED_DIGEST_MISMATCH"
            )
        if self.projected.current_entity_sequence != 2:
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_PROJECTED_SEQUENCE_MISMATCH"
            )

        # applied/reason consistency.
        if self.applied and self.reason != "APPENDED":
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_APPLIED_REASON_MISMATCH"
            )
        if not self.applied and self.reason != "IDEMPOTENT_APPEND":
            raise AssumptionGovernanceContractError(
                "GOVERNED_ALT_MODEL_RESULT_NOT_APPLIED_REASON_MISMATCH"
            )


def _build_admit_event(
    authorization: GovernedAlternativeModelAuthorization,
) -> RegistryEvent:
    """Build the exact ADMIT RegistryEvent from the authorization."""
    return build_alternative_model_event(
        model_id=authorization.model_id,
        entity_sequence=2,
        previous_entity_event_digest=authorization.candidate_predecessor_event_digest,
        clock_sequence=authorization.event_sequence,
        source_receipt_digest=authorization.authorization_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": authorization.admitting_authority_id,
        },
    )


def _compute_predicted_post_root(
    view: LockedRegistryView,
    model_id: str,
    predicted_head: RegistryEntityHead,
) -> str:
    """Compute the predicted post-append alternative-model root from the locked snapshot."""
    snap = view.snapshot("ALTERNATIVE_MODEL")
    heads = list(snap.heads)
    new_heads: list[RegistryEntityHead] = []
    replaced = False
    for head in heads:
        if head.entity_id == model_id:
            new_heads.append(predicted_head)
            replaced = True
        else:
            new_heads.append(head)
    if not replaced:
        new_heads.append(predicted_head)
    new_heads.sort(key=lambda item: item.entity_id)
    return _snapshot_root("ALTERNATIVE_MODEL", tuple(new_heads))


def append_governed_alternative_model_admit(
    *,
    store: GovernedRegistryStore,
    model_id: str,
    structural_difference_receipt: StructuralDifferenceReceipt,
    admitting_authority_id: str,
    event_sequence: int,
    retry_authorization: GovernedAlternativeModelAuthorization | None = None,
) -> GovernedAlternativeModelAdmitResult:
    """Atomically append one governed ADMIT event for a PROPOSED alternative model.

    The entire operation runs under one registry lock via ``store.locked_view()``.
    The structural-difference receipt is cross-validated against the model's
    shadow graph and declared difference digest. All semantic work and result
    construction completes before the ``os.replace`` commit point.

    Raises:
        GovernedAlternativeModelError: on semantic denial, stale state, retry
            mismatch, or internal conflict.
        RegistryStoreError: on commit durability uncertainty or locked-view
            violation.
    """
    if type(model_id) is not str or not model_id:
        raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_MODEL_ID_INVALID")
    if type(structural_difference_receipt) is not StructuralDifferenceReceipt:
        raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_RECEIPT_TYPE_INVALID")
    if type(admitting_authority_id) is not str or not admitting_authority_id:
        raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_AUTHORITY_INVALID")
    if type(event_sequence) is not int or isinstance(event_sequence, bool) or event_sequence < 1:
        raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_EVENT_SEQUENCE_INVALID")
    if (
        retry_authorization is not None
        and type(retry_authorization) is not GovernedAlternativeModelAuthorization
    ):
        raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_AUTHORIZATION_INVALID")

    with store.locked_view() as view:
        # --- Read current candidate head ---
        current_head = view.entity_head("ALTERNATIVE_MODEL", model_id)

        # --- Exact retry check (before PROPOSED requirement) ---
        if current_head is not None and current_head.entity_sequence == 2:
            existing_head_event = view.get_event(current_head.event_digest)
            if existing_head_event is not None:
                existing_payload = existing_head_event.to_json_value().get("payload")
                if type(existing_payload) is dict and existing_payload.get("operation") == "ADMIT":
                    if retry_authorization is not None:
                        return _handle_retry(
                            view,
                            model_id,
                            admitting_authority_id,
                            event_sequence,
                            retry_authorization,
                            current_head,
                            structural_difference_receipt,
                        )
                    raise GovernedAlternativeModelError(
                        "GOVERNED_ALT_MODEL_ALREADY_ADMITTED", detail=model_id
                    )

        # --- Reconstruct PROPOSE ---
        candidate_history = view.reconstruct_entity("ALTERNATIVE_MODEL", model_id)
        if not candidate_history:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_NOT_PROPOSED", detail="no history"
            )
        try:
            propose_state = project_alternative_model_history(candidate_history)
        except AlternativeModelRegistryError as exc:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_NOT_PROPOSED", detail=str(exc)
            ) from exc
        if propose_state is None:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_NOT_PROPOSED", detail="empty projection"
            )
        if (
            propose_state.separation_status != STANDING_PROPOSED
            or propose_state.current_entity_sequence != 1
        ):
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_NOT_PROPOSED",
                detail=(
                    f"standing={propose_state.standing} seq={propose_state.current_entity_sequence}"
                ),
            )
        if event_sequence <= propose_state.last_clock_sequence:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_NOT_PROPOSED",
                detail=(
                    f"event_sequence={event_sequence} <= clock={propose_state.last_clock_sequence}"
                ),
            )

        # --- Capture root ---
        alt_model_root = view.snapshot_root("ALTERNATIVE_MODEL")

        # --- Cross-validate structural-difference receipt against the model ---
        receipt = structural_difference_receipt
        if not receipt.has_material_difference:
            raise GovernedAlternativeModelError("GOVERNED_ALT_MODEL_NO_MATERIAL_DIFFERENCE")
        if receipt.shadow_graph_digest != propose_state.graph_digest:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_SHADOW_GRAPH_MISMATCH",
                detail="receipt shadow digest != model graph digest",
            )
        if receipt.declared_difference_digest != propose_state.declared_difference_digest:
            raise GovernedAlternativeModelError(
                "GOVERNED_ALT_MODEL_DECLARED_DIFFERENCE_MISMATCH",
                detail="receipt declared digest != model declared digest",
            )

        # --- Build authorization ---
        unsigned_auth = {
            "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
            "admitting_authority_id": admitting_authority_id,
            "alternative_model_registry_root": alt_model_root,
            "assumption_ids": list(propose_state.assumption_ids),
            "candidate_entity_sequence": 2,
            "candidate_predecessor_event_digest": propose_state.current_event_digest,
            "evidence_ids": list(propose_state.evidence_ids),
            "event_sequence": event_sequence,
            "materiality": propose_state.materiality,
            "model_id": model_id,
            "primary_graph_digest": receipt.primary_graph_digest,
            "primary_model_id": propose_state.primary_model_id,
            "scope_ids": list(propose_state.scope_ids),
            "shadow_graph_digest": receipt.shadow_graph_digest,
            "structural_difference_receipt": receipt.to_json_value(),
        }
        authorization = GovernedAlternativeModelAuthorization(
            model_id=model_id,
            candidate_predecessor_event_digest=propose_state.current_event_digest,
            candidate_entity_sequence=2,
            event_sequence=event_sequence,
            admitting_authority_id=admitting_authority_id,
            alternative_model_registry_root=alt_model_root,
            structural_difference_receipt=receipt,
            primary_model_id=propose_state.primary_model_id,
            primary_graph_digest=receipt.primary_graph_digest,
            shadow_graph_digest=receipt.shadow_graph_digest,
            scope_ids=propose_state.scope_ids,
            materiality=propose_state.materiality,
            assumption_ids=propose_state.assumption_ids,
            evidence_ids=propose_state.evidence_ids,
            authorization_digest=_domain_digest(_AUTHORIZATION_DOMAIN, unsigned_auth),
        )

        # --- Build ADMIT event ---
        event = _build_admit_event(authorization)

        # --- Project UNVERIFIED state ---
        projected = reduce_alternative_model(propose_state, event)

        # --- Predict head + post-root ---
        predicted_head = RegistryEntityHead(
            "ALTERNATIVE_MODEL",
            model_id,
            2,
            event.digest,
        )
        predicted_post_root = _compute_predicted_post_root(view, model_id, predicted_head)

        # --- Construct + validate result (BEFORE commit) ---
        result = GovernedAlternativeModelAdmitResult(
            event=event,
            head=predicted_head,
            applied=True,
            reason="APPENDED",
            alternative_model_registry_root=predicted_post_root,
            projected=projected,
            authorization=authorization,
        )

        # --- Commit ---
        view._commit_prepared(
            event=event,
            expected_current_head=current_head,
            predicted_head=predicted_head,
        )

        return result


def _handle_retry(
    view: LockedRegistryView,
    model_id: str,
    admitting_authority_id: str,
    event_sequence: int,
    retry_auth: GovernedAlternativeModelAuthorization,
    current_head: RegistryEntityHead,
    structural_difference_receipt: StructuralDifferenceReceipt,
) -> GovernedAlternativeModelAdmitResult:
    """Handle exact snapshot-equivalent retry for an already-committed ADMIT."""
    if retry_auth.model_id != model_id:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="model_id"
        )
    if retry_auth.admitting_authority_id != admitting_authority_id:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="authority_id"
        )
    if retry_auth.event_sequence != event_sequence:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="event_sequence"
        )
    # The separately supplied structural-difference receipt must equal the one
    # bound inside the retry authorization (it is otherwise ignored on retry).
    if (
        structural_difference_receipt.receipt_digest
        != retry_auth.structural_difference_receipt.receipt_digest
    ):
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="structural_difference_receipt"
        )

    existing_event = view.get_event(current_head.event_digest)
    if existing_event is None:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="event missing"
        )
    rebuilt_event = _build_admit_event(retry_auth)
    if rebuilt_event.canonical_bytes != existing_event.canonical_bytes:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="event bytes"
        )
    if rebuilt_event.digest != current_head.event_digest:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="digest"
        )

    # Reconstruct hypothetical pre-root for snapshot-equivalence proof: replace
    # the model's current seq-2 head with its seq-1 predecessor and recompute.
    # The authorization binds the PRE-admit root; the hypothetical pre-root must
    # equal it for the retry to be snapshot-equivalent.
    snap = view.snapshot("ALTERNATIVE_MODEL")
    heads = list(snap.heads)
    existing_value = existing_event.to_json_value()
    predecessor_digest = existing_value["previous_entity_event_digest"]
    if predecessor_digest is None:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="no predecessor"
        )
    predecessor_head = RegistryEntityHead(
        "ALTERNATIVE_MODEL", model_id, 1, cast(str, predecessor_digest)
    )
    new_heads: list[RegistryEntityHead] = []
    for head in heads:
        if head.entity_id == model_id:
            new_heads.append(predecessor_head)
        else:
            new_heads.append(head)
    new_heads.sort(key=lambda item: item.entity_id)
    hypothetical_pre_root = _snapshot_root("ALTERNATIVE_MODEL", tuple(new_heads))
    if hypothetical_pre_root != retry_auth.alternative_model_registry_root:
        raise GovernedAlternativeModelError(
            "GOVERNED_ALT_MODEL_RETRY_SNAPSHOT_MISMATCH", detail="pre-root"
        )

    projected = reduce_alternative_model(
        project_alternative_model_history(
            view.reconstruct_entity("ALTERNATIVE_MODEL", model_id)[:1]
        ),
        existing_event,
    )
    return GovernedAlternativeModelAdmitResult(
        event=existing_event,
        head=current_head,
        applied=False,
        reason="IDEMPOTENT_APPEND",
        alternative_model_registry_root=snap.root_digest,
        projected=projected,
        authorization=retry_auth,
    )


# --------------------------------------------------------------------------- #
# D. Replay executor protocol + receipt
# --------------------------------------------------------------------------- #


class AlternativeModelReplayExecutor(Protocol):
    """Protocol for injecting a deterministic alternative-model graph replay."""

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
        """Replay one model graph and return a self-digesting FULL_REPLAY receipt.

        Implementations MUST execute exactly the ``required_inventory`` and
        raise (rather than return a partial receipt) when the replay cannot
        fully execute the required inventory.
        """
        ...


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """Self-digesting FULL_REPLAY receipt for one alternative-model graph.

    Mechanically proves the replay executed exactly the required inventory with
    nothing skipped or pruned. The semantic outcome digest is the replay's
    deterministic result, used by the comparison layer to classify INVARIANT
    vs DIVERGENT pairs.
    """

    graph_digest: str
    decision_context_digest: str
    initial_state_digest: str
    logical_clock: int
    runner_revision: str
    required_inventory: tuple[str, ...]
    executed_inventory: tuple[str, ...]
    skipped_inventory: tuple[str, ...]
    pruned_inventory: tuple[str, ...]
    semantic_outcome_digest: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.graph_digest, "REPLAY_RECEIPT_GRAPH_DIGEST_INVALID")
        _require_digest(self.decision_context_digest, "REPLAY_RECEIPT_DECISION_CONTEXT_INVALID")
        _require_digest(self.initial_state_digest, "REPLAY_RECEIPT_INITIAL_STATE_INVALID")
        _require_digest(self.semantic_outcome_digest, "REPLAY_RECEIPT_SEMANTIC_OUTCOME_INVALID")
        if (
            type(self.logical_clock) is not int
            or isinstance(self.logical_clock, bool)
            or self.logical_clock < 1
        ):
            raise AssumptionGovernanceContractError("REPLAY_RECEIPT_LOGICAL_CLOCK_INVALID")
        _require_token(self.runner_revision, "REPLAY_RECEIPT_RUNNER_REVISION_INVALID")
        required = _require_canonical_tokens(
            self.required_inventory,
            "REPLAY_RECEIPT_REQUIRED_INVENTORY_INVALID",
            allow_empty=True,
        )
        executed = _require_canonical_tokens(
            self.executed_inventory,
            "REPLAY_RECEIPT_EXECUTED_INVENTORY_INVALID",
            allow_empty=True,
        )
        skipped = _require_canonical_tokens(
            self.skipped_inventory,
            "REPLAY_RECEIPT_SKIPPED_INVENTORY_INVALID",
            allow_empty=True,
        )
        pruned = _require_canonical_tokens(
            self.pruned_inventory,
            "REPLAY_RECEIPT_PRUNED_INVENTORY_INVALID",
            allow_empty=True,
        )

        # FULL_REPLAY invariants.
        if executed != required:
            raise AssumptionGovernanceContractError("REPLAY_RECEIPT_NOT_FULLY_EXECUTED")
        if skipped != ():
            raise AssumptionGovernanceContractError("REPLAY_RECEIPT_SKIPPED_NONEMPTY")
        if pruned != ():
            raise AssumptionGovernanceContractError("REPLAY_RECEIPT_PRUNED_NONEMPTY")

        # Self-digest.
        _require_self_digest(
            _REPLAY_RECEIPT_DOMAIN,
            self._unsigned_value(),
            self.receipt_digest,
            "REPLAY_RECEIPT_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _REPLAY_RECEIPT_SCHEMA_VERSION,
            "graph_digest": self.graph_digest,
            "decision_context_digest": self.decision_context_digest,
            "initial_state_digest": self.initial_state_digest,
            "logical_clock": self.logical_clock,
            "runner_revision": self.runner_revision,
            "required_inventory": list(self.required_inventory),
            "executed_inventory": list(self.executed_inventory),
            "skipped_inventory": list(self.skipped_inventory),
            "pruned_inventory": list(self.pruned_inventory),
            "semantic_outcome_digest": self.semantic_outcome_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "receipt_digest": self.receipt_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


# --------------------------------------------------------------------------- #
# E. Canonical comparison
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ComparisonReceipt:
    """Self-digesting canonical comparison of a primary replay vs a shadow replay.

    Both replays must bind identical decision context (context digest, initial
    state, logical clock, runner revision, required inventory) and must bind
    the graph digests carried by the structural-difference receipt. The
    comparison result is INVARIANT iff the two semantic outcome digests are
    equal, DIVERGENT otherwise.
    """

    primary_replay_receipt: ReplayReceipt
    shadow_replay_receipt: ReplayReceipt
    structural_difference_receipt: StructuralDifferenceReceipt
    comparison_result: str
    comparison_digest: str

    def __post_init__(self) -> None:
        if type(self.primary_replay_receipt) is not ReplayReceipt:
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_PRIMARY_REPLAY_TYPE_INVALID"
            )
        if type(self.shadow_replay_receipt) is not ReplayReceipt:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_SHADOW_REPLAY_TYPE_INVALID")
        if type(self.structural_difference_receipt) is not StructuralDifferenceReceipt:
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_DIFFERENCE_RECEIPT_TYPE_INVALID"
            )
        if type(self.comparison_result) is not str:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_RESULT_TYPE_INVALID")

        primary = self.primary_replay_receipt
        shadow = self.shadow_replay_receipt
        diff = self.structural_difference_receipt

        # Identical decision context binding.
        if primary.decision_context_digest != shadow.decision_context_digest:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_DECISION_CONTEXT_MISMATCH")
        if primary.initial_state_digest != shadow.initial_state_digest:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_INITIAL_STATE_MISMATCH")
        if primary.logical_clock != shadow.logical_clock:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_LOGICAL_CLOCK_MISMATCH")
        if primary.runner_revision != shadow.runner_revision:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_RUNNER_REVISION_MISMATCH")
        if primary.required_inventory != shadow.required_inventory:
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_REQUIRED_INVENTORY_MISMATCH"
            )

        # Graph binding to the structural-difference receipt.
        if primary.graph_digest != diff.primary_graph_digest:
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_PRIMARY_GRAPH_BINDING_MISMATCH"
            )
        if shadow.graph_digest != diff.shadow_graph_digest:
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_SHADOW_GRAPH_BINDING_MISMATCH"
            )

        # Result classification.
        if primary.semantic_outcome_digest == shadow.semantic_outcome_digest:
            expected_result = "INVARIANT"
        else:
            expected_result = "DIVERGENT"
        if self.comparison_result not in ("INVARIANT", "DIVERGENT"):
            raise AssumptionGovernanceContractError(
                "COMPARISON_RECEIPT_RESULT_INVALID", self.comparison_result
            )
        if self.comparison_result != expected_result:
            raise AssumptionGovernanceContractError("COMPARISON_RECEIPT_RESULT_MISMATCH")

        # Self-digest.
        _require_self_digest(
            _COMPARISON_RECEIPT_DOMAIN,
            self._unsigned_value(),
            self.comparison_digest,
            "COMPARISON_RECEIPT_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _COMPARISON_RECEIPT_SCHEMA_VERSION,
            "primary_replay_receipt": self.primary_replay_receipt.to_json_value(),
            "shadow_replay_receipt": self.shadow_replay_receipt.to_json_value(),
            "structural_difference_receipt": self.structural_difference_receipt.to_json_value(),
            "comparison_result": self.comparison_result,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "comparison_digest": self.comparison_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def compare_alternative_model_replays(
    *,
    structural_difference_receipt: StructuralDifferenceReceipt,
    primary_replay_receipt: ReplayReceipt,
    shadow_replay_receipt: ReplayReceipt,
) -> ComparisonReceipt:
    """Construct a canonical comparison receipt for a primary/shadow replay pair.

    Validates the two replays bind identical decision context and bind the
    structural-difference receipt's graph digests, then classifies the pair
    as INVARIANT or DIVERGENT.
    """
    if (
        primary_replay_receipt.semantic_outcome_digest
        == shadow_replay_receipt.semantic_outcome_digest
    ):
        comparison_result = "INVARIANT"
    else:
        comparison_result = "DIVERGENT"
    unsigned = {
        "schema_version": _COMPARISON_RECEIPT_SCHEMA_VERSION,
        "primary_replay_receipt": primary_replay_receipt.to_json_value(),
        "shadow_replay_receipt": shadow_replay_receipt.to_json_value(),
        "structural_difference_receipt": structural_difference_receipt.to_json_value(),
        "comparison_result": comparison_result,
    }
    comparison_digest = _domain_digest(_COMPARISON_RECEIPT_DOMAIN, unsigned)
    return ComparisonReceipt(
        primary_replay_receipt=primary_replay_receipt,
        shadow_replay_receipt=shadow_replay_receipt,
        structural_difference_receipt=structural_difference_receipt,
        comparison_result=comparison_result,
        comparison_digest=comparison_digest,
    )


def _bind_replay_receipt(
    receipt: ReplayReceipt,
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    logical_clock: int,
    runner_revision: str,
    required_inventory: tuple[str, ...],
) -> None:
    """Exact-type and cross-bind every replay receipt field to its invocation args.

    Defends against an injected executor returning a receipt whose fields do not
    match the arguments it was invoked with.
    """
    if type(receipt) is not ReplayReceipt:
        raise AssumptionGovernanceContractError("FULL_REPLAY_RECEIPT_TYPE_INVALID")
    if receipt.graph_digest != graph_digest:
        raise AssumptionGovernanceContractError("FULL_REPLAY_GRAPH_DIGEST_BINDING_MISMATCH")
    if receipt.decision_context_digest != decision_context_digest:
        raise AssumptionGovernanceContractError("FULL_REPLAY_DECISION_CONTEXT_BINDING_MISMATCH")
    if receipt.initial_state_digest != initial_state_digest:
        raise AssumptionGovernanceContractError("FULL_REPLAY_INITIAL_STATE_BINDING_MISMATCH")
    if receipt.logical_clock != logical_clock:
        raise AssumptionGovernanceContractError("FULL_REPLAY_LOGICAL_CLOCK_BINDING_MISMATCH")
    if receipt.runner_revision != runner_revision:
        raise AssumptionGovernanceContractError("FULL_REPLAY_RUNNER_REVISION_BINDING_MISMATCH")
    if receipt.required_inventory != required_inventory:
        raise AssumptionGovernanceContractError("FULL_REPLAY_REQUIRED_INVENTORY_BINDING_MISMATCH")


def run_full_replay_comparison(
    *,
    executor: AlternativeModelReplayExecutor,
    structural_difference_receipt: StructuralDifferenceReceipt,
    primary_graph_bytes: bytes,
    shadow_graph_bytes: bytes,
    decision_context_digest: str,
    initial_state_digest: str,
    logical_clock: int,
    runner_revision: str,
    required_inventory: tuple[str, ...],
) -> ComparisonReceipt:
    """Production FULL_REPLAY orchestration: replay both graphs and compare.

    Canonicalizes both graph byte strings, verifies both graph digests against
    the structural-difference receipt, invokes the injected executor for the
    primary and shadow graphs under identical decision context, exact-type and
    cross-binds every returned receipt field to its invocation arguments,
    validates the FULL_REPLAY invariants (executed == required, nothing skipped
    or pruned), then constructs and returns the canonical comparison receipt.
    """
    if type(structural_difference_receipt) is not StructuralDifferenceReceipt:
        raise AssumptionGovernanceContractError("FULL_REPLAY_DIFFERENCE_RECEIPT_TYPE_INVALID")
    _require_digest(decision_context_digest, "FULL_REPLAY_DECISION_CONTEXT_INVALID")
    _require_digest(initial_state_digest, "FULL_REPLAY_INITIAL_STATE_INVALID")
    if type(logical_clock) is not int or isinstance(logical_clock, bool) or logical_clock < 1:
        raise AssumptionGovernanceContractError("FULL_REPLAY_LOGICAL_CLOCK_INVALID")
    _require_token(runner_revision, "FULL_REPLAY_RUNNER_REVISION_INVALID")
    required = _require_canonical_tokens(
        required_inventory, "FULL_REPLAY_REQUIRED_INVENTORY_INVALID", allow_empty=True
    )

    # Canonicalize both graph byte strings.
    primary_canon = _canonical_graph_bytes(primary_graph_bytes)
    shadow_canon = _canonical_graph_bytes(shadow_graph_bytes)

    # Verify both graph digests against the structural-difference receipt.
    if _graph_digest_of(primary_canon) != structural_difference_receipt.primary_graph_digest:
        raise AssumptionGovernanceContractError("FULL_REPLAY_PRIMARY_GRAPH_DIGEST_MISMATCH")
    if _graph_digest_of(shadow_canon) != structural_difference_receipt.shadow_graph_digest:
        raise AssumptionGovernanceContractError("FULL_REPLAY_SHADOW_GRAPH_DIGEST_MISMATCH")

    # Invoke the executor for the primary graph.
    primary_replay = executor.replay(
        graph_bytes=primary_canon,
        graph_digest=structural_difference_receipt.primary_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required,
    )
    _bind_replay_receipt(
        primary_replay,
        graph_digest=structural_difference_receipt.primary_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required,
    )

    # Invoke the executor for the shadow graph (identical context except graph).
    shadow_replay = executor.replay(
        graph_bytes=shadow_canon,
        graph_digest=structural_difference_receipt.shadow_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required,
    )
    _bind_replay_receipt(
        shadow_replay,
        graph_digest=structural_difference_receipt.shadow_graph_digest,
        decision_context_digest=decision_context_digest,
        initial_state_digest=initial_state_digest,
        logical_clock=logical_clock,
        runner_revision=runner_revision,
        required_inventory=required,
    )

    # Validate FULL_REPLAY invariants on both receipts.
    for receipt in (primary_replay, shadow_replay):
        if receipt.executed_inventory != required:
            raise AssumptionGovernanceContractError("FULL_REPLAY_NOT_FULLY_EXECUTED")
        if receipt.skipped_inventory != ():
            raise AssumptionGovernanceContractError("FULL_REPLAY_SKIPPED_NONEMPTY")
        if receipt.pruned_inventory != ():
            raise AssumptionGovernanceContractError("FULL_REPLAY_PRUNED_NONEMPTY")

    return compare_alternative_model_replays(
        structural_difference_receipt=structural_difference_receipt,
        primary_replay_receipt=primary_replay,
        shadow_replay_receipt=shadow_replay,
    )


# --------------------------------------------------------------------------- #
# F. Use-time authority gate
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class UseAuthorityDecision:
    """Self-digesting use-time authority decision for one alternative model.

    Records the decision context (model identity, logical clock, scope,
    required reuse class) and the model's admissibility state, with the final
    ALLOW/DENY result and a stable reason code.
    """

    model_id: str
    logical_clock: int
    scope_id: str
    required_reuse_class: str
    maximum_reuse_class: str
    separation_status: str
    expires_at_sequence: int | None
    decision: str
    reason_code: str
    decision_digest: str

    def __post_init__(self) -> None:
        _require_token(self.model_id, "USE_AUTHORITY_MODEL_ID_INVALID")
        if (
            type(self.logical_clock) is not int
            or isinstance(self.logical_clock, bool)
            or self.logical_clock < 1
        ):
            raise AssumptionGovernanceContractError("USE_AUTHORITY_LOGICAL_CLOCK_INVALID")
        _require_token(self.scope_id, "USE_AUTHORITY_SCOPE_ID_INVALID")
        if self.required_reuse_class not in _REUSE_CLASSES:
            raise AssumptionGovernanceContractError("USE_AUTHORITY_REQUIRED_REUSE_CLASS_INVALID")
        if self.maximum_reuse_class not in _REUSE_CLASSES:
            raise AssumptionGovernanceContractError("USE_AUTHORITY_MAXIMUM_REUSE_CLASS_INVALID")
        if type(self.separation_status) is not str or not self.separation_status:
            raise AssumptionGovernanceContractError("USE_AUTHORITY_SEPARATION_STATUS_INVALID")
        if self.expires_at_sequence is not None and (
            type(self.expires_at_sequence) is not int
            or isinstance(self.expires_at_sequence, bool)
            or self.expires_at_sequence < 1
        ):
            raise AssumptionGovernanceContractError("USE_AUTHORITY_EXPIRES_INVALID")
        if self.decision not in ("ALLOW", "DENY"):
            raise AssumptionGovernanceContractError("USE_AUTHORITY_DECISION_INVALID")
        _require_token(self.reason_code, "USE_AUTHORITY_REASON_CODE_INVALID")

        _require_self_digest(
            _USE_AUTHORITY_DECISION_DOMAIN,
            self._unsigned_value(),
            self.decision_digest,
            "USE_AUTHORITY_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": _USE_AUTHORITY_DECISION_SCHEMA_VERSION,
            "model_id": self.model_id,
            "logical_clock": self.logical_clock,
            "scope_id": self.scope_id,
            "required_reuse_class": self.required_reuse_class,
            "maximum_reuse_class": self.maximum_reuse_class,
            "separation_status": self.separation_status,
            "expires_at_sequence": self.expires_at_sequence,
            "decision": self.decision,
            "reason_code": self.reason_code,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "decision_digest": self.decision_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return _json_bytes(self.to_json_value())


def evaluate_alternative_model_use_authority(
    *,
    model: AlternativeModel,
    logical_clock: int,
    scope_id: str,
    required_reuse_class: str,
) -> UseAuthorityDecision:
    """Decide whether an alternative model may be reused at use time.

    Returns ALLOW only when the model is in an admissible standing (ADMITTED or
    CONFIRMED, with no active challenges), not expired at the requested logical
    clock, in scope, and the required reuse class does not exceed the model's
    maximum reuse class. Every other condition returns DENY with a stable
    reason code. UNVERIFIED, terminal, and not-yet-admitted models are always
    denied.
    """
    if type(model) is not AlternativeModel:
        raise AssumptionGovernanceContractError("USE_AUTHORITY_MODEL_TYPE_INVALID")
    if type(logical_clock) is not int or isinstance(logical_clock, bool) or logical_clock < 1:
        raise AssumptionGovernanceContractError("USE_AUTHORITY_LOGICAL_CLOCK_INVALID")
    if type(scope_id) is not str or not scope_id:
        raise AssumptionGovernanceContractError("USE_AUTHORITY_SCOPE_ID_INVALID")
    if required_reuse_class not in _REUSE_CLASSES:
        raise AssumptionGovernanceContractError("USE_AUTHORITY_REQUIRED_REUSE_CLASS_INVALID")

    standing = model.standing

    if standing == STANDING_UNVERIFIED:
        decision = "DENY"
        reason_code = "USE_DENIED_UNVERIFIED"
    elif model.terminal:
        decision = "DENY"
        reason_code = "USE_DENIED_TERMINAL"
    elif standing not in _USABLE_STANDINGS:
        decision = "DENY"
        reason_code = "USE_DENIED_NOT_ADMISSIBLE"
    elif model.expires_at_sequence is not None and logical_clock >= model.expires_at_sequence:
        decision = "DENY"
        reason_code = "USE_DENIED_EXPIRED"
    elif scope_id not in model.scope_ids:
        decision = "DENY"
        reason_code = "USE_DENIED_SCOPE"
    elif _REUSE_CLASS_RANK[required_reuse_class] > _REUSE_CLASS_RANK[model.maximum_reuse_class]:
        decision = "DENY"
        reason_code = "USE_DENIED_REUSE_CLASS"
    else:
        decision = "ALLOW"
        reason_code = "USE_ALLOWED"

    unsigned = {
        "schema_version": _USE_AUTHORITY_DECISION_SCHEMA_VERSION,
        "model_id": model.model_id,
        "logical_clock": logical_clock,
        "scope_id": scope_id,
        "required_reuse_class": required_reuse_class,
        "maximum_reuse_class": model.maximum_reuse_class,
        "separation_status": model.separation_status,
        "expires_at_sequence": model.expires_at_sequence,
        "decision": decision,
        "reason_code": reason_code,
    }
    decision_digest = _domain_digest(_USE_AUTHORITY_DECISION_DOMAIN, unsigned)
    return UseAuthorityDecision(
        model_id=model.model_id,
        logical_clock=logical_clock,
        scope_id=scope_id,
        required_reuse_class=required_reuse_class,
        maximum_reuse_class=model.maximum_reuse_class,
        separation_status=model.separation_status,
        expires_at_sequence=model.expires_at_sequence,
        decision=decision,
        reason_code=reason_code,
        decision_digest=decision_digest,
    )


__all__ = [
    "AlternativeModelReplayExecutor",
    "ComparisonReceipt",
    "GovernedAlternativeModelAdmitResult",
    "GovernedAlternativeModelAuthorization",
    "GovernedAlternativeModelError",
    "ReplayReceipt",
    "StructuralDifferenceReceipt",
    "UseAuthorityDecision",
    "append_governed_alternative_model_admit",
    "compare_alternative_model_replays",
    "compute_structural_difference_digest",
    "detect_structural_difference",
    "evaluate_alternative_model_use_authority",
    "run_full_replay_comparison",
]
