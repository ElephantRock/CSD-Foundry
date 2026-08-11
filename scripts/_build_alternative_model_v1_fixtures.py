"""Generate the v0.5-D4 alternative-model-v1 conformance corpus (one-shot build helper).

Uses production code (alternative_model.py + _governed_alternative_model.py) to
construct valid event envelopes and structural-difference / replay / comparison
receipts, then computes expected registry roots / authorization digests / use-
authority decision digests with an INDEPENDENT re-implementation baked into this
script. The committed fixtures therefore pin values that the independent
validator (alternative_model_validation.py) re-derives and checks.

Run: python scripts/_build_alternative_model_v1_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from csd_foundry.governance.v0_5.alternative_model import build_alternative_model_event
from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.contracts import RegistryEvent

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data/canary/v0.5/alternative-model-v1"

SCOPE = "scope:17"

# Schema versions and domain strings (mirror the validator + production exactly).
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

_DIFFERENCE_FAMILIES_ORDER = (
    "ADDED_REMOVED",
    "AUTHORITY",
    "EVIDENCE_ADMISSION",
    "RELABELED",
    "SCOPE",
    "TEMPORAL",
)


# =====================================================================
# Independent digest helpers (must mirror alternative_model_validation.py exactly).
# =====================================================================


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _domain_digest(domain: str, value: object) -> str:
    return (
        "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + _json_bytes(value)).hexdigest()
    )


def _receipt(label: str) -> str:
    return "sha256:" + hashlib.sha256(b"receipt\0" + label.encode("utf-8")).hexdigest()


def _literal_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _snapshot_root(envelopes: list[dict[str, Any]]) -> str:
    heads: dict[str, dict[str, Any]] = {}
    for ev in envelopes:
        heads[ev["entity_id"]] = {
            "entity_id": ev["entity_id"],
            "entity_sequence": ev["entity_sequence"],
            "event_digest": ev["registry_event_digest"],
        }
    value = {
        "schema_version": "registry-snapshot/1",
        "registry_type": "ALTERNATIVE_MODEL",
        "heads": [heads[k] for k in sorted(heads)],
    }
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(b"REGISTRY_SNAPSHOT\0" + payload).hexdigest()


# =====================================================================
# Structural-difference detector (mirrors the validator exactly).
# =====================================================================


def _graph_digest_of(canonical_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()


def _canonical_graph(obj: dict[str, object]) -> bytes:
    return _json_bytes(obj)


def _classify_difference(path: str, *, present_both_sides: bool) -> str:
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
    return key.replace("~", "~0").replace("/", "~1")


def _collect_differences(
    primary: dict[str, Any],
    shadow: dict[str, Any],
    prefix: str,
    paths: list[str],
    families: list[str],
) -> None:
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


def _compute_difference_set(
    primary: dict[str, object],
    shadow: dict[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    paths: list[str] = []
    families: list[str] = []
    _collect_differences(primary, shadow, "", paths, families)
    return tuple(sorted(set(families))), tuple(sorted(set(paths)))


def _compute_difference_set_digest(
    difference_families: tuple[str, ...],
    difference_paths: tuple[str, ...],
) -> str:
    return _domain_digest(
        _STRUCTURAL_DIFFERENCE_SET_DOMAIN,
        {
            "difference_families": list(difference_families),
            "difference_paths": list(difference_paths),
        },
    )


def _build_structural_difference_receipt(
    primary: dict[str, object],
    shadow: dict[str, object],
) -> tuple[dict[str, Any], dict[str, object], dict[str, object]]:
    """Build a full structural-difference receipt + return the graph objects.

    Returns ``(receipt, primary_graph, shadow_graph)``.
    """
    primary_bytes = _canonical_graph(primary)
    shadow_bytes = _canonical_graph(shadow)
    primary_digest = _graph_digest_of(primary_bytes)
    shadow_digest = _graph_digest_of(shadow_bytes)
    families, paths = _compute_difference_set(primary, shadow)
    computed = _compute_difference_set_digest(families, paths)
    material = len(paths) > 0
    unsigned = {
        "schema_version": _STRUCTURAL_DIFFERENCE_SCHEMA_VERSION,
        "primary_graph_digest": primary_digest,
        "shadow_graph_digest": shadow_digest,
        "computed_difference_digest": computed,
        "declared_difference_digest": computed,
        "difference_families": list(families),
        "difference_paths": list(paths),
        "has_material_difference": material,
    }
    receipt_digest = _domain_digest(_STRUCTURAL_DIFFERENCE_RECEIPT_DOMAIN, unsigned)
    receipt = {**unsigned, "receipt_digest": receipt_digest}
    return receipt, primary, shadow


# =====================================================================
# Governed ADMIT authorization (mirrors the validator exactly).
# =====================================================================


def _authorization_digest(
    *,
    propose_event: dict[str, Any],
    admit_clock: int,
    admitting_authority_id: str,
    alt_model_root: str,
    receipt: dict[str, Any],
) -> str:
    """Independently recompute the GovernedAlternativeModelAuthorization digest."""
    payload = propose_event["payload"]
    unsigned = {
        "schema_version": _AUTHORIZATION_SCHEMA_VERSION,
        "admitting_authority_id": admitting_authority_id,
        "alternative_model_registry_root": alt_model_root,
        "assumption_ids": list(payload["assumption_ids"]),
        "candidate_entity_sequence": 2,
        "candidate_predecessor_event_digest": propose_event["registry_event_digest"],
        "evidence_ids": list(payload["evidence_ids"]),
        "event_sequence": admit_clock,
        "materiality": payload["materiality"],
        "model_id": propose_event["entity_id"],
        "primary_graph_digest": receipt["primary_graph_digest"],
        "primary_model_id": payload["primary_model_id"],
        "scope_ids": list(payload["scope_ids"]),
        "shadow_graph_digest": receipt["shadow_graph_digest"],
        "structural_difference_receipt": receipt,
    }
    return _domain_digest(_AUTHORIZATION_DOMAIN, unsigned)


# =====================================================================
# Replay + comparison receipt builders.
# =====================================================================


def _build_replay_receipt(
    *,
    graph_digest: str,
    decision_context_digest: str,
    initial_state_digest: str,
    logical_clock: int,
    runner_revision: str,
    required_inventory: tuple[str, ...],
    semantic_outcome_digest: str,
) -> dict[str, Any]:
    executed = required_inventory
    skipped: tuple[str, ...] = ()
    pruned: tuple[str, ...] = ()
    unsigned = {
        "schema_version": _REPLAY_RECEIPT_SCHEMA_VERSION,
        "graph_digest": graph_digest,
        "decision_context_digest": decision_context_digest,
        "initial_state_digest": initial_state_digest,
        "logical_clock": logical_clock,
        "runner_revision": runner_revision,
        "required_inventory": list(required_inventory),
        "executed_inventory": list(executed),
        "skipped_inventory": list(skipped),
        "pruned_inventory": list(pruned),
        "semantic_outcome_digest": semantic_outcome_digest,
    }
    receipt_digest = _domain_digest(_REPLAY_RECEIPT_DOMAIN, unsigned)
    return {**unsigned, "receipt_digest": receipt_digest}


def _build_comparison_receipt(
    *,
    primary_replay: dict[str, Any],
    shadow_replay: dict[str, Any],
    structural_difference_receipt: dict[str, Any],
) -> dict[str, Any]:
    if primary_replay["semantic_outcome_digest"] == shadow_replay["semantic_outcome_digest"]:
        comparison_result = "INVARIANT"
    else:
        comparison_result = "DIVERGENT"
    unsigned = {
        "schema_version": _COMPARISON_RECEIPT_SCHEMA_VERSION,
        "primary_replay_receipt": primary_replay,
        "shadow_replay_receipt": shadow_replay,
        "structural_difference_receipt": structural_difference_receipt,
        "comparison_result": comparison_result,
    }
    comparison_digest = _domain_digest(_COMPARISON_RECEIPT_DOMAIN, unsigned)
    return {**unsigned, "comparison_digest": comparison_digest}


# =====================================================================
# Use-authority decision digest (mirrors the validator exactly).
# =====================================================================

_REUSE_CLASS_RANK = {"D0": 0, "D1": 1, "D2": 2, "D3": 3, "BENCHMARK": 4}


def _use_authority_decision(
    *,
    model_id: str,
    logical_clock: int,
    scope_id: str,
    required_reuse_class: str,
    maximum_reuse_class: str,
    separation_status: str,
    expires_at_sequence: int | None,
    standing: str,
    terminal: bool,
) -> dict[str, Any]:
    if standing == "UNVERIFIED":
        decision = "DENY"
        reason_code = "USE_DENIED_UNVERIFIED"
    elif terminal:
        decision = "DENY"
        reason_code = "USE_DENIED_TERMINAL"
    elif standing not in ("ADMITTED", "CONFIRMED"):
        decision = "DENY"
        reason_code = "USE_DENIED_NOT_ADMISSIBLE"
    elif expires_at_sequence is not None and logical_clock >= expires_at_sequence:
        decision = "DENY"
        reason_code = "USE_DENIED_EXPIRED"
    elif scope_id != SCOPE:
        decision = "DENY"
        reason_code = "USE_DENIED_SCOPE"
    elif _REUSE_CLASS_RANK[required_reuse_class] > _REUSE_CLASS_RANK[maximum_reuse_class]:
        decision = "DENY"
        reason_code = "USE_DENIED_REUSE_CLASS"
    else:
        decision = "ALLOW"
        reason_code = "USE_ALLOWED"
    unsigned = {
        "schema_version": _USE_AUTHORITY_DECISION_SCHEMA_VERSION,
        "model_id": model_id,
        "logical_clock": logical_clock,
        "scope_id": scope_id,
        "required_reuse_class": required_reuse_class,
        "maximum_reuse_class": maximum_reuse_class,
        "separation_status": separation_status,
        "expires_at_sequence": expires_at_sequence,
        "decision": decision,
        "reason_code": reason_code,
    }
    decision_digest = _domain_digest(_USE_AUTHORITY_DECISION_DOMAIN, unsigned)
    return {
        "decision": decision,
        "reason_code": reason_code,
        "decision_digest": decision_digest,
    }


# =====================================================================
# Event construction.
# =====================================================================


def _propose_payload(
    *,
    model_version: str = "v1",
    primary_model_id: str = "model:primary",
    graph_digest: str,
    declared_difference_digest: str,
    challenge_basis_code: str = "basis:shadow-divergence",
    scope_ids: tuple[str, ...] = (SCOPE,),
    assumption_ids: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
    proposer: str = "authority:proposer",
    materiality: str = "MATERIAL",
    valid_from: int,
    expires_at: int | None,
    limitations: tuple[str, ...] = ("limitation:declared-model",),
    reuse: str = "D2",
) -> dict[str, object]:
    return {
        "operation": "PROPOSE",
        "model_version": model_version,
        "primary_model_id": primary_model_id,
        "graph_digest": graph_digest,
        "declared_difference_digest": declared_difference_digest,
        "challenge_basis_code": challenge_basis_code,
        "scope_ids": list(scope_ids),
        "assumption_ids": list(assumption_ids),
        "evidence_ids": list(evidence_ids),
        "proposer_authority_id": proposer,
        "materiality": materiality,
        "valid_from_sequence": valid_from,
        "expires_at_sequence": expires_at,
        "limitations": list(limitations),
        "maximum_reuse_class": reuse,
    }


def _ev(
    *,
    model_id: str,
    entity_sequence: int,
    previous: str | None,
    clock: int,
    source_receipt: str,
    payload: dict[str, object],
) -> dict[str, Any]:
    event = build_alternative_model_event(
        model_id=model_id,
        entity_sequence=entity_sequence,
        previous_entity_event_digest=previous,
        clock_sequence=clock,
        source_receipt_digest=source_receipt,
        payload=payload,
    )
    return event.to_json_value()


def _rebuild_chain(envelopes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rebuild the per-entity event chain so predecessors/digests are consistent."""
    heads: dict[str, str] = {}
    rebuilt: list[dict[str, Any]] = []
    for raw_event in envelopes:
        unsigned = deepcopy(raw_event)
        unsigned.pop("registry_event_digest", None)
        entity_id = unsigned["entity_id"]
        # Preserve an explicitly-set predecessor (None for genesis); otherwise
        # re-point at the rebuilt head of the immediately preceding same-entity
        # event so the chain is internally consistent.
        if (
            unsigned.get("previous_entity_event_digest") is None
            and unsigned.get("entity_sequence") != 1
        ):
            # A non-genesis event with None predecessor is preserved as-is
            # (intentionally-broken rejected vectors).
            pass
        heads.setdefault(entity_id, "")
        rebuilt_event = cast(RegistryEvent, RegistryEvent.build(unsigned)).to_json_value()
        heads[entity_id] = rebuilt_event["registry_event_digest"]
        rebuilt.append(rebuilt_event)
    return rebuilt


# =====================================================================
# Lifecycle replay (to derive projected state for use-authority decisions).
# =====================================================================


def _replay_lifecycle(
    envelopes: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Replay the lifecycle to derive each model's projected state."""
    by_model: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_model.setdefault(ev["entity_id"], []).append(ev)
    result: dict[str, dict[str, Any]] = {}
    for model_id, evs in by_model.items():
        separation_status = "PROPOSED"
        active: set[str] = set()
        pre_challenge_status = "PROPOSED"
        expires_at: int | None = None
        scope_ids: list[str] = []
        reuse = "D2"
        for ev in evs:
            payload = ev["payload"]
            op = payload["operation"]
            if op == "PROPOSE":
                separation_status = "PROPOSED"
                expires_at = payload.get("expires_at_sequence")
                scope_ids = payload["scope_ids"]
                reuse = payload["maximum_reuse_class"]
            elif op == "ADMIT":
                separation_status = "UNVERIFIED"
            elif op == "CONFIRM":
                separation_status = "CONFIRMED"
            elif op == "CHALLENGE":
                if not active:
                    pre_challenge_status = separation_status
                active.add(payload["challenge_id"])
            elif op == "RESOLVE_CHALLENGES":
                for cid in payload["resolved_challenge_ids"]:
                    active.discard(cid)
                outcome = payload["resolution_outcome"]
                if outcome == "INVALIDATE":
                    separation_status = "REJECTED"
                    active.clear()
                else:
                    if not active:
                        separation_status = pre_challenge_status
            elif op == "REJECT":
                separation_status = "REJECTED"
                active.clear()
            elif op == "EXPIRE":
                separation_status = "EXPIRED"
                active.clear()
            elif op == "SUPERSEDE":
                separation_status = "SUPERSEDED"
                active.clear()
        standing = "CHALLENGED" if active else separation_status
        terminal = separation_status in {"REJECTED", "EXPIRED", "SUPERSEDED"}
        result[model_id] = {
            "separation_status": separation_status,
            "standing": standing,
            "terminal": terminal,
            "expires_at_sequence": expires_at,
            "scope_ids": scope_ids,
            "maximum_reuse_class": reuse,
        }
    return result


# =====================================================================
# Vector builders.
# =====================================================================


def _primary_graph() -> dict[str, object]:
    return {
        "nodes": [
            {"node_id": "n1", "authority_id": "authority:primary", "scope": "scope:17"},
            {"node_id": "n2", "authority_id": "authority:primary", "scope": "scope:17"},
        ],
        "edges": [{"from": "n1", "to": "n2"}],
        "semantic_seed": "primary",
    }


def _shadow_graph(seed: str = "shadow") -> dict[str, object]:
    return {
        "nodes": [
            {"node_id": "n1", "authority_id": "authority:shadow", "scope": "scope:18"},
            {"node_id": "n2", "authority_id": "authority:shadow", "scope": "scope:18"},
            {"node_id": "n3", "authority_id": "authority:shadow", "scope": "scope:18"},
        ],
        "edges": [{"from": "n1", "to": "n2"}, {"from": "n2", "to": "n3"}],
        "semantic_seed": seed,
    }


def _build_admission(
    *,
    model_id: str,
    shadow_seed: str = "shadow",
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the admission evidence (receipt + graphs) for one model."""
    primary = _primary_graph()
    shadow = _shadow_graph(shadow_seed)
    receipt, _, _ = _build_structural_difference_receipt(primary, shadow)
    return {
        "model_id": model_id,
        "structural_difference_receipt": receipt,
        "primary_graph": primary,
        "shadow_graph": shadow,
    }, receipt


def _admit_event(
    *,
    model_id: str,
    propose_event: dict[str, Any],
    admit_clock: int,
    admitting_authority_id: str,
    alt_model_root: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    auth_digest = _authorization_digest(
        propose_event=propose_event,
        admit_clock=admit_clock,
        admitting_authority_id=admitting_authority_id,
        alt_model_root=alt_model_root,
        receipt=receipt,
    )
    return _ev(
        model_id=model_id,
        entity_sequence=2,
        previous=propose_event["registry_event_digest"],
        clock=admit_clock,
        source_receipt=auth_digest,
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": admitting_authority_id,
        },
    )


def _expected_authorization_digests(
    envelopes: list[dict[str, Any]],
    admissions: list[dict[str, Any]],
) -> dict[str, str]:
    """Compute expected_authorization_digests from the rebuilt envelopes."""
    receipt_by_model = {a["model_id"]: a["structural_difference_receipt"] for a in admissions}
    result: dict[str, str] = {}
    # Walk envelopes; when an ADMIT follows a PROPOSE, compute the auth digest
    # from the pre-ADMIT snapshot root.
    for i, ev in enumerate(envelopes):
        payload = ev["payload"]
        if payload.get("operation") != "ADMIT":
            continue
        model_id = ev["entity_id"]
        if model_id not in receipt_by_model:
            continue
        propose = None
        for prior in envelopes[:i]:
            if prior["entity_id"] == model_id and prior["payload"].get("operation") == "PROPOSE":
                propose = prior
        if propose is None:
            continue
        pre_admit = _snapshot_root(envelopes[:i])
        auth = _authorization_digest(
            propose_event=propose,
            admit_clock=ev["clock_sequence"],
            admitting_authority_id=payload["admitting_authority_id"],
            alt_model_root=pre_admit,
            receipt=receipt_by_model[model_id],
        )
        result[model_id] = auth
    return result


def _finalize_vector(vector: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the event chain, compute expected roots + auth digests."""
    envelopes = _rebuild_chain(vector["events"])
    vector["events"] = envelopes
    vector["expected_registry_root"] = _snapshot_root(envelopes)
    vector["expected_authorization_digests"] = _expected_authorization_digests(
        envelopes, vector.get("admissions", [])
    )
    return vector


def _v_basic_governed_admit() -> dict[str, Any]:
    """AMV-A01: PROPOSE -> ADMIT (basic governed ADMIT, UNVERIFIED)."""
    model_id = "alt-model:a01"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    envelopes = [propose, admit]
    return _finalize_vector(
        {
            "vector_id": "AMV-A01",
            "description": "PROPOSE -> governed ADMIT (UNVERIFIED).",
            "events": envelopes,
            "admissions": [admission],
        }
    )


def _v_propose_admit_confirm() -> dict[str, Any]:
    """AMV-A02: PROPOSE -> ADMIT -> CONFIRM (ALLOW use authority)."""
    model_id = "alt-model:a02"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    confirm = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    envelopes = [propose, admit, confirm]
    # confirm digest must be rebuilt with the correct predecessor.
    vector = _finalize_vector(
        {
            "vector_id": "AMV-A02",
            "description": "PROPOSE -> governed ADMIT -> CONFIRM (ALLOW).",
            "events": envelopes,
            "admissions": [admission],
            "use_authority": {
                "model_id": model_id,
                "logical_clock": 10,
                "scope_id": SCOPE,
                "required_reuse_class": "D2",
            },
        }
    )
    state = _replay_lifecycle(vector["events"])[model_id]
    decision = _use_authority_decision(
        model_id=model_id,
        logical_clock=10,
        scope_id=SCOPE,
        required_reuse_class="D2",
        maximum_reuse_class=state["maximum_reuse_class"],
        separation_status=state["separation_status"],
        expires_at_sequence=state["expires_at_sequence"],
        standing=state["standing"],
        terminal=state["terminal"],
    )
    vector["expected_use_authority"] = decision
    return vector


def _v_challenge_uphold() -> dict[str, Any]:
    """AMV-A03: PROPOSE -> ADMIT -> CHALLENGE -> RESOLVE(UPHOLD, all resolved)."""
    model_id = "alt-model:a03"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    challenge = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:challenge"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:a03c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute",
            "challenge_receipt_digest": _receipt("challenge:a03"),
        },
    )
    resolve = _ev(
        model_id=model_id,
        entity_sequence=4,
        previous=challenge["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{model_id}:resolve"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "UPHOLD",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt("resolve:a03"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": ["challenge:a03c1"],
            "replacement_model_id": None,
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A03",
            "description": "PROPOSE -> ADMIT -> CHALLENGE -> RESOLVE(UPHOLD).",
            "events": [propose, admit, challenge, resolve],
            "admissions": [admission],
        }
    )


def _v_challenge_invalidate() -> dict[str, Any]:
    """AMV-A04: PROPOSE -> ADMIT -> CHALLENGE -> RESOLVE(INVALIDATE -> REJECTED)."""
    model_id = "alt-model:a04"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    challenge = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:challenge"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:a04c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:fatal",
            "challenge_receipt_digest": _receipt("challenge:a04"),
        },
    )
    resolve = _ev(
        model_id=model_id,
        entity_sequence=4,
        previous=challenge["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{model_id}:resolve"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "INVALIDATE",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt("resolve:a04"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": ["challenge:a04c1"],
            "replacement_model_id": None,
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A04",
            "description": "PROPOSE -> ADMIT -> CHALLENGE -> RESOLVE(INVALIDATE).",
            "events": [propose, admit, challenge, resolve],
            "admissions": [admission],
        }
    )


def _v_expire() -> dict[str, Any]:
    """AMV-A05: PROPOSE -> ADMIT -> CONFIRM -> EXPIRE."""
    model_id = "alt-model:a05"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=5,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    confirm = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    expire = _ev(
        model_id=model_id,
        entity_sequence=4,
        previous=confirm["registry_event_digest"],
        clock=5,
        source_receipt=_receipt(f"{model_id}:expire"),
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:expiry",
            "expiry_receipt_digest": _receipt("expire:a05"),
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A05",
            "description": "PROPOSE -> ADMIT -> CONFIRM -> EXPIRE.",
            "events": [propose, admit, confirm, expire],
            "admissions": [admission],
        }
    )


def _v_supersede() -> dict[str, Any]:
    """AMV-A06: PROPOSE -> ADMIT -> CONFIRM -> SUPERSEDE."""
    model_id = "alt-model:a06"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    confirm = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    supersede = _ev(
        model_id=model_id,
        entity_sequence=4,
        previous=confirm["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{model_id}:supersede"),
        payload={
            "operation": "SUPERSEDE",
            "replacement_model_id": "alt-model:a06b",
            "superseding_authority_id": "authority:superseder",
            "supersession_receipt_digest": _receipt("supersede:a06"),
            "reason_code": "reason:superseded",
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A06",
            "description": "PROPOSE -> ADMIT -> CONFIRM -> SUPERSEDE.",
            "events": [propose, admit, confirm, supersede],
            "admissions": [admission],
        }
    )


def _v_reject() -> dict[str, Any]:
    """AMV-A07: PROPOSE -> ADMIT -> REJECT."""
    model_id = "alt-model:a07"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    reject = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:reject"),
        payload={
            "operation": "REJECT",
            "rejecting_authority_id": "authority:rejector",
            "reason_code": "reason:invalid",
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A07",
            "description": "PROPOSE -> ADMIT -> REJECT.",
            "events": [propose, admit, reject],
            "admissions": [admission],
        }
    )


def _v_use_authority_denied_cases() -> dict[str, Any]:
    """AMV-A08: PROPOSE -> ADMIT (UNVERIFIED) -> use authority DENY (UNVERIFIED)."""
    model_id = "alt-model:a08"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    vector = _finalize_vector(
        {
            "vector_id": "AMV-A08",
            "description": "PROPOSE -> ADMIT (UNVERIFIED); use authority DENY.",
            "events": [propose, admit],
            "admissions": [admission],
            "use_authority": {
                "model_id": model_id,
                "logical_clock": 10,
                "scope_id": SCOPE,
                "required_reuse_class": "D2",
            },
        }
    )
    state = _replay_lifecycle(vector["events"])[model_id]
    decision = _use_authority_decision(
        model_id=model_id,
        logical_clock=10,
        scope_id=SCOPE,
        required_reuse_class="D2",
        maximum_reuse_class=state["maximum_reuse_class"],
        separation_status=state["separation_status"],
        expires_at_sequence=state["expires_at_sequence"],
        standing=state["standing"],
        terminal=state["terminal"],
    )
    vector["expected_use_authority"] = decision
    return vector


def _v_replay_and_comparison() -> dict[str, Any]:
    """AMV-A09: governed ADMIT + replay receipts + DIVERGENT comparison receipt."""
    model_id = "alt-model:a09"
    admission, receipt = _build_admission(model_id=model_id, shadow_seed="shadow-divergent")
    primary = admission["primary_graph"]
    shadow = admission["shadow_graph"]
    primary_digest = receipt["primary_graph_digest"]
    shadow_digest = receipt["shadow_graph_digest"]
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=shadow_digest,
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    decision_context = _literal_digest("decision-context:a09")
    initial_state = _literal_digest("initial-state:a09")
    primary_replay = _build_replay_receipt(
        graph_digest=primary_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        logical_clock=5,
        runner_revision="runner:v1",
        required_inventory=("node:n1", "node:n2"),
        semantic_outcome_digest=_literal_digest(f"outcome:{primary.get('semantic_seed')}"),
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=shadow_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        logical_clock=5,
        runner_revision="runner:v1",
        required_inventory=("node:n1", "node:n2"),
        semantic_outcome_digest=_literal_digest(f"outcome:{shadow.get('semantic_seed')}"),
    )
    comparison = _build_comparison_receipt(
        primary_replay=primary_replay,
        shadow_replay=shadow_replay,
        structural_difference_receipt=receipt,
    )
    vector = _finalize_vector(
        {
            "vector_id": "AMV-A09",
            "description": "governed ADMIT + FULL_REPLAY receipts + DIVERGENT comparison.",
            "events": [propose, admit],
            "admissions": [admission],
            "replay_receipts": [primary_replay, shadow_replay],
            "comparison_receipts": [comparison],
        }
    )
    return vector


def _v_invariant_comparison() -> dict[str, Any]:
    """AMV-A10: governed ADMIT + INVARIANT comparison (same semantic outcome)."""
    model_id = "alt-model:a10"
    admission, receipt = _build_admission(model_id=model_id, shadow_seed="primary")
    primary_digest = receipt["primary_graph_digest"]
    shadow_digest = receipt["shadow_graph_digest"]
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=shadow_digest,
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    decision_context = _literal_digest("decision-context:a10")
    initial_state = _literal_digest("initial-state:a10")
    shared_outcome = _literal_digest("outcome:shared")
    primary_replay = _build_replay_receipt(
        graph_digest=primary_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        logical_clock=5,
        runner_revision="runner:v1",
        required_inventory=("node:n1", "node:n2"),
        semantic_outcome_digest=shared_outcome,
    )
    shadow_replay = _build_replay_receipt(
        graph_digest=shadow_digest,
        decision_context_digest=decision_context,
        initial_state_digest=initial_state,
        logical_clock=5,
        runner_revision="runner:v1",
        required_inventory=("node:n1", "node:n2"),
        semantic_outcome_digest=shared_outcome,
    )
    comparison = _build_comparison_receipt(
        primary_replay=primary_replay,
        shadow_replay=shadow_replay,
        structural_difference_receipt=receipt,
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A10",
            "description": "governed ADMIT + INVARIANT comparison.",
            "events": [propose, admit],
            "admissions": [admission],
            "replay_receipts": [primary_replay, shadow_replay],
            "comparison_receipts": [comparison],
        }
    )


def _v_multi_challenge_partial_uphold() -> dict[str, Any]:
    """AMV-A11: two challenges, resolve one (UPHOLD) -> still CHALLENGED."""
    model_id = "alt-model:a11"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=100,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    confirm = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    c1 = _ev(
        model_id=model_id,
        entity_sequence=4,
        previous=confirm["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{model_id}:c1"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:a11c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute1",
            "challenge_receipt_digest": _receipt("challenge:a11c1"),
        },
    )
    c2 = _ev(
        model_id=model_id,
        entity_sequence=5,
        previous=c1["registry_event_digest"],
        clock=5,
        source_receipt=_receipt(f"{model_id}:c2"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:a11c2",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "reason:dispute2",
            "challenge_receipt_digest": _receipt("challenge:a11c2"),
        },
    )
    resolve = _ev(
        model_id=model_id,
        entity_sequence=6,
        previous=c2["registry_event_digest"],
        clock=6,
        source_receipt=_receipt(f"{model_id}:resolve"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "UPHOLD",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt("resolve:a11"),
            "resolution_basis_code": "basis:adjudication",
            "resolved_challenge_ids": ["challenge:a11c1"],
            "replacement_model_id": None,
        },
    )
    return _finalize_vector(
        {
            "vector_id": "AMV-A11",
            "description": "two challenges, resolve one (UPHOLD) -> still CHALLENGED.",
            "events": [propose, admit, confirm, c1, c2, resolve],
            "admissions": [admission],
        }
    )


# =====================================================================
# Rejected vectors.
# =====================================================================


def _r_corrupt_predecessor() -> dict[str, Any]:
    """AMV-R01: ADMIT predecessor points at the wrong digest."""
    base = _v_basic_governed_admit()
    events = deepcopy(base["events"])
    events[1]["previous_entity_event_digest"] = _literal_digest("bogus-predecessor")
    rebuilt = _rebuild_chain(events)
    return {
        "vector_id": "AMV-R01",
        "description": "ADMIT predecessor mismatch (HISTORY).",
        "events": rebuilt,
        "admissions": deepcopy(base["admissions"]),
        "expected_authorization_digests": deepcopy(base["expected_authorization_digests"]),
        "expected_error": "ALTERNATIVE_MODEL_PREDECESSOR_MISMATCH",
        "stage": "HISTORY",
    }


def _r_terminal_revival() -> dict[str, Any]:
    """AMV-R02: terminal REJECTED model revived with a new ADMIT."""
    base = _v_reject()
    events = deepcopy(base["events"])
    head = events[-1]
    revival = {
        "schema_version": "registry-event/1",
        "registry_type": "ALTERNATIVE_MODEL",
        "entity_id": head["entity_id"],
        "entity_sequence": cast(int, head["entity_sequence"]) + 1,
        "previous_entity_event_digest": head["registry_event_digest"],
        "clock_sequence": cast(int, head["clock_sequence"]) + 1,
        "projection_phase": "ALTERNATIVE_MODEL_REGISTRY",
        "source_receipt_digest": _literal_digest("revive:r02"),
        "payload_schema_version": "alternative-model-event/1",
        "payload": {
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
        },
        "registry_event_digest": _literal_digest("placeholder"),
    }
    events.append(revival)
    rebuilt = _rebuild_chain(events)
    return {
        "vector_id": "AMV-R02",
        "description": "terminal revival (LIFECYCLE).",
        "events": rebuilt,
        "admissions": deepcopy(base["admissions"]),
        "expected_authorization_digests": deepcopy(base["expected_authorization_digests"]),
        "expected_error": "ALTERNATIVE_MODEL_TERMINAL_IDENTITY_REUSE",
        "stage": "LIFECYCLE",
    }


def _r_authorization_mismatch() -> dict[str, Any]:
    """AMV-R03: ADMIT source_receipt_digest != authorization_digest."""
    base = _v_basic_governed_admit()
    events = deepcopy(base["events"])
    events[1]["source_receipt_digest"] = _literal_digest("forged-authorization")
    rebuilt = _rebuild_chain(events)
    return {
        "vector_id": "AMV-R03",
        "description": "ADMIT authorization digest mismatch (ADMISSION).",
        "events": rebuilt,
        "admissions": deepcopy(base["admissions"]),
        "expected_authorization_digests": deepcopy(base["expected_authorization_digests"]),
        "expected_error": "ALTERNATIVE_MODEL_ADMISSION_AUTHORIZATION_MISMATCH",
        "stage": "ADMISSION",
    }


def _r_use_denied_unverified() -> dict[str, Any]:
    """AMV-R04: use authority on a UNVERIFIED model is DENY."""
    base = _v_basic_governed_admit()
    events = deepcopy(base["events"])
    model_id = events[0]["entity_id"]
    return {
        "vector_id": "AMV-R04",
        "description": "use authority DENY (UNVERIFIED).",
        "events": events,
        "admissions": deepcopy(base["admissions"]),
        "expected_authorization_digests": deepcopy(base["expected_authorization_digests"]),
        "expected_error": "USE_DENIED_UNVERIFIED",
        "stage": "USE",
        "use_authority": {
            "model_id": model_id,
            "logical_clock": 10,
            "scope_id": SCOPE,
            "required_reuse_class": "D2",
        },
    }


def _r_use_denied_expired() -> dict[str, Any]:
    """AMV-R05: use authority DENY (EXPIRED) - CONFIRMED model used past expiry."""
    model_id = "alt-model:r05"
    admission, receipt = _build_admission(model_id=model_id)
    propose = _ev(
        model_id=model_id,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{model_id}:propose"),
        payload=_propose_payload(
            graph_digest=receipt["shadow_graph_digest"],
            declared_difference_digest=receipt["declared_difference_digest"],
            valid_from=1,
            expires_at=5,
        ),
    )
    propose = _rebuild_chain([propose])[0]
    admit = _admit_event(
        model_id=model_id,
        propose_event=propose,
        admit_clock=2,
        admitting_authority_id="authority:admitter",
        alt_model_root=_snapshot_root([propose]),
        receipt=receipt,
    )
    confirm = _ev(
        model_id=model_id,
        entity_sequence=3,
        previous=admit["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{model_id}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
        },
    )
    events = _rebuild_chain([propose, admit, confirm])
    return {
        "vector_id": "AMV-R05",
        "description": "use authority DENY (EXPIRED at use time, model still CONFIRMED).",
        "events": events,
        "admissions": [admission],
        "expected_authorization_digests": _expected_authorization_digests(events, [admission]),
        "expected_error": "USE_DENIED_EXPIRED",
        "stage": "USE",
        "use_authority": {
            "model_id": model_id,
            "logical_clock": 50,
            "scope_id": SCOPE,
            "required_reuse_class": "D2",
        },
    }


def _r_corrupt_expected_root() -> dict[str, Any]:
    """AMV-R06: expected_registry_root tampered (IDENTITY)."""
    base = _v_basic_governed_admit()
    return {
        "vector_id": "AMV-R06",
        "description": "expected_registry_root tampered (IDENTITY).",
        "events": deepcopy(base["events"]),
        "admissions": deepcopy(base["admissions"]),
        "expected_authorization_digests": deepcopy(base["expected_authorization_digests"]),
        "expected_registry_root": _literal_digest("tampered-root"),
        "expected_error": "ALTERNATIVE_MODEL_EXPECTED_ROOT_MISMATCH",
        "stage": "IDENTITY",
    }


def _r_admission_evidence_missing() -> dict[str, Any]:
    """AMV-R07: ADMIT with no admission evidence (ADMISSION)."""
    base = _v_basic_governed_admit()
    return {
        "vector_id": "AMV-R07",
        "description": "ADMIT admission evidence missing.",
        "events": deepcopy(base["events"]),
        "admissions": [],
        "expected_authorization_digests": {},
        "expected_error": "ALTERNATIVE_MODEL_ADMISSION_EVIDENCE_MISSING",
        "stage": "ADMISSION",
    }


def main() -> None:
    accepted_builders = [
        _v_basic_governed_admit,
        _v_propose_admit_confirm,
        _v_challenge_uphold,
        _v_challenge_invalidate,
        _v_expire,
        _v_supersede,
        _v_reject,
        _v_use_authority_denied_cases,
        _v_replay_and_comparison,
        _v_invariant_comparison,
        _v_multi_challenge_partial_uphold,
    ]
    rejected_builders = [
        _r_corrupt_predecessor,
        _r_terminal_revival,
        _r_authorization_mismatch,
        _r_use_denied_unverified,
        _r_use_denied_expired,
        _r_corrupt_expected_root,
        _r_admission_evidence_missing,
    ]

    accepted_files: list[str] = []
    rejected_files: list[str] = []
    DEST.mkdir(parents=True, exist_ok=True)

    catalog = {
        "schema_version": "alternative-model-conformance-vectors/0.5",
        "vector_version": 1,
        "accepted_vectors": [],
        "rejected_vectors": [],
        "claim_boundary": (
            "These vectors establish deterministic serialized alternative-model-history, "
            "lifecycle, structural-difference, governed-ADMIT authorization, FULL_REPLAY, "
            "comparison, and use-time authority behavior. They do not establish external "
            "truth, source completeness, real-world dependency completeness, or production "
            "safety."
        ),
    }

    for builder in accepted_builders:
        vector = builder()
        fname = f"{vector['vector_id'].lower()}.json"
        (DEST / fname).write_text(
            json.dumps(vector, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        accepted_files.append(fname)
        catalog["accepted_vectors"].append(vector)
        print(f"  accepted {vector['vector_id']} -> {fname}")

    for builder in rejected_builders:
        vector = builder()
        fname = f"{vector['vector_id'].lower()}.json"
        (DEST / fname).write_text(
            json.dumps(vector, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        rejected_files.append(fname)
        catalog["rejected_vectors"].append(vector)
        print(f"  rejected {vector['vector_id']} -> {fname}")

    # The manifest carries the catalog digest computed over the ASSEMBLED catalog
    # (manifest fields + inlined accepted/rejected vectors), matching how
    # resources.alternative_model_vectors() re-assembles it.
    manifest = {
        "schema_version": "alternative-model-conformance-manifest/0.5",
        "vector_schema_version": "alternative-model-conformance-vectors/0.5",
        "vector_version": 1,
        "accepted_files": sorted(accepted_files),
        "rejected_files": sorted(rejected_files),
        "claim_boundary": catalog["claim_boundary"],
    }
    # Compute the catalog digest over the full assembled catalog (the shape the
    # validator sees), then bind it into both the manifest and the catalog.
    catalog["catalog_digest"] = catalog_digest(catalog, b"ALTERNATIVE_MODEL_VECTOR_CATALOG\0")
    manifest["catalog_digest"] = catalog["catalog_digest"]
    (DEST / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"\nWrote {len(accepted_files)} accepted + {len(rejected_files)} rejected vectors")
    print(f"catalog_digest={catalog['catalog_digest']}")


if __name__ == "__main__":
    main()
