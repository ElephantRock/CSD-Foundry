"""Generate the v0.5-D3.1 assumption-v1 conformance corpus (one-shot build helper).

Uses production code (assumption.py + governance contracts) to construct valid
event envelopes, then computes expected registry roots / authority decision
digests / admissibility decision digests with an INDEPENDENT re-implementation
baked into this script. The committed fixtures therefore pin values that the
independent validator (assumption_validation.py) re-derives and checks.

Run: python scripts/_build_assumption_v1_fixtures.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from csd_foundry.governance.v0_5.assumption import build_assumption_event
from csd_foundry.governance.v0_5.canonicalization import catalog_digest

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data/canary/v0.5/assumption-v1"
MUT_DIR = ROOT / "data/canary/v0.5/assumption-mutations-v1"

AUTHORITY_ROOT = "sha256:" + hashlib.sha256(b"assumption-authority-root-v1").hexdigest()
SCOPE = "control:17"


# =====================================================================
# Independent digest helpers (must mirror assumption_validation.py exactly).
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
        "registry_type": "ASSUMPTION",
        "heads": [heads[k] for k in sorted(heads)],
    }
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(b"REGISTRY_SNAPSHOT\0" + payload).hexdigest()


# =====================================================================
# Authority policy construction.
# =====================================================================


def _policy() -> dict[str, Any]:
    """Build the canonical authority policy for the assumption corpus.

    The policy is the independent validator's OWN fixture artifact (a plain
    JSON dict, schema ``assumption-authority-policy/1``), keyed by lifecycle
    operation — mirroring the evidence corpus's operation-keyed authority
    model exactly. Grants cover all eight lifecycle operations.
    """
    actions = [
        ("grant:admitter", "ADMIT", "authority:admitter"),
        ("grant:challenger", "CHALLENGE", "authority:challenger"),
        ("grant:confirmer", "CONFIRM", "authority:confirmer"),
        ("grant:expiry", "EXPIRE", "authority:expiry"),
        ("grant:proposer", "PROPOSE", "authority:proposer"),
        ("grant:rejector", "REJECT", "authority:rejector"),
        ("grant:resolver", "RESOLVE_CHALLENGES", "authority:resolver"),
        ("grant:superseder", "SUPERSEDE", "authority:superseder"),
    ]
    grants = [
        {
            "grant_id": gid,
            "action": action,
            "authority_id": authority,
            "scope_ids": [SCOPE],
            "assumption_materialities": ["ADVISORY", "CRITICAL", "MATERIAL"],
        }
        for gid, action, authority in actions
    ]
    unsigned = {
        "schema_version": "assumption-authority-policy/1",
        "policy_id": "policy:assumption-v1",
        "authority_root_digest": AUTHORITY_ROOT,
        "committed_at_sequence": 0,
        "grants": grants,
    }
    policy = dict(unsigned)
    policy["policy_digest"] = _domain_digest("ASSUMPTION_AUTHORITY_POLICY", unsigned)
    return policy


# Map lifecycle operation -> authority_id used by the corpus.
_AUTHORITY = {
    "PROPOSE": "authority:proposer",
    "ADMIT": "authority:admitter",
    "CONFIRM": "authority:confirmer",
    "CHALLENGE": "authority:challenger",
    "RESOLVE_CHALLENGES": "authority:resolver",
    "REJECT": "authority:rejector",
    "EXPIRE": "authority:expiry",
    "SUPERSEDE": "authority:superseder",
}


# =====================================================================
# Event construction.
# =====================================================================


def _propose_payload(
    *,
    proposition_id: str = "control.connected",
    scope_ids: tuple[str, ...] = (SCOPE,),
    materiality: str = "MATERIAL",
    proposer: str = "authority:proposer",
    clock: int,
    valid_from: int | None = None,
    expires_at: int | None,
    assumption_deps: tuple[str, ...] = (),
    evidence_deps: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
    reuse: str = "D2",
) -> dict[str, object]:
    vf = clock if valid_from is None else valid_from
    return {
        "operation": "PROPOSE",
        "proposition_id": proposition_id,
        "scope_ids": list(scope_ids),
        "materiality": materiality,
        "proposer_authority_id": proposer,
        "proposed_at_sequence": clock,
        "valid_from_sequence": vf,
        "expires_at_sequence": expires_at,
        "assumption_dependency_ids": list(assumption_deps),
        "evidence_dependency_ids": list(evidence_deps),
        "limitations": list(limitations),
        "maximum_reuse_class": reuse,
    }


def _ev(
    *,
    assumption_id: str,
    entity_sequence: int,
    previous: str | None,
    clock: int,
    source_receipt: str,
    payload: dict[str, object],
) -> dict[str, Any]:
    event = build_assumption_event(
        assumption_id=assumption_id,
        entity_sequence=entity_sequence,
        previous_entity_event_digest=previous,
        clock_sequence=clock,
        source_receipt_digest=source_receipt,
        payload=payload,
    )
    return event.to_json_value()


# =====================================================================
# Independent lifecycle replay to compute expected status per entity.
# =====================================================================

_TERMINAL = {"REJECTED", "EXPIRED", "SUPERSEDED"}
_ACTIVE = {"ADMITTED", "CONFIRMED"}


def _replay_status(envelopes: list[dict[str, Any]]) -> dict[str, str]:
    """Return {entity_id: derived_status} from the envelope chain."""
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    result: dict[str, str] = {}
    for entity_id, evs in by_entity.items():
        standing = "PROPOSED"
        active: set[str] = set()
        for ev in evs:
            op = ev["payload"]["operation"]
            if op == "PROPOSE":
                standing = "PROPOSED"
            elif op == "ADMIT":
                standing = "ADMITTED"
            elif op == "CONFIRM":
                standing = "CONFIRMED"
            elif op == "CHALLENGE":
                active.add(ev["payload"]["challenge_id"])
            elif op == "RESOLVE_CHALLENGES":
                payload = ev["payload"]
                for cid in payload["resolved_challenge_ids"]:
                    active.discard(cid)
                outcome = payload["resolution_outcome"]
                if outcome == "RETURN_TO_ADMITTED":
                    standing = "ADMITTED"
                elif outcome == "CONFIRM":
                    standing = "CONFIRMED"
                elif outcome == "REJECT":
                    standing = "REJECTED"
                    active.clear()
                elif outcome == "SUPERSEDE":
                    standing = "SUPERSEDED"
                    active.clear()
            elif op == "REJECT":
                standing = "REJECTED"
                active.clear()
            elif op == "EXPIRE":
                standing = "EXPIRED"
                active.clear()
            elif op == "SUPERSEDE":
                standing = "SUPERSEDED"
                active.clear()
        # Derived status.
        status = "CHALLENGED" if active else standing
        # For superseded terminal, we still report standing (SUPERSEDED) since
        # active is empty. Consistent with production Assumption.status.
        result[entity_id] = status
    return result


def _current_digests(envelopes: list[dict[str, Any]]) -> dict[str, str]:
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    return {eid: evs[-1]["registry_event_digest"] for eid, evs in by_entity.items()}


# =====================================================================
# Authority decision digest (must match assumption_validation._authority_decision).
# =====================================================================


def _authority_decisions(
    envelopes: list[dict[str, Any]],
    policy: dict[str, Any],
) -> list[str]:
    decisions: list[str] = []
    for ev in envelopes:
        payload = ev["payload"]
        op = payload["operation"]
        auth_field = {
            "PROPOSE": "proposer_authority_id",
            "ADMIT": "admitting_authority_id",
            "CONFIRM": "confirming_authority_id",
            "CHALLENGE": "challenger_authority_id",
            "RESOLVE_CHALLENGES": "resolver_authority_id",
            "REJECT": "rejecting_authority_id",
            "EXPIRE": "expiry_authority_id",
            "SUPERSEDE": "superseding_authority_id",
        }[op]
        authority_id = payload[auth_field]
        if op == "PROPOSE":
            scope_ids = payload["scope_ids"]
            materiality = payload["materiality"]
        else:
            scope_ids = [SCOPE]
            materiality = "MATERIAL"
        allowed = True
        code = "ASSUMPTION_AUTHORITY_PERMITTED"
        unsigned = {
            "schema_version": "assumption-authority-decision/1",
            "allowed": allowed,
            "authority_id": authority_id,
            "authority_root_digest": policy["authority_root_digest"],
            "code": code,
            "event_digest": ev["registry_event_digest"],
            "assumption_id": ev["entity_id"],
            "operation": op,
            "policy_digest": policy["policy_digest"],
            "scope_ids": list(scope_ids),
            "materiality": materiality,
        }
        decisions.append(_domain_digest("ASSUMPTION_AUTHORITY_DECISION", unsigned))
    return decisions


# =====================================================================
# Use-time admissibility decision digest (must match validator._evaluate_use).
# =====================================================================


def _work_digest(work: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "assumption-evaluation-work/1",
        "assumption_histories_reconstructed": work["assumption_histories_reconstructed"],
        "assumption_events_replayed": work["assumption_events_replayed"],
        "authority_decisions_evaluated": 0,
        "unique_assumption_nodes_evaluated": work["unique_assumption_nodes_evaluated"],
        "assumption_dependency_edges_examined": work["assumption_dependency_edges_examined"],
        "evidence_dependency_references_evaluated": work[
            "evidence_dependency_references_evaluated"
        ],
        "active_challenges_evaluated": work["active_challenges_evaluated"],
        "separation_duty_rules_evaluated": 0,
    }
    return _domain_digest("ASSUMPTION_EVALUATION_WORK", unsigned)


def _evidence_request_digest(
    *,
    decision_id: str,
    evidence_id: str,
    owner_proposition: str,
    owner_scopes: list[str],
    owner_reuse: str,
    clock: int,
    owner_limitations: list[str],
) -> str:
    rebuilt = {
        "schema_version": "evidence-use-request/1",
        "decision_id": decision_id,
        "evidence_id": evidence_id,
        "proposition_id": owner_proposition,
        "scope_ids": sorted(owner_scopes),
        "required_reuse_class": owner_reuse,
        "clock_sequence": clock,
        "accepted_limitation_codes": sorted(owner_limitations),
    }
    return _domain_digest("EVIDENCE_USE_REQUEST", rebuilt)


def _build_use_request(
    *,
    decision_id: str,
    assumption_id: str,
    proposition_id: str,
    scope_ids: list[str],
    required_reuse_class: str,
    clock: int,
    accepted_limitation_codes: list[str],
    evidence_requests: dict[str, Any],
) -> dict[str, Any]:
    request = {
        "schema_version": "assumption-use-request/1",
        "decision_id": decision_id,
        "assumption_id": assumption_id,
        "proposition_id": proposition_id,
        "scope_ids": sorted(scope_ids),
        "required_reuse_class": required_reuse_class,
        "clock_sequence": clock,
        "accepted_limitation_codes": sorted(accepted_limitation_codes),
        "evidence_requests": evidence_requests,
    }
    unsigned = {
        k: v for k, v in request.items() if k not in {"request_digest", "evidence_requests"}
    }
    request["request_digest"] = _domain_digest("ASSUMPTION_USE_REQUEST", unsigned)
    return request


def _use_decision(
    request: dict[str, Any],
    allowed: bool,
    code: str,
    assumption_event_digest: str | None,
    work: dict[str, object],
    policy: dict[str, Any],
) -> str:
    unsigned = {
        "schema_version": "assumption-use-admissibility-decision/1",
        "allowed": allowed,
        "authority_policy_digest": policy["policy_digest"],
        "code": code,
        "assumption_id": request["assumption_id"],
        "decision_id": request["decision_id"],
        "assumption_event_digest": assumption_event_digest,
        "request_digest": request["request_digest"],
        "assumption_histories_reconstructed": work["assumption_histories_reconstructed"],
        "assumption_events_replayed": work["assumption_events_replayed"],
        "unique_assumption_nodes_evaluated": work["unique_assumption_nodes_evaluated"],
        "assumption_dependency_edges_examined": work["assumption_dependency_edges_examined"],
        "evidence_dependency_references_evaluated": work[
            "evidence_dependency_references_evaluated"
        ],
        "active_challenges_evaluated": work["active_challenges_evaluated"],
        "work_digest": work["work_digest"],
    }
    return _domain_digest("ASSUMPTION_USE_ADMISSIBILITY_DECISION", unsigned)


# =====================================================================
# Output helpers.
# =====================================================================


def _write_json(path: Path, value: dict[str, Any]) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    path.write_text(rendered + "\n", encoding="utf-8")


def _accepted_vector(
    vector_id: str,
    description: str,
    envelopes: list[dict[str, Any]],
    policy: dict[str, Any],
    *,
    use_request: dict[str, Any],
    expected_admissibility: dict[str, Any],
) -> dict[str, Any]:
    return {
        "vector_id": vector_id,
        "description": description,
        "events": envelopes,
        "expected_statuses": _replay_status(envelopes),
        "expected_current_event_digests": _current_digests(envelopes),
        "expected_registry_root": _snapshot_root(envelopes),
        "expected_authority_decision_digests": _authority_decisions(envelopes, policy),
        "use_request": use_request,
        "expected_admissibility": expected_admissibility,
    }


def _rejected_vector(
    vector_id: str,
    description: str,
    envelopes: list[dict[str, Any]],
    stage: str,
    expected_error: str,
) -> dict[str, Any]:
    return {
        "vector_id": vector_id,
        "description": description,
        "events": envelopes,
        "stage": stage,
        "expected_error": expected_error,
        "use_request": None,
    }


def build_vectors(policy: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Build all 25 vectors and write them. Returns [(filename, vector_dict)]."""
    written: list[tuple[str, dict[str, Any]]] = []
    builders = [
        av_a01,
        av_a02,
        av_a03,
        av_a04,
        av_a05,
        av_a06,
        av_a07,
        av_a08,
        av_a09,
        av_a10,
        av_a11,
        av_a12,
        av_a13,
        av_r01,
        av_r02,
        av_r03,
        av_r04,
        av_r05,
        av_r06,
        av_r07,
        av_r08,
        av_r09,
        av_r10,
        av_r11,
        av_r12,
    ]
    for build in builders:
        vid, vector = build(policy)
        # filename derived from vector_id
        fname = vid.lower().replace("_", "-") + ".json"
        _write_json(DEST / fname, vector)
        written.append((fname, vector))
    return written


# =====================================================================
# Accepted vectors.
# =====================================================================


def _simple_use_request(
    *,
    decision_id: str = "decision:release-17",
    assumption_id: str,
    proposition_id: str = "control.connected",
    scope_ids: list[str] | None = None,
    clock: int = 5,
    evidence_requests: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _build_use_request(
        decision_id=decision_id,
        assumption_id=assumption_id,
        proposition_id=proposition_id,
        scope_ids=scope_ids if scope_ids is not None else [SCOPE],
        required_reuse_class="D2",
        clock=clock,
        accepted_limitation_codes=[],
        evidence_requests=evidence_requests if evidence_requests is not None else {},
    )


def _allowed_admissibility(
    request: dict[str, Any],
    envelopes: list[dict[str, Any]],
    assumption_id: str,
    policy: dict[str, Any],
    *,
    extra_histories: int = 0,
    extra_events: int = 0,
    extra_nodes: int = 0,
    extra_edges: int = 0,
    extra_evidence: int = 0,
    extra_challenges: int = 0,
) -> dict[str, Any]:
    # Determine work counters from the envelopes for the root assumption.
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    root_events = by_entity[assumption_id]
    work = {
        "assumption_histories_reconstructed": 1 + extra_histories,
        "assumption_events_replayed": len(root_events) + extra_events,
        "unique_assumption_nodes_evaluated": 1 + extra_nodes,
        "assumption_dependency_edges_examined": extra_edges,
        "evidence_dependency_references_evaluated": extra_evidence,
        "active_challenges_evaluated": extra_challenges,
    }
    work["work_digest"] = _work_digest(work)
    digest = _use_decision(
        request,
        allowed=True,
        code="ASSUMPTION_USE_ALLOWED",
        assumption_event_digest=root_events[-1]["registry_event_digest"],
        work=work,
        policy=policy,
    )
    return {"allowed": True, "code": "ASSUMPTION_USE_ALLOWED", "decision_digest": digest}


def _denied_admissibility(
    request: dict[str, Any],
    envelopes: list[dict[str, Any]],
    assumption_id: str,
    policy: dict[str, Any],
    code: str,
) -> dict[str, Any]:
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    root_events = by_entity.get(assumption_id, [])
    event_digest = root_events[-1]["registry_event_digest"] if root_events else None
    # For a self-gate denial (TERMINAL/NOT_ADMITTED/CHALLENGED/NOT_YET_VALID/EXPIRED),
    # the DFS never runs: 1 history reconstructed, no edges/evidence traversed,
    # challenges counted from the projected active set.
    active_challenges = 0
    if root_events:
        # replay minimal challenge state
        active: set[str] = set()
        for ev in root_events:
            op = ev["payload"]["operation"]
            if op == "CHALLENGE":
                active.add(ev["payload"]["challenge_id"])
            elif op == "RESOLVE_CHALLENGES":
                for cid in ev["payload"]["resolved_challenge_ids"]:
                    active.discard(cid)
                outcome = ev["payload"]["resolution_outcome"]
                if outcome in {"REJECT", "SUPERSEDE"}:
                    active.clear()
            elif op in {"REJECT", "EXPIRE", "SUPERSEDE"}:
                active.clear()
        active_challenges = len(active)
    work = {
        "assumption_histories_reconstructed": 1,
        "assumption_events_replayed": len(root_events),
        "unique_assumption_nodes_evaluated": 1,
        "assumption_dependency_edges_examined": 0,
        "evidence_dependency_references_evaluated": 0,
        "active_challenges_evaluated": active_challenges,
    }
    work["work_digest"] = _work_digest(work)
    digest = _use_decision(
        request,
        allowed=False,
        code=code,
        assumption_event_digest=event_digest,
        work=work,
        policy=policy,
    )
    return {"allowed": False, "code": code, "decision_digest": digest}


def av_a01(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A01: PROPOSED only (genesis projection)."""
    aid = "assumption:a01"
    prop = _propose_payload(clock=1, expires_at=20)
    ev = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=prop,
    )
    envelopes = [ev]
    request = _simple_use_request(assumption_id=aid)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_NOT_ADMITTED"
    )
    return "AV-A01", _accepted_vector(
        "AV-A01",
        "Proposed-only genesis projection is not admitted at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a02(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A02: PROPOSED -> ADMITTED."""
    aid = "assumption:a02"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    envelopes = [e1, e2]
    request = _simple_use_request(assumption_id=aid, clock=5)
    admissibility = _allowed_admissibility(request, envelopes, aid, policy)
    return "AV-A02", _accepted_vector(
        "AV-A02",
        "Proposed then admitted assumption is usable.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a03(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A03: ADMITTED -> CHALLENGED (one challenge)."""
    aid = "assumption:a03"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:challenge"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:challenge-receipt"),
        },
    )
    envelopes = [e1, e2, e3]
    request = _simple_use_request(assumption_id=aid, clock=5)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_CHALLENGED"
    )
    return "AV-A03", _accepted_vector(
        "AV-A03",
        "Challenged assumption is denied at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a04(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A04: Multiple concurrent challenges (canonical active set)."""
    aid = "assumption:a04"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:c1"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:c1-receipt"),
        },
    )
    e4 = _ev(
        assumption_id=aid,
        entity_sequence=4,
        previous=e3["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid}:c2"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c2",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:c2-receipt"),
        },
    )
    envelopes = [e1, e2, e3, e4]
    request = _simple_use_request(assumption_id=aid, clock=6)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_CHALLENGED"
    )
    return "AV-A04", _accepted_vector(
        "AV-A04",
        "Multiple concurrent challenges form a canonical active set.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a05(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A05: Partial challenge resolution (subset resolved, rest remain)."""
    aid = "assumption:a05"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:c1"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:c1-receipt"),
        },
    )
    e4 = _ev(
        assumption_id=aid,
        entity_sequence=4,
        previous=e3["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid}:c2"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c2",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:c2-receipt"),
        },
    )
    e5 = _ev(
        assumption_id=aid,
        entity_sequence=5,
        previous=e4["registry_event_digest"],
        clock=5,
        source_receipt=_receipt(f"{aid}:resolve-c1"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt(f"{aid}:resolve-c1-receipt"),
            "resolution_basis_code": "BASIS_REVIEW",
            "resolved_challenge_ids": ["challenge:c1"],
            "replacement_assumption_id": None,
        },
    )
    envelopes = [e1, e2, e3, e4, e5]
    request = _simple_use_request(assumption_id=aid, clock=6)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_CHALLENGED"
    )
    return "AV-A05", _accepted_vector(
        "AV-A05",
        "Partial challenge resolution leaves remaining challenges active.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a06(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A06: CONFIRMED (from ADMITTED with no active challenges)."""
    aid = "assumption:a06"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _receipt(f"{aid}:confirm-receipt"),
        },
    )
    envelopes = [e1, e2, e3]
    request = _simple_use_request(assumption_id=aid, clock=5)
    admissibility = _allowed_admissibility(request, envelopes, aid, policy)
    return "AV-A06", _accepted_vector(
        "AV-A06",
        "Confirmed assumption (from ADMITTED) is usable.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a07(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A07: REJECTED (from ADMITTED)."""
    aid = "assumption:a07"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:reject"),
        payload={
            "operation": "REJECT",
            "rejecting_authority_id": "authority:rejector",
            "rejection_receipt_digest": _receipt(f"{aid}:reject-receipt"),
            "reason_code": "REASON_REJECTED",
        },
    )
    envelopes = [e1, e2, e3]
    request = _simple_use_request(assumption_id=aid, clock=5)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_TERMINAL"
    )
    return "AV-A07", _accepted_vector(
        "AV-A07",
        "Rejected assumption is terminal and denied at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a08(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A08: EXPIRED (from ADMITTED, at declared expiry)."""
    aid = "assumption:a08"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=20,
        source_receipt=_receipt(f"{aid}:expire"),
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:expiry",
            "expiry_receipt_digest": _receipt(f"{aid}:expire-receipt"),
        },
    )
    envelopes = [e1, e2, e3]
    request = _simple_use_request(assumption_id=aid, clock=25)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_TERMINAL"
    )
    return "AV-A08", _accepted_vector(
        "AV-A08",
        "Expired assumption is terminal and denied at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a09(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A09: SUPERSEDED (from ADMITTED, with replacement identity)."""
    aid = "assumption:a09"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:supersede"),
        payload={
            "operation": "SUPERSEDE",
            "replacement_assumption_id": "assumption:a09b",
            "superseding_authority_id": "authority:superseder",
            "supersession_receipt_digest": _receipt(f"{aid}:supersede-receipt"),
            "reason_code": "REASON_SUPERSEDED",
        },
    )
    envelopes = [e1, e2, e3]
    request = _simple_use_request(assumption_id=aid, clock=5)
    admissibility = _denied_admissibility(
        request, envelopes, aid, policy, code="ASSUMPTION_USE_TERMINAL"
    )
    return "AV-A09", _accepted_vector(
        "AV-A09",
        "Superseded assumption is terminal and denied at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a10(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A10: Nested assumption dependency (A depends on B depends on C)."""
    aid_a = "assumption:a10a"
    aid_b = "assumption:a10b"
    aid_c = "assumption:a10c"
    # C first (no deps), then B (deps on C), then A (deps on B).
    e_c = _ev(
        assumption_id=aid_c,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_c}:propose"),
        payload=_propose_payload(clock=1, expires_at=20),
    )
    e_c2 = _ev(
        assumption_id=aid_c,
        entity_sequence=2,
        previous=e_c["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_c}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_c}:admit-receipt"),
        },
    )
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=3, expires_at=20, assumption_deps=(aid_c,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_b}:admit-receipt"),
        },
    )
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=5,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(clock=5, expires_at=20, assumption_deps=(aid_b,)),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=6,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_a}:admit-receipt"),
        },
    )
    envelopes = [e_c, e_c2, e_b, e_b2, e_a, e_a2]
    request = _simple_use_request(assumption_id=aid_a, clock=7)
    # 3 nodes (A, B, C), 2 dep edges (A->B, B->C).
    admissibility = _allowed_admissibility(
        request,
        envelopes,
        aid_a,
        policy,
        extra_histories=2,
        extra_events=4,
        extra_nodes=2,
        extra_edges=2,
    )
    return "AV-A10", _accepted_vector(
        "AV-A10",
        "Nested assumption dependency chain is traversed at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a11(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A11: Assumption with evidence dependency."""
    aid = "assumption:a11"
    evidence_id = "evidence:a11e"
    p1 = _propose_payload(clock=1, expires_at=20, evidence_deps=(evidence_id,))
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    envelopes = [e1, e2]
    # Build evidence request for the single evidence dependency.
    ev_req_digest = _evidence_request_digest(
        decision_id="decision:release-17",
        evidence_id=evidence_id,
        owner_proposition="control.connected",
        owner_scopes=[SCOPE],
        owner_reuse="D2",
        clock=5,
        owner_limitations=[],
    )
    evidence_requests = {
        evidence_id: {
            "request_digest": ev_req_digest,
            "admissibility_receipt": {"allowed": True, "code": "EVIDENCE_ADMISSIBLE"},
        }
    }
    request = _simple_use_request(assumption_id=aid, clock=5, evidence_requests=evidence_requests)
    admissibility = _allowed_admissibility(
        request,
        envelopes,
        aid,
        policy,
        extra_evidence=1,
    )
    return "AV-A11", _accepted_vector(
        "AV-A11",
        "Assumption with evidence dependency evaluates it at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a12(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A12: Shared dependency DAG (A and B both depend on C)."""
    aid_a = "assumption:a12a"
    aid_b = "assumption:a12b"
    aid_c = "assumption:a12c"
    e_c = _ev(
        assumption_id=aid_c,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_c}:propose"),
        payload=_propose_payload(clock=1, expires_at=20),
    )
    e_c2 = _ev(
        assumption_id=aid_c,
        entity_sequence=2,
        previous=e_c["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_c}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_c}:admit-receipt"),
        },
    )
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(clock=3, expires_at=20, assumption_deps=(aid_c,)),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_a}:admit-receipt"),
        },
    )
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=5,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=5, expires_at=20, assumption_deps=(aid_c,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=6,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_b}:admit-receipt"),
        },
    )
    envelopes = [e_c, e_c2, e_a, e_a2, e_b, e_b2]
    # Use A: A -> C. C is visited once (1 edge). B is not in scope.
    request = _simple_use_request(assumption_id=aid_a, clock=7)
    admissibility = _allowed_admissibility(
        request,
        envelopes,
        aid_a,
        policy,
        extra_histories=1,
        extra_events=2,
        extra_nodes=1,
        extra_edges=1,
    )
    return "AV-A12", _accepted_vector(
        "AV-A12",
        "Shared dependency DAG is traversed at use time.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


def av_a13(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A13: Use-time ALLOW (complete evidence closure + work counters)."""
    aid_a = "assumption:a13a"
    aid_b = "assumption:a13b"
    evidence_id = "evidence:a13e"
    # B depends on evidence; A depends on B.
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=1, expires_at=30, evidence_deps=(evidence_id,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_b}:admit-receipt"),
        },
    )
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(clock=3, expires_at=30, assumption_deps=(aid_b,)),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_a}:admit-receipt"),
        },
    )
    envelopes = [e_b, e_b2, e_a, e_a2]
    # Evidence request bound to B (the owner of the evidence dependency).
    ev_req_digest = _evidence_request_digest(
        decision_id="decision:release-17",
        evidence_id=evidence_id,
        owner_proposition="control.connected",
        owner_scopes=[SCOPE],
        owner_reuse="D2",
        clock=5,
        owner_limitations=[],
    )
    evidence_requests = {
        evidence_id: {
            "request_digest": ev_req_digest,
            "admissibility_receipt": {"allowed": True, "code": "EVIDENCE_ADMISSIBLE"},
        }
    }
    request = _simple_use_request(assumption_id=aid_a, clock=5, evidence_requests=evidence_requests)
    # A (2 events) + B (2 events) = 4 events; 2 nodes; 1 edge (A->B); 1 evidence ref.
    admissibility = _allowed_admissibility(
        request,
        envelopes,
        aid_a,
        policy,
        extra_histories=1,
        extra_events=2,
        extra_nodes=1,
        extra_edges=1,
        extra_evidence=1,
    )
    return "AV-A13", _accepted_vector(
        "AV-A13",
        "Use-time ALLOW with complete evidence closure and work counters.",
        envelopes,
        policy,
        use_request=request,
        expected_admissibility=admissibility,
    )


# =====================================================================
# Rejected vectors.
# =====================================================================


def av_r01(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R01: Broken predecessor (wrong digest chain)."""
    aid = "assumption:r01"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    # Forge a wrong predecessor.
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous="sha256:" + "0" * 64,
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    return "AV-R01", _rejected_vector(
        "AV-R01",
        "Broken predecessor digest chain is rejected.",
        [e1, e2],
        stage="HISTORY",
        expected_error="ASSUMPTION_PREDECESSOR_MISMATCH",
    )


def av_r02(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R02: Wrong entity sequence (gap)."""
    aid = "assumption:r02"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    # Skip sequence 2 -> jump to 3.
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    return "AV-R02", _rejected_vector(
        "AV-R02",
        "Wrong entity sequence (gap) is rejected.",
        [e1, e2],
        stage="HISTORY",
        expected_error="ASSUMPTION_SEQUENCE_MISMATCH",
    )


def av_r03(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R03: Illegal lifecycle transition (PROPOSED -> CONFIRM)."""
    aid = "assumption:r03"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:confirm"),
        payload={
            "operation": "CONFIRM",
            "confirming_authority_id": "authority:confirmer",
            "confirmation_receipt_digest": _receipt(f"{aid}:confirm-receipt"),
        },
    )
    return "AV-R03", _rejected_vector(
        "AV-R03",
        "Illegal lifecycle transition (PROPOSED -> CONFIRM) is rejected.",
        [e1, e2],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_CONFIRM_TRANSITION_INVALID",
    )


def av_r04(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R04: Terminal reactivation (REJECTED -> ADMIT)."""
    aid = "assumption:r04"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:reject"),
        payload={
            "operation": "REJECT",
            "rejecting_authority_id": "authority:rejector",
            "rejection_receipt_digest": _receipt(f"{aid}:reject-receipt"),
            "reason_code": "REASON_REJECTED",
        },
    )
    e4 = _ev(
        assumption_id=aid,
        entity_sequence=4,
        previous=e3["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid}:readmit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:readmit-receipt"),
        },
    )
    return "AV-R04", _rejected_vector(
        "AV-R04",
        "Terminal reactivation (REJECTED -> ADMIT) is rejected.",
        [e1, e2, e3, e4],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_TERMINAL_IDENTITY_REUSE",
    )


def av_r05(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R05: Premature expiry (EXPIRE before declared sequence)."""
    aid = "assumption:r05"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    # EXPIRE at clock 5 but declared expiry is 20.
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=5,
        source_receipt=_receipt(f"{aid}:expire"),
        payload={
            "operation": "EXPIRE",
            "expiry_authority_id": "authority:expiry",
            "expiry_receipt_digest": _receipt(f"{aid}:expire-receipt"),
        },
    )
    return "AV-R05", _rejected_vector(
        "AV-R05",
        "Premature expiry (before declared sequence) is rejected.",
        [e1, e2, e3],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_EXPIRY_PREMATURE",
    )


def av_r06(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R06: Malformed challenge resolution (unknown challenge ID)."""
    aid = "assumption:r06"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    e3 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e2["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid}:c1"),
        payload={
            "operation": "CHALLENGE",
            "challenge_id": "challenge:c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_MATERIAL",
            "challenge_receipt_digest": _receipt(f"{aid}:c1-receipt"),
        },
    )
    # Resolve an unknown challenge id.
    e4 = _ev(
        assumption_id=aid,
        entity_sequence=4,
        previous=e3["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid}:resolve-unknown"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt(f"{aid}:resolve-receipt"),
            "resolution_basis_code": "BASIS_REVIEW",
            "resolved_challenge_ids": ["challenge:unknown"],
            "replacement_assumption_id": None,
        },
    )
    return "AV-R06", _rejected_vector(
        "AV-R06",
        "Malformed challenge resolution (unknown challenge ID) is rejected.",
        [e1, e2, e3, e4],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_RESOLUTION_CHALLENGE_UNKNOWN",
    )


def av_r07(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R07: Authority substitution (wrong admitting authority)."""
    aid = "assumption:r07"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    # Intruder authority is not granted ADMIT.
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit-intruder"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:intruder",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    return "AV-R07", _rejected_vector(
        "AV-R07",
        "Authority substitution (wrong admitting authority) is denied.",
        [e1, e2],
        stage="AUTHORITY",
        expected_error="ASSUMPTION_AUTHORITY_DENIED",
    )


def av_r08(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R08: Missing admission dependency (declared dependency does not exist)."""
    aid = "assumption:r08"
    p1 = _propose_payload(clock=1, expires_at=20, assumption_deps=("assumption:nonexistent",))
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    request = _simple_use_request(assumption_id=aid, clock=5)
    return "AV-R08", _rejected_vector(
        "AV-R08",
        "Missing admission dependency is detected at use time.",
        [e1, e2],
        stage="USE",
        expected_error="ASSUMPTION_USE_DEPENDENCY_MISSING",
    ) | {"use_request": request}


def av_r09(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R09: Cyclic dependency (A -> B -> A)."""
    aid_a = "assumption:r09a"
    aid_b = "assumption:r09b"
    # A depends on B; B depends on A (declared at propose time).
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(clock=1, expires_at=20, assumption_deps=(aid_b,)),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_a}:admit-receipt"),
        },
    )
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=3, expires_at=20, assumption_deps=(aid_a,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid_b}:admit-receipt"),
        },
    )
    envelopes = [e_a, e_a2, e_b, e_b2]
    request = _simple_use_request(assumption_id=aid_a, clock=5)
    return "AV-R09", _rejected_vector(
        "AV-R09",
        "Cyclic dependency (A -> B -> A) is detected at use time.",
        envelopes,
        stage="USE",
        expected_error="ASSUMPTION_USE_DEPENDENCY_CYCLE",
    ) | {"use_request": request}


def av_r10(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R10: Temporal invalidity (valid_from in future)."""
    aid = "assumption:r10"
    # valid_from (50) > proposed_at (1) is allowed, but at use time clock(5) < valid_from(50).
    p1 = _propose_payload(clock=1, valid_from=50, expires_at=80)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    request = _simple_use_request(assumption_id=aid, clock=5)
    return "AV-R10", _rejected_vector(
        "AV-R10",
        "Temporal invalidity (valid_from in future at use time) is detected.",
        [e1, e2],
        stage="USE",
        expected_error="ASSUMPTION_USE_NOT_YET_VALID",
    ) | {"use_request": request}


def av_r11(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R11: Stale root (expected root doesn't match recomputed).

    Built as an accepted-shaped vector (with a use_request) but carrying a
    wrong ``expected_registry_root``. The validator recomputes the root from
    the events and detects the mismatch before evaluating admissibility.
    """
    aid = "assumption:r11"
    p1 = _propose_payload(clock=1, expires_at=20)
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload={
            "operation": "ADMIT",
            "admitting_authority_id": "authority:admitter",
            "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
        },
    )
    envelopes = [e1, e2]
    request = _simple_use_request(assumption_id=aid, clock=5)
    # Carry a deliberately-wrong expected root: the validator recomputes and
    # raises ASSUMPTION_EXPECTED_ROOT_MISMATCH during the accepted-vector pass.
    return "AV-R11", {
        "vector_id": "AV-R11",
        "description": "Stale expected registry root is detected.",
        "events": envelopes,
        "expected_statuses": _replay_status(envelopes),
        "expected_current_event_digests": _current_digests(envelopes),
        "expected_registry_root": "sha256:" + "0" * 64,
        "expected_authority_decision_digests": _authority_decisions(envelopes, policy),
        "use_request": request,
        "expected_admissibility": _denied_admissibility(
            request, envelopes, aid, policy, code="ASSUMPTION_USE_TERMINAL"
        ),
        "stage": "IDENTITY",
        "expected_error": "ASSUMPTION_EXPECTED_ROOT_MISMATCH",
    }


def av_r12(policy: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R12: Self-dependency (assumption depends on itself)."""
    aid = "assumption:r12"
    p1 = _propose_payload(clock=1, expires_at=20, assumption_deps=(aid,))
    e1 = _ev(
        assumption_id=aid,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid}:propose"),
        payload=p1,
    )
    return "AV-R12", _rejected_vector(
        "AV-R12",
        "Self-dependency is rejected at propose time.",
        [e1],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_SELF_DEPENDENCY",
    )


# =====================================================================
# Manifest assembly.
# =====================================================================


def _build_catalog(policy: dict[str, Any]) -> dict[str, Any]:
    accepted_files = sorted(p.name for p in DEST.glob("av-a*.json"))
    rejected_files = sorted(p.name for p in DEST.glob("av-r*.json"))
    # Build the assembled catalog (mirrors resources.assumption_vectors()) and
    # compute the catalog_digest over the ASSEMBLED structure.
    accepted_vectors = [
        json.loads((DEST / name).read_text(encoding="utf-8")) for name in accepted_files
    ]
    rejected_vectors = [
        json.loads((DEST / name).read_text(encoding="utf-8")) for name in rejected_files
    ]
    assembled = {
        "schema_version": "assumption-conformance-vectors/0.5",
        "vector_version": 1,
        "authority_policy": policy,
        "accepted_vectors": accepted_vectors,
        "rejected_vectors": rejected_vectors,
        "claim_boundary": (
            "These vectors establish deterministic assumption-history, authority, lifecycle, "
            "dependency, and admissibility behavior relative to the encoded policy. They do "
            "not establish external truth, source completeness, or production safety."
        ),
    }
    catalog_digest_value = catalog_digest(assembled, b"ASSUMPTION_VECTOR_CATALOG\0")
    manifest: dict[str, Any] = {
        "schema_version": "assumption-conformance-manifest/0.5",
        "vector_schema_version": "assumption-conformance-vectors/0.5",
        "vector_version": 1,
        "accepted_files": accepted_files,
        "rejected_files": rejected_files,
        "authority_policy": policy,
        "claim_boundary": assembled["claim_boundary"],
        "catalog_digest": catalog_digest_value,
    }
    return manifest


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for p in DEST.glob("av-*.json"):
        p.unlink()
    policy = _policy()
    build_vectors(policy)
    manifest = _build_catalog(policy)
    _write_json(DEST / "manifest.json", manifest)
    print(f"Wrote manifest with catalog_digest={manifest['catalog_digest']}")
    print(f"accepted_files ({len(manifest['accepted_files'])}): {manifest['accepted_files']}")
    print(f"rejected_files ({len(manifest['rejected_files'])}): {manifest['rejected_files']}")


if __name__ == "__main__":
    main()
