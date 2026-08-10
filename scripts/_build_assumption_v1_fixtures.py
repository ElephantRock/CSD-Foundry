"""Generate the v0.5-D3.2 assumption-v1 conformance corpus (one-shot build helper).

Uses production code (assumption.py + governance contracts) to construct valid
event envelopes, then computes expected registry roots / authority decision
digests / admissibility decision digests with an INDEPENDENT re-implementation
baked into this script. The committed fixtures therefore pin values that the
independent validator (assumption_validation.py) re-derives and checks.

The corpus carries a serialized V3 policy context (ledger entries with grants +
duty rules + duty exceptions) and DecisionAssumptionBinding-shaped use bindings
with complete D2 EvidenceUseRequest + EvidenceAdmissibilityReceipt objects.

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
EVIDENCE_REGISTRY_ROOT = "sha256:" + hashlib.sha256(b"assumption-evidence-root-v1").hexdigest()
LEDGER_ROOT = "sha256:" + hashlib.sha256(b"assumption-ledger-root-v1").hexdigest()


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
# Serialized V3 policy context construction.
# =====================================================================

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


def _grant_digest(grant: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "authority-grant/1",
        "grant_id": grant["grant_id"],
        "action": grant["action"],
        "authority_id": grant["authority_id"],
        "scope_ids": grant["scope_ids"],
        "assumption_materialities": grant["assumption_materialities"],
        "effective_from_sequence": grant["effective_from_sequence"],
        "effective_until_sequence": grant["effective_until_sequence"],
    }
    return _domain_digest("ASSUMPTION_AUTHORITY_GRANT", unsigned)


def _build_grant(
    *,
    grant_id: str,
    action: str,
    authority_id: str,
    scope_ids: tuple[str, ...],
    materialities: tuple[str, ...],
    effective_from: int,
    effective_until: int | None,
) -> dict[str, Any]:
    grant = {
        "grant_id": grant_id,
        "action": action,
        "authority_id": authority_id,
        "scope_ids": sorted(scope_ids),
        "assumption_materialities": sorted(materialities),
        "effective_from_sequence": effective_from,
        "effective_until_sequence": effective_until,
    }
    grant["grant_digest"] = _grant_digest(grant)
    return grant


def _rule_digest(rule: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "separation-duty-rule/1",
        "action": rule["action"],
        "assumption_materialities": rule["assumption_materialities"],
        "conflicting_roles": rule["conflicting_roles"],
        "rule_id": rule["rule_id"],
        "scope_ids": rule["scope_ids"],
    }
    return _domain_digest("ASSUMPTION_SEPARATION_DUTY_RULE", unsigned)


def _build_rule(
    *,
    rule_id: str,
    action: str,
    conflicting_roles: tuple[str, ...],
    scope_ids: tuple[str, ...],
    materialities: tuple[str, ...],
) -> dict[str, Any]:
    rule = {
        "rule_id": rule_id,
        "action": action,
        "conflicting_roles": sorted(conflicting_roles),
        "scope_ids": sorted(scope_ids),
        "assumption_materialities": sorted(materialities),
    }
    rule["rule_digest"] = _rule_digest(rule)
    return rule


def _exception_digest(exc: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "duty-exception/1",
        "action": exc["action"],
        "assumption_ids": exc["assumption_ids"],
        "assumption_materialities": exc["assumption_materialities"],
        "authority_id": exc["authority_id"],
        "conflicting_roles": exc["conflicting_roles"],
        "effective_from_sequence": exc["effective_from_sequence"],
        "effective_until_sequence": exc["effective_until_sequence"],
        "exception_id": exc["exception_id"],
        "reason_code": exc["reason_code"],
        "rule_id": exc["rule_id"],
        "scope_ids": exc["scope_ids"],
    }
    return _domain_digest("ASSUMPTION_DUTY_EXCEPTION", unsigned)


def _build_exception(
    *,
    exception_id: str,
    rule_id: str,
    action: str,
    authority_id: str,
    conflicting_roles: tuple[str, ...],
    scope_ids: tuple[str, ...],
    assumption_ids: tuple[str, ...],
    materialities: tuple[str, ...],
    reason_code: str,
    effective_from: int,
    effective_until: int,
) -> dict[str, Any]:
    exc = {
        "exception_id": exception_id,
        "rule_id": rule_id,
        "action": action,
        "authority_id": authority_id,
        "conflicting_roles": sorted(conflicting_roles),
        "scope_ids": sorted(scope_ids),
        "assumption_ids": sorted(assumption_ids),
        "assumption_materialities": sorted(materialities),
        "reason_code": reason_code,
        "effective_from_sequence": effective_from,
        "effective_until_sequence": effective_until,
    }
    exc["exception_digest"] = _exception_digest(exc)
    return exc


def _policy_digest(unsigned: dict[str, object]) -> str:
    return _domain_digest("ASSUMPTION_AUTHORITY_POLICY", unsigned)


def _signing_payload_digest(effective_from: int) -> str:
    unsigned = {
        "schema_version": "assumption-policy-signing-payload/1",
        "effective_from_sequence": effective_from,
    }
    return _domain_digest("ASSUMPTION_POLICY_SIGNING_PAYLOAD", unsigned)


def _commit_receipt_digest(policy_id: str) -> str:
    return _domain_digest("ASSUMPTION_POLICY_COMMIT_RECEIPT", {"policy_id": policy_id})


def _ledger_entry_digest(entry_unsigned: dict[str, object]) -> str:
    return _domain_digest("ASSUMPTION_POLICY_LEDGER_ENTRY", entry_unsigned)


def _policy_context() -> dict[str, Any]:
    """Build the canonical V3 policy context for the assumption corpus.

    One ledger entry active from sequence 0, with grants covering all eight
    lifecycle operations for the eight canonical authorities, plus a single
    duty rule that prohibits PROPOSER -> ADMIT (same authority may not propose
    then admit the same assumption). The duty rule has NO exception, so the
    genuine SoD mutation (AM-SOD-001: proposer==admitter) is detected by the
    SoD rule rather than by grant denial.
    """
    grants = [
        _build_grant(
            grant_id=f"grant:{op.lower()}",
            action=op,
            authority_id=authority,
            scope_ids=(SCOPE,),
            materialities=("ADVISORY", "CRITICAL", "MATERIAL"),
            effective_from=0,
            effective_until=None,
        )
        for op, authority in _AUTHORITY.items()
    ]
    grants.sort(key=lambda g: g["grant_id"])
    duty_rules = [
        _build_rule(
            rule_id="sod:proposer-not-admitter",
            action="ADMIT",
            conflicting_roles=("PROPOSER",),
            scope_ids=(SCOPE,),
            materialities=("ADVISORY", "CRITICAL", "MATERIAL"),
        )
    ]
    policy_id = "policy:assumption-v1"
    policy_unsigned = {
        "schema_version": "assumption-authority-policy/1",
        "policy_id": policy_id,
        "authority_root_digest": AUTHORITY_ROOT,
        "committed_at_sequence": 0,
        "grants": grants,
    }
    policy_digest_value = _policy_digest(policy_unsigned)
    effective_from = 0
    signing_payload_digest_value = _signing_payload_digest(effective_from)
    commit_receipt_digest_value = _commit_receipt_digest(policy_id)
    entry_unsigned = {
        "effective_from_sequence": effective_from,
        "policy_id": policy_id,
        "policy_digest": policy_digest_value,
        "commit_receipt_digest": commit_receipt_digest_value,
        "signing_payload_digest": signing_payload_digest_value,
        # grants/rules/exceptions are part of the ledger entry's serialized
        # state; they are not part of the ledger_entry_digest (which binds only
        # the identity/digest/sequence fields), matching production.
    }
    entry_unsigned["ledger_entry_digest"] = _ledger_entry_digest(entry_unsigned)
    entry = {
        **entry_unsigned,
        "grants": grants,
        "duty_rules": duty_rules,
        "duty_exceptions": [],
    }
    return {
        "schema_version": "assumption-policy-context/1",
        "authority_root_digest": AUTHORITY_ROOT,
        "ledger_root_digest": LEDGER_ROOT,
        "policy_digest": policy_digest_value,
        "ledger_entries": [entry],
        "evidence_registry": _evidence_registry(),
    }


def _evidence_registry() -> dict[str, Any]:
    """Pinned admission receipts for every evidence identity referenced by the
    corpus. Each receipt is a complete A0-style eligibility decision.
    """
    evidence_ids = [
        "evidence:a11e",
        "evidence:a13e",
        "evidence:a14ae",
        "evidence:a14be",
    ]
    receipts: dict[str, Any] = {}
    for evidence_id in evidence_ids:
        receipts[evidence_id] = {
            "evidence_id": evidence_id,
            "eligible": True,
            "code": "EVIDENCE_ADMISSIBLE",
            "evaluated_at_sequence": 0,
            "evidence_registry_root": EVIDENCE_REGISTRY_ROOT,
            "admission_receipt_digest": _receipt(f"{evidence_id}:admission"),
        }
    return {
        "evidence_registry_root": EVIDENCE_REGISTRY_ROOT,
        "receipts": receipts,
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


def _admit_payload(aid: str) -> dict[str, object]:
    return {
        "operation": "ADMIT",
        "admitting_authority_id": "authority:admitter",
        "admission_receipt_digest": _receipt(f"{aid}:admit-receipt"),
    }


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
        status = "CHALLENGED" if active else standing
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
    policy_context: dict[str, Any],
) -> list[str]:
    entry = policy_context["ledger_entries"][0]
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
            "authority_root_digest": policy_context["authority_root_digest"],
            "code": code,
            "event_digest": ev["registry_event_digest"],
            "assumption_id": ev["entity_id"],
            "operation": op,
            "policy_digest": entry["policy_digest"],
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
        "separation_duty_rules_evaluated": work.get("separation_duty_rules_evaluated", 0),
    }
    return _domain_digest("ASSUMPTION_EVALUATION_WORK", unsigned)


def _evidence_request_unsigned(
    *,
    decision_id: str,
    evidence_id: str,
    owner_proposition: str,
    owner_scopes: list[str],
    owner_reuse: str,
    clock: int,
    owner_limitations: list[str],
) -> dict[str, object]:
    return {
        "schema_version": "evidence-use-request/1",
        "accepted_limitation_codes": sorted(owner_limitations),
        "clock_sequence": clock,
        "decision_id": decision_id,
        "evidence_id": evidence_id,
        "proposition_id": owner_proposition,
        "required_reuse_class": owner_reuse,
        "scope_ids": sorted(owner_scopes),
    }


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
    return _domain_digest(
        "EVIDENCE_USE_REQUEST",
        _evidence_request_unsigned(
            decision_id=decision_id,
            evidence_id=evidence_id,
            owner_proposition=owner_proposition,
            owner_scopes=owner_scopes,
            owner_reuse=owner_reuse,
            clock=clock,
            owner_limitations=owner_limitations,
        ),
    )


def _evidence_receipt(
    *,
    allowed: bool,
    code: str,
    request_digest: str,
    evidence_id: str,
    evidence_event_digest: str | None,
    authority_policy_digest: str,
    challenge_policy_digest: str,
    dependency_event_digests: tuple[str, ...],
    advisory_codes: tuple[str, ...],
) -> dict[str, Any]:
    canonical_deps = sorted(dependency_event_digests)
    canonical_advisories = sorted(set(advisory_codes))
    unsigned = {
        "schema_version": "evidence-admissibility-receipt/1",
        "advisory_codes": list(canonical_advisories),
        "allowed": allowed,
        "authority_policy_digest": authority_policy_digest,
        "challenge_policy_digest": challenge_policy_digest,
        "code": code,
        "dependency_event_digests": list(canonical_deps),
        "evidence_event_digest": evidence_event_digest,
        "evidence_id": evidence_id,
        "request_digest": request_digest,
    }
    return {
        "schema_version": "evidence-admissibility-receipt/1",
        "advisory_codes": list(canonical_advisories),
        "allowed": allowed,
        "authority_policy_digest": authority_policy_digest,
        "challenge_policy_digest": challenge_policy_digest,
        "code": code,
        "dependency_event_digests": list(canonical_deps),
        "evidence_event_digest": evidence_event_digest,
        "evidence_id": evidence_id,
        "request_digest": request_digest,
        "receipt_digest": _domain_digest("EVIDENCE_ADMISSIBILITY_RECEIPT", unsigned),
    }


def _build_use_binding(
    *,
    decision_id: str,
    validated_event_digest: str,
    semantic_projection_receipt_digest: str,
    control_state_digest: str,
    assumption_registry_root: str,
    logical_clock_sequence: int,
    required_assumption_ids: tuple[str, ...],
    evidence_requests: dict[str, Any],
) -> dict[str, Any]:
    assumptions = sorted(required_assumption_ids)
    unsigned = {
        "schema_version": "decision-assumption-binding/1",
        "assumption_registry_root": assumption_registry_root,
        "control_state_digest": control_state_digest,
        "decision_id": decision_id,
        "evidence_registry_root": EVIDENCE_REGISTRY_ROOT,
        "logical_clock_sequence": logical_clock_sequence,
        "required_assumption_ids": list(assumptions),
        "semantic_projection_receipt_digest": semantic_projection_receipt_digest,
        "validated_event_digest": validated_event_digest,
    }
    return {
        **unsigned,
        "binding_digest": _domain_digest("DECISION_ASSUMPTION_BINDING", unsigned),
        "evidence_requests": evidence_requests,
    }


def _use_decision(
    binding: dict[str, Any],
    allowed: bool,
    code: str,
    assumption_event_digest: str | None,
    work: dict[str, object],
    policy_context: dict[str, Any],
) -> str:
    unsigned = {
        "schema_version": "assumption-use-admissibility-decision/1",
        "allowed": allowed,
        "authority_policy_digest": policy_context["policy_digest"],
        "code": code,
        "assumption_id": binding["required_assumption_ids"][0],
        "decision_id": binding["decision_id"],
        "assumption_event_digest": assumption_event_digest,
        "request_digest": binding["binding_digest"],
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
    policy_context: dict[str, Any],
    *,
    use_binding: dict[str, Any],
    expected_admissibility: dict[str, Any],
) -> dict[str, Any]:
    """Build an accepted vector.

    The caller MUST pass a use_binding already finalized against the snapshot
    root via _finalize_binding_for_vector, so the binding_digest used inside
    expected_admissibility matches the binding actually written.
    """
    root = _snapshot_root(envelopes)
    return {
        "vector_id": vector_id,
        "description": description,
        "events": envelopes,
        "expected_statuses": _replay_status(envelopes),
        "expected_current_event_digests": _current_digests(envelopes),
        "expected_registry_root": root,
        "expected_authority_decision_digests": _authority_decisions(envelopes, policy_context),
        "use_binding": use_binding,
        "expected_admissibility": expected_admissibility,
    }


def _finalize_binding_for_vector(
    envelopes: list[dict[str, Any]],
    binding: dict[str, Any],
) -> dict[str, Any]:
    """Finalize a binding against the snapshot root of ``envelopes``."""
    return _finalize_binding_root(binding, _snapshot_root(envelopes))


def _allowed_admissibility(
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    assumption_id: str,
    policy_context: dict[str, Any],
    *,
    extra_histories: int = 0,
    extra_events: int = 0,
    extra_nodes: int = 0,
    extra_edges: int = 0,
    extra_evidence: int = 0,
    extra_challenges: int = 0,
) -> dict[str, Any]:
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
        "separation_duty_rules_evaluated": 0,
    }
    work["work_digest"] = _work_digest(work)
    digest = _use_decision(
        binding,
        allowed=True,
        code="ASSUMPTION_USE_ALLOWED",
        assumption_event_digest=root_events[-1]["registry_event_digest"],
        work=work,
        policy_context=policy_context,
    )
    return {"allowed": True, "code": "ASSUMPTION_USE_ALLOWED", "decision_digest": digest}


def _denied_admissibility(
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    assumption_id: str,
    policy_context: dict[str, Any],
    code: str,
) -> dict[str, Any]:
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    root_events = by_entity.get(assumption_id, [])
    event_digest = root_events[-1]["registry_event_digest"] if root_events else None
    active_challenges = 0
    if root_events:
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
        "separation_duty_rules_evaluated": 0,
    }
    work["work_digest"] = _work_digest(work)
    digest = _use_decision(
        binding,
        allowed=False,
        code=code,
        assumption_event_digest=event_digest,
        work=work,
        policy_context=policy_context,
    )
    return {"allowed": False, "code": code, "decision_digest": digest}


def _evidence_request_for(
    *,
    evidence_id: str,
    owner_proposition: str,
    owner_scopes: list[str],
    owner_reuse: str,
    clock: int,
    owner_limitations: list[str],
    policy_context: dict[str, Any],
) -> dict[str, Any]:
    """Build a complete D2 EvidenceUseRequest + admissibility receipt pair."""
    request_unsigned = _evidence_request_unsigned(
        decision_id=_DECISION_ID,
        evidence_id=evidence_id,
        owner_proposition=owner_proposition,
        owner_scopes=owner_scopes,
        owner_reuse=owner_reuse,
        clock=clock,
        owner_limitations=owner_limitations,
    )
    request_digest = _domain_digest("EVIDENCE_USE_REQUEST", request_unsigned)
    request = {**request_unsigned, "request_digest": request_digest}
    evidence_event_digest = (
        "sha256:" + hashlib.sha256(b"evidence-event\0" + evidence_id.encode("utf-8")).hexdigest()
    )
    receipt = _evidence_receipt(
        allowed=True,
        code="EVIDENCE_ADMISSIBLE",
        request_digest=request_digest,
        evidence_id=evidence_id,
        evidence_event_digest=evidence_event_digest,
        authority_policy_digest=policy_context["policy_digest"],
        challenge_policy_digest="sha256:"
        + hashlib.sha256(b"evidence-challenge-policy-v1").hexdigest(),
        dependency_event_digests=(),
        advisory_codes=(),
    )
    return {"request": request, "receipt": receipt}


def _rejected_vector(
    vector_id: str,
    description: str,
    envelopes: list[dict[str, Any]],
    stage: str,
    expected_error: str,
    *,
    use_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if use_binding is not None:
        use_binding = _finalize_binding_for_vector(envelopes, use_binding)
    result: dict[str, Any] = {
        "vector_id": vector_id,
        "description": description,
        "events": envelopes,
        "stage": stage,
        "expected_error": expected_error,
        "use_binding": use_binding,
    }
    return result


def build_vectors(policy_context: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Build all vectors and write them. Returns [(filename, vector_dict)]."""
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
        av_a14,
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
        vid, vector = build(policy_context)
        fname = vid.lower().replace("_", "-") + ".json"
        _write_json(DEST / fname, vector)
        written.append((fname, vector))
    return written


# =====================================================================
# Use-binding helpers.
# =====================================================================

_DECISION_ID = "decision:release-17"
_VALIDATED_EVENT_DIGEST = "sha256:" + hashlib.sha256(b"validated-event-v1").hexdigest()
_SEMANTIC_RECEIPT_DIGEST = "sha256:" + hashlib.sha256(b"semantic-receipt-v1").hexdigest()
_CONTROL_STATE_DIGEST = "sha256:" + hashlib.sha256(b"control-state-v1").hexdigest()


def _simple_use_binding(
    *,
    assumption_id: str,
    clock: int = 5,
    required_assumption_ids: tuple[str, ...] | None = None,
    evidence_requests: dict[str, Any] | None = None,
    registry_root: str | None = None,
) -> dict[str, Any]:
    return _build_use_binding(
        decision_id=_DECISION_ID,
        validated_event_digest=_VALIDATED_EVENT_DIGEST,
        semantic_projection_receipt_digest=_SEMANTIC_RECEIPT_DIGEST,
        control_state_digest=_CONTROL_STATE_DIGEST,
        assumption_registry_root=(
            registry_root
            if registry_root is not None
            else "sha256:" + "0" * 64  # filled in by caller via _finalize_binding_root
        ),
        logical_clock_sequence=clock,
        required_assumption_ids=(
            required_assumption_ids if required_assumption_ids is not None else (assumption_id,)
        ),
        evidence_requests=evidence_requests if evidence_requests is not None else {},
    )


def _finalize_binding_root(binding: dict[str, Any], registry_root: str) -> dict[str, Any]:
    """Re-bind the binding to the actual registry root and recompute binding_digest."""
    binding = dict(binding)
    binding["assumption_registry_root"] = registry_root
    unsigned = {
        "schema_version": "decision-assumption-binding/1",
        "assumption_registry_root": registry_root,
        "control_state_digest": binding["control_state_digest"],
        "decision_id": binding["decision_id"],
        "evidence_registry_root": binding["evidence_registry_root"],
        "logical_clock_sequence": binding["logical_clock_sequence"],
        "required_assumption_ids": binding["required_assumption_ids"],
        "semantic_projection_receipt_digest": binding["semantic_projection_receipt_digest"],
        "validated_event_digest": binding["validated_event_digest"],
    }
    binding["binding_digest"] = _domain_digest("DECISION_ASSUMPTION_BINDING", unsigned)
    return binding


def _finalize_vector(vector: dict[str, Any]) -> dict[str, Any]:
    """No-op retained for backwards call-site compatibility.

    Binding finalization now happens inside _accepted_vector / _rejected_vector
    before the admissibility digest is computed, so the post-pass is unnecessary.
    """
    return vector


def av_a01(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
    binding = _finalize_binding_for_vector(envelopes, _simple_use_binding(assumption_id=aid))

    vector = _accepted_vector(
        "AV-A01",
        "Proposed-only genesis projection is not admitted at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_NOT_ADMITTED"
        ),
    )
    return "AV-A01", _finalize_vector(vector)


def av_a02(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
    )
    envelopes = [e1, e2]
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A02",
        "Proposed then admitted assumption is usable.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(binding, envelopes, aid, policy_context),
    )
    return "AV-A02", _finalize_vector(vector)


def av_a03(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A03",
        "Challenged assumption is denied at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_CHALLENGED"
        ),
    )
    return "AV-A03", _finalize_vector(vector)


def av_a04(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=6)
    )

    vector = _accepted_vector(
        "AV-A04",
        "Multiple concurrent challenges form a canonical active set.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_CHALLENGED"
        ),
    )
    return "AV-A04", _finalize_vector(vector)


def av_a05(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=6)
    )

    vector = _accepted_vector(
        "AV-A05",
        "Partial challenge resolution leaves remaining challenges active.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_CHALLENGED"
        ),
    )
    return "AV-A05", _finalize_vector(vector)


def av_a06(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A06",
        "Confirmed assumption (from ADMITTED) is usable.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(binding, envelopes, aid, policy_context),
    )
    return "AV-A06", _finalize_vector(vector)


def av_a07(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A07",
        "Rejected assumption is terminal and denied at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_TERMINAL"
        ),
    )
    return "AV-A07", _finalize_vector(vector)


def av_a08(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=25)
    )

    vector = _accepted_vector(
        "AV-A08",
        "Expired assumption is terminal and denied at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_TERMINAL"
        ),
    )
    return "AV-A08", _finalize_vector(vector)


def av_a09(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A09",
        "Superseded assumption is terminal and denied at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_TERMINAL"
        ),
    )
    return "AV-A09", _finalize_vector(vector)


def av_a10(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A10: Nested assumption dependency (A depends on B depends on C)."""
    aid_a = "assumption:a10a"
    aid_b = "assumption:a10b"
    aid_c = "assumption:a10c"
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
        payload=_admit_payload(aid_c),
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
        payload=_admit_payload(aid_b),
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
        payload=_admit_payload(aid_a),
    )
    envelopes = [e_c, e_c2, e_b, e_b2, e_a, e_a2]
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid_a, clock=7)
    )

    vector = _accepted_vector(
        "AV-A10",
        "Nested assumption dependency chain is traversed at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(
            binding,
            envelopes,
            aid_a,
            policy_context,
            extra_histories=2,
            extra_events=4,
            extra_nodes=2,
            extra_edges=2,
        ),
    )
    return "AV-A10", _finalize_vector(vector)


def av_a11(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A11: Assumption with evidence dependency (complete D2 receipt)."""
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
        payload=_admit_payload(aid),
    )
    envelopes = [e1, e2]
    evidence_requests = {
        evidence_id: _evidence_request_for(
            evidence_id=evidence_id,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=5,
            owner_limitations=[],
            policy_context=policy_context,
        )
    }
    binding = _finalize_binding_for_vector(
        envelopes,
        _simple_use_binding(assumption_id=aid, clock=5, evidence_requests=evidence_requests),
    )

    vector = _accepted_vector(
        "AV-A11",
        "Assumption with evidence dependency evaluates it at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(
            binding, envelopes, aid, policy_context, extra_evidence=1
        ),
    )
    return "AV-A11", _finalize_vector(vector)


def av_a12(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid_c),
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
        payload=_admit_payload(aid_a),
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
        payload=_admit_payload(aid_b),
    )
    envelopes = [e_c, e_c2, e_a, e_a2, e_b, e_b2]
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid_a, clock=7)
    )

    vector = _accepted_vector(
        "AV-A12",
        "Shared dependency DAG is traversed at use time.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(
            binding,
            envelopes,
            aid_a,
            policy_context,
            extra_histories=1,
            extra_events=2,
            extra_nodes=1,
            extra_edges=1,
        ),
    )
    return "AV-A12", _finalize_vector(vector)


def av_a13(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A13: Use-time ALLOW (complete evidence closure + work counters)."""
    aid_a = "assumption:a13a"
    aid_b = "assumption:a13b"
    evidence_id = "evidence:a13e"
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
        payload=_admit_payload(aid_b),
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
        payload=_admit_payload(aid_a),
    )
    envelopes = [e_b, e_b2, e_a, e_a2]
    evidence_requests = {
        evidence_id: _evidence_request_for(
            evidence_id=evidence_id,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=5,
            owner_limitations=[],
            policy_context=policy_context,
        )
    }
    binding = _finalize_binding_for_vector(
        envelopes,
        _simple_use_binding(assumption_id=aid_a, clock=5, evidence_requests=evidence_requests),
    )

    vector = _accepted_vector(
        "AV-A13",
        "Use-time ALLOW with complete evidence closure and work counters.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(
            binding,
            envelopes,
            aid_a,
            policy_context,
            extra_histories=1,
            extra_events=2,
            extra_nodes=1,
            extra_edges=1,
            extra_evidence=1,
        ),
    )
    return "AV-A13", _finalize_vector(vector)


def av_a14(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A14: Two top-level assumptions (A and B) sharing one dependency (C).

    The binding requires both A and B. The evaluator evaluates both, and C is
    deduplicated for work counters (visited once even though reachable from
    both A and B). Each of A and B carries its own evidence dependency; C
    carries none.
    """
    aid_a = "assumption:a14a"
    aid_b = "assumption:a14b"
    aid_c = "assumption:a14c"
    evidence_a = "evidence:a14ae"
    evidence_b = "evidence:a14be"
    # C (no deps, no evidence).
    e_c = _ev(
        assumption_id=aid_c,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_c}:propose"),
        payload=_propose_payload(clock=1, expires_at=40),
    )
    e_c2 = _ev(
        assumption_id=aid_c,
        entity_sequence=2,
        previous=e_c["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_c}:admit"),
        payload=_admit_payload(aid_c),
    )
    # A depends on C, owns evidence_a.
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(
            clock=3, expires_at=40, assumption_deps=(aid_c,), evidence_deps=(evidence_a,)
        ),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload=_admit_payload(aid_a),
    )
    # B depends on C, owns evidence_b.
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=5,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(
            clock=5, expires_at=40, assumption_deps=(aid_c,), evidence_deps=(evidence_b,)
        ),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=6,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload=_admit_payload(aid_b),
    )
    envelopes = [e_c, e_c2, e_a, e_a2, e_b, e_b2]
    evidence_requests = {
        evidence_a: _evidence_request_for(
            evidence_id=evidence_a,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=7,
            owner_limitations=[],
            policy_context=policy_context,
        ),
        evidence_b: _evidence_request_for(
            evidence_id=evidence_b,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=7,
            owner_limitations=[],
            policy_context=policy_context,
        ),
    }
    binding = _finalize_binding_for_vector(
        envelopes,
        _simple_use_binding(
            assumption_id=aid_a,
            clock=7,
            required_assumption_ids=(aid_a, aid_b),
            evidence_requests=evidence_requests,
        ),
    )

    # Work counters: 3 unique nodes (A, B, C) -- C is deduplicated.
    # Events: A(2) + B(2) + C(2) = 6.
    # Edges: A->C, B->C = 2.
    # Evidence refs: evidence_a, evidence_b = 2.
    vector = _accepted_vector(
        "AV-A14",
        "Two top-level assumptions sharing one dependency are both evaluated.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_allowed_admissibility(
            binding,
            envelopes,
            aid_a,
            policy_context,
            extra_histories=2,
            extra_events=4,
            extra_nodes=2,
            extra_edges=2,
            extra_evidence=2,
        ),
    )
    return "AV-A14", _finalize_vector(vector)


# =====================================================================
# Rejected vectors.
# =====================================================================


def av_r01(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=2,
        previous="sha256:" + "0" * 64,
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload=_admit_payload(aid),
    )
    return "AV-R01", _rejected_vector(
        "AV-R01",
        "Broken predecessor digest chain is rejected.",
        [e1, e2],
        stage="HISTORY",
        expected_error="ASSUMPTION_PREDECESSOR_MISMATCH",
    )


def av_r02(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
    e2 = _ev(
        assumption_id=aid,
        entity_sequence=3,
        previous=e1["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid}:admit"),
        payload=_admit_payload(aid),
    )
    return "AV-R02", _rejected_vector(
        "AV-R02",
        "Wrong entity sequence (gap) is rejected.",
        [e1, e2],
        stage="HISTORY",
        expected_error="ASSUMPTION_SEQUENCE_MISMATCH",
    )


def av_r03(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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


def av_r04(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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
        payload=_admit_payload(aid),
    )
    return "AV-R04", _rejected_vector(
        "AV-R04",
        "Terminal reactivation (REJECTED -> ADMIT) is rejected.",
        [e1, e2, e3, e4],
        stage="LIFECYCLE",
        expected_error="ASSUMPTION_TERMINAL_IDENTITY_REUSE",
    )


def av_r05(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
    )
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


def av_r06(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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
        payload=_admit_payload(aid),
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


def av_r07(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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


def av_r08(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R08: Missing admission dependency (detected at ADMIT time, not USE).

    The candidate declares a dependency on ``assumption:nonexistent`` at
    PROPOSE; at ADMIT, the I1-C admission-time dependency DFS detects the
    missing dependency and fails the ADMIT with
    ``ASSUMPTION_ADMISSION_DEPENDENCY_MISSING``.
    """
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
        payload=_admit_payload(aid),
    )
    return "AV-R08", _rejected_vector(
        "AV-R08",
        "Missing admission dependency is detected at admission time.",
        [e1, e2],
        stage="ADMISSION",
        expected_error="ASSUMPTION_ADMISSION_DEPENDENCY_MISSING",
    )


def av_r09(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R09: Cyclic dependency attempt (A -> B -> A), detected at ADMIT time.

    A genuine directed cycle cannot be constructed because each assumption's
    dependencies must exist at its ADMIT time. Attempting A -> B -> A: at A's
    ADMIT, B does not yet exist, so the I1-C admission-time dependency DFS
    rejects with ASSUMPTION_ADMISSION_DEPENDENCY_MISSING (the cycle is never
    reachable).
    """
    aid_a = "assumption:r09a"
    aid_b = "assumption:r09b"
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
        payload=_admit_payload(aid_a),
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
        payload=_admit_payload(aid_b),
    )
    envelopes = [e_a, e_a2, e_b, e_b2]
    return "AV-R09", _rejected_vector(
        "AV-R09",
        "Cyclic dependency attempt (A -> B -> A) is detected at admission time.",
        envelopes,
        stage="ADMISSION",
        expected_error="ASSUMPTION_ADMISSION_DEPENDENCY_MISSING",
    )


def av_r10(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R10: Temporal invalidity (valid_from in future at use time)."""
    aid = "assumption:r10"
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
        payload=_admit_payload(aid),
    )
    envelopes = [e1, e2]
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _rejected_vector(
        "AV-R10",
        "Temporal invalidity (valid_from in future at use time) is detected.",
        envelopes,
        stage="USE",
        expected_error="ASSUMPTION_USE_NOT_YET_VALID",
        use_binding=binding,
    )
    vector = _finalize_vector(vector)
    return "AV-R10", vector


def av_r11(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-R11: Stale root (expected root doesn't match recomputed)."""
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
        payload=_admit_payload(aid),
    )
    envelopes = [e1, e2]
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    return "AV-R11", {
        "vector_id": "AV-R11",
        "description": "Stale expected registry root is detected.",
        "events": envelopes,
        "expected_statuses": _replay_status(envelopes),
        "expected_current_event_digests": _current_digests(envelopes),
        "expected_registry_root": "sha256:" + "0" * 64,
        "expected_authority_decision_digests": _authority_decisions(envelopes, policy_context),
        "use_binding": binding,
        "expected_admissibility": _denied_admissibility(
            binding, envelopes, aid, policy_context, code="ASSUMPTION_USE_TERMINAL"
        ),
        "stage": "IDENTITY",
        "expected_error": "ASSUMPTION_EXPECTED_ROOT_MISMATCH",
    }


def av_r12(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
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


def _build_catalog(policy_context: dict[str, Any]) -> dict[str, Any]:
    accepted_files = sorted(p.name for p in DEST.glob("av-a*.json"))
    rejected_files = sorted(p.name for p in DEST.glob("av-r*.json"))
    accepted_vectors = [
        json.loads((DEST / name).read_text(encoding="utf-8")) for name in accepted_files
    ]
    rejected_vectors = [
        json.loads((DEST / name).read_text(encoding="utf-8")) for name in rejected_files
    ]
    assembled = {
        "schema_version": "assumption-conformance-vectors/0.5",
        "vector_version": 1,
        "authority_policy": policy_context,
        "accepted_vectors": accepted_vectors,
        "rejected_vectors": rejected_vectors,
        "claim_boundary": (
            "These vectors establish deterministic assumption-history, authority, lifecycle, "
            "dependency, separation-of-duty, and use-time admissibility behavior relative to "
            "the encoded V3 policy context. They do not establish external truth, source "
            "completeness, or production safety."
        ),
    }
    catalog_digest_value = catalog_digest(assembled, b"ASSUMPTION_VECTOR_CATALOG\0")
    manifest: dict[str, Any] = {
        "schema_version": "assumption-conformance-manifest/0.5",
        "vector_schema_version": "assumption-conformance-vectors/0.5",
        "vector_version": 1,
        "accepted_files": accepted_files,
        "rejected_files": rejected_files,
        "authority_policy": policy_context,
        "claim_boundary": assembled["claim_boundary"],
        "catalog_digest": catalog_digest_value,
    }
    return manifest


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for p in DEST.glob("av-*.json"):
        p.unlink()
    policy_context = _policy_context()
    build_vectors(policy_context)
    manifest = _build_catalog(policy_context)
    _write_json(DEST / "manifest.json", manifest)
    print(f"Wrote manifest with catalog_digest={manifest['catalog_digest']}")
    print(f"accepted_files ({len(manifest['accepted_files'])}): {manifest['accepted_files']}")
    print(f"rejected_files ({len(manifest['rejected_files'])}): {manifest['rejected_files']}")


if __name__ == "__main__":
    main()
