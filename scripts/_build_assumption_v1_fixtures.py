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
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from csd_foundry.governance.v0_5.assumption import build_assumption_event
from csd_foundry.governance.v0_5.canonicalization import catalog_digest
from csd_foundry.governance.v0_5.contracts import RegistryEvent

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


_RESOLUTION_AUTHORITY_ACTIONS = (
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
)


def _grant_digest(grant: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "assumption-authority-grant/1",
        "action": grant["action"],
        "assumption_materialities": grant["assumption_materialities"],
        "authority_id": grant["authority_id"],
        "challenge_materialities": grant["challenge_materialities"],
        "effective_from_sequence": grant["effective_from_sequence"],
        "effective_until_sequence": grant["effective_until_sequence"],
        "grant_id": grant["grant_id"],
        "scope_ids": grant["scope_ids"],
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
    challenge_materialities: tuple[str, ...] = (),
) -> dict[str, Any]:
    grant = {
        "grant_id": grant_id,
        "action": action,
        "authority_id": authority_id,
        "scope_ids": sorted(scope_ids),
        "assumption_materialities": sorted(materialities),
        "challenge_materialities": sorted(challenge_materialities),
        "effective_from_sequence": effective_from,
        "effective_until_sequence": effective_until,
    }
    grant["grant_digest"] = _grant_digest(grant)
    return grant


def _rule_digest(rule: dict[str, object]) -> str:
    unsigned = {
        "schema_version": "assumption-separation-duty-rule/1",
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
        "schema_version": "assumption-duty-exception/1",
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

    One ledger entry active from sequence 0, with grants covering every frozen
    authority action (the seven lifecycle actions plus the four RESOLVE_TO_*
    resolution actions, the latter carrying challenge_materialities), plus a
    single duty rule that prohibits PROPOSER -> ADMIT (same authority may not
    propose then admit the same assumption). The duty rule has NO exception, so
    the genuine SoD mutation (AM-SOD-001: proposer==admitter) is detected by the
    SoD rule rather than by grant denial.

    The ledger entry carries the recomputed grant_set_digest,
    separation_duty_rule_set_digest, and exception_set_digest, plus the policy
    digest recomputed over the canonical policy content. The validator
    independently recomputes each and requires equality.
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
        if op != "RESOLVE_CHALLENGES"
    ]
    # Resolution grants: RESOLVE_CHALLENGES expands to four RESOLVE_TO_* actions
    # carrying challenge_materialities. The resolver authority holds all four.
    for action in _RESOLUTION_AUTHORITY_ACTIONS:
        grants.append(
            _build_grant(
                grant_id=f"grant:{action.lower()}",
                action=action,
                authority_id="authority:resolver",
                scope_ids=(SCOPE,),
                materialities=("ADVISORY", "CRITICAL", "MATERIAL"),
                effective_from=0,
                effective_until=None,
                challenge_materialities=("ADVISORY", "CRITICAL", "MATERIAL"),
            )
        )
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
    policy_unsigned, grant_set_digest_value, rule_set_digest_value, exception_set_digest_value = (
        _policy_unsigned_value(
            policy_id=policy_id,
            authority_root_digest=AUTHORITY_ROOT,
            grants=grants,
            rules=duty_rules,
            exceptions=[],
        )
    )
    policy_digest_value = _domain_digest("ASSUMPTION_AUTHORITY_POLICY", policy_unsigned)
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
        "grant_set_digest": grant_set_digest_value,
        "separation_duty_rule_set_digest": rule_set_digest_value,
        "exception_set_digest": exception_set_digest_value,
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
        "evidence_registry": _evidence_registry(_EVIDENCE_CLOCKS),
        # Defect #4: serialized challenge-classification material mapping each
        # challenge reason_code to its own materiality, independent of the
        # assumption's own materiality. Production treats
        # assumption_materialities and challenge_materialities as separate
        # dimensions.
        "challenge_classifications": {
            "REASON_MATERIAL": "MATERIAL",
            "REASON_CRITICAL": "CRITICAL",
            "REASON_ADVISORY": "ADVISORY",
        },
    }


# Each evidence_id is bound to the exact ADMIT clock of the assumption that
# consumes it (the A0 decision's evaluated_at_sequence binds to the consuming
# ADMIT clock). See av_a11/av_a13/av_a14/av_a15 for the consuming ADMITs.
_EVIDENCE_CLOCKS = {
    "evidence:a11e": 2,  # AV-A11 admit at clock 2
    "evidence:a13e": 2,  # AV-A13 admit of a13b at clock 2
    "evidence:a14ae": 4,  # AV-A14 admit of a14a at clock 4
    "evidence:a14be": 6,  # AV-A14 admit of a14b at clock 6
    "evidence:a15ae": 4,  # AV-A15 admit of a15a at clock 4
    "evidence:a15be": 2,  # AV-A15 admit of a15b at clock 2
}


def _set_digest(domain: str, members: list[dict[str, object]]) -> str:
    return _domain_digest(domain, {"members": members})


def _policy_unsigned_value(
    *,
    policy_id: str,
    authority_root_digest: str,
    grants: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> tuple[dict[str, object], str, str, str]:
    """Independently recompute the canonical authority-policy unsigned value and
    its three set digests. Mirrors _policy_unsigned_value in the validator."""
    grant_set = _set_digest("ASSUMPTION_AUTHORITY_GRANT_SET", [dict(g) for g in grants])
    rule_set = _set_digest("ASSUMPTION_SEPARATION_DUTY_RULE_SET", [dict(r) for r in rules])
    exception_set = _set_digest("ASSUMPTION_DUTY_EXCEPTION_SET", [dict(e) for e in exceptions])
    unsigned = {
        "schema_version": "assumption-authority-policy/1",
        "authority_root_digest": authority_root_digest,
        "duty_exceptions": [dict(e) for e in exceptions],
        "exception_set_digest": exception_set,
        "grant_set_digest": grant_set,
        "grants": [dict(g) for g in grants],
        "policy_id": policy_id,
        "separation_duty_rule_set_digest": rule_set,
        "separation_duty_rules": [dict(r) for r in rules],
    }
    return unsigned, grant_set, rule_set, exception_set


def _evidence_decision_unsigned(
    *,
    evidence_id: str,
    eligible: bool,
    code: str,
    evaluated_at_sequence: int,
    current_event_digest: str | None,
    current_status: str | None,
) -> dict[str, object]:
    return {
        "schema_version": "evidence-admission-eligibility/1",
        "code": code,
        "current_event_digest": current_event_digest,
        "current_status": current_status,
        "eligible": eligible,
        "evaluated_at_sequence": evaluated_at_sequence,
        "evidence_id": evidence_id,
        "evidence_registry_root": EVIDENCE_REGISTRY_ROOT,
    }


def _evidence_decision(
    *,
    evidence_id: str,
    evaluated_at_sequence: int,
) -> dict[str, Any]:
    """Build a complete A0 EvidenceAdmissionEligibilityDecision record.

    Mirrors EvidenceAdmissionEligibilityDecision.build exactly: eligible<->code
    consistency is enforced, the current_event_digest is derived from the
    evidence identity, and the decision_digest is recomputed over the canonical
    unsigned value under the EVIDENCE_ADMISSION_ELIGIBILITY domain.
    """
    eligible = True
    code = "EVIDENCE_ADMISSION_ELIGIBLE"
    current_event_digest = (
        "sha256:" + hashlib.sha256(b"evidence-event\0" + evidence_id.encode("utf-8")).hexdigest()
    )
    current_status = "ADMITTED"
    unsigned = _evidence_decision_unsigned(
        evidence_id=evidence_id,
        eligible=eligible,
        code=code,
        evaluated_at_sequence=evaluated_at_sequence,
        current_event_digest=current_event_digest,
        current_status=current_status,
    )
    decision_digest = _domain_digest("EVIDENCE_ADMISSION_ELIGIBILITY", unsigned)
    return {
        **unsigned,
        "decision_digest": decision_digest,
    }


def _evidence_registry(evidence_clocks: dict[str, int]) -> dict[str, Any]:
    """Pinned A0 admission decisions for every evidence identity referenced by
    the corpus. Each entry is a complete EvidenceAdmissionEligibilityDecision
    record whose decision_digest the validator independently recomputes and
    requires. ``evidence_clocks`` maps each evidence_id to the exact ADMIT clock
    of the assumption that consumes it (the A0 decision's
    evaluated_at_sequence binds to the consuming ADMIT clock).
    """
    receipts: dict[str, Any] = {}
    for evidence_id, evaluated_at_sequence in evidence_clocks.items():
        receipts[evidence_id] = _evidence_decision(
            evidence_id=evidence_id,
            evaluated_at_sequence=evaluated_at_sequence,
        )
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


def _projection_state(
    envelopes: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Replay built envelopes to derive each assumption's current projection
    state: ``{assumption_id: {current_entity_sequence, current_event_digest,
    assumption_dependency_ids}}``. Mirrors what the validator's
    _validate_history projects. ``assumption_dependency_ids`` comes from the
    entity's PROPOSE event (immutable).
    """
    state: dict[str, dict[str, Any]] = {}
    for ev in envelopes:
        aid = ev["entity_id"]
        seq = ev["entity_sequence"]
        digest = ev["registry_event_digest"]
        op = ev["payload"]["operation"]
        entry = state.setdefault(
            aid,
            {
                "current_entity_sequence": seq,
                "current_event_digest": digest,
                "assumption_dependency_ids": [],
            },
        )
        entry["current_entity_sequence"] = seq
        entry["current_event_digest"] = digest
        if op == "PROPOSE":
            entry["assumption_dependency_ids"] = list(ev["payload"]["assumption_dependency_ids"])
    return state


def _admission_traversal(
    candidate_assumption_id: str,
    assumption_dependency_ids: list[str],
    projections: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Independently replay the admission dependency DFS over the candidate's
    assumption_dependency_ids, collecting first-discovery traversal records.
    Mirrors the validator's admission-gate DFS exactly (same field names, same
    first-discovery order).
    """
    traversed: list[dict[str, Any]] = []
    visited: set[str] = set()
    stack_index: dict[str, int] = {candidate_assumption_id: 0}

    def _dfs(node: str) -> None:
        if node in stack_index:
            return
        if node in visited:
            return
        dep = projections.get(node)
        if dep is None:
            return
        traversed.append(
            {
                "assumption_id": node,
                "validation_code": "DEPENDENCY_PRESENT",
                "current_entity_sequence": dep["current_entity_sequence"],
                "current_event_digest": dep["current_event_digest"],
                "direct_dependency_ids": list(dep["assumption_dependency_ids"]),
            }
        )
        stack_index[node] = len(stack_index)
        for child in dep["assumption_dependency_ids"]:
            _dfs(child)
        visited.add(node)

    for dep_id in assumption_dependency_ids:
        _dfs(dep_id)
    return traversed


def _admission_dependency_receipt_unsigned(
    *,
    assumption_id: str,
    candidate_predecessor_event_digest: str,
    assumption_registry_root: str,
    evidence_registry_root: str,
    assumption_dependency_ids: list[str],
    evidence_dependency_ids: list[str],
    traversed_dependencies: list[dict[str, Any]],
    evidence_eligibility_decisions: list[dict[str, object]],
    event_sequence: int,
) -> dict[str, object]:
    """Independently recompute the admission dependency receipt UNSIGNED value.

    Mirrors the validator's _admission_dependency_receipt_unsigned_value exactly.
    The candidate_entity_sequence is mechanically 2. Defect #1: the REAL
    assumption_registry_root (pre-ADMIT snapshot root) is bound, not "".
    """
    return {
        "schema_version": "assumption-dependency-validation/1",
        "assumption_dependency_ids": list(assumption_dependency_ids),
        "assumption_id": assumption_id,
        "assumption_registry_root": assumption_registry_root,
        "candidate_entity_sequence": 2,
        "candidate_predecessor_event_digest": candidate_predecessor_event_digest,
        "cycle_witness": [],
        "evidence_dependency_ids": list(evidence_dependency_ids),
        "evidence_eligibility_decisions": evidence_eligibility_decisions,
        "evidence_registry_root": evidence_registry_root,
        "event_sequence": event_sequence,
        "traversed_dependencies": traversed_dependencies,
        "validation_code": "DEPENDENCY_VALIDATION_PASSED",
        "validation_result": "PASS",
    }


# Schema versions and domain strings for the governed-ADMIT receipt chain
# (Defect #1). Mirror the validator exactly.
_SOD_DECISION_SCHEMA_VERSION = "assumption-separation-of-duty-decision/1"
_SOD_DOMAIN = "ASSUMPTION_SEPARATION_OF_DUTY_DECISION"
_GOVERNED_ADMIT_AUTH_SCHEMA_VERSION = "assumption-governed-admit-authorization/1"
_GRANT_SELECTION_DECISION_SCHEMA_VERSION = "assumption-grant-selection-decision/1"
_GOVERNMENT_AUTHORITY_ROLES = (
    "ADMITTER",
    "CHALLENGER",
    "CONFIRMER",
    "EXPIRY_AUTHORITY",
    "PROPOSER",
    "REJECTOR",
    "RESOLVER",
    "SUPERSEDER",
)
_OPERATION_TO_ROLE = {
    "PROPOSE": "PROPOSER",
    "ADMIT": "ADMITTER",
    "CONFIRM": "CONFIRMER",
    "CHALLENGE": "CHALLENGER",
    "RESOLVE_CHALLENGES": "RESOLVER",
    "REJECT": "REJECTOR",
    "EXPIRE": "EXPIRY_AUTHORITY",
    "SUPERSEDE": "SUPERSEDER",
}


def _scope_covers_request(scope_id: str, grant_scopes: tuple[str, ...] | list[str]) -> bool:
    gs = tuple(grant_scopes)
    return gs == ("scope:*",) or scope_id in gs


def _grant_selection_unsigned(
    *,
    entry: dict[str, Any],
    policy_context: dict[str, Any],
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    decision_type: str,
    grant: dict[str, Any] | None,
) -> dict[str, object]:
    """Mirrors the validator's _grant_selection_unsigned_value exactly."""
    decision_code = {
        "SELECTED": "ASSUMPTION_GRANT_SELECTED",
        "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
        "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
    }[decision_type]
    return {
        "schema_version": _GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_materiality": assumption_materiality,
        "authority_id": authority_id,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": entry["commit_receipt_digest"],
        "decision_code": decision_code,
        "decision_type": decision_type,
        "effective_from_sequence": entry["effective_from_sequence"],
        "event_sequence": event_sequence,
        "grant_digest": grant["grant_digest"] if grant is not None else None,
        "ledger_entry_digest": entry["ledger_entry_digest"],
        "ledger_root_digest": policy_context["ledger_root_digest"],
        "policy_digest": entry["policy_digest"],
        "policy_id": entry["policy_id"],
        "scope_id": scope_id,
        "selected_grant_id": grant["grant_id"] if grant is not None else None,
        "signing_payload_digest": entry["signing_payload_digest"],
    }


def _select_applicable_grant_for_fixture(
    entry: dict[str, Any],
    *,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    event_sequence: int,
) -> tuple[str, dict[str, Any] | None]:
    """Fixture-side grant selection for ADMIT (challenge_materiality=None).
    Mirrors the validator's _select_applicable_grant for non-resolution actions.
    """
    matches: list[dict[str, Any]] = []
    for grant in cast(list[dict[str, Any]], entry["grants"]):
        if cast(str, grant["action"]) != action:
            continue
        if cast(str, grant["authority_id"]) != authority_id:
            continue
        if not _scope_covers_request(scope_id, cast(list[str], grant["scope_ids"])):
            continue
        if assumption_materiality not in set(cast(list[str], grant["assumption_materialities"])):
            continue
        eff_from = cast(int, grant["effective_from_sequence"])
        eff_until = grant.get("effective_until_sequence")
        if event_sequence < eff_from:
            continue
        if eff_until is not None and event_sequence >= cast(int, eff_until):
            continue
        matches.append(grant)
    if not matches:
        return "NO_APPLICABLE_GRANT", None
    if len(matches) == 1:
        return "SELECTED", matches[0]
    return "AMBIGUOUS_GRANTS", None


def _sod_decision_unsigned(
    *,
    policy_context: dict[str, Any],
    assumption_history: list[dict[str, Any]],
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    assumption_id: str,
) -> dict[str, object]:
    """Mirrors the validator's _sod_decision_unsigned_value exactly, for ADMIT
    (challenge_materiality=None). Builds the full SeparationOfDutyDecision
    unsigned value including the I1-A selection_digest, B0 prior roles, and
    per-rule evaluations.
    """
    entry = cast(dict[str, Any], policy_context["ledger_entries"][0])
    decision_type, selected_grant = _select_applicable_grant_for_fixture(
        entry,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        event_sequence=event_sequence,
    )
    selection_unsigned = _grant_selection_unsigned(
        entry=entry,
        policy_context=policy_context,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        decision_type=decision_type,
        grant=selected_grant,
    )
    selection_digest = _domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", selection_unsigned)
    # B0 prior roles from the assumption history (events before candidate seq 2).
    prior_roles: set[str] = set()
    for ev in assumption_history:
        if cast(int, ev["entity_sequence"]) >= 2:
            break
        op = cast(str, cast(dict[str, Any], ev["payload"])["operation"])
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
        if cast(dict[str, Any], ev["payload"]).get(auth_field) == authority_id:
            prior_roles.add(_OPERATION_TO_ROLE[op])
    prior_ordered = tuple(role for role in _GOVERNMENT_AUTHORITY_ROLES if role in prior_roles)
    prior_set = set(prior_ordered)
    rules = cast(list[dict[str, Any]], entry.get("duty_rules", []))
    exceptions = cast(list[dict[str, Any]], entry.get("duty_exceptions", []))
    rule_evaluations: list[dict[str, object]] = []
    conflicting_union: set[str] = set()
    waived_union: set[str] = set()
    remaining_union: set[str] = set()
    evaluated_rule_digests: list[str] = []
    waiving_exception_digests: list[str] = []
    for rule in rules:
        if cast(str, rule["action"]) != action:
            continue
        if not _scope_covers_request(scope_id, cast(list[str], rule["scope_ids"])):
            continue
        if assumption_materiality not in set(cast(list[str], rule["assumption_materialities"])):
            continue
        # Defect #1 (fixed): every APPLICABLE rule emits a rule evaluation entry,
        # including when it has zero actual conflicts. Matches production
        # (_assumption_separation_duty_evaluator) and the validator's
        # _sod_decision_unsigned_value exactly.
        rule_conflicts = prior_set & set(cast(list[str], rule["conflicting_roles"]))
        rule_waived: set[str] = set()
        rule_waiving: list[tuple[str, str]] = []
        for exception in exceptions:
            if cast(str, exception["rule_id"]) != cast(str, rule["rule_id"]):
                continue
            if cast(str, exception["action"]) != action:
                continue
            if cast(str, exception["authority_id"]) != authority_id:
                continue
            if not _scope_covers_request(scope_id, cast(list[str], exception["scope_ids"])):
                continue
            if assumption_materiality not in set(
                cast(list[str], exception["assumption_materialities"])
            ):
                continue
            exc_assumptions = cast(list[str], exception.get("assumption_ids", []))
            if exc_assumptions and assumption_id not in exc_assumptions:
                continue
            eff_from = cast(int, exception["effective_from_sequence"])
            eff_until = cast(int, exception["effective_until_sequence"])
            if not (eff_from <= event_sequence < eff_until):
                continue
            waived_by_this = set(cast(list[str], exception["conflicting_roles"])) & rule_conflicts
            if waived_by_this:
                rule_waived |= waived_by_this
                rule_waiving.append(
                    (cast(str, exception["exception_id"]), cast(str, exception["exception_digest"]))
                )
        rule_waiving.sort(key=lambda pair: pair[0])
        rule_remaining = rule_conflicts - rule_waived
        rule_evaluations.append(
            {
                "rule_id": rule["rule_id"],
                "rule_digest": rule["rule_digest"],
                "conflicting_roles": [
                    r for r in _GOVERNMENT_AUTHORITY_ROLES if r in rule_conflicts
                ],
                "waiving_exceptions": [list(pair) for pair in rule_waiving],
                "waived_roles": [r for r in _GOVERNMENT_AUTHORITY_ROLES if r in rule_waived],
                "remaining_conflicts": [
                    r for r in _GOVERNMENT_AUTHORITY_ROLES if r in rule_remaining
                ],
            }
        )
        evaluated_rule_digests.append(cast(str, rule["rule_digest"]))
        conflicting_union |= rule_conflicts
        waived_union |= rule_waived
        remaining_union |= rule_remaining
        waiving_exception_digests.extend(digest for _eid, digest in rule_waiving)
    conflicting_ordered = [r for r in _GOVERNMENT_AUTHORITY_ROLES if r in conflicting_union]
    waived_ordered = [r for r in _GOVERNMENT_AUTHORITY_ROLES if r in waived_union]
    remaining_ordered = [r for r in _GOVERNMENT_AUTHORITY_ROLES if r in remaining_union]
    decision = "ALLOW" if decision_type == "SELECTED" and not remaining_union else "DENY"
    return {
        "schema_version": _SOD_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_id": assumption_id,
        "assumption_materiality": assumption_materiality,
        "candidate_entity_sequence": 2,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": entry["commit_receipt_digest"],
        "conflicting_roles": conflicting_ordered,
        "decision": decision,
        "event_sequence": event_sequence,
        "authority_id": authority_id,
        "evaluated_rule_digests": evaluated_rule_digests,
        "grant_digest": selected_grant["grant_digest"] if selected_grant is not None else None,
        "ledger_root_digest": policy_context["ledger_root_digest"],
        "policy_digest": entry["policy_digest"],
        "prior_roles": list(prior_ordered),
        "remaining_conflicts": remaining_ordered,
        "rule_evaluations": rule_evaluations,
        "scope_id": scope_id,
        "selected_grant_id": selected_grant["grant_id"] if selected_grant is not None else None,
        "selection_decision_type": decision_type,
        "selection_digest": selection_digest,
        "waived_roles": waived_ordered,
        "waiving_exception_digests": waiving_exception_digests,
    }


def _governed_admit_authorization_digest(
    *,
    admitting_authority_id: str,
    assumption_id: str,
    assumption_materiality: str,
    assumption_registry_root: str,
    candidate_predecessor_event_digest: str,
    dep_receipt_unsigned: dict[str, object],
    event_sequence: int,
    evidence_registry_root: str,
    scope_ids: tuple[str, ...],
    sod_decisions: list[dict[str, object]],
    policy_context: dict[str, Any],
    assumption_history: list[dict[str, Any]],
) -> str:
    """Compute the GovernedAdmitAuthorization digest. Mirrors the validator's
    _governed_admit_authorization_unsigned_value + domain digest exactly.
    """
    dep_receipt_digest = _domain_digest("ASSUMPTION_DEPENDENCY_VALIDATION", dep_receipt_unsigned)
    dep_receipt_value = {**dep_receipt_unsigned, "receipt_digest": dep_receipt_digest}
    sod_values: list[dict[str, object]] = []
    for sod_unsigned in sod_decisions:
        dd = _domain_digest(_SOD_DOMAIN, sod_unsigned)
        sod_values.append({**sod_unsigned, "decision_digest": dd})
    auth_unsigned = {
        "schema_version": _GOVERNED_ADMIT_AUTH_SCHEMA_VERSION,
        "admitting_authority_id": admitting_authority_id,
        "assumption_id": assumption_id,
        "assumption_materiality": assumption_materiality,
        "assumption_registry_root": assumption_registry_root,
        "candidate_entity_sequence": 2,
        "candidate_predecessor_event_digest": candidate_predecessor_event_digest,
        "dependency_validation_receipt": dep_receipt_value,
        "event_sequence": event_sequence,
        "evidence_registry_root": evidence_registry_root,
        "scope_ids": list(scope_ids),
        "sod_decisions": sod_values,
    }
    return _domain_digest("ASSUMPTION_GOVERNED_ADMIT_AUTHORIZATION", auth_unsigned)


def _pre_admit_snapshot_root(envelopes_so_far: list[dict[str, Any]]) -> str:
    """Compute the assumption registry snapshot root of the projections
    reachable from ``envelopes_so_far`` (each entity's current head). This is
    the pre-ADMIT root the governed authorization binds."""
    return _snapshot_root(envelopes_so_far)


def _evidence_decision_unsigned_for(
    evidence_id: str,
    admit_clock: int,
) -> dict[str, object]:
    """Canonical unsigned A0 decision value for ``evidence_id`` bound to
    ``admit_clock``. Mirrors the validator's _evidence_admission_unsigned_value.
    """
    eligible = True
    code = "EVIDENCE_ADMISSION_ELIGIBLE"
    current_event_digest = (
        "sha256:" + hashlib.sha256(b"evidence-event\0" + evidence_id.encode("utf-8")).hexdigest()
    )
    current_status = "ADMITTED"
    return _evidence_decision_unsigned(
        evidence_id=evidence_id,
        eligible=eligible,
        code=code,
        evaluated_at_sequence=admit_clock,
        current_event_digest=current_event_digest,
        current_status=current_status,
    )


def _admit_payload(aid: str) -> dict[str, object]:
    """Placeholder ADMIT payload. The admission_receipt_digest is finalized by
    _finalize_admission_receipts after every event is built (the receipt digest
    depends on the candidate PROPOSE state, dependency projections, and
    evidence decisions, which are only fully known once all events exist)."""
    return {
        "operation": "ADMIT",
        "admitting_authority_id": "authority:admitter",
        "admission_receipt_digest": _receipt(f"{aid}:admit-receipt-placeholder"),
    }


def _finalize_admission_receipts(
    envelopes: list[dict[str, Any]],
    evidence_registry_root: str,
    policy_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Recompute every ADMIT event's governed-ADMIT receipt chain from the
    candidate PROPOSE state + dependency projections + evidence decisions +
    per-scope SoD decisions, then rebuild the per-entity event chain.

    Defect #1: the envelope's ``source_receipt_digest`` binds the
    DependencyValidationReceipt receipt_digest (computed with the REAL pre-ADMIT
    assumption_registry_root), and the payload's ``admission_receipt_digest``
    binds the GovernedAdmitAuthorization authorization_digest (cross-binding the
    dep receipt + both roots + authority + materiality + scope_ids + per-scope
    SoD decisions).

    Each event's ORIGINAL ``previous_entity_event_digest`` is preserved as-is
    unless it pointed at an earlier event of the same entity whose digest was
    itself rebuilt (in which case it is re-pointed to keep the chain
    internally consistent). Intentionally-broken predecessors (rejected
    vectors) are therefore preserved. Mirrors the validator's admission gate
    exactly. Returns a NEW list of rebuilt envelopes (the input is not mutated).
    """
    # Map: (entity_id, entity_sequence) -> (old_digest, new_digest), so a
    # later event whose predecessor legitimately pointed at the old digest can
    # be re-pointed at the rebuilt digest. Intentionally-broken predecessors
    # (which point at nothing real) are preserved verbatim.
    digest_map: dict[tuple[str, int], tuple[str | None, str]] = {}
    rebuilt: list[dict[str, Any]] = []
    for raw_event in envelopes:
        event = deepcopy(raw_event)
        aid = event["entity_id"]
        seq = event["entity_sequence"]
        payload = event["payload"]
        old_digest = event.get("registry_event_digest")
        original_previous = event.get("previous_entity_event_digest")
        # Re-point the predecessor at the rebuilt digest iff the original
        # predecessor pointed at the real (old) digest of the immediately
        # preceding same-entity event. This preserves intentionally-broken
        # predecessors (which match no real prior event) while keeping
        # legitimate chains consistent when an earlier ADMIT's digest changed.
        prior = digest_map.get((aid, seq - 1))
        if (
            prior is not None
            and prior[0] is not None
            and original_previous == prior[0]
            and prior[1] != prior[0]
        ):
            event["previous_entity_event_digest"] = prior[1]
        if payload.get("operation") == "ADMIT":
            # Recompute the governed-ADMIT receipt chain. The candidate's PROPOSE
            # state is the entity's entity_sequence-1 event; dependency
            # projections come from the rebuilt envelopes built so far. Skip
            # recomputation when the predecessor is absent or is not a PROPOSE
            # (malformed-by-design rejected vectors such as AV-R02 / AV-R04
            # revival leave the placeholder receipt).
            propose_event = _find_entity_seq(rebuilt, aid, seq - 1)
            if propose_event is not None and propose_event["payload"].get("operation") == "PROPOSE":
                projections = _projection_state(rebuilt)
                propose_payload = propose_event["payload"]
                assumption_dependency_ids = list(propose_payload["assumption_dependency_ids"])
                evidence_dependency_ids = list(propose_payload["evidence_dependency_ids"])
                traversed = _admission_traversal(aid, assumption_dependency_ids, projections)
                evidence_decisions_unsigned = [
                    _evidence_decision_unsigned_for(eid, event["clock_sequence"])
                    for eid in sorted(evidence_dependency_ids)
                ]
                # Pre-ADMIT assumption_registry_root: snapshot root of the
                # rebuilt envelopes built so far (candidate still at PROPOSE).
                assumption_registry_root = _pre_admit_snapshot_root(rebuilt)
                dep_receipt_unsigned = _admission_dependency_receipt_unsigned(
                    assumption_id=aid,
                    candidate_predecessor_event_digest=propose_event["registry_event_digest"],
                    assumption_registry_root=assumption_registry_root,
                    evidence_registry_root=evidence_registry_root,
                    assumption_dependency_ids=assumption_dependency_ids,
                    evidence_dependency_ids=evidence_dependency_ids,
                    traversed_dependencies=traversed,
                    evidence_eligibility_decisions=evidence_decisions_unsigned,
                    event_sequence=event["clock_sequence"],
                )
                dep_receipt_digest = _domain_digest(
                    "ASSUMPTION_DEPENDENCY_VALIDATION", dep_receipt_unsigned
                )
                # Per-scope SoD decisions (ADMIT, challenge_materiality=None).
                scope_ids = tuple(sorted(propose_payload["scope_ids"]))
                materiality = propose_payload["materiality"]
                admitting_authority_id = payload["admitting_authority_id"]
                assumption_history = [
                    e for e in rebuilt if e["entity_id"] == aid and e["entity_sequence"] < seq
                ]
                sod_decisions = [
                    _sod_decision_unsigned(
                        policy_context=policy_context,
                        assumption_history=assumption_history,
                        action="ADMIT",
                        authority_id=admitting_authority_id,
                        scope_id=scope_id,
                        assumption_materiality=materiality,
                        challenge_materiality=None,
                        event_sequence=event["clock_sequence"],
                        assumption_id=aid,
                    )
                    for scope_id in scope_ids
                ]
                auth_digest = _governed_admit_authorization_digest(
                    admitting_authority_id=admitting_authority_id,
                    assumption_id=aid,
                    assumption_materiality=materiality,
                    assumption_registry_root=assumption_registry_root,
                    candidate_predecessor_event_digest=propose_event["registry_event_digest"],
                    dep_receipt_unsigned=dep_receipt_unsigned,
                    event_sequence=event["clock_sequence"],
                    evidence_registry_root=evidence_registry_root,
                    scope_ids=scope_ids,
                    sod_decisions=sod_decisions,
                    policy_context=policy_context,
                    assumption_history=assumption_history,
                )
                # Bind: source_receipt_digest = dep receipt; admission_receipt_digest = auth.
                event["source_receipt_digest"] = dep_receipt_digest
                payload["admission_receipt_digest"] = auth_digest
        # Rebuild this event's own registry_event_digest from its payload and
        # (possibly re-pointed) predecessor.
        unsigned = deepcopy(event)
        unsigned.pop("registry_event_digest", None)
        new_event = cast("RegistryEvent", RegistryEvent.build(unsigned)).to_json_value()
        digest_map[(aid, seq)] = (old_digest, new_event["registry_event_digest"])
        rebuilt.append(new_event)
    return rebuilt


def _find_entity_seq(
    envelopes: list[dict[str, Any]],
    entity_id: str,
    entity_sequence: int,
) -> dict[str, Any] | None:
    for ev in envelopes:
        if ev["entity_id"] == entity_id and ev["entity_sequence"] == entity_sequence:
            return ev
    return None


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


def _fixture_run_dfs(
    root_id: str,
    root_proj: dict[str, Any],
    projections: dict[str, dict[str, Any]],
    clock: int,
) -> dict[str, Any]:
    """Run the per-evaluation assumption dependency DFS for the fixture builder,
    mirroring the validator's _evaluate_one_use_assumption DFS exactly.

    Returns a dict with: traversed_records, cycle_witness, failed, code,
    dep_edges. Module-level (not a closure) to keep the linter happy and to
    mirror the validator structure.
    """
    traversed_records: list[dict[str, object]] = []
    cycle_witness: list[str] = []
    failed = False
    code = ""
    dep_edges = 0
    dfs_stack = [root_id]
    dfs_stack_index: dict[str, int] = {root_id: 0}
    dfs_visited: set[str] = set()

    def _dfs(node: str) -> None:
        nonlocal failed, code, dep_edges
        if failed:
            return
        if node in dfs_stack_index:
            i = dfs_stack_index[node]
            raw = tuple(dfs_stack[i:] + [node])
            cycle_witness.extend(_canonical_cycle_witness_fixture(raw))
            failed = True
            code = "ASSUMPTION_USE_DEPENDENCY_CYCLE"
            return
        if node in dfs_visited:
            return
        dproj = projections.get(node)
        if dproj is None:
            traversed_records.append(
                _traversed_state(node, None, "ASSUMPTION_USE_DEPENDENCY_MISSING", 0)
            )
            failed = True
            code = "ASSUMPTION_USE_DEPENDENCY_MISSING"
            return
        dhist = dproj["history_event_count"]
        dgate = _self_gate_code_fixture(dproj, clock)
        if dgate is not None:
            traversed_records.append(_traversed_state(node, dproj, dgate, dhist))
            failed = True
            code = dgate
            return
        traversed_records.append(
            _traversed_state(node, dproj, "ASSUMPTION_USE_NODE_PRESENT", dhist)
        )
        dfs_stack_index[node] = len(dfs_stack)
        dfs_stack.append(node)
        # Defect #2b (fixed): count one examined edge per _dfs(child) invocation
        # from this parent's dependency list, BEFORE the recursive call. Matches
        # production's _replay_dfs_closure and the validator's _dfs. The edge is
        # counted regardless of whether the child is new, already visited, or
        # terminal; the failed short-circuit prevents counting children after a
        # sibling already terminated the DFS.
        for child in dproj["assumption_dependency_ids"]:
            if failed:
                break
            dep_edges += 1
            _dfs(child)
        if not failed:
            dfs_stack.pop()
            del dfs_stack_index[node]
            dfs_visited.add(node)

    for dep_id in root_proj["assumption_dependency_ids"]:
        if failed:
            break
        # Defect #2b (fixed): each top-level dependency edge from the root is
        # counted before the _dfs invocation, matching production.
        dep_edges += 1
        _dfs(dep_id)
    return {
        "traversed_records": traversed_records,
        "cycle_witness": cycle_witness,
        "failed": failed,
        "code": code,
        "dep_edges": dep_edges,
    }


def _use_decision_unsigned(
    *,
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    policy_context: dict[str, Any],
) -> tuple[dict[str, object], str, bool, str]:
    """Independently reconstruct the production AssumptionUseAdmissibilityDecision
    unsigned value by replaying the full D3.2-B use-time evaluation from the
    envelopes + binding. Defect #2: the decision_digest is computed over the
    production receipt shape (binding + evaluated_assumptions +
    evaluation_work), not a flat synthetic decision.

    Returns ``(decision_unsigned, reported_code, admissible, first_event_digest)``.
    """
    projections = _fixture_projections(envelopes)
    required = list(cast(list[str], binding["required_assumption_ids"]))
    clock = cast(int, binding["logical_clock_sequence"])
    decision_id = cast(str, binding["decision_id"])
    evidence_requests = cast(dict[str, Any], binding.get("evidence_requests", {}))
    # Work counters, cross-evaluation dedup.
    histories = 0
    events_count = 0
    unique_nodes = 0
    dep_edges = 0
    evidence_refs = 0
    challenges_count = 0
    shared_visited: set[str] = set()

    def _count_node(node_id: str, node_history: int, node_challenges: int) -> None:
        """Record one unique node in the work counters (Defect #2a). Mirrors
        the validator's _record_self_node + _record_traversed_nodes: each unique
        assumption_id contributes one history + one unique_node, its
        history_event_count to events, and its active-challenge count."""
        nonlocal histories, events_count, unique_nodes, challenges_count
        if node_id in shared_visited:
            return
        shared_visited.add(node_id)
        histories += 1
        events_count += node_history
        unique_nodes += 1
        challenges_count += node_challenges

    evaluated_assumptions: list[dict[str, object]] = []
    reported_code = "ASSUMPTION_USE_ALLOWED"
    first_event_digest: str | None = None
    for aid in required:
        proj = projections.get(aid)
        if proj is None:
            self_state = _traversed_state(aid, None, "ASSUMPTION_USE_MISSING", 0)
            # Defect #2a (fixed): a top-level MISSING node still counts as one
            # unique history/node (0 events, 0 challenges), matching production.
            _count_node(aid, 0, 0)
            evaluated_assumptions.append(
                _use_evaluation(aid, "ASSUMPTION_USE_MISSING", "DENY", self_state, [], [], [])
            )
            if reported_code == "ASSUMPTION_USE_ALLOWED":
                reported_code = "ASSUMPTION_USE_MISSING"
            continue
        history_event_count = proj["history_event_count"]
        gate_code = _self_gate_code_fixture(proj, clock)
        if gate_code is not None:
            self_state = _traversed_state(aid, proj, gate_code, history_event_count)
            _count_node(aid, history_event_count, len(proj["active_challenge_ids"]))
            evaluated_assumptions.append(
                _use_evaluation(aid, gate_code, "DENY", self_state, [], [], [])
            )
            if reported_code == "ASSUMPTION_USE_ALLOWED":
                reported_code = gate_code
                first_event_digest = proj["current_event_digest"]
            continue
        self_state = _traversed_state(aid, proj, "ASSUMPTION_USE_NODE_PRESENT", history_event_count)
        # DFS (module-level helper to avoid closure-in-loop lint warnings).
        dfs_result = _fixture_run_dfs(aid, proj, projections, clock)
        traversed_records = dfs_result["traversed_records"]
        cycle_witness = dfs_result["cycle_witness"]
        dfs_failed = dfs_result["failed"]
        dfs_code = dfs_result["code"]
        dep_edges += dfs_result["dep_edges"]
        _count_node(aid, history_event_count, len(proj["active_challenge_ids"]))
        # Defect #2a (fixed): every traversed dependency node counts toward
        # histories/events/unique_nodes/challenges, deduplicated by id. Mirrors
        # production's _validate_work_counters and the validator's
        # _record_traversed_nodes.
        for rec in cast(list[dict[str, object]], traversed_records):
            _count_node(
                cast(str, rec["assumption_id"]),
                cast(int, rec["history_event_count"]),
                len(cast(list[str], rec["active_challenge_ids"])),
            )
        if dfs_failed:
            evaluated_assumptions.append(
                _use_evaluation(
                    aid, dfs_code, "DENY", self_state, traversed_records, cycle_witness, []
                )
            )
            if reported_code == "ASSUMPTION_USE_ALLOWED":
                reported_code = dfs_code
                first_event_digest = proj["current_event_digest"]
            continue
        # Evidence phase.
        ordered_ids = [aid] + [cast(str, rec["assumption_id"]) for rec in traversed_records]
        evidence_evaluations: list[dict[str, object]] = []
        evidence_failed = False
        evidence_code = ""
        for owner_id in ordered_ids:
            if evidence_failed:
                break
            oproj = projections.get(owner_id)
            if oproj is None:
                continue
            for eid in oproj["evidence_dependency_ids"]:
                pinned = evidence_requests.get(eid)
                if pinned is None:
                    evidence_failed = True
                    evidence_code = "ASSUMPTION_USE_EVIDENCE_REQUEST_MISSING"
                    break
                # Rebuild request digest.
                rebuilt_req_unsigned = {
                    "schema_version": "evidence-use-request/1",
                    "accepted_limitation_codes": sorted(oproj["limitations"]),
                    "clock_sequence": clock,
                    "decision_id": decision_id,
                    "evidence_id": eid,
                    "proposition_id": oproj["proposition_id"],
                    "required_reuse_class": oproj["maximum_reuse_class"],
                    "scope_ids": sorted(oproj["scope_ids"]),
                }
                rebuilt_req_digest = _domain_digest("EVIDENCE_USE_REQUEST", rebuilt_req_unsigned)
                pinned_req = pinned["request"]
                if pinned_req.get("request_digest") != rebuilt_req_digest:
                    evidence_failed = True
                    evidence_code = "ASSUMPTION_USE_EVIDENCE_REQUEST_MISMATCH"
                    break
                pinned_receipt = pinned["receipt"]
                receipt_unsigned = {
                    "schema_version": "evidence-admissibility-receipt/1",
                    "advisory_codes": sorted(set(pinned_receipt.get("advisory_codes", []))),
                    "allowed": pinned_receipt.get("allowed"),
                    "authority_policy_digest": pinned_receipt.get("authority_policy_digest"),
                    "challenge_policy_digest": pinned_receipt.get("challenge_policy_digest"),
                    "code": pinned_receipt.get("code"),
                    "dependency_event_digests": sorted(
                        pinned_receipt.get("dependency_event_digests", [])
                    ),
                    "evidence_event_digest": pinned_receipt.get("evidence_event_digest"),
                    "evidence_id": eid,
                    "request_digest": pinned_req.get("request_digest"),
                }
                rebuilt_receipt_digest = _domain_digest(
                    "EVIDENCE_ADMISSIBILITY_RECEIPT", receipt_unsigned
                )
                if pinned_receipt.get("receipt_digest") != rebuilt_receipt_digest:
                    evidence_failed = True
                    evidence_code = "ASSUMPTION_USE_EVIDENCE_RECEIPT_INVALID"
                    break
                evidence_refs += 1
                evidence_evaluations.append(
                    {
                        "owner_assumption_id": owner_id,
                        "request": pinned_req,
                        "receipt": pinned_receipt,
                    }
                )
                if pinned_receipt.get("allowed") is not True:
                    evidence_failed = True
                    evidence_code = cast(str, pinned_receipt.get("code", "EVIDENCE_INADMISSIBLE"))
                    break
        if evidence_failed:
            evaluated_assumptions.append(
                _use_evaluation(
                    aid,
                    evidence_code,
                    "DENY",
                    self_state,
                    traversed_records,
                    [],
                    evidence_evaluations,
                )
            )
            if reported_code == "ASSUMPTION_USE_ALLOWED":
                reported_code = evidence_code
                first_event_digest = proj["current_event_digest"]
            continue
        evaluated_assumptions.append(
            _use_evaluation(
                aid,
                "ASSUMPTION_USE_ALLOWED",
                "ALLOW",
                self_state,
                traversed_records,
                [],
                evidence_evaluations,
            )
        )
    admissible = all(cast(str, ev["result"]) == "ALLOW" for ev in evaluated_assumptions)
    evaluation_work_unsigned = {
        "schema_version": "assumption-evaluation-work/1",
        "active_challenges_evaluated": challenges_count,
        "assumption_dependency_edges_examined": dep_edges,
        "assumption_events_replayed": events_count,
        "assumption_histories_reconstructed": histories,
        "authority_decisions_evaluated": 0,
        "evidence_dependency_references_evaluated": evidence_refs,
        "separation_duty_rules_evaluated": 0,
        "unique_assumption_nodes_evaluated": unique_nodes,
    }
    work_digest = _domain_digest("ASSUMPTION_EVALUATION_WORK", evaluation_work_unsigned)
    binding_value = {
        "schema_version": "decision-assumption-binding/1",
        "assumption_registry_root": binding["assumption_registry_root"],
        "control_state_digest": binding["control_state_digest"],
        "decision_id": binding["decision_id"],
        "evidence_registry_root": binding["evidence_registry_root"],
        "logical_clock_sequence": binding["logical_clock_sequence"],
        "required_assumption_ids": list(binding["required_assumption_ids"]),
        "semantic_projection_receipt_digest": binding["semantic_projection_receipt_digest"],
        "validated_event_digest": binding["validated_event_digest"],
        "binding_digest": binding["binding_digest"],
    }
    decision_unsigned: dict[str, object] = {
        "schema_version": "assumption-use-admissibility-decision/1",
        "admissible": admissible,
        "binding": binding_value,
        "evaluated_assumptions": evaluated_assumptions,
        "evaluation_work": {**evaluation_work_unsigned, "work_digest": work_digest},
    }
    decision_digest = _domain_digest("ASSUMPTION_USE_ADMISSIBILITY_DECISION", decision_unsigned)
    return (
        {**decision_unsigned, "decision_digest": decision_digest},
        reported_code,
        admissible,
        first_event_digest or "",
    )


def _fixture_projections(envelopes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Replay envelopes to derive each assumption's projected state for the
    use-time evaluator. Mirrors the validator's IndependentAssumptionProjection
    fields needed by the use-time DFS + evidence phase."""
    by_entity: dict[str, list[dict[str, Any]]] = {}
    for ev in envelopes:
        by_entity.setdefault(ev["entity_id"], []).append(ev)
    projections: dict[str, dict[str, Any]] = {}
    for aid, evs in by_entity.items():
        standing = "PROPOSED"
        active: set[str] = set()
        propose_payload: dict[str, Any] = {}
        last_event = evs[-1]
        for ev in evs:
            payload = ev["payload"]
            op = payload["operation"]
            if op == "PROPOSE":
                standing = "PROPOSED"
                propose_payload = dict(payload)
            elif op == "ADMIT":
                standing = "ADMITTED"
            elif op == "CONFIRM":
                standing = "CONFIRMED"
            elif op == "CHALLENGE":
                active.add(payload["challenge_id"])
            elif op == "RESOLVE_CHALLENGES":
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
        projections[aid] = {
            "assumption_id": aid,
            "proposition_id": propose_payload.get("proposition_id"),
            "scope_ids": list(propose_payload.get("scope_ids", [])),
            "materiality": propose_payload.get("materiality"),
            "valid_from_sequence": propose_payload.get("valid_from_sequence"),
            "expires_at_sequence": propose_payload.get("expires_at_sequence"),
            "assumption_dependency_ids": list(propose_payload.get("assumption_dependency_ids", [])),
            "evidence_dependency_ids": list(propose_payload.get("evidence_dependency_ids", [])),
            "limitations": list(propose_payload.get("limitations", [])),
            "maximum_reuse_class": propose_payload.get("maximum_reuse_class"),
            "standing": standing,
            "active_challenge_ids": tuple(sorted(active)),
            "current_event_digest": last_event["registry_event_digest"],
            "current_entity_sequence": last_event["entity_sequence"],
            "history_event_count": len(evs),
        }
    return projections


def _self_gate_code_fixture(proj: dict[str, Any], clock: int) -> str | None:
    """Mirror the validator's _self_gate_code for the fixture projections."""
    standing = proj["standing"]
    if standing in _TERMINAL:
        return "ASSUMPTION_USE_TERMINAL"
    if standing not in _ACTIVE:
        return "ASSUMPTION_USE_NOT_ADMITTED"
    if proj["active_challenge_ids"]:
        return "ASSUMPTION_USE_CHALLENGED"
    if clock < cast(int, proj["valid_from_sequence"]):
        return "ASSUMPTION_USE_NOT_YET_VALID"
    expires = proj["expires_at_sequence"]
    if expires is not None and clock >= cast(int, expires):
        return "ASSUMPTION_USE_EXPIRED"
    return None


def _traversed_state(
    aid: str,
    proj: dict[str, Any] | None,
    code: str,
    history_event_count: int,
) -> dict[str, object]:
    """Mirror the validator's _traversed_to_json_value."""
    if proj is None:
        return {
            "assumption_id": aid,
            "validation_code": code,
            "current_event_digest": None,
            "current_entity_sequence": None,
            "history_event_count": history_event_count,
            "proposition_id": None,
            "scope_ids": [],
            "materiality": None,
            "standing": None,
            "active_challenge_ids": [],
            "valid_from_sequence": None,
            "expires_at_sequence": None,
            "assumption_dependency_ids": [],
            "evidence_dependency_ids": [],
            "limitations": [],
            "maximum_reuse_class": None,
        }
    return {
        "assumption_id": aid,
        "validation_code": code,
        "current_event_digest": proj["current_event_digest"],
        "current_entity_sequence": proj["current_entity_sequence"],
        "history_event_count": history_event_count,
        "proposition_id": proj["proposition_id"],
        "scope_ids": list(proj["scope_ids"]),
        "materiality": proj["materiality"],
        "standing": proj["standing"],
        "active_challenge_ids": list(proj["active_challenge_ids"]),
        "valid_from_sequence": proj["valid_from_sequence"],
        "expires_at_sequence": proj["expires_at_sequence"],
        "assumption_dependency_ids": list(proj["assumption_dependency_ids"]),
        "evidence_dependency_ids": list(proj["evidence_dependency_ids"]),
        "limitations": list(proj["limitations"]),
        "maximum_reuse_class": proj["maximum_reuse_class"],
    }


def _use_evaluation(
    aid: str,
    code: str,
    result: str,
    self_state: dict[str, object],
    traversed: list[dict[str, object]],
    cycle_witness: list[str],
    evidence_evaluations: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "assumption_id": aid,
        "validation_code": code,
        "result": result,
        "self_state": self_state,
        "traversed_dependencies": list(traversed),
        "cycle_witness": list(cycle_witness),
        "evidence_evaluations": list(evidence_evaluations),
    }


def _canonical_cycle_witness_fixture(raw_cycle: tuple[str, ...]) -> tuple[str, ...]:
    smallest_idx = min(range(len(raw_cycle) - 1), key=lambda i: raw_cycle[i])
    return raw_cycle[smallest_idx:-1] + raw_cycle[:smallest_idx] + (raw_cycle[smallest_idx],)


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


def _admissibility_for(
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    policy_context: dict[str, Any],
) -> dict[str, Any]:
    """Compute the production-shaped expected_admissibility for a binding by
    replaying the full use-time evaluation. Defect #2: this replaces the flat
    synthetic decision with the production AssumptionUseAdmissibilityDecision
    shape, so the pinned decision_digest matches the validator byte-for-byte.
    """
    decision, reported_code, admissible, _ = _use_decision_unsigned(
        binding=binding,
        envelopes=envelopes,
        policy_context=policy_context,
    )
    return {
        "allowed": admissible,
        "code": reported_code,
        "decision_digest": decision["decision_digest"],
    }


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
    del (
        assumption_id,
        extra_histories,
        extra_events,
        extra_nodes,
        extra_edges,
        extra_evidence,
        extra_challenges,
    )  # derived from envelopes
    return _admissibility_for(binding, envelopes, policy_context)


def _denied_admissibility(
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    assumption_id: str,
    policy_context: dict[str, Any],
    code: str,
    *,
    extra_histories: int = 0,
    extra_events: int = 0,
    extra_nodes: int = 0,
    extra_edges: int = 0,
    extra_evidence: int = 0,
) -> dict[str, Any]:
    del (
        assumption_id,
        code,
        extra_histories,
        extra_events,
        extra_nodes,
        extra_edges,
        extra_evidence,
    )  # derived from envelopes
    return _admissibility_for(binding, envelopes, policy_context)


def _denied_two_assumption_admissibility(
    binding: dict[str, Any],
    envelopes: list[dict[str, Any]],
    *,
    first_assumption_id: str,
    second_assumption_id: str,
    policy_context: dict[str, Any],
    code: str,
) -> dict[str, Any]:
    del first_assumption_id, second_assumption_id, code  # derived from envelopes
    return _admissibility_for(binding, envelopes, policy_context)


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


def _evidence_request_inadmissible(
    *,
    evidence_id: str,
    owner_proposition: str,
    owner_scopes: list[str],
    owner_reuse: str,
    clock: int,
    owner_limitations: list[str],
    policy_context: dict[str, Any],
    code: str,
) -> dict[str, Any]:
    """Build a complete D2 EvidenceUseRequest + INADMISSIBLE receipt pair.

    The request digest is recomputed from the owner's projected state (so the
    use-time evidence phase binds the request to the owner), and the receipt is
    rebuilt from its canonical fields with allowed=False and the given denial
    code. The validator's use-time evidence phase fail-closes on this receipt
    and raises the receipt's code.
    """
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
        allowed=False,
        code=code,
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
    policy_context: dict[str, Any],
    *,
    use_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
        av_a15,
        av_a16,
        av_a17,
        av_a18,
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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


def av_a15(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A15: Root and dependency BOTH have evidence dependencies, making the
    frozen D3.2-B DFS-then-evidence ordering observable.

    A depends on B; A owns evidence:a15ae and B owns evidence:a15be. The
    complete DFS runs first (collecting [A, B] in first-discovery order), THEN
    evidence evaluates in first-discovery order (A's evidence first). A's use-
    time D2 receipt is INADMISSIBLE, so the evidence phase denies after
    evaluating exactly ONE evidence reference (A's). A depth-first post-order
    evaluator (the prior defect) would have evaluated B's evidence first -- two
    references -- before reaching A's denial. The pinned
    ``evidence_dependency_references_evaluated == 1`` therefore proves the
    first-discovery ordering and would break under post-order evaluation.
    """
    aid_a = "assumption:a15a"
    aid_b = "assumption:a15b"
    evidence_a = "evidence:a15ae"
    evidence_b = "evidence:a15be"
    evidence_deny_code = "EVIDENCE_REUSE_EXHAUSTED"
    # B owns evidence_b; admitted at clock 2.
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=1, expires_at=30, evidence_deps=(evidence_b,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload=_admit_payload(aid_b),
    )
    # A depends on B, owns evidence_a; admitted at clock 4.
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(
            clock=3, expires_at=30, assumption_deps=(aid_b,), evidence_deps=(evidence_a,)
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
    envelopes = [e_b, e_b2, e_a, e_a2]
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    evidence_requests = {
        # A's use-time evidence is INADMISSIBLE; under first-discovery order it
        # is evaluated first and denies after exactly one evidence reference.
        evidence_a: _evidence_request_inadmissible(
            evidence_id=evidence_a,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=5,
            owner_limitations=[],
            policy_context=policy_context,
            code=evidence_deny_code,
        ),
        evidence_b: _evidence_request_for(
            evidence_id=evidence_b,
            owner_proposition="control.connected",
            owner_scopes=[SCOPE],
            owner_reuse="D2",
            clock=5,
            owner_limitations=[],
            policy_context=policy_context,
        ),
    }
    binding = _finalize_binding_for_vector(
        envelopes,
        _simple_use_binding(assumption_id=aid_a, clock=5, evidence_requests=evidence_requests),
    )

    # Work counters: DFS completes fully (2 histories, 4 events, 2 nodes, 1
    # edge A->B), then evidence evaluates A first and denies after ONE evidence
    # reference (B's evidence is never reached). evidence_refs=1 pins the
    # first-discovery order.
    vector = _accepted_vector(
        "AV-A15",
        "Root+dep both carry evidence; DFS completes, then evidence denies on root first.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_admissibility(
            binding,
            envelopes,
            aid_a,
            policy_context,
            code=evidence_deny_code,
            extra_histories=1,
            extra_events=2,
            extra_nodes=1,
            extra_edges=1,
            extra_evidence=1,
        ),
    )
    return "AV-A15", _finalize_vector(vector)


def av_a16(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A16: Two top-level assumptions where the first DENYs and the second
    ALLOWs.

    The binding requires both X (PROPOSED-only, denied at use time) and Y
    (ADMITTED, allowed). Under the frozen D3.2-B contract EVERY required
    assumption must be evaluated (no global top-level fail-fast), so BOTH X and
    Y are evaluated. The binding is NOT admissible (X denies); the reported
    denial is X's. The work counters pin that Y's history was also reconstructed
    (Y counts as one history + two events), proving the second assumption was
    evaluated rather than short-circuited by X's denial.
    """
    aid_x = "assumption:a16x"
    aid_y = "assumption:a16y"
    # X: PROPOSED only (denied at use time as ASSUMPTION_USE_NOT_ADMITTED).
    e_x = _ev(
        assumption_id=aid_x,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_x}:propose"),
        payload=_propose_payload(clock=1, expires_at=30),
    )
    # Y: PROPOSED -> ADMITTED (allowed at use time).
    e_y = _ev(
        assumption_id=aid_y,
        entity_sequence=1,
        previous=None,
        clock=2,
        source_receipt=_receipt(f"{aid_y}:propose"),
        payload=_propose_payload(clock=2, expires_at=30),
    )
    e_y2 = _ev(
        assumption_id=aid_y,
        entity_sequence=2,
        previous=e_y["registry_event_digest"],
        clock=3,
        source_receipt=_receipt(f"{aid_y}:admit"),
        payload=_admit_payload(aid_y),
    )
    envelopes = [e_x, e_y, e_y2]
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    binding = _finalize_binding_for_vector(
        envelopes,
        _simple_use_binding(assumption_id=aid_x, clock=5, required_assumption_ids=(aid_x, aid_y)),
    )

    vector = _accepted_vector(
        "AV-A16",
        "Two top-level assumptions: first denies, second allows; both evaluated.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_denied_two_assumption_admissibility(
            binding,
            envelopes,
            first_assumption_id=aid_x,
            second_assumption_id=aid_y,
            policy_context=policy_context,
            code="ASSUMPTION_USE_NOT_ADMITTED",
        ),
    )
    return "AV-A16", _finalize_vector(vector)


def av_a17(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A17: Diamond DAG (A->B->D, A->C->D) where D is visited once.

    Defect #3 canary: the DFS first-discovery deduplication must visit D exactly
    once within A's evaluation. Without a ``visited`` set, D would appear twice
    in the ordered node list (its evidence evaluated twice, its events counted
    twice). The pinned work counters prove D is deduplicated:

    * 4 unique nodes (A, B, C, D) -- not 5.
    * 4 dependency edges (A->B, B->D, A->C, C->D) -- D's second arrival does
      not re-traverse, but each edge is followed once.
    * Events: A(2) + B(2) + C(2) + D(2) = 8 -- D counted once.
    """
    aid_a = "assumption:a17a"
    aid_b = "assumption:a17b"
    aid_c = "assumption:a17c"
    aid_d = "assumption:a17d"
    # D: no deps.
    e_d = _ev(
        assumption_id=aid_d,
        entity_sequence=1,
        previous=None,
        clock=1,
        source_receipt=_receipt(f"{aid_d}:propose"),
        payload=_propose_payload(clock=1, expires_at=40),
    )
    e_d2 = _ev(
        assumption_id=aid_d,
        entity_sequence=2,
        previous=e_d["registry_event_digest"],
        clock=2,
        source_receipt=_receipt(f"{aid_d}:admit"),
        payload=_admit_payload(aid_d),
    )
    # B depends on D.
    e_b = _ev(
        assumption_id=aid_b,
        entity_sequence=1,
        previous=None,
        clock=3,
        source_receipt=_receipt(f"{aid_b}:propose"),
        payload=_propose_payload(clock=3, expires_at=40, assumption_deps=(aid_d,)),
    )
    e_b2 = _ev(
        assumption_id=aid_b,
        entity_sequence=2,
        previous=e_b["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid_b}:admit"),
        payload=_admit_payload(aid_b),
    )
    # C depends on D.
    e_c = _ev(
        assumption_id=aid_c,
        entity_sequence=1,
        previous=None,
        clock=5,
        source_receipt=_receipt(f"{aid_c}:propose"),
        payload=_propose_payload(clock=5, expires_at=40, assumption_deps=(aid_d,)),
    )
    e_c2 = _ev(
        assumption_id=aid_c,
        entity_sequence=2,
        previous=e_c["registry_event_digest"],
        clock=6,
        source_receipt=_receipt(f"{aid_c}:admit"),
        payload=_admit_payload(aid_c),
    )
    # A depends on B and C (both reach D).
    e_a = _ev(
        assumption_id=aid_a,
        entity_sequence=1,
        previous=None,
        clock=7,
        source_receipt=_receipt(f"{aid_a}:propose"),
        payload=_propose_payload(clock=7, expires_at=40, assumption_deps=(aid_b, aid_c)),
    )
    e_a2 = _ev(
        assumption_id=aid_a,
        entity_sequence=2,
        previous=e_a["registry_event_digest"],
        clock=8,
        source_receipt=_receipt(f"{aid_a}:admit"),
        payload=_admit_payload(aid_a),
    )
    envelopes = [e_d, e_d2, e_b, e_b2, e_c, e_c2, e_a, e_a2]
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid_a, clock=9)
    )

    vector = _accepted_vector(
        "AV-A17",
        "Diamond DAG (A->B->D, A->C->D): D visited once within A's evaluation.",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_admissibility_for(binding, envelopes, policy_context),
    )
    return "AV-A17", _finalize_vector(vector)


def av_a18(policy_context: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """AV-A18: Challenge materiality != assumption materiality (resolved).

    Defect #4 canary: the assumption is MATERIAL, but it is challenged with
    reason_code REASON_CRITICAL (classified CRITICAL), then RESOLVED. The
    resolution grant binds to the CHALLENGE materiality (CRITICAL), not the
    assumption's own materiality (MATERIAL). The resolver authority holds the
    RESOLVE_TO_ADMITTED grant for CRITICAL challenge materiality.

    A mutation that substitutes the assumption's materiality for the challenge
    materiality would select the wrong grant and be denied.
    """
    aid = "assumption:a18"
    # PROPOSE with MATERIAL assumption, challenged with REASON_CRITICAL.
    p1 = _propose_payload(clock=1, expires_at=30, materiality="MATERIAL")
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
            "challenge_id": "challenge:a18c1",
            "challenger_authority_id": "authority:challenger",
            "challenge_reason_code": "REASON_CRITICAL",
            "challenge_receipt_digest": _receipt(f"{aid}:challenge-receipt"),
        },
    )
    e4 = _ev(
        assumption_id=aid,
        entity_sequence=4,
        previous=e3["registry_event_digest"],
        clock=4,
        source_receipt=_receipt(f"{aid}:resolve"),
        payload={
            "operation": "RESOLVE_CHALLENGES",
            "resolution_outcome": "RETURN_TO_ADMITTED",
            "resolver_authority_id": "authority:resolver",
            "resolution_receipt_digest": _receipt(f"{aid}:resolve-receipt"),
            "resolution_basis_code": "BASIS_REVIEW",
            "resolved_challenge_ids": ["challenge:a18c1"],
            "replacement_assumption_id": None,
        },
    )
    envelopes = [e1, e2, e3, e4]
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _accepted_vector(
        "AV-A18",
        "Challenge materiality (CRITICAL) differs from assumption materiality (MATERIAL).",
        envelopes,
        policy_context,
        use_binding=binding,
        expected_admissibility=_admissibility_for(binding, envelopes, policy_context),
    )
    return "AV-A18", _finalize_vector(vector)


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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
        policy_context=policy_context,
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    return "AV-R09", _rejected_vector(
        "AV-R09",
        "Cyclic dependency attempt (A -> B -> A) is detected at admission time.",
        envelopes,
        stage="ADMISSION",
        expected_error="ASSUMPTION_ADMISSION_DEPENDENCY_MISSING",
        policy_context=policy_context,
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
    binding = _finalize_binding_for_vector(
        envelopes, _simple_use_binding(assumption_id=aid, clock=5)
    )

    vector = _rejected_vector(
        "AV-R10",
        "Temporal invalidity (valid_from in future at use time) is detected.",
        envelopes,
        stage="USE",
        expected_error="ASSUMPTION_USE_NOT_YET_VALID",
        policy_context=policy_context,
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
    envelopes = _finalize_admission_receipts(envelopes, EVIDENCE_REGISTRY_ROOT, policy_context)
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
        policy_context=policy_context,
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
