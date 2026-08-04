"""V0.5-D3.2-A1.3-C historical V3 policy resolution and exact grant selection.

This module closes the A1 activation read path against the non-circular V3
signing envelope. It provides pure, deterministic functions that, together,
answer the question:

    "At event sequence ``s``, which activated authority policy governed this
    decision, and which exact grant authorized this action by this authority
    for this scope at this materiality?"

The public API is:

* :class:`ResolvedPolicyAtSequence` — frozen binding of the resolved policy
  generation and its activation envelope at the queried sequence. The binding
  identity is its digest fields; it additionally carries the resolved entry's
  grant set (a non-digested reference) so grant selection can scan it without
  a second ledger lookup;
* :func:`resolve_policy_at_v3` — pure historical policy resolution over a
  validated ``AssumptionPolicyLedgerV3`` using half-open ``[s_i, s_{i+1})``
  intervals keyed on each entry's ``effective_from_sequence``;
* :class:`GrantSelectionDecision` — frozen fail-closed decision binding the
  selected grant (or denial) to the resolved policy, the request, and the
  sequence;
* :func:`select_applicable_grant_v3` — pure exact grant selection matching
  the request against every dimension (action, authority, scope,
  materialities, effective interval) with deterministic fail-closed ambiguity
  handling;
* :func:`resolve_policy_and_select_grant` — composite: reconstruct -> resolve
  -> select.

A read-only :meth:`FilesystemAssumptionPolicyPublisher.resolve_at` is added to
the durable publisher: it acquires the publication lock, reconstructs the
ledger from authoritative bytes, runs the pure resolver, releases the lock, and
performs NO writes.

Claim boundary
==============

A1.3-C claims, on every supported platform:

* pure, deterministic historical resolution: the policy that governed an event
  sequence ``s`` depends only on the ledger entries whose
  ``effective_from_sequence <= s``; future entries never affect an earlier
  query, and an earlier result is byte-identical after a later append;
* exact, fail-closed grant selection: at most one grant may match a request;
  zero matches deny, two or more matches deny, exactly one matches and is
  selected;
* V3-only resolution: a V2 ``AssumptionPolicyLedgerV2`` (or any non-V3 ledger
  object) is rejected by an exact type check before any field is read, so the
  stable ``ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE`` code is
  surfaced rather than an ``AttributeError``;
* strict sequence typing: a ``bool`` sequence is rejected even though
  ``bool`` subclasses ``int`` in Python, so a stored ``true`` cannot
  masquerade as ``1``;
* read-only lock scope on the durable publisher: ``resolve_at`` acquires the
  same strict publication lock used by publish, but performs no writes and
  proves the authoritative bytes are unchanged on exit.

A1.3-C explicitly does NOT claim (deferred to A2 / A3):

* signature or approval re-verification at resolution time (the V3 ledger is
  already fully self-validating; A1.2 verified every signature);
* separation-of-duty rule evaluation (A2);
* active-challenge suppression or materiality aggregation across the assumption
  registry (A3);
* evaluation-work accounting (A3 composes this with the registry read path).

Half-open interval semantics
============================

A validated ``AssumptionPolicyLedgerV3`` is a strictly-increasing chain of
entries ``e_0, e_1, ..., e_{n-1}`` where entry ``e_i`` activates at sequence
``s_i = e_i.signing_payload.effective_from_sequence`` and ``s_i`` is strictly
greater than ``s_{i-1}`` (enforced by
:func:`validate_successor_position_v3`). Resolution of a queried event
sequence ``q`` is therefore the unique entry ``e_i`` such that::

    s_i <= q   AND   (i == n-1  OR  q < s_{i+1})

i.e. the half-open interval ``[s_i, s_{i+1})`` contains ``q``. Concretely:

* ``q < s_0``              -> ``ASSUMPTION_POLICY_NOT_ACTIVE`` (before genesis)
* ``q == s_i``             -> ``e_i`` (exact activation boundary is the new
  policy; the half-open interval is closed on the left)
* ``s_i < q < s_{i+1}``    -> ``e_i`` (strictly between activations is the
  preceding policy)
* ``q >= s_{n-1}``         -> ``e_{n-1}`` (after the latest activation is the
  latest policy)

Future entries (those with ``s_i > q``) never affect the resolution of ``q``.
Consequently, appending a new entry ``e_n`` after a query of ``q < s_n``
returns byte-identical results: the resolver walks the chain in reverse and
stops at the first entry with ``s_i <= q``.

Grant applicability dimensions
==============================

Given a resolved policy and a request ``(action, authority_id, scope_id,
assumption_materiality, challenge_materiality, event_sequence)``, a grant is
applicable if and only if ALL of the following hold:

* ``grant.action == action`` (exact, case-sensitive);
* ``grant.authority_id == authority_id`` (exact, case-sensitive);
* the request ``scope_id`` is covered by ``grant.scope_ids``: a global grant
  (``("scope:*",)``) matches any narrow scope, but a narrow grant never
  matches a global request, and a narrow grant matches only if the request
  scope is in its scope set;
* ``assumption_materiality in grant.assumption_materialities`` (exact);
* ``challenge_materiality in grant.challenge_materialities`` (exact; for
  non-resolution actions this is empty and the request must supply ``None``);
* the request ``event_sequence`` falls in the grant's half-open
  ``[effective_from_sequence, effective_until_sequence)`` interval, where
  ``effective_until_sequence`` of ``None`` denotes an unbounded upper bound.

Exactly one applicable grant yields ``SELECTED``. Zero yields
``NO_APPLICABLE_GRANT`` (a denial, not an error). Two or more yields
``AMBIGUOUS_GRANTS`` (a fail-closed denial, because two applicable grants in a
well-formed policy is a configuration error the operator must reconcile).
"""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionPolicyActivationContractError,
    domain_digest,
    json_bytes,
    require_digest,
    require_self_digest,
    require_token,
)
from csd_foundry.governance.v0_5._assumption_policy_activation_envelope import (
    AssumptionPolicyLedgerEntryV3,
    AssumptionPolicyLedgerV3,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    ASSUMPTION_MATERIALITIES,
    GLOBAL_ASSUMPTION_SCOPE,
    RESOLUTION_AUTHORITY_ACTIONS,
    AssumptionAuthorityGrant,
)

RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION = "assumption-resolved-policy-at-sequence/1"
GRANT_SELECTION_DECISION_SCHEMA_VERSION = "assumption-grant-selection-decision/1"

#: The complete, closed set of assumption-authority actions a grant may cover.
#: Mirrors ``ASSUMPTION_AUTHORITY_ACTIONS`` from the contracts module but is
#: inlined here so the selection gate is auditable in one place and does not
#: import the constant (which the contracts module does not export as a name
#: re-exported here -- the tuple literal is the stable gate).
_GRANT_ACTIONS = (
    "ADMIT",
    "CHALLENGE",
    "CONFIRM",
    "EXPIRE",
    "PROPOSE",
    "REJECT",
    "RESOLVE_TO_ADMITTED",
    "RESOLVE_TO_CONFIRMED",
    "RESOLVE_TO_REJECTED",
    "RESOLVE_TO_SUPERSEDED",
    "SUPERSEDE",
)

#: Stable decision-type enumeration. Exactly one of these is produced on every
#: call to :func:`select_applicable_grant_v3`. ``NO_APPLICABLE_GRANT`` and
#: ``AMBIGUOUS_GRANTS`` are denials (the caller is not authorized), not errors:
#: they surface a deterministic decision the caller may persist. A genuine
#: input-contract violation (unknown action, bad materiality, negative
#: sequence) raises ``AssumptionPolicyActivationContractError`` instead.
DECISION_TYPES = ("SELECTED", "NO_APPLICABLE_GRANT", "AMBIGUOUS_GRANTS")


# ===========================================================================
# 1. ResolvedPolicyAtSequence
# ===========================================================================


@dataclass(frozen=True, slots=True)
class ResolvedPolicyAtSequence:
    """Frozen binding of the resolved policy generation at a queried sequence.

    The binding identity is the digest and sequence fields listed below: two
    resolutions of the same ``(ledger, event_sequence)`` pair produce
    byte-identical ``resolution_digest`` values. The ``resolution_digest`` is
    a domain-separated self-digest over the complete unsigned value.

    The ``grants`` field is a non-digested carry-through of the resolved
    entry's grant set, present so that :func:`select_applicable_grant_v3` can
    scan grants without a second ledger lookup. It is excluded from the digest
    because it is fully determined by ``ledger_entry_digest`` (the grant set
    is part of the entry's canonical bytes, which the digest already covers).
    This mirrors how ``AssumptionPolicyLedgerEntryV3`` carries the full
    ``policy`` object alongside its ``ledger_entry_digest``.
    """

    event_sequence: int
    policy_id: str
    policy_digest: str
    effective_from_sequence: int
    signing_payload_digest: str
    commit_receipt_digest: str
    ledger_entry_digest: str
    ledger_root_digest: str
    resolution_digest: str
    # Non-digested carry-through for grant selection. Defaulted to the empty
    # tuple so a caller who constructs the binding directly (without going
    # through ``from_entry``) still gets a valid, denial-producing selection.
    grants: tuple[AssumptionAuthorityGrant, ...] = ()

    def __post_init__(self) -> None:
        # Strict sequence typing: reject bool even though bool subclasses int.
        # A stored ``true`` must never masquerade as ``1``.
        if (
            type(self.event_sequence) is not int
            or isinstance(self.event_sequence, bool)
            or self.event_sequence < 0
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"
            )
        if (
            type(self.effective_from_sequence) is not int
            or isinstance(self.effective_from_sequence, bool)
            or self.effective_from_sequence < 0
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_RESOLUTION_EFFECTIVE_SEQUENCE_INVALID"
            )
        require_token(self.policy_id, "ASSUMPTION_POLICY_RESOLUTION_POLICY_ID_INVALID")
        digest_fields = (
            (self.policy_digest, "ASSUMPTION_POLICY_RESOLUTION_POLICY_DIGEST_INVALID"),
            (
                self.signing_payload_digest,
                "ASSUMPTION_POLICY_RESOLUTION_SIGNING_PAYLOAD_INVALID",
            ),
            (
                self.commit_receipt_digest,
                "ASSUMPTION_POLICY_RESOLUTION_COMMIT_RECEIPT_INVALID",
            ),
            (
                self.ledger_entry_digest,
                "ASSUMPTION_POLICY_RESOLUTION_LEDGER_ENTRY_INVALID",
            ),
            (self.ledger_root_digest, "ASSUMPTION_POLICY_RESOLUTION_LEDGER_ROOT_INVALID"),
        )
        for value, code in digest_fields:
            require_digest(value, code)
        # The grants carry-through must be a tuple of exactly-typed grants.
        # It is NOT part of the digest (it is determined by the entry digest),
        # but its type is validated so a foreign object cannot sneak in here.
        if type(self.grants) is not tuple:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_RESOLUTION_GRANTS_INVALID"
            )
        for grant in self.grants:
            if type(grant) is not AssumptionAuthorityGrant:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_POLICY_RESOLUTION_GRANTS_INVALID"
                )
        require_self_digest(
            "ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE",
            self._unsigned_value(),
            self.resolution_digest,
            "ASSUMPTION_POLICY_RESOLUTION_DIGEST_MISMATCH",
        )

    @classmethod
    def from_entry(
        cls,
        *,
        entry: AssumptionPolicyLedgerEntryV3,
        ledger: AssumptionPolicyLedgerV3,
        event_sequence: int,
    ) -> ResolvedPolicyAtSequence:
        """Build a ``ResolvedPolicyAtSequence`` from a resolved ledger entry.

        Carries the entry's grant set so the returned binding is directly
        usable by :func:`select_applicable_grant_v3` without a second lookup.
        """

        payload = entry.signing_payload
        unsigned = {
            "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
            "commit_receipt_digest": entry.policy_commit.commit_receipt_digest,
            "effective_from_sequence": payload.effective_from_sequence,
            "event_sequence": event_sequence,
            "ledger_entry_digest": entry.ledger_entry_digest,
            "ledger_root_digest": ledger.ledger_root_digest,
            "policy_digest": entry.policy.policy_digest,
            "policy_id": entry.policy.policy_id,
            "signing_payload_digest": payload.signing_payload_digest,
        }
        return cls(
            event_sequence=event_sequence,
            policy_id=entry.policy.policy_id,
            policy_digest=entry.policy.policy_digest,
            effective_from_sequence=payload.effective_from_sequence,
            signing_payload_digest=payload.signing_payload_digest,
            commit_receipt_digest=entry.policy_commit.commit_receipt_digest,
            ledger_entry_digest=entry.ledger_entry_digest,
            ledger_root_digest=ledger.ledger_root_digest,
            resolution_digest=domain_digest("ASSUMPTION_RESOLVED_POLICY_AT_SEQUENCE", unsigned),
            grants=entry.policy.grants,
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION,
            "commit_receipt_digest": self.commit_receipt_digest,
            "effective_from_sequence": self.effective_from_sequence,
            "event_sequence": self.event_sequence,
            "ledger_entry_digest": self.ledger_entry_digest,
            "ledger_root_digest": self.ledger_root_digest,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "signing_payload_digest": self.signing_payload_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "resolution_digest": self.resolution_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# ===========================================================================
# 2. resolve_policy_at_v3
# ===========================================================================


def resolve_policy_at_v3(
    ledger: AssumptionPolicyLedgerV3,
    event_sequence: int,
) -> ResolvedPolicyAtSequence:
    """Pure historical V3 policy resolution.

    Returns the :class:`ResolvedPolicyAtSequence` binding the policy
    generation that governed ``event_sequence`` according to the half-open
    ``[s_i, s_{i+1})`` interval semantics documented at the module top.

    Raises ``AssumptionPolicyActivationContractError`` with stable codes for:

    * ``ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE`` -- the
      ledger is not exactly an ``AssumptionPolicyLedgerV3`` (e.g. a V2
      ledger). The exact type check runs before any field is read so a V2 or
      foreign object surfaces the stable code rather than ``AttributeError``.
    * ``ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID`` -- ``event_sequence``
      is not a nonnegative ``int`` (a ``bool`` is rejected even though it
      subclasses ``int``).
    * ``ASSUMPTION_POLICY_NOT_ACTIVE`` -- ``event_sequence`` precedes the
      genesis entry's ``effective_from_sequence`` (no policy was yet active),
      or the ledger is empty.
    """

    # V3-only: exact type check before any field access so a V2 ledger surfaces
    # the stable governance code rather than AttributeError.
    if type(ledger) is not AssumptionPolicyLedgerV3:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_RESOLUTION_LEDGER_VERSION_NOT_ACTIVATABLE"
        )
    # Strict sequence typing: reject bool. The order matters: the ``type is
    # not int`` check would pass for ``True`` (bool subclasses int), so the
    # explicit ``isinstance(..., bool)`` guard is required.
    if type(event_sequence) is not int or isinstance(event_sequence, bool):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"
        )
    if event_sequence < 0:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_POLICY_RESOLUTION_SEQUENCE_INVALID"
        )

    entries = ledger.entries
    if not entries:
        # An empty V3 ledger has no genesis: every query precedes genesis and
        # is therefore not active.
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_NOT_ACTIVE")

    # Walk the chain in reverse: the latest entry whose
    # ``effective_from_sequence <= event_sequence`` is the unique entry whose
    # half-open ``[s_i, s_{i+1})`` interval contains ``event_sequence``.
    # Because the chain is strictly increasing, the first hit from the end is
    # the answer. Future entries (those with ``s_i > event_sequence``) are
    # skipped, so appending a later entry cannot change an earlier result.
    for entry in reversed(entries):
        if entry.signing_payload.effective_from_sequence <= event_sequence:
            return ResolvedPolicyAtSequence.from_entry(
                entry=entry, ledger=ledger, event_sequence=event_sequence
            )

    # No entry has ``effective_from_sequence <= event_sequence``: the query
    # precedes genesis.
    raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_NOT_ACTIVE")


# ===========================================================================
# 3. GrantSelectionDecision
# ===========================================================================


@dataclass(frozen=True, slots=True)
class GrantSelectionDecision:
    """Frozen fail-closed grant-selection decision.

    The decision binds the resolved policy generation, the request, and the
    selected grant (or the denial reason) at the queried sequence. The
    ``selection_digest`` is a domain-separated self-digest over the complete
    unsigned value, so two selections of the same ``(resolved_policy,
    request)`` pair produce byte-identical digests regardless of whether the
    outcome was a selection or a denial.
    """

    # --- resolved-policy bindings (mirrors of ResolvedPolicyAtSequence) ---
    policy_id: str
    policy_digest: str
    effective_from_sequence: int
    signing_payload_digest: str
    commit_receipt_digest: str
    ledger_entry_digest: str
    ledger_root_digest: str
    # --- request + outcome ---
    event_sequence: int
    action: str
    authority_id: str
    scope_id: str
    assumption_materiality: str
    challenge_materiality: str | None
    decision_type: str
    selected_grant_id: str | None
    grant_digest: str | None
    selection_digest: str

    def __post_init__(self) -> None:
        if self.decision_type not in DECISION_TYPES:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_DECISION_TYPE_INVALID"
            )
        # Selection consistency: a SELECTED decision must carry both grant
        # bindings; a denial must carry neither.
        if self.decision_type == "SELECTED":
            if self.selected_grant_id is None or self.grant_digest is None:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_GRANT_SELECTION_SELECTED_GRANT_MISSING"
                )
        else:
            if self.selected_grant_id is not None or self.grant_digest is not None:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_GRANT_SELECTION_DENIAL_GRANT_PRESENT"
                )
        # Strict sequence typing on both sequence fields.
        for _name, value in (
            ("event_sequence", self.event_sequence),
            ("effective_from_sequence", self.effective_from_sequence),
        ):
            if type(value) is not int or isinstance(value, bool) or value < 0:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_GRANT_SELECTION_SEQUENCE_INVALID"
                )
        require_token(self.policy_id, "ASSUMPTION_GRANT_SELECTION_POLICY_ID_INVALID")
        require_token(self.authority_id, "ASSUMPTION_GRANT_SELECTION_AUTHORITY_INVALID")
        require_token(self.scope_id, "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID")
        if self.action not in _GRANT_ACTIONS:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_ACTION_INVALID"
            )
        if self.assumption_materiality not in ASSUMPTION_MATERIALITIES:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_ASSUMPTION_MATERIALITY_INVALID"
            )
        if (
            self.challenge_materiality is not None
            and self.challenge_materiality not in ASSUMPTION_MATERIALITIES
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_INVALID"
            )
        # Resolution-action / challenge-materiality consistency (mirrors the
        # grant contract): a resolution action requires a challenge
        # materiality, and a non-resolution action forbids one.
        if self.action in RESOLUTION_AUTHORITY_ACTIONS:
            if self.challenge_materiality is None:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_REQUIRED"
                )
        elif self.challenge_materiality is not None:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_UNEXPECTED"
            )
        digest_fields = (
            (self.policy_digest, "ASSUMPTION_GRANT_SELECTION_POLICY_DIGEST_INVALID"),
            (
                self.signing_payload_digest,
                "ASSUMPTION_GRANT_SELECTION_SIGNING_PAYLOAD_INVALID",
            ),
            (
                self.commit_receipt_digest,
                "ASSUMPTION_GRANT_SELECTION_COMMIT_RECEIPT_INVALID",
            ),
            (
                self.ledger_entry_digest,
                "ASSUMPTION_GRANT_SELECTION_LEDGER_ENTRY_INVALID",
            ),
            (self.ledger_root_digest, "ASSUMPTION_GRANT_SELECTION_LEDGER_ROOT_INVALID"),
        )
        for digest_value, code in digest_fields:
            require_digest(digest_value, code)
        if self.grant_digest is not None:
            require_digest(self.grant_digest, "ASSUMPTION_GRANT_SELECTION_GRANT_INVALID")
        require_self_digest(
            "ASSUMPTION_GRANT_SELECTION_DECISION",
            self._unsigned_value(),
            self.selection_digest,
            "ASSUMPTION_GRANT_SELECTION_DIGEST_MISMATCH",
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
            "action": self.action,
            "assumption_materiality": self.assumption_materiality,
            "authority_id": self.authority_id,
            "challenge_materiality": self.challenge_materiality,
            "commit_receipt_digest": self.commit_receipt_digest,
            "decision_type": self.decision_type,
            "effective_from_sequence": self.effective_from_sequence,
            "event_sequence": self.event_sequence,
            "grant_digest": self.grant_digest,
            "ledger_entry_digest": self.ledger_entry_digest,
            "ledger_root_digest": self.ledger_root_digest,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "scope_id": self.scope_id,
            "selected_grant_id": self.selected_grant_id,
            "signing_payload_digest": self.signing_payload_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "selection_digest": self.selection_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# ===========================================================================
# 4. select_applicable_grant_v3
# ===========================================================================


def _scope_matches(request_scope: str, grant_scopes: tuple[str, ...]) -> bool:
    """Return whether ``request_scope`` is covered by ``grant_scopes``.

    A global grant (``("scope:*",)``) matches any request scope. A narrow grant
    matches only if the request scope is exactly in its scope set. A narrow
    grant never matches a global request: ``scope:*`` as a request is rejected
    upstream as an invalid token-shape scope, so this case is defense-in-depth.
    """

    if grant_scopes == (GLOBAL_ASSUMPTION_SCOPE,):
        return True
    return request_scope in grant_scopes


def _grant_covers_request(
    *,
    grant: AssumptionAuthorityGrant,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
) -> bool:
    """Return whether ``grant`` is applicable to the request on every dimension."""

    if grant.action != action:
        return False
    if grant.authority_id != authority_id:
        return False
    if not _scope_matches(scope_id, grant.scope_ids):
        return False
    if assumption_materiality not in grant.assumption_materialities:
        return False
    # Challenge-materiality match: for resolution actions the grant carries a
    # non-empty challenge_materialities tuple and the request supplies a
    # materiality; for non-resolution actions the grant carries an empty tuple
    # and the request supplies None. The decision-dataclass post-init has
    # already enforced the action/materiality consistency, so here we only
    # check membership when a challenge materiality is present.
    if challenge_materiality is not None:
        if challenge_materiality not in grant.challenge_materialities:
            return False
    elif grant.challenge_materialities:
        # The grant requires a challenge materiality but the request supplies
        # none: not applicable.
        return False
    # Half-open effective interval [effective_from, effective_until). The lower
    # bound is inclusive (a grant is active at its effective_from_sequence);
    # the upper bound is exclusive (a grant expires AT effective_until_sequence,
    # not after).
    if event_sequence < grant.effective_from_sequence:
        return False
    return not (
        grant.effective_until_sequence is not None
        and event_sequence >= grant.effective_until_sequence
    )


def _build_decision(
    *,
    resolved_policy: ResolvedPolicyAtSequence,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    decision_type: str,
    grant: AssumptionAuthorityGrant | None,
) -> GrantSelectionDecision:
    """Construct a GrantSelectionDecision with the grant bindings if selected."""

    unsigned = {
        "schema_version": GRANT_SELECTION_DECISION_SCHEMA_VERSION,
        "action": action,
        "assumption_materiality": assumption_materiality,
        "authority_id": authority_id,
        "challenge_materiality": challenge_materiality,
        "commit_receipt_digest": resolved_policy.commit_receipt_digest,
        "decision_type": decision_type,
        "effective_from_sequence": resolved_policy.effective_from_sequence,
        "event_sequence": event_sequence,
        "grant_digest": grant.grant_digest if grant is not None else None,
        "ledger_entry_digest": resolved_policy.ledger_entry_digest,
        "ledger_root_digest": resolved_policy.ledger_root_digest,
        "policy_digest": resolved_policy.policy_digest,
        "policy_id": resolved_policy.policy_id,
        "scope_id": scope_id,
        "selected_grant_id": grant.grant_id if grant is not None else None,
        "signing_payload_digest": resolved_policy.signing_payload_digest,
    }
    return GrantSelectionDecision(
        policy_id=resolved_policy.policy_id,
        policy_digest=resolved_policy.policy_digest,
        effective_from_sequence=resolved_policy.effective_from_sequence,
        signing_payload_digest=resolved_policy.signing_payload_digest,
        commit_receipt_digest=resolved_policy.commit_receipt_digest,
        ledger_entry_digest=resolved_policy.ledger_entry_digest,
        ledger_root_digest=resolved_policy.ledger_root_digest,
        event_sequence=event_sequence,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        decision_type=decision_type,
        selected_grant_id=grant.grant_id if grant is not None else None,
        grant_digest=grant.grant_digest if grant is not None else None,
        selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
    )


def _validate_selection_request(
    *,
    action: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
    resolved_policy: ResolvedPolicyAtSequence,
) -> None:
    """Validate the request inputs (raises on contract violations).

    Does NOT return a denial: a denial is a valid outcome produced by the
    caller. This gate raises only on genuine input-contract violations. The
    order mirrors the decision-dataclass post-init so a bad input surfaces the
    same code regardless of which gate fires first.
    """

    if action not in _GRANT_ACTIONS:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_GRANT_SELECTION_ACTION_INVALID")
    if assumption_materiality not in ASSUMPTION_MATERIALITIES:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_ASSUMPTION_MATERIALITY_INVALID"
        )
    if challenge_materiality is not None and challenge_materiality not in ASSUMPTION_MATERIALITIES:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_INVALID"
        )
    if action in RESOLUTION_AUTHORITY_ACTIONS:
        if challenge_materiality is None:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_REQUIRED"
            )
    elif challenge_materiality is not None:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_CHALLENGE_MATERIALITY_UNEXPECTED"
        )
    if type(event_sequence) is not int or isinstance(event_sequence, bool) or event_sequence < 0:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_GRANT_SELECTION_SEQUENCE_INVALID")
    # The resolved policy's effective_from_sequence bounds the event_sequence:
    # the event must be at or after the policy's activation. This is a
    # defense-in-depth check; resolve_policy_at_v3 already ensures
    # event_sequence >= effective_from_sequence for the resolved entry.
    if event_sequence < resolved_policy.effective_from_sequence:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_EVENT_BEFORE_POLICY_EFFECTIVE"
        )


def select_applicable_grant_v3(
    resolved_policy: ResolvedPolicyAtSequence,
    *,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
    event_sequence: int,
) -> GrantSelectionDecision:
    """Pure exact grant selection against the resolved policy.

    Scans ``resolved_policy.grants`` (the grant set carried from the resolved
    ledger entry) for every grant applicable to the request and returns exactly
    one of:

    * ``SELECTED`` -- exactly one grant is applicable; ``selected_grant_id``
      and ``grant_digest`` carry its bindings.
    * ``NO_APPLICABLE_GRANT`` -- zero grants are applicable (a denial).
    * ``AMBIGUOUS_GRANTS`` -- two or more grants are applicable (a fail-closed
      denial: a well-formed policy never has two applicable grants for one
      request, so this is a configuration error the operator must reconcile).

    Raises ``AssumptionPolicyActivationContractError`` for genuine
    input-contract violations (bad action, bad materiality, negative sequence,
    action/materiality inconsistency, event before the policy's effective
    sequence). Denials (zero or multiple matches) are returned as decisions,
    not raised.

    The scan is deterministic because ``resolved_policy.grants`` is the
    canonical (grant_id-sorted) grant tuple from the resolved entry's policy.
    """

    _validate_selection_request(
        action=action,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        resolved_policy=resolved_policy,
    )
    matches = [
        grant
        for grant in resolved_policy.grants
        if _grant_covers_request(
            grant=grant,
            action=action,
            authority_id=authority_id,
            scope_id=scope_id,
            assumption_materiality=assumption_materiality,
            challenge_materiality=challenge_materiality,
            event_sequence=event_sequence,
        )
    ]
    if not matches:
        return _build_decision(
            resolved_policy=resolved_policy,
            action=action,
            authority_id=authority_id,
            scope_id=scope_id,
            assumption_materiality=assumption_materiality,
            challenge_materiality=challenge_materiality,
            event_sequence=event_sequence,
            decision_type="NO_APPLICABLE_GRANT",
            grant=None,
        )
    if len(matches) == 1:
        return _build_decision(
            resolved_policy=resolved_policy,
            action=action,
            authority_id=authority_id,
            scope_id=scope_id,
            assumption_materiality=assumption_materiality,
            challenge_materiality=challenge_materiality,
            event_sequence=event_sequence,
            decision_type="SELECTED",
            grant=matches[0],
        )
    # Two or more applicable grants: fail closed. The decision carries no
    # grant bindings (it is a denial), but the operator can reconcile by
    # inspecting the policy. The scan is stable because
    # ``resolved_policy.grants`` is canonical (sorted by grant_id).
    return _build_decision(
        resolved_policy=resolved_policy,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
        decision_type="AMBIGUOUS_GRANTS",
        grant=None,
    )


# ===========================================================================
# 5. Composite: resolve_policy_and_select_grant
# ===========================================================================


def resolve_policy_and_select_grant(
    *,
    ledger: AssumptionPolicyLedgerV3,
    event_sequence: int,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
) -> GrantSelectionDecision:
    """Composite: reconstruct (no-op for an in-memory ledger) -> resolve -> select.

    Order of operations:

    1. ``resolve_policy_at_v3(ledger, event_sequence)`` -- pure resolution,
       yielding the resolved policy binding (which carries the grant set);
    2. ``select_applicable_grant_v3(resolved, ...)`` -- pure exact grant
       selection against the resolved binding's carried grant set.

    The composite performs no I/O and no locking: it is the pure read path
    over an already-validated in-memory ``AssumptionPolicyLedgerV3``. For the
    durable filesystem path, use
    :meth:`FilesystemAssumptionPolicyPublisher.resolve_at` to obtain the
    resolved policy (which carries the grants), then call
    :func:`select_applicable_grant_v3`.

    The composite guarantees the resolution and selection share the same
    entry: the binding returned by resolution carries the grants of the
    located entry, so a concurrent append cannot split the read across two
    generations (for the in-memory ledger the whole call is over a single
    immutable snapshot; for the filesystem publisher, ``resolve_at`` holds the
    lock across reconstruction).
    """

    resolved = resolve_policy_at_v3(ledger, event_sequence)
    return select_applicable_grant_v3(
        resolved,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        event_sequence=event_sequence,
    )
