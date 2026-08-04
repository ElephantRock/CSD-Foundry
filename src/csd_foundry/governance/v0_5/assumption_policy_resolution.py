"""V0.5-D3.2-A1.3-C historical V3 policy resolution and exact grant selection.

This module closes the A1 activation read path against the non-circular V3
signing envelope. It provides pure, deterministic functions that, together,
answer the question:

    "At event sequence ``s``, which activated authority policy governed this
    decision, and which exact grant authorized this action by this authority
    for this scope at this materiality?"

The public API is:

* :class:`ResolvedPolicyAtSequence` -- frozen binding of the resolved policy
  generation and its activation envelope at the queried sequence. The binding
  carries ONLY digest and sequence fields: its canonical bytes are a digest
  receipt, never hidden authorization material. A resolution object alone is
  NOT an authoritative source for grant selection -- grant selection must
  re-bind the resolution to its source ledger entry via
  :func:`_source_entry_for_resolution` and scan that entry's digested grants;
* :func:`resolve_policy_at_v3` -- pure historical policy resolution over a
  validated ``AssumptionPolicyLedgerV3`` using half-open ``[s_i, s_{i+1})``
  intervals keyed on each entry's ``effective_from_sequence``;
* :class:`GrantSelectionDecision` -- frozen fail-closed decision binding the
  selected grant (or denial) to the resolved policy, the request, and the
  sequence;
* :func:`select_applicable_grant_v3` -- pure exact grant selection matching
  the request against every dimension (action, authority, scope,
  materialities, effective interval) with deterministic fail-closed ambiguity
  handling. The selector takes BOTH the ledger and the resolved policy: the
  resolution binds the generation; the ledger re-binds the source entry whose
  ``policy.grants`` are scanned. There is no independently supplied event
  sequence -- the resolved policy's ``event_sequence`` governs all grant
  interval evaluation;
* :func:`resolve_policy_and_select_grant` -- composite: resolve -> select.

A read-only :meth:`FilesystemAssumptionPolicyPublisher.resolve_at` is added to
the durable publisher: it acquires the publication lock, reconstructs the
ledger from authoritative bytes, runs the pure resolver, releases the lock, and
performs NO writes. The publisher additionally offers the composite
:meth:`FilesystemAssumptionPolicyPublisher.resolve_policy_and_select_grant_at`
which resolves AND selects under a single locked snapshot, proving the bytes
are unchanged across the read.

Claim boundary
==============

A1.3-C claims, on every supported platform:

* pure, deterministic historical resolution: the policy that governed an event
  sequence ``s`` depends only on the ledger entries whose
  ``effective_from_sequence <= s``; future entries never change the resolved
  generation bindings (policy ID/digest, effective sequence, signing-payload
  digest, commit-receipt digest, ledger-entry digest). The complete resolution
  receipt is snapshot-bound and changes when the observed authoritative ledger
  root changes;
* exact, fail-closed grant selection: at most one grant may match a request;
  zero matches deny, two or more matches deny, exactly one matches and is
  selected. The grants scanned are the source entry's digested grants -- never
  a caller-carried tuple -- so a substituted tuple cannot authorize;
* V3-only resolution: a V2 ``AssumptionPolicyLedgerV2`` (or any non-V3 ledger
  object) is rejected by an exact type check before any field is read, so the
  stable ``ASSUMPTION_POLICY_LEDGER_ENTRY_VERSION_NOT_ACTIVATABLE`` code is
  surfaced rather than an ``AttributeError``;
* strict sequence typing: a ``bool`` sequence is rejected even though
  ``bool`` subclasses ``int`` in Python, so a stored ``true`` cannot
  masquerade as ``1``;
* read-only lock scope on the durable publisher: ``resolve_at`` and the
  composite ``resolve_policy_and_select_grant_at`` acquire the same strict
  publication lock used by publish, but perform no writes and prove the
  authoritative bytes are unchanged on exit.

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

Future entries (those with ``s_i > q``) never change the resolved generation
bindings.

Grant applicability dimensions
==============================

Given a resolved policy and a request ``(action, authority_id, scope_id,
assumption_materiality, challenge_materiality)``, a grant is applicable if and
only if ALL of the following hold:

* ``grant.action == action`` (exact, case-sensitive);
* ``grant.authority_id == authority_id`` (exact, case-sensitive);
* the request ``scope_id`` is covered by ``grant.scope_ids``: a global grant
  (``("scope:*",)``) matches any narrow scope, but a narrow grant never
  matches a global request, and a narrow grant matches only if the request
  scope is in its scope set;
* ``assumption_materiality in grant.assumption_materialities`` (exact);
* ``challenge_materiality in grant.challenge_materialities`` (exact; for
  non-resolution actions this is empty and the request must supply ``None``);
* the resolved policy's ``event_sequence`` falls in the grant's half-open
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
    ASSUMPTION_AUTHORITY_ACTIONS,
    ASSUMPTION_MATERIALITIES,
    GLOBAL_ASSUMPTION_SCOPE,
    RESOLUTION_AUTHORITY_ACTIONS,
    AssumptionAuthorityGrant,
)

RESOLVED_POLICY_AT_SEQUENCE_SCHEMA_VERSION = "assumption-resolved-policy-at-sequence/1"
GRANT_SELECTION_DECISION_SCHEMA_VERSION = "assumption-grant-selection-decision/1"

#: Stable decision-type enumeration. Exactly one of these is produced on every
#: call to :func:`select_applicable_grant_v3`. ``NO_APPLICABLE_GRANT`` and
#: ``AMBIGUOUS_GRANTS`` are denials (the caller is not authorized), not errors:
#: they surface a deterministic decision the caller may persist. A genuine
#: input-contract violation (unknown action, bad materiality, negative
#: sequence) raises ``AssumptionPolicyActivationContractError`` instead.
DECISION_TYPES = ("SELECTED", "NO_APPLICABLE_GRANT", "AMBIGUOUS_GRANTS")

#: Stable decision-code enumeration (one per decision type). The decision code
#: is bound into the ``selection_digest`` so a SELECTED, NO_APPLICABLE_GRANT,
#: and AMBIGUOUS_GRANTS outcome for the same (resolved policy, request) triple
#: produce distinct, distinguishable digests. The action vocabulary is the one
#: normative enumeration imported from the contracts module
#: (``ASSUMPTION_AUTHORITY_ACTIONS``); this module defines no local action set.
DECISION_CODES = {
    "SELECTED": "ASSUMPTION_GRANT_SELECTED",
    "NO_APPLICABLE_GRANT": "ASSUMPTION_POLICY_NO_APPLICABLE_GRANT",
    "AMBIGUOUS_GRANTS": "ASSUMPTION_POLICY_AMBIGUOUS_GRANTS",
}


# ===========================================================================
# 1. ResolvedPolicyAtSequence
# ===========================================================================


@dataclass(frozen=True, slots=True)
class ResolvedPolicyAtSequence:
    """Frozen binding of the resolved policy generation at a queried sequence.

    The binding carries ONLY digest, id, and sequence fields. Its canonical
    bytes are a digest receipt: they are fully determined by the digested
    envelope of the resolved ledger entry plus the queried event sequence.
    The class carries NO authorization material (no grant tuple): a resolution
    object alone is therefore NOT an authoritative source for grant selection.
    Grant selection re-binds this resolution to its source ledger entry via
    :func:`_source_entry_for_resolution` and scans that entry's digested
    grants, so a caller cannot substitute a grant tuple to authorize.

    Two resolutions of the same ``(ledger, event_sequence)`` pair produce
    byte-identical ``resolution_digest`` values. The ``resolution_digest`` is
    a domain-separated self-digest over the complete unsigned value.
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
        # Closed contract invariant: the queried event sequence must fall at or
        # after the resolved policy's effective_from_sequence. An event below
        # the policy's activation cannot be governed by that policy.
        if self.event_sequence < self.effective_from_sequence:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_RESOLUTION_EVENT_BEFORE_EFFECTIVE"
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

        The returned binding carries only digest and sequence fields. The
        grant set is NOT carried: grant selection must re-bind the binding to
        its source entry (via :func:`_source_entry_for_resolution`) and scan
        that entry's digested grants.
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
# 3. Source-entry re-binding for grant selection
# ===========================================================================


def _source_entry_for_resolution(
    *,
    ledger: AssumptionPolicyLedgerV3,
    resolved_policy: ResolvedPolicyAtSequence,
) -> AssumptionPolicyLedgerEntryV3:
    """Re-bind a resolved policy to its exact source ledger entry.

    Grant selection scans ``source_entry.policy.grants`` -- the digested grant
    set carried by the resolved entry -- never a caller-carried tuple. This
    helper locates that entry and verifies it is the exact entry the
    resolution bound.

    Requirements (each surfaced with a distinct stable code, never an
    ``AttributeError``):

    * ``ledger`` is exactly ``AssumptionPolicyLedgerV3`` ->
      ``ASSUMPTION_GRANT_SELECTION_LEDGER_VERSION_NOT_ACTIVATABLE``;
    * ``resolved_policy`` is exactly ``ResolvedPolicyAtSequence`` ->
      ``ASSUMPTION_GRANT_SELECTION_RESOLUTION_TYPE_INVALID``;
    * ``resolved_policy.ledger_root_digest == ledger.ledger_root_digest`` ->
      ``ASSUMPTION_GRANT_SELECTION_LEDGER_ROOT_MISMATCH`` (the resolution and
      the ledger do not describe the same authoritative snapshot);
    * exactly one ledger entry has ``ledger_entry_digest == resolved's`` ->
      ``ASSUMPTION_GRANT_SELECTION_SOURCE_ENTRY_MISSING`` (zero) or
      ``ASSUMPTION_GRANT_SELECTION_SOURCE_ENTRY_AMBIGUOUS`` (two or more);
    * that entry matches the resolved policy's ``policy_id``,
      ``policy_digest``, ``effective_from_sequence``,
      ``signing_payload_digest``, ``commit_receipt_digest``, and
      ``ledger_entry_digest`` -> ``ASSUMPTION_GRANT_SELECTION_SOURCE_BINDING_MISMATCH``.

    A foreign object passed as ``resolved_policy`` (lacking the digest fields)
    produces ``ASSUMPTION_GRANT_SELECTION_RESOLUTION_TYPE_INVALID`` rather
    than an ``AttributeError``, because the exact type check runs before any
    field access.
    """

    # Exact type checks before any field access so foreign objects surface
    # stable codes rather than AttributeError.
    if type(ledger) is not AssumptionPolicyLedgerV3:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_LEDGER_VERSION_NOT_ACTIVATABLE"
        )
    if type(resolved_policy) is not ResolvedPolicyAtSequence:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_RESOLUTION_TYPE_INVALID"
        )
    # The resolution and the ledger must describe the same authoritative
    # snapshot: their ledger root digests must agree. A resolution from a
    # different generation of the same chain has a different root.
    if resolved_policy.ledger_root_digest != ledger.ledger_root_digest:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_LEDGER_ROOT_MISMATCH"
        )
    # Locate the unique source entry by ledger_entry_digest. There must be
    # exactly one (the ledger chain is strictly increasing on commit-receipt
    # digests, and ledger_entry_digest is derived from the entry's canonical
    # bytes which include that commit-receipt digest, so collisions are
    # impossible in a well-formed ledger -- but fail closed on zero or many).
    matches = [
        entry
        for entry in ledger.entries
        if entry.ledger_entry_digest == resolved_policy.ledger_entry_digest
    ]
    if not matches:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_SOURCE_ENTRY_MISSING"
        )
    if len(matches) > 1:
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_SOURCE_ENTRY_AMBIGUOUS"
        )
    source_entry = matches[0]
    # Verify the located entry matches the resolution on every binding. Any
    # divergence means the resolution does not describe this entry.
    payload = source_entry.signing_payload
    bindings = (
        (source_entry.policy.policy_id, resolved_policy.policy_id),
        (source_entry.policy.policy_digest, resolved_policy.policy_digest),
        (payload.effective_from_sequence, resolved_policy.effective_from_sequence),
        (payload.signing_payload_digest, resolved_policy.signing_payload_digest),
        (source_entry.policy_commit.commit_receipt_digest, resolved_policy.commit_receipt_digest),
        (source_entry.ledger_entry_digest, resolved_policy.ledger_entry_digest),
    )
    if any(left != right for left, right in bindings):
        raise AssumptionPolicyActivationContractError(
            "ASSUMPTION_GRANT_SELECTION_SOURCE_BINDING_MISMATCH"
        )
    return source_entry


# ===========================================================================
# 4. GrantSelectionDecision
# ===========================================================================


@dataclass(frozen=True, slots=True)
class GrantSelectionDecision:
    """Frozen fail-closed grant-selection decision.

    The decision binds the resolved policy generation, the request, and the
    selected grant (or the denial reason) at the queried sequence. The
    ``selection_digest`` is a domain-separated self-digest over the complete
    unsigned value (including ``decision_code``), so two selections of the
    same ``(resolved_policy, request)`` pair produce byte-identical digests
    only when the outcome (selected / no-applicable-grant / ambiguous) also
    agrees.
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
    decision_code: str
    selected_grant_id: str | None
    grant_digest: str | None
    selection_digest: str

    def __post_init__(self) -> None:
        if self.decision_type not in DECISION_TYPES:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_DECISION_TYPE_INVALID"
            )
        # The decision code is the frozen vocabulary: one per decision type.
        expected_code = DECISION_CODES[self.decision_type]
        if self.decision_code != expected_code:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_DECISION_CODE_INVALID"
            )
        # Selection consistency: a SELECTED decision must carry both grant
        # bindings and a valid selected_grant_id token; a denial must carry
        # neither and no grant id.
        if self.decision_type == "SELECTED":
            if self.selected_grant_id is None or self.grant_digest is None:
                raise AssumptionPolicyActivationContractError(
                    "ASSUMPTION_GRANT_SELECTION_SELECTED_GRANT_MISSING"
                )
            require_token(
                self.selected_grant_id,
                "ASSUMPTION_GRANT_SELECTION_SELECTED_GRANT_ID_INVALID",
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
        # Closed contract invariant: the queried event sequence must fall at
        # or after the resolved policy's effective_from_sequence.
        if self.event_sequence < self.effective_from_sequence:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_GRANT_SELECTION_EVENT_BEFORE_POLICY_EFFECTIVE"
            )
        require_token(self.policy_id, "ASSUMPTION_GRANT_SELECTION_POLICY_ID_INVALID")
        require_token(self.authority_id, "ASSUMPTION_GRANT_SELECTION_AUTHORITY_INVALID")
        require_token(self.scope_id, "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID")
        if self.action not in ASSUMPTION_AUTHORITY_ACTIONS:
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
            "decision_code": self.decision_code,
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
# 5. select_applicable_grant_v3
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
        "decision_code": DECISION_CODES[decision_type],
        "decision_type": decision_type,
        "effective_from_sequence": resolved_policy.effective_from_sequence,
        "event_sequence": resolved_policy.event_sequence,
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
        event_sequence=resolved_policy.event_sequence,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        decision_type=decision_type,
        decision_code=DECISION_CODES[decision_type],
        selected_grant_id=grant.grant_id if grant is not None else None,
        grant_digest=grant.grant_digest if grant is not None else None,
        selection_digest=domain_digest("ASSUMPTION_GRANT_SELECTION_DECISION", unsigned),
    )


def _validate_selection_request(
    *,
    action: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
) -> None:
    """Validate the request inputs (raises on contract violations).

    Does NOT return a denial: a denial is a valid outcome produced by the
    caller. This gate raises only on genuine input-contract violations. The
    order mirrors the decision-dataclass post-init so a bad input surfaces the
    same code regardless of which gate fires first.
    """

    if action not in ASSUMPTION_AUTHORITY_ACTIONS:
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


def select_applicable_grant_v3(
    *,
    ledger: AssumptionPolicyLedgerV3,
    resolved_policy: ResolvedPolicyAtSequence,
    action: str,
    authority_id: str,
    scope_id: str,
    assumption_materiality: str,
    challenge_materiality: str | None,
) -> GrantSelectionDecision:
    """Pure exact grant selection against the resolved policy.

    Re-binds ``resolved_policy`` to its source ledger entry via
    :func:`_source_entry_for_resolution` and scans THAT entry's digested grant
    set (``source_entry.policy.grants``) -- never a caller-carried tuple -- so
    a substituted grant tuple cannot authorize. The single event sequence used
    for all grant-interval evaluation is ``resolved_policy.event_sequence``:
    there is no independently supplied event sequence, so the sequence cannot
    be rebound to a different generation.

    Returns exactly one of:

    * ``SELECTED`` -- exactly one grant is applicable; ``selected_grant_id``
      and ``grant_digest`` carry its bindings.
    * ``NO_APPLICABLE_GRANT`` -- zero grants are applicable (a denial).
    * ``AMBIGUOUS_GRANTS`` -- two or more grants are applicable (a fail-closed
      denial: a well-formed policy never has two applicable grants for one
      request, so this is a configuration error the operator must reconcile).

    Raises ``AssumptionPolicyActivationContractError`` for genuine
    input-contract violations (bad ledger type, foreign resolution object,
    ledger-root mismatch, missing/ambiguous source entry, source binding
    mismatch, bad action, bad materiality, bad authority/scope token, wrong
    decision code, event before the policy's effective sequence). Denials
    (zero or multiple matches) are returned as decisions, not raised.

    The scan is deterministic because ``source_entry.policy.grants`` is the
    canonical (grant_id-sorted) grant tuple from the resolved entry's policy.
    """

    # Re-bind the resolution to its source entry. This validates the ledger
    # type, the resolution type, the ledger-root agreement, the uniqueness of
    # the source entry, and every binding. A foreign resolution object or a
    # ledger from a different generation surfaces a stable code here, before
    # any request input is read.
    source_entry = _source_entry_for_resolution(ledger=ledger, resolved_policy=resolved_policy)
    # Validate the request inputs BEFORE scanning grants, mirroring the
    # decision-dataclass post-init order.
    _validate_selection_request(
        action=action,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
    )
    # Validate the authority and scope tokens before scanning. A bad token
    # raises the stable contract code, never an AttributeError from a foreign
    # resolution object.
    require_token(authority_id, "ASSUMPTION_GRANT_SELECTION_AUTHORITY_INVALID")
    require_token(scope_id, "ASSUMPTION_GRANT_SELECTION_SCOPE_INVALID")
    # The single event sequence for all grant-interval evaluation is the
    # resolved policy's. It cannot be rebound.
    event_sequence = resolved_policy.event_sequence
    matches = [
        grant
        for grant in source_entry.policy.grants
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
            decision_type="SELECTED",
            grant=matches[0],
        )
    # Two or more applicable grants: fail closed. The decision carries no
    # grant bindings (it is a denial), but the operator can reconcile by
    # inspecting the policy. The scan is stable because
    # ``source_entry.policy.grants`` is canonical (sorted by grant_id).
    return _build_decision(
        resolved_policy=resolved_policy,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
        decision_type="AMBIGUOUS_GRANTS",
        grant=None,
    )


# ===========================================================================
# 6. Composite: resolve_policy_and_select_grant
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
    """Composite: resolve -> select.

    Order of operations:

    1. ``resolve_policy_at_v3(ledger, event_sequence)`` -- pure resolution,
       yielding the resolved policy binding (a digest receipt, no grants);
    2. ``select_applicable_grant_v3(ledger=ledger, resolved_policy=resolved,
       ...)`` -- pure exact grant selection that re-binds the resolution to
       its source entry and scans that entry's digested grants.

    The composite performs no I/O and no locking: it is the pure read path
    over an already-validated in-memory ``AssumptionPolicyLedgerV3``. For the
    durable filesystem path, use
    :meth:`FilesystemAssumptionPolicyPublisher.resolve_policy_and_select_grant_at`.

    The composite guarantees the resolution and selection share the same
    snapshot: selection re-binds the resolution to the SAME ledger (the
    resolution's ``ledger_root_digest`` must equal the ledger's root), so a
    concurrent append cannot split the read across two generations.
    """

    resolved = resolve_policy_at_v3(ledger, event_sequence)
    return select_applicable_grant_v3(
        ledger=ledger,
        resolved_policy=resolved,
        action=action,
        authority_id=authority_id,
        scope_id=scope_id,
        assumption_materiality=assumption_materiality,
        challenge_materiality=challenge_materiality,
    )
