"""Non-circular v0.5-D3.2-A1.2-0 assumption policy signing envelope.

This module corrects a self-referential signing dependency in the frozen V2
contracts. Under V2, ``signature_set_digest`` is a commit field, and signatures
target ``commit_receipt_digest``; since the commit digest incorporates the
signature-set digest, and the signature records contribute to the signature-set
digest, the V2 envelope contains signatures over a digest that contains the
digest of those signatures. This is a circular dependency with no fixed point.

The V3 envelope separates the pre-signing payload from the post-signature
activation commitment:

```text
policy-generation commitments
  -> signing payload
  -> signing_payload_digest
  -> signatures target signing_payload_digest
  -> signature set
  -> signature_set_digest
  -> commit/3 binds (signing_payload_digest, signature_set_digest)
  -> commit_receipt_digest
```

There is no cycle: the signing payload excludes all signature-derived fields, so
signers sign a payload that does not transitively depend on their signatures.

The old V2 contracts (commit/2, proof/1, entry/2, ledger/2) remain parseable
but the executable preparer rejects them with
``ASSUMPTION_POLICY_COMMIT_VERSION_NOT_ACTIVATABLE``.
"""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
    AssumptionChallengeClassificationPolicy,
    AssumptionPolicyActivationContractError,
    AssumptionPolicySignatureProfile,
    domain_digest,
    json_bytes,
    require_digest,
    require_self_digest,
    require_token,
)
from csd_foundry.governance.v0_5.assumption_governance_contracts import (
    AssumptionAuthorityPolicy,
)
from csd_foundry.governance.v0_5.assumption_governance_execution_contracts import (
    AssumptionPolicyApprovalPolicy,
)

SIGNING_PAYLOAD_SCHEMA_VERSION = "assumption-policy-signing-payload/1"
AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION = "assumption-authority-policy-commit/3"
ACTIVATION_PROOF_V2_SCHEMA_VERSION = "assumption-policy-activation-proof/2"
POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION = "assumption-policy-ledger-entry/3"
POLICY_LEDGER_V3_SCHEMA_VERSION = "assumption-policy-ledger/3"


# --- 1. pre-signing payload ------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssumptionPolicySigningPayload:
    """Every policy-generation fact that signers approve, excluding signatures.

    The signing payload is the sole target of policy-activation signatures.
    It must NOT contain ``signature_set_digest``, signature bytes, activation
    proof, ledger-entry digest, or resulting ledger root -- those are all
    post-signature artifacts whose inclusion would recreate the V2 cycle.
    """

    policy_id: str
    policy_digest: str
    predecessor_policy_digest: str | None
    predecessor_commit_receipt_digest: str | None
    authority_root_digest: str
    grant_set_digest: str
    separation_duty_rule_set_digest: str
    exception_set_digest: str
    exception_count: int
    approval_class: str
    effective_from_sequence: int
    approval_policy_digest: str
    signature_profile_digest: str
    challenge_classification_policy_digest: str
    signing_payload_digest: str

    def __post_init__(self) -> None:
        require_token(self.policy_id, "ASSUMPTION_POLICY_SIGNING_PAYLOAD_POLICY_ID_INVALID")
        digest_fields = (
            (self.policy_digest, "ASSUMPTION_POLICY_SIGNING_PAYLOAD_POLICY_DIGEST_INVALID"),
            (self.authority_root_digest, "ASSUMPTION_POLICY_SIGNING_PAYLOAD_ROOT_INVALID"),
            (self.grant_set_digest, "ASSUMPTION_POLICY_SIGNING_PAYLOAD_GRANT_SET_INVALID"),
            (
                self.separation_duty_rule_set_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_DUTY_RULE_SET_INVALID",
            ),
            (self.exception_set_digest, "ASSUMPTION_POLICY_SIGNING_PAYLOAD_EXCEPTION_SET_INVALID"),
            (
                self.approval_policy_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_APPROVAL_POLICY_INVALID",
            ),
            (
                self.signature_profile_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_SIGNATURE_PROFILE_INVALID",
            ),
            (
                self.challenge_classification_policy_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_CHALLENGE_POLICY_INVALID",
            ),
        )
        for value, code in digest_fields:
            require_digest(value, code)
        predecessor_none = self.predecessor_policy_digest is None
        receipt_none = self.predecessor_commit_receipt_digest is None
        if predecessor_none != receipt_none:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_PREDECESSOR_INCOMPLETE"
            )
        if self.predecessor_policy_digest is not None:
            require_digest(
                self.predecessor_policy_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_PREDECESSOR_POLICY_INVALID",
            )
            require_digest(
                self.predecessor_commit_receipt_digest,
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_PREDECESSOR_RECEIPT_INVALID",
            )
        if type(self.exception_count) is not int or self.exception_count < 0:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_EXCEPTION_COUNT_INVALID"
            )
        expected_class = "DUTY_EXCEPTION" if self.exception_count else "STANDARD"
        if self.approval_class != expected_class:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_APPROVAL_CLASS_DOWNGRADE"
            )
        if type(self.effective_from_sequence) is not int or self.effective_from_sequence < 0:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_SIGNING_PAYLOAD_EFFECTIVE_SEQUENCE_INVALID"
            )
        require_self_digest(
            "ASSUMPTION_POLICY_SIGNING_PAYLOAD",
            self._unsigned_value(),
            self.signing_payload_digest,
            "ASSUMPTION_POLICY_SIGNING_PAYLOAD_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy: AssumptionAuthorityPolicy,
        predecessor_policy_digest: str | None,
        predecessor_commit_receipt_digest: str | None,
        effective_from_sequence: int,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_policy: AssumptionChallengeClassificationPolicy,
    ) -> AssumptionPolicySigningPayload:
        approval_class = "DUTY_EXCEPTION" if policy.duty_exceptions else "STANDARD"
        unsigned = {
            "schema_version": SIGNING_PAYLOAD_SCHEMA_VERSION,
            "approval_class": approval_class,
            "approval_policy_digest": approval_policy.approval_policy_digest,
            "authority_root_digest": policy.authority_root_digest,
            "challenge_classification_policy_digest": challenge_policy.policy_digest,
            "effective_from_sequence": effective_from_sequence,
            "exception_count": len(policy.duty_exceptions),
            "exception_set_digest": policy.exception_set_digest,
            "grant_set_digest": policy.grant_set_digest,
            "policy_digest": policy.policy_digest,
            "policy_id": policy.policy_id,
            "predecessor_commit_receipt_digest": predecessor_commit_receipt_digest,
            "predecessor_policy_digest": predecessor_policy_digest,
            "separation_duty_rule_set_digest": policy.separation_duty_rule_set_digest,
            "signature_profile_digest": signature_profile.profile_digest,
        }
        return cls(
            policy_id=policy.policy_id,
            policy_digest=policy.policy_digest,
            predecessor_policy_digest=predecessor_policy_digest,
            predecessor_commit_receipt_digest=predecessor_commit_receipt_digest,
            authority_root_digest=policy.authority_root_digest,
            grant_set_digest=policy.grant_set_digest,
            separation_duty_rule_set_digest=policy.separation_duty_rule_set_digest,
            exception_set_digest=policy.exception_set_digest,
            exception_count=len(policy.duty_exceptions),
            approval_class=approval_class,
            effective_from_sequence=effective_from_sequence,
            approval_policy_digest=approval_policy.approval_policy_digest,
            signature_profile_digest=signature_profile.profile_digest,
            challenge_classification_policy_digest=challenge_policy.policy_digest,
            signing_payload_digest=domain_digest("ASSUMPTION_POLICY_SIGNING_PAYLOAD", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": SIGNING_PAYLOAD_SCHEMA_VERSION,
            "approval_class": self.approval_class,
            "approval_policy_digest": self.approval_policy_digest,
            "authority_root_digest": self.authority_root_digest,
            "challenge_classification_policy_digest": (self.challenge_classification_policy_digest),
            "effective_from_sequence": self.effective_from_sequence,
            "exception_count": self.exception_count,
            "exception_set_digest": self.exception_set_digest,
            "grant_set_digest": self.grant_set_digest,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "predecessor_commit_receipt_digest": self.predecessor_commit_receipt_digest,
            "predecessor_policy_digest": self.predecessor_policy_digest,
            "separation_duty_rule_set_digest": self.separation_duty_rule_set_digest,
            "signature_profile_digest": self.signature_profile_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "signing_payload_digest": self.signing_payload_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# --- 2. post-signature activation commit v3 --------------------------------


@dataclass(frozen=True, slots=True)
class AssumptionAuthorityPolicyCommitV3:
    """Post-signature commitment binding the signing payload and signature set.

    The commit receipt digest binds ``signing_payload_digest`` (what was signed)
    and ``signature_set_digest`` (the signatures). Signers never sign this
    object; they sign the signing payload, which excludes both fields.
    """

    signing_payload_digest: str
    signature_set_digest: str
    commit_receipt_digest: str

    def __post_init__(self) -> None:
        require_digest(
            self.signing_payload_digest,
            "ASSUMPTION_POLICY_COMMIT_V3_SIGNING_PAYLOAD_INVALID",
        )
        require_digest(
            self.signature_set_digest,
            "ASSUMPTION_POLICY_COMMIT_V3_SIGNATURE_SET_INVALID",
        )
        require_self_digest(
            "ASSUMPTION_AUTHORITY_POLICY_COMMIT_V3",
            self._unsigned_value(),
            self.commit_receipt_digest,
            "ASSUMPTION_POLICY_COMMIT_V3_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        signing_payload_digest: str,
        signature_set_digest: str,
    ) -> AssumptionAuthorityPolicyCommitV3:
        unsigned = {
            "schema_version": AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION,
            "signature_set_digest": signature_set_digest,
            "signing_payload_digest": signing_payload_digest,
        }
        return cls(
            signing_payload_digest=signing_payload_digest,
            signature_set_digest=signature_set_digest,
            commit_receipt_digest=domain_digest("ASSUMPTION_AUTHORITY_POLICY_COMMIT_V3", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": AUTHORITY_POLICY_COMMIT_V3_SCHEMA_VERSION,
            "signature_set_digest": self.signature_set_digest,
            "signing_payload_digest": self.signing_payload_digest,
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "commit_receipt_digest": self.commit_receipt_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# --- 3. activation proof v2 ------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssumptionPolicyActivationProofV2:
    """Verified activation proof binding the V3 envelope."""

    signing_payload_digest: str
    policy_commit_receipt_digest: str
    approval_policy_digest: str
    approval_rule_digest: str
    signature_profile_digest: str
    challenge_classification_policy_digest: str
    authority_root_digest: str
    signature_set_digest: str
    valid_signer_ids: tuple[str, ...]
    rejected_signer_codes: tuple[str, ...]
    activation_proof_digest: str

    def __post_init__(self) -> None:
        from csd_foundry.governance.v0_5._assumption_policy_activation_common import (
            require_sorted_tokens,
        )

        digest_fields = (
            (self.signing_payload_digest, "ASSUMPTION_ACTIVATION_PROOF_V2_PAYLOAD_INVALID"),
            (
                self.policy_commit_receipt_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_COMMIT_INVALID",
            ),
            (
                self.approval_policy_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_APPROVAL_POLICY_INVALID",
            ),
            (
                self.approval_rule_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_APPROVAL_RULE_INVALID",
            ),
            (
                self.signature_profile_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_SIGNATURE_PROFILE_INVALID",
            ),
            (
                self.challenge_classification_policy_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_CHALLENGE_POLICY_INVALID",
            ),
            (self.authority_root_digest, "ASSUMPTION_ACTIVATION_PROOF_V2_ROOT_INVALID"),
            (
                self.signature_set_digest,
                "ASSUMPTION_ACTIVATION_PROOF_V2_SIGNATURE_SET_INVALID",
            ),
        )
        for value, code in digest_fields:
            require_digest(value, code)
        require_sorted_tokens(
            self.valid_signer_ids,
            "ASSUMPTION_ACTIVATION_PROOF_V2_SIGNERS_INVALID",
            allow_empty=False,
        )
        require_sorted_tokens(
            self.rejected_signer_codes,
            "ASSUMPTION_ACTIVATION_PROOF_V2_REJECTIONS_INVALID",
            allow_empty=True,
        )
        require_self_digest(
            "ASSUMPTION_POLICY_ACTIVATION_PROOF_V2",
            self._unsigned_value(),
            self.activation_proof_digest,
            "ASSUMPTION_ACTIVATION_PROOF_V2_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        signing_payload_digest: str,
        policy_commit_receipt_digest: str,
        approval_policy_digest: str,
        approval_rule_digest: str,
        signature_profile_digest: str,
        challenge_classification_policy_digest: str,
        authority_root_digest: str,
        signature_set_digest: str,
        valid_signer_ids: tuple[str, ...],
        rejected_signer_codes: tuple[str, ...] = (),
    ) -> AssumptionPolicyActivationProofV2:
        signers = tuple(sorted(set(valid_signer_ids)))
        rejected = tuple(sorted(set(rejected_signer_codes)))
        unsigned = {
            "schema_version": ACTIVATION_PROOF_V2_SCHEMA_VERSION,
            "approval_policy_digest": approval_policy_digest,
            "approval_rule_digest": approval_rule_digest,
            "authority_root_digest": authority_root_digest,
            "challenge_classification_policy_digest": (challenge_classification_policy_digest),
            "policy_commit_receipt_digest": policy_commit_receipt_digest,
            "rejected_signer_codes": list(rejected),
            "signature_profile_digest": signature_profile_digest,
            "signature_set_digest": signature_set_digest,
            "signing_payload_digest": signing_payload_digest,
            "valid_signer_ids": list(signers),
        }
        return cls(
            signing_payload_digest=signing_payload_digest,
            policy_commit_receipt_digest=policy_commit_receipt_digest,
            approval_policy_digest=approval_policy_digest,
            approval_rule_digest=approval_rule_digest,
            signature_profile_digest=signature_profile_digest,
            challenge_classification_policy_digest=challenge_classification_policy_digest,
            authority_root_digest=authority_root_digest,
            signature_set_digest=signature_set_digest,
            valid_signer_ids=signers,
            rejected_signer_codes=rejected,
            activation_proof_digest=domain_digest(
                "ASSUMPTION_POLICY_ACTIVATION_PROOF_V2", unsigned
            ),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": ACTIVATION_PROOF_V2_SCHEMA_VERSION,
            "approval_policy_digest": self.approval_policy_digest,
            "approval_rule_digest": self.approval_rule_digest,
            "authority_root_digest": self.authority_root_digest,
            "challenge_classification_policy_digest": (self.challenge_classification_policy_digest),
            "policy_commit_receipt_digest": self.policy_commit_receipt_digest,
            "rejected_signer_codes": list(self.rejected_signer_codes),
            "signature_profile_digest": self.signature_profile_digest,
            "signature_set_digest": self.signature_set_digest,
            "signing_payload_digest": self.signing_payload_digest,
            "valid_signer_ids": list(self.valid_signer_ids),
        }

    def to_json_value(self) -> dict[str, object]:
        return {
            **self._unsigned_value(),
            "activation_proof_digest": self.activation_proof_digest,
        }


# --- 4. ledger entry v3 ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedgerEntryV3:
    """V3 ledger entry embedding the complete signing-payload envelope."""

    policy: AssumptionAuthorityPolicy
    signing_payload: AssumptionPolicySigningPayload
    policy_commit: AssumptionAuthorityPolicyCommitV3
    approval_policy: AssumptionPolicyApprovalPolicy
    signature_profile: AssumptionPolicySignatureProfile
    challenge_classification_policy: AssumptionChallengeClassificationPolicy
    activation_proof: AssumptionPolicyActivationProofV2
    ledger_entry_digest: str

    def __post_init__(self) -> None:
        payload = self.signing_payload
        commit = self.policy_commit
        proof = self.activation_proof
        rule = self.approval_policy.rule_for(payload.approval_class)
        bindings = (
            # payload <-> policy
            (payload.policy_id, self.policy.policy_id),
            (payload.policy_digest, self.policy.policy_digest),
            (payload.authority_root_digest, self.policy.authority_root_digest),
            (payload.grant_set_digest, self.policy.grant_set_digest),
            (
                payload.separation_duty_rule_set_digest,
                self.policy.separation_duty_rule_set_digest,
            ),
            (payload.exception_set_digest, self.policy.exception_set_digest),
            (payload.exception_count, len(self.policy.duty_exceptions)),
            # payload <-> approval/profile/challenge
            (
                payload.approval_policy_digest,
                self.approval_policy.approval_policy_digest,
            ),
            (
                payload.signature_profile_digest,
                self.signature_profile.profile_digest,
            ),
            (
                payload.challenge_classification_policy_digest,
                self.challenge_classification_policy.policy_digest,
            ),
            # commit binds payload + sig set
            (commit.signing_payload_digest, payload.signing_payload_digest),
            (commit.signature_set_digest, proof.signature_set_digest),
            # proof binds to payload + commit + objects
            (proof.signing_payload_digest, payload.signing_payload_digest),
            (proof.policy_commit_receipt_digest, commit.commit_receipt_digest),
            (proof.approval_policy_digest, self.approval_policy.approval_policy_digest),
            (proof.approval_rule_digest, rule.rule_digest),
            (proof.signature_profile_digest, self.signature_profile.profile_digest),
            (
                proof.challenge_classification_policy_digest,
                self.challenge_classification_policy.policy_digest,
            ),
            (proof.authority_root_digest, self.policy.authority_root_digest),
            (proof.signature_set_digest, commit.signature_set_digest),
        )
        if any(left != right for left, right in bindings):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_BINDING_MISMATCH"
            )
        require_self_digest(
            "ASSUMPTION_POLICY_LEDGER_ENTRY_V3",
            self._unsigned_value(),
            self.ledger_entry_digest,
            "ASSUMPTION_POLICY_LEDGER_ENTRY_V3_DIGEST_MISMATCH",
        )

    @classmethod
    def build(
        cls,
        *,
        policy: AssumptionAuthorityPolicy,
        signing_payload: AssumptionPolicySigningPayload,
        policy_commit: AssumptionAuthorityPolicyCommitV3,
        approval_policy: AssumptionPolicyApprovalPolicy,
        signature_profile: AssumptionPolicySignatureProfile,
        challenge_classification_policy: AssumptionChallengeClassificationPolicy,
        activation_proof: AssumptionPolicyActivationProofV2,
    ) -> AssumptionPolicyLedgerEntryV3:
        unsigned = {
            "schema_version": POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION,
            "activation_proof": activation_proof.to_json_value(),
            "approval_policy": approval_policy.to_json_value(),
            "challenge_classification_policy": (challenge_classification_policy.to_json_value()),
            "policy": policy.to_json_value(),
            "policy_commit": policy_commit.to_json_value(),
            "signature_profile": signature_profile.to_json_value(),
            "signing_payload": signing_payload.to_json_value(),
        }
        return cls(
            policy=policy,
            signing_payload=signing_payload,
            policy_commit=policy_commit,
            approval_policy=approval_policy,
            signature_profile=signature_profile,
            challenge_classification_policy=challenge_classification_policy,
            activation_proof=activation_proof,
            ledger_entry_digest=domain_digest("ASSUMPTION_POLICY_LEDGER_ENTRY_V3", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_ENTRY_V3_SCHEMA_VERSION,
            "activation_proof": self.activation_proof.to_json_value(),
            "approval_policy": self.approval_policy.to_json_value(),
            "challenge_classification_policy": (
                self.challenge_classification_policy.to_json_value()
            ),
            "policy": self.policy.to_json_value(),
            "policy_commit": self.policy_commit.to_json_value(),
            "signature_profile": self.signature_profile.to_json_value(),
            "signing_payload": self.signing_payload.to_json_value(),
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "ledger_entry_digest": self.ledger_entry_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# --- 5. ledger v3 ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssumptionPolicyLedgerV3:
    """Validated linear V3 policy chain with full-chain root digest."""

    entries: tuple[AssumptionPolicyLedgerEntryV3, ...]
    ledger_root_digest: str

    def __post_init__(self) -> None:
        ordered = order_policy_entries_v3(self.entries)
        if ordered != self.entries:
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_V3_ENTRIES_NOT_CANONICAL"
            )
        require_self_digest(
            "ASSUMPTION_POLICY_LEDGER_V3",
            self._unsigned_value(),
            self.ledger_root_digest,
            "ASSUMPTION_POLICY_LEDGER_V3_ROOT_MISMATCH",
        )

    @classmethod
    def build(cls, entries: tuple[AssumptionPolicyLedgerEntryV3, ...]) -> AssumptionPolicyLedgerV3:
        ordered = order_policy_entries_v3(entries)
        unsigned = {
            "schema_version": POLICY_LEDGER_V3_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in ordered],
        }
        return cls(
            entries=ordered,
            ledger_root_digest=domain_digest("ASSUMPTION_POLICY_LEDGER_V3", unsigned),
        )

    def _unsigned_value(self) -> dict[str, object]:
        return {
            "schema_version": POLICY_LEDGER_V3_SCHEMA_VERSION,
            "entries": [item.to_json_value() for item in self.entries],
        }

    def to_json_value(self) -> dict[str, object]:
        return {**self._unsigned_value(), "ledger_root_digest": self.ledger_root_digest}

    @property
    def canonical_bytes(self) -> bytes:
        return json_bytes(self.to_json_value())


# --- chain ordering for V3 -------------------------------------------------


def order_policy_entries_v3(
    entries: tuple[AssumptionPolicyLedgerEntryV3, ...],
) -> tuple[AssumptionPolicyLedgerEntryV3, ...]:
    if not entries:
        return ()
    children: dict[str, list[AssumptionPolicyLedgerEntryV3]] = {}
    genesis: list[AssumptionPolicyLedgerEntryV3] = []
    for entry in entries:
        predecessor = entry.signing_payload.predecessor_commit_receipt_digest
        if predecessor is None:
            genesis.append(entry)
        else:
            children.setdefault(predecessor, []).append(entry)
    if len(genesis) != 1:
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_V3_GENESIS_INVALID")
    ordered: list[AssumptionPolicyLedgerEntryV3] = []
    visited: set[str] = set()
    current = genesis[0]
    while True:
        digest = current.policy_commit.commit_receipt_digest
        if digest in visited:
            raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_V3_CYCLE")
        visited.add(digest)
        ordered.append(current)
        successors = children.get(digest, [])
        if len(successors) > 1:
            raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_V3_CHAIN_FORK")
        if not successors:
            break
        successor = successors[0]
        if (
            successor.signing_payload.effective_from_sequence
            <= current.signing_payload.effective_from_sequence
        ):
            raise AssumptionPolicyActivationContractError(
                "ASSUMPTION_POLICY_LEDGER_V3_EFFECTIVE_SEQUENCE_NOT_INCREASING"
            )
        current = successor
    if len(visited) != len(entries):
        raise AssumptionPolicyActivationContractError("ASSUMPTION_POLICY_LEDGER_V3_DISCONNECTED")
    return tuple(ordered)
