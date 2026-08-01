"""Complete diagnostic replay bundles for one deterministic attempt."""

from __future__ import annotations

from dataclasses import dataclass

from csd_foundry.synthesis.v0_4.attempts import (
    AttemptAccepted,
    AttemptCompletion,
    AttemptRejected,
    AttemptReplayError,
)
from csd_foundry.synthesis.v0_4.choice_ledger import ChoiceLedger
from csd_foundry.synthesis.v0_4.choice_paths import RootSeed
from csd_foundry.synthesis.v0_4.generation_namespace import GenerationNamespace
from csd_foundry.synthesis.v0_4.identities import IdentityRecord
from csd_foundry.synthesis.v0_4.replay import (
    replay_bundle_commitment,
    replay_choice_ledger,
    replay_identity_records,
)
from csd_foundry.synthesis.v0_4.replay_policy import (
    AttemptInputCommitment,
    SearchBranchCommitment,
)
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256


@dataclass(frozen=True, slots=True)
class AttemptReplayBundle:
    input_commitment: AttemptInputCommitment
    completion: AttemptCompletion
    search_branch: SearchBranchCommitment
    choice_ledger: ChoiceLedger
    identity_records: tuple[IdentityRecord, ...]

    def __post_init__(self) -> None:
        if type(self) is not AttemptReplayBundle:
            raise AttemptReplayError("replay bundles must use the exact contract class")
        if type(self.input_commitment) is not AttemptInputCommitment:
            raise AttemptReplayError("input commitment must use the exact contract class")
        if type(self.completion) not in {AttemptAccepted, AttemptRejected}:
            raise AttemptReplayError("completion must use an exact semantic completion class")
        if type(self.search_branch) is not SearchBranchCommitment:
            raise AttemptReplayError("search branch must use the exact contract class")
        if type(self.choice_ledger) is not ChoiceLedger:
            raise AttemptReplayError("choice ledger must use the exact contract class")
        if type(self.identity_records) is not tuple or not all(
            type(record) is IdentityRecord for record in self.identity_records
        ):
            raise AttemptReplayError("identity records must be an exact immutable tuple")

        attempt_key = self.completion.attempt_key
        namespace_digest = self.completion.generation_namespace_digest
        if self.input_commitment.attempt_key != attempt_key:
            raise AttemptReplayError("input commitment belongs to a different attempt")
        if self.search_branch.attempt_key != attempt_key:
            raise AttemptReplayError("search branch belongs to a different attempt")
        if self.choice_ledger.attempt_key != attempt_key:
            raise AttemptReplayError("choice ledger belongs to a different attempt")
        if self.input_commitment.generation_namespace_digest != namespace_digest:
            raise AttemptReplayError("input commitment belongs to a different namespace")
        if self.search_branch.generation_namespace_digest != namespace_digest:
            raise AttemptReplayError("search branch belongs to a different namespace")
        if self.choice_ledger.generation_namespace_digest != namespace_digest:
            raise AttemptReplayError("choice ledger belongs to a different namespace")
        if self.completion.attempt_input_commitment_digest != self.input_commitment.digest:
            raise AttemptReplayError("completion input commitment digest does not match")
        if self.search_branch.attempt_input_commitment_digest != self.input_commitment.digest:
            raise AttemptReplayError("branch input commitment digest does not match")
        if self.completion.choice_ledger_digest != self.choice_ledger.canonical_digest:
            raise AttemptReplayError("completion choice ledger digest does not match")
        if self.search_branch.choice_ledger_digest != self.choice_ledger.canonical_digest:
            raise AttemptReplayError("branch choice ledger digest does not match")
        if self.completion.search_branch_digest != self.search_branch.digest:
            raise AttemptReplayError("completion search branch digest does not match")

    def validate(self, seed: RootSeed, namespace: GenerationNamespace) -> str:
        if type(seed) is not RootSeed:
            raise AttemptReplayError("bundle replay seed must use the exact RootSeed class")
        if type(namespace) is not GenerationNamespace:
            raise AttemptReplayError(
                "bundle replay namespace must use the exact GenerationNamespace class"
            )
        if namespace.digest != self.completion.generation_namespace_digest:
            raise AttemptReplayError("bundle generation namespace does not match")
        replay_choice_ledger(seed, namespace, self.choice_ledger)
        replay_identity_records(
            seed,
            namespace,
            self.identity_records,
            self.completion.identity_ledger_digest,
        )
        return self.evidence_digest

    @property
    def replay_evidence_digest(self) -> str:
        return replay_bundle_commitment(
            choice_ledger=self.choice_ledger,
            identity_records=self.identity_records,
            identity_ledger_digest=self.completion.identity_ledger_digest,
        )

    def to_json_value(self) -> dict[str, object]:
        return {
            "choice_ledger": self.choice_ledger.to_json_value(),
            "completion": self.completion.to_json_value(),
            "identity_records": [record.to_json_value() for record in self.identity_records],
            "input_commitment": self.input_commitment.to_json_value(),
            "replay_evidence_digest": self.replay_evidence_digest,
            "search_branch": self.search_branch.to_json_value(),
        }

    @property
    def evidence_digest(self) -> str:
        return canonical_sha256(self.to_json_value())
