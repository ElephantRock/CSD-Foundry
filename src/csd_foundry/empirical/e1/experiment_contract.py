"""Frozen repository-side selection contract for the bounded E1 experiment."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from csd_foundry.empirical.e1.execution_splits import (
    E1Split,
    FamilySplitError,
    FamilySplitManifest,
    ScenarioFamilyIdentity,
    compile_family_split_manifest,
    derive_scenario_family_identity,
)
from csd_foundry.scenarios.spec import ScenarioSpec
from csd_foundry.synthesis.v0_4.serialization import canonical_sha256

_EXPERIMENT_SCHEMA_VERSION = "e1-experiment-contract/1"
_SOURCE_SPLIT_POLICY = {
    "train": E1Split.TRAIN.value,
    "validation": E1Split.DEVELOPMENT.value,
    "test": "excluded_blind",
}
_EXPECTED_SOURCE_SPLIT = {
    E1Split.TRAIN: "train",
    E1Split.DEVELOPMENT: "validation",
}
_CLAIM_BOUNDARY = (
    "This contract fixes E1 candidate admission and symbolic-family train/development "
    "isolation while excluding the source test split from identity derivation. It does "
    "not fix a model, tokenizer, training recipe, token budget, GPU allocation, metric "
    "result, or Phase 10 blind-holdout evaluation."
)


@dataclass(frozen=True, slots=True)
class E1ExperimentContract:
    """Digest-bound E1 candidate partition with an explicit blind exclusion."""

    release: str
    source_commit: str
    split_manifest: FamilySplitManifest
    eligible_scenario_count: int
    excluded_blind_scenario_count: int

    def __post_init__(self) -> None:
        if not self.release.strip():
            raise FamilySplitError("E1 experiment release must be nonempty")
        if self.source_commit != self.split_manifest.source_commit:
            raise FamilySplitError("experiment and split-manifest source commits must match")
        if self.release != self.split_manifest.release:
            raise FamilySplitError("experiment and split-manifest releases must match")
        if self.eligible_scenario_count <= 0:
            raise FamilySplitError("E1 experiment requires eligible scenarios")
        if self.excluded_blind_scenario_count <= 0:
            raise FamilySplitError("E1 experiment requires an excluded blind source split")

        assigned_count = sum(len(item.scenario_ids) for item in self.split_manifest.assignments)
        if assigned_count != self.eligible_scenario_count:
            raise FamilySplitError("eligible scenario count does not match split assignments")

        for assignment in self.split_manifest.assignments:
            expected_source_split = _EXPECTED_SOURCE_SPLIT[assignment.split]
            if assignment.source_splits != (expected_source_split,):
                raise FamilySplitError(
                    "E1 assignment contradicts the source split policy: "
                    f"{assignment.family_digest} maps {assignment.source_splits} "
                    f"to {assignment.split.value}"
                )

    def _digest_payload(self) -> dict[str, object]:
        return {
            "schema_version": _EXPERIMENT_SCHEMA_VERSION,
            "release": self.release,
            "source_commit": self.source_commit,
            "source_split_policy": dict(_SOURCE_SPLIT_POLICY),
            "eligible_scenario_count": self.eligible_scenario_count,
            "excluded_blind_scenario_count": self.excluded_blind_scenario_count,
            "split_manifest": self.split_manifest.to_dict(),
            "claim_boundary": _CLAIM_BOUNDARY,
        }

    @property
    def contract_digest(self) -> str:
        return canonical_sha256(self._digest_payload())

    def to_dict(self) -> dict[str, object]:
        return {**self._digest_payload(), "contract_digest": self.contract_digest}


def _partition_source_splits(
    scenarios: Iterable[ScenarioSpec],
) -> tuple[tuple[ScenarioSpec, ...], tuple[ScenarioSpec, ...]]:
    ordered = tuple(sorted(scenarios, key=lambda item: item.scenario_id))
    if not ordered:
        raise FamilySplitError("cannot compile an E1 experiment contract without scenarios")

    scenario_ids = tuple(item.scenario_id for item in ordered)
    if len(scenario_ids) != len(set(scenario_ids)):
        raise FamilySplitError("scenario identifiers must be unique")

    unknown = sorted({item.split for item in ordered} - _SOURCE_SPLIT_POLICY.keys())
    if unknown:
        raise FamilySplitError(f"unsupported E1 source splits: {unknown}")

    eligible = tuple(item for item in ordered if item.split in {"train", "validation"})
    excluded_blind = tuple(item for item in ordered if item.split == "test")
    if not excluded_blind:
        raise FamilySplitError("E1 experiment requires an excluded blind source split")
    return eligible, excluded_blind


def _derive_eligible_identities(
    eligible: tuple[ScenarioSpec, ...],
) -> tuple[ScenarioFamilyIdentity, ...]:
    identities = tuple(derive_scenario_family_identity(item) for item in eligible)
    source_splits_by_family: dict[str, set[str]] = {}
    for identity in identities:
        source_splits_by_family.setdefault(identity.family_digest, set()).add(identity.source_split)

    crossing = {
        digest: tuple(sorted(source_splits))
        for digest, source_splits in source_splits_by_family.items()
        if len(source_splits) > 1
    }
    if crossing:
        raise FamilySplitError(
            "symbolic families cross source train/validation boundaries: "
            f"{sorted(crossing.items())}"
        )
    return identities


def compile_e1_experiment_contract(
    scenarios: Iterable[ScenarioSpec],
    *,
    release: str,
    source_commit: str,
) -> E1ExperimentContract:
    """Compile the fixed repository-side E1 candidate and blind-exclusion contract."""

    eligible, excluded_blind = _partition_source_splits(scenarios)
    identities = _derive_eligible_identities(eligible)
    development_family_digests = frozenset(
        item.family_digest for item in identities if item.source_split == "validation"
    )
    split_manifest = compile_family_split_manifest(
        eligible,
        development_family_digests=development_family_digests,
        release=release,
        source_commit=source_commit,
    )
    return E1ExperimentContract(
        release=release,
        source_commit=source_commit,
        split_manifest=split_manifest,
        eligible_scenario_count=len(eligible),
        excluded_blind_scenario_count=len(excluded_blind),
    )
