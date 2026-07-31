#!/usr/bin/env python3
"""Deterministically generate the CSD reasoning seed corpus.

The generator uses only Python's standard library and performs no provider calls.
It converts reviewed Control-Status Discipline scenarios into:

* supervised fine-tuning records with public, structured justifications; and
* contrastive preference pairs with one rule-conformant and one defective answer.

The output is synthetic. It is a seed corpus, not evidence that a model trained
on it has acquired general reasoning ability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = "csd-reasoning-example/0.1"
DATASET_VERSION = "0.1.0"
SYSTEM_PROMPT = (
    "Apply the Control-Status Discipline exactly. Treat issued evidence and "
    "approved bases as explicit inputs, not as semantic truth. Invalidation is "
    "direction-agnostic and revocation-only: do not infer a replacement state "
    "or verdict. Give the decision first, followed by a concise, auditable "
    "justification using the cited rule identifiers."
)

SOURCE_BASELINES = {
    "control_status_discipline": {
        "version": "v0.9.0 Candidate",
        "sha256": "b2ae29adb3f2ae275c42a7fdb067cba758b54c606e9e350f6b2e41baee293d4e",
    },
    "formalization_charter": {
        "version": "v0.1.1 Approved",
        "sha256": "c59fc9779342c9a16fc8be3b7990f190ee3476eda198a7d7149e27664e6e7df2",
    },
}

VALID_RULES = {
    *(f"INV-{number:02d}" for number in range(1, 22)),
    "SYM-01",
    "LIVE-01",
    "A-04",
    "A-07",
    "G-INV-06",
    "G-INV-07",
    "G-INV-08",
    "G-INV-09",
    "G-INV-10",
    "G-INV-11",
    "G-INV-12",
    "G-INV-13",
    "G-INV-14",
    "G-INV-17",
    "REAL-01",
    "REAL-02",
}


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    split: str
    family: str
    difficulty: str
    source_section: str
    snapshot: str
    event: str
    decision: str
    evidence_impact: str
    basis_result: str
    justification: str
    rules: tuple[str, ...]
    rejected_answer: str
    rejected_reason: str
    next_step: str


VARIANTS = (
    {
        "variant": "infra",
        "surface": "enterprise infrastructure control",
        "c": "CTRL-NET-17",
        "c2": "CTRL-NET-18",
        "c3": "CTRL-NET-19",
        "dep": "DEP-FW-POLICY-7",
        "dep2": "DEP-IDENTITY-4",
        "e1": "EV-N17-001",
        "e2": "EV-N17-002",
        "e3": "EV-N17-003",
        "b1": "BASIS-N17-01",
        "b2": "BASIS-N17-02",
        "b3": "BASIS-N17-03",
    },
    {
        "variant": "ml_eval",
        "surface": "ML evaluation pipeline control",
        "c": "CTRL-ML-42",
        "c2": "CTRL-ML-43",
        "c3": "CTRL-ML-44",
        "dep": "DEP-DATASET-REV-12",
        "dep2": "DEP-HARNESS-REV-5",
        "e1": "EV-ML42-101",
        "e2": "EV-ML42-102",
        "e3": "EV-ML42-103",
        "b1": "BASIS-ML42-11",
        "b2": "BASIS-ML42-12",
        "b3": "BASIS-ML42-13",
    },
    {
        "variant": "research",
        "surface": "research evidence control",
        "c": "CTRL-RSCH-08",
        "c2": "CTRL-RSCH-09",
        "c3": "CTRL-RSCH-10",
        "dep": "DEP-METHOD-REV-3",
        "dep2": "DEP-CORPUS-REV-9",
        "e1": "EV-R08-201",
        "e2": "EV-R08-202",
        "e3": "EV-R08-203",
        "b1": "BASIS-R08-21",
        "b2": "BASIS-R08-22",
        "b3": "BASIS-R08-23",
    },
)


SCENARIOS = (
    Scenario(
        "M-01",
        "train",
        "revocation_non_inference",
        "medium",
        "Charter §12 M-01",
        (
            "{c} is current with sourceState=wiredInert. Approved source basis "
            "{b1} supports wiredInert and has sole member {e1}. {e1} is current "
            "S0 evidence and declares dependency {dep}."
        ),
        "DependencyChange({dep}, apparentlyFavourable).",
        (
            "{e1} becomes invalidated; {b1} is removed from current references; "
            "sourceState becomes sourceUnknown."
        ),
        "Only the evidence matched by {dep} is invalidated.",
        "No current basis remains for the previously assessed source state.",
        (
            "Apparent favourability is metadata, not authority to infer "
            "connected. Loss of the only state basis causes demotion to unknown."
        ),
        ("INV-11", "INV-12", "INV-13", "INV-15", "SYM-01"),
        "Promote sourceState from wiredInert to connected because the change looks favourable.",
        "Invalidation cannot promote or choose a replacement classification.",
        (
            "Keep sourceUnknown until governed reassessment issues qualifying "
            "new evidence and establishes a new approved source basis."
        ),
    ),
    Scenario(
        "M-02",
        "train",
        "lost_source_basis",
        "easy",
        "Charter §12 M-02",
        (
            "{c} is current with sourceState=connected. Its only current source "
            "basis {b1} contains S1 evidence {e1}, which depends on {dep}."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable).",
        ("{e1} becomes invalidated; {b1} is no longer current; sourceState becomes sourceUnknown."),
        "The matched S1 evidence is invalidated.",
        "Every current basis supporting connected is lost.",
        "Loss of the only connected basis demotes the source state to unknown.",
        ("INV-05", "INV-11", "INV-13", "INV-15"),
        "Select wiredInert as the most plausible remaining source state.",
        "Revocation may preserve the existing state or demote it to unknown; it cannot select another state.",
        (
            "Issue new qualifying S1 evidence with a new identity and establish "
            "a new approved source basis before restoring connected."
        ),
    ),
    Scenario(
        "M-03",
        "train",
        "expiry_and_staleness",
        "medium",
        "Charter §12 M-03",
        (
            "{c} is current with deploymentState=active and assurance=pass/current. "
            "The only deployment basis and the only pass basis both require current "
            "D evidence {e1}. No alternative basis exists."
        ),
        "AdvanceClock crosses the maximum age of {e1}.",
        (
            "{e1} becomes expired; deploymentState becomes deploymentUnknown; "
            "assurance and verdictFreshness become stale."
        ),
        "The expired D item can no longer be a current basis member.",
        "Both the active-deployment basis and the only pass basis become unsupported.",
        "Expiry applies the same atomic loss-of-basis semantics as a dependency change.",
        ("INV-06", "INV-07", "INV-09", "INV-15", "INV-20", "INV-21"),
        "Keep active/pass until a separate cleanup job removes the expired basis.",
        "Publication must not expose expired evidence as support for a current deployment or verdict.",
        (
            "Perform governed reassessment with new qualifying D evidence and "
            "new approved bases; do not reactivate the expired item."
        ),
    ),
    Scenario(
        "M-04",
        "train",
        "independent_failure_preservation",
        "medium",
        "Charter §12 M-04",
        (
            "{c} has assurance=fail/current. Failure basis {b1} contains F evidence "
            "{e1}. Independent failure basis {b2} contains current A, B, and D "
            "evidence and is sufficient on its own. Only {e1} depends on {dep}."
        ),
        "DependencyChange({dep}, apparentlyFavourable).",
        "F coverage becomes stale, {b1} is removed, and assurance remains fail/current on {b2}.",
        "Only {e1} and its dependent basis are invalidated.",
        "{b2} remains a current sufficient basis for the existing fail verdict.",
        "A surviving basis for the same verdict preserves that verdict.",
        ("INV-11", "INV-14", "INV-16", "INV-21", "SYM-01"),
        "Change fail to stale because any evidence used by the record changed.",
        "Whole-record staleness would destroy an independent current failure basis.",
        (
            "No verdict reassessment is required to retain fail. Reassess only "
            "the affected F coverage if that coverage must be restored."
        ),
    ),
    Scenario(
        "M-05",
        "train",
        "unsupported_historical_verdict",
        "easy",
        "Charter §12 M-05",
        (
            "{c} has assurance=fail/current and verdictEverEstablished=true. Its "
            "only failure basis {b1} requires A, B, and D evidence. D evidence "
            "{e1} depends on {dep}; there is no alternative fail basis."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable).",
        "{e1} is invalidated; {b1} is removed; assurance and verdictFreshness become stale.",
        "The matched D evidence is invalidated.",
        "No current basis survives for the previously established fail verdict.",
        "An unsupported historical verdict becomes stale, not pass or unverified.",
        ("INV-07", "INV-09", "INV-13", "INV-15"),
        "Set assurance to unverified because no current basis remains.",
        "Unverified means a substantive verdict was never established; this record had an established fail verdict.",
        (
            "Run a governed reassessment. A substantive verdict returns only "
            "with new qualifying evidence and a new approved basis."
        ),
    ),
    Scenario(
        "M-06",
        "train",
        "alternative_basis",
        "easy",
        "Charter §12 M-06",
        (
            "{c} has assurance=fail/current with two independently sufficient "
            "failure bases, {b1} using {e1} and {b2} using {e2}. Only {e1} "
            "depends on {dep}; {e2} is current and independent."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable).",
        "{e1} is invalidated and {b1} is removed; fail/current survives on {b2}.",
        "{e2} is unmatched and remains current.",
        "At least one current sufficient basis for the existing fail verdict survives.",
        "Alternative sufficient bases are disjunctive; one survivor is enough.",
        ("INV-11", "INV-14", "INV-16"),
        "Require both original failure bases to remain current or make the verdict stale.",
        "Alternative sufficient bases are disjunctive, not conjunctive.",
        "No restoration is needed for the verdict; optionally reassess the affected evidence path.",
    ),
    Scenario(
        "M-07",
        "train",
        "no_replacement_verdict",
        "hard",
        "Charter §12 M-07",
        (
            "{c} has assurance=pass/current on sole pass basis {b1}, which depends "
            "on {e1}. Unused surviving facts appear adverse but have not been "
            "assembled into an approved fail basis."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable) invalidates {e1}.",
        "{b1} is removed and the previous pass becomes stale; no fail verdict is selected.",
        "The only pass-supporting evidence is invalidated.",
        "No current basis supports the existing pass, and no approved basis supports fail.",
        "Invalidation tests support for the existing verdict; it does not perform a new assessment.",
        ("INV-09", "INV-12", "INV-13", "INV-15"),
        "Automatically replace pass with fail because the surviving facts look adverse.",
        "A different substantive verdict requires an explicit governed assessment and approved basis.",
        (
            "Assess the surviving facts explicitly and establish a new approved "
            "pass, partial, or fail basis as warranted."
        ),
    ),
    Scenario(
        "M-08",
        "train",
        "level_preserving_recovery",
        "medium",
        "Charter §12 M-08",
        (
            "{c} is sourceUnknown with assurance=stale. Earlier S1 and D evidence "
            "is invalidated. A new green S0 observation is available as {e2}."
        ),
        "RebaseS0 issues {e2} as current S0 evidence.",
        "Only S0 coverage becomes current; sourceState remains sourceUnknown and assurance remains stale.",
        "The new item covers S0 only; invalidated higher-dimensional items stay invalidated.",
        "No new S1, D, source, deployment, or verdict basis is established.",
        "Recovery is evidence-level preserving; a structural check cannot restore higher claims.",
        ("INV-17", "INV-18", "G-INV-10"),
        "Restore connected and pass because the structural predicate is green again.",
        "S0 cannot restore S1 or D knowledge or any claim dependent on them.",
        (
            "Issue qualifying evidence at each affected dimension, or an approved "
            "stronger dimension, and establish new approved bases."
        ),
    ),
    Scenario(
        "M-09",
        "train",
        "governed_source_restoration",
        "medium",
        "Charter §12 M-09",
        (
            "{c} is sourceUnknown after S1 evidence {e1} was invalidated. "
            "{e1} remains in history. Unused IDs {e2} and {b2} are available."
        ),
        (
            "ReassessState atomically issues new qualifying S1 evidence {e2}, "
            "creates approved source basis {b2}, and publishes the result."
        ),
        "sourceState becomes connected on {b2}; {e1} remains invalidated and is not reactivated.",
        "A new S1 identity is current; the old identity is retained unchanged in history.",
        "A new approved source basis supports connected.",
        "Restoration is a governed reassessment transition, not reversal of invalidation.",
        ("INV-05", "INV-18", "G-INV-09", "G-INV-10"),
        "Reactivate {e1} and reuse {b1} because the reassessment passed.",
        "Invalidated evidence and superseded bases are immutable historical records.",
        "The described atomic reassessment is sufficient; retain all superseded identities in history.",
    ),
    Scenario(
        "M-10",
        "train",
        "dependency_scoped_multi_control",
        "hard",
        "Charter §12 M-10 and README Layer 2",
        (
            "{c} has one fail basis {b1} on shared dependency {dep}. {c2} has a "
            "shared fail basis plus independent fail basis {b2} on {dep2}. {c3} "
            "is unrelated to {dep}."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable).",
        (
            "{c} becomes stale; {c2} remains fail/current on {b2}; {c3} remains "
            "substantively unchanged."
        ),
        "Only evidence declaring {dep} is invalidated across controls.",
        (
            "{c} loses every fail basis, {c2} retains an independent fail basis, "
            "and {c3} loses no basis."
        ),
        "Dependency precision and surviving-basis preservation are evaluated per control.",
        ("INV-11", "INV-14", "INV-15", "INV-16"),
        "Mark all three controls stale because they share one register event.",
        "Event scope does not replace the declared evidence-impact relation.",
        "Reassess {c} and the affected path of {c2}; do not mutate {c3}.",
    ),
    Scenario(
        "M-11",
        "train",
        "atomic_interleavings",
        "hard",
        "Charter §12 M-11 and README Layer 2",
        (
            "{c} is fail/current on evidence tied to {dep}. Both an atomic "
            "DependencyChange({dep}) and a qualifying atomic reassessment with "
            "new evidence and a new basis are enabled."
        ),
        "Consider both serializable action orders.",
        (
            "Each interleaving preserves the safety invariants; no externally "
            "visible state shows invalidated evidence supporting a current claim."
        ),
        "Each action publishes its evidence, basis references, state, and history atomically.",
        "Current claims after either action order have a current approved basis.",
        "Concurrency changes reachability order, not the atomic-support requirement.",
        ("INV-03", "INV-07", "INV-18", "INV-19", "INV-20"),
        "Expose fail/current briefly after its evidence is invalidated, then clean up the basis reference.",
        "That intermediate publication violates atomic invalidation.",
        "Serialize either atomic order and append a complete event for each committed action.",
    ),
    Scenario(
        "G-01",
        "train",
        "evidence_is_not_verdict",
        "easy",
        "README Layer 3B workflow 1",
        (
            "{c} is current and unverified. Current A evidence {e1} and current B "
            "evidence {e2} have been issued, but no verdict basis exists."
        ),
        "No assessment action has yet established a verdict basis.",
        "assurance remains unverified.",
        "Both evidence items are current and retained.",
        "There is no approved current verdict basis.",
        "Evidence issuance alone does not decide assurance.",
        ("INV-07", "G-INV-07", "A-07"),
        "Set assurance to pass because all required evidence items are present.",
        "Current evidence becomes a verdict only through an approved sufficient basis.",
        "Have an authorized I3 approver establish a complete approved verdict basis.",
    ),
    Scenario(
        "G-02",
        "train",
        "new_identity_restoration",
        "hard",
        "README Layer 3B workflow 2",
        (
            "{c} is stale. Prior evidence {e1} and basis {b1} are invalidated and "
            "retained in history. New IDs {e2} and {b2} are unused."
        ),
        (
            "An I3-approved reassessment atomically issues {e2}, creates {b2}, "
            "and appends an audit event."
        ),
        "A substantive current verdict may be restored on {b2}; {e1} and {b1} remain historical.",
        "Restoration uses a new immutable evidence identity.",
        "Restoration uses a new approved basis identity.",
        "Freshness restoration cannot rewrite or reactivate superseded records.",
        ("INV-18", "G-INV-06", "G-INV-08", "G-INV-09", "G-INV-10", "G-INV-11"),
        "Overwrite {e1} with the new result and mark {b1} current again.",
        "Issued evidence is immutable and invalidated identities never reactivate.",
        "Use the new identities and retain the old evidence, basis, and events append-only.",
    ),
    Scenario(
        "C-01",
        "train",
        "fresh_adverse_evidence",
        "medium",
        "Charter §7.2 and INV-21",
        (
            "{c} has newly issued evidence {e1} with status=currentEvidence and "
            "outcome=demonstratesFailure. The collection and validation process succeeded."
        ),
        "Aggregate coverage for {e1}'s dimension is derived.",
        "Coverage is coverageCurrent, and {e1} may support a current fail basis.",
        "The evidence is fresh and valid even though its substantive outcome is adverse.",
        "A fail verdict still requires an approved sufficient fail basis.",
        "Evidence freshness, evidence outcome, and collection failure are distinct concepts.",
        ("INV-07", "INV-21"),
        "Set coverage to failed because the evidence demonstrates that the control failed.",
        "Coverage failed is reserved for an unsuccessful evidence-production or validation attempt.",
        "Keep the evidence current; establish an approved fail basis if it is sufficient for a verdict.",
    ),
    Scenario(
        "M-12",
        "validation",
        "age_trigger_symmetry",
        "medium",
        "Charter §12 M-12",
        (
            "{c} is pass/current on {b1}. Member {e1} is current but its maximum "
            "age will be crossed. Independent evidence {e2} does not expire."
        ),
        "AdvanceClock crosses {e1}'s deadline without any predicate change.",
        (
            "{e1} expires and dependent bases are recomputed atomically; unmatched "
            "{e2} stays current. The existing verdict survives only if a same-verdict "
            "basis independent of {e1} remains."
        ),
        "Expiry affects the item whose age limit is crossed, not unrelated evidence.",
        "Basis survival is evaluated with the same rules used after dependency invalidation.",
        "A time trigger does not justify broader or weaker state-transition rules.",
        ("INV-11", "INV-14", "INV-15", "INV-20", "INV-21"),
        "Ignore the deadline because the monitored predicate did not change.",
        "Maximum-age expiry is itself a revocation trigger.",
        "Reassess only claims whose support was lost and use new evidence identities.",
    ),
    Scenario(
        "M-13",
        "validation",
        "non_current_obligation",
        "easy",
        "Charter §12 M-13",
        (
            "{c} has obligation=retired and assurance=assuranceNA. Historical "
            "evidence remains retained."
        ),
        "A dependency referenced by historical evidence changes.",
        "assurance remains assuranceNA; no substantive verdict is created.",
        "Historical status processing does not make the retired obligation current.",
        "No current verdict basis is introduced.",
        "Planned and retired obligations are not assessed.",
        ("INV-04", "INV-12"),
        "Set assurance to stale because old evidence was affected.",
        "Stale is a verdict-freshness result for a current obligation with a previously established verdict.",
        "Retain history and require a governed lifecycle action before any future assessment.",
    ),
    Scenario(
        "M-14",
        "validation",
        "profile_strengthening",
        "hard",
        "Charter §12 M-14 and README Layer 3B workflow 3",
        (
            "{c} is pass/current under required profile {{A}}. Approved basis {b1} "
            "contains current A evidence {e1}; no current B evidence is in {b1}."
        ),
        "An authorized ChangeRequiredProfile strengthens the contract to {{A,B}}.",
        "The old basis cannot satisfy the new pass contract; assurance becomes stale pending reassessment.",
        "The existing A evidence remains immutable; missing B support is not fabricated.",
        "The prior pass basis is incomplete under the new required profile.",
        "A profile change is prospective and cannot retroactively make an incomplete basis complete.",
        ("INV-08", "INV-09", "G-INV-12", "G-INV-14"),
        "Keep pass/current because {b1} was valid when it was approved.",
        "Current pass must satisfy the current required profile, not only the historical one.",
        "Issue qualifying B evidence and establish a new complete approved pass basis.",
    ),
    Scenario(
        "G-04",
        "validation",
        "governed_retirement",
        "medium",
        "README Layer 3B workflow 4",
        (
            "{c} is a current obligation with a substantive verdict and append-only "
            "evidence and basis history."
        ),
        "An I3-authorized retirement issues a new retirement evidence item and commits atomically.",
        (
            "obligation becomes retired, assurance becomes assuranceNA, current "
            "verdict references are cleared, and history is retained."
        ),
        "Retirement adds a new evidence record; it does not delete earlier evidence.",
        "Current verdict references are cleared because the obligation is no longer current.",
        "Lifecycle retirement is a protected, auditable transition.",
        ("INV-04", "INV-19", "G-INV-11", "G-INV-12", "G-INV-13"),
        "Delete all prior evidence and bases when retiring the control.",
        "Retirement changes the current view but does not erase append-only history.",
        "No further action is needed unless the obligation is later reintroduced through a governed lifecycle process.",
    ),
    Scenario(
        "M-15",
        "test",
        "assumption_boundary",
        "expert",
        "Charter §12 M-15 and Layer 3A results",
        (
            "{c} is pass/current on alternative basis {b2} using {e2}. The declared "
            "dependency relation says {e2} is independent of {dep}, but the external "
            "RealDependencies oracle says {e2} actually depends on {dep}."
        ),
        "DependencyChange({dep}, apparentlyUnfavourable) is processed using only the declared relation.",
        (
            "Internally, {e2}, {b2}, and pass/current survive; relative to the real "
            "dependency oracle, the retained verdict is unsound."
        ),
        "Declared-impact precision passes, but REAL-01 fails because affected real evidence remains current.",
        "A declared-current basis survives, but REAL-02 fails because no real surviving basis exists.",
        "Internal consistency is conditional on A-04 and cannot prove impact completeness from the declared graph itself.",
        ("A-04", "INV-11", "REAL-01", "REAL-02"),
        "Report the passing internal invariants as proof that the real dependency graph is complete.",
        "Using the declared graph as its own completeness oracle is circular.",
        (
            "Validate A-04 with an independent source of dependency truth, such as "
            "independent discovery, mutation tests, observed-event coverage, or authority-separated review."
        ),
    ),
    Scenario(
        "L-01",
        "test",
        "conditional_liveness",
        "expert",
        "Charter LIVE-01 and README temporal structure",
        (
            "{c} has a qualifying stale reassessment request that remains pending "
            "and continuously enabled. CompleteReassessment is weakly fair."
        ),
        "The system may execute heartbeat actions while the request remains pending.",
        (
            "Eventually the request must produce either a new current approved "
            "basis with a substantive verdict or an explicit failed-reassessment "
            "event that retains stale."
        ),
        "Heartbeat does not itself supply evidence or complete the request.",
        "Success requires a new basis; failure is explicit and preserves stale.",
        "The liveness claim is conditional on continuous enablement and weak fairness.",
        ("LIVE-01", "INV-07", "INV-18", "INV-19"),
        "Weak fairness guarantees a successful pass verdict.",
        "Fairness guarantees completion, not success or a specific substantive verdict.",
        "Implement an explicit success-or-failure completion action and preserve the fairness assumptions in the claim.",
    ),
    Scenario(
        "H-01",
        "test",
        "append_only_history",
        "medium",
        "Charter INV-19 and counterexample policy",
        (
            "{c} has history [issue({e1}), establish({b1}), invalidate({e1})]. A "
            "reassessment now produces {e2} and {b2}."
        ),
        "A proposed implementation replaces the history with [issue({e2}), establish({b2})].",
        "Reject the transition; the old history must remain a prefix and the new reassessment event must be appended.",
        "Old evidence and basis identities remain retained.",
        "New current references may point to {e2} and {b2}, but history cannot be overwritten.",
        "Restoration creates new records while preserving the causal audit trail.",
        ("INV-18", "INV-19", "G-INV-06", "G-INV-11"),
        "Accept the shorter history because only current evidence matters for inference.",
        "CSD requires append-only history for auditability and forbids silent identity replacement.",
        "Publish a corrected transition that appends the complete reassessment event to the existing history.",
    ),
)


TASK_TYPES = ("transition", "critique", "counterfactual", "audit")


def render(value: str, variant: dict[str, str]) -> str:
    return value.format(**variant)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def response_for(scenario: Scenario, variant: dict[str, str]) -> str:
    rules = ", ".join(scenario.rules)
    return "\n".join(
        (
            f"Decision: {render(scenario.decision, variant)}",
            f"Evidence impact: {render(scenario.evidence_impact, variant)}",
            f"Basis result: {render(scenario.basis_result, variant)}",
            f"Justification: {render(scenario.justification, variant)}",
            f"Rejected inference: {render(scenario.rejected_answer, variant)}",
            f"Rules: {rules}.",
            f"Next governed step: {render(scenario.next_step, variant)}",
        )
    )


def task_prompt(scenario: Scenario, variant: dict[str, str], task_type: str) -> str:
    header = (
        f"Context: {variant['surface']}.\n"
        f"Initial snapshot: {render(scenario.snapshot, variant)}\n"
        f"Event: {render(scenario.event, variant)}\n"
    )
    if task_type == "transition":
        question = (
            "Determine the correct post-event evidence status, surviving basis "
            "status, and control state or verdict."
        )
    elif task_type == "critique":
        question = (
            f'A reviewer proposes: "{render(scenario.rejected_answer, variant)}" '
            "Identify the error and give the corrected decision."
        )
    elif task_type == "counterfactual":
        question = (
            "What governed action or missing condition is required before a "
            "different current substantive conclusion may be published?"
        )
    elif task_type == "audit":
        question = (
            "Produce an audit-ready decision trace covering evidence impact, "
            "basis survival, prohibited inference, applicable rules, and next step."
        )
    else:
        raise ValueError(f"unknown task type: {task_type}")
    return header + "Question: " + question


def task_response(scenario: Scenario, variant: dict[str, str], task_type: str) -> str:
    full = response_for(scenario, variant)
    if task_type == "transition":
        return full
    if task_type == "critique":
        return f"Finding: Incorrect.\nError: {render(scenario.rejected_reason, variant)}\n" + full
    if task_type == "counterfactual":
        return "\n".join(
            (
                f"Required action: {render(scenario.next_step, variant)}",
                f"Current decision: {render(scenario.decision, variant)}",
                f"Why: {render(scenario.justification, variant)}",
                f"Rules: {', '.join(scenario.rules)}.",
            )
        )
    if task_type == "audit":
        return f"Source scenario: {scenario.scenario_id}.\n" + full
    raise ValueError(f"unknown task type: {task_type}")


def expected_object(scenario: Scenario, variant: dict[str, str]) -> dict[str, object]:
    return {
        "decision": render(scenario.decision, variant),
        "evidence_impact": render(scenario.evidence_impact, variant),
        "basis_result": render(scenario.basis_result, variant),
        "justification": render(scenario.justification, variant),
        "rejected_inference": render(scenario.rejected_answer, variant),
        "rejected_reason": render(scenario.rejected_reason, variant),
        "next_governed_step": render(scenario.next_step, variant),
        "rule_ids": list(scenario.rules),
    }


def sft_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        for variant in VARIANTS:
            for task_type in TASK_TYPES:
                example_id = (
                    f"csd-r-{DATASET_VERSION}-{scenario.scenario_id.lower()}-"
                    f"{variant['variant']}-{task_type}"
                )
                prompt = task_prompt(scenario, variant, task_type)
                response = task_response(scenario, variant, task_type)
                records.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "dataset_version": DATASET_VERSION,
                        "id": example_id,
                        "split": scenario.split,
                        "synthetic": True,
                        "task_type": task_type,
                        "scenario_family": scenario.family,
                        "source_scenario": scenario.scenario_id,
                        "difficulty": scenario.difficulty,
                        "surface": variant["surface"],
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                            {"role": "assistant", "content": response},
                        ],
                        "expected": expected_object(scenario, variant),
                        "provenance": {
                            "generation_method": "deterministic_template",
                            "provider_calls": 0,
                            "source_section": scenario.source_section,
                            "source_baselines": SOURCE_BASELINES,
                        },
                    }
                )
    return records


def preference_records() -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        for variant in VARIANTS:
            prompt = task_prompt(scenario, variant, "transition")
            chosen = response_for(scenario, variant)
            rejected = "\n".join(
                (
                    f"Decision: {render(scenario.rejected_answer, variant)}",
                    (
                        "Justification: The apparent event direction or the "
                        "presence of surviving facts is enough to select the result."
                    ),
                )
            )
            records.append(
                {
                    "schema_version": "csd-reasoning-preference/0.1",
                    "dataset_version": DATASET_VERSION,
                    "id": (
                        f"csd-rp-{DATASET_VERSION}-{scenario.scenario_id.lower()}-"
                        f"{variant['variant']}"
                    ),
                    "split": scenario.split,
                    "synthetic": True,
                    "scenario_family": scenario.family,
                    "source_scenario": scenario.scenario_id,
                    "surface": variant["surface"],
                    "prompt_messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "chosen": chosen,
                    "rejected": rejected,
                    "preference_basis": {
                        "rule_ids": list(scenario.rules),
                        "rejected_reason": render(scenario.rejected_reason, variant),
                    },
                    "provenance": {
                        "generation_method": "deterministic_contrastive_template",
                        "provider_calls": 0,
                        "source_section": scenario.source_section,
                        "source_baselines": SOURCE_BASELINES,
                    },
                }
            )
    return records


def validate_sft(records: list[dict[str, object]]) -> None:
    expected_count = len(SCENARIOS) * len(VARIANTS) * len(TASK_TYPES)
    if len(records) != expected_count:
        raise ValueError(f"expected {expected_count} SFT records, got {len(records)}")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate SFT ids")
    splits_by_scenario: dict[str, set[str]] = {}
    for record in records:
        split = str(record["split"])
        if split not in {"train", "validation", "test"}:
            raise ValueError(f"invalid split: {split}")
        scenario = str(record["source_scenario"])
        splits_by_scenario.setdefault(scenario, set()).add(split)
        messages = record["messages"]
        if not isinstance(messages, list) or [m["role"] for m in messages] != [
            "system",
            "user",
            "assistant",
        ]:
            raise ValueError(f"invalid messages in {record['id']}")
        expected = record["expected"]
        if not isinstance(expected, dict):
            raise ValueError(f"invalid expected object in {record['id']}")
        unknown_rules = set(expected["rule_ids"]) - VALID_RULES
        if unknown_rules:
            raise ValueError(f"unknown rules in {record['id']}: {sorted(unknown_rules)}")
    leaking = {key: value for key, value in splits_by_scenario.items() if len(value) != 1}
    if leaking:
        raise ValueError(f"scenario-family leakage across splits: {leaking}")


def validate_preferences(records: list[dict[str, object]]) -> None:
    expected_count = len(SCENARIOS) * len(VARIANTS)
    if len(records) != expected_count:
        raise ValueError(f"expected {expected_count} preference records, got {len(records)}")
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate preference ids")
    for record in records:
        if record["chosen"] == record["rejected"]:
            raise ValueError(f"identical chosen and rejected answers in {record['id']}")


def write_jsonl(path: Path, records: Iterable[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(canonical_json(record) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_counts(records: Iterable[dict[str, object]]) -> dict[str, int]:
    counts = {"train": 0, "validation": 0, "test": 0}
    for record in records:
        counts[str(record["split"])] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory for generated JSONL and manifest files.",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    sft = sft_records()
    preferences = preference_records()
    validate_sft(sft)
    validate_preferences(preferences)

    sft_path = args.output_dir / "csd_reasoning_sft_v0.1.jsonl"
    preference_path = args.output_dir / "csd_reasoning_preference_v0.1.jsonl"
    manifest_path = args.output_dir / "csd_reasoning_manifest_v0.1.json"
    write_jsonl(sft_path, sft)
    write_jsonl(preference_path, preferences)

    scenario_snapshot = [
        {
            "scenario_id": scenario.scenario_id,
            "split": scenario.split,
            "family": scenario.family,
            "rules": list(scenario.rules),
            "source_section": scenario.source_section,
        }
        for scenario in SCENARIOS
    ]
    manifest = {
        "dataset": "CSD Reasoning Seed",
        "dataset_version": DATASET_VERSION,
        "status": "synthetic_seed_unbenchmarked",
        "generated_by": Path(__file__).name,
        "generation_method": "deterministic_templates",
        "provider_calls": 0,
        "source_baselines": SOURCE_BASELINES,
        "scenario_count": len(SCENARIOS),
        "surface_variant_count": len(VARIANTS),
        "task_types": list(TASK_TYPES),
        "split_policy": "source_scenario_family_exclusive",
        "sft": {
            "file": sft_path.name,
            "records": len(sft),
            "split_counts": split_counts(sft),
            "sha256": sha256_file(sft_path),
        },
        "preference": {
            "file": preference_path.name,
            "records": len(preferences),
            "split_counts": split_counts(preferences),
            "sha256": sha256_file(preference_path),
        },
        "scenarios": scenario_snapshot,
        "claim_boundary": (
            "Passing deterministic validation establishes schema and declared-rule "
            "consistency only. It does not establish pedagogical effectiveness, "
            "general reasoning transfer, or absence of specification-level errors."
        ),
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "sft_records": len(sft),
                "preference_records": len(preferences),
                "sft_sha256": manifest["sft"]["sha256"],
                "preference_sha256": manifest["preference"]["sha256"],
                "manifest": str(manifest_path),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
