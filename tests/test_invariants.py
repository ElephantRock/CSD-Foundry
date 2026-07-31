from dataclasses import replace

from csd_foundry.fixtures.v0_1.scenarios import m01, m09
from csd_foundry.kernel.invariants import validate_state, validate_transition
from csd_foundry.kernel.models import Assurance, EvidenceStatus, SourceState
from csd_foundry.kernel.oracle import CsdOracle


def test_current_basis_cannot_reference_invalidated_evidence() -> None:
    state, event = m01()
    valid = CsdOracle().apply(state, event).after
    invalid = replace(valid, current_source_basis_ids=state.current_source_basis_ids)
    assert "INV-13" in {violation.invariant_id for violation in validate_state(invalid)}


def test_substantive_claim_requires_current_basis() -> None:
    state, event = m01()
    valid = CsdOracle().apply(state, event).after
    invalid = replace(valid, source_state=SourceState.CONNECTED, assurance=Assurance.PASS)
    observed = {violation.invariant_id for violation in validate_state(invalid)}
    assert {"INV-05", "INV-07"} <= observed


def test_reactivation_is_rejected() -> None:
    before, event = m01()
    after = CsdOracle().apply(before, event).after
    evidence = tuple(
        replace(item, status=EvidenceStatus.CURRENT) if item.evidence_id == "EV-N17-001" else item
        for item in after.evidence
    )
    invalid = replace(after, evidence=evidence)
    assert "INV-18" in {violation.invariant_id for violation in validate_transition(after, invalid)}


def test_history_must_be_append_only() -> None:
    before, event = m09()
    after = CsdOracle().apply(before, event).after
    invalid = replace(after, history=after.history[-1:])
    assert "INV-19" in {
        violation.invariant_id for violation in validate_transition(before, invalid)
    }
