from csd_foundry.fixtures.v0_1.scenarios import m01, m06, m09
from csd_foundry.kernel.models import Assurance, EvidenceStatus, SourceState
from csd_foundry.kernel.oracle import CsdOracle


def test_m01_revocation_demotes_without_promotion() -> None:
    state, event = m01()
    result = CsdOracle().apply(state, event)
    assert result.after.source_state is SourceState.UNKNOWN
    assert result.after.current_source_basis_ids == frozenset()
    assert result.after.evidence_by_id()["EV-N17-001"].status is EvidenceStatus.INVALIDATED
    assert result.trace.resulting_source_state == "sourceUnknown"


def test_m06_independent_basis_preserves_fail() -> None:
    state, event = m06()
    result = CsdOracle().apply(state, event)
    assert result.after.assurance is Assurance.FAIL
    assert result.after.current_verdict_basis_ids == frozenset({"BASIS-N17-02"})
    assert result.trace.removed_bases == ("BASIS-N17-01",)


def test_m09_restoration_uses_new_identity_and_preserves_history() -> None:
    state, event = m09()
    result = CsdOracle().apply(state, event)
    assert result.after.source_state is SourceState.CONNECTED
    assert result.after.evidence_by_id()["EV-N17-001"].status is EvidenceStatus.INVALIDATED
    assert result.after.evidence_by_id()["EV-N17-002"].status is EvidenceStatus.CURRENT
    assert result.after.history[: len(state.history)] == state.history
