from csd_foundry.kernel.oracle import CsdOracle
from csd_foundry.synthesis.kill_matrix import evaluate
from csd_foundry.synthesis.mutations import (
    overwrite_history,
    promote_after_revocation,
    reactivate_evidence,
    retain_invalid_basis,
)
from fixtures.v0_1.scenarios import m01


def test_initial_mutation_families_are_killed() -> None:
    before, event = m01()
    valid_after = CsdOracle().apply(before, event).after
    mutations = (
        retain_invalid_basis("mut-001", before, valid_after),
        promote_after_revocation("mut-002", valid_after),
        reactivate_evidence("mut-003", valid_after),
        overwrite_history("mut-004", valid_after),
    )
    results = [evaluate(valid_after, mutation) for mutation in mutations]
    assert all(result.killed for result in results)
