# E3 Execution Result — `e3-safety-anchored`

## Terminal Classification: `HARMFUL`

E3 is the safety-anchored replication of E2: the same GPT-2 (124M) × 128-step
× response-token-only recipe, with 10 shared clean anchors (5 NEITHER + 5
SURVIVES_ONLY) added identically to both trained arms so the only differential
variable remains the v6 curriculum.

The result is **HARMFUL**: the shared safety anchors repaired the E2 clean-case
regression (both trained arms now pass all 10 clean cases), but under equal
safety anchoring the E2 Foundry primary differential did not survive
(P_foundry < P_control).

**G1 — Learning Signal: NOT PASSED.**

## Execution provenance

E3 executed from an uncommitted worktree based on
`ca129c43fb2d0c81f14f8b387bd0b1eb01d1dabd` (`Record E1 execution result`, PR
#98). The experiment-defining files were promoted to durable git evidence in a
subsequent commit on this branch. That promotion does **not** retroactively
make its merge commit the source commit of the historical GPU execution.

The historical execution bytes (Windows worktree, CRLF line endings) are not
the bytes now committed. `.gitattributes` enforces LF on commit, so the
committed blobs are LF-normalized; two E3 Python files (`build_e3_data.py`,
`run_e3_experiment.py`) were additionally ruff-formatted / lint-fixed during
promotion to satisfy the repository gates that all existing tracked experiment
source already satisfies. The receipts use a two-identity model per file
(`per_file_provenance` in `execution_receipt.json`): Category A files
(protected primary/clean, clean anchors) have a frozen historical digest that
equals SHA256(CRLF reconstruction of the LF blob), asserted at build time;
Category C multi-line outputs preserve semantic content modulo line endings;
Category D Python source records a static pre-format LF content digest and is
a post-hoc normalized repository copy, not the historical execution identity.

## Evidence

```text
publication_channel              git_repository
results_json_repository_sha256   70bab740ace7e61761203273464086d6b080a8767a1821f587a97562b3c85c3c
```

The full evidence set (source, inputs, outputs) is tracked under
`experiments/e3/`. Per-file provenance (historical and repository identities,
category, transformation) is recorded in `execution_receipt.json`
(`durable_evidence.per_file_provenance`).

## Primary metric

```
e3-primary-family-macro-accuracy/1

P_base    = 0.0
P_control = 0.6
P_foundry = 0.55
```

The E2 Foundry primary differential (0.60 > 0.40) inverted to a Foundry deficit
(0.55 < 0.60) after both arms received identical safety anchoring.

## Safety metric

```
e3-clean-case-regression/1  (relative five-count non-regression)

                              BASE   CONTROL   FOUNDRY
clean_exact_error_count         10         0         0
spurious_basis_removal_count     0         0         0
valid_basis_rejection_count      0         0         0
clean_not_applicable_count       0         0         0
clean_malformed_count           10         0         0

safety_nonregression_holds = true
```

Safety non-regression **HOLDS**: for all 5 counts, Foundry ≤ Base AND
Foundry ≤ Control. Both trained arms produced 0 clean errors and 0 malformed
outputs on the 10 clean cases. BASE remains the correct unanchored comparator
(10/10 clean errors, 10/10 malformed). The E2 shared safety regression is
eliminated.

## Classification logic

E3's contract and code agree (no divergence). The relative five-count
non-regression rule is implemented exactly in `run_e3_experiment.py`
(`_safety_nonregression`, lines 631-653; `_classify`, lines 656-684).

```
safety_nonregression_passes = true
P_foundry (0.55) < P_control (0.60)
-> HARMFUL via primary accuracy ALONE
```

The HARMFUL classification is **not** attributable to a safety failure: safety
passed on all 5 counts. It is attributable solely to the primary-accuracy
comparison.

## Claim boundary

E3 does not establish that executable-semantics curriculum is intrinsically
harmful, and the one-family primary gap (11 vs 12 of 20) sits at the granularity
floor of 4-cases-per-class. What E3 establishes is narrower and sufficient for
governance: the E2 Foundry primary advantage was not robust to the
precommitted equal safety correction. This experiment does not measure
reasoning improvement, transfer, statistical power, or scale readiness.
