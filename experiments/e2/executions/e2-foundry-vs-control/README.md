# E2 Execution Result — `e2-foundry-vs-control`

## Terminal Classification: `HARMFUL`

E2 is a bounded Foundry-vs-control experiment measuring directional learning
value of executable-semantics curriculum over a task-matched conventional
control on GPT-2 (124M) at 128 steps with response-token-only loss.

The result is **HARMFUL**: both trained arms acquired the response task and
Foundry showed a positive primary differential, but both trained arms failed
the clean-case safety metric, so the Foundry differential is non-ratifiable.

**G1 — Learning Signal: NOT PASSED.**

## Execution provenance

E2 executed from an uncommitted worktree based on
`ca129c43fb2d0c81f14f8b387bd0b1eb01d1dabd` (`Record E1 execution result`, PR
#98). The experiment-defining files were promoted to durable git evidence in a
subsequent commit on this branch. That promotion does **not** retroactively
make its merge commit the source commit of the historical GPU execution.

The historical execution bytes (Windows worktree, CRLF line endings) are not
the bytes now committed. `.gitattributes` enforces LF on commit, so the
committed blobs are LF-normalized; three Python files
(`_arm_worker.py`, and the E3 analogues) were additionally ruff-formatted /
lint-fixed during promotion to satisfy the repository gates that all existing
tracked experiment source already satisfies. The receipts therefore use a
two-identity model per file (`per_file_provenance` in `execution_receipt.json`):

```text
A — frozen historical digest (contract): historical identity known via the
    contract digest, which equals SHA256(CRLF reconstruction of the LF blob).
    Asserted at build time (fail closed). Exact bytes not preserved.
B — unchanged single-line artifact: zero transforming newlines, so the
    committed LF blob IS the execution bytes.
C — normalized multi-line output without prior digest: exact bytes not
    preserved; semantic content preserved modulo line endings.
D — normalized/formatted Python source: pre-format LF content digest captured
    as a static value; promoted copy is a post-hoc normalized repository copy,
    not the historical execution identity.
```

## Evidence

```text
publication_channel              git_repository
results_json_repository_sha256   f10dc42c0f6a7fead548bc0e444e0ed304366437d32dbd876577e65c02a556bf
```

The full evidence set (source, inputs, outputs) is tracked under
`experiments/e2/`. Per-file provenance (historical and repository identities,
category, transformation) is recorded in `execution_receipt.json`
(`durable_evidence.per_file_provenance`).

## Primary metric

```
e2-primary-family-macro-accuracy/1

P_base    = 0.0
P_control = 0.4
P_foundry = 0.6
```

Both trained arms acquired the response task (unlike E1, where no arm did).
Foundry shows a positive primary differential over Control. This differential
is non-ratifiable for G1 because of the safety failure below.

## Safety metric

```
e2-clean-case-regression/1

                              BASE   CONTROL   FOUNDRY
clean_exact_error_count         10        10        10
spurious_basis_removal_count     0         5         5
valid_basis_rejection_count      0         5         5
clean_not_applicable_count       0         5         5
clean_malformed_count           10         0         0
```

All three arms produced 10/10 clean-case exact errors. BASE produced 10/10
malformed outputs; both trained arms produced zero malformed but systematically
wrong codewords on the 10 clean cases. The safety failure is shared, not
Foundry-specific — Foundry equals Control on every safety count.

## Classification logic

E2's classification truth table prose (contract) describes a *relative*
five-count non-regression rule. The as-executed code
(`run_e2_experiment.py` `_classify`) implemented an *absolute* rule
(`FOUNDRY.clean_exact_error_count == 0`). This divergence is recorded as an
execution defect.

The divergence is **not material to the terminal classification** — the
recorded evidence fails both formulations:

```
Rule A (absolute, as-executed):
    safety_passes = (FOUNDRY.clean_exact_error_count == 0)
    -> safety fails (clean_exact_error_count = 10 != 0)
    -> HARMFUL via safety

Rule B (relative, contract prose):
    safety_passes = for all 5 counts: Foundry <= Base AND Foundry <= Control
    -> safety fails (Foundry > Base on spurious_basis_removal,
       valid_basis_rejection, clean_not_applicable; 5 > 0 each;
       Foundry == Control on every count, so the failure is purely
       Foundry-vs-Base)
    -> HARMFUL via safety

terminal_invariant_to_divergence = true
divergence_material_to_terminal  = false
```

No GPU rerun and no metric recomputation are warranted by this divergence.

## Claim boundary

E2 does not establish that executable-semantics curriculum lacks value at
larger scale. It establishes that, under this exact model × recipe × budget,
the Foundry primary advantage was observed but could not be ratified because
both trained arms violated the clean-case safety metric. This experiment does
not measure reasoning improvement, transfer, statistical power, or scale
readiness.
