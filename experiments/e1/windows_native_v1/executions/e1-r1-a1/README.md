# E1 Execution Result — `e1-r1-a1`

## Terminal Classification: `NO_OBSERVED_SIGNAL`

E1 is a bounded engineering experiment measuring directional learning value of
executable-semantics curriculum over a task-matched conventional control.

The result is **NO_OBSERVED_SIGNAL**: no arm acquired the response task, no
relative safety regression was observed under the frozen safety metric, and no
directional Foundry improvement was detected.

**G1 — Learning Signal: NOT PASSED.**

## Evidence tuple

```text
source_commit                          cab05f576040ad7f8b7ba395db86e14181bc3c44
sealed_execution_receipt_sha256        7f2e7f6819283468408b4f1b90a8a83b57a4ec46f30f08854cd6e6845c6b8db1
sealed_prediction_manifest_sha256      e87267c346ab068a8eac7a3be0f8fe2acd32a46a4ec25f5ed205b3733121619c
metric_release_receipt_sha256          2b7d1b4ca04eca7f8bacee37995af3635e0b99053ca986537b37b1f3857eb03a
```

## Primary metric

```
structural-holdout-exact-semantic-decision-accuracy/family-macro/1

P_base    = 0.0
P_control = 0.0
P_foundry = 0.0
```

No arm acquired the response task. All predictions were malformed under the
A0b2 ABI (token ID 5087 → " factors").

## Safety metric

```
clean-case-regression/base-and-control/1

safety_nonregression = true
```

No relative safety regression. All three arms failed all four clean cases with
malformed output (clean_malformed_count = 4 for each arm).

## Classification logic

```
safety_nonregression = true
P_foundry NOT > P_control (0.0 = 0.0)
P_foundry NOT > P_base (0.0 = 0.0)
→ NO_OBSERVED_SIGNAL
```

## Execution ledger

| Attempt | Source | Result | Classification |
|---|---|---|---|
| E1-original-A1 | `afbd4086` (frozen) | SEALED_EXECUTION_FAILED | INFRASTRUCTURE_INVALID |
| E1-original-A2 | `afbd4086` + uncommitted | SEALED_EXECUTION_PASSED | UNAUTHORIZED_SOURCE |
| E1-R1-A1 | `cab05f5` (corrected) | SEALED_EXECUTION_PASSED | VALID_RECOVERY |

Original E1 terminal status: TECHNICALLY_INVALID. Original prediction manifest
`e87267c3…` permanently non-scorable.

## Claim boundary

This does not establish that executable-semantics curriculum lacks value at
larger scale. It establishes that this exact model × recipe × budget did not
reach a learnability floor sufficient to test curriculum separation. This
experiment does not measure reasoning improvement, curriculum efficacy,
transfer, statistical power, or scale readiness.
