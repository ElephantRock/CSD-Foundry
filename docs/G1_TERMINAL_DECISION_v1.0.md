# G1 Terminal Decision — Learning Signal Gate

**Status:** Terminal / Superseded only by a new roadmap revision  
**Version:** 1.0  
**Date:** 2026-08-08  
**Repository authority:** containing merged commit  
**Governing roadmap:** `docs/STRATEGIC_ROADMAP.md`  
**Governing charter:** `docs/FOUNDRY_PLATFORM_CHARTER_v1.1.md`

## Decision

**G1 — Learning Signal: NOT PASSED.** The learning-signal hypothesis is
closed. The G1 empirical sequence (E1 → LF → E2 → E3) is evidentially closed
by this decision and its accompanying receipts.

This record supersedes the embedded `g1_status` field in the E1 execution
receipt in *scope* (it records the full E1–E3 progression, not E1 alone); it
does not edit the E1 receipt.

## Evidence progression

```text
E1
  Recipe did not acquire the task (tiny-gpt2, 8 steps); no arm produced
  valid A-E codewords.
  -> NO_OBSERVED_SIGNAL

LF
  Intermediate calibration identified response-token-only supervision as
  the viable recipe. No standalone LF receipt was preserved; the recipe
  consequence is frozen in the E2 and E3 experiment definitions
  (training_recipe.loss = "response-token-only (all prompt tokens masked
  to -100)").

E2
  Both trained arms acquired the task under the response-only recipe.
  Primary: CONTROL = 0.40, FOUNDRY = 0.60 (positive Foundry differential).
  Safety: failed (all three arms 10/10 clean exact errors).
  Terminal: HARMFUL.
  The E2 classifier implementation diverged from the contract's relative
  safety formulation (as-executed absolute rule vs. contract relative
  rule), but the terminal HARMFUL result is invariant — both formulations
  fail on the recorded evidence.

E3
  Equal clean anchors (5 NEITHER + 5 SURVIVES_ONLY, added identically to
  both arms) repaired the shared safety regression.
  Primary: CONTROL = 0.60, FOUNDRY = 0.55.
  Safety: passed (relative five-count non-regression holds; Foundry 0
  clean errors; <= Base 10 and <= Control 0 on all 5 counts).
  Terminal: HARMFUL via primary accuracy alone.

G1
  NOT PASSED.
```

Durable receipts: `experiments/e2/executions/e2-foundry-vs-control/` and
`experiments/e3/executions/e3-safety-anchored/`. E1's receipt is at
`experiments/e1/windows_native_v1/executions/e1-r1-a1/`.

## What this establishes

Three conclusions are supported by the durable evidence.

**1. Learnability is not the current blocking failure mode.**

E1 could not test curriculum separation because no arm acquired the response
task. After response-token-only supervision was identified, both trained arms
in E2 and E3 generated valid A–E responses and achieved substantial exact
accuracy on the 20-family primary evaluation. The durable inference is that
task acquisition ceased to be the blocker under the response-only recipe.

This is stated as an inference supported by the E2/E3 receipts themselves, not
as the missing standalone LF receipt. No standalone LF receipt was preserved;
its only durable footprint is the frozen `response-token-only` loss recipe in
the E2/E3 experiment definitions.

**2. The E2 safety failure was repairable.**

Equal NEITHER/SURVIVES_ONLY anchors eliminated the clean-case regression in
both trained arms in E3 (0/10 clean errors each, vs. E2's 10/10). The shared
E2 safety regression was repairable by equal clean anchoring; E2–E3 do not
independently isolate whether the underlying mechanism was coverage, transfer,
or another training-distribution effect.

**3. No demonstrated Foundry advantage.**

E2 contained a positive Foundry primary differential (0.60 > 0.40), but it was
non-ratifiable because safety failed. After the precommitted equal safety
correction in E3, safety passed and the differential did not survive
(0.55 < 0.60). There is no reproducible evidence that executable-semantic
label authority provides a directional learning advantage under this bounded
setup.

## What this does NOT establish

- It does **not** mathematically prove that E2's +0.20 differential was a
  regression-related artifact. That interpretation is plausible and the best
  working explanation, but E3 establishes only the narrower fact: *the E2
  Foundry advantage was not robust to the precommitted safety correction.*
- It does **not** generalize the one-family E3 primary gap (11 vs 12 of 20)
  into a claim that executable semantics are intrinsically harmful. That gap
  sits at the granularity floor of 4-cases-per-class.
- It does **not** invalidate the CSD Foundry architecture as a whole. What
  failed is the narrower proposition tested by G1: under the current small
  paired-SFT formulation, replacing conventional synthetic label authority
  with executable-semantic label authority has not demonstrated a robust
  incremental learning benefit.

## Scope of closure

The G1 training sequence is stopped and the current learning-signal hypothesis
is closed. The following are explicitly prohibited as responses to this
non-pass:

- running E4;
- adding more anchors;
- rebalancing classes;
- changing representation;
- increasing model size;
- tuning learning rate or steps;
- weakening the G1 criterion;
- reinterpreting E3 as `NO_OBSERVED_SIGNAL`.

These would constitute a new empirical program after the current gate failed,
and require explicit authorization as such.

## Architecture status

This decision does not invalidate the parts of CSD Foundry that E1–E3 did not
test. The executable kernel retains independent value for deterministic label
generation, verification, adversarial evaluation, provenance, runtime
governance, and proof-carrying data. None of those properties were contingent
on E1–E3 producing a positive supervised-fine-tuning delta.

## Roadmap disposition

The empirical lane is closed by this decision. The roadmap-level question of
how to proceed is a separate governance decision, not enacted by this record:

```text
Option A — preserve the current roadmap:
    G1 failed
    -> stop before G2

Option B — explicitly revise the roadmap:
    separate "executable governance / verified-data infrastructure"
    from "demonstrated model-learning advantage"
    -> define a new hypothesis and new gate before further training work
```

A recommendation toward Option B is recorded but **not** enacted here. The
empirical lane remains closed until that roadmap-level decision is made.
