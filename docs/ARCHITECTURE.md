# Architecture

## Trust boundary

Natural-language templates are renderers, not semantic authorities. Canonical labels come
from executable transitions. A separate invariant layer evaluates the resulting state and
transition; it must not simply ask the transition function whether it was correct.

## Kernel contract

```python
result = CsdOracle().apply(pre_state, event)
```

The result contains immutable `before`, `after`, and a public `TransitionTrace`. The oracle
fails closed on invalid pre-states and invalid post-states.

## Mutation contract

Each mutation records:

- a stable mutation ID;
- one mutation operator;
- the expected invariant family;
- the mutated state.

The kill matrix reports whether at least one expected invariant detected the mutation. The
long-term release gate is high mutation kill coverage with zero false rejection of canonical
states.
