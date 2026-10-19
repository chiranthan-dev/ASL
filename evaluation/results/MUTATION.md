# Tool-identity mutation

Generated 2026-10-07T23:39:00 · seed 20260909 · reproducible with
`python -m evaluation.mutation`.

110 harmful scenarios, materialised into concrete tool calls and
re-issued under different tool names with byte-identical arguments. Behaviour is
unchanged by construction; only the label on the wrapper moves.

## Detection under renaming

| strategy | static rules | ASL | static Δ | ASL Δ |
|---|---|---|---|---|
| identity | 0.836 | 0.909 | — | — |
| rename | 0.282 | 0.973 | -0.555 | +0.064 |
| namespace | 0.282 | 0.973 | -0.555 | +0.064 |
| opaque | 0.282 | 0.927 | -0.555 | +0.018 |
| disguise | 0.282 | 0.927 | -0.555 | +0.018 |

## Fingerprint continuity

Fraction of scenarios whose *per-call behavioural fingerprint is byte-identical*
to the unmutated original. This is the mechanism's claim stated as a measurement:
authorization memory should survive a rename because the tool's name is not in the key.

| strategy | fingerprint preserved |
|---|---|
| disguise | 0.864 |
| namespace | 1.000 |
| opaque | 0.754 |
| rename | 0.882 |

### Where the operation verb lives

Continuity is not uniform, and the variation is structural rather than noisy.
A call whose payload states the operation -- a shell command, a SQL statement,
Python source -- keeps its identity under any relabelling. A call carrying only an
operand cannot: `f(path="/production/db")` is equally consistent with a read, a
write and a delete, so the verb exists only in the name and a rename destroys it.
This is a property of the tool's schema, not of the analyzer.

| strategy | verb in payload | verb in name |
|---|---|---|
| rename | 1.000 (n=60) | 0.740 (n=50) |
| namespace | 1.000 (n=60) | 1.000 (n=50) |
| opaque | 1.000 (n=60) | 0.460 (n=50) |
| disguise | 1.000 (n=60) | 0.700 (n=50) |
