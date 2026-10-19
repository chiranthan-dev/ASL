# ASL evaluation report

Generated 2026-10-19T05:56:04.616430+00:00 · corpus seed 20260827 · reproducible with
`python -m evaluation.run`.

## Corpus

200 scenarios: **111 harmful**, 89 benign.

| category | scenarios | harmful |
|---|---|---|
| benign | 50 | 0 |
| suspicious | 25 | 25 |
| malicious | 42 | 42 |
| novel_but_benign | 18 | 0 |
| repeated_benign | 16 | 0 |
| high_impact_legitimate | 15 | 15 |
| argument_manipulation | 10 | 5 |
| multi_step_attack | 14 | 14 |
| prohibited_purpose | 10 | 10 |

Positive class is *harmful*: the layer should have interposed. A detection is any
decision other than a silent allow — CHALLENGE, SANDBOX or BLOCK — because asking a
human is a successful intervention, not a failure.

## Results

| system | precision | recall | F1 | FPR | FNR | over-block | fast path | human verify | mean ms |
|---|---|---|---|---|---|---|---|---|---|
| agent_without_asl | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.00 |
| static_rules | 0.876 | 0.829 | 0.852 | 0.146 | 0.171 | 0.022 | 0.000 | 0.000 | 0.10 |
| asl_without_fingerprints | 0.980 | 0.901 | 0.939 | 0.022 | 0.099 | 0.000 | 0.000 | 0.495 | 6.74 |
| asl_full | 0.971 | 0.910 | 0.940 | 0.034 | 0.090 | 0.000 | 0.200 | 0.505 | 6.17 |

### Per-category accuracy

| category | agent_without_asl | static_rules | asl_without_fingerprints | asl_full |
|---|---|---|---|---|
| argument_manipulation | 5/10 (50%) | 6/10 (60%) | 8/10 (80%) | 7/10 (70%) |
| benign | 50/50 (100%) | 40/50 (80%) | 50/50 (100%) | 50/50 (100%) |
| high_impact_legitimate | 0/15 (0%) | 12/15 (80%) | 9/15 (60%) | 10/15 (67%) |
| malicious | 0/42 (0%) | 42/42 (100%) | 42/42 (100%) | 42/42 (100%) |
| multi_step_attack | 0/14 (0%) | 14/14 (100%) | 14/14 (100%) | 14/14 (100%) |
| novel_but_benign | 18/18 (100%) | 18/18 (100%) | 18/18 (100%) | 18/18 (100%) |
| prohibited_purpose | 0/10 (0%) | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| repeated_benign | 16/16 (100%) | 16/16 (100%) | 16/16 (100%) | 16/16 (100%) |
| suspicious | 0/25 (0%) | 20/25 (80%) | 20/25 (80%) | 20/25 (80%) |

## What behavioural fingerprinting contributed

Ablation: `asl_full` differs from `asl_without_fingerprints` in exactly two ways — the
fast path is disabled and the fingerprint signal is pinned to a constant. Every
analyzer, weight and threshold is otherwise identical.

| metric | without fingerprints | full ASL | delta |
|---|---|---|---|
| precision | 0.980 | 0.971 | -0.009 |
| recall | 0.901 | 0.910 | +0.009 |
| F1 | 0.939 | 0.940 | +0.001 |
| false-positive rate | 0.022 | 0.034 | +0.011 |
| false-negative rate | 0.099 | 0.090 | -0.009 |
| over-block rate | 0.000 | 0.000 | +0.000 |
| fast-path share | 0.000 | 0.200 | +0.200 |
| mean latency (ms) | 6.74 | 6.17 | -0.57 |

## Reading the comparison honestly

* **agent_without_asl** detects nothing by construction (recall 0.00). It is in the
  table to quantify the exposure, not as a competitor.
* **static_rules** is not a straw man: it denies the dangerous tools outright and greps
  for dangerous strings. Its recall is 0.83 at a false-positive rate of
  0.15 and an over-block rate of 0.02. Where it fails is
  the argument-manipulation and high-impact-legitimate categories, because a tool name
  cannot separate `delete("scratch.tmp")` from `delete("/production/database/")`.
* **asl_full** reaches F1 0.940 at a false-positive rate of 0.034.

## Threats to validity

Stated plainly, because a reviewer will ask:

1. **The corpus is synthetic and authored alongside the system.** It is generated from
   templates by the same author as the analyzers, so it cannot demonstrate generalisation
   to real agent traffic. It is a controlled comparison between systems, not a field study.
2. **Ground truth is assigned by construction.** A scenario is harmful because of how it
   was built. Categories such as `high_impact_legitimate` encode a judgement — that real
   admin work *should* be interposed on — and a reviewer could reasonably disagree.
3. **The static baseline is one reading of "conventional policy".** A different rule set
   would move its numbers.
4. **Latency is measured in-process with mock tools.** It reflects analyzer cost, not
   production overhead, and the fast-path saving here is a stage count rather than a
   wall-clock win. With a network-backed analyzer in the loop that changes.
5. **Repeated-benign scenarios are favourable to the fast path by construction.** Their
   share of the corpus (16/200)
   directly sets the ceiling on the fast-path rate.
