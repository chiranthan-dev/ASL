"""Run the evaluation: `python -m evaluation.run`.

Writes `evaluation/results/results.json` and `evaluation/results/REPORT.md`.
Deterministic — same corpus, same seed, same numbers on every machine.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import load_config
from evaluation.corpus import build_corpus, summary
from evaluation.metrics import Metrics, ablation, category_table, markdown_table, score
from evaluation.systems import EvaluatedSystem, Outcome, build_systems

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def run_system(system: EvaluatedSystem, scenarios: list, verbose: bool = True) -> list[Outcome]:
    system.prepare()
    outcomes: list[Outcome] = []
    started = time.perf_counter()
    for index, scenario in enumerate(scenarios, start=1):
        outcomes.append(system.judge(scenario))
        if verbose and index % 50 == 0:
            print(f"    {system.name}: {index}/{len(scenarios)}", flush=True)
    if verbose:
        print(f"    {system.name}: done in {time.perf_counter() - started:.1f}s", flush=True)
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASL evaluation harness")
    parser.add_argument("--out", default=str(RESULTS_DIR), help="output directory")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    verbose = not args.quiet

    scenarios = build_corpus()
    corpus_summary = summary()
    if verbose:
        print(f"corpus: {corpus_summary['size']} scenarios "
              f"({corpus_summary['harmful']} harmful / {corpus_summary['benign']} benign)\n")

    with tempfile.TemporaryDirectory(prefix="asl_eval_", ignore_cleanup_errors=True) as store_dir:
        config = load_config().with_overrides(database_path=f"{store_dir}/unused.db")
        systems = build_systems(config, store_dir)

        all_metrics: list[Metrics] = []
        all_outcomes: dict[str, list[dict]] = {}
        for system in systems:
            if verbose:
                print(f"  running {system.name} …", flush=True)
            outcomes = run_system(system, scenarios, verbose)
            all_metrics.append(score(system.name, system.description, outcomes))
            all_outcomes[system.name] = [
                {"scenario_id": o.scenario_id, "category": o.category, "harmful": o.harmful,
                 "decision": o.decision.value, "risk": o.risk_score, "fast_path": o.fast_path,
                 "latency_ms": o.latency_ms}
                for o in outcomes
            ]
            system.close()

    by_name = {m.system: m for m in all_metrics}
    contribution = ablation(by_name["asl_full"], by_name["asl_without_fingerprints"])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus": corpus_summary,
        "systems": [m.as_dict() for m in all_metrics],
        "fingerprinting_contribution": contribution,
        "outcomes": all_outcomes,
    }
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out_dir / "REPORT.md").write_text(render_report(payload, all_metrics, contribution), encoding="utf-8")

    if verbose:
        print("\n" + markdown_table(all_metrics))
        print(f"\nfingerprinting contribution: delta F1 {contribution['delta_f1']:+.3f}, "
              f"delta FPR {contribution['delta_fpr']:+.3f}, "
              f"fast path {contribution['fast_path_rate_gained']:+.1%}")
        print(f"\nwritten to {out_dir}")
    return 0


def render_report(payload: dict, all_metrics: list[Metrics], contribution: dict) -> str:
    corpus = payload["corpus"]
    full = next(m for m in all_metrics if m.system == "asl_full")
    ablated = next(m for m in all_metrics if m.system == "asl_without_fingerprints")
    static = next(m for m in all_metrics if m.system == "static_rules")
    none = next(m for m in all_metrics if m.system == "agent_without_asl")

    return f"""# ASL evaluation report

Generated {payload['generated_at']} · corpus seed {corpus['seed']} · reproducible with
`python -m evaluation.run`.

## Corpus

{corpus['size']} scenarios: **{corpus['harmful']} harmful**, {corpus['benign']} benign.

| category | scenarios | harmful |
|---|---|---|
""" + "\n".join(
        f"| {name} | {data['total']} | {data['harmful']} |"
        for name, data in corpus["categories"].items()
    ) + f"""

Positive class is *harmful*: the layer should have interposed. A detection is any
decision other than a silent allow — CHALLENGE, SANDBOX or BLOCK — because asking a
human is a successful intervention, not a failure.

## Results

{markdown_table(all_metrics)}

### Per-category accuracy

{category_table(all_metrics)}

## What behavioural fingerprinting contributed

Ablation: `asl_full` differs from `asl_without_fingerprints` in exactly two ways — the
fast path is disabled and the fingerprint signal is pinned to a constant. Every
analyzer, weight and threshold is otherwise identical.

| metric | without fingerprints | full ASL | delta |
|---|---|---|---|
| precision | {ablated.precision:.3f} | {full.precision:.3f} | {contribution['delta_precision']:+.3f} |
| recall | {ablated.recall:.3f} | {full.recall:.3f} | {contribution['delta_recall']:+.3f} |
| F1 | {ablated.f1:.3f} | {full.f1:.3f} | {contribution['delta_f1']:+.3f} |
| false-positive rate | {ablated.fpr:.3f} | {full.fpr:.3f} | {contribution['delta_fpr']:+.3f} |
| false-negative rate | {ablated.fnr:.3f} | {full.fnr:.3f} | {contribution['delta_fnr']:+.3f} |
| over-block rate | {ablated.over_block_rate:.3f} | {full.over_block_rate:.3f} | {contribution['delta_over_block_rate']:+.3f} |
| fast-path share | {ablated.fast_path_rate:.3f} | {full.fast_path_rate:.3f} | {contribution['fast_path_rate_gained']:+.3f} |
| mean latency (ms) | {ablated.mean_latency_ms:.2f} | {full.mean_latency_ms:.2f} | {contribution['delta_mean_latency_ms']:+.2f} |

## Reading the comparison honestly

* **{none.system}** detects nothing by construction (recall {none.recall:.2f}). It is in the
  table to quantify the exposure, not as a competitor.
* **{static.system}** is not a straw man: it denies the dangerous tools outright and greps
  for dangerous strings. Its recall is {static.recall:.2f} at a false-positive rate of
  {static.fpr:.2f} and an over-block rate of {static.over_block_rate:.2f}. Where it fails is
  the argument-manipulation and high-impact-legitimate categories, because a tool name
  cannot separate `delete("scratch.tmp")` from `delete("/production/database/")`.
* **{full.system}** reaches F1 {full.f1:.3f} at a false-positive rate of {full.fpr:.3f}.

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
   share of the corpus ({corpus['categories']['repeated_benign']['total']}/{corpus['size']})
   directly sets the ceiling on the fast-path rate.
"""


if __name__ == "__main__":
    sys.exit(main())
