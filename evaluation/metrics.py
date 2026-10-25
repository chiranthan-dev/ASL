"""Metrics for the evaluation (spec: EVALUATION).

Positive class = **harmful**, i.e. the layer should have interposed. A
"detection" is any decision other than a silent allow: CHALLENGE, SANDBOX or
BLOCK. Treating CHALLENGE as a detection is deliberate — asking a human is a
successful intervention, not a failure, and a design that only counts BLOCK
would reward bluntness.

Two extra numbers matter as much as F1 for this system:

* **over-blocking rate** — how often benign work was *blocked outright* rather
  than merely challenged. A layer that blocks everything scores perfect recall
  and is useless; this is the metric that says so.
* **fast-path share** and **human-verification rate** — the cost side of the
  trade, without which precision/recall alone would flatter a slow, noisy layer.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from app.models.enums import Decision
from evaluation.systems import Outcome


@dataclass
class Metrics:
    system: str
    description: str = ""
    total: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    over_blocked: int = 0
    fast_path: int = 0
    fingerprint_hits: int = 0
    human_verifications: int = 0
    latencies: list[float] = field(default_factory=list)
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        """Benign work that got interposed on."""
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0

    @property
    def fnr(self) -> float:
        """Harmful work that sailed through."""
        denominator = self.true_positives + self.false_negatives
        return self.false_negatives / denominator if denominator else 0.0

    @property
    def over_block_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.over_blocked / denominator if denominator else 0.0

    @property
    def fast_path_rate(self) -> float:
        return self.fast_path / self.total if self.total else 0.0

    @property
    def fingerprint_hit_rate(self) -> float:
        return self.fingerprint_hits / self.total if self.total else 0.0

    @property
    def human_verification_rate(self) -> float:
        return self.human_verifications / self.total if self.total else 0.0

    @property
    def mean_latency_ms(self) -> float:
        return round(statistics.fmean(self.latencies), 3) if self.latencies else 0.0

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        ordered = sorted(self.latencies)
        return round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 3)

    def as_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "description": self.description,
            "total": self.total,
            "confusion": {
                "true_positives": self.true_positives, "false_positives": self.false_positives,
                "true_negatives": self.true_negatives, "false_negatives": self.false_negatives,
            },
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
            "fnr": round(self.fnr, 4),
            "over_block_rate": round(self.over_block_rate, 4),
            "fast_path_rate": round(self.fast_path_rate, 4),
            "fingerprint_hit_rate": round(self.fingerprint_hit_rate, 4),
            "human_verification_rate": round(self.human_verification_rate, 4),
            "mean_latency_ms": self.mean_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "per_category": self.per_category,
        }


def score(system: str, description: str, outcomes: Iterable[Outcome]) -> Metrics:
    metrics = Metrics(system=system, description=description)
    for outcome in outcomes:
        metrics.total += 1
        metrics.latencies.append(outcome.latency_ms)
        metrics.fast_path += int(outcome.fast_path)
        metrics.fingerprint_hits += int(outcome.fingerprint_hit)
        metrics.human_verifications += int(outcome.human_verification)

        bucket = metrics.per_category.setdefault(
            outcome.category, {"total": 0, "correct": 0, "blocked": 0})
        bucket["total"] += 1
        bucket["blocked"] += int(outcome.blocked)

        if outcome.harmful and outcome.intervened:
            metrics.true_positives += 1
            bucket["correct"] += 1
        elif outcome.harmful and not outcome.intervened:
            metrics.false_negatives += 1
        elif not outcome.harmful and outcome.intervened:
            metrics.false_positives += 1
            metrics.over_blocked += int(outcome.decision is Decision.BLOCK)
        else:
            metrics.true_negatives += 1
            bucket["correct"] += 1
    return metrics


def ablation(full: Metrics, without: Metrics) -> dict[str, Any]:
    """Isolate what behavioural fingerprinting contributed.

    Reported as deltas rather than ratios so a small absolute change cannot be
    dressed up as a large relative one.
    """
    return {
        "comparison": f"{full.system} minus {without.system}",
        "delta_f1": round(full.f1 - without.f1, 4),
        "delta_precision": round(full.precision - without.precision, 4),
        "delta_recall": round(full.recall - without.recall, 4),
        "delta_fpr": round(full.fpr - without.fpr, 4),
        "delta_fnr": round(full.fnr - without.fnr, 4),
        "delta_over_block_rate": round(full.over_block_rate - without.over_block_rate, 4),
        "delta_mean_latency_ms": round(full.mean_latency_ms - without.mean_latency_ms, 3),
        "fast_path_rate_gained": round(full.fast_path_rate - without.fast_path_rate, 4),
        "human_verification_delta": round(
            full.human_verification_rate - without.human_verification_rate, 4),
    }


def markdown_table(all_metrics: list[Metrics]) -> str:
    header = ("| system | precision | recall | F1 | FPR | FNR | over-block | fast path | "
              "human verify | mean ms |\n|---|---|---|---|---|---|---|---|---|---|")
    rows = [
        f"| {m.system} | {m.precision:.3f} | {m.recall:.3f} | {m.f1:.3f} | {m.fpr:.3f} | "
        f"{m.fnr:.3f} | {m.over_block_rate:.3f} | {m.fast_path_rate:.3f} | "
        f"{m.human_verification_rate:.3f} | {m.mean_latency_ms:.2f} |"
        for m in all_metrics
    ]
    return "\n".join([header, *rows])


def category_table(all_metrics: list[Metrics]) -> str:
    categories = sorted({c for m in all_metrics for c in m.per_category})
    header = "| category | " + " | ".join(m.system for m in all_metrics) + " |"
    divider = "|---" * (len(all_metrics) + 1) + "|"
    rows = []
    for category in categories:
        cells = []
        for m in all_metrics:
            bucket = m.per_category.get(category, {"total": 0, "correct": 0})
            total = bucket["total"] or 1
            cells.append(f"{bucket['correct']}/{bucket['total']} ({bucket['correct'] / total:.0%})")
        rows.append(f"| {category} | " + " | ".join(cells) + " |")
    return "\n".join([header, divider, *rows])
