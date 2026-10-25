"""Anomaly Detector (spec section 13).

`AnomalyDetector` is the interface; `StatisticalAnomalyDetector` is the initial
implementation, backed by the streaming statistics in the trust store. A
learned detector can be dropped in later without touching the risk engine —
`MLAnomalyDetector` marks that seam explicitly.

Five families of evidence, per the specification: frequency, unusual
transitions, unusual capability combinations, timing, and action volume. Each
contributes an independent sub-score; the detector reports the worst plus a
bounded premium for corroboration, mirroring how findings are aggregated
elsewhere.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.models.context import AnalysisContext
from app.models.enums import Capability
from app.trust.fingerprint_store import FingerprintStore


@dataclass
class AnomalySignal:
    score: float
    confidence: float
    anomalous: bool
    reasons: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


class AnomalyDetector(ABC):
    """Interface every detector implementation must satisfy."""

    name = "anomaly"

    @abstractmethod
    def score(self, context: AnalysisContext) -> AnomalySignal:
        """Return an anomaly signal for one intercepted call."""


class StatisticalAnomalyDetector(AnomalyDetector):
    """Frequency / transition / combination / timing / volume heuristics."""

    BURST_CALLS_PER_MINUTE = 30
    VOLUME_THRESHOLD = 12

    def __init__(self, store: FingerprintStore, threshold: float = 55.0) -> None:
        self.store = store
        self.threshold = threshold

    def score(self, context: AnalysisContext) -> AnomalySignal:
        reasons: list[str] = []
        components: dict[str, float] = {}
        user = context.user.user_id

        components["novel_combination"] = self._combination(context, user, reasons)
        components["novel_transition"] = self._transition(context, user, reasons)
        components["frequency"] = self._frequency(context, reasons)
        components["timing"] = self._timing(context, reasons)
        components["volume"] = self._volume(context, reasons)

        ordered = sorted(components.values(), reverse=True)
        score = ordered[0] + sum(min(6.0, v * 0.12) for v in ordered[1:])
        score = round(min(100.0, score), 2)

        history_size = self.store.seen_key("user", user)
        confidence = round(min(0.9, 0.35 + 0.05 * history_size), 3)

        return AnomalySignal(
            score=score,
            confidence=confidence,
            anomalous=score >= self.threshold and history_size >= 3,
            reasons=reasons or ["nothing unusual relative to this user's history"],
            detail={"components": components, "observations_for_user": history_size},
        )

    def _combination(self, context: AnalysisContext, user: str, reasons: list[str]) -> float:
        key = "+".join(sorted(c.value for c in context.capability_set)) or "NONE"
        seen = self.store.seen_key("user_combination", f"{user}|{key}")
        self.store.observe_stat("user_combination", f"{user}|{key}", 1.0)
        self.store.observe_stat("user", user, 1.0)
        if seen == 0:
            reasons.append(f"first time this user has requested the combination {key}")
            return 62.0
        if seen < 3:
            return 35.0
        return 10.0

    READ_ONLY_STEPS = frozenset({Capability.READ.value, "NONE"})

    def _transition(self, context: AnalysisContext, user: str, reasons: list[str]) -> float:
        transitions = context.chain_fingerprint.transitions
        if not transitions:
            return 8.0
        worst = 8.0
        for transition in transitions:
            key = f"{user}|{transition}"
            seen = self.store.seen_key("user_transition", key)
            self.store.observe_stat("user_transition", key, 1.0)
            if seen == 0 and self._benign_transition(transition):
                worst = max(worst, 30.0)
            elif seen == 0:
                reasons.append(f"unseen action transition for this user: {transition}")
                worst = max(worst, 58.0)
            elif seen < 3:
                worst = max(worst, 30.0)
        return worst

    @classmethod
    def _benign_transition(cls, transition: str) -> bool:
        """`SRC-EDGE->DST`: true when DST only reads and the edge is a plain
        sequence. A data-flow edge is never benign here -- what flows matters."""
        left, _, target = transition.partition("->")
        _, _, edge = left.rpartition("-")
        return edge == "SEQUENCE" and target in cls.READ_ONLY_STEPS

    def _frequency(self, context: AnalysisContext, reasons: list[str]) -> float:
        started = context.history.started_at or time.time()
        elapsed_minutes = max((time.time() - started) / 60.0, 1e-3)
        rate = context.history.call_count / elapsed_minutes
        if context.history.call_count >= 5 and rate > self.BURST_CALLS_PER_MINUTE:
            reasons.append(f"call rate {rate:.0f}/min looks automated")
            return 70.0
        if context.history.call_count >= 5 and rate > self.BURST_CALLS_PER_MINUTE / 2:
            return 40.0
        return 8.0

    def _timing(self, context: AnalysisContext, reasons: list[str]) -> float:
        hour = context.invocation.timestamp.hour
        key = f"{context.user.user_id}|hour"
        mean, stddev, count = self.store.observe_stat("user_hour", key, float(hour))
        if count >= 5 and stddev > 0 and abs(hour - mean) > 2.5 * stddev:
            reasons.append(f"activity at {hour:02d}:00 is unusual for this user")
            return 55.0
        if count == 0 and (hour < 5 or hour >= 23):
            return 25.0
        return 8.0

    def _volume(self, context: AnalysisContext, reasons: list[str]) -> float:
        count = context.history.call_count
        if count >= self.VOLUME_THRESHOLD * 2:
            reasons.append(f"{count} actions in a single session")
            return 65.0
        if count >= self.VOLUME_THRESHOLD:
            reasons.append(f"{count} actions in a single session")
            return 40.0
        return 8.0


class MLAnomalyDetector(AnomalyDetector):
    """Seam for a learned detector (autoencoder / isolation forest / sequence model).

    Deliberately unimplemented: the point of declaring it is that the risk
    engine depends on `AnomalyDetector`, not on the statistical implementation,
    so swapping in a trained model is a constructor change and an evaluation
    run — not a refactor.
    """

    def __init__(self, model_path: str | None = None) -> None:
        self.model_path = model_path

    def score(self, context: AnalysisContext) -> AnomalySignal:
        raise NotImplementedError(
            "learned anomaly detection is future work; use StatisticalAnomalyDetector"
        )
