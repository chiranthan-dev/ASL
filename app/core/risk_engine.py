"""Adaptive Risk Engine (spec section 15).

`RiskFusionStrategy` is the seam that keeps this research honest: the weighted
model below is a **baseline**, not the contribution. Alternative strategies
(`AdaptiveRiskFusion`, `GraphRiskPropagation`, `LearnedRiskFusion`) must be
swappable without touching a single analyzer, so that phase 15 can attribute
results to behavioral fingerprinting rather than to hand-tuned weights.

`WeightedRiskFusion` is explicitly *not* an average. It combines:

1. a confidence-weighted mean of every signal (the baseline view),
2. a **dominance floor** — the worst signal drags the result up, so one
   CRITICAL analyzer cannot be out-voted by benign ones,
3. **invariant floors** — named conditions that pin risk at a minimum no
   amount of trust, history or averaging may lower,
4. a **bounded trust discount**, applied last and never below an invariant.
"""

from __future__ import annotations

import statistics
from abc import ABC, abstractmethod

from app.core.config import ASLConfig, get_config
from app.models.context import AnalysisContext
from app.models.enums import Capability, Environment, Intent, ResourceClass, Scope
from app.models.risk import RiskAssessment, RiskSignal

#: how much the single worst signal is allowed to pull the fused score up
DOMINANCE_FACTOR = 0.86

#: Only signals that describe *what is actually being done* may set the
#: dominance floor: the analysed arguments, the inferred purpose, and the
#: chain the call sits in.
#:
#: Everything else is a **modulator**. Tool sensitivity and capability weight
#: describe potential rather than action (`gmail.send` is powerful even when
#: the mail is harmless); novelty, user trust, environment and anomaly describe
#: circumstances. Modulators move the weighted mean, but letting them dominate
#: would mean an unfamiliar user doing something harmless scores like an
#: attack — which is precisely the false-positive mode this system must avoid.
DOMINANT_SIGNALS = frozenset({"argument", "intent", "execution_chain", "request_policy"})

#: Signals that are *supposed* to agree with each other. Disagreement among
#: these means the pipeline genuinely does not understand the call, and a human
#: should look.
#:
#: `tool` and `capability` are excluded on purpose. A powerful tool used
#: harmlessly (`gmail.send` for one internal message) always shows a large gap
#: between potential and action — that gap is the thing ASL exists to resolve,
#: not evidence of confusion. Counting it would fire the confusion alarm on
#: every ordinary use of any capable tool.
DISAGREEMENT_SIGNALS = DOMINANT_SIGNALS | {"fingerprint"}

#: Signals that describe the *behaviour*, for what a fingerprint remembers.
#:
#: `request_policy` is excluded, and the distinction is load-bearing. "HACK INTO
#: SERVER" and "look up a dog picture" produce the *same* behavioural
#: fingerprint, because both really are a web search. Recording the resulting
#: block against that fingerprint would poison an innocent signature and make
#: every later legitimate search inherit the punishment — a user could degrade
#: everyone else's searches simply by asking prohibited things. The block was
#: caused by the purpose, so it is charged to the user's trust, never to the
#: behaviour's record.
BEHAVIOURAL_SIGNALS = DOMINANT_SIGNALS - {"request_policy"}

#: Signals intrinsic to a single call. `execution_chain` is deliberately
#: absent: it describes the session, and charging it to a per-call
#: fingerprint means a safe action inherits the risk of whatever it
#: happened to be performed alongside.
CALL_SIGNALS = BEHAVIOURAL_SIGNALS - {"execution_chain"}

#: Invariants that are properties of the behaviour rather than of the request.
#: Only these pin a fingerprint's stored risk high.
BEHAVIOURAL_INVARIANTS = frozenset({
    "DESTRUCTIVE_PRODUCTION", "CREDENTIAL_ACCESS", "PRIVILEGE_ESCALATION",
    "REMOTE_CODE_EXECUTION", "EXFILTRATION_CHAIN",
})


class RiskFusionStrategy(ABC):
    """Pluggable fusion algorithm."""

    name = "RiskFusionStrategy"

    @abstractmethod
    def fuse(self, signals: list[RiskSignal], context: AnalysisContext) -> RiskAssessment:
        ...


class WeightedRiskFusion(RiskFusionStrategy):
    """Baseline: confidence-weighted mean + dominance floor + invariants."""

    name = "WeightedRiskFusion"

    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()

    def fuse(self, signals: list[RiskSignal], context: AnalysisContext) -> RiskAssessment:
        if not signals:
            return RiskAssessment(
                risk_score=100.0, confidence=0.0, strategy=self.name,
                explanation="no analyzer produced a signal, so the call cannot be cleared",
                invariants=["NO_SIGNALS"],
            )

        # 1. confidence-weighted mean --------------------------------------
        numerator = sum(s.value * s.weight * max(s.confidence, 0.1) for s in signals)
        denominator = sum(s.weight * max(s.confidence, 0.1) for s in signals)
        weighted_mean = numerator / denominator if denominator else 0.0

        # 2. dominance floor (action signals only) ---------------------------
        acting = [s for s in signals if s.name in DOMINANT_SIGNALS] or signals
        worst = max(acting, key=lambda s: s.value)
        score = max(weighted_mean, DOMINANCE_FACTOR * worst.value)

        # 3. environment shaping -------------------------------------------
        multiplier = self._environment_multiplier(context)
        score *= multiplier

        # 4. invariant floors ----------------------------------------------
        invariants = self.invariants(context)
        floor = max((self.config.invariant_floors[name] for name in invariants), default=0.0)
        score = max(score, floor)

        # 5. bounded trust discount ----------------------------------------
        discount = self._trust_discount(context, invariants)
        score = max(floor, score - discount)

        score = round(min(100.0, max(0.0, score)), 2)
        disagreement = self._disagreement(signals)
        confidence = self._confidence(signals, disagreement)
        behavioural = self.behavioural_risk(signals, invariants)
        per_call = self.call_risk(signals, invariants)

        return RiskAssessment(
            risk_score=score,
            confidence=confidence,
            strategy=self.name,
            signals=signals,
            capabilities=sorted(context.capability_set, key=lambda c: c.value),
            invariants=invariants,
            disagreement=disagreement,
            behavioural_risk=behavioural,
            call_risk=per_call,
            explanation=self.explain(score, signals, invariants, multiplier, discount, disagreement),
        )

    @staticmethod
    def call_risk(signals: list[RiskSignal], invariants: list[str]) -> float:
        """Risk of this call in isolation, for the per-call fingerprint.

        Same construction as `behavioural_risk` but over CALL_SIGNALS, so the
        stored history of "read a user file" reflects reading a user file and
        nothing else. Invariants still pin it high: a call that reached for a
        credential is not made cheap by appearing alone.
        """
        acting = [s for s in signals if s.name in CALL_SIGNALS]
        if not acting:
            return 0.0
        numerator = sum(s.value * s.weight for s in acting)
        denominator = sum(s.weight for s in acting)
        risk = numerator / denominator if denominator else 0.0
        if set(invariants) & BEHAVIOURAL_INVARIANTS:
            risk = max(risk, 90.0)
        return round(min(100.0, max(0.0, risk)), 2)

    @staticmethod
    def behavioural_risk(signals: list[RiskSignal], invariants: list[str]) -> float:
        """Risk attributable to the *behaviour alone*, for fingerprint history.

        A fingerprint describes an action, not an occasion. Storing the fully
        modulated score would let circumstance leak into the behaviour's
        permanent record: the same safe action would look riskier because a new
        user performed it, and could never accumulate a clean history. So only
        the action signals count here — and any invariant pins it high forever,
        because a behaviour that tripped an invariant must never become cheap.
        """
        acting = [s for s in signals if s.name in BEHAVIOURAL_SIGNALS]
        if not acting:
            return 0.0
        numerator = sum(s.value * s.weight for s in acting)
        denominator = sum(s.weight for s in acting)
        risk = numerator / denominator if denominator else 0.0
        if set(invariants) & BEHAVIOURAL_INVARIANTS:
            risk = max(risk, 90.0)
        return round(min(100.0, max(0.0, risk)), 2)

    # -- pieces -----------------------------------------------------------
    def invariants(self, context: AnalysisContext) -> list[str]:
        """Named conditions that pin a minimum risk regardless of history."""
        fired: list[str] = []
        caps = context.capability_set
        resources = {r.resource_class for r in context.arguments.resources}
        chain_caps = set(context.chain_fingerprint.capabilities)
        codes = context.finding_codes()

        destructive_target = resources & {
            ResourceClass.PRODUCTION_RESOURCE, ResourceClass.SYSTEM_PATH, ResourceClass.SENSITIVE_TABLE
        }
        if caps & {Capability.DELETE, Capability.MODIFY} and (
            destructive_target
            or (context.arguments.scope is Scope.UNBOUNDED)
            or (context.arguments.scope is Scope.RECURSIVE and context.environment is Environment.PRODUCTION)
        ):
            fired.append("DESTRUCTIVE_PRODUCTION")

        credential_finding = bool(
            codes & {"PATH_CREDENTIAL_STORE", "URL_CLOUD_METADATA", "GEN_CREDENTIAL_ARGUMENT"}
        )
        if ResourceClass.CREDENTIAL_STORE in resources or (
            Capability.AUTHENTICATE in caps and credential_finding
        ):
            fired.append("CREDENTIAL_ACCESS")

        if Capability.PRIVILEGE_CHANGE in caps:
            fired.append("PRIVILEGE_ESCALATION")

        if {Capability.DOWNLOAD, Capability.EXECUTE} <= (caps | chain_caps) and Capability.EXECUTE in caps:
            fired.append("REMOTE_CODE_EXECUTION")
        if "SH_DOWNLOAD_PIPE_EXEC" in codes or "SH_OBFUSCATED_EXEC" in codes:
            if "REMOTE_CODE_EXECUTION" not in fired:
                fired.append("REMOTE_CODE_EXECUTION")

        exfil_now = bool(caps & {Capability.UPLOAD, Capability.EMAIL}) and (
            context.sensitive_resource or "HTTP_EXFILTRATION_SHAPE" in codes
        )
        exfil_chain = (
            bool(chain_caps & {Capability.DATABASE, Capability.READ})
            and bool(chain_caps & {Capability.UPLOAD, Capability.EMAIL})
            and len(context.chain_fingerprint.steps) > 1
            and context.sensitive_resource
        )
        if exfil_now or exfil_chain:
            fired.append("EXFILTRATION_CHAIN")

        # A request for a prohibited purpose is an invariant in its own right:
        # the tool call it produces may be trivially safe (a web search), so
        # nothing else in this list would ever fire for it.
        if context.extras.get("policy_severity") == "PROHIBITED":
            fired.append("PROHIBITED_PURPOSE")

        return fired

    def _environment_multiplier(self, context: AnalysisContext) -> float:
        from app.analyzers.environment_analyzer import ENVIRONMENT_PROFILE

        destructive = context.capability_set & {
            Capability.DELETE, Capability.MODIFY, Capability.EXECUTE, Capability.PRIVILEGE_CHANGE
        }
        if not destructive:
            return 1.0
        return ENVIRONMENT_PROFILE[context.environment][1]

    def _trust_discount(self, context: AnalysisContext, invariants: list[str]) -> float:
        """Established users get a small break — never on an invariant."""
        if invariants:
            return 0.0
        if not context.user.known:
            return 0.0
        headroom = self.config.user_trust_max_risk_reduction
        return round(headroom * max(0.0, (context.user.trust_score - 0.5) / 0.45), 2)

    @staticmethod
    def _disagreement(signals: list[RiskSignal]) -> float:
        """How much do the analyzers that should agree contradict each other?

        Measured only across `DISAGREEMENT_SIGNALS`: these all describe the
        same act from different angles, so a wide spread means the pipeline
        genuinely does not understand the call. 0 = unanimous.
        """
        values = [s.value for s in signals if s.name in DISAGREEMENT_SIGNALS]
        if len(values) < 2:
            return 0.0
        return round(min(1.0, statistics.pstdev(values) / 50.0), 3)

    @staticmethod
    def _confidence(signals: list[RiskSignal], disagreement: float) -> float:
        weighted = sum(s.confidence * s.weight for s in signals) / max(sum(s.weight for s in signals), 1e-9)
        return round(min(0.99, max(0.05, weighted * (1.0 - 0.35 * disagreement))), 3)

    def explain(
        self,
        score: float,
        signals: list[RiskSignal],
        invariants: list[str],
        multiplier: float,
        discount: float,
        disagreement: float,
    ) -> str:
        top = sorted(signals, key=lambda s: s.value * s.weight, reverse=True)[:3]
        parts = [f"{s.name.replace('_', ' ')} {s.value:.0f}" for s in top]
        text = f"risk {score:.0f} driven by " + ", ".join(parts)
        if invariants:
            text += f"; invariant floor from {', '.join(invariants)}"
        if multiplier != 1.0:
            text += f"; environment multiplier x{multiplier}"
        if discount:
            text += f"; user trust discount -{discount}"
        if disagreement > 0.45:
            text += f"; analyzers disagree ({disagreement:.2f})"
        return text


class AdaptiveRiskFusion(WeightedRiskFusion):
    """Planned comparator: weights adapt to observed detection performance.

    Declared now so the interface is exercised by more than one class; the
    adaptation loop itself is phase-15 work and deliberately not faked here.
    """

    name = "AdaptiveRiskFusion"

    def fuse(self, signals: list[RiskSignal], context: AnalysisContext) -> RiskAssessment:  # pragma: no cover
        raise NotImplementedError(
            "AdaptiveRiskFusion is a planned comparator for the phase-15 evaluation"
        )


STRATEGIES: dict[str, type[RiskFusionStrategy]] = {
    WeightedRiskFusion.name: WeightedRiskFusion,
    AdaptiveRiskFusion.name: AdaptiveRiskFusion,
}


def get_strategy(name: str | None = None, config: ASLConfig | None = None) -> RiskFusionStrategy:
    config = config or get_config()
    strategy = STRATEGIES.get(name or config.fusion_strategy, WeightedRiskFusion)
    return strategy(config)  # type: ignore[call-arg]


def build_signals(context: AnalysisContext, parts: dict[str, tuple[float, float, str]],
                  config: ASLConfig | None = None) -> list[RiskSignal]:
    """Turn analyzer outputs into weighted `RiskSignal`s using config weights."""
    config = config or get_config()
    weights = config.weights.model_dump()
    return [
        RiskSignal(
            name=name,
            value=round(min(100.0, max(0.0, value)), 2),
            weight=float(weights.get(name, 1.0)),
            confidence=round(min(1.0, max(0.0, confidence)), 3),
            detail=detail,
        )
        for name, (value, confidence, detail) in parts.items()
    ]


#: Intent risk is looked up by the engine when assembling signals.
def intent_signal_value(intent: Intent, risk: float) -> float:
    return risk
