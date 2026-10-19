"""Decision Engine (spec section 16).

    risk < 20      -> ALLOW
    20 - 50        -> ALLOW + LOG
    50 - 70        -> CHALLENGE USER
    70 - 90        -> SANDBOX
    >= 90          -> BLOCK

Human verification is an **independent** trigger, not a band. A call can sit at
risk 42 and still require confirmation because it is irreversible, because the
analyzers disagree, because confidence is low, or because policy says so. Tying
confirmation solely to the score would mean a confidently-wrong pipeline never
asks for help — which is exactly when it should.
"""

from __future__ import annotations

from app.core.config import ASLConfig, get_config
from app.models.context import AnalysisContext
from app.models.decision import DecisionResult
from app.models.enums import Capability, Decision, DecisionPath, Environment
from app.models.risk import RiskAssessment


class DecisionEngine:
    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()

    # -- bands ------------------------------------------------------------
    def band(self, risk: float) -> Decision:
        cfg = self.config
        if risk < cfg.risk_allow_threshold:
            return Decision.ALLOW
        if risk < cfg.risk_log_threshold:
            return Decision.ALLOW_WITH_LOG
        if risk < cfg.risk_challenge_threshold:
            return Decision.CHALLENGE
        if risk < cfg.risk_sandbox_threshold:
            return Decision.SANDBOX
        return Decision.BLOCK

    # -- decision ---------------------------------------------------------
    def decide(
        self,
        assessment: RiskAssessment,
        context: AnalysisContext,
        path: DecisionPath = DecisionPath.FULL_ANALYSIS,
    ) -> DecisionResult:
        decision = self.band(assessment.risk_score)
        reasons = self.human_verification_reasons(assessment, context, decision)

        # A confirmation requirement can only make a decision stricter.
        if reasons and decision in (Decision.ALLOW, Decision.ALLOW_WITH_LOG):
            decision = Decision.CHALLENGE

        return DecisionResult(
            decision=decision,
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            path=path,
            human_verification_required=bool(reasons),
            human_verification_reasons=reasons,
            explanation=self.explain(decision, assessment, reasons),
        )

    def fast_path_decision(self, context: AnalysisContext, risk: float, confidence: float) -> DecisionResult:
        """The fast path still produces a real decision, just a cheaper one."""
        return DecisionResult(
            decision=Decision.ALLOW,
            risk_score=risk,
            confidence=confidence,
            path=DecisionPath.FAST_PATH,
            human_verification_required=False,
            explanation=(
                f"FAST_PATH_ALLOW — behaviour {context.match.matched_fingerprint_id} has been "
                f"validated {context.match.occurrence_count}x for this user in this environment "
                f"(historical risk {context.match.historical_risk:.1f}); expensive analysis skipped, "
                f"identity, environment, policy and anomaly checks still applied"
            ),
        )

    # -- human verification -----------------------------------------------
    def human_verification_reasons(
        self, assessment: RiskAssessment, context: AnalysisContext, decision: Decision
    ) -> list[str]:
        cfg = self.config
        reasons: list[str] = []

        high_impact = {Capability(c) for c in cfg.high_impact_capabilities if c in Capability.__members__}
        touched = context.capability_set & high_impact
        irreversible = not context.tool.reversible
        if touched and irreversible:
            reasons.append(
                "high-impact and irreversible: " + ", ".join(sorted(c.value for c in touched))
            )
        elif touched and context.environment is Environment.PRODUCTION:
            reasons.append("high-impact capability in production")

        if assessment.confidence < cfg.low_confidence_threshold:
            reasons.append(f"low confidence in the analysis ({assessment.confidence:.2f})")

        if assessment.disagreement > cfg.analyzer_disagreement_threshold:
            reasons.append(f"analyzers disagree ({assessment.disagreement:.2f} spread)")

        if assessment.invariants and decision not in (Decision.BLOCK,):
            reasons.append("policy requires confirmation for: " + ", ".join(assessment.invariants))

        if not context.tool.known_tool and context.capability_set - {Capability.READ, Capability.NETWORK}:
            reasons.append("unregistered tool requesting more than read access")

        return reasons

    # -- explanation -------------------------------------------------------
    def explain(self, decision: Decision, assessment: RiskAssessment, reasons: list[str]) -> str:
        lines = [f"{decision.value} — risk {assessment.risk_score:.0f}, confidence {assessment.confidence:.2f}"]
        for signal in sorted(assessment.signals, key=lambda s: s.value * s.weight, reverse=True)[:5]:
            lines.append(f"  {signal.name.replace('_', ' ').title()}: {signal.value:.0f}")
        if assessment.invariants:
            lines.append("  Invariants: " + ", ".join(assessment.invariants))
        if reasons:
            lines.append("  Human verification: " + "; ".join(reasons))
        lines.append(f"  {assessment.explanation}")
        return "\n".join(lines)

    @staticmethod
    def summarize(decisions: list[Decision]) -> Decision:
        """Session roll-up: the strictest decision wins."""
        order = [Decision.ALLOW, Decision.ALLOW_WITH_LOG, Decision.CHALLENGE, Decision.SANDBOX, Decision.BLOCK]
        return max(decisions, key=order.index) if decisions else Decision.ALLOW
