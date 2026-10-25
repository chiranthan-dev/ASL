"""Environment Analyzer (spec section 11).

The same action is not equally dangerous everywhere. Deleting a directory in a
sandbox is a test; in production it is an incident. This analyzer turns the
deployment context — environment, device, session, policy version — into a risk
contribution and a set of multipliers the fusion engine can apply.
"""

from __future__ import annotations

from app.core.config import ASLConfig, get_config
from app.models.context import AnalysisContext
from app.models.enums import Capability, Environment

ENVIRONMENT_PROFILE: dict[Environment, tuple[float, float]] = {
    Environment.SANDBOX: (5.0, 0.75),
    Environment.DEVELOPMENT: (12.0, 0.9),
    Environment.STAGING: (30.0, 1.1),
    Environment.PRODUCTION: (55.0, 1.35),
}

DESTRUCTIVE = {Capability.DELETE, Capability.MODIFY, Capability.PRIVILEGE_CHANGE, Capability.EXECUTE}


class EnvironmentAnalyzer:
    name = "environment"

    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()

    def analyze(self, context: AnalysisContext) -> tuple[float, float, str, dict]:
        base, multiplier = ENVIRONMENT_PROFILE[context.environment]
        risk = base
        notes = [f"{context.environment.value} environment"]
        detail: dict[str, object] = {
            "environment": context.environment.value,
            "destructive_multiplier": multiplier,
        }

        destructive = context.capability_set & DESTRUCTIVE
        if destructive and context.environment is Environment.PRODUCTION:
            risk += 25
            notes.append(
                "destructive capability in production: "
                + ", ".join(sorted(c.value for c in destructive))
            )
        elif destructive and context.environment is Environment.SANDBOX:
            notes.append("destructive capability, but blast radius is contained by the sandbox")

        if not context.device_id:
            risk += 8
            detail["device"] = "unidentified"
            notes.append("no device identity supplied")
        else:
            detail["device"] = context.device_id

        policy = context.policy_version or self.config.policy_version
        detail["policy_version"] = policy
        if policy != self.config.policy_version:
            risk += 20
            notes.append(f"request cites policy {policy}, active policy is {self.config.policy_version}")

        confidence = 0.9 if context.device_id else 0.7
        return round(min(100.0, risk), 2), confidence, "; ".join(notes), detail

    def multiplier(self, environment: Environment) -> float:
        return ENVIRONMENT_PROFILE[environment][1]


class TrustAnalyzer:
    """User Trust Manager as a risk *signal* (spec section 10).

    Emits a low number for established users and a high one for unknown or
    previously-blocked users. The fusion engine bounds how much this can move
    the final score, so trust can shade a decision but never carry it.
    """

    name = "user_trust"

    def __init__(self, config: ASLConfig | None = None) -> None:
        self.config = config or get_config()

    def analyze(self, context: AnalysisContext) -> tuple[float, float, str, dict]:
        state = context.user
        if not state.known:
            return (
                60.0, 0.5,
                "unknown user: no track record, so nothing offsets the action's own risk",
                {"trust_score": state.trust_score, "known": False},
            )

        risk = round(100.0 - state.trust_score * 92.0, 2)
        notes = [
            f"trust {state.trust_score:.2f} across {state.successful_actions} allowed "
            f"and {state.blocked_actions} stopped actions"
        ]
        if state.blocked_actions:
            notes.append(f"{state.blocked_actions} previous action(s) were stopped")
        if state.anomalies:
            risk = min(100.0, risk + 6 * state.anomalies)
            notes.append(f"{state.anomalies} anomaly(ies) on record")

        confidence = min(0.9, 0.5 + 0.04 * (state.successful_actions + state.blocked_actions))
        return risk, round(confidence, 3), "; ".join(notes), {
            "trust_score": state.trust_score,
            "known": True,
            "successful_actions": state.successful_actions,
            "blocked_actions": state.blocked_actions,
            "anomalies": state.anomalies,
        }
